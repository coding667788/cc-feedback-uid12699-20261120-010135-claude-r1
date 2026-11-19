"""The request engine: op dispatch, persistence and the protected I/O mode.

Every step runs inside its own ``BEGIN IMMEDIATE`` transaction, except
``protected_io`` which owns a longer one spanning all of its items.  Step
results are plain JSON so a child process killed mid-operation can be
restarted against the same on-disk database and produce the same answer.

Two fault points exist, both requiring ``allow_faults``:

``io_uncommitted``
    Simulated I/O rows have been inserted but ``COMMIT`` is never reached.
    The process is terminated with ``os._exit`` so no Python cleanup runs; on
    the next open SQLite rolls the frames back.

``committed_unacked``
    ``COMMIT`` has succeeded and the receipt is durable, then the process is
    terminated before the caller sees any answer.  The retry must return the
    stored result without recomputing history.
"""

from __future__ import annotations

import json
import os

from . import capability
from .capability import chain_of, evaluate, handle_digest, node_failures
from .db import connect, next_counter, read_clock
from .errors import (  # noqa: F401
    E_ALREADY_EXISTS,
    E_FAULT_NOT_ALLOWED,
    E_GENERATION_CONFLICT,
    E_HANDLE_NOT_FOUND,
    E_INTERNAL,
    E_INVALID_REQUEST,
    E_PRECHECK_EXPIRED,
    E_PRECHECK_MODE_MISMATCH,
    E_PRECHECK_NOT_FOUND,
    E_PRECHECK_STALE,
    E_PRECHECK_USED,
    E_PROCESS_DEAD,
    E_PROCESS_NOT_FOUND,
    E_RESOURCE_METHOD_UNSUPPORTED,
    E_RESOURCE_NOT_FOUND,
    E_RIGHTS_ESCALATION,
    E_SANDBOX_NOT_FOUND,
    E_SANDBOX_NOT_NARROWING,
    E_TIME_REGRESSION,
    E_UNKNOWN_OP,
    E_WINDOW_ESCALATION,
    OK,
    REASON_CODES,
    EngineError,
)
from .util import (
    METHOD_BITS,
    METHODS,
    canonical,
    handle_ref,
    mask_to_methods,
    methods_to_mask,
    optional_int,
    require_dict,
    require_int,
    require_str,
    sha256_hex,
)

FAULT_IO_UNCOMMITTED = "io_uncommitted"
FAULT_COMMITTED_UNACKED = "committed_unacked"
ALLOWED_FAULTS = {FAULT_IO_UNCOMMITTED, FAULT_COMMITTED_UNACKED}

MODE_ALL_OR_NOTHING = "all_or_nothing"
MODE_BEST_EFFORT = "best_effort"
ALLOWED_MODES = {MODE_ALL_OR_NOTHING, MODE_BEST_EFFORT}

# Transactions in these states are finished and replayable.
REPLAYABLE_STATES = ("committed", "denied")


# ---------------------------------------------------------------------------
# world loading
# ---------------------------------------------------------------------------
def load_world(conn) -> capability.World:
    """Read every piece of state that can influence a decision, consistently.

    The caller is expected to hold a transaction (read or write); every query
    then observes one commit.
    """
    clock = read_clock(conn)
    processes = {
        row["name"]: {"generation": row["generation"], "alive": bool(row["alive"])}
        for row in conn.execute("SELECT name, generation, alive FROM processes")
    }
    resources = {
        row["name"]: {
            "name": row["name"],
            "tenant": row["tenant"],
            "generation": row["generation"],
            "rights_mask": row["rights_mask"],
        }
        for row in conn.execute(
            "SELECT name, tenant, generation, rights_mask FROM resources"
        )
    }
    sandboxes = {
        row["name"]: row["rights_mask"]
        for row in conn.execute("SELECT name, rights_mask FROM sandboxes")
    }

    tags = {}
    for row in conn.execute(
        "SELECT handle_id, sandbox FROM handle_sandboxes ORDER BY handle_id, sandbox"
    ):
        tags.setdefault(row["handle_id"], []).append(row["sandbox"])

    handles = {}
    index = {}
    slot_max = {}
    slot_gens = {}
    rows = conn.execute(
        """
        SELECT h.*, p.handle_no AS parent_no, p.generation AS parent_gen,
               p.owner AS parent_owner
          FROM handles h
          LEFT JOIN handles p ON p.id = h.parent_handle_id
         ORDER BY h.id
        """
    ).fetchall()
    for r in rows:
        box_list = tags.get(r["id"], [])
        h = {
            "id": r["id"],
            "owner": r["owner"],
            "handle_no": r["handle_no"],
            "generation": r["generation"],
            "parent_id": r["parent_handle_id"],
            "parent_no": r["parent_no"],
            "parent_gen": r["parent_gen"],
            "parent_owner": r["parent_owner"],
            "resource": r["resource"],
            "resource_gen": r["resource_gen"],
            "rights_mask": r["rights_mask"],
            "session_gen": r["session_gen"],
            "not_before": r["not_before"],
            "not_after": r["not_after"],
            "created_ms": r["created_ms"],
            "revoked_ms": r["revoked_ms"],
            # Membership is a name; the mask is resolved live so a later
            # sandbox tightening applies to already-issued handles.
            "sandboxes": {name: sandboxes.get(name, 0) for name in box_list},
        }
        handles[h["id"]] = h
        index[(h["owner"], h["handle_no"], h["generation"])] = h
        key = (h["owner"], h["handle_no"])
        slot_max[key] = max(slot_max.get(key, 0), h["generation"])
        slot_gens.setdefault(key, []).append(h["generation"])
    for gens in slot_gens.values():
        gens.sort()

    return capability.World(
        clock=clock,
        processes=processes,
        resources=resources,
        sandboxes=sandboxes,
        handles=handles,
        index=index,
        slot_max=slot_max,
        slot_gens=slot_gens,
    )


def _blk_summary(blocker):
    if blocker is None:
        return None
    out = {
        "reason": blocker["reason"],
        "code": blocker["code"],
        "hop": blocker.get("hop"),
        "owner": blocker.get("owner"),
        "handle": blocker.get("handle"),
        "generation": blocker.get("generation"),
    }
    for key in ("sandbox", "resource", "method", "handle_id"):
        if key in blocker:
            out[key] = blocker[key]
    return out


def _sort_failures(failures):
    failures.sort(
        key=lambda f: (
            f.get("hop", 0),
            capability.REASON_RANK.get(f["reason"], 99),
            f.get("sandbox", ""),
            f.get("handle_id") or 0,
        )
    )
    return failures


class Engine:
    """Owns one SQLite connection and executes steps on it."""

    def __init__(self, db_path: str, allow_faults: bool = False):
        self.path = db_path
        self.allow_faults = (
            allow_faults or os.environ.get("SANDBOX_ALLOW_FAULTS") == "1"
        )
        self.conn = connect(db_path)
        self.case_id = None
        self.step_index = 0
        self._op_name = None

    # -- lifecycle ---------------------------------------------------------
    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    # -- transactions ------------------------------------------------------
    def _begin(self):
        self.conn.execute("BEGIN IMMEDIATE")

    def _commit(self):
        self.conn.execute("COMMIT")

    def _rollback(self):
        try:
            self.conn.execute("ROLLBACK")
        except Exception:
            pass

    def _txn(self, fn):
        self._begin()
        try:
            out = fn()
            self._commit()
            return out
        except BaseException:
            self._rollback()
            raise

    def _read_txn(self, fn):
        """Run ``fn`` in a deferred read transaction.

        On WAL this pins one snapshot for the whole callback, so a multi-query
        read can never observe a commit halfway through.  It also does not take
        the write lock, which is what lets readers keep running while a writer
        commits.
        """
        self.conn.execute("BEGIN")
        try:
            out = fn()
            self.conn.execute("COMMIT")
            return out
        except BaseException:
            self._rollback()
            raise

    # -- dispatch ----------------------------------------------------------
    def run_step(self, step, case_id=None, step_index=0):
        self.case_id = case_id
        self.step_index = step_index
        if not isinstance(step, dict):
            raise EngineError(E_INVALID_REQUEST, "step must be an object")
        op = step.get("op")
        if not isinstance(op, str) or op not in self.HANDLERS:
            raise EngineError(
                E_UNKNOWN_OP, f"unknown op {op!r}", {"known": sorted(self.HANDLERS)}
            )
        self._op_name = op
        return self.HANDLERS[op](self, step)

    # =====================================================================
    # clock and state ops
    # =====================================================================
    def op_set_clock(self, step):
        now = require_int(step, "now_ms")

        def run():
            current = read_clock(self.conn)
            if now < current:
                raise EngineError(
                    E_TIME_REGRESSION,
                    "clock must not move backwards",
                    {"current": current, "requested": now},
                )
            self.conn.execute("UPDATE clock SET now_ms=? WHERE id=1", (now,))
            return {"status": "ok", "code": OK, "now_ms": now}

        return self._txn(run)

    def op_create_process(self, step):
        name = require_str(step, "process")

        def run():
            existing = self.conn.execute(
                "SELECT generation FROM processes WHERE name=?", (name,)
            ).fetchone()
            if existing is not None:
                raise EngineError(
                    E_ALREADY_EXISTS,
                    f"process {name!r} already exists",
                    {"generation": existing["generation"]},
                )
            self.conn.execute(
                "INSERT INTO processes(name, generation, alive, created_ms)"
                " VALUES(?, 1, 1, ?)",
                (name, read_clock(self.conn)),
            )
            return {
                "status": "ok",
                "code": OK,
                "process": name,
                "generation": 1,
                "alive": True,
            }

        return self._txn(run)

    def op_restart_process(self, step):
        name = require_str(step, "process")

        def run():
            row = self.conn.execute(
                "SELECT generation FROM processes WHERE name=?", (name,)
            ).fetchone()
            if row is None:
                raise EngineError(E_PROCESS_NOT_FOUND, f"unknown process {name!r}")
            gen = row["generation"] + 1
            self.conn.execute(
                "UPDATE processes SET generation=?, alive=1, restarted_ms=?"
                " WHERE name=?",
                (gen, read_clock(self.conn), name),
            )
            return {
                "status": "ok",
                "code": OK,
                "process": name,
                "generation": gen,
                "alive": True,
                "session_generation": gen,
            }

        return self._txn(run)

    def op_create_resource(self, step):
        name = require_str(step, "resource")
        tenant = require_str(step, "tenant")
        rights = methods_to_mask(step.get("rights", list(METHODS)), "rights")

        def run():
            if self.conn.execute(
                "SELECT 1 FROM resources WHERE name=?", (name,)
            ).fetchone():
                raise EngineError(
                    E_ALREADY_EXISTS, f"resource {name!r} already exists"
                )
            self.conn.execute(
                "INSERT INTO resources(name, tenant, generation, rights_mask)"
                " VALUES(?, ?, 1, ?)",
                (name, tenant, rights),
            )
            return {
                "status": "ok",
                "code": OK,
                "resource": name,
                "tenant": tenant,
                "generation": 1,
                "rights": mask_to_methods(rights),
            }

        return self._txn(run)

    def op_rebuild_resource(self, step):
        name = require_str(step, "resource")

        def run():
            row = self.conn.execute(
                "SELECT generation FROM resources WHERE name=?", (name,)
            ).fetchone()
            if row is None:
                raise EngineError(E_RESOURCE_NOT_FOUND, f"unknown resource {name!r}")
            gen = row["generation"] + 1
            self.conn.execute(
                "UPDATE resources SET generation=?, rebuilds=rebuilds+1 WHERE name=?",
                (gen, name),
            )
            return {
                "status": "ok",
                "code": OK,
                "resource": name,
                "generation": gen,
                "previous_generation": row["generation"],
            }

        return self._txn(run)

    def op_create_sandbox(self, step):
        name = require_str(step, "sandbox")
        rights = methods_to_mask(step.get("rights"), "rights")
        def run():
            if self.conn.execute(
                "SELECT 1 FROM sandboxes WHERE name=?", (name,)
            ).fetchone():
                raise EngineError(
                    E_ALREADY_EXISTS, f"sandbox {name!r} already exists"
                )
            now = read_clock(self.conn)
            self.conn.execute(
                "INSERT INTO sandboxes(name, rights_mask, created_ms, updated_ms)"
                " VALUES(?, ?, ?, ?)",
                (name, rights, now, now),
            )
            return {
                "status": "ok",
                "code": OK,
                "sandbox": name,
                "rights": mask_to_methods(rights),
            }

        return self._txn(run)

    def op_tighten_sandbox(self, step):
        name = require_str(step, "sandbox")
        # A sandbox may be tightened all the way down to "allows nothing";
        # that is the strongest possible rule, not an invalid request.
        rights = methods_to_mask(step.get("rights"), "rights", allow_empty=True)

        def run():
            row = self.conn.execute(
                "SELECT rights_mask FROM sandboxes WHERE name=?", (name,)
            ).fetchone()
            if row is None:
                raise EngineError(E_SANDBOX_NOT_FOUND, f"unknown sandbox {name!r}")
            old = row["rights_mask"]
            if rights & ~old or rights == old:
                raise EngineError(
                    E_SANDBOX_NOT_NARROWING,
                    "tighten_sandbox must remove at least one right and add none",
                    {
                        "previous": mask_to_methods(old),
                        "requested": mask_to_methods(rights),
                    },
                )
            self.conn.execute(
                "UPDATE sandboxes SET rights_mask=?, updated_ms=?,"
                " updates=updates+1 WHERE name=?",
                (rights, read_clock(self.conn), name),
            )
            return {
                "status": "ok",
                "code": OK,
                "sandbox": name,
                "previous_rights": mask_to_methods(old),
                "rights": mask_to_methods(rights),
            }

        return self._txn(run)

    # =====================================================================
    # capability ops
    # =====================================================================
    def op_grant(self, step):
        process = require_str(step, "process")
        handle_no = require_int(step, "handle")
        resource = require_str(step, "resource")
        rights = methods_to_mask(step.get("rights"), "rights")
        requested_gen = optional_int(step, "generation")
        not_before = optional_int(step, "not_before")
        not_after = optional_int(step, "not_after")
        sandboxes = step.get("sandboxes", [])
        if not isinstance(sandboxes, list) or not all(
            isinstance(s, str) for s in sandboxes
        ):
            raise EngineError(E_INVALID_REQUEST, "sandboxes must be a list of names")
        sandboxes = sorted(set(sandboxes))

        def run():
            world = load_world(self.conn)
            proc = world.processes.get(process)
            if proc is None:
                raise EngineError(
                    E_PROCESS_NOT_FOUND, f"unknown process {process!r}"
                )
            if not proc["alive"]:
                raise EngineError(
                    E_PROCESS_DEAD,
                    f"process {process!r} is not alive",
                    {"generation": proc["generation"]},
                )
            resource_row = world.resources.get(resource)
            if resource_row is None:
                raise EngineError(
                    E_RESOURCE_NOT_FOUND, f"unknown resource {resource!r}"
                )
            if rights & ~resource_row["rights_mask"]:
                raise EngineError(
                    E_RESOURCE_METHOD_UNSUPPORTED,
                    "granted rights exceed what the resource supports",
                    {
                        "requested": mask_to_methods(rights),
                        "supported": mask_to_methods(resource_row["rights_mask"]),
                    },
                )
            for name in sandboxes:
                if name not in world.sandboxes:
                    raise EngineError(
                        E_SANDBOX_NOT_FOUND, f"unknown sandbox {name!r}"
                    )
            now = world.clock
            lo = now if not_before is None else not_before
            hi = (now + 86_400_000) if not_after is None else not_after
            if hi < lo:
                raise EngineError(E_INVALID_REQUEST, "not_after must be >= not_before")
            slot_key = (process, handle_no)
            max_gen = world.slot_max.get(slot_key, 0)
            gen = max_gen + 1
            if requested_gen is not None:
                if requested_gen <= max_gen:
                    raise EngineError(
                        E_GENERATION_CONFLICT,
                        "handle generation must be newer than every generation"
                        " already in the slot",
                        {"slot_max_generation": max_gen, "requested": requested_gen},
                    )
                gen = requested_gen
            cur = self.conn.execute(
                "INSERT INTO handles(owner, handle_no, generation, parent_handle_id,"
                " resource, resource_gen, rights_mask, session_gen, not_before,"
                " not_after, created_ms)"
                " VALUES(?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)",
                (
                    process,
                    handle_no,
                    gen,
                    resource,
                    resource_row["generation"],
                    rights,
                    proc["generation"],
                    lo,
                    hi,
                    now,
                ),
            )
            hid = cur.lastrowid
            for name in sandboxes:
                self.conn.execute(
                    "INSERT INTO handle_sandboxes(handle_id, sandbox) VALUES(?, ?)",
                    (hid, name),
                )
            out = {
                "status": "ok",
                "code": OK,
                "handle_id": hid,
                "process": process,
                "handle": handle_no,
                "generation": gen,
                "slot_max_generation": max_gen,
                "previous_generations": list(world.slot_gens.get(slot_key, [])),
                "resource": resource,
                "resource_generation": resource_row["generation"],
                "rights": mask_to_methods(rights),
                "session_generation": proc["generation"],
                "not_before": lo,
                "not_after": hi,
                "sandboxes": sandboxes,
            }
            self._audit_decision(out, allowed=True)
            return out

        return self._txn(run)

    def op_transfer(self, step):
        parent = require_dict(step, "parent", allow_none=False)
        to_process = require_str(step, "to_process")
        handle_no = require_int(step, "handle")
        rights_raw = step.get("rights")
        requested_gen = optional_int(step, "generation")
        not_before = optional_int(step, "not_before")
        not_after = optional_int(step, "not_after")
        extra_sandboxes = step.get("sandboxes", [])
        if not isinstance(extra_sandboxes, list) or not all(
            isinstance(s, str) for s in extra_sandboxes
        ):
            raise EngineError(E_INVALID_REQUEST, "sandboxes must be a list of names")
        parent_process = require_str(parent, "process")
        parent_no = require_int(parent, "handle")
        parent_gen = optional_int(parent, "generation")

        def run():
            world = load_world(self.conn)
            leaf = world.resolve(parent_process, parent_no, parent_gen)
            if leaf is None:
                raise EngineError(
                    E_HANDLE_NOT_FOUND,
                    "parent handle does not exist",
                    {
                        "process": parent_process,
                        "handle": parent_no,
                        "generation": parent_gen,
                    },
                )

            # Structural validity of the entire parent chain at transfer time:
            # exact generations present, sessions live, resource generations
            # matching, nothing revoked, nothing superseded.
            nodes, tail = chain_of(world, leaf)
            structural = []
            for hop, h in enumerate(nodes):
                structural.extend(
                    node_failures(
                        world,
                        h,
                        hop,
                        method=None,
                        resource_name=leaf["resource"],
                        tenant=None,
                        include_time=False,
                    )
                )
            if tail is not None:
                structural.append(tail)
            if structural:
                _sort_failures(structural)
                raise EngineError(
                    REASON_CODES.get(structural[0]["reason"], E_INTERNAL),
                    "parent chain is not usable: %s" % structural[0]["reason"],
                    {
                        "blocker": _blk_summary(structural[0]),
                        "failures": [_blk_summary(f) for f in structural],
                        "chain": [handle_digest(h) for h in nodes],
                    },
                )

            target = world.processes.get(to_process)
            if target is None:
                raise EngineError(
                    E_PROCESS_NOT_FOUND, f"unknown process {to_process!r}"
                )
            if not target["alive"]:
                raise EngineError(
                    E_PROCESS_DEAD, f"target process {to_process!r} is not alive"
                )
            resource_row = world.resources.get(leaf["resource"])
            if resource_row is None:
                raise EngineError(
                    E_RESOURCE_NOT_FOUND, f"unknown resource {leaf['resource']!r}"
                )

            parent_mask = capability.effective_mask(world, nodes)
            child_mask = (
                parent_mask
                if rights_raw is None
                else methods_to_mask(rights_raw, "rights")
            )
            if child_mask & ~parent_mask:
                raise EngineError(
                    E_RIGHTS_ESCALATION,
                    "transfer cannot add rights the parent chain does not hold",
                    {
                        "parent_effective": mask_to_methods(parent_mask),
                        "requested": mask_to_methods(child_mask),
                    },
                )
            if child_mask & ~resource_row["rights_mask"]:
                raise EngineError(
                    E_RESOURCE_METHOD_UNSUPPORTED,
                    "transferred rights exceed what the resource supports",
                )

            now = world.clock
            lo = leaf["not_before"] if not_before is None else not_before
            hi = leaf["not_after"] if not_after is None else not_after
            if lo < leaf["not_before"] or hi > leaf["not_after"]:
                raise EngineError(
                    E_WINDOW_ESCALATION,
                    "transfer window must be inside the parent window",
                    {
                        "parent_window": [leaf["not_before"], leaf["not_after"]],
                        "requested_window": [lo, hi],
                    },
                )
            if hi < lo:
                raise EngineError(
                    E_INVALID_REQUEST, "not_after must be >= not_before"
                )
            # A child may add sandbox tags but may never drop an inherited one.
            inherited = sorted(leaf["sandboxes"] or {})
            child_tags = sorted(set(inherited) | set(extra_sandboxes))
            for name in child_tags:
                if name not in world.sandboxes:
                    raise EngineError(
                        E_SANDBOX_NOT_FOUND, f"unknown sandbox {name!r}"
                    )

            slot_key = (to_process, handle_no)
            max_gen = world.slot_max.get(slot_key, 0)
            gen = max_gen + 1
            if requested_gen is not None:
                if requested_gen <= max_gen:
                    raise EngineError(
                        E_GENERATION_CONFLICT,
                        "handle generation must be newer than every generation"
                        " already in the slot",
                        {"slot_max_generation": max_gen, "requested": requested_gen},
                    )
                gen = requested_gen
            cur = self.conn.execute(
                "INSERT INTO handles(owner, handle_no, generation, parent_handle_id,"
                " resource, resource_gen, rights_mask, session_gen, not_before,"
                " not_after, created_ms)"
                " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    to_process,
                    handle_no,
                    gen,
                    leaf["id"],
                    leaf["resource"],
                    leaf["resource_gen"],
                    child_mask,
                    target["generation"],
                    lo,
                    hi,
                    now,
                ),
            )
            hid = cur.lastrowid
            for name in child_tags:
                self.conn.execute(
                    "INSERT INTO handle_sandboxes(handle_id, sandbox) VALUES(?, ?)",
                    (hid, name),
                )
            out = {
                "status": "ok",
                "code": OK,
                "handle_id": hid,
                "process": to_process,
                "handle": handle_no,
                "generation": gen,
                "slot_max_generation": max_gen,
                "previous_generations": list(world.slot_gens.get(slot_key, [])),
                "parent": {
                    "handle_id": leaf["id"],
                    "owner": leaf["owner"],
                    "handle": leaf["handle_no"],
                    "generation": leaf["generation"],
                },
                "resource": leaf["resource"],
                "resource_generation": leaf["resource_gen"],
                "rights": mask_to_methods(child_mask),
                "parent_effective_rights": mask_to_methods(parent_mask),
                "session_generation": target["generation"],
                "not_before": lo,
                "not_after": hi,
                "sandboxes": child_tags,
                "chain_depth": len(nodes) + 1,
            }
            self._audit_decision(out, allowed=True)
            return out

        return self._txn(run)

    def op_revoke(self, step):
        process = require_str(step, "process")
        handle_no = require_int(step, "handle")
        gen = optional_int(step, "generation")

        def run():
            world = load_world(self.conn)
            h = world.resolve(process, handle_no, gen)
            if h is None:
                raise EngineError(
                    E_HANDLE_NOT_FOUND,
                    "handle does not exist",
                    {"process": process, "handle": handle_no, "generation": gen},
                )
            if h["revoked_ms"] is not None:
                return {
                    "status": "ok",
                    "code": OK,
                    "already_revoked": True,
                    "handle_id": h["id"],
                    "process": process,
                    "handle": handle_no,
                    "generation": h["generation"],
                    "revoked_ms": h["revoked_ms"],
                    "descendants_now_blocked": self._descendants(h["id"]),
                }
            now = world.clock
            self.conn.execute(
                "UPDATE handles SET revoked_ms=? WHERE id=?", (now, h["id"])
            )
            return {
                "status": "ok",
                "code": OK,
                "already_revoked": False,
                "handle_id": h["id"],
                "process": process,
                "handle": handle_no,
                "generation": h["generation"],
                "revoked_ms": now,
                # Deliberately not cascaded in storage: descendants are
                # invalidated by the chain walk, which is what preserves the
                # exact blocking-ancestor generation in the report.
                "descendants_now_blocked": self._descendants(h["id"]),
            }

        return self._txn(run)

    def _descendants(self, handle_id):
        out = []
        frontier = [handle_id]
        while frontier:
            marks = ",".join("?" * len(frontier))
            rows = self.conn.execute(
                "SELECT id, owner, handle_no, generation FROM handles"
                " WHERE parent_handle_id IN (%s) ORDER BY id" % marks,
                frontier,
            ).fetchall()
            frontier = []
            for r in rows:
                out.append(
                    {
                        "handle_id": r["id"],
                        "owner": r["owner"],
                        "handle": r["handle_no"],
                        "generation": r["generation"],
                    }
                )
                frontier.append(r["id"])
        return out

    # =====================================================================
    # read-only capability ops
    # =====================================================================
    def op_handle_info(self, step):
        process = require_str(step, "process")
        handle_no = require_int(step, "handle")
        gen = optional_int(step, "generation")

        def run():
            world = load_world(self.conn)
            h = world.resolve(process, handle_no, gen)
            if h is None:
                raise EngineError(
                    E_HANDLE_NOT_FOUND,
                    "handle does not exist",
                    {"process": process, "handle": handle_no, "generation": gen},
                )
            nodes, tail = chain_of(world, h)
            failures = []
            for hop, node in enumerate(nodes):
                failures.extend(
                    node_failures(
                        world,
                        node,
                        hop,
                        method=None,
                        resource_name=None,
                        tenant=None,
                        include_time=True,
                    )
                )
            if tail is not None:
                failures.append(tail)
            _sort_failures(failures)
            return {
                "status": "ok",
                "code": OK,
                "handle": handle_digest(h),
                "chain": [handle_digest(n) for n in nodes],
                "chain_depth": len(nodes),
                "structurally_valid": not failures,
                "failures": failures,
                "blocker": failures[0] if failures else None,
                "blocking_ancestor": next(
                    (f for f in failures if f.get("hop", 0) >= 1), None
                ),
                "effective_rights": mask_to_methods(
                    capability.effective_mask(world, nodes)
                ),
            }

        return self._read_txn(run)

    def op_list_slot(self, step):
        process = require_str(step, "process")
        handle_no = require_int(step, "handle")

        def run():
            world = load_world(self.conn)
            gens = world.slot_gens.get((process, handle_no), [])
            newest = gens[-1] if gens else None
            rows = self.conn.execute(
                "SELECT * FROM handles WHERE owner=? AND handle_no=?"
                " ORDER BY generation",
                (process, handle_no),
            ).fetchall()
            items = []
            for r in rows:
                items.append(
                    {
                        "handle_id": r["id"],
                        "generation": r["generation"],
                        "latest": r["generation"] == newest,
                        "superseded": r["generation"] < newest,
                        "resource": r["resource"],
                        "resource_generation": r["resource_gen"],
                        "rights": mask_to_methods(r["rights_mask"]),
                        "session_generation": r["session_gen"],
                        "revoked": r["revoked_ms"] is not None,
                        "parent_handle_id": r["parent_handle_id"],
                        "window": [r["not_before"], r["not_after"]],
                    }
                )
            return {
                "status": "ok",
                "code": OK,
                "process": process,
                "handle": handle_no,
                "generation_count": len(items),
                "slot_max_generation": newest,
                "generations": items,
            }

        return self._read_txn(run)

    def op_check(self, step):
        process = require_str(step, "process")
        handle_no = require_int(step, "handle")
        gen = optional_int(step, "generation")
        method = require_str(step, "method")
        if method not in METHOD_BITS:
            raise EngineError(
                E_INVALID_REQUEST,
                f"unknown method {method!r}",
                {"allowed": list(METHODS)},
            )
        resource = step.get("resource")
        tenant = step.get("tenant")
        if resource is not None and not isinstance(resource, str):
            raise EngineError(E_INVALID_REQUEST, "resource must be a string")
        if tenant is not None and not isinstance(tenant, str):
            raise EngineError(E_INVALID_REQUEST, "tenant must be a string")

        def run():
            world = load_world(self.conn)
            leaf = world.resolve(process, handle_no, gen)
            target_resource = resource
            if target_resource is None and leaf is not None:
                target_resource = leaf["resource"]
            # An unknown handle with no explicit resource is still a capability
            # answer (HANDLE_NOT_FOUND), not a request-level error: callers
            # need the negative decision to be auditable.
            ev = evaluate(
                world, process, handle_no, gen, target_resource, method, tenant
            )
            out = {
                "status": "ok" if ev["allowed"] else "denied",
                "code": OK if ev["allowed"] else ev["blocker"]["code"],
                "decision": "allow" if ev["allowed"] else "deny",
                "subject": {
                    "owner": process,
                    "handle": handle_no,
                    "generation": gen,
                    "resolved_generation": (
                        ev["chain"][0]["generation"] if ev["chain"] else None
                    ),
                    "handle_id": ev["chain"][0]["id"] if ev["chain"] else None,
                    "resource": target_resource,
                    "method": method,
                },
                "clock": world.clock,
                "effective_rights": ev["effective_rights"],
                "chain": [handle_digest(h) for h in ev["chain"]],
                "chain_depth": len(ev["chain"]),
                "blocker": ev["blocker"],
                "blocking_ancestor": ev["blocking_ancestor"],
                "failures": ev["failures"],
            }
            self._audit_decision(
                out,
                allowed=ev["allowed"],
                subject=handle_ref(process, handle_no, gen),
                blocker=ev["blocker"],
                ancestor=ev["blocking_ancestor"],
            )
            return out

        return self._txn(run)

    # =====================================================================
    # precheck snapshots
    # =====================================================================
    def op_precheck(self, step):
        process = require_str(step, "process")
        handle_no = require_int(step, "handle")
        gen = optional_int(step, "generation")
        method = require_str(step, "method")
        if method not in METHOD_BITS:
            raise EngineError(
                E_INVALID_REQUEST,
                f"unknown method {method!r}",
                {"allowed": list(METHODS)},
            )
        resource = step.get("resource")
        ttl = optional_int(step, "ttl_ms")
        ttl = 60_000 if ttl is None else ttl
        if ttl < 0:
            raise EngineError(E_INVALID_REQUEST, "ttl_ms must be >= 0")

        def run():
            world = load_world(self.conn)
            leaf = world.resolve(process, handle_no, gen)
            if leaf is None:
                raise EngineError(
                    E_HANDLE_NOT_FOUND,
                    "handle does not exist",
                    {"process": process, "handle": handle_no, "generation": gen},
                )
            target_resource = resource or leaf["resource"]
            ev = evaluate(world, process, handle_no, gen, target_resource, method)
            if not ev["allowed"]:
                out = {
                    "status": "denied",
                    "code": ev["blocker"]["code"],
                    "decision": "deny",
                    "precheck": None,
                    "blocker": ev["blocker"],
                    "blocking_ancestor": ev["blocking_ancestor"],
                    "failures": ev["failures"],
                    "chain": [handle_digest(h) for h in ev["chain"]],
                }
                self._audit_decision(
                    out,
                    allowed=False,
                    subject=handle_ref(process, handle_no, gen),
                    blocker=ev["blocker"],
                    ancestor=ev["blocking_ancestor"],
                )
                return out

            seq = next_counter(self.conn, "precheck_seq")
            # Tokens are a pure function of the per-database sequence, which
            # keeps result.json byte-stable across replays and lets cases.json
            # name a token it issued earlier.
            token = "P%04d" % seq
            now = world.clock
            expires_at = now + ttl
            chain_snapshot = [
                {
                    "handle_id": h["id"],
                    "owner": h["owner"],
                    "handle": h["handle_no"],
                    "generation": h["generation"],
                    "resource": h["resource"],
                    "resource_generation": h["resource_gen"],
                    "session_generation": h["session_gen"],
                    "rights": mask_to_methods(h["rights_mask"]),
                    "window": [h["not_before"], h["not_after"]],
                    "sandboxes": sorted(h["sandboxes"] or {}),
                }
                for h in ev["chain"]
            ]
            leaf_snap = chain_snapshot[0]
            item = {
                "process": process,
                "handle": handle_no,
                "generation": leaf_snap["generation"],
                "handle_id": leaf_snap["handle_id"],
                "method": method,
                "resource": target_resource,
            }
            snapshot = {
                "token": token,
                "issue_seq": seq,
                "clock": now,
                "process": process,
                "resource": target_resource,
                "method": method,
                "chain": chain_snapshot,
                "process_generation": world.processes[process]["generation"],
                "resource_generation": world.resources[target_resource]["generation"],
            }
            self.conn.execute(
                "INSERT INTO prechecks(token, process, item_json, snapshot_json,"
                " expires_at, observed_clock_ms, created_ms)"
                " VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    token,
                    process,
                    canonical(item),
                    canonical(snapshot),
                    expires_at,
                    now,
                    now,
                ),
            )
            out = {
                "status": "ok",
                "code": OK,
                "decision": "allow",
                "precheck": token,
                "issued_at_ms": now,
                "expires_at_ms": expires_at,
                "method": method,
                "resource": target_resource,
                "item": item,
                "chain": [handle_digest(h) for h in ev["chain"]],
                "chain_ids": [h["id"] for h in ev["chain"]],
                "blocker": None,
                "blocking_ancestor": None,
            }
            self._audit_decision(
                out, allowed=True, subject=handle_ref(process, handle_no, gen)
            )
            return out

        return self._txn(run)

    # =====================================================================
    # protected multi-resource operation
    # =====================================================================
    def op_protected_io(self, step):
        op_id = require_str(step, "op_id")
        mode = step.get("mode", MODE_ALL_OR_NOTHING)
        if mode not in ALLOWED_MODES:
            raise EngineError(
                E_INVALID_REQUEST,
                f"unknown mode {mode!r}",
                {"allowed": sorted(ALLOWED_MODES)},
            )
        process = require_str(step, "process")
        raw_items = step.get("items")
        if not isinstance(raw_items, list) or not raw_items:
            raise EngineError(E_INVALID_REQUEST, "items must be a non-empty list")
        fault = step.get("fault")
        if fault is not None:
            if fault not in ALLOWED_FAULTS:
                raise EngineError(
                    E_INVALID_REQUEST,
                    f"unknown fault {fault!r}",
                    {"allowed": sorted(ALLOWED_FAULTS)},
                )
            if not self.allow_faults:
                raise EngineError(
                    E_FAULT_NOT_ALLOWED,
                    "fault injection is disabled; run with --allow-faults or"
                    " SANDBOX_ALLOW_FAULTS=1",
                )
        items = [self._parse_io_item(i, raw) for i, raw in enumerate(raw_items)]
        return self._protected_io_run(op_id, mode, process, items, fault)

    def _parse_io_item(self, index, raw):
        if not isinstance(raw, dict):
            raise EngineError(E_INVALID_REQUEST, f"items[{index}] must be an object")
        handle_no = require_int(raw, "handle")
        gen = optional_int(raw, "generation")
        method = require_str(raw, "method")
        if method not in METHOD_BITS:
            raise EngineError(E_INVALID_REQUEST, f"items[{index}].method is invalid")
        resource = raw.get("resource")
        if resource is not None and not isinstance(resource, str):
            raise EngineError(E_INVALID_REQUEST, f"items[{index}].resource invalid")
        precheck = raw.get("precheck")
        if precheck is not None and not isinstance(precheck, str):
            raise EngineError(
                E_INVALID_REQUEST, f"items[{index}].precheck must be a token"
            )
        return {
            "index": index,
            "handle": handle_no,
            "generation": gen,
            "method": method,
            "resource": resource,
            "payload": raw.get("payload"),
            "precheck": precheck,
            "tenant": raw.get("tenant"),
        }

    def _protected_io_run(self, op_id, mode, process, items, fault):
        self._begin()
        try:
            existing = self.conn.execute(
                "SELECT * FROM transactions WHERE op_id=? AND state IN"
                " ('committed','denied') ORDER BY started_ms DESC, rowid DESC"
                " LIMIT 1",
                (op_id,),
            ).fetchone()
            if existing is not None:
                replay = self._replay(existing, process, mode, items)
                self._commit()
                return replay

            world = load_world(self.conn)
            results, blockers = self._evaluate_items(world, process, items)
            all_allowed = not blockers
            txn_seq = next_counter(self.conn, "txn_seq")
            txn_id = "T%04d" % txn_seq
            started_ms = world.clock

            if mode == MODE_ALL_OR_NOTHING and not all_allowed:
                result = self._denied_payload(
                    op_id, txn_id, mode, process, blockers, results, items
                )
                self._store_txn(
                    txn_id=txn_id,
                    op_id=op_id,
                    mode=mode,
                    state="denied",
                    item_count=len(items),
                    result=result,
                    started_ms=started_ms,
                    finished_ms=world.clock,
                    blockers=blockers,
                    fault=fault,
                )
                self._audit_results(op_id, process, results)
                self._commit()
                return result

            to_write = results if all_allowed else [
                r for r in results if r["allowed"]
            ]
            written = []
            for seq, r in enumerate(to_write, start=1):
                cur = self.conn.execute(
                    "INSERT INTO io_log(txn_id, op_id, seq, item_index, handle_id,"
                    " handle_no, handle_gen, resource, method, payload_json,"
                    " created_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        txn_id,
                        op_id,
                        seq,
                        r["item_index"],
                        r["handle_id"],
                        r["handle"],
                        r["resolved_generation"],
                        r["resource"],
                        r["method"],
                        canonical(r["payload"]),
                        world.clock,
                    ),
                )
                written.append(
                    {
                        "io_id": cur.lastrowid,
                        "seq": seq,
                        "item_index": r["item_index"],
                        "handle": r["handle"],
                        "generation": r["resolved_generation"],
                        "resource": r["resource"],
                        "method": r["method"],
                    }
                )

            if fault == FAULT_IO_UNCOMMITTED:
                # Rows are in the WAL; die before COMMIT so SQLite recovery
                # discards them and no Python cleanup can run.
                os._exit(70)

            receipt = None
            if all_allowed:
                receipt = self._write_receipt(
                    txn_id, op_id, mode, process, results, written
                )

            for r in results:
                if r["allowed"] and r["precheck"] is not None:
                    self.conn.execute(
                        "UPDATE prechecks SET used_ms=?, used_by_op=?"
                        " WHERE token=? AND used_ms IS NULL",
                        (world.clock, op_id, r["precheck"]),
                    )

            result = {
                "status": "ok" if all_allowed else "partial",
                "code": OK if all_allowed else blockers[0]["code"],
                "op_id": op_id,
                "txn_id": txn_id,
                "mode": mode,
                "process": process,
                "decision": "allow" if all_allowed else "deny",
                "all_allowed": all_allowed,
                "item_count": len(items),
                "allowed_count": sum(1 for r in results if r["allowed"]),
                "items": [_public_item(r) for r in results],
                "blockers": blockers,
                "io_written": written,
                "receipt": receipt,
                "receipt_written": receipt is not None,
                "clock": world.clock,
                "request_digest": self._request_digest(process, mode, items),
                "replayed": False,
            }
            self._store_txn(
                txn_id=txn_id,
                op_id=op_id,
                mode=mode,
                state="committed",
                item_count=len(items),
                result=result,
                started_ms=started_ms,
                finished_ms=world.clock,
                blockers=blockers or None,
                fault=fault,
            )
            self._audit_results(op_id, process, results)
            self._commit()

            if fault == FAULT_COMMITTED_UNACKED:
                # Commit is durable; the caller never learns the answer.
                os._exit(71)
            return result
        except BaseException:
            self._rollback()
            raise

    # -- protected_io helpers ---------------------------------------------
    @staticmethod
    def _request_digest(process, mode, items):
        return sha256_hex(
            {
                "process": process,
                "mode": mode,
                "items": [
                    {
                        "handle": item["handle"],
                        "generation": item["generation"],
                        "method": item["method"],
                        "resource": item["resource"],
                        "precheck": item["precheck"],
                        "payload": item["payload"],
                        "tenant": item["tenant"],
                    }
                    for item in items
                ],
            }
        )

    def _replay(self, row, process, mode, items):
        result = json.loads(row["result_json"])
        replay = dict(result)
        replay["replayed"] = True
        replay["replay_of_state"] = row["state"]
        replay["replay_txn_id"] = row["txn_id"]
        replay["replayed_at_ms"] = read_clock(self.conn)
        digest = self._request_digest(process, mode, items)
        replay["request_digest"] = digest
        # A different payload reusing the same consumption id is answered from
        # the original commit, and the mismatch is reported, never recomputed.
        replay["replay_mismatch"] = result.get("request_digest") != digest
        self.conn.execute(
            "INSERT INTO decisions(case_id, step_index, op, subject_json, allowed,"
            " code, clock_ms) VALUES(?,?,?,?,?,?,?)",
            (
                self.case_id,
                self.step_index,
                "protected_io_replay",
                canonical({"op_id": row["op_id"], "txn_id": row["txn_id"]}),
                1 if row["state"] == "committed" else 0,
                result.get("code"),
                read_clock(self.conn),
            ),
        )
        return replay

    def _lookup_precheck(self, token, item, process):
        row = self.conn.execute(
            "SELECT * FROM prechecks WHERE token=?", (token,)
        ).fetchone()
        if row is None:
            return None, {
                "reason": "PRECHECK_NOT_FOUND",
                "code": E_PRECHECK_NOT_FOUND,
                "hop": 0,
                "detail": {"token": token},
            }
        if row["used_ms"] is not None:
            return None, {
                "reason": "PRECHECK_USED",
                "code": E_PRECHECK_USED,
                "hop": 0,
                "detail": {"token": token, "used_by_op": row["used_by_op"]},
            }
        stored = json.loads(row["item_json"])
        mismatch = (
            stored["process"] != process
            or stored["handle"] != item["handle"]
            or stored["method"] != item["method"]
            or (
                item["generation"] is not None
                and stored["generation"] != item["generation"]
            )
            or (
                item["resource"] is not None
                and stored["resource"] != item["resource"]
            )
        )
        if mismatch:
            return None, {
                "reason": "PRECHECK_MODE_MISMATCH",
                "code": E_PRECHECK_MODE_MISMATCH,
                "hop": 0,
                "detail": {"stored": stored, "requested": {
                    "process": process,
                    "handle": item["handle"],
                    "generation": item["generation"],
                    "method": item["method"],
                    "resource": item["resource"],
                }},
            }
        return row, None

    def _recheck_precheck(self, row, world):
        """Re-read the whole ancestor chain against the snapshot, right now.

        Every hop is re-verified for: exact identity (no replacement), rights,
        resource generation, session generation, authorization window, sandbox
        membership and liveness.  The snapshot itself is only a claim; nothing
        in it is trusted as an authorization.
        """
        snapshot = json.loads(row["snapshot_json"])
        issues = []
        if world.clock > row["expires_at"]:
            issues.append(
                {
                    "reason": "PRECHECK_EXPIRED",
                    "code": E_PRECHECK_EXPIRED,
                    "hop": 0,
                    "owner": snapshot["process"],
                    "handle": snapshot["chain"][0]["handle"],
                    "generation": snapshot["chain"][0]["generation"],
                    "detail": {
                        "expires_at": row["expires_at"],
                        "clock": world.clock,
                    },
                }
            )
        leaf = world.handles.get(snapshot["chain"][0]["handle_id"])
        if leaf is None:
            issues.append(
                {
                    "reason": "PRE_CHECKED_HANDLE_MISSING",
                    "code": E_PRECHECK_STALE,
                    "hop": 0,
                    "detail": {
                        "expected_ids": [n["handle_id"] for n in snapshot["chain"]],
                        "live_ids": [],
                    },
                }
            )
            return issues, None
        same, diff = capability.chain_matches_snapshot(
            world, leaf, snapshot["chain"]
        )
        if not same:
            issues.append(
                {
                    "reason": "CHAIN_CHANGED",
                    "code": E_PRECHECK_STALE,
                    "hop": 0,
                    "owner": leaf["owner"],
                    "handle": leaf["handle_no"],
                    "generation": leaf["generation"],
                    "detail": diff,
                }
            )
        # The live authorization failures are produced by the caller's own
        # evaluate() on the same world, so they are not duplicated here.  What
        # this method adds is integrity evidence: the chain still matches, the
        # token is fresh, and a per-hop report proving each ancestor was
        # re-read at the current clock.
        ev = evaluate(
            world,
            snapshot["process"],
            snapshot["chain"][0]["handle"],
            snapshot["chain"][0]["generation"],
            snapshot["resource"],
            snapshot["method"],
        )
        report = capability.recheck_report(
            world,
            ev["chain"],
            snapshot["method"],
            snapshot["resource"],
            world.clock,
        )
        _sort_failures(issues)
        return issues, report

    def _evaluate_items(self, world, process, items):
        results = []
        blockers = []
        for item in items:
            precheck_row = None
            issue = None
            if item["precheck"] is not None:
                precheck_row, issue = self._lookup_precheck(
                    item["precheck"], item, process
                )
            pinned_generation = item["generation"]
            target_resource = item["resource"]
            if precheck_row is not None:
                snap = json.loads(precheck_row["snapshot_json"])
                # A precheck pins the exact authorized generation; a newer
                # generation in the same slot must not stand in for it.
                pinned_generation = snap["chain"][0]["generation"]
                target_resource = snap["resource"]
            leaf = world.resolve(process, item["handle"], pinned_generation)
            if target_resource is None and leaf is not None:
                target_resource = leaf["resource"]

            if target_resource is None:
                missing = {
                    "reason": "HANDLE_NOT_FOUND",
                    "code": E_HANDLE_NOT_FOUND,
                    "hop": 0,
                    "owner": process,
                    "handle": item["handle"],
                    "generation": None,
                    "requested_generation": item["generation"],
                }
                ev = {
                    "allowed": False,
                    "blocker": missing,
                    "blocking_ancestor": None,
                    # The synthetic failure must be in ``failures`` too, or the
                    # item would be treated as allowed and written.
                    "failures": [missing],
                    "chain": [],
                    "effective_rights": [],
                }
            else:
                ev = evaluate(
                    world,
                    process,
                    item["handle"],
                    pinned_generation,
                    target_resource,
                    item["method"],
                    item["tenant"],
                )

            recheck = None
            denials = []
            if issue is not None:
                denials.append(issue)
            if item["precheck"] is not None and precheck_row is not None:
                recheck_issues, recheck = self._recheck_precheck(
                    precheck_row, world
                )
                if recheck_issues:
                    ev = dict(ev)
                    ev["allowed"] = False
                    ev["failures"] = list(ev["failures"]) + recheck_issues
            if not ev["allowed"]:
                denials.extend(ev["failures"])
            if denials:
                # Precheck integrity failures outrank ordinary capability
                # failures at the same hop: if the token is unusable, that is
                # the reason the operation was refused.
                denials.sort(
                    key=lambda f: (
                        0 if f["reason"].startswith("PRECHECK_") else 1,
                        f.get("hop", 0),
                        capability.REASON_RANK.get(
                            f["reason"].replace("RECHECK_", ""), 99
                        ),
                        f.get("sandbox", ""),
                    )
                )

            entry = {
                "item_index": item["index"],
                "handle": item["handle"],
                "generation": item["generation"],
                "resolved_generation": (
                    ev["chain"][0]["generation"] if ev["chain"] else None
                ),
                "handle_id": ev["chain"][0]["id"] if ev["chain"] else None,
                "resource": target_resource if target_resource else "<unknown>",
                "method": item["method"],
                "precheck": item["precheck"],
                "allowed": not denials,
                "blocker": denials[0] if denials else None,
                "blocking_ancestor": next(
                    (d for d in denials if d.get("hop", 0) >= 1), None
                ),
                "failures": denials,
                "chain": [handle_digest(h) for h in ev["chain"]],
                "effective_rights": ev["effective_rights"],
                "recheck": recheck,
                "payload": item["payload"],
            }
            if denials:
                first = denials[0]
                blockers.append(
                    {
                        "item_index": item["index"],
                        "handle": item["handle"],
                        "generation": item["generation"],
                        "resolved_generation": entry["resolved_generation"],
                        "reason": first["reason"],
                        "code": first["code"],
                        "hop": first.get("hop", 0),
                        "owner": first.get("owner"),
                        "blocking_handle": first.get("handle"),
                        "blocking_generation": first.get("generation"),
                        "blocking_ancestor": _blk_summary(
                            entry["blocking_ancestor"]
                        ),
                    }
                )
            results.append(entry)
        return results, blockers

    def _write_receipt(self, txn_id, op_id, mode, process, results, written):
        seq = next_counter(self.conn, "receipt_seq")
        body = {
            "receipt_seq": seq,
            "op_id": op_id,
            "txn_id": txn_id,
            "process": process,
            "mode": mode,
            "items": [
                {
                    "handle_id": r["handle_id"],
                    "handle": r["handle"],
                    "generation": r["resolved_generation"],
                    "resource": r["resource"],
                    "method": r["method"],
                    "precheck": r["precheck"],
                    "payload": r["payload"],
                }
                for r in results
            ],
            "io_seqs": [w["seq"] for w in written],
            "created_ms": read_clock(self.conn),
        }
        digest = sha256_hex(body)
        cur = self.conn.execute(
            "INSERT INTO receipts(txn_id, op_id, seq, receipt_json, receipt_sha256,"
            " created_ms) VALUES(?,?,?,?,?,?)",
            (txn_id, op_id, seq, canonical(body), digest, read_clock(self.conn)),
        )
        return {
            "receipt_id": cur.lastrowid,
            "receipt_seq": seq,
            "receipt_sha256": digest,
            "body": body,
        }

    def _denied_payload(self, op_id, txn_id, mode, process, blockers, results, items):
        return {
            "status": "denied",
            "code": blockers[0]["code"] if blockers else E_INTERNAL,
            "op_id": op_id,
            "txn_id": txn_id,
            "mode": mode,
            "process": process,
            "decision": "deny",
            "all_allowed": False,
            "item_count": len(results),
            "allowed_count": sum(1 for r in results if r["allowed"]),
            "items": [_public_item(r) for r in results],
            "blockers": blockers,
            "io_written": [],
            "receipt": None,
            "receipt_written": False,
            "clock": read_clock(self.conn),
            "request_digest": self._request_digest(process, mode, items),
            "replayed": False,
        }

    def _audit_results(self, op_id, process, results):
        for r in results:
            self._audit_decision(
                {"status": "ok" if r["allowed"] else "denied",
                 "code": OK if r["allowed"] else (r["blocker"] or {}).get("code")},
                allowed=r["allowed"],
                subject={
                    "op_id": op_id,
                    "item_index": r["item_index"],
                    "process": process,
                    "handle": r["handle"],
                    "generation": r["generation"],
                },
                blocker=r["blocker"],
                ancestor=r["blocking_ancestor"],
            )

    def _store_txn(
        self,
        txn_id,
        op_id,
        mode,
        state,
        item_count,
        result,
        started_ms,
        finished_ms,
        blockers=None,
        fault=None,
    ):
        self.conn.execute(
            "INSERT INTO transactions(txn_id, op_id, mode, state, item_count,"
            " abort_code, blocked_json, fault, result_json, started_ms,"
            " finished_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                txn_id,
                op_id,
                mode,
                state,
                item_count,
                None if state == "committed" else result.get("code"),
                None if not blockers else canonical(blockers),
                fault,
                canonical(result),
                started_ms,
                finished_ms,
            ),
        )

    # =====================================================================
    # audit / diagnostics ops
    # =====================================================================
    def _audit_decision(self, out, allowed, subject=None, blocker=None, ancestor=None):
        if blocker is None:
            blocker = out.get("blocker")
        if ancestor is None:
            ancestor = out.get("blocking_ancestor")
        self.conn.execute(
            "INSERT INTO decisions(case_id, step_index, op, subject_json, allowed,"
            " code, blocker_reason, blocker_hop, blocker_owner, blocker_handle,"
            " blocker_generation, ancestor_reason, ancestor_hop, ancestor_owner,"
            " ancestor_handle, ancestor_generation, clock_ms)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                self.case_id,
                self.step_index,
                self._op_name,
                canonical(subject or {}),
                1 if allowed else 0,
                out.get("code"),
                None if blocker is None else blocker.get("reason"),
                None if blocker is None else blocker.get("hop"),
                None if blocker is None else blocker.get("owner"),
                None if blocker is None else blocker.get("handle"),
                None if blocker is None else blocker.get("generation"),
                None if ancestor is None else ancestor.get("reason"),
                None if ancestor is None else ancestor.get("hop"),
                None if ancestor is None else ancestor.get("owner"),
                None if ancestor is None else ancestor.get("handle"),
                None if ancestor is None else ancestor.get("generation"),
                read_clock(self.conn),
            ),
        )

    def op_decision_log(self, step):
        limit = optional_int(step, "limit")

        def run():
            sql = (
                "SELECT id, case_id, step_index, op, subject_json, allowed, code,"
                " blocker_reason, blocker_hop, blocker_owner, blocker_handle,"
                " blocker_generation, ancestor_reason, ancestor_hop, ancestor_owner,"
                " ancestor_handle, ancestor_generation, clock_ms"
                " FROM decisions ORDER BY id"
            )
            params = ()
            if limit is not None:
                sql += " LIMIT ?"
                params = (limit,)
            entries = []
            for r in self.conn.execute(sql, params):
                entries.append(
                    {
                        "decision_id": r["id"],
                        "case_id": r["case_id"],
                        "step_index": r["step_index"],
                        "op": r["op"],
                        "subject": json.loads(r["subject_json"]),
                        "allowed": bool(r["allowed"]),
                        "code": r["code"],
                        "blocker": (
                            None
                            if r["blocker_reason"] is None
                            else {
                                "reason": r["blocker_reason"],
                                "hop": r["blocker_hop"],
                                "owner": r["blocker_owner"],
                                "handle": r["blocker_handle"],
                                "generation": r["blocker_generation"],
                            }
                        ),
                        "blocking_ancestor": (
                            None
                            if r["ancestor_reason"] is None
                            else {
                                "reason": r["ancestor_reason"],
                                "hop": r["ancestor_hop"],
                                "owner": r["ancestor_owner"],
                                "handle": r["ancestor_handle"],
                                "generation": r["ancestor_generation"],
                            }
                        ),
                        "clock_ms": r["clock_ms"],
                    }
                )
            return {
                "status": "ok",
                "code": OK,
                "count": len(entries),
                "decisions": entries,
            }

        return self._read_txn(run)

    def op_io_audit(self, step):
        op_id = step.get("op_id")

        def run():
            if op_id is None:
                rows = self.conn.execute(
                    "SELECT * FROM io_log ORDER BY id"
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM io_log WHERE op_id=? ORDER BY id", (op_id,)
                ).fetchall()
            io_entries = [
                {
                    "io_id": r["id"],
                    "txn_id": r["txn_id"],
                    "op_id": r["op_id"],
                    "seq": r["seq"],
                    "item_index": r["item_index"],
                    "handle_id": r["handle_id"],
                    "handle": r["handle_no"],
                    "generation": r["handle_gen"],
                    "resource": r["resource"],
                    "method": r["method"],
                    "payload": json.loads(r["payload_json"]),
                    "created_ms": r["created_ms"],
                }
                for r in rows
            ]
            txns = [
                {
                    "txn_id": r["txn_id"],
                    "op_id": r["op_id"],
                    "mode": r["mode"],
                    "state": r["state"],
                    "item_count": r["item_count"],
                    "abort_code": r["abort_code"],
                    "fault": r["fault"],
                    "started_ms": r["started_ms"],
                    "finished_ms": r["finished_ms"],
                }
                for r in self.conn.execute(
                    "SELECT * FROM transactions ORDER BY started_ms, rowid"
                )
            ]
            receipts = [
                {
                    "receipt_id": r["id"],
                    "txn_id": r["txn_id"],
                    "op_id": r["op_id"],
                    "receipt_seq": r["seq"],
                    "receipt_sha256": r["receipt_sha256"],
                    "body": json.loads(r["receipt_json"]),
                    "created_ms": r["created_ms"],
                }
                for r in self.conn.execute("SELECT * FROM receipts ORDER BY id")
            ]
            return {
                "status": "ok",
                "code": OK,
                "io_count": len(io_entries),
                "io": io_entries,
                "txn_count": len(txns),
                "transactions": txns,
                "receipt_count": len(receipts),
                "receipts": receipts,
            }

        return self._read_txn(run)

    def op_snapshot_stats(self, step):
        """All counts read inside one snapshot transaction.

        Used by the parallel-reader test: a reader that loops on this op while
        a writer commits multi-resource transactions must never see a receipt
        whose I/O rows are missing, nor a transaction in a non-final state.
        """

        def run():
            receipts = self.conn.execute(
                "SELECT COUNT(*) AS n FROM receipts"
            ).fetchone()["n"]
            txns = self.conn.execute(
                "SELECT COUNT(*) AS n FROM transactions"
            ).fetchone()["n"]
            committed = self.conn.execute(
                "SELECT COUNT(*) AS n FROM transactions WHERE state='committed'"
            ).fetchone()["n"]
            denied = self.conn.execute(
                "SELECT COUNT(*) AS n FROM transactions WHERE state='denied'"
            ).fetchone()["n"]
            io_rows = self.conn.execute(
                "SELECT COUNT(*) AS n FROM io_log"
            ).fetchone()["n"]
            orphan_receipts = self.conn.execute(
                "SELECT COUNT(*) AS n FROM receipts WHERE txn_id NOT IN"
                " (SELECT txn_id FROM io_log)"
            ).fetchone()["n"]
            return {
                "status": "ok",
                "code": OK,
                "clock": read_clock(self.conn),
                "receipts": receipts,
                "transactions": txns,
                "committed_transactions": committed,
                "denied_transactions": denied,
                "io_rows": io_rows,
                "orphan_receipts": orphan_receipts,
            }

        return self._read_txn(run)

    HANDLERS = {}


def _public_item(r):
    return {
        "item_index": r["item_index"],
        "handle": r["handle"],
        "generation": r["generation"],
        "resolved_generation": r["resolved_generation"],
        "handle_id": r["handle_id"],
        "resource": r["resource"],
        "method": r["method"],
        "precheck": r["precheck"],
        "allowed": r["allowed"],
        "code": OK if r["allowed"] else (r["blocker"] or {}).get("code"),
        "blocker": r["blocker"],
        "blocking_ancestor": r["blocking_ancestor"],
        "failures": r["failures"],
        "chain": r["chain"],
        "effective_rights": r["effective_rights"],
        "recheck": r["recheck"],
        "payload": r["payload"],
    }


Engine.HANDLERS = {
    "set_clock": Engine.op_set_clock,
    "create_process": Engine.op_create_process,
    "restart_process": Engine.op_restart_process,
    "create_resource": Engine.op_create_resource,
    "rebuild_resource": Engine.op_rebuild_resource,
    "create_sandbox": Engine.op_create_sandbox,
    "tighten_sandbox": Engine.op_tighten_sandbox,
    "grant": Engine.op_grant,
    "transfer": Engine.op_transfer,
    "revoke": Engine.op_revoke,
    "handle_info": Engine.op_handle_info,
    "list_slot": Engine.op_list_slot,
    "check": Engine.op_check,
    "precheck": Engine.op_precheck,
    "protected_io": Engine.op_protected_io,
    "decision_log": Engine.op_decision_log,
    "io_audit": Engine.op_io_audit,
    "snapshot_stats": Engine.op_snapshot_stats,
}
