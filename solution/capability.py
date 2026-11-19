"""Pure capability evaluation over a consistent world snapshot.

Nothing in this module writes to SQLite.  The engine loads a consistent
:class:`World` from the database and asks this module for a decision.  The
function is pure: identical worlds and queries always produce identical
results, which is what makes ``cases.json`` replayable.

Decision precedence
-------------------
The handle chain is walked from the leaf to the root.  Every hop is checked
for every failure (not just the first) so the report is complete.  Failures
are ordered by hop first, then by the fixed reason order below:

1.  ``HANDLE_SUPERSEDED``     - a newer generation exists in the same slot
2.  ``PROCESS_NOT_FOUND``
3.  ``PROCESS_DEAD``
4.  ``SESSION_GENERATION_MISMATCH``
5.  ``HANDLE_REVOKED``
6.  ``RESOURCE_NOT_FOUND``
7.  ``RESOURCE_GENERATION_MISMATCH``
8.  ``RESOURCE_MISMATCH``     - ancestor/leaf points at another resource
9.  ``NOT_YET_VALID``
10. ``EXPIRED``
11. ``METHOD_NOT_GRANTED`` (leaf) / ``ANCESTOR_MISSING_RIGHT`` (ancestor)
12. ``RESOURCE_METHOD_UNSUPPORTED`` (leaf)
13. ``TENANT_MISMATCH`` (leaf)
14. ``SANDBOX_DENIED``        - one entry per blocking sandbox tag

``blocker`` is the first failure after sorting by (hop, reason order), i.e.
the leaf's problem if the leaf has one.  ``blocking_ancestor`` is the first
failure at hop >= 1: exactly the ancestor that makes a descendant unusable,
reported with its exact generation and the field that failed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import REASON_CODES
from .util import METHOD_BITS, mask_to_methods

REASON_ORDER = (
    "HANDLE_SUPERSEDED",
    "PROCESS_NOT_FOUND",
    "PROCESS_DEAD",
    "SESSION_GENERATION_MISMATCH",
    "HANDLE_REVOKED",
    "RESOURCE_NOT_FOUND",
    "RESOURCE_GENERATION_MISMATCH",
    "RESOURCE_MISMATCH",
    "NOT_YET_VALID",
    "EXPIRED",
    "METHOD_NOT_GRANTED",
    "ANCESTOR_MISSING_RIGHT",
    "RESOURCE_METHOD_UNSUPPORTED",
    "TENANT_MISMATCH",
    "SANDBOX_DENIED",
    "PARENT_MISSING",
    "CYCLE_DETECTED",
)
REASON_RANK = {reason: i for i, reason in enumerate(REASON_ORDER)}


@dataclass(frozen=True)
class World:
    """Immutable view of all state that can affect a capability decision."""

    clock: int
    processes: dict  # name -> {"generation": int, "alive": bool}
    resources: dict  # name -> {"tenant": str, "generation": int, "rights_mask": int}
    sandboxes: dict  # name -> allowed mask
    handles: dict  # id -> handle dict
    index: dict  # (owner, handle_no, generation) -> handle dict
    slot_max: dict  # (owner, handle_no) -> highest generation
    slot_gens: dict  # (owner, handle_no) -> tuple of generations, ascending

    def resolve(self, process: str, handle_no: int, generation):
        """Resolve a reference; ``generation=None`` means the newest in slot."""
        if generation is None:
            gens = self.slot_gens.get((process, handle_no))
            if not gens:
                return None
            generation = gens[-1]
        return self.index.get((process, handle_no, generation))


def handle_digest(h: dict) -> dict:
    """The stable, serialisable shape of one capability handle."""
    return {
        "handle_id": h["id"],
        "owner": h["owner"],
        "handle": h["handle_no"],
        "generation": h["generation"],
        "resource": h["resource"],
        "resource_generation": h["resource_gen"],
        "rights": mask_to_methods(h["rights_mask"]),
        "session_generation": h["session_gen"],
        "parent": (
            None
            if h["parent_id"] is None
            else {
                "handle_id": h["parent_id"],
                "owner": h["parent_owner"],
                "handle": h["parent_no"],
                "generation": h["parent_gen"],
            }
        ),
        "not_before": h["not_before"],
        "not_after": h["not_after"],
        "sandboxes": {
            name: mask_to_methods(mask)
            for name, mask in sorted((h["sandboxes"] or {}).items())
        },
        "revoked_ms": h["revoked_ms"],
    }


def chain_of(world: World, leaf: dict):
    """Return ``(nodes_leaf_to_root, tail_failure)`` for a leaf handle."""
    nodes = []
    seen = set()
    cur = leaf
    while cur is not None:
        if cur["id"] in seen:
            return nodes, {
                "reason": "CYCLE_DETECTED",
                "code": REASON_CODES["CYCLE_DETECTED"],
                "hop": len(nodes),
                "owner": cur["owner"],
                "handle": cur["handle_no"],
                "generation": cur["generation"],
                "handle_id": cur["id"],
            }
        seen.add(cur["id"])
        nodes.append(cur)
        pid = cur["parent_id"]
        if pid is None:
            return nodes, None
        parent = world.handles.get(pid)
        if parent is None:
            return nodes, {
                "reason": "PARENT_MISSING",
                "code": REASON_CODES["PARENT_MISSING"],
                "hop": len(nodes),
                "owner": cur["parent_owner"],
                "handle": cur["parent_no"],
                "generation": cur["parent_gen"],
                "handle_id": pid,
            }
        cur = parent
    return nodes, None


def _fail(reason, hop, h, method=None, **extra):
    out = {
        "reason": reason,
        "code": REASON_CODES.get(reason, reason),
        "hop": hop,
        "handle_id": h["id"],
        "owner": h["owner"],
        "handle": h["handle_no"],
        "generation": h["generation"],
    }
    if method is not None:
        out["method"] = method
    out.update(extra)
    return out


def node_failures(
    world: World,
    h: dict,
    hop: int,
    method,
    resource_name,
    tenant,
    include_time=True,
    include_sandbox=False,
):
    """All failures for one hop.

    ``method=None`` skips method/right/sandbox/resource-support checks; that
    mode is used by grant-time structural validation and by ``handle_info``.
    ``include_sandbox`` is off by default because inherited tags are checked
    once for the whole chain by :func:`sandbox_failures`.
    """
    fails = []

    newest = world.slot_max.get((h["owner"], h["handle_no"]))
    if newest is not None and h["generation"] < newest:
        fails.append(_fail("HANDLE_SUPERSEDED", hop, h, newest_generation=newest))

    process = world.processes.get(h["owner"])
    if process is None:
        fails.append(_fail("PROCESS_NOT_FOUND", hop, h))
    else:
        if not process["alive"]:
            fails.append(
                _fail(
                    "PROCESS_DEAD",
                    hop,
                    h,
                    process_generation=process["generation"],
                )
            )
        if process["generation"] != h["session_gen"]:
            fails.append(
                _fail(
                    "SESSION_GENERATION_MISMATCH",
                    hop,
                    h,
                    session_generation=h["session_gen"],
                    process_generation=process["generation"],
                )
            )

    if h["revoked_ms"] is not None:
        fails.append(_fail("HANDLE_REVOKED", hop, h, revoked_ms=h["revoked_ms"]))

    resource = world.resources.get(h["resource"])
    if resource is None:
        fails.append(
            _fail("RESOURCE_NOT_FOUND", hop, h, resource=h["resource"])
        )
    else:
        if resource["generation"] != h["resource_gen"]:
            fails.append(
                _fail(
                    "RESOURCE_GENERATION_MISMATCH",
                    hop,
                    h,
                    resource=h["resource"],
                    resource_generation=resource["generation"],
                    handle_resource_generation=h["resource_gen"],
                )
            )
        if resource_name is not None and h["resource"] != resource_name:
            fails.append(
                _fail(
                    "RESOURCE_MISMATCH",
                    hop,
                    h,
                    expected_resource=resource_name,
                    actual_resource=h["resource"],
                )
            )

    if include_time:
        if world.clock < h["not_before"]:
            fails.append(
                _fail("NOT_YET_VALID", hop, h, not_before=h["not_before"])
            )
        if world.clock > h["not_after"]:
            fails.append(_fail("EXPIRED", hop, h, not_after=h["not_after"]))

    if method is None:
        return fails

    bit = METHOD_BITS[method]
    if not h["rights_mask"] & bit:
        reason = "METHOD_NOT_GRANTED" if hop == 0 else "ANCESTOR_MISSING_RIGHT"
        fails.append(_fail(reason, hop, h, method=method))
    elif hop == 0 and resource is not None:
        if not resource["rights_mask"] & bit:
            fails.append(
                _fail(
                    "RESOURCE_METHOD_UNSUPPORTED",
                    hop,
                    h,
                    method=method,
                    resource=resource["name"],
                    supported=mask_to_methods(resource["rights_mask"]),
                )
            )

    if hop == 0 and tenant is not None and resource is not None:
        if resource["tenant"] != tenant:
            fails.append(
                _fail(
                    "TENANT_MISMATCH",
                    hop,
                    h,
                    expected_tenant=tenant,
                    actual_tenant=resource["tenant"],
                )
            )

    if include_sandbox:
        bit2 = METHOD_BITS[method]
        for name in sorted(h["sandboxes"] or {}):
            allowed = world.sandboxes.get(name, 0)
            if not allowed & bit2:
                fails.append(
                    _fail(
                        "SANDBOX_DENIED",
                        hop,
                        h,
                        sandbox=name,
                        sandbox_rights=mask_to_methods(allowed),
                    )
                )

    return fails


def inherited_sandboxes(nodes) -> list:
    """Every sandbox tag in force for a chain.

    Tags are inherited at transfer time, so the union over the chain is the
    set of sandboxes that must *all* allow the operation.  Checking it once at
    the leaf avoids reporting the same blocking sandbox at every hop.
    """
    names = set()
    for h in nodes:
        names.update(h["sandboxes"] or {})
    return sorted(names)


def effective_mask(world: World, nodes) -> int:
    mask = 0
    for i, h in enumerate(nodes):
        hop_mask = h["rights_mask"]
        for name in inherited_sandboxes(nodes):
            hop_mask &= world.sandboxes.get(name, 0)
        mask = hop_mask if i == 0 else mask & hop_mask
    return mask


def sandbox_failures(world: World, nodes, method: str) -> list:
    """One failure per sandbox that does not allow ``method``.

    The hop reported is the deepest node that carries the tag - the ancestor
    that originally introduced it - so a sandbox inherited through a transfer
    still points at that ancestor's exact generation.
    """
    bit = METHOD_BITS[method]
    carrier = {}
    for hop, h in enumerate(nodes):
        for name in h["sandboxes"] or {}:
            prev = carrier.get(name)
            if prev is None or hop > prev[0]:
                carrier[name] = (hop, h)
    fails = []
    for name in sorted(carrier):
        allowed = world.sandboxes.get(name, 0)
        if not allowed & bit:
            hop, h = carrier[name]
            fails.append(
                _fail(
                    "SANDBOX_DENIED",
                    hop,
                    h,
                    sandbox=name,
                    sandbox_rights=mask_to_methods(allowed),
                )
            )
    return fails


def _sort_key(f):
    return (
        f["hop"],
        REASON_RANK.get(f["reason"], 99),
        f.get("sandbox", ""),
        f.get("handle_id", 0),
    )


def evaluate(
    world: World,
    process: str,
    handle_no: int,
    generation,
    resource_name: str,
    method: str,
    tenant=None,
):
    """Evaluate one reference down its full ancestor chain.

    Returns a dict with ``allowed``, ``blocker`` (leaf-first first failure),
    ``blocking_ancestor`` (first failure at hop >= 1), the full ``failures``
    list, the ``chain`` (leaf..root) and the effective rights mask.
    """
    leaf = world.resolve(process, handle_no, generation)
    if leaf is None:
        # No handle exists, so there is no blocking generation to report;
        # the requested generation is echoed separately for diagnostics.
        blocker = {
            "reason": "HANDLE_NOT_FOUND",
            "code": REASON_CODES["HANDLE_NOT_FOUND"],
            "hop": 0,
            "owner": process,
            "handle": handle_no,
            "generation": None,
            "requested_generation": generation,
        }
        return {
            "allowed": False,
            "blocker": blocker,
            "blocking_ancestor": None,
            "failures": [blocker],
            "chain": [],
            "effective_rights": [],
            "effective_mask": 0,
        }

    nodes, tail = chain_of(world, leaf)
    failures = []
    for hop, h in enumerate(nodes):
        failures.extend(
            node_failures(world, h, hop, method, resource_name, tenant)
        )
    failures.extend(sandbox_failures(world, nodes, method))
    if tail is not None:
        failures.append(tail)

    failures.sort(key=_sort_key)
    blocker = failures[0] if failures else None
    ancestor = next((f for f in failures if f["hop"] >= 1), None)
    mask = effective_mask(world, nodes)
    return {
        "allowed": not failures,
        "blocker": blocker,
        "blocking_ancestor": ancestor,
        "failures": failures,
        "chain": nodes,
        "effective_rights": mask_to_methods(mask),
        "effective_mask": mask,
    }


def chain_matches_snapshot(world: World, leaf: dict, snapshot_chain) -> tuple:
    """Compare a live chain with the exact identities recorded by a precheck."""
    nodes, tail = chain_of(world, leaf)
    if tail is not None:
        return False, tail
    live = [
        {
            "handle_id": h["id"],
            "owner": h["owner"],
            "handle": h["handle_no"],
            "generation": h["generation"],
        }
        for h in nodes
    ]
    expected = [
        {
            "handle_id": item["handle_id"],
            "owner": item["owner"],
            "handle": item["handle"],
            "generation": item["generation"],
        }
        for item in (snapshot_chain or [])
    ]
    if live == expected:
        return True, None
    return False, {
        "reason": "CHAIN_CHANGED",
        "expected": expected,
        "live": live,
        "live_ids": [n["handle_id"] for n in live],
        "expected_ids": [n["handle_id"] for n in expected],
    }


def recheck_report(world: World, nodes, method: str, resource_name, clock) -> dict:
    """Evidence that every hop's authorization, resource generation, session
    generation, window and sandbox masks were re-read at the current clock."""
    resource = world.resources.get(resource_name) if resource_name else None
    inherited = inherited_sandboxes(nodes)
    out = {
        "clock": clock,
        "resource": resource_name,
        "resource_generation": None if resource is None else resource["generation"],
        "resource_tenant": None if resource is None else resource["tenant"],
        "sandboxes": {
            name: {
                "rights": mask_to_methods(world.sandboxes.get(name, 0)),
                "method_allowed": bool(
                    world.sandboxes.get(name, 0) & METHOD_BITS[method]
                ),
            }
            for name in inherited
        },
        "nodes": [],
    }
    for hop, h in enumerate(nodes):
        process = world.processes.get(h["owner"])
        out["nodes"].append(
            {
                "hop": hop,
                "handle_id": h["id"],
                "owner": h["owner"],
                "handle": h["handle_no"],
                "generation": h["generation"],
                "rights": mask_to_methods(h["rights_mask"]),
                "method_granted": bool(h["rights_mask"] & METHOD_BITS[method]),
                "resource": h["resource"],
                "resource_generation": h["resource_gen"],
                "current_resource_generation": (
                    None if resource is None else resource["generation"]
                ),
                "resource_generation_current": bool(
                    resource is not None
                    and resource["generation"] == h["resource_gen"]
                ),
                "session_generation": h["session_gen"],
                "current_session_generation": (
                    None if process is None else process["generation"]
                ),
                "session_generation_current": bool(
                    process is not None
                    and process["generation"] == h["session_gen"]
                    and process["alive"]
                ),
                "window": [h["not_before"], h["not_after"]],
                "window_ok": h["not_before"] <= clock <= h["not_after"],
                "revoked": h["revoked_ms"] is not None,
                "superseded": (
                    world.slot_max.get((h["owner"], h["handle_no"]), h["generation"])
                    > h["generation"]
                ),
            }
        )
    return out
