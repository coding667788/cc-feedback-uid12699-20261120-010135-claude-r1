"""An independent, deliberately naive capability model.

Used by ``tests/test_reference_crosscheck.py`` to cross-check the SQLite-backed
engine.  This module imports nothing from ``solution``: it is a plain Python
state machine that transcribes the README rules, and it answers a capability
question with a direct walk over a list of handle records.

Kept intentionally dumb: no SQL, no caching, no shared helpers with the engine.
"""

from __future__ import annotations

METHODS = ("read", "write", "list")
BITS = {"read": 1, "write": 2, "list": 4}

# Fixed precedence when two failures land on the same hop.
REASON_ORDER = (
    "HANDLE_NOT_FOUND",
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
)
RANK = {r: i for i, r in enumerate(REASON_ORDER)}

# Reason -> public error code, transcribed by hand from the README table so a
# change in either side shows up as a cross-check failure.
CODE = {
    "HANDLE_NOT_FOUND": "E_HANDLE_NOT_FOUND",
    "HANDLE_SUPERSEDED": "E_HANDLE_SUPERSEDED",
    "PROCESS_NOT_FOUND": "E_PROCESS_NOT_FOUND",
    "PROCESS_DEAD": "E_PROCESS_DEAD",
    "SESSION_GENERATION_MISMATCH": "E_SESSION_STALE",
    "HANDLE_REVOKED": "E_HANDLE_REVOKED",
    "RESOURCE_NOT_FOUND": "E_RESOURCE_NOT_FOUND",
    "RESOURCE_GENERATION_MISMATCH": "E_RESOURCE_GENERATION_MISMATCH",
    "RESOURCE_MISMATCH": "E_RESOURCE_MISMATCH",
    "NOT_YET_VALID": "E_NOT_YET_VALID",
    "EXPIRED": "E_EXPIRED",
    "METHOD_NOT_GRANTED": "E_METHOD_NOT_GRANTED",
    "ANCESTOR_MISSING_RIGHT": "E_ANCESTOR_MISSING_RIGHT",
    "RESOURCE_METHOD_UNSUPPORTED": "E_RESOURCE_METHOD_UNSUPPORTED",
    "TENANT_MISMATCH": "E_TENANT_MISMATCH",
    "SANDBOX_DENIED": "E_SANDBOX_DENIED",
}


def bits(methods):
    out = 0
    for m in methods:
        out |= BITS[m]
    return out


class RefError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class H:
    __slots__ = ("id", "owner", "no", "gen", "parent", "resource", "rgen",
                 "rights", "sgen", "nb", "na", "tags", "revoked")

    def __init__(self, hid, owner, no, gen, parent, resource, rgen, rights,
                 sgen, nb, na, tags):
        self.id = hid
        self.owner = owner
        self.no = no
        self.gen = gen
        self.parent = parent
        self.resource = resource
        self.rgen = rgen
        self.rights = rights
        self.sgen = sgen
        self.nb = nb
        self.na = na
        self.tags = tuple(sorted(tags))
        self.revoked = None


class RefModel:
    def __init__(self):
        self.clock = 0
        self.procs = {}      # name -> [generation, alive]
        self.res = {}        # name -> [tenant, generation, mask]
        self.boxes = {}      # name -> mask
        self.by_id = {}
        self.by_slot = {}    # (owner, no) -> {generation: H}
        self.next_id = 1
        self.ops = {}        # op_id -> frozen result dict

    # ---- mutations ------------------------------------------------------
    def set_clock(self, now):
        if now < self.clock:
            raise RefError("E_TIME_REGRESSION", "clock")
        self.clock = now

    def create_process(self, name):
        if name in self.procs:
            raise RefError("E_ALREADY_EXISTS", "process")
        self.procs[name] = [1, True]

    def restart_process(self, name):
        if name not in self.procs:
            raise RefError("E_PROCESS_NOT_FOUND", "process")
        self.procs[name][0] += 1
        self.procs[name][1] = True

    def create_resource(self, name, tenant, rights):
        if name in self.res:
            raise RefError("E_ALREADY_EXISTS", "resource")
        self.res[name] = [tenant, 1, bits(rights)]

    def rebuild_resource(self, name):
        if name not in self.res:
            raise RefError("E_RESOURCE_NOT_FOUND", "resource")
        self.res[name][1] += 1

    def create_sandbox(self, name, rights):
        if name in self.boxes:
            raise RefError("E_ALREADY_EXISTS", "sandbox")
        self.boxes[name] = bits(rights)

    def tighten_sandbox(self, name, rights):
        if name not in self.boxes:
            raise RefError("E_SANDBOX_NOT_FOUND", "sandbox")
        new = bits(rights)
        old = self.boxes[name]
        if new & ~old or new == old:
            raise RefError("E_SANDBOX_NOT_NARROWING", "sandbox")
        self.boxes[name] = new

    # ---- handles --------------------------------------------------------
    def _generation_for(self, owner, no, requested):
        gens = self.by_slot.get((owner, no), {})
        top = max(gens) if gens else 0
        if requested is None:
            return top + 1
        if requested <= top:
            raise RefError("E_GENERATION_CONFLICT", "generation")
        return requested

    def grant(self, owner, no, resource, rights, tags=(), not_before=None,
              not_after=None, requested_gen=None):
        if owner not in self.procs:
            raise RefError("E_PROCESS_NOT_FOUND", "process")
        if not self.procs[owner][1]:
            raise RefError("E_PROCESS_DEAD", "process")
        if resource not in self.res:
            raise RefError("E_RESOURCE_NOT_FOUND", "resource")
        if bits(rights) & ~self.res[resource][2]:
            raise RefError("E_RESOURCE_METHOD_UNSUPPORTED", "resource")
        for t in tags:
            if t not in self.boxes:
                raise RefError("E_SANDBOX_NOT_FOUND", "sandbox")
        gen = self._generation_for(owner, no, requested_gen)
        lo = self.clock if not_before is None else not_before
        hi = self.clock + 86400000 if not_after is None else not_after
        if hi < lo:
            raise RefError("E_INVALID_REQUEST", "window")
        h = H(self.next_id, owner, no, gen, None, resource,
              self.res[resource][1], bits(rights), self.procs[owner][0],
              lo, hi, tags)
        self.next_id += 1
        self._store(h)
        return h

    def transfer(self, parent, to_process, no, rights=None, not_before=None,
                 not_after=None, tags=(), requested_gen=None):
        chain = self.chain(parent)
        candidates = self._structural_candidates(chain)
        blockers = sorted(candidates, key=lambda c: (c[1], RANK[c[0]]))
        if blockers:
            reason, hop, node, _tag = blockers[0]
            raise RefError(CODE[reason], "parent unusable at hop %d" % hop)
        if to_process not in self.procs or not self.procs[to_process][1]:
            raise RefError("E_PROCESS_NOT_FOUND", "target")
        eff = self.effective(chain)
        child = eff if rights is None else bits(rights)
        if child & ~eff:
            raise RefError("E_RIGHTS_ESCALATION", "rights")
        if child & ~self.res[parent.resource][2]:
            raise RefError("E_RESOURCE_METHOD_UNSUPPORTED", "rights")
        lo = parent.nb if not_before is None else not_before
        hi = parent.na if not_after is None else not_after
        if lo < parent.nb or hi > parent.na:
            raise RefError("E_WINDOW_ESCALATION", "window")
        if hi < lo:
            raise RefError("E_INVALID_REQUEST", "window")
        for t in tags:
            if t not in self.boxes:
                raise RefError("E_SANDBOX_NOT_FOUND", "sandbox")
        gen = self._generation_for(to_process, no, requested_gen)
        h = H(self.next_id, to_process, no, gen, parent, parent.resource,
              parent.rgen, child, self.procs[to_process][0], lo, hi,
              sorted(set(parent.tags) | set(tags)))
        self.next_id += 1
        self._store(h)
        return h

    def _store(self, h):
        self.by_id[h.id] = h
        self.by_slot.setdefault((h.owner, h.no), {})[h.gen] = h

    def revoke(self, h):
        h.revoked = self.clock

    def find(self, owner, no, gen=None):
        slot = self.by_slot.get((owner, no), {})
        if gen is None:
            return slot[max(slot)] if slot else None
        return slot.get(gen)

    def chain(self, h):
        out, seen, cur = [], set(), h
        while cur is not None and cur.id not in seen:
            seen.add(cur.id)
            out.append(cur)
            cur = cur.parent
        return out

    def effective(self, chain):
        m = 7
        for h in chain:
            m &= h.rights
        return m

    # ---- the actual check ----------------------------------------------
    def check(self, owner, no, gen, resource, method, tenant=None):
        """Return a full, sorted report so the test can compare all fields."""
        h = self.find(owner, no, gen)
        if h is None:
            return self._report([("HANDLE_NOT_FOUND", 0, None, None)])
        chain = self.chain(h)
        cands = self._structural_candidates(chain)
        cands += self._method_candidates(chain, resource, method, tenant)
        return self._report(cands, chain)

    def _report(self, cands, chain=None):
        cands.sort(key=lambda c: (c[1], RANK[c[0]], c[3] or ""))
        failures = [
            self._result(False, reason, hop, node.gen if node else None, tag)
            for reason, hop, node, tag in cands
        ]
        ancestor = next(
            (f for f in failures if f["hop"] and f["hop"] >= 1), None
        )
        primary = failures[0] if failures else None
        return {
            "allowed": not failures,
            "chain_len": len(chain) if chain is not None else 0,
            "blocker": primary,
            "blocking_ancestor": ancestor,
            "failures": failures,
        }

    def _structural_candidates(self, chain):
        out = []
        for hop, node in enumerate(chain):
            slot = self.by_slot.get((node.owner, node.no), {})
            if slot and max(slot) > node.gen:
                out.append(("HANDLE_SUPERSEDED", hop, node, None))
            proc = self.procs.get(node.owner)
            if proc is None:
                out.append(("PROCESS_NOT_FOUND", hop, node, None))
                continue
            if not proc[1]:
                out.append(("PROCESS_DEAD", hop, node, None))
            if proc[0] != node.sgen:
                out.append(("SESSION_GENERATION_MISMATCH", hop, node, None))
            if node.revoked is not None:
                out.append(("HANDLE_REVOKED", hop, node, None))
            res = self.res.get(node.resource)
            if res is None:
                out.append(("RESOURCE_NOT_FOUND", hop, node, None))
            elif res[1] != node.rgen:
                out.append(("RESOURCE_GENERATION_MISMATCH", hop, node, None))
        return out

    def _method_candidates(self, chain, resource, method, tenant):
        out = []
        mbit = BITS[method]
        res = self.res.get(resource)
        for hop, node in enumerate(chain):
            if self.clock < node.nb:
                out.append(("NOT_YET_VALID", hop, node, None))
            if self.clock > node.na:
                out.append(("EXPIRED", hop, node, None))
            if not node.rights & mbit:
                out.append((
                    "METHOD_NOT_GRANTED" if hop == 0 else "ANCESTOR_MISSING_RIGHT",
                    hop, node, None,
                ))
            if node.resource != resource:
                out.append(("RESOURCE_MISMATCH", hop, node, None))
        if res is not None and not res[2] & mbit:
            out.append(("RESOURCE_METHOD_UNSUPPORTED", 0, chain[0], None))
        if res is not None and tenant is not None and res[0] != tenant:
            out.append(("TENANT_MISMATCH", 0, chain[0], None))
        # A sandbox is checked once for the whole chain and attributed to the
        # deepest hop carrying the tag.
        introducer = {}
        for hop, node in enumerate(chain):
            for tag in node.tags:
                if tag not in introducer or hop > introducer[tag][0]:
                    introducer[tag] = (hop, node)
        for tag in sorted(introducer):
            if not self.boxes.get(tag, 0) & mbit:
                hop, node = introducer[tag]
                out.append(("SANDBOX_DENIED", hop, node, tag))
        return out

    def _result(self, allowed, reason, hop, generation, sandbox=None):
        item = {
            "allowed": allowed,
            "reason": reason,
            "hop": hop or 0,
            "generation": generation,
        }
        if sandbox is not None:
            item["sandbox"] = sandbox
        return item
