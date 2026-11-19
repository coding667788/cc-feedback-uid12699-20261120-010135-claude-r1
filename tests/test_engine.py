"""Engine-level tests: capability semantics, persistence, prechecks, I/O modes.

Every assertion pins a concrete value (decision, reason, hop, generation),
not merely "not None" - that is what makes these tests useful against a
regression in the precedence order or in ancestry attribution.
"""

from __future__ import annotations

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

from solution.db import connect
from solution.engine import Engine
from solution.errors import EngineError

from support import Mirror, TempDirCase


def run(engine, **step):
    return engine.run_step(step)


class EngineBasics(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)

    def seed(self):
        run(self.e, op="set_clock", now_ms=1000)
        run(self.e, op="create_process", process="p1")
        run(self.e, op="create_resource", resource="r1", tenant="t1")
        run(self.e, op="create_process", process="p2")

    # -- grants ----------------------------------------------------------
    def test_grant_assigns_first_generation(self):
        self.seed()
        out = run(self.e, op="grant", process="p1", handle=3, resource="r1",
                  rights=["read", "write"])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["generation"], 1)
        self.assertEqual(out["slot_max_generation"], 0)
        self.assertEqual(out["resource_generation"], 1)
        self.assertEqual(out["rights"], ["read", "write"])
        self.assertEqual(out["session_generation"], 1)
        self.assertEqual(out["not_before"], 1000)
        self.assertEqual(out["not_after"], 1000 + 86_400_000)

    def test_grant_rejects_rights_the_resource_lacks(self):
        run(self.e, op="set_clock", now_ms=10)
        run(self.e, op="create_process", process="p1")
        run(self.e, op="create_resource", resource="r1", tenant="t1",
            rights=["read"])
        with self.assertRaises(EngineError) as ctx:
            run(self.e, op="grant", process="p1", handle=1, resource="r1",
                rights=["read", "write"])
        self.assertEqual(ctx.exception.code, "E_RESOURCE_METHOD_UNSUPPORTED")

    def test_grant_rejects_unknown_sandbox(self):
        self.seed()
        with self.assertRaises(EngineError) as ctx:
            run(self.e, op="grant", process="p1", handle=1, resource="r1",
                rights=["read"], sandboxes=["nope"])
        self.assertEqual(ctx.exception.code, "E_SANDBOX_NOT_FOUND")

    # -- checks ----------------------------------------------------------
    def test_check_reports_method_not_granted_with_exact_generation(self):
        self.seed()
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read"])
        out = run(self.e, op="check", process="p1", handle=1, method="write")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["code"], "E_METHOD_NOT_GRANTED")
        self.assertEqual(out["blocker"]["reason"], "METHOD_NOT_GRANTED")
        self.assertEqual(out["blocker"]["hop"], 0)
        self.assertEqual(out["blocker"]["generation"], 1)
        self.assertIsNone(out["blocking_ancestor"])
        self.assertEqual(out["effective_rights"], ["read"])
        self.assertEqual(len(out["chain"]), 1)
        self.assertEqual(out["chain"][0]["handle_id"], out["blocker"]["handle_id"])

    def test_check_unknown_handle_slot(self):
        self.seed()
        out = run(self.e, op="check", process="p1", handle=99, method="read")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["blocker"]["reason"], "HANDLE_NOT_FOUND")
        self.assertEqual(out["blocker"]["generation"], None)
        self.assertEqual(out["chain"], [])

    def test_tenant_is_checked(self):
        self.seed()
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read"])
        ok = run(self.e, op="check", process="p1", handle=1, method="read",
                 tenant="t1")
        self.assertEqual(ok["decision"], "allow")
        bad = run(self.e, op="check", process="p1", handle=1, method="read",
                  tenant="t2")
        self.assertEqual(bad["decision"], "deny")
        self.assertEqual(bad["blocker"]["reason"], "TENANT_MISMATCH")

    def test_time_window(self):
        self.seed()
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read"], not_before=1200, not_after=1300)
        early = run(self.e, op="check", process="p1", handle=1, method="read")
        self.assertEqual(early["blocker"]["reason"], "NOT_YET_VALID")
        run(self.e, op="set_clock", now_ms=1250)
        self.assertEqual(
            run(self.e, op="check", process="p1", handle=1, method="read")[
                "decision"
            ],
            "allow",
        )
        run(self.e, op="set_clock", now_ms=1400)
        late = run(self.e, op="check", process="p1", handle=1, method="read")
        self.assertEqual(late["blocker"]["reason"], "EXPIRED")
        self.assertEqual(late["blocker"]["generation"], 1)


class AncestrySemantics(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)
        run(self.e, op="set_clock", now_ms=1000)
        for name in ("p1", "p2", "p3"):
            run(self.e, op="create_process", process=name)
        run(self.e, op="create_resource", resource="r1", tenant="t1")
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write", "list"])
        run(self.e, op="transfer",
            parent={"process": "p1", "handle": 1, "generation": 1},
            to_process="p2", handle=2, rights=["read", "write"])
        run(self.e, op="transfer",
            parent={"process": "p2", "handle": 2, "generation": 1},
            to_process="p3", handle=3, rights=["read"])

    def test_three_generation_chain_allows_narrowed_rights(self):
        out = run(self.e, op="check", process="p3", handle=3, method="read")
        self.assertEqual(out["decision"], "allow")
        self.assertEqual([h["generation"] for h in out["chain"]], [1, 1, 1])
        self.assertEqual(
            [h["owner"] for h in out["chain"]], ["p3", "p2", "p1"]
        )
        self.assertEqual(out["effective_rights"], ["read"])

    def test_ancestor_missing_right_blocks_a_grandchild(self):
        # p3 was narrowed to read+write? no: widened request must be refused.
        with self.assertRaises(EngineError) as ctx:
            run(self.e, op="transfer",
                parent={"process": "p3", "handle": 3},
                to_process="p1", handle=4, rights=["read", "list"])
        self.assertEqual(ctx.exception.code, "E_RIGHTS_ESCALATION")

    def test_ancestor_window_shrinks_leaf_effective_rights(self):
        # Granting a narrower leaf window is legal, and the leaf expires first.
        run(self.e, op="transfer",
            parent={"process": "p2", "handle": 2},
            to_process="p1", handle=8, rights=["read"], not_after=1100)
        self.assertEqual(
            run(self.e, op="check", process="p1", handle=8, method="read")[
                "decision"
            ],
            "allow",
        )
        run(self.e, op="set_clock", now_ms=1150)
        out = run(self.e, op="check", process="p1", handle=8, method="read")
        self.assertEqual(out["blocker"]["reason"], "EXPIRED")
        self.assertEqual(out["blocker"]["hop"], 0)

    def test_revoke_ancestor_reports_exact_blocking_generation(self):
        run(self.e, op="revoke", process="p2", handle=2)
        out = run(self.e, op="check", process="p3", handle=3, method="read")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["blocker"]["reason"], "HANDLE_REVOKED")
        # the leaf is fine; the only failure is the revoked ancestor at hop 1,
        # so it is both the primary blocker and the blocking ancestor
        self.assertEqual(out["blocker"]["hop"], 1)
        self.assertEqual(out["blocker"]["generation"], 1)
        self.assertEqual(out["blocker"]["revoked_ms"], 1000)
        anc = out["blocking_ancestor"]
        self.assertEqual(anc["reason"], "HANDLE_REVOKED")
        self.assertEqual(anc["hop"], 1)
        self.assertEqual(anc["owner"], "p2")
        self.assertEqual(anc["handle"], 2)
        self.assertEqual(anc["generation"], 1)
        self.assertEqual(anc["revoked_ms"], 1000)

    def test_revoked_ancestor_cannot_be_used_for_new_transfers(self):
        run(self.e, op="revoke", process="p1", handle=1)
        with self.assertRaises(EngineError) as ctx:
            run(self.e, op="transfer",
                parent={"process": "p2", "handle": 2},
                to_process="p3", handle=9, rights=["read"])
        self.assertEqual(ctx.exception.code, "E_HANDLE_REVOKED")
        self.assertEqual(ctx.exception.detail["blocker"]["hop"], 1)
        self.assertEqual(ctx.exception.detail["blocker"]["generation"], 1)

    def test_process_restart_invalidates_descendants(self):
        run(self.e, op="restart_process", process="p1")
        out = run(self.e, op="check", process="p3", handle=3, method="read")
        self.assertEqual(out["blocker"]["reason"], "SESSION_GENERATION_MISMATCH")
        self.assertEqual(out["blocking_ancestor"]["hop"], 2)
        self.assertEqual(out["blocking_ancestor"]["owner"], "p1")
        self.assertEqual(out["blocker"]["session_generation"], 1)
        self.assertEqual(out["blocker"]["process_generation"], 2)

    def test_resource_rebuild_blocks_every_descendant(self):
        run(self.e, op="rebuild_resource", resource="r1")
        out = run(self.e, op="check", process="p3", handle=3, method="read")
        self.assertEqual(
            out["blocker"]["reason"], "RESOURCE_GENERATION_MISMATCH"
        )
        self.assertEqual(out["blocker"]["hop"], 0)
        self.assertEqual(out["blocking_ancestor"]["hop"], 1)
        self.assertEqual(out["blocker"]["resource_generation"], 2)
        self.assertEqual(out["blocker"]["handle_resource_generation"], 1)


class HandleNumberReuse(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)
        run(self.e, op="set_clock", now_ms=1000)
        run(self.e, op="create_process", process="p1")
        run(self.e, op="create_resource", resource="r1", tenant="t1")

    def test_two_generations_share_a_number(self):
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read", "write"])
        slot = run(self.e, op="list_slot", process="p1", handle=5)
        self.assertEqual(slot["generation_count"], 2)
        self.assertEqual(slot["slot_max_generation"], 2)
        generations = slot["generations"]
        self.assertEqual([g["generation"] for g in generations], [1, 2])
        self.assertEqual([g["superseded"] for g in generations], [True, False])
        self.assertEqual(generations[0]["rights"], ["read"])
        self.assertEqual(generations[1]["rights"], ["read", "write"])
        self.assertNotEqual(generations[0]["handle_id"], generations[1]["handle_id"])

    def test_old_generation_is_superseded_not_silently_upgraded(self):
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read", "write"])
        old = run(self.e, op="check", process="p1", handle=5, method="read",
                  generation=1)
        self.assertEqual(old["decision"], "deny")
        self.assertEqual(old["blocker"]["reason"], "HANDLE_SUPERSEDED")
        self.assertEqual(old["blocker"]["generation"], 1)
        self.assertEqual(old["blocker"]["newest_generation"], 2)
        # the newest generation is still usable
        new = run(self.e, op="check", process="p1", handle=5, method="read",
                  generation=2)
        self.assertEqual(new["decision"], "allow")

    def test_omitted_generation_resolves_to_newest(self):
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["write"])
        out = run(self.e, op="check", process="p1", handle=5, method="write")
        self.assertEqual(out["decision"], "allow")
        self.assertEqual(out["subject"]["resolved_generation"], 2)
        self.assertIsNone(out["subject"]["generation"])

    def test_explicit_older_generation_cannot_be_reused(self):
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        with self.assertRaises(EngineError) as ctx:
            run(self.e, op="grant", process="p1", handle=5, resource="r1",
                rights=["read"], generation=1)
        self.assertEqual(ctx.exception.code, "E_GENERATION_CONFLICT")
        self.assertEqual(ctx.exception.detail["slot_max_generation"], 2)

    def test_regranting_identical_rights_does_not_revive_generation_one(self):
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        run(self.e, op="revoke", process="p1", handle=5)
        regrant = run(self.e, op="grant", process="p1", handle=5,
                      resource="r1", rights=["read"])
        self.assertEqual(regrant["generation"], 2)
        old = run(self.e, op="check", process="p1", handle=5, method="read",
                  generation=1)
        self.assertEqual(old["decision"], "deny")
        # gen 1 is still flagged revoked even though gen 2 has the same rights
        self.assertIn(
            old["blocker"]["reason"], ("HANDLE_SUPERSEDED", "HANDLE_REVOKED")
        )
        new = run(self.e, op="check", process="p1", handle=5, method="read",
                  generation=2)
        self.assertEqual(new["decision"], "allow")

    def test_restart_does_not_resurrect_old_session_generation(self):
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        run(self.e, op="restart_process", process="p1")
        stale = run(self.e, op="check", process="p1", handle=5, method="read")
        self.assertEqual(stale["blocker"]["reason"], "SESSION_GENERATION_MISMATCH")
        self.assertEqual(stale["blocker"]["session_generation"], 1)
        run(self.e, op="grant", process="p1", handle=5, resource="r1",
            rights=["read"])
        fresh = run(self.e, op="check", process="p1", handle=5, method="read")
        self.assertEqual(fresh["decision"], "allow")
        self.assertEqual(fresh["subject"]["resolved_generation"], 2)


class SandboxSemantics(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)
        run(self.e, op="set_clock", now_ms=1000)
        for name in ("p1", "p2"):
            run(self.e, op="create_process", process=name)
        run(self.e, op="create_resource", resource="r1", tenant="t1")
        run(self.e, op="create_sandbox", sandbox="sb_ro",
            rights=["read", "list"])
        run(self.e, op="create_sandbox", sandbox="sb_rw",
            rights=["read", "write"])

    def test_every_sandbox_must_allow(self):
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write", "list"], sandboxes=["sb_ro", "sb_rw"])
        self.assertEqual(
            run(self.e, op="check", process="p1", handle=1, method="read")[
                "decision"
            ],
            "allow",
        )
        write = run(self.e, op="check", process="p1", handle=1, method="write")
        self.assertEqual(write["decision"], "deny")
        self.assertEqual(write["blocker"]["reason"], "SANDBOX_DENIED")
        self.assertEqual(write["blocker"]["sandbox"], "sb_ro")
        listed = run(self.e, op="check", process="p1", handle=1, method="list")
        self.assertEqual(listed["decision"], "deny")
        self.assertEqual(listed["blocker"]["sandbox"], "sb_rw")

    def test_tightening_applies_to_already_issued_handles(self):
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"], sandboxes=["sb_rw"])
        self.assertEqual(
            run(self.e, op="check", process="p1", handle=1, method="write")[
                "decision"
            ],
            "allow",
        )
        run(self.e, op="tighten_sandbox", sandbox="sb_rw", rights=["read"])
        out = run(self.e, op="check", process="p1", handle=1, method="write")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["blocker"]["reason"], "SANDBOX_DENIED")
        self.assertEqual(out["blocker"]["sandbox_rights"], ["read"])

    def test_tightening_to_empty_blocks_everything(self):
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"], sandboxes=["sb_rw"])
        run(self.e, op="tighten_sandbox", sandbox="sb_rw", rights=[])
        out = run(self.e, op="check", process="p1", handle=1, method="read")
        self.assertEqual(out["blocker"]["reason"], "SANDBOX_DENIED")
        self.assertEqual(out["blocker"]["sandbox_rights"], [])

    def test_sandbox_cannot_be_widened_through_tighten(self):
        with self.assertRaises(EngineError) as ctx:
            run(self.e, op="tighten_sandbox", sandbox="sb_ro",
                rights=["read", "write"])
        self.assertEqual(ctx.exception.code, "E_SANDBOX_NOT_NARROWING")

    def test_inherited_sandbox_is_attributed_to_the_introducing_ancestor(self):
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"], sandboxes=["sb_rw"])
        run(self.e, op="transfer",
            parent={"process": "p1", "handle": 1},
            to_process="p2", handle=2, rights=["read"])
        run(self.e, op="tighten_sandbox", sandbox="sb_rw", rights=["write"])
        out = run(self.e, op="check", process="p2", handle=2, method="read")
        # leaf hop 0 has no own denial; the inherited tag is charged to p1 (hop 1)
        self.assertEqual(out["blocking_ancestor"]["reason"], "SANDBOX_DENIED")
        self.assertEqual(out["blocking_ancestor"]["hop"], 1)
        self.assertEqual(out["blocking_ancestor"]["owner"], "p1")
        self.assertEqual(out["blocking_ancestor"]["generation"], 1)

    def test_child_inherits_parent_tags_and_may_add_more(self):
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"], sandboxes=["sb_ro"])
        run(self.e, op="transfer",
            parent={"process": "p1", "handle": 1},
            to_process="p2", handle=2, rights=["read"],
            sandboxes=["sb_rw"])
        info = run(self.e, op="handle_info", process="p2", handle=2)
        self.assertEqual(
            sorted(info["handle"]["sandboxes"]), ["sb_ro", "sb_rw"]
        )


class PrecheckSemantics(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)
        run(self.e, op="set_clock", now_ms=1000)
        run(self.e, op="create_process", process="p1")
        run(self.e, op="create_resource", resource="r1", tenant="t1")
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"])

    def _use(self, op_id, token, **extra):
        item = {"handle": 1, "method": "write", "resource": "r1",
                "payload": "p", "precheck": token}
        item.update(extra)
        return run(self.e, op="protected_io", op_id=op_id, process="p1",
                   items=[item])

    def test_precheck_snapshot_is_detachable(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write",
                 ttl_ms=500)
        self.assertEqual(pc["status"], "ok")
        self.assertEqual(pc["precheck"], "P0001")
        self.assertEqual(pc["expires_at_ms"], 1500)
        self.assertEqual([n["handle_id"] for n in pc["chain"]],
                         [pc["chain_ids"][0]])

    def test_precheck_denies_when_not_currently_authorized(self):
        run(self.e, op="revoke", process="p1", handle=1)
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write")
        self.assertEqual(pc["status"], "denied")
        self.assertEqual(pc["blocker"]["reason"], "HANDLE_REVOKED")
        self.assertIsNone(pc["precheck"])

    def test_precheck_expiry_is_enforced_at_use(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write",
                 ttl_ms=100)
        run(self.e, op="set_clock", now_ms=1101)
        out = self._use("op-exp", pc["precheck"])
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["blockers"][0]["reason"], "PRECHECK_EXPIRED")
        self.assertEqual(out["io_written"], [])
        self.assertFalse(out["receipt_written"])

    def test_precheck_used_before_expiry_succeeds(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write",
                 ttl_ms=500)
        out = self._use("op-ok", pc["precheck"])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(len(out["io_written"]), 1)
        self.assertTrue(out["receipt_written"])

    def test_precheck_token_is_single_use(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write")
        first = self._use("op-1", pc["precheck"])
        self.assertEqual(first["status"], "ok")
        second = self._use("op-2", pc["precheck"])
        self.assertEqual(second["status"], "denied")
        self.assertEqual(second["blockers"][0]["reason"], "PRECHECK_USED")

    def test_precheck_rejects_method_swap(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="read")
        item = {"handle": 1, "method": "write", "resource": "r1",
                "payload": "p", "precheck": pc["precheck"]}
        out = run(self.e, op="protected_io", op_id="op-swap", process="p1",
                  items=[item])
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["blockers"][0]["reason"], "PRECHECK_MODE_MISMATCH")

    def test_precheck_rejects_replaced_generation(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write")
        # replacing the slot with a fresh, narrower generation
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read"])
        out = self._use("op-gen", pc["precheck"])
        self.assertEqual(out["status"], "denied")
        # The pinned generation is still on disk, but a newer generation now
        # occupies the same slot, so the authorized generation is superseded.
        reasons = {b["reason"] for b in out["blockers"]}
        self.assertIn("HANDLE_SUPERSEDED", reasons)
        self.assertEqual(out["io_written"], [])

    def test_precheck_rechecks_resource_generation(self):
        pc = run(self.e, op="precheck", process="p1", handle=1, method="write")
        run(self.e, op="rebuild_resource", resource="r1")
        out = self._use("op-rg", pc["precheck"])
        self.assertEqual(out["status"], "denied")
        reasons = [b["reason"] for b in out["blockers"]]
        self.assertEqual(reasons, ["RESOURCE_GENERATION_MISMATCH"])
        self.assertEqual(out["blockers"][0]["blocking_generation"], 1)
        self.assertEqual(out["io_written"], [])
        recheck = out["items"][0]["recheck"]
        self.assertEqual(recheck["resource_generation"], 2)
        self.assertFalse(recheck["nodes"][0]["resource_generation_current"])

    def test_precheck_rechecks_sandbox_tightening(self):
        run(self.e, op="create_sandbox", sandbox="sb", rights=["read", "write"])
        run(self.e, op="grant", process="p1", handle=2, resource="r1",
            rights=["read", "write"], sandboxes=["sb"])
        pc = run(self.e, op="precheck", process="p1", handle=2, method="write")
        run(self.e, op="tighten_sandbox", sandbox="sb", rights=["read"])
        out = run(self.e, op="protected_io", op_id="op-sb", process="p1",
                  items=[{"handle": 2, "method": "write", "resource": "r1",
                          "payload": "p", "precheck": pc["precheck"]}])
        self.assertEqual(out["status"], "denied")
        self.assertEqual([b["reason"] for b in out["blockers"]],
                         ["SANDBOX_DENIED"])
        # the per-hop evidence still shows the sandbox was re-read live
        recheck = out["items"][0]["recheck"]
        self.assertEqual(recheck["sandboxes"]["sb"]["rights"], ["read"])
        self.assertFalse(recheck["sandboxes"]["sb"]["method_allowed"])
        self.assertEqual(out["io_written"], [])

    def test_precheck_recheck_report_records_every_hop(self):
        run(self.e, op="create_process", process="p2")
        run(self.e, op="transfer", parent={"process": "p1", "handle": 1},
            to_process="p2", handle=2, rights=["read", "write"])
        pc = run(self.e, op="precheck", process="p2", handle=2, method="write")
        out = run(self.e, op="protected_io", op_id="op-rep", process="p2",
                  items=[{"handle": 2, "method": "write", "resource": "r1",
                          "payload": "p", "precheck": pc["precheck"]}])
        recheck = out["items"][0]["recheck"]
        self.assertEqual(len(recheck["nodes"]), 2)
        self.assertEqual([n["hop"] for n in recheck["nodes"]], [0, 1])
        for node in recheck["nodes"]:
            self.assertTrue(node["resource_generation_current"])
            self.assertTrue(node["session_generation_current"])
            self.assertTrue(node["window_ok"])
            self.assertFalse(node["revoked"])
            self.assertFalse(node["superseded"])
        self.assertEqual(recheck["clock"], 1000)


class ProtectedIoTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)
        run(self.e, op="set_clock", now_ms=1000)
        run(self.e, op="create_process", process="p1")
        for name in ("r1", "r2", "r3"):
            run(self.e, op="create_resource", resource=name, tenant="t1")
            run(self.e, op="grant", process="p1", handle=int(name[1]),
                resource=name, rights=["read", "write"])

    def test_all_or_nothing_writes_one_receipt_for_all_resources(self):
        out = run(self.e, op="protected_io", op_id="op-a", process="p1",
                  items=[
                      {"handle": 1, "method": "write", "resource": "r1",
                       "payload": "a"},
                      {"handle": 2, "method": "write", "resource": "r2",
                       "payload": "b"},
                      {"handle": 3, "method": "write", "resource": "r3",
                       "payload": "c"},
                  ])
        self.assertEqual(out["status"], "ok")
        self.assertTrue(out["all_allowed"])
        self.assertEqual(out["allowed_count"], 3)
        self.assertEqual([w["seq"] for w in out["io_written"]], [1, 2, 3])
        self.assertTrue(out["receipt_written"])
        receipt = out["receipt"]
        self.assertEqual(receipt["receipt_seq"], 1)
        self.assertEqual(receipt["body"]["txn_id"], out["txn_id"])
        self.assertEqual(len(receipt["body"]["items"]), 3)
        self.assertEqual(receipt["body"]["io_seqs"], [1, 2, 3])
        self.assertEqual(len(receipt["receipt_sha256"]), 64)

        audit = run(self.e, op="io_audit")
        self.assertEqual(audit["io_count"], 3)
        self.assertEqual(audit["receipt_count"], 1)
        self.assertEqual(audit["transactions"][0]["state"], "committed")

    def test_all_or_nothing_aborts_on_one_denied_item(self):
        run(self.e, op="revoke", process="p1", handle=2)
        out = run(self.e, op="protected_io", op_id="op-b", process="p1",
                  items=[
                      {"handle": 1, "method": "write", "resource": "r1",
                       "payload": "a"},
                      {"handle": 2, "method": "write", "resource": "r2",
                       "payload": "b"},
                      {"handle": 3, "method": "write", "resource": "r3",
                       "payload": "c"},
                  ])
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["decision"], "deny")
        self.assertEqual(out["io_written"], [])
        self.assertFalse(out["receipt_written"])
        self.assertEqual(out["allowed_count"], 2)
        self.assertEqual(len(out["blockers"]), 1)
        blocker = out["blockers"][0]
        self.assertEqual(blocker["item_index"], 1)
        self.assertEqual(blocker["reason"], "HANDLE_REVOKED")
        self.assertEqual(blocker["blocking_generation"], 1)
        # nothing reached the audit
        self.assertEqual(run(self.e, op="io_audit")["io_count"], 0)

    def test_best_effort_writes_only_the_allowed_items(self):
        run(self.e, op="revoke", process="p1", handle=2)
        out = run(self.e, op="protected_io", op_id="op-c", process="p1",
                  mode="best_effort",
                  items=[
                      {"handle": 1, "method": "write", "resource": "r1",
                       "payload": "a"},
                      {"handle": 2, "method": "write", "resource": "r2",
                       "payload": "b"},
                      {"handle": 3, "method": "write", "resource": "r3",
                       "payload": "c"},
                  ])
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["allowed_count"], 2)
        self.assertEqual([w["handle"] for w in out["io_written"]], [1, 3])
        self.assertFalse(out["receipt_written"])

    def test_best_effort_still_needs_a_receipt_when_all_are_allowed(self):
        out = run(self.e, op="protected_io", op_id="op-d", process="p1",
                  mode="best_effort",
                  items=[
                      {"handle": 1, "method": "write", "resource": "r1",
                       "payload": "a"},
                      {"handle": 2, "method": "write", "resource": "r2",
                       "payload": "b"},
                  ])
        self.assertEqual(out["status"], "ok")
        self.assertTrue(out["receipt_written"])
        self.assertEqual(out["receipt"]["body"]["mode"], "best_effort")

    def test_denied_transaction_is_replayable_without_io(self):
        run(self.e, op="revoke", process="p1", handle=2)
        items = [
            {"handle": 1, "method": "write", "resource": "r1", "payload": "a"},
            {"handle": 2, "method": "write", "resource": "r2", "payload": "b"},
        ]
        first = run(self.e, op="protected_io", op_id="op-e", process="p1",
                    items=items)
        self.assertEqual(first["status"], "denied")
        # a retry of a denied transaction replays the stored denial even
        # though the reason for it no longer holds
        run(self.e, op="grant", process="p1", handle=2, resource="r2",
            rights=["write"])
        second = run(self.e, op="protected_io", op_id="op-e", process="p1",
                     items=items)
        self.assertTrue(second["replayed"])
        self.assertEqual(second["status"], "denied")
        self.assertEqual(second["io_written"], [])

    def test_unknown_handle_item_is_denied_not_written(self):
        """A missing handle with no resource must not be treated as allowed."""
        out = run(self.e, op="protected_io", op_id="op-m", process="p1",
                  items=[
                      {"handle": 1, "method": "write", "resource": "r1",
                       "payload": "a"},
                      {"handle": 77, "method": "write", "payload": "b"},
                  ])
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["io_written"], [])
        self.assertEqual(out["blockers"][0]["item_index"], 1)
        self.assertEqual(out["blockers"][0]["reason"], "HANDLE_NOT_FOUND")
        self.assertIsNone(out["blockers"][0]["blocking_generation"])
        self.assertEqual(run(self.e, op="io_audit")["io_count"], 0)

        partial = run(self.e, op="protected_io", op_id="op-n", process="p1",
                      mode="best_effort",
                      items=[
                          {"handle": 1, "method": "write", "resource": "r1",
                           "payload": "a"},
                          {"handle": 77, "method": "write", "payload": "b"},
                      ])
        self.assertEqual(partial["status"], "partial")
        self.assertEqual([w["handle"] for w in partial["io_written"]], [1])


class IdempotencyTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.e = Engine(self.db())
        self.addCleanup(self.e.close)
        run(self.e, op="set_clock", now_ms=1000)
        run(self.e, op="create_process", process="p1")
        run(self.e, op="create_resource", resource="r1", tenant="t1")
        run(self.e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"])

    def _items(self, payload="x"):
        return [{"handle": 1, "method": "write", "resource": "r1",
                 "payload": payload}]

    def test_duplicate_op_id_returns_first_committed_result(self):
        first = run(self.e, op="protected_io", op_id="dup", process="p1",
                    items=self._items("first"))
        self.assertEqual(first["status"], "ok")
        self.assertFalse(first["replayed"])
        digest = first["receipt"]["receipt_sha256"]

        # everything that could change the answer is changed
        run(self.e, op="revoke", process="p1", handle=1)
        run(self.e, op="set_clock", now_ms=5000)

        second = run(self.e, op="protected_io", op_id="dup", process="p1",
                     items=self._items("first"))
        self.assertTrue(second["replayed"])
        self.assertEqual(second["status"], "ok")
        self.assertEqual(second["txn_id"], first["txn_id"])
        self.assertEqual(second["receipt"]["receipt_sha256"], digest)
        self.assertEqual(second["replayed_at_ms"], 5000)
        self.assertFalse(second["replay_mismatch"])

        audit = run(self.e, op="io_audit")
        self.assertEqual(audit["io_count"], 1)
        self.assertEqual(audit["receipt_count"], 1)
        self.assertEqual(len(audit["transactions"]), 1)

    def test_replay_with_different_payload_is_flagged_not_recomputed(self):
        run(self.e, op="protected_io", op_id="dup2", process="p1",
            items=self._items("original"))
        replay = run(self.e, op="protected_io", op_id="dup2", process="p1",
                     items=self._items("changed"))
        self.assertTrue(replay["replayed"])
        self.assertTrue(replay["replay_mismatch"])
        self.assertEqual(replay["items"][0]["payload"], "original")
        self.assertEqual(run(self.e, op="io_audit")["io_count"], 1)

    def test_idempotency_survives_process_restart(self):
        run(self.e, op="protected_io", op_id="dup3", process="p1",
            items=self._items())
        self.e.close()
        e2 = Engine(self.db())
        self.addCleanup(e2.close)
        replay = run(e2, op="protected_io", op_id="dup3", process="p1",
                     items=self._items())
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["receipt"]["receipt_seq"], 1)

    def test_concurrent_duplicate_op_ids_commit_once(self):
        import threading

        results = []
        errors = []
        barrier = threading.Barrier(4)

        def worker():
            engine = Engine(self.db(), allow_faults=False)
            try:
                barrier.wait()
                results.append(
                    run(engine, op="protected_io", op_id="race", process="p1",
                        items=self._items())
                )
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)
            finally:
                engine.close()

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 4)
        txn_ids = {r["txn_id"] for r in results}
        self.assertEqual(len(txn_ids), 1, txn_ids)
        self.assertTrue(all(r["status"] == "ok" for r in results))
        replay_flags = [r["replayed"] for r in results]
        self.assertEqual(replay_flags.count(False), 1, replay_flags)
        self.assertEqual(run(self.e, op="io_audit")["io_count"], 1)


class PersistenceTests(TempDirCase):
    def test_state_survives_reopen(self):
        e = Engine(self.db())
        run(e, op="set_clock", now_ms=1000)
        run(e, op="create_process", process="p1")
        run(e, op="create_process", process="p2")
        run(e, op="create_resource", resource="r1", tenant="t1")
        run(e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"])
        run(e, op="transfer", parent={"process": "p1", "handle": 1},
            to_process="p2", handle=2, rights=["read"])
        e.close()

        e2 = Engine(self.db())
        self.addCleanup(e2.close)
        out = run(e2, op="check", process="p2", handle=2, method="read")
        self.assertEqual(out["decision"], "allow")
        self.assertEqual(out["clock"], 1000)
        self.assertEqual([h["generation"] for h in out["chain"]], [1, 1])

    def test_schema_is_idempotent(self):
        conn1 = connect(self.db())
        conn1.close()
        conn2 = connect(self.db())
        self.addCleanup(conn2.close)
        row = conn2.execute("SELECT value FROM meta WHERE key='schema_version'")
        self.assertEqual(row.fetchone()["value"], "1")

    def test_all_audit_tables_exist(self):
        conn = connect(self.db())
        self.addCleanup(conn.close)
        names = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for expected in (
            "processes",
            "resources",
            "sandboxes",
            "handles",
            "handle_sandboxes",
            "prechecks",
            "io_log",
            "transactions",
            "receipts",
            "decisions",
        ):
            self.assertIn(expected, names)


class DecisionAuditTests(TempDirCase):
    def test_every_denial_is_recorded_with_ancestor_generation(self):
        e = Engine(self.db())
        self.addCleanup(e.close)
        run(e, op="set_clock", now_ms=1000)
        run(e, op="create_process", process="p1")
        run(e, op="create_process", process="p2")
        run(e, op="create_resource", resource="r1", tenant="t1")
        run(e, op="grant", process="p1", handle=1, resource="r1",
            rights=["read", "write"])
        run(e, op="transfer", parent={"process": "p1", "handle": 1},
            to_process="p2", handle=2, rights=["read"])
        run(e, op="revoke", process="p1", handle=1)
        run(e, op="check", process="p2", handle=2, method="read")

        log = run(e, op="decision_log")
        check_rows = [d for d in log["decisions"] if d["op"] == "check"]
        self.assertEqual(len(check_rows), 1)
        row = check_rows[0]
        self.assertFalse(row["allowed"])
        self.assertEqual(row["code"], "E_HANDLE_REVOKED")
        self.assertEqual(row["blocker"]["reason"], "HANDLE_REVOKED")
        self.assertEqual(row["blocker"]["generation"], 1)
        self.assertEqual(row["blocking_ancestor"]["hop"], 1)
        self.assertEqual(row["blocking_ancestor"]["owner"], "p1")
        self.assertEqual(row["blocking_ancestor"]["generation"], 1)


if __name__ == "__main__":
    unittest.main()
