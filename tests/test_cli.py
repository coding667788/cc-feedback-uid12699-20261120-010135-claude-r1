"""CLI-level tests for ``python -m solution``.

These assert on the concrete contents of ``result.json`` for the checked-in
``cases.json``: the exact decision, reason, hop and generation for the
interesting steps.  They are the executable form of the README's "measured
results" table.

Step labels are ``<case prefix>#<index>`` and are emitted by the CLI, so the
assertions stay readable and do not depend on list positions.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from support import TempDirCase


def run_cli(input_path, output_path, extra=()):
    return subprocess.run(
        [sys.executable, "-m", "solution", "--input", input_path,
         "--output", output_path, *extra],
        cwd=_ROOT,
        capture_output=True,
        text=True,
    )


class CliCase(TempDirCase):
    # The full corpus is replayed once per class; every test reads the same
    # result document.  The CLI itself is deterministic, which is asserted
    # separately.
    _shared = None

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls._shared_dir = tempfile.mkdtemp(prefix="sandbox-cli-")
        out_path = os.path.join(cls._shared_dir, "result.json")
        proc = run_cli(os.path.join(_ROOT, "cases.json"), out_path,
                       ("--db-dir", os.path.join(cls._shared_dir, "db")))
        assert proc.returncode == 0, proc.stderr
        with open(out_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for case in doc["cases"]:
            case["db"] = "<DB>"
        cls._shared = doc

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._shared_dir, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.out_path = os.path.join(self.tmp, "out.json")
        self.result = json.loads(json.dumps(self._shared))
        self.cases = {c["case_id"]: c for c in self.result["cases"]}
        self.input = {}
        with open(os.path.join(_ROOT, "cases.json"), encoding="utf-8") as fh:
            for case in json.load(fh)["cases"]:
                self.input[case["case_id"]] = case

    # -- helpers ---------------------------------------------------------
    def step(self, label):
        for case in self.result["cases"]:
            for entry in case["steps"]:
                if entry["label"] == label:
                    return entry
        raise AssertionError("no step labelled %r" % (label,))

    def ok(self, label):
        entry = self.step(label)
        self.assertTrue(entry["ok"], entry)
        return entry["result"]

    def err(self, label):
        entry = self.step(label)
        self.assertFalse(entry["ok"], entry)
        return entry["error"]["code"]

    # -- document shape --------------------------------------------------
    def test_output_shape(self):
        self.assertEqual(self.result["format"], "sandbox-service/1")
        self.assertEqual(len(self.result["cases"]), len(self.input))
        for case in self.result["cases"]:
            self.assertEqual(
                [s["step_index"] for s in case["steps"]],
                list(range(len(case["steps"]))),
            )
            source = self.input[case["case_id"]]["steps"]
            for entry, step in zip(case["steps"], source):
                self.assertEqual(entry["op"], step["op"])
                self.assertEqual(entry["label"], step["label"])
                self.assertIn("ok", entry)

    def test_cli_is_deterministic(self):
        first = os.path.join(self.tmp, "result1.json")
        second = os.path.join(self.tmp, "result2.json")
        for out in (first, second):
            proc = run_cli(os.path.join(_ROOT, "cases.json"), out,
                           ("--db-dir", os.path.join(out + ".db")))
            self.assertEqual(proc.returncode, 0, proc.stderr)
        docs = []
        for out in (first, second):
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
            for case in doc["cases"]:
                # The per-case ``db`` path is the only environment-dependent
                # value; the case_id and result content must not move.
                case["db"] = "<DB>"
            docs.append(doc)
        self.assertEqual(docs[0], docs[1])

    def test_cli_rejects_empty_input(self):
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"format": "sandbox-cases/1", "cases": []}, fh)
        proc = run_cli(bad, self.out_path)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("E_INVALID_REQUEST", proc.stderr)

    def test_cli_rejects_unknown_format(self):
        bad = os.path.join(self.tmp, "bad2.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"format": "other/9",
                       "cases": [{"case_id": "x", "steps": []}]}, fh)
        proc = run_cli(bad, self.out_path)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unsupported cases format", proc.stderr)

    def test_cli_rejects_duplicate_case_ids(self):
        bad = os.path.join(self.tmp, "bad3.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"format": "sandbox-cases/1",
                       "cases": [{"case_id": "x", "steps": []},
                                 {"case_id": "x", "steps": []}]}, fh)
        proc = run_cli(bad, self.out_path)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("duplicate case_id", proc.stderr)


class CaseExpectations(CliCase):
    """Concrete expected results for each scenario in cases.json."""

    def test_01_basic_allow_deny(self):
        self.assertEqual(self.ok("01#04")["decision"], "allow")
        self.assertEqual(self.ok("01#05")["decision"], "allow")
        denied = self.ok("01#06")
        self.assertEqual(denied["decision"], "deny")
        self.assertEqual(denied["blocker"]["reason"], "METHOD_NOT_GRANTED")
        self.assertEqual(denied["blocker"]["hop"], 0)
        self.assertEqual(denied["blocker"]["generation"], 1)
        self.assertEqual(self.ok("01#07")["decision"], "allow")
        tenant = self.ok("01#08")
        self.assertEqual(tenant["blocker"]["reason"], "TENANT_MISMATCH")
        self.assertEqual(tenant["blocker"]["generation"], 1)

    def test_02_transfer_attenuation(self):
        self.assertEqual(self.ok("02#07")["decision"], "allow")
        self.assertEqual(self.ok("02#08")["blocker"]["reason"],
                         "METHOD_NOT_GRANTED")
        grandchild = self.ok("02#09")
        self.assertEqual(grandchild["decision"], "allow")
        self.assertEqual(grandchild["effective_rights"], ["read"])
        self.assertEqual(
            [(h["owner"], h["generation"]) for h in grandchild["chain"]],
            [("p1", 1), ("p2", 1), ("p1", 1)],
        )
        self.assertEqual(self.ok("02#10")["blocker"]["reason"],
                         "METHOD_NOT_GRANTED")
        self.assertEqual(self.err("02#11"), "E_RIGHTS_ESCALATION")
        self.assertEqual(self.err("02#12"), "E_WINDOW_ESCALATION")
        self.assertEqual(self.ok("02#13")["status"], "ok")
        self.assertEqual(self.ok("02#14")["decision"], "allow")
        expired = self.ok("02#16")
        self.assertEqual(expired["blocker"]["reason"], "EXPIRED")
        self.assertEqual(expired["blocker"]["hop"], 0)

    def test_03_multi_sandbox(self):
        self.assertEqual(self.ok("03#07")["decision"], "allow")
        write = self.ok("03#08")
        self.assertEqual(write["blocker"]["reason"], "SANDBOX_DENIED")
        self.assertEqual(write["blocker"]["sandbox"], "sb_ro")
        self.assertEqual(write["blocker"]["sandbox_rights"], ["read", "list"])
        # sb_ro allows list; sb_all no longer does after tightening
        self.assertEqual(self.ok("03#09")["decision"], "allow")
        listed = self.ok("03#11")
        self.assertEqual(listed["blocker"]["sandbox"], "sb_all")
        self.assertEqual(listed["blocker"]["sandbox_rights"], ["read", "write"])
        # after tightening sb_all to write-only, read is denied by sb_all
        read = self.ok("03#13")
        self.assertEqual(read["blocker"]["sandbox"], "sb_all")
        self.assertEqual(self.err("03#16"), "E_SANDBOX_NOT_NARROWING")

    def test_04_restart(self):
        stale = self.ok("04#08")
        self.assertEqual(stale["blocker"]["reason"],
                         "SESSION_GENERATION_MISMATCH")
        self.assertEqual(stale["blocker"]["hop"], 1)
        self.assertEqual(stale["blocker"]["generation"], 1)
        self.assertEqual(stale["blocker"]["session_generation"], 1)
        self.assertEqual(stale["blocker"]["process_generation"], 2)
        ancestor = stale["blocking_ancestor"]
        self.assertEqual(
            (ancestor["owner"], ancestor["hop"], ancestor["generation"]),
            ("p1", 1, 1),
        )
        self.assertEqual(self.err("04#10"), "E_SESSION_STALE")

    def test_05_resource_rebuild(self):
        stale = self.ok("05#06")
        self.assertEqual(stale["blocker"]["reason"],
                         "RESOURCE_GENERATION_MISMATCH")
        self.assertEqual(stale["blocker"]["generation"], 1)
        self.assertEqual(stale["blocker"]["resource_generation"], 2)
        self.assertEqual(stale["blocker"]["handle_resource_generation"], 1)
        self.assertEqual(self.ok("05#08")["decision"], "allow")
        # the old generation is superseded by the rebuild-era re-grant
        old = self.ok("05#09")
        self.assertEqual(old["blocker"]["reason"], "HANDLE_SUPERSEDED")
        self.assertEqual(old["blocker"]["generation"], 1)

    def test_06_handle_number_reuse(self):
        slot = self.ok("06#05")
        self.assertEqual(slot["generation_count"], 2)
        self.assertEqual(slot["slot_max_generation"], 2)
        self.assertEqual(
            [(g["generation"], g["superseded"]) for g in slot["generations"]],
            [(1, True), (2, False)],
        )
        self.assertEqual(slot["generations"][0]["rights"], ["read"])
        self.assertEqual(slot["generations"][1]["rights"], ["read", "write"])
        old = self.ok("06#06")
        self.assertEqual(old["blocker"]["reason"], "HANDLE_SUPERSEDED")
        self.assertEqual(old["blocker"]["generation"], 1)
        self.assertEqual(old["blocker"]["newest_generation"], 2)
        self.assertEqual(self.ok("06#07")["decision"], "allow")
        self.assertEqual(self.err("06#08"), "E_GENERATION_CONFLICT")
        final_slot = self.ok("06#10")
        self.assertEqual(final_slot["generation_count"], 3)
        self.assertEqual(
            [g["generation"] for g in final_slot["generations"]], [1, 2, 9]
        )

    def test_07_parent_revoke(self):
        blocked = self.ok("07#10")
        self.assertEqual(blocked["decision"], "deny")
        self.assertEqual(blocked["blocker"]["reason"], "HANDLE_REVOKED")
        self.assertEqual(blocked["blocker"]["hop"], 1)
        self.assertEqual(blocked["blocker"]["owner"], "p2")
        self.assertEqual(blocked["blocker"]["generation"], 1)
        self.assertEqual(blocked["blocker"]["revoked_ms"], 1000)
        info = self.ok("07#11")
        self.assertFalse(info["structurally_valid"])
        self.assertEqual(info["chain_depth"], 3)
        self.assertEqual(
            [(h["owner"], h["generation"]) for h in info["chain"]],
            [("p3", 1), ("p2", 1), ("p1", 1)],
        )
        self.assertEqual(info["blocking_ancestor"]["generation"], 1)
        self.assertEqual(info["blocking_ancestor"]["revoked_ms"], 1000)
        self.assertEqual(self.ok("07#12")["blocker"]["hop"], 0)
        sibling = self.ok("07#14")
        self.assertEqual(sibling["decision"], "allow")

    def test_08_regrant_no_revival(self):
        self.assertEqual(self.ok("08#06")["blocker"]["reason"],
                         "HANDLE_REVOKED")
        old_gen = self.ok("08#08")
        self.assertEqual(old_gen["decision"], "deny")
        self.assertEqual(old_gen["blocker"]["reason"], "HANDLE_SUPERSEDED")
        self.assertEqual(old_gen["blocker"]["generation"], 1)
        new_gen = self.ok("08#09")
        self.assertEqual(new_gen["decision"], "allow")
        self.assertIsNone(new_gen["blocker"])
        slot = self.ok("08#10")
        self.assertEqual(
            [(g["generation"], g["superseded"], g["revoked"])
             for g in slot["generations"]],
            [(1, True, True), (2, False, False)],
        )

    def test_09_protected_io(self):
        first = self.ok("09#08")
        self.assertEqual(first["status"], "ok")
        self.assertEqual([w["handle"] for w in first["io_written"]], [1, 2, 3])
        self.assertTrue(first["receipt_written"])
        self.assertEqual(first["receipt"]["receipt_seq"], 1)
        self.assertEqual(len(first["receipt"]["receipt_sha256"]), 64)
        self.assertEqual(first["receipt"]["body"]["io_seqs"], [1, 2, 3])

        replay = self.ok("09#09")
        self.assertTrue(replay["replayed"])
        self.assertFalse(replay["replay_mismatch"])
        self.assertEqual(replay["txn_id"], first["txn_id"])
        self.assertEqual(replay["receipt"]["receipt_sha256"],
                         first["receipt"]["receipt_sha256"])

        denied = self.ok("09#11")
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(denied["allowed_count"], 2)
        self.assertEqual(denied["io_written"], [])
        self.assertFalse(denied["receipt_written"])
        self.assertEqual(len(denied["blockers"]), 1)
        self.assertEqual(denied["blockers"][0]["reason"], "HANDLE_REVOKED")
        self.assertEqual(denied["blockers"][0]["item_index"], 1)
        self.assertEqual(denied["blockers"][0]["blocking_generation"], 1)

        partial = self.ok("09#12")
        self.assertEqual(partial["status"], "partial")
        self.assertEqual([w["handle"] for w in partial["io_written"]], [1])
        self.assertEqual(partial["allowed_count"], 1)
        self.assertFalse(partial["receipt_written"])

        audit = self.ok("09#13")
        self.assertEqual(audit["io_count"], 4)
        self.assertEqual(audit["receipt_count"], 1)
        self.assertEqual(
            [(t["op_id"], t["state"]) for t in audit["transactions"]],
            [("txn-001", "committed"), ("txn-002", "denied"),
             ("txn-003", "committed")],
        )

    def test_10_precheck_staleness(self):
        stale = self.ok("10#09")
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["io_written"], [])
        self.assertFalse(stale["receipt_written"])
        self.assertEqual([b["reason"] for b in stale["blockers"]],
                         ["RESOURCE_GENERATION_MISMATCH"])

        fresh = self.ok("10#12")
        self.assertEqual(fresh["status"], "ok")
        self.assertEqual(len(fresh["io_written"]), 1)
        self.assertTrue(fresh["receipt_written"])

        self.assertEqual([b["reason"] for b in self.ok("10#13")["blockers"]],
                         ["PRECHECK_USED"])
        self.assertEqual(
            [b["reason"] for b in self.ok("10#16")["blockers"]],
            ["PRECHECK_EXPIRED"],
        )
        self.assertEqual(
            [b["reason"] for b in self.ok("10#17")["blockers"]],
            ["PRECHECK_NOT_FOUND"],
        )
        self.assertEqual(
            [b["reason"] for b in self.ok("10#19")["blockers"]],
            ["PRECHECK_MODE_MISMATCH"],
        )
        audit = self.ok("10#20")
        self.assertEqual(audit["io_count"], 1)
        self.assertEqual(audit["receipt_count"], 1)

    def test_11_rights_exchange(self):
        self.assertEqual(self.ok("11#06")["decision"], "allow")
        self.assertEqual(self.err("11#08"), "E_RIGHTS_ESCALATION")
        self.assertEqual(self.ok("11#09")["status"], "ok")
        write = self.ok("11#10")
        self.assertEqual(write["blocker"]["reason"], "METHOD_NOT_GRANTED")
        self.assertEqual(write["blocker"]["hop"], 0)
        self.assertEqual(self.ok("11#11")["decision"], "allow")

    def test_12_read_write_swap(self):
        for label in ("12#05", "12#06"):
            self.assertEqual(self.ok(label)["blocker"]["reason"],
                             "METHOD_NOT_GRANTED")
        self.assertEqual(self.ok("12#09")["decision"], "allow")
        self.assertEqual(self.ok("12#10")["blocker"]["reason"],
                         "METHOD_NOT_GRANTED")
        self.assertEqual(self.ok("12#10")["blocker"]["generation"], 3)
        self.assertEqual(self.ok("12#11")["decision"], "allow")

        first = self.ok("12#12")
        self.assertEqual(first["status"], "ok")
        self.assertEqual([i["handle"] for i in first["items"]], [1, 2])
        # same consumption id, opposite item order, after a resource rebuild
        replay = self.ok("12#14")
        self.assertTrue(replay["replayed"])
        self.assertTrue(replay["replay_mismatch"])
        self.assertEqual(replay["txn_id"], first["txn_id"])
        self.assertEqual([i["handle"] for i in replay["items"]], [1, 2])
        self.assertEqual(replay["receipt"]["receipt_sha256"],
                         first["receipt"]["receipt_sha256"])

    def test_13_sandbox_tightening(self):
        self.assertEqual(self.ok("13#05")["decision"], "allow")
        for label in ("13#07", "13#08"):
            out = self.ok(label)
            self.assertEqual(out["decision"], "deny")
            self.assertEqual(out["blocker"]["reason"], "SANDBOX_DENIED")
            self.assertEqual(out["blocker"]["sandbox"], "sb")
            self.assertEqual(out["blocker"]["sandbox_rights"], [])
        info = self.ok("13#09")
        self.assertTrue(info["structurally_valid"])
        self.assertEqual(info["handle"]["sandboxes"], {"sb": []})
        self.assertEqual(info["effective_rights"], [])

    def test_14_error_codes(self):
        expected = {
            4: "E_RESOURCE_NOT_FOUND",
            5: "E_SANDBOX_NOT_FOUND",
            6: "E_TIME_REGRESSION",
            7: "E_INVALID_REQUEST",
            8: "E_ALREADY_EXISTS",
            9: "E_HANDLE_NOT_FOUND",
            10: "E_INVALID_REQUEST",
            11: "E_INVALID_REQUEST",
            12: "E_UNKNOWN_OP",
        }
        for index, code in expected.items():
            self.assertEqual(self.err("14#%02d" % index), code, (index, code))
        # an unknown handle is a decision, not a request error
        unknown = self.ok("14#03")
        self.assertEqual(unknown["decision"], "deny")
        self.assertEqual(unknown["blocker"]["reason"], "HANDLE_NOT_FOUND")
        self.assertIsNone(unknown["blocker"]["generation"])


if __name__ == "__main__":
    unittest.main()
