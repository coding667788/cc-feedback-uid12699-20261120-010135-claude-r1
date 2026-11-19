"""Independent-process tests.

The requirement is that the service survives a *hard* kill at two specific
points, with state that is still auditable afterwards:

1. ``io_uncommitted`` - simulated I/O rows are in the WAL but the transaction
   has not committed.  A hard kill must leave no partial I/O *and* no
   transaction record that claims success.
2. ``committed_unacked`` - the commit succeeded, but the process dies before
   the caller sees the answer.  The retry must return the stored result.

``os._exit`` bypasses ``finally`` blocks, ``atexit`` and ``__del__``, so these
really are abrupt terminations rather than exceptions; the child scripts are
launched with ``subprocess`` and their exit statuses are asserted.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import sys
import textwrap
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from solution.engine import Engine
from solution.errors import EngineError

from support import TempDirCase

EXIT_UNCOMMITTED = 70
EXIT_COMMITTED_UNACKED = 71


class ChildProcessCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.db_path = self.db("crash.sqlite3")
        engine = Engine(self.db_path)
        for step in (
            {"op": "set_clock", "now_ms": 1000},
            {"op": "create_process", "process": "p1"},
            {"op": "create_resource", "resource": "r1", "tenant": "t1"},
            {"op": "create_resource", "resource": "r2", "tenant": "t1"},
            {"op": "grant", "process": "p1", "handle": 1, "resource": "r1",
             "rights": ["read", "write"]},
            {"op": "grant", "process": "p1", "handle": 2, "resource": "r2",
             "rights": ["read", "write"]},
        ):
            engine.run_step(step)
        engine.close()

    # -- helpers ---------------------------------------------------------
    def run_child(self, script, *args):
        return subprocess.run(
            [sys.executable, "-c", textwrap.dedent(script), self.db_path]
            + list(args),
            cwd=_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def audit(self):
        engine = Engine(self.db_path)
        try:
            return engine.run_step({"op": "io_audit"})
        finally:
            engine.close()

    # -- the two crash points -------------------------------------------
    def test_kill_before_commit_leaves_no_partial_io(self):
        child = """
            import os, sys
            sys.path.insert(0, os.getcwd())
            from solution.engine import Engine
            e = Engine(sys.argv[1], allow_faults=True)
            e.run_step({
                "op": "protected_io", "op_id": "crash-a", "process": "p1",
                "fault": "io_uncommitted",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "x"},
                    {"handle": 2, "method": "write", "resource": "r2",
                     "payload": "y"},
                ],
            })
            print("UNREACHABLE")
        """
        proc = self.run_child(child)
        self.assertEqual(proc.returncode, EXIT_UNCOMMITTED, proc.stderr)
        self.assertNotIn("UNREACHABLE", proc.stdout)

        audit = self.audit()
        self.assertEqual(audit["io_count"], 0)
        self.assertEqual(audit["receipt_count"], 0)
        self.assertEqual(audit["txn_count"], 0)

    def test_retry_after_uncommitted_crash_succeeds_and_commits_once(self):
        child = """
            import os, sys
            sys.path.insert(0, os.getcwd())
            from solution.engine import Engine
            e = Engine(sys.argv[1], allow_faults=True)
            e.run_step({
                "op": "protected_io", "op_id": "crash-b", "process": "p1",
                "fault": "io_uncommitted",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "x"},
                ],
            })
        """
        self.assertEqual(self.run_child(child).returncode, EXIT_UNCOMMITTED)

        engine = Engine(self.db_path)
        try:
            retry = engine.run_step({
                "op": "protected_io", "op_id": "crash-b", "process": "p1",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "x"},
                ],
            })
            audit = engine.run_step({"op": "io_audit"})
        finally:
            engine.close()

        # The crashed attempt wrote nothing, so this is a first execution, not
        # a replay - it must recompute and commit exactly once.
        self.assertFalse(retry["replayed"])
        self.assertEqual(retry["status"], "ok")
        self.assertEqual(retry["txn_id"], "T0001")
        self.assertTrue(retry["receipt_written"])
        self.assertEqual(audit["io_count"], 1)
        self.assertEqual(audit["receipt_count"], 1)
        self.assertEqual(len(audit["transactions"]), 1)

    def test_kill_after_commit_leaves_durable_receipt(self):
        child = """
            import os, sys
            sys.path.insert(0, os.getcwd())
            from solution.engine import Engine
            e = Engine(sys.argv[1], allow_faults=True)
            e.run_step({
                "op": "protected_io", "op_id": "crash-c", "process": "p1",
                "fault": "committed_unacked",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "x"},
                    {"handle": 2, "method": "write", "resource": "r2",
                     "payload": "y"},
                ],
            })
            print("UNREACHABLE")
        """
        proc = self.run_child(child)
        self.assertEqual(proc.returncode, EXIT_COMMITTED_UNACKED, proc.stderr)

        audit = self.audit()
        self.assertEqual(audit["io_count"], 2)
        self.assertEqual(audit["receipt_count"], 1)
        self.assertEqual(len(audit["transactions"]), 1)
        self.assertEqual(audit["transactions"][0]["state"], "committed")
        self.assertEqual(audit["transactions"][0]["op_id"], "crash-c")
        body = audit["receipts"][0]["body"]
        self.assertEqual(body["op_id"], "crash-c")
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual(len(audit["receipts"][0]["receipt_sha256"]), 64)

    def test_retry_after_committed_but_unacked_returns_stored_result(self):
        child = """
            import os, sys
            sys.path.insert(0, os.getcwd())
            from solution.engine import Engine
            e = Engine(sys.argv[1], allow_faults=True)
            e.run_step({
                "op": "protected_io", "op_id": "crash-d", "process": "p1",
                "fault": "committed_unacked",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "x"},
                ],
            })
        """
        self.assertEqual(self.run_child(child).returncode, EXIT_COMMITTED_UNACKED)
        before = self.audit()

        engine = Engine(self.db_path)
        try:
            # Capability state is changed between commit and retry; a correct
            # replay must not consult it at all.
            engine.run_step({"op": "revoke", "process": "p1", "handle": 1})
            retry = engine.run_step({
                "op": "protected_io", "op_id": "crash-d", "process": "p1",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "x"},
                ],
            })
            after = engine.run_step({"op": "io_audit"})
        finally:
            engine.close()

        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["status"], "ok")
        self.assertEqual(retry["replay_of_state"], "committed")
        self.assertEqual(retry["replayed_at_ms"], 1000)
        self.assertEqual(
            retry["receipt"]["receipt_sha256"],
            before["receipts"][0]["receipt_sha256"],
        )
        self.assertEqual(after["io_count"], before["io_count"])
        self.assertEqual(after["receipt_count"], 1)

    def test_faults_are_refused_without_the_flag(self):
        child = """
            import os, sys
            sys.path.insert(0, os.getcwd())
            from solution.engine import Engine
            from solution.errors import EngineError
            e = Engine(sys.argv[1])
            try:
                e.run_step({
                    "op": "protected_io", "op_id": "nope", "process": "p1",
                    "fault": "io_uncommitted",
                    "items": [
                        {"handle": 1, "method": "write", "resource": "r1"},
                    ],
                })
            except EngineError as exc:
                print(exc.code)
        """
        proc = self.run_child(child)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "E_FAULT_NOT_ALLOWED")


class ParallelReaderCase(TempDirCase):
    """A reader looping on one snapshot must never see a torn commit."""

    WRITER = """
        import os, sys
        sys.path.insert(0, os.getcwd())
        from solution.engine import Engine
        engine = Engine(sys.argv[1])
        for i in range(int(sys.argv[2])):
            out = engine.run_step({
                "op": "protected_io", "op_id": "par-%03d" % i,
                "process": "p1",
                "items": [
                    {"handle": 1, "method": "write", "resource": "r1",
                     "payload": "a%d" % i},
                    {"handle": 2, "method": "write", "resource": "r2",
                     "payload": "b%d" % i},
                ],
            })
            assert out["status"] == "ok", out
        engine.close()
        print("writer done")
    """

    READER = """
        import os, sys, json, time
        sys.path.insert(0, os.getcwd())
        from solution.engine import Engine
        engine = Engine(sys.argv[1])
        stop_file = sys.argv[2]
        samples = []
        # Keep sampling until the parent drops a stop file after the writer
        # exits, so the reader is guaranteed to overlap every commit.  The
        # hard deadline only bounds a hang.
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            samples.append(engine.run_step({"op": "snapshot_stats"}))
            if os.path.exists(stop_file):
                break
        engine.close()
        print(json.dumps(samples))
    """

    def test_reader_never_observes_partial_commit(self):
        db_path = self.db("parallel.sqlite3")
        engine = Engine(db_path)
        for step in (
            {"op": "set_clock", "now_ms": 1000},
            {"op": "create_process", "process": "p1"},
            {"op": "create_resource", "resource": "r1", "tenant": "t1"},
            {"op": "create_resource", "resource": "r2", "tenant": "t1"},
            {"op": "grant", "process": "p1", "handle": 1, "resource": "r1",
             "rights": ["read", "write"]},
            {"op": "grant", "process": "p1", "handle": 2, "resource": "r2",
             "rights": ["read", "write"]},
        ):
            engine.run_step(step)
        engine.close()

        stop_file = self.db("reader.stop")
        # Reader starts first and runs until told to stop, so it must span the
        # entire writer run.
        reader = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent(self.READER), db_path,
             stop_file],
            cwd=_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        time.sleep(0.3)
        writer = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent(self.WRITER), db_path, "150"],
            cwd=_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        writer_out, writer_err = writer.communicate(timeout=120)
        open(stop_file, "w").close()
        reader_out, reader_err = reader.communicate(timeout=120)

        self.assertEqual(writer.returncode, 0, writer_err)
        self.assertEqual(reader.returncode, 0, reader_err)
        self.assertEqual(writer_out.strip(), "writer done")

        samples = json.loads(reader_out)
        self.assertGreater(len(samples), 10)
        for sample in samples:
            # Invariant: every committed transaction has all of its I/O rows,
            # every receipt belongs to a transaction with I/O, and no
            # transaction is ever seen in a non-final state.
            self.assertEqual(sample["orphan_receipts"], 0, sample)
            self.assertEqual(sample["receipts"], sample["committed_transactions"],
                             sample)
            self.assertEqual(sample["io_rows"],
                             sample["committed_transactions"] * 2, sample)
            self.assertEqual(
                sample["transactions"],
                sample["committed_transactions"] + sample["denied_transactions"],
                sample,
            )
        # The reader must have seen it grow (both processes really overlapped).
        self.assertGreater(samples[-1]["transactions"],
                           samples[0]["transactions"])

        final = Engine(db_path)
        try:
            audit = final.run_step({"op": "io_audit"})
        finally:
            final.close()
        self.assertEqual(audit["receipt_count"], 150)
        self.assertEqual(audit["io_count"], 300)


if __name__ == "__main__":
    unittest.main()
