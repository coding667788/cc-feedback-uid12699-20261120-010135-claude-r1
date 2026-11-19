"""Shared test helpers.

* :class:`TempDirCase` - per-test scratch directory.
* :class:`Mirror` - drives one ``Engine`` and one independent
  :class:`reference_model.RefModel` from the same steps and compares every
  capability answer.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from solution.engine import Engine
from solution.errors import EngineError

from reference_model import RefError, RefModel


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sandbox-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def db(self, name="state.sqlite3"):
        return os.path.join(self.tmp, name)


class Mirror:
    """Runs steps against the engine and the reference model in lockstep.

    The model is fed only from the step text, never from engine output, so any
    agreement is evidence that the two implementations independently agree.
    """

    def __init__(self, db_path, allow_faults=False, testcase=None):
        self.engine = Engine(db_path, allow_faults=allow_faults)
        self.model = RefModel()
        self.tc = testcase or unittest.TestCase()

    def close(self):
        self.engine.close()

    # -- step execution ---------------------------------------------------
    def try_step(self, step=None, **fields):
        """Run one step where either side may legitimately reject it.

        Returns ``(code_or_None, engine_result)``.  The two sides must agree
        on both *whether* the step failed and on the error code; that is the
        interesting property for a random walk that deliberately probes
        invalid requests.
        """
        if step is None:
            step = fields
        engine_result = None
        engine_code = None
        try:
            engine_result = self.engine.run_step(step)
        except EngineError as exc:
            engine_code = exc.code
        model_code = None
        try:
            self._model_apply(step)
        except RefError as exc:
            model_code = exc.code
        self.tc.assertEqual(
            engine_code,
            model_code,
            "engine/model disagreed on rejection for step %r" % (step,),
        )
        return engine_code, engine_result

    def step(self, step=None, expect_error=None, **fields):
        """Run one step on both sides.

        ``expect_error`` is an engine error code; the model must raise the
        same code.  Returns the engine result (or None on expected error).
        """
        if step is None:
            step = fields
        engine_result = None
        engine_error = None
        try:
            engine_result = self.engine.run_step(step)
        except EngineError as exc:
            engine_error = exc
        model_error = None
        try:
            self._model_apply(step)
        except RefError as exc:
            model_error = exc

        if expect_error is not None:
            self.tc.assertEqual(
                engine_error.code if engine_error else None,
                expect_error,
                "engine should raise %s, got %r" % (
                    expect_error,
                    engine_error.code if engine_error else engine_result,
                ),
            )
            self.tc.assertEqual(
                model_error.code if model_error else None,
                expect_error,
                "model should raise %s, got %r" % (
                    expect_error,
                    model_error.code if model_error else "success",
                ),
            )
            return None
        if engine_error is not None:
            raise AssertionError(
                "unexpected engine error %s: %s (step=%r)"
                % (engine_error.code, engine_error.message, step)
            )
        if model_error is not None:
            raise AssertionError(
                "unexpected model error %s: %s (step=%r)"
                % (model_error.code, model_error.message, step)
            )
        return engine_result

    def _model_apply(self, step):
        op = step["op"]
        m = self.model
        if op == "set_clock":
            m.set_clock(step["now_ms"])
        elif op == "create_process":
            m.create_process(step["process"])
        elif op == "restart_process":
            m.restart_process(step["process"])
        elif op == "create_resource":
            m.create_resource(
                step["resource"], step["tenant"], step.get("rights", ["read", "write", "list"])
            )
        elif op == "rebuild_resource":
            m.rebuild_resource(step["resource"])
        elif op == "create_sandbox":
            m.create_sandbox(step["sandbox"], step["rights"])
        elif op == "tighten_sandbox":
            m.tighten_sandbox(step["sandbox"], step["rights"])
        elif op == "grant":
            m.grant(
                step["process"],
                step["handle"],
                step["resource"],
                step["rights"],
                step.get("sandboxes", []),
                step.get("not_before"),
                step.get("not_after"),
                step.get("generation"),
            )
        elif op == "transfer":
            parent = step["parent"]
            parent_h = m.find(
                parent["process"], parent["handle"], parent.get("generation")
            )
            if parent_h is None:
                raise RefError("E_HANDLE_NOT_FOUND", "parent")
            m.transfer(
                parent_h,
                step["to_process"],
                step["handle"],
                step.get("rights"),
                step.get("not_before"),
                step.get("not_after"),
                step.get("sandboxes", []),
                step.get("generation"),
            )
        elif op == "revoke":
            target = m.find(
                step["process"], step["handle"], step.get("generation")
            )
            if target is None:
                raise RefError("E_HANDLE_NOT_FOUND", "handle")
            m.revoke(target)
        elif op in ("check", "precheck", "protected_io", "handle_info"):
            pass  # no state change in the model
        else:
            raise AssertionError("mirror does not model op %r" % op)

    # -- comparison -------------------------------------------------------
    def compare_check(self, step):
        """Run ``check`` on both sides and compare the full report."""
        result = self.engine.run_step(step)
        model = self.model.check(
            step["process"],
            step["handle"],
            step.get("generation"),
            step["resource"]
            if "resource" in step
            else self._leaf_resource(step),
            step["method"],
            step.get("tenant"),
        )
        self._assert_same_report(step, result, model)
        return result

    def _leaf_resource(self, step):
        h = self.model.find(step["process"], step["handle"], step.get("generation"))
        return h.resource if h else None

    def _assert_same_report(self, step, result, model):
        engine_failures = [
            (f["reason"], f.get("hop", 0), f.get("generation"), f.get("sandbox"))
            for f in result["failures"]
        ]
        model_failures = [
            (f["reason"], f.get("hop", 0), f.get("generation"), f.get("sandbox"))
            for f in model["failures"]
        ]
        self.tc.assertEqual(
            engine_failures,
            model_failures,
            "failure lists disagree for step %r\nengine=%r\nmodel=%r"
            % (step, engine_failures, model_failures),
        )
        self.tc.assertEqual(
            result["decision"] == "allow",
            model["allowed"],
            "allow/deny disagree for step %r\nengine=%r\nmodel=%r"
            % (step, result, model),
        )
        eb = result["blocker"]
        mb = model["blocker"]
        if mb is None:
            self.tc.assertIsNone(eb)
        else:
            self.tc.assertIsNotNone(eb)
            self.tc.assertEqual(eb["reason"], mb["reason"], step)
            self.tc.assertEqual(eb.get("hop", 0), mb.get("hop", 0), step)
            self.tc.assertEqual(eb.get("generation"), mb.get("generation"), step)
        ea = result["blocking_ancestor"]
        ma = model["blocking_ancestor"]
        if ma is None:
            self.tc.assertIsNone(ea, step)
        else:
            self.tc.assertIsNotNone(ea, step)
            self.tc.assertEqual(ea["reason"], ma["reason"], step)
            self.tc.assertEqual(ea.get("hop"), ma.get("hop"), step)
            self.tc.assertEqual(ea.get("generation"), ma.get("generation"), step)
