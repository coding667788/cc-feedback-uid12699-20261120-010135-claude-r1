"""Cross-check the SQLite engine against the independent reference model.

Each test drives a scenario through :class:`support.Mirror`, which feeds the
same steps to the engine and to ``tests/reference_model.py`` (a separate,
plain-Python transcription of the rules).  Every capability answer - allow/
deny, the primary blocker, the blocking ancestor and its exact generation -
must match.
"""

from __future__ import annotations

import os
import random
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

from support import Mirror, TempDirCase


class ScenarioCrosscheck(TempDirCase):
    def mirror(self):
        m = Mirror(self.db(), testcase=self)
        self.addCleanup(m.close)
        return m

    def test_read_write_swap_and_consumption(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=1000)
        m.step(op="create_process", process="p1")
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read"])
        m.step(op="grant", process="p1", handle=2, resource="r1",
               rights=["write"])
        for handle in (1, 2):
            for method in ("read", "write", "list"):
                m.compare_check(
                    {"op": "check", "process": "p1", "handle": handle,
                     "method": method}
                )
        m.step(op="revoke", process="p1", handle=1)
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["write"], generation=3)
        for handle, gen in ((1, None), (1, 3), (1, 1), (2, None)):
            for method in ("read", "write"):
                m.compare_check(
                    {"op": "check", "process": "p1", "handle": handle,
                     "generation": gen, "method": method}
                )

    def test_two_generations_same_handle_number(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=500)
        m.step(op="create_process", process="p1")
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="grant", process="p1", handle=9, resource="r1",
               rights=["read"])
        m.step(op="grant", process="p1", handle=9, resource="r1",
               rights=["read", "write"])
        for gen in (1, 2, None):
            for method in ("read", "write", "list"):
                m.compare_check(
                    {"op": "check", "process": "p1", "handle": 9,
                     "generation": gen, "method": method}
                )

    def test_multi_sandbox_with_one_tightened(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=1000)
        m.step(op="create_process", process="p1")
        m.step(op="create_process", process="p2")
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="create_sandbox", sandbox="A", rights=["read", "write", "list"])
        m.step(op="create_sandbox", sandbox="B", rights=["read", "write"])
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read", "write", "list"], sandboxes=["A", "B"])
        m.step(op="transfer", parent={"process": "p1", "handle": 1},
               to_process="p2", handle=2, rights=["read", "write"])
        m.step(op="tighten_sandbox", sandbox="A", rights=["read", "list"])
        for handle in (1, 2):
            for method in ("read", "write", "list"):
                m.compare_check(
                    {"op": "check", "process": "p1" if handle == 1 else "p2",
                     "handle": handle, "method": method}
                )

    def test_ancestor_keeps_read_loses_write(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=1000)
        for name in ("p1", "p2", "p3"):
            m.step(op="create_process", process=name)
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read", "write"])
        m.step(op="transfer", parent={"process": "p1", "handle": 1},
               to_process="p2", handle=1, rights=["read"])
        m.step(op="transfer", parent={"process": "p2", "handle": 1},
               to_process="p3", handle=1, rights=["read"])
        for owner in ("p1", "p2", "p3"):
            for method in ("read", "write", "list"):
                m.compare_check(
                    {"op": "check", "process": owner, "handle": 1,
                     "method": method}
                )

    def test_revoked_middle_ancestor(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=1000)
        for name in ("p1", "p2", "p3"):
            m.step(op="create_process", process=name)
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read", "write"])
        m.step(op="transfer", parent={"process": "p1", "handle": 1},
               to_process="p2", handle=1, rights=["read", "write"])
        m.step(op="transfer", parent={"process": "p2", "handle": 1},
               to_process="p3", handle=1, rights=["read"])
        m.step(op="revoke", process="p2", handle=1)
        m.compare_check({"op": "check", "process": "p3", "handle": 1,
                         "method": "read"})
        m.compare_check({"op": "check", "process": "p2", "handle": 1,
                         "method": "read"})
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "method": "read"})

    def test_restart_then_regrant(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=1000)
        m.step(op="create_process", process="p1")
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read", "write"])
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "method": "read"})
        m.step(op="restart_process", process="p1")
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "method": "read"})
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read"])
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "generation": 1, "method": "read"})
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "generation": 2, "method": "read"})

    def test_resource_rebuild_with_explicit_generation(self):
        m = self.mirror()
        m.step(op="set_clock", now_ms=1000)
        m.step(op="create_process", process="p1")
        m.step(op="create_resource", resource="r1", tenant="t1")
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read"])
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "method": "read"})
        m.step(op="rebuild_resource", resource="r1")
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "method": "read"})
        m.step(op="grant", process="p1", handle=1, resource="r1",
               rights=["read"])
        m.compare_check({"op": "check", "process": "p1", "handle": 1,
                         "method": "read"})


class RandomizedCrosscheck(TempDirCase):
    """A seeded random walk; the seed is fixed so failures reproduce."""

    def test_random_walk_matches_reference(self):
        rng = random.Random(20261120)
        m = Mirror(self.db(), testcase=self)
        self.addCleanup(m.close)
        m.step(op="set_clock", now_ms=1000)
        processes = ["p1", "p2", "p3", "p4"]
        resources = ["r1", "r2"]
        sandboxes = ["A", "B", "C"]
        for name in processes:
            m.step(op="create_process", process=name)
        for name in resources:
            m.step(op="create_resource", resource=name, tenant="t1")
        for name, rights in zip(sandboxes, (["read"], ["read", "write"],
                                            ["write", "list"])):
            m.step(op="create_sandbox", sandbox=name, rights=rights)

        granted = []  # (process, handle_no)
        for _ in range(80):
            choice = rng.random()
            if choice < 0.28:
                owner = rng.choice(processes)
                no = rng.randrange(1, 5)
                resource = rng.choice(resources)
                rights = rng.sample(["read", "write", "list"],
                                    rng.randrange(1, 4))
                tags = rng.sample(sandboxes, rng.randrange(0, 3))
                code, _ = m.try_step(op="grant", process=owner, handle=no,
                                     resource=resource, rights=rights,
                                     sandboxes=tags)
                if code is None:
                    granted.append((owner, no))
            elif choice < 0.50 and granted:
                owner, no = rng.choice(granted)
                h = m.model.find(owner, no)
                if h is None:
                    continue
                to = rng.choice(processes)
                rights = rng.sample(
                    ["read", "write", "list"],
                    rng.randrange(1, 4),
                )
                child_no = rng.randrange(1, 5)
                code, _ = m.try_step(
                    op="transfer",
                    parent={"process": owner, "handle": no},
                    to_process=to, handle=child_no, rights=rights,
                )
                if code is None:
                    granted.append((to, child_no))
            elif choice < 0.62 and granted:
                owner, no = rng.choice(granted)
                m.try_step(op="revoke", process=owner, handle=no)
            elif choice < 0.68:
                m.try_step(op="rebuild_resource",
                           resource=rng.choice(resources))
            elif choice < 0.74:
                m.try_step(op="restart_process",
                           process=rng.choice(processes))
            elif choice < 0.80:
                name = rng.choice(sandboxes)
                current = m.model.boxes.get(name)
                if current is None:
                    continue
                options = [
                    subset
                    for subset in (
                        [], ["read"], ["write"], ["list"],
                        ["read", "write"], ["read", "list"], ["write", "list"],
                    )
                    if _mask(subset) & ~current == 0 and _mask(subset) != current
                ]
                if not options:
                    continue
                m.try_step(op="tighten_sandbox", sandbox=name,
                           rights=rng.choice(options))
            elif choice < 0.86:
                m.step(op="set_clock", now_ms=m.model.clock + rng.randrange(0, 400))
            else:
                owner = rng.choice(processes)
                no = rng.randrange(1, 6)
                gen = rng.choice([None, 1, 2, 3])
                method = rng.choice(["read", "write", "list"])
                m.compare_check(
                    {"op": "check", "process": owner, "handle": no,
                     "generation": gen, "method": method}
                )

        # Final exhaustive sweep: every owner/slot/generation/method.
        checked = 0
        for owner in processes:
            for no in range(1, 6):
                for gen in (None, 1, 2, 3, 4):
                    for method in ("read", "write", "list"):
                        m.compare_check(
                            {"op": "check", "process": owner, "handle": no,
                             "generation": gen, "method": method}
                        )
                        checked += 1
        self.assertEqual(checked, 4 * 5 * 5 * 3)


def _mask(methods):
    bits = {"read": 1, "write": 2, "list": 4}
    out = 0
    for method in methods:
        out |= bits[method]
    return out


if __name__ == "__main__":
    unittest.main()
