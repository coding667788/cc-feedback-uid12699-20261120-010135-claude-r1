"""CLI: ``python -m solution --input cases.json --output result.json``.

Input format (``cases.json``)::

    {
      "format": "sandbox-cases/1",
      "cases": [
        {"case_id": "basic", "steps": [{"op": "...", ...}, ...]}
      ],
      "fault_cases": [ ... ]        # ignored by the CLI, used by tests
    }

Output format (``result.json``)::

    {
      "format": "sandbox-results/1",
      "cases": [
        {"case_id": "basic",
         "db": "<path to the SQLite file>",
         "steps": [{"step_index": 0, "op": "set_clock", "ok": true,
                    "result": {...}},
                   {"step_index": 1, "op": "grant", "ok": false,
                    "error": {"code": "E_...", "error": "..."}}]}
      ]
    }

The CLI is deterministic: no wall-clock time, no randomness, and the only
ordering used is input order.  Re-running the same input against fresh
databases produces a byte-identical output file (the ``db`` path is the only
value taken from the environment).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import traceback

from . import FORMAT_VERSION
from .engine import Engine
from .errors import E_INTERNAL, E_INVALID_REQUEST, EngineError


def run_case(case, db_path, allow_faults=False):
    case_id = case.get("case_id")
    steps = case.get("steps")
    if not isinstance(steps, list):
        raise EngineError(E_INVALID_REQUEST, "case.steps must be a list")
    if os.path.exists(db_path):
        os.remove(db_path)
    for suffix in ("-wal", "-shm"):
        if os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)
    engine = Engine(db_path, allow_faults=allow_faults)
    out_steps = []
    try:
        for index, step in enumerate(steps):
            op = step.get("op") if isinstance(step, dict) else None
            try:
                result = engine.run_step(step, case_id=case_id, step_index=index)
                out_steps.append(
                    {
                        "step_index": index,
                        "label": step.get("label") if isinstance(step, dict) else None,
                        "op": op,
                        "ok": True,
                        "result": result,
                    }
                )
            except EngineError as exc:
                out_steps.append(
                    {
                        "step_index": index,
                        "label": step.get("label") if isinstance(step, dict) else None,
                        "op": op,
                        "ok": False,
                        "error": exc.to_dict(),
                    }
                )
            except Exception as exc:  # pragma: no cover - defensive
                out_steps.append(
                    {
                        "step_index": index,
                        "label": step.get("label") if isinstance(step, dict) else None,
                        "op": op,
                        "ok": False,
                        "error": {
                            "code": E_INTERNAL,
                            "error": f"{type(exc).__name__}: {exc}",
                            "traceback": traceback.format_exc(limit=4),
                        },
                    }
                )
    finally:
        engine.close()
    return {"case_id": case_id, "db": db_path, "steps": out_steps}


def load_cases(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise EngineError(E_INVALID_REQUEST, "cases file must be a JSON object")
    fmt = doc.get("format")
    if fmt is not None and fmt != "sandbox-cases/1":
        raise EngineError(
            E_INVALID_REQUEST,
            f"unsupported cases format {fmt!r}",
            {"expected": "sandbox-cases/1"},
        )
    cases = doc.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EngineError(E_INVALID_REQUEST, "cases must be a non-empty list")
    seen = set()
    for case in cases:
        cid = case.get("case_id")
        if not isinstance(cid, str) or not cid:
            raise EngineError(E_INVALID_REQUEST, "each case needs a case_id")
        if cid in seen:
            raise EngineError(
                E_INVALID_REQUEST, f"duplicate case_id {cid!r}"
            )
        seen.add(cid)
    return doc


def default_db_dir(output_path):
    return output_path + ".db"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Offline sandbox capability-check service",
    )
    parser.add_argument("--input", required=True, help="path to cases.json")
    parser.add_argument("--output", required=True, help="path to result.json")
    parser.add_argument(
        "--db-dir",
        default=None,
        help="directory for per-case SQLite files (default: <output>.db)",
    )
    parser.add_argument(
        "--allow-faults",
        action="store_true",
        help="enable fault steps that terminate the process (tests only)",
    )
    parser.add_argument(
        "--keep-db",
        action="store_true",
        help="do not delete an existing per-case database before replay",
    )
    args = parser.parse_args(argv)

    try:
        doc = load_cases(args.input)
    except EngineError as exc:
        sys.stderr.write("input error: %s\n" % json.dumps(exc.to_dict()))
        return 2
    except OSError as exc:
        sys.stderr.write(f"cannot read input: {exc}\n")
        return 2
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"input is not valid JSON: {exc}\n")
        return 2

    db_dir = args.db_dir or default_db_dir(args.output)
    if not args.keep_db and os.path.isdir(db_dir):
        shutil.rmtree(db_dir)
    os.makedirs(db_dir, exist_ok=True)

    cases_out = []
    for case in doc["cases"]:
        db_path = os.path.join(db_dir, f"{case['case_id']}.sqlite3")
        cases_out.append(run_case(case, db_path, allow_faults=args.allow_faults))

    payload = {
        "format": FORMAT_VERSION,
        "input": os.path.basename(args.input),
        "cases": cases_out,
    }
    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
