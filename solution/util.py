"""Small deterministic helpers shared by the engine, CLI and tests."""

from __future__ import annotations

import hashlib
import json

from .errors import E_INVALID_REQUEST, E_NO_RIGHTS, EngineError

# Canonical method order.  Masks: read=1, write=2, list=4.
METHODS = ("read", "write", "list")
METHOD_BITS = {"read": 1, "write": 2, "list": 4}
ALL_MASK = 7


def canonical(obj) -> str:
    """Canonical JSON used for every digest in the system."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(obj) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def methods_to_mask(value, field="rights", allow_empty=False) -> int:
    if not isinstance(value, list):
        raise EngineError(E_INVALID_REQUEST, f"{field} must be a list of method names")
    mask = 0
    for item in value:
        if not isinstance(item, str) or item not in METHOD_BITS:
            raise EngineError(
                E_INVALID_REQUEST,
                f"{field} contains unknown method {item!r}",
                {"allowed": list(METHODS)},
            )
        mask |= METHOD_BITS[item]
    if mask == 0 and not allow_empty:
        raise EngineError(E_NO_RIGHTS, f"{field} must grant at least one method")
    return mask

def mask_to_methods(mask: int) -> list[str]:
    return [m for m in METHODS if mask & METHOD_BITS[m]]


def require_str(step, key, allow_none=False):
    value = step.get(key)
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or value == "":
        raise EngineError(E_INVALID_REQUEST, f"{key} must be a non-empty string")
    return value


def require_int(step, key, allow_none=False):
    value = step.get(key)
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise EngineError(E_INVALID_REQUEST, f"{key} must be an integer")
    return value


def optional_int(step, key):
    return require_int(step, key, allow_none=True)


def require_bool(step, key, default=None):
    value = step.get(key, default)
    if not isinstance(value, bool):
        raise EngineError(E_INVALID_REQUEST, f"{key} must be a boolean")
    return value


def require_dict(step, key, allow_none=True):
    value = step.get(key)
    if value is None and allow_none:
        return None
    if not isinstance(value, dict):
        raise EngineError(E_INVALID_REQUEST, f"{key} must be an object")
    return value


def handle_ref(process: str, handle_no: int, generation: int | None) -> dict:
    return {"process": process, "handle": handle_no, "generation": generation}
