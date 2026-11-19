"""Stable error codes and the exception used for request-level failures.

Two different things are reported by the service:

* a **request error** - the request could not be executed (bad input, duplicate
  id, unknown handle slot, ...).  It raises :class:`EngineError` and comes back
  as ``{"ok": false, "code": "E_...", "error": "..."}``.
* an **authorization denial** - the request ran fine but a capability check
  said no.  It comes back as a normal step result with ``decision: "deny"``,
  a ``blocker`` naming the exact blocking handle generation, and a ``code``.

Both use the same code vocabulary so callers do not need two tables.
"""

OK = "OK"

# --- request level -----------------------------------------------------------
E_INVALID_REQUEST = "E_INVALID_REQUEST"
E_UNKNOWN_OP = "E_UNKNOWN_OP"
E_ALREADY_EXISTS = "E_ALREADY_EXISTS"
E_TIME_REGRESSION = "E_TIME_REGRESSION"
E_GENERATION_CONFLICT = "E_GENERATION_CONFLICT"
E_FAULT_NOT_ALLOWED = "E_FAULT_NOT_ALLOWED"
E_FAULT_INJECTED = "E_FAULT_INJECTED"
E_INTERNAL = "E_INTERNAL"

# --- state lookup ------------------------------------------------------------
E_PROCESS_NOT_FOUND = "E_PROCESS_NOT_FOUND"
E_PROCESS_DEAD = "E_PROCESS_DEAD"
E_RESOURCE_NOT_FOUND = "E_RESOURCE_NOT_FOUND"
E_SANDBOX_NOT_FOUND = "E_SANDBOX_NOT_FOUND"
E_HANDLE_NOT_FOUND = "E_HANDLE_NOT_FOUND"
E_TENANT_MISMATCH = "E_TENANT_MISMATCH"

# --- capability denials ------------------------------------------------------
E_HANDLE_REVOKED = "E_HANDLE_REVOKED"
E_HANDLE_SUPERSEDED = "E_HANDLE_SUPERSEDED"
E_SESSION_STALE = "E_SESSION_STALE"
E_RESOURCE_GENERATION_MISMATCH = "E_RESOURCE_GENERATION_MISMATCH"
E_METHOD_NOT_GRANTED = "E_METHOD_NOT_GRANTED"
E_ANCESTOR_MISSING_RIGHT = "E_ANCESTOR_MISSING_RIGHT"
E_RESOURCE_METHOD_UNSUPPORTED = "E_RESOURCE_METHOD_UNSUPPORTED"
E_NOT_YET_VALID = "E_NOT_YET_VALID"
E_EXPIRED = "E_EXPIRED"
E_SANDBOX_DENIED = "E_SANDBOX_DENIED"
E_PARENT_MISSING = "E_PARENT_MISSING"
E_HANDLE_NOT_OWNED = "E_HANDLE_NOT_OWNED"
E_RESOURCE_MISMATCH = "E_RESOURCE_MISMATCH"

# --- attenuation (grant / transfer) -----------------------------------------
E_RIGHTS_ESCALATION = "E_RIGHTS_ESCALATION"
E_WINDOW_ESCALATION = "E_WINDOW_ESCALATION"
E_SANDBOX_NOT_NARROWING = "E_SANDBOX_NOT_NARROWING"
E_NO_RIGHTS = "E_NO_RIGHTS"

# --- precheck snapshots ------------------------------------------------------
E_PRECHECK_NOT_FOUND = "E_PRECHECK_NOT_FOUND"
E_PRECHECK_USED = "E_PRECHECK_USED"
E_PRECHECK_EXPIRED = "E_PRECHECK_EXPIRED"
E_PRECHECK_MODE_MISMATCH = "E_PRECHECK_MODE_MISMATCH"
E_PRECHECK_STALE = "E_PRECHECK_STALE"

# Denial reason (stable, machine readable) -> public error code.
REASON_CODES = {
    "HANDLE_NOT_FOUND": E_HANDLE_NOT_FOUND,
    "HANDLE_SUPERSEDED": E_HANDLE_SUPERSEDED,
    "HANDLE_REVOKED": E_HANDLE_REVOKED,
    "PROCESS_NOT_FOUND": E_PROCESS_NOT_FOUND,
    "PROCESS_DEAD": E_PROCESS_DEAD,
    "SESSION_GENERATION_MISMATCH": E_SESSION_STALE,
    "RESOURCE_NOT_FOUND": E_RESOURCE_NOT_FOUND,
    "RESOURCE_GENERATION_MISMATCH": E_RESOURCE_GENERATION_MISMATCH,
    "TENANT_MISMATCH": E_TENANT_MISMATCH,
    "METHOD_NOT_GRANTED": E_METHOD_NOT_GRANTED,
    "ANCESTOR_MISSING_RIGHT": E_ANCESTOR_MISSING_RIGHT,
    "RESOURCE_METHOD_UNSUPPORTED": E_RESOURCE_METHOD_UNSUPPORTED,
    "NOT_YET_VALID": E_NOT_YET_VALID,
    "EXPIRED": E_EXPIRED,
    "SANDBOX_DENIED": E_SANDBOX_DENIED,
    "PARENT_MISSING": E_PARENT_MISSING,
    "RESOURCE_MISMATCH": E_RESOURCE_MISMATCH,
    "HANDLE_NOT_OWNED": E_HANDLE_NOT_OWNED,
    "CYCLE_DETECTED": E_INTERNAL,
}


class EngineError(Exception):
    """A request-level failure (as opposed to a capability denial)."""

    def __init__(self, code, message, detail=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_dict(self):
        out = {"code": self.code, "error": self.message}
        if self.detail is not None:
            out["detail"] = self.detail
        return out
