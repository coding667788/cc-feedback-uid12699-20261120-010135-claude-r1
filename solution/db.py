"""SQLite persistence for the sandbox capability service.

The database is a single file and holds every durable fact: simulated
processes and their session generations, resources and their generations,
sandboxes and their currently allowed method masks, the full capability
handle graph, preflight snapshots, the simulated I/O audit and the simulated
business receipts.

Isolation notes
---------------
``connect()`` opens with ``isolation_level=None`` so that every transaction
boundary is explicit.  Writers use ``BEGIN IMMEDIATE``; that makes lock
acquisition deterministic and lets a second writer block (up to the busy
timeout) instead of failing with a deferred-lock upgrade error.

Readers that need more than one query to be consistent hold a
:class:`ReadSnapshot`, which keeps a single read transaction open.  On WAL
that pins a snapshot at one commit, so a reader can never observe a
half-applied multi-resource commit.
"""

from __future__ import annotations

import os
import sqlite3

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clock (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    now_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    name         TEXT PRIMARY KEY,
    generation   INTEGER NOT NULL,
    alive        INTEGER NOT NULL,
    created_ms   INTEGER NOT NULL,
    restarted_ms INTEGER
);

CREATE TABLE IF NOT EXISTS resources (
    name        TEXT PRIMARY KEY,
    tenant      TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    rights_mask INTEGER NOT NULL,
    rebuilds    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sandboxes (
    name        TEXT PRIMARY KEY,
    rights_mask INTEGER NOT NULL,
    created_ms  INTEGER NOT NULL,
    updated_ms  INTEGER NOT NULL,
    updates     INTEGER NOT NULL DEFAULT 0
);

-- One row per logical handle generation.  (owner, handle_no, generation) is
-- the handle's exact identity; (owner, handle_no) is the recyclable slot.
CREATE TABLE IF NOT EXISTS handles (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    owner            TEXT    NOT NULL,
    handle_no        INTEGER NOT NULL,
    generation       INTEGER NOT NULL,
    parent_handle_id INTEGER,
    resource         TEXT    NOT NULL,
    resource_gen     INTEGER NOT NULL,
    rights_mask      INTEGER NOT NULL,
    session_gen      INTEGER NOT NULL,
    not_before       INTEGER NOT NULL,
    not_after        INTEGER NOT NULL,
    created_ms       INTEGER NOT NULL,
    revoked_ms       INTEGER,
    UNIQUE (owner, handle_no, generation),
    FOREIGN KEY (parent_handle_id) REFERENCES handles(id)
);

CREATE INDEX IF NOT EXISTS handles_by_slot   ON handles(owner, handle_no);
CREATE INDEX IF NOT EXISTS handles_by_parent ON handles(parent_handle_id);

-- Sandbox membership stores only the name; the mask is read live, which is
-- what makes a later sandbox tightening apply to already-issued handles.
CREATE TABLE IF NOT EXISTS handle_sandboxes (
    handle_id INTEGER NOT NULL,
    sandbox   TEXT    NOT NULL,
    PRIMARY KEY (handle_id, sandbox),
    FOREIGN KEY (handle_id) REFERENCES handles(id)
);

CREATE TABLE IF NOT EXISTS prechecks (
    token             TEXT PRIMARY KEY,
    process           TEXT NOT NULL,
    item_json         TEXT NOT NULL,
    snapshot_json     TEXT NOT NULL,
    expires_at        INTEGER NOT NULL,
    observed_clock_ms INTEGER NOT NULL,
    created_ms        INTEGER NOT NULL,
    used_ms           INTEGER,
    used_by_op        TEXT
);

CREATE TABLE IF NOT EXISTS io_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    txn_id      TEXT    NOT NULL,
    op_id       TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    item_index  INTEGER NOT NULL,
    handle_id   INTEGER NOT NULL,
    handle_no   INTEGER NOT NULL,
    handle_gen  INTEGER NOT NULL,
    resource    TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    payload_json TEXT   NOT NULL,
    created_ms  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS io_by_op  ON io_log(op_id, seq);
CREATE INDEX IF NOT EXISTS io_by_txn ON io_log(txn_id, seq);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id       TEXT PRIMARY KEY,
    op_id        TEXT NOT NULL,
    mode         TEXT NOT NULL,
    state        TEXT NOT NULL,
    item_count   INTEGER NOT NULL,
    abort_code   TEXT,
    blocked_json TEXT,
    fault        TEXT,
    result_json  TEXT,
    started_ms   INTEGER NOT NULL,
    finished_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS txn_by_op ON transactions(op_id, state);

CREATE TABLE IF NOT EXISTS receipts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    txn_id         TEXT    NOT NULL,
    op_id          TEXT    NOT NULL,
    seq            INTEGER NOT NULL,
    receipt_json   TEXT    NOT NULL,
    receipt_sha256 TEXT    NOT NULL,
    created_ms     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS receipts_by_op ON receipts(op_id, seq);

-- One row for every capability decision taken by any op.  This is the
-- durable answer to "which ancestor and which exact generation blocked it".
CREATE TABLE IF NOT EXISTS decisions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id             TEXT,
    step_index          INTEGER,
    op                  TEXT    NOT NULL,
    subject_json        TEXT    NOT NULL,
    allowed             INTEGER NOT NULL,
    code                TEXT,
    blocker_reason      TEXT,
    blocker_hop         INTEGER,
    blocker_owner       TEXT,
    blocker_handle      INTEGER,
    blocker_generation  INTEGER,
    ancestor_reason     TEXT,
    ancestor_hop        INTEGER,
    ancestor_owner      TEXT,
    ancestor_handle     INTEGER,
    ancestor_generation INTEGER,
    clock_ms            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS decisions_by_step ON decisions(case_id, step_index);
"""

COUNTER_DEFAULTS = {"txn_seq": "0", "receipt_seq": "0", "precheck_seq": "0"}


def connect(path: str) -> sqlite3.Connection:
    """Open (and migrate) the database.  ``:memory:`` is supported for tests."""
    is_memory = path == ":memory:"
    if not is_memory:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if not is_memory:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
    elif int(row["value"]) != SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported schema version {row['value']!r}, expected {SCHEMA_VERSION}"
        )
    if conn.execute("SELECT 1 FROM clock WHERE id=1").fetchone() is None:
        conn.execute("INSERT INTO clock(id, now_ms) VALUES(1, 0)")
    for key, default in COUNTER_DEFAULTS.items():
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)", (key, default)
        )
    return conn


def read_clock(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT now_ms FROM clock WHERE id=1").fetchone()["now_ms"])


def next_counter(conn: sqlite3.Connection, key: str) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    value = int(row["value"]) + 1
    conn.execute("UPDATE meta SET value=? WHERE key=?", (str(value), key))
    return value


class ReadSnapshot:
    """Keeps one read transaction open so all queries see the same commit."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        conn.execute("BEGIN")

    def close(self) -> None:
        self.conn.execute("COMMIT")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
