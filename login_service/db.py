"""SQLite storage. Every query uses ``?`` parameters; no value is ever put into SQL text.
One connection shared by Waitress' threads, guarded by a lock."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,          -- the OIDC "sub": random, never reused, never changes
    username      TEXT NOT NULL UNIQUE,      -- lower case: a-z 0-9 . _ - (users.USERNAME_RE)
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',  -- '' until the invitation is used
    is_admin      INTEGER NOT NULL DEFAULT 0,
    disabled      INTEGER NOT NULL DEFAULT 0,
    totp_secret   TEXT NOT NULL DEFAULT '',  -- encrypted (crypto_box); '' = no 2FA
    totp_last_step INTEGER NOT NULL DEFAULT 0, -- last accepted time step: a code works once
    invite_hash   TEXT NOT NULL DEFAULT '',  -- sha256 of the one-time invitation / reset token
    invite_expires INTEGER NOT NULL DEFAULT 0,
    created       INTEGER NOT NULL,
    last_login    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    sid        TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created    INTEGER NOT NULL,
    amr        TEXT NOT NULL                -- "pwd" or "pwd otp"
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS pw_sessions (       -- admin-password sessions (not a user; can't sign in to apps)
    sid        TEXT PRIMARY KEY,
    created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    client_id      TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    secret_hash    TEXT NOT NULL,            -- sha256 of the client secret (shown once)
    redirect_uris  TEXT NOT NULL,            -- JSON list; matched EXACTLY
    logout_uris    TEXT NOT NULL,            -- JSON list: allowed post_logout_redirect_uri values
    backchannel_uri TEXT NOT NULL DEFAULT '',-- back-channel logout endpoint ('' = none)
    created        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sid            TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    challenge      TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    scope          TEXT NOT NULL,
    auth_time      INTEGER NOT NULL,
    amr            TEXT NOT NULL,
    expires        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS backchannel_outbox (  -- logout notices to apps, retried until delivered
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    sid        TEXT NOT NULL DEFAULT '',  -- '' = every sign-in of the user (blocked, reset, deleted)
    attempts   INTEGER NOT NULL DEFAULT 0,
    next_try   INTEGER NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY,
    sid        TEXT NOT NULL DEFAULT '',   -- the sign-in it was issued for (revoked on sign-out)
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    expires    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_clients (   -- which apps a sign-in was used for (back-channel logout)
    sid        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    PRIMARY KEY (sid, client_id)
);
"""


class Database:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path or ":memory:", check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if path:
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            return self._conn.execute(sql, params).rowcount

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, params).fetchone()
            return row

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def checkpoint(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
