"""SQLite 永続化レイヤ。単一接続 + ロックでスレッドセーフに扱う。"""
import json
import os
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get("SHSW_DB_PATH", "/data/shsw.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    action TEXT NOT NULL DEFAULT 'block',
    patterns TEXT NOT NULL DEFAULT '[]',
    schedule_mode TEXT NOT NULL DEFAULT 'always',
    windows TEXT NOT NULL DEFAULT '[]',
    override_state TEXT,
    override_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token TEXT NOT NULL,
    action TEXT NOT NULL,
    policy_ids TEXT NOT NULL DEFAULT '[]',
    duration_minutes INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    fire_count INTEGER NOT NULL DEFAULT 0,
    last_fired_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS block_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    client TEXT,
    method TEXT,
    scheme TEXT,
    host TEXT,
    path TEXT,
    policy_id INTEGER,
    policy_name TEXT
);
CREATE INDEX IF NOT EXISTS idx_block_events_ts ON block_events(ts);
CREATE TABLE IF NOT EXISTS trigger_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    trigger_id INTEGER,
    trigger_name TEXT,
    action TEXT,
    source TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS issued_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial TEXT NOT NULL,
    common_name TEXT NOT NULL,
    sans TEXT NOT NULL DEFAULT '[]',
    not_after TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    hint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    last_used_from TEXT,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS passes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    patterns TEXT NOT NULL DEFAULT '[]',
    default_seconds INTEGER NOT NULL DEFAULT 300,
    max_seconds INTEGER NOT NULL DEFAULT 3600,
    daily_limit_seconds INTEGER,
    token TEXT NOT NULL,
    unlocked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pass_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pass_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_pass_sessions ON pass_sessions(pass_id, ends_at);
CREATE TABLE IF NOT EXISTS pass_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    pass_id INTEGER,
    pass_name TEXT,
    action TEXT NOT NULL,
    seconds INTEGER,
    source TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def init() -> None:
    global _conn
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA busy_timeout=5000")  # CLI など別プロセスからの同時書き込み対策
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.execute("PRAGMA foreign_keys=ON")
    _conn.executescript(SCHEMA)


@contextmanager
def tx():
    """トランザクション付きでカーソルを返す。"""
    with _lock:
        assert _conn is not None
        cur = _conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            cur.execute("COMMIT")
        except BaseException:
            cur.execute("ROLLBACK")
            raise


def query(sql: str, params: tuple = ()) -> list[dict]:
    with _lock:
        assert _conn is not None
        return [dict(r) for r in _conn.execute(sql, params).fetchall()]


def query_one(sql: str, params: tuple = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: tuple = ()) -> int:
    with tx() as cur:
        cur.execute(sql, params)
        return cur.lastrowid


def get_setting(key: str, default=None):
    row = query_one("SELECT value FROM settings WHERE key = ?", (key,))
    return json.loads(row["value"]) if row else default


def set_setting(key: str, value) -> None:
    execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value)),
    )
