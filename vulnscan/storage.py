"""Local scan history in SQLite (stdlib only; single user, local file).

Kept deliberately simple: a list of past point-in-time scans. Trend tracking
and centralised storage are out of scope (IR section 1.5.2)."""
import datetime
import json
import os
import sqlite3
import threading
from contextlib import contextmanager

from .config import user_data_dir

_lock = threading.Lock()
_db_path = None


def db_path() -> str:
    global _db_path
    if _db_path is None:
        _db_path = os.environ.get("VULNSCAN_DB") or os.path.join(user_data_dir(), "scans.db")
    return _db_path


@contextmanager
def _db():
    conn = sqlite3.connect(db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def init() -> None:
    with _lock, _db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                context TEXT NOT NULL,
                status TEXT NOT NULL,
                log TEXT NOT NULL DEFAULT '[]',
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                finished_at TEXT
            )"""
        )
        c.execute(
            "UPDATE scans SET status='failed', error='Interrupted: application closed', "
            "finished_at=? WHERE status='running'", (now(),)
        )


def create(scan_id, target, profile, context) -> None:
    with _lock, _db() as c:
        c.execute(
            "INSERT INTO scans (id, target, profile, context, status, created_at) "
            "VALUES (?, ?, ?, ?, 'running', ?)",
            (scan_id, target, profile, json.dumps(context), now()),
        )


def _close(scan_id, status, log, result=None, error=None) -> None:
    with _lock, _db() as c:
        c.execute(
            "UPDATE scans SET status=?, log=?, result=?, error=?, finished_at=? WHERE id=?",
            (status, json.dumps(log[-300:]),
             json.dumps(result) if result is not None else None,
             str(error)[:500] if error else None, now(), scan_id),
        )


def finish(scan_id, result, log) -> None:
    _close(scan_id, "done", log, result=result)


def fail(scan_id, error, log) -> None:
    _close(scan_id, "failed", log, error=error)


def cancel(scan_id, log) -> None:
    _close(scan_id, "cancelled", log, error="Cancelled by user")


def update_result(scan_id, result, extra_log=None) -> None:
    """Replace a finished scan's result (used by 'Retry AI advice')."""
    with _lock, _db() as c:
        row = c.execute("SELECT log FROM scans WHERE id=?", (scan_id,)).fetchone()
        log = json.loads(row["log"] or "[]") if row else []
        log += extra_log or []
        c.execute("UPDATE scans SET result=?, log=? WHERE id=?",
                  (json.dumps(result), json.dumps(log[-300:]), scan_id))


def _decode(row) -> dict:
    d = dict(row)
    d["context"] = json.loads(d["context"])
    d["log"] = json.loads(d["log"] or "[]")
    d["result"] = json.loads(d["result"]) if d["result"] else None
    return d


def get(scan_id):
    with _db() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _decode(row) if row else None


def list_all(limit=500) -> list:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_decode(r) for r in rows]


def delete(scan_id) -> None:
    with _lock, _db() as c:
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
