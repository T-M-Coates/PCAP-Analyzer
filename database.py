"""
SQLite wrapper for PCAP Analyzer analysis history.

Table schema:
    analyses (job_id, filename, file_size, uploaded_at, completed_at,
              critical_count, high_count, medium_count, info_count, json_path)

All public functions degrade gracefully — a failure never kills a report.
"""
from __future__ import annotations
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone


# ── DDL ───────────────────────────────────────────────────────────
_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS analyses (
    job_id         TEXT PRIMARY KEY,
    filename       TEXT NOT NULL,
    file_size      INTEGER NOT NULL DEFAULT 0,
    uploaded_at    TEXT NOT NULL DEFAULT '',
    completed_at   TEXT,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    medium_count   INTEGER NOT NULL DEFAULT 0,
    info_count     INTEGER NOT NULL DEFAULT 0,
    json_path      TEXT
);
"""


# ── Connection helper ─────────────────────────────────────────────
@contextmanager
def _connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ── Initialise (idempotent) ───────────────────────────────────────
def init_db(db_path: str) -> None:
    """Create the database file and table if they don't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with _connect(db_path) as conn:
        conn.execute(_CREATE_TABLE)


# ── Write ─────────────────────────────────────────────────────────
def save_analysis(
    db_path: str,
    job_id: str,
    filename: str,
    file_size: int,
    uploaded_at: str,
    critical: int,
    high: int,
    medium: int,
    info: int,
    json_path: str,
) -> None:
    """Insert or replace an analysis record."""
    try:
        init_db(db_path)
        completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _connect(db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO analyses
                   (job_id, filename, file_size, uploaded_at, completed_at,
                    critical_count, high_count, medium_count, info_count, json_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (job_id, filename, file_size, uploaded_at, completed_at,
                 critical, high, medium, info, json_path),
            )
    except Exception:
        pass   # DB failure never kills a report


# ── Read ──────────────────────────────────────────────────────────
def get_analysis(db_path: str, job_id: str) -> dict | None:
    """Return one analysis record as a dict, or None."""
    try:
        init_db(db_path)
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM analyses WHERE job_id = ?", (job_id,)
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def list_analyses(db_path: str) -> list[dict]:
    """Return all analyses ordered by completion time (newest first)."""
    try:
        init_db(db_path)
        with _connect(db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM analyses ORDER BY completed_at DESC LIMIT 200"
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


# ── Delete ────────────────────────────────────────────────────────
def delete_analysis(db_path: str, job_id: str) -> bool:
    """Remove an analysis record from the database. Returns True on success."""
    try:
        init_db(db_path)
        with _connect(db_path) as conn:
            conn.execute("DELETE FROM analyses WHERE job_id = ?", (job_id,))
        return True
    except Exception:
        return False
