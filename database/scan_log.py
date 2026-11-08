# database/scan_log.py
"""
Scan history log (SQLite on your computer, Postgres on Vercel).
Stores one row per scan: the URL, the risk level/score, and when it happened.
"""

from datetime import datetime
from database.db import execute, id_column, DB_PATH  # DB_PATH kept for older scripts


def init_db():
    """Creates the scans table if it doesn't already exist. Safe to call every startup."""
    execute(f"""
        CREATE TABLE IF NOT EXISTS scans (
            id {id_column()},
            website TEXT NOT NULL,
            risk_level TEXT,
            score INTEGER,
            scanned_at TEXT NOT NULL
        )
    """)


def log_scan(website: str, risk_level: str, score: int):
    """Call this once per completed scan, after risk_info is calculated."""
    execute(
        "INSERT INTO scans (website, risk_level, score, scanned_at) VALUES (?, ?, ?, ?)",
        (website, risk_level, score, datetime.now().isoformat(timespec="seconds")),
    )


def get_scan_history(limit: int = 50):
    """Returns the most recent scans, newest first, as a list of dicts."""
    return execute(
        "SELECT id, website, risk_level, score, scanned_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
        fetch="all",
    )


def delete_scan(scan_id: int):
    """Deletes a single scan from the history by its id."""
    execute("DELETE FROM scans WHERE id = ?", (scan_id,))
