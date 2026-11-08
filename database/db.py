# database/db.py
"""
One tiny database helper used by scan_log.py and users.py.

- On your computer (no DATABASE_URL set)  -> uses the local SQLite file, as before.
- On Vercel (DATABASE_URL set)            -> uses the hosted Postgres database (Neon).

Write SQL with ? placeholders; this helper converts them for Postgres.
"""

import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL", "")
USING_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))

# Local SQLite file (only used when DATABASE_URL is not set)
DB_PATH = os.path.join(os.path.dirname(__file__), "scan_history.db")

if USING_PG:
    import psycopg2
    IntegrityError = psycopg2.IntegrityError
else:
    IntegrityError = sqlite3.IntegrityError


def _connect():
    if USING_PG:
        return psycopg2.connect(DATABASE_URL, connect_timeout=8)
    return sqlite3.connect(DB_PATH)


def execute(sql: str, params=(), fetch: str = "none"):
    """
    fetch = "none" -> returns None
            "one"  -> returns one row as a dict (or None)
            "all"  -> returns a list of dicts
    """
    if USING_PG:
        sql = sql.replace("?", "%s")
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        result = None
        if fetch in ("one", "all"):
            cols = [d[0] for d in cur.description]
            if fetch == "one":
                row = cur.fetchone()
                result = dict(zip(cols, row)) if row else None
            else:
                result = [dict(zip(cols, r)) for r in cur.fetchall()]
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def id_column() -> str:
    """Auto-numbering primary key, written the way each database expects."""
    return "SERIAL PRIMARY KEY" if USING_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
