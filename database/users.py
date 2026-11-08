# database/users.py
"""
Optional user accounts for NGcheck.

- Anyone can use the scanner without an account.
- A registered user can log in and view the dashboard.
- The FIRST account ever created becomes the admin. Only the admin can delete scans.
- Passwords are never stored as plain text, only as salted hashes.
"""

import re
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

from database.db import execute, id_column, IntegrityError

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MIN_PASSWORD_LENGTH = 8


def init_users_table():
    """Creates the users table if it doesn't exist. Safe to call on every startup."""
    execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id {id_column()},
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    # Usernames are unique regardless of upper/lower case ("Emma" == "emma")
    execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users (LOWER(username))")


def create_user(username: str, password: str):
    """
    Returns (True, "") on success, or (False, "reason") on failure.
    The very first user to register becomes the admin.
    """
    username = (username or "").strip()

    if not USERNAME_PATTERN.match(username):
        return False, "Username must be 3-20 characters: letters, numbers or underscore."
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    try:
        existing = execute("SELECT COUNT(*) AS n FROM users", fetch="one")["n"]
        is_admin = 1 if existing == 0 else 0
        execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), is_admin,
             datetime.now().isoformat(timespec="seconds")),
        )
        return True, ""
    except IntegrityError:
        return False, "That username is already taken."


def verify_user(username: str, password: str):
    """Returns the user dict if the username/password are right, otherwise None."""
    row = execute(
        "SELECT id, username, password_hash, is_admin FROM users WHERE LOWER(username) = LOWER(?)",
        ((username or "").strip(),),
        fetch="one",
    )
    if row and check_password_hash(row["password_hash"], password or ""):
        return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"])}
    return None


def get_user(user_id):
    """Returns the user dict for a logged-in session, or None."""
    if user_id is None:
        return None
    row = execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,), fetch="one")
    if row:
        return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"])}
    return None
