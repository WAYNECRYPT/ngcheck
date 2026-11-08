# reset_password.py  -- put this in your project's main folder (next to app.py) and run:
#     python reset_password.py
# Passwords are stored hashed, so they can't be read back; this sets a NEW one.
import sqlite3
from werkzeug.security import generate_password_hash
from database.scan_log import DB_PATH

conn = sqlite3.connect(DB_PATH)
users = conn.execute("SELECT username, is_admin FROM users ORDER BY id").fetchall()
if not users:
    print("No accounts exist yet. Just register a new one on the website.")
    raise SystemExit

print("Existing accounts:")
for name, admin in users:
    print(f"  - {name}{'  (admin)' if admin else ''}")

username = input("\nUsername to reset: ").strip()
new_pw = input("New password (min 6 characters): ")
if len(new_pw) < 6:
    raise SystemExit("Password too short. Nothing changed.")

cur = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                   (generate_password_hash(new_pw), username))
conn.commit()
print("Password updated. You can log in now." if cur.rowcount else "No account with that username. Nothing changed.")
conn.close()
