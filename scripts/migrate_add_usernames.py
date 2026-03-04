"""
Migration: add `usernames` column to the `alerts` table.

SQLite supports ALTER TABLE ... ADD COLUMN since SQLite 3.1.3.
This script is idempotent – running it twice is safe.

Usage:
    .\\.venv\\Scripts\\python.exe -m scripts.migrate_add_usernames
"""

import sqlite3
import sys
from pathlib import Path

# ── Locate DB file ───────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "logsentinel.db"


def run() -> None:
    if not DB_PATH.exists():
        print(f"[migrate] Database not found at {DB_PATH}. Nothing to do.")
        sys.exit(0)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Check whether column already exists
    cur.execute("PRAGMA table_info(alerts)")
    columns = {row[1] for row in cur.fetchall()}

    if "usernames" in columns:
        print("[migrate] Column 'usernames' already exists – nothing to do.")
        conn.close()
        return

    print("[migrate] Adding column 'usernames TEXT' to table 'alerts' …")
    cur.execute("ALTER TABLE alerts ADD COLUMN usernames TEXT")
    conn.commit()
    print("[migrate] Done.  Existing rows will have usernames = NULL (decoded as []).")
    conn.close()


if __name__ == "__main__":
    run()
