"""
Migration script: v1 → v2 (multi-tenant)

Adds user_id columns to log_events and alerts tables,
creates new tables: users, api_keys, threat_intel_cache, audit_logs.
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "logsentinel.db"


def migrate():
    print(f"Migrating database: {DB_PATH}")
    if not DB_PATH.exists():
        print("Database not found — it will be created on first startup.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()

    # ── Check existing schema ────────────────────────────────────────────
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = {row[0] for row in cur.fetchall()}
    print(f"Existing tables: {existing_tables}")

    # ── Create new tables if missing ─────────────────────────────────────
    if "users" not in existing_tables:
        print("Creating 'users' table...")
        cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON users(email)")

    if "api_keys" not in existing_tables:
        print("Creating 'api_keys' table...")
        cur.execute("""
            CREATE TABLE api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label VARCHAR(128) NOT NULL DEFAULT 'default',
                key_prefix VARCHAR(8) NOT NULL,
                key_hash VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                revoked_at DATETIME
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS ix_api_keys_user_id ON api_keys(user_id)")

    if "threat_intel_cache" not in existing_tables:
        print("Creating 'threat_intel_cache' table...")
        cur.execute("""
            CREATE TABLE threat_intel_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                country VARCHAR(64),
                city VARCHAR(128),
                asn VARCHAR(32),
                isp VARCHAR(256),
                reputation_score FLOAT,
                is_tor INTEGER DEFAULT 0,
                raw_json TEXT,
                fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS ix_threat_intel_cache_ip ON threat_intel_cache(ip_address)")

    if "audit_logs" not in existing_tables:
        print("Creating 'audit_logs' table...")
        cur.execute("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action VARCHAR(64) NOT NULL,
                detail TEXT,
                ip_address VARCHAR(45),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs(user_id)")

    # ── Add user_id column to log_events if missing ──────────────────────
    cur.execute("PRAGMA table_info(log_events)")
    le_cols = {row[1] for row in cur.fetchall()}
    if "user_id" not in le_cols:
        print("Adding 'user_id' column to 'log_events'...")
        cur.execute("ALTER TABLE log_events ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_log_events_user_id ON log_events(user_id)")

    # ── Add user_id column to alerts if missing ──────────────────────────
    cur.execute("PRAGMA table_info(alerts)")
    al_cols = {row[1] for row in cur.fetchall()}
    if "user_id" not in al_cols:
        print("Adding 'user_id' column to 'alerts'...")
        cur.execute("ALTER TABLE alerts ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_alerts_user_id ON alerts(user_id)")

    # ── Add usernames column to alerts if missing (from v1.5) ────────────
    if "usernames" not in al_cols:
        print("Adding 'usernames' column to 'alerts'...")
        cur.execute("ALTER TABLE alerts ADD COLUMN usernames TEXT")

    conn.commit()
    conn.close()
    print("Migration complete!")


if __name__ == "__main__":
    migrate()
