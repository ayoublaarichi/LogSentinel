"""
SQLAlchemy engine, session factory, and declarative base.
"""

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import DATABASE_URL, _ON_VERCEL

logger = logging.getLogger("logsentinel.db")

_IS_SQLITE = DATABASE_URL.startswith("sqlite")
_IS_POSTGRES = DATABASE_URL.startswith("postgresql+psycopg://")
_URL_LOWER = DATABASE_URL.lower()
_USING_EXTERNAL_POOLER = any(
    hint in _URL_LOWER for hint in ("pooler.", "-pooler", "pgbouncer", "connection_limit=")
)
_USE_NULLPOOL = _IS_POSTGRES and (_ON_VERCEL or _USING_EXTERNAL_POOLER)

# ── Engine & session ─────────────────────────────────────────────────────────
_engine_kwargs = {
    "pool_pre_ping": True,
    "echo": False,
}

if _IS_SQLITE:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
elif _IS_POSTGRES:
    _engine_kwargs["connect_args"] = {
        "connect_timeout": 10,
        "options": "-c statement_timeout=15000",
    }

if _USE_NULLPOOL:
    _engine_kwargs["poolclass"] = NullPool
    logger.info("Using NullPool for serverless/pooled Postgres connections")

engine = create_engine(
    DATABASE_URL,
    **_engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Declarative base ────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ── Dependency ───────────────────────────────────────────────────────────────
def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and patch legacy SQLite schemas at startup.

    Note: ``create_all`` is not a full migration system for production.
    Use Alembic for schema evolution in long-running Postgres environments.
    """
    Base.metadata.create_all(bind=engine)

    if not _IS_SQLITE:
        logger.info("Database initialized (non-SQLite): create_all executed; Alembic recommended for migrations.")
        return

    # Legacy schema compatibility (v1 -> v2)
    with engine.begin() as conn:
        table_names = {
            row[0]
            for row in conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }

        if "projects" not in table_names:
            Base.metadata.tables["projects"].create(bind=conn, checkfirst=True)
            table_names.add("projects")

        if "log_events" in table_names:
            log_event_cols = {
                row[1] for row in conn.exec_driver_sql("PRAGMA table_info(log_events)").fetchall()
            }
            if "user_id" not in log_event_cols:
                conn.exec_driver_sql(
                    "ALTER TABLE log_events ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE"
                )
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_log_events_user_id ON log_events(user_id)"
                )

        if "alerts" in table_names:
            alert_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(alerts)").fetchall()}
            if "user_id" not in alert_cols:
                conn.exec_driver_sql(
                    "ALTER TABLE alerts ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE"
                )
                conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_alerts_user_id ON alerts(user_id)")
            if "usernames" not in alert_cols:
                conn.exec_driver_sql("ALTER TABLE alerts ADD COLUMN usernames TEXT")

        for table_name in ("log_events", "alerts", "api_keys", "audit_logs"):
            if table_name not in table_names:
                continue
            cols = {
                row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table_name})").fetchall()
            }
            if "project_id" not in cols:
                conn.exec_driver_sql(f"ALTER TABLE {table_name} ADD COLUMN project_id INTEGER")
                conn.exec_driver_sql(
                    f"CREATE INDEX IF NOT EXISTS ix_{table_name}_project_id ON {table_name}(project_id)"
                )
