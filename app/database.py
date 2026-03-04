"""
SQLAlchemy engine, session factory, and declarative base.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import DATABASE_URL

# ── Engine & session ─────────────────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=False,
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
    """Create all tables and patch legacy SQLite schemas at startup."""
    Base.metadata.create_all(bind=engine)

    # Legacy schema compatibility (v1 -> v2)
    with engine.begin() as conn:
        table_names = {
            row[0]
            for row in conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }

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
