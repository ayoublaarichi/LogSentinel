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
    """Create all tables. Called once at startup."""
    Base.metadata.create_all(bind=engine)
