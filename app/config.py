"""
Application configuration loaded from environment variables with safe defaults.
"""

import logging
import os
from pathlib import Path
from typing import Literal

# ── Logging (configure early) ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent.parent
TEMPLATES_DIR: Path = BASE_DIR / "templates"
STATIC_DIR: Path = Path(__file__).resolve().parent / "static"
SAMPLE_LOGS_DIR: Path = BASE_DIR / "sample_logs"

# Vercel serverless uses a read-only filesystem; /tmp is the only writable area.
# Check multiple env vars so detection survives cold-start edge cases.
_ON_VERCEL: bool = bool(
    os.environ.get("VERCEL")
    or os.environ.get("VERCEL_URL")
    or os.environ.get("VERCEL_ENV")
    or os.environ.get("VERCEL_REGION")
)
_DATA_DIR: Path = Path("/tmp") if _ON_VERCEL else BASE_DIR
_ENV: str = os.environ.get("ENV", os.environ.get("APP_ENV", "development")).lower()
_IS_PRODUCTION: bool = _ON_VERCEL or _ENV == "production"

UPLOAD_DIR: Path = _DATA_DIR / "uploads"

# ── Database ─────────────────────────────────────────────────────────────────
_db_env = (
    os.environ.get("DATABASE_URL", "").strip()
    or os.environ.get("POSTGRES_URL_NON_POOLING", "").strip()
    or os.environ.get("POSTGRES_URL", "").strip()
    or os.environ.get("POSTGRES_PRISMA_URL", "").strip()
)
if _IS_PRODUCTION:
    if not _db_env:
        raise RuntimeError(
            "DATABASE_URL (or POSTGRES_URL/POSTGRES_URL_NON_POOLING) is required in production "
            "(Vercel/ENV=production). "
            "Use a persistent Postgres database. Example: "
            "postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME"
        )
    DATABASE_URL: str = _db_env
else:
    # Local development default: persistent SQLite file in project root.
    DATABASE_URL = _db_env or f"sqlite:///{BASE_DIR / 'logsentinel.db'}"

# Accept Heroku-style postgres:// URLs by normalizing for SQLAlchemy.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# ── Application ──────────────────────────────────────────────────────────────
APP_TITLE: str = "LogSentinel"
APP_DESCRIPTION: str = "Multi-Tenant SOC Log Analyzer & Alert Dashboard"
APP_VERSION: str = "2.0.0"
DEBUG: bool = not _ON_VERCEL  # auto-disable debug on Vercel

# ── Auth / session settings ──────────────────────────────────────────────────
_secret_env = os.environ.get("LOGSENTINEL_SECRET", "")
_DEV_FALLBACK = "change-me-in-production-32chars!!"
if _IS_PRODUCTION and (not _secret_env or _secret_env == _DEV_FALLBACK):
    raise RuntimeError(
        "LOGSENTINEL_SECRET env var must be set to a strong random value in production. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )
SECRET_KEY: str = _secret_env or _DEV_FALLBACK
SESSION_COOKIE_NAME: str = "ls_session"
SESSION_MAX_AGE: int = 86400 * 7  # 7 days
# Cookie security flags driven by environment
SESSION_COOKIE_SECURE: bool = _ON_VERCEL   # True on HTTPS (Vercel), False locally
SESSION_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"  # prevents CSRF while allowing top-level nav

# ── Rate limiting (in-memory, per-process) ───────────────────────────────────
INGEST_RATE_LIMIT: int = 60          # max requests per window
INGEST_RATE_WINDOW: int = 60         # window in seconds
INGEST_RPM: int = int(os.environ.get("INGEST_RPM", str(INGEST_RATE_LIMIT)))

# ── CORS ─────────────────────────────────────────────────────────────────────
# On Vercel the frontend and API share the same origin, but custom domains or
# preview deployments may differ.  Allow the Vercel URL explicitly + localhost.
_vercel_url = os.environ.get("VERCEL_URL", "")  # e.g. "logsentinel-tau.vercel.app"
CORS_ORIGINS: list[str] = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
if _vercel_url:
    CORS_ORIGINS.append(f"https://{_vercel_url}")
# Also allow the production custom domain if set
_custom_domain = os.environ.get("LOGSENTINEL_DOMAIN", "")
if _custom_domain:
    CORS_ORIGINS.append(f"https://{_custom_domain}")

# ── Threat intel ─────────────────────────────────────────────────────────────
THREAT_INTEL_CACHE_TTL: int = 3600   # 1 hour

# Ensure upload directory exists at import time
try:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass  # read-only filesystem fallback
