"""
Application configuration loaded from environment variables with safe defaults.
"""

import os
from pathlib import Path


# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent.parent
TEMPLATES_DIR: Path = BASE_DIR / "templates"
STATIC_DIR: Path = Path(__file__).resolve().parent / "static"
SAMPLE_LOGS_DIR: Path = BASE_DIR / "sample_logs"

# Vercel serverless uses a read-only filesystem; /tmp is the only writable area.
_ON_VERCEL: bool = bool(os.environ.get("VERCEL") or os.environ.get("VERCEL_URL"))
_DATA_DIR: Path = Path("/tmp") if _ON_VERCEL else BASE_DIR

UPLOAD_DIR: Path = _DATA_DIR / "uploads"

# ── Database ─────────────────────────────────────────────────────────────────
DATABASE_URL: str = f"sqlite:///{_DATA_DIR / 'logsentinel.db'}"

# ── Application ──────────────────────────────────────────────────────────────
APP_TITLE: str = "LogSentinel"
APP_DESCRIPTION: str = "Multi-Tenant SOC Log Analyzer & Alert Dashboard"
APP_VERSION: str = "2.0.0"
DEBUG: bool = True

# ── Auth / session settings ──────────────────────────────────────────────────
SECRET_KEY: str = os.environ.get("LOGSENTINEL_SECRET", "change-me-in-production-32chars!!")
SESSION_COOKIE_NAME: str = "ls_session"
SESSION_MAX_AGE: int = 86400 * 7  # 7 days

# ── Rate limiting (in-memory, per-process) ───────────────────────────────────
INGEST_RATE_LIMIT: int = 60          # max requests per window
INGEST_RATE_WINDOW: int = 60         # window in seconds

# ── Threat intel ─────────────────────────────────────────────────────────────
THREAT_INTEL_CACHE_TTL: int = 3600   # 1 hour

# Ensure upload directory exists at import time
try:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass  # read-only filesystem fallback
