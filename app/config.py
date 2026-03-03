"""
Application configuration loaded from environment variables with safe defaults.
"""

from pathlib import Path


# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent.parent
UPLOAD_DIR: Path = BASE_DIR / "uploads"
SAMPLE_LOGS_DIR: Path = BASE_DIR / "sample_logs"
TEMPLATES_DIR: Path = BASE_DIR / "templates"
STATIC_DIR: Path = Path(__file__).resolve().parent / "static"

# ── Database ─────────────────────────────────────────────────────────────────
DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'logsentinel.db'}"

# ── Application ──────────────────────────────────────────────────────────────
APP_TITLE: str = "LogSentinel"
APP_DESCRIPTION: str = "Mini SOC Log Analyzer & Alert Dashboard"
APP_VERSION: str = "1.0.0"
DEBUG: bool = True

# Ensure upload directory exists at import time
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
