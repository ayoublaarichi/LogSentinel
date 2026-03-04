"""
FastAPI dependencies — authentication guards, rate limiting, API-key auth.
"""

import logging
import time
from collections import defaultdict
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import INGEST_RATE_LIMIT, INGEST_RATE_WINDOW
from app.database import get_db
from app.models import User
from app.services.auth_service import get_current_user as _get_current_user

logger = logging.getLogger("logsentinel.auth")


# ═══════════════════════════════════════════════════════════════════════════════
#  Session-based user resolution
# ═══════════════════════════════════════════════════════════════════════════════
def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Return the logged-in user or None (for pages that optionally show data)."""
    return _get_current_user(request, db)


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Raise 401 if user is not authenticated — use on protected endpoints."""
    user = _get_current_user(request, db)
    if user is None:
        client_ip = request.client.host if request.client else "unknown"
        logger.info("Auth denied: %s %s from %s (no valid session)",
                    request.method, request.url.path, client_ip)
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# ═══════════════════════════════════════════════════════════════════════════════
#  API-key based user resolution  (for POST /api/ingest)
# ═══════════════════════════════════════════════════════════════════════════════
def require_api_key_user(request: Request, db: Session = Depends(get_db)) -> User:
    """
    Authenticate via ``Authorization: Bearer <api_key>`` header.
    Returns the User who owns the key or raises 401.
    """
    from app.services.api_key_service import validate_api_key

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <key>")
    raw_key = auth[7:].strip()
    if not raw_key:
        raise HTTPException(status_code=401, detail="Empty API key")

    api_key = validate_api_key(db, raw_key)
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    user = db.query(User).filter(User.id == api_key.user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="API key owner not found")
    return user


# ═══════════════════════════════════════════════════════════════════════════════
#  Simple in-memory rate limiter
# ═══════════════════════════════════════════════════════════════════════════════
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def rate_limit_ingest(request: Request) -> None:
    """
    Enforce per-IP rate limiting on the ingest endpoint.
    Raises 429 if limit is exceeded.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - INGEST_RATE_WINDOW

    # Purge old entries
    _rate_buckets[client_ip] = [t for t in _rate_buckets[client_ip] if t > window_start]
    if len(_rate_buckets[client_ip]) >= INGEST_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {INGEST_RATE_LIMIT} requests per {INGEST_RATE_WINDOW}s.",
        )
    _rate_buckets[client_ip].append(now)
