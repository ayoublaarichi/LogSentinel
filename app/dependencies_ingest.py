"""
Ingest-specific dependencies — API-key auth and DB-backed rate limiting.
"""

from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import INGEST_RPM
from app.database import get_db
from app.models import AgentRateLimit, ApiKey, User
from app.services.api_key_service import validate_api_key


def _current_window_start() -> datetime:
    now = datetime.utcnow()
    return now.replace(second=0, microsecond=0)


def require_ingest_api_key(request: Request, db: Session = Depends(get_db)) -> ApiKey:
    """Authenticate ingest calls using X-API-Key only."""
    raw_key = (request.headers.get("x-api-key") or "").strip()
    if not raw_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")

    api_key = validate_api_key(db, raw_key)
    if api_key is None or api_key.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    owner = db.query(User).filter(User.id == api_key.user_id).first()
    if owner is None:
        raise HTTPException(status_code=401, detail="API key owner not found")

    request.state.api_key = api_key
    request.state.ingest_user = owner
    return api_key


def enforce_ingest_payload_limit(request: Request) -> None:
    """Reject oversized ingest requests to reduce abuse risk."""
    max_bytes = 1_000_000
    raw = request.headers.get("content-length")
    if raw is None:
        return
    try:
        size = int(raw)
    except ValueError:
        return
    if size > max_bytes:
        raise HTTPException(status_code=413, detail=f"Payload too large. Max {max_bytes} bytes")


def enforce_agent_rate_limit(
    api_key: ApiKey,
    db: Session,
    units: int = 1,
) -> None:
    """DB-backed per-key request/event limiter over 1-minute windows."""
    limit = max(1, int(INGEST_RPM))
    window_start = _current_window_start()

    bucket = (
        db.query(AgentRateLimit)
        .filter(
            AgentRateLimit.api_key_id == api_key.id,
            AgentRateLimit.window_start == window_start,
        )
        .first()
    )

    if bucket is None:
        bucket = AgentRateLimit(
            api_key_id=api_key.id,
            window_start=window_start,
            request_count=0,
        )
        db.add(bucket)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            bucket = (
                db.query(AgentRateLimit)
                .filter(
                    AgentRateLimit.api_key_id == api_key.id,
                    AgentRateLimit.window_start == window_start,
                )
                .first()
            )
            if bucket is None:
                raise HTTPException(status_code=429, detail="Rate limiter unavailable")

    bucket.request_count += max(1, int(units))
    if bucket.request_count > limit:
        db.rollback()
        retry_in = int((window_start + timedelta(minutes=1) - datetime.utcnow()).total_seconds())
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {limit} ingested items per minute",
            headers={"Retry-After": str(max(1, retry_in))},
        )

    db.commit()
