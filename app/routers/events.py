"""
Events router — list and filter parsed log events.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import LogEvent
from app.schemas import LogEventOut

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("/", response_model=list[LogEventOut])
def list_events(
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    log_source: Optional[str] = Query(None, description="Filter by log source (auth/nginx)"),
    start_time: Optional[datetime] = Query(None, description="Start of time range (ISO 8601)"),
    end_time: Optional[datetime] = Query(None, description="End of time range (ISO 8601)"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Results per page"),
    db: Session = Depends(get_db),
) -> list[LogEventOut]:
    """Return paginated, filtered log events."""
    query = db.query(LogEvent)

    if source_ip:
        query = query.filter(LogEvent.source_ip == source_ip)
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if log_source:
        query = query.filter(LogEvent.log_source == log_source)
    if start_time:
        query = query.filter(LogEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(LogEvent.timestamp <= end_time)

    events = (
        query.order_by(LogEvent.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return [LogEventOut.model_validate(e) for e in events]


@router.get("/types", response_model=list[str])
def list_event_types(db: Session = Depends(get_db)) -> list[str]:
    """Return distinct event types in the database."""
    rows = db.query(LogEvent.event_type).distinct().all()
    return sorted([r[0] for r in rows])


@router.get("/count")
def count_events(db: Session = Depends(get_db)) -> dict[str, int]:
    """Return total event count."""
    total = db.query(func.count(LogEvent.id)).scalar() or 0
    return {"total": total}


@router.get("/bulk", response_model=list[LogEventOut])
def bulk_events(
    limit: int = Query(2000, ge=1, le=10000, description="Max events to return"),
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    log_source: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
) -> list[LogEventOut]:
    """Return a large batch of events for client-side virtual table (up to 10 000)."""
    query = db.query(LogEvent)
    if source_ip:
        query = query.filter(LogEvent.source_ip == source_ip)
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if log_source:
        query = query.filter(LogEvent.log_source == log_source)
    if username:
        query = query.filter(LogEvent.username == username)
    if start_time:
        query = query.filter(LogEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(LogEvent.timestamp <= end_time)
    events = query.order_by(LogEvent.timestamp.desc()).limit(limit).all()
    return [LogEventOut.model_validate(e) for e in events]


@router.get("/timeline")
def events_timeline(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return event counts bucketed by hour for the last N hours."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    since = now - timedelta(hours=hours)

    rows = (
        db.query(
            func.strftime("%Y-%m-%dT%H:00:00", LogEvent.timestamp).label("bucket"),
            func.count(LogEvent.id).label("count"),
        )
        .filter(LogEvent.timestamp >= since)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    return [{"bucket": r.bucket, "count": r.count} for r in rows]


@router.get("/ips", response_model=list[str])
def list_ips(db: Session = Depends(get_db)) -> list[str]:
    """Return distinct source IPs (for autocomplete)."""
    rows = db.query(LogEvent.source_ip).filter(LogEvent.source_ip.isnot(None)).distinct().all()
    return sorted([r[0] for r in rows])


@router.get("/users", response_model=list[str])
def list_users(db: Session = Depends(get_db)) -> list[str]:
    """Return distinct usernames (for autocomplete)."""
    rows = db.query(LogEvent.username).filter(LogEvent.username.isnot(None)).distinct().all()
    return sorted([r[0] for r in rows])
