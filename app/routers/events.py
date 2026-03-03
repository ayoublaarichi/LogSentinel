"""
Events router — list and filter parsed log events.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
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
