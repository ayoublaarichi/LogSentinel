"""
Events router — list / filter / timeline / metadata, always scoped by user_id.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import LogEvent, User
from app.schemas import LogEventOut

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("/", response_model=list[LogEventOut])
def list_events(
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    log_source: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[LogEventOut]:
    q = db.query(LogEvent).filter(LogEvent.user_id == user.id)
    if source_ip:
        q = q.filter(LogEvent.source_ip == source_ip)
    if event_type:
        q = q.filter(LogEvent.event_type == event_type)
    if log_source:
        q = q.filter(LogEvent.log_source == log_source)
    if username:
        q = q.filter(LogEvent.username == username)

    events = (
        q.order_by(LogEvent.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return [LogEventOut.model_validate(e) for e in events]


@router.get("/timeline")
def event_timeline(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return event counts grouped by hour for the last 24h."""
    from datetime import datetime, timedelta

    cutoff = datetime.utcnow() - timedelta(hours=24)
    rows = (
        db.query(
            func.strftime("%Y-%m-%dT%H:00:00", LogEvent.timestamp).label("hour"),
            func.count(LogEvent.id).label("count"),
        )
        .filter(LogEvent.user_id == user.id, LogEvent.timestamp >= cutoff)
        .group_by("hour")
        .order_by("hour")
        .all()
    )
    return [{"hour": r.hour, "count": r.count} for r in rows]


@router.get("/types")
def event_types(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[str]:
    rows = (
        db.query(distinct(LogEvent.event_type))
        .filter(LogEvent.user_id == user.id)
        .all()
    )
    return sorted([r[0] for r in rows if r[0]])


@router.get("/ips")
def unique_ips(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[str]:
    rows = (
        db.query(distinct(LogEvent.source_ip))
        .filter(LogEvent.user_id == user.id, LogEvent.source_ip.isnot(None))
        .all()
    )
    return sorted([r[0] for r in rows if r[0]])


@router.get("/users")
def unique_users(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[str]:
    rows = (
        db.query(distinct(LogEvent.username))
        .filter(LogEvent.user_id == user.id, LogEvent.username.isnot(None))
        .all()
    )
    return sorted([r[0] for r in rows if r[0]])


@router.delete("/bulk")
def bulk_delete(
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    q = db.query(LogEvent).filter(LogEvent.user_id == user.id)
    if source_ip:
        q = q.filter(LogEvent.source_ip == source_ip)
    if event_type:
        q = q.filter(LogEvent.event_type == event_type)
    count = q.delete(synchronize_session=False)
    db.commit()
    return {"deleted": count}
