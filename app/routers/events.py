"""
Events router — list / filter / timeline / metadata, always scoped by user_id.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.database import _IS_SQLITE, get_db
from app.dependencies import require_user
from app.models import LogEvent, User
from app.schemas import LogEventOut

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("/", response_model=list[LogEventOut])
@router.get("", response_model=list[LogEventOut], include_in_schema=False)
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
    hours: int = Query(24, ge=1, le=168),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return event counts grouped by hour for the last ``hours`` hours.

    Uses dialect-specific SQL grouping so it works on both SQLite and Postgres.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    if _IS_SQLITE:
        hour_expr = func.strftime("%Y-%m-%dT%H:00:00", LogEvent.timestamp)
        rows = (
            db.query(
                hour_expr.label("hour"),
                func.count(LogEvent.id).label("count"),
            )
            .filter(LogEvent.user_id == user.id, LogEvent.timestamp >= cutoff)
            .group_by(hour_expr)
            .order_by(hour_expr)
            .all()
        )
        return [{"hour": r.hour, "count": r.count} for r in rows]

    # Postgres path
    hour_expr = func.date_trunc("hour", LogEvent.timestamp)
    rows = (
        db.query(
            hour_expr.label("hour"),
            func.count(LogEvent.id).label("count"),
        )
        .filter(LogEvent.user_id == user.id, LogEvent.timestamp >= cutoff)
        .group_by(hour_expr)
        .order_by(hour_expr)
        .all()
    )
    return [
        {"hour": r.hour.isoformat() if hasattr(r.hour, "isoformat") else str(r.hour), "count": r.count}
        for r in rows
    ]


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


@router.get("/bulk", response_model=list[LogEventOut])
def bulk_events(
    limit: int = Query(5000, ge=1, le=10000),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[LogEventOut]:
    """Return up to `limit` events in one call (used by the Events UI)."""
    events = (
        db.query(LogEvent)
        .filter(LogEvent.user_id == user.id)
        .order_by(LogEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [LogEventOut.model_validate(e) for e in events]


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
