"""
Events router — list / filter / timeline / metadata, always scoped by user_id.
"""

import random
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.database import _IS_SQLITE, get_db
from app.dependencies import require_user
from app.models import LogEvent, Project, User
from app.schemas import LogEventOut
from app.services.project_service import get_user_project_or_default
from app.services.threat_intel_service import enrich_ip

router = APIRouter(prefix="/api/events", tags=["Events"])


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _visible_user_ids(db: Session, user: User, request: Request) -> list[int]:
    """Strict tenant isolation: only the authenticated user's data is visible."""
    return [user.id]


def _resolve_project_filter(db: Session, user: User, project_id: Optional[int]) -> Optional[int]:
    if project_id is None:
        return None
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.id


def _country_code(country: str) -> str:
    if not country:
        return "ZZ"
    value = country.strip()
    if len(value) == 2 and value.isalpha():
        return value.upper()
    mapping = {
        "United States": "US",
        "United Kingdom": "GB",
        "Germany": "DE",
        "France": "FR",
        "China": "CN",
        "Russia": "RU",
        "Brazil": "BR",
        "Netherlands": "NL",
        "India": "IN",
        "Canada": "CA",
        "Japan": "JP",
        "Private": "PR",
        "Unknown": "ZZ",
    }
    if value in mapping:
        return mapping[value]
    parts = [p for p in value.split() if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return value[:2].upper()


@router.get("/", response_model=list[LogEventOut])
@router.get("", response_model=list[LogEventOut], include_in_schema=False)
def list_events(
    request: Request,
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    log_source: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    project_id: Optional[int] = Query(None, ge=1),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[LogEventOut]:
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)
    q = db.query(LogEvent).filter(LogEvent.user_id.in_(visible_ids))
    if project_filter is not None:
        q = q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
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
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return event counts grouped by hour for the last ``hours`` hours.

    Uses dialect-specific SQL grouping so it works on both SQLite and Postgres.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)

    if _IS_SQLITE:
        hour_expr = func.strftime("%Y-%m-%dT%H:00:00", LogEvent.timestamp)
        q = (
            db.query(
                hour_expr.label("hour"),
                func.count(LogEvent.id).label("count"),
            )
            .filter(LogEvent.user_id.in_(visible_ids), LogEvent.timestamp >= cutoff)
        )
        if project_filter is not None:
            q = q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
        rows = q.group_by(hour_expr).order_by(hour_expr).all()
        return [{"hour": r.hour, "count": r.count} for r in rows]

    # Postgres path
    hour_expr = func.date_trunc("hour", LogEvent.timestamp)
    q = (
        db.query(
            hour_expr.label("hour"),
            func.count(LogEvent.id).label("count"),
        )
        .filter(LogEvent.user_id.in_(visible_ids), LogEvent.timestamp >= cutoff)
    )
    if project_filter is not None:
        q = q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    rows = q.group_by(hour_expr).order_by(hour_expr).all()
    return [
        {"hour": r.hour.isoformat() if hasattr(r.hour, "isoformat") else str(r.hour), "count": r.count}
        for r in rows
    ]


@router.get("/geo-stats")
def event_geo_stats(
    request: Request,
    hours: int = Query(168, ge=1, le=720),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)

    rows_q = (
        db.query(LogEvent.source_ip, func.count(LogEvent.id).label("count"))
        .filter(
            LogEvent.user_id.in_(visible_ids),
            LogEvent.source_ip.isnot(None),
            LogEvent.timestamp >= cutoff,
        )
    )
    if project_filter is not None:
        rows_q = rows_q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    rows = (
        rows_q
        .group_by(LogEvent.source_ip)
        .order_by(func.count(LogEvent.id).desc())
        .limit(200)
        .all()
    )

    counts: dict[str, int] = {}
    for source_ip, count in rows:
        try:
            intel = enrich_ip(db, source_ip)
        except Exception:
            intel = {"country": "Unknown"}
        code = _country_code(str(intel.get("country") or "Unknown"))
        counts[code] = counts.get(code, 0) + int(count)
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))


@router.get("/types")
def event_types(
    request: Request,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[str]:
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)
    rows_q = db.query(distinct(LogEvent.event_type)).filter(LogEvent.user_id.in_(visible_ids))
    if project_filter is not None:
        rows_q = rows_q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    rows = rows_q.all()
    return sorted([r[0] for r in rows if r[0]])


@router.get("/ips")
def unique_ips(
    request: Request,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[str]:
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)
    rows_q = db.query(distinct(LogEvent.source_ip)).filter(
        LogEvent.user_id.in_(visible_ids), LogEvent.source_ip.isnot(None)
    )
    if project_filter is not None:
        rows_q = rows_q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    rows = rows_q.all()
    return sorted([r[0] for r in rows if r[0]])


@router.get("/users")
def unique_users(
    request: Request,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[str]:
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)
    rows_q = db.query(distinct(LogEvent.username)).filter(
        LogEvent.user_id.in_(visible_ids), LogEvent.username.isnot(None)
    )
    if project_filter is not None:
        rows_q = rows_q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    rows = rows_q.all()
    return sorted([r[0] for r in rows if r[0]])


@router.get("/bulk", response_model=list[LogEventOut])
def bulk_events(
    request: Request,
    limit: int = Query(5000, ge=1, le=10000),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[LogEventOut]:
    """Return up to `limit` events in one call (used by the Events UI)."""
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)
    q = db.query(LogEvent).filter(LogEvent.user_id.in_(visible_ids))
    if project_filter is not None:
        q = q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    events = q.order_by(LogEvent.timestamp.desc()).limit(limit).all()
    return [LogEventOut.model_validate(e) for e in events]


@router.post("/seed")
def seed_events(
    request: Request,
    count: int = Query(50, ge=1, le=1000),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """Create demo events for the current user (quick bootstrap for empty DBs)."""
    now = datetime.utcnow()
    project = get_user_project_or_default(db, user, project_id=project_id)
    client_ip = _extract_client_ip(request) or "192.168.1.100"
    event_types = [
        "ssh_failed_login",
        "ssh_invalid_user",
        "http_client_error",
        "http_server_error",
        "http_ok",
    ]
    usernames = ["root", "admin", "ubuntu", "nginx", None]
    log_sources = ["auth", "nginx"]

    rows: list[LogEvent] = []
    for i in range(count):
        rows.append(
            LogEvent(
                user_id=user.id,
                project_id=project.id,
                timestamp=now - timedelta(minutes=i),
                source_ip=client_ip,
                username=random.choice(usernames),
                event_type=random.choice(event_types),
                log_source=random.choice(log_sources),
                raw_line=f"seed-event-{i} for user {user.email}",
                file_name="seed-generated.log",
            )
        )

    db.add_all(rows)
    db.commit()
    return {"seeded": len(rows), "user_id": user.id, "project_id": project.id, "source_ip": client_ip}


@router.delete("/seed")
def delete_seed_events(
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """Delete only seed-generated demo events for current user.

    Scope can be narrowed by project_id.
    """
    project_filter = _resolve_project_filter(db, user, project_id)
    q = db.query(LogEvent).filter(
        LogEvent.user_id == user.id,
        LogEvent.file_name == "seed-generated.log",
        LogEvent.raw_line.like("seed-event-%"),
    )
    if project_filter is not None:
        q = q.filter(LogEvent.project_id == project_filter)
    deleted = q.delete(synchronize_session=False)
    db.commit()
    return {"deleted": int(deleted), "project_id": project_filter}


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
