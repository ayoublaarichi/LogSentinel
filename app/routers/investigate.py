"""
Investigation router — IP investigation page + threat intel API.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, Project, User
from app.services.threat_intel_service import enrich_ip
from app.templating import templates

router = APIRouter(tags=["Investigate"])


@router.get("/investigate/ip/{ip}", include_in_schema=False)
def investigate_ip_page(
    ip: str,
    request: Request,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """IP investigation page — timeline, alerts, threat intel, targeted users."""
    project_filter = None
    if project_id is not None:
        project = (
            db.query(Project)
            .filter(Project.id == project_id, Project.user_id == user.id)
            .first()
        )
        if project:
            project_filter = project.id

    # Events for this IP (user-scoped)
    events_q = db.query(LogEvent).filter(LogEvent.user_id == user.id, LogEvent.source_ip == ip)
    alerts_q = db.query(Alert).filter(Alert.user_id == user.id, Alert.source_ip == ip)
    usernames_q = (
        db.query(LogEvent.username)
        .filter(
            LogEvent.user_id == user.id,
            LogEvent.source_ip == ip,
            LogEvent.username.isnot(None),
        )
    )
    if project_filter is not None:
        events_q = events_q.filter(LogEvent.project_id == project_filter)
        alerts_q = alerts_q.filter(Alert.project_id == project_filter)
        usernames_q = usernames_q.filter(LogEvent.project_id == project_filter)

    events = (
        events_q
        .order_by(LogEvent.timestamp.asc())
        .limit(500)
        .all()
    )

    # Alerts for this IP (user-scoped)
    alerts = (
        alerts_q
        .order_by(Alert.created_at.desc())
        .all()
    )

    # Unique usernames targeted
    usernames = usernames_q.distinct().all()
    targeted_users = sorted([u[0] for u in usernames if u[0] and u[0] != "unknown"])

    # Threat intel
    intel = enrich_ip(db, ip)

    timeline_data = [
        {"ts": e.timestamp.strftime("%Y-%m-%dT%H:%M:%S"), "type": e.event_type}
        for e in events
    ]

    return templates.TemplateResponse(
        "investigate_ip.html",
        {
            "request": request,
            "user": user,
            "ip": ip,
            "events": events,
            "alerts": alerts,
            "targeted_users": targeted_users,
            "intel": intel,
            "timeline_data": timeline_data,
            "active_project_id": project_filter,
        },
    )


@router.get("/api/threat-intel/{ip}", tags=["Threat Intel"])
def get_threat_intel(
    ip: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return threat intelligence data for an IP."""
    return enrich_ip(db, ip)
