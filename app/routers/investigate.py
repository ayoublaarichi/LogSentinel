"""
Investigation router — IP investigation page + threat intel API.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import TEMPLATES_DIR
from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, User
from app.services.threat_intel_service import enrich_ip

router = APIRouter(tags=["Investigate"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/investigate/ip/{ip}", include_in_schema=False)
def investigate_ip_page(
    ip: str,
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """IP investigation page — timeline, alerts, threat intel, targeted users."""
    # Events for this IP (user-scoped)
    events = (
        db.query(LogEvent)
        .filter(LogEvent.user_id == user.id, LogEvent.source_ip == ip)
        .order_by(LogEvent.timestamp.asc())
        .limit(500)
        .all()
    )

    # Alerts for this IP (user-scoped)
    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == user.id, Alert.source_ip == ip)
        .order_by(Alert.created_at.desc())
        .all()
    )

    # Unique usernames targeted
    usernames = (
        db.query(LogEvent.username)
        .filter(
            LogEvent.user_id == user.id,
            LogEvent.source_ip == ip,
            LogEvent.username.isnot(None),
        )
        .distinct()
        .all()
    )
    targeted_users = sorted([u[0] for u in usernames if u[0] and u[0] != "unknown"])

    # Threat intel
    intel = enrich_ip(db, ip)

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
