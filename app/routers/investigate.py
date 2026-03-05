"""
Investigation router — IP investigation page + threat intel API.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, Project, User
from app.services.threat_intel_service import enrich_ip
from app.templating import templates

router = APIRouter(tags=["Investigate"])


def _resolve_project_filter(db: Session, user: User, project_id: Optional[int]) -> Optional[int]:
    if project_id is None:
        return None
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        return None
    return project.id


def _categorize_event(event: LogEvent) -> str:
    message = (event.raw_line or "").lower()
    event_type = (event.event_type or "").lower()
    if event_type in {"ssh_failed_login", "ssh_invalid_user"} or "failed password" in message:
        return "auth_failure"
    if event_type == "ssh_accepted_login" or "accepted" in message:
        return "auth_success"
    if "sudo" in message:
        return "privilege_escalation"
    if "config" in message or "modified" in message:
        return "configuration_change"
    return "activity"


def _build_summary(timeline: list[dict]) -> str:
    failures = sum(1 for e in timeline if e["category"] == "auth_failure")
    success = sum(1 for e in timeline if e["category"] == "auth_success")
    privilege = sum(1 for e in timeline if e["category"] == "privilege_escalation")
    config = sum(1 for e in timeline if e["category"] == "configuration_change")

    if failures >= 5 and success > 0 and (privilege > 0 or config > 0):
        return "Possible brute force attack followed by post-auth privileged activity."
    if failures >= 5 and success > 0:
        return "Possible brute force attack: repeated auth failures followed by successful login."
    if privilege > 0 or config > 0:
        return "Suspicious post-auth activity detected (privilege escalation or configuration change)."
    if failures > 0:
        return "Repeated authentication failures detected."
    return "No high-confidence attack pattern detected from timeline heuristics."


def _safe_enrich_ip(db: Session, ip: str) -> dict:
    try:
        return enrich_ip(db, ip)
    except Exception:
        return {
            "ip": ip,
            "country": "Unknown",
            "city": "—",
            "asn": "—",
            "isp": "—",
            "reputation_score": None,
            "is_tor": False,
            "source": "error",
        }


@router.get("/investigate/ip/{ip}", include_in_schema=False)
def investigate_ip_page(
    ip: str,
    request: Request,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """IP investigation page — timeline, alerts, threat intel, targeted users."""
    project_filter = _resolve_project_filter(db, user, project_id)

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
    intel = _safe_enrich_ip(db, ip)

    timeline_data = [
        {
            "ts": e.timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "type": e.event_type,
            "category": _categorize_event(e),
            "raw": e.raw_line,
            "source": e.log_source,
        }
        for e in events
    ]
    timeline_summary = _build_summary(timeline_data)

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
            "timeline_summary": timeline_summary,
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
    return _safe_enrich_ip(db, ip)


@router.get("/api/investigate/timeline", tags=["Investigate"])
def investigation_timeline(
    ip: Optional[str] = Query(None),
    user_name: Optional[str] = Query(None, alias="user"),
    host: Optional[str] = Query(None),
    hours: int = Query(6, ge=1, le=168),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    if not ip and not user_name and not host:
        raise HTTPException(status_code=400, detail="Provide at least one of ip, user, or host.")

    since = datetime.utcnow() - timedelta(hours=hours)
    project_filter = _resolve_project_filter(db, user, project_id)

    events_q = db.query(LogEvent).filter(LogEvent.user_id == user.id, LogEvent.timestamp >= since)
    if project_filter is not None:
        events_q = events_q.filter(LogEvent.project_id == project_filter)
    if ip:
        events_q = events_q.filter(LogEvent.source_ip == ip)
    if user_name:
        events_q = events_q.filter(LogEvent.username == user_name)
    if host:
        host_value = f"%{host}%"
        events_q = events_q.filter((LogEvent.file_name.ilike(host_value)) | (LogEvent.raw_line.ilike(host_value)))

    events = (
        events_q
        .order_by(LogEvent.timestamp.asc())
        .limit(200)
        .all()
    )

    timeline = [
        {
            "time": event.timestamp,
            "message": event.raw_line,
            "level": event.event_type,
            "source": event.log_source,
            "ip": event.source_ip,
            "user": event.username,
            "category": _categorize_event(event),
        }
        for event in events
    ]
    summary = _build_summary(timeline)
    counts = {
        "auth_failure": sum(1 for e in timeline if e["category"] == "auth_failure"),
        "auth_success": sum(1 for e in timeline if e["category"] == "auth_success"),
        "privilege_escalation": sum(1 for e in timeline if e["category"] == "privilege_escalation"),
        "configuration_change": sum(1 for e in timeline if e["category"] == "configuration_change"),
    }

    return {
        "filters": {
            "ip": ip,
            "user": user_name,
            "host": host,
            "hours": hours,
            "project_id": project_filter,
        },
        "summary": summary,
        "counts": counts,
        "timeline": timeline,
    }
