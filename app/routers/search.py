"""
Search router — structured query parser for SOC-style search.

Supports queries like:
    ip:192.168.1.1
    severity:high
    rule:"SSH Brute Force"
    user:root
    type:ssh_failed_login

Translates to SQLAlchemy filters, always scoped by user_id.
"""

import re
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, Project, User
from app.templating import templates

router = APIRouter(tags=["Search"])

# ── Query parser ─────────────────────────────────────────────────────────────
_TOKEN_RE = re.compile(
    r'(\w+):'            # field name + colon
    r'(?:"([^"]*)"'     # quoted value
    r"|(\S+))"           # or unquoted value
)


def parse_search_query(raw: str) -> dict[str, str]:
    """Parse 'ip:1.2.3.4 severity:high rule:\"SSH Brute Force\"' into a dict."""
    result: dict[str, str] = {}
    for m in _TOKEN_RE.finditer(raw):
        field = m.group(1).lower()
        value = m.group(2) if m.group(2) is not None else m.group(3)
        result[field] = value
    return result


def apply_event_filters(query, filters: dict, user_id: int):
    """Apply parsed search filters to a LogEvent query."""
    query = query.filter(LogEvent.user_id == user_id)
    if "ip" in filters:
        query = query.filter(LogEvent.source_ip == filters["ip"])
    if "type" in filters:
        query = query.filter(LogEvent.event_type == filters["type"])
    if "user" in filters:
        query = query.filter(LogEvent.username == filters["user"])
    if "source" in filters:
        query = query.filter(LogEvent.log_source == filters["source"])
    return query


def apply_alert_filters(query, filters: dict, user_id: int):
    """Apply parsed search filters to an Alert query."""
    query = query.filter(Alert.user_id == user_id)
    if "ip" in filters:
        query = query.filter(Alert.source_ip == filters["ip"])
    if "severity" in filters:
        query = query.filter(Alert.severity == filters["severity"])
    if "rule" in filters:
        query = query.filter(Alert.rule_name == filters["rule"])
    return query


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


@router.get("/search", include_in_schema=False)
def search_page(
    request: Request,
    q: str = Query("", description="Structured search query"),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    project_filter = _resolve_project_filter(db, user, project_id)
    filters = parse_search_query(q) if q else {}

    events = []
    alerts = []
    if filters:
        events_q = apply_event_filters(db.query(LogEvent), filters, user.id)
        alerts_q = apply_alert_filters(db.query(Alert), filters, user.id)
        if project_filter is not None:
            events_q = events_q.filter(LogEvent.project_id == project_filter)
            alerts_q = alerts_q.filter(Alert.project_id == project_filter)

        events = (
            events_q
            .order_by(LogEvent.timestamp.desc())
            .limit(200)
            .all()
        )
        alerts = (
            alerts_q
            .order_by(Alert.created_at.desc())
            .limit(50)
            .all()
        )

    return templates.TemplateResponse(
        "search.html",
        {
            "request": request,
            "user": user,
            "query": q,
            "filters": filters,
            "events": events,
            "alerts": alerts,
            "active_project_id": project_filter,
        },
    )


@router.get("/api/search", tags=["Search"])
def api_search(
    q: str = Query(..., description="Structured query (e.g. ip:1.2.3.4 severity:high)"),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """JSON search endpoint."""
    project_filter = _resolve_project_filter(db, user, project_id)
    filters = parse_search_query(q)
    events_q = apply_event_filters(db.query(LogEvent), filters, user.id)
    alerts_q = apply_alert_filters(db.query(Alert), filters, user.id)
    if project_filter is not None:
        events_q = events_q.filter(LogEvent.project_id == project_filter)
        alerts_q = alerts_q.filter(Alert.project_id == project_filter)

    events = (
        events_q
        .order_by(LogEvent.timestamp.desc())
        .limit(200)
        .all()
    )
    alerts = (
        alerts_q
        .order_by(Alert.created_at.desc())
        .limit(50)
        .all()
    )
    from app.schemas import AlertOut, LogEventOut
    return {
        "filters": filters,
        "project_id": project_filter,
        "events": [LogEventOut.model_validate(e) for e in events],
        "alerts": [AlertOut.model_validate(a) for a in alerts],
    }
