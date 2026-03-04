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
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import TEMPLATES_DIR
from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, User

router = APIRouter(tags=["Search"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

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


@router.get("/search", include_in_schema=False)
def search_page(
    request: Request,
    q: str = Query("", description="Structured search query"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    filters = parse_search_query(q) if q else {}

    events = []
    alerts = []
    if filters:
        events = (
            apply_event_filters(db.query(LogEvent), filters, user.id)
            .order_by(LogEvent.timestamp.desc())
            .limit(200)
            .all()
        )
        alerts = (
            apply_alert_filters(db.query(Alert), filters, user.id)
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
        },
    )


@router.get("/api/search", tags=["Search"])
def api_search(
    q: str = Query(..., description="Structured query (e.g. ip:1.2.3.4 severity:high)"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """JSON search endpoint."""
    filters = parse_search_query(q)
    events = (
        apply_event_filters(db.query(LogEvent), filters, user.id)
        .order_by(LogEvent.timestamp.desc())
        .limit(200)
        .all()
    )
    alerts = (
        apply_alert_filters(db.query(Alert), filters, user.id)
        .order_by(Alert.created_at.desc())
        .limit(50)
        .all()
    )
    from app.schemas import AlertOut, LogEventOut
    return {
        "filters": filters,
        "events": [LogEventOut.model_validate(e) for e in events],
        "alerts": [AlertOut.model_validate(a) for a in alerts],
    }
