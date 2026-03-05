"""
Ingest router — API-key-authenticated log ingestion (POST /api/ingest).

Accepts raw log text, parses it, persists events scoped to the API-key
owner, and runs detection.
"""

import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies_ingest import (
    enforce_agent_rate_limit,
    enforce_ingest_payload_limit,
    require_ingest_api_key,
)
from app.detection.engine import run_detection
from app.models import ApiKey, LogEvent, User
from app.parsers.auth_log import AuthLogParser
from app.parsers.nginx import NginxAccessParser
from app.services.auth_service import audit
from app.services.project_service import get_user_project_or_default

router = APIRouter(prefix="/api/ingest", tags=["Ingest"])

_auth_parser = AuthLogParser()
_nginx_parser = NginxAccessParser()


class IngestPayload(BaseModel):
    log_type: str = Field("auto", description="'auth', 'nginx', or 'auto'")
    filename: str = Field("api_ingest.log", max_length=256)
    content: str = Field(..., min_length=1, max_length=1_000_000,
                         description="Raw log text (max 1 MB)")


class IngestEventIn(BaseModel):
    timestamp: datetime | None = None
    level: str = Field("info", min_length=3, max_length=16)
    message: str = Field(..., min_length=1, max_length=4000)
    source: str = Field(..., min_length=1, max_length=64)
    ip: str | None = Field(None, max_length=45)
    user: str | None = Field(None, max_length=128)
    meta: dict | None = None

    @field_validator("level")
    @classmethod
    def validate_level(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"info", "warning", "error", "critical"}
        if normalized not in allowed:
            raise ValueError("level must be one of info|warning|error|critical")
        return normalized

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError as exc:
            raise ValueError("invalid ip") from exc


class BulkIngestPayload(BaseModel):
    events: list[IngestEventIn] = Field(..., min_length=1, max_length=500)


def _ingest_user_from_request(request: Request, db: Session, api_key: ApiKey) -> User:
    user = getattr(request.state, "ingest_user", None)
    if isinstance(user, User):
        return user
    owner = db.query(User).filter(User.id == api_key.user_id).first()
    if owner is None:
        raise HTTPException(status_code=401, detail="API key owner not found")
    return owner


def _serialize_event(event: IngestEventIn, user_id: int, project_id: int, file_name: str) -> LogEvent:
    payload_suffix = f" meta={event.meta}" if event.meta else ""
    return LogEvent(
        user_id=user_id,
        project_id=project_id,
        timestamp=event.timestamp or datetime.utcnow(),
        source_ip=event.ip,
        username=event.user,
        event_type=f"ingest_{event.level}",
        log_source=event.source,
        raw_line=f"{event.message}{payload_suffix}",
        file_name=file_name,
    )


@router.post("/")
def ingest_logs(
    request: Request,
    payload: IngestPayload,
    api_key: ApiKey = Depends(require_ingest_api_key),
    _payload_limit: None = Depends(enforce_ingest_payload_limit),
    db: Session = Depends(get_db),
) -> dict:
    """
    Ingest logs via API key.

    ```
    curl -X POST http://localhost:8000/api/ingest/ \\
            -H "X-API-Key: <YOUR_API_KEY>" \\
      -H "Content-Type: application/json" \\
      -d '{"log_type":"auth","filename":"myserver.log","content":"<raw log text>"}'
    ```
    """
    user = _ingest_user_from_request(request, db, api_key)

    parser = _resolve(payload.log_type, payload.filename)
    parsed = parser.parse_file(payload.content)
    if not parsed:
        raise HTTPException(422, "No valid log lines could be parsed.")

    enforce_agent_rate_limit(api_key=api_key, db=db, units=len(parsed))

    project_hint = api_key.project_id
    project = get_user_project_or_default(db, user, project_id=project_hint)

    db_events = [
        LogEvent(
            user_id=user.id,
            project_id=project.id,
            timestamp=ev.timestamp,
            source_ip=ev.source_ip,
            username=ev.username,
            event_type=ev.event_type,
            log_source=ev.log_source,
            raw_line=ev.raw_line,
            file_name=payload.filename,
        )
        for ev in parsed
    ]
    db.add_all(db_events)
    db.commit()

    new_alerts = run_detection(
        db,
        file_name=payload.filename,
        user_id=user.id,
        project_id=project.id,
    )

    audit(db, user.id, "ingest",
          f"{len(db_events)} events, {len(new_alerts)} alerts from API key")

    # Broadcast new events via WebSocket
    from app.websocket.manager import broadcast_events
    broadcast_events(user.id, db_events)

    return {
        "events_parsed": len(db_events),
        "alerts_generated": len(new_alerts),
        "project_id": project.id,
        "message": f"Ingested {len(db_events)} events for user {user.email}.",
    }


@router.post("/bulk")
def ingest_bulk_events(
    request: Request,
    payload: BulkIngestPayload,
    api_key: ApiKey = Depends(require_ingest_api_key),
    _payload_limit: None = Depends(enforce_ingest_payload_limit),
    db: Session = Depends(get_db),
) -> dict:
    user = _ingest_user_from_request(request, db, api_key)
    if not payload.events:
        raise HTTPException(status_code=400, detail="events list cannot be empty")
    if len(payload.events) > 500:
        raise HTTPException(status_code=413, detail="max 500 events per batch")

    enforce_agent_rate_limit(api_key=api_key, db=db, units=len(payload.events))

    project = get_user_project_or_default(db, user, project_id=api_key.project_id)
    db_events = [
        _serialize_event(event, user_id=user.id, project_id=project.id, file_name="api-bulk.json")
        for event in payload.events
    ]
    db.add_all(db_events)
    db.commit()

    new_alerts = run_detection(
        db,
        file_name="api-bulk.json",
        user_id=user.id,
        project_id=project.id,
    )

    audit(db, user.id, "ingest_bulk", f"{len(db_events)} structured events via API key")
    from app.websocket.manager import broadcast_events
    broadcast_events(user.id, db_events)

    return {
        "events_parsed": len(db_events),
        "alerts_generated": len(new_alerts),
        "project_id": project.id,
        "message": f"Bulk ingested {len(db_events)} events for user {user.email}.",
    }


def _resolve(log_type: str, filename: str):
    if log_type == "auth":
        return _auth_parser
    if log_type == "nginx":
        return _nginx_parser
    lower = filename.lower()
    if "auth" in lower or "secure" in lower or "sshd" in lower:
        return _auth_parser
    if "access" in lower or "nginx" in lower:
        return _nginx_parser
    raise HTTPException(400, "Cannot determine log type. Specify 'auth' or 'nginx'.")
