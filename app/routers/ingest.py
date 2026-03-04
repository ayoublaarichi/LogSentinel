"""
Ingest router — API-key-authenticated log ingestion (POST /api/ingest).

Accepts raw log text, parses it, persists events scoped to the API-key
owner, and runs detection.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import rate_limit_ingest, require_api_key_user
from app.detection.engine import run_detection
from app.models import LogEvent, User
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
    content: str = Field(..., min_length=1, max_length=5_000_000,
                         description="Raw log text (max 5 MB)")


@router.post("/")
def ingest_logs(
    request: Request,
    payload: IngestPayload,
    user: User = Depends(require_api_key_user),
    _rl: None = Depends(rate_limit_ingest),
    db: Session = Depends(get_db),
) -> dict:
    """
    Ingest logs via API key.

    ```
    curl -X POST http://localhost:8000/api/ingest/ \\
      -H "Authorization: Bearer <YOUR_API_KEY>" \\
      -H "Content-Type: application/json" \\
      -d '{"log_type":"auth","filename":"myserver.log","content":"<raw log text>"}'
    ```
    """
    parser = _resolve(payload.log_type, payload.filename)
    parsed = parser.parse_file(payload.content)
    if not parsed:
        raise HTTPException(422, "No valid log lines could be parsed.")

    api_key = getattr(request.state, "api_key", None)
    project_hint = api_key.project_id if api_key is not None else None
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
