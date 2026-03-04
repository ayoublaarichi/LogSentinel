"""
Upload router — file upload, parse, detect, user-scoped.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.detection.engine import run_detection
from app.models import LogEvent, User
from app.parsers.auth_log import AuthLogParser
from app.parsers.nginx import NginxAccessParser

router = APIRouter(prefix="/api/upload", tags=["Upload"])

_auth_parser = AuthLogParser()
_nginx_parser = NginxAccessParser()


@router.post("/")
async def upload_log(
    file: UploadFile = File(...),
    log_type: str = Query("auto"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """Upload a log file, parse it, persist events, run detection."""
    content = (await file.read()).decode("utf-8", errors="replace")

    parser = _resolve(log_type, file.filename or "unknown.log")
    parsed = parser.parse_file(content)

    if not parsed:
        raise HTTPException(status_code=422, detail="No valid log lines could be parsed.")

    db_events = [
        LogEvent(
            user_id=user.id,
            timestamp=ev.timestamp,
            source_ip=ev.source_ip,
            username=ev.username,
            event_type=ev.event_type,
            log_source=ev.log_source,
            raw_line=ev.raw_line,
            file_name=file.filename or "unknown.log",
        )
        for ev in parsed
    ]
    db.add_all(db_events)
    db.commit()

    new_alerts = run_detection(db, file_name=file.filename or "unknown.log", user_id=user.id)

    # Broadcast new events via WebSocket
    try:
        from app.websocket.manager import broadcast_events
        broadcast_events(user.id, db_events)
    except Exception:
        pass

    return {
        "filename": file.filename,
        "events_parsed": len(db_events),
        "alerts_generated": len(new_alerts),
        "message": f"Parsed {len(db_events)} events, generated {len(new_alerts)} alerts.",
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
