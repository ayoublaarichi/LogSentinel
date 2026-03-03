"""
Upload router — handles log file ingestion, parsing, and detection.
"""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.engine import run_detection
from app.models import LogEvent
from app.parsers.auth_log import AuthLogParser
from app.parsers.nginx import NginxAccessParser
from app.schemas import UploadResponse

router = APIRouter(prefix="/api/upload", tags=["Upload"])

# Parser instances (stateless, safe to reuse)
_auth_parser = AuthLogParser()
_nginx_parser = NginxAccessParser()


@router.post("/", response_model=UploadResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    log_type: str = "auto",
    db: Session = Depends(get_db),
) -> UploadResponse:
    """
    Upload a log file for parsing and analysis.

    - **file**: The log file to upload (.log or .txt).
    - **log_type**: ``"auth"``, ``"nginx"``, or ``"auto"`` (detect from filename).
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    content = (await file.read()).decode("utf-8", errors="replace")
    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # ── Determine parser ─────────────────────────────────────────────────
    parser = _resolve_parser(file.filename, log_type)

    # ── Parse ─────────────────────────────────────────────────────────────
    parsed_events = parser.parse_file(content)
    if not parsed_events:
        raise HTTPException(
            status_code=422,
            detail="No valid log lines could be parsed from the file.",
        )

    # ── Persist events ───────────────────────────────────────────────────
    db_events = [
        LogEvent(
            timestamp=ev.timestamp,
            source_ip=ev.source_ip,
            username=ev.username,
            event_type=ev.event_type,
            log_source=ev.log_source,
            raw_line=ev.raw_line,
            file_name=file.filename,
        )
        for ev in parsed_events
    ]
    db.add_all(db_events)
    db.commit()

    # ── Run detection engine ─────────────────────────────────────────────
    new_alerts = run_detection(db, file_name=file.filename)

    return UploadResponse(
        filename=file.filename,
        events_parsed=len(db_events),
        alerts_generated=len(new_alerts),
        message=f"Successfully parsed {len(db_events)} events and generated {len(new_alerts)} alert(s).",
    )


def _resolve_parser(filename: str, log_type: str):
    """Return the appropriate parser based on log_type or filename heuristics."""
    if log_type == "auth":
        return _auth_parser
    if log_type == "nginx":
        return _nginx_parser
    if log_type == "auto":
        lower = filename.lower()
        if "auth" in lower or "secure" in lower or "sshd" in lower:
            return _auth_parser
        if "access" in lower or "nginx" in lower:
            return _nginx_parser
    raise HTTPException(
        status_code=400,
        detail=(
            f"Cannot determine log type for '{filename}'. "
            "Please specify log_type as 'auth' or 'nginx'."
        ),
    )
