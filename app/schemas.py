"""
Pydantic schemas for API serialization.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


# ── Log Event ────────────────────────────────────────────────────────────────
class LogEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: Optional[int] = None
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str
    log_source: str
    raw_line: str
    file_name: str
    created_at: datetime


# ── Alert ────────────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: Optional[int] = None
    rule_name: str
    severity: str
    source_ip: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    usernames: list[str] = []
    status: str = "open"
    created_at: datetime

    @classmethod
    def model_validate(cls, obj, **kwargs):
        """Custom validation that decodes JSON usernames from the ORM model."""
        if hasattr(obj, "get_usernames"):
            data = {
                "id": obj.id,
                "project_id": getattr(obj, "project_id", None),
                "rule_name": obj.rule_name,
                "severity": obj.severity,
                "source_ip": obj.source_ip,
                "event_count": obj.event_count,
                "first_seen": obj.first_seen,
                "last_seen": obj.last_seen,
                "description": obj.description,
                "usernames": obj.get_usernames(),
                "status": getattr(obj, "status", "open"),
                "created_at": obj.created_at,
            }
            return cls(**data)
        return super().model_validate(obj, **kwargs)


# ── Upload response ──────────────────────────────────────────────────────────
class UploadResponse(BaseModel):
    filename: str
    events_parsed: int
    alerts_generated: int
    message: str


# ── User ─────────────────────────────────────────────────────────────────────
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    created_at: datetime


# ── API Key ──────────────────────────────────────────────────────────────────
class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    label: str
    key_prefix: str
    created_at: datetime
    revoked_at: Optional[datetime] = None
