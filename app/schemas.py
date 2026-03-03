"""
Pydantic schemas for API request/response validation.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


# ── LogEvent Schemas ─────────────────────────────────────────────────────────
class LogEventOut(BaseModel):
    """Schema returned when listing log events."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str
    log_source: str
    raw_line: str
    file_name: str
    created_at: datetime


class LogEventFilter(BaseModel):
    """Query parameters for filtering events."""

    source_ip: Optional[str] = None
    event_type: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = 1
    per_page: int = 50


# ── Alert Schemas ────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    """
    Schema returned when listing alerts.

    `usernames` is decoded from the JSON-encoded column on the model so
    consumers always receive a plain Python list, never a raw JSON string.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_name: str
    severity: str
    source_ip: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    created_at: datetime
    # Decoded list of unique usernames targeted by this attacker IP.
    # Falls back to [] for legacy alerts that predate the column.
    usernames: list[str] = []

    @classmethod
    def model_validate(cls, obj, **kw):  # type: ignore[override]
        """Decode the JSON usernames string before pydantic sees it."""
        if hasattr(obj, "get_usernames"):
            # ORM object — call the helper to decode JSON → list[str]
            data = {
                "id": obj.id,
                "rule_name": obj.rule_name,
                "severity": obj.severity,
                "source_ip": obj.source_ip,
                "event_count": obj.event_count,
                "first_seen": obj.first_seen,
                "last_seen": obj.last_seen,
                "description": obj.description,
                "created_at": obj.created_at,
                "usernames": obj.get_usernames(),
            }
            return cls(**data)
        return super().model_validate(obj, **kw)


# ── Upload Response ──────────────────────────────────────────────────────────
class UploadResponse(BaseModel):
    """Response after a successful log file upload."""

    filename: str
    events_parsed: int
    alerts_generated: int
    message: str


# ── Dashboard Stats ──────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    """Aggregate statistics for the dashboard."""

    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    unique_ips: int
    recent_alerts: list[AlertOut]
