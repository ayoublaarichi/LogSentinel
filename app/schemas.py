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
    """Schema returned when listing alerts."""

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
