"""
SQLAlchemy ORM models for LogSentinel — multi-tenant SIEM.

Tables:
    users              – registered accounts (email + bcrypt hash)
    api_keys           – per-user API ingestion keys (stored hashed)
    log_events         – parsed log events (scoped by user_id)
    alerts             – detection-engine alerts (scoped by user_id)
    threat_intel_cache – cached IP enrichment data
    audit_logs         – security-relevant actions
"""

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ═══════════════════════════════════════════════════════════════════════════════
#  User
# ═══════════════════════════════════════════════════════════════════════════════
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    events: Mapped[list["LogEvent"]] = relationship(back_populates="owner", lazy="dynamic")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="owner", lazy="dynamic")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="owner", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"


# ═══════════════════════════════════════════════════════════════════════════════
#  API Key  (per-user ingestion tokens — stored as bcrypt hash)
# ═══════════════════════════════════════════════════════════════════════════════
class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    owner: Mapped["User"] = relationship(back_populates="api_keys")


# ═══════════════════════════════════════════════════════════════════════════════
#  Log Event  (scoped by user_id)
# ═══════════════════════════════════════════════════════════════════════════════
class LogEvent(Base):
    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    log_source: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_line: Mapped[str] = mapped_column(Text, nullable=False)
    file_name: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    owner: Mapped[Optional["User"]] = relationship(back_populates="events")

    def __repr__(self) -> str:
        return f"<LogEvent id={self.id} type={self.event_type} ip={self.source_ip}>"


# ═══════════════════════════════════════════════════════════════════════════════
#  Alert  (scoped by user_id)
# ═══════════════════════════════════════════════════════════════════════════════
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    usernames: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    owner: Mapped[Optional["User"]] = relationship(back_populates="alerts")

    def get_usernames(self) -> list[str]:
        if not self.usernames:
            return []
        try:
            return json.loads(self.usernames)
        except (json.JSONDecodeError, TypeError):
            return []

    @staticmethod
    def encode_usernames(names: list[str]) -> str:
        return json.dumps(sorted(set(names)))

    def __repr__(self) -> str:
        return f"<Alert id={self.id} rule={self.rule_name} sev={self.severity}>"


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Intelligence Cache
# ═══════════════════════════════════════════════════════════════════════════════
class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    isp: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    reputation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_tor: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=0)
    raw_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Audit Log
# ═══════════════════════════════════════════════════════════════════════════════
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
