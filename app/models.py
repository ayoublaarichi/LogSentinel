"""
SQLAlchemy ORM models for LogSentinel — multi-tenant SIEM.

Tables:
    users              – registered accounts (email + bcrypt hash)
    projects           – per-user investigation / environment scopes
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
    UniqueConstraint,
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
    projects: Mapped[list["Project"]] = relationship(back_populates="owner", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"


# ═══════════════════════════════════════════════════════════════════════════════
#  Project (per-user scope)
# ═══════════════════════════════════════════════════════════════════════════════
class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_projects_user_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    owner: Mapped["User"] = relationship(back_populates="projects")
    events: Mapped[list["LogEvent"]] = relationship(back_populates="project", lazy="dynamic")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="project", lazy="dynamic")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="project", lazy="dynamic")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="project", lazy="dynamic")


# ═══════════════════════════════════════════════════════════════════════════════
#  API Key  (per-user ingestion tokens — stored as bcrypt hash)
# ═══════════════════════════════════════════════════════════════════════════════
class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    owner: Mapped["User"] = relationship(back_populates="api_keys")
    project: Mapped[Optional["Project"]] = relationship(back_populates="api_keys")


# ═══════════════════════════════════════════════════════════════════════════════
#  Log Event  (scoped by user_id)
# ═══════════════════════════════════════════════════════════════════════════════
class LogEvent(Base):
    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    project_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
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
    project: Mapped[Optional["Project"]] = relationship(back_populates="events")

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
    project_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
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
    project: Mapped[Optional["Project"]] = relationship(back_populates="alerts")

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
    project_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    project: Mapped[Optional["Project"]] = relationship(back_populates="audit_logs")


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    priority: Mapped[str] = mapped_column(String(32), nullable=False, default="medium", index=True)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class CaseAlert(Base):
    __tablename__ = "case_alerts"
    __table_args__ = (UniqueConstraint("case_id", "alert_id", name="uq_case_alerts_case_alert"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
