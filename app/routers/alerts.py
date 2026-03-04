"""
Alerts router — list / get / delete alerts, always scoped by user_id.
"""

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, AuditLog, Project, User
from app.schemas import AlertOut

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

_ALERT_ID_RE = re.compile(r"\balert_id=(\d+)\b")


def _validate_project(db: Session, user: User, project_id: Optional[int]) -> Optional[int]:
    if project_id is None:
        return None
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")
    return project.id


def _parse_alert_id(detail: Optional[str]) -> Optional[int]:
    if not detail:
        return None
    match = _ALERT_ID_RE.search(detail)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


def _status_map(db: Session, user_id: int, alert_ids: list[int]) -> dict[int, str]:
    if not alert_ids:
        return {}
    status = {alert_id: "open" for alert_id in alert_ids}
    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user_id,
            AuditLog.action.in_(["alert_ack", "alert_close"]),
            AuditLog.detail.isnot(None),
        )
        .order_by(AuditLog.created_at.asc())
        .all()
    )
    alert_id_set = set(alert_ids)
    for log in logs:
        alert_id = _parse_alert_id(log.detail)
        if alert_id is None or alert_id not in alert_id_set:
            continue
        if log.action == "alert_close":
            status[alert_id] = "closed"
            continue
        if status[alert_id] != "closed":
            status[alert_id] = "acked"
    return status


def _serialize_alert(alert: Alert, status: str) -> AlertOut:
    return AlertOut(
        id=alert.id,
        project_id=alert.project_id,
        rule_name=alert.rule_name,
        severity=alert.severity,
        source_ip=alert.source_ip,
        event_count=alert.event_count,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
        description=alert.description,
        usernames=alert.get_usernames(),
        status=status,
        created_at=alert.created_at,
    )


@router.get("/", response_model=list[AlertOut])
def list_alerts(
    severity: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    project_id: Optional[int] = Query(None, ge=1),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    project_filter = _validate_project(db, user, project_id)
    query = db.query(Alert).filter(Alert.user_id == user.id)
    if project_filter is not None:
        query = query.filter(Alert.project_id == project_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    if rule_name:
        query = query.filter(Alert.rule_name == rule_name)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)

    alerts = (
        query.order_by(Alert.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    statuses = _status_map(db, user.id, [a.id for a in alerts])
    normalized_status = (status or "").strip().lower()
    rows: list[AlertOut] = []
    for alert in alerts:
        computed = statuses.get(alert.id, "open")
        if normalized_status and normalized_status in {"open", "acked", "closed"}:
            if computed != normalized_status:
                continue
        rows.append(_serialize_alert(alert, computed))
    return rows


@router.get("/stats")
def alert_stats(
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    project_filter = _validate_project(db, user, project_id)
    base = db.query(func.count(Alert.id)).filter(Alert.user_id == user.id)
    if project_filter is not None:
        base = base.filter(Alert.project_id == project_filter)
    total = base.scalar() or 0
    critical = base.filter(Alert.severity == "critical").scalar() or 0
    high_q = db.query(func.count(Alert.id)).filter(Alert.user_id == user.id, Alert.severity == "high")
    medium_q = db.query(func.count(Alert.id)).filter(Alert.user_id == user.id, Alert.severity == "medium")
    if project_filter is not None:
        high_q = high_q.filter(Alert.project_id == project_filter)
        medium_q = medium_q.filter(Alert.project_id == project_filter)
    high = high_q.scalar() or 0
    medium = medium_q.scalar() or 0
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": total - critical - high - medium,
    }


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> AlertOut:
    project_filter = _validate_project(db, user, project_id)
    q = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id)
    if project_filter is not None:
        q = q.filter(Alert.project_id == project_filter)
    alert = q.first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    status = _status_map(db, user.id, [alert.id]).get(alert.id, "open")
    return _serialize_alert(alert, status)


@router.post("/{alert_id}/ack")
def acknowledge_alert(
    alert_id: int,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    project_filter = _validate_project(db, user, project_id)
    q = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id)
    if project_filter is not None:
        q = q.filter(Alert.project_id == project_filter)
    alert = q.first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    current_status = _status_map(db, user.id, [alert.id]).get(alert.id, "open")
    if current_status == "closed":
        return {"id": alert.id, "status": "closed", "detail": "Alert already closed."}
    if current_status == "acked":
        return {"id": alert.id, "status": "acked", "detail": "Alert already acknowledged."}

    db.add(
        AuditLog(
            user_id=user.id,
            project_id=alert.project_id,
            action="alert_ack",
            detail=f"alert_id={alert.id}",
            ip_address=None,
        )
    )
    db.commit()
    return {"id": alert.id, "status": "acked", "detail": "Alert acknowledged."}


@router.post("/{alert_id}/close")
def close_alert(
    alert_id: int,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    project_filter = _validate_project(db, user, project_id)
    q = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id)
    if project_filter is not None:
        q = q.filter(Alert.project_id == project_filter)
    alert = q.first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    current_status = _status_map(db, user.id, [alert.id]).get(alert.id, "open")
    if current_status == "closed":
        return {"id": alert.id, "status": "closed", "detail": "Alert already closed."}

    db.add(
        AuditLog(
            user_id=user.id,
            project_id=alert.project_id,
            action="alert_close",
            detail=f"alert_id={alert.id}",
            ip_address=None,
        )
    )
    db.commit()
    return {"id": alert.id, "status": "closed", "detail": "Alert closed."}


@router.delete("/{alert_id}")
def delete_alert(
    alert_id: int,
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    project_filter = _validate_project(db, user, project_id)
    q = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id)
    if project_filter is not None:
        q = q.filter(Alert.project_id == project_filter)
    alert = q.first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    db.delete(alert)
    db.commit()
    return {"detail": f"Alert {alert_id} deleted."}
