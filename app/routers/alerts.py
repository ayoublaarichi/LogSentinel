"""
Alerts router — list / get / delete alerts, always scoped by user_id.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, Project, User
from app.schemas import AlertOut

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


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


@router.get("/", response_model=list[AlertOut])
def list_alerts(
    severity: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
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
    return [AlertOut.model_validate(a) for a in alerts]


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
    return AlertOut.model_validate(alert)


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
