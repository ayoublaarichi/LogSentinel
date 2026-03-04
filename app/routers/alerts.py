"""
Alerts router — list / get / delete alerts, always scoped by user_id.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, User
from app.schemas import AlertOut

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/", response_model=list[AlertOut])
def list_alerts(
    severity: Optional[str] = Query(None),
    rule_name: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    query = db.query(Alert).filter(Alert.user_id == user.id)
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
def alert_stats(user: User = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    base = db.query(func.count(Alert.id)).filter(Alert.user_id == user.id)
    total = base.scalar() or 0
    critical = base.filter(Alert.severity == "critical").scalar() or 0
    high = (
        db.query(func.count(Alert.id))
        .filter(Alert.user_id == user.id, Alert.severity == "high")
        .scalar() or 0
    )
    medium = (
        db.query(func.count(Alert.id))
        .filter(Alert.user_id == user.id, Alert.severity == "medium")
        .scalar() or 0
    )
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
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> AlertOut:
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return AlertOut.model_validate(alert)


@router.delete("/{alert_id}")
def delete_alert(
    alert_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    db.delete(alert)
    db.commit()
    return {"detail": f"Alert {alert_id} deleted."}
