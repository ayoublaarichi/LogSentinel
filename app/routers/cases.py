from datetime import datetime
import json
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, Case, CaseActivity, CaseAlert, CaseChainSnapshot, CaseNote, Project, User
from app.routers.chains import build_chain_payload
from app.templating import templates

router = APIRouter(tags=["Cases"])

_ALLOWED_STATUS = {"open", "investigating", "resolved", "false_positive"}
_ALLOWED_PRIORITY = {"low", "medium", "high", "critical"}


def _resolve_project(db: Session, user: User, project_id: Optional[int]) -> Optional[int]:
    if project_id is None:
        return None
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.id


def _get_case(db: Session, user: User, case_id: int) -> Case:
    case = db.query(Case).filter(Case.id == case_id, Case.user_id == user.id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def _serialize_case(db: Session, case: Case) -> dict:
    alert_count = db.query(func.count(CaseAlert.id)).filter(CaseAlert.case_id == case.id).scalar() or 0
    return {
        "id": case.id,
        "project_id": case.project_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "priority": case.priority,
        "owner": case.owner,
        "alert_count": int(alert_count),
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }


def _log_activity(db: Session, case_id: int, actor: Optional[str], action: str, detail: Optional[str]) -> None:
    db.add(
        CaseActivity(
            case_id=case_id,
            actor=actor,
            action=action,
            detail=detail,
        )
    )


@router.get("/cases", include_in_schema=False)
def cases_page(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse("cases.html", {"request": request, "user": user})


@router.post("/api/cases", tags=["Cases"])
def create_case(
    payload: dict = Body(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    title = str(payload.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")

    priority = str(payload.get("priority") or "medium").strip().lower()
    if priority not in _ALLOWED_PRIORITY:
        raise HTTPException(status_code=400, detail="Invalid priority")

    status = str(payload.get("status") or "open").strip().lower()
    if status not in _ALLOWED_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")

    project_id = payload.get("project_id")
    project_filter = _resolve_project(db, user, int(project_id)) if project_id is not None else None

    case = Case(
        user_id=user.id,
        project_id=project_filter,
        title=title,
        description=(payload.get("description") or "").strip() or None,
        status=status,
        priority=priority,
        owner=(payload.get("owner") or user.email),
    )
    db.add(case)
    db.flush()
    _log_activity(db, case.id, user.email, "case_created", f"title={title}")
    db.commit()
    db.refresh(case)
    return _serialize_case(db, case)


@router.get("/api/cases", tags=["Cases"])
def list_cases(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    project_filter = _resolve_project(db, user, project_id)

    q = db.query(Case).filter(Case.user_id == user.id)
    if project_filter is not None:
        q = q.filter(Case.project_id == project_filter)
    if status:
        q = q.filter(Case.status == status)
    if priority:
        q = q.filter(Case.priority == priority)

    rows = q.order_by(Case.updated_at.desc(), Case.created_at.desc()).limit(300).all()
    return [_serialize_case(db, row) for row in rows]


@router.get("/api/cases/{case_id}", tags=["Cases"])
def get_case(
    case_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    case = _get_case(db, user, case_id)

    linked_alerts = (
        db.query(Alert)
        .join(CaseAlert, CaseAlert.alert_id == Alert.id)
        .filter(CaseAlert.case_id == case.id, Alert.user_id == user.id)
        .order_by(Alert.created_at.desc())
        .all()
    )

    notes = (
        db.query(CaseNote)
        .filter(CaseNote.case_id == case.id)
        .order_by(CaseNote.created_at.desc())
        .all()
    )

    activities = (
        db.query(CaseActivity)
        .filter(CaseActivity.case_id == case.id)
        .order_by(CaseActivity.created_at.desc())
        .limit(80)
        .all()
    )

    chain_snapshots = (
        db.query(CaseChainSnapshot)
        .filter(CaseChainSnapshot.case_id == case.id)
        .order_by(CaseChainSnapshot.created_at.desc())
        .limit(20)
        .all()
    )

    return {
        **_serialize_case(db, case),
        "linked_alerts": [
            {
                "id": alert.id,
                "project_id": alert.project_id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "event_count": alert.event_count,
                "first_seen": alert.first_seen,
                "last_seen": alert.last_seen,
                "created_at": alert.created_at,
            }
            for alert in linked_alerts
        ],
        "notes": [
            {
                "id": note.id,
                "author": note.author,
                "note": note.note,
                "created_at": note.created_at,
            }
            for note in notes
        ],
        "activities": [
            {
                "id": item.id,
                "actor": item.actor,
                "action": item.action,
                "detail": item.detail,
                "created_at": item.created_at,
            }
            for item in activities
        ],
        "chain_snapshots": [
            {
                "id": snap.id,
                "chain_id": snap.chain_id,
                "entity_type": snap.entity_type,
                "entity_value": snap.entity_value,
                "score": snap.score,
                "confidence": snap.confidence,
                "summary": snap.summary,
                "payload": json.loads(snap.payload),
                "created_at": snap.created_at,
            }
            for snap in chain_snapshots
        ],
    }


@router.post("/api/cases/{case_id}/alerts/{alert_id}", tags=["Cases"])
def link_alert_to_case(
    case_id: int,
    alert_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    case = _get_case(db, user, case_id)
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if case.project_id is not None and alert.project_id is not None and case.project_id != alert.project_id:
        raise HTTPException(status_code=400, detail="Alert project does not match case project")

    existing = (
        db.query(CaseAlert)
        .filter(CaseAlert.case_id == case.id, CaseAlert.alert_id == alert.id)
        .first()
    )
    if existing:
        return {"detail": "Alert already linked", "case_id": case.id, "alert_id": alert.id}

    db.add(CaseAlert(case_id=case.id, alert_id=alert.id))
    case.updated_at = datetime.utcnow()
    _log_activity(db, case.id, user.email, "alert_linked", f"alert_id={alert.id}")
    db.commit()
    return {"detail": "Alert linked", "case_id": case.id, "alert_id": alert.id}


@router.post("/api/cases/{case_id}/status", tags=["Cases"])
def update_case_status(
    case_id: int,
    payload: dict = Body(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    case = _get_case(db, user, case_id)
    status = str(payload.get("status") or "").strip().lower()
    if status not in _ALLOWED_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")

    case.status = status
    case.updated_at = datetime.utcnow()
    _log_activity(db, case.id, user.email, "status_changed", f"status={status}")
    db.commit()
    db.refresh(case)
    return _serialize_case(db, case)


@router.post("/api/cases/{case_id}/notes", tags=["Cases"])
def add_case_note(
    case_id: int,
    payload: dict = Body(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    case = _get_case(db, user, case_id)
    note_text = str(payload.get("note") or "").strip()
    if not note_text:
        raise HTTPException(status_code=400, detail="note is required")

    note = CaseNote(
        case_id=case.id,
        author=(payload.get("author") or user.email),
        note=note_text,
    )
    db.add(note)
    case.updated_at = datetime.utcnow()
    _log_activity(db, case.id, user.email, "note_added", f"note_id=pending")
    db.commit()
    db.refresh(note)
    return {
        "id": note.id,
        "case_id": case.id,
        "author": note.author,
        "note": note.note,
        "created_at": note.created_at,
    }


@router.post("/api/cases/{case_id}/chains/save", tags=["Cases"])
def save_chain_to_case(
    case_id: int,
    payload: dict = Body(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    case = _get_case(db, user, case_id)

    chain = payload.get("chain")
    if not isinstance(chain, dict):
        chain = build_chain_payload(
            db=db,
            user=user,
            ip=payload.get("ip"),
            user_name=payload.get("user"),
            host=payload.get("host"),
            alert_id=payload.get("alert_id"),
            hours=int(payload.get("hours") or 24),
            project_id=payload.get("project_id") or case.project_id,
        )

    entity = chain.get("entity") or {}
    snapshot = CaseChainSnapshot(
        case_id=case.id,
        chain_id=str(chain.get("chain_id") or f"case:{case.id}:chain"),
        entity_type=str(entity.get("type") or "unknown"),
        entity_value=str(entity.get("value") or "unknown"),
        score=int(chain.get("score") or 0),
        confidence=str(chain.get("confidence") or "Low"),
        summary=str(chain.get("summary") or ""),
        payload=json.dumps(chain),
    )
    db.add(snapshot)
    case.updated_at = datetime.utcnow()
    _log_activity(db, case.id, user.email, "chain_snapshot_saved", f"chain_id={snapshot.chain_id}")
    db.commit()
    db.refresh(snapshot)

    return {
        "id": snapshot.id,
        "case_id": case.id,
        "chain_id": snapshot.chain_id,
        "score": snapshot.score,
        "confidence": snapshot.confidence,
        "created_at": snapshot.created_at,
    }
