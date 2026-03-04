"""
Projects router — CRUD operations for user-owned project scopes.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, ApiKey, AuditLog, LogEvent, Project, User
from app.services.project_service import DEFAULT_PROJECT_NAME, get_or_create_default_project

router = APIRouter(prefix="/api/projects", tags=["Projects"])


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=2000)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=2000)


def _as_dict(p: Project) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "is_default": p.name == DEFAULT_PROJECT_NAME,
    }


@router.get("/")
def list_projects(user: User = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    get_or_create_default_project(db, user)
    rows = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.created_at.asc())
        .all()
    )
    return [_as_dict(p) for p in rows]


@router.post("/")
def create_project(
    payload: ProjectCreate,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Project name cannot be empty")

    exists = (
        db.query(Project)
        .filter(Project.user_id == user.id, Project.name == name)
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Project name already exists")

    project = Project(user_id=user.id, name=name, description=payload.description)
    db.add(project)
    db.commit()
    db.refresh(project)
    return _as_dict(project)


@router.patch("/{project_id}")
def update_project(
    project_id: int,
    payload: ProjectUpdate,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Project name cannot be empty")
        dupe = (
            db.query(Project)
            .filter(Project.user_id == user.id, Project.name == name, Project.id != project.id)
            .first()
        )
        if dupe:
            raise HTTPException(status_code=409, detail="Project name already exists")
        project.name = name

    if payload.description is not None:
        project.description = payload.description

    db.commit()
    db.refresh(project)
    return _as_dict(project)


@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.name == DEFAULT_PROJECT_NAME:
        raise HTTPException(status_code=400, detail="Default project cannot be deleted")

    fallback = get_or_create_default_project(db, user)

    db.query(LogEvent).filter(LogEvent.user_id == user.id, LogEvent.project_id == project.id).update(
        {"project_id": fallback.id}, synchronize_session=False
    )
    db.query(Alert).filter(Alert.user_id == user.id, Alert.project_id == project.id).update(
        {"project_id": fallback.id}, synchronize_session=False
    )
    db.query(ApiKey).filter(ApiKey.user_id == user.id, ApiKey.project_id == project.id).update(
        {"project_id": fallback.id}, synchronize_session=False
    )
    db.query(AuditLog).filter(AuditLog.user_id == user.id, AuditLog.project_id == project.id).update(
        {"project_id": fallback.id}, synchronize_session=False
    )

    db.delete(project)
    db.commit()
    return {"deleted": project_id, "reassigned_to": fallback.id}
