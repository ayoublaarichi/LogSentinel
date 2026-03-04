"""
Project service helpers for default project lifecycle and access checks.
"""

from typing import Optional

from sqlalchemy.orm import Session

from app.models import Project, User

DEFAULT_PROJECT_NAME = "Default"


def get_or_create_default_project(db: Session, user: User) -> Project:
    project = (
        db.query(Project)
        .filter(Project.user_id == user.id, Project.name == DEFAULT_PROJECT_NAME)
        .first()
    )
    if project:
        return project

    project = Project(
        user_id=user.id,
        name=DEFAULT_PROJECT_NAME,
        description="Auto-created default project",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def get_user_project_or_default(
    db: Session,
    user: User,
    project_id: Optional[int] = None,
) -> Project:
    if project_id is not None:
        project = (
            db.query(Project)
            .filter(Project.id == project_id, Project.user_id == user.id)
            .first()
        )
        if project:
            return project

    return get_or_create_default_project(db, user)
