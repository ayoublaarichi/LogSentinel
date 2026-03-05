"""
API-key service — generate, hash, validate, revoke per-user ingestion keys.

Each key is a 40-char hex token.  We store only a bcrypt hash + a 6-char
display prefix so the user can identify their key in the settings UI.
"""

import secrets
from datetime import datetime
from typing import Optional

import bcrypt
from sqlalchemy.orm import Session

from app.models import ApiKey, Project, User
from app.services.project_service import get_or_create_default_project


def generate_api_key(
    db: Session,
    user_id: int,
    label: str = "default",
    project_id: Optional[int] = None,
) -> tuple[str, ApiKey]:
    """
    Create a new API key for a user.
    Returns (plaintext_key, ApiKey ORM object).
    The plaintext key is shown ONCE; we store only the hash.
    """
    raw_key = secrets.token_hex(20)  # 40 hex chars
    prefix = raw_key[:6]
    hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    user = db.query(User).filter(User.id == user_id).first()
    resolved_project_id = None
    if user is not None:
        default_project = get_or_create_default_project(db, user)
        resolved_project_id = default_project.id
        if project_id is not None:
            selected_project = (
                db.query(Project)
                .filter(Project.id == project_id, Project.user_id == user.id)
                .first()
            )
            if selected_project is None:
                raise ValueError("Invalid project_id for this user")
            resolved_project_id = selected_project.id

    api_key = ApiKey(
        user_id=user_id,
        project_id=resolved_project_id,
        label=label.strip() or "default",
        key_prefix=prefix,
        key_hash=hashed,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    return raw_key, api_key


def validate_api_key(db: Session, raw_key: str) -> Optional[ApiKey]:
    """
    Validate an API key against all non-revoked keys.
    Uses the prefix to narrow the search, then bcrypt-verifies.
    """
    prefix = raw_key[:6]
    candidates = (
        db.query(ApiKey)
        .filter(ApiKey.key_prefix == prefix, ApiKey.revoked_at.is_(None))
        .all()
    )
    for ak in candidates:
        try:
            if bcrypt.checkpw(raw_key.encode(), ak.key_hash.encode()):
                return ak
        except Exception:
            continue
    return None


def revoke_api_key(db: Session, key_id: int, user_id: int) -> bool:
    """Revoke a key. Returns True on success, False if not found or not owned."""
    ak = (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.user_id == user_id)
        .first()
    )
    if not ak:
        return False
    ak.revoked_at = datetime.utcnow()
    db.commit()
    return True


def list_user_keys(db: Session, user_id: int) -> list[ApiKey]:
    """Return all keys (active + revoked) for a user, newest first."""
    return (
        db.query(ApiKey)
        .filter(ApiKey.user_id == user_id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )


def get_user_api_key(db: Session, key_id: int, user_id: int) -> Optional[ApiKey]:
    """Return a key owned by user, or None if not found."""
    return (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.user_id == user_id)
        .first()
    )


def rotate_agent_api_key(db: Session, key_id: int, user_id: int) -> tuple[str, ApiKey, ApiKey]:
    """Rotate an active agent key by revoking it and issuing a replacement.

    Returns (new_raw_key, old_key, new_key).
    Raises ValueError when key does not exist, is revoked, or is not an agent key.
    """
    old_key = get_user_api_key(db, key_id, user_id)
    if old_key is None:
        raise ValueError("API key not found")
    if old_key.revoked_at is not None:
        raise ValueError("API key already revoked")
    if not old_key.label.startswith("agent:"):
        raise ValueError("Only agent keys can be rotated from this endpoint")

    old_key.revoked_at = datetime.utcnow()
    db.commit()

    new_raw_key, new_key = generate_api_key(
        db,
        user_id=user_id,
        label=old_key.label,
        project_id=old_key.project_id,
    )
    return new_raw_key, old_key, new_key
