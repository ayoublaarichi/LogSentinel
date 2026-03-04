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

from app.models import ApiKey


def generate_api_key(db: Session, user_id: int, label: str = "default") -> tuple[str, ApiKey]:
    """
    Create a new API key for a user.
    Returns (plaintext_key, ApiKey ORM object).
    The plaintext key is shown ONCE; we store only the hash.
    """
    raw_key = secrets.token_hex(20)  # 40 hex chars
    prefix = raw_key[:6]
    hashed = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    api_key = ApiKey(
        user_id=user_id,
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
