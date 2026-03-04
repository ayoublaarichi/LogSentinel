"""
Authentication service — password hashing, session management, user CRUD.
"""

import logging
import secrets
from datetime import datetime
from typing import Optional

import bcrypt
from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import (
    SECRET_KEY,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE,
    SESSION_MAX_AGE,
)
from app.models import AuditLog, User

logger = logging.getLogger("logsentinel.auth")

_serializer = URLSafeTimedSerializer(SECRET_KEY)
RESET_TOKEN_MAX_AGE = 1800


# ── Password helpers ─────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── User CRUD ────────────────────────────────────────────────────────────────
def create_user(db: Session, email: str, password: str) -> User:
    user = User(email=email.lower().strip(), password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email.lower().strip()).first()


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if user and verify_password(password, user.password_hash):
        return user
    return None


def update_user_password(db: Session, user: User, password: str) -> None:
    user.password_hash = hash_password(password)
    db.add(user)
    db.commit()


def create_password_reset_token(email: str) -> str:
    payload = {"email": email.lower().strip(), "nonce": secrets.token_hex(8)}
    return _serializer.dumps(payload, salt="password-reset")


def verify_password_reset_token(token: str) -> Optional[str]:
    try:
        data = _serializer.loads(
            token,
            max_age=RESET_TOKEN_MAX_AGE,
            salt="password-reset",
        )
        email = data.get("email", "")
        if not email:
            return None
        return str(email).lower().strip()
    except (BadSignature, Exception):
        return None


# ── Session cookie helpers ───────────────────────────────────────────────────
REMEMBER_ME_MAX_AGE = 86400 * 30  # 30 days


def create_session_cookie(
    response: Response, user_id: int, *, remember: bool = False
) -> None:
    token = _serializer.dumps({"uid": user_id})
    age = REMEMBER_ME_MAX_AGE if remember else SESSION_MAX_AGE
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=age,
        path="/",
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
        secure=SESSION_COOKIE_SECURE,
    )
    logger.info("Session cookie set for user_id=%s (remember=%s, secure=%s)",
                user_id, remember, SESSION_COOKIE_SECURE)


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
        secure=SESSION_COOKIE_SECURE,
    )


def get_user_id_from_cookie(request: Request) -> Optional[int]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        logger.debug("Auth: no session cookie '%s' in request", SESSION_COOKIE_NAME)
        return None
    try:
        data = _serializer.loads(token, max_age=REMEMBER_ME_MAX_AGE)
        uid = data.get("uid")
        if uid is None:
            logger.warning("Auth: session token decoded but missing 'uid' key")
        return uid
    except SignatureExpired:
        logger.info("Auth: session cookie expired")
        return None
    except BadSignature:
        logger.warning("Auth: session cookie has invalid signature (tampered or wrong SECRET_KEY)")
        return None
    except Exception as exc:
        logger.warning("Auth: unexpected error decoding session cookie: %s", exc)
        return None


def get_current_user(request: Request, db: Session) -> Optional[User]:
    uid = get_user_id_from_cookie(request)
    if uid is None:
        return None
    user = db.query(User).filter(User.id == uid).first()
    if user is None:
        logger.warning("Auth: valid session token for uid=%s but user not found in DB", uid)
    return user


# ── Audit log helpers ────────────────────────────────────────────────────────
def audit(db: Session, user_id: Optional[int], action: str,
          detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, detail=detail, ip_address=ip))
    db.commit()
