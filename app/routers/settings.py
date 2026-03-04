"""
Settings router — API key management page.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import User
from app.services.api_key_service import generate_api_key, list_user_keys, revoke_api_key
from app.services.auth_service import audit
from app.templating import templates

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("/api-keys", include_in_schema=False)
def api_keys_page(
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    keys = list_user_keys(db, user.id)
    return templates.TemplateResponse(
        "api_keys.html",
        {"request": request, "user": user, "keys": keys, "new_key": None},
    )


@router.post("/api-keys/create", include_in_schema=False)
def create_key(
    request: Request,
    label: str = Form("default"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    raw_key, _obj = generate_api_key(db, user.id, label)
    audit(db, user.id, "api_key_created", f"prefix={_obj.key_prefix}",
          ip=request.client.host if request.client else "")
    keys = list_user_keys(db, user.id)
    return templates.TemplateResponse(
        "api_keys.html",
        {"request": request, "user": user, "keys": keys, "new_key": raw_key},
    )


@router.post("/api-keys/{key_id}/revoke", include_in_schema=False)
def revoke_key(
    key_id: int,
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    revoke_api_key(db, key_id, user.id)
    audit(db, user.id, "api_key_revoked", f"key_id={key_id}",
          ip=request.client.host if request.client else "")
    return RedirectResponse("/settings/api-keys", status_code=303)
