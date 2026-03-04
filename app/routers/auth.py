"""
Auth router — signup, login, logout HTML pages + POST handlers.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import TEMPLATES_DIR
from app.database import get_db
from app.services.auth_service import (
    authenticate_user,
    audit,
    clear_session_cookie,
    create_session_cookie,
    create_user,
    get_user_by_email,
)

router = APIRouter(tags=["Auth"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/signup", include_in_schema=False)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request, "error": None})


@router.post("/signup", include_in_schema=False)
def signup_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    db: Session = Depends(get_db),
):
    error = None
    if len(password) < 8:
        error = "Password must be at least 8 characters."
    elif password != password2:
        error = "Passwords do not match."
    elif get_user_by_email(db, email):
        error = "An account with that email already exists."

    if error:
        return templates.TemplateResponse("signup.html", {"request": request, "error": error})

    user = create_user(db, email, password)
    audit(db, user.id, "signup", f"New account: {user.email}",
          ip=request.client.host if request.client else "")
    response = RedirectResponse("/", status_code=303)
    create_session_cookie(response, user.id)
    return response


@router.get("/login", include_in_schema=False)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", include_in_schema=False)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, email, password)
    if not user:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid email or password."}
        )

    audit(db, user.id, "login", f"Login: {user.email}",
          ip=request.client.host if request.client else "")
    response = RedirectResponse("/", status_code=303)
    create_session_cookie(response, user.id)
    return response


@router.get("/logout", include_in_schema=False)
def logout(request: Request, db: Session = Depends(get_db)):
    from app.services.auth_service import get_user_id_from_cookie
    uid = get_user_id_from_cookie(request)
    if uid:
        audit(db, uid, "logout", "", ip=request.client.host if request.client else "")
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    return response
