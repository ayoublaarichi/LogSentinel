"""
Auth router — signup, login, logout HTML pages + POST handlers.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.auth_service import (
    authenticate_user,
    audit,
    clear_session_cookie,
    create_password_reset_token,
    create_session_cookie,
    create_user,
    get_user_by_email,
    update_user_password,
    verify_password_reset_token,
)
from app.templating import templates

router = APIRouter(tags=["Auth"])


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
    create_session_cookie(response, user.id, request=request)
    return response


@router.get("/login", include_in_schema=False)
def login_page(request: Request):
    info = "Password updated. Please sign in." if request.query_params.get("reset") == "1" else None
    next_url = request.query_params.get("next", "/")
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "info": info, "next": next_url})


@router.post("/login", include_in_schema=False)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    remember: str = Form(""),
    next: str = Form("/"),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, email, password)
    if not user:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid email or password.", "info": None, "next": next}
        )

    audit(db, user.id, "login", f"Login: {user.email}",
          ip=request.client.host if request.client else "")
    # Sanitise redirect target — only allow relative paths to prevent open-redirect.
    redirect_to = next if next.startswith("/") else "/"
    response = RedirectResponse(redirect_to, status_code=303)
    create_session_cookie(response, user.id, remember=bool(remember), request=request)
    return response


@router.get("/forgot-password", include_in_schema=False)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        "forgot_password.html",
        {"request": request, "error": None, "info": None, "reset_url": None},
    )


@router.post("/forgot-password", include_in_schema=False)
def forgot_password_submit(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    candidate = get_user_by_email(db, email)
    reset_url = None
    if candidate:
        token = create_password_reset_token(candidate.email)
        base = str(request.base_url).rstrip("/")
        reset_url = f"{base}/reset-password?token={token}"
        audit(
            db,
            candidate.id,
            "password_reset_requested",
            "Password reset link generated",
            ip=request.client.host if request.client else "",
        )

    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "error": None,
            "info": "If an account exists for that email, a reset link is ready below.",
            "reset_url": reset_url,
        },
    )


@router.get("/reset-password", include_in_schema=False)
def reset_password_page(request: Request, token: str = ""):
    email = verify_password_reset_token(token)
    if not email:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": "",
                "error": "Invalid or expired reset link.",
                "info": None,
            },
        )
    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "token": token, "error": None, "info": None},
    )


@router.post("/reset-password", include_in_schema=False)
def reset_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    db: Session = Depends(get_db),
):
    email = verify_password_reset_token(token)
    if not email:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": "",
                "error": "Invalid or expired reset link.",
                "info": None,
            },
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": token,
                "error": "Password must be at least 8 characters.",
                "info": None,
            },
        )

    if password != password2:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": token,
                "error": "Passwords do not match.",
                "info": None,
            },
        )

    user = get_user_by_email(db, email)
    if not user:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": "",
                "error": "Invalid or expired reset link.",
                "info": None,
            },
        )

    update_user_password(db, user, password)
    audit(
        db,
        user.id,
        "password_reset_completed",
        "Password updated via reset flow",
        ip=request.client.host if request.client else "",
    )
    return RedirectResponse("/login?reset=1", status_code=303)


@router.get("/logout", include_in_schema=False)
def logout(request: Request, db: Session = Depends(get_db)):
    from app.services.auth_service import get_user_id_from_cookie
    uid = get_user_id_from_cookie(request)
    if uid:
        audit(db, uid, "logout", "", ip=request.client.host if request.client else "")
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response, request=request)
    return response
