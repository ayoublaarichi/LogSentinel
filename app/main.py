"""
LogSentinel — Multi-Tenant SOC Log Analyzer & Detection Dashboard.

FastAPI application entry point.
"""

import socket
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.config import (
    APP_DESCRIPTION,
    APP_TITLE,
    APP_VERSION,
    STATIC_DIR,
    TEMPLATES_DIR,
)
from app.database import get_db, init_db
from app.dependencies import get_current_user, require_user
from app.models import Alert, LogEvent, User


# ── Lifespan ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
)

# ── Static files ─────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ── 401 handler — redirect browsers to /login ───────────────────────────────
from starlette.exceptions import HTTPException as StarletteHTTPException


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 401:
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": exc.detail}, status_code=401)
    # Let FastAPI handle other HTTP exceptions normally
    if exc.status_code == 422:
        return JSONResponse({"detail": exc.detail}, status_code=422)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# ── Include routers ──────────────────────────────────────────────────────────
from app.routers import alerts, auth, events, ingest, investigate, search, settings, upload  # noqa: E402

app.include_router(auth.router)
app.include_router(upload.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(ingest.router)
app.include_router(settings.router)
app.include_router(investigate.router)
app.include_router(search.router)


# ═══════════════════════════════════════════════════════════════════════════════
#  HTML page routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    total_events = db.query(func.count(LogEvent.id)).filter(LogEvent.user_id == user.id).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.user_id == user.id).scalar() or 0
    critical_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.user_id == user.id, Alert.severity == "critical")
        .scalar() or 0
    )
    high_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.user_id == user.id, Alert.severity == "high")
        .scalar() or 0
    )
    medium_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.user_id == user.id, Alert.severity == "medium")
        .scalar() or 0
    )
    unique_ips = (
        db.query(func.count(distinct(LogEvent.source_ip)))
        .filter(LogEvent.user_id == user.id, LogEvent.source_ip.isnot(None))
        .scalar() or 0
    )
    recent_alerts = (
        db.query(Alert)
        .filter(Alert.user_id == user.id)
        .order_by(Alert.created_at.desc())
        .limit(5)
        .all()
    )
    recent_events = (
        db.query(LogEvent)
        .filter(LogEvent.user_id == user.id)
        .order_by(LogEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "total_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "unique_ips": unique_ips,
            "recent_alerts": recent_alerts,
            "recent_events": recent_events,
        },
    )


@app.get("/upload", response_class=HTMLResponse, include_in_schema=False)
def upload_page(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse("upload.html", {"request": request, "user": user})


@app.get("/events", response_class=HTMLResponse, include_in_schema=False)
def events_page(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse("events.html", {"request": request, "user": user})


@app.get("/alerts", response_class=HTMLResponse, include_in_schema=False)
def alerts_page(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse("alerts.html", {"request": request, "user": user})


# ═══════════════════════════════════════════════════════════════════════════════
#  Utility API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/ip", tags=["Utility"])
def get_ip_info(request: Request) -> dict:
    """Return client IP, server LAN IP, and public WAN IP."""
    client_ip = request.client.host if request.client else "unknown"
    server_lan = _get_lan_ip()
    server_wan = _get_wan_ip()
    return {"client_ip": client_ip, "server_lan": server_lan, "server_wan": server_wan}


def _get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unavailable"


def _get_wan_ip() -> str:
    try:
        r = httpx.get("https://api.ipify.org?format=json", timeout=5)
        return r.json().get("ip", "unavailable")
    except Exception:
        return "unavailable"


# ═══════════════════════════════════════════════════════════════════════════════
#  WebSocket endpoint — per-user live event streaming
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/events")
async def ws_events(ws: WebSocket, db: Session = Depends(get_db)):
    """
    WebSocket endpoint for real-time event streaming.
    Reads the session cookie from the WS handshake to identify the user.
    """
    from app.services.auth_service import get_user_id_from_cookie
    from app.websocket.manager import connect, disconnect

    # The WS handshake carries cookies → we can read the session
    class _FakeRequest:
        def __init__(self, cookies: dict):
            self.cookies = cookies
    fake: Request = _FakeRequest(ws.cookies)  # type: ignore[assignment]
    user_id = get_user_id_from_cookie(fake)

    if user_id is None:
        await ws.close(code=4001, reason="Not authenticated")
        return

    await connect(ws, user_id)
    try:
        while True:
            await ws.receive_text()  # keep alive; we don't expect messages
    except WebSocketDisconnect:
        disconnect(ws, user_id)
