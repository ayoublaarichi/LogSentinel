"""
LogSentinel — Multi-Tenant SOC Log Analyzer & Detection Dashboard.

FastAPI application entry point.
"""

import logging
import socket
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.config import (
    APP_DESCRIPTION,
    APP_TITLE,
    APP_VERSION,
    CORS_ORIGINS,
    STATIC_DIR,
    TEMPLATES_DIR,
    _ON_VERCEL,
)
from app.database import get_db, init_db
from app.dependencies import get_current_user, require_user
from app.models import Alert, LogEvent, Project, User
from app.templating import templates

logger = logging.getLogger("logsentinel.app")


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
    redirect_slashes=False,   # Prevent 307 redirects that cause 405 on Vercel
)

# ── CORS middleware (must be added before routes) ────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files ─────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── 401 handler — redirect browsers to /login, return JSON for API calls ─────
from starlette.exceptions import HTTPException as StarletteHTTPException


def _wants_html(request: Request) -> bool:
    """True if the client expects an HTML response (browser navigation)."""
    # API paths NEVER redirect — this is the strongest signal.
    if request.url.path.startswith("/api/"):
        return False
    # XMLHttpRequest / fetch often set X-Requested-With
    if request.headers.get("x-requested-with", "").lower() == "xmlhttprequest":
        return False
    if request.headers.get("sec-fetch-dest", "").lower() == "document":
        return True
    if request.headers.get("upgrade-insecure-requests", "") == "1":
        return True
    accept = request.headers.get("accept", "")
    # fetch() calls from JS typically send */* or application/json.
    # Browser navigation sends text/html explicitly.
    if "text/html" in accept and "application/json" not in accept:
        return True
    # Fallback: if the client accepts text/html at all (even */*)
    # and the path is NOT an API path, treat as browser navigation.
    if "text/html" in accept:
        return True
    return False


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 401:
        if _wants_html(request):
            # Preserve the original URL so login can redirect back.
            from urllib.parse import quote
            next_url = str(request.url.path)
            qs = str(request.url.query)
            if qs:
                next_url = f"{next_url}?{qs}"
            login_url = f"/login?next={quote(next_url, safe='')}"
            logger.info("401 → redirecting browser to %s", login_url)
            return RedirectResponse(login_url, status_code=303)
        logger.warning("401 API response for path=%s", request.url.path)
        return JSONResponse({"detail": exc.detail}, status_code=401)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# ── Health & session probes (no auth) ────────────────────────────────────────
@app.get("/api/health", tags=["Utility"])
def health_check() -> dict:
    """Unprivileged health probe."""
    return {"status": "ok"}


@app.get("/api/session-check", tags=["Utility"])
def session_check(request: Request, db: Session = Depends(get_db)) -> dict:
    """Check whether the caller has a valid session cookie.

    Returns ``{"authenticated": true, "user": {"id": ..., "email": "..."}}`` or
    ``{"authenticated": false}``.  Always HTTP 200 — never 401.
    """
    user = get_current_user(request, db)
    if user:
        return {"authenticated": True, "user": {"id": user.id, "email": user.email}}
    return {"authenticated": False}


@app.options("/api/{path:path}", include_in_schema=False)
def options_fallback(path: str) -> Response:
    """Fallback OPTIONS responder to avoid 405 on strict/proxy edge cases."""
    return Response(status_code=204)


# ── Include routers ──────────────────────────────────────────────────────────
from app.routers import alerts, auth, events, ingest, investigate, projects, search, settings, upload  # noqa: E402

app.include_router(auth.router)
app.include_router(upload.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(ingest.router)
app.include_router(projects.router)
app.include_router(settings.router)
app.include_router(investigate.router)
app.include_router(search.router)


# ═══════════════════════════════════════════════════════════════════════════════
#  HTML page routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    project_filter = None
    project_name = None
    raw_project_id = request.query_params.get("project_id")
    if raw_project_id:
        try:
            requested_id = int(raw_project_id)
        except ValueError:
            requested_id = -1
        if requested_id < 1:
            return JSONResponse(status_code=400, content={"detail": "Invalid project_id"})
        project = (
            db.query(Project)
            .filter(Project.id == requested_id, Project.user_id == user.id)
            .first()
        )
        if not project:
            return JSONResponse(status_code=404, content={"detail": "Project not found"})
        project_filter = project.id
        project_name = project.name

    event_base = db.query(LogEvent).filter(LogEvent.user_id == user.id)
    alert_base = db.query(Alert).filter(Alert.user_id == user.id)
    if project_filter is not None:
        event_base = event_base.filter(LogEvent.project_id == project_filter)
        alert_base = alert_base.filter(Alert.project_id == project_filter)

    total_events = event_base.with_entities(func.count(LogEvent.id)).scalar() or 0
    total_alerts = alert_base.with_entities(func.count(Alert.id)).scalar() or 0
    critical_alerts = (
        alert_base.filter(Alert.severity == "critical")
        .with_entities(func.count(Alert.id))
        .scalar() or 0
    )
    high_alerts = (
        alert_base.filter(Alert.severity == "high")
        .with_entities(func.count(Alert.id))
        .scalar() or 0
    )
    medium_alerts = (
        alert_base.filter(Alert.severity == "medium")
        .with_entities(func.count(Alert.id))
        .scalar() or 0
    )
    unique_ips = (
        event_base.filter(LogEvent.source_ip.isnot(None))
        .with_entities(func.count(distinct(LogEvent.source_ip)))
        .scalar() or 0
    )
    recent_alerts = (
        alert_base
        .order_by(Alert.created_at.desc())
        .limit(5)
        .all()
    )
    recent_events = (
        event_base
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
            "active_project_id": project_filter,
            "active_project_name": project_name,
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

@app.get("/api/whoami", tags=["Utility"])
def whoami(request: Request, user: User = Depends(require_user)) -> dict:
    """Return authenticated user context + network identity with IP classification."""
    client_ip = _extract_client_ip(request)
    server_lan = _get_lan_ip()
    server_wan = _get_wan_ip()
    return {
        "email": user.email,
        "client_ip": client_ip,
        "client_ip_class": _classify_ip(client_ip),
        "server_lan": server_lan,
        "server_lan_class": _classify_ip(server_lan),
        "server_wan": server_wan,
        "server_wan_class": _classify_ip(server_wan),
        "environment": "cloud" if _ON_VERCEL else "self-hosted",
    }


# Keep legacy /api/ip for backward compatibility (no auth required)
@app.get("/api/ip", tags=["Utility"], include_in_schema=False)
def get_ip_info(request: Request) -> dict:
    """Legacy IP endpoint — prefer /api/whoami."""
    client_ip = _extract_client_ip(request)
    server_lan = _get_lan_ip()
    server_wan = _get_wan_ip()
    return {"client_ip": client_ip, "server_lan": server_lan, "server_wan": server_wan}


def _extract_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For on cloud."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _classify_ip(ip: str) -> str:
    """Classify an IP as private, loopback, demo, cloud-proxy, or public."""
    if not ip or ip in ("unavailable", "unknown"):
        return "unavailable"
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        # Well-known demo/documentation ranges
        demo_nets = [
            ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
            ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
            ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
        ]
        for net in demo_nets:
            if addr in net:
                return "demo"
        return "public"
    except ValueError:
        return "unknown"


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
