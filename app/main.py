"""
LogSentinel — FastAPI application entry point.

Registers routers, mounts static files, configures Jinja2 templates,
and exposes the HTML dashboard alongside the JSON API.
"""

import socket

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION, STATIC_DIR, TEMPLATES_DIR
from app.database import get_db, init_db
from app.models import Alert, LogEvent
from app.routers import alerts, events, upload

# ── Application factory ──────────────────────────────────────────────────────
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Static files & templates ─────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ── Register API routers ─────────────────────────────────────────────────────
app.include_router(upload.router)
app.include_router(events.router)
app.include_router(alerts.router)


@app.get("/api/ip", tags=["Info"])
async def get_ip_info(request: Request) -> dict:
    """
    Return the client's visible IP (as seen by the server) plus the
    server's own LAN IP and public WAN IP.

    - client_ip  : IP of the browser/device making this request
    - server_lan : LAN IP of the machine running LogSentinel
    - server_wan : Public WAN IP of the machine running LogSentinel
    """
    import httpx as _httpx

    # ── Client (browser) IP ──────────────────────────────────────────────
    forwarded_for = request.headers.get("x-forwarded-for")
    client_ip: str = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else (request.client.host if request.client else "unknown")
    )

    # ── Server LAN IP ────────────────────────────────────────────────────
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
            _s.connect(("8.8.8.8", 80))
            server_lan: str = _s.getsockname()[0]
    except OSError:
        server_lan = "127.0.0.1"

    # ── Server WAN IP (cached for 60 s to avoid hammering external APIs) ─
    wan_services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    server_wan: str = server_lan  # default
    try:
        for url in wan_services:
            try:
                r = _httpx.get(url, timeout=5)
                if r.status_code == 200 and r.text.strip():
                    server_wan = r.text.strip()
                    break
            except Exception:
                continue
    except Exception:
        pass

    return {
        "client_ip": client_ip,
        "server_lan": server_lan,
        "server_wan": server_wan,
    }


# ── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
def on_startup() -> None:
    """Initialise database tables on first run."""
    init_db()


# ── HTML pages ───────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main dashboard page with summary statistics."""
    total_events = db.query(func.count(LogEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    critical_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0
    )
    high_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.severity == "high").scalar() or 0
    )
    medium_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.severity == "medium").scalar() or 0
    )
    unique_ips = (
        db.query(func.count(func.distinct(LogEvent.source_ip))).scalar() or 0
    )
    recent_alerts = (
        db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()
    )
    recent_events = (
        db.query(LogEvent).order_by(LogEvent.timestamp.desc()).limit(10).all()
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
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


@app.get("/upload", include_in_schema=False)
def upload_page(request: Request):
    """Log file upload page."""
    return templates.TemplateResponse("upload.html", {"request": request})


@app.get("/events", include_in_schema=False)
def events_page(request: Request):
    """Events browser page."""
    return templates.TemplateResponse("events.html", {"request": request})


@app.get("/alerts", include_in_schema=False)
def alerts_page(request: Request):
    """Alerts viewer page."""
    return templates.TemplateResponse("alerts.html", {"request": request})
