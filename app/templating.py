"""
Shared Jinja2Templates instance with global context variables.

Every router / module that renders HTML should import `templates` from here
instead of creating its own Jinja2Templates instance.
"""

from fastapi.templating import Jinja2Templates

from app.config import APP_VERSION, TEMPLATES_DIR, _ON_VERCEL

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ── Inject global context available in every template ────────────────────────
templates.env.globals["app_version"] = APP_VERSION
templates.env.globals["environment"] = "cloud" if _ON_VERCEL else "self-hosted"
