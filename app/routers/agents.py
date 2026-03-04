"""
Agent installer router.
"""

from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Project, User
from app.services.api_key_service import generate_api_key
from app.templating import templates

router = APIRouter(tags=["Agents"])


class AgentCreatePayload(BaseModel):
    name: str = Field("default-agent", min_length=2, max_length=64)
    project_id: int | None = Field(None, ge=1)


@router.get("/agents", include_in_schema=False)
def agents_page(
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.created_at.asc())
        .all()
    )
    return templates.TemplateResponse(
        "agents.html",
        {"request": request, "user": user, "projects": projects},
    )


@router.post("/api/agents/create")
def create_agent(
    payload: AgentCreatePayload,
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    name = payload.name.strip()
    raw_key, key_obj = generate_api_key(
        db,
        user_id=user.id,
        label=f"agent:{name}",
        project_id=payload.project_id,
    )

    base_url = str(request.base_url).rstrip("/")
    install_command = (
        f"curl -s '{base_url}/api/agents/install.sh?key={quote(raw_key)}&name={quote(name)}' | bash"
    )
    python_snippet = (
        "import requests, socket\n\n"
        f"requests.post(\n"
        f"    \"{base_url}/api/ingest/\",\n"
        f"    headers={{\"Authorization\": \"Bearer {raw_key}\"}},\n"
        "    json={\n"
        "        \"log_type\": \"auth\",\n"
        "        \"filename\": \"agent.log\",\n"
        "        \"content\": f\"Jan 10 12:34:56 {socket.gethostname()} sshd[1234]: Failed password for root from 10.0.0.99 port 22 ssh2\"\n"
        "    }\n"
        ")\n"
    )

    return {
        "agent_name": name,
        "project_id": key_obj.project_id,
        "api_key": raw_key,
        "install_command": install_command,
        "python_snippet": python_snippet,
    }


@router.get("/api/agents/install.sh", response_class=PlainTextResponse)
def install_script(
    request: Request,
    key: str = Query(..., min_length=20),
    name: str = Query("logsentinel-agent"),
) -> str:
    base_url = str(request.base_url).rstrip("/")
    safe_name = name.replace("\n", "").replace("\r", "").strip() or "logsentinel-agent"

    return f"""#!/usr/bin/env bash
set -euo pipefail

AGENT_NAME=\"{safe_name}\"
API_KEY=\"{key}\"
API_URL=\"{base_url}/api/ingest/\"

if ! command -v python3 >/dev/null 2>&1; then
  echo \"python3 is required\" >&2
  exit 1
fi

cat >/tmp/logsentinel-agent.py <<'PY'
import os
import socket
import requests

api_url = os.environ.get("LOGSENTINEL_API_URL")
api_key = os.environ.get("LOGSENTINEL_API_KEY")
hostname = socket.gethostname()
line = f"Jan 10 12:34:56 {{hostname}} sshd[1234]: Failed password for root from 10.0.0.88 port 22 ssh2"

requests.post(
    api_url,
    headers={{"Authorization": f"Bearer {{api_key}}"}},
    json={"log_type": "auth", "filename": "agent.log", "content": line},
    timeout=10,
)
print("LogSentinel agent test event sent")
PY

export LOGSENTINEL_API_URL=\"$API_URL\"
export LOGSENTINEL_API_KEY=\"$API_KEY\"
python3 /tmp/logsentinel-agent.py

echo \"$AGENT_NAME installed\"
"""