# 🛡️ LogSentinel

**Mini SOC Log Analyzer & Alert Dashboard**

A portfolio-grade security operations tool built with **Python / FastAPI** that ingests Linux `auth.log` and Nginx access logs, parses them into structured security events, and runs detection rules to surface actionable alerts — all served through a professional dark-themed dashboard.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Log Upload** | Upload `.log` / `.txt` files via the web UI or API |
| **Dual Parser** | Supports Linux auth.log (sshd) & Nginx combined access logs |
| **Structured Events** | Every line → `timestamp`, `source_ip`, `username`, `event_type`, `raw_line` |
| **Detection Rules** | SSH Brute Force (≥ 6 failures / 10 min), Nginx Flood (≥ 200 req / 2 min) |
| **Alerts Dashboard** | Severity badges, filtering, dismiss/acknowledge actions |
| **Events Browser** | Paginated table with filters (IP, type, source, time range) |
| **Live Refresh (MVP)** | Events stream via WebSocket; Dashboard/Alerts auto-refresh key data every 10s |
| **Attack Graph** | Relationship graph (`IP ↔ event type ↔ users ↔ alert rules`) with click-through intel |
| **Case Management** | Incident cases with status, priority, linked alerts, and analyst notes |
| **Attack Chains** | Heuristic chain reconstruction (`Recon → Access → Privilege/Impact`) with confidence score |
| **REST API** | Full JSON API at `/docs` (Swagger) and `/redoc` |

---

## 🗂️ Project Structure

```
LogSentinel/
├── app/
│   ├── __init__.py            # Package metadata
│   ├── config.py              # Paths, DB URL, constants
│   ├── database.py            # SQLAlchemy engine + session
│   ├── models.py              # ORM models (LogEvent, Alert)
│   ├── schemas.py             # Pydantic request/response schemas
│   ├── main.py                # FastAPI app + HTML routes
│   ├── parsers/
│   │   ├── base.py            # Abstract BaseParser
│   │   ├── auth_log.py        # Linux auth.log parser
│   │   └── nginx.py           # Nginx access-log parser
│   ├── detection/
│   │   ├── engine.py          # Sliding-window detection engine
│   │   └── rules.py           # Rule definitions (dataclasses)
│   ├── routers/
│   │   ├── upload.py          # POST /api/upload/
│   │   ├── events.py          # GET  /api/events/
│   │   └── alerts.py          # GET  /api/alerts/
│   └── static/
│       ├── css/style.css      # Dark SOC theme
│       └── js/app.js          # Client-side utilities
├── templates/
│   ├── base.html              # Jinja2 layout
│   ├── dashboard.html         # Main dashboard
│   ├── upload.html            # File upload page
│   ├── events.html            # Events browser
│   └── alerts.html            # Alerts viewer
├── sample_logs/
│   ├── auth.log               # Sample SSH auth log
│   └── access.log             # Sample Nginx access log (generated)
├── scripts/
│   └── seed.py                # Generate sample logs + auto-seed
├── uploads/                   # Uploaded files (gitignored)
├── requirements.txt
├── run.py                     # Convenience entry point
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone & install

```bash
git clone <your-repo-url>
cd LogSentinel

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate    # Linux / macOS
venv\Scripts\activate       # Windows

pip install -r requirements.txt
```

### 2. Generate sample logs

```bash
python -m scripts.seed
```

This creates `sample_logs/auth.log` and `sample_logs/access.log` using your current device/network IP, including brute-force and request-flood patterns.

### 3. Start the server

```bash
python run.py
```

The app will be available at **http://localhost:8000**

### 4. Upload sample logs

1. Navigate to **http://localhost:8000/upload**
2. Upload `sample_logs/auth.log` → auto-detected as SSH log
3. Upload `sample_logs/access.log` → auto-detected as Nginx log
4. Go to the **Dashboard** to see stats and alerts

> **Tip:** If the server is already running, you can auto-seed by running `python -m scripts.seed` in another terminal.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload/?log_type=auto` | Upload & parse a log file |
| `GET` | `/api/events/?source_ip=...&event_type=...&page=1&project_id=...` | List events (filtered; optional project scope) |
| `GET` | `/api/projects/` | List projects for current user |
| `POST` | `/api/projects/` | Create a project |
| `PATCH` | `/api/projects/{id}` | Update project name/description |
| `DELETE` | `/api/projects/{id}` | Delete project (reassigns data to Default) |
| `POST` | `/api/events/seed?count=50` | Insert demo events for current account |
| `GET` | `/api/events/types` | List distinct event types |
| `GET` | `/api/events/count` | Total event count |
| `GET` | `/api/alerts/?severity=...&rule_name=...&project_id=...` | List alerts (filtered; optional project scope) |
| `GET` | `/api/alerts/stats` | Alert severity breakdown |
| `GET` | `/api/graph?hours=24&project_id=...` | Attack graph nodes/edges for visualization |
| `POST` | `/api/cases` | Create a case |
| `GET` | `/api/cases` | List cases (filter by `status`, `priority`, `project_id`) |
| `GET` | `/api/cases/{id}` | Case details (linked alerts + notes) |
| `POST` | `/api/cases/{id}/alerts/{alert_id}` | Link alert to case |
| `POST` | `/api/cases/{id}/status` | Update case status |
| `POST` | `/api/cases/{id}/notes` | Add analyst note |
| `GET` | `/api/chains/build?ip=...&hours=24&project_id=...` | Build attack chain with score/confidence |
| `DELETE` | `/api/alerts/{id}` | Dismiss an alert |

Interactive docs: **http://localhost:8000/docs**

---

## 🔍 Detection Rules

### SSH Brute Force (HIGH)
- **Trigger:** ≥ 6 failed SSH login attempts from the same IP within 10 minutes
- **Event types:** `ssh_failed_login`, `ssh_invalid_user`

### Nginx Request Flood (MEDIUM)
- **Trigger:** ≥ 200 HTTP requests from the same IP within 2 minutes
- **Event types:** `http_ok`, `http_client_error`, `http_server_error`

---

## 📸 Screenshots

> *Replace these placeholders with actual screenshots after running the app.*

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Upload Page
![Upload](screenshots/upload.png)

### Events Browser
![Events](screenshots/events.png)

### Alerts Viewer
![Alerts](screenshots/alerts.png)

---

## 🛠️ Tech Stack

- **Backend:** Python 3.11+ / FastAPI
- **Database:** SQLAlchemy 2.0 ORM (SQLite local dev, Postgres in production)
- **Templates:** Jinja2 + Bootstrap 5.3 (dark theme)
- **Detection:** Custom sliding-window engine
- **API Docs:** Swagger UI (auto-generated)

---

## ☁️ Vercel Deployment Notes (Auth + DB Stability)

### Required environment variables

- `LOGSENTINEL_SECRET` — strong random session signing key (required in production)
- `DATABASE_URL` — **required in production**; must point to persistent Postgres
- `ENV=production` (or Vercel-managed `VERCEL=1`) to activate production checks

### `DATABASE_URL` example

```bash
postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME
```

### Why SQLite `/tmp` is not used in production

Vercel serverless instances have ephemeral local storage. Data in `/tmp` is not guaranteed across cold starts/instances, so user/session persistence becomes unreliable. In production, LogSentinel now fails fast if `DATABASE_URL` is not configured.

### Migration strategy

Current startup still uses `Base.metadata.create_all(...)` for baseline schema creation. This is acceptable for MVP/bootstrap, but **not** a full migration workflow. Use **Alembic** for controlled schema evolution in persistent Postgres environments.

#### Alembic commands

```bash
# apply latest migrations
alembic upgrade head

# create a new migration from model changes
alembic revision --autogenerate -m "describe change"

# inspect current DB revision
alembic current
```

#### One-time sync for existing databases

If a database already has tables created before Alembic was added, run this once:

```bash
alembic stamp head
```

This records the baseline revision without dropping data.

---

## 🍪 Cookie / Session Debugging Checklist

In browser DevTools (Application/Storage → Cookies):

- Ensure `ls_session` is present after login
- Verify attributes:
	- `HttpOnly = true`
	- `Path = /`
	- `SameSite = Lax`
	- `Secure = true` on HTTPS/Vercel
- If `/events` redirects to login, check `/api/session-check` response:
	- `{"authenticated": true, "user": {...}}` when session is valid
	- `{"authenticated": false}` when cookie missing/expired

---

## 📄 License

MIT — free for personal and commercial use.
