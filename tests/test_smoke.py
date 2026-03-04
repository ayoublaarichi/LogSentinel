"""
LogSentinel — Smoke Tests
=========================
Validates that core authentication, session management, CORS, and event
endpoints behave correctly — both locally and on Vercel.

Run locally:
    pytest tests/test_smoke.py -v

Run against Vercel:
    BASE_URL=https://logsentinel-tau.vercel.app pytest tests/test_smoke.py -v

Equivalent curl commands are included as comments for manual verification.
"""

import os
import re
import uuid

import pytest
from fastapi.testclient import TestClient

# When BASE_URL is set we test against a live deployment;
# otherwise we use the in-process TestClient.
BASE_URL = os.environ.get("BASE_URL", "")

if BASE_URL:
    import httpx

    class _LiveClient:
        """Minimal wrapper around httpx that mirrors TestClient's interface."""

        def __init__(self, base_url: str):
            self._base = base_url.rstrip("/")
            self._cookies: dict[str, str] = {}

        def get(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            r = httpx.get(self._base + path, cookies=self._cookies, **kw)
            self._cookies.update(dict(r.cookies))
            return r

        def post(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            r = httpx.post(self._base + path, cookies=self._cookies, **kw)
            self._cookies.update(dict(r.cookies))
            return r

        def delete(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            r = httpx.delete(self._base + path, cookies=self._cookies, **kw)
            self._cookies.update(dict(r.cookies))
            return r

        def options(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            r = httpx.options(self._base + path, cookies=self._cookies, **kw)
            self._cookies.update(dict(r.cookies))
            return r


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    if BASE_URL:
        yield _LiveClient(BASE_URL)
    else:
        # Import here so the Vercel-only SECRET_KEY check does not fire
        os.environ.setdefault("LOGSENTINEL_SECRET", "test-secret-not-for-production!!!")
        from app.main import app
        with TestClient(app, raise_server_exceptions=False) as tc:
            yield tc


@pytest.fixture(scope="module")
def test_email():
    """Unique email so parallel test runs don't collide."""
    return f"smoke-{uuid.uuid4().hex[:8]}@test.local"


TEST_PASSWORD = "SmokeTest1234!"


@pytest.fixture(scope="module")
def authed_client(client, test_email):
    """Return a client that has been signed up and is authenticated."""
    # Signup
    r = client.post("/signup", data={
        "email": test_email,
        "password": TEST_PASSWORD,
        "password2": TEST_PASSWORD,
    })
    assert r.status_code in (200, 303), f"Signup failed: {r.status_code}"
    return client


# ---------------------------------------------------------------------------
#  1. Health probe — no auth required
# ---------------------------------------------------------------------------
# curl -s https://logsentinel-tau.vercel.app/api/health | jq .

class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"

    def test_session_check_unauthenticated(self, client):
        """Session check returns 200 (never 401) even without a cookie."""
        # curl -s .../api/session-check | jq .
        r = client.get("/api/session-check")
        assert r.status_code == 200
        body = r.json()
        assert body["authenticated"] is False


# ---------------------------------------------------------------------------
#  2. Authentication flow
# ---------------------------------------------------------------------------
# curl -c cookies.txt -X POST -d 'email=test@test.local&password=Test1234!' .../login
# curl -b cookies.txt .../api/session-check | jq .

class TestAuth:
    def test_signup_and_session(self, authed_client, test_email):
        r = authed_client.get("/api/session-check")
        assert r.status_code == 200
        body = r.json()
        assert body["authenticated"] is True
        assert body["user"]["email"] == test_email

    def test_whoami(self, authed_client, test_email):
        r = authed_client.get("/api/whoami")
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == test_email

    def test_logout_clears_session(self, client, authed_client):
        r = authed_client.get("/logout")
        assert r.status_code in (200, 303)
        # After logout, session-check should report unauthenticated
        r2 = authed_client.get("/api/session-check")
        assert r2.status_code == 200
        assert r2.json()["authenticated"] is False


# ---------------------------------------------------------------------------
#  3. Unauthenticated access
# ---------------------------------------------------------------------------
# curl -s -o /dev/null -w '%{http_code}' .../api/events/bulk  → 401
# curl -s -o /dev/null -w '%{http_code}' -H 'Accept: text/html' .../events  → 303

class TestUnauthenticated:
    def test_api_returns_401_json(self, client):
        """API paths must return 401 JSON, NOT a redirect."""
        r = client.get("/api/events/bulk")
        assert r.status_code == 401
        body = r.json()
        assert "detail" in body

    def test_html_page_redirects_to_login(self, client):
        """Browser requests to protected HTML pages should 303 → /login."""
        r = client.get("/events", headers={"Accept": "text/html"}, follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")


# ---------------------------------------------------------------------------
#  4. Events endpoints (authenticated)
# ---------------------------------------------------------------------------
# curl -b cookies.txt -s .../api/events/bulk?limit=10 | jq 'length'
# curl -b cookies.txt -s .../api/events/ips | jq .
# curl -b cookies.txt -s .../api/events/types | jq .
# curl -b cookies.txt -s .../api/events/users | jq .

class TestEvents:
    @pytest.fixture(autouse=True)
    def _login(self, client, test_email):
        """Ensure we are logged in for every test in this class."""
        client.post("/login", data={
            "email": test_email,
            "password": TEST_PASSWORD,
        })

    def test_bulk_events(self, client):
        r = client.get("/api/events/bulk?limit=10")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_event_ips(self, client):
        r = client.get("/api/events/ips")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_event_types(self, client):
        r = client.get("/api/events/types")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_event_users(self, client):
        r = client.get("/api/events/users")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_event_timeline(self, client):
        r = client.get("/api/events/timeline")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_event_timeline_hours_param(self, client):
        r = client.get("/api/events/timeline?hours=6")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_events_no_trailing_slash_alias(self, client):
        r = client.get("/api/events?per_page=5")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_seed_events_endpoint(self, client):
        r = client.post("/api/events/seed?count=3")
        assert r.status_code == 200
        body = r.json()
        assert body["seeded"] == 3


# ---------------------------------------------------------------------------
#  5. CORS & OPTIONS preflight
# ---------------------------------------------------------------------------
# curl -s -X OPTIONS -H 'Origin: http://localhost:8000' \
#     -H 'Access-Control-Request-Method: GET' \
#     -o /dev/null -w '%{http_code}' .../api/events/bulk  → 200

class TestCORS:
    def test_options_preflight_not_405(self, client):
        """OPTIONS should return 200 (CORS preflight), NOT 405."""
        r = client.options(
            "/api/events/bulk",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code in (200, 204), f"OPTIONS returned {r.status_code}"


# ---------------------------------------------------------------------------
#  6. No trailing-slash redirect on API
# ---------------------------------------------------------------------------
# curl -s -o /dev/null -w '%{http_code}' -b cookies.txt .../api/events/bulk → 200 (not 307)

class TestTrailingSlash:
    @pytest.fixture(autouse=True)
    def _login(self, client, test_email):
        client.post("/login", data={
            "email": test_email,
            "password": TEST_PASSWORD,
        })

    def test_no_307_redirect(self, client):
        """With redirect_slashes=False the app must not 307-redirect API calls."""
        r = client.get("/api/events/bulk?limit=1")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"


# ---------------------------------------------------------------------------
#  7. Login ?next= redirect flow
# ---------------------------------------------------------------------------
# curl -s -o /dev/null -w '%{http_code}\n%{redirect_url}' \
#   -H 'Accept: text/html' .../events  → 303  .../login?next=%2Fevents

class TestLoginNextRedirect:
    def test_401_redirect_preserves_next(self, client):
        """When a browser hits a protected page unauthenticated, the
        redirect to /login must include ?next=<original_path>."""
        # Ensure we are logged out first
        client.get("/logout", follow_redirects=False)
        r = client.get("/events", headers={"Accept": "text/html"}, follow_redirects=False)
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert "/login" in loc
        assert "next=" in loc, f"Expected ?next= in Location header, got: {loc}"

    def test_login_post_with_next(self, client, test_email):
        """POST /login with next= should redirect to the specified path."""
        r = client.post("/login", data={
            "email": test_email,
            "password": TEST_PASSWORD,
            "next": "/events",
        }, follow_redirects=False)
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert loc == "/events", f"Expected redirect to /events, got: {loc}"

    def test_login_post_blocks_open_redirect(self, client, test_email):
        """next= pointing to an external URL must be ignored (redirect to /)."""
        r = client.post("/login", data={
            "email": test_email,
            "password": TEST_PASSWORD,
            "next": "https://evil.example.com/steal",
        }, follow_redirects=False)
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert loc == "/", f"Expected redirect to /, got: {loc}"


# ---------------------------------------------------------------------------
#  8. Project CRUD + project-scoped filtering
# ---------------------------------------------------------------------------

class TestProjects:
    @pytest.fixture(autouse=True)
    def _login(self, client, test_email):
        client.post("/login", data={
            "email": test_email,
            "password": TEST_PASSWORD,
        })

    def test_project_crud_and_scoped_seed(self, client):
        list_r = client.get("/api/projects/")
        assert list_r.status_code == 200
        projects = list_r.json()
        assert isinstance(projects, list)
        assert any(p.get("is_default") for p in projects)

        create_r = client.post("/api/projects/", json={"name": f"smoke-proj-{uuid.uuid4().hex[:6]}"})
        assert create_r.status_code == 200
        project = create_r.json()
        pid = project["id"]

        seed_r = client.post(f"/api/events/seed?count=2&project_id={pid}")
        assert seed_r.status_code == 200
        seed_body = seed_r.json()
        assert seed_body["project_id"] == pid

        bulk_r = client.get(f"/api/events/bulk?limit=50&project_id={pid}")
        assert bulk_r.status_code == 200
        rows = bulk_r.json()
        assert isinstance(rows, list)
        assert all((row.get("project_id") == pid) for row in rows)

        del_r = client.delete(f"/api/projects/{pid}")
        assert del_r.status_code == 200
        assert del_r.json().get("deleted") == pid

    def test_api_key_project_assignment_scopes_ingest(self, client):
        create_proj = client.post("/api/projects/", json={"name": f"ingest-proj-{uuid.uuid4().hex[:6]}"})
        assert create_proj.status_code == 200
        pid = create_proj.json()["id"]

        key_page = client.post(
            "/settings/api-keys/create",
            data={"label": "ingest-scoped", "project_id": str(pid)},
        )
        assert key_page.status_code == 200
        html = key_page.text
        key_match = re.search(r">([0-9a-f]{40})</code>", html)
        assert key_match, "Expected plaintext API key in create response"
        raw_key = key_match.group(1)

        payload = {
            "log_type": "auth",
            "filename": "ingest-smoke.log",
            "content": "Jan 10 12:34:56 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2",
        }
        ingest = client.post(
            "/api/ingest/",
            headers={"Authorization": f"Bearer {raw_key}"},
            json=payload,
        )
        assert ingest.status_code == 200
        body = ingest.json()
        assert body["project_id"] == pid

    def test_search_and_investigate_respect_project_scope(self, client):
        create_proj = client.post("/api/projects/", json={"name": f"search-proj-{uuid.uuid4().hex[:6]}"})
        assert create_proj.status_code == 200
        pid = create_proj.json()["id"]

        seed_r = client.post(f"/api/events/seed?count=3&project_id={pid}")
        assert seed_r.status_code == 200
        seeded_ip = seed_r.json()["source_ip"]

        search_r = client.get(f"/api/search?q=ip:{seeded_ip}&project_id={pid}")
        assert search_r.status_code == 200
        search_body = search_r.json()
        assert search_body.get("project_id") == pid
        events = search_body.get("events", [])
        assert isinstance(events, list)
        assert all((e.get("project_id") == pid) for e in events)

        inv_r = client.get(f"/investigate/ip/{seeded_ip}?project_id={pid}")
        assert inv_r.status_code == 200

    def test_upload_respects_project_scope(self, client):
        create_proj = client.post("/api/projects/", json={"name": f"upload-proj-{uuid.uuid4().hex[:6]}"})
        assert create_proj.status_code == 200
        pid = create_proj.json()["id"]

        line = "Jan 10 12:34:56 host sshd[1234]: Failed password for root from 10.0.0.6 port 22 ssh2\n"
        up_r = client.post(
            f"/api/upload/?log_type=auth&project_id={pid}",
            files={"file": ("upload-smoke.log", line.encode("utf-8"), "text/plain")},
        )
        assert up_r.status_code == 200
        body = up_r.json()
        assert body["project_id"] == pid
        assert body["events_parsed"] >= 1

        bulk_r = client.get(f"/api/events/bulk?limit=200&project_id={pid}")
        assert bulk_r.status_code == 200
        rows = bulk_r.json()
        assert isinstance(rows, list)
        assert any(r.get("file_name") == "upload-smoke.log" for r in rows)
        assert all((row.get("project_id") == pid) for row in rows)
