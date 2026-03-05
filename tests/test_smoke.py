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
import time
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
            self._client = httpx.Client(base_url=self._base, follow_redirects=False)

        def close(self):
            self._client.close()

        def clear_cookies(self):
            self._client.cookies.clear()

        def get(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            return self._client.get(path, **kw)

        def post(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            return self._client.post(path, **kw)

        def delete(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            return self._client.delete(path, **kw)

        def options(self, path, **kw):
            kw.setdefault("follow_redirects", False)
            return self._client.options(path, **kw)


def _force_logout(client):
    client.get("/logout", follow_redirects=False)
    if hasattr(client, "clear_cookies"):
        client.clear_cookies()
        return
    if hasattr(client, "cookies"):
        try:
            client.cookies.clear()
        except Exception:
            pass


def login_with_retry(client, email: str, password: str, retries: int = 3, delay_seconds: float = 1.0):
    payload = {
        "email": email,
        "password": password,
    }
    last_error = None
    for attempt in range(retries):
        try:
            response = client.post("/login", data=payload)
            if response.status_code in (200, 303):
                return response
            last_error = RuntimeError(f"Unexpected login status: {response.status_code}")
        except Exception as exc:
            last_error = exc
        if attempt < retries - 1:
            time.sleep(delay_seconds)
    if last_error:
        raise last_error
    raise RuntimeError("Login failed after retries")


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    if BASE_URL:
        live = _LiveClient(BASE_URL)
        try:
            yield live
        finally:
            live.close()
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
        _force_logout(authed_client)
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
        _force_logout(client)
        r = client.get("/api/events/bulk")
        assert r.status_code == 401
        body = r.json()
        assert "detail" in body

    def test_html_page_redirects_to_login(self, client):
        """Browser requests to protected HTML pages should 303 → /login."""
        _force_logout(client)
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
        login_with_retry(client, test_email, TEST_PASSWORD)

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

    def test_delete_seed_events_endpoint(self, client):
        seed_r = client.post("/api/events/seed?count=4")
        assert seed_r.status_code == 200

        delete_r = client.delete("/api/events/seed")
        assert delete_r.status_code == 200
        body = delete_r.json()
        assert body.get("deleted", 0) >= 4


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
        login_with_retry(client, test_email, TEST_PASSWORD)

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
        _force_logout(client)
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
        login_with_retry(client, test_email, TEST_PASSWORD)

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
            headers={"X-API-Key": raw_key},
            json=payload,
        )
        assert ingest.status_code == 200
        body = ingest.json()
        assert body["project_id"] == pid

    def test_bulk_ingest_with_api_key(self, client):
        create_proj = client.post("/api/projects/", json={"name": f"bulk-proj-{uuid.uuid4().hex[:6]}"})
        assert create_proj.status_code == 200
        pid = create_proj.json()["id"]

        key_page = client.post(
            "/settings/api-keys/create",
            data={"label": "bulk-ingest", "project_id": str(pid)},
        )
        assert key_page.status_code == 200
        key_match = re.search(r">([0-9a-f]{40})</code>", key_page.text)
        assert key_match
        raw_key = key_match.group(1)

        bulk = client.post(
            "/api/ingest/bulk",
            headers={"X-API-Key": raw_key},
            json={
                "events": [
                    {
                        "level": "warning",
                        "message": "login failed for root",
                        "source": "ssh",
                        "ip": "10.0.0.120",
                        "user": "root",
                    },
                    {
                        "level": "info",
                        "message": "normal request",
                        "source": "nginx",
                        "ip": "10.0.0.121",
                    },
                ]
            },
        )
        assert bulk.status_code == 200
        b = bulk.json()
        assert b["events_parsed"] == 2
        assert b["project_id"] == pid

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


class TestSIEMFeatures:
    @pytest.fixture(autouse=True)
    def _login(self, client, test_email):
        login_with_retry(client, test_email, TEST_PASSWORD)

    def test_geo_stats_endpoint(self, client):
        seed_r = client.post("/api/events/seed?count=5")
        assert seed_r.status_code == 200

        geo_r = client.get("/api/events/geo-stats")
        assert geo_r.status_code == 200
        body = geo_r.json()
        assert isinstance(body, dict)

    def test_alert_ack_and_close(self, client):
        line = "\n".join([
            "Jan 10 12:34:50 host sshd[1234]: Failed password for root from 10.0.0.50 port 21 ssh2",
            "Jan 10 12:34:51 host sshd[1234]: Failed password for root from 10.0.0.50 port 22 ssh2",
            "Jan 10 12:34:52 host sshd[1234]: Failed password for root from 10.0.0.50 port 23 ssh2",
            "Jan 10 12:34:53 host sshd[1234]: Failed password for root from 10.0.0.50 port 24 ssh2",
            "Jan 10 12:34:54 host sshd[1234]: Failed password for root from 10.0.0.50 port 25 ssh2",
        ]) + "\n"
        up_r = client.post(
            "/api/upload/?log_type=auth",
            files={"file": ("alerts-smoke.log", line.encode("utf-8"), "text/plain")},
        )
        assert up_r.status_code == 200

        alerts_r = client.get("/api/alerts/")
        assert alerts_r.status_code == 200
        alerts = alerts_r.json()
        target = next((a for a in alerts if a.get("source_ip") == "10.0.0.50"), None)
        assert target is not None

        ack_r = client.post(f"/api/alerts/{target['id']}/ack")
        assert ack_r.status_code == 200
        assert ack_r.json().get("status") in {"acked", "closed"}

        close_r = client.post(f"/api/alerts/{target['id']}/close")
        assert close_r.status_code == 200
        assert close_r.json().get("status") == "closed"

    def test_investigation_timeline_api(self, client):
        line = "Jan 10 12:34:56 host sshd[1234]: Failed password for root from 10.0.0.77 port 22 ssh2\n"
        up_r = client.post(
            "/api/upload/?log_type=auth",
            files={"file": ("timeline-smoke.log", line.encode("utf-8"), "text/plain")},
        )
        assert up_r.status_code == 200

        timeline_r = client.get("/api/investigate/timeline?ip=10.0.0.77")
        assert timeline_r.status_code == 200
        body = timeline_r.json()
        assert "timeline" in body
        assert "summary" in body
        assert isinstance(body["timeline"], list)

    def test_agents_create_api(self, client):
        proj_r = client.get("/api/projects/")
        assert proj_r.status_code == 200
        projects = proj_r.json()
        assert projects
        pid = projects[0]["id"]

        create_r = client.post(
            "/api/agents/create",
            json={"name": f"agent-{uuid.uuid4().hex[:5]}", "project_id": pid},
        )
        assert create_r.status_code == 200
        body = create_r.json()
        assert body.get("key_id")
        assert body.get("api_key")
        assert body.get("install_command")
        assert body.get("python_snippet")

    def test_agents_rotate_api_key(self, client):
        proj_r = client.get("/api/projects/")
        assert proj_r.status_code == 200
        projects = proj_r.json()
        assert projects
        pid = projects[0]["id"]

        create_r = client.post(
            "/api/agents/create",
            json={"name": f"rotate-{uuid.uuid4().hex[:5]}", "project_id": pid},
        )
        assert create_r.status_code == 200
        created = create_r.json()
        old_key_id = created.get("key_id")
        old_raw_key = created.get("api_key")
        assert old_key_id
        assert old_raw_key

        before_rotate_ingest = client.post(
            "/api/ingest/",
            headers={"X-API-Key": old_raw_key},
            json={
                "log_type": "auth",
                "filename": "agent-rotate-before.log",
                "content": "Jan 10 12:34:56 host sshd[1234]: Failed password for root from 10.0.0.91 port 22 ssh2",
            },
        )
        assert before_rotate_ingest.status_code == 200

        rotate_r = client.post(f"/api/agents/keys/{old_key_id}/rotate")
        assert rotate_r.status_code == 200
        rotated = rotate_r.json()
        new_raw_key = rotated.get("api_key")
        assert rotated.get("rotated_from_key_id") == old_key_id
        assert rotated.get("key_id")
        assert new_raw_key

        old_key_ingest = client.post(
            "/api/ingest/",
            headers={"X-API-Key": old_raw_key},
            json={
                "log_type": "auth",
                "filename": "agent-rotate-old-key.log",
                "content": "Jan 10 12:34:57 host sshd[1234]: Failed password for root from 10.0.0.92 port 22 ssh2",
            },
        )
        assert old_key_ingest.status_code == 401

        new_key_ingest = client.post(
            "/api/ingest/",
            headers={"X-API-Key": new_raw_key},
            json={
                "log_type": "auth",
                "filename": "agent-rotate-new-key.log",
                "content": "Jan 10 12:34:58 host sshd[1234]: Failed password for root from 10.0.0.93 port 22 ssh2",
            },
        )
        assert new_key_ingest.status_code == 200

    def test_attack_graph_api(self, client):
        seed_r = client.post("/api/events/seed?count=4")
        assert seed_r.status_code == 200

        graph_r = client.get("/api/graph?hours=24")
        assert graph_r.status_code == 200
        body = graph_r.json()
        assert "nodes" in body
        assert "edges" in body
        assert isinstance(body["nodes"], list)
        assert isinstance(body["edges"], list)

    def test_graph_page(self, client):
        page_r = client.get("/graph", headers={"Accept": "text/html"})
        assert page_r.status_code == 200
        assert "Attack Graph" in page_r.text

    def test_cases_and_chain_workflow(self, client):
        up_r = client.post(
            "/api/upload/?log_type=auth",
            files={
                "file": (
                    "case-chain-smoke.log",
                    (
                        "Jan 10 12:34:50 host sshd[1234]: Failed password for root from 10.0.0.88 port 22 ssh2\n"
                        "Jan 10 12:34:52 host sshd[1234]: Failed password for root from 10.0.0.88 port 23 ssh2\n"
                        "Jan 10 12:34:54 host sshd[1234]: Failed password for root from 10.0.0.88 port 24 ssh2\n"
                        "Jan 10 12:34:56 host sshd[1234]: Failed password for root from 10.0.0.88 port 25 ssh2\n"
                        "Jan 10 12:34:58 host sshd[1234]: Failed password for root from 10.0.0.88 port 26 ssh2\n"
                        "Jan 10 12:35:05 host sshd[1234]: Accepted password for root from 10.0.0.88 port 22 ssh2\n"
                        "Jan 10 12:35:20 host sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
                    ).encode("utf-8"),
                    "text/plain",
                )
            },
        )
        assert up_r.status_code == 200

        create_case_r = client.post(
            "/api/cases",
            json={"title": "SSH brute force investigation", "priority": "high"},
        )
        assert create_case_r.status_code == 200
        case_obj = create_case_r.json()
        case_id = case_obj["id"]

        alerts_r = client.get("/api/alerts/")
        assert alerts_r.status_code == 200
        target = next((a for a in alerts_r.json() if a.get("source_ip") == "10.0.0.88"), None)
        assert target is not None

        link_r = client.post(f"/api/cases/{case_id}/alerts/{target['id']}")
        assert link_r.status_code == 200

        status_r = client.post(f"/api/cases/{case_id}/status", json={"status": "investigating"})
        assert status_r.status_code == 200
        assert status_r.json().get("status") == "investigating"

        note_r = client.post(
            f"/api/cases/{case_id}/notes",
            json={"note": "IP belongs to TOR exit node"},
        )
        assert note_r.status_code == 200

        detail_r = client.get(f"/api/cases/{case_id}")
        assert detail_r.status_code == 200
        detail = detail_r.json()
        assert isinstance(detail.get("linked_alerts"), list)
        assert isinstance(detail.get("notes"), list)

        cases_page_r = client.get("/cases", headers={"Accept": "text/html"})
        assert cases_page_r.status_code == 200
        assert "Cases" in cases_page_r.text

        chain_r = client.get("/api/chains/build?ip=10.0.0.88&hours=24")
        assert chain_r.status_code == 200
        chain = chain_r.json()
        assert "score" in chain
        assert "phases" in chain
        assert isinstance(chain["phases"], list)

        save_chain_r = client.post(
            f"/api/cases/{case_id}/chains/save",
            json={"chain": chain},
        )
        assert save_chain_r.status_code == 200
        saved = save_chain_r.json()
        assert saved.get("case_id") == case_id

        detail_after_r = client.get(f"/api/cases/{case_id}")
        assert detail_after_r.status_code == 200
        detail_after = detail_after_r.json()
        assert isinstance(detail_after.get("chain_snapshots"), list)
        assert detail_after.get("chain_snapshots")
        assert isinstance(detail_after.get("activities"), list)
        assert detail_after.get("activities")

        summary_r = client.get("/api/dashboard/summary")
        assert summary_r.status_code == 200
        summary = summary_r.json()
        assert "open_alerts" in summary
        assert "open_cases" in summary
        assert "high_risk_ips" in summary
        assert "events_last_24h" in summary
