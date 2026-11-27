"""OAuth-first Instagram Insight app.

Uses Meta's supported Instagram Login for professional accounts. Passwords and
2FA codes are entered only on Instagram; this server receives an OAuth code and
stores the resulting access token encrypted at rest.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

APP_VERSION = "3.0.0"
GRAPH_VERSION = os.environ.get("INSTAGRAM_GRAPH_VERSION", "v27.0")
if not re.fullmatch(r"v\d+\.\d+", GRAPH_VERSION):
    GRAPH_VERSION = "v27.0"

DATA_DIR = Path(os.environ.get("DATA_DIR", "data")).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "insight.sqlite3"

OAUTH_AUTHORIZE_URL = "https://www.facebook.com/dialog/oauth"
GRAPH_BASE_URL = "https://graph.facebook.com"


class InstagramOAuthError(RuntimeError):
    pass


class ReauthorizationRequired(InstagramOAuthError):
    pass


def _secret_key() -> str:
    configured = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
    if configured:
        return configured
    key_file = DATA_DIR / "secret.key"
    try:
        stored = key_file.read_text(encoding="utf-8").strip()
        if len(stored) >= 32:
            return stored
    except OSError:
        pass
    generated = secrets.token_urlsafe(48)
    try:
        key_file.write_text(generated + "\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return generated


app = Flask(__name__)
app.secret_key = _secret_key()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_NAME="insight_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER") or os.environ.get("COOKIE_SECURE") == "1"),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
    MAX_CONTENT_LENGTH=1024 * 1024,
)


def _meta_app_id() -> str:
    return (os.environ.get("META_APP_ID") or "").strip()


def _meta_app_secret() -> str:
    return (os.environ.get("META_APP_SECRET") or "").strip()


def _login_config_id() -> str:
    return (os.environ.get("META_LOGIN_CONFIG_ID") or "").strip()


def _redirect_uri() -> str:
    configured = (os.environ.get("META_REDIRECT_URI") or "").strip()
    if configured:
        return configured
    return url_for("instagram_callback", _external=True)


def _fernet() -> Fernet:
    raw = (os.environ.get("TOKEN_ENCRYPTION_KEY") or "").strip()
    if raw:
        try:
            return Fernet(raw.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("TOKEN_ENCRYPTION_KEY must be a valid Fernet key.") from exc
    material = (os.environ.get("SECRET_KEY") or app.secret_key).encode("utf-8")
    digest = hashlib.sha256(b"insight-studio-instagram-token-v1:" + material).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 20000")
    db.execute("PRAGMA secure_delete = ON")
    return db


def init_db() -> None:
    """Remove obsolete import/credential material and create OAuth-only storage."""
    with connect() as db:
        existing = {
            row["name"]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        obsolete = {
            "accounts", "imports", "import_relations", "events",
            "creds", "ig_sessions", "attempts", "verification_attempts",
            "followers_cache", "following_cache", "profiles", "snapshots",
            "engagement", "visits", "actions", "self",
        }
        if existing & obsolete:
            for table in obsolete:
                db.execute('DROP TABLE IF EXISTS "' + table + '"')
            db.commit()
            db.execute("VACUUM")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_accounts (
                cid TEXT PRIMARY KEY,
                ig_user_id TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                client_business_id TEXT NOT NULL DEFAULT '',
                config_id TEXT NOT NULL DEFAULT '',
                token_ciphertext TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                granted_scopes TEXT NOT NULL DEFAULT '[]',
                profile_json TEXT NOT NULL DEFAULT '{}',
                media_json TEXT NOT NULL DEFAULT '[]',
                analytics_json TEXT NOT NULL DEFAULT '{}',
                connected_at TEXT NOT NULL,
                synced_at TEXT NOT NULL
            )
            """
        )
        columns = {row["name"] for row in db.execute("PRAGMA table_info(oauth_accounts)")}
        for name, declaration in (
            ("client_business_id", "TEXT NOT NULL DEFAULT ''"),
            ("config_id", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in columns:
                db.execute("ALTER TABLE oauth_accounts ADD COLUMN " + name + " " + declaration)
        db.commit()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def csrf_ok() -> bool:
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("_csrf") or ""
    stored = session.get("_csrf") or ""
    return bool(supplied and stored and secrets.compare_digest(supplied, stored))


@app.before_request
def ensure_browser_session() -> None:
    if not session.get("cid"):
        session["cid"] = secrets.token_urlsafe(32)
    session.permanent = True


@app.after_request
def security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https://*.cdninstagram.com data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://www.instagram.com"
    )
    return response


def _multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = "----InsightStudio" + secrets.token_hex(18)
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.append(("--" + boundary + "\r\n").encode("ascii"))
        chunks.append(
            ('Content-Disposition: form-data; name="' + key + '"\r\n\r\n').encode("utf-8")
        )
        chunks.append(value.encode("utf-8"))
        chunks.append(b"\r\n")
    chunks.append(("--" + boundary + "--\r\n").encode("ascii"))
    return b"".join(chunks), "multipart/form-data; boundary=" + boundary


def _http_json(
    url: str,
    method: str = "GET",
    form: dict[str, str] | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    headers = {"Accept": "application/json", "User-Agent": "InsightStudio/3.0"}
    body = None
    if form is not None:
        body = urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024)
    except HTTPError as exc:
        try:
            detail = exc.read(64 * 1024).decode("utf-8", "replace")
            parsed = json.loads(detail)
            message = parsed.get("error", {}).get("message") or parsed.get("error_description") or "Instagram rejected the request."
        except Exception:
            message = "Instagram request failed with HTTP " + str(exc.code) + "."
        raise InstagramOAuthError(str(message)[:400]) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise InstagramOAuthError("Could not reach Instagram. Check the server network and try again.") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstagramOAuthError("Instagram returned an unreadable response.") from exc
    if not isinstance(payload, dict):
        raise InstagramOAuthError("Instagram returned an unexpected response.")
    if payload.get("error"):
        error = payload["error"]
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise InstagramOAuthError(str(message or "Instagram API error.")[:400])
    return payload


def exchange_authorization_code(code: str) -> dict[str, Any]:
    app_id, app_secret = _meta_app_id(), _meta_app_secret()
    if not app_id or not app_secret:
        raise InstagramOAuthError("Meta App ID and App Secret are not configured on this server.")
    response = _http_json(
        GRAPH_BASE_URL + "/" + GRAPH_VERSION + "/oauth/access_token?" + urlencode({
            "client_id": app_id,
            "client_secret": app_secret,
            "code": code,
        })
    )
    token = response.get("access_token")
    if not token:
        raise InstagramOAuthError("Meta did not return an access token.")
    expires_in = int(response.get("expires_in") or 0)
    expiry = iso(now_utc() + timedelta(seconds=expires_in)) if expires_in > 0 else ""
    return {"access_token": token, "expires_at": expiry}


def instagram_get(path: str, access_token: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    clean_path = path.strip("/")
    query = dict(params or {})
    query["access_token"] = access_token
    url = GRAPH_BASE_URL + "/" + GRAPH_VERSION + "/" + clean_path + "?" + urlencode(query)
    return _http_json(url)


def fetch_assigned_instagram_account(access_token: str) -> dict[str, str]:
    business = instagram_get("me", access_token, {"fields": "client_business_id"})
    client_business_id = str(business.get("client_business_id") or "")
    accounts = instagram_get(
        "me/assigned_instagram_accounts",
        access_token,
        {"fields": "id,username"},
    )
    rows = accounts.get("data") or []
    if not isinstance(rows, list) or not rows:
        raise InstagramOAuthError(
            "No Instagram professional account was shared with this app. In the Meta login dialog, select your Business Portfolio and Instagram account."
        )
    first = rows[0]
    if not isinstance(first, dict) or not first.get("id"):
        raise InstagramOAuthError("Meta did not return a usable Instagram account ID.")
    return {
        "ig_user_id": str(first["id"]),
        "username": str(first.get("username") or ""),
        "client_business_id": client_business_id,
    }


def fetch_profile(access_token: str, ig_user_id: str) -> dict[str, Any]:
    field_sets = (
        "id,username,account_type,media_count,followers_count,follows_count,profile_picture_url,biography,website",
        "id,username,account_type,media_count,followers_count,follows_count",
        "id,username,media_count",
    )
    last_error: Exception | None = None
    for fields in field_sets:
        try:
            profile = instagram_get(ig_user_id, access_token, {"fields": fields})
            if profile.get("username") or profile.get("id"):
                return profile
        except InstagramOAuthError as exc:
            last_error = exc
    raise InstagramOAuthError(str(last_error or "Could not read your Instagram profile."))


def fetch_media(access_token: str, ig_user_id: str) -> list[dict[str, Any]]:
    try:
        response = instagram_get(
            ig_user_id + "/media",
            access_token,
            {
                "fields": "id,caption,media_type,permalink,timestamp,like_count,comments_count",
                "limit": "25",
            },
        )
    except InstagramOAuthError:
        response = instagram_get(
            ig_user_id + "/media",
            access_token,
            {"fields": "id,caption,media_type,permalink,timestamp", "limit": "25"},
        )
    rows = response.get("data") or []
    if not isinstance(rows, list):
        return []
    clean: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        clean.append({
            "id": str(item.get("id") or ""),
            "caption": str(item.get("caption") or "")[:500],
            "media_type": str(item.get("media_type") or "POST"),
            "permalink": str(item.get("permalink") or ""),
            "timestamp": str(item.get("timestamp") or ""),
            "like_count": item.get("like_count") if isinstance(item.get("like_count"), int) else None,
            "comments_count": item.get("comments_count") if isinstance(item.get("comments_count"), int) else None,
        })
    return clean

def build_analytics(profile: dict[str, Any], media: list[dict[str, Any]]) -> dict[str, Any]:
    likes = [item["like_count"] for item in media if isinstance(item.get("like_count"), int)]
    comments = [item["comments_count"] for item in media if isinstance(item.get("comments_count"), int)]
    engagement_known = bool(likes or comments)
    type_counts: dict[str, int] = {}
    cutoff = now_utc() - timedelta(days=30)
    recent = 0
    for item in media:
        media_type = item.get("media_type") or "OTHER"
        type_counts[media_type] = type_counts.get(media_type, 0) + 1
        posted = parse_iso(item.get("timestamp"))
        if posted and posted >= cutoff:
            recent += 1
    top_posts = sorted(
        [item for item in media if isinstance(item.get("like_count"), int) or isinstance(item.get("comments_count"), int)],
        key=lambda item: (item.get("like_count") or 0) + (item.get("comments_count") or 0),
        reverse=True,
    )[:5]
    return {
        "posts_loaded": len(media),
        "recent_posts_30d": recent,
        "media_types": type_counts,
        "likes_on_loaded_posts": sum(likes) if likes else None,
        "comments_on_loaded_posts": sum(comments) if comments else None,
        "top_posts": top_posts,
        "engagement_available": engagement_known,
        "note": "Calculated from the latest media items returned by Instagram; it is not a full-account historical total.",
    }


def _store_account(
    cid: str,
    user_id: str,
    username: str,
    client_business_id: str,
    config_id: str,
    access_token: str,
    expires_at: str,
    scopes: list[str] | None = None,
    profile: dict[str, Any] | None = None,
    media: list[dict[str, Any]] | None = None,
) -> None:
    encrypted = _fernet().encrypt(access_token.encode("utf-8")).decode("ascii")
    profile_data = profile or {}
    media_data = media or []
    analytics = build_analytics(profile_data, media_data)
    timestamp = iso(now_utc())
    with connect() as db:
        db.execute(
            """
            INSERT INTO oauth_accounts
                (cid, ig_user_id, username, client_business_id, config_id, token_ciphertext,
                 expires_at, granted_scopes, profile_json, media_json, analytics_json, connected_at, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cid) DO UPDATE SET
                ig_user_id=excluded.ig_user_id,
                username=excluded.username,
                client_business_id=excluded.client_business_id,
                config_id=excluded.config_id,
                token_ciphertext=excluded.token_ciphertext,
                expires_at=excluded.expires_at,
                granted_scopes=excluded.granted_scopes,
                profile_json=excluded.profile_json,
                media_json=excluded.media_json,
                analytics_json=excluded.analytics_json,
                synced_at=excluded.synced_at,
                connected_at=excluded.connected_at
            """,
            (
                cid, user_id, username, client_business_id, config_id, encrypted, expires_at,
                json.dumps(scopes or []), json.dumps(profile_data), json.dumps(media_data),
                json.dumps(analytics), timestamp, timestamp,
            ),
        )
        db.commit()


def _row_for(cid: str):
    with connect() as db:
        return db.execute("SELECT * FROM oauth_accounts WHERE cid = ?", (cid,)).fetchone()


def _decrypt_token(row) -> str:
    try:
        return _fernet().decrypt(row["token_ciphertext"].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeEncodeError) as exc:
        raise ReauthorizationRequired("The saved authorization cannot be decrypted. Reconnect Instagram.") from exc


def sync_instagram_data(cid: str) -> dict[str, Any]:
    row = _row_for(cid)
    if not row:
        raise InstagramOAuthError("Connect your Instagram account first.")
    token = _decrypt_token(row)
    expires_at = parse_iso(row["expires_at"])
    if expires_at and expires_at <= now_utc():
        raise ReauthorizationRequired("This Meta authorization has expired. Please reconnect Instagram.")
    ig_user_id = str(row["ig_user_id"])
    profile = fetch_profile(token, ig_user_id)
    media = fetch_media(token, ig_user_id)
    username = str(profile.get("username") or row["username"])
    _store_account(
        cid, ig_user_id, username, row["client_business_id"], row["config_id"],
        token, row["expires_at"], json.loads(row["granted_scopes"] or "[]"),
        profile, media,
    )
    return {"profile": profile, "media": media, "analytics": build_analytics(profile, media)}

def dashboard_payload(cid: str) -> dict[str, Any]:
    row = _row_for(cid)
    if not row:
        return {"ok": True, "connected": False}
    try:
        profile = json.loads(row["profile_json"] or "{}")
        media = json.loads(row["media_json"] or "[]")
        analytics = json.loads(row["analytics_json"] or "{}")
    except json.JSONDecodeError:
        profile, media, analytics = {}, [], {}
    return {
        "ok": True,
        "connected": True,
        "username": row["username"],
        "ig_user_id": row["ig_user_id"],
        "client_business_id": row["client_business_id"],
        "config_id": row["config_id"],
        "profile": profile,
        "media": media,
        "analytics": analytics,
        "connected_at": row["connected_at"],
        "synced_at": row["synced_at"],
        "expires_at": row["expires_at"],
        "scopes": json.loads(row["granted_scopes"] or "[]"),
    }


@app.get("/")
def home():
    config_ready = bool(_meta_app_id() and _meta_app_secret() and _login_config_id())
    return render_template_string(
        PAGE,
        csrf=csrf_token(),
        config_ready=config_ready,
        configured_redirect=_redirect_uri() if config_ready else "",
    )


@app.get("/connect/instagram")
def connect_instagram():
    app_id, app_secret, config_id = _meta_app_id(), _meta_app_secret(), _login_config_id()
    if not app_id or not app_secret or not config_id:
        return render_template_string(ERROR_PAGE, title="Meta Unified Login is not configured", message="The server owner must add META_APP_ID, META_APP_SECRET and META_LOGIN_CONFIG_ID in the hosting environment before users can connect Instagram."), 503
    redirect_uri = _redirect_uri()
    parsed = urlparse(redirect_uri)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
        return render_template_string(ERROR_PAGE, title="Secure redirect URL required", message="Set INSTAGRAM_REDIRECT_URI to the exact HTTPS callback URL registered in the Meta developer dashboard."), 500
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_started_at"] = int(time.time())
    query = urlencode({
        "client_id": app_id,
        "config_id": config_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "display": "popup",
        "prompt": "login",
        "state": state,
    })
    return redirect(OAUTH_AUTHORIZE_URL + "?" + query, code=302)


@app.get("/oauth/callback")
def instagram_callback():
    expected_state = session.pop("oauth_state", None)
    started_at = session.pop("oauth_started_at", 0)
    supplied_state = request.args.get("state", "")
    if not expected_state or not supplied_state or not secrets.compare_digest(expected_state, supplied_state):
        return render_template_string(ERROR_PAGE, title="Connection could not be verified", message="The Meta authorization state did not match. Start the connection again."), 400
    if not started_at or time.time() - int(started_at) > 15 * 60:
        return render_template_string(ERROR_PAGE, title="Connection timed out", message="The authorization session expired. Please connect again."), 400
    if request.args.get("error"):
        reason = request.args.get("error_description") or request.args.get("error_reason") or "You cancelled Instagram authorization."
        return render_template_string(ERROR_PAGE, title="Meta authorization was not completed", message=reason), 400
    code = (request.args.get("code") or "").split("#", 1)[0]
    if not code:
        return render_template_string(ERROR_PAGE, title="Authorization code missing", message="Meta did not return an authorization code. Please try again."), 400
    try:
        token_data = exchange_authorization_code(code)
        account = fetch_assigned_instagram_account(token_data["access_token"])
        profile = fetch_profile(token_data["access_token"], account["ig_user_id"])
        media = fetch_media(token_data["access_token"], account["ig_user_id"])
        username = str(profile.get("username") or account.get("username") or "")
        _store_account(
            session["cid"], account["ig_user_id"], username,
            account["client_business_id"], _login_config_id(),
            token_data["access_token"], token_data["expires_at"], [], profile, media,
        )
    except InstagramOAuthError as exc:
        return render_template_string(ERROR_PAGE, title="Instagram connection failed", message=str(exc)), 502
    return redirect(url_for("home", connected="1"))


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify(dashboard_payload(session["cid"]))


@app.post("/api/sync")
def api_sync():
    if not csrf_ok():
        return jsonify(ok=False, error="Security token expired. Refresh the page and try again."), 403
    try:
        payload = sync_instagram_data(session["cid"])
    except ReauthorizationRequired as exc:
        return jsonify(ok=False, reauthorize=True, error=str(exc)), 401
    except InstagramOAuthError as exc:
        return jsonify(ok=False, error=str(exc)), 502
    return jsonify(ok=True, **payload)


@app.post("/api/disconnect")
def api_disconnect():
    if not csrf_ok():
        return jsonify(ok=False, error="Security token expired. Refresh the page and try again."), 403
    with connect() as db:
        db.execute("DELETE FROM oauth_accounts WHERE cid = ?", (session["cid"],))
        db.commit()
    session.pop("oauth_state", None)
    return jsonify(ok=True, message="Instagram connection and locally stored token deleted.")


@app.get("/healthz")
def healthz():
    try:
        with connect() as db:
            db.execute("SELECT 1").fetchone()
        db_ok = True
    except sqlite3.Error:
        db_ok = False
    configured = bool(_meta_app_id() and _meta_app_secret() and _login_config_id())
    return jsonify(
        ok=db_ok,
        app_version=APP_VERSION,
        database="available" if db_ok else "unavailable",
        instagram_login_configured=configured,
        oauth_provider="Meta Instagram API with Unified Login",
        password_collection=False,
        token_storage="encrypted_at_rest",
        data_import_enabled=False,
        relationship_lists_api=False,
        unfollow_api=False,
    ), (200 if db_ok else 503)


@app.errorhandler(413)
def too_large(_error):
    return jsonify(ok=False, error="Request is too large."), 413


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{{ csrf }}">
<title>Insight Studio — Instagram Analytics</title>
<style>
:root{color-scheme:dark;--bg:#090b12;--surface:#111621;--surface2:#171f2d;--line:#293244;--muted:#9aa6ba;--text:#f7f8fc;--pink:#ff6c9a;--purple:#9b89ff;--green:#5ad4a4;--amber:#f3bd72}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 10% -10%,#4b1d3d 0,transparent 35%),radial-gradient(ellipse at 100% 0,#1b3451 0,transparent 32%),var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit;text-decoration:none}.wrap{width:min(1120px,calc(100% - 34px));margin:auto}.top{height:76px;display:flex;align-items:center;border-bottom:1px solid #ffffff12}.top-inner{display:flex;justify-content:space-between;align-items:center}.brand{display:flex;align-items:center;gap:11px;font-weight:850;letter-spacing:.7px}.logo{height:38px;width:38px;border-radius:13px;display:grid;place-items:center;font-size:22px;background:linear-gradient(140deg,#ff9a54,#f0448e 58%,#855eff);box-shadow:0 10px 25px #ef438b30}.tag{font-size:11px;color:#b9c4d7;border:1px solid #ffffff1a;border-radius:99px;padding:6px 10px}.hero{padding:48px 0 24px}.eyebrow{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#ff98bb;font-weight:800}.hero h1{font-size:clamp(32px,5vw,53px);line-height:1.05;letter-spacing:-2px;margin:10px 0}.gradient{background:linear-gradient(100deg,#ff9b60,#ff5d9a,#9c91ff);color:transparent;background-clip:text}.hero p{color:var(--muted);max-width:680px;margin:0}.panel{background:linear-gradient(150deg,#151c2a,#101520);border:1px solid var(--line);border-radius:19px;padding:22px;box-shadow:0 16px 40px #0002;margin:14px 0}.connect-panel{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}.panel h2{font-size:17px;margin:0}.sub{font-size:12px;color:var(--muted);margin-top:5px}.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;border:0;border-radius:11px;padding:12px 18px;font-weight:800;font-size:13px;cursor:pointer;color:#100d16;background:linear-gradient(110deg,#ffad66,#ff5b98)}.btn.secondary{background:#222d40;color:#e5edff;border:1px solid #394760}.btn.danger{background:#3b202e;color:#ffdbe6;border:1px solid #734058}.btn:disabled{opacity:.5;cursor:wait}.status{display:inline-flex;align-items:center;gap:8px;font-size:12px;color:#d3e9e0}.dot{height:8px;width:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 4px #5ad4a41a}.notice{font-size:12px;line-height:1.65;color:#c7d0e1;background:#111d29;border:1px solid #263c4b;border-radius:13px;padding:14px;margin-top:14px}.notice b{color:white}.warning{background:#251d17;border-color:#51402d;color:#eed6ae}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin:15px 0}.stat{padding:18px;border:1px solid var(--line);border-radius:16px;background:linear-gradient(150deg,#171f2e,#101520)}.stat label{display:block;color:var(--muted);font-size:12px}.stat strong{display:block;font-size:29px;letter-spacing:-1px;margin-top:6px}.stat small{font-size:10px;color:#75829a}.section-head{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:15px}.muted{color:var(--muted)}.media-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.media-card{background:#0c111c;border:1px solid #252f41;border-radius:14px;padding:15px;min-width:0}.media-type{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#ff9bbd}.caption{font-size:13px;margin:9px 0;min-height:38px;overflow-wrap:anywhere}.meta{font-size:11px;color:var(--muted);display:flex;gap:12px;flex-wrap:wrap}.media-card a{display:inline-block;color:#9bbcff;font-size:11px;margin-top:10px;font-weight:700}.empty{padding:28px 12px;text-align:center;color:var(--muted);font-size:13px}.hidden{display:none!important}.two{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.metric-list{display:grid;grid-template-columns:1fr 1fr;gap:10px}.metric{padding:14px;border-radius:12px;background:#0d1320;border:1px solid #293244}.metric label{font-size:11px;color:var(--muted);display:block}.metric strong{font-size:22px;display:block;margin-top:4px}.footer{padding:16px 0 35px;color:#768198;font-size:11px}.footer a{color:#a8c8ff}.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#202b3d;border:1px solid #475872;border-radius:12px;padding:12px 18px;box-shadow:0 14px 36px #0008;display:none;z-index:10;max-width:calc(100% - 28px)}.toast.show{display:block}
@media(max-width:760px){.hero{padding-top:34px}.stats{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}.media-grid{grid-template-columns:1fr}.panel{padding:16px}.connect-panel{align-items:flex-start}.tag{display:none}}
</style></head>
<body>
<header class="top"><div class="wrap top-inner"><div class="brand"><span class="logo">◎</span><span>INSIGHT <span style="color:#ff83ad">STUDIO</span></span></div><span class="tag">OFFICIAL META UNIFIED LOGIN</span></div></header>
<main class="wrap">
<section class="hero"><div class="eyebrow">Your account · Your authorization · Your insights</div><h1>Understand your Instagram.<br><span class="gradient">Without sharing your password.</span></h1><p>Connect through Meta's official Instagram/Facebook authorization screen. Your password and two-factor code stay on Instagram; Insight Studio receives a limited access token after you approve access.</p></section>
<section class="panel connect-panel">
 <div><div id="connectionStatus" class="status"><span class="dot" style="background:#78859b"></span> Not connected</div><h2 id="connectTitle" style="margin-top:8px">Connect your Instagram account</h2><div class="sub" id="connectSubtitle">Business and Creator accounts using Meta Unified Login are supported.</div></div>
 <div style="display:flex;gap:9px;flex-wrap:wrap"><a class="btn" id="connectButton" href="/connect/instagram">◎ Continue with Instagram</a><button class="btn secondary hidden" id="syncButton" type="button">↻ Sync data</button><button class="btn danger hidden" id="disconnectButton" type="button">Disconnect</button></div>
</section>
{% if not config_ready %}
<div class="notice warning"><b>Server setup required.</b> Add META_APP_ID, META_APP_SECRET, META_LOGIN_CONFIG_ID, META_REDIRECT_URI, SECRET_KEY and TOKEN_ENCRYPTION_KEY to the hosting service. Configure the Meta Unified Login callback URL as <b>https://instagrams.cc.cd/oauth/callback</b>.</div>
{% endif %}
<div id="dashboard" class="hidden">
<section class="stats">
 <div class="stat"><label>Followers</label><strong id="followers">—</strong><small>Instagram profile count</small></div>
 <div class="stat"><label>Following</label><strong id="following">—</strong><small>Instagram profile count</small></div>
 <div class="stat"><label>Published media</label><strong id="mediaCount">—</strong><small>Total reported by Instagram</small></div>
 <div class="stat"><label>Recent posts loaded</label><strong id="loadedPosts">—</strong><small>Latest media returned by API</small></div>
</section>
<section class="two">
 <div class="panel"><div class="section-head"><div><h2>Account snapshot</h2><div class="sub">Profile details returned by Instagram</div></div><span id="accountType" class="tag">Professional</span></div>
  <div class="metric-list"><div class="metric"><label>Username</label><strong id="username" style="font-size:18px">—</strong></div><div class="metric"><label>Media published</label><strong id="mediaCount2">—</strong></div><div class="metric"><label>Posts in last 30 days</label><strong id="recentPosts">—</strong></div><div class="metric"><label>Media types</label><strong id="mediaTypes" style="font-size:15px">—</strong></div></div>
 </div>
 <div class="panel"><div class="section-head"><div><h2>Content analysis</h2><div class="sub">Calculated from the latest media returned by Instagram</div></div></div>
  <div class="metric-list"><div class="metric"><label>Likes on loaded posts</label><strong id="likes">—</strong></div><div class="metric"><label>Comments on loaded posts</label><strong id="comments">—</strong></div></div>
  <div class="sub" id="analysisNote" style="margin-top:12px">Engagement totals appear only when Instagram returns those fields.</div>
 </div>
</section>
<section class="panel"><div class="section-head"><div><h2>Recent Instagram content</h2><div class="sub">Latest media available through the approved API permissions</div></div><span id="syncedAt" class="tag">Not synced</span></div><div class="media-grid" id="mediaGrid"><div class="empty">Connect and sync your Instagram account to load media.</div></div></section>
<section class="panel"><div class="section-head"><div><h2>Following management</h2><span class="tag">Manual action</span></div></div><div class="notice warning"><b>Direct unfollow is not available through the official Instagram API.</b> This app will not automate private endpoints or store your password/cookies. Open Instagram to review and manage follows there.</div><p style="margin:14px 0 0"><a class="btn secondary" href="https://www.instagram.com/" target="_blank" rel="noopener noreferrer">Open Instagram to manage follows ↗</a></p></section>
</div>
<section class="panel"><h2>Privacy &amp; security</h2><div class="sub">Insight Studio never displays or stores your Instagram password or 2FA code. OAuth access tokens are encrypted before being stored on the server and are never sent to browser JavaScript. Disconnect deletes the locally stored token and cached profile/media data. You can also revoke this app from Instagram's authorized-app settings.</div></section>
<footer class="footer">Insight Studio v3 · Independent app, not affiliated with Meta or Instagram. · <a href="https://www.instagram.com/" target="_blank" rel="noopener noreferrer">Instagram ↗</a></footer>
</main><div id="toast" class="toast" role="status" aria-live="polite"></div>
<script>
const csrf=document.querySelector('meta[name="csrf-token"]').content;
const $=id=>document.getElementById(id);
function showToast(message){const el=$("toast");el.textContent=message;el.classList.add("show");window.setTimeout(()=>el.classList.remove("show"),3500);}
function count(value){return value===null||value===undefined?"—":Number(value).toLocaleString();}
async function api(url,options){const opts=options||{};opts.headers=Object.assign({},opts.headers||{},{"X-CSRF-Token":csrf});const response=await fetch(url,opts);let data={};try{data=await response.json();}catch(_e){}if(!response.ok||data.ok===false){const error=new Error(data.error||("Request failed ("+response.status+")"));error.reauthorize=!!data.reauthorize;throw error;}return data;}
function mediaCard(item){const card=document.createElement("article");card.className="media-card";const type=document.createElement("div");type.className="media-type";type.textContent=item.media_type||"POST";const caption=document.createElement("div");caption.className="caption";caption.textContent=item.caption||"No caption";const meta=document.createElement("div");meta.className="meta";if(item.like_count!==null&&item.like_count!==undefined){const likes=document.createElement("span");likes.textContent="♥ "+count(item.like_count);meta.append(likes);}if(item.comments_count!==null&&item.comments_count!==undefined){const comments=document.createElement("span");comments.textContent="▤ "+count(item.comments_count);meta.append(comments);}const date=document.createElement("span");date.textContent=item.timestamp?new Date(item.timestamp).toLocaleDateString():"";meta.append(date);card.append(type,caption,meta);if(item.permalink){const link=document.createElement("a");link.href=item.permalink;link.target="_blank";link.rel="noopener noreferrer";link.textContent="Open on Instagram ↗";card.append(link);}return card;}
function renderDashboard(data){const connected=!!data.connected;$("dashboard").classList.toggle("hidden",!connected);$("connectButton").classList.toggle("hidden",connected);$("syncButton").classList.toggle("hidden",!connected);$("disconnectButton").classList.toggle("hidden",!connected);if(!connected){$("connectionStatus").innerHTML='<span class="dot" style="background:#78859b"></span> Not connected';$("connectTitle").textContent="Connect your Instagram account";$("connectSubtitle").textContent="Business and Creator accounts using Meta Unified Login are supported.";return;}
$("connectionStatus").innerHTML='<span class="dot"></span> Instagram connected';$("connectTitle").textContent="@"+(data.username||"Instagram account");$("connectSubtitle").textContent="Your account is connected through official Instagram Login.";const p=data.profile||{},a=data.analytics||{},media=data.media||[];$("username").textContent="@"+(data.username||p.username||"");$("accountType").textContent=p.account_type||"Professional";$("followers").textContent=count(p.followers_count);$("following").textContent=count(p.follows_count);$("mediaCount").textContent=count(p.media_count);$("mediaCount2").textContent=count(p.media_count);$("loadedPosts").textContent=count(a.posts_loaded);$("recentPosts").textContent=count(a.recent_posts_30d);$("mediaTypes").textContent=Object.keys(a.media_types||{}).length?Object.entries(a.media_types).map(x=>x[0]+": "+x[1]).join(" · "):"—";$("likes").textContent=count(a.likes_on_loaded_posts);$("comments").textContent=count(a.comments_on_loaded_posts);$("analysisNote").textContent=a.note||"Engagement totals are only available when returned by Instagram."; $("syncedAt").textContent="Synced "+(data.synced_at?new Date(data.synced_at).toLocaleString():"");const grid=$("mediaGrid");grid.replaceChildren();if(!media.length){grid.innerHTML='<div class="empty">No media was returned. Check your granted permissions and account content.</div>';}else{media.forEach(item=>grid.append(mediaCard(item)));}}
async function loadDashboard(){try{const data=await api("/api/dashboard");renderDashboard(data);}catch(error){showToast(error.message);}}
$("syncButton").addEventListener("click",async()=>{const btn=$("syncButton");btn.disabled=true;btn.textContent="Syncing…";try{const result=await api("/api/sync",{method:"POST"});showToast("Instagram data synced.");const current=await api("/api/dashboard");renderDashboard(current);}catch(error){showToast(error.message);if(error.reauthorize){$("connectButton").classList.remove("hidden");$("dashboard").classList.add("hidden");}}finally{btn.disabled=false;btn.textContent="↻ Sync data";}});
$("disconnectButton").addEventListener("click",async()=>{if(!window.confirm("Disconnect Instagram and delete the encrypted access token and cached data stored by this app?"))return;try{await api("/api/disconnect",{method:"POST"});showToast("Instagram disconnected and local token deleted.");renderDashboard({connected:false});}catch(error){showToast(error.message);}});
loadDashboard();
</script></body></html>"""

ERROR_PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · Insight Studio</title><style>body{margin:0;min-height:100vh;background:#0b0e17;color:#f6f7fb;font:15px/1.6 system-ui;display:grid;place-items:center}.box{width:min(560px,calc(100% - 32px));border:1px solid #303b50;background:#151c29;border-radius:18px;padding:28px}h1{font-size:24px;margin:0 0 12px}p{color:#aeb9cb}.btn{display:inline-block;background:#ff709c;color:#18101a;padding:10px 16px;border-radius:10px;text-decoration:none;font-weight:800}</style></head><body><main class="box"><h1>{{ title }}</h1><p>{{ message }}</p><a class="btn" href="/">Return to Insight Studio</a></main></body></html>"""


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
