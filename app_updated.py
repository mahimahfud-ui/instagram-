"""Insight: privacy-first Instagram export analytics.

This application never asks for Instagram passwords, 2FA codes, cookies, or access
tokens. It analyzes the JSON archive downloaded by the account owner from Instagram.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template_string, request, session

APP_VERSION = "2.0.0"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 2500
MAX_JSON_FILE_BYTES = 5 * 1024 * 1024
USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")

DATA_DIR = Path(os.environ.get("DATA_DIR", "data")).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "insight.sqlite3"


def _secret_key() -> str:
    configured = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
    if configured:
        return configured
    key_file = DATA_DIR / "secret.key"
    try:
        value = key_file.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    except OSError:
        pass
    value = secrets.token_urlsafe(48)
    try:
        key_file.write_text(value + "\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
    except OSError:
        # Ephemeral hosts may not preserve local files. Set SECRET_KEY in production.
        pass
    return value


app = Flask(__name__)
app.secret_key = _secret_key()
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 1024 * 1024,
    SESSION_COOKIE_NAME="insight_export_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER") or os.environ.get("COOKIE_SECURE") == "1"),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    cid TEXT PRIMARY KEY,
    profile_username TEXT NOT NULL DEFAULT '',
    current_import_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT NOT NULL,
    filename TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    follower_count INTEGER NOT NULL,
    following_count INTEGER NOT NULL,
    FOREIGN KEY (cid) REFERENCES accounts(cid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_imports_cid ON imports(cid, id DESC);
CREATE TABLE IF NOT EXISTS import_relations (
    import_id INTEGER NOT NULL,
    relation TEXT NOT NULL CHECK (relation IN ('followers', 'following')),
    username TEXT NOT NULL,
    PRIMARY KEY (import_id, relation, username),
    FOREIGN KEY (import_id) REFERENCES imports(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT NOT NULL,
    import_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (cid) REFERENCES accounts(cid) ON DELETE CASCADE,
    FOREIGN KEY (import_id) REFERENCES imports(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_cid ON events(cid, id DESC);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 20000")
    conn.execute("PRAGMA secure_delete = ON")
    return conn


def _purge_legacy_credential_material() -> None:
    """Remove credential-capture tables and files created by the old app."""
    with connect() as conn:
        existing = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        legacy_tables = {
            "creds", "ig_sessions", "attempts", "verification_attempts",
            "followers_cache", "following_cache", "profiles", "snapshots",
            "engagement", "visits", "actions", "self",
        }
        legacy_present = bool(existing & legacy_tables)
        if legacy_present:
            for table in legacy_tables:
                conn.execute(f'DROP TABLE IF EXISTS "{table}"')
            # The previous application used the same events table for scraped activity.
            conn.execute("DROP TABLE IF EXISTS events")
            conn.commit()
            conn.execute("VACUUM")
    shutil.rmtree(DATA_DIR / "sessions", ignore_errors=True)
    for pattern in ("events.jsonl", "insight.log", "insight.log.*"):
        for old_file in DATA_DIR.glob(pattern):
            try:
                old_file.unlink()
            except OSError:
                pass


def init_db() -> None:
    _purge_legacy_credential_material()
    with connect() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def csrf_ok() -> bool:
    submitted = request.headers.get("X-CSRF-Token") or request.form.get("_csrf") or ""
    stored = session.get("_csrf") or ""
    return bool(submitted and stored and secrets.compare_digest(submitted, stored))


@app.before_request
def ensure_browser_session() -> None:
    if not session.get("cid"):
        session["cid"] = secrets.token_urlsafe(24)
    session.permanent = True


@app.after_request
def security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    return response


def normalize_username(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if "instagram.com" in candidate.lower():
        try:
            candidate = urlparse(candidate if "://" in candidate else "https://" + candidate).path
            candidate = candidate.strip("/").split("/")[0]
        except ValueError:
            return None
    candidate = candidate.lstrip("@").strip()
    if USERNAME_RE.fullmatch(candidate):
        return candidate.lower()
    return None


def username_from_record(record: object) -> str | None:
    if isinstance(record, str):
        return normalize_username(record)
    if not isinstance(record, dict):
        return None

    candidates: list[object] = []
    string_data = record.get("string_list_data")
    if isinstance(string_data, list):
        for item in string_data:
            if isinstance(item, dict):
                candidates.extend((item.get("value"), item.get("href")))
    candidates.extend((record.get("title"), record.get("username"), record.get("href")))
    for candidate in candidates:
        username = normalize_username(candidate)
        if username:
            return username
    return None


def records_for(payload: object, relation: str) -> list:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    keys = (
        ("relationships_followers", "followers", "data")
        if relation == "followers"
        else ("relationships_following", "following", "data")
    )
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = records_for(value, relation)
            if nested:
                return nested
    if "string_list_data" in payload:
        return [payload]
    return []


def parse_relation_document(payload: object, relation: str) -> set[str]:
    return {
        username
        for record in records_for(payload, relation)
        if (username := username_from_record(record))
    }


def parse_instagram_archive(data: bytes, filename: str) -> tuple[set[str], set[str]]:
    if not data:
        raise ValueError("The selected file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload is too large. Maximum size is 25 MB.")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ValueError("Upload the ZIP archive downloaded from Instagram in JSON format.")

    followers: set[str] = set()
    following: set[str] = set()
    found_followers = False
    found_following = False

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = [item for item in archive.infolist() if not item.is_dir()]
            if len(entries) > MAX_ARCHIVE_FILES:
                raise ValueError("The archive contains too many files.")
            unpacked_total = sum(item.file_size for item in entries)
            if unpacked_total > MAX_ARCHIVE_BYTES:
                raise ValueError("The uncompressed archive is too large.")
            for item in entries:
                basename = Path(item.filename.replace("\\", "/")).name.lower()
                if not basename.endswith(".json"):
                    continue
                is_followers = bool(re.fullmatch(r"followers(?:_\d+)?\.json", basename))
                is_following = bool(re.fullmatch(r"following(?:_\d+)?\.json", basename))
                if not (is_followers or is_following):
                    continue
                if item.flag_bits & 0x1:
                    raise ValueError("Password-protected ZIP files are not supported.")
                if item.file_size > MAX_JSON_FILE_BYTES:
                    raise ValueError("A relationship JSON file exceeds the 5 MB limit.")
                try:
                    payload = json.loads(archive.read(item).decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
                    raise ValueError("A follower/following JSON file could not be read.") from exc
                if is_followers:
                    found_followers = True
                    followers.update(parse_relation_document(payload, "followers"))
                if is_following:
                    found_following = True
                    following.update(parse_relation_document(payload, "following"))
    except zipfile.BadZipFile as exc:
        raise ValueError("The ZIP archive is damaged or invalid.") from exc

    if not found_followers or not found_following:
        raise ValueError(
            "This archive must include both followers and following JSON files. "
            "In Instagram export settings, choose Followers and following and JSON format."
        )
    return followers, following


def read_current_relations(conn: sqlite3.Connection, import_id: int | None) -> dict[str, set[str]]:
    result = {"followers": set(), "following": set()}
    if not import_id:
        return result
    rows = conn.execute(
        "SELECT relation, username FROM import_relations WHERE import_id = ?",
        (import_id,),
    ).fetchall()
    for row in rows:
        result[row["relation"]].add(row["username"])
    return result


def save_import(
    cid: str,
    filename: str,
    profile_username: str,
    followers: set[str],
    following: set[str],
) -> dict:
    imported_at = now_iso()
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO accounts (cid, profile_username, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (cid, profile_username, imported_at, imported_at),
        )
        account = conn.execute(
            "SELECT current_import_id, profile_username FROM accounts WHERE cid = ?", (cid,)
        ).fetchone()
        previous = read_current_relations(conn, account["current_import_id"])
        cursor = conn.execute(
            "INSERT INTO imports (cid, filename, imported_at, follower_count, following_count) "
            "VALUES (?, ?, ?, ?, ?)",
            (cid, Path(filename).name[:120], imported_at, len(followers), len(following)),
        )
        import_id = int(cursor.lastrowid)
        conn.executemany(
            "INSERT INTO import_relations (import_id, relation, username) VALUES (?, ?, ?)",
            [(import_id, "followers", name) for name in sorted(followers)]
            + [(import_id, "following", name) for name in sorted(following)],
        )

        events: list[tuple[str, str]] = []
        if account["current_import_id"]:
            events.extend(("added_to_followers", name) for name in sorted(followers - previous["followers"]))
            events.extend(("removed_from_followers", name) for name in sorted(previous["followers"] - followers))
            events.extend(("added_to_following", name) for name in sorted(following - previous["following"]))
            events.extend(("removed_from_following", name) for name in sorted(previous["following"] - following))
            conn.executemany(
                "INSERT INTO events (cid, import_id, kind, username, created_at) VALUES (?, ?, ?, ?, ?)",
                [(cid, import_id, kind, name, imported_at) for kind, name in events],
            )

        chosen_username = profile_username or account["profile_username"] or ""
        conn.execute(
            "UPDATE accounts SET profile_username = ?, current_import_id = ?, updated_at = ? WHERE cid = ?",
            (chosen_username, import_id, imported_at, cid),
        )
    return {
        "import_id": import_id,
        "imported_at": imported_at,
        "followers": len(followers),
        "following": len(following),
        "changes": len(events),
        "profile_username": chosen_username,
    }


def current_account(conn: sqlite3.Connection, cid: str):
    return conn.execute(
        "SELECT a.profile_username, a.current_import_id, i.filename, i.imported_at, "
        "i.follower_count, i.following_count FROM accounts a "
        "LEFT JOIN imports i ON i.id = a.current_import_id WHERE a.cid = ?",
        (cid,),
    ).fetchone()


def get_relation_sets(conn: sqlite3.Connection, cid: str) -> dict[str, set[str]]:
    account = current_account(conn, cid)
    return read_current_relations(conn, account["current_import_id"] if account else None)


@app.get("/")
def home():
    return render_template_string(PAGE.replace("__CSRF__", csrf_token()))


@app.get("/favicon.ico")
def favicon():
    artwork = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
        '<stop stop-color="#ff9c58"/><stop offset=".55" stop-color="#ed3c91"/>'
        '<stop offset="1" stop-color="#735cf4"/></linearGradient></defs>'
        '<rect width="64" height="64" rx="18" fill="#111523"/>'
        '<rect x="7" y="7" width="50" height="50" rx="15" fill="url(#g)"/>'
        '<circle cx="32" cy="32" r="13" fill="none" stroke="white" stroke-width="4"/>'
        '<circle cx="46" cy="18" r="3" fill="white"/></svg>'
    )
    return Response(artwork, mimetype="image/svg+xml")


@app.post("/api/import")
def api_import():
    if not csrf_ok():
        return jsonify(ok=False, error="Security token expired. Refresh the page and retry."), 403
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify(ok=False, error="Choose your Instagram ZIP export first."), 400
    data = uploaded.stream.read(MAX_UPLOAD_BYTES + 1)
    try:
        followers, following = parse_instagram_archive(data, uploaded.filename)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400

    handle = normalize_username(request.form.get("profile_username", "")) or ""
    result = save_import(
        session["cid"], uploaded.filename, handle, followers, following
    )
    return jsonify(ok=True, message="Instagram export imported successfully.", result=result)


@app.get("/api/state")
def api_state():
    with connect() as conn:
        account = current_account(conn, session["cid"])
        if not account or not account["current_import_id"]:
            return jsonify(ok=True, ready=False, followers=0, following=0,
                           not_following_back=0, fans=0, mutual=0, events=0)
        sets = get_relation_sets(conn, session["cid"])
        events = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE cid = ?", (session["cid"],)
        ).fetchone()["n"]
        return jsonify(
            ok=True,
            ready=True,
            profile_username=account["profile_username"],
            filename=account["filename"],
            imported_at=account["imported_at"],
            followers=len(sets["followers"]),
            following=len(sets["following"]),
            not_following_back=len(sets["following"] - sets["followers"]),
            fans=len(sets["followers"] - sets["following"]),
            mutual=len(sets["followers"] & sets["following"]),
            events=events,
        )


@app.get("/api/list")
def api_list():
    kind = request.args.get("kind", "notback")
    query = (request.args.get("q") or "").strip().lower()[:80]
    labels = {
        "notback": "following",
        "fans": "followers",
        "mutual": "mutual",
        "followers": "followers_all",
        "following": "following_all",
    }
    if kind not in labels:
        return jsonify(ok=False, error="Unknown list type."), 400

    with connect() as conn:
        sets = get_relation_sets(conn, session["cid"])
    if kind == "notback":
        names = sets["following"] - sets["followers"]
    elif kind == "fans":
        names = sets["followers"] - sets["following"]
    elif kind == "mutual":
        names = sets["followers"] & sets["following"]
    elif kind == "followers":
        names = sets["followers"]
    else:
        names = sets["following"]
    rows = [{"username": name} for name in sorted(names) if query in name]
    return jsonify(ok=True, kind=kind, total=len(rows), rows=rows)


@app.get("/api/activity")
def api_activity():
    with connect() as conn:
        rows = conn.execute(
            "SELECT kind, username, created_at FROM events WHERE cid = ? "
            "ORDER BY id DESC LIMIT 200",
            (session["cid"],),
        ).fetchall()
    return jsonify(ok=True, rows=[dict(row) for row in rows])


@app.get("/api/export")
def api_export():
    kind = request.args.get("kind", "notback")
    fmt = request.args.get("format", "csv").lower()
    if kind not in ("notback", "fans", "mutual", "followers", "following", "all"):
        return jsonify(ok=False, error="Unknown export type."), 400
    with connect() as conn:
        sets = get_relation_sets(conn, session["cid"])
        account = current_account(conn, session["cid"])
    if kind == "notback":
        data = sorted(sets["following"] - sets["followers"])
    elif kind == "fans":
        data = sorted(sets["followers"] - sets["following"])
    elif kind == "mutual":
        data = sorted(sets["followers"] & sets["following"])
    elif kind == "followers":
        data = sorted(sets["followers"])
    elif kind == "following":
        data = sorted(sets["following"])
    else:
        data = None

    if fmt == "json":
        payload = {
            "exported_at": now_iso(),
            "profile_username": account["profile_username"] if account else "",
            "relationships": {
                "followers": sorted(sets["followers"]),
                "following": sorted(sets["following"]),
                "not_following_back": sorted(sets["following"] - sets["followers"]),
                "fans": sorted(sets["followers"] - sets["following"]),
                "mutual": sorted(sets["followers"] & sets["following"]),
            },
        }
        return Response(
            json.dumps(payload, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": 'attachment; filename="instagram-report.json"'},
        )
    if fmt != "csv":
        return jsonify(ok=False, error="Format must be csv or json."), 400

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "relationship"])
    if data is None:
        for name in sorted(sets["followers"]):
            writer.writerow([name, "follower"])
        for name in sorted(sets["following"]):
            writer.writerow([name, "following"])
    else:
        relationship = kind
        for name in data:
            writer.writerow([name, relationship])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="instagram-{kind}.csv"'},
    )


@app.post("/api/clear")
def api_clear():
    if not csrf_ok():
        return jsonify(ok=False, error="Security token expired. Refresh the page and retry."), 403
    with connect() as conn:
        conn.execute("DELETE FROM accounts WHERE cid = ?", (session["cid"],))
    return jsonify(ok=True, message="Imported account data deleted.")


@app.get("/healthz")
def healthz():
    try:
        with connect() as conn:
            conn.execute("SELECT 1").fetchone()
        database_ok = True
    except sqlite3.Error:
        database_ok = False
    return jsonify(
        ok=database_ok,
        app_version=APP_VERSION,
        database="available" if database_ok else "unavailable",
        storage_configured=bool(os.environ.get("DATA_DIR")),
        credential_capture=False,
        instagram_password_login=False,
        profile_visitors_supported=False,
        import_formats=["Instagram JSON ZIP"],
    ), (200 if database_ok else 503)


@app.errorhandler(413)
def too_large(_error):
    return jsonify(ok=False, error="Upload is too large. Maximum size is 25 MB."), 413


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="__CSRF__">
<title>Insight — Instagram Data Studio</title>
<style>
:root{color-scheme:dark;--bg:#080a12;--panel:#111523;--panel2:#171d2e;--line:#252d42;--muted:#929bb1;--text:#f5f7ff;--pink:#ff4e8a;--blue:#6ca7ff;--green:#54d6a0;--red:#ff7288}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 12% 0%,#27142a 0,transparent 34%),radial-gradient(ellipse at 90% 3%,#13264a 0,transparent 32%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
a{color:inherit;text-decoration:none}.wrap{width:min(1160px,calc(100% - 32px));margin:auto}.top{height:76px;border-bottom:1px solid #ffffff12;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.2px}.mark{width:38px;height:38px;border-radius:13px;background:linear-gradient(135deg,#ff8c4e,#ef348f 55%,#7558f5);display:grid;place-items:center;font-size:21px;box-shadow:0 8px 25px #ef348f30}.top-note{color:var(--muted);font-size:12px}.hero{padding:48px 0 28px;display:flex;justify-content:space-between;gap:28px;align-items:end}.eyebrow{color:#ff8eaf;text-transform:uppercase;letter-spacing:2px;font-size:11px;font-weight:800}.hero h1{font-size:clamp(30px,5vw,48px);line-height:1.08;letter-spacing:-1.7px;margin:10px 0}.hero p{margin:0;color:var(--muted);max-width:590px}.hero-side{color:#bcc6dd;font-size:12px;text-align:right;max-width:250px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:10px 0 18px}.stat,.panel{background:linear-gradient(155deg,#151b2b,#0f1421);border:1px solid var(--line);border-radius:18px;box-shadow:0 12px 35px #0002}.stat{padding:18px 19px}.stat .name{color:var(--muted);font-size:12px}.stat strong{display:block;font-size:30px;letter-spacing:-1px;margin-top:5px}.stat small{color:#758199;font-size:11px}.panel{padding:22px;margin:14px 0}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:14px}.panel h2{font-size:17px;margin:0}.hint{font-size:12px;color:var(--muted)}.upload{border:1px dashed #596685;background:#0b1020;border-radius:14px;padding:20px;display:grid;grid-template-columns:1fr auto;gap:15px;align-items:center}.upload input[type=file]{max-width:100%;color:var(--muted);font-size:13px}.upload input[type=text],.search{background:#090e19;border:1px solid #303b55;border-radius:10px;color:var(--text);padding:11px 12px;outline:0}.upload input:focus,.search:focus{border-color:var(--blue)}.handle{display:flex;gap:8px;align-items:center;margin-top:10px}.handle label{font-size:12px;color:var(--muted);white-space:nowrap}.btn{border:0;border-radius:10px;padding:11px 16px;color:#08101d;background:linear-gradient(110deg,#ffa15d,#ff5a91);font-weight:800;cursor:pointer;white-space:nowrap}.btn.secondary{color:#dce5ff;background:#202a40;border:1px solid #364461}.btn.danger{color:#ffdce2;background:#401d2b;border:1px solid #743044}.btn:disabled{opacity:.5;cursor:wait}.notice{color:#c4cce0;font-size:12px;margin-top:14px;line-height:1.6}.notice b{color:#fff}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 14px}.tab{border:1px solid #303a52;border-radius:999px;background:#141b2b;color:#aeb8ce;padding:9px 15px;font-weight:700;font-size:12px;cursor:pointer}.tab.active{background:#30203a;color:#fff;border-color:#a44475;box-shadow:0 0 0 2px #c44e8620}.tools{display:flex;align-items:center;justify-content:space-between;gap:12px}.search{width:min(360px,100%)}.list{margin-top:16px}.userrow{display:flex;align-items:center;justify-content:space-between;padding:13px 2px;border-bottom:1px solid #ffffff10;gap:12px}.userrow:last-child{border:0}.user-left{display:flex;align-items:center;gap:11px;min-width:0}.avatar{width:34px;height:34px;border-radius:12px;background:#252e45;display:grid;place-items:center;color:#dce7ff;font-size:12px;font-weight:800}.user-name{font-weight:700;overflow:hidden;text-overflow:ellipsis}.user-meta{font-size:11px;color:var(--muted)}.open-link{color:#8db5ff;font-size:12px;font-weight:700}.empty{padding:34px 10px;text-align:center;color:var(--muted);font-size:13px}.events{display:grid;gap:9px}.event{display:flex;justify-content:space-between;gap:12px;padding:11px 13px;background:#0c1120;border:1px solid #222b40;border-radius:12px;font-size:12px}.event span:last-child{color:var(--muted);white-space:nowrap}.bottom{padding:5px 0 36px;color:#79839a;font-size:11px}.bottom a{color:#a8c6ff}.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#202a40;border:1px solid #465573;padding:12px 17px;border-radius:12px;box-shadow:0 15px 40px #0008;display:none;max-width:calc(100% - 30px);z-index:10}.toast.show{display:block}.split{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.unsupported{border:1px solid #503b35;background:#211914;border-radius:13px;padding:14px;color:#eac8b9;font-size:12px}
@media(max-width:760px){.hero{display:block;padding-top:34px}.hero-side{text-align:left;margin-top:14px}.grid{grid-template-columns:repeat(2,1fr)}.upload{grid-template-columns:1fr}.split{grid-template-columns:1fr}.top-note{display:none}.panel{padding:16px}.tools{align-items:stretch;flex-direction:column}.search{width:100%}.handle{align-items:flex-start;flex-direction:column}.handle input{width:100%}}
</style>
</head>
<body>
<header class="top"><div class="wrap" style="display:flex;align-items:center;justify-content:space-between;width:100%"><div class="brand"><span class="mark">◎</span><span>INSIGHT <span style="color:#ff7ca8">STUDIO</span></span></div><span class="top-note">Private export analysis · No Instagram login required</span></div></header>
<main class="wrap">
<section class="hero"><div><div class="eyebrow">Your account data, clearly</div><h1>Know your connections.<br><span style="background:linear-gradient(100deg,#ff8d65,#ff4d98,#8c8bff);background-clip:text;color:transparent">Keep your data yours.</span></h1><p>Upload the JSON ZIP downloaded directly from Instagram. Compare followers and following, find non-mutual connections, and export clean reports.</p></div><div class="hero-side">Works from your official Instagram export.<br>No password, cookie, or 2FA code is ever requested.</div></section>
<section class="grid" aria-label="Account statistics">
<div class="stat"><span class="name">Followers</span><strong id="followers">—</strong><small>In your latest export</small></div>
<div class="stat"><span class="name">Following</span><strong id="following">—</strong><small>In your latest export</small></div>
<div class="stat"><span class="name">Not following back</span><strong id="notback">—</strong><small>You follow them; they do not follow you</small></div>
<div class="stat"><span class="name">Mutual connections</span><strong id="mutual">—</strong><small>Both lists contain the account</small></div>
</section>
<section class="panel">
<div class="panel-head"><div><h2>Import Instagram data</h2><div class="hint">Use the ZIP archive from Accounts Center → Export your information.</div></div><span class="hint" id="importStatus">No data imported</span></div>
<form id="uploadForm" class="upload">
<div><input type="file" id="file" name="file" accept=".zip,application/zip" required>
<div class="handle"><label for="profile_username">Instagram username (optional)</label><input id="profile_username" name="profile_username" type="text" maxlength="30" placeholder="@yourusername"></div>
<div class="notice">Choose <b>Followers and following</b>, set the date range to <b>All time</b>, and choose <b>JSON</b> format before creating the export.</div></div>
<button class="btn" id="uploadButton" type="submit">Import &amp; compare</button>
</form>
<div class="notice">Your ZIP is processed in memory. Only follower/following usernames and import comparison events are stored. Photos, messages, passwords, and unrelated archive content are not saved.</div>
</section>
<section class="split">
<div class="panel">
<div class="panel-head"><div><h2>Relationship lists</h2><div class="hint">Search, review and open profiles manually.</div></div><a class="open-link" id="exportLink" href="/api/export?kind=notback&amp;format=csv">Export CSV ↗</a></div>
<div class="tabs" id="tabs">
<button class="tab active" data-kind="notback">Not following back</button>
<button class="tab" data-kind="fans">Follows you</button>
<button class="tab" data-kind="mutual">Mutual</button>
<button class="tab" data-kind="followers">Followers</button>
<button class="tab" data-kind="following">Following</button>
</div>
<div class="tools"><input class="search" id="search" type="search" placeholder="Search usernames…" aria-label="Search usernames"><a class="open-link" href="/api/export?kind=all&amp;format=json">Full JSON report ↗</a></div>
<div class="list" id="list"><div class="empty">Import your Instagram JSON export to see your lists.</div></div>
</div>
<div>
<section class="panel"><div class="panel-head"><div><h2>Import activity</h2><div class="hint">Changes between your last two exports</div></div></div><div id="activity" class="events"><div class="empty">No comparison history yet.</div></div></section>
<section class="panel"><h2>What Instagram does not share</h2><div class="unsupported" style="margin-top:13px"><b>Profile visitors are not available.</b><br>Instagram does not provide a list of people who viewed your profile. Insight will never invent visitor names or visit counts.</div><div class="notice">“Ghost follower” or engagement scoring is not calculated from the follower export because it does not prove who viewed or engaged with your content.</div></section>
</div>
</section>
<section class="panel" style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap"><div><h2>Privacy controls</h2><div class="hint">Delete all imported relationship data for this browser session.</div></div><button id="clearButton" class="btn danger" type="button">Delete my imported data</button></section>
<footer class="bottom">Insight Studio v2 · Independent data viewer, not affiliated with Instagram or Meta. <span id="updated"></span><br>Never enter your Instagram password into third-party tools. <a href="https://www.instagram.com/" target="_blank" rel="noopener noreferrer">Open Instagram ↗</a></footer>
</main><div class="toast" id="toast" role="status" aria-live="polite"></div>
<script>
const csrf = document.querySelector('meta[name="csrf-token"]').content;
let activeKind = "notback";
let ready = false;
const $ = (id) => document.getElementById(id);
function toast(message){const el=$("toast");el.textContent=message;el.classList.add("show");window.setTimeout(()=>el.classList.remove("show"),3200);}
async function requestJson(url, options){
  const opts=options||{};
  opts.headers=Object.assign({},opts.headers||{},{"X-CSRF-Token":csrf});
  const response=await fetch(url,opts);
  let payload={};try{payload=await response.json();}catch(_e){}
  if(!response.ok||payload.ok===false)throw new Error(payload.error||("Request failed ("+response.status+")"));
  return payload;
}
function count(id,value){$(id).textContent=Number(value||0).toLocaleString();}
function makeRow(username){
  const row=document.createElement("div");row.className="userrow";
  const left=document.createElement("div");left.className="user-left";
  const avatar=document.createElement("span");avatar.className="avatar";avatar.textContent=username.slice(0,2).toUpperCase();
  const name=document.createElement("span");name.className="user-name";name.textContent="@"+username;
  left.append(avatar,name);
  const link=document.createElement("a");link.className="open-link";link.href="https://www.instagram.com/"+encodeURIComponent(username)+"/";link.target="_blank";link.rel="noopener noreferrer";link.textContent="Open profile ↗";
  row.append(left,link);return row;
}
async function loadList(){
  const list=$("list");list.replaceChildren();
  if(!ready){list.innerHTML='<div class="empty">Import your Instagram JSON export to see your lists.</div>';return;}
  const query=encodeURIComponent($("search").value.trim());
  try{
    const result=await requestJson("/api/list?kind="+activeKind+"&q="+query);
    if(!result.rows.length){list.innerHTML='<div class="empty">No accounts found in this list.</div>';return;}
    result.rows.forEach(item=>list.append(makeRow(item.username)));
    const hint=document.createElement("div");hint.className="user-meta";hint.style.padding="12px 2px";hint.textContent=result.total.toLocaleString()+" accounts";list.append(hint);
  }catch(error){list.textContent=error.message;}
}
async function loadActivity(){
  const container=$("activity");container.replaceChildren();
  try{
    const result=await requestJson("/api/activity");
    if(!result.rows.length){container.innerHTML='<div class="empty">Import another export later to see changes.</div>';return;}
    result.rows.slice(0,14).forEach(item=>{
      const row=document.createElement("div");row.className="event";
      const left=document.createElement("span");left.textContent=eventLabel(item.kind)+" · @"+item.username;
      const right=document.createElement("span");right.textContent=new Date(item.created_at).toLocaleDateString();
      row.append(left,right);container.append(row);
    });
  }catch(error){container.textContent=error.message;}
}
function eventLabel(kind){
  const labels={added_to_followers:"Added to followers",removed_from_followers:"No longer in followers",added_to_following:"Added to following",removed_from_following:"Removed from following"};
  return labels[kind]||kind;
}
async function loadState(){
  try{
    const state=await requestJson("/api/state");
    ready=state.ready;
    count("followers",state.followers);count("following",state.following);
    count("notback",state.not_following_back);count("mutual",state.mutual);
    $("importStatus").textContent=ready?(state.profile_username?"@"+state.profile_username+" · ":"")+"Imported "+new Date(state.imported_at).toLocaleString():"No data imported";
    $("updated").textContent=ready?"Last import: "+new Date(state.imported_at).toLocaleString():"";
    await loadList();await loadActivity();
  }catch(error){toast(error.message);}
}
$("uploadForm").addEventListener("submit",async(event)=>{
  event.preventDefault();
  if(!$("file").files.length){toast("Choose the Instagram ZIP export first.");return;}
  const button=$("uploadButton");button.disabled=true;button.textContent="Importing…";
  try{
    const body=new FormData($("uploadForm"));
    const result=await requestJson("/api/import",{method:"POST",body});
    toast(result.message+" "+result.result.followers+" followers and "+result.result.following+" following.");
    $("file").value="";await loadState();
  }catch(error){toast(error.message);}
  finally{button.disabled=false;button.textContent="Import & compare";}
});
$("tabs").addEventListener("click",async(event)=>{
  const button=event.target.closest("[data-kind]");if(!button)return;
  activeKind=button.dataset.kind;
  document.querySelectorAll(".tab").forEach(item=>item.classList.toggle("active",item===button));
  $("exportLink").href="/api/export?kind="+activeKind+"&format=csv";
  await loadList();
});
$("search").addEventListener("input",()=>loadList());
$("clearButton").addEventListener("click",async()=>{
  if(!window.confirm("Delete all imported data and comparison history for this browser?"))return;
  try{await requestJson("/api/clear",{method:"POST"});toast("Your imported data was deleted.");await loadState();}
  catch(error){toast(error.message);}
});
loadState();
</script>
</body></html>"""


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
