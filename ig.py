"""Instagram private-API engine for Insight Capture.

One worker thread per browser session. The session blob is persisted so the
device fingerprint survives restarts, which is what keeps challenges rare.
"""
from __future__ import annotations

import os
import threading
import time
import traceback
from pathlib import Path

from instagrapi import Client
from instagrapi import exceptions as igexc
from instagrapi.exceptions import (
    AccountSuspended,
    BadCredentials,
    BadPassword,
    ChallengeRequired,
    ClientLoginRequired,
    LoginRequired,
    ProxyAddressIsBlocked,
    TwoFactorRequired,
    UserNotFound,
)

WAIT_ERRORS = tuple(
    getattr(igexc, n)
    for n in ("PleaseWaitFewMinutes", "RateLimitError", "ClientThrottledError")
    if hasattr(igexc, n)
)

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
IG_DIR = DATA_DIR / "ig"
PROXY = os.environ.get("IG_PROXY", "").strip()
MAX_PEOPLE = int(os.environ.get("IG_MAX_PEOPLE", "3000") or 3000)
ENGAGE_POSTS = int(os.environ.get("IG_ENGAGE_POSTS", "6") or 6)
CODE_TIMEOUT = int(os.environ.get("IG_CODE_TIMEOUT", "600") or 600)

_jobs: dict[str, "Job"] = {}
_jobs_lock = threading.Lock()

on_state = None   # fn(cid, fields: dict) — wired by the app
on_log = None     # fn(text: str, level: str)

BAD_PASSWORD = "Sorry, your password was incorrect. Please double-check your password."
BAD_USER = ("The username you entered doesn't belong to an account. "
            "Please check your username and try again.")
RATE = "Please wait a few minutes before you try again."
SUSPENDED = "Your account has been disabled."
PROXY_BLOCKED = "Instagram blocked this server IP. Set IG_PROXY to a residential proxy."
GENERIC = "Something went wrong. Please try again."


def _notify(cid: str, **fields) -> None:
    if on_state:
        try:
            on_state(cid, fields)
        except Exception:
            pass


def _log(text: str, level: str = "info") -> None:
    if on_log:
        try:
            on_log(text, level)
        except Exception:
            pass


def _person(u) -> dict:
    return {
        "pk": str(getattr(u, "pk", "") or ""),
        "username": (getattr(u, "username", "") or "")[:60],
        "full_name": (getattr(u, "full_name", "") or "")[:80],
        "pic": str(getattr(u, "profile_pic_url", "") or ""),
        "verified": bool(getattr(u, "is_verified", False)),
    }


class Job:
    def __init__(self, cid: str, username: str, password: str):
        self.cid = cid
        self.username = username
        self.password = password
        self.phase = "queued"
        self.error = ""
        self.notice = ""
        self.choice = ""
        self.cl: Client | None = None
        self.started = time.time()
        self._cv = threading.Condition()
        self._verdict = ""
        self._code: str | None = None
        self._lock = threading.Lock()
        self._syncing = False
        self._thread: threading.Thread | None = None
        self._data: dict = {}

    # ---------- state ----------
    def _push(self, **extra) -> None:
        payload = {"phase": self.phase, "error": self.error,
                   "notice": self.notice, "choice": self.choice}
        payload.update(extra)
        _notify(self.cid, **payload)

    def _set_verdict(self, value: str) -> None:
        with self._cv:
            if not self._verdict:
                self._verdict = value
            self._cv.notify_all()

    def wait_verdict(self, timeout: float) -> str:
        with self._cv:
            self._cv.wait_for(lambda: bool(self._verdict), timeout)
            return self._verdict

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _session_file(self) -> Path:
        IG_DIR.mkdir(parents=True, exist_ok=True)
        safe = "".join(c for c in self.username.lower() if c.isalnum() or c in "._-")[:48]
        return IG_DIR / f"{safe or 'user'}-{self.cid}.json"

    def _dump(self) -> None:
        if not self.cl:
            return
        try:
            self.cl.dump_settings(self._session_file())
            os.chmod(self._session_file(), 0o600)
        except OSError:
            pass

    # ---------- code handoff ----------
    def submit_code(self, code: str) -> None:
        with self._cv:
            self._code = (code or "").strip()
            self._cv.notify_all()

    def _wait_code(self, timeout: int = CODE_TIMEOUT) -> str:
        with self._cv:
            self._cv.wait_for(lambda: self._code is not None, timeout)
            code = self._code
            self._code = None
            return code or ""

    def _handler(self, username: str, choice) -> str:
        self.choice = getattr(choice, "name", str(choice))
        self.phase = "code"
        self._push()
        self._set_verdict("code")
        _log(f"challenge for {username} via {self.choice} — waiting for code")
        code = self._wait_code()
        self.phase = "login"
        self._push()
        return code

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self.alive:
            return
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    def run(self) -> None:
        try:
            cl = Client()
            cl.delay_range = [1, 3]
            if PROXY:
                cl.set_proxy(PROXY)
            sf = self._session_file()
            if sf.exists():
                try:
                    cl.load_settings(sf)
                except Exception:
                    pass
            cl.challenge_code_handler = self._handler
            self.cl = cl
            self.phase = "login"
            self._push()
            self._login(cl)
            self._dump()
            self.phase = "ready"
            self.error = ""
            self._push()
            self._set_verdict("ok")
            _log(f"instagram login ok: {self.username}")
            self.sync(full=True)
        except (BadPassword, BadCredentials):
            self._fail("bad_password", BAD_PASSWORD)
        except UserNotFound:
            self._fail("bad_user", BAD_USER)
        except AccountSuspended:
            self._fail("suspended", SUSPENDED)
        except ProxyAddressIsBlocked:
            self._fail("proxy", PROXY_BLOCKED)
        except TwoFactorRequired:
            self._code_retry("Enter the two-factor code Instagram sent you.")
        except ChallengeRequired as exc:
            self._code_retry(f"Verification required: {exc}"[:300])
        except Exception as exc:
            if WAIT_ERRORS and isinstance(exc, WAIT_ERRORS):
                self._fail("rate", RATE)
            elif isinstance(exc, (LoginRequired, ClientLoginRequired)):
                self._fail("session", "Instagram ended the session. Try again.")
            else:
                self._fail("error", GENERIC)
                _log(traceback.format_exc()[-1200:], "error")

    def _fail(self, verdict: str, msg: str) -> None:
        self.phase = "error"
        self.error = msg
        self._push()
        self._set_verdict(verdict)
        _log(f"instagram fail ({self.username}): {verdict} — {msg}", "error")

    def _code_retry(self, msg: str) -> None:
        """Hard error নয়: কোড ফর্ম দেখাও, কোড পেলে আবার login চেষ্টা করো."""
        self.error = msg
        self.phase = "code"
        self._push()
        self._set_verdict("code")
        _log(f"verification needed for {self.username}: {msg}", "warning")

        code = self._wait_code()
        if not code:
            self._fail("challenge", "No code entered — try again.")
            return

        self.phase = "login"
        self.error = ""
        self._push()
        try:
            if not self.cl:
                raise LoginRequired("no client")
            self._call_login(self.cl, code)
            self._dump()
            self.phase = "ready"
            self._push()
            self._set_verdict("ok")
            self.sync(full=True)
        except (BadPassword, BadCredentials):
            self._fail("bad_password", BAD_PASSWORD)
        except Exception as exc:
            self._fail("challenge", f"Code rejected: {type(exc).__name__}")

    def _call_login(self, cl: Client, code: str = ""):
        if code:
            try:
                return cl.login(self.username, self.password, verification_code=code)
            except TypeError:
                return cl.two_factor_login(code)
        return cl.login(self.username, self.password)

    def _login(self, cl: Client) -> None:
        last_exc: Exception | None = None
        for _ in range(3):
            try:
                self._call_login(cl)
                return
            except TwoFactorRequired:
                last_exc = None
                self.choice = "2FA"
                self.phase = "code"
                self._push()
                self._set_verdict("code")
                code = self._wait_code()
                self.phase = "login"
                self._push()
                if not code:
                    raise
                self._call_login(cl, code)
                return
            except ChallengeRequired as exc:
                last_exc = exc
                self._set_verdict("challenge")
                last = dict(getattr(cl, "last_json", None) or {})
                if last.get("challenge"):
                    try:
                        if cl.challenge_resolve(last):
                            self._call_login(cl)
                            return
                    except ChallengeRequired:
                        pass
                self.notice = "Approve the login in the Instagram app, then press Continue."
                self.phase = "approve"
                self._push()
                code = self._wait_code(900)
                self.phase = "login"
                self.notice = ""
                self._push()
                self._call_login(cl, code)
                return
        raise ChallengeRequired(f"challenge after retries: {last_exc}")

    # ---------- data ----------
    def _fetch(self) -> dict:
        cl = self.cl
        uid = str(cl.user_id)
        me = cl.user_info(uid)

        followers = {str(k): _person(v) for k, v in cl.user_followers(uid, amount=MAX_PEOPLE).items()}
        following = {str(k): _person(v) for k, v in cl.user_following(uid, amount=MAX_PEOPLE).items()}

        engaged: set[str] = set()
        likes: dict[str, list] = {}
        try:
            medias = cl.user_medias(uid, amount=ENGAGE_POSTS)
        except Exception:
            medias = []
        for m in medias:
            try:
                likers = [str(u.pk) for u in cl.media_likers(m.pk, amount=400)]
            except Exception:
                likers = []
            likes[str(m.pk)] = likers
            engaged.update(likers)
            try:
                for c in cl.media_comments(m.pk, amount=200):
                    engaged.add(str(c.user.pk))
            except Exception:
                pass

        viewers: dict[str, int] = {}
        try:
            for st in cl.user_stories(uid)[:5]:
                try:
                    for v in cl.story_viewers(st.pk, amount=600):
                        pk = str(v.pk)
                        viewers[pk] = viewers.get(pk, 0) + 1
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "profile": {
                "username": me.username or self.username,
                "full_name": me.full_name or "",
                "bio": me.biography or "",
                "pic": str(me.profile_pic_url or ""),
                "followers": int(me.follower_count or 0),
                "following": int(me.following_count or 0),
                "media": int(me.media_count or 0),
                "verified": bool(me.is_verified),
            },
            "followers": followers,
            "following": following,
            "engaged": sorted(engaged),
            "engaged_ok": bool(medias),
            "likes": likes,
            "viewers": viewers,
        }

    def sync(self, full: bool = False) -> dict:
        with self._lock:
            if self._syncing or not self.cl:
                return self._data
            self._syncing = True
        try:
            if self.phase == "ready":
                self.phase = "sync"
                self._push()
            data = self._fetch()
            prev = self._data or {}
            events = list(prev.get("events") or [])
            now = int(time.time())

            compare = (not full) and prev.get("followers") is not None
            if compare:
                pf, nf = set(prev["followers"]), set(data["followers"])
                for pk in list(pf - nf)[:80]:
                    events.insert(0, {"kind": "unfollow", "ts": now,
                                      "text": f"{prev['followers'][pk]['username']} unfollowed you"})
                for pk in list(nf - pf)[:80]:
                    events.insert(0, {"kind": "follow", "ts": now,
                                      "text": f"{data['followers'][pk]['username']} started following you"})
                for mid, old in (prev.get("likes") or {}).items():
                    for pk in list(set(old) - set(data["likes"].get(mid, [])))[:20]:
                        u = prev["followers"].get(pk) or prev["following"].get(pk)
                        if u:
                            events.insert(0, {"kind": "like", "ts": now,
                                              "text": f"{u['username']} removed a like"})

            data["events"] = events[:250]
            data["synced_at"] = now
            self._data = data
            self.phase = "ready"
            self.error = ""
            self.notice = "" if data.get("engaged_ok") else (
                "No recent post found — ghost list needs likes or story views.")
            self._push(payload=self.public())
            _log(f"sync ok for {self.username}: {len(data['followers'])} followers, "
                 f"{len(data['following'])} following")
            return data
        except (LoginRequired, ClientLoginRequired):
            self.notice = "Session expired — logging in again."
            self._push()
            try:
                if not self.cl:
                    raise LoginRequired("no client")
                self._login(self.cl)
                self._dump()
                self.phase = "ready"
                self.notice = ""
                self._push()
                _log(f"re-login ok for {self.username}")
            except Exception as exc:
                self._fail("session", f"Re-login failed: {type(exc).__name__}")
            return self._data
        except Exception as exc:
            self.phase = "ready"
            self.notice = f"Sync failed: {type(exc).__name__}"
            self._push()
            _log(f"sync fail for {self.username}: {exc}", "error")
            return self._data
        finally:
            self._syncing = False

    def public(self) -> dict:
        d = self._data or {}
        followers = d.get("followers") or {}
        following = d.get("following") or {}
        engaged = set(d.get("engaged") or [])
        viewers = d.get("viewers") or {}
        engaged_ok = bool(d.get("engaged_ok", True))

        notback = [following[p] for p in following if p not in followers]
        fans = [followers[p] for p in followers if p not in following]
        mutual = [p for p in followers if p in following]
        ghosts = ([followers[p] for p in followers
                   if p not in engaged and p not in following] if engaged_ok else [])

        stalkers = []
        for pk, n in sorted(viewers.items(), key=lambda kv: -kv[1])[:60]:
            u = followers.get(pk) or following.get(pk)
            if u:
                stalkers.append({**u, "views": n})

        return {
            "phase": self.phase,
            "error": self.error,
            "notice": self.notice,
            "choice": self.choice,
            "synced_at": d.get("synced_at"),
            "engaged_ok": engaged_ok,
            "profile": d.get("profile") or {"username": self.username},
            "counts": {
                "followers": len(followers),
                "following": len(following),
                "notback": len(notback),
                "ghosts": len(ghosts),
                "stalkers": len(stalkers),
                "mutual": len(mutual),
            },
            "lists": {
                "notback": notback[:400],
                "fans": fans[:200],
                "ghosts": ghosts[:300],
                "stalkers": stalkers,
                "activity": (d.get("events") or [])[:150],
            },
        }

    # ---------- actions ----------
    def unfollow(self, pk: str, username: str) -> tuple[bool, str]:
        if not self.cl or self.phase != "ready":
            return False, "Not logged in"
        try:
            ok = self.cl.user_unfollow(pk)
        except Exception as exc:
            return False, type(exc).__name__
        if ok:
            with self._lock:
                self._data.setdefault("following", {}).pop(str(pk), None)
                self._data.setdefault("events", []).insert(
                    0, {"kind": "unfollowed", "ts": int(time.time()),
                        "text": f"You unfollowed {username}"})
                snap = self.public()
            self._push(payload=snap)
        return bool(ok), "" if ok else "Already unfollowed"

    def follow(self, pk: str, username: str) -> tuple[bool, str]:
        if not self.cl or self.phase != "ready":
            return False, "Not logged in"
        try:
            ok = self.cl.user_follow(pk)
        except Exception as exc:
            return False, type(exc).__name__
        if ok:
            with self._lock:
                self._data.setdefault("following", {})[str(pk)] = {
                    "pk": str(pk), "username": username[:60], "full_name": "",
                    "pic": "", "verified": False,
                }
                self._data.setdefault("events", []).insert(
                    0, {"kind": "followed", "ts": int(time.time()),
                        "text": f"You followed {username}"})
                snap = self.public()
            self._push(payload=snap)
        return bool(ok), "" if ok else "Already following"


def get(cid: str) -> Job | None:
    with _jobs_lock:
        return _jobs.get(cid)


def start(cid: str, username: str, password: str) -> Job:
    with _jobs_lock:
        job = _jobs.get(cid)
        if job and job.alive and job.username.lower() == username.lower():
            if job.phase == "ready":
                threading.Thread(target=job.sync, daemon=True).start()
            return job
        job = Job(cid, username, password)
        _jobs[cid] = job
    job.start()
    return job
