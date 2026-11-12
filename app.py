import copy
import hmac
import os
import re
import secrets
from functools import wraps
from urllib.parse import urlsplit

from flask import (
    Flask, abort, flash, redirect, render_template, render_template_string,
    request, session, url_for,
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required.")

DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "demo").strip() or "demo"

LOGIN_PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Insight — Demo access</title>
<style>
*{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
body{margin:0;min-height:100vh;display:flex;justify-content:center;background:#fff;color:#262626}
.app{width:100%;max-width:420px;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:28px 0 env(safe-area-inset-bottom)}
.content{width:100%;padding:0 24px;text-align:center;flex:1}
.language{font-size:14px;margin:12px 0 36px}
.logo img{width:72px;height:72px;object-fit:contain;margin-bottom:22px}
.note{font-size:12px;line-height:1.5;color:#737373;margin:0 auto 20px;max-width:310px}
input{width:100%;padding:14px 12px;font-size:14px;border:1px solid #dbdbdb;border-radius:10px;background:#fafafa}
.login-btn{width:100%;margin-top:12px;padding:12px;background:#0095f6;color:#fff;border:0;border-radius:24px;font-size:15px;font-weight:600;cursor:pointer}
.error{font-size:13px;color:#ed4956;margin-top:12px}
.foot{width:100%;text-align:center;color:#8e8e8e;font-size:12px;padding:0 18px 12px}
.meta{font-size:14px;margin-bottom:6px}
</style>
</head>
<body>
<div class="app">
<main class="content">
<div class="language">English (US)</div>
<div class="logo"><img src="https://upload.wikimedia.org/wikipedia/commons/2/21/Instagram_Glyph_Gradient_RGB_logo.svg" alt="Gradient camera icon"></div>
<p class="note">Private Insight demo. Use the demo username only. This application does not request or store your Instagram password and is not affiliated with Meta.</p>
<form method="post" action="{{ url_for('login') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<input name="username" type="text" placeholder="Demo username (default: demo)" autocomplete="username" maxlength="80" required>
<button type="submit" class="login-btn">Continue</button>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
</form>
</main>
<footer class="foot"><div class="meta">∞ Meta</div>Independent demo interface · Not affiliated with or endorsed by Meta</footer>
</div>
</body>
</html>"""

PROFILE_DEFAULT = {
    "handle": "your.handle", "name": "Your Name", "initials": "YO",
    "bio": "Creator · Demo profile", "website": "", "posts": "248",
    "followers": "12.4K", "following": "842",
}
SETTINGS_DEFAULT = {
    "theme": "system", "notify_likes": True, "notify_comments": True,
    "notify_unfollows": True, "notify_visits": False,
    "privacy_hide_activity": False, "sync_frequency": 15,
}
NOT_BACK = [
    {"username":"aria.moreau","name":"Aria Moreau","initials":"AM","verified":True,"meta":"Followed since Mar 2024","days_inactive":None,"visits":None,"follows_you":False,"is_following":True},
    {"username":"kai.nkmr","name":"Kai Nakamura","initials":"KN","verified":False,"meta":"Followed 8 months ago","days_inactive":None,"visits":None,"follows_you":False,"is_following":True},
    {"username":"sofia.laurent","name":"Sofia Laurent","initials":"SL","verified":True,"meta":"Followed 3 weeks ago","days_inactive":None,"visits":None,"follows_you":False,"is_following":True},
    {"username":"mateo.s","name":"Mateo Silva","initials":"MS","verified":False,"meta":"Followed 1 year ago","days_inactive":None,"visits":None,"follows_you":False,"is_following":True},
    {"username":"zarakhan","name":"Zara Khan","initials":"ZK","verified":False,"meta":"Followed 5 months ago","days_inactive":None,"visits":None,"follows_you":False,"is_following":True},
    {"username":"leobrandt","name":"Leo Brandt","initials":"LB","verified":False,"meta":"Followed 2 days ago","days_inactive":None,"visits":None,"follows_you":False,"is_following":True},
]
FANS = [
    {"username":"noor.ahmed","name":"Noor Ahmed","initials":"NA","verified":False,"meta":"Follows you · 4 mutual","days_inactive":None,"visits":None,"follows_you":True,"is_following":False},
    {"username":"ivychen.studio","name":"Ivy Chen","initials":"IC","verified":False,"meta":"Follows you · 1 mutual","days_inactive":None,"visits":None,"follows_you":True,"is_following":False},
    {"username":"omar.h","name":"Omar Haddad","initials":"OH","verified":False,"meta":"Follows you","days_inactive":None,"visits":None,"follows_you":True,"is_following":False},
]
GHOSTS = [
    {"username":"nina.p","name":"Nina Patel","initials":"NP","verified":False,"meta":"No likes or comments in 142 days","reason":"No likes or comments","days_inactive":142,"visits":0,"follows_you":True,"is_following":False},
    {"username":"jules.mrn","name":"Jules Moreno","initials":"JM","verified":False,"meta":"Never interacted · 11 months","reason":"No recorded interactions","days_inactive":330,"visits":0,"follows_you":True,"is_following":False},
    {"username":"tariq.az","name":"Tariq Aziz","initials":"TA","verified":False,"meta":"No story views in 96 days","reason":"No story views","days_inactive":96,"visits":0,"follows_you":True,"is_following":False},
    {"username":"elena.rossi","name":"Elena Rossi","initials":"ER","verified":False,"meta":"No interaction in 74 days","reason":"No recorded interactions","days_inactive":74,"visits":0,"follows_you":True,"is_following":False},
    {"username":"finnwalker","name":"Finn Walker","initials":"FW","verified":False,"meta":"Never interacted · 5 months","reason":"No recorded interactions","days_inactive":150,"visits":0,"follows_you":True,"is_following":False},
]
VISITORS = [
    {"username":"maya.ellis","name":"Maya Ellis","initials":"ME","verified":False,"meta":"Sample visitor activity","last_visit":"Today · 9:41 PM","visits":14,"days_inactive":None,"follows_you":False,"is_following":False},
    {"username":"dev.sharma","name":"Dev Sharma","initials":"DS","verified":False,"meta":"Sample visitor activity","last_visit":"Yesterday","visits":9,"days_inactive":None,"follows_you":False,"is_following":False},
    {"username":"lina.park","name":"Lina Park","initials":"LP","verified":False,"meta":"Sample visitor activity","last_visit":"2 days ago","visits":7,"days_inactive":None,"follows_you":True,"is_following":False},
    {"username":"rafi.hasan","name":"Rafi Hasan","initials":"RH","verified":False,"meta":"Sample visitor activity","last_visit":"3 days ago","visits":5,"days_inactive":None,"follows_you":False,"is_following":False},
    {"username":"chloe.db","name":"Chloe Dubois","initials":"CD","verified":False,"meta":"Sample visitor activity","last_visit":"5 days ago","visits":3,"days_inactive":None,"follows_you":False,"is_following":False},
]
EVENTS = [
    {"group":"Today","category":"likes","actor":"maya.ellis","text":"removed her like","when":"12m ago","icon":"broken","tag":"Like removed","tag_class":"red"},
    {"group":"Today","category":"comments","actor":"dev.sharma","text":"deleted a comment","when":"1h ago","icon":"trash","tag":"Comment removed","tag_class":"red"},
    {"group":"Today","category":"unfollows","actor":"zane.cole","text":"unfollowed you","when":"3h ago","icon":"out","tag":"Unfollow","tag_class":"red"},
    {"group":"Yesterday","category":"comments","actor":"lina.park","text":"commented on your post","when":"1d ago","icon":"chat","tag":"Comment","tag_class":""},
    {"group":"Yesterday","category":"likes","actor":"rafi.hasan","text":"liked 6 of your posts","when":"1d ago","icon":"act","tag":"Binge like","tag_class":"hot"},
    {"group":"Yesterday","category":"comments","actor":"chloe.db","text":"removed a comment","when":"1d ago","icon":"trash","tag":"Comment removed","tag_class":"red"},
    {"group":"This week","category":"follows","actor":"noor.ahmed","text":"started following you","when":"2d ago","icon":"plus","tag":"New follower","tag_class":""},
]

def state_dict(key, defaults):
    value = session.get(key)
    merged = copy.deepcopy(defaults)
    if isinstance(value, dict):
        merged.update(value)
    return merged

def get_profile():
    return state_dict("profile", PROFILE_DEFAULT)

def get_settings():
    return state_dict("settings", SETTINGS_DEFAULT)

def get_not_back():
    removed = set(session.get("unfollowed_users", [])) | set(session.get("followed_users", []))
    return [copy.deepcopy(x) for x in NOT_BACK if x["username"] not in removed]

def get_fans():
    followed = set(session.get("followed_users", []))
    return [copy.deepcopy(x) for x in FANS if x["username"] not in followed]

def get_ghosts():
    removed = set(session.get("removed_ghosts", []))
    return [copy.deepcopy(x) for x in GHOSTS if x["username"] not in removed]

def get_visitors():
    followed = set(session.get("followed_users", []))
    data = copy.deepcopy(VISITORS)
    for account in data:
        account["is_following"] = account["username"] in followed
    return data

def all_accounts():
    rows = []
    for source, items in (
        ("notback", get_not_back()), ("fans", get_fans()),
        ("ghosts", get_ghosts()), ("visitors", get_visitors()),
    ):
        for item in items:
            item.update(source=source, is_demo=True, color_index=len(rows) % 6)
            rows.append(item)
    return rows

def find_account(username, source=None):
    for item in all_accounts():
        if item["username"].casefold() == username.casefold() and (source is None or source == item["source"]):
            return item
    if source == "activity" or source is None:
        for event in EVENTS:
            if event["actor"].casefold() == username.casefold():
                return {
                    "username": username,
                    "name": username.replace(".", " ").title(),
                    "initials": "".join(p[:1].upper() for p in username.split(".")),
                    "meta": "Illustrative activity entry", "verified": False,
                    "days_inactive": None, "visits": None, "follows_you": False,
                    "is_following": False, "source": "activity", "is_demo": True,
                    "color_index": 0,
                }
    return None

def safe_local_path(value):
    if not value:
        return url_for("overview")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/") or value.startswith("//"):
        return url_for("overview")
    return value

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("demo_authenticated"):
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped

@app.before_request
def csrf_protection():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "POST" and request.endpoint != "static":
        expected = session.get("_csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            abort(400, description="The form expired or its security token is invalid. Reload and try again.")

@app.context_processor
def shared_context():
    current_settings = get_settings()
    return {
        "profile": get_profile(),
        "settings": current_settings,
        "counts": {
            "not_following_back": len(get_not_back()),
            "ghost_followers": len(get_ghosts()),
        },
        "csrf_token": session.get("_csrf_token", ""),
    }

@app.get("/")
def index():
    if session.get("demo_authenticated"):
        return redirect(url_for("overview"))
    return render_template_string(LOGIN_PAGE_HTML, error=None, csrf_token=session.get("_csrf_token", ""))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect(url_for("index"))
    username = request.form.get("username", "").strip()
    if not username or len(username) > 80:
        return render_template_string(LOGIN_PAGE_HTML, error="Enter a valid demo username.", csrf_token=session.get("_csrf_token", "")), 400
    if not hmac.compare_digest(username.casefold(), DEMO_USERNAME.casefold()):
        return render_template_string(LOGIN_PAGE_HTML, error=f"Demo access is limited to username: {DEMO_USERNAME}", csrf_token=session.get("_csrf_token", "")), 401
    session.clear()
    session["_csrf_token"] = secrets.token_urlsafe(32)
    session["demo_authenticated"] = True
    session["username"] = username
    session.permanent = True
    return redirect(url_for("overview"))

@app.get("/health")
def health():
    return {"status": "ok", "app": "Insight multi-page demo", "instagram_connected": False}, 200

@app.get("/overview")
@login_required
def overview():
    visitors = get_visitors()
    stats = {
        "not_following_back": len(get_not_back()),
        "ghost_followers": len(get_ghosts()),
        "regular_visitors": sum(1 for x in visitors if x["visits"] >= 5),
        "visitors_change": "Sample activity · demo only",
        "removed_likes": 7, "deleted_comments": 4, "unfollows": 3,
        "active_pct": 62, "passive_pct": 24, "ghost_pct": 14,
    }
    visits_7d = [
        {"label": d, "value": n, "percent": p}
        for d, n, p in zip(
            ("M", "T", "W", "T", "F", "S", "S"),
            (12, 18, 15, 23, 17, 28, 21),
            (40, 62, 48, 80, 55, 92, 70),
        )
    ]
    recent_activity = [
        {"icon": e["icon"], "text": f'{e["actor"]} {e["text"]}', "when": e["when"]}
        for e in EVENTS[:4]
    ]
    return render_template(
        "overview.html", visitors=visitors, stats=stats,
        visits_7d=visits_7d, recent_activity=recent_activity,
    )

@app.get("/not-following-back")
@login_required
def not_following_back():
    q = request.args.get("q", "").strip()[:80]
    f = request.args.get("f", "all")
    if f not in {"all", "verified"}:
        f = "all"
    accounts, fans = get_not_back(), get_fans()
    if q:
        accounts = [x for x in accounts if q.casefold() in (x["username"] + " " + x["name"]).casefold()]
        fans = [x for x in fans if q.casefold() in (x["username"] + " " + x["name"]).casefold()]
    if f == "verified":
        accounts = [x for x in accounts if x["verified"]]
    return render_template("not_following_back.html", q=q, f=f, accounts=accounts, fans=fans)

@app.get("/ghost-followers")
@login_required
def ghost_followers():
    q = request.args.get("q", "").strip()[:80]
    f = request.args.get("f", "all")
    if f not in {"all", "old"}:
        f = "all"
    accounts = get_ghosts()
    if q:
        accounts = [x for x in accounts if q.casefold() in (x["username"] + " " + x["name"] + " " + x["reason"]).casefold()]
    if f == "old":
        accounts = [x for x in accounts if x["days_inactive"] >= 120]
    return render_template("ghost_followers.html", q=q, f=f, accounts=accounts)

@app.get("/profile-visitors")
@login_required
def profile_visitors():
    q = request.args.get("q", "").strip()[:80]
    f = request.args.get("f", "all")
    sort = request.args.get("sort", "visits")
    if f not in {"all", "top"}:
        f = "all"
    if sort not in {"visits", "recent", "name"}:
        sort = "visits"
    visitors = get_visitors()
    if q:
        visitors = [x for x in visitors if q.casefold() in (x["username"] + " " + x["name"]).casefold()]
    if f == "top":
        visitors = [x for x in visitors if x["visits"] >= 7]
    if sort == "visits":
        visitors.sort(key=lambda x: x["visits"], reverse=True)
    elif sort == "recent":
        visitors.sort(key=lambda x: VISITORS.index(next(v for v in VISITORS if v["username"] == x["username"])))
    else:
        visitors.sort(key=lambda x: x["name"].casefold())
    return render_template("profile_visitors.html", q=q, f=f, sort=sort, visitors=visitors)

@app.get("/activity")
@login_required
def activity():
    category = request.args.get("category", "all")
    period = request.args.get("range", "all")
    if category not in {"all", "likes", "comments", "unfollows", "follows"}:
        category = "all"
    if period not in {"today", "yesterday", "week", "all"}:
        period = "all"
    events = copy.deepcopy(EVENTS)
    if category != "all":
        events = [x for x in events if x["category"] == category]
    if period == "today":
        events = [x for x in events if x["group"] == "Today"]
    elif period == "yesterday":
        events = [x for x in events if x["group"] == "Yesterday"]
    return render_template("activity.html", category=category, range=period, events=events)

@app.get("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.post("/settings/update")
@login_required
def update_settings():
    theme = request.form.get("theme", "system")
    if theme not in {"system", "light", "dark"}:
        flash("Invalid theme selection.", "error")
        return redirect(url_for("settings"))
    try:
        frequency = int(request.form.get("sync_frequency", "15"))
    except (TypeError, ValueError):
        frequency = 15
    if frequency not in {15, 30, 60}:
        frequency = 15
    session["settings"] = {
        "theme": theme,
        "notify_likes": "notify_likes" in request.form,
        "notify_comments": "notify_comments" in request.form,
        "notify_unfollows": "notify_unfollows" in request.form,
        "notify_visits": "notify_visits" in request.form,
        "privacy_hide_activity": "privacy_hide_activity" in request.form,
        "sync_frequency": frequency,
    }
    flash("Settings saved for this demo session.", "success")
    return redirect(url_for("settings"))

@app.get("/profile")
@login_required
def profile():
    p = get_profile()
    form = {
        "name": p["name"], "username": p["handle"],
        "bio": p["bio"], "website": p.get("website", ""),
    }
    return render_template("profile.html", form=form, errors={})

@app.post("/profile/update")
@login_required
def update_profile():
    current = get_profile()
    form = {
        "name": request.form.get("name", "").strip()[:40],
        "username": current["handle"],
        "bio": request.form.get("bio", "").strip()[:150],
        "website": request.form.get("website", "").strip()[:120],
    }
    errors = {}
    if not form["name"]:
        errors["name"] = "Name is required."
    if form["website"] and not re.match(r"^https?://[^\s]+$", form["website"], re.I):
        errors["website"] = "Enter a valid http:// or https:// URL."
    if errors:
        return render_template("profile.html", form=form, errors=errors), 400
    current.update({"name": form["name"], "bio": form["bio"], "website": form["website"]})
    initials = "".join(part[:1].upper() for part in form["name"].split()[:2]) or "YO"
    current["initials"] = initials
    session["profile"] = current
    flash("Profile updated in this demo session.", "success")
    return redirect(url_for("profile"))

@app.get("/account/<username>")
@login_required
def account_details(username):
    source = request.args.get("source")
    allowed = {None, "notback", "ghosts", "visitors", "fans", "activity"}
    account = find_account(username, source if source in allowed else None)
    if not account:
        abort(404)
    return render_template("account_details.html", account=account)

@app.get("/confirm-action")
@login_required
def confirm_action():
    action = request.args.get("action", "")
    username = request.args.get("username", "").strip()
    source = request.args.get("source")
    if action not in {"unfollow", "remove", "follow_back"} or not username:
        return render_template("confirm_action.html"), 400
    account = find_account(username, source) if source else find_account(username)
    if not account:
        abort(404)
    if action == "unfollow" and not account.get("is_following"):
        flash("This demo account is not currently followed.", "error")
        return redirect(safe_local_path(request.args.get("back")))
    if action == "remove" and account.get("source") != "ghosts":
        abort(400)
    return render_template("confirm_action.html")

@app.post("/action/perform")
@login_required
def perform_action():
    action = request.form.get("action", "")
    username = request.form.get("username", "").strip()
    next_url = safe_local_path(request.form.get("next"))
    if action not in {"unfollow", "remove", "follow_back"} or not username:
        abort(400)
    account = find_account(username)
    if not account:
        abort(404)
    if action == "unfollow":
        if account.get("source") != "notback" or not account.get("is_following"):
            abort(400)
        values = set(session.get("unfollowed_users", []))
        values.add(username)
        session["unfollowed_users"] = sorted(values)
        flash(f"@{username} removed from the demo following list.", "success")
    elif action == "follow_back":
        if account.get("source") not in {"fans", "visitors"}:
            abort(400)
        values = set(session.get("followed_users", []))
        values.add(username)
        session["followed_users"] = sorted(values)
        flash(f"@{username} added to the demo following list.", "success")
    else:
        if account.get("source") != "ghosts":
            abort(400)
        values = set(session.get("removed_ghosts", []))
        values.add(username)
        session["removed_ghosts"] = sorted(values)
        flash(f"@{username} removed from the demo ghost-follower list.", "success")
    return redirect(next_url)

@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have logged out of the demo.", "success")
    return redirect(url_for("index"))

@app.errorhandler(400)
def bad_request(error):
    return render_template(
        "error.html", code=400, heading="Request could not be processed",
        message=getattr(error, "description", "Please reload the page and try again."),
    ), 400

@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html", code=404, heading="This page isn’t available",
        message="The requested demo page or account could not be found.",
    ), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
