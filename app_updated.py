import os
from flask import Flask, Response, jsonify

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#101326">
  <title>Security Awareness Demo</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      padding: 28px; color: #f3f5ff;
      font: 16px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      background: radial-gradient(ellipse at 15% 10%, #27346a 0, transparent 42%),
                  radial-gradient(ellipse at 90% 85%, #39245a 0, transparent 38%), #101326;
    }
    main { width: min(720px, 100%); }
    .eyebrow { color: #aab7ff; font-size: 12px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
    h1 { margin: 14px 0; font-size: clamp(34px, 7vw, 58px); line-height: 1.05; letter-spacing: -.04em; }
    .lead { max-width: 610px; color: #c7cce2; font-size: 18px; }
    .panel {
      margin-top: 30px; padding: 24px; border: 1px solid #353d63;
      border-radius: 20px; background: rgba(22, 28, 57, .82);
      box-shadow: 0 24px 70px rgba(0,0,0,.25);
    }
    .status { display: inline-flex; align-items: center; gap: 9px; color: #baf5d0; font-weight: 700; }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: #55db91; box-shadow: 0 0 14px #55db91; }
    h2 { margin: 18px 0 8px; font-size: 20px; }
    ul { margin: 10px 0 0; padding-left: 22px; color: #c7cce2; }
    li { padding: 5px 0; }
    .notice { margin-top: 18px; padding: 14px 16px; border-left: 3px solid #8ea0ff; background: #20294c; color: #e1e6ff; border-radius: 8px; }
    footer { margin-top: 22px; color: #8f98bc; font-size: 13px; }
  </style>
</head>
<body>
  <main>
    <div class="eyebrow">Learning environment</div>
    <h1>Security starts<br>with awareness.</h1>
    <p class="lead">This is a safe demonstration page for security-awareness training. It does not imitate a third-party sign-in page or ask visitors to enter account details.</p>
    <section class="panel" aria-label="Demo status and guidance">
      <div class="status"><span class="dot" aria-hidden="true"></span> Demo is online</div>
      <h2>Protect your accounts</h2>
      <ul>
        <li>Never enter your password on an unfamiliar page or link.</li>
        <li>Check the website address before signing in.</li>
        <li>Use a unique password and turn on multi-factor authentication.</li>
        <li>Do not share one-time verification codes with anyone.</li>
      </ul>
      <div class="notice"><strong>Privacy note:</strong> This demo has no login form and does not collect or store usernames, passwords, or verification codes.</div>
    </section>
    <footer>Security Awareness Demo · Safe informational page</footer>
  </main>
</body>
</html>
"""

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def home():
    return Response(PAGE, mimetype="text/html; charset=utf-8")

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "service": "security-awareness-demo"})

@app.get("/favicon.ico")
def favicon():
    return ("", 204)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
