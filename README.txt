INSIGHT MULTI-PAGE FLASK DEMO

Project:
- app.py: Flask app, demo login, page routes and session-only demo actions.
- templates/: independent Jinja2 HTML pages plus shared base and SVG icon macro.
- requirements.txt: Flask and Gunicorn.

Local run (PowerShell):
  $env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
  pip install -r requirements.txt
  python app.py

Render Web Service:
  Runtime: Python
  Build Command: pip install -r requirements.txt
  Start Command: gunicorn --bind 0.0.0.0:$PORT app:app
  Publish Directory: leave blank (not applicable to Web Services)

Required Render environment variable:
  FLASK_SECRET_KEY = a long, random, private secret
Optional environment variable:
  DEMO_USERNAME = demo

Demo login username: demo (or DEMO_USERNAME).
No Instagram password is requested or stored. All follower, activity and visitor
records are sample data. Follow/unfollow/remove actions only mutate the current
demo session and never perform Instagram actions. Instagram does not provide
profile visitor identities; the visitor page is explicitly marked as demo data.

Session data is stored in a signed browser session cookie, not a durable database.
This is a demo interface, not a production Instagram analytics integration.
