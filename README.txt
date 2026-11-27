# Insight Studio — Instagram Data Analyzer

Insight Studio analyzes the **JSON ZIP export that you download from Instagram**. It does not ask for your Instagram password, 2FA code, login cookie, or access token.

## Real workflows

- Import your official Instagram Followers and following export (ZIP / JSON).
- See follower, following, mutual, fans, and not-following-back lists.
- Search usernames and open the corresponding Instagram profile for manual review.
- Import a later export to compare relationship-list changes.
- Export relationship lists as CSV or a full JSON report.
- Delete all imported data for the current browser session.
- Health check: `/healthz`.

Profile visitors, story viewers, private engagement history, and automated follow/unfollow are deliberately not shown. Instagram does not provide a real profile-visitor identity list, and this app does not fabricate one or automate account actions.

## Get your Instagram export

In Instagram, open **Accounts Center → Your information and permissions → Export your information**. Select your Instagram profile, choose **Followers and following**, set the date range to **All time**, and select **JSON** format. Download the ZIP when Instagram makes it available, then upload that ZIP here.

The archive needs both follower and following JSON files. The app reads only those relationship files. It processes the ZIP in memory and stores only usernames, import dates, and differences between imports; it does not retain the uploaded archive or unrelated files.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-secret"
python app.py
```

Open http://127.0.0.1:5000.

## Render deployment

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --workers 1 --threads 8 --timeout 60 --bind 0.0.0.0:$PORT app:app`
- Set `SECRET_KEY` to a long random value.
- For durable storage, attach a persistent disk and set `DATA_DIR=/var/data`. Without a persistent disk, imported data may be lost when the service is replaced or restarted.

The deployment entry point remains `app:app`. The app uses SQLite and Python's standard library; no unofficial Instagram client or proxy is required.

## Security migration

On startup, version 2 removes the legacy credential-capture database tables, locally stored Instagram session files, and legacy credential/event log files from the configured data directory. The app no longer serves the former `/admin`, `/credential`, or `/cookies` endpoints. Provider-side historical logs (for example, logs already retained by a hosting provider) must be managed separately from that provider's dashboard.
