# Insight Studio — Instagram Login & Analytics

Insight Studio now uses Instagram's official OAuth login. It does **not** ask for, receive, or store an Instagram password, two-factor code, login cookie, or browser session. A user is redirected to Instagram to sign in and approve access. The server receives an authorization code and exchanges it for an access token. The token is encrypted at rest and is never sent to browser JavaScript.

## Current application flow

1. User selects **Continue with Instagram**.
2. Instagram hosts the sign-in and consent screen.
3. Instagram redirects to `/oauth/callback`; the app validates OAuth state.
4. The server exchanges the code for a short-lived token, then a long-lived token.
5. The app fetches the authorized professional account profile and recent media, and calculates local summaries from the fields Instagram returns.
6. Users can sync data again or disconnect and delete the locally stored token/cache.

The API integration uses Instagram Login for **Business and Creator (professional) accounts**. Personal consumer accounts are not supported by this official API flow. For an app serving accounts outside its own roles, Meta Advanced Access/App Review may be required.

## Important platform boundaries

- Instagram passwords and 2FA codes are entered only on Instagram's website.
- OAuth tokens are sensitive authorization credentials. They are encrypted in SQLite with Fernet and are not exposed to the frontend.
- The official API can return profile fields, owned media, and approved insights, depending on granted permissions and account eligibility.
- The official API does not provide a complete per-user followers/following relationship list for this use case. Therefore this version does not claim to identify every non-follower-back account.
- The official Instagram API does not provide a supported unfollow action. The UI links to Instagram for manual follow management; no private endpoint, cookie automation, or password workaround is used.
- Profile visitor identities are not available and are not fabricated.
- The former JSON ZIP import flow and its endpoints have been removed from the active app. On startup, the database migration drops its old import tables.

## Meta app setup

Create/configure a Meta app and add **Instagram API with Instagram Login / Business Login for Instagram**. The Instagram product's App ID and App Secret are required; do not confuse these with Meta App Settings → Basic credentials if Meta provides a separate Instagram credential pair.

Set these environment variables on Render (or your host):

| Variable | Required | Meaning |
|---|---:|---|
| `INSTAGRAM_APP_ID` | Yes | Instagram Login product App ID |
| `INSTAGRAM_APP_SECRET` | Yes | Instagram Login product App Secret |
| `INSTAGRAM_REDIRECT_URI` | Yes in production | Exact callback URL registered in Meta, e.g. `https://instagrams.cc.cd/oauth/callback` |
| `SECRET_KEY` | Yes | Stable, long random Flask session secret |
| `TOKEN_ENCRYPTION_KEY` | Recommended | Fernet key used to encrypt OAuth access tokens at rest |
| `INSTAGRAM_GRAPH_VERSION` | No | Defaults to `v27.0`; pin to a supported version in your Meta app |
| `INSTAGRAM_SCOPES` | No | Defaults to `instagram_business_basic,instagram_business_manage_insights` |
| `DATA_DIR` | No | Persistent directory for SQLite and the fallback secret key |

Generate a Fernet key locally with:

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

Register the exact callback URI in the Instagram Login settings of the Meta developer dashboard. For local development, use an HTTPS tunnel or localhost callback registered with Meta. Never commit the App Secret, Flask secret, encryption key, or user access tokens to Git.

## Render deployment

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --workers 1 --threads 8 --timeout 60 --bind 0.0.0.0:$PORT app:app`
- Add all required environment variables above.
- Attach a persistent disk and set `DATA_DIR=/var/data` if the SQLite cache should survive redeploys/restarts.
- Ensure your registered callback URI points to the production domain and uses HTTPS.

## Local run

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-secret"
$env:INSTAGRAM_APP_ID = "your-instagram-app-id"
$env:INSTAGRAM_APP_SECRET = "your-instagram-app-secret"
$env:INSTAGRAM_REDIRECT_URI = "https://your-domain.example/oauth/callback"
python app.py
```

Health check: `/healthz`. The endpoint reports whether Instagram Login credentials are configured without exposing them.
