# Insight Studio — Instagram Unified Login & Analytics

Insight Studio uses Meta's supported **Instagram API with Unified Login**. Users sign in and approve access on Meta's official Facebook/Instagram dialog. The app never asks for or stores an Instagram password, two-factor code, login cookie, or browser session.

## Current connection flow

1. User selects **Continue with Instagram**.
2. The Meta Login for Business dialog opens with this app's `config_id` and redirect URL.
3. The user signs in, chooses a Business Portfolio, selects their Instagram professional account, and approves the configured permissions.
4. Meta redirects to `/oauth/callback` with an authorization code.
5. The server exchanges the code using the Meta App ID and App Secret, then retrieves the business ID and the Instagram professional account ID shared with the app.
6. The server encrypts the access token in SQLite. Profile and recent media are fetched from the Instagram account ID. The UI displays available counts and local summaries calculated from returned media.
7. Users can sync again or disconnect and delete the locally stored token/cache.

## Current Meta setup (Unified Login)

New apps use Unified Login. The Meta app must:
- Have the **Manage messaging & content on Instagram** use case.
- Be owned by a **Business Portfolio**.
- Use **Facebook Login for Business**.
- Configure a Unified Login configuration that includes the Instagram professional account asset and the permissions required by this app (at least `instagram_basic`; add `instagram_manage_insights` only if insights are needed and available).
- Register the exact HTTPS redirect URL `https://instagrams.cc.cd/oauth/callback` in the configuration.

In the Meta Dashboard, open **Use cases → Manage messaging & content on Instagram → Customize → API setup with Unified login → Configure your app → Create new configuration**. Select permissions, **Use this configuration**, set the Redirect URL, Save, and copy the configuration ID (`config_id`). The `config_id` is not a secret; it identifies the selected login configuration.

## Platform boundaries

- Passwords and 2FA codes are only entered on Meta's official sign-in page.
- The OAuth access token is a sensitive credential. It is encrypted at rest and never sent to browser JavaScript.
- The official API can return profile fields and owned media, plus approved insights depending on permissions and eligibility.
- This use case does not provide a complete per-user followers/following list for identifying every non-follower-back account.
- The official API does not provide a supported unfollow action. The app links to Instagram for manual follow management; it does not automate private endpoints or cookies.
- Profile visitor identities are not available and are not fabricated.
- The former JSON ZIP import flow and its endpoints have been removed. Startup migrations remove obsolete export-import tables.

## Render environment variables

Set these on the Render web service:

| Variable | Required | Meaning |
|---|---:|---|
| `META_APP_ID` | Yes | App ID from Meta App Dashboard → App settings → Basic |
| `META_APP_SECRET` | Yes | App Secret from Meta App Dashboard → App settings → Basic |
| `META_LOGIN_CONFIG_ID` | Yes | `config_id` copied from the Unified Login configuration |
| `META_REDIRECT_URI` | Yes | Exact HTTPS callback URL saved in the Unified Login configuration |
| `SECRET_KEY` | Yes | Stable, long random Flask session secret |
| `TOKEN_ENCRYPTION_KEY` | Recommended | Fernet key used to encrypt OAuth access tokens at rest |
| `INSTAGRAM_GRAPH_VERSION` | No | Defaults to `v27.0` |

Generate a Fernet encryption key locally with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Generate a session key locally with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Never commit Meta App Secret, Flask secret, encryption key, or user access tokens to Git. Keep all values in Render Environment settings.

## Render deployment

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --workers 1 --threads 8 --timeout 60 --bind 0.0.0.0:$PORT app:app`
- Add all environment variables above.
- Attach a persistent disk and set `DATA_DIR=/var/data` if the SQLite cache should survive redeploys/restarts.
- The registered callback URL and redirect URL in the Meta configuration must match exactly.

## Health check

`/healthz` reports whether Meta Unified Login credentials are configured without exposing their values.
