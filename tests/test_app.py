import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import oauth_app


class OAuthAppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        oauth_app.DATA_DIR = oauth_app.Path(self.tmp.name)
        oauth_app.DB_PATH = oauth_app.DATA_DIR / "test.sqlite3"
        oauth_app.app.config.update(TESTING=True, SECRET_KEY="test-secret-that-is-long-enough-123456")
        oauth_app.app.secret_key = "test-secret-that-is-long-enough-123456"
        os.environ["SECRET_KEY"] = "test-secret-that-is-long-enough-123456"
        os.environ["INSTAGRAM_APP_ID"] = "test-instagram-app-id"
        os.environ["INSTAGRAM_APP_SECRET"] = "test-instagram-app-secret"
        os.environ["INSTAGRAM_REDIRECT_URI"] = "https://insight.example/oauth/callback"
        os.environ.pop("TOKEN_ENCRYPTION_KEY", None)
        os.environ.pop("INSTAGRAM_SCOPES", None)
        oauth_app.init_db()
        self.client = oauth_app.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_home_has_oauth_cta_and_no_json_import(self):
        response = self.client.get("/")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Continue with Instagram", body)
        self.assertIn("password", body.lower())
        self.assertNotIn("type=\"file\"", body)
        self.assertNotIn("Import Instagram data", body)

    def test_connect_redirects_to_instagram_with_state_and_scope(self):
        response = self.client.get("/connect/instagram")
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response.headers["Location"])
        self.assertEqual(parsed.netloc, "www.instagram.com")
        params = parse_qs(parsed.query)
        self.assertEqual(params["client_id"], ["test-instagram-app-id"])
        self.assertEqual(params["redirect_uri"], ["https://insight.example/oauth/callback"])
        self.assertTrue(params.get("state", [""])[0])
        self.assertIn("instagram_business_basic", params["scope"][0])

    def test_oauth_token_exchange_uses_urlencoded_form(self):
        seen = {}
        original = oauth_app.urlopen

        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self, _limit):
                return b'{"access_token":"short","user_id":123}'

        def fake_urlopen(req, timeout=20):
            seen["content_type"] = req.headers.get("Content-type")
            seen["body"] = req.data.decode("utf-8")
            return FakeResponse()

        oauth_app.urlopen = fake_urlopen
        try:
            result = oauth_app._http_json("https://api.instagram.com/oauth/access_token", method="POST", form={
                "client_id": "app-id", "client_secret": "secret", "code": "a+b/c",
            })
        finally:
            oauth_app.urlopen = original
        self.assertEqual(seen["content_type"], "application/x-www-form-urlencoded")
        self.assertIn("code=a%2Bb%2Fc", seen["body"])
        self.assertEqual(result["user_id"], 123)

    def test_connect_fails_closed_without_meta_credentials(self):
        os.environ.pop("INSTAGRAM_APP_SECRET", None)
        response = self.client.get("/connect/instagram")
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"not configured", response.data)

    def test_callback_rejects_missing_or_mismatched_state(self):
        response = self.client.get("/oauth/callback?code=sample&state=wrong")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"could not be verified", response.data)

    def test_callback_exchanges_token_and_saves_encrypted_token(self):
        with self.client.session_transaction() as sess:
            sess["cid"] = "browser-session-1"
            sess["oauth_state"] = "valid-state"
            sess["oauth_started_at"] = int(oauth_app.time.time())
        oauth_app.exchange_authorization_code = lambda code: {
            "access_token": "LONG_LIVED_SECRET_TOKEN",
            "user_id": "123456",
            "username": "sample.creator",
            "expires_at": oauth_app.iso(oauth_app.now_utc() + timedelta(days=55)),
            "scopes": ["instagram_business_basic"],
        }
        oauth_app.fetch_profile = lambda token: {
            "user_id": "123456", "username": "sample.creator",
            "account_type": "CREATOR", "media_count": 10,
            "followers_count": 250, "follows_count": 180,
        }
        oauth_app.fetch_media = lambda token: [{
            "id": "m1", "caption": "Hello", "media_type": "IMAGE",
            "permalink": "https://www.instagram.com/p/example/",
            "timestamp": oauth_app.iso(oauth_app.now_utc()),
            "like_count": 20, "comments_count": 4,
        }]
        response = self.client.get("/oauth/callback?code=sample-code&state=valid-state")
        self.assertEqual(response.status_code, 302)
        self.assertIn("connected=1", response.headers["Location"])
        with oauth_app.connect() as db:
            row = db.execute("SELECT * FROM oauth_accounts WHERE cid=?", ("browser-session-1",)).fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn("LONG_LIVED_SECRET_TOKEN", row["token_ciphertext"])
        self.assertEqual(row["username"], "sample.creator")
        dashboard = self.client.get("/api/dashboard").get_json()
        self.assertTrue(dashboard["connected"])

    def test_dashboard_does_not_expose_access_token(self):
        with self.client.session_transaction() as sess:
            sess["cid"] = "browser-session-2"
        oauth_app._store_account(
            "browser-session-2", "9", "account", "hidden-token",
            oauth_app.iso(oauth_app.now_utc() + timedelta(days=55)), [],
            {"username": "account", "followers_count": 12}, [],
        )
        payload = self.client.get("/api/dashboard").get_json()
        self.assertNotIn("access_token", json.dumps(payload))
        self.assertNotIn("token_ciphertext", json.dumps(payload))

    def test_sync_requires_csrf(self):
        response = self.client.post("/api/sync")
        self.assertEqual(response.status_code, 403)

    def test_disconnect_deletes_local_token_and_cache(self):
        with self.client.session_transaction() as sess:
            sess["cid"] = "browser-session-3"
            sess["_csrf"] = "csrf-value"
        oauth_app._store_account(
            "browser-session-3", "10", "account", "secret-token",
            oauth_app.iso(oauth_app.now_utc() + timedelta(days=55)), [], {}, [],
        )
        response = self.client.post("/api/disconnect", headers={"X-CSRF-Token": "csrf-value"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.get("/api/dashboard").get_json()["connected"])

    def test_health_check_reports_oauth_architecture(self):
        data = self.client.get("/healthz").get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["password_collection"] is False)
        self.assertTrue(data["data_import_enabled"] is False)
        self.assertTrue(data["unfollow_api"] is False)

    def test_analytics_only_describes_loaded_media(self):
        analytics = oauth_app.build_analytics(
            {"media_count": 99},
            [{"media_type": "REELS", "timestamp": oauth_app.iso(oauth_app.now_utc()),
              "like_count": 8, "comments_count": 2, "permalink": "https://instagram.com/p/x/"}],
        )
        self.assertEqual(analytics["posts_loaded"], 1)
        self.assertEqual(analytics["likes_on_loaded_posts"], 8)
        self.assertEqual(analytics["comments_on_loaded_posts"], 2)
        self.assertIn("not a full-account", analytics["note"])


if __name__ == "__main__":
    unittest.main()
