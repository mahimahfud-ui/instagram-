import json
import os
import tempfile
import unittest
from datetime import timedelta
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
        os.environ["META_APP_ID"] = "test-meta-app-id"
        os.environ["META_APP_SECRET"] = "test-meta-app-secret"
        os.environ["META_LOGIN_CONFIG_ID"] = "test-config-123"
        os.environ["META_REDIRECT_URI"] = "https://insight.example/oauth/callback"
        os.environ.pop("TOKEN_ENCRYPTION_KEY", None)
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
        self.assertNotIn('type="file"', body)
        self.assertNotIn("Import Instagram data", body)

    def test_connect_redirects_to_meta_unified_login(self):
        response = self.client.get("/connect/instagram")
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response.headers["Location"])
        self.assertEqual(parsed.netloc, "www.facebook.com")
        self.assertEqual(parsed.path, "/dialog/oauth")
        params = parse_qs(parsed.query)
        self.assertEqual(params["client_id"], ["test-meta-app-id"])
        self.assertEqual(params["config_id"], ["test-config-123"])
        self.assertEqual(params["redirect_uri"], ["https://insight.example/oauth/callback"])
        self.assertEqual(params["response_type"], ["code"])
        self.assertNotIn("scope", params)
        self.assertTrue(params.get("state", [""])[0])

    def test_connect_fails_closed_without_meta_credentials(self):
        os.environ.pop("META_APP_SECRET", None)
        response = self.client.get("/connect/instagram")
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"not configured", response.data)

    def test_code_exchange_uses_meta_app_credentials_server_side(self):
        seen = {}
        original = oauth_app._http_json

        def fake_http(url, **_kwargs):
            seen["url"] = url
            return {"access_token": "test-access-token", "expires_in": 3600}

        oauth_app._http_json = fake_http
        try:
            result = oauth_app.exchange_authorization_code("abc+123")
        finally:
            oauth_app._http_json = original
        parsed = urlparse(seen["url"])
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.netloc, "graph.facebook.com")
        self.assertEqual(params["client_id"], ["test-meta-app-id"])
        self.assertEqual(params["client_secret"], ["test-meta-app-secret"])
        self.assertEqual(params["code"], ["abc+123"])
        self.assertTrue(result["access_token"])

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
            "expires_at": "",
        }
        oauth_app.fetch_assigned_instagram_account = lambda token: {
            "ig_user_id": "123456",
            "username": "sample.creator",
            "client_business_id": "biz-001",
        }
        oauth_app.fetch_profile = lambda token, ig_user_id: {
            "id": ig_user_id, "username": "sample.creator",
            "account_type": "CREATOR", "media_count": 10,
            "followers_count": 250, "follows_count": 180,
        }
        oauth_app.fetch_media = lambda token, ig_user_id: [{
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
        self.assertEqual(row["client_business_id"], "biz-001")
        dashboard = self.client.get("/api/dashboard").get_json()
        self.assertTrue(dashboard["connected"])

    def test_dashboard_does_not_expose_access_token(self):
        with self.client.session_transaction() as sess:
            sess["cid"] = "browser-session-2"
        oauth_app._store_account(
            "browser-session-2", "9", "account", "biz-9", "cfg-9", "hidden-token",
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
            "browser-session-3", "10", "account", "biz-10", "cfg-10", "secret-token",
            "", [], {}, [],
        )
        response = self.client.post("/api/disconnect", headers={"X-CSRF-Token": "csrf-value"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.get("/api/dashboard").get_json()["connected"])

    def test_health_check_reports_unified_oauth_architecture(self):
        data = self.client.get("/healthz").get_json()
        self.assertTrue(data["ok"])
        self.assertFalse(data["password_collection"])
        self.assertFalse(data["data_import_enabled"])
        self.assertFalse(data["unfollow_api"])
        self.assertEqual(data["oauth_provider"], "Meta Instagram API with Unified Login")

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
