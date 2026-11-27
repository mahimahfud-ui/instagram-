import io
import json
import sqlite3
import zipfile

import pytest

import app_updated as module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "DB_PATH", tmp_path / "test.sqlite3")
    module.init_db()
    module.app.config.update(TESTING=True)
    with module.app.test_client() as test_client:
        with test_client.session_transaction() as state:
            state["cid"] = "test-browser"
            state["_csrf"] = "test-csrf-token"
        yield test_client


def make_archive(followers, following):
    payload = io.BytesIO()
    follower_records = [
        {
            "title": name,
            "string_list_data": [
                {"value": name, "href": f"https://www.instagram.com/{name}/"}
            ],
        }
        for name in followers
    ]
    following_records = {
        "relationships_following": [
            {
                "title": name,
                "string_list_data": [
                    {"value": name, "href": f"https://www.instagram.com/{name}/"}
                ],
            }
            for name in following
        ]
    }
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "connections/followers_and_following/followers_1.json",
            json.dumps(follower_records),
        )
        archive.writestr(
            "connections/followers_and_following/following.json",
            json.dumps(following_records),
        )
    return payload.getvalue()


def upload(client, archive_bytes):
    return client.post(
        "/api/import",
        data={
            "file": (io.BytesIO(archive_bytes), "instagram-export.zip"),
            "profile_username": "my.test_account",
        },
        headers={"X-CSRF-Token": "test-csrf-token"},
        content_type="multipart/form-data",
    )


def test_import_and_relationship_lists(client):
    response = upload(client, make_archive(["alice", "bob"], ["alice", "charlie"]))
    assert response.status_code == 200
    assert response.json["result"]["followers"] == 2
    assert response.json["result"]["following"] == 2

    state = client.get("/api/state").json
    assert state["ready"] is True
    assert state["not_following_back"] == 1
    assert state["fans"] == 1
    assert state["mutual"] == 1
    assert state["profile_username"] == "my.test_account"

    not_back = client.get("/api/list?kind=notback").json
    assert [row["username"] for row in not_back["rows"]] == ["charlie"]
    fans = client.get("/api/list?kind=fans").json
    assert [row["username"] for row in fans["rows"]] == ["bob"]


def test_second_import_records_only_actual_list_differences(client):
    upload(client, make_archive(["alice", "bob"], ["alice", "charlie"]))
    response = upload(client, make_archive(["alice", "charlie"], ["alice", "bob", "dan"]))
    assert response.status_code == 200
    assert response.json["result"]["changes"] == 5
    events = client.get("/api/activity").json["rows"]
    kinds = {(item["kind"], item["username"]) for item in events}
    assert ("added_to_followers", "charlie") in kinds
    assert ("removed_from_followers", "bob") in kinds
    assert ("added_to_following", "dan") in kinds
    assert ("added_to_following", "bob") in kinds
    assert ("removed_from_following", "charlie") in kinds


def test_rejects_non_zip_and_missing_relationship_file(client):
    bad = client.post(
        "/api/import",
        data={"file": (io.BytesIO(b"not a zip"), "bad.zip")},
        headers={"X-CSRF-Token": "test-csrf-token"},
        content_type="multipart/form-data",
    )
    assert bad.status_code == 400

    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("followers_and_following/followers_1.json", "[]")
    missing = upload(client, content.getvalue())
    assert missing.status_code == 400
    assert "both followers and following" in missing.json["error"]


def test_csrf_and_removed_credential_endpoints(client):
    blocked = client.post("/api/clear")
    assert blocked.status_code == 403
    assert client.get("/admin").status_code == 404
    assert client.post("/credential").status_code == 404
    assert client.get("/cookies").status_code == 404


def test_page_and_health_endpoint(client):
    page = client.get("/")
    assert page.status_code == 200
    assert 'name="csrf-token"' in page.get_data(as_text=True)
    assert "__CSRF__" not in page.get_data(as_text=True)
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json["ok"] is True


def test_legacy_credential_storage_is_removed_on_upgrade(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(module, "DB_PATH", tmp_path / "insight.sqlite3")

    conn = sqlite3.connect(module.DB_PATH)
    conn.executescript(
        """
        CREATE TABLE creds (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        INSERT INTO creds (username, password) VALUES ('old-user', 'old-password');
        CREATE TABLE ig_sessions (cid TEXT PRIMARY KEY, username TEXT, pass_enc TEXT);
        INSERT INTO ig_sessions (cid, username, pass_enc)
            VALUES ('old-browser', 'old-user', 'encrypted-password');
        CREATE TABLE events (id INTEGER PRIMARY KEY, cid TEXT, kind TEXT);
        """
    )
    conn.commit()
    conn.close()

    sessions = tmp_path / "sessions"
    sessions.mkdir()
    (sessions / "old-browser.json").write_text('{"session":"old"}', encoding="utf-8")
    (tmp_path / "events.jsonl").write_text('{"password":"old-password"}\n', encoding="utf-8")
    (tmp_path / "insight.log").write_text("password=old-password\n", encoding="utf-8")

    module.init_db()

    with module.connect() as migrated:
        tables = {
            row["name"]
            for row in migrated.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "creds" not in tables
    assert "ig_sessions" not in tables
    assert "accounts" in tables
    assert not sessions.exists()
    assert not (tmp_path / "events.jsonl").exists()
    assert not (tmp_path / "insight.log").exists()


def test_favicon_is_served(client):
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert response.mimetype == "image/svg+xml"
    assert "<svg" in response.get_data(as_text=True)


def test_database_reinitialization_preserves_import_history(client):
    upload(client, make_archive(["alice"], ["alice", "bob"]))
    upload(client, make_archive(["alice", "bob"], ["alice", "bob"]))
    module.init_db()
    assert client.get("/api/state").json["ready"] is True
    assert len(client.get("/api/activity").json["rows"]) == 1


def test_export_and_delete(client):
    upload(client, make_archive(["alice"], ["alice", "bob"]))
    exported = client.get("/api/export?kind=notback&format=csv")
    assert exported.status_code == 200
    assert "bob,notback" in exported.get_data(as_text=True)

    deleted = client.post("/api/clear", headers={"X-CSRF-Token": "test-csrf-token"})
    assert deleted.status_code == 200
    assert client.get("/api/state").json["ready"] is False
