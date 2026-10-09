import base64
import json
import time
from unittest import mock

import pytest

from app import create_app
from app.auth import make_token, verify_token
from app.db import get_db


@pytest.fixture
def client(tmp_path):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    (uploads / "hello.txt").write_text("hi")
    app = create_app({"DATABASE": str(tmp_path / "t.sqlite"), "UPLOAD_DIR": str(uploads), "JWT_SECRET": "test", "TESTING": True})
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO users (username, password_hash, role) VALUES ('root', 'x', 'admin')")
        db.commit()
    return app.test_client(), app


def _register_login(c, name="alice"):
    c.post("/api/register", json={"username": name, "password": "correct-horse"})
    token = c.post("/api/login", json={"username": name, "password": "correct-horse"}).get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_ticket_flow(client):
    c, _ = client
    h = _register_login(c)
    tid = c.post("/api/tickets", json={"title": "printer"}, headers=h).get_json()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"status": "closed"}, headers=h)
    assert r.status_code == 200 and r.get_json()["status"] == "closed"


def test_requires_auth(client):
    c, _ = client
    assert c.get("/api/files").status_code == 401


def test_file_download_and_dotdot_blocked(client):
    c, _ = client
    h = _register_login(c)
    assert c.get("/api/files/hello.txt", headers=h).data == b"hi"
    assert c.get("/api/files/..%2fsecret", headers=h).status_code in (400, 404)


def test_webhook_rejects_foreign_host(client):
    c, _ = client
    h = _register_login(c)
    assert c.post("/api/webhooks/test", json={"url": "http://example.org/x"}, headers=h).status_code == 400
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 204
        r = c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/a"}, headers=h)
    assert r.get_json()["status"] == 204


def test_prefs_roundtrip(client):
    c, _ = client
    h = _register_login(c)
    exported = c.post("/api/prefs/export", json={"theme": "dark"}, headers=h).get_json()
    r = c.post("/api/prefs/import", json=exported, headers=h)
    assert r.get_json()["prefs"] == {"theme": "dark"}
    assert c.post("/api/prefs/import", json={**exported, "sig": "0"}, headers=h).status_code == 400


def test_audit_summary_admin_only(client):
    c, app = client
    h = _register_login(c)
    assert c.get("/api/audit/summary", headers=h).status_code == 403
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/audit/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.get_json()["alice"] == 2


def test_login_next_local_only(client):
    c, _ = client
    c.post("/api/register", json={"username": "bob", "password": "correct-horse"})
    r = c.post("/api/login", json={"username": "bob", "password": "correct-horse", "next": "/dashboard"})
    assert r.status_code == 302 and r.headers["Location"] == "/dashboard"
    r = c.post("/api/login", json={"username": "bob", "password": "correct-horse", "next": "https://evil.example"})
    assert r.status_code == 200


# --- app/auth.py: legitimate token, register and login behaviour ---


def test_make_token_roundtrip(client):
    c, app = client
    with app.app_context():
        token = make_token({"id": 7, "username": "carol", "role": "user"})
    with app.app_context():
        claims = verify_token(token)
    assert claims is not None
    assert claims["sub"] == 7
    assert claims["name"] == "carol"
    assert claims["role"] == "user"
    assert claims["iss"] == "vaultdesk"
    assert claims["exp"] > time.time()


def test_valid_token_authorizes_protected_endpoint(client):
    c, app = client
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/files", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert "files" in r.get_json()


def test_register_valid_returns_201_and_duplicate_409(client):
    c, _ = client
    r = c.post("/api/register", json={"username": "dave", "password": "supersecret"})
    assert r.status_code == 201 and r.get_json()["ok"] is True
    dup = c.post("/api/register", json={"username": "dave", "password": "supersecret"})
    assert dup.status_code == 409


def test_register_rejects_short_input(client):
    c, _ = client
    assert c.post("/api/register", json={"username": "ab", "password": "longenough"}).status_code == 400
    assert c.post("/api/register", json={"username": "validname", "password": "short"}).status_code == 400


def test_login_valid_returns_token_and_invalid_401(client):
    c, _ = client
    c.post("/api/register", json={"username": "erin", "password": "safepass1"})
    ok = c.post("/api/login", json={"username": "erin", "password": "safepass1"})
    assert ok.status_code == 200
    assert ok.get_json()["token"]
    bad = c.post("/api/login", json={"username": "erin", "password": "wrongpass"})
    assert bad.status_code == 401


def test_login_next_local_redirect(client):
    c, _ = client
    c.post("/api/register", json={"username": "frank", "password": "safepass1"})
    r = c.post("/api/login", json={"username": "frank", "password": "safepass1", "next": "/dashboard"})
    assert r.status_code == 302 and r.headers["Location"] == "/dashboard"
    r = c.post("/api/login", json={"username": "frank", "password": "safepass1", "next": "/tickets/3"})
    assert r.status_code == 302 and r.headers["Location"] == "/tickets/3"


# --- app/files.py: listing and downloading legitimate attachments ---


def test_list_files_returns_sorted_uploads(client):
    c, _ = client
    h = _register_login(c)
    r = c.get("/api/files", headers=h)
    assert r.status_code == 200
    files = r.get_json()["files"]
    assert "hello.txt" in files
    assert files == sorted(files)


def test_download_normal_attachment(client):
    c, _ = client
    h = _register_login(c)
    r = c.get("/api/files/hello.txt", headers=h)
    assert r.status_code == 200 and r.data == b"hi"


# --- app/prefs.py: export/import round-trip of user preferences ---


def test_export_prefs_shape(client):
    c, _ = client
    h = _register_login(c)
    r = c.post("/api/prefs/export", json={"theme": "dark", "lang": "en"}, headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert {"data", "sig"} <= set(body)
    assert json.loads(base64.b64decode(body["data"])) == {"theme": "dark", "lang": "en"}


def test_import_prefs_roundtrip(client):
    c, _ = client
    h = _register_login(c)
    exported = c.post("/api/prefs/export", json={"notify": True}, headers=h).get_json()
    r = c.post("/api/prefs/import", json=exported, headers=h)
    assert r.status_code == 200 and r.get_json()["prefs"] == {"notify": True}


# --- app/reports.py: admin stats and audit summary ---


def test_stats_known_table_count(client):
    c, app = client
    _register_login(c)  # root (seeded) + alice
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    h = {"Authorization": f"Bearer {token}"}
    r = c.get("/api/stats/users", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "users" and body["count"] == 2
    assert c.get("/api/stats/tickets", headers=h).get_json()["count"] == 0


def test_stats_unknown_kind_404(client):
    c, app = client
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/stats/nope", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404


def test_audit_summary_shape_for_admin(client):
    c, app = client
    _register_login(c)  # alice -> register + login = 2 audit rows
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/audit/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    summary = r.get_json()
    assert summary["alice"] == 2
    assert all(isinstance(v, int) for v in summary.values())


# --- app/tickets.py: core create + update flow and ownership rules ---


def test_create_ticket_owner_is_creator(client):
    c, app = client
    h = _register_login(c)
    r = c.post("/api/tickets", json={"title": "vpn", "body": "help"}, headers=h)
    assert r.status_code == 201
    tid = r.get_json()["id"]
    with app.app_context():
        alice_id = get_db().execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
    updated = c.patch(f"/api/tickets/{tid}", json={"status": "in-progress"}, headers=h)
    assert updated.status_code == 200
    body = updated.get_json()
    assert body["status"] == "in-progress"
    assert body["title"] == "vpn" and body["body"] == "help"
    assert body["owner_id"] == alice_id


def test_patch_ignores_non_editable_fields(client):
    c, app = client
    h = _register_login(c)
    tid = c.post("/api/tickets", json={"title": "keep-owner"}, headers=h).get_json()["id"]
    with app.app_context():
        alice_id = get_db().execute("SELECT id FROM users WHERE username = 'alice'").fetchone()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"assignee": "carol", "owner_id": 999}, headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["assignee"] == "carol"
    assert body["owner_id"] == alice_id


def test_patch_ticket_by_non_owner_forbidden(client):
    c, _ = client
    alice = _register_login(c, "alice")
    bob = _register_login(c, "bob")
    tid = c.post("/api/tickets", json={"title": "secret"}, headers=alice).get_json()["id"]
    r = c.patch(f"/api/tickets/{tid}", json={"status": "closed"}, headers=bob)
    assert r.status_code == 403


def test_patch_ticket_by_admin_allowed(client):
    c, app = client
    h = _register_login(c)
    tid = c.post("/api/tickets", json={"title": "admin-edit"}, headers=h).get_json()["id"]
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.patch(f"/api/tickets/{tid}", json={"status": "closed"}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.get_json()["status"] == "closed"


def test_patch_missing_ticket_404(client):
    c, _ = client
    h = _register_login(c)
    assert c.patch("/api/tickets/99999", json={"status": "closed"}, headers=h).status_code == 404


# --- app/webhooks.py: allowed host posting and auth gating ---


def test_webhook_allowed_host_still_posts(client):
    c, _ = client
    h = _register_login(c)
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 200
        r = c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/events"}, headers=h)
        post.assert_called_once()
    assert r.status_code == 200 and r.get_json()["status"] == 200


def test_webhook_requires_auth(client):
    c, _ = client
    assert c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/x"}).status_code == 401
