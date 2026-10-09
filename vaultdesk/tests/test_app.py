from unittest import mock

import pytest

from app import create_app
from app.auth import make_token
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
