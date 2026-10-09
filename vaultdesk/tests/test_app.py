import base64
import hashlib
import hmac
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


def test_webhook_allows_exact_host_with_path_and_query(client):
    # The exact allowed host (with a path/query, no userinfo or explicit port)
    # must still be considered valid and posted to.
    c, _ = client
    h = _register_login(c)
    url = "https://hooks.vaultdesk.example/events?x=1"
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 200
        r = c.post("/api/webhooks/test", json={"url": url}, headers=h)
    assert r.status_code == 200 and r.get_json()["status"] == 200
    post.assert_called_once_with(url, json={"event": "ping"}, timeout=3, allow_redirects=False)


def test_webhook_sends_ping_payload_without_redirects(client):
    # Legitimate webhooks carry the documented ping body and do not follow
    # redirects (so the allow-list cannot be bypassed downstream).
    c, _ = client
    h = _register_login(c)
    with mock.patch("app.webhooks.requests.post") as post:
        post.return_value.status_code = 204
        r = c.post("/api/webhooks/test", json={"url": "https://hooks.vaultdesk.example/ping"}, headers=h)
        post.assert_called_once_with("https://hooks.vaultdesk.example/ping", json={"event": "ping"}, timeout=3, allow_redirects=False)
    assert r.get_json()["status"] == 204


# --- app/auth.py: token verification contract (expiry + malformed input) ---


def _raw_token(app, claims):
    """Build an HS256 token with an arbitrary claim set (mirrors make_token)."""
    secret = app.config["JWT_SECRET"].encode()

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def test_verify_token_rejects_expired_token(client):
    c, app = client
    with app.app_context():
        token = _raw_token(app, {"sub": 1, "name": "root", "role": "admin", "iss": "vaultdesk", "exp": int(time.time()) - 10})
        assert verify_token(token) is None
        fresh = _raw_token(app, {"sub": 1, "name": "root", "role": "admin", "iss": "vaultdesk", "exp": int(time.time()) + 3600})
        assert verify_token(fresh)["name"] == "root"


def test_verify_token_rejects_malformed_tokens(client):
    c, app = client
    with app.app_context():
        assert verify_token("") is None
        assert verify_token("not-a-token") is None
        assert verify_token("only.two") is None


def test_login_next_rejects_non_local_targets(client):
    # Local paths redirect (302); anything not a plain local path stays a 200 JSON login.
    c, _ = client
    c.post("/api/register", json={"username": "grace", "password": "safepass1"})
    for nxt in ("/\\evil.com", "///evil.com", "//evil.com", "https://evil.example"):
        r = c.post("/api/login", json={"username": "grace", "password": "safepass1", "next": nxt})
        assert r.status_code == 200 and r.get_json()["token"]
    good = c.post("/api/login", json={"username": "grace", "password": "safepass1", "next": "/dashboard"})
    assert good.status_code == 302 and good.headers["Location"] == "/dashboard"


# --- app/files.py: legitimate attachment download behaviour ---


def test_download_missing_attachment_404(client):
    c, _ = client
    h = _register_login(c)
    assert c.get("/api/files/does-not-exist.txt", headers=h).status_code == 404


# --- app/prefs.py: export/import round-trip of richer preference payloads ---


def test_export_import_roundtrip_nested_prefs(client):
    c, _ = client
    h = _register_login(c)
    prefs = {"theme": "dark", "nested": {"a": 1, "b": [1, 2]}, "notify": False}
    exported = c.post("/api/prefs/export", json=prefs, headers=h).get_json()
    r = c.post("/api/prefs/import", json=exported, headers=h)
    assert r.status_code == 200 and r.get_json()["prefs"] == prefs


def test_import_prefs_requires_auth(client):
    c, _ = client
    assert c.post("/api/prefs/import", json={"data": "", "sig": ""}).status_code == 401


# --- app/reports.py: audit summary grouping for legitimate actors ---


def test_audit_summary_groups_multiple_actors(client):
    c, app = client
    _register_login(c, "alice")  # register + login = 2 rows
    _register_login(c, "bob")    # register + login = 2 rows
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/audit/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.get_json() == {"alice": 2, "bob": 2}


def test_audit_summary_counts_actor_names_literally(client):
    # Actor names are treated as data: an oddly-named actor is reported with its
    # literal name and its true count, and no extra rows are swept in.
    c, app = client
    weird = "x' OR '1'='1"
    _register_login(c, weird)
    with app.app_context():
        token = make_token({"id": 1, "username": "root", "role": "admin"})
    r = c.get("/api/audit/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.get_json() == {weird: 2}


# --- app/tickets.py: legitimate create validation ---


def test_create_ticket_requires_title(client):
    c, _ = client
    h = _register_login(c)
    assert c.post("/api/tickets", json={}, headers=h).status_code == 400
    assert c.post("/api/tickets", json={"title": ""}, headers=h).status_code == 400
    assert c.post("/api/tickets", json={"title": "ok"}, headers=h).status_code == 201
