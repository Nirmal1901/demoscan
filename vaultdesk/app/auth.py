import base64
import functools
import hashlib
import hmac
import json
import time
from urllib.parse import urlparse

from flask import Blueprint, current_app, g, jsonify, redirect, request
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

bp = Blueprint("auth", __name__)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(signing_input: str) -> str:
    key = current_app.config["JWT_SECRET"].encode()
    return _b64(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def make_token(user) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({
        "sub": user["id"], "name": user["username"], "role": user["role"],
        "iss": "vaultdesk", "exp": int(time.time()) + 3600,
    }).encode())
    return f"{head}.{body}.{_sign(head + '.' + body)}"


def verify_token(token: str):
    try:
        head_b, body_b, sig_b = token.split(".")
        header = json.loads(_unb64(head_b))
        claims = json.loads(_unb64(body_b))
    except Exception:
        return None

    alg = header.get("alg")
    if alg == "HS256":
        if not hmac.compare_digest(_sign(f"{head_b}.{body_b}"), sig_b):
            return None
    else:
        return None

    if claims.get("exp", 0) < time.time():
        return None
    return claims


def require_auth(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        claims = verify_token(header[7:]) if header.startswith("Bearer ") else None
        if not claims:
            return jsonify(error="unauthorized"), 401
        g.user = claims
        return view(*args, **kwargs)
    return wrapped


def require_role(role):
    def decorator(view):
        @require_auth
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.user.get("role") != role:
                return jsonify(error="forbidden"), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _is_local(target: str) -> bool:
    if not target or "\\" in target or target.startswith("//"):
        return False
    if not target.startswith("/"):
        return False
    parts = urlparse(target)
    return parts.scheme == "" and parts.netloc == ""


@bp.post("/api/register")
def register():
    data = request.get_json() or {}
    username, password = data.get("username", ""), data.get("password", "")
    if not (3 <= len(username) <= 40) or len(password) < 8:
        return jsonify(error="invalid username or password"), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   (username, generate_password_hash(password)))
        db.execute("INSERT INTO audit (actor, action) VALUES (?, ?)", (username, "register"))
        db.commit()
    except Exception:
        return jsonify(error="username taken"), 409
    return jsonify(ok=True), 201


@bp.post("/api/login")
def login():
    data = request.get_json() or {}
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (data.get("username", ""),)).fetchone()
    if not user or not check_password_hash(user["password_hash"], data.get("password", "")):
        return jsonify(error="bad credentials"), 401
    db.execute("INSERT INTO audit (actor, action) VALUES (?, ?)", (user["username"], "login"))
    db.commit()

    nxt = data.get("next")
    if nxt and _is_local(nxt):
        return redirect(nxt)
    return jsonify(token=make_token(user))
