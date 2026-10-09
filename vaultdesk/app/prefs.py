import base64
import hashlib
import hmac
import json
import os

from flask import Blueprint, current_app, jsonify, request

from .auth import require_auth

bp = Blueprint("prefs", __name__)

def _signing_key() -> bytes:
    override = os.environ.get("PREFS_KEY")
    if override:
        return override.encode()
    return current_app.config["JWT_SECRET"].encode()


def _sig(blob: bytes) -> str:
    return hmac.new(_signing_key(), blob, hashlib.sha256).hexdigest()


@bp.post("/api/prefs/export")
@require_auth
def export_prefs():
    blob = json.dumps(request.get_json() or {}).encode()
    return jsonify(data=base64.b64encode(blob).decode(), sig=_sig(blob))


@bp.post("/api/prefs/import")
@require_auth
def import_prefs():
    payload = request.get_json() or {}
    try:
        blob = base64.b64decode(payload.get("data", ""))
    except Exception:
        return jsonify(error="bad data"), 400
    if not hmac.compare_digest(_sig(blob), payload.get("sig", "")):
        return jsonify(error="bad signature"), 400
    prefs = json.loads(blob)
    return jsonify(prefs=prefs)
