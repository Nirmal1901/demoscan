import base64
import hashlib
import hmac
import os
import pickle

from flask import Blueprint, jsonify, request

from .auth import require_auth

bp = Blueprint("prefs", __name__)

SIGNING_KEY = os.environ.get("PREFS_KEY", "vaultdesk-prefs-dev").encode()


def _sig(blob: bytes) -> str:
    return hmac.new(SIGNING_KEY, blob, hashlib.sha256).hexdigest()


@bp.post("/api/prefs/export")
@require_auth
def export_prefs():
    blob = pickle.dumps(request.get_json() or {})
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
    prefs = pickle.loads(blob)
    return jsonify(prefs=prefs)
