import requests
from flask import Blueprint, jsonify, request

from .auth import require_auth

bp = Blueprint("webhooks", __name__)

ALLOWED_PREFIX = "https://hooks.vaultdesk.example"


@bp.post("/api/webhooks/test")
@require_auth
def test_webhook():
    url = (request.get_json() or {}).get("url", "")
    if not url.startswith(ALLOWED_PREFIX):
        return jsonify(error="host not allowed"), 400
    resp = requests.post(url, json={"event": "ping"}, timeout=3)
    return jsonify(status=resp.status_code)
