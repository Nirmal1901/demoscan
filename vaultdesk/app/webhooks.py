import urllib.parse

import requests
from flask import Blueprint, jsonify, request

from .auth import require_auth

bp = Blueprint("webhooks", __name__)

ALLOWED_PREFIX = "https://hooks.vaultdesk.example"


@bp.post("/api/webhooks/test")
@require_auth
def test_webhook():
    url = (request.get_json() or {}).get("url", "")
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "hooks.vaultdesk.example"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
    ):
        return jsonify(error="host not allowed"), 400
    resp = requests.post(
        url, json={"event": "ping"}, timeout=3, allow_redirects=False
    )
    return jsonify(status=resp.status_code)
