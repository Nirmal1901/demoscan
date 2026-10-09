import os
from urllib.parse import unquote

from flask import Blueprint, abort, current_app, jsonify, send_file

from .auth import require_auth

bp = Blueprint("files", __name__)


@bp.get("/api/files")
@require_auth
def list_files():
    return jsonify(files=sorted(os.listdir(current_app.config["UPLOAD_DIR"])))


@bp.get("/api/files/<path:name>")
@require_auth
def download(name):
    if ".." in name or name.startswith("/"):
        abort(400)
    path = os.path.join(current_app.config["UPLOAD_DIR"], unquote(name))
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)
