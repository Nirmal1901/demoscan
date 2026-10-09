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
    name = unquote(name)
    base = os.path.realpath(current_app.config["UPLOAD_DIR"])
    path = os.path.realpath(os.path.join(base, name))
    if path != base and not path.startswith(base + os.sep):
        abort(400)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)
