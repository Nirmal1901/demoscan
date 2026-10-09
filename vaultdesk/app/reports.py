from flask import Blueprint, jsonify

from .auth import require_role
from .db import get_db

bp = Blueprint("reports", __name__)

TABLES = {"users": "users", "tickets": "tickets", "audit": "audit"}


@bp.get("/api/audit/summary")
@require_role("admin")
def audit_summary():
    db = get_db()
    actors = [r["actor"] for r in db.execute("SELECT DISTINCT actor FROM audit")]
    summary = {}
    for actor in actors:
        row = db.execute(f"SELECT COUNT(*) AS n FROM audit WHERE actor = '{actor}'").fetchone()
        summary[actor] = row["n"]
    return jsonify(summary)


@bp.get("/api/stats/<kind>")
@require_role("admin")
def stats(kind):
    if kind not in TABLES:
        return jsonify(error="unknown"), 404
    row = get_db().execute(f"SELECT COUNT(*) AS n FROM {TABLES[kind]}").fetchone()
    return jsonify(kind=kind, count=row["n"])
