from flask import Blueprint, g, jsonify, request

from .auth import require_auth
from .db import get_db

bp = Blueprint("tickets", __name__)

EDITABLE = {"title", "body", "status", "assignee"}


@bp.post("/api/tickets")
@require_auth
def create_ticket():
    data = request.get_json() or {}
    if not data.get("title"):
        return jsonify(error="title required"), 400
    db = get_db()
    cur = db.execute("INSERT INTO tickets (title, body, owner_id) VALUES (?, ?, ?)",
                     (data["title"], data.get("body", ""), g.user["sub"]))
    db.commit()
    return jsonify(id=cur.lastrowid), 201


@bp.patch("/api/tickets/<int:ticket_id>")
@require_auth
def update_ticket(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        return jsonify(error="not found"), 404

    if ticket["owner_id"] != g.user.get("sub") and g.user.get("role") != "admin":
        return jsonify(error="forbidden"), 403

    for field, value in (request.get_json() or {}).items():
        if field in EDITABLE:
            db.execute(f"UPDATE tickets SET {field} = ? WHERE id = ?", (value, ticket_id))
    db.commit()
    updated = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return jsonify(dict(updated))
