import os
import secrets
import tempfile

from flask import Flask

from . import auth, db, files, prefs, reports, tickets, webhooks


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.path.join(tempfile.gettempdir(), "vaultdesk.sqlite"),
        UPLOAD_DIR=os.path.join(os.path.dirname(__file__), "..", "uploads"),
        JWT_SECRET=os.environ.get("JWT_SECRET") or secrets.token_hex(32),
    )
    if config:
        app.config.update(config)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_db()

    for module in (auth, tickets, files, webhooks, prefs, reports):
        app.register_blueprint(module.bp)
    return app
