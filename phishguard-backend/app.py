"""PhishGuard Backend — Flask application entry point.

Thin app factory only; all logic lives in routes/ (blueprints) and services/.

Run:
    flask --app app run --debug
or:
    python app.py
"""
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Config
from database.models import init_db
from routes import BLUEPRINTS


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    logging.basicConfig(level=logging.INFO)

    # CORS so the local HTML/JS frontend can call the API during development
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialise SQLAlchemy / SQLite (creates tables on first run)
    db = init_db(app.config["SQLALCHEMY_DATABASE_URI"])
    app.extensions["phishguard_db"] = db
    app.logger.info("Database ready at %s", app.config["SQLALCHEMY_DATABASE_URI"])

    # Register blueprints under /api
    for bp in BLUEPRINTS:
        prefix = "/api"
        if bp.name == "scan":
            prefix = "/api/scan"
        elif bp.name == "assistant":
            prefix = "/api/assistant"
        elif bp.name == "evidence":
            prefix = "/api/evidence"
        app.register_blueprint(bp, url_prefix=prefix)

    # ---- Health check ------------------------------------------------------
    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": app.config["SERVICE_NAME"],
            "version": app.config["VERSION"],
        }), 200

    @app.get("/")
    def root():
        return jsonify({
            "service": app.config["SERVICE_NAME"],
            "version": app.config["VERSION"],
            "endpoints": [
                "POST /api/scan/url",
                "POST /api/scan/sms",
                "GET  /api/scan/<scan_id>",
                "POST /api/assistant/chat",
                "GET  /api/history",
                "DELETE /api/history",
                "DELETE /api/history/<scan_id>",
                "GET  /api/dashboard",
                "GET  /api/evidence/<scan_id>",
                "GET  /api/health",
            ],
        }), 200

    # ---- JSON error handlers ----------------------------------------------
    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({
            "success": False,
            "error": f"Endpoint not found: {request.method} {request.path}",
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"success": False, "error": "Method not allowed"}), 405

    @app.errorhandler(415)
    def unsupported_media(_e):
        return jsonify({"success": False, "error": "Unsupported Media Type"}), 415

    @app.errorhandler(Exception)
    def unhandled(e):
        app.logger.exception("Unhandled error")
        # Never leak internals to the client
        return jsonify({"success": False, "error": "Internal server error"}), 500

    return app


app = create_app()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug)
