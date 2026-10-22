"""Scan history endpoints.

GET    /api/history            - recent scans (?limit=150, ?type=URL|SMS)
DELETE /api/history            - clear all stored scans
DELETE /api/history/<scan_id>  - delete one scan
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from database.models import Scan

history_bp = Blueprint("history", __name__)

DEFAULT_LIMIT = 150
MAX_LIMIT = 1000


@history_bp.get("/history")
def list_history():
    try:
        limit = int(request.args.get("limit", DEFAULT_LIMIT))
    except ValueError:
        return jsonify({"success": False, "error": "Invalid limit parameter"}), 400
    limit = max(1, min(limit, MAX_LIMIT))

    scan_type = (request.args.get("type") or "").strip().upper() or None

    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        q = session.query(Scan).order_by(Scan.timestamp.desc())
        if scan_type in ("URL", "SMS"):
            q = q.filter(Scan.type == scan_type)
        rows = q.limit(limit).all()
        scans = [r.to_dict() for r in rows]

    return jsonify({"success": True, "count": len(scans), "scans": scans}), 200


@history_bp.delete("/history")
def clear_history():
    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        deleted = session.query(Scan).delete()
        session.commit()
    return jsonify({"success": True, "deleted": deleted}), 200


@history_bp.delete("/history/<scan_id>")
def delete_scan(scan_id: str):
    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        record = session.query(Scan).filter(Scan.scan_id == scan_id).one_or_none()
        if record is None:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        session.delete(record)
        session.commit()
    return jsonify({"success": True, "deleted": scan_id}), 200
