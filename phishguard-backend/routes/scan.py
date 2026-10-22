"""Scan endpoints: URL scanning, SMS scanning and single-scan details.

POST /api/scan/url           - analyze + store a URL scan
POST /api/scan/sms           - analyze + store an SMS scan
GET  /api/scan/<scan_id>     - full stored scan details
(The evidence endpoint lives in routes/history.py -> GET /api/evidence/<scan_id>)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from database.models import Scan, new_scan_id
from services import sms_analyzer, url_analyzer
from services.hash_service import sha256_of

scan_bp = Blueprint("scan", __name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store_scan(session, result: dict, scan_type: str, raw_input: str) -> Scan:
    """Persist an analyzer result and return the ORM row."""
    record = Scan(
        scan_id=new_scan_id(),
        type=scan_type,
        input=raw_input,
        normalized=result.get("normalized"),
        hostname=result.get("hostname"),
        root_domain=result.get("rootDomain"),
        official_domain=result.get("officialDomain"),
        verdict=result["verdict"],
        score=result["score"],
        reasons=json.dumps(result["reasons"], ensure_ascii=False),
        features=json.dumps(result["features"], ensure_ascii=False),
        timestamp=datetime.now(timezone.utc),
        sha256_hash=sha256_of(raw_input),
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def _response_from(record: Scan) -> dict:
    d = record.to_dict()
    return {
        "success": True,
        "type": d["type"],
        "input": d["input"],
        "normalized": d["normalized"],
        "hostname": d["hostname"],
        "rootDomain": d["rootDomain"],
        "officialDomain": d["officialDomain"],
        "verdict": d["verdict"],
        "score": d["score"],
        "reasons": d["reasons"],
        "features": d["features"],
        "timestamp": d["timestamp"] or _now_iso(),
        "hash": d["hash"],
        "scanId": d["scanId"],
    }


@scan_bp.post("/url")
def scan_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url") or request.form.get("url") or ""
    if not isinstance(url, str) or not url.strip():
        return jsonify({"success": False, "error": "Invalid URL"}), 400

    cfg = current_app.config
    try:
        result = url_analyzer.analyze_url(url, cfg["SAFE_MAX"], cfg["SUSPICIOUS_MAX"])
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        record = _store_scan(session, result, "URL", url.strip())
        return jsonify(_response_from(record)), 201


@scan_bp.post("/sms")
def scan_sms():
    data = request.get_json(silent=True) or {}
    message = data.get("message") or request.form.get("message") or ""
    if not isinstance(message, str) or not message.strip():
        return jsonify({"success": False, "error": "Invalid SMS message"}), 400

    cfg = current_app.config
    try:
        result = sms_analyzer.analyze_sms(message, cfg["SAFE_MAX"], cfg["SUSPICIOUS_MAX"])
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    # Expose hostname/rootDomain of the first embedded link (if parseable)
    features = result["features"]
    first_link = (features.get("links") or [None])[0]
    host = root = None
    if first_link:
        try:
            feats = url_analyzer.extract_features(first_link)
            host = feats.get("hostname")
            root = feats.get("rootDomain")
        except ValueError:
            pass

    stored = dict(result)
    stored.update({"normalized": None, "hostname": host, "rootDomain": root})

    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        record = _store_scan(session, stored, "SMS", message.strip())
        return jsonify(_response_from(record)), 201


@scan_bp.get("/<scan_id>")
def get_scan(scan_id: str):
    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        record = session.query(Scan).filter(Scan.scan_id == scan_id).one_or_none()
    if record is None:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    payload = {"success": True}
    payload.update(record.to_dict())
    return jsonify(payload), 200
