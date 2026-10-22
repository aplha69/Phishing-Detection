"""Evidence endpoint.

GET /api/evidence/<scan_id> - structured, authoritative evidence payload the
frontend can render into a PDF report.
"""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify

from database.models import Scan

evidence_bp = Blueprint("evidence", __name__)


def _band(score, safe_max: int, susp_max: int) -> str:
    s = float(score or 0)
    if s <= safe_max:
        return f"Safe (0-{safe_max})"
    if s <= susp_max:
        return f"Suspicious ({safe_max + 1}-{susp_max})"
    return f"Phishing ({susp_max + 1}-100)"


@evidence_bp.get("/<scan_id>")
def evidence(scan_id: str):
    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        record = session.query(Scan).filter(Scan.scan_id == scan_id).one_or_none()
    if record is None:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    d = record.to_dict()
    reasons = [r for r in (d["reasons"] or []) if int(r.get("points", 0)) > 0]

    payload = {
        "success": True,
        "evidenceId": f"EVD-{record.scan_id}",
        "scanId": record.scan_id,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "timestamp": d["timestamp"],
        "scanType": d["type"],
        "input": d["input"],
        "normalized": d["normalized"],
        "verdict": d["verdict"],
        "riskScore": d["score"],
        "scoreBand": _band(
            d["score"],
            current_app.config["SAFE_MAX"],
            current_app.config["SUSPICIOUS_MAX"],
        ),
        "hostname": d["hostname"],
        "rootDomain": d["rootDomain"],
        "expectedOfficialDomain": d["officialDomain"],
        "sha256Fingerprint": d["hash"],
        "reasons": reasons,
        "features": d["features"],
        "summary": (
            f"PhishGuard analysis of {d['type']} '{str(d['input'])[:80]}' returned "
            f"verdict {d['verdict']} (risk score {d['score']}/100) based on "
            f"{len(reasons)} weighted signal(s). SHA-256 fingerprint: {d['hash']}"
        ),
    }
    return jsonify(payload), 200
