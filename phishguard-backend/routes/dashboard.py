"""Dashboard statistics endpoint.

GET /api/dashboard - aggregate stats computed from the database (not localStorage).
"""
from __future__ import annotations

import json
from collections import Counter

from flask import Blueprint, current_app, jsonify

from database.models import Scan

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard")
def dashboard():
    db = current_app.extensions["phishguard_db"]
    with db.session() as session:
        rows = session.query(Scan).order_by(Scan.timestamp.desc()).all()

    total = len(rows)
    counts = Counter(r.verdict for r in rows)
    type_counts = Counter(r.type for r in rows)

    # Top risk features: sum points per reason label across all scans
    feature_points: Counter = Counter()
    feature_hits: Counter = Counter()
    for r in rows:
        try:
            reasons = json.loads(r.reasons or "[]")
        except ValueError:
            reasons = []
        for reason in reasons:
            pts = int(reason.get("points", 0))
            if pts > 0:
                label = reason.get("label", "Unknown")
                feature_points[label] += pts
                feature_hits[label] += 1

    top_risk_features = [
        {"feature": label, "totalPoints": pts, "occurrences": feature_hits[label]}
        for label, pts in feature_points.most_common(10)
    ]

    recent_high_risk = [
        {
            "scanId": r.scan_id,
            "type": r.type,
            "input": (r.input or "")[:120],
            "verdict": r.verdict,
            "score": r.score,
            "hostname": r.hostname,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "hash": r.sha256_hash,
        }
        for r in rows if r.verdict == "Phishing"
    ][:10]

    avg_score = round(sum(r.score for r in rows) / total, 1) if total else 0.0

    return jsonify({
        "totalScans": total,
        "safe": counts.get("Safe", 0),
        "suspicious": counts.get("Suspicious", 0),
        "phishing": counts.get("Phishing", 0),
        "urlScans": type_counts.get("URL", 0),
        "smsScans": type_counts.get("SMS", 0),
        "averageRiskScore": avg_score,
        "topRiskFeatures": top_risk_features,
        "recentHighRiskScans": recent_high_risk,
    }), 200
