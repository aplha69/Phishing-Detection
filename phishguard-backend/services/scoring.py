"""Weighted scoring & classification for PhishGuard.

Each analyzer produces a list of "reasons":
    {"label": str, "points": int, "detail": str}

The score is the normalised weighted sum (0-100) and the verdict follows:
    0-34  -> Safe
    35-69 -> Suspicious
    70-100 -> Phishing
"""
from __future__ import annotations

MAX_POINTS = 100  # points at/above which the score saturates at 100


def make_reason(label: str, points: int, detail: str) -> dict:
    return {"label": label, "points": int(points), "detail": detail}


def compute_score(reasons: list[dict]) -> float:
    """Sum weighted points and clamp to 0-100 (rounded to 1 decimal)."""
    total = sum(int(r.get("points", 0)) for r in reasons)
    if total < 0:
        total = 0
    if total > MAX_POINTS:
        total = MAX_POINTS
    return round(float(total), 1)


def classify(score: float, safe_max: int = 34, suspicious_max: int = 69) -> str:
    if score <= safe_max:
        return "Safe"
    if score <= suspicious_max:
        return "Suspicious"
    return "Phishing"


def analyze_result(
    reasons: list[dict],
    safe_max: int = 34,
    suspicious_max: int = 69,
) -> tuple[float, str]:
    """Return (score, verdict) from a reason list."""
    score = compute_score(reasons)
    return score, classify(score, safe_max, suspicious_max)
