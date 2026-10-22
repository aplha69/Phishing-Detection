"""Route blueprints for PhishGuard backend."""
from routes.scan import scan_bp
from routes.assistant import assistant_bp
from routes.history import history_bp
from routes.dashboard import dashboard_bp
from routes.evidence import evidence_bp

BLUEPRINTS = (scan_bp, assistant_bp, history_bp, dashboard_bp, evidence_bp)

__all__ = [
    "scan_bp", "assistant_bp", "history_bp", "dashboard_bp", "evidence_bp",
    "BLUEPRINTS",
]
