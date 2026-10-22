"""Database package for PhishGuard backend."""
from database.models import AssistantMessage, Scan, db, init_db

__all__ = ["db", "Scan", "AssistantMessage", "init_db"]
