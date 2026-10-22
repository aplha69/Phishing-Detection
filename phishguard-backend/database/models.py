"""SQLAlchemy models for PhishGuard.

Tables
------
Scan              – every URL/SMS scan result (authoritative record).
AssistantMessage  – chat history for the AI Security Assistant.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """A stored scan result (URL or SMS)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    type: Mapped[str] = mapped_column(String(10), index=True)          # "URL" | "SMS"
    input: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    root_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    official_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verdict: Mapped[str] = mapped_column(String(20), index=True)       # Safe/Suspicious/Phishing
    score: Mapped[float] = mapped_column(Float, default=0.0)
    reasons: Mapped[str] = mapped_column(Text, default="[]")           # JSON string
    features: Mapped[str] = mapped_column(Text, default="{}")          # JSON string
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    sha256_hash: Mapped[str] = mapped_column(String(64), index=True)

    def to_dict(self) -> dict:
        """Serialise to the exact JSON shape used by the frontend."""
        import json

        return {
            "scanId": self.scan_id,
            "type": self.type,
            "input": self.input,
            "normalized": self.normalized,
            "hostname": self.hostname,
            "rootDomain": self.root_domain,
            "officialDomain": self.official_domain,
            "verdict": self.verdict,
            "score": self.score,
            "reasons": json.loads(self.reasons or "[]"),
            "features": json.loads(self.features or "{}"),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "hash": self.sha256_hash,
        }


class AssistantMessage(Base):
    """Chat messages exchanged with the AI Security Assistant."""

    __tablename__ = "assistant_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(20))     # "user" | "assistant"
    message: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sessionId": self.session_id,
            "role": self.role,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


def new_scan_id() -> str:
    return f"PG-{uuid.uuid4().hex[:12].upper()}"


class Database:
    """Small wrapper so routes can share one engine/session factory."""

    def __init__(self, url: str):
        self.engine = create_engine(url, future=True)
        self._session_factory = lambda: Session(self.engine)

    def session(self) -> Session:
        return self._session_factory()

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)


_db_instance: Database | None = None


def init_db(url: str) -> Database:
    """Create (or reuse) the global Database instance and tables."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(url)
        _db_instance.create_all()
    return _db_instance


def get_db() -> Database:
    if _db_instance is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _db_instance


# Convenience alias used in imports (database.models.db style)
class _DbProxy:
    """Proxy exposing module-level helpers under a `db` name."""

    @staticmethod
    def session() -> Session:
        return get_db().session()

    @staticmethod
    def init(url: str) -> Database:
        return init_db(url)


db = _DbProxy()
