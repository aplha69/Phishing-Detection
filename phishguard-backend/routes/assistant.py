"""AI Security Assistant endpoint.

POST /api/assistant/chat

The Qwen API key is stored ONLY in backend environment variables and is never
sent to the browser. If the LLM is unavailable, an honest heuristic fallback
explains scans locally (never fabricated scan data).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request

from database.models import AssistantMessage
from services import qwen_service

assistant_bp = Blueprint("assistant", __name__)


@assistant_bp.post("/chat")
def chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"success": False, "error": "Message is required"}), 400

    context = data.get("context") if isinstance(data.get("context"), dict) else None
    session_id = (data.get("sessionId") or "").strip() or f"anon-{uuid.uuid4().hex[:10]}"

    cfg = current_app.config
    db = current_app.extensions["phishguard_db"]

    # Recent conversation history for this session (backend-side memory)
    with db.session() as session:
        rows = (
            session.query(AssistantMessage)
            .filter(AssistantMessage.session_id == session_id)
            .order_by(AssistantMessage.timestamp.desc())
            .limit(6)
            .all()
        )
        history = [r.to_dict() | {"message": r.message} for r in reversed(rows)]

        used_fallback = False
        try:
            reply = qwen_service.ask_qwen(
                message=message,
                context=context,
                history=history,
                api_key=cfg["QWEN_API_KEY"],
                base_url=cfg["QWEN_BASE_URL"],
                model=cfg["QWEN_MODEL"],
                timeout=cfg["QWEN_TIMEOUT"],
            )
        except RuntimeError as exc:
            current_app.logger.warning("LLM unavailable, using fallback: %s", exc)
            reply = qwen_service.fallback_reply(message, context)
            used_fallback = True

        now = datetime.now(timezone.utc)
        session.add(AssistantMessage(
            session_id=session_id, role="user", message=message, timestamp=now,
        ))
        session.add(AssistantMessage(
            session_id=session_id, role="assistant", message=reply,
            timestamp=datetime.now(timezone.utc),
        ))
        session.commit()

    return jsonify({
        "success": True,
        "reply": reply,
        "timestamp": now.isoformat(),
        "sessionId": session_id,
        "source": "fallback-heuristic" if used_fallback else "qwen-llm",
    }), 200
