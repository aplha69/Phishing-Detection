"""Configuration for the PhishGuard backend.

All secrets come from environment variables (see .env.example).
The LLM API key is NEVER exposed to the frontend.
"""
import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Central Flask/SQLAlchemy/LLM configuration."""

    # --- Database -----------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///phishguard.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Flask --------------------------------------------------------------
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
    JSON_SORT_KEYS = False

    # --- Qwen / OpenAI-compatible LLM (backend only!) -----------------------
    QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")
    QWEN_BASE_URL = os.getenv(
        "QWEN_BASE_URL",
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen-plus")
    QWEN_TIMEOUT = int(os.getenv("QWEN_TIMEOUT", "30"))

    # --- Scoring thresholds ---------------------------------------------------
    SAFE_MAX = 34          # 0-34  -> Safe
    SUSPICIOUS_MAX = 69    # 35-69 -> Suspicious, 70-100 -> Phishing

    VERSION = "1.0.0"
    SERVICE_NAME = "PhishGuard Backend"
