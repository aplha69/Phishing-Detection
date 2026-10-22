"""SHA-256 fingerprinting for scan inputs (evidence integrity)."""
import hashlib


def sha256_of(text: str) -> str:
    """Return the hex SHA-256 digest of the given text."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()
