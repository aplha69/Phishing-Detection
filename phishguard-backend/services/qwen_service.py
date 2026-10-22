"""Qwen / LLM integration for the PhishGuard AI Security Assistant.

SECURITY: The API key lives ONLY on the backend (environment variable).
It is never returned to, or accepted from, the browser.

If no API key is configured, or the remote call fails, a deterministic
rule-based fallback assistant answers common security questions so the
project keeps working offline (this is NOT a fake scan result — it only
powers the chat assistant).
"""
from __future__ import annotations

import json
import logging

import requests

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are PhishGuard's AI Security Assistant, embedded in a \
cybersecurity student project that detects phishing URLs, smishing SMS and brand \
impersonation using weighted rule-based feature analysis, backed by a Flask + \
SQLite + SQLAlchemy REST API.

Your duties:
- Explain the latest scan result (verdict, 0-100 risk score, reasons) provided in \
the conversation context.
- Explain risk-score bands: 0-34 Safe, 35-69 Suspicious, 70-100 Phishing.
- Explain why a URL/SMS is suspicious, phishing concepts (typosquatting, \
homograph/punycode, brand impersonation, urgency tactics, OTP/CVV/KYC scams).
- Give safe actions and incident-response steps after clicking a phishing link \
(disconnect, change passwords from a trusted device, enable 2FA, monitor bank \
accounts, report to cybercrime.gov.in / 1930, revoke sessions).
- Answer academic viva questions about THIS project: architecture (HTML/JS \
frontend -> fetch() -> Flask blueprints -> analyzer services -> weighted \
scoring -> SQLite history -> evidence with SHA-256 fingerprint), the algorithm \
(feature extraction + Levenshtein typosquat detection + weighted scoring + \
classification thresholds), and future scope (ML classifier such as Random \
Forest/XGBoost or a neural model, live threat feeds like PhishTank/Google \
Safe Browsing, WHOIS/domain-age checks, browser extension, mobile app).
- Be concise, structured (short paragraphs/bullets), and never invent scan data.

If asked to do something outside cybersecurity/project help, politely refuse and \
steer back to the topic."""


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _build_messages(message: str, context: dict | None, history: list[dict] | None) -> list[dict]:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    ctx = (context or {}).get("latestScan") if context else None
    if ctx:
        slim = {
            k: ctx.get(k)
            for k in ("type", "input", "verdict", "score", "hostname",
                      "rootDomain", "officialDomain", "timestamp")
        }
        slim["topReasons"] = [
            {"label": r.get("label"), "points": r.get("points")}
            for r in (ctx.get("reasons") or [])[:8]
        ]
        messages.append({
            "role": "system",
            "content": "Latest scan context (authoritative, produced by the "
                       "PhishGuard analyzer): " + json.dumps(slim, ensure_ascii=False),
        })

    for h in (history or [])[-6:]:
        role = h.get("role")
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": str(h.get("message", ""))[:2000]})

    messages.append({"role": "user", "content": message[:4000]})
    return messages


def ask_qwen(
    message: str,
    context: dict | None = None,
    history: list[dict] | None = None,
    api_key: str = "",
    base_url: str = "",
    model: str = "qwen-plus",
    timeout: int = 30,
) -> str:
    """Call the Qwen chat-completions endpoint (OpenAI-compatible mode).

    Raises RuntimeError if the remote call fails; caller decides fallback.
    """
    if not api_key:
        raise RuntimeError("QWEN_API_KEY is not configured on the backend")

    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": _build_messages(message, context, history),
        "temperature": 0.4,
        "max_tokens": 700,
    }
    try:
        resp = requests.post(url, headers=_headers(api_key), json=payload, timeout=timeout)
    except requests.RequestException as exc:
        raise RuntimeError(f"LLM request failed: {exc}") from exc

    if resp.status_code != 200:
        raise RuntimeError(f"LLM error HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    except (ValueError, KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected LLM response format: {exc}") from exc


# ---------------------------------------------------------------------------
# Offline fallback (deterministic, honest — clearly labelled as heuristic help)
# ---------------------------------------------------------------------------
def fallback_reply(message: str, context: dict | None) -> str:
    low = (message or "").lower()
    scan = (context or {}).get("latestScan") or {}

    def scan_summary() -> str:
        if not scan:
            return ""
        reasons = scan.get("reasons") or []
        top = "; ".join(r.get("label", "?") for r in reasons[:5]) or "no flags raised"
        return (
            f"About your latest scan — input: “{str(scan.get('input', ''))[:120]}” "
            f"({scan.get('type', 'URL')}). Verdict: **{scan.get('verdict')}** with risk "
            f"score {scan.get('score')}/100. Main signals: {top}."
        )

    if any(w in low for w in ("after clicking", "clicked", "what do i do", "already entered", "compromised")):
        return (
            "If you interacted with a phishing page:\n"
            "1. Disconnect the device from Wi-Fi/mobile data.\n"
            "2. From a *known-safe* device, change the affected password and sign out all sessions.\n"
            "3. Enable 2FA everywhere; contact your bank to freeze the card if CVV/UPI details were shared.\n"
            "4. Never share an OTP — no legitimate company asks for it.\n"
            "5. Report in India at cybercrime.gov.in or dial 1930; keep the SMS/URL as evidence.\n"
            + ("\n\n" + scan_summary() if scan else "")
        )
    if "score" in low or ("why" in low and scan):
        band = "Safe (0–34)" if scan.get("score", 0) <= 34 else (
            "Suspicious (35–69)" if scan.get("score", 0) <= 69 else "Phishing (70–100)")
        return (
            f"{scan_summary()}\n\n"
            f"The score is the sum of weighted feature points, capped at 100. This falls in the {band} band. "
            "Each reason lists the exact points it contributed, so the decision is fully explainable.\n\n"
            "Note: HTTPS alone never proves safety — scammers use free TLS certificates."
        )
    if any(w in low for w in ("algorithm", "architecture", "viva", "how does it work", "project", "future scope", "working")):
        return (
            "PhishGuard architecture: an HTML/CSS/JS frontend calls this Flask REST API via fetch(). "
            "Blueprints (scan, assistant, history, dashboard) delegate to service modules: "
            "url_analyzer extracts ~14 features (HTTPS, IP host, length, subdomains, hyphens, TLD, shortener, "
            "keywords, @ symbol, punycode, file extension, brand spoofing, typosquatting, blocklist); "
            "brand_detector uses Levenshtein edit distance with leet-normalisation against an official-brand registry; "
            "sms_analyzer matches urgency/KYC/OTP/CVV/refund/prize patterns and scans embedded links; "
            "scoring sums weights into 0–100 and classifies 0–34 Safe, 35–69 Suspicious, 70–100 Phishing. "
            "Results persist in SQLite via SQLAlchemy with a SHA-256 fingerprint for tamper-evident evidence reports. "
            "The assistant uses the Qwen LLM through the backend only (API key stays server-side). "
            "Future scope: train an ML classifier (Random Forest/XGBoost) on extracted features, add PhishTank/Google "
            "Safe Browsing feeds, WHOIS domain-age checks, a browser extension and a mobile app."
        )
    if any(w in low for w in ("sms", "smishing", "kyc", "otp")):
        return (
            "Smishing = phishing over SMS. Red flags: urgency ('KYC expires today'), threats "
            "('account blocked'), rewards ('you won/cashback'), credential demands (OTP/PIN/CVV), "
            "shortened or look-alike links. Banks never ask for OTP/PIN by SMS. "
            "Paste the message into the SMS Scanner for a scored, explainable verdict."
            + ("\n\n" + scan_summary() if scan else "")
        )
    if scan:
        return scan_summary() + "\n\nAsk me to explain the score, the reasons, or what to do next."
    return (
        "I'm the PhishGuard AI Security Assistant. I can explain scan results, risk scores, "
        "phishing/smishing concepts, safe actions after a click, and the project's algorithm "
        "for your viva. (Heuristic reply — configure QWEN_API_KEY on the backend for full LLM answers.)"
    )
