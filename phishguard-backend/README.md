# PhishGuard Backend

REST API backend for the **PhishGuard** cybersecurity project. It replaces the
frontend's browser-side rule engine and localStorage with real server-side
analysis, SQLite persistence, dashboard statistics, evidence reports, and an
AI security assistant (Qwen LLM — API key stays on the backend only).

## Features

| Module | Endpoint | Description |
|---|---|---|
| URL Scanner | `POST /api/scan/url` | 14-feature extraction + weighted scoring (HTTPS, IP host, length, subdomains, hyphens, suspicious TLD, shortener, keywords, `@`, punycode, risky extension, brand impersonation, typosquatting via Levenshtein, known-phishing list) |
| SMS Scanner | `POST /api/scan/sms` | Smishing detection: urgency, KYC, OTP/PIN/CVV/password requests, UPI/refund/prize/cashback lures, suspicious & shortened links |
| AI Assistant | `POST /api/assistant/chat` | Explains latest scan, risk score, phishing concepts, remediation steps, viva/project questions. Uses Qwen if `QWEN_API_KEY` set; otherwise a clearly-labelled heuristic fallback (`"source": "fallback-heuristic"`). |
| History | `GET /api/history?limit=150&type=URL` | Recent scans |
| | `DELETE /api/history` | Clear all |
| | `DELETE /api/history/<scan_id>` | Delete one |
| Scan details | `GET /api/scan/<scan_id>` | Full stored scan (verdict, score, reasons, features, timestamp, SHA-256) |
| Dashboard | `GET /api/dashboard` | totalScans, safe/suspicious/phishing counts, topRiskFeatures, recentHighRiskScans |
| Evidence | `GET /api/evidence/<scan_id>` | Structured data for PDF report generation (evidence ID, verdict, score band, hostname, expected official domain, SHA-256 fingerprint, reasons) |
| Health | `GET /api/health` | `{status:"ok", service:"PhishGuard Backend", version:"1.0.0"}` |

Verdict bands: **0–34 Safe · 35–69 Suspicious · 70–100 Phishing**.
HTTPS is treated as a small trust adjustment (−5), never as proof of safety.

## Project Structure

```
phishguard-backend/
├── app.py                  # Flask app factory, health check, JSON error handlers
├── config.py               # Environment-variable configuration
├── requirements.txt
├── .env.example            # Copy to .env and fill in secrets
├── database/
│   ├── __init__.py
│   └── models.py           # SQLAlchemy models: Scan, AssistantMessage
├── routes/
│   ├── __init__.py         # Blueprint registry
│   ├── scan.py             # /api/scan/url, /api/scan/sms, /api/scan/<id>
│   ├── assistant.py        # /api/assistant/chat
│   ├── history.py          # /api/history (GET/DELETE)
│   ├── dashboard.py        # /api/dashboard
│   └── evidence.py         # /api/evidence/<scan_id>
└── services/
    ├── url_analyzer.py     # URL feature extraction + weighted scoring
    ├── sms_analyzer.py     # SMS/smishing pattern engine
    ├── brand_detector.py   # Brand registry + Levenshtein typosquat detection
    ├── scoring.py          # Score clamping, verdict bands, reason builder
    ├── hash_service.py     # SHA-256 fingerprints + scan IDs
    └── qwen_service.py     # LLM client (server-side key only) + fallback
```

## Installation

```bash
cd phishguard-backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then edit .env
```

`.env` keys:

```
DATABASE_URL=sqlite:///database/phishguard.db
QWEN_API_KEY=your-key-here      # NEVER put this in frontend JavaScript
QWEN_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
QWEN_MODEL=qwen-plus
FLASK_SECRET_KEY=change-me
```

## Run

```bash
flask --app app run --debug --port 5000
# or
python app.py
```

SQLite DB is created automatically on first run. CORS is enabled for `/api/*`.

## Example Requests

```bash
curl -X POST http://127.0.0.1:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypa1.com/login?verify=account"}'

curl -X POST http://127.0.0.1:5000/api/scan/sms \
  -H "Content-Type: application/json" \
  -d '{"message": "Your KYC will expire today. Verify now, share OTP."}'

curl -X POST http://127.0.0.1:5000/api/assistant/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Why is this URL phishing?", "context": {"latestScan": {}}}'

curl "http://127.0.0.1:5000/api/history?limit=150"
curl http://127.0.0.1:5000/api/dashboard
curl http://127.0.0.1:5000/api/scan/PG-XXXXXXXXXXXX
curl http://127.0.0.1:5000/api/evidence/PG-XXXXXXXXXXXX
curl http://127.0.0.1:5000/api/health
```

Errors are always JSON: `{"success": false, "error": "Invalid URL"}` with
proper HTTP status codes (400 / 404 / 405 / 415 / 500).

## Frontend Integration

Keep your existing HTML/CSS/UI unchanged. Replace only the bodies of the
functions that currently do local analysis or use localStorage:

```js
const API = "http://127.0.0.1:5000/api";

// scanURL()            -> await fetch(`${API}/scan/url`, {method:"POST", ...})
// scanSMS()            -> await fetch(`${API}/scan/sms`, ...)
// sendAssistantMessage -> await fetch(`${API}/assistant/chat`, ...)
// Dashboard loader     -> await fetch(`${API}/dashboard`)
// History loader       -> await fetch(`${API}/history?limit=150`)
// Evidence/PDF         -> await fetch(`${API}/evidence/${scanId}`)
```

Responses contain `verdict`, `score`, `reasons[]`, `features{}`, `scanId`,
`hash` — feed them into your existing render functions.

## Extending with Machine Learning

Every stored scan keeps its full `features` dict — that is already a feature
vector. To add an ML classifier later: export rows from the `scans` table,
train Random Forest / XGBoost, and swap the call inside
`services/scoring.analyze_result()` behind the same API contract. The brand
list in `services/brand_detector.py` and threat lists in
`services/url_analyzer.py` / `sms_analyzer.py` are plain Python sets/dicts —
edit them freely or load them from a feed.
