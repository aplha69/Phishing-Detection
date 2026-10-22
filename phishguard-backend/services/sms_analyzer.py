"""SMS / smishing analyzer for PhishGuard.

Weighted keyword + link analysis of an SMS message body. Returns explainable
reasons, extracted features, a 0-100 score and a Safe/Suspicious/Phishing verdict.
"""
from __future__ import annotations

import re

from services import brand_detector, url_analyzer
from services.scoring import analyze_result, make_reason

# ---------------------------------------------------------------------------
# Configurable smishing signal categories: label -> (points, [regex patterns])
# ---------------------------------------------------------------------------
SMS_PATTERNS: list[tuple[str, int, list[str]]] = [
    ("Urgency / Time Pressure", 12, [
        r"\b(today|tonight|immediately|right now|hurry|expires?|expiring|"
        r"last chance|within \d+ (hours?|minutes?|days?)|deadline|urgent)\b",
    ]),
    ("Account Blocked / Suspended Threat", 18, [
        r"\b(blocked|blocked\.?|suspended|suspend|deactivated|disabled|frozen|"
        r"on hold|closed|restricted)\b.{0,40}\b(account|card|upi|wallet|number)?",
        r"\b(account|card|upi|wallet).{0,40}\b(blocked|suspended|deactivated|disabled|frozen)\b",
    ]),
    ("KYC / PAN Pressure", 16, [
        r"\bkyc\b", r"\bpan card\b", r"\bupdate.{0,20}kyc\b", r"\bkyc.{0,20}(expire|verify|update)\b",
    ]),
    ("Banking / Payment Pressure", 12, [
        r"\b(bank|account|balance|transaction|payment|transfer|neft|imps|rtgs|"
        r"loan|emi|due)\b",
    ]),
    ("UPI Reference", 8, [
        r"\bupi\b", r"\bupi\s?(pin|collect|request|money)?\b", r"\bpaytm\b", r"\bphonepe\b",
    ]),
    ("Refund / Compensation Bait", 12, [
        r"\b(refund|compensation|reimburse|credited|amount.{0,20}(received|returned))\b",
    ]),
    ("Prize / Reward / Lottery Bait", 15, [
        r"\b(prize|winner|won|lucky draw|lottery|reward|congratulations|you have been selected|"
        r"gift ?card|voucher)\b",
    ]),
    ("Cashback Bait", 10, [
        r"\bcash ?back\b",
    ]),
    ("OTP Request", 20, [
        r"\b(share|send|tell|enter|read out|provide|don'?t share).{0,30}\botp\b",
        r"\botp\b.{0,30}\b(share|valid|expire)\b",
        r"\b(one time password|verification code)\b",
    ]),
    ("PIN / CVV / Password Request", 22, [
        r"\b(pin|cvv|cvc|password|passcode|security code|atm pin)\b",
        r"\b(enter|type|share|update|verify).{0,25}\b(pin|cvv|password|passcode)\b",
    ]),
    ("Credential Request", 18, [
        r"\b(login|log in|username|credentials|net ?banking|internet banking|"
        r"sign in|account details|card details|debit card|credit card)\b",
    ]),
    ("Suspicious Link", 15, [
        r"https?://\S+", r"\bwww\.\S+", r"\b\w+\.(tk|ml|ga|cf|gq|xyz|top|click|link|zip|work)/?\b",
    ]),
    ("Shortened URL", 12, [
        r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy|cutt\.ly|tiny\.cc|t\.iny\.it|s\.id|rebrand\.ly)\b",
    ]),
    ("Impersonation Of Sender", 10, [
        r"\b(from|team|department|support|helpline|customer care|official)\b",
        r"\b(bank of|sbi|hdfc|icici|axis|paypal|amazon|google|apple|facebook|whatsapp|netflix)\b",
    ]),
    ("Call Back / Number Pressure", 8, [
        r"\b(call|dial|contact).{0,25}\b(\+?\d[\d\s\-]{7,})\b",
        r"\b(helpline|customer care|toll free).{0,20}(\+?\d[\d\s\-]{7,})?",
        r"\b\+91[\d\s\-]{10}\b",
    ]),
    ("Money Amount Mention", 6, [
        r"(₹|rs\.?|inr)\s?\d[\d,]*", r"\b\d[\d,]*\s?(rupees|rs|inr)\b",
    ]),
    ("Greeting-Free Spam Style", 6, [
        r"^(hi|dear|respected)[ ,]", r"\b(dear customer|respected sir|valued customer)\b",
    ]),
]

ALL_CAP_SENTENCE_POINTS = 6
LINK_COUNT_POINTS = 8   # additional per link beyond the first


def extract_links(message: str) -> list[str]:
    return re.findall(r"(?:https?://|www\.)[^\s]+|\b[a-z0-9.\-]+\.(?:tk|ml|ga|cf|xyz|top|click|zip|work)\b",
                      message or "", flags=re.IGNORECASE)


def analyze_sms(message: str, safe_max: int = 34, suspicious_max: int = 69) -> dict:
    """Analyze one SMS body. Raises ValueError on empty input."""
    text = (message or "").strip()
    if not text:
        raise ValueError("Empty SMS message")

    reasons: list[dict] = []
    links = extract_links(text)
    shortened = [l for l in links if any(
        s in l.lower() for s in
        ("bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy",
         "cutt.ly", "tiny.cc", "s.id", "rebrand.ly")
    )]

    matched_categories: list[str] = []
    for label, points, patterns in SMS_PATTERNS:
        hit = None
        for pat in patterns:
            m = re.search(pat, text, flags=re.IGNORECASE)
            if m:
                hit = m.group(0).strip()
                break
        if hit:
            # Skip generic "Suspicious Link"/"Shortened URL" duplication noise:
            # keep both but they carry different weights already.
            matched_categories.append(label)
            reasons.append(make_reason(
                label, points,
                f"Matched pattern '{hit[:60]}' — this is a common smishing tactic.",
            ))

    # Extra links beyond the first
    if len(links) > 1:
        reasons.append(make_reason(
            "Multiple Links In Message", LINK_COUNT_POINTS * (len(links) - 1),
            f"Message contains {len(links)} links; legitimate alerts rarely do.",
        ))

    # ALL-CAPS shouting sentence
    caps = re.findall(r"[A-Z][A-Z0-9 !,.?]{15,}", text)
    if caps:
        reasons.append(make_reason(
            "Shouting / ALL CAPS Text", ALL_CAP_SENTENCE_POINTS,
            "Message contains long ALL-CAPS segments, a pressure tactic typical of scams.",
        ))

    # Brand impersonation inside embedded links
    spoof_brands: list[str] = []
    official_domain = None
    for link in links:
        try:
            feats = url_analyzer.extract_features(link)
        except ValueError:
            continue
        imp = feats.get("brandImpersonation")
        if imp:
            spoof_brands.append(imp["brand"])
            official_domain = official_domain or imp["officialDomain"]
            reasons.append(make_reason(
                "Brand-Spoofing Link In SMS", 30,
                imp["explanation"],
            ))

    # Brands mentioned in text (context only, low weight)
    mentioned = brand_detector.find_brand_in_text(text)
    if mentioned and "Impersonation Of Sender" in matched_categories:
        reasons.append(make_reason(
            "Trusted Brand Named As Sender", 6,
            f"Message claims association with: {', '.join(sorted(set(mentioned)))}. "
            "Verify via the official app/website — never via links in SMS.",
        ))

    score, verdict = analyze_result(reasons, safe_max, suspicious_max)

    features = {
        "length": len(text),
        "wordCount": len(text.split()),
        "links": links,
        "shortenedLinks": shortened,
        "matchedCategories": sorted(set(matched_categories)),
        "brandsMentioned": sorted(set(mentioned)),
        "brandsSpoofedInLinks": sorted(set(spoof_brands)),
        "allCapsSegments": len(caps),
        "hasDigitsSequence": bool(re.search(r"\d[\d\s\-+()]{7,}", text)),
    }

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "features": features,
        "officialDomain": official_domain,
    }
