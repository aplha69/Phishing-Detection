"""URL phishing analyzer for PhishGuard.

Pure, deterministic feature extraction + weighted scoring. HTTPS is treated
as a small positive signal only — it is NEVER trusted as proof of safety.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, unquote

from services import brand_detector
from services.scoring import analyze_result, make_reason

# ---------------------------------------------------------------------------
# Configurable threat intelligence lists (extend freely)
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "pw", "cc", "top", "xyz", "vip",
    "click", "link", "download", "work", "men", "loan", "racing",
    "stream", "win", "bid", "date", "zip", "mov", "cam", "rest",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorte.st", "adf.ly", "rb.gy", "cutt.ly", "rebrand.ly",
    "tr.im", "cli.gs", "lnkd.in", "yo.rl", "s.id", "shrinkme.io",
    "ouo.io", "za.gl", "v.gd", "j.mp", "tiny.cc",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "password", "credentials", "banking",
    "wallet", "refund", "unlock", "suspend", "confirm", "identity",
    "payment", "invoice", "reset", "auth", "access", "alert", "urgent",
    "prize", "winner", "gift", "bonus", "claim", "lottery", "kyc", "pan",
]

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".pif", ".jar",
    ".vbs", ".js", ".hta", ".apk", ".zip", ".rar", ".docm", ".xlsm",
    ".docx", ".xlsx", ".pdf", ".html", ".htm", ".php",
]  # NOTE: '.com' intentionally excluded — it is a TLD, not a file extension

# Small curated list of known-bad domains (replace/extend with a feed or ML model)
KNOWN_PHISHING_DOMAINS = {
    "paypal-support-login.tk",
    "facebook-security-check.xyz",
    "appleid-verify.account-recovery.ml",
    "sbi-kyc-update.top",
    "paytm-kyc-verify.click",
    "google-drive-file-share.zip",
    "amazon-prize-winner.work",
}

IP_HOSTNAME_POINTS = 30
HTTPS_TRUST_BONUS = -5    # tiny trust adjustment; HTTPS alone never proves safety
LONG_URL_POINTS = 10
SUBDOMAIN_POINTS = 12     # per extra level above 3, capped
HYPHEN_POINTS = 8         # per cluster of hyphens in hostname, capped
SUS_TLD_POINTS = 20
SHORTENER_POINTS = 15
KEYWORD_POINTS = 6        # per suspicious keyword hit, capped
AT_SYMBOL_POINTS = 25
PUNYCODE_POINTS = 25
EXTENSION_POINTS = 20
BRAND_IMPERSONATION_POINTS = 40
TYPOSQUAT_POINTS = 45
KNOWN_PHISH_POINTS = 60


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _validate_host(host: str) -> None:
    """Raise ValueError for syntactically invalid hostnames.

    Accepts multi-label TLDs like onlinesbi.sbi and single-label hosts like
    'localhost'; rejects underscores, spaces, percent signs and other
    characters that cannot appear in a real hostname.
    """
    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid URL: '{host}' is not a valid hostname")


def normalize_url(raw: str) -> str:
    """Add scheme if missing and strip whitespace."""
    u = (raw or "").strip()
    if not u:
        return ""
    if any(c.isspace() for c in u):
        raise ValueError("Invalid URL: input contains whitespace")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", u):
        # e.g. "example.com/login" or "//example.com"
        if u.startswith("//"):
            u = "http:" + u
        else:
            u = "http://" + u
    return u


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(url: str) -> dict:
    """Extract all URL features used by the scoring engine."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "")
    full = normalized.lower()

    subdomains = []
    if host and not _is_ip_host(host):
        labels = host.split(".")
        root = brand_detector.root_domain(host)
        if len(labels) > 2 and host != root and not host.endswith("." + root):
            subdomains = labels[:-2]
        elif len(labels) > 3:
            subdomains = labels[: len(labels) - 3] if root.count(".") == 1 else labels[:-2]

    tld = host.rsplit(".", 1)[-1] if "." in host and not _is_ip_host(host) else ""

    keyword_hits = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in full})
    ext_hit = next(
        (ext for ext in RISKY_EXTENSIONS if re.search(re.escape(ext) + r"(?:[/?&#]|$)", full)),
        None,
    )

    features = {
        "scheme": parsed.scheme or "",
        "https": parsed.scheme.lower() == "https",
        "hostname": host,
        "isIPAddress": _is_ip_host(host),
        "rootDomain": brand_detector.root_domain(host) if host else "",
        "port": parsed.port,
        "path": path,
        "query": parsed.query or "",
        "urlLength": len(normalized),
        "subdomainCount": max(len(subdomains), 0),
        "subdomains": subdomains,
        "hyphenCountHost": host.count("-"),
        "tld": tld,
        "suspiciousTLD": tld in SUSPICIOUS_TLDS,
        "isShortener": host in URL_SHORTENERS,
        "suspiciousKeywords": keyword_hits,
        "hasAtSymbol": "@" in normalized.replace("mailto:", "", 1),
        "punycode": ("xn--" in host),
        "riskyExtension": ext_hit,
        "brandImpersonation": brand_detector.detect_brand_impersonation(host, path),
        "knownPhishingDomain": host in KNOWN_PHISHING_DOMAINS
        or (brand_detector.root_domain(host) in KNOWN_PHISHING_DOMAINS if host else False),
    }
    return features


def analyze_url(url: str, safe_max: int = 34, suspicious_max: int = 69) -> dict:
    """Run feature extraction + weighted scoring on one URL.

    Returns a dict ready to be serialised / stored:
        verdict, score, reasons[], features{}, normalized, hostname,
        rootDomain, officialDomain
    """
    normalized = normalize_url(url)
    if not normalized:
        raise ValueError("Empty URL")
    parsed = urlparse(normalized)
    if not parsed.hostname:
        raise ValueError("Invalid URL: no hostname could be parsed")
    _validate_host(parsed.hostname)

    f = extract_features(url)
    reasons: list[dict] = []

    # --- Positive signal: HTTPS (small trust adjustment, never trusted blindly)
    if f["https"]:
        reasons.append(make_reason(
            "HTTPS Enabled", HTTPS_TRUST_BONUS,
            "Connection uses HTTPS. Note: HTTPS only encrypts traffic — many "
            "phishing sites use free TLS certificates, so this is NOT proof of safety.",
        ))

    # --- IP address hostname -------------------------------------------------
    if f["isIPAddress"]:
        reasons.append(make_reason(
            "IP Address Hostname", IP_HOSTNAME_POINTS,
            f"URL points directly at an IP address ({f['hostname']}). "
            "Legitimate services almost always use domain names.",
        ))

    # --- Long URL ------------------------------------------------------------
    if f["urlLength"] > 100:
        reasons.append(make_reason(
            "Excessive URL Length", LONG_URL_POINTS,
            f"URL is {f['urlLength']} characters long (>100). Long URLs hide "
            "the real domain and can carry extra malicious parameters.",
        ))

    # --- Subdomains ----------------------------------------------------------
    if f["subdomainCount"] >= 2:
        pts = min(SUBDOMAIN_POINTS * (f["subdomainCount"] - 1), 24)
        reasons.append(make_reason(
            "Deep Subdomain Structure", pts,
            f"Found {f['subdomainCount']} subdomain levels "
            f"({'.'.join(f['subdomains'])}). Attackers abuse subdomains to fake "
            "brand names in the visible part of the URL.",
        ))

    # --- Hyphens -------------------------------------------------------------
    if f["hyphenCountHost"] >= 2:
        pts = min(HYPHEN_POINTS * (f["hyphenCountHost"] - 1), 16)
        reasons.append(make_reason(
            "Hyphenated Domain", pts,
            f"Hostname contains {f['hyphenCountHost']} hyphens. Legitimate brands "
            "rarely use hyphenated look-alike domains such as 'paypal-verify.com'.",
        ))

    # --- Suspicious TLD ------------------------------------------------------
    if f["suspiciousTLD"]:
        reasons.append(make_reason(
            "Suspicious TLD", SUS_TLD_POINTS,
            f"Top-level domain '.{f['tld']}' is heavily abused in phishing "
            "campaigns due to free/cheap registration.",
        ))

    # --- URL shortener -------------------------------------------------------
    if f["isShortener"]:
        reasons.append(make_reason(
            "URL Shortener Detected", SHORTENER_POINTS,
            f"'{f['hostname']}' is a link shortener. The true destination is "
            "hidden, which prevents visual inspection of the target domain.",
        ))

    # --- Suspicious keywords -------------------------------------------------
    if f["suspiciousKeywords"]:
        pts = min(KEYWORD_POINTS * len(f["suspiciousKeywords"]), 24)
        reasons.append(make_reason(
            "Credential-Bait Keywords", pts,
            "URL contains security-sensitive keywords: "
            + ", ".join(f["suspiciousKeywords"][:8])
            + ". Login/verify keywords in URLs are common in credential-harvesting pages.",
        ))

    # --- @ symbol ------------------------------------------------------------
    if f["hasAtSymbol"]:
        reasons.append(make_reason(
            "@ Symbol In URL", AT_SYMBOL_POINTS,
            "A '@' before the hostname tricks some parsers/users — everything "
            "before @ is ignored and the real host is after it (classic obfuscation).",
        ))

    # --- Punycode ------------------------------------------------------------
    if f["punycode"]:
        reasons.append(make_reason(
            "Punycode / Homograph Risk", PUNYCODE_POINTS,
            "Hostname uses 'xn--' punycode encoding, which can render Unicode "
            "look-alike characters (homograph attacks mimicking apple.com etc.).",
        ))

    # --- Risky file extension ------------------------------------------------
    if f["riskyExtension"]:
        reasons.append(make_reason(
            "Risky File Extension", EXTENSION_POINTS,
            f"URL references a '{f['riskyExtension']}' file, likely a download "
            "payload (malware/APK) rather than a web page.",
        ))

    # --- Brand impersonation / typosquatting ---------------------------------
    imp = f["brandImpersonation"]
    if imp:
        if imp["technique"] == "typosquatting":
            reasons.append(make_reason(
                "Typosquatted Brand Domain", TYPOSQUAT_POINTS,
                imp["explanation"],
            ))
        else:
            reasons.append(make_reason(
                "Brand Impersonation", BRAND_IMPERSONATION_POINTS,
                imp["explanation"],
            ))

    # --- Known phishing domain ----------------------------------------------
    if f["knownPhishingDomain"]:
        reasons.append(make_reason(
            "Known Phishing Domain", KNOWN_PHISH_POINTS,
            f"'{f['rootDomain']}' matches the internal blocklist of confirmed "
            "phishing domains.",
        ))

    score, verdict = analyze_result(reasons, safe_max, suspicious_max)

    return {
        "normalized": normalized,
        "hostname": f["hostname"],
        "rootDomain": f["rootDomain"],
        "officialDomain": (imp["officialDomain"] if imp else None),
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "features": f,
    }
