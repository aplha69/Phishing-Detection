"""Brand & typosquatting detection for PhishGuard.

Maintains a configurable list of official brands/domains and uses
Levenshtein edit-distance similarity to spot look-alike domains such as:

    paypa1.com   -> PayPal   (paypal.com)
    faceb00k.com -> Facebook (facebook.com)
    paytm-login-example.com -> Paytm (paytm.com)  [brand keyword in subdomain]
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Configurable brand registry: brand name -> official domain(s)
# Add / remove entries freely; the detector reads only from this dict.
# ---------------------------------------------------------------------------
OFFICIAL_BRANDS: dict[str, list[str]] = {
    "Facebook": ["facebook.com", "messenger.com", "instagram.com", "whatsapp.com"],
    "Google": ["google.com", "gmail.com", "youtube.com"],
    "Microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "Apple": ["apple.com", "icloud.com"],
    "Amazon": ["amazon.com", "amazon.in"],
    "PayPal": ["paypal.com"],
    "Netflix": ["netflix.com"],
    "WhatsApp": ["whatsapp.com"],
    "PhonePe": ["phonepe.com"],
    "Paytm": ["paytm.com", "paytm.in"],
    "SBI": ["onlinesbi.sbi", "sbi.co.in"],
    "HDFC": ["hdfcbank.com", "hdfc.com"],
    "ICICI": ["icicibank.com", "icici.com"],
    "Axis": ["axisbank.com", "axis.bank"],
}

# Common character substitutions used by attackers (leet-speak normalisation)
LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)

MULTI_PART_TLDS = {
    "co.in", "co.uk", "com.au", "com.br", "org.in", "net.in",
    "gov.in", "ac.in", "co.za", "com.cn",
}


def _brand_tokens(brand: str) -> set[str]:
    """Lowercase alphanumeric tokens of a brand name."""
    return {t for t in re.split(r"[^a-z0-9]+", brand.lower()) if len(t) >= 3}


# Brand keywords that often appear inside phishing hostnames/paths
BRAND_KEYWORDS = {
    brand: _brand_tokens(brand)
    for brand in OFFICIAL_BRANDS
}


def levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def normalize_domain(domain: str) -> str:
    """Lowercase, strip leading www., keep only the hostname part."""
    d = (domain or "").strip().lower()
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1]
    if d.startswith("www."):
        d = d[4:]
    return d


def root_domain(host: str) -> str:
    """Return the registrable root domain (handles co.in style TLDs)."""
    host = normalize_domain(host)
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return last_two


def _leet(s: str) -> str:
    return s.translate(LEET_MAP)


def similarity(a: str, b: str) -> float:
    """0..1 similarity between two strings using Levenshtein distance."""
    if not a or not b:
        return 0.0
    dist = min(
        levenshtein(a, b),
        levenshtein(_leet(a), _leet(b)),  # catches paypa1 <-> paypal
    )
    return 1.0 - dist / max(len(a), len(b))


def all_official_domains() -> list[tuple[str, str]]:
    """Flat list of (brand, domain) pairs."""
    return [(brand, dom) for brand, doms in OFFICIAL_BRANDS.items() for dom in doms]


def detect_brand_impersonation(hostname: str, path: str = "") -> dict | None:
    """Detect brand impersonation / typosquatting on a hostname.

    Returns a dict with keys: brand, officialDomain, matchedDomain,
    technique, similarity, explanation — or None if nothing found.
    """
    host = normalize_domain(hostname)
    if not host:
        return None
    rd = root_domain(host)
    rd_label = rd.split(".")[0]  # e.g. 'paypa1' from 'paypa1.com'

    best: dict | None = None

    for brand, domains in OFFICIAL_BRANDS.items():
        for official in domains:
            off_root = root_domain(official)
            off_label = off_root.split(".")[0]

            # 1. Exact official domain -> NOT impersonation
            if rd == off_root:
                return None if best is None else best  # genuine domain wins

            # 2. Typosquat: high similarity but not identical
            sim = similarity(rd_label, off_label)
            if rd != off_root and sim >= 0.75 and len(rd_label) >= 4:
                cand = {
                    "brand": brand,
                    "officialDomain": official,
                    "matchedDomain": rd,
                    "technique": "typosquatting",
                    "similarity": round(sim, 3),
                    "explanation": (
                        f"Domain '{rd}' is a near-identical look-alike of the "
                        f"official {brand} domain '{official}' "
                        f"(similarity {sim:.0%}). This is classic typosquatting."
                    ),
                }
                if best is None or cand["similarity"] > best["similarity"]:
                    best = cand

            # 3. Brand token embedded in a non-official domain
            #    e.g. paytm-login-example.com, facebook-security.tk
            tokens = BRAND_KEYWORDS.get(brand, {off_label})
            host_labels = [l for l in re.split(r"[.\-_]", host) if l]
            for tok in tokens:
                if tok in host_labels and rd != off_root:
                    cand = {
                        "brand": brand,
                        "officialDomain": official,
                        "matchedDomain": rd,
                        "technique": "brand-keyword-in-domain",
                        "similarity": round(sim, 3),
                        "explanation": (
                            f"The registered domain '{rd}' embeds the brand name "
                            f"'{brand}' but is NOT the official {official} domain. "
                            f"Attackers register '<brand>-something.tld' domains to "
                            f"impersonate legitimate services."
                        ),
                    }
                    if best is None or cand["similarity"] > best["similarity"]:
                        best = cand
                    break

    return best


def find_brand_in_text(text: str) -> list[str]:
    """Return brand names mentioned anywhere in free text (e.g. SMS body)."""
    found: list[str] = []
    low = (text or "").lower()
    for brand, domains in OFFICIAL_BRANDS.items():
        tokens = set(BRAND_KEYWORDS.get(brand, set()))
        for dom in domains:
            tokens.add(root_domain(dom).split(".")[0])
        if brand.lower() in low or any(t in low for t in tokens):
            found.append(brand)
    return found


def expected_official_domain(hostname: str) -> str | None:
    """If hostname looks like a spoof of a known brand, return the real domain."""
    hit = detect_brand_impersonation(hostname)
    return hit["officialDomain"] if hit else None
