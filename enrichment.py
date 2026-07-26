"""
enrichment.py
-------------
Extra signals for DNSGuard AI beyond the core 8 lexical features the
trained model was built on.

IMPORTANT: none of this feeds into model.predict(). The model has a fixed
input schema (query_length, subdomain_length, num_labels, avg_label_length,
entropy, digit_ratio, uncomman_tld, query_type) and changing that requires
retraining on a matching dataset. Everything here is purely DISPLAY /
CONTEXT information shown alongside the model's verdict — the same way a
real analyst would look at extra signals before deciding what to do about
an alert, without those signals having been part of the original model.
"""

import re
import socket
import ssl
from datetime import datetime

import requests

try:
    import whois
except ImportError:  # pragma: no cover
    whois = None


BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
BASE32_PATTERN = re.compile(r"^[A-Z2-7]{8,}={0,6}$")
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{8,}$")

# NOTE: TLD risk used to live here as a static allow/deny list. It has been
# replaced by proper target encoding - see tld_encoding.py.


# TLDs repeatedly flagged as high-abuse by published threat intelligence
# (Spamhaus Domain Reputation reports, Interisle Cybercrime Supply Chain
# studies, Netcraft). This tracks REAL-WORLD PHISHING/SPAM/MALWARE hosting
# abuse - a completely different signal from DNS tunneling, which is what
# the trained model detects. A domain landing on this list is NOT run
# through the model's uncommon_tld feature (which only checks a tiny
# common-vs-not list) - it's a separate, explicit lookup against TLDs with
# a documented history of bulk/cheap-registration abuse.
#
# This list will drift as abuse patterns shift - it's illustrative of the
# category, not a live-updated feed. For production use, a service like
# Spamhaus's TLD statistics (https://www.spamhaus.org/statistics/tlds/)
# should be queried directly instead of a hardcoded list.
HIGH_RISK_TLDS = {
    # Frequently cited in Spamhaus / Netcraft / Palo Alto "worst TLD" reports
    "xyz", "top", "cfd", "buzz", "loan", "men", "xin", "ooo", "cam",
    "click", "work", "party", "review", "trade", "date", "faith",
    "accountant", "science", "download", "racing", "cricket", "country",
    "stream", "surf", "monster", "quest", "bond", "rest", "autos", "lol",
    "mov", "zip", "icu", "cyou", "win", "bid", "support", "fit", "locker",
    "webcam", "vip", "live", "lat", "cn",
    # Free/very-cheap ccTLDs with a long documented history of bulk abuse
    "tk", "ml", "ga", "cf", "gq",
}


def check_tld_risk(domain):
    """
    Checks the domain's TLD against a curated high-abuse list. Returns
    {"flagged": bool, "tld": str} - purely informational, does not affect
    the model's prediction.
    """
    labels = domain.split(".")
    tld = labels[-1].lower() if labels else ""
    return {"flagged": tld in HIGH_RISK_TLDS, "tld": tld}


# ============================================================
# Lexical enrichment (pure string math, no network calls)
# ============================================================

def get_longest_label(domain):
    """Longest single label between the dots. Tunneling payloads often pile
    encoded data into one very long label rather than spreading it out."""
    labels = domain.split(".")
    return max((len(label) for label in labels), default=0)


def get_character_diversity(domain):
    """Unique characters used / total characters. Encoded/random strings
    tend to use a wider variety of characters than typical words."""
    cleaned = domain.replace(".", "")
    if not cleaned:
        return 0.0
    return round(len(set(cleaned)) / len(cleaned), 3)


def get_character_distribution(domain):
    """Rough letters/digits/special-character split, shown as percentages."""
    cleaned = domain.replace(".", "")
    total = len(cleaned) or 1
    letters = sum(c.isalpha() for c in cleaned)
    digits = sum(c.isdigit() for c in cleaned)
    special = total - letters - digits
    return {
        "letters_pct": round(letters / total * 100, 1),
        "digits_pct": round(digits / total * 100, 1),
        "special_pct": round(special / total * 100, 1),
    }


def get_randomness_score(domain):
    """
    A second, cheaper 'does this look random' signal distinct from Shannon
    entropy: real words average roughly 40% vowels, encoded/random strings
    usually don't. Returns 0 (word-like) to 1 (random-looking).
    """
    cleaned = re.sub(r"[^a-z]", "", domain.lower())
    if len(cleaned) < 3:
        return 0.0
    vowels = set("aeiou")
    vowel_ratio = sum(c in vowels for c in cleaned) / len(cleaned)
    score = min(abs(0.4 - vowel_ratio) / 0.4, 1.0)
    return round(score, 3)


def detect_encoding(domain):
    """Heuristic check on the subdomain portion for base64 / base32 / hex
    looking strings — a strong tunneling tell when combined with length."""
    labels = domain.split(".")
    candidate = "".join(labels[:-2]) if len(labels) > 2 else ""

    return {
        "base64_like": bool(candidate) and len(candidate) >= 12 and bool(BASE64_PATTERN.match(candidate)),
        "base32_like": bool(candidate) and len(candidate) >= 12 and bool(BASE32_PATTERN.match(candidate.upper())),
        "hex_like": bool(candidate) and len(candidate) >= 12 and bool(HEX_PATTERN.match(candidate)),
    }


def lexical_enrichment(domain):
    """Bundle of all the string-only enrichment features for one domain."""
    return {
        "longest_label": get_longest_label(domain),
        "character_diversity": get_character_diversity(domain),
        "character_distribution": get_character_distribution(domain),
        "randomness_score": get_randomness_score(domain),
        "encoding": detect_encoding(domain),
    }


# ============================================================
# Live network checks
# ============================================================

def check_ssl(domain, timeout=3):
    """Attempts a real TLS handshake on port 443. No API key needed —
    this is a direct socket connection, same as a browser would do."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "present": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "error": None,
                }
    except Exception as exc:
        return {"present": False, "issuer": None, "error": str(exc)}


def get_domain_age(domain):
    """
    WHOIS-based domain age. Requires the `python-whois` package.
    WHOIS servers are sometimes slow or rate-limit; failures are caught
    and reported rather than crashing the request.
    """
    if whois is None:
        return {"available": False, "error": "python-whois is not installed.", "age_days": None, "created": None}
    try:
        record = whois.whois(domain)
        created = record.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return {"available": False, "error": "No creation date returned by WHOIS.", "age_days": None, "created": None}
        age_days = (datetime.now() - created).days
        return {"available": True, "error": None, "age_days": age_days, "created": created.strftime("%Y-%m-%d")}
    except Exception as exc:
        return {"available": False, "error": str(exc), "age_days": None, "created": None}


def get_reputation(domain, api_key):
    """
    VirusTotal domain reputation lookup (free tier).
    Get your own key at https://www.virustotal.com/gui/join-us and set it
    as the VT_API_KEY environment variable before running the app.
    """
    if not api_key:
        return {
            "available": False,
            "error": "No VirusTotal API key configured. Set the VT_API_KEY environment variable.",
            "malicious": None, "harmless": None, "suspicious": None,
        }
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=5,
        )
        if resp.status_code == 404:
            return {"available": False, "error": "Domain not found in VirusTotal's database.",
                    "malicious": None, "harmless": None, "suspicious": None}
        if resp.status_code != 200:
            return {"available": False, "error": f"VirusTotal returned HTTP {resp.status_code}.",
                    "malicious": None, "harmless": None, "suspicious": None}

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "available": True,
            "error": None,
            "malicious": stats.get("malicious", 0),
            "harmless": stats.get("harmless", 0),
            "suspicious": stats.get("suspicious", 0),
        }
    except requests.exceptions.RequestException as exc:
        return {"available": False, "error": f"Request failed: {exc}",
                "malicious": None, "harmless": None, "suspicious": None}
    except Exception as exc:
        return {"available": False, "error": str(exc),
                "malicious": None, "harmless": None, "suspicious": None}
