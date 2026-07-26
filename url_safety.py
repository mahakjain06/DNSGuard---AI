"""
url_safety.py
-------------
A second, complementary check to the DNS-tunneling model: given a full URL
a person is about to visit, is the URL/website itself worth trusting?

This is INTENTIONALLY NOT a machine-learning model - it's a transparent,
explainable heuristic scorer, the same style real browser warnings
(Google Safe Browsing, Microsoft SmartScreen) show a simplified version of.
Each check adds "risk points" for a known phishing/malware red flag; the
total maps to a verdict. It's meant to sit ALONGSIDE the DNS tunneling
model's domain-string verdict, not replace it - together they answer two
different questions:
    1. Does the query itself look like encoded tunneling data? (the model)
    2. Does the URL/website itself look like a phishing/malware trap? (this)
"""

import re
from urllib.parse import urlparse

import enrichment
import tld_encoding
from dns_utils import resolve_domain

# A handful of well-known URL shorteners. Shorteners hide the real
# destination, which is a classic phishing distribution technique.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
}

# Keywords commonly used in phishing URLs to impersonate trusted services.
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "suspended", "unlock",
]

IP_HOST_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def parse_url(raw_url):
    """Normalizes and parses a URL string. Adds https:// if no scheme given."""
    raw_url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    return parsed


def run_heuristic_checks(url, parsed):
    """
    Returns a list of {"check": str, "triggered": bool, "points": int, "note": str}.
    Higher points = more suspicious. Each check is independently explainable.
    """
    host = (parsed.hostname or "").lower()
    checks = []

    # 1. No HTTPS
    no_https = parsed.scheme != "https"
    checks.append({
        "check": "HTTPS Encryption",
        "triggered": no_https,
        "points": 2 if no_https else 0,
        "note": "Site does not use HTTPS" if no_https else "Uses HTTPS",
    })

    # 2. Raw IP address instead of a domain name
    is_ip = bool(IP_HOST_PATTERN.match(host))
    checks.append({
        "check": "IP Address as Host",
        "triggered": is_ip,
        "points": 3 if is_ip else 0,
        "note": "URL uses a raw IP instead of a domain name" if is_ip else "Uses a normal domain name",
    })

    # 3. "@" trick - browsers ignore everything before @ when resolving host
    has_at = "@" in url.split("://", 1)[-1]
    checks.append({
        "check": "\"@\" Redirect Trick",
        "triggered": has_at,
        "points": 3 if has_at else 0,
        "note": "URL contains an '@' symbol, a known redirect trick" if has_at else "No '@' trick detected",
    })

    # 4. Known URL shortener
    is_shortener = host in URL_SHORTENERS
    checks.append({
        "check": "URL Shortener",
        "triggered": is_shortener,
        "points": 2 if is_shortener else 0,
        "note": "Real destination is hidden behind a shortener" if is_shortener else "Not a known shortener",
    })

    # 5. Punycode / homograph domain (xn--)
    is_punycode = "xn--" in host
    checks.append({
        "check": "Punycode / Homograph Domain",
        "triggered": is_punycode,
        "points": 3 if is_punycode else 0,
        "note": "Domain uses punycode encoding, sometimes used to mimic real brands with lookalike characters" if is_punycode else "No punycode encoding detected",
    })

    # 6. Excessive subdomains
    label_count = host.count(".") + 1 if host else 0
    too_many_labels = label_count >= 5
    checks.append({
        "check": "Excessive Subdomains",
        "triggered": too_many_labels,
        "points": 2 if too_many_labels else 0,
        "note": f"{label_count} labels in the hostname" if too_many_labels else "Normal number of subdomains",
    })

    # 7. Very long URL
    too_long = len(url) >= 150
    checks.append({
        "check": "Unusually Long URL",
        "triggered": too_long,
        "points": 1 if too_long else 0,
        "note": f"{len(url)} characters long" if too_long else "Normal length",
    })

    # 8. Suspicious keywords in the path/query (phishing brand impersonation)
    haystack = (parsed.path + "?" + parsed.query).lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack]
    checks.append({
        "check": "Suspicious Keywords",
        "triggered": bool(found_keywords),
        "points": 1 if found_keywords else 0,
        "note": f"Found: {', '.join(found_keywords)}" if found_keywords else "No suspicious keywords in path/query",
    })

    return checks


def compute_website_verdict(raw_url, vt_api_key=""):
    """
    Full orchestration: parse URL, run heuristics, layer on SSL cert check,
    WHOIS domain age, and VirusTotal domain reputation (reusing the same
    enrichment functions the domain-check flow already uses). Returns a
    single dict the template can render directly.
    """
    parsed = parse_url(raw_url)
    host = parsed.hostname or ""

    if not host:
        return {"error": "Couldn't parse a valid hostname from that URL."}

    # If the site doesn't even exist on public DNS, there's nothing to
    # check for safety - skip straight to a neutral verdict rather than
    # let a nonexistent domain quietly score as "Looks Safe".
    dns_result = resolve_domain(host, "A")
    if dns_result.get("nxdomain"):
        return {
            "url": raw_url,
            "host": host,
            "scheme": parsed.scheme,
            "checks": [],
            "ssl": None,
            "domain_age": None,
            "reputation": None,
            "risk_points": None,
            "verdict": "Website Does Not Exist",
            "verdict_color": "unknown",
            "error": None,
        }

    checks = run_heuristic_checks(raw_url if "://" in raw_url else parsed.geturl(), parsed)
    points = sum(c["points"] for c in checks)

    # Target-encoded TLD risk (continuous, not a flat "is it in the list" flag) -
    # scaled to a 0-5 point contribution so it sits comfortably alongside the
    # other heuristic weights above.
    tld_risk = tld_encoding.get_tld_risk_score(host)
    tld_points = round(tld_risk["risk_score"] * 10)
    points += tld_points
    checks.append({
        "check": "TLD Risk (Target Encoded)",
        "triggered": tld_risk["risk_score"] >= 0.15,
        "points": tld_points,
        "note": f".{tld_risk['tld']} risk score: {tld_risk['risk_score']} ({'known' if tld_risk['known'] else 'unseen, using prior'})",
    })

    ssl_info = enrichment.check_ssl(host)
    if not ssl_info["present"]:
        points += 2

    domain_age = enrichment.get_domain_age(host)
    if domain_age["available"]:
        if domain_age["age_days"] < 30:
            points += 3
        elif domain_age["age_days"] < 180:
            points += 1

    reputation = enrichment.get_reputation(host, vt_api_key)
    if reputation["available"]:
        if reputation["malicious"] and reputation["malicious"] > 0:
            points += 5
        elif reputation["suspicious"] and reputation["suspicious"] > 0:
            points += 2

    if points >= 7:
        verdict, color = "Unsafe - High Risk", "danger"
    elif points >= 3:
        verdict, color = "Suspicious - Proceed with Caution", "warn"
    else:
        verdict, color = "Looks Safe", "success"

    return {
        "url": raw_url,
        "host": host,
        "scheme": parsed.scheme,
        "checks": checks,
        "ssl": ssl_info,
        "domain_age": domain_age,
        "reputation": reputation,
        "risk_points": points,
        "verdict": verdict,
        "verdict_color": color,
        "error": None,
    }
