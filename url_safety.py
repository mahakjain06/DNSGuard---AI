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

IMPORTANT DESIGN NOTE: URL-structure heuristics (keywords, hyphens, IP host,
punycode, etc.) run REGARDLESS of whether the domain currently resolves.
A phishing URL's structure is dangerous whether or not its infrastructure
happens to be live at the exact moment you check it - DNS existence is
surfaced as its own separate signal, not something that hides the pattern
analysis (matching how the Domain Check page treats the ML verdict).
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

# Keywords commonly used in phishing domains/URLs to impersonate trusted
# services. Checked against the HOSTNAME as well as the path/query, since
# real phishing domains usually bake these directly into the domain name
# itself (e.g. "secure-bank-login-update.com") rather than the URL path.
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "bank", "password", "suspended", "unlock",
    "billing", "payment", "wallet",
]

IP_HOST_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def parse_url(raw_url):
    """
    Normalizes and parses a URL string. Adds https:// if no scheme given,
    and repairs the common typo of a single slash after the scheme
    (e.g. "https:/example.com" instead of "https://example.com") - left
    unhandled, that typo makes urlparse() treat "https" itself as the
    hostname and silently swallow the real domain into the path.
    """
    raw_url = raw_url.strip()

    # Fix "scheme:/host" (one slash) -> "scheme://host" (two slashes)
    raw_url = re.sub(r"^([a-zA-Z][a-zA-Z0-9+.-]*):/(?!/)", r"\1://", raw_url)

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

    # 7. Excessive hyphens - classic typosquatting pattern, e.g.
    # "secure-bank-login-update.com" stringing together brand-adjacent words
    hyphen_count = host.count("-")
    too_many_hyphens = hyphen_count >= 3
    checks.append({
        "check": "Excessive Hyphens in Domain",
        "triggered": too_many_hyphens,
        "points": 3 if too_many_hyphens else 0,
        "note": f"{hyphen_count} hyphens in the hostname - typosquatting pattern" if too_many_hyphens else "Normal hyphen usage",
    })

    # 8. Very long URL
    too_long = len(url) >= 150
    checks.append({
        "check": "Unusually Long URL",
        "triggered": too_long,
        "points": 1 if too_long else 0,
        "note": f"{len(url)} characters long" if too_long else "Normal length",
    })

    # 9. Suspicious keywords - checked in the HOSTNAME as well as path/query,
    # since real phishing domains put the keywords directly in the domain
    # name. Weighted by how many distinct keywords appear (more = worse).
    haystack = (host + parsed.path + "?" + parsed.query).lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack]
    keyword_points = min(len(found_keywords), 4)  # cap so this can't dominate the score alone
    checks.append({
        "check": "Suspicious Keywords",
        "triggered": bool(found_keywords),
        "points": keyword_points,
        "note": f"Found: {', '.join(found_keywords)}" if found_keywords else "No suspicious keywords in domain/path/query",
    })

    return checks


def compute_website_verdict(raw_url, vt_api_key=""):
    """
    Full orchestration: parse URL, run URL-structure heuristics (always),
    then layer on SSL cert check, WHOIS domain age, and VirusTotal domain
    reputation IF the site actually resolves. Returns a single dict the
    template can render directly.
    """
    parsed = parse_url(raw_url)
    host = parsed.hostname or ""

    if not host:
        return {"error": "Couldn't parse a valid hostname from that URL."}

    # URL-structure heuristics run regardless of DNS existence - a phishing
    # URL's structure is the same red flag whether or not it's live right now.
    checks = run_heuristic_checks(raw_url if "://" in raw_url else parsed.geturl(), parsed)
    points = sum(c["points"] for c in checks)

    tld_risk = tld_encoding.get_tld_risk_score(host)
    tld_points = round(tld_risk["risk_score"] * 10)
    points += tld_points
    checks.append({
        "check": "TLD Risk (Target Encoded)",
        "triggered": tld_risk["risk_score"] >= 0.15,
        "points": tld_points,
        "note": f".{tld_risk['tld']} risk score: {tld_risk['risk_score']} ({'known' if tld_risk['known'] else 'unseen, using prior'})",
    })

    # Existence check - an IP host is inherently "reachable" (no DNS lookup
    # needed); otherwise resolve and see if it's NXDOMAIN.
    is_ip = bool(IP_HOST_PATTERN.match(host))
    if is_ip:
        exists = True
        connection_status = "Reachable"
    else:
        dns_result = resolve_domain(host, "A")
        exists = not dns_result.get("nxdomain")
        connection_status = "Reachable" if exists else "Does Not Resolve (NXDOMAIN)"

    # Only check SSL/WHOIS/reputation if the site actually exists - can't
    # meaningfully check a certificate or registration for a domain that
    # isn't registered.
    if exists:
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
    else:
        ssl_info = {"present": False, "issuer": None, "error": "Domain does not resolve"}
        domain_age = {"available": False, "error": "Domain does not resolve", "age_days": None, "created": None}
        reputation = {"available": False, "error": "Domain does not resolve", "malicious": None, "harmless": None, "suspicious": None}

    # Verdict: URL-structure risk points decide danger/suspicious REGARDLESS
    # of existence - a clearly phishing-shaped URL stays flagged even if it
    # isn't live right now. Only fall through to "Does Not Exist" when there
    # were no meaningful red flags to begin with.
    # Verdict: URL-structure risk points decide danger/suspicious REGARDLESS
    # of existence - a clearly phishing-shaped URL stays flagged even if it
    # isn't live right now. Only fall through to "Does Not Exist" when there
    # were no meaningful STRUCTURAL red flags to begin with - a nonexistent
    # domain on a merely-higher-risk TLD (with no actual phishing shape)
    # shouldn't get bumped to "Suspicious" on TLD score alone.
    STRUCTURAL_CHECK_NAMES = {
        "IP Address as Host", "\"@\" Redirect Trick", "URL Shortener",
        "Punycode / Homograph Domain", "Excessive Subdomains",
        "Excessive Hyphens in Domain", "Unusually Long URL", "Suspicious Keywords",
    }
    structural_points = sum(c["points"] for c in checks if c["check"] in STRUCTURAL_CHECK_NAMES)
    can_override_nonexistence = exists or structural_points >= 3

    if points >= 7 and can_override_nonexistence:
        verdict, color = "Unsafe - High Risk", "danger"
    elif points >= 3 and can_override_nonexistence:
        verdict, color = "Suspicious - Proceed with Caution", "warn"
    elif not exists:
        verdict, color = "Website Does Not Exist", "unknown"
    else:
        verdict, color = "Looks Safe", "success"

    # --- Derived, honest summary labels ---
    # These are INFERENCES from the signals we actually checked above (URL
    # structure, SSL, WHOIS age, reputation) - not a verified page-content
    # classification (we never crawl or render the page). Phrased as
    # patterns/indicators rather than certainties.
    triggered_names = {c["check"] for c in checks if c["triggered"]}
    security_score = None if color == "unknown" else max(0, 100 - points * 10)

    if color == "unknown":
        website_type = "Inactive / No Server Found"
        threat_type = None
        summary_message = (
            "This domain name does not exist. Check the spelling, or the "
            "domain extension (like .com, .net) - it may simply not be registered."
        )
    elif color == "success":
        website_type = "Active Site - No Red Flags Detected"
        threat_type = None
        summary_message = "This website looks safe to visit. No phishing, malware, or suspicious patterns were detected by any check."
    else:
        if "Suspicious Keywords" in triggered_names and "Excessive Hyphens in Domain" in triggered_names:
            threat_type = "Deceptive Site (Social Engineering) - typosquatting / credential phishing pattern"
        elif "Suspicious Keywords" in triggered_names and (
            "IP Address as Host" in triggered_names or "HTTPS Encryption" in triggered_names
        ):
            threat_type = "Deceptive Site (Social Engineering) - credential phishing pattern"
        elif "Punycode / Homograph Domain" in triggered_names:
            threat_type = "Deceptive Site - Brand Impersonation (Homograph/Punycode)"
        elif "URL Shortener" in triggered_names:
            threat_type = "Obscured Destination (URL Shortener)"
        elif reputation.get("available") and reputation.get("malicious", 0) > 0:
            threat_type = "Flagged Malicious by Threat Intelligence (VirusTotal)"
        else:
            threat_type = "Multiple Elevated Risk Indicators"

        website_type = "High-Risk - Likely Malicious Pattern" if color == "danger" else "Suspicious - Multiple Red Flags"
        summary_message = (
            "Do not enter sensitive information on this site. It matches patterns "
            "commonly associated with phishing or malicious domains - proceed with caution."
            if color == "danger" else
            "This site has some red flags worth a second look before you trust it with sensitive information."
        )
        if not exists:
            summary_message += " Note: this domain also does not currently resolve on public DNS."

    if is_ip:
        domain_type = "N/A - Raw IP Address (no domain registration applies)"
    elif "Suspicious Keywords" in triggered_names or "Excessive Hyphens in Domain" in triggered_names:
        domain_type = "Typosquatting / Suspicious Keyword"
    elif not exists:
        domain_type = "Unregistered / Available for Purchase"
    elif domain_age.get("available"):
        domain_type = "Registered / Clean" if color == "success" else "Registered - Suspicious Structure"
    else:
        domain_type = "Registered (age unverified)"

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
        "website_type": website_type,
        "domain_type": domain_type,
        "threat_type": threat_type,
        "connection_status": connection_status,
        "security_score": security_score,
        "summary_message": summary_message,
        "error": None,
    }
