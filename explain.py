"""
explain.py
----------
Turns the raw feature values into a short, human-readable checklist of
WHY a domain was flagged safe or suspicious — the kind of explanation a
security analyst (or a recruiter reading your project) wants to see
instead of just a bare prediction.

These thresholds are reasonable heuristics based on typical DNS tunneling
literature, not values learned from your specific training data. If your
model was trained on a dataset with different characteristics, tune the
THRESHOLDS dict below to match.
"""

THRESHOLDS = {
    "entropy_high": 3.5,
    "subdomain_long": 20,
    "subdomain_very_long": 40,
    "digit_ratio_high": 0.15,
    "query_length_long": 50,
}


def generate_reasons(features, lexical=None):
    """
    features: the feature dict already computed by feature_engineering.py
              (query_length, subdomain_length, entropy, digit_ratio,
               uncomman_tld, num_labels, avg_label_length, query_type)
    lexical:  optional dict from enrichment.lexical_enrichment(), used to
              also flag base64/base32/hex-looking patterns when available.

    Returns a list of {"ok": bool, "text": str} — ok=True renders as a
    green checkmark, ok=False as a warning triangle.
    """
    reasons = []

    entropy = features.get("entropy", 0) or 0
    digit_ratio = features.get("digit_ratio", 0) or 0
    subdomain_length = features.get("subdomain_length", 0) or 0
    uncommon_tld = features.get("uncomman_tld", 0)
    query_length = features.get("query_length", 0) or 0

    # Entropy
    if entropy >= THRESHOLDS["entropy_high"]:
        reasons.append({"ok": False, "text": f"High entropy ({entropy})"})
    else:
        reasons.append({"ok": True, "text": f"Low entropy ({entropy})"})

    # Subdomain length
    if subdomain_length >= THRESHOLDS["subdomain_very_long"]:
        reasons.append({"ok": False, "text": f"Very long subdomain ({subdomain_length} chars)"})
    elif subdomain_length >= THRESHOLDS["subdomain_long"]:
        reasons.append({"ok": False, "text": f"Long subdomain ({subdomain_length} chars)"})
    else:
        reasons.append({"ok": True, "text": "Normal subdomain length"})

    # Digit ratio
    if digit_ratio >= THRESHOLDS["digit_ratio_high"]:
        reasons.append({"ok": False, "text": f"High digit ratio ({digit_ratio})"})
    else:
        reasons.append({"ok": True, "text": "Very low digit ratio"})

    # TLD commonality
    if uncommon_tld:
        reasons.append({"ok": False, "text": "Uncommon TLD"})
    else:
        reasons.append({"ok": True, "text": "Common TLD"})

    # Overall query length
    if query_length >= THRESHOLDS["query_length_long"]:
        reasons.append({"ok": False, "text": f"Unusually long query ({query_length} chars)"})
    else:
        reasons.append({"ok": True, "text": "Normal query length"})

    # Encoded pattern (only if lexical enrichment was run)
    if lexical is not None:
        encoding = lexical.get("encoding", {})
        found = [name for name, flag in [
            ("Base64", encoding.get("base64_like")),
            ("Base32", encoding.get("base32_like")),
            ("Hex", encoding.get("hex_like")),
        ] if flag]
        if found:
            reasons.append({"ok": False, "text": f"{'/'.join(found)} pattern detected"})
        else:
            reasons.append({"ok": True, "text": "No encoded pattern detected"})

    return reasons
