"""
tld_encoding.py
----------------
Target Encoding for TLD risk - replaces the earlier static "is this TLD in
a risky list" rule with a continuous, smoothed numeric score, the way a
categorical feature is properly encoded in a data science pipeline instead
of hardcoded if/else rules.

TARGET ENCODING, THE ACTUAL MATH
---------------------------------
For a categorical feature (here: TLD) and a binary target (malicious/benign),
target encoding replaces each category with the target's mean for that
category, smoothed toward the global mean so categories with few observed
samples don't get an overconfident score:

    encoded(tld) = (n(tld) * mean_target(tld) + k * global_mean)
                   ---------------------------------------------
                                 (n(tld) + k)

  n(tld)          - how many training samples had this TLD
  mean_target(tld)- fraction of those samples that were malicious
  global_mean     - overall malicious rate across ALL samples (the prior)
  k               - smoothing strength; higher k trusts the prior more
                     when n(tld) is small

HONEST LIMITATION - PLEASE READ BEFORE PRESENTING THIS AS "TRAINED ON YOUR DATA"
---------------------------------------------------------------------------------
Real target encoding is fit on YOUR labeled dataset: you'd group your
training rows by TLD, compute n(tld) and mean_target(tld) directly from
the data, then apply the smoothing formula above. That raw dataset isn't
available to this app (your notebook loads it from a local path this
project doesn't have access to), so TLD_STATS below is NOT computed from
your training data - it's a categorical approximation, grouping TLDs into
rough risk tiers based on widely-reported phishing/abuse patterns (the
kind of thing you'll find in industry reports like Interisle Consulting's
"Phishing Landscape" studies), with made-up-but-plausible (n, mean_target)
pairs standing in for real counts.

TO MAKE THIS GENUINE TARGET ENCODING:
  1. Get a labeled dataset with a `tld` (or full `domain`) column and a
     malicious/benign label per row.
  2. Group by TLD, compute real n(tld) and mean_target(tld) for each.
  3. Replace TLD_STATS with those real numbers.
  4. Recompute GLOBAL_MEAN from the full dataset's malicious rate.
Once that's done, this file is doing real target encoding, not an
approximation - the formula and pipeline shape below are already correct.
"""

# Overall malicious rate prior, used to pull the score toward the middle
# for TLDs with no data (or a category we've never seen).
GLOBAL_MEAN_RISK = 0.05

SMOOTHING_K = 20

# (n_tld, mean_target) pairs. See the module docstring - these are
# category-tier approximations, not counts pulled from a real dataset.
TLD_STATS = {
    # --- Elevated historical abuse rates in public phishing reports ---
    "zip": (500, 0.42), "top": (500, 0.38), "xyz": (500, 0.31),
    "click": (500, 0.35), "work": (500, 0.29), "support": (500, 0.33),
    "country": (500, 0.40), "stream": (500, 0.37), "gq": (500, 0.45),
    "tk": (500, 0.44), "ml": (500, 0.41), "cf": (500, 0.43), "ga": (500, 0.42),
    "loan": (500, 0.36), "win": (500, 0.30), "bid": (500, 0.34),
    "men": (500, 0.32), "download": (500, 0.28), "review": (500, 0.27),
    "party": (500, 0.31), "trade": (500, 0.26), "date": (500, 0.29),
    "faith": (500, 0.30), "icu": (500, 0.33), "mov": (500, 0.30),

    # --- Low historical abuse rates - large, well-governed legacy TLDs ---
    "com": (500, 0.02), "org": (500, 0.015), "net": (500, 0.02),
    "edu": (500, 0.001), "gov": (500, 0.001), "io": (500, 0.03),
    "co": (500, 0.025), "ai": (500, 0.02),
}


def get_tld_risk_score(domain):
    """
    Returns {"tld": str, "risk_score": float 0-1, "known": bool}.
    risk_score is the smoothed target-encoded value - use it directly as
    a continuous feature/signal rather than thresholding into a binary
    flag, which is the whole point of encoding it this way.
    """
    tld = domain.split(".")[-1].lower() if "." in domain else ""
    n, mean_target = TLD_STATS.get(tld, (0, GLOBAL_MEAN_RISK))
    encoded = (n * mean_target + SMOOTHING_K * GLOBAL_MEAN_RISK) / (n + SMOOTHING_K)
    return {
        "tld": tld,
        "risk_score": round(encoded, 4),
        "known": tld in TLD_STATS,
    }
