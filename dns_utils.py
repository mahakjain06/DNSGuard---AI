"""
dns_utils.py
------------
Real DNS resolution for DNSGuard AI.

This is informational only — it does NOT feed into the ML model (which was
trained purely on lexical/statistical features of the query string). It just
shows the user what the domain actually resolves to, the way a real security
console would, alongside the model's prediction.
"""

import time

import dns.resolver
import dns.exception


def resolve_domain(domain, record_type="A", timeout=2.5):
    """
    Attempt a real DNS lookup for the given domain.

    Returns a dict:
        {
            "resolved": bool,
            "records": [str, ...],   # e.g. resolved IPs or record values
            "response_time_ms": float | None,
            "error": str | None,
        }
    Never raises — any failure (NXDOMAIN, timeout, no answer, etc.) is
    captured in "error" so callers can render it safely.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    result = {
        "resolved": False,
        "records": [],
        "ttl": None,
        "response_time_ms": None,
        "error": None,
    }

    start = time.perf_counter()
    try:
        answer = resolver.resolve(domain, record_type)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

        result["resolved"] = True
        result["records"] = [rdata.to_text() for rdata in answer]
        result["ttl"] = answer.rrset.ttl if answer.rrset is not None else None
        result["response_time_ms"] = elapsed_ms

    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist (NXDOMAIN)."
    except dns.resolver.NoAnswer:
        result["error"] = f"No {record_type} record found for this domain."
    except dns.resolver.NoNameservers:
        result["error"] = "No nameservers could answer this query."
    except dns.exception.Timeout:
        result["error"] = "DNS lookup timed out."
    except Exception as exc:  # noqa: BLE001 - resolution should never crash the app
        result["error"] = f"DNS lookup failed: {exc}"

    return result


def get_txt_record(domain, timeout=2.5):
    """
    Looks up TXT records for a domain. Separate from resolve_domain() since
    TXT is a distinct query type from whatever the user selected (A/AAAA/etc.)
    and most domains simply won't have one — that's expected, not an error.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answer = resolver.resolve(domain, "TXT")
        return {"present": True, "records": [rdata.to_text() for rdata in answer], "error": None}
    except dns.resolver.NoAnswer:
        return {"present": False, "records": [], "error": None}
    except dns.resolver.NXDOMAIN:
        return {"present": False, "records": [], "error": "Domain does not exist."}
    except Exception as exc:
        return {"present": False, "records": [], "error": str(exc)}
