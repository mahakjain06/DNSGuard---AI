"""
database.py
-----------
Tiny SQLite helper for DNSGuard AI.

Stores every prediction that is made so the dashboard can show a
"Recent Scans" history — mirrors what a real security tool would keep
as an audit log.
"""

import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "dnsguard.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the scans and url_scans tables if they don't already exist. Safe to call on every app start."""
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            query_type TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            confidence REAL NOT NULL,
            entropy REAL,
            digit_ratio REAL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            host TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_points INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def log_scan(domain, query_type, prediction, risk_level, confidence, entropy=None, digit_ratio=None):
    """Insert one scan result into the history table."""
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO scans (domain, query_type, prediction, risk_level, confidence, entropy, digit_ratio, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            domain,
            query_type,
            prediction,
            risk_level,
            confidence,
            entropy,
            digit_ratio,
            datetime.utcnow().isoformat(timespec="seconds"),
        ),
    )
    conn.commit()
    conn.close()


def get_recent_scans(limit=25):
    """Return the most recent scans, newest first."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats():
    """Basic counts used for a small stats strip on the history page."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    threats = conn.execute(
        "SELECT COUNT(*) AS c FROM scans WHERE prediction != 'benign'"
    ).fetchone()["c"]
    conn.close()
    return {"total": total, "threats": threats, "safe": total - threats}


def delete_scan(scan_id):
    """Delete a single scan by id. Returns True if a row was actually deleted."""
    conn = get_connection()
    cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


def clear_scans():
    """Wipe the entire scan history."""
    conn = get_connection()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


def get_dashboard_data(limit=5000):
    """
    Pulls scan history and pre-aggregates it into the shapes the
    dashboard charts need — safe/threat split, query type counts,
    an entropy histogram, and a confidence-score histogram.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT prediction, query_type, entropy, confidence FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()

    total = len(rows)
    safe_count = sum(1 for r in rows if r["prediction"] == "benign")
    threat_count = total - safe_count

    query_type_counts = {}
    for r in rows:
        qt = r["query_type"] or "Unknown"
        query_type_counts[qt] = query_type_counts.get(qt, 0) + 1

    # Entropy histogram: 7 buckets, 0-1, 1-2, ... 6+
    entropy_bins = [0] * 7
    for r in rows:
        e = r["entropy"] if r["entropy"] is not None else 0
        idx = min(int(e), 6)
        entropy_bins[idx] += 1

    # Confidence / risk-score histogram: 5 buckets of 20% each
    confidence_bins = [0] * 5
    for r in rows:
        c = r["confidence"] if r["confidence"] is not None else 0
        idx = min(int(c // 20), 4)
        confidence_bins[idx] += 1

    return {
        "total": total,
        "safe_count": safe_count,
        "threat_count": threat_count,
        "query_type_counts": query_type_counts,
        "entropy_bins": entropy_bins,
        "confidence_bins": confidence_bins,
    }


def log_url_scan(url, host, verdict, risk_points):
    """Insert one URL/website safety check result into its own history table."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO url_scans (url, host, verdict, risk_points, created_at) VALUES (?, ?, ?, ?, ?)",
        (url, host, verdict, risk_points, datetime.utcnow().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def get_recent_url_scans(limit=25):
    """Return the most recent URL safety checks, newest first."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM url_scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_url_scans():
    """Wipe the entire URL/website check history."""
    conn = get_connection()
    conn.execute("DELETE FROM url_scans")
    conn.commit()
    conn.close()


def delete_url_scan(scan_id):
    """Delete a single URL scan by id. Returns True if a row was actually deleted."""
    conn = get_connection()
    cur = conn.execute("DELETE FROM url_scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted
