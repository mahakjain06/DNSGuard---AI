import io
import logging
import os
import re

from flask import Flask, render_template, request, jsonify, redirect, url_for
import joblib
import pandas as pd

from feature_engineering import extract_features
from database import (
    init_db,
    log_scan,
    get_recent_scans,
    get_stats,
    delete_scan,
    clear_scans,
    get_dashboard_data,
)
from dns_utils import resolve_domain, get_txt_record
import enrichment
from explain import generate_reasons
import model_insights

app = Flask(__name__)

# VirusTotal API key for the reputation check — get a free one at
# https://www.virustotal.com/gui/join-us and set it as an environment
# variable before running the app:
#   export VT_API_KEY="your-key-here"      (Linux/macOS)
#   setx VT_API_KEY "your-key-here"        (Windows)
VT_API_KEY = os.environ.get("VT_API_KEY", "")

# ==========================
# Logging (replaces print statements)
# ==========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("dnsguard")

# ==========================
# Load Trained Model
# ==========================
try:
    model = joblib.load("models/dnsguard_models.pkl")
    logger.info("Model loaded successfully.")
except FileNotFoundError:
    model = None
    logger.error("Model file not found at models/dnsguard_models.pkl. Predictions will fail until it is added.")

# Global feature importance - computed once from the fitted model, reused everywhere.
FEATURE_IMPORTANCE = model_insights.get_feature_importance(model) if model is not None else []

# ==========================
# Initialize scan history database
# ==========================
init_db()

VALID_QUERY_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX"}
BATCH_ROW_LIMIT = 200

# Basic domain format check: labels separated by dots, valid characters, a TLD at the end.
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain):
    """Returns an error message string if the domain is invalid, otherwise None."""
    if not domain:
        return "Please enter a domain name."
    if len(domain) > 253:
        return "Domain name is too long."
    if not DOMAIN_PATTERN.match(domain):
        return "That doesn't look like a valid domain (example: google.com)."
    return None


def analyze_domain(domain, query_type, resolve_dns=False, deep_enrichment=False, save_history=True):
    """
    Runs full validation + feature extraction + prediction for a single domain.
    Shared by the web form, the REST API, and batch CSV processing so the
    logic only lives in one place.

    resolve_dns: do a live A/AAAA/etc. lookup + basic TTL/response time.
    deep_enrichment: additionally run lexical enrichment (free), SSL check,
        WHOIS domain age, TXT lookup, and VirusTotal reputation (all display
        info only — none of it is fed into the trained model).

    Returns a dict with either an "error" key, or the full result payload.
    """
    domain = (domain or "").strip().lower()
    query_type = (query_type or "").strip().upper()

    error = validate_domain(domain)
    if not error and query_type not in VALID_QUERY_TYPES:
        error = "Query type must be one of: A, AAAA, CNAME, TXT, MX."

    if error:
        return {"domain": domain, "query_type": query_type, "error": error}

    if model is None:
        return {
            "domain": domain,
            "query_type": query_type,
            "error": "The detection model isn't loaded on the server.",
        }

    try:
        features = extract_features(domain, query_type)
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        confidence = round(max(probabilities) * 100, 2)
    except Exception:
        logger.exception("Prediction failed for domain=%r query_type=%r", domain, query_type)
        return {
            "domain": domain,
            "query_type": query_type,
            "error": "Something went wrong while analyzing that domain.",
        }

    if prediction == "benign":
        status = "Safe Domain"
        risk_level = "Low"
        status_color = "success"
        message = "No suspicious DNS tunneling behavior detected."
    else:
        status = "Potential DNS Security Threat"
        risk_level = "High"
        status_color = "danger"
        message = (
            "This DNS query contains patterns commonly associated "
            "with DNS tunneling and should be investigated before use."
        )

    feature_dict = features.iloc[0].to_dict()

    result = {
        "domain": domain,
        "query_type": query_type,
        "status": status,
        "prediction": str(prediction),
        "risk_level": risk_level,
        "status_color": status_color,
        "confidence": confidence,
        "message": message,
        "features": feature_dict,
        "reasons": generate_reasons(feature_dict),
        "error": None,
    }

    if resolve_dns:
        result["dns"] = resolve_domain(domain, query_type if query_type != "TXT" else "A")

    if deep_enrichment:
        try:
            result["lexical"] = enrichment.lexical_enrichment(domain)
            result["reasons"] = generate_reasons(feature_dict, lexical=result["lexical"])
        except Exception:
            logger.exception("Lexical enrichment failed for domain=%r", domain)
            result["lexical"] = None

        result["shap_explanation"] = model_insights.explain_prediction(model, features)

        result["ssl"] = enrichment.check_ssl(domain)
        result["domain_age"] = enrichment.get_domain_age(domain)
        result["txt"] = get_txt_record(domain)
        result["reputation"] = enrichment.get_reputation(domain, VT_API_KEY)

    if save_history:
        try:
            log_scan(
                domain=domain,
                query_type=query_type,
                prediction=prediction,
                risk_level=risk_level,
                confidence=confidence,
                entropy=feature_dict.get("entropy"),
                digit_ratio=feature_dict.get("digit_ratio"),
            )
        except Exception:
            logger.exception("Failed to write scan to history for domain=%r", domain)

    logger.info(
        "Prediction complete - domain=%s query_type=%s prediction=%s confidence=%s",
        domain, query_type, prediction, confidence,
    )
    return result


# ==========================
# Home Page
# ==========================
@app.route("/")
def home():
    return render_template("index.html")


# ==========================
# Prediction (web form)
# ==========================
@app.route("/predict", methods=["POST"])
def predict():
    domain = request.form.get("domain", "")
    query_type = request.form.get("query_type", "")

    result = analyze_domain(domain, query_type, resolve_dns=True, deep_enrichment=True)

    if result.get("error"):
        return render_template("index.html", error=result["error"], domain=result["domain"])

    return render_template(
        "index.html",
        domain=result["domain"],
        status=result["status"],
        risk_level=result["risk_level"],
        confidence=result["confidence"],
        message=result["message"],
        status_color=result["status_color"],
        features=result["features"],
        reasons=result.get("reasons"),
        shap_explanation=result.get("shap_explanation"),
        dns=result.get("dns"),
        lexical=result.get("lexical"),
        ssl_info=result.get("ssl"),
        domain_age=result.get("domain_age"),
        txt=result.get("txt"),
        reputation=result.get("reputation"),
    )


# ==========================
# REST API
# ==========================
@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    JSON API for programmatic access.

    Request body:
        { "domain": "example.com", "query_type": "A", "resolve_dns": false, "deep_enrichment": false }

    Response (200):
        {
            "domain": "...", "query_type": "...", "prediction": "benign",
            "status": "...", "risk_level": "...", "confidence": 98.4,
            "message": "...", "features": {...}, "dns": {...}?
        }

    Response (400) on invalid input:
        { "error": "..." }
    """
    payload = request.get_json(silent=True) or {}
    domain = payload.get("domain", "")
    query_type = payload.get("query_type", "")
    resolve_dns = bool(payload.get("resolve_dns", False))
    deep_enrichment = bool(payload.get("deep_enrichment", False))

    result = analyze_domain(domain, query_type, resolve_dns=resolve_dns, deep_enrichment=deep_enrichment)

    if result.get("error"):
        return jsonify({"error": result["error"], "domain": result.get("domain", "")}), 400

    return jsonify(result), 200


# ==========================
# Batch CSV Upload
# ==========================
@app.route("/batch", methods=["GET", "POST"])
def batch():
    if request.method == "GET":
        return render_template("batch.html", results=None)

    file = request.files.get("csv_file")
    if not file or file.filename == "":
        return render_template("batch.html", results=None, error="Please choose a CSV file to upload.")

    if not file.filename.lower().endswith(".csv"):
        return render_template("batch.html", results=None, error="Only .csv files are supported.")

    try:
        raw = file.read().decode("utf-8", errors="ignore")
        df = pd.read_csv(io.StringIO(raw))
    except Exception:
        logger.exception("Failed to parse uploaded CSV")
        return render_template("batch.html", results=None, error="Couldn't read that CSV file. Check the format.")

    if "domain" not in df.columns:
        return render_template(
            "batch.html", results=None,
            error="CSV must have a 'domain' column (a 'query_type' column is optional, defaults to A)."
        )

    if len(df) > BATCH_ROW_LIMIT:
        return render_template(
            "batch.html", results=None,
            error=f"That file has {len(df)} rows. Please limit batch uploads to {BATCH_ROW_LIMIT} rows."
        )

    results = []
    for _, row in df.iterrows():
        domain = str(row.get("domain", "")).strip()
        query_type = str(row.get("query_type", "A")).strip() or "A"
        results.append(analyze_domain(domain, query_type, resolve_dns=False))

    summary = {
        "total": len(results),
        "failed": sum(1 for r in results if r.get("error")),
        "threats": sum(1 for r in results if r.get("prediction") not in (None, "benign") and not r.get("error")),
    }
    summary["safe"] = summary["total"] - summary["failed"] - summary["threats"]

    return render_template("batch.html", results=results, summary=summary)


# ==========================
# Scan History
# ==========================
@app.route("/history")
def history():
    scans = get_recent_scans(limit=50)
    stats = get_stats()
    return render_template("history.html", scans=scans, stats=stats)


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
def history_delete(scan_id):
    delete_scan(scan_id)
    return redirect(url_for("history"))


@app.route("/history/clear", methods=["POST"])
def history_clear():
    clear_scans()
    return redirect(url_for("history"))


# ==========================
# Data Visualization Dashboard
# ==========================
@app.route("/dashboard")
def dashboard():
    data = get_dashboard_data()
    return render_template("dashboard.html", data=data)


# ==========================
# Model Info (ML/DS insights)
# ==========================
@app.route("/model-info")
def model_info():
    return render_template(
        "model_info.html",
        metrics=model_insights.TRAINING_METRICS,
        importance=FEATURE_IMPORTANCE,
    )


# ==========================
# Run Flask App
# ==========================
if __name__ == "__main__":
    app.run(debug=True)
