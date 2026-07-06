"""
app.py
------
Flask application entry point — PhishGuard v3.

Full analysis pipeline:

  URL Input
      ↓
  Feature Extraction  ──→  Raw Signals + Findings
      ↓
  ┌───────────────────────────────────────────────────────┐
  │  Parallel (ThreadPoolExecutor, max_workers=4):        │
  │   • Threat Intelligence  (Safe Browsing + VirusTotal) │
  │   • ML Detector          (RandomForest)               │
  │   • Brand Impersonation  (Levenshtein + homograph)    │
  │   • Visual Scanner       (Playwright + Gemini Vision) │
  └───────────────────────────────────────────────────────┘
      ↓
  Enrich signals with all parallel results
      ↓
  Risk Engine  →  Score + Verdict (deterministic)
      ↓
  Confidence Engine  →  Confidence % 
      ↓
  Gemini AI  →  Plain-English Explanation + Recommendations
      ↓
  Full JSON Response

API Endpoints:
  GET  /api/health
  POST /api/analyze   { "url": "...", "visual": true|false }

Query params:
  visual=true   Enable visual screenshot analysis (adds ~5s, default: true)

Response shape (v3):
  {
    "verdict":           str,
    "risk_score":        int  (0-100),
    "severity":          str  ("LOW"|"MEDIUM"|"HIGH"|"CRITICAL"),
    "confidence":        int  (0-100),
    "confidence_label":  str,
    "confidence_reason": str,
    "ai_explanation":    { "summary", "recommendations", "fallback" },
    "threat_intel":      { "safe_browsing", "virustotal", "any_detected" },
    "ml_result":         { "available", "prediction", "confidence" },
    "brand_result":      { "brand_impersonation", "target_brand", "similarity", ... },
    "visual_result":     { "checked", "visual_threat", "reason", "screenshot_b64", ... },
    "triggered_rules":   [{ "rule", "points", "detail" }],
    "findings":          [{ "name", "value", "explain" }],
    "timestamp":         str  (ISO-8601 UTC),

    # Legacy v1/v2 key kept for backward compatibility:
    "ai_result":         { "verdict", "reason" }
  }
"""

import logging
import datetime
import time
import concurrent.futures

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from services.url_utils          import normalize_url, is_valid_url
from services.feature_extractor  import extract_raw_signals
from services.risk_engine        import calculate_risk, verdict_to_severity
from services.threat_intelligence import run_threat_intelligence
from services.confidence_engine  import calculate_confidence
from services.brand_detector     import check_brand_impersonation
from services.visual_scanner     import scan_visual
from services.ai_analyzer        import generate_explanation
from ml.detector                 import predict_phishing
from services.url_utils          import extract_hostname

# ─── Bootstrap ────────────────────────────────────────────────────────────────

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ─── Health Check ─────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    """Liveness probe."""
    return jsonify({"status": "ok", "timestamp": _utc_now()}), 200


# ─── Main Endpoint ────────────────────────────────────────────────────────────

@app.post("/api/analyze")
def analyze():
    """
    Full multi-layer URL analysis (v3).
    Accepts optional JSON field "visual": true|false (default: true).
    """
    # ── 1. Parse & validate ────────────────────────────────────────────────────
    body = request.get_json(silent=True)
    if not body:
        return _error("Request body must be JSON.", 400)

    raw_url = body.get("url", "").strip()
    if not raw_url:
        return _error("The 'url' field is required and cannot be empty.", 400)

    enable_visual = body.get("visual", True)   # default: visual scan on

    try:
        url = normalize_url(raw_url)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not is_valid_url(url):
        return _error(
            f"'{raw_url}' does not appear to be a valid URL. "
            "Please include the full address (e.g. https://example.com).",
            400,
        )

    logger.info("[PhishGuard] === Analyzing URL: %s (visual=%s) ===", url, enable_visual)
    hostname = extract_hostname(url)
    scan_start = time.time()

    # ── 2. Feature extraction ──────────────────────────────────────────────────
    findings, signals = extract_raw_signals(url)

    # ── 3. Parallel analysis (TI, ML, Brand) ──────────────────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        ti_future    = pool.submit(run_threat_intelligence, url)
        ml_future    = pool.submit(predict_phishing, url, signals)
        brand_future = pool.submit(check_brand_impersonation, url, hostname)

    threat_intel  = ti_future.result()
    ml_result     = ml_future.result()
    brand_result  = brand_future.result()

    # ── 4. Enrich signals ──────────────────────────────────────────────────────
    if threat_intel["any_detected"]:
        signals["threat_detected"]   = True
        signals["threat_source"]     = threat_intel["threat_source"]
        signals["threat_detections"] = threat_intel["detections"]
        signals["threat_types"]      = threat_intel.get("threat_types", [])

    if ml_result.get("available") and ml_result.get("prediction") == "phishing":
        signals["ml_prediction"] = "phishing"
        signals["ml_confidence"] = ml_result["confidence"]

    if brand_result.get("brand_impersonation"):
        signals["brand_impersonation"]      = True
        signals["impersonated_brand"]       = brand_result["target_brand"]
        signals["brand_similarity"]         = brand_result["similarity"]
        signals["brand_method"]             = brand_result.get("method", "similarity")
        signals["brand_category"]           = brand_result.get("category", "")
        signals["brand_char_substitution"]  = brand_result.get("character_substitution", False)
        signals["brand_homoglyph"]          = brand_result.get("homoglyph_detected", False)
        signals["brand_suspicious_tld"]     = brand_result.get("suspicious_tld", False)

    # ── 5. Preliminary Risk Score ─────────────────────────────────────────────
    risk = calculate_risk(signals)

    # ── 6. Conditional Visual Scanner ──────────────────────────────────────────
    # Only run visual scanner if risk is already suspicious (>=40) or if a major threat is flagged.
    needs_visual = False
    if enable_visual:
        if risk["score"] >= 40 or signals.get("threat_detected") or signals.get("brand_impersonation") or signals.get("ml_prediction") == "phishing":
            needs_visual = True

    if needs_visual:
        logger.info("Preliminary risk %s >= 40 or threat indicators found. Triggering Visual Scanner.", risk["score"])
        visual_result = scan_visual(url)
        if visual_result.get("visual_threat"):
            signals["visual_threat"] = True
            signals["visual_reason"] = visual_result.get("reason", "")
            # Recalculate risk now that we have a visual threat
            risk = calculate_risk(signals)
    else:
        visual_result = {
            "checked": False, "visual_threat": False,
            "reason": "Visual scan skipped (domain appears safe).",
            "screenshot_b64": None, "error": None,
        }

    # ── 7. Confidence engine ──────────────────────────────────────────────────
    confidence_result = calculate_confidence(
        signals, threat_intel, ml_result, brand_result, visual_result
    )

    # ── 8. Gemini explanation (verdict already set — AI only explains) ─────────
    ai_explanation = generate_explanation(
        url,
        risk["score"],
        risk["verdict"],
        risk["triggered_rules"],
    )

    # ── 9. Build response ──────────────────────────────────────────────────────
    response_body = {
        # ── Core verdict ───────────────────────────────────────────────────
        "verdict":           risk["verdict"],
        "risk_score":        risk["score"],
        "severity":          verdict_to_severity(risk["verdict"]),

        # ── Confidence ─────────────────────────────────────────────────────
        "confidence":        confidence_result["confidence"],
        "confidence_label":  confidence_result["confidence_label"],
        "confidence_reason": confidence_result["confidence_reason"],

        # ── AI explanation ─────────────────────────────────────────────────
        "ai_explanation":    ai_explanation,

        # ── Parallel layer results ─────────────────────────────────────────
        "threat_intel": {
            "safe_browsing": threat_intel["safe_browsing"],
            "virustotal":    threat_intel["virustotal"],
            "any_detected":  threat_intel["any_detected"],
        },
        "ml_result":    ml_result,
        "brand_result": brand_result,
        "visual_result": {k: v for k, v in visual_result.items()
                          if k != "screenshot_b64"},   # keep response small
        # screenshot sent separately to avoid bloating triggered_rules response
        "screenshot_b64":   visual_result.get("screenshot_b64"),

        # ── Risk detail ────────────────────────────────────────────────────
        "triggered_rules": risk["triggered_rules"],
        "findings":        findings,
        "timestamp":       _utc_now(),

        # ── Legacy v1/v2 compat ────────────────────────────────────────────
        "ai_result": {
            "verdict": risk["verdict"],
            "reason":  ai_explanation["summary"],
        },
    }

    scan_time = time.time() - scan_start
    logger.info(
        "[PhishGuard] === Complete — verdict=%s score=%d confidence=%d%% rules=%d time=%.1fs ===",
        risk["verdict"], risk["score"],
        confidence_result["confidence"], risk["rule_count"], scan_time,
    )
    return jsonify(response_body), 200


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _error(message: str, status: int):
    return jsonify({"error": message}), status


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
