"""
confidence_engine.py
--------------------
Calculates detection confidence — how much we trust the risk score.

Risk and confidence are DIFFERENT things:
  - Risk Score  = How dangerous the URL appears (0-100)
  - Confidence  = How sure we are about that assessment (0-100%)

A high risk score with low confidence means: "this looks bad, but we
couldn't gather enough data to be certain."

Confidence factors (max 100 points):
  DNS resolved successfully         +10
  WHOIS / domain age available      +10
  SSL certificate checked           +10
  Hosting reachable                 +10
  Google Safe Browsing checked      +10
  VirusTotal checked                +10
  ML model available                +10
  Brand detection ran               +10
  Visual scanner ran                +10
  URL features analyzed             +10

Signal strength bonus (up to +20):
  Strong brand impersonation        +10
  ML agrees with brand detector     +10

Confidence → Label:
  >= 90%  → Very High
  >= 75%  → High
  >= 55%  → Moderate
  >= 35%  → Low
  <  35%  → Very Low
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

# ─── Base Confidence Factors ──────────────────────────────────────────────────

_BASE_FACTORS = [
    ("dns_resolves",         10, "DNS resolution"),
    ("whois_available",      10, "WHOIS domain age lookup"),
    ("ssl_checked",          10, "SSL certificate check"),
    ("hosting_checked",      10, "Hosting availability check"),
    ("gsb_checked",          10, "Google Safe Browsing"),
    ("vt_checked",           10, "VirusTotal"),
    ("ml_available",         10, "ML model prediction"),
    ("brand_checked",        10, "Brand impersonation check"),
    ("visual_checked",       10, "Visual AI scanner"),
    ("url_features",         10, "URL feature analysis"),
]

_BASE_MAX = sum(w for _, w, _ in _BASE_FACTORS)   # = 100


def _confidence_label(confidence: int) -> str:
    if confidence >= 90:
        return "Very High"
    if confidence >= 75:
        return "High"
    if confidence >= 55:
        return "Moderate"
    if confidence >= 35:
        return "Low"
    return "Very Low"


# ─── Public API ───────────────────────────────────────────────────────────────

def calculate_confidence(
    signals:       dict,
    threat_intel:  dict,
    ml_result:     dict,
    brand_result:  dict | None = None,
    visual_result: dict | None = None,
) -> dict:
    """
    Calculate detection confidence from the available signal coverage.
    Includes signal strength bonuses when multiple detectors agree.

    Args:
        signals:       Raw signals dict from feature_extractor
        threat_intel:  Result from threat_intelligence.run_threat_intelligence()
        ml_result:     Result from ml.detector.predict_phishing()
        brand_result:  Result from brand_detector.check_brand() (optional)
        visual_result: Result from visual_scanner.scan_visual() (optional)

    Returns:
        {
          "confidence":        int   (0-100),
          "confidence_label":  str,
          "checks_completed":  int,
          "checks_total":      int,
          "confidence_reason": str,
          "factor_breakdown":  list[dict]
        }
    """
    gsb = threat_intel.get("safe_browsing", {})
    vt  = threat_intel.get("virustotal",    {})

    # Build a lookup of which factors were available
    availability = {
        "dns_resolves":    signals.get("dns_resolves", False),
        "whois_available": signals.get("domain_age_days") is not None,
        "ssl_checked":     signals.get("ssl_valid") is not None or
                           signals.get("ssl_expired", False) or
                           signals.get("ssl_invalid", False),
        "hosting_checked": signals.get("is_online") is not None,
        "gsb_checked":     gsb.get("checked", False),
        "vt_checked":      vt.get("checked", False),
        "ml_available":    ml_result.get("available", False),
        "brand_checked":   brand_result is not None,
        "visual_checked":  visual_result is not None and visual_result.get("checked", False),
        "url_features":    True,   # URL features are always analyzed
    }

    # Score base factors
    earned     = 0
    completed  = 0
    breakdown  = []
    for key, weight, label in _BASE_FACTORS:
        available = availability.get(key, False)
        pts       = weight if available else 0
        earned   += pts
        if available:
            completed += 1
        breakdown.append({
            "factor":    label,
            "available": available,
            "points":    pts,
            "max":       weight,
        })

    # ── Signal Strength Bonuses ───────────────────────────────────────────
    # When strong signals agree, confidence should be high even if some
    # checks are missing.
    bonus = 0
    bonus_reasons = []

    # Strong brand impersonation detected
    if brand_result and brand_result.get("brand_impersonation"):
        sim = brand_result.get("similarity", 0)
        if sim >= 85:
            bonus += 10
            bonus_reasons.append(f"Strong brand impersonation ({sim}%)")

    # ML agrees with brand detector
    if (brand_result and brand_result.get("brand_impersonation") and
        ml_result.get("available") and ml_result.get("prediction") == "phishing"):
        bonus += 10
        bonus_reasons.append("ML confirms brand impersonation")

    # Threat intel positive detection
    if threat_intel.get("any_detected"):
        bonus += 5
        bonus_reasons.append("Threat intelligence positive")

    # Visual scanner found threat
    if visual_result and visual_result.get("visual_threat"):
        bonus += 5
        bonus_reasons.append("Visual AI confirmed threat")

    # Confidence is a percentage of max possible + bonus (capped at 100)
    raw_confidence = int(round((earned / _BASE_MAX) * 100))
    confidence = min(raw_confidence + bonus, 100)
    label_str  = _confidence_label(confidence)
    total      = len(_BASE_FACTORS)

    if bonus_reasons:
        reason = (
            f"{completed}/{total} security checks completed. "
            f"Signal strength bonus: {', '.join(bonus_reasons)}. "
            f"Confidence is {label_str.lower()}."
        )
    else:
        reason = (
            f"{completed}/{total} security checks completed successfully — "
            f"confidence is {label_str.lower()}."
        )

    logger.info(
        "[Confidence Engine] %d%% (%s) — %d/%d checks, bonus=%d",
        confidence, label_str, completed, total, bonus,
    )

    return {
        "confidence":        confidence,
        "confidence_label":  label_str,
        "checks_completed":  completed,
        "checks_total":      total,
        "confidence_reason": reason,
        "factor_breakdown":  breakdown,
    }
