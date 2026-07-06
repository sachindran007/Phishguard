"""
risk_engine.py
--------------
Deterministic, rule-based risk scoring engine with threat priority system.

This module is the PRIMARY decision maker for phishing verdicts.
Gemini AI is only used for explanation — never for the verdict itself.

Scoring table:
  No HTTPS                     +15
  Invalid / Expired SSL        +20
  Domain age < 30 days         +25
  Domain age 30–180 days       +10
  Suspicious keywords found    +20
  IP address as hostname       +20
  Excessive subdomains (>3)    +10
  URL length > 75 chars        +10
  Special characters in URL    +10
  DNS failure / NXDOMAIN       +15
  ML model predicts phishing   +30
  Brand impersonation          +35
  Visual phishing detected     +40

Threat Intelligence Overrides (Priority 1):
  MALWARE                      → force score 98, verdict "Malware Detected"
  SOCIAL_ENGINEERING           → force score 98, verdict "Phishing Detected"
  UNWANTED_SOFTWARE            → force score 90, verdict "Unwanted Software Detected"
  POTENTIALLY_HARMFUL          → force score 90, verdict "Harmful Application Detected"

Brand Impersonation Override (Priority 2):
  similarity >= 90%            → force score min 95, verdict "Phishing Detected"

Score → Verdict (when no override):
  0  – 20  → Safe
  21 – 40  → Suspicious
  41 – 70  → High Risk
  71 – 100 → Confirmed Threat  (score capped at 100)
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

# ─── Verdict Thresholds ───────────────────────────────────────────────────────

VERDICT_THRESHOLDS = [
    (71,  "Confirmed Threat"),
    (41,  "High Risk"),
    (21,  "Suspicious"),
    (0,   "Safe"),
]

# ─── Threat Type → Override Mapping ───────────────────────────────────────────

_THREAT_TYPE_OVERRIDES = {
    "MALWARE":                          {"score": 98, "verdict": "Malware Detected"},
    "SOCIAL_ENGINEERING":               {"score": 98, "verdict": "Phishing Detected"},
    "UNWANTED_SOFTWARE":                {"score": 90, "verdict": "Unwanted Software Detected"},
    "POTENTIALLY_HARMFUL_APPLICATION":  {"score": 90, "verdict": "Harmful Application Detected"},
}


# ─── Scoring Rules ────────────────────────────────────────────────────────────

def _score_signals(signals: dict) -> list[dict]:
    """
    Evaluate raw signals and return a list of triggered rule dicts.
    Each triggered rule: {"rule": str, "points": int, "detail": str}
    """
    triggered: list[dict] = []

    def hit(rule: str, points: int, detail: str = ""):
        triggered.append({"rule": rule, "points": points, "detail": detail})

    # ── Protocol ─────────────────────────────────────────────────────────────
    if not signals.get("is_https", True):
        hit("No HTTPS", 15, "Site uses plain HTTP — no transport encryption.")

    # ── SSL ──────────────────────────────────────────────────────────────────
    if signals.get("ssl_expired", False):
        hit("Expired SSL Certificate", 20, "The SSL certificate has expired.")
    elif signals.get("ssl_invalid", False):
        hit("Invalid SSL Certificate", 20, "SSL certificate is untrusted or misconfigured.")

    # ── Domain Age ───────────────────────────────────────────────────────────
    age = signals.get("domain_age_days")
    if age is not None:
        if age < 30:
            hit("Very New Domain", 25, f"Domain is only {age} day(s) old — common in phishing campaigns.")
        elif age < 180:
            hit("Recently Registered Domain", 10, f"Domain is {age} days old — relatively new.")

    # ── Suspicious Keywords ───────────────────────────────────────────────────
    keywords = signals.get("keyword_list", [])
    if keywords:
        hit("Suspicious Keywords", 20, f"Keywords detected: {', '.join(keywords)}.")

    # ── IP Address Hostname ───────────────────────────────────────────────────
    if signals.get("is_ip_host", False):
        hit("IP Address as Hostname", 20, "URL uses a raw IP instead of a domain name.")

    # ── Subdomains ────────────────────────────────────────────────────────────
    if signals.get("subdomain_count", 0) > 3:
        count = signals["subdomain_count"]
        hit("Excessive Subdomains", 10, f"{count} subdomains detected — common obfuscation tactic.")

    # ── URL Length ────────────────────────────────────────────────────────────
    if signals.get("url_length", 0) > 75:
        hit("Very Long URL", 10, f"URL is {signals['url_length']} characters — often used to hide real domain.")

    # ── Special Characters ────────────────────────────────────────────────────
    if signals.get("has_special_chars", False):
        hit("Suspicious Characters in URL", 10, "URL contains @, //, or percent-encoded characters.")

    # ── Structural Anomalies ──────────────────────────────────────────────────
    struct_issues = signals.get("structural_issues", [])
    if struct_issues:
        for issue in struct_issues:
            if "Suspicious TLD" in issue:
                hit("Suspicious TLD", 15, issue)
            elif "Random/gibberish" in issue:
                hit("Random/Gibberish Domain", 15, issue)
            else:
                hit("Structural Anomaly", 10, issue)

    # ── DNS ───────────────────────────────────────────────────────────────────
    if not signals.get("dns_resolves", True):
        hit("DNS Resolution Failure", 15, "Domain does not resolve — may be a dead or fake site.")

    # ── Threat Intelligence ───────────────────────────────────────────────────
    if signals.get("threat_detected", False):
        source  = signals.get("threat_source", "Threat API")
        detects = signals.get("threat_detections", 0)
        threat_types = signals.get("threat_types", [])
        type_str = f" ({', '.join(threat_types)})" if threat_types else ""
        hit(
            "Threat Intelligence Detection",
            50,
            f"Flagged by {source}{type_str}"
            + (f" — {detects} engine(s)" if detects else "") + ".",
        )

    # ── ML Model ─────────────────────────────────────────────────────────────
    if signals.get("ml_prediction") == "phishing":
        conf = signals.get("ml_confidence", 0)
        hit("ML Model: Phishing Detected", 30, f"Machine learning model confidence: {conf}%.")

    # ── Brand Impersonation ───────────────────────────────────────────────────
    if signals.get("brand_impersonation", False):
        brand    = signals.get("impersonated_brand", "a known brand")
        sim      = signals.get("brand_similarity", 0)
        method   = signals.get("brand_method", "similarity detection")
        category = signals.get("brand_category", "")
        char_sub = signals.get("brand_char_substitution", False)
        homoglyph = signals.get("brand_homoglyph", False)
        susp_tld  = signals.get("brand_suspicious_tld", False)

        # Base brand impersonation rule
        base_pts = 35 if sim >= 90 else (20 if sim >= 80 else 15)
        hit(
            "Brand Impersonation Detected",
            base_pts,
            f"Domain is impersonating '{brand}' via {method} with {sim}% similarity.",
        )

        # Category bonus: banking / government targets are higher risk
        if category in ("banking", "government"):
            hit(
                f"{'Banking' if category == 'banking' else 'Government'} Brand Target",
                15,
                f"Impersonated brand belongs to '{category}' category — high-value target.",
            )

        # Character substitution bonus
        if char_sub:
            hit(
                "Character Substitution Attack",
                15,
                "Domain uses character substitutions (e.g. 0→o, 1→l, rn→m) to mimic brand.",
            )

        # Homoglyph / Unicode attack bonus
        if homoglyph:
            hit(
                "Homoglyph/Unicode Attack",
                25,
                "Domain uses Unicode homoglyph characters (Cyrillic, punycode) to impersonate brand.",
            )

        # Brand + suspicious TLD combo
        if susp_tld and sim >= 70:
            hit(
                "Brand + Suspicious TLD",
                20,
                "Brand name combined with suspicious TLD (.xyz, .top, .click, etc.).",
            )

    # ── Visual Phishing ───────────────────────────────────────────────────────
    if signals.get("visual_threat", False):
        reason = signals.get("visual_reason", "Visual analysis flagged suspicious content.")
        hit("Visual Phishing Detected", 40, reason)

    return triggered


# ─── Public API ───────────────────────────────────────────────────────────────

def calculate_risk(signals: dict) -> dict:
    """
    Run the scoring engine with threat priority overrides.

    Priority System:
      1. Confirmed Threat Intelligence → force score/verdict
      2. Brand Impersonation >= 90%    → force score >= 95
      3. Normal rule-based scoring     → thresholds

    Args:
        signals: dict produced by feature_extractor.extract_raw_signals()
                 optionally enriched with threat_intel and ml_result keys.

    Returns:
        {
          "score":           int   (0–100),
          "verdict":         str,
          "triggered_rules": list[dict],
          "rule_count":      int,
        }
    """
    triggered = _score_signals(signals)
    raw_score  = sum(r["points"] for r in triggered)
    score      = min(raw_score, 100)

    # ── Priority 1: Threat Intelligence Override ──────────────────────────────
    # If a trusted TI source confirms a threat, force high score + specific verdict
    threat_types = signals.get("threat_types", [])
    ti_override_verdict = None
    ti_override_score = None

    for tt in threat_types:
        override = _THREAT_TYPE_OVERRIDES.get(tt)
        if override:
            if ti_override_score is None or override["score"] > ti_override_score:
                ti_override_score = override["score"]
                ti_override_verdict = override["verdict"]

    if ti_override_verdict:
        score = max(score, ti_override_score)
        verdict = ti_override_verdict
        logger.info(
            "[Risk Engine] PRIORITY 1 OVERRIDE: TI confirmed %s → score=%d verdict='%s'",
            ", ".join(threat_types), score, verdict,
        )
        return {
            "score":           score,
            "verdict":         verdict,
            "triggered_rules": triggered,
            "rule_count":      len(triggered),
        }

    # ── Priority 2: Brand Impersonation Override ──────────────────────────────
    # If brand impersonation with >= 90% similarity, force phishing
    if signals.get("brand_impersonation", False):
        sim = signals.get("brand_similarity", 0)
        if sim >= 90:
            score = max(score, 95)
            verdict = "Phishing Detected"
            brand = signals.get("impersonated_brand", "unknown")
            logger.info(
                "[Risk Engine] PRIORITY 2 OVERRIDE: Brand '%s' impersonation %d%% → score=%d",
                brand, sim, score,
            )
            return {
                "score":           score,
                "verdict":         verdict,
                "triggered_rules": triggered,
                "rule_count":      len(triggered),
            }

    # ── Normal threshold-based verdict ────────────────────────────────────────
    verdict = "Safe"
    for threshold, label in VERDICT_THRESHOLDS:
        if score >= threshold:
            verdict = label
            break

    logger.info(
        "[Risk Engine] score=%d verdict='%s' rules=%d",
        score, verdict, len(triggered),
    )

    return {
        "score":           score,
        "verdict":         verdict,
        "triggered_rules": triggered,
        "rule_count":      len(triggered),
    }


def verdict_to_severity(verdict: str) -> str:
    """Map a verdict string to a short severity label used by the UI."""
    return {
        "Safe":                         "LOW",
        "Looks Safe":                   "LOW",     # backward compat
        "Suspicious":                   "MEDIUM",
        "Suspicious Website":           "MEDIUM",
        "High Risk":                    "HIGH",
        "Confirmed Threat":             "CRITICAL",
        "Phishing Detected":            "CRITICAL",
        "Malware Detected":             "CRITICAL",
        "Unwanted Software Detected":   "CRITICAL",
        "Harmful Application Detected": "CRITICAL",
        "Brand Impersonation Detected": "CRITICAL",
    }.get(verdict, "UNKNOWN")
