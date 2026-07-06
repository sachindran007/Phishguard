"""
ai_analyzer.py
--------------
Gemini AI — EXPLAINER ONLY (not decision maker).

The verdict and risk score are determined by risk_engine.py.
Gemini's sole job is to produce a plain-English explanation of
WHY the score was assigned, plus actionable user recommendations.

If Gemini is unavailable, a clear rule-based explanation is
generated from the triggered rules — the verdict is never affected.
"""

from __future__ import annotations
import os
import json
import re
import time
import logging

import google.generativeai as genai

logger = logging.getLogger(__name__)

# Ordered fallback chain — gemini-2.5-flash first (best quota availability)
_MODEL_CHAIN = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
]
_RETRY_DELAY_SECS = 2   # short delay before trying next model on 429


# ─── Gemini Setup ─────────────────────────────────────────────────────────────

def _get_model(name: str) -> genai.GenerativeModel | None:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        genai.configure(api_key=api_key)
        return genai.GenerativeModel(name)
    except Exception as e:
        logger.error("Gemini config error: %s", e)
        return None


# ─── Prompt Builder ───────────────────────────────────────────────────────────

def _build_explanation_prompt(
    url: str,
    score: int,
    verdict: str,
    triggered_rules: list[dict],
) -> str:
    """
    Build a prompt that tells Gemini the risk score is already decided.
    Gemini must ONLY explain and advise — never override the verdict.
    """
    rules_text = "\n".join(
        f"  • {r['rule']} (+{r['points']} pts): {r['detail']}"
        for r in triggered_rules
    ) or "  • No specific risk rules were triggered."

    return f"""You are a cybersecurity analyst writing a security report for an end user.

The automated risk engine has already determined the threat level. Your task is ONLY to:
1. Write a 2-3 sentence summary explaining EXACTLY why this URL was flagged.
2. Reference the SPECIFIC detection reasons listed below (e.g., "Google Safe Browsing identified this as SOCIAL_ENGINEERING" or "the domain uses character substitution to impersonate Google").
3. Provide 2-3 short, actionable recommendations.

IMPORTANT:
- DO NOT use vague language like "this website has security issues".
- DO reference the exact threat type, brand name, or detection method.
- DO NOT re-evaluate the verdict or change the score.

URL ANALYZED: {url}
RISK SCORE: {score}/100
THREAT LEVEL: {verdict}

DETECTION RULES THAT TRIGGERED:
{rules_text}

Respond with ONLY valid JSON (no markdown, no code fences):
{{
  "summary": "<2-3 sentence explanation citing SPECIFIC detection reasons from the rules above>",
  "recommendations": ["<recommendation 1>", "<recommendation 2>", "<recommendation 3>"]
}}"""


# ─── Response Parser ──────────────────────────────────────────────────────────

def _parse_response(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    data = json.loads(text.strip())
    return {
        "summary":         str(data.get("summary", "")),
        "recommendations": list(data.get("recommendations", [])),
    }


# ─── Rule-Based Fallback ──────────────────────────────────────────────────────

def _fallback_explanation(
    verdict: str,
    triggered_rules: list[dict],
    score: int,
) -> dict:
    """Generate a plain-English explanation without Gemini."""
    if not triggered_rules:
        summary = (
            f"This URL scored {score}/100 with no significant risk indicators detected. "
            "It appears to follow standard security practices."
        )
        recs = [
            "Still exercise caution before entering any sensitive information.",
            "Verify the domain matches the service you intended to visit.",
            "Check that the padlock icon is visible in your browser.",
        ]
    else:
        top = triggered_rules[:3]
        rule_names = ", ".join(r["rule"] for r in top)
        summary = (
            f"This URL received a risk score of {score}/100 ({verdict}). "
            f"Key concerns include: {rule_names}. "
            "These patterns are commonly associated with phishing and social engineering attacks."
        )
        recs = [
            "Do not enter passwords, credit card numbers, or personal data on this site.",
            "Verify the URL carefully — phishing sites often mimic legitimate services.",
            "If you received this link via email or message, treat it as highly suspicious.",
        ]

    return {
        "summary":         summary,
        "recommendations": recs,
        "fallback":        True,   # flag so frontend can note "AI unavailable"
    }


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_explanation(
    url: str,
    score: int,
    verdict: str,
    triggered_rules: list[dict],
) -> dict:
    """
    Generate a plain-English AI explanation for the given risk score.

    The verdict is NOT determined here — it is passed in from risk_engine.
    Tries gemini-2.0-flash, then gemini-2.0-flash-lite, then rule-based fallback.

    Returns:
        {
          "summary":         str,
          "recommendations": list[str],
          "fallback":        bool  (True if Gemini was unavailable)
        }
    """
    # Quick check: is any API key configured at all?
    model = _get_model(_MODEL_CHAIN[0])
    if model is None:
        logger.info("Gemini unavailable — using rule-based explanation.")
        return _fallback_explanation(verdict, triggered_rules, score)

    prompt = _build_explanation_prompt(url, score, verdict, triggered_rules)

    for model_name in _MODEL_CHAIN:
        mdl = _get_model(model_name)
        if mdl is None:
            continue
        try:
            response  = mdl.generate_content(prompt)
            result    = _parse_response(response.text)
            result["fallback"] = False
            logger.info("Gemini explanation generated via %s", model_name)
            return result

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("Gemini response parse error (%s): %s", model_name, e)
            break

        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err.lower() or "RESOURCE_EXHAUSTED" in err:
                logger.warning("Quota hit on %s, trying next fallback model...", model_name)
                time.sleep(_RETRY_DELAY_SECS)
                continue   # try next model
            logger.error("Gemini API error (%s): %s", model_name, e)
            break

    # All models exhausted — use deterministic rule-based explanation
    logger.info("All Gemini models exhausted. Using rule-based fallback explanation.")
    return _fallback_explanation(verdict, triggered_rules, score)


# ─── Legacy shim (keeps existing tests passing) ───────────────────────────────

def analyze_with_ai(url: str, findings: list) -> dict:
    """
    DEPRECATED shim — maintained for backward compatibility with existing tests.
    New code should call generate_explanation() directly.
    """
    warning_count = sum(1 for f in findings if "⚠" in f.get("value","") or "✗" in f.get("value",""))
    score_map     = {0: (0,"Looks Safe"), 1: (35,"Suspicious")}
    score, verdict = score_map.get(warning_count, (65 if warning_count <= 3 else 85, "High Risk" if warning_count <= 3 else "Phishing Detected"))
    explanation = generate_explanation(url, score, verdict, [])
    return {
        "verdict": verdict,
        "reason":  explanation["summary"],
    }
