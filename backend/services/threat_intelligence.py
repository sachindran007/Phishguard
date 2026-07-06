"""
threat_intelligence.py
----------------------
Threat intelligence layer: Google Safe Browsing + VirusTotal.

Both checkers are fully independent and fail gracefully.
Missing API keys → checker is skipped, result marked as "not_configured".

Environment variables:
  GOOGLE_SAFE_BROWSING_API_KEY  – Google Safe Browsing v4 API key
  VIRUSTOTAL_API_KEY            – VirusTotal public API key

Standard result shape:
  {
    "checked":    bool   – True if the API was actually called
    "detected":   bool   – True if a threat was found
    "source":     str    – "Google Safe Browsing" | "VirusTotal"
    "details":    str    – human-readable summary
    "detections": int    – number of engines that flagged (VT only)
    "error":      str|None
  }
"""

from __future__ import annotations
import os
import base64
import hashlib
import logging
import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 8   # seconds for each API call

# ─── Shared result builder ────────────────────────────────────────────────────

def _result(
    source: str,
    *,
    checked: bool = True,
    detected: bool = False,
    details: str = "",
    detections: int = 0,
    error: str | None = None,
    threat_types: list[str] | None = None,
) -> dict:
    return {
        "checked":      checked,
        "detected":     detected,
        "source":       source,
        "details":      details,
        "detections":   detections,
        "error":        error,
        "threat_types": threat_types or [],
    }


# ─── Google Safe Browsing ─────────────────────────────────────────────────────
# NOTE: This is a PLACEHOLDER implementation.
# To activate: add GOOGLE_SAFE_BROWSING_API_KEY to your .env file.
# API docs: https://developers.google.com/safe-browsing/v4/lookup-api
# ─────────────────────────────────────────────────────────────────────────────

_GSB_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
)
_GSB_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

def check_google_safe_browsing(url: str) -> dict:
    """
    Query Google Safe Browsing v4 Lookup API.

    Returns a standard threat-intel result dict.
    Gracefully returns 'not_configured' if the API key is absent.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    # ── Placeholder mode (no key) ──────────────────────────────────────────
    if not api_key:
        return _result(
            "Google Safe Browsing",
            checked=False,
            details="API key not configured. Add GOOGLE_SAFE_BROWSING_API_KEY to .env to enable.",
        )

    # ── Live API call ──────────────────────────────────────────────────
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "3.0"},
        "threatInfo": {
            "threatTypes":      _GSB_THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    logger.info("[Safe Browsing] Request started for: %s", url[:60])
    try:
        resp = requests.post(
            _GSB_ENDPOINT.format(key=api_key),
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        if matches:
            types = list({m.get("threatType", "") for m in matches})
            logger.info("[Safe Browsing] THREAT FOUND: %s", ", ".join(types))
            return _result(
                "Google Safe Browsing",
                detected=True,
                details=f"Threat detected: {', '.join(types)}.",
                detections=len(matches),
                threat_types=types,
            )
        logger.info("[Safe Browsing] Result: SAFE")
        return _result(
            "Google Safe Browsing",
            detected=False,
            details="No threats found in Google Safe Browsing database.",
        )

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "unknown"
        logger.warning("[Safe Browsing] API ERROR: HTTP %s — %s", status_code, str(e)[:100])
        return _result("Google Safe Browsing", checked=False, error=f"HTTP {status_code}: {str(e)[:100]}")
    except requests.exceptions.Timeout:
        logger.warning("[Safe Browsing] API ERROR: Request timed out (%ds)", _TIMEOUT)
        return _result("Google Safe Browsing", checked=False, error="Request timed out")
    except Exception as e:
        logger.warning("[Safe Browsing] API ERROR: %s", str(e)[:120])
        return _result("Google Safe Browsing", checked=False, error=str(e)[:120])


# ─── VirusTotal ───────────────────────────────────────────────────────────────

_VT_BASE   = "https://www.virustotal.com/api/v3"

def _vt_url_id(url: str) -> str:
    """VirusTotal expects a base64url-encoded URL (no padding) as the resource ID."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check_virustotal(url: str) -> dict:
    """
    Query VirusTotal v3 URL analysis endpoint.

    Free tier limit: 4 requests/minute, 500/day.
    Returns a standard threat-intel result dict.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        return _result(
            "VirusTotal",
            checked=False,
            details="API key not configured. Add VIRUSTOTAL_API_KEY to .env to enable.",
        )

    headers = {"x-apikey": api_key}
    url_id  = _vt_url_id(url)

    try:
        resp = requests.get(
            f"{_VT_BASE}/urls/{url_id}",
            headers=headers,
            timeout=_TIMEOUT,
        )

        # 404 → URL not in VT database yet; submit for analysis
        if resp.status_code == 404:
            return _result(
                "VirusTotal",
                detected=False,
                details="URL not yet in VirusTotal database. No prior scan results available.",
            )

        resp.raise_for_status()
        data  = resp.json()
        stats = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) if stats else 0
        flagged    = malicious + suspicious

        if malicious > 0:
            return _result(
                "VirusTotal",
                detected=True,
                details=(
                    f"{malicious} security engine(s) flagged this URL as malicious "
                    f"({suspicious} suspicious) out of {total} total."
                ),
                detections=flagged,
            )
        if suspicious > 0:
            return _result(
                "VirusTotal",
                detected=True,
                details=f"{suspicious} engine(s) marked this URL as suspicious out of {total}.",
                detections=flagged,
            )

        return _result(
            "VirusTotal",
            detected=False,
            details=f"No threats detected. Checked by {total} security engine(s).",
        )

    except requests.exceptions.HTTPError as e:
        logger.warning("VirusTotal HTTP error: %s", e)
        return _result("VirusTotal", checked=False, error=str(e)[:120])
    except Exception as e:
        logger.warning("VirusTotal check failed: %s", e)
        return _result("VirusTotal", checked=False, error=str(e)[:120])


# ─── Combined Checker ─────────────────────────────────────────────────────────

def run_threat_intelligence(url: str) -> dict:
    """
    Run both threat-intel checks and return a combined result.

    Returns:
        {
          "safe_browsing": {...},
          "virustotal":    {...},
          "any_detected":  bool,
          "threat_source": str | None,
          "detections":    int,
        }
    """
    gsb = check_google_safe_browsing(url)
    vt  = check_virustotal(url)

    any_detected   = gsb["detected"] or vt["detected"]
    threat_source  = None
    detections     = 0
    threat_types   = []

    if gsb["detected"]:
        threat_source = "Google Safe Browsing"
        detections   += gsb["detections"]
        threat_types.extend(gsb.get("threat_types", []))
    if vt["detected"]:
        threat_source = "VirusTotal" if not threat_source else "Multiple Sources"
        detections   += vt["detections"]

    return {
        "safe_browsing": gsb,
        "virustotal":    vt,
        "any_detected":  any_detected,
        "threat_source": threat_source,
        "detections":    detections,
        "threat_types":  threat_types,
    }
