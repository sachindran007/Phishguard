"""
detector.py
-----------
ML-based phishing detector with advanced security features.

Loads the pre-trained Random Forest model (model.pkl) and predicts
whether a URL is phishing or legitimate from enriched features.

Enhanced feature vector (v2) includes brand/typosquatting signals:
  [url_length, num_dots, num_hyphens, num_slashes, num_special_chars,
   has_https, domain_age_days, subdomain_count, is_ip_host, keyword_count,
   has_at_sign, url_depth,
   # v2 additions:
   brand_similarity, has_homograph, has_number_substitution,
   entropy, suspicious_tld, hyphen_ratio]

Usage:
    from ml.detector import predict_phishing
    result = predict_phishing(url, signals)
    # → {"prediction": "phishing", "confidence": 94, "available": True}
"""

from __future__ import annotations
import os
import re
import math
import logging
import numpy as np

logger = logging.getLogger(__name__)

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
_model = None   # lazy-loaded singleton


# ─── Brand / Typosquatting Helpers ────────────────────────────────────────────

_TOP_BRANDS = [
    "google", "facebook", "instagram", "amazon", "paypal", "microsoft",
    "apple", "netflix", "twitter", "linkedin", "github", "whatsapp",
    "telegram", "yahoo", "dropbox", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "alibaba", "ebay", "spotify", "zoom", "slack",
]

_HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "8": "b",
    "@": "a", "!": "i", "|": "l", "$": "s",
}


def _normalize_homographs(domain: str) -> str:
    """Replace common homograph characters to get the 'intended' domain."""
    result = []
    for c in domain.lower():
        result.append(_HOMOGRAPH_MAP.get(c, c))
    return "".join(result)


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]


def _best_brand_similarity(domain_label: str) -> tuple[float, str]:
    """
    Check domain against all known brands.
    Returns (similarity_0_to_1, matched_brand).
    """
    normalized = _normalize_homographs(domain_label)
    best_sim = 0.0
    best_brand = ""

    for brand in _TOP_BRANDS:
        # Exact match after normalization
        if normalized == brand:
            return 1.0, brand

        # Levenshtein similarity
        max_len = max(len(normalized), len(brand))
        if max_len == 0:
            continue
        dist = _levenshtein(normalized, brand)
        sim = 1.0 - (dist / max_len)

        # Also check if brand is a substring (e.g. "paypal" in "paypal-login")
        if brand in normalized and len(brand) >= 4:
            sim = max(sim, 0.85)

        if sim > best_sim:
            best_sim = sim
            best_brand = brand

    return best_sim, best_brand


def _has_number_substitution(domain: str) -> bool:
    """Check if domain uses numbers as letter substitutes."""
    for char, replacement in _HOMOGRAPH_MAP.items():
        if char.isdigit() and char in domain:
            # Check if replacing this makes it closer to a brand
            test = domain.replace(char, replacement)
            for brand in _TOP_BRANDS:
                if brand in test:
                    return True
    return False


def _calculate_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cc", ".su", ".buzz", ".club", ".work", ".space",
}


# ─── Model Loading ────────────────────────────────────────────────────────────

def _load_model():
    """Load and cache the trained model. Returns None if model.pkl not found."""
    global _model
    if _model is not None:
        return _model
    if not os.path.exists(_MODEL_PATH):
        logger.warning(
            "[ML Engine] Model not found at %s. Run 'python -m ml.train' to generate it.",
            _MODEL_PATH,
        )
        return None
    try:
        import joblib
        _model = joblib.load(_MODEL_PATH)
        logger.info("[ML Engine] Model loaded from %s", _MODEL_PATH)
        return _model
    except Exception as e:
        logger.error("[ML Engine] Failed to load model: %s", e)
        return None


# ─── Feature Engineering ──────────────────────────────────────────────────────

def _build_feature_vector(url: str, signals: dict) -> np.ndarray:
    """
    Convert a URL + signals dict into the numeric feature vector
    expected by the model. Includes v2 brand/security features.
    """
    from urllib.parse import urlparse
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path     or ""

    # ── Original v1 features ──────────────────────────────────────────────
    url_length      = len(url)
    num_dots        = hostname.count(".")
    num_hyphens     = url.count("-")
    num_slashes     = path.count("/")
    num_special     = sum(url.count(c) for c in ("@", "%", "="))
    has_https       = 1 if signals.get("is_https", False) else 0
    age_days        = signals.get("domain_age_days") or 999   # 999 = unknown
    subdomain_count = signals.get("subdomain_count", 0)
    is_ip           = 1 if signals.get("is_ip_host", False) else 0
    keyword_count   = len(signals.get("keyword_list", []))
    has_at          = 1 if "@" in url else 0
    url_depth       = len([s for s in path.split("/") if s])

    # ── v2 brand/typosquatting features ───────────────────────────────────
    domain_label = hostname.split(".")[0] if "." in hostname else hostname

    brand_sim, matched_brand = _best_brand_similarity(domain_label)
    has_homograph   = 1 if _normalize_homographs(domain_label) != domain_label else 0
    has_num_subst   = 1 if _has_number_substitution(domain_label) else 0
    entropy         = _calculate_entropy(domain_label)
    suspicious_tld  = 0
    for tld in _SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            suspicious_tld = 1
            break
    hyphen_ratio = num_hyphens / max(len(hostname), 1)

    return np.array([[
        url_length, num_dots, num_hyphens, num_slashes, num_special,
        has_https, age_days, subdomain_count, is_ip, keyword_count,
        has_at, url_depth,
        # v2 additions
        brand_sim, has_homograph, has_num_subst,
        entropy, suspicious_tld, hyphen_ratio,
    ]], dtype=float)


# ─── Prediction ───────────────────────────────────────────────────────────────

def predict_phishing(url: str, signals: dict) -> dict:
    """
    Predict whether a URL is phishing using the trained ML model.
    Falls back to heuristic scoring if the model feature count doesn't match.

    Returns:
        {
          "available":   bool  – False if model.pkl is not loaded
          "prediction":  str   – "phishing" | "legitimate"
          "confidence":  int   – 0–100 (model probability %)
        }
    """
    model = _load_model()
    if model is None:
        return {"available": False, "prediction": "unknown", "confidence": 0}

    try:
        features = _build_feature_vector(url, signals)

        # Handle model trained on v1 features (12 cols) vs v2 (18 cols)
        expected_features = model.n_features_in_
        if features.shape[1] > expected_features:
            # Model was trained on fewer features — use only the first N
            # but also run heuristic scoring on the extra features
            brand_sim = features[0, 12] if features.shape[1] > 12 else 0
            has_homograph = features[0, 13] if features.shape[1] > 13 else 0
            has_num_subst = features[0, 14] if features.shape[1] > 14 else 0

            features_trimmed = features[:, :expected_features]
            proba = model.predict_proba(features_trimmed)[0]
            phish_prob = proba[1]

            # Boost phishing probability if brand signals are strong
            if brand_sim > 0.8 and (has_homograph or has_num_subst):
                # Strong brand impersonation — boost significantly
                phish_prob = min(phish_prob + 0.45, 0.99)
                logger.info("[ML Engine] Brand boost applied: sim=%.2f homograph=%d num_subst=%d",
                            brand_sim, has_homograph, has_num_subst)
            elif brand_sim > 0.6:
                phish_prob = min(phish_prob + 0.25, 0.95)

        else:
            proba = model.predict_proba(features)[0]
            phish_prob = proba[1]

        label = "phishing" if phish_prob >= 0.5 else "legitimate"
        confidence = int(round(phish_prob * 100 if label == "phishing" else (1 - phish_prob) * 100))

        logger.info("[ML Engine] Prediction: %s (%.1f%%)", label, phish_prob * 100)
        return {
            "available":  True,
            "prediction": label,
            "confidence": confidence,
        }
    except Exception as e:
        logger.error("[ML Engine] Prediction failed: %s", e)
        return {"available": False, "prediction": "unknown", "confidence": 0}
