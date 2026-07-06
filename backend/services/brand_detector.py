"""
brand_detector.py
-----------------
Production-quality brand impersonation detection engine.

Loads brand database, TLD lists, character rules, and whitelist from
JSON config files in backend/config/. No hardcoded brand lists.

Detection algorithms:
  1. Levenshtein edit distance
  2. Jaro-Winkler similarity
  3. Unicode homoglyph detection (Cyrillic, punycode)
  4. Character substitution detection (0→o, 1→l, rn→m, etc.)
  5. Hyphen abuse detection (paypal-login-secure.xyz)
  6. Subdomain abuse detection (paypal.evil.com)
  7. Suspicious TLD detection
  8. Brand + keyword combination detection

Category-aware risk scoring:
  Banking / Government brand impersonation → extra +15 points
  Homoglyph attack → extra +25 points

Output format:
  {
    "brand_impersonation": bool,
    "target_brand":        str | None,
    "category":            str | None,
    "similarity":          int (0-100),
    "method":              str | None,
    "character_substitution": bool,
    "homoglyph_detected":  bool,
    "suspicious_tld":      bool,
    "risk_added":          int,
    "detail":              str,
    "checked":             bool,
  }
"""

from __future__ import annotations
import os
import re
import json
import math
import logging
import unicodedata
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)

_CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")


# ═══════════════════════════════════════════════════════════════════════════════
#  Configuration Loader
# ═══════════════════════════════════════════════════════════════════════════════

def _load_json(filename: str) -> Any:
    """Load a JSON config file from backend/config/."""
    path = os.path.join(_CONFIG_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug("[Brand Detector] Loaded config: %s", filename)
        return data
    except FileNotFoundError:
        logger.warning("[Brand Detector] Config not found: %s", path)
        return {}
    except json.JSONDecodeError as e:
        logger.error("[Brand Detector] Invalid JSON in %s: %s", path, e)
        return {}


@lru_cache(maxsize=1)
def _get_brands() -> dict[str, dict]:
    """
    Load brands.json and flatten into:
      { "google": {"domains": [...], "keywords": [...], "category": "technology"}, ... }
    """
    raw = _load_json("brands.json")
    flat: dict[str, dict] = {}
    for category, brands in raw.items():
        for brand_name, brand_data in brands.items():
            flat[brand_name] = {
                "domains":  brand_data.get("domains", []),
                "keywords": brand_data.get("keywords", []),
                "category": category,
            }
    logger.info("[Brand Detector] Loaded %d brands across %d categories",
                len(flat), len(raw))
    return flat


@lru_cache(maxsize=1)
def _get_suspicious_tlds() -> set[str]:
    data = _load_json("suspicious_tlds.json")
    return set(data.get("suspicious_tlds", []))


@lru_cache(maxsize=1)
def _get_trusted_tlds() -> set[str]:
    data = _load_json("trusted_tlds.json")
    return set(data.get("trusted_tlds", []))


@lru_cache(maxsize=1)
def _get_char_rules() -> tuple[dict[str, str], dict[str, str]]:
    data = _load_json("character_rules.json")
    single = data.get("single_char_substitutions", {})
    multi  = data.get("multi_char_substitutions", {})
    return single, multi


@lru_cache(maxsize=1)
def _get_whitelist() -> set[str]:
    data = _load_json("whitelist.json")
    return set(d.lower() for d in data.get("whitelisted_domains", []))


# ═══════════════════════════════════════════════════════════════════════════════
#  String Distance Algorithms
# ═══════════════════════════════════════════════════════════════════════════════

def _levenshtein(a: str, b: str) -> int:
    """Standard dynamic-programming Levenshtein distance."""
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[j] = prev[j - 1]
            else:
                dp[j] = 1 + min(prev[j], dp[j - 1], prev[j - 1])
    return dp[n]


def _jaro_winkler(s1: str, s2: str) -> float:
    """
    Jaro-Winkler similarity (0.0 – 1.0).
    Higher values = more similar. Gives a prefix bonus for matching starts.
    """
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (matches / len1 + matches / len2 +
            (matches - transpositions / 2) / matches) / 3

    # Winkler prefix bonus
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + prefix * 0.1 * (1 - jaro)


def _similarity_pct(a: str, b: str) -> int:
    """Return 0-100 similarity using max of Levenshtein-based and Jaro-Winkler."""
    if not a and not b:
        return 100
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 100

    lev_sim = 1 - _levenshtein(a, b) / max_len
    jw_sim = _jaro_winkler(a, b)
    return int(round(max(lev_sim, jw_sim) * 100))


# ═══════════════════════════════════════════════════════════════════════════════
#  Normalization & Detection Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize(s: str) -> str:
    """Apply character substitution rules and lowercase."""
    single, multi = _get_char_rules()
    s = s.lower()
    # Apply multi-char substitutions first (rn→m, vv→w)
    for pattern, replacement in multi.items():
        s = s.replace(pattern, replacement)
    # Apply single-char substitutions
    for char, replacement in single.items():
        s = s.replace(char.lower(), replacement)
    return s


def _detect_homoglyphs(domain_label: str) -> bool:
    """
    Detect Unicode homoglyph characters (Cyrillic, Greek, etc.)
    that visually mimic ASCII characters.
    """
    for char in domain_label:
        if ord(char) > 127:
            # Non-ASCII character in domain label
            cat = unicodedata.category(char)
            if cat.startswith("L"):  # Letter category
                return True
    return False


def _is_punycode(hostname: str) -> bool:
    """Check if hostname contains punycode-encoded labels (xn--)."""
    return any(part.startswith("xn--") for part in hostname.split("."))


def _detect_char_substitution(raw_label: str, brand: str) -> bool:
    """Check if the raw label uses character substitutions to mimic a brand."""
    single, multi = _get_char_rules()
    normalized = _normalize(raw_label)
    if normalized == brand and raw_label.lower() != brand:
        return True
    # Check if any substitution chars from the rules appear in the raw label
    for char in single:
        if char.lower() in raw_label.lower():
            test = raw_label.lower().replace(char.lower(), single[char])
            for mp, mr in multi.items():
                test = test.replace(mp, mr)
            if brand in test:
                return True
    return False


def _get_tld(hostname: str) -> str:
    """Extract the TLD from a hostname."""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 3:
        # Check compound TLDs first (gov.in, co.in, co.uk)
        compound = "." + ".".join(parts[-2:])
        if compound in _get_trusted_tlds() or compound in _get_suspicious_tlds():
            return compound
    return "." + parts[-1] if parts else ""


def _is_suspicious_tld(hostname: str) -> bool:
    """Check if the hostname uses a suspicious TLD."""
    tld = _get_tld(hostname)
    return tld in _get_suspicious_tlds()


# ═══════════════════════════════════════════════════════════════════════════════
#  Domain Extraction Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _registered_domain(hostname: str) -> str:
    """Extract registered domain: 'secure.paypal.evil.com' → 'evil.com'"""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return hostname


def _domain_label(hostname: str) -> str:
    """Return the SLD label: 'paypal.com' → 'paypal'"""
    parts = hostname.rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


# ═══════════════════════════════════════════════════════════════════════════════
#  Official Domain Checking
# ═══════════════════════════════════════════════════════════════════════════════

def _check_exact_official(hostname: str) -> tuple[bool, str | None]:
    """
    Check if hostname is an official brand domain.
    Returns (is_official, brand_name_or_none).
    """
    # Check whitelist first
    if hostname in _get_whitelist():
        return True, None

    brands = _get_brands()
    for brand_name, brand_data in brands.items():
        for domain in brand_data["domains"]:
            if hostname == domain or hostname.endswith("." + domain):
                return True, brand_name
    return False, None


def is_official_domain(hostname: str) -> bool:
    """Public helper — returns True if hostname belongs to a known brand."""
    hostname = hostname.lower().rstrip(".")
    is_official, _ = _check_exact_official(hostname)
    return is_official


# ═══════════════════════════════════════════════════════════════════════════════
#  Core Detection Engine
# ═══════════════════════════════════════════════════════════════════════════════

def _calculate_risk_points(
    similarity: int,
    category: str,
    char_sub: bool,
    homoglyph: bool,
    suspicious_tld: bool,
) -> int:
    """Calculate total risk points based on detection signals."""
    points = 0

    # Base similarity scoring
    if similarity >= 90:
        points += 35
    elif similarity >= 80:
        points += 20

    # Category bonuses
    if category in ("banking", "government"):
        points += 15

    # Character substitution bonus
    if char_sub:
        points += 15

    # Homoglyph bonus
    if homoglyph:
        points += 25

    # Brand + suspicious TLD combo
    if suspicious_tld and similarity >= 70:
        points += 20

    return points


def check_brand_impersonation(url: str, hostname: str) -> dict:
    """
    Run production-quality brand impersonation detection.

    Args:
        url:      Full normalized URL string
        hostname: Extracted hostname (e.g. 'paypal-secure.xyz')

    Returns:
        {
          "brand_impersonation":    bool,
          "target_brand":           str | None,
          "category":               str | None,
          "similarity":             int (0-100),
          "method":                 str | None,
          "matched_algorithm":      str | None,
          "character_substitution": bool,
          "homoglyph_detected":     bool,
          "suspicious_tld":         bool,
          "risk_added":             int,
          "detail":                 str,
          "checked":                bool,
        }
    """
    _safe_result = {
        "brand_impersonation":    False,
        "target_brand":           None,
        "category":               None,
        "similarity":             0,
        "method":                 None,
        "matched_algorithm":      None,
        "character_substitution": False,
        "homoglyph_detected":     False,
        "suspicious_tld":         False,
        "risk_added":             0,
        "detail":                 "",
        "checked":                True,
    }

    try:
        hostname = hostname.lower().rstrip(".")

        # ── Whitelist / official domain check ─────────────────────────────
        is_official, official_brand = _check_exact_official(hostname)
        if is_official:
            return {
                **_safe_result,
                "similarity": 100,
                "detail":     "Domain matches an official brand domain.",
            }

        # ── Extract domain parts ──────────────────────────────────────────
        reg_domain   = _registered_domain(hostname)
        sld_raw      = _domain_label(hostname)
        sld_norm     = _normalize(sld_raw)
        sld_clean    = re.sub(r"[-_.]+", "", sld_norm)
        has_susp_tld = _is_suspicious_tld(hostname)
        has_homoglyph = _detect_homoglyphs(sld_raw) or _is_punycode(hostname)

        brands = _get_brands()

        best: dict = {
            "brand": None, "category": None, "sim": 0,
            "method": None, "algorithm": None, "char_sub": False,
            "detail": "",
        }

        for brand_name, brand_data in brands.items():
            category = brand_data["category"]
            official_domains = brand_data["domains"]

            # ── Method 1: Subdomain abuse ─────────────────────────────────
            for od in official_domains:
                od_bare = od.split(".")[0]
                if hostname != od and hostname.endswith("." + od):
                    continue  # legit subdomain
                if reg_domain not in official_domains and \
                   (hostname.startswith(f"{od_bare}.") or f".{od_bare}." in hostname):
                    sim = 95
                    if sim > best["sim"]:
                        best.update({
                            "brand": brand_name, "category": category,
                            "sim": sim, "method": "subdomain_abuse",
                            "algorithm": "pattern_match",
                            "char_sub": False,
                            "detail": f"Brand '{brand_name}' appears as subdomain of non-official domain.",
                        })

            # ── Method 2: Levenshtein on normalized SLD ───────────────────
            brand_norm = _normalize(brand_name)
            dist = _levenshtein(sld_norm, brand_norm)
            max_l = max(len(sld_norm), len(brand_norm))
            threshold = 1 if len(brand_norm) <= 5 else (2 if len(brand_norm) <= 8 else 3)

            if dist <= threshold and dist > 0 and max_l > 0:
                sim = _similarity_pct(sld_norm, brand_norm)
                if sim > best["sim"]:
                    char_sub = _detect_char_substitution(sld_raw, brand_name)
                    best.update({
                        "brand": brand_name, "category": category,
                        "sim": sim, "method": "typosquatting",
                        "algorithm": "levenshtein",
                        "char_sub": char_sub,
                        "detail": (
                            f"Domain SLD '{sld_raw}' is {dist} edit(s) from '{brand_name}' "
                            f"({sim}% similarity)."
                        ),
                    })

            # ── Method 3: Jaro-Winkler on normalized SLD ──────────────────
            jw_score = _jaro_winkler(sld_norm, brand_norm)
            jw_pct = int(round(jw_score * 100))
            if jw_pct > best["sim"] and jw_pct >= 85 and sld_norm != brand_norm:
                char_sub = _detect_char_substitution(sld_raw, brand_name)
                best.update({
                    "brand": brand_name, "category": category,
                    "sim": jw_pct, "method": "typosquatting",
                    "algorithm": "jaro_winkler",
                    "char_sub": char_sub,
                    "detail": (
                        f"Domain SLD '{sld_raw}' has {jw_pct}% Jaro-Winkler similarity "
                        f"to '{brand_name}'."
                    ),
                })

            # ── Method 4: Homograph substitution (exact match after norm) ─
            brand_clean = re.sub(r"[-_.]+", "", brand_norm)
            if sld_clean == brand_clean and sld_raw.lower() != brand_name:
                sim = 96
                char_sub = _detect_char_substitution(sld_raw, brand_name)
                if sim > best["sim"]:
                    best.update({
                        "brand": brand_name, "category": category,
                        "sim": sim, "method": "homograph_substitution",
                        "algorithm": "character_normalization",
                        "char_sub": char_sub,
                        "detail": (
                            f"Domain '{sld_raw}' uses character substitutions "
                            f"to impersonate '{brand_name}' (e.g. 0→o, I→l)."
                        ),
                    })

            # ── Method 5: Prefix / suffix abuse ───────────────────────────
            for od in official_domains:
                od_bare = od.split(".")[0]
                od_norm = _normalize(od_bare)
                if (sld_clean.startswith(od_norm) or sld_clean.endswith(od_norm)) \
                        and sld_clean != od_norm and len(sld_clean) > len(od_norm):
                    sim = 80
                    if sim > best["sim"]:
                        best.update({
                            "brand": brand_name, "category": category,
                            "sim": sim, "method": "prefix_suffix_abuse",
                            "algorithm": "pattern_match",
                            "char_sub": False,
                            "detail": (
                                f"Domain '{sld_raw}' contains brand name '{od_bare}' "
                                f"with additional text — common phishing pattern."
                            ),
                        })

            # ── Method 6: Brand + keyword combo ───────────────────────────
            brand_keywords = brand_data.get("keywords", [])
            url_lower = url.lower()
            if brand_name in sld_clean or _normalize(brand_name) in sld_clean:
                for kw in brand_keywords:
                    if kw in url_lower and sld_clean != _normalize(brand_name):
                        sim = 82
                        if sim > best["sim"]:
                            best.update({
                                "brand": brand_name, "category": category,
                                "sim": sim, "method": "brand_keyword_combo",
                                "algorithm": "keyword_analysis",
                                "char_sub": False,
                                "detail": (
                                    f"Domain contains '{brand_name}' with associated "
                                    f"keyword '{kw}' — brand + keyword phishing pattern."
                                ),
                            })
                            break

        # ── Decision ──────────────────────────────────────────────────────
        THRESHOLD = 78
        detected = best["brand"] is not None and best["sim"] >= THRESHOLD

        if not detected:
            return {**_safe_result, "detail": "No brand impersonation detected."}

        risk_added = _calculate_risk_points(
            similarity=best["sim"],
            category=best["category"],
            char_sub=best["char_sub"],
            homoglyph=has_homoglyph,
            suspicious_tld=has_susp_tld,
        )

        logger.info(
            "[Brand Detector] Target: %s | Category: %s | Attack: %s | "
            "Algorithm: %s | Similarity: %d%% | CharSub: %s | Homoglyph: %s | "
            "SuspTLD: %s | Risk: +%d",
            best["brand"], best["category"], best["method"],
            best["algorithm"], best["sim"], best["char_sub"],
            has_homoglyph, has_susp_tld, risk_added,
        )

        return {
            "brand_impersonation":    True,
            "target_brand":           best["brand"],
            "category":               best["category"],
            "similarity":             best["sim"],
            "method":                 best["method"],
            "matched_algorithm":      best["algorithm"],
            "character_substitution": best["char_sub"],
            "homoglyph_detected":     has_homoglyph,
            "suspicious_tld":         has_susp_tld,
            "risk_added":             risk_added,
            "detail":                 best["detail"],
            "checked":                True,
        }

    except Exception as e:
        logger.error("[Brand Detector] Error: %s", e)
        return {
            **_safe_result,
            "detail":  f"Check failed: {str(e)[:120]}",
            "checked": False,
        }
