"""
test_brand_detector.py
----------------------
Comprehensive tests for the JSON-config-driven brand detection engine.
"""
import pytest
from services.brand_detector import check_brand_impersonation, is_official_domain


# ═══════════════════════════════════════════════════════════════════════════════
#  Official Domain Tests (must NEVER trigger false positives)
# ═══════════════════════════════════════════════════════════════════════════════

class TestOfficialDomains:
    """Legitimate official domains must never be flagged."""

    def test_google_dot_com(self):
        res = check_brand_impersonation("https://google.com", "google.com")
        assert res["brand_impersonation"] is False
        assert res["similarity"] == 100

    def test_accounts_google(self):
        res = check_brand_impersonation("https://accounts.google.com", "accounts.google.com")
        assert res["brand_impersonation"] is False

    def test_support_microsoft(self):
        res = check_brand_impersonation("https://support.microsoft.com", "support.microsoft.com")
        assert res["brand_impersonation"] is False

    def test_paypal_dot_com(self):
        res = check_brand_impersonation("https://paypal.com", "paypal.com")
        assert res["brand_impersonation"] is False
        assert res["similarity"] == 100

    def test_hdfcbank_dot_com(self):
        res = check_brand_impersonation("https://hdfcbank.com", "hdfcbank.com")
        assert res["brand_impersonation"] is False

    def test_is_official_domain_helper(self):
        assert is_official_domain("google.com") is True
        assert is_official_domain("accounts.google.com") is True
        assert is_official_domain("g00gle.com") is False


# ═══════════════════════════════════════════════════════════════════════════════
#  Typosquatting Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestTyposquatting:
    """Character substitutions and typos must be detected."""

    def test_g00gle(self):
        res = check_brand_impersonation("https://g00gle.com", "g00gle.com")
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "google"
        assert res["similarity"] >= 90
        assert res["character_substitution"] is True

    def test_paypa1(self):
        res = check_brand_impersonation("https://paypa1.com", "paypa1.com")
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "paypal"

    def test_micros0ft(self):
        res = check_brand_impersonation("https://micros0ft.com", "micros0ft.com")
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "microsoft"

    def test_amaz0n_login(self):
        res = check_brand_impersonation("https://amaz0n-login.com", "amaz0n-login.com")
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "amazon"

    def test_paypaI(self):
        """Capital I replacing lowercase l."""
        res = check_brand_impersonation("https://paypaI.com", "paypaI.com")
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "paypal"
        assert res["method"] in ("homograph_substitution", "typosquatting")


# ═══════════════════════════════════════════════════════════════════════════════
#  Subdomain & Prefix/Suffix Abuse
# ═══════════════════════════════════════════════════════════════════════════════

class TestStructuralAbuse:

    def test_subdomain_abuse(self):
        res = check_brand_impersonation(
            "https://paypal.secure-login.com", "paypal.secure-login.com"
        )
        assert res["brand_impersonation"] is True
        assert res["method"] == "subdomain_abuse"
        assert res["target_brand"] == "paypal"

    def test_prefix_suffix_abuse(self):
        res = check_brand_impersonation(
            "https://secure-paypal.com", "secure-paypal.com"
        )
        assert res["brand_impersonation"] is True
        assert res["method"] == "prefix_suffix_abuse"
        assert res["target_brand"] == "paypal"

    def test_paypal_login_xyz(self):
        res = check_brand_impersonation(
            "https://paypal-login.xyz", "paypal-login.xyz"
        )
        assert res["brand_impersonation"] is True
        assert res["suspicious_tld"] is True


# ═══════════════════════════════════════════════════════════════════════════════
#  Banking & Government Category Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestCategoryDetection:

    def test_sbi_banking_attack(self):
        """SBI impersonation on suspicious TLD should detect banking category."""
        res = check_brand_impersonation(
            "https://sbi-online-kyc-update.top", "sbi-online-kyc-update.top"
        )
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "sbi"
        assert res["category"] == "banking"
        assert res["suspicious_tld"] is True

    def test_icici_bank_verify(self):
        res = check_brand_impersonation(
            "https://secure-login.icicibank.verify-account.xyz",
            "secure-login.icicibank.verify-account.xyz"
        )
        assert res["brand_impersonation"] is True
        assert res["target_brand"] == "icicibank"


# ═══════════════════════════════════════════════════════════════════════════════
#  Output Format Validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestOutputFormat:
    """Ensure all required fields are present in the output."""

    def test_safe_result_has_all_keys(self):
        res = check_brand_impersonation("https://example.com", "example.com")
        required = [
            "brand_impersonation", "target_brand", "category",
            "similarity", "method", "character_substitution",
            "homoglyph_detected", "suspicious_tld", "risk_added",
            "detail", "checked",
        ]
        for key in required:
            assert key in res, f"Missing key: {key}"

    def test_detected_result_has_all_keys(self):
        res = check_brand_impersonation("https://g00gle.com", "g00gle.com")
        assert res["brand_impersonation"] is True
        assert res["target_brand"] is not None
        assert res["category"] is not None
        assert res["similarity"] > 0
        assert res["risk_added"] > 0
        assert res["checked"] is True
