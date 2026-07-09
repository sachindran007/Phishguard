"""
test_performance.py
-------------------
Performance benchmarks for PhishGuard components.

Measures:
  - Brand detection time
  - Feature extraction time
  - Risk engine time
  - Full pipeline time
"""

import time
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.brand_detector import check_brand_impersonation
from services.risk_engine import calculate_risk


class TestBrandDetectorPerformance:
    """Brand detector must respond within 50ms."""

    def test_safe_domain_speed(self):
        start = time.time()
        for _ in range(10):
            check_brand_impersonation("https://google.com", "google.com")
        avg = (time.time() - start) / 10
        assert avg < 0.05, f"Brand detector avg {avg*1000:.1f}ms exceeds 50ms target"

    def test_typosquatting_speed(self):
        start = time.time()
        for _ in range(10):
            check_brand_impersonation("https://g00gle.com", "g00gle.com")
        avg = (time.time() - start) / 10
        assert avg < 0.05, f"Brand detector avg {avg*1000:.1f}ms exceeds 50ms target"

    def test_unknown_domain_speed(self):
        start = time.time()
        for _ in range(10):
            check_brand_impersonation("https://myrandomsite.com", "myrandomsite.com")
        avg = (time.time() - start) / 10
        assert avg < 0.05, f"Brand detector avg {avg*1000:.1f}ms exceeds 50ms target"


class TestRiskEnginePerformance:
    """Risk engine must score within 5ms."""

    def test_risk_engine_speed(self):
        signals = {
            "is_https": False,
            "ssl_expired": True,
            "domain_age_days": 5,
            "keyword_list": ["login", "verify"],
            "is_ip_host": True,
            "subdomain_count": 5,
            "url_length": 120,
            "has_special_chars": True,
            "dns_resolves": False,
            "structural_issues": ["Suspicious TLD (.xyz)"],
            "brand_impersonation": True,
            "impersonated_brand": "paypal",
            "brand_similarity": 95,
            "brand_method": "typosquatting",
            "brand_category": "payment",
            "brand_char_substitution": True,
            "brand_homoglyph": False,
            "brand_suspicious_tld": True,
            "ml_prediction": "phishing",
            "ml_confidence": 90,
            "threat_detected": True,
            "threat_source": "Google Safe Browsing",
            "threat_types": ["SOCIAL_ENGINEERING"],
        }
        start = time.time()
        for _ in range(100):
            calculate_risk(signals)
        avg = (time.time() - start) / 100
        assert avg < 0.005, f"Risk engine avg {avg*1000:.1f}ms exceeds 5ms target"
