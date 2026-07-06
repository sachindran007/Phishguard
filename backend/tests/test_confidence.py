import pytest
from services.confidence_engine import calculate_confidence

def test_full_confidence():
    signals = {
        "dns_resolves": True,
        "domain_age_days": 100,
        "ssl_valid": True,
        "is_online": True
    }
    threat_intel = {
        "safe_browsing": {"checked": True},
        "virustotal": {"checked": True}
    }
    ml_result = {"available": True}
    brand_result = {"checked": True}
    visual_result = {"checked": True}

    res = calculate_confidence(signals, threat_intel, ml_result, brand_result, visual_result)
    assert res["confidence"] == 100
    assert res["confidence_label"] == "Very High"
    assert res["checks_completed"] == 10   # 10 factors now

def test_low_confidence():
    # Only 2 factors available (dns + url_features which is always True)
    signals = {"dns_resolves": True}
    threat_intel = {}
    ml_result = {}
    
    res = calculate_confidence(signals, threat_intel, ml_result, None, None)
    assert res["confidence"] < 30
    assert res["checks_completed"] == 2   # dns + url_features

def test_brand_boost():
    """When brand impersonation is strong, confidence should get a bonus."""
    signals = {
        "dns_resolves": True,
        "domain_age_days": 5,
        "ssl_valid": True,
        "is_online": True
    }
    threat_intel = {
        "safe_browsing": {"checked": True},
        "virustotal": {"checked": True}
    }
    ml_result = {"available": True, "prediction": "phishing"}
    brand_result = {"checked": True, "brand_impersonation": True, "similarity": 96}
    
    res = calculate_confidence(signals, threat_intel, ml_result, brand_result, None)
    # Should get base + brand bonus + ML-agrees bonus
    assert res["confidence"] >= 90
