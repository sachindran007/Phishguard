import pytest
from unittest.mock import patch
from services.visual_scanner import scan_visual

@patch("services.visual_scanner._capture_screenshot")
@patch("services.visual_scanner._analyze_screenshot")
def test_scan_visual_threat(mock_analyze, mock_capture):
    mock_capture.return_value = b"fake_png_data"
    mock_analyze.return_value = {
        "visual_threat": True,
        "confidence": 95,
        "reason": "Fake paypal login form detected.",
        "detected_brands": ["paypal"],
        "has_login_form": True,
        "has_payment_form": False
    }

    res = scan_visual("https://fake-paypal.com")
    assert res["checked"] is True
    assert res["visual_threat"] is True
    assert res["confidence"] == 95
    assert res["has_login_form"] is True
    assert "screenshot_b64" in res

@patch("services.visual_scanner._capture_screenshot")
def test_scan_visual_capture_failure(mock_capture):
    mock_capture.return_value = None
    res = scan_visual("https://bad-url.com")
    assert res["checked"] is False
    assert "failed" in res["error"]
