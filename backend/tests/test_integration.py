"""
test_integration.py
-------------------
End-to-end integration tests for the PhishGuard analysis pipeline.

Tests the complete flow: Flask API → Feature Extractor → TI → Brand Detector →
Risk Engine → Confidence Engine → Gemini Explanation → JSON Response.
"""

import json
import pytest
import time


@pytest.fixture
def app():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from app import app as flask_app
    flask_app.config["TESTING"] = True
    yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()


def _post(client, url, visual=False):
    return client.post(
        "/api/analyze",
        data=json.dumps({"url": url, "visual": visual}),
        content_type="application/json",
    )


def _json(resp):
    return json.loads(resp.data)


# ═════════════════════════════════════════════════════════════════════════════
#  Full Pipeline Integration Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestFullPipeline:
    """Test the complete analysis pipeline end-to-end."""

    def test_safe_url_pipeline(self, client):
        """google.com should return Safe/Low verdict."""
        resp = _post(client, "https://www.google.com")
        assert resp.status_code == 200
        data = _json(resp)
        assert data["risk_score"] <= 30
        assert data["severity"] in ("LOW", "MEDIUM")
        assert data["confidence"] > 0
        assert data["timestamp"] is not None

    def test_response_has_all_layers(self, client):
        """Response must include all analysis layers."""
        resp = _post(client, "https://www.google.com")
        data = _json(resp)
        required_keys = [
            "verdict", "risk_score", "severity",
            "confidence", "confidence_label",
            "ai_explanation", "threat_intel", "ml_result",
            "brand_result", "visual_result",
            "triggered_rules", "findings", "timestamp",
            "ai_result",
        ]
        for key in required_keys:
            assert key in data, f"Missing response key: {key}"

    def test_threat_intel_structure(self, client):
        """Threat intel layer must have safe_browsing and virustotal."""
        resp = _post(client, "https://www.google.com")
        data = _json(resp)
        ti = data["threat_intel"]
        assert "safe_browsing" in ti
        assert "virustotal" in ti
        assert "any_detected" in ti

    def test_brand_result_structure(self, client):
        """Brand detector must return expected keys."""
        resp = _post(client, "https://www.google.com")
        data = _json(resp)
        br = data["brand_result"]
        assert "brand_impersonation" in br
        assert "checked" in br

    def test_findings_are_complete(self, client):
        """Findings list must contain all 8 feature checks."""
        resp = _post(client, "https://www.google.com")
        data = _json(resp)
        findings = data["findings"]
        assert len(findings) >= 8
        names = {f["name"] for f in findings}
        assert "URL Length" in names
        assert "Protocol" in names
        assert "DNS Resolution" in names

    def test_triggered_rules_format(self, client):
        """Each triggered rule must have rule, points, detail."""
        resp = _post(client, "https://www.google.com")
        data = _json(resp)
        for rule in data["triggered_rules"]:
            assert "rule" in rule
            assert "points" in rule
            assert "detail" in rule


# ═════════════════════════════════════════════════════════════════════════════
#  Error Handling Integration Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Test graceful degradation across the pipeline."""

    def test_missing_url_returns_400(self, client):
        resp = client.post(
            "/api/analyze",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_empty_url_returns_400(self, client):
        resp = _post(client, "")
        assert resp.status_code == 400

    def test_malformed_url_returns_400(self, client):
        resp = _post(client, "not a url at all!!!")
        assert resp.status_code == 400

    def test_non_json_body_returns_400(self, client):
        resp = client.post(
            "/api/analyze",
            data="plain text",
            content_type="text/plain",
        )
        assert resp.status_code == 400

    def test_offline_domain_still_returns_200(self, client):
        """Non-existent domain should still produce a valid analysis."""
        resp = _post(client, "https://thisdomaindefinitelydoesnotexist12345.com")
        assert resp.status_code == 200
        data = _json(resp)
        assert "verdict" in data
        assert "risk_score" in data


# ═════════════════════════════════════════════════════════════════════════════
#  Visual Scanner Integration
# ═════════════════════════════════════════════════════════════════════════════

class TestVisualIntegration:
    """Test visual scanner is conditionally triggered."""

    def test_safe_url_skips_visual(self, client):
        """Safe URLs should skip visual scanning."""
        resp = _post(client, "https://www.google.com", visual=True)
        data = _json(resp)
        vr = data["visual_result"]
        # google.com is safe -> visual scan should be skipped
        if data["risk_score"] < 40 and not data.get("brand_result", {}).get("brand_impersonation"):
            assert vr["checked"] is False

    def test_visual_disabled_skips_scan(self, client):
        """When visual=false, scanner should not run."""
        resp = _post(client, "https://www.google.com", visual=False)
        data = _json(resp)
        vr = data["visual_result"]
        assert vr.get("checked") is False or vr.get("visual_threat") is False


# ═════════════════════════════════════════════════════════════════════════════
#  Performance Smoke Test
# ═════════════════════════════════════════════════════════════════════════════

class TestPerformanceSmoke:
    """Basic performance assertions."""

    def test_scan_completes_within_timeout(self, client):
        """A single scan should complete within 60 seconds."""
        start = time.time()
        resp = _post(client, "https://www.google.com", visual=False)
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 60, f"Scan took {elapsed:.1f}s — too slow!"
