"""
test_api.py
-----------
pytest test suite for the Flask /api/analyze endpoint.

Run with:
    cd backend
    pytest tests/ -v

Requires: pytest, pytest-flask
"""

import json
import pytest

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    """Create and configure the Flask app for testing."""
    import sys
    import os
    # Ensure the backend package root is on the path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    from app import app as flask_app
    flask_app.config["TESTING"] = True
    yield flask_app


@pytest.fixture
def client(app):
    """Return a test client for the Flask app."""
    return app.test_client()


# ─── Health Check ─────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_returns_ok_status(self, client):
        data = resp_json(client.get("/api/health"))
        assert data["status"] == "ok"

    def test_health_returns_timestamp(self, client):
        data = resp_json(client.get("/api/health"))
        assert "timestamp" in data


# ─── Input Validation ─────────────────────────────────────────────────────────

class TestInputValidation:
    def test_missing_url_field_returns_400(self, client):
        resp = client.post(
            "/api/analyze",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_empty_url_returns_400(self, client):
        resp = post_url(client, "")
        assert resp.status_code == 400

    def test_non_json_body_returns_400(self, client):
        resp = client.post(
            "/api/analyze",
            data="not-json",
            content_type="text/plain",
        )
        assert resp.status_code == 400

    def test_invalid_url_structure_returns_400(self, client):
        # A string that cannot be interpreted as a URL
        resp = post_url(client, "this is not a url!!!")
        assert resp.status_code == 400

    def test_error_response_has_error_key(self, client):
        resp = post_url(client, "")
        data = resp_json(resp)
        assert "error" in data


# ─── Valid URL Analysis ───────────────────────────────────────────────────────

class TestAnalyzeEndpoint:
    def test_valid_url_returns_200(self, client):
        """A well-formed URL should always return 200 (analysis may be partial)."""
        resp = post_url(client, "https://example.com")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = resp_json(post_url(client, "https://example.com"))
        assert "ai_result"  in data
        assert "findings"   in data
        assert "timestamp"  in data

    def test_ai_result_has_verdict_and_reason(self, client):
        data = resp_json(post_url(client, "https://example.com"))
        ai   = data["ai_result"]
        assert "verdict" in ai
        assert "reason"  in ai

    def test_findings_is_list(self, client):
        data = resp_json(post_url(client, "https://example.com"))
        assert isinstance(data["findings"], list)

    def test_findings_have_expected_keys(self, client):
        data = resp_json(post_url(client, "https://example.com"))
        for finding in data["findings"]:
            assert "name"    in finding
            assert "value"   in finding
            assert "explain" in finding

    def test_verdict_is_valid_category(self, client):
        data    = resp_json(post_url(client, "https://example.com"))
        verdict = data["ai_result"]["verdict"]
        valid   = {
            "Safe", "Looks Safe", "Suspicious", "Suspicious Website",
            "High Risk", "Confirmed Threat",
            "Phishing Detected", "Malware Detected",
            "Unwanted Software Detected", "Harmful Application Detected",
            "Brand Impersonation Detected",
        }
        assert verdict in valid

    def test_url_without_scheme_is_auto_normalized(self, client):
        """URLs submitted without https:// should be auto-normalized."""
        resp = post_url(client, "google.com")
        assert resp.status_code == 200

    def test_http_url_is_accepted(self, client):
        resp = post_url(client, "http://example.com")
        assert resp.status_code == 200

    def test_timestamp_format(self, client):
        """Timestamp should be ISO-8601 UTC string ending with Z."""
        data = resp_json(post_url(client, "https://example.com"))
        ts   = data["timestamp"]
        assert ts.endswith("Z")
        assert "T" in ts


# ─── Edge Cases ───────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_very_long_url(self, client):
        """A very long URL path should be handled without crashing."""
        long_url = "https://example.com/" + "a" * 500
        resp = post_url(client, long_url)
        assert resp.status_code == 200

    def test_url_with_suspicious_keywords(self, client):
        """URLs containing phishing keywords should complete analysis."""
        resp = post_url(client, "https://secure-login-verify.example.com/account/update")
        assert resp.status_code == 200

    def test_ip_address_url(self, client):
        """IP-based URLs should be processed (not crashed)."""
        resp = post_url(client, "http://192.168.1.1")
        assert resp.status_code == 200


# ─── Helpers ──────────────────────────────────────────────────────────────────

def post_url(client, url: str):
    """POST to /api/analyze with the given url value."""
    return client.post(
        "/api/analyze",
        data=json.dumps({"url": url}),
        content_type="application/json",
    )


def resp_json(resp) -> dict:
    """Parse the response body as JSON."""
    return json.loads(resp.data)
