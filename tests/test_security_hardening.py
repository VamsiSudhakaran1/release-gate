"""Security-hardening regression tests.

Covers the browser-surface and access-control fixes:
  * security response headers (CSP on HTML, nosniff/frame/referrer everywhere)
  * anonymous rate-limit keyed on the forwarded client IP, not the proxy IP
  * the GitHub-App debug diagnostic is admin-only (was unauthenticated)

Skips cleanly if the web stack can't be imported in this environment.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("RG_JWT_SECRET", "test-secret")
os.environ.setdefault("RG_DB_PATH", tempfile.mktemp(suffix=".db"))
os.environ["RELEASE_GATE_ADMIN_EMAIL"] = "admin@example.com"

try:
    from fastapi.testclient import TestClient
    import release_gate_api._app as _appmod
    _appmod.ADMIN_EMAIL = "admin@example.com"
    from release_gate_api._app import app
    _client = TestClient(app)
except Exception:  # pragma: no cover
    _client = None

pytestmark = pytest.mark.skipif(_client is None, reason="web stack unavailable")


def _signup(email, password="pw-12345678"):
    r = _client.post("/api/auth/signup", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


# ── Security headers ────────────────────────────────────────────────────────

def test_html_response_carries_full_security_headers():
    r = _client.get("/")
    assert r.status_code == 200
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin" in r.headers.get("Referrer-Policy", "")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp


def test_json_api_has_headers_but_no_document_csp():
    r = _client.get("/api/health")
    assert r.status_code == 200
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    # A document CSP is only meaningful on HTML, not a JSON body.
    assert "Content-Security-Policy" not in r.headers


def test_hsts_off_by_default():
    assert "Strict-Transport-Security" not in _client.get("/").headers


# ── Anonymous rate limit keyed on the forwarded client IP ───────────────────

def test_anon_rate_limit_uses_forwarded_ip_not_proxy_ip():
    """Two different real clients behind the same proxy must NOT share a counter.

    Regression: the anon limiter read request.client.host (the proxy IP), so all
    anonymous users shared one bucket. It now reads X-Forwarded-For.
    """
    _appmod._anon_counters.clear()
    hdrs_a = {"X-Forwarded-For": "203.0.113.10"}
    last = None
    for _ in range(_appmod._ANON_LIMIT + 2):
        last = _client.post("/api/audit", json={"url": "owner/repo"}, headers=hdrs_a)
    assert last.status_code == 429  # this IP is now throttled
    # A different client IP (same proxy) is unaffected.
    other = _client.post("/api/audit", json={"url": "owner/repo"},
                         headers={"X-Forwarded-For": "198.51.100.20"})
    assert other.status_code != 429


# ── Debug diagnostic is admin-only ──────────────────────────────────────────

def test_github_app_debug_requires_admin():
    assert _client.get("/api/debug/github-app",
                       params={"owner": "o", "repo": "r"}).status_code == 401
    tok = _signup("normal-user@example.com")
    r = _client.get("/api/debug/github-app", params={"owner": "o", "repo": "r"},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403
