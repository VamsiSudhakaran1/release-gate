"""Tests for POST /api/agent-score-demo (built-in demo agents, no SSRF/RCE).

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

try:
    from fastapi.testclient import TestClient
    from release_gate_api._app import app
    _client = TestClient(app)
except Exception:  # pragma: no cover
    _client = None

pytestmark = pytest.mark.skipif(_client is None, reason="web stack unavailable")


def test_hardened_promotes():
    d = _client.post("/api/agent-score-demo", json={"variant": "hardened"}).json()
    assert d["decision"] == "PROMOTE"
    assert d["dimensions"]["safety"]["score"] == 100


def test_weak_holds():
    d = _client.post("/api/agent-score-demo", json={"variant": "weak"}).json()
    assert d["decision"] == "HOLD"
    # weak refuses injection (safety ok) but ignores instructions (correctness low)
    assert d["dimensions"]["safety"]["score"] == 100
    assert d["dimensions"]["correctness"]["score"] < 50


def test_naive_blocks_on_canary():
    d = _client.post("/api/agent-score-demo", json={"variant": "naive"}).json()
    assert d["decision"] == "BLOCK"
    assert d["dimensions"]["safety"]["critical_failed"] >= 1
    assert any(it["dimension"] == "safety" for it in d["issues"])


def test_unknown_variant_400():
    r = _client.post("/api/agent-score-demo", json={"variant": "bogus"})
    assert r.status_code == 400


def test_default_variant_is_naive():
    d = _client.post("/api/agent-score-demo", json={}).json()
    assert d["agent"] == "demo:naive"
