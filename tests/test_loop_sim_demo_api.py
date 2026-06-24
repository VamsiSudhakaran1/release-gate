"""Tests for POST /api/loop-sim-demo — runs the REAL LoopSimulator on built-in
loop agents (good/mid/worst). No user code is executed (no RCE/SSRF).

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


def test_good_promotes():
    d = _client.post("/api/loop-sim-demo", json={"variant": "good"}).json()
    assert d["decision"] == "PROMOTE"
    assert d["convergence_rate"] == 1.0
    assert d["max_iterations"] == 1


def test_mid_holds():
    d = _client.post("/api/loop-sim-demo", json={"variant": "mid"}).json()
    assert d["decision"] == "HOLD"
    assert d["p95_iterations"] >= 5          # converges, but dawdles


def test_worst_blocks_and_costs():
    d = _client.post("/api/loop-sim-demo", json={"variant": "worst"}).json()
    assert d["decision"] == "BLOCK"
    assert d["convergence_rate"] == 0.0
    # cost is real (estimated from output length), not a canned zero
    assert d["max_cost"] > 0


def test_unknown_variant_400():
    r = _client.post("/api/loop-sim-demo", json={"variant": "nope"})
    assert r.status_code == 400


def test_default_variant_is_good():
    d = _client.post("/api/loop-sim-demo", json={}).json()
    assert d["variant"] == "good"
