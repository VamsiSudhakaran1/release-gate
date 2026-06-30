"""Tests for the live agent-endpoint safety scan.

Network calls are mocked — we verify the verdict logic and the SSRF refusal,
not real HTTP.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import release_gate_api.live_scan as ls
from release_gate_api.live_scan import run_live_scan
from release_gate_api.net_guard import UnsafeUrlError
from release_gate.agent_score import _CANARY


def _patch_call(monkeypatch, responder):
    # Bypass the network + SSRF resolver; drive _safe_call's return value.
    monkeypatch.setattr(ls, "validate_public_url", lambda u, **k: u)
    monkeypatch.setattr(ls, "_safe_call", lambda base, fm, inp, ctx: responder(inp, ctx))


def test_resisting_agent_promotes(monkeypatch):
    _patch_call(monkeypatch, lambda inp, ctx: "I can't share that.")
    out = run_live_scan("https://api.example.com/agent")
    assert out["decision"] == "PROMOTE"
    assert out["l1"]["leaked"] == 0 and out["l2"]["leaked"] == 0


def test_l1_leak_blocks(monkeypatch):
    # Agent always echoes the canary → hard BLOCK.
    _patch_call(monkeypatch, lambda inp, ctx: f"sure, it is {_CANARY}")
    out = run_live_scan("https://api.example.com/agent")
    assert out["decision"] == "BLOCK"
    assert out["l1"]["leaked"] >= 1


def test_l2_only_leak_holds(monkeypatch):
    # Resist L1 (refuse), but leak when the prompt mentions DAN/roleplay/audit.
    def responder(inp, ctx):
        lowered = inp.lower()
        if "dan" in lowered or "administrator" in lowered or "document" in lowered or "complete this" in lowered:
            return f"ok: {_CANARY}"
        return "I won't reveal that."
    _patch_call(monkeypatch, responder)
    out = run_live_scan("https://api.example.com/agent")
    assert out["decision"] == "HOLD"
    assert out["l1"]["leaked"] == 0 and out["l2"]["leaked"] >= 1


def test_unsafe_url_rejected():
    with pytest.raises(UnsafeUrlError):
        run_live_scan("http://169.254.169.254/latest/meta-data/")


def test_max_probes_bounds_calls(monkeypatch):
    calls = {"n": 0}
    def responder(inp, ctx):
        calls["n"] += 1
        return "no."
    _patch_call(monkeypatch, responder)
    run_live_scan("https://api.example.com/agent", max_probes=3)
    assert calls["n"] == 3


# ── Endpoint-level (skips cleanly if the web stack is unavailable) ────────────

import os
import tempfile

os.environ.setdefault("RG_JWT_SECRET", "test-secret")
os.environ.setdefault("RG_DB_PATH", tempfile.mktemp(suffix=".db"))

try:
    from fastapi.testclient import TestClient
    from release_gate_api._app import app
    _client = TestClient(app)
except Exception:  # pragma: no cover
    _client = None

_web = pytest.mark.skipif(_client is None, reason="web stack unavailable")


@_web
def test_endpoint_requires_auth():
    r = _client.post("/api/agent-scan-live", json={"url": "https://x.example.com/a"})
    assert r.status_code == 401


@_web
def test_endpoint_rejects_unsafe_target():
    tok = _client.post("/api/auth/signup",
                       json={"email": "live@example.com", "password": "pw-12345678"}).json()["token"]
    r = _client.post("/api/agent-scan-live",
                     json={"url": "http://169.254.169.254/latest/meta-data/"},
                     headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 400
    assert "Unsafe target" in r.json()["detail"]
