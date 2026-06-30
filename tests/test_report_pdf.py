"""Tests for the run PDF report endpoint and renderer.

  GET /api/run/{run_id}/report.pdf   owner-only; free=summary, paid=full

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
    from release_gate_api.db import save_run, update_user_plan
    _client = TestClient(app)
except Exception:  # pragma: no cover
    _client = None

pytestmark = pytest.mark.skipif(_client is None, reason="web stack unavailable")

_REPORT = {
    "score": 35, "decision": "BLOCK",
    "safeguards": {"governance_file": False, "budget_ceiling": True,
                   "kill_switch": False, "team_owner": True, "eval_evidence": False},
    "code_findings": [
        {"severity": "high", "title": "Dangerous execution sink",
         "file": "agent/run.py", "line": 42,
         "recommendation": "Never pass LLM output to exec()."},
        {"severity": "medium", "title": "LLM call with no token ceiling",
         "file": "chat.py", "line": 88, "recommendation": "Set max_tokens."},
    ],
}


def _signup(email, password="pw-12345678"):
    r = _client.post("/api/auth/signup", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _make_run(user_id):
    return save_run("https://github.com/acme/agent", _REPORT, user_id=user_id)


def test_renderer_produces_valid_pdf_both_tiers():
    from release_gate_api.report_pdf import render_report_pdf
    full = render_report_pdf(_REPORT, repo_url="x", run_id="r1", full=True)
    free = render_report_pdf(_REPORT, repo_url="x", run_id="r1", full=False)
    assert full[:5] == b"%PDF-" and free[:5] == b"%PDF-"
    # The full report renders every finding + recommendation + framework mapping,
    # so it carries materially more content than the locked summary.
    assert len(full) > len(free)


def test_pdf_requires_auth():
    r = _client.get("/api/run/whatever/report.pdf")
    assert r.status_code == 401


def test_pdf_owner_only():
    me = _signup("owner@example.com")
    other = _signup("intruder@example.com")
    run_id = _make_run(me["user"].get("id") or _me_id(me["token"]))
    r = _client.get(f"/api/run/{run_id}/report.pdf",
                    headers={"Authorization": "Bearer " + other["token"]})
    assert r.status_code == 404


def _me_id(token):
    r = _client.get("/api/auth/me", headers={"Authorization": "Bearer " + token})
    return r.json()["id"]


def test_free_user_gets_summary_pdf():
    acc = _signup("free-pdf@example.com")
    run_id = _make_run(_me_id(acc["token"]))
    r = _client.get(f"/api/run/{run_id}/report.pdf",
                    headers={"Authorization": "Bearer " + acc["token"]})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
    assert "summary" in r.headers.get("content-disposition", "")


def test_paid_user_gets_full_pdf():
    acc = _signup("paid-pdf@example.com")
    update_user_plan("paid-pdf@example.com", "pro")
    # Re-login so the JWT carries the upgraded plan.
    tok = _client.post("/api/auth/login",
                       json={"email": "paid-pdf@example.com", "password": "pw-12345678"}).json()["token"]
    run_id = _make_run(_me_id(tok))
    r = _client.get(f"/api/run/{run_id}/report.pdf",
                    headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 200
    assert "full" in r.headers.get("content-disposition", "")
    assert r.content[:5] == b"%PDF-"
