"""Tests for the signup-gated FAQ question flow.

  POST /api/questions          authenticated users submit a question
  GET  /api/admin/questions    admin lists submitted questions

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
# The admin endpoint is gated on this email getting the admin plan on signup.
os.environ["RELEASE_GATE_ADMIN_EMAIL"] = "admin@example.com"

try:
    from fastapi.testclient import TestClient
    import release_gate_api._app as _appmod
    # Pick up the admin email we just set (module read it at import time).
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


def test_question_requires_auth():
    r = _client.post("/api/questions", json={"question": "anonymous?"})
    assert r.status_code == 401


def test_empty_question_rejected():
    tok = _signup("asker-empty@example.com")
    r = _client.post("/api/questions", json={"question": "   "},
                     headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 400


def test_submit_and_admin_sees_it():
    tok = _signup("asker1@example.com")
    r = _client.post("/api/questions", json={"question": "Does it support gRPC agents?"},
                     headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 200 and r.json()["ok"] is True

    admin_tok = _signup("admin@example.com")
    r = _client.get("/api/admin/questions", headers={"Authorization": "Bearer " + admin_tok})
    assert r.status_code == 200
    qs = r.json()["questions"]
    mine = [q for q in qs if q["email"] == "asker1@example.com"]
    assert mine and mine[0]["question"] == "Does it support gRPC agents?"


def test_non_admin_cannot_list_questions():
    tok = _signup("normal@example.com")
    r = _client.get("/api/admin/questions", headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 403


def test_overlong_question_rejected():
    tok = _signup("asker-long@example.com")
    r = _client.post("/api/questions", json={"question": "x" * 2001},
                     headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 400
