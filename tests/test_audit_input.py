"""Forgiving repo-input normalization for the web audit endpoint.

A malformed paste (a bare owner/repo, or the CLI command pasted whole) must be
normalized or rejected with a clear error — never silently scanned as a local
path and reported as 'no agent framework detected'.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("RG_JWT_SECRET", "test-secret")
os.environ.setdefault("RG_DB_PATH", tempfile.mktemp(suffix=".db"))

from release_gate_api._app import _normalize_repo_input


@pytest.mark.parametrize("raw,expected", [
    ("release-gate audit TransformerOptimus/SuperAGI", "https://github.com/TransformerOptimus/SuperAGI"),
    ("TransformerOptimus/SuperAGI", "https://github.com/TransformerOptimus/SuperAGI"),
    ("github.com/openai/openai-python", "https://github.com/openai/openai-python"),
    ("https://github.com/foo/bar/", "https://github.com/foo/bar"),
    ("$ rg audit foo/bar", "https://github.com/foo/bar"),
    ("  owner/repo.git ", "https://github.com/owner/repo"),
])
def test_normalizes_forgiving_input(raw, expected):
    assert _normalize_repo_input(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a repo", "just-one-word", "https://evil.com/x", "a/b/c/d"])
def test_rejects_non_repo_input(raw):
    assert _normalize_repo_input(raw) is None


def test_endpoint_rejects_garbage_with_clear_error():
    try:
        from fastapi.testclient import TestClient
        from release_gate_api._app import app
        client = TestClient(app)
    except Exception:  # pragma: no cover
        pytest.skip("web stack unavailable")
    r = client.post("/api/audit", json={"url": "this is not a repo"})
    assert r.status_code == 400
    assert "github.com" in r.json()["detail"].lower()
