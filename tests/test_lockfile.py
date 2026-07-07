"""Tests for the context lockfile (AIBOM) + drift gate."""
import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.lockfile import (
    build_lock, compare_lock, collect_components, SCHEMA,
)

_T0 = datetime.datetime(2026, 7, 7, tzinfo=datetime.timezone.utc)


def _make(root, files):
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)


def test_lock_pins_behavior_artifacts(tmp_path):
    _make(tmp_path, {
        "governance.yaml": "project:\n  name: x\n",
        "evals.yaml": "evals: []\n",
        "prompts/system.txt": "You are a helpful agent.",
        "agent.py": "from openai import OpenAI\nmodel='gpt-4o'\n",
    })
    lock = build_lock(tmp_path, ttl_days=30, now=_T0)
    assert lock["schema"] == SCHEMA
    kinds = {c["kind"] for c in lock["components"]}
    assert {"governance", "evals", "prompt", "model"} <= kinds
    assert lock["model"] == "gpt-4o"
    assert lock["valid_until"].startswith("2026-08-06")


def test_lock_is_deterministic(tmp_path):
    _make(tmp_path, {"governance.yaml": "a: 1\n", "prompts/p.txt": "hi"})
    a = build_lock(tmp_path, now=_T0)
    b = build_lock(tmp_path, now=_T0)
    assert a["digest"] == b["digest"]


def test_no_drift_when_unchanged(tmp_path):
    _make(tmp_path, {"governance.yaml": "a: 1\n", "prompts/p.txt": "hi"})
    saved = build_lock(tmp_path, now=_T0)
    cur = build_lock(tmp_path, now=_T0)
    cmp = compare_lock(cur, saved, now=_T0)
    assert cmp["gate_ok"] is True and cmp["drift"] is False


def test_prompt_edit_is_drift(tmp_path):
    _make(tmp_path, {"prompts/p.txt": "original"})
    saved = build_lock(tmp_path, now=_T0)
    (tmp_path / "prompts" / "p.txt").write_text("EDITED — behaves differently now")
    cmp = compare_lock(build_lock(tmp_path, now=_T0), saved, now=_T0)
    assert cmp["gate_ok"] is False
    assert "prompts/p.txt" in cmp["changed"]


def test_model_change_is_drift(tmp_path):
    _make(tmp_path, {"agent.py": "model='gpt-4o'\n"})
    saved = build_lock(tmp_path, now=_T0)
    (tmp_path / "agent.py").write_text("model='gpt-5'\n")
    cmp = compare_lock(build_lock(tmp_path, now=_T0), saved, now=_T0)
    assert cmp["model_changed"] is True and cmp["gate_ok"] is False
    assert any("model changed" in r for r in cmp["reasons"])


def test_added_and_removed_artifacts_are_drift(tmp_path):
    _make(tmp_path, {"governance.yaml": "a: 1\n"})
    saved = build_lock(tmp_path, now=_T0)
    _make(tmp_path, {"prompts/new.txt": "new prompt"})   # add
    (tmp_path / "governance.yaml").unlink()               # remove
    cmp = compare_lock(build_lock(tmp_path, now=_T0), saved, now=_T0)
    assert "prompts/new.txt" in cmp["added"]
    assert "governance.yaml" in cmp["removed"]
    assert cmp["gate_ok"] is False


def test_expiry_invalidates_even_without_drift(tmp_path):
    _make(tmp_path, {"governance.yaml": "a: 1\n"})
    saved = build_lock(tmp_path, ttl_days=30, now=_T0)
    later = _T0 + datetime.timedelta(days=31)
    cmp = compare_lock(build_lock(tmp_path, now=later), saved, now=later)
    assert cmp["expired"] is True and cmp["gate_ok"] is False


def test_ignores_noise_dirs(tmp_path):
    _make(tmp_path, {"prompts/p.txt": "hi", "node_modules/pkg/prompt.txt": "noise"})
    comps = collect_components(tmp_path)
    paths = [c["path"] for c in comps]
    assert "prompts/p.txt" in paths
    assert not any("node_modules" in p for p in paths)
