"""Tests for release-gate audit — repo scanner."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.audit import (
    build_report,
    compute_score,
    detect_frameworks,
    detect_safeguards,
    SAFEGUARDS,
)


# ─────────────────────────── helpers ────────────────────────────────────────

def make_repo(tmp_path, files: dict) -> Path:
    """Write a mini repo from {relative_path: content} dict."""
    for rel, content in files.items():
        fpath = tmp_path / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    return tmp_path


# ─────────────────────────── framework detection ────────────────────────────

def test_detects_openai(tmp_path):
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI\nclient = OpenAI()"})
    fw = detect_frameworks(tmp_path)
    assert "OpenAI / Agents SDK" in fw


def test_detects_langchain(tmp_path):
    make_repo(tmp_path, {"chain.py": "from langchain.chat_models import ChatOpenAI"})
    fw = detect_frameworks(tmp_path)
    assert "LangChain" in fw


def test_detects_multiple_frameworks(tmp_path):
    make_repo(tmp_path, {
        "a.py": "from openai import OpenAI",
        "b.py": "from anthropic import Anthropic",
        "c.py": "import litellm",
    })
    fw = detect_frameworks(tmp_path)
    assert len(fw) >= 3


def test_no_frameworks_in_empty_repo(tmp_path):
    make_repo(tmp_path, {"hello.py": "print('hello world')"})
    fw = detect_frameworks(tmp_path)
    assert fw == {}


def test_skips_pycache(tmp_path):
    make_repo(tmp_path, {
        "__pycache__/cached.py": "from openai import OpenAI",
        "real.py": "print('nothing')",
    })
    fw = detect_frameworks(tmp_path)
    assert fw == {}


# ─────────────────────────── safeguard detection ────────────────────────────

def test_governance_file_detected(tmp_path):
    make_repo(tmp_path, {"governance.yaml": "project:\n  name: test\n"})
    present, gov_path = detect_safeguards(tmp_path)
    assert present["governance_file"] is True
    assert gov_path is not None


def test_no_governance_file(tmp_path):
    make_repo(tmp_path, {"main.py": "print('hi')"})
    present, gov_path = detect_safeguards(tmp_path)
    assert present["governance_file"] is False
    assert gov_path is None


def test_evals_yaml_detected(tmp_path):
    make_repo(tmp_path, {"evals.yaml": "evals:\n  - name: test\n"})
    present, _ = detect_safeguards(tmp_path)
    assert present["eval_evidence"] is True


def test_budget_in_governance(tmp_path):
    make_repo(tmp_path, {
        "governance.yaml": "checks:\n  action_budget:\n    max_daily_cost: 500\n"
    })
    present, _ = detect_safeguards(tmp_path)
    assert present["budget_ceiling"] is True


def test_kill_switch_in_governance(tmp_path):
    make_repo(tmp_path, {
        "governance.yaml": "checks:\n  fallback_declared:\n    kill_switch:\n      type: feature-flag\n"
    })
    present, _ = detect_safeguards(tmp_path)
    assert present["kill_switch"] is True


def test_team_owner_not_inferred_from_code(tmp_path):
    # team_owner can only be confirmed from a governance file
    make_repo(tmp_path, {"main.py": "TEAM_OWNER = 'platform-team'"})
    present, _ = detect_safeguards(tmp_path)
    assert present["team_owner"] is False


def test_github_actions_integration(tmp_path):
    make_repo(tmp_path, {
        ".github/workflows/ci.yml":
        "- uses: VamsiSudhakaran1/release-gate@v0.6.1\n  with:\n    config: governance.yaml\n"
    })
    from release_gate.audit import _has_github_actions_integration
    assert _has_github_actions_integration(tmp_path) is True


def test_no_github_actions(tmp_path):
    make_repo(tmp_path, {".github/workflows/ci.yml": "- run: pytest\n"})
    from release_gate.audit import _has_github_actions_integration
    assert _has_github_actions_integration(tmp_path) is False


# ─────────────────────────── scoring ────────────────────────────────────────

def test_all_present_scores_100():
    present = {s["id"]: True for s in SAFEGUARDS}
    score, decision = compute_score(present)
    assert score == 100
    assert decision == "PROMOTE"


def test_all_missing_scores_0():
    present = {s["id"]: False for s in SAFEGUARDS}
    score, decision = compute_score(present)
    assert score == 0
    assert decision == "BLOCK"


def test_partial_score_hold(tmp_path):
    # governance + budget + kill_switch present = 25+20+20 = 65/100 → BLOCK
    # governance + budget + kill_switch + team + auth = 25+20+20+10+10 = 85/100 → HOLD
    present = {
        "governance_file": True,
        "budget_ceiling":  True,
        "kill_switch":     True,
        "team_owner":      True,
        "auth_rate_limit": True,
        "eval_evidence":   False,
        "trace_policy":    False,
    }
    score, decision = compute_score(present)
    assert score == 85
    assert decision == "HOLD"


def test_block_threshold():
    present = {s["id"]: False for s in SAFEGUARDS}
    present["governance_file"] = True   # 25 pts
    present["budget_ceiling"]  = True   # 20 pts  → 45 total → BLOCK
    score, decision = compute_score(present)
    assert score == 45
    assert decision == "BLOCK"


# ─────────────────────────── full report ────────────────────────────────────

def test_build_report_empty_repo(tmp_path):
    report = build_report(tmp_path)
    assert report["score"] == 0
    assert report["decision"] == "BLOCK"
    assert report["frameworks"] == {}
    assert report["agent_detected"] is False
    assert len(report["missing"]) == len(SAFEGUARDS)


def test_agent_detected_flag(tmp_path):
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    assert report["agent_detected"] is True


def test_is_github_url():
    from release_gate.audit import _is_github_url
    assert _is_github_url("https://github.com/org/repo") is True
    assert _is_github_url("http://github.com/org/repo") is True
    assert _is_github_url("git@github.com:org/repo.git") is True
    assert _is_github_url("https://gitlab.com/org/repo") is True
    assert _is_github_url("./local/path") is False
    assert _is_github_url(".") is False


def test_render_terminal_no_agent_exits_early(tmp_path, capsys):
    from release_gate.audit import render_terminal
    report = build_report(tmp_path)  # empty repo, no frameworks
    render_terminal(report)
    captured = capsys.readouterr()
    assert "does not appear to use an AI agent" in captured.out
    assert "Readiness Score" not in captured.out


def test_build_report_with_governance(tmp_path):
    make_repo(tmp_path, {
        "governance.yaml": (
            "project:\n  name: test\n"
            "checks:\n"
            "  action_budget:\n    max_daily_cost: 500\n"
            "  fallback_declared:\n    kill_switch:\n      type: feature-flag\n"
            "    team_owner: platform-team\n    runbook_url: https://runbook.example\n"
            "  identity_boundary:\n    auth_required: true\n    rate_limit_per_user: 100\n"
        ),
        "evals.yaml": "evals:\n  - name: pii_test\n",
        "agent.py": "from openai import OpenAI",
    })
    report = build_report(tmp_path)
    assert report["safeguards"]["governance_file"] is True
    assert report["safeguards"]["eval_evidence"] is True
    assert report["frameworks"].get("OpenAI / Agents SDK", 0) >= 1
    assert report["score"] > 0


def test_build_report_json_serialisable(tmp_path):
    report = build_report(tmp_path)
    out = {k: v for k, v in report.items() if k != "real_checks"}
    json.dumps(out)  # must not raise


def test_render_terminal_does_not_crash(tmp_path, capsys):
    from release_gate.audit import render_terminal
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    render_terminal(report)
    captured = capsys.readouterr()
    assert "Readiness Score" in captured.out
    assert "BLOCK" in captured.out or "HOLD" in captured.out or "PROMOTE" in captured.out
