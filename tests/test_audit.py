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
    detect_model,
    detect_safeguards,
    emit_config,
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


# ─────────────────────────── model detection ────────────────────────────────

def test_detect_model_openai(tmp_path):
    make_repo(tmp_path, {"a.py": 'resp = client.chat.completions.create(model="gpt-4-turbo")'})
    assert detect_model(tmp_path) == "gpt-4-turbo"


def test_detect_model_claude(tmp_path):
    make_repo(tmp_path, {"a.py": 'msg = client.messages.create(model="claude-3-opus-20240229")'})
    assert detect_model(tmp_path) == "claude-3-opus-20240229"


def test_detect_model_name_kwarg(tmp_path):
    make_repo(tmp_path, {"a.py": 'llm = ChatOpenAI(model_name="gpt-4o")'})
    assert detect_model(tmp_path) == "gpt-4o"


def test_detect_model_picks_most_frequent(tmp_path):
    make_repo(tmp_path, {
        "a.py": 'model="gpt-4-turbo"\nmodel="gpt-4-turbo"',
        "b.py": 'model="gpt-3.5-turbo"',
    })
    assert detect_model(tmp_path) == "gpt-4-turbo"


def test_detect_model_ignores_unknown_strings(tmp_path):
    make_repo(tmp_path, {"a.py": 'model="my-custom-thing"'})
    assert detect_model(tmp_path) is None


def test_detect_model_none_when_absent(tmp_path):
    make_repo(tmp_path, {"a.py": "x = 1"})
    assert detect_model(tmp_path) is None


# ─────────────────────────── emit_config ────────────────────────────────────

def test_emit_config_is_valid_yaml(tmp_path):
    import yaml
    make_repo(tmp_path, {"agent.py": 'from openai import OpenAI\nmodel="gpt-4-turbo"'})
    report = build_report(tmp_path)
    text = emit_config(report)
    parsed = yaml.safe_load(text)
    assert parsed["project"]["name"]
    assert parsed["agent"]["model"] == "gpt-4-turbo"
    assert "action_budget" in parsed["checks"]
    assert "trace_policies" in parsed


def test_emit_config_uses_detected_model(tmp_path):
    make_repo(tmp_path, {"agent.py": 'from anthropic import Anthropic\nmodel="claude-3-opus-20240229"'})
    report = build_report(tmp_path)
    text = emit_config(report)
    assert "claude-3-opus-20240229" in text


def test_emit_config_todo_when_no_model(tmp_path):
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    text = emit_config(report)
    assert "TODO" in text
    assert "could not auto-detect" in text


def test_emit_config_flags_missing_safeguards(tmp_path):
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    text = emit_config(report)
    # bare repo has missing safeguards → should carry the MISSING marker
    assert "MISSING" in text


def test_project_name_from_url():
    from release_gate.audit import _project_name_from_path
    assert _project_name_from_path("https://github.com/org/my-agent") == "my-agent"
    assert _project_name_from_path("https://github.com/org/my-agent.git") == "my-agent"
    assert _project_name_from_path("/home/user/cool-bot/") == "cool-bot"


# ─────────────────────────── badge + markdown (self-serve) ───────────────────

def test_badge_url_block_is_red(tmp_path):
    from release_gate.audit import badge_url
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    url = badge_url(report)
    assert url.startswith("https://img.shields.io/badge/")
    assert "BLOCK" in url
    assert url.endswith("-red")


def test_badge_url_no_agent_is_grey(tmp_path):
    from release_gate.audit import badge_url
    report = build_report(tmp_path)  # empty repo, no agent
    url = badge_url(report)
    assert "no%20agent%20detected" in url
    assert url.endswith("-lightgrey")


def test_badge_markdown_links_to_repo(tmp_path):
    from release_gate.audit import badge_markdown
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    md = badge_markdown(report)
    assert md.startswith("[![")
    assert "github.com/VamsiSudhakaran1/release-gate" in md


def test_render_markdown_has_score_and_table(tmp_path):
    from release_gate.audit import render_markdown
    make_repo(tmp_path, {"agent.py": 'from openai import OpenAI\nmodel="gpt-4-turbo"'})
    report = build_report(tmp_path)
    md = render_markdown(report)
    assert "AI Release Readiness Audit" in md
    assert "Score:" in md
    assert "| Safeguard | Status | Risk if missing |" in md
    assert "gpt-4-turbo" in md
    assert "--emit-config" in md  # next-step guidance present when safeguards missing


def test_render_markdown_no_agent_message(tmp_path):
    from release_gate.audit import render_markdown
    report = build_report(tmp_path)  # empty repo
    md = render_markdown(report)
    assert "No AI agent framework detected" in md
    assert "| Safeguard |" not in md  # no score table for non-agent repos
