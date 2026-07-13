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
    apply_decision_mode,
    compare_to_baseline,
    render_pr_comment,
    SAFEGUARDS,
)


# ─────────────────────────── PR comment ─────────────────────────────────────

def test_pr_comment_snapshot_no_baseline(tmp_path):
    _risky_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="audit")
    md = render_pr_comment(report)
    assert "release-gate:" in md
    assert "Dangerous execution sink" in md
    assert "release-gate.com" in md  # footer link


def test_pr_comment_delta_leads_with_verdict(tmp_path):
    clean = tmp_path / "clean"; clean.mkdir()
    _clean_agent_repo(clean)
    risky = tmp_path / "risky"; risky.mkdir()
    _risky_agent_repo(risky)
    diff = compare_to_baseline(build_report(risky, mode="ci"),
                               build_report(clean, mode="ci"))
    md = render_pr_comment(build_report(risky, mode="ci"), diff)
    assert "vs baseline" in md
    assert "BLOCK" in md
    assert "New findings:" in md


def test_pr_comment_clean_delta_says_no_new(tmp_path):
    clean = tmp_path / "clean"; clean.mkdir()
    _clean_agent_repo(clean)
    report = build_report(clean, mode="ci")
    diff = compare_to_baseline(report, report)
    md = render_pr_comment(report, diff)
    assert "No new code findings" in md
    assert "Governance unchanged" in md


# ─────────────────────────── suppressions ───────────────────────────────────

def test_suppression_removes_finding_from_scoring(tmp_path):
    _make(tmp_path, {"a.py": (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "r = client.chat.completions.create(model='gpt-4', messages=m)\n"),
        ".release-gate-ignore.yaml": (
        "ignore:\n  - rule: missing_max_tokens\n    file: a.py\n"
        "    reason: provider default is fine\n    expires: 2099-01-01\n")})
    report = build_report(tmp_path, mode="ci")
    titles = [f["title"] for f in report["code_findings"]]
    assert "LLM call with no token ceiling" not in titles
    assert len(report["suppressed"]) == 1
    assert report["suppressed"][0]["suppressed_by"]["reason"]


def test_no_suppress_flag_shows_everything(tmp_path):
    _make(tmp_path, {"a.py": (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "r = client.chat.completions.create(model='gpt-4', messages=m)\n"),
        ".release-gate-ignore.yaml": (
        "ignore:\n  - rule: missing_max_tokens\n    expires: 2099-01-01\n")})
    report = build_report(tmp_path, mode="ci", apply_ignore=False)
    titles = [f["title"] for f in report["code_findings"]]
    assert "LLM call with no token ceiling" in titles
    assert report["suppressed"] == []


def test_findings_sorted_high_severity_first(tmp_path):
    # Two uncapped calls (low) BEFORE the eval (high) in file order — the high
    # must still surface first in code_findings.
    _make(tmp_path, {"agent.py": (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "r1 = client.chat.completions.create(model='gpt-4', messages=a)\n"
        "r2 = client.chat.completions.create(model='gpt-4', messages=b)\n"
        "def h(user_input):\n    return eval(user_input)\n")})
    report = build_report(tmp_path, mode="ci")
    sevs = [f["severity"] for f in report["code_findings"]]
    assert sevs[0] in ("high", "critical")
    # non-increasing severity ordering
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert sevs == sorted(sevs, key=lambda s: rank.get(s, 9))


def test_cookbook_findings_excluded_from_score(tmp_path):
    # A framework whose core is clean but whose cookbook/ demo runs eval on user
    # input: the demo must NOT drive the grade, but must still be surfaced.
    (tmp_path / "pocketflow").mkdir()
    (tmp_path / "pocketflow" / "core.py").write_text(
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def run(m):\n    return client.chat.completions.create("
        "model='gpt-4', messages=m, max_tokens=50)\n")
    (tmp_path / "cookbook").mkdir()
    (tmp_path / "cookbook" / "agent.py").write_text(
        "def tool(user_input):\n    return eval(user_input)\n")
    report = build_report(tmp_path, mode="audit")
    # Core is clean → nothing scored; the cookbook eval is surfaced separately.
    assert report["code_findings"] == []
    assert any(f["title"] == "Dangerous execution sink"
               for f in report["example_findings"])
    assert report["code_safety"]["score"] == 100


def test_scan_code_findings_split_partitions_examples():
    import tempfile, os
    from pathlib import Path
    from release_gate.verify import scan_code_findings
    d = tempfile.mkdtemp()
    os.makedirs(Path(d) / "src"); os.makedirs(Path(d) / "examples")
    (Path(d) / "src" / "app.py").write_text(
        "def f(user_input):\n    return eval(user_input)\n")
    (Path(d) / "examples" / "demo.py").write_text(
        "def g(user_input):\n    return eval(user_input)\n")
    scored, excluded = scan_code_findings(Path(d), return_excluded=True)
    assert any(f["file"].startswith("src") for f in scored)
    assert not any(f["file"].startswith("examples") for f in scored)
    assert any(f["file"].startswith("examples") for f in excluded)


def test_expired_suppression_does_not_hide(tmp_path):
    from release_gate.audit import apply_suppressions
    import datetime
    findings = [{"title": "Dangerous execution sink", "file": "a.py"}]
    rules = [{"rule": "exec_sink", "reason": "x", "expires": "2020-01-01"}]
    kept, suppressed, expired = apply_suppressions(
        findings, rules, today=datetime.date(2026, 7, 5))
    assert kept == findings           # not hidden
    assert suppressed == []
    assert len(expired) == 1          # surfaced as lapsed


def _make(tmp_path, files):
    for name, body in files.items():
        (tmp_path / name).write_text(body)


# ─────────────────────────── policy modes ───────────────────────────────────

def _clean_agent_repo(tmp_path):
    _make(tmp_path, {"agent.py": (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def h(m):\n    return client.chat.completions.create("
        "model='gpt-4', messages=m, max_tokens=100)\n")})


def _risky_agent_repo(tmp_path):
    _make(tmp_path, {"agent.py": (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def h(user_input):\n"
        "    client.chat.completions.create(model='gpt-4', messages=[], max_tokens=1)\n"
        "    return eval(user_input)\n")})


def test_audit_mode_clean_repo_is_review_not_block(tmp_path):
    _clean_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="audit")
    # No code risk + undeclared governance → advisory REVIEW, never a harsh BLOCK.
    assert report["decision"] == "REVIEW"
    assert report["mode"] == "audit"
    assert report.get("decision_reason")


def test_audit_mode_real_high_finding_holds(tmp_path):
    _risky_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="audit")
    assert report["decision"] in ("HOLD", "BLOCK")  # real code risk still surfaces


def test_ci_mode_missing_governance_blocks(tmp_path):
    _clean_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="ci")
    assert report["decision"] == "BLOCK"  # historical enforce behavior preserved


def test_strict_mode_blocks_on_missing_critical_safeguard(tmp_path):
    _clean_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="strict")
    assert report["decision"] == "BLOCK"
    assert "critical safeguard" in report["decision_reason"]


def test_public_advisory_governance_never_gates(tmp_path):
    # Clean code but zero declared governance → PROMOTE, because governance
    # gaps on a stranger's repo are never something we'd file publicly.
    _clean_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="public-advisory")
    assert report["decision"] == "PROMOTE"
    assert report["advisory"]["governance_gated"] is False


def test_public_advisory_confirmed_high_blocks_inferred_holds():
    base = {"code_safety": {"applicable": True}, "missing": [{"id": "kill_switch"}]}

    confirmed = {**base, "code_findings": [
        {"severity": "high", "basis": "confirmed", "title": "os.system",
         "file": "a.py", "line": 3}]}
    apply_decision_mode(confirmed, "public-advisory")
    assert confirmed["decision"] == "BLOCK"
    assert len(confirmed["advisory"]["confirmed_high"]) == 1

    inferred = {**base, "code_findings": [
        {"severity": "high", "basis": "inferred", "title": "eval", "file": "b.py"}]}
    apply_decision_mode(inferred, "public-advisory")
    assert inferred["decision"] == "HOLD"  # unconfirmed → context, not a public block
    assert inferred["advisory"]["confirmed_high"] == []


def test_public_advisory_is_a_valid_mode():
    from release_gate.audit import VALID_MODES
    assert "public-advisory" in VALID_MODES


def test_apply_decision_mode_does_not_mutate_scores(tmp_path):
    _risky_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="ci")
    cs_before = dict(report["code_safety"])
    apply_decision_mode(report, "audit")
    assert report["code_safety"] == cs_before  # only the verdict is reinterpreted


# ─────────────────────────── evidence quality ───────────────────────────────

def test_findings_carry_confidence_and_basis(tmp_path):
    _risky_agent_repo(tmp_path)
    report = build_report(tmp_path, mode="ci")
    for f in report["code_findings"]:
        assert f.get("confidence") in ("high", "medium", "low")
        assert f.get("basis") in ("confirmed", "inferred")
    sink = next(f for f in report["code_findings"]
                if f["title"] == "Dangerous execution sink")
    assert sink["basis"] == "confirmed" and sink["confidence"] == "high"


def test_standalone_token_ceiling_is_low(tmp_path):
    _clean_agent_repo(tmp_path)  # has max_tokens → no finding; use uncapped one
    _make(tmp_path, {"a.py": (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "r = client.chat.completions.create(model='gpt-4', messages=m)\n")})
    report = build_report(tmp_path, mode="ci")
    tc = [f for f in report["code_findings"]
          if f["title"] == "LLM call with no token ceiling"]
    assert tc and all(f["severity"] == "low" for f in tc)


def test_token_ceiling_elevated_inside_unbounded_loop():
    from release_gate.agent_analysis import analyze_python
    src = ("from openai import OpenAI\nclient = OpenAI()\n"
           "while True:\n"
           "    client.chat.completions.create(model='gpt-4', messages=m)\n")
    fs = analyze_python(src, "x.py")
    tc = [f for f in fs if f["title"] == "LLM call with no token ceiling"]
    assert tc and tc[0]["severity"] == "medium"  # compound runaway-cost path


# ─────────────────────────── baseline gate ──────────────────────────────────

def test_baseline_blocks_on_new_high(tmp_path):
    base = build_report(tmp_path / "b", mode="ci") if False else None
    clean = tmp_path / "clean"; clean.mkdir()
    _clean_agent_repo(clean)
    risky = tmp_path / "risky"; risky.mkdir()
    _risky_agent_repo(risky)
    baseline = build_report(clean, mode="ci")
    current = build_report(risky, mode="ci")
    diff = compare_to_baseline(current, baseline)
    assert diff["verdict"] == "BLOCK"
    assert any("new high" in r for r in diff["reasons"])


def test_baseline_pass_when_no_regression(tmp_path):
    clean = tmp_path / "clean"; clean.mkdir()
    _clean_agent_repo(clean)
    report = build_report(clean, mode="ci")
    diff = compare_to_baseline(report, report)  # compare to itself
    assert diff["verdict"] == "PASS"


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


def test_governance_file_with_placeholder_name_fails(tmp_path):
    # Strict: a project name that's a placeholder doesn't count.
    make_repo(tmp_path, {"governance.yaml": "project:\n  name: TODO\n"})
    present, _ = detect_safeguards(tmp_path)
    assert present["governance_file"] is False


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
        "- uses: VamsiSudhakaran1/release-gate@v0.7.0\n  with:\n    config: governance.yaml\n"
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
    present["budget_ceiling"]  = True   # 20 pts  → 45 total (<50) → BLOCK
    score, decision = compute_score(present)
    assert score == 45
    assert decision == "BLOCK"


def test_no_governance_file_caps_at_hold():
    # Every safeguard EXCEPT the governance file = 75/100. A repo that has done
    # the real work but never wrote a governance.yaml should never PROMOTE.
    present = {s["id"]: True for s in SAFEGUARDS}
    present["governance_file"] = False
    score, decision = compute_score(present)
    assert score == 75
    assert decision == "HOLD"


def test_substantial_safeguards_is_hold_not_block():
    # The gpt-researcher case: budget + kill_switch + auth + evals = 60/100.
    # Already has most heavy safeguards → HOLD ("formalize it"), not BLOCK.
    present = {s["id"]: False for s in SAFEGUARDS}
    present["budget_ceiling"]  = True   # 20
    present["kill_switch"]     = True   # 20
    present["auth_rate_limit"] = True   # 10
    present["eval_evidence"]   = True   # 10  → 60 total
    score, decision = compute_score(present)
    assert score == 60
    assert decision == "HOLD"


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
    assert report["safeguards"]["governance_file"]["present"] is True
    assert report["safeguards"]["eval_evidence"]["present"] is True
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


# ──────────────────── strict verification (the gate) ─────────────────────────

def test_untouched_scaffold_does_not_score_100(tmp_path):
    """The core bug: committing an unfilled emit_config() scaffold must NOT pass.

    Uses a genuinely *deployed* agent (a real LLM call, not a bare import) so the
    Governance axis applies — a repo whose only agent references live in
    tests/tooling is correctly N/A and out of scope for this scaffold-integrity
    check.
    """
    make_repo(tmp_path, {"agent.py": (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def run(msgs):\n"
        "    return client.chat.completions.create(model='gpt-4', messages=msgs, max_tokens=50)\n"
    )})
    report = build_report(tmp_path)
    scaffold = emit_config(report)
    make_repo(tmp_path, {"governance.yaml": scaffold})

    report2 = build_report(tmp_path)
    assert report2["score"] < 90
    assert report2["decision"] != "PROMOTE"
    assert report2["safeguards"]["team_owner"]["present"] is False
    assert report2["safeguards"]["trace_policy"]["present"] is False


def test_non_deployed_agent_governance_is_na(tmp_path):
    """A repo that references an LLM framework only in tests/examples/tooling is
    NOT a deployed agent — Governance must read N/A and never gate it to HOLD."""
    make_repo(tmp_path, {
        "examples/demo.py": (
            "from openai import OpenAI\n"
            "c = OpenAI()\n"
            "c.chat.completions.create(model='gpt-4', messages=[])\n"
        ),
        "README.md": "A library, not a deployed agent.",
    })
    for mode in ("ci", "strict", "audit"):
        report = build_report(tmp_path, mode=mode)
        assert report["governance_applicable"] is False, mode
        assert report["governance"]["level"] == "N/A", mode
        assert report["governance"]["score"] is None, mode
        # Governance can't drag a clean, non-deployed repo below PROMOTE.
        assert report["decision"] == "PROMOTE", mode


def test_deployed_agent_still_governed(tmp_path):
    """The guard must not over-suppress: a repo whose PRODUCTION code actually
    calls an LLM IS a deployed agent — Governance applies and still gates."""
    make_repo(tmp_path, {"bot.py": (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def run(msgs):\n"
        "    return client.chat.completions.create(model='gpt-4', messages=msgs, max_tokens=50)\n"
    )})
    report = build_report(tmp_path, mode="ci")
    assert report["governance_applicable"] is True
    assert report["governance"]["score"] is not None
    # No governance.yaml declared → not PROMOTE (governance still gates a real agent).
    assert report["decision"] != "PROMOTE"


def test_placeholder_team_owner_rejected(tmp_path):
    make_repo(tmp_path, {
        "governance.yaml": (
            "project:\n  name: real-bot\n"
            "checks:\n"
            "  fallback_declared:\n"
            "    team_owner: \"TODO-your-team\"\n"
            "    runbook_url: \"https://TODO/runbook\"\n"
        ),
    })
    present, _ = detect_safeguards(tmp_path)
    assert present["team_owner"] is False


def test_kill_switch_location_must_exist(tmp_path):
    make_repo(tmp_path, {
        "governance.yaml": (
            "project:\n  name: real-bot\n"
            "checks:\n"
            "  fallback_declared:\n"
            "    kill_switch:\n"
            "      type: feature-flag\n"
            "      location: config/does-not-exist\n"
        ),
    })
    present, _ = detect_safeguards(tmp_path)
    assert present["kill_switch"] is False

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "does-not-exist").write_text("flags")
    present2, _ = detect_safeguards(tmp_path)
    assert present2["kill_switch"] is True


def test_model_mismatch_flagged(tmp_path):
    make_repo(tmp_path, {
        "agent.py": 'from anthropic import Anthropic\nmodel="claude-3-opus-20240229"',
        "governance.yaml": "project:\n  name: real-bot\nagent:\n  model: gpt-4o\n",
    })
    present, _ = detect_safeguards(tmp_path)
    assert present["governance_file"] is False


def test_budget_below_projected_spend_fails(tmp_path):
    make_repo(tmp_path, {
        "governance.yaml": (
            "project:\n  name: real-bot\n"
            "agent:\n  model: gpt-4\n  daily_requests: 100000\n"
            "  avg_input_tokens: 800\n  avg_output_tokens: 400\n"
            "checks:\n  action_budget:\n    max_daily_cost: 5\n"
        ),
    })
    present, _ = detect_safeguards(tmp_path)
    assert present["budget_ceiling"] is False


def test_code_findings_exec_sink(tmp_path):
    from release_gate.verify import scan_code_findings
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI\nx = eval(user_input)\n"})
    findings = scan_code_findings(tmp_path)
    assert any(f["title"] == "Dangerous execution sink" for f in findings)


def test_code_findings_llm_no_token_ceiling(tmp_path):
    from release_gate.verify import scan_code_findings
    make_repo(tmp_path, {
        "agent.py": (
            "from openai import OpenAI\n"
            "client = OpenAI()\n"
            "r = client.chat.completions.create(model='gpt-4o', messages=msgs)\n"
        ),
    })
    findings = scan_code_findings(tmp_path)
    assert any(f["title"] == "LLM call with no token ceiling" for f in findings)


def test_high_severity_findings_block_promote(tmp_path):
    from release_gate.audit import compute_score, SAFEGUARDS
    present = {s["id"]: True for s in SAFEGUARDS}
    findings = [{"severity": "high"}, {"severity": "high"}, {"severity": "high"}]
    score, decision = compute_score(present, findings)
    assert score == 100
    assert decision == "BLOCK"


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

def test_badge_url_reflects_agent_code_safety(tmp_path):
    # The badge now reflects the objective Agent Code Safety axis, not the
    # (circular) governance-driven combined score. Clean agent code with no
    # findings → PROMOTE/green even without a governance.yaml.
    from release_gate.audit import badge_url
    make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    url = badge_url(report)
    assert url.startswith("https://img.shields.io/badge/")
    assert "agent%20code%20safety" in url


def test_badge_url_block_is_red_with_high_findings():
    # A report carrying high-severity code findings → BLOCK/red badge.
    from release_gate.audit import badge_url
    report = {
        "agent_detected": True,
        "code_safety": {"applicable": True, "score": 20, "decision": "BLOCK",
                        "high": 4, "medium": 2, "low": 0},
    }
    url = badge_url(report)
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
    # A genuinely deployed agent (real LLM call) so the Governance axis applies
    # and the safeguard table renders — a bare import is not a deployed agent.
    make_repo(tmp_path, {"agent.py": (
        'from openai import OpenAI\n'
        'client = OpenAI()\n'
        'def run(msgs):\n'
        '    return client.chat.completions.create(model="gpt-4-turbo", messages=msgs)\n'
    )})
    report = build_report(tmp_path)
    md = render_markdown(report)
    assert "AI Release Readiness Audit" in md
    assert "Agent Code Safety:" in md
    assert "Governance:" in md
    assert "| Safeguard | Status | Why |" in md
    assert "gpt-4-turbo" in md
    assert "--emit-config" in md  # next-step guidance present when safeguards missing


def test_render_markdown_no_agent_message(tmp_path):
    from release_gate.audit import render_markdown
    report = build_report(tmp_path)  # empty repo
    md = render_markdown(report)
    assert "No AI agent framework detected" in md
    assert "| Safeguard |" not in md  # no score table for non-agent repos


# ─────────────────────────── loop_boundary safeguard ────────────────────────

def test_loop_boundary_advisory_is_score_neutral(tmp_path):
    """loop_boundary is weight 0 — its absence must not change the score."""
    weights = {s["id"]: s["weight"] for s in SAFEGUARDS}
    assert weights.get("loop_boundary") == 0
    # full marks on the seven weighted safeguards still totals 100
    assert sum(s["weight"] for s in SAFEGUARDS) == 100


def test_loop_boundary_missing_when_no_loop_block(tmp_path):
    make_repo(tmp_path, {
        "agent.py": "from openai import OpenAI\nclient = OpenAI()",
        "governance.yaml": "project:\n  name: test\nagent:\n  model: gpt-4o\n",
    })
    present, _ = detect_safeguards(tmp_path)
    assert present.get("loop_boundary") is False


def test_loop_boundary_present_with_max_iterations(tmp_path):
    make_repo(tmp_path, {
        "agent.py": "from openai import OpenAI\nclient = OpenAI()",
        "governance.yaml": (
            "project:\n  name: test\n"
            "agent:\n  model: gpt-4o\n"
            "loop:\n  max_iterations: 10\n  total_cost_limit: 1.0\n"
        ),
    })
    present, _ = detect_safeguards(tmp_path)
    assert present.get("loop_boundary") is True


def test_loop_boundary_fails_on_identical_maker_checker(tmp_path):
    make_repo(tmp_path, {
        "agent.py": "from openai import OpenAI\nclient = OpenAI()",
        "governance.yaml": (
            "project:\n  name: test\n"
            "agent:\n  model: gpt-4o\n"
            "loop:\n  max_iterations: 10\n"
            "  maker_model: gpt-4o\n  checker_model: gpt-4o\n"
        ),
    })
    present, _ = detect_safeguards(tmp_path)
    assert present.get("loop_boundary") is False


# ── AI-change review gate (`release-gate pr`) ───────────────────────────────

def test_changed_tests_ratio_flags_untested_source():
    from release_gate.audit import changed_tests_ratio
    # product code changed, no test touched → untested
    r = changed_tests_ratio(["src/agent/tools.py", "src/agent/loop.py"])
    assert r["source_without_tests"] is True and r["source_files_changed"] == 2
    # a test moved alongside → not untested
    r2 = changed_tests_ratio(["src/agent/tools.py", "tests/test_tools.py"])
    assert r2["source_without_tests"] is False and r2["test_files_changed"] == 1
    # docs/config only → no source demand at all
    r3 = changed_tests_ratio(["README.md", "docs/guide.md", "release-gate.lock"])
    assert r3["source_without_tests"] is False and r3["source_files_changed"] == 0
    # TS spec conventions recognized as tests
    r4 = changed_tests_ratio(["app/agent.ts", "app/agent.test-d.ts"])
    assert r4["test_files_changed"] == 1 and r4["source_without_tests"] is False


def test_unify_verdict_blocks_on_baseline_block():
    from release_gate.audit import unify_verdict
    u = unify_verdict({"verdict": "BLOCK", "reasons": ["1 new high"]}, None)
    assert u["decision"] == "BLOCK"


def test_unify_verdict_drift_is_hold_not_block():
    from release_gate.audit import unify_verdict
    # clean baseline, but the model changed and the lock wasn't updated → HOLD
    lock = {"drift": True, "model_changed": True, "reasons": ["model changed"],
            "changed": [], "added": [], "removed": []}
    u = unify_verdict({"verdict": "PASS", "reasons": []}, lock)
    assert u["decision"] == "HOLD" and u["drift"] == "drift"


def test_unify_verdict_lock_updated_in_pr_is_promote():
    from release_gate.audit import unify_verdict
    # drift is expected when the PR itself re-locked → not held against it
    lock = {"drift": True, "model_changed": True, "reasons": ["model changed"],
            "changed": [], "added": [], "removed": [], "_lock_updated_in_pr": True}
    u = unify_verdict({"verdict": "PASS", "reasons": []}, lock)
    assert u["decision"] == "PROMOTE"


def test_unify_verdict_expired_certificate_holds():
    from release_gate.audit import unify_verdict
    lock = {"drift": False, "expired": True, "reasons": [], "changed": [],
            "added": [], "removed": []}
    u = unify_verdict({"verdict": "PASS", "reasons": []}, lock)
    assert u["decision"] == "HOLD"


def test_render_ai_pr_comment_leads_with_net_new_and_ignores_debt():
    from release_gate.audit import render_ai_pr_comment
    baseline_cmp = {
        "verdict": "BLOCK",
        "code_safety_delta": -12, "baseline_code_safety": 100, "current_code_safety": 88,
        "new_code_findings": [{"severity": "high", "title": "Dangerous execution sink",
                               "file": "a.py", "line": 10, "confidence": "high",
                               "basis": "confirmed", "recommendation": "Use ast.literal_eval. More."}],
        "new_safeguard_failures": [], "resolved_code_findings": [],
    }
    unified = {"decision": "BLOCK", "reasons": ["1 new high"], "drift": None}
    head = {"code_findings": [{"x": 1}] * 5}  # 1 new + 4 inherited
    md = render_ai_pr_comment(head, baseline_cmp, unified,
                              {"source_files_changed": 1, "test_files_changed": 0,
                               "source_without_tests": True})
    assert "AI-change review: **BLOCK**" in md
    assert "Introduced by this change" in md
    assert "Dangerous execution sink" in md and "a.py:10" in md
    assert "Inherited debt ignored" in md and "4 finding" in md
    assert "0 test files touched" in md
