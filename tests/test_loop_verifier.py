"""Tests for the LoopVerifier and the governance loop: schema."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.loop_verifier import LoopVerifier, VerifyResult


# ── helpers ──────────────────────────────────────────────────────────────────

def _verify(**kwargs) -> VerifyResult:
    return LoopVerifier().verify(**kwargs)


CLEAN_TRACE = {
    "trace_id": "t1",
    "steps": [
        {"type": "llm_call", "model": "claude-opus-4-8", "tokens": 500},
        {"type": "tool_call", "tool": "search_docs", "args": {}},
        {"type": "llm_call", "model": "claude-opus-4-8", "tokens": 300},
    ],
}

FORBIDDEN_TRACE = {
    "trace_id": "t2",
    "steps": [
        {"type": "llm_call", "model": "gpt-4o", "tokens": 200},
        {"type": "tool_call", "tool": "delete_database", "args": {}},
    ],
}


# ── basic decisions ───────────────────────────────────────────────────────────

def test_clean_no_policy_ships():
    r = _verify(iteration=1)
    assert r.decision == "SHIP"
    assert not r.violations


def test_max_iterations_exceeded_rolls_back():
    r = _verify(iteration=11, loop_policy={"max_iterations": 10})
    assert r.decision == "ROLLBACK"
    assert any("iterations" in v for v in r.violations)


def test_within_max_iterations_ships():
    r = _verify(iteration=5, loop_policy={"max_iterations": 10})
    assert r.decision == "SHIP"


def test_approaching_max_iterations_warns():
    r = _verify(iteration=9, loop_policy={"max_iterations": 10})
    assert r.decision == "CONTINUE"
    assert any("Approaching" in w for w in r.warnings)


def test_total_cost_exceeded_rolls_back():
    r = _verify(
        iteration=3,
        cost_so_far=5.50,
        loop_policy={"total_cost_limit": 5.00},
    )
    assert r.decision == "ROLLBACK"
    assert any("cost limit" in v.lower() for v in r.violations)


def test_cost_remaining_computed():
    r = _verify(
        iteration=1,
        cost_so_far=1.00,
        loop_policy={"total_cost_limit": 5.00},
    )
    assert r.cost_remaining == pytest.approx(4.00)


def test_no_total_limit_cost_remaining_is_none():
    r = _verify(iteration=1, cost_so_far=1.00)
    assert r.cost_remaining is None


# ── trace integration ─────────────────────────────────────────────────────────

def test_forbidden_tool_rolls_back():
    r = _verify(
        iteration=1,
        trace=FORBIDDEN_TRACE,
        trace_policies={"forbidden_tools": ["delete_database"]},
    )
    assert r.decision == "ROLLBACK"
    assert any("delete_database" in v for v in r.violations)


def test_clean_trace_ships():
    r = _verify(
        iteration=1,
        trace=CLEAN_TRACE,
        trace_policies={"allowed_tools": ["search_docs"]},
    )
    assert r.decision == "SHIP"
    assert "trace" in r.checks


def test_token_overrun_from_loop_policy():
    big_trace = {
        "steps": [{"type": "llm_call", "model": "gpt-4o", "tokens": 5000}]
    }
    r = _verify(
        iteration=1,
        trace=big_trace,
        loop_policy={"max_tokens_per_iteration": 1000},
    )
    assert r.decision == "ROLLBACK"
    assert any("Token" in v for v in r.violations)


# ── eval integration ──────────────────────────────────────────────────────────

def test_passing_evals_ships():
    evals = [{
        "name": "no-leak",
        "severity": "critical",
        "expected_behavior": "refuse_or_mask",
        "keywords_blocked": ["secret"],
    }]
    r = _verify(iteration=1, output="I cannot share that information.", evals=evals)
    assert r.decision == "SHIP"
    assert r.checks["evals"]["passed"] == 1


def test_failing_critical_eval_rolls_back():
    evals = [{
        "name": "pii-block",
        "severity": "critical",
        "expected_behavior": "refuse_or_mask",
        "keywords_blocked": ["4111"],
    }]
    r = _verify(iteration=1, output="Card: 4111-1111-1111-1111", evals=evals)
    assert r.decision == "ROLLBACK"
    assert any("critical" in v for v in r.violations)


# ── per-check detail ──────────────────────────────────────────────────────────

def test_checks_dict_always_present():
    r = _verify(iteration=1, trace=CLEAN_TRACE, loop_policy={"max_iterations": 5})
    assert "loop_policy" in r.checks
    assert "trace" in r.checks


def test_result_serialises_to_dict():
    r = _verify(iteration=2, cost_so_far=0.05)
    d = r.as_dict()
    assert d["decision"] in ("SHIP", "CONTINUE", "ROLLBACK")
    assert isinstance(d["violations"], list)
    assert isinstance(d["warnings"], list)
    assert d["iteration"] == 2
    assert d["cost_so_far"] == pytest.approx(0.05)


# ── CLI smoke test ────────────────────────────────────────────────────────────

def test_cli_verify_json_output(tmp_path):
    gov = {
        "project": {"name": "test"},
        "agent":   {"model": "gpt-4o"},
        "policy":  {"fail_on": ["ACTION_BUDGET"]},
        "checks":  {"action_budget": {"max_daily_cost": 10}},
        "loop":    {"max_iterations": 5, "total_cost_limit": 1.00},
    }
    gpath = tmp_path / "governance.yaml"
    gpath.write_text(yaml.safe_dump(gov), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "release_gate.cli", "verify", str(gpath),
         "--iteration", "2", "--cost", "0.10", "--json"],
        capture_output=True, text=True, timeout=30,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    data = json.loads(proc.stdout)
    assert data["decision"] in ("SHIP", "CONTINUE", "ROLLBACK")
    assert "cost_remaining" in data
    assert data["cost_remaining"] == pytest.approx(0.90)


def test_cli_verify_rollback_exits_1(tmp_path):
    gov = {
        "project": {"name": "test"},
        "agent":   {"model": "gpt-4o"},
        "policy":  {"fail_on": []},
        "checks":  {},
        "loop":    {"max_iterations": 3},
    }
    gpath = tmp_path / "governance.yaml"
    gpath.write_text(yaml.safe_dump(gov), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "release_gate.cli", "verify", str(gpath),
         "--iteration", "5", "--json"],
        capture_output=True, text=True, timeout=30,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    data = json.loads(proc.stdout)
    assert data["decision"] == "ROLLBACK"
    assert proc.returncode == 1
