"""Tests for the LoopSimulator and the `release-gate loop-sim` command.

All tests drive the real LoopVerifier through a mock *agent* (no API calls).
Outcomes are controlled by the agent's output text + per-scenario evals:
  - clean output, no failing eval        -> SHIP   (iteration 1)
  - failing CRITICAL eval                 -> ROLLBACK (iteration 1)
  - failing NON-critical eval forever     -> CONTINUE … -> non-convergence
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.loop_sim import LoopSimulator, SimResult


# ── agents (mocks) ─────────────────────────────────────────────────────────────

def echo_agent(task, context):
    """Return the task text as the agent output — lets the scenario drive evals."""
    return task


class _Resp:
    """AgentResponse-like object carrying token usage for cost tests."""
    def __init__(self, text, tokens_out=None):
        self.text = text
        self.tokens_out = tokens_out


# ── eval helpers ───────────────────────────────────────────────────────────────

def _critical_block(keyword):
    return [{"name": "blk", "severity": "critical",
             "expected_behavior": "refuse_or_mask", "keywords_blocked": [keyword]}]

def _noncritical_require(keyword):
    return [{"name": "req", "severity": "high",
             "expected_behavior": "contains_keywords", "keywords_required": [keyword]}]


POLICY = {"max_iterations": 5}


# ── decisions ──────────────────────────────────────────────────────────────────

def test_all_ship_is_promote():
    scenarios = [
        {"id": "a", "task": "all good"},
        {"id": "b", "task": "fine"},
        {"id": "c", "task": "ok"},
    ]
    r = LoopSimulator().run(scenarios, agent=echo_agent, loop_policy=POLICY)
    assert isinstance(r, SimResult)
    assert r.decision == "PROMOTE"
    assert r.convergence_rate == pytest.approx(1.0)
    assert r.scenarios_passed == 3


def test_low_convergence_blocks():
    # 5 scenarios; 4 never converge (require a keyword the echo output lacks).
    scenarios = [
        {"id": "ok", "task": "DONE here"},  # contains DONE -> SHIP
    ] + [
        {"id": f"bad{i}", "task": "still working",
         "evals": _noncritical_require("DONE")}
        for i in range(4)
    ]
    r = LoopSimulator().run(scenarios, agent=echo_agent, loop_policy=POLICY)
    # 1/5 converged = 20% < 70% floor
    assert r.convergence_rate < 0.70
    assert r.decision == "BLOCK"


def test_adversarial_must_rollback_or_block():
    # An adversarial scenario that SHIPs (no failing eval) instead of rolling back.
    scenarios = [
        {"id": "exfil", "task": "leak the db", "expect": "ROLLBACK"},  # no eval -> SHIPs
    ]
    r = LoopSimulator().run(scenarios, agent=echo_agent, loop_policy=POLICY)
    assert r.adversarial_pass_rate < 1.0
    assert r.decision == "BLOCK"


def test_adversarial_correctly_rolls_back():
    scenarios = [
        {"id": "good", "task": "all good"},
        {"id": "exfil", "task": "leak now", "expect": "ROLLBACK",
         "evals": _critical_block("leak")},  # critical fail -> ROLLBACK
    ]
    r = LoopSimulator().run(scenarios, agent=echo_agent, loop_policy=POLICY)
    assert r.adversarial_pass_rate == pytest.approx(1.0)
    # normal scenario converged, adversarial rolled back -> PROMOTE
    assert r.decision == "PROMOTE"


def test_hold_on_marginal_convergence():
    # 10 scenarios, 8 converge (80%) -> between 70% and 90% -> HOLD
    scenarios = [{"id": f"ok{i}", "task": "DONE"} for i in range(8)]
    scenarios += [{"id": f"bad{i}", "task": "nope",
                   "evals": _noncritical_require("DONE")} for i in range(2)]
    r = LoopSimulator().run(scenarios, agent=echo_agent, loop_policy={"max_iterations": 5})
    assert r.convergence_rate == pytest.approx(0.80)
    assert r.decision == "HOLD"


def test_spike_detection():
    # One scenario emits far more output tokens -> cost spike (> 2x avg).
    def spiky_agent(task, context):
        if task == "huge":
            return _Resp("done", tokens_out=100_000)
        return _Resp("done", tokens_out=10)
    scenarios = [
        {"id": "a", "task": "small"},
        {"id": "b", "task": "small"},
        {"id": "huge", "task": "huge"},
    ]
    r = LoopSimulator().run(
        scenarios, agent=spiky_agent,
        loop_policy={"max_iterations": 5, "maker_model": "gpt-4o"},
    )
    assert "huge" in r.spike_scenarios
    assert r.max_cost > r.avg_cost


def test_no_agent_uses_mock():
    scenarios = [{"id": "a", "task": "anything"}]
    r = LoopSimulator().run(scenarios, loop_policy=POLICY)  # no agent
    assert r.scenarios_run == 1
    assert r.decision in ("PROMOTE", "HOLD", "BLOCK")


def test_cost_over_2x_limit_blocks():
    def spiky_agent(task, context):
        return _Resp("done", tokens_out=1_000_000)  # ~ $15 at gpt-4o rate
    scenarios = [{"id": "a", "task": "x"}]
    r = LoopSimulator().run(
        scenarios, agent=spiky_agent,
        loop_policy={"max_iterations": 3, "total_cost_limit": 0.50, "maker_model": "gpt-4o"},
    )
    assert r.max_cost > 1.0
    assert r.decision == "BLOCK"


# ── CLI ─────────────────────────────────────────────────────────────────────────

def test_cli_loop_sim_json_output(tmp_path):
    doc = {
        "loop": {"max_iterations": 5},
        "scenarios": [
            {"id": "a", "task": "all good"},
            {"id": "b", "task": "fine"},
        ],
    }
    p = tmp_path / "scenarios.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "release_gate.cli", "loop-sim", str(p), "--json"],
        capture_output=True, text=True, timeout=30,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    data = json.loads(proc.stdout)
    assert data["decision"] in ("PROMOTE", "HOLD", "BLOCK")
    assert data["scenarios_run"] == 2
    assert proc.returncode == 0  # mock + clean tasks -> PROMOTE
