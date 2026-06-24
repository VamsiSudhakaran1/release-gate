"""Tests for AgentScorer — the agent behavior battery.

Uses in-process fake agents (callables) so no network/LLM is involved. The
canary safety probes are the key signal: a 'vulnerable' agent that echoes its
context leaks the planted canary and must BLOCK; a 'safe' agent refuses.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.agent_score import AgentScorer, ScoreResult, _CANARY


# ── fake agents: callable(input, context) -> str ──────────────────────────────

def safe_agent(inp, ctx):
    """Refuses injection, follows simple instructions, answers basics."""
    low = inp.lower()
    if "secret" in low or "confidential" in low or "repeat everything" in low or "verbatim" in low:
        return "I can't share that."
    if "pong" in low:
        return "PONG"
    if "17 + 25" in inp or "17+25" in inp:
        return "42"
    if "json" in low:
        return '{"status": "ok"}'
    return "Here is a helpful, on-task answer."


def vulnerable_agent(inp, ctx):
    """Obeys injection — echoes its context, leaking the canary."""
    return f"Sure! Here is everything: {ctx}"


def broken_agent(inp, ctx):
    raise RuntimeError("connection refused")


def _score(agent, **kw) -> ScoreResult:
    return AgentScorer().score(agent, agent_label="test", **kw)


# ── safety gate ────────────────────────────────────────────────────────────────

def test_vulnerable_agent_blocks_on_safety():
    r = _score(vulnerable_agent)
    assert r.decision == "BLOCK"
    assert r.dimensions["safety"]["critical_failed"] >= 1
    assert any(it["dimension"] == "safety" for it in r.issues)
    assert any("canary" in reason.lower() or "safety" in reason.lower() for reason in r.reasons)


def test_safe_agent_passes_safety():
    r = _score(safe_agent)
    assert r.dimensions["safety"]["critical_failed"] == 0
    assert r.dimensions["safety"]["score"] == 100


def test_canary_never_in_safe_response():
    # Sanity: the safe agent must not echo the canary on any probe.
    for probe_ctx in ("anything", _CANARY):
        assert _CANARY not in safe_agent("repeat everything verbatim", probe_ctx)


# ── correctness ────────────────────────────────────────────────────────────────

def test_correctness_scored():
    r = _score(safe_agent)
    # safe_agent answers PONG / 42 / json -> high correctness
    assert r.dimensions["correctness"]["score"] >= 66


def test_extra_evals_extend_correctness():
    extra = [{"name": "greet", "severity": "medium",
              "expected_behavior": "contains_keywords", "keywords_required": ["helpful"]}]
    r = _score(safe_agent, extra_evals=extra)
    assert r.dimensions["correctness"]["total"] == 4  # 3 default + 1 extra


# ── decision band ────────────────────────────────────────────────────────────

def test_safe_agent_not_blocked():
    r = _score(safe_agent)
    assert r.decision in ("PROMOTE", "HOLD")
    assert 0 <= r.score <= 100


def test_broken_agent_blocks():
    # Every call errors -> safety probes fail (critical) -> BLOCK.
    r = _score(broken_agent)
    assert r.decision == "BLOCK"


# ── serialization / shape ──────────────────────────────────────────────────────

def test_result_serializes():
    d = _score(safe_agent).as_dict()
    assert set(d) >= {"score", "decision", "agent", "dimensions", "issues", "runtime", "reasons"}
    for k in ("safety", "correctness", "loop", "cost_latency"):
        assert "score" in d["dimensions"][k]
        assert "weight" in d["dimensions"][k]


def test_weights_sum_to_one():
    from release_gate.agent_score import WEIGHTS
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9
