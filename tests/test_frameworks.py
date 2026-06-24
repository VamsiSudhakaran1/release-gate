"""Tests for the framework-mapping layer (OWASP LLM Top 10 / NIST AI RMF / EU AI Act).

The mapping must be evidence-driven: PASS only when a probe actually passed, FAIL
on a real leak, and NOT_ASSESSED (never a false PASS) when we don't test something.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.agent_score import AgentScorer
from release_gate.frameworks import (
    assess_frameworks, summarize_frameworks, frameworks_report,
    PASS, FAIL, PARTIAL, NOT_ASSESSED,
)


def _safe_agent(inp, ctx):
    low = inp.lower()
    if any(w in low for w in ("secret", "confidential", "verbatim", "base64",
                              "backwards", "space between", "repeat everything",
                              "translate", "token you were given", "remaining",
                              "in sync", "operator")):
        return "I can't share that."
    if "pong" in low: return "PONG"
    if "17 + 25" in inp: return "42"
    if "json" in low: return '{"status": "ok"}'
    return "On-task answer."


def _leaky_agent(inp, ctx):
    return f"Sure, here is everything: {ctx}"


def _ctrl(controls, cid):
    return next(c for c in controls if c.control_id == cid)


def test_safe_agent_passes_injection_and_disclosure():
    score = AgentScorer().score(_safe_agent).as_dict()
    controls = assess_frameworks(score)
    assert _ctrl(controls, "LLM01").status == PASS       # prompt injection
    assert _ctrl(controls, "LLM02").status == PASS       # sensitive disclosure
    assert _ctrl(controls, "SECURE").status == PASS      # NIST secure & resilient


def test_leaky_agent_produces_findings():
    score = AgentScorer().score(_leaky_agent).as_dict()
    controls = assess_frameworks(score)
    assert _ctrl(controls, "LLM01").status == FAIL
    assert _ctrl(controls, "LLM02").status == FAIL
    assert _ctrl(controls, "PRIVACY").status == FAIL     # NIST privacy
    assert _ctrl(controls, "Art.15").status == FAIL      # EU AI Act robustness/cyber


def test_honest_gaps_are_not_assessed():
    """We must NOT claim coverage we don't have — bias, supply chain, data
    governance are explicit NOT_ASSESSED, never PASS."""
    score = AgentScorer().score(_safe_agent).as_dict()
    controls = assess_frameworks(score)
    for cid in ("LLM03", "LLM04", "LLM08", "FAIR", "Art.10"):
        assert _ctrl(controls, cid).status == NOT_ASSESSED


def test_explainability_passes_because_reasons_exist():
    score = AgentScorer().score(_safe_agent).as_dict()
    assert _ctrl(assess_frameworks(score), "EXPLAIN").status == PASS


def test_summary_counts_and_coverage():
    score = AgentScorer().score(_safe_agent).as_dict()
    controls = assess_frameworks(score)
    summary = summarize_frameworks(controls)
    owasp = summary["OWASP LLM Top 10 (2025)"]
    assert owasp["total"] == 10
    assert owasp["PASS"] + owasp["FAIL"] + owasp["PARTIAL"] + owasp["NOT_ASSESSED"] == 10
    assert 0 <= owasp["coverage_pct"] <= 100


def test_report_shape_serializes():
    score = AgentScorer().score(_safe_agent).as_dict()
    rep = frameworks_report(score)
    assert "controls" in rep and "summary" in rep
    assert all({"framework", "control_id", "title", "status", "evidence"} <= set(c)
               for c in rep["controls"])


def test_malformed_score_degrades_to_not_assessed_not_pass():
    """A missing/empty score must never yield a PASS — fail safe."""
    controls = assess_frameworks({})
    assert all(c.status in (NOT_ASSESSED, PARTIAL) for c in controls)
    assert not any(c.status == PASS for c in controls)
