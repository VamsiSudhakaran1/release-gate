"""Tests for the two-axis audit scoring: Agent Code Safety + Governance."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.audit import compute_code_safety, compute_governance, SAFEGUARDS


def test_clean_code_is_promote():
    cs = compute_code_safety([], agent_detected=True)
    assert cs["score"] == 100 and cs["decision"] == "PROMOTE" and cs["applicable"]


def test_three_highs_block():
    findings = [{"severity": "high"}] * 3
    cs = compute_code_safety(findings, agent_detected=True)
    assert cs["decision"] == "BLOCK" and cs["high"] == 3


def test_one_high_holds():
    cs = compute_code_safety([{"severity": "high"}, {"severity": "low"}], agent_detected=True)
    assert cs["decision"] == "HOLD" and cs["score"] < 100


def test_not_applicable_when_no_agent():
    cs = compute_code_safety([{"severity": "high"}], agent_detected=False)
    assert cs["applicable"] is False and cs["score"] is None and cs["decision"] == "N/A"


def test_code_safety_moves_per_repo():
    # Two different repos get two different scores — not a flat 10/BLOCK.
    a = compute_code_safety([{"severity": "medium"}], agent_detected=True)
    b = compute_code_safety([{"severity": "medium"}] * 6, agent_detected=True)
    assert a["score"] != b["score"]


def test_governance_levels():
    none_present = {s["id"]: False for s in SAFEGUARDS}
    all_present = {s["id"]: True for s in SAFEGUARDS}
    g0 = compute_governance(none_present)
    g1 = compute_governance(all_present)
    assert g0["score"] == 0 and g0["level"] == "Undeclared" and g0["present"] == 0
    assert g1["score"] == 100 and g1["level"] == "Mature" and g1["present"] == len(SAFEGUARDS)
