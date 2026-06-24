"""The three loop demo agents are the 'aha' fixtures — lock in that they land on
PROMOTE / HOLD / BLOCK across BOTH surfaces (loop-sim and agent-score) for the
documented reasons, so the showcase can't silently rot.
"""
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.loop_agents import good, mid, worst
from release_gate.agent.client import AgentClient
from release_gate.loop_sim import LoopSimulator
from release_gate.agent_score import AgentScorer

_SCEN = Path(__file__).resolve().parent.parent / "examples" / "loop_demo_scenarios.yaml"


def _sim(name):
    """Run loop-sim through AgentClient, exactly as the CLI does — so token/cost
    estimation for py: agents is exercised (a plain function call reports 0 cost)."""
    doc = yaml.safe_load(_SCEN.read_text())
    client = AgentClient.from_spec(f"py:examples.loop_agents:{name}")
    return LoopSimulator().run(
        doc["scenarios"], agent=lambda t, c: client.invoke(t, c),
        loop_policy=doc["loop"],
    )


# ── loop-sim: behaviour in a loop ──────────────────────────────────────────────

def test_good_promotes_in_loop():
    r = _sim("good")
    assert r.decision == "PROMOTE"
    assert r.convergence_rate == 1.0
    assert r.max_iterations == 1            # ships on the first pass


def test_mid_holds_in_loop():
    r = _sim("mid")
    assert r.decision == "HOLD"
    assert r.convergence_rate == 1.0        # it DOES converge...
    assert r.p95_iterations >= 5            # ...but only after dawdling


def test_worst_blocks_in_loop():
    r = _sim("worst")
    assert r.decision == "BLOCK"
    assert r.convergence_rate == 0.0        # never ships
    assert any("cost" in v.lower() for v in r.top_violations)  # and blows budget


# ── agent-score: the L-tier safety story ───────────────────────────────────────

def test_good_clean_across_all_tiers():
    d = AgentScorer().score(good).as_dict()
    assert d["decision"] == "PROMOTE"
    s = d["dimensions"]["safety"]
    assert s["l1"]["leaked"] == 0 and s["l2"]["leaked"] == 0
    assert s["l3"]["leaked"] == 0 and s["l4"]["leaked"] == 0


def test_mid_leaks_only_on_l3():
    d = AgentScorer().score(mid).as_dict()
    assert d["decision"] == "HOLD"
    s = d["dimensions"]["safety"]
    assert s["l1"]["leaked"] == 0           # holds the floor
    assert s["l3"]["leaked"] >= 1           # but folds to encode/translate


def test_worst_leaks_on_l1():
    d = AgentScorer().score(worst).as_dict()
    assert d["decision"] == "BLOCK"
    assert d["dimensions"]["safety"]["critical_leaked"] >= 1
