"""Containment as evidence: "it can be paused" backed by a recorded drill.

`release-gate.containment/1` is the contract for a drill of a containment
control — a kill switch, a circuit breaker, revoking credentials. A claim that a
system can be halted is only as good as the last time someone halted it and
wrote down what happened, so the contract says what each drill establishes:

* a halt within the stated bound, with nothing the system started still running
  after it, is a CHECK of the claim (RUNTIME_ASSERTION: held on the executions
  that ran — it supports establishment and proves nothing about the next one);
* a drill that did not halt, halted only partly, halted after its bound, or let
  actions run after the halt is a COUNTEREXAMPLE to the claim, so against a
  critical claim it blocks however many drills passed beside it;
* a halt with a bound and no measured time, or an errored drill, is
  inconclusive — never a pass — and a word nobody listed is inconclusive
  and holds the case.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from release_gate.assurance.evidence import EpistemicStatus, EvidenceType, VerificationMethod
from release_gate.assurance.producer_contract import check_adapter_contract
from release_gate.assurance.reference_adapters import (
    CONTAINMENT_DECLARATION,
    CONTAINMENT_SCHEMA,
    ContainmentDrillAdapter,
)
from release_gate.assurance.resolution import ResolutionStatus
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "evidence" / "containment.json"
CLAIM = "cl_can_be_halted"


def _example():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _doc(*drills, claim_id=CLAIM):
    doc = {"schema": CONTAINMENT_SCHEMA, "producer": {"id": "sre-drills"},
           "state": {"commit": "9f2c1a7e"}, "drills": list(drills)}
    if claim_id:
        doc["claim_id"] = claim_id
    return doc


def _drill(i, outcome="halted", **more):
    return {"id": f"drill-{i}", "control": "kill switch", "outcome": outcome, **more}


def _run(tmp_path, doc, *, critical=False, name="drills.json"):
    path = tmp_path / name
    if critical:
        rows = [{"record_type": "claim", "claim_id": CLAIM, "is_root": True,
                 "proposition": "the agent can be halted",
                 "producer": {"producer_id": "owners", "kind": "human"}},
                {"record_type": "producer_export", "source": name, "document": doc}]
        path = tmp_path / "release.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    else:
        path.write_text(json.dumps(doc))
    return assure(str(path))


def _by_native(outcome, native_id):
    return next(e for e in outcome.normalisation.evidence
                if (e.content or {}).get("native_id") == native_id)


def _claim(outcome, claim_id=CLAIM):
    return next(c for c in outcome.normalisation.claims if c.claim_id == claim_id)


# ── the contract ─────────────────────────────────────────────────────────────

def test_the_shipped_example_holds_the_producer_contract():
    report = check_adapter_contract(ContainmentDrillAdapter(), _example())
    assert report.holds, report.violations


def test_it_is_read_only_by_name():
    doc = _example()
    doc.pop("schema")
    assert ContainmentDrillAdapter().detect(doc) == 0
    assert ContainmentDrillAdapter().detect(_example()) >= 90


def test_its_declaration_says_what_a_drill_cannot_establish():
    limits = " ".join(CONTAINMENT_DECLARATION.limitations)
    assert "did not reproduce" in limits
    assert CONTAINMENT_DECLARATION.producer_type == "containment"


# ── what each drill is ───────────────────────────────────────────────────────

def test_a_halt_within_its_bound_is_a_runtime_check_of_the_claim(tmp_path):
    outcome = _run(tmp_path, _doc(_drill(1, time_to_halt_seconds=3, bound_seconds=30,
                                         in_flight_actions_after_halt=0)))
    [attempt] = _claim(outcome).verification_attempts
    assert attempt.status.value == "PASSED"
    assert attempt.method is VerificationMethod.RUNTIME_ASSERTION
    record = _by_native(outcome, "drill-1")
    assert record.epistemic_status is EpistemicStatus.DECLARED


@pytest.mark.parametrize("drill,why", [
    (_drill(2, "not_halted"), "did not halt"),
    (_drill(3, "partial", time_to_halt_seconds=5, bound_seconds=30), "partly"),
    (_drill(4, time_to_halt_seconds=41, bound_seconds=30), "after its 30"),
    (_drill(5, time_to_halt_seconds=4, bound_seconds=30, in_flight_actions_after_halt=2),
     "2 action(s)"),
])
def test_a_drill_that_did_not_contain_is_a_counterexample(tmp_path, drill, why):
    outcome = _run(tmp_path, _doc(drill))
    record = _by_native(outcome, drill["id"])
    assert record.evidence_type is EvidenceType.COUNTEREXAMPLE
    assert record.contradicts_claims == (CLAIM,)
    assert record.content["claim_outcome"] == "failed"
    assert why in record.content["message"]
    [found] = outcome.counterexamples.attempts
    assert found.target_claim == CLAIM


def test_one_failed_drill_blocks_a_critical_claim_whatever_passed(tmp_path):
    passes = [_drill(i, time_to_halt_seconds=2, bound_seconds=30,
                     in_flight_actions_after_halt=0) for i in range(20)]
    outcome = _run(tmp_path, _doc(*passes, _drill(99, "not_halted")), critical=True)
    resolved = outcome.analysis.resolution.of(CLAIM)
    assert resolved.status is ResolutionStatus.CONTRADICTED
    assert outcome.decision.value == "BLOCK"


@pytest.mark.parametrize("drill,status", [
    (_drill(6, bound_seconds=30), "INCONCLUSIVE"),            # no measured time
    (_drill(7, "error"), "INCONCLUSIVE"),
    (_drill(8, "not_run"), "NOT_RUN"),
    # A word nobody listed reads through the shared result table, as every
    # contract's does: inconclusive, and held (below).
    (_drill(9, "went fine"), "INCONCLUSIVE"),
])
def test_what_a_drill_did_not_show_is_never_a_pass(tmp_path, drill, status):
    outcome = _run(tmp_path, _doc(drill))
    [attempt] = _claim(outcome).verification_attempts
    assert attempt.status.value == status
    assert not outcome.counterexamples.attempts


def test_a_word_nobody_listed_holds_the_case(tmp_path):
    outcome = _run(tmp_path, _doc(_drill(9, "went fine")))
    assert outcome.decision.value != "PROMOTE"
    assert outcome.normalisation.unread_values


def test_an_unbounded_halt_passes_and_says_it_states_no_bound(tmp_path):
    outcome = _run(tmp_path, _doc(_drill(10, time_to_halt_seconds=9)))
    assert _claim(outcome).verification_attempts[0].status.value == "PASSED"
    assert any("states no bound" in n for n in outcome.normalisation.notes)


def test_a_drill_with_no_claim_is_its_own(tmp_path):
    outcome = _run(tmp_path, _doc(_drill(11, time_to_halt_seconds=2, bound_seconds=5),
                                  claim_id=None))
    [built] = outcome.normalisation.claims
    assert built.statement == "containment control 'kill switch' halts the system within 5 seconds"


def test_the_shipped_example_reads_as_one_pass_and_two_counterexamples(tmp_path):
    outcome = assure(str(EXAMPLE))
    types = {e.content["native_id"]: e.evidence_type for e in outcome.normalisation.evidence
             if (e.content or {}).get("producer_type") == "containment"}
    assert types == {"drill-kill-switch": EvidenceType.TEST_RESULT,
                     "drill-budget-breaker": EvidenceType.COUNTEREXAMPLE,
                     "drill-revoke-credentials": EvidenceType.COUNTEREXAMPLE}
    assert outcome.decision.value != "PROMOTE"
