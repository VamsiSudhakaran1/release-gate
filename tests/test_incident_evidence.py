"""Incidents: a failure in operation becomes a counterexample every later release must answer.

An `incident` envelope record states a failure once: who reported it, which
claims it breaks, which states of the release it was seen on, whether it was
disclosed, and where its remediation stands. What these tests pin:

* it is one ATTESTATION (the reporter's account) and one counterexample per
  claim and affected state — never a lifted duplicate of itself;
* against the state that failed, an open incident blocks a critical claim;
  against a later state it holds the case (STALE) until something answers it;
  with no affected state it stands against every candidate;
* only an answer the counterexample checks accept moves it — a resolution must
  cite evidence this case holds, a mitigation is not a fix, a word nobody listed
  stays open and holds;
* an incident that names no claim is its own claim, and disclosure is recorded
  as stated.
"""
from __future__ import annotations

import copy
import dataclasses
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from release_gate.assurance.counterexample import CounterexampleStanding
from release_gate.assurance.evidence import EpistemicStatus, EvidenceType
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.resolution import DEFAULT_RESOLUTION_POLICY
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "evidence" / "incident.jsonl"
GENERAL = default_registry().resolve("general-agent-action@1.0.0")
OLD, NEW = "9f2c1a7e", "b7e4f2a1c3d5"
CLAIM = "cl_refund_once"


def _rows():
    return [json.loads(line) for line in EXAMPLE.read_text().splitlines() if line.strip()]


def _incident(rows):
    return next(r for r in rows if r["record_type"] == "incident")


def _write(tmp_path, rows):
    path = tmp_path / "release.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


def _run(tmp_path, rows, **kwargs):
    return assure(str(_write(tmp_path, rows)), methodology=GENERAL, **kwargs)


def _with(**changes):
    rows = _rows()
    incident = _incident(rows)
    for key, value in changes.items():
        if value is None:
            incident.pop(key, None)
        else:
            incident[key] = value
    return rows


def _candidate(rows, commit):
    rows = copy.deepcopy(rows)
    next(r for r in rows if r["record_type"] == "candidate")["components"]["commit"] = commit
    return rows


def _standings(outcome):
    return {s.target_claim: s.standing for s in outcome.analysis.counterexample_standings}


def _fired(outcome):
    return {f.rule_id for f in outcome.analysis.findings if f.effect.value != "ADVISORY"}


def _incident_records(outcome):
    return [e for e in outcome.normalisation.evidence
            if isinstance(e.content, Mapping) and "incident" in e.content]


# ── what an incident is ──────────────────────────────────────────────────────

def test_it_is_one_account_and_one_counterexample_per_claim_and_state(tmp_path):
    rows = _with(affected_states=[{"commit": OLD}, {"commit": "1234567abc"}])
    outcome = _run(tmp_path, rows)
    [record] = _incident_records(outcome)
    assert record.evidence_type is EvidenceType.ATTESTATION
    assert record.epistemic_status is EpistemicStatus.DECLARED
    assert record.supports_claims == () and record.contradicts_claims == ()
    attempts = outcome.counterexamples.attempts
    assert len(attempts) == 2
    assert {a.state.get("commit") for a in attempts} == {OLD, "1234567abc"}
    assert all(a.evidence == (record.evidence_id,) for a in attempts)


def test_against_the_state_that_failed_it_blocks_the_critical_claim(tmp_path):
    outcome = _run(tmp_path, _candidate(_rows(), OLD))
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.VALID
    assert "RG-CEX-001" in _fired(outcome)
    assert outcome.decision.value == "BLOCK"


def test_against_a_later_release_it_holds_until_answered(tmp_path):
    outcome = _run(tmp_path, _rows())
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.STALE
    held = [f for f in outcome.analysis.findings if f.rule_id == "RG-CEX-004"]
    assert held and held[0].effect.value == "HOLD"
    assert "RG-CEX-001" not in _fired(outcome)
    # general-agent-action also requires that no contradiction stays open, and a
    # stale counterexample is still an open one: under it the release blocks.
    assert outcome.decision.value == "BLOCK"


def test_with_no_affected_state_it_stands_against_every_release(tmp_path):
    outcome = _run(tmp_path, _with(affected_states=None))
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.VALID
    assert outcome.decision.value == "BLOCK"


def test_an_unreadable_affected_state_is_kept_against_every_state(tmp_path):
    outcome = _run(tmp_path, _with(affected_states=[{"colour": "blue"}]))
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.VALID
    assert any("affected state could not be read" in u
               for u in outcome.normalisation.unread_values)


def test_an_incident_that_names_no_claim_is_its_own(tmp_path):
    outcome = _run(tmp_path, _with(claims=None))
    claim = next(c for c in outcome.normalisation.claims
                 if c.claim_id == "rg-incident:INC-2291")
    assert "INC-2291" in claim.statement and "does not recur" in claim.statement
    assert [a.target_claim for a in outcome.counterexamples.attempts] == [claim.claim_id]
    assert outcome.decision.value != "PROMOTE"


def test_disclosure_is_recorded_as_stated(tmp_path):
    outcome = _run(tmp_path, _rows())
    [record] = _incident_records(outcome)
    assert record.content["incident"]["disclosure"]["status"] == "disclosed"
    assert "disclosure disclosed to the two affected customers" in \
        outcome.counterexamples.attempts[0].detail


def test_an_incident_without_an_id_is_refused_and_holds(tmp_path):
    outcome = _run(tmp_path, _with(incident_id=None))
    assert not _incident_records(outcome)
    assert any("incident" in reason for reason in outcome.normalisation.skipped)
    assert outcome.decision.value != "PROMOTE"


def test_a_replayed_incident_is_one_incident(tmp_path):
    rows = _rows()
    rows.append(copy.deepcopy(_incident(rows)))
    outcome = _run(tmp_path, rows)
    assert len(_incident_records(outcome)) == 1
    assert len(outcome.counterexamples.attempts) == 1


# ── answering it ─────────────────────────────────────────────────────────────

def _fix_row():
    return {"record_type": "evidence", "evidence_id": "e-retry-test", "kind": "TEST_RESULT",
            "producer": {"producer_id": "ci://github-actions/run/10234", "kind": "tool"},
            "supports_claims": [CLAIM], "state": {"commit": NEW},
            "coverage_note": "regression test: a timed-out refund is not retried"}


def test_a_resolution_citing_evidence_the_case_holds_answers_it(tmp_path):
    rows = _with(remediation={"status": "resolved",
                              "resolution": "idempotency key on every refund call",
                              "resolution_evidence": ["e-retry-test"]})
    rows.append(_fix_row())
    outcome = _run(tmp_path, rows)
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.RESOLVED
    assert not {"RG-CEX-001", "RG-CEX-004"} & _fired(outcome)
    [attempt] = outcome.counterexamples.attempts
    held = {e.evidence_id for e in outcome.normalisation.evidence}
    assert set(attempt.resolution_evidence) <= held


def test_a_resolution_citing_evidence_the_case_does_not_hold_is_refused(tmp_path):
    rows = _with(remediation={"status": "resolved", "resolution": "fixed",
                              "resolution_evidence": ["e-retry-test"]})
    outcome = _run(tmp_path, rows)
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.STALE
    assert any("does not hold" in u for u in outcome.normalisation.unread_values)


def test_a_resolution_with_no_evidence_is_refused(tmp_path):
    outcome = _run(tmp_path, _with(remediation={"status": "fixed", "resolution": "fixed"}))
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.STALE
    assert outcome.normalisation.unread_values


@pytest.mark.parametrize("word", ["mitigated", "investigating", "monitoring"])
def test_a_mitigation_is_not_a_fix(tmp_path, word):
    outcome = _run(tmp_path, _with(remediation={"status": word}))
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.STALE
    assert not outcome.normalisation.unread_values


def test_a_remediation_word_nobody_listed_stays_open_and_holds(tmp_path):
    outcome = _run(tmp_path, _with(remediation={"status": "done"}))
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.STALE
    assert any("'done'" in u for u in outcome.normalisation.unread_values)


def test_an_accepted_risk_lifts_nothing_unless_the_policy_permits_it(tmp_path):
    rows = _candidate(_with(remediation={
        "status": "accepted_risk", "resolution": "refunds are capped at 50 USD",
        "accepted_by": "cfo@acme.example", "reference": "RISK-88",
        "accepted_for": {"commit": OLD}}), OLD)
    held = _run(tmp_path, rows)
    assert _standings(held)[CLAIM] is CounterexampleStanding.VALID
    permitting = dataclasses.replace(DEFAULT_RESOLUTION_POLICY,
                                     counterexample_exceptions=True)
    accepted = _run(tmp_path, rows, resolution_policy=permitting)
    assert _standings(accepted)[CLAIM] is CounterexampleStanding.ACCEPTED


def test_an_invalid_incident_must_say_why(tmp_path):
    with_reason = _run(tmp_path, _with(remediation={
        "status": "not_a_defect", "resolution": "the second payment was a separate refund"}))
    assert _standings(with_reason)[CLAIM] is CounterexampleStanding.INVALIDATED
    without = _run(tmp_path, _with(remediation={"status": "invalid"}))
    assert _standings(without)[CLAIM] is CounterexampleStanding.STALE


def test_the_shipped_example_stops_the_next_release(tmp_path):
    outcome = assure(str(EXAMPLE), methodology=GENERAL)
    assert _standings(outcome)[CLAIM] is CounterexampleStanding.STALE
    assert "RG-CEX-004" in _fired(outcome)
    assert outcome.decision.value == "BLOCK"
