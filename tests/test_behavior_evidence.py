"""release-gate.behavior/1, and ProofAgent's PER read through it (an example mapping).

What a behavioural harness says arrives as attributed evidence: its verdict
words are kept and read through one table, the decider of each check fixes the
method (a model jury is a model's reading), a violation it proved is a
counterexample, and its own recommendation and scores are recorded and read by
nothing. The ProofAgent example is exercised end to end, and changed one input
at a time to show which inputs move the decision and which cannot.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.evidence import VerificationMethod
from release_gate.assurance.producer_contract import (
    ConfidenceSemantics, NativeResult, ProducerContractError, ResultKind,
    check_adapter_contract, default_producer_registry)
from release_gate.assurance.reference_adapters import (
    BEHAVIOR_DECLARATION, BEHAVIOR_SCHEMA, BehaviorEvalAdapter, reference_adapters)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "proofagent"


def doc(*checks, violations=(), recommendation=None, scores=None, state=None, **extra):
    d = {"schema": BEHAVIOR_SCHEMA,
         "producer": {"id": "acme-behaviour", "version": "2.0"},
         "run_id": "run-1", "ran_at": "2026-10-07T09:00:00Z",
         "state": state if state is not None else {"commit": "c4f8d31"},
         "checks": list(checks)}
    if violations:
        d["violations"] = list(violations)
    if recommendation:
        d["recommendation"] = {"decision": recommendation, "basis": "its own"}
    if scores is not None:
        d["scores"] = scores
    d.update(extra)
    return d


def check(cid, outcome, claim="cl_authz", decided_by="deterministic", **extra):
    row = {"id": cid, "claim_id": claim, "claim": "no action without approval",
           "outcome": outcome}
    if decided_by is not None:
        row["decided_by"] = decided_by
    row.update(extra)
    return row


def run(tmp_path, document, *, claims=(), candidate=None):
    rows = []
    if candidate:
        rows.append({"record_type": "candidate", "components": candidate})
    for c in claims:
        rows.append({"record_type": "claim", "claim_id": c, "is_root": True,
                     "proposition": "no action without approval",
                     "producer": {"producer_id": "owner", "kind": "human"}})
    rows.append({"record_type": "producer_export", "source": "behaviour.json",
                 "document": document})
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "release.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return assure(path)


def attempts_on(outcome, claim_id):
    claim = next(c for c in outcome.case.collection("claims").materialised
                 if c.claim_id == claim_id)
    return list(claim.verification_attempts)


def status(outcome, claim_id):
    return outcome.analysis.resolution.of(claim_id).status.value


# ── the contract ─────────────────────────────────────────────────────────────

class TestTheContract:

    def test_it_is_one_of_the_registered_reference_contracts(self):
        assert any(isinstance(a, BehaviorEvalAdapter) for a in reference_adapters())
        registry = default_producer_registry()
        adapter, _ = registry.read(doc(check("c1", "pass")))
        assert isinstance(adapter, BehaviorEvalAdapter)

    def test_it_is_read_only_by_its_schema_name(self):
        assert BehaviorEvalAdapter().detect(doc(check("c1", "pass"))) == 95
        lookalike = doc(check("c1", "pass"))
        lookalike["schema"] = "release-gate.eval/1"
        assert BehaviorEvalAdapter().detect(lookalike) == 0
        assert BehaviorEvalAdapter().detect({"checks": []}) == 0

    def test_it_passes_the_producer_contract(self):
        report = check_adapter_contract(BehaviorEvalAdapter(), doc(
            check("c1", "APPLICABLE_PASS"), check("c2", "APPLICABLE_FAIL"),
            violations=[{"id": "v1", "check_ids": ["c2"], "proof": "PROVEN"}],
            recommendation="BLOCK", scores={"pai": 41}))
        assert report.violations == ()

    def test_its_scores_are_declared_as_no_confidence_at_all(self):
        assert BEHAVIOR_DECLARATION.confidence is ConfidenceSemantics.NONE
        assert any("jury" in limit for limit in BEHAVIOR_DECLARATION.limitations)


class TestTheWordsAreKeptAndReadThroughOneTable:

    @pytest.mark.parametrize("word,expected", [
        ("APPLICABLE_PASS", "PASSED"), ("pass", "PASSED"),
        ("APPLICABLE_FAIL", "FAILED"), ("fail", "FAILED"),
        ("NOT_APPLICABLE", "NOT_RUN"), ("skipped", "NOT_RUN"),
        ("UNRESOLVED", "INCONCLUSIVE"), ("EVIDENCE_INVALID", "INCONCLUSIVE"),
        ("EVIDENCE_INCOMPLETE", "INCONCLUSIVE"), ("EVALUATOR_ERROR", "INCONCLUSIVE"),
        ("timeout", "INCONCLUSIVE"), ("probably fine", "INCONCLUSIVE")])
    def test_each_state(self, word, expected, tmp_path):
        outcome = run(tmp_path, doc(check("c1", word)))
        (attempt,) = attempts_on(outcome, "cl_authz")
        assert attempt.status.value == expected
        record = next(r for r in outcome.normalisation.evidence
                      if r.producer.producer_id == "acme-behaviour")
        assert record.content["native_outcome"] == word

    def test_an_evaluator_fault_is_never_support(self, tmp_path):
        outcome = run(tmp_path, doc(check("c1", "EVALUATOR_ERROR")), claims=["cl_authz"])
        assert status(outcome, "cl_authz") == "UNKNOWN"


class TestTheDeciderFixesTheMethod:

    @pytest.mark.parametrize("decider,method", [
        ("deterministic", "SIMULATION"), ("semantic", "CROSS_MODEL_REVIEW"),
        ("human", "HUMAN_REVIEW"), (None, "OTHER"), ("oracle", "OTHER")])
    def test_each_decider(self, decider, method, tmp_path):
        outcome = run(tmp_path, doc(check("c1", "pass", decided_by=decider)))
        (attempt,) = attempts_on(outcome, "cl_authz")
        assert attempt.method.value == method

    def test_an_unclassified_decider_is_named(self, tmp_path):
        outcome = run(tmp_path, doc(check("c1", "pass", decided_by="oracle")))
        assert any("'oracle'" in n and "OTHER" in n for n in outcome.normalisation.notes)

    def test_a_model_jurys_pass_supports_and_never_establishes(self, tmp_path):
        outcome = run(tmp_path, doc(
            check("c1", "pass", decided_by="semantic", evaluator_model="judge-a"),
            check("c2", "pass", decided_by="semantic", evaluator_model="judge-b")),
            claims=["cl_authz"])
        assert status(outcome, "cl_authz") == "SUPPORTED"

    def test_the_jury_model_is_kept_for_correlation(self, tmp_path):
        outcome = run(tmp_path, doc(check("c1", "pass", decided_by="semantic",
                                          evaluator_model="judge-a")))
        (attempt,) = attempts_on(outcome, "cl_authz")
        assert attempt.result["provenance"]["evaluator_model"] == "judge-a"

    def test_without_a_stated_method_a_result_takes_its_lanes(self):
        """The new field is additive: every other producer is unchanged."""
        result = NativeResult(kind=ResultKind.CHECK, native_id="x")
        assert result.method is None
        assert NativeResult(kind=ResultKind.CHECK, native_id="x",
                            method="SIMULATION").method is VerificationMethod.SIMULATION
        with pytest.raises(ValueError):
            NativeResult(kind=ResultKind.CHECK, native_id="x", method="GUESS")

    def test_an_eval_harness_is_still_a_test_suite(self, tmp_path):
        eval_doc = {"schema": "release-gate.eval/1", "producer": {"id": "e"},
                    "cases": [{"id": "k1", "outcome": "passed", "claim_id": "cl_authz"}]}
        outcome = run(tmp_path, eval_doc)
        (attempt,) = attempts_on(outcome, "cl_authz")
        assert attempt.method is VerificationMethod.TEST_SUITE


class TestViolations:

    def test_a_proven_violation_is_a_counterexample(self, tmp_path):
        outcome = run(tmp_path, doc(
            check("c1", "APPLICABLE_FAIL"),
            violations=[{"id": "v1", "check_ids": ["c1"], "proof": "PROVEN",
                         "severity": "CRITICAL", "observed": "t07 · boundary"}]),
            claims=["cl_authz"])
        standings = outcome.analysis.counterexample_standings
        assert [s.standing.value for s in standings] == ["VALID"]
        assert status(outcome, "cl_authz") == "CONTRADICTED"
        assert outcome.decision.value == "BLOCK"

    def test_an_unproven_violation_is_not_a_counterexample_and_the_fail_still_stands(
            self, tmp_path):
        outcome = run(tmp_path, doc(
            check("c1", "APPLICABLE_FAIL"),
            violations=[{"id": "v1", "check_ids": ["c1"], "proof": "UNPROVEN"}]),
            claims=["cl_authz"])
        standings = outcome.analysis.counterexample_standings
        assert not standings
        assert status(outcome, "cl_authz") == "CONTRADICTED"
        assert any("not proven" in n for n in outcome.normalisation.notes)


class TestNothingTheHarnessConcludesIsAdopted:

    def _case(self, tmp_path, **changes):
        base = dict(recommendation="PASS", scores={"pai": {"value": 97}})
        base.update(changes)
        return run(tmp_path, doc(check("c1", "APPLICABLE_FAIL"), **base),
                   claims=["cl_authz"])

    def _conditions(self, outcome):
        return sorted((c.dimension.value, c.effect.value, c.summary)
                      for c in outcome.admission.conditions)

    def test_its_recommendation_moves_nothing(self, tmp_path):
        passing = self._case(tmp_path / "a", recommendation="PASS")
        blocking = self._case(tmp_path / "b", recommendation="BLOCK")
        assert passing.decision is blocking.decision
        assert self._conditions(passing) == self._conditions(blocking)

    def test_its_scores_move_nothing(self, tmp_path):
        high = self._case(tmp_path / "a", scores={"pai": {"value": 99}})
        low = self._case(tmp_path / "b", scores={"pai": {"value": 3}})
        absent = self._case(tmp_path / "c", scores=None)
        assert high.decision is low.decision is absent.decision
        assert self._conditions(high) == self._conditions(low) == self._conditions(absent)

    def test_no_check_carries_a_confidence(self, tmp_path):
        """Not a per-check score, not the run's readiness index: nothing is confidence."""
        outcome = self._case(tmp_path, scores={"pai": 0.97, "metrics": {"safety": 9.9}})
        for record in outcome.normalisation.evidence:
            if record.producer.producer_id == "acme-behaviour":
                assert "confidence" not in record.content

    def test_its_recommendation_is_recorded_as_its_own_decision(self, tmp_path):
        outcome = self._case(tmp_path, recommendation="REVIEW")
        (record,) = [r for r in outcome.normalisation.evidence
                     if r.evidence_type.value == "ATTESTATION"]
        assert record.content["native"]["decision"] == "REVIEW"
        assert record.content["native"]["scores"] == {"pai": {"value": 97}}
        assert not record.supports_claims and not record.contradicts_claims

    def test_its_limitations_are_said(self, tmp_path):
        outcome = run(tmp_path, doc(check("c1", "pass"),
                                    limitations=["tool outputs not captured"]))
        assert any("tool outputs not captured" in n for n in outcome.normalisation.notes)

    def test_its_evidence_is_read_not_run(self, tmp_path):
        outcome = run(tmp_path, doc(check("c1", "pass")))
        entry = next(e for e in outcome.evidence_origin.entries
                     if e.producer_id == "acme-behaviour")
        assert entry.origin.value == "READ"


class TestStateBinding:

    def test_a_run_against_another_ai_bom_stops_supporting(self, tmp_path):
        state = {"model": "m1", "artifact:ai-bom": "sha256:" + "1" * 64}
        candidate = {"model": "m1", "artifact:ai-bom": "sha256:" + "2" * 64}
        outcome = run(tmp_path, doc(check("c1", "pass"), state=state),
                      claims=["cl_authz"], candidate=candidate)
        withheld = [b for b in outcome.analysis.state_binding.bindings
                    if b.withholds_support]
        assert withheld
        assert status(outcome, "cl_authz") != "SUPPORTED"


# ── the ProofAgent example ───────────────────────────────────────────────────

def _example():
    spec = importlib.util.spec_from_file_location("pa_run_example",
                                                  EXAMPLE / "run_example.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def example():
    return _example()


class TestTheShim:

    def test_it_refuses_a_per_version_it_was_not_written_against(self, example):
        from per_to_behavior import MappingError, per_to_behavior
        per = example.load_per()
        for version in ("2.0.0", "3.0.0", None):
            changed = copy.deepcopy(per)
            changed["header"]["per_version"] = version
            with pytest.raises(MappingError, match="not one this mapping"):
                per_to_behavior(changed)

    def test_it_passes_proofagents_words_through_verbatim(self, example):
        from per_to_behavior import per_to_behavior
        per = example.load_per()
        document, _ = per_to_behavior(per)
        assert [c["outcome"] for c in document["checks"]] == \
            [c["state"] for c in per["claims"]]
        assert [c["decided_by"] for c in document["checks"]] == \
            [c["decided_by"] for c in per["claims"]]
        assert document["recommendation"]["decision"] == \
            per["release_recommendation"]["state"]
        assert document["scores"] == per["scores"]
        assert "confidence" not in json.dumps(document["checks"])

    def test_context_gaps_are_left_out_and_counted(self, example):
        from per_to_behavior import per_to_behavior
        per = example.load_per()
        per["findings"].append({"finding_id": "c" * 20, "kind": "CONTEXT_GAP",
                                "claim_ids": [], "display_label": "no escalation policy"})
        document, notes = per_to_behavior(per)
        assert len(document["violations"]) == 1
        assert any("1 CONTEXT_GAP" in n for n in notes)

    def test_the_cli_writes_the_document(self, tmp_path):
        out = tmp_path / "behaviour.json"
        result = subprocess.run([sys.executable, str(EXAMPLE / "per_to_behavior.py"),
                                 str(EXAMPLE / "sample-run.per.json"), "-o", str(out)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert json.loads(out.read_text())["schema"] == BEHAVIOR_SCHEMA

    def test_the_sample_claims_are_valid_per_claims(self):
        """Run where `eio-agents` is installed: the sample against the real schema."""
        eio = pytest.importorskip("eio_agents")
        jsonschema = pytest.importorskip("jsonschema")
        schema_path = (Path(eio.__file__).parent / "schemas" / "per" /
                       "per-2.1.2.schema.json")
        schema = json.loads(schema_path.read_text())
        sample = json.loads((EXAMPLE / "sample-run.per.json").read_text())
        validator = jsonschema.Draft202012Validator(
            {"$schema": schema.get("$schema"), "$defs": schema["$defs"],
             "$ref": "#/$defs/claim"})
        for claim in sample["claims"]:
            assert not list(validator.iter_errors(claim))


class TestTheExample:

    def test_the_check_passes(self):
        result = subprocess.run([sys.executable, str(EXAMPLE / "run_example.py"), "--check"],
                                capture_output=True, text=True, cwd=ROOT,
                                env={**os.environ, "PYTHONPATH": str(ROOT)})
        assert result.returncode == 0, result.stdout + result.stderr
        assert "example check OK" in result.stdout

    def test_proofagents_recommendation_and_scores_move_nothing(self, example):
        per = example.load_per()
        base = example.reading(example.admit(per))
        flipped = copy.deepcopy(per)
        flipped["release_recommendation"]["state"] = "PASS"
        flipped["scores"] = {"pai": {"value": 99, "band": "ready"}}
        moved = example.reading(example.admit(flipped))
        assert (base["decision"], base["blocking"]) == (moved["decision"], moved["blocking"])
        assert base["graph"] == moved["graph"]

    def test_the_proven_violation_is_what_blocks(self, example):
        per = example.load_per()
        fixed = copy.deepcopy(per)
        for claim in fixed["claims"]:
            if claim["predicate"].endswith("autonomy-boundary-exceeded"):
                claim["state"] = "APPLICABLE_PASS"
        fixed["findings"] = []
        facts = example.reading(example.admit(fixed))
        assert facts["graph"]["root"]["status"] != "CONTRADICTED"
        assert "RG-CEX-001" not in facts["blocking"]
        assert facts["counterexamples"] == []

    def test_a_per_of_another_agent_stops_supporting_this_release(self, example):
        per = example.load_per()
        other = copy.deepcopy(per)
        other["subject"]["ai_bom"]["content_hash"] = "sha256:" + "0" * 64
        outcome = example.admit(other)
        withheld = [b for b in outcome.analysis.state_binding.bindings
                    if b.withholds_support]
        assert withheld


def test_a_contract_error_still_refuses_a_decision_with_a_claim():
    with pytest.raises(ProducerContractError):
        NativeResult(kind=ResultKind.DECISION, native_id="r", claim_statement="x")
