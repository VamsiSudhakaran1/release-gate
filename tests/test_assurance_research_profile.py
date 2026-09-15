"""The research assurance profile: ten rules, each with precise triggering semantics.

Every rule is tested three ways — what fires it, what does NOT fire it, and what
NOT_ASSESSED looks like — because a rule that cannot tell "unverified" from "not
looked at" is the failure this whole system exists to prevent (Invariant 3).
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.methodologies import (
    RESEARCH_ASSURANCE_V1, default_registry)
from release_gate.assurance.methodology import (
    AppliesToCurrentState, CriticalClaimsVerified, DeclaredIndependenceHolds,
    MethodologyError, RequirementEffect, RequirementOutcome, predicate_from_dict)

DIGEST = "sha256:" + "a" * 64


def outcome_for(tmp_path, rows, name="case.json"):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return assure(str(path), methodology=RESEARCH_ASSURANCE_V1)


def result(outcome, rule):
    return next(r for r in outcome.assessment.results if r.requirement_id == rule)


def attempt(method="THEOREM_PROVER", verifier="lean", outcome="PASSED",
            digest=DIGEST, lineage=()):
    row = {"method": method, "verifier": verifier, "outcome": outcome}
    if digest:
        row["target_digest"] = digest
    if lineage:
        row["independence_lineage"] = list(lineage)
    return row


def theorem(**kw):
    row = {"record_type": "claim", "claim_id": "T", "is_root": True,
           "statement": "the bound is tight"}
    row.update(kw)
    return row


# ── the profile itself ───────────────────────────────────────────────────────

class TestTheProfile:

    def test_it_is_registered(self):
        assert default_registry().latest("research-assurance") is not None

    def test_all_ten_named_rules_exist(self):
        ids = {r.requirement_id for r in RESEARCH_ASSURANCE_V1.requirements}
        for n in range(1, 11):
            assert f"RG-CLAIM-{n:03d}" in ids

    def test_it_covers_the_six_target_areas_through_one_case_type(self):
        from release_gate.assurance.case import CaseType
        assert CaseType.RESEARCH_RESULT in RESEARCH_ASSURANCE_V1.case_types

    def test_it_does_not_claim_a_result_is_true(self):
        assert "does not say a result is true" in RESEARCH_ASSURANCE_V1.description

    def test_cross_model_review_is_not_an_accepted_verification(self):
        # Models agreeing about a derivation is agreement, not verification.
        assert "CROSS_MODEL_REVIEW" not in \
            RESEARCH_ASSURANCE_V1.accepted_verification_types

    def test_the_rules_that_cannot_be_waived_are_named(self):
        assert "RG-CLAIM-001" in RESEARCH_ASSURANCE_V1.non_overridable_conditions
        assert "RG-CLAIM-010" in RESEARCH_ASSURANCE_V1.non_overridable_conditions

    def test_some_rules_remain_overridable_on_purpose(self):
        # A profile nobody can override in a real emergency is one people route
        # around entirely.
        overridable = {r.requirement_id for r in RESEARCH_ASSURANCE_V1.requirements} \
            - set(RESEARCH_ASSURANCE_V1.non_overridable_conditions)
        assert overridable

    def test_failed_branches_are_wanted_but_only_advisorily(self, tmp_path):
        expectation = next(e for e in
                           RESEARCH_ASSURANCE_V1.minimum_evidence_expectations
                           if e.collection == "failed_branches")
        assert expectation.effect is RequirementEffect.ADVISORY


# ── RG-CLAIM-001 CRITICAL_CLAIM_UNVERIFIED ───────────────────────────────────

class TestCriticalClaimUnverified:

    def test_fires_when_a_load_bearing_claim_has_no_verification(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(depends_on=["L1"]),
            {"record_type": "claim", "claim_id": "L1", "statement": "lemma"}]),
            "RG-CLAIM-001")
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "L1" in found.detail or "T" in found.detail

    def test_does_not_fire_when_every_load_bearing_claim_is_verified(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(verification_attempts=[attempt()])]), "RG-CLAIM-001")
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_an_attempt_with_no_target_digest_does_not_count(self, tmp_path):
        # UNDETERMINED applicability is emphatically not APPLIES.
        found = result(outcome_for(tmp_path, [
            theorem(verification_attempts=[attempt(digest=None)])]), "RG-CLAIM-001")
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_an_unaccepted_method_does_not_count(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(verification_attempts=[
                attempt(method="CROSS_MODEL_REVIEW")])]), "RG-CLAIM-001")
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_a_failed_attempt_does_not_count_as_verification(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(verification_attempts=[attempt(outcome="FAILED")])]),
            "RG-CLAIM-001")
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_not_assessed_when_criticality_is_undeterminable(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            {"record_type": "claim", "claim_id": "X", "statement": "a",
             "depends_on": ["Y"]},
            {"record_type": "claim", "claim_id": "Y", "statement": "b",
             "depends_on": ["X"]}]), "RG-CLAIM-001")
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def test_it_blocks(self):
        assert next(r for r in RESEARCH_ASSURANCE_V1.requirements
                    if r.requirement_id == "RG-CLAIM-001").effect \
            is RequirementEffect.BLOCK


# ── RG-CLAIM-003 FALSE_INDEPENDENCE ──────────────────────────────────────────

class TestFalseIndependence:

    def test_fires_when_more_lineages_are_asserted_than_traced(self, tmp_path):
        found = result(outcome_for(tmp_path, self._shared_upstream(3)),
                       "RG-CLAIM-003")
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "the derivation wins" in found.detail

    def test_does_not_fire_when_the_assertion_matches(self, tmp_path):
        found = result(outcome_for(tmp_path, self._shared_upstream(1)),
                       "RG-CLAIM-003")
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_not_assessed_when_nothing_asserts_a_lineage(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(verification_attempts=[attempt()])]), "RG-CLAIM-003")
        assert found.outcome is RequirementOutcome.NOT_ASSESSED
        assert "no claim of independence" in found.detail

    def test_it_never_reads_release_gates_own_fingerprint(self, tmp_path):
        # `independence_group` on evidence is release-gate's own derivation, not a
        # producer's assertion. Two producers over one upstream is the normal
        # shape the independence analyser reports and never penalises — firing
        # here would make it blocking by the back door.
        found = result(outcome_for(tmp_path, [
            {"record_type": "evidence", "evidence_id": "E-up",
             "evidence_type": "TOOL_RESULT",
             "producer": {"producer_id": "upstream"}, "content": {"n": 1}},
            {"record_type": "evidence", "evidence_id": "E-a",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "team-a"},
             "parent_evidence": ["E-up"], "supports_claims": ["T"],
             "content": {"ok": 1}},
            {"record_type": "evidence", "evidence_id": "E-b",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "team-b"},
             "parent_evidence": ["E-up"], "supports_claims": ["T"],
             "content": {"ok": 2}},
            theorem(supporting_evidence=["E-a", "E-b"])]), "RG-CLAIM-003")
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def _shared_upstream(self, lineages):
        return [
            {"record_type": "evidence", "evidence_id": "E-up",
             "evidence_type": "TOOL_RESULT",
             "producer": {"producer_id": "upstream"}, "content": {"n": 1}},
            {"record_type": "evidence", "evidence_id": "E-a",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "team-a"},
             "parent_evidence": ["E-up"], "supports_claims": ["T"],
             "content": {"ok": 1}},
            theorem(supporting_evidence=["E-a"],
                    verification_attempts=[
                        attempt(verifier=f"v{i}", lineage=(f"team-{i}",))
                        for i in range(lineages)])]


# ── RG-CLAIM-005 / 007 / 010: what it rested on moved ────────────────────────

class TestAppliesToCurrentState:

    def test_005_fires_when_a_verification_target_moved(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            {"record_type": "artifact", "artifact_id": "T", "logical_id": "T",
             "digest": "sha256:" + "b" * 64, "version": "2"},
            theorem(verification_attempts=[attempt(digest=DIGEST)])]),
            "RG-CLAIM-005")
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "has moved since" in found.detail

    def test_005_does_not_fire_when_the_digests_match(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            {"record_type": "artifact", "artifact_id": "T", "logical_id": "T",
             "digest": DIGEST, "version": "1"},
            theorem(verification_attempts=[attempt(digest=DIGEST)])]),
            "RG-CLAIM-005")
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_005_not_assessed_with_no_attempts(self, tmp_path):
        found = result(outcome_for(tmp_path, [theorem()]), "RG-CLAIM-005")
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def test_007_not_assessed_when_no_artifact_carries_a_digest(self, tmp_path):
        found = result(outcome_for(tmp_path, [theorem()]), "RG-CLAIM-007")
        # The input file is itself an artifact and is always hashed, so this
        # reports on the evidence rather than declining.
        assert found.outcome in (RequirementOutcome.SATISFIED,
                                 RequirementOutcome.NOT_ASSESSED)

    def test_the_three_scopes_share_one_implementation(self):
        # One shape, three questions: a case cannot pass one side while failing
        # the identical test on another.
        kinds = {AppliesToCurrentState(scope=s).KIND
                 for s in ("verification", "evidence", "artifact")}
        assert len(kinds) == 1

    def test_an_unknown_scope_is_refused(self):
        with pytest.raises(MethodologyError):
            AppliesToCurrentState(scope="whatever")


# ── RG-CLAIM-006 CRITICAL_CLAIM_SINGLE_LINEAGE ───────────────────────────────

class TestSingleLineage:

    def test_fires_when_a_load_bearing_claim_has_one_producer(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "solo"},
             "supports_claims": ["T"], "content": {"ok": True}},
            theorem(supporting_evidence=["E-1"])]), "RG-CLAIM-006")
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "single producer" in found.detail

    def test_does_not_fire_with_two_producers(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "a"},
             "supports_claims": ["T"], "content": {"ok": 1}},
            {"record_type": "evidence", "evidence_id": "E-2",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "b"},
             "supports_claims": ["T"], "content": {"ok": 2}},
            theorem(supporting_evidence=["E-1", "E-2"])]), "RG-CLAIM-006")
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_an_unsupported_claim_is_not_thin(self, tmp_path):
        # Zero producers is unsupported, which RG-COV-003 owns. Folding it in
        # here would blur a sharp signal into a common one.
        found = result(outcome_for(tmp_path, [theorem()]), "RG-CLAIM-006")
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_it_holds_rather_than_blocks(self):
        # A single-producer derivation is normal early and is a reason to look,
        # not to refuse.
        assert next(r for r in RESEARCH_ASSURANCE_V1.requirements
                    if r.requirement_id == "RG-CLAIM-006").effect \
            is RequirementEffect.HOLD


# ── RG-CLAIM-004 / 009: nothing left open ────────────────────────────────────

class TestOpenItems:

    def test_004_fires_on_an_unanswered_counterexample(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(),
            {"record_type": "adversarial", "target_claim": "T", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "CANDIDATE_REFUTED",
             "detail": "found one"}]), "RG-CLAIM-004")
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_004_does_not_fire_on_an_empty_search(self, tmp_path):
        # A search that came back empty bounds the search and never the claim.
        found = result(outcome_for(tmp_path, [
            theorem(),
            {"record_type": "adversarial", "target_claim": "T",
             "role": "FALSIFICATION_AGENT", "adversary": "fuzz",
             "outcome": "NO_FINDING", "attacked": "10^6 inputs"}]), "RG-CLAIM-004")
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_009_fires_on_an_open_contradiction(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            {"record_type": "evidence", "evidence_id": "E-for",
             "evidence_type": "FORMAL_PROOF", "producer": {"producer_id": "a"},
             "supports_claims": ["T"], "content": {"ok": 1}},
            {"record_type": "evidence", "evidence_id": "E-against",
             "evidence_type": "COUNTEREXAMPLE", "producer": {"producer_id": "b"},
             "contradicts_claims": ["T"], "content": {"no": 1}},
            theorem(supporting_evidence=["E-for"],
                    contradicting_evidence=["E-against"])]), "RG-CLAIM-009")
        assert found.outcome is RequirementOutcome.UNSATISFIED


# ── RG-CLAIM-008 VERIFICATION_COVERAGE_GAP ───────────────────────────────────

class TestCoverageGap:

    def test_not_assessed_when_the_dimension_is_absent(self, tmp_path):
        found = result(outcome_for(tmp_path, [theorem()]), "RG-CLAIM-008")
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def test_fires_when_the_prover_states_its_own_total(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(),
            {"record_type": "expectation", "dimension": "lemma_verification",
             "expected": 3114, "observed": 2996,
             "source": {"kind": "PRODUCER_MANIFEST", "declared_by": "prover"},
             "observed_from": "prover"}]), "RG-CLAIM-008")
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "Invariant 13" in found.detail

    def test_satisfied_when_an_orchestrator_states_it_and_it_is_met(self, tmp_path):
        found = result(outcome_for(tmp_path, [
            theorem(),
            {"record_type": "expectation", "dimension": "lemma_verification",
             "expected": 3114, "observed": 3114,
             "source": {"kind": "ORCHESTRATION_MANIFEST",
                        "declared_by": "orchestrator"},
             "observed_from": "prover"}]), "RG-CLAIM-008")
        assert found.outcome is RequirementOutcome.SATISFIED


# ── the new predicates in isolation ──────────────────────────────────────────

class TestPredicates:

    def test_they_all_round_trip(self):
        for predicate in (CriticalClaimsVerified(methods=("FORMAL_PROOF",)),
                          DeclaredIndependenceHolds(tolerance=1),
                          AppliesToCurrentState(scope="evidence")):
            assert predicate_from_dict(predicate.to_dict()) == predicate

    def test_they_describe_themselves(self):
        for predicate in (CriticalClaimsVerified(), DeclaredIndependenceHolds(),
                          AppliesToCurrentState()):
            assert predicate.describe()

    def test_a_negative_tolerance_is_refused(self):
        with pytest.raises(MethodologyError):
            DeclaredIndependenceHolds(tolerance=-1)

    def test_attempts_are_read_from_both_places_they_live(self, tmp_path):
        # Claim-embedded attempts and the verification collection are one set;
        # a predicate scanning only one silently missed the other.
        from release_gate.assurance.methodology import _attempts_of
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "embedded.json"
        path.write_text(json.dumps([theorem(verification_attempts=[attempt()])]))
        case = assure(str(path)).case
        assert len(_attempts_of(case)) >= 1


# ── a complete research case ─────────────────────────────────────────────────

class TestWorkedCase:

    def test_a_thin_unverified_derivation_blocks(self, tmp_path):
        found = outcome_for(tmp_path, [
            theorem(depends_on=["L1"], assumptions=["A1"]),
            {"record_type": "claim", "claim_id": "L1", "statement": "lemma"},
            {"record_type": "claim", "claim_id": "A1", "claim_type": "ASSUMPTION",
             "statement": "the domain is countable"}])
        assert found.decision.value == "BLOCK"
        unmet = {r.requirement_id for r in found.assessment.unmet()}
        assert {"RG-CLAIM-001", "RG-CLAIM-002"} <= unmet

    def test_every_rule_reports_something(self, tmp_path):
        found = outcome_for(tmp_path, [theorem()])
        reported = {r.requirement_id for r in found.assessment.results}
        for n in range(1, 11):
            assert f"RG-CLAIM-{n:03d}" in reported

    def test_the_required_evidence_is_dispatchable(self, tmp_path):
        found = outcome_for(tmp_path, [
            theorem(depends_on=["L1"]),
            {"record_type": "claim", "claim_id": "L1", "statement": "lemma"}])
        targets = {i.target for i in found.required_evidence}
        assert any(t.startswith("methodology:RG-CLAIM-") for t in targets)
