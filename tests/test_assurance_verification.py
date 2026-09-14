"""Verification as a graph, not a boolean.

The test plan is the prompt's example and the rule under it: a verification binds
to an exact target state, and when the target moves the verification does not move
with it. Several tests below do nothing but try to get a superseded attempt to
count as current.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
from release_gate.assurance.claims import AttemptOutcome, Claim, ClaimGraph, ClaimStatus
from release_gate.assurance.evidence import (
    Producer, TrustStatus, VerificationMethod,
)
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.subject import (
    AssuranceSubject, ContentReference, DigestMethod, DigestStatus, ReferenceKind,
    SubjectType,
)
from release_gate.assurance.verification import (
    Applicability,
    TargetKind,
    VerificationAttempt,
    VerificationEdgeType,
    VerificationError,
    VerificationGraph,
    VerificationStatus,
    VerificationTarget,
)
from release_gate.assurance.zero_config import assure, render_text

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TARGET = VerificationTarget.claim("C-12")


def attempt(method, status, *, verifier="v://1", digest=DIGEST_A, lineage=(),
            target=TARGET, **kwargs):
    return VerificationAttempt(method=method, target=target, verifier=verifier,
                               target_digest=digest, status=status,
                               independence_lineage=tuple(lineage), **kwargs)


def graph(*attempts, digest=DIGEST_A, target=TARGET):
    return VerificationGraph(attempts, digests={target.key: digest})


# ── the exact target state ───────────────────────────────────────────────────

class TestVerificationBindsToState:

    def test_an_attempt_applies_to_the_digest_it_ran_against(self):
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED)
        assert a.applicability(DIGEST_A) is Applicability.APPLIES

    def test_a_moved_target_supersedes_the_attempt(self):
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED)
        assert a.applicability(DIGEST_B) is Applicability.SUPERSEDED

    def test_a_superseded_pass_does_not_verify_the_target(self):
        """A proof of an earlier state is not a proof of this one."""
        g = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED),
                  digest=DIGEST_B)
        assessment = g.assess(TARGET)
        assert assessment.verified is False
        assert assessment.status is VerificationStatus.UNKNOWN
        assert assessment.superseded == 1
        assert "no longer apply" in assessment.basis

    def test_a_missing_digest_is_undetermined_not_applicable(self):
        a = attempt(VerificationMethod.TEST_SUITE, VerificationStatus.PASSED,
                    digest=None)
        assert a.applicability(DIGEST_A) is Applicability.UNDETERMINED

    def test_an_undetermined_attempt_never_verifies(self):
        """'Cannot tell whether this still holds' must not read as 'it holds'."""
        g = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                          digest=None))
        assessment = g.assess(TARGET)
        assert assessment.verified is False
        assert assessment.undetermined == 1
        assert assessment.applies == 0

    def test_no_current_digest_is_also_undetermined(self):
        g = VerificationGraph([attempt(VerificationMethod.FORMAL_PROOF,
                                       VerificationStatus.PASSED)])
        assert g.assess(TARGET).undetermined == 1

    def test_re_running_against_new_content_is_a_different_attempt(self):
        first = attempt(VerificationMethod.TEST_SUITE, VerificationStatus.PASSED,
                        digest=DIGEST_A)
        second = attempt(VerificationMethod.TEST_SUITE, VerificationStatus.PASSED,
                         digest=DIGEST_B)
        assert first.verification_id != second.verification_id

    def test_identical_attempts_share_an_id(self):
        kwargs = dict(method=VerificationMethod.TEST_SUITE, target=TARGET,
                      verifier="v://1", target_digest=DIGEST_A,
                      status=VerificationStatus.PASSED, timestamp="2026-01-01T00:00:00Z")
        assert (VerificationAttempt(**kwargs).verification_id
                == VerificationAttempt(**kwargs).verification_id)


# ── the six statuses ─────────────────────────────────────────────────────────

class TestStatuses:

    def test_all_six_exist(self):
        assert {s.value for s in VerificationStatus} == {
            "PASSED", "FAILED", "INCONCLUSIVE", "NOT_RUN", "INVALIDATED", "UNKNOWN"}

    def test_a_challenge_is_not_cancelled_by_a_pass(self):
        g = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED),
                  attempt(VerificationMethod.PROPERTY_TEST, VerificationStatus.FAILED,
                          verifier="v://2"))
        assessment = g.assess(TARGET)
        assert assessment.status is VerificationStatus.FAILED
        assert assessment.verified is False

    def test_an_invalidated_pass_is_not_a_pass(self):
        g = graph(attempt(VerificationMethod.FORMAL_PROOF,
                          VerificationStatus.INVALIDATED))
        assessment = g.assess(TARGET)
        assert assessment.verified is False
        assert assessment.status is VerificationStatus.UNKNOWN

    def test_invalidated_is_not_failed(self):
        """One means the check was withdrawn; the other that the claim did not hold."""
        g = graph(attempt(VerificationMethod.FORMAL_PROOF,
                          VerificationStatus.INVALIDATED))
        assert g.assess(TARGET).status is not VerificationStatus.FAILED
        assert len(g.invalidated()) == 1

    def test_not_run_is_recorded_as_a_fact(self):
        a = VerificationAttempt.not_run(VerificationMethod.INDEPENDENT_REPLICATION,
                                        target=TARGET, reason="no second lab available")
        g = VerificationGraph([a])
        assert g.not_run() == (a,)
        assert a.status is VerificationStatus.NOT_RUN

    def test_a_not_run_attempt_cannot_cite_evidence(self):
        with pytest.raises(VerificationError, match="nothing ran"):
            VerificationAttempt(method=VerificationMethod.TEST_SUITE, target=TARGET,
                                status=VerificationStatus.NOT_RUN,
                                evidence=("ev_1",))

    def test_inconclusive_alone_is_inconclusive_not_verified(self):
        g = graph(attempt(VerificationMethod.SIMULATION,
                          VerificationStatus.INCONCLUSIVE))
        assessment = g.assess(TARGET)
        assert assessment.status is VerificationStatus.INCONCLUSIVE
        assert assessment.verified is False

    def test_no_attempts_is_unknown_not_passed(self):
        assert VerificationGraph().assess(TARGET).status is VerificationStatus.UNKNOWN

    def test_an_attempt_that_ran_must_name_its_verifier(self):
        with pytest.raises(VerificationError, match="answerable"):
            VerificationAttempt(method=VerificationMethod.TEST_SUITE, target=TARGET,
                                status=VerificationStatus.PASSED)


# ── the graph shape ──────────────────────────────────────────────────────────

class TestGraphShape:

    def test_the_prompts_example_renders(self):
        g = graph(
            attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    verifier="lean://1"),
            attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                    verifier="sim://8"),
            attempt(VerificationMethod.PROPERTY_TEST, VerificationStatus.FAILED,
                    verifier="fuzz://2"),
            attempt(VerificationMethod.HUMAN_REVIEW, VerificationStatus.PASSED,
                    verifier="agent://818"))
        rendered = g.render(TARGET)
        assert "CLAIM C-12" in rendered
        for relationship in ("verified_by", "tested_by", "challenged_by", "reviewed_by"):
            assert relationship in rendered

    def test_method_decides_the_relationship(self):
        assert attempt(VerificationMethod.FORMAL_PROOF,
                       VerificationStatus.PASSED).relationship \
            is VerificationEdgeType.VERIFIED_BY
        assert attempt(VerificationMethod.SIMULATION,
                       VerificationStatus.PASSED).relationship \
            is VerificationEdgeType.TESTED_BY
        assert attempt(VerificationMethod.HUMAN_REVIEW,
                       VerificationStatus.PASSED).relationship \
            is VerificationEdgeType.REVIEWED_BY

    def test_a_failure_challenges_whatever_produced_it(self):
        """A failed proof argues against the claim; it does not verify it."""
        assert attempt(VerificationMethod.FORMAL_PROOF,
                       VerificationStatus.FAILED).relationship \
            is VerificationEdgeType.CHALLENGED_BY

    def test_an_explicit_edge_type_wins(self):
        a = attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                    edge_type=VerificationEdgeType.CHALLENGED_BY)
        assert a.relationship is VerificationEdgeType.CHALLENGED_BY

    def test_edges_are_derived_from_attempts(self):
        g = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED))
        assert len(g.edges) == 1
        assert g.edges[0].edge_type is VerificationEdgeType.VERIFIED_BY

    def test_challenges_are_retrievable(self):
        g = graph(attempt(VerificationMethod.PROPERTY_TEST, VerificationStatus.FAILED))
        assert len(g.challenges(TARGET)) == 1

    def test_targets_are_listed_once(self):
        g = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED),
                  attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                          verifier="v://2"))
        assert len(g.targets()) == 1


# ── independence lineage ─────────────────────────────────────────────────────

class TestIndependence:

    def test_shared_lineage_is_one_confirmation_not_two(self):
        g = graph(
            attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    verifier="a", lineage=("org://acme", "ci://lean")),
            attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                    verifier="b", lineage=("org://acme", "ci://sim")))
        assessment = g.assess(TARGET)
        assert assessment.independent_confirmations == 1
        assert assessment.corroborated is False

    def test_disjoint_lineages_corroborate(self):
        g = graph(
            attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    verifier="a", lineage=("org://acme",)),
            attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                    verifier="b", lineage=("org://other",)))
        assessment = g.assess(TARGET)
        assert assessment.independent_confirmations == 2
        assert assessment.corroborated is True

    def test_an_unrecorded_lineage_is_not_credited(self):
        """Provenance nobody recorded is not independence."""
        g = graph(
            attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    verifier="a", lineage=("org://acme",)),
            attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                    verifier="b"))
        assessment = g.assess(TARGET)
        assert assessment.independent_confirmations == 1
        assert assessment.unattributed_confirmations == 1
        assert assessment.corroborated is False

    def test_independence_of_an_unrecorded_pair_is_unknown_not_true(self):
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED)
        b = attempt(VerificationMethod.SIMULATION, VerificationStatus.PASSED,
                    verifier="b")
        assert a.independent_of(b) is None

    def test_a_failed_attempt_does_not_count_as_a_confirmation(self):
        """Only passes corroborate; a disjoint failure does not make it two."""
        g = graph(
            attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    verifier="a", lineage=("org://a",)),
            attempt(VerificationMethod.PROPERTY_TEST, VerificationStatus.FAILED,
                    verifier="b", lineage=("org://b",)))
        assessment = g.assess(TARGET)
        assert assessment.independent_confirmations == 1
        assert assessment.corroborated is False, "a challenged target is not corroborated"


# ── the twelve fields ────────────────────────────────────────────────────────

class TestAttemptRecord:

    def test_every_named_field_is_present(self):
        payload = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                          lineage=("org://a",), input_state="sha256:" + "c" * 64,
                          result={"goals_closed": 3}).to_dict()
        for name in ("verification_id", "verifier", "method", "target",
                     "target_digest", "input_state", "result", "evidence",
                     "timestamp", "independence_lineage", "trust_status", "status"):
            assert name in payload, name

    def test_the_id_is_derived_not_supplied(self):
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED)
        assert a.verification_id.startswith("ver_")
        with pytest.raises(TypeError):
            VerificationAttempt(method=VerificationMethod.TEST_SUITE,
                                verification_id="mine")

    def test_trust_status_defaults_to_not_established(self):
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED)
        assert a.trust_status is TrustStatus.NOT_ESTABLISHED

    def test_it_round_trips(self):
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    lineage=("org://a",), result={"n": 1})
        restored = VerificationAttempt.from_dict(json.loads(json.dumps(a.to_dict())))
        assert restored.verification_id == a.verification_id

    def test_the_graph_digest_is_stable(self):
        g1 = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED))
        g2 = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED))
        assert g1.digest() == g2.digest()

    def test_the_graph_serialises(self):
        g = graph(attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED))
        payload = json.loads(json.dumps(g.to_dict()))
        assert payload["attempts"] == 1
        assert payload["by_relationship"]["VERIFIED_BY"] == 1


# ── the generalisation ───────────────────────────────────────────────────────

class TestOneAttemptType:
    """claims.VerificationAttempt was a narrower version of this one, not a peer."""

    def test_the_claims_module_uses_the_same_class(self):
        from release_gate.assurance import claims

        assert claims.VerificationAttempt is VerificationAttempt

    def test_attempt_outcome_is_the_old_name_for_the_status(self):
        assert AttemptOutcome is VerificationStatus
        assert AttemptOutcome.PASSED is VerificationStatus.PASSED

    def test_the_old_vocabulary_could_not_express_these(self):
        assert AttemptOutcome.NOT_RUN is VerificationStatus.NOT_RUN
        assert AttemptOutcome.INVALIDATED is VerificationStatus.INVALIDATED

    def test_claim_status_still_folds_attempts(self):
        claim = Claim(claim_id="cl_1", statement="p",
                      producer=Producer(producer_id="agent://x"),
                      verification_attempts=(
                          attempt(VerificationMethod.TEST_SUITE,
                                  VerificationStatus.FAILED, target=None),))
        assert ClaimGraph([claim]).status("cl_1") is ClaimStatus.REFUTED

    def test_claim_attempts_lift_into_the_graph(self):
        claim = Claim(claim_id="cl_1", statement="p",
                      producer=Producer(producer_id="agent://x"),
                      verification_attempts=(
                          attempt(VerificationMethod.TEST_SUITE,
                                  VerificationStatus.PASSED, target=None),))
        g = VerificationGraph.from_claims([claim])
        assert g.targets()[0].target_id == "cl_1"
        assert g.targets()[0].kind is TargetKind.CLAIM


# ── the case and the pipeline ────────────────────────────────────────────────

class TestCaseIntegration:

    def _case(self, *attempts, claims=()):
        reference = ContentReference(kind=ReferenceKind.INLINE, locator="x",
                                     detail={"inline": "x"})
        subject = AssuranceSubject(
            subject_type=SubjectType.GENERAL_RESULT, requested_action="ship",
            content_reference=reference, digest=DIGEST_A,
            digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED, digest_basis="test")
        builder = AssuranceCaseBuilder(
            case_type=CaseType.GENERAL_DECISION, objective="o",
            requested_decision="d", subject=subject)
        builder.declare_present("verification", "test")
        builder.extend("verification", attempts)
        builder.declare_present("claims", "test")
        builder.extend("claims", claims)
        return builder.build()

    def test_from_case_reads_both_places_attempts_live(self):
        standalone = attempt(VerificationMethod.FORMAL_PROOF,
                             VerificationStatus.PASSED)
        claim = Claim(claim_id="cl_1", statement="p",
                      producer=Producer(producer_id="agent://x"),
                      verification_attempts=(
                          attempt(VerificationMethod.SIMULATION,
                                  VerificationStatus.PASSED, target=None,
                                  verifier="sim://1"),))
        g = VerificationGraph.from_case(self._case(standalone, claims=(claim,)))
        assert len(g.attempts) == 2
        assert {t.kind for t in g.targets()} == {TargetKind.CLAIM}

    def test_the_subject_digest_makes_subject_verification_checkable(self):
        target = VerificationTarget(kind=TargetKind.SUBJECT, target_id="ignored")
        case = self._case(attempt(VerificationMethod.FORMAL_PROOF,
                                  VerificationStatus.PASSED, target=target))
        g = VerificationGraph.from_case(case)
        subject_target = VerificationTarget(kind=TargetKind.SUBJECT,
                                            target_id=case.subject.subject_id)
        assert g.current_digest(subject_target) == DIGEST_A

    def test_a_case_refuses_to_hold_the_same_attempt_twice(self):
        """Stronger than deduping on read: the id is derived, so a repeat is
        caught where it enters rather than counted and quietly folded later."""
        from release_gate.assurance.records import RecordError

        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED)
        with pytest.raises(RecordError, match="duplicate record_id"):
            self._case(a, a)

    def test_an_attempt_reaching_the_graph_twice_is_folded_once(self):
        """The same attempt can arrive standalone and embedded on a claim."""
        a = attempt(VerificationMethod.FORMAL_PROOF, VerificationStatus.PASSED,
                    target=VerificationTarget.claim("cl_1"))
        claim = Claim(claim_id="cl_1", statement="p",
                      producer=Producer(producer_id="agent://x"),
                      verification_attempts=(a,))
        g = VerificationGraph.from_case(self._case(a, claims=(claim,)))
        assert len(g.attempts) == 1


class TestFindings:

    def _assure(self, tmp_path, rows):
        path = tmp_path / "e.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return assure(str(path))

    def test_an_attempt_with_no_target_state_is_advisory(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "TEST_SUITE", "outcome": "PASSED",
                  "verifier": "ci://1"}]}])
        finding = next(f for f in outcome.analysis.findings
                       if f.rule_id == "RG-VERIF-005")
        assert finding.effect is RequirementEffect.ADVISORY
        assert finding.domain is AnalysisDomain.VERIFICATION

    def test_an_invalidated_attempt_holds(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "TEST_SUITE", "status": "INVALIDATED",
                  "verifier": "ci://1"}]}])
        assert next(f for f in outcome.analysis.findings
                    if f.rule_id == "RG-VERIF-006").effect is RequirementEffect.HOLD

    def test_an_unrun_attempt_is_advisory(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "INDEPENDENT_REPLICATION", "status": "NOT_RUN",
                  "detail": "no second lab"}]}])
        assert next(f for f in outcome.analysis.findings
                    if f.rule_id == "RG-VERIF-007").effect is RequirementEffect.ADVISORY

    def test_the_envelope_can_carry_the_full_attempt(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "FORMAL_PROOF", "status": "PASSED", "verifier": "lean://1",
                  "target_digest": DIGEST_A, "input_state": DIGEST_B,
                  "independence_lineage": ["org://acme"]}]}])
        held = outcome.verification.attempts[0]
        assert held.target_digest == DIGEST_A
        assert held.input_state == DIGEST_B
        assert held.independence_lineage == ("org://acme",)

    def test_a_target_digest_is_never_filled_in_from_the_current_state(self, tmp_path):
        """Doing so would assert a currency the check never established."""
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "TEST_SUITE", "status": "PASSED", "verifier": "ci://1"}]}])
        assert outcome.verification.attempts[0].target_digest is None

    def test_verification_coverage_is_stated(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "TEST_SUITE", "status": "PASSED", "verifier": "ci://1"}]}])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "verification_currency")
        assert row["status"] == "NOT_ASSESSED"
        assert row["undetermined"] == 1

    def test_the_report_renders_the_tree(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "FORMAL_PROOF", "status": "PASSED", "verifier": "lean://1"}]}])
        text = render_text(outcome)
        assert "VERIFICATION" in text
        assert "verified_by" in text

    def test_the_outcome_serialises(self, tmp_path):
        outcome = self._assure(tmp_path, [
            {"record_type": "claim", "claim_id": "cl_1", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"method": "TEST_SUITE", "status": "PASSED", "verifier": "ci://1"}]}])
        payload = json.loads(json.dumps(outcome.to_dict()))
        assert payload["verification"]["attempts"] == 1
