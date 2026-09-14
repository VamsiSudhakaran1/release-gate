"""Replication analysis: whether a second answer could be wrong differently."""

from __future__ import annotations

import time

import pytest

from release_gate.assurance.contradiction import ContradictionKind, ContradictionStatus
from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind, VerificationMethod)
from release_gate.assurance.methodology import (
    MethodologyError, RequirementOutcome, ReplicationEstablished, predicate_from_dict)
from release_gate.assurance.records import MaterialisationBasis
from release_gate.assurance.replication import (
    CollapseReason, ReplicationAxis, ReplicationOutcome, ReplicationProfile,
    ReplicationRelation, ResultEquivalence, analyse_replication)
from release_gate.assurance.verification import (
    TargetKind, VerificationAttempt, VerificationStatus, VerificationTarget)

CLAIM = VerificationTarget.claim("C-main")
OTHER = VerificationTarget.claim("C-other")


def attempt(verifier="v", *, target=CLAIM, method=VerificationMethod.FORMAL_PROOF,
            status=VerificationStatus.PASSED, lineage=(), input_state=None,
            evidence=(), result=None, timestamp="2026-01-01T00:00:00Z"):
    return VerificationAttempt(
        method=method, target=target, verifier=verifier, status=status,
        independence_lineage=tuple(lineage), input_state=input_state,
        evidence=tuple(evidence), result=dict(result or {}), timestamp=timestamp)


def record(producer_id, parents=(), payload=None):
    return EvidenceRecord(
        evidence_type=EvidenceType.TOOL_RESULT, source="s",
        producer=Producer(kind=ProducerKind.AGENT, producer_id=producer_id),
        parent_evidence=tuple(parents), content=dict(payload or {"p": producer_id}),
        timestamp="2026-01-01T00:00:00Z")


def only(attempts, **kw):
    profile = analyse_replication(attempts, **kw)
    assert len(profile.targets) == 1
    return profile.targets[0]


# ── copies do not count ──────────────────────────────────────────────────────

class TestCopiesDoNotCount:

    def test_ten_thousand_agents_on_one_lineage_are_one_path(self):
        many = [attempt(f"agent-{i}", lineage=("upstream-api",), input_state=f"run-{i}")
                for i in range(10_000)]
        entry = only(many)
        assert entry.outcome is ReplicationOutcome.SINGLE_PATH
        assert entry.paths == 1
        assert entry.replications == 0
        assert entry.copies_collapsed == 9_999

    def test_the_collapse_says_why_it_happened(self):
        entry = only([attempt("a", lineage=("up",)), attempt("b", lineage=("up",))])
        assert entry.groups[0].collapse_reasons == (CollapseReason.SHARED_LINEAGE,)

    def test_identical_attempts_collapse_on_signature(self):
        one = attempt("a", lineage=("x",), input_state="s")
        two = attempt("a", lineage=("x",), input_state="s", timestamp="2026-06-06T00:00:00Z")
        entry = only([one, two])
        assert entry.paths == 1
        assert CollapseReason.IDENTICAL_SIGNATURE in entry.groups[0].collapse_reasons

    def test_a_lone_attempt_collapsed_nothing(self):
        entry = only([attempt("a", lineage=("x",))])
        assert entry.groups[0].collapse_reasons == ()
        assert entry.copies_collapsed == 0

    def test_shared_evidence_root_collapses_two_verifiers(self):
        root = record("upstream")
        left, right = record("a", [root.evidence_id]), record("b", [root.evidence_id])
        entry = only([attempt("lean", evidence=[left.evidence_id]),
                      attempt("coq", evidence=[right.evidence_id])],
                     records=[root, left, right])
        assert entry.paths == 1
        assert CollapseReason.SHARED_EVIDENCE_ROOT in entry.groups[0].collapse_reasons

    def test_separate_evidence_roots_are_separate_paths(self):
        root = record("upstream")
        left, elsewhere = record("a", [root.evidence_id]), record("c")
        entry = only([attempt("lean", evidence=[left.evidence_id]),
                      attempt("coq", evidence=[elsewhere.evidence_id])],
                     records=[root, left, elsewhere])
        assert entry.paths == 2
        assert entry.outcome is ReplicationOutcome.CONFIRMED

    def test_a_repeat_with_nothing_to_distinguish_it_is_not_a_second_path(self):
        # Same tool, same everything, nothing recorded about what changed.
        entry = only([attempt("runner"), attempt("runner")])
        assert entry.paths == 1
        assert entry.replications == 0

    def test_timestamp_alone_never_makes_a_second_path(self):
        hourly = [attempt("cron", lineage=("box-1",), timestamp=f"2026-01-01T{h:02d}:00:00Z")
                  for h in range(24)]
        assert only(hourly).paths == 1


# ── a declaration is not a path ──────────────────────────────────────────────

class TestDeclarationsEarnNothing:

    def test_the_independent_replication_label_earns_nothing(self):
        original = attempt("lean", lineage=("team-a",))
        labelled = attempt("agent-x", method=VerificationMethod.INDEPENDENT_REPLICATION,
                           lineage=("team-a",))
        entry = only([original, labelled])
        assert entry.outcome is ReplicationOutcome.SINGLE_PATH
        assert entry.replications == 0

    def test_the_label_is_credited_when_the_lineage_really_is_disjoint(self):
        entry = only([attempt("lean", lineage=("team-a",)),
                      attempt("agent-x", method=VerificationMethod.INDEPENDENT_REPLICATION,
                              lineage=("team-b",))])
        assert entry.outcome is ReplicationOutcome.CONFIRMED
        assert entry.replications == 1


# ── missing data never manufactures independence ─────────────────────────────

class TestUnrecordedIsNeverIndependent:

    def test_an_unrecorded_axis_is_undetermined_not_a_difference(self):
        entry = only([attempt("a", lineage=("x",)), attempt("b", lineage=("y",))])
        pair = entry.pairs[0]
        assert ReplicationAxis.INPUT in pair.axes_undetermined
        assert ReplicationAxis.INPUT not in pair.axes_differ

    def test_paths_with_no_lineage_are_not_independent(self):
        # Everything observable differs; only the lineage is unrecorded. That is
        # still not independence, and the basis has to say which axis is missing.
        entry = only([attempt("a", method=VerificationMethod.TEST_SUITE, input_state="s1"),
                      attempt("b", method=VerificationMethod.SIMULATION, input_state="s2")])
        assert entry.pairs[0].relation is ReplicationRelation.PARTIAL
        assert "independence lineage" in entry.pairs[0].basis

    def test_paths_that_record_nothing_are_counted_apart_not_credited(self):
        entry = only([attempt("a"), attempt("b")])
        assert entry.paths == 2
        assert entry.established_paths == 0
        assert entry.unattributed_paths == 2
        assert entry.outcome is ReplicationOutcome.UNDETERMINED
        assert entry.replications == 0

    def test_independence_needs_lineage_specifically(self):
        entry = only([attempt("a", method=VerificationMethod.TEST_SUITE, input_state="s1"),
                      attempt("b", method=VerificationMethod.SIMULATION, input_state="s2")])
        assert entry.pairs[0].relation is not ReplicationRelation.INDEPENDENT

    def test_everything_differing_including_lineage_is_independent(self):
        entry = only([attempt("lean", method=VerificationMethod.THEOREM_PROVER,
                              lineage=("a",), input_state="s1"),
                      attempt("coq", method=VerificationMethod.FORMAL_PROOF,
                              lineage=("b",), input_state="s2")])
        pair = entry.pairs[0]
        assert pair.relation is ReplicationRelation.INDEPENDENT
        assert pair.independent
        assert set(pair.axes_differ) == {ReplicationAxis.METHOD,
                                         ReplicationAxis.IMPLEMENTATION,
                                         ReplicationAxis.INPUT, ReplicationAxis.LINEAGE}

    def test_cited_evidence_supplies_the_producer_axis(self):
        left, right = record("lab-a"), record("lab-b")
        entry = only([attempt("t1", lineage=("a",), evidence=[left.evidence_id]),
                      attempt("t2", lineage=("b",), evidence=[right.evidence_id])],
                     records=[left, right])
        assert ReplicationAxis.PRODUCER in entry.pairs[0].axes_differ

    def test_producer_is_undetermined_when_records_are_absent(self):
        entry = only([attempt("t1", lineage=("a",)), attempt("t2", lineage=("b",))])
        assert ReplicationAxis.PRODUCER in entry.pairs[0].axes_undetermined

    def test_citing_evidence_makes_a_path_attributed(self):
        held = record("lab-a")
        entry = only([attempt("t1", evidence=[held.evidence_id]), attempt("t2")],
                     records=[held])
        attributed = [g for g in entry.groups if g.attributed]
        assert len(attributed) == 1


# ── disagreement is never outvoted ───────────────────────────────────────────

class TestDivergence:

    def test_nine_agreeing_and_one_divergent_is_not_ninety_percent(self):
        nine = [attempt(f"v{i}", lineage=(f"l{i}",)) for i in range(9)]
        odd = attempt("v9", lineage=("l9",), status=VerificationStatus.FAILED)
        entry = only(nine + [odd])
        assert entry.outcome is ReplicationOutcome.DIVERGENT
        assert entry.replications == 0
        assert entry.divergent_verdicts == ("FAILED", "PASSED")

    def test_divergence_becomes_an_open_contradiction(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", lineage=("y",),
                                               status=VerificationStatus.FAILED)])
        contradictions = profile.to_contradictions()
        assert len(contradictions) == 1
        found = contradictions[0]
        assert found.kind is ContradictionKind.VERIFICATION_CONFLICT
        assert found.status is ContradictionStatus.OPEN
        assert found.target_claims == ("C-main",)
        assert len(found.sides) == 2

    def test_divergence_on_a_critical_claim_is_marked_critical(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", lineage=("y",),
                                               status=VerificationStatus.FAILED)])
        found = profile.to_contradictions(critical_claims=["C-main"])[0]
        assert found.affects_critical

    def test_a_non_claim_target_produces_no_contradiction(self):
        target = VerificationTarget.artifact("build.tar")
        profile = analyse_replication([attempt("a", target=target, lineage=("x",)),
                                       attempt("b", target=target, lineage=("y",),
                                               status=VerificationStatus.FAILED)])
        assert profile.divergent
        assert profile.to_contradictions() == ()

    def test_failure_within_one_path_means_that_path_did_not_confirm(self):
        entry = only([attempt("a", lineage=("x",)),
                      attempt("a", lineage=("x",), status=VerificationStatus.FAILED)])
        assert entry.groups[0].verdict == "FAILED"

    def test_replicated_failure_is_replication(self):
        entry = only([attempt("a", lineage=("x",), status=VerificationStatus.FAILED),
                      attempt("b", lineage=("y",), status=VerificationStatus.FAILED)])
        assert entry.outcome is ReplicationOutcome.CONFIRMED
        assert entry.replications == 1


# ── outcomes ─────────────────────────────────────────────────────────────────

class TestOutcomes:

    def test_a_single_attempt_replicates_nothing(self):
        entry = only([attempt("a", lineage=("x",))])
        assert entry.outcome is ReplicationOutcome.SINGLE_PATH
        assert entry.replications == 0

    def test_two_established_paths_confirm(self):
        entry = only([attempt("a", lineage=("x",)), attempt("b", lineage=("y",))])
        assert entry.outcome is ReplicationOutcome.CONFIRMED
        assert entry.replications == 1

    def test_replication_counts_paths_beyond_the_first(self):
        entry = only([attempt(f"v{i}", lineage=(f"l{i}",)) for i in range(4)])
        assert entry.paths == 4
        assert entry.replications == 3

    def test_a_second_path_that_reached_no_verdict_is_not_achieved(self):
        entry = only([attempt("a", lineage=("x",)),
                      attempt("b", lineage=("y",),
                              status=VerificationStatus.INCONCLUSIVE)])
        assert entry.outcome is ReplicationOutcome.NOT_ACHIEVED
        assert entry.replications == 0
        assert len(entry.not_achieved) == 1

    def test_a_failed_reproduction_is_retained_not_dropped(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", lineage=("y",),
                                               status=VerificationStatus.INCONCLUSIVE)])
        assert profile.not_achieved
        assert profile.attempts_examined == 2

    def test_single_path_is_reported_without_penalty_language(self):
        entry = only([attempt("a", lineage=("up",)), attempt("b", lineage=("up",))])
        assert "normal" in entry.basis

    def test_targets_are_kept_apart(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", target=OTHER, lineage=("y",))])
        assert len(profile.targets) == 2
        assert {t.target.target_id for t in profile.targets} == {"C-main", "C-other"}

    def test_an_attempt_without_a_target_is_not_examined(self):
        loose = VerificationAttempt(method=VerificationMethod.FORMAL_PROOF,
                                    verifier="v", status=VerificationStatus.PASSED,
                                    timestamp="2026-01-01T00:00:00Z")
        profile = analyse_replication([loose])
        assert profile.targets == ()
        assert "could be reproduced or compared" in profile.basis


# ── result equivalence ───────────────────────────────────────────────────────

class TestResultEquivalence:

    def test_identical_payloads_are_identical(self):
        entry = only([attempt("a", lineage=("x",), result={"value": 42}),
                      attempt("b", lineage=("y",), result={"value": 42})])
        assert entry.equivalence is ResultEquivalence.IDENTICAL

    def test_different_payloads_with_no_basis_are_verdict_only(self):
        entry = only([attempt("a", lineage=("x",), result={"value": 3.14159}),
                      attempt("b", lineage=("y",), result={"value": 3.14160})])
        assert entry.outcome is ReplicationOutcome.CONFIRMED
        assert entry.equivalence is ResultEquivalence.VERDICT_ONLY

    def test_a_declared_tolerance_is_recorded_as_a_declaration(self):
        entry = only([attempt("a", lineage=("x",), result={"value": 3.14159}),
                      attempt("b", lineage=("y",),
                              result={"value": 3.14160, "tolerance": 1e-4,
                                      "equivalence_basis": "4 dp per SPEC-7"})])
        assert entry.equivalence is ResultEquivalence.TOLERANCE

    def test_a_declared_basis_without_tolerance_is_declared(self):
        entry = only([attempt("a", lineage=("x",), result={"value": "A"}),
                      attempt("b", lineage=("y",),
                              result={"value": "B", "equivalence_basis": "same modulo naming"})])
        assert entry.equivalence is ResultEquivalence.DECLARED

    def test_no_payload_at_all_is_undetermined(self):
        entry = only([attempt("a", lineage=("x",)), attempt("b", lineage=("y",))])
        assert entry.equivalence is ResultEquivalence.UNDETERMINED

    def test_equivalence_does_not_depend_on_which_member_sorts_first(self):
        # One path ran twice, recording an extra field the second time. The other
        # path matched the first run exactly.
        entry = only([attempt("a", lineage=("x",), result={"value": 42}),
                      attempt("a", lineage=("x",), result={"value": 42, "rerun": True}),
                      attempt("b", lineage=("y",), result={"value": 42})])
        assert entry.equivalence is ResultEquivalence.IDENTICAL

    def test_the_weakest_pair_decides_the_target(self):
        entry = only([attempt("a", lineage=("x",), result={"v": 1}),
                      attempt("b", lineage=("y",), result={"v": 1}),
                      attempt("c", lineage=("z",), result={"v": 2})])
        assert entry.equivalence is ResultEquivalence.VERDICT_ONLY


# ── the profile ──────────────────────────────────────────────────────────────

class TestProfile:

    def test_an_empty_profile_is_not_falsy(self):
        # `if profile:` must not silently discard "we looked and found nothing to
        # compare"; there is no __len__ to make that mistake possible.
        profile = analyse_replication([])
        assert not hasattr(ReplicationProfile, "__len__")
        assert profile is not None

    def test_serialisation_carries_the_record_protocol(self):
        profile = analyse_replication([attempt("a", lineage=("x",))])
        payload = profile.to_dict()
        assert payload["record_type"] == "replication"
        assert payload["record_id"] == profile.record_id
        assert payload["by_target"]

    def test_the_digest_is_stable_across_equal_profiles(self):
        attempts = [attempt("a", lineage=("x",)), attempt("b", lineage=("y",))]
        assert analyse_replication(attempts).digest() == \
            analyse_replication(list(reversed(attempts))).digest()

    def test_for_target_finds_an_entry(self):
        profile = analyse_replication([attempt("a", lineage=("x",))])
        assert profile.for_target(CLAIM) is not None
        assert profile.for_target(OTHER) is None

    def test_render_names_the_outcome(self):
        profile = analyse_replication([attempt("a", lineage=("x",))])
        assert "SINGLE_PATH" in profile.render()

    def test_render_flags_that_results_are_not_established_equal(self):
        entry = only([attempt("a", lineage=("x",), result={"v": 1}),
                      attempt("b", lineage=("y",), result={"v": 2})])
        assert "not established to have computed the same thing" in entry.render()

    def test_axes_established_reports_what_actually_differed(self):
        entry = only([attempt("lean", method=VerificationMethod.THEOREM_PROVER,
                              lineage=("a",)),
                      attempt("coq", lineage=("b",))])
        assert ReplicationAxis.IMPLEMENTATION in entry.axes_established()
        assert ReplicationAxis.INPUT not in entry.axes_established()

    def test_pairs_are_capped_and_the_cap_is_declared(self):
        wide = [attempt(f"v{i}", lineage=(f"l{i}",), input_state=f"s{i}")
                for i in range(60)]
        entry = only(wide)
        assert entry.paths == 60
        assert entry.pairs_basis is MaterialisationBasis.CAPPED
        assert len(entry.pairs) < 60 * 59 // 2

    def test_small_cases_report_complete_pairs(self):
        entry = only([attempt("a", lineage=("x",)), attempt("b", lineage=("y",))])
        assert entry.pairs_basis is MaterialisationBasis.COMPLETE


# ── scale ────────────────────────────────────────────────────────────────────

class TestScale:

    def test_ten_thousand_attempts_stay_linear(self):
        many = [attempt(f"a{i}", lineage=("up",), input_state=f"r{i}")
                for i in range(10_000)]
        started = time.time()
        entry = only(many)
        assert time.time() - started < 10
        assert entry.attempts_examined == 10_000
        assert entry.paths == 1

    def test_five_hundred_genuine_paths_do_not_explode(self):
        wide = [attempt(f"v{i}", lineage=(f"l{i}",), input_state=f"s{i}")
                for i in range(500)]
        started = time.time()
        entry = only(wide)
        assert time.time() - started < 10
        assert entry.paths == 500
        assert entry.replications == 499


# ── the methodology hook ─────────────────────────────────────────────────────

class TestReplicationEstablished:

    def case_with(self, profile):
        from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
        from release_gate.assurance.evidence import ContentReference, ReferenceKind
        from release_gate.assurance.subject import (
            AssuranceSubject, DigestMethod, DigestStatus, SubjectType)
        subject = AssuranceSubject(
            subject_type=SubjectType.RESEARCH_RESULT, requested_action="publish",
            content_reference=ContentReference(kind=ReferenceKind.INLINE, locator="x",
                                               detail={"inline": "x"}),
            digest="sha256:" + "a" * 64, digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED, digest_basis="test")
        builder = AssuranceCaseBuilder(
            case_type=CaseType.RESEARCH_RESULT, objective="o",
            requested_decision="d", subject=subject)
        builder.declare_present("evidence", "test")
        if profile is not None:
            builder.add("evidence", profile)
        return builder.build()

    def test_absence_of_a_profile_is_not_assessed(self):
        found = ReplicationEstablished().evaluate(self.case_with(None))
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def test_one_path_does_not_satisfy_a_requirement_for_two(self):
        profile = analyse_replication([attempt(f"a{i}", lineage=("up",))
                                       for i in range(50)])
        found = ReplicationEstablished(minimum_paths=2).evaluate(self.case_with(profile))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "Copies do not count" in found.detail

    def test_two_established_paths_satisfy_it(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", lineage=("y",))])
        found = ReplicationEstablished(minimum_paths=2).evaluate(self.case_with(profile))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_divergence_is_never_satisfied(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", lineage=("y",)),
                                       attempt("c", lineage=("z",),
                                               status=VerificationStatus.FAILED)])
        found = ReplicationEstablished(minimum_paths=2).evaluate(self.case_with(profile))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "disagree" in found.detail

    def test_the_weakest_target_decides(self):
        profile = analyse_replication([attempt("a", lineage=("x",)),
                                       attempt("b", lineage=("y",)),
                                       attempt("c", target=OTHER, lineage=("z",))])
        found = ReplicationEstablished(minimum_paths=2).evaluate(self.case_with(profile))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert found.observed["target"] == "C-other"

    def test_a_required_axis_that_never_differs_is_unsatisfied(self):
        profile = analyse_replication([attempt("runner", lineage=("x",)),
                                       attempt("runner", lineage=("y",))])
        found = ReplicationEstablished(
            minimum_paths=2, required_axes=("IMPLEMENTATION",)).evaluate(
                self.case_with(profile))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "not shown to differ" in found.detail

    def test_a_required_axis_that_does_differ_is_satisfied(self):
        profile = analyse_replication([attempt("lean", lineage=("x",)),
                                       attempt("coq", lineage=("y",))])
        found = ReplicationEstablished(
            minimum_paths=2, required_axes=("IMPLEMENTATION",)).evaluate(
                self.case_with(profile))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_verdict_only_agreement_fails_a_result_equivalence_requirement(self):
        profile = analyse_replication([attempt("a", lineage=("x",), result={"v": 1}),
                                       attempt("b", lineage=("y",), result={"v": 2})])
        found = ReplicationEstablished(
            minimum_paths=2, require_result_equivalence=True).evaluate(
                self.case_with(profile))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "VERDICT_ONLY" in found.detail

    def test_identical_results_satisfy_a_result_equivalence_requirement(self):
        profile = analyse_replication([attempt("a", lineage=("x",), result={"v": 1}),
                                       attempt("b", lineage=("y",), result={"v": 1})])
        found = ReplicationEstablished(
            minimum_paths=2, require_result_equivalence=True).evaluate(
                self.case_with(profile))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_a_requirement_for_zero_paths_is_refused(self):
        with pytest.raises(MethodologyError):
            ReplicationEstablished(minimum_paths=0)

    def test_the_predicate_round_trips(self):
        predicate = ReplicationEstablished(minimum_paths=3,
                                           required_axes=("method", "lineage"),
                                           require_result_equivalence=True)
        assert predicate_from_dict(predicate.to_dict()) == predicate

    def test_required_axes_are_normalised(self):
        assert ReplicationEstablished(required_axes=("method",)).required_axes == ("METHOD",)


# ── the analysers and the zero-config path ───────────────────────────────────

class TestAnalysisWiring:

    def analyse_attempts(self, attempts, records=(), critical=()):
        from release_gate.assurance.analysis import _analyse_replication
        return _analyse_replication(analyse_replication(attempts, records=records),
                                    set(critical))

    def test_divergence_on_a_critical_claim_blocks(self):
        from release_gate.assurance.methodology import RequirementEffect
        findings = self.analyse_attempts(
            [attempt("a", lineage=("x",)),
             attempt("b", lineage=("y",), status=VerificationStatus.FAILED)],
            critical=["C-main"])
        blocking = [f for f in findings if f.effect is RequirementEffect.BLOCK]
        assert [f.rule_id for f in blocking] == ["RG-REPL-001"]

    def test_divergence_elsewhere_holds(self):
        from release_gate.assurance.methodology import RequirementEffect
        findings = self.analyse_attempts(
            [attempt("a", lineage=("x",)),
             attempt("b", lineage=("y",), status=VerificationStatus.FAILED)])
        holding = [f for f in findings if f.effect is RequirementEffect.HOLD]
        assert [f.rule_id for f in holding] == ["RG-REPL-002"]

    def test_an_echo_is_advisory_never_blocking(self):
        from release_gate.assurance.methodology import RequirementEffect
        findings = self.analyse_attempts(
            [attempt(f"a{i}", lineage=("up",)) for i in range(20)])
        echo = [f for f in findings if f.rule_id == "RG-REPL-003"]
        assert echo and echo[0].effect is RequirementEffect.ADVISORY
        assert "not penalised" in echo[0].detail

    def test_a_lone_attempt_raises_no_echo_finding(self):
        findings = self.analyse_attempts([attempt("a", lineage=("x",))])
        assert not [f for f in findings if f.rule_id == "RG-REPL-003"]

    def test_verdict_only_agreement_is_reported(self):
        findings = self.analyse_attempts([attempt("a", lineage=("x",), result={"v": 1}),
                                          attempt("b", lineage=("y",), result={"v": 2})])
        assert [f for f in findings if f.rule_id == "RG-REPL-005"]

    def test_unattributed_paths_are_reported(self):
        findings = self.analyse_attempts([attempt("a"), attempt("b")])
        assert [f for f in findings if f.rule_id == "RG-REPL-006"]

    def test_no_profile_produces_no_findings(self):
        from release_gate.assurance.analysis import _analyse_replication
        assert _analyse_replication(None, set()) == []


class TestZeroConfig:

    def write(self, tmp_path, payload):
        import json
        path = tmp_path / "report.json"
        path.write_text(json.dumps(payload))
        return str(path)

    def report(self, results):
        return {"verifier": {"name": "lean", "version": "4.8.0",
                             "family": "PROOF_ASSISTANT"},
                "results": results}

    def test_a_verifier_report_produces_a_replication_profile(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = self.write(tmp_path, self.report([
            {"target": "C-main", "result": "proved", "independence_lineage": ["oslo"],
             "input_state": "dataset-A", "result_detail": {"value": 42}},
            {"target": "C-main", "result": "proved", "independence_lineage": ["kyoto"],
             "input_state": "dataset-B", "result_detail": {"value": 42}},
        ]))
        outcome = assure(path)
        entry = outcome.replication.for_target(VerificationTarget.claim("C-main"))
        assert entry is not None
        assert entry.outcome is ReplicationOutcome.CONFIRMED
        assert entry.replications == 1
        assert entry.equivalence is ResultEquivalence.IDENTICAL

    def test_reruns_on_one_lineage_collapse_end_to_end(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = self.write(tmp_path, self.report([
            {"target": "C-main", "result": "proved", "independence_lineage": ["oslo"],
             "input_state": "dataset-A", "result_detail": {"value": 42}},
            {"target": "C-main", "result": "proved", "independence_lineage": ["oslo"],
             "input_state": "dataset-A", "result_detail": {"value": 42, "run": 2}},
        ]))
        entry = assure(path).replication.targets[0]
        assert entry.paths == 1
        assert entry.outcome is ReplicationOutcome.SINGLE_PATH

    def test_the_profile_is_stored_on_the_case(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = self.write(tmp_path, self.report([
            {"target": "C-main", "result": "proved", "independence_lineage": ["oslo"]},
        ]))
        case = assure(path).case
        stored = [r.to_dict() for r in case.records("evidence")
                  if r.to_dict().get("record_type") == "replication"]
        assert len(stored) == 1

    def test_coverage_reports_replication(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = self.write(tmp_path, self.report([
            {"target": "C-main", "result": "proved", "independence_lineage": ["oslo"]},
        ]))
        rows = [r.to_dict() for r in assure(path).case.records("coverage")]
        row = next(r for r in rows if r.get("dimension") == "replication")
        assert "single path" in row["note"]

    def test_an_input_with_no_verification_still_reports_the_dimension(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = self.write(tmp_path, {"spans": []})
        rows = [r.to_dict() for r in assure(path).case.records("coverage")]
        assert any(r.get("dimension") == "replication" for r in rows)

    def test_zero_config_still_never_promotes(self, tmp_path):
        from release_gate.assurance.case import Decision
        from release_gate.assurance.zero_config import assure
        path = self.write(tmp_path, self.report([
            {"target": "C-main", "result": "proved", "independence_lineage": ["oslo"]},
            {"target": "C-main", "result": "proved", "independence_lineage": ["kyoto"]},
        ]))
        assert assure(path).decision is not Decision.PROMOTE
