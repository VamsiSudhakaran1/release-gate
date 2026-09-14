"""Evidence expectation: a percentage needs a denominator, and a denominator a source."""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain, _analyse_expectation
from release_gate.assurance.expectation import (
    CoverageLedger, CoverageState, EvidenceExpectation, ExpectationError,
    ExpectationSource, ExpectationSourceKind, ExpectationStanding)
from release_gate.assurance.methodology import (
    ExpectationDeclared, MethodologyError, RequirementEffect, RequirementOutcome,
    predicate_from_dict)


def source(kind=ExpectationSourceKind.ORCHESTRATION_MANIFEST, by="orchestrator",
           authenticated=False):
    return ExpectationSource(kind=kind, declared_by=by, authenticated=authenticated)


def expectation(**kw):
    kw.setdefault("dimension", "verifier_results")
    kw.setdefault("observed_from", "agent-fleet")
    if kw.get("expected") is not None or kw.get("expected_ids"):
        kw.setdefault("source", source())
    return EvidenceExpectation(**kw)


# ── the two worked examples ──────────────────────────────────────────────────

class TestTheWorkedExamples:

    def test_expected_ten_observed_nine_is_ninety_percent_known_missing_one(self):
        row = expectation(expected=10, observed=9)
        assert row.state is CoverageState.KNOWN_MISSING
        assert row.expected == 10
        assert row.observed == 9
        assert row.known_missing == 1
        assert row.coverage == 0.9

    def test_observed_nine_with_no_expectation_is_unknown_not_a_percentage(self):
        row = expectation(observed=9)
        assert row.state is CoverageState.UNKNOWN
        assert row.expected is None
        assert row.observed == 9
        assert row.coverage is None
        assert "expected total UNKNOWN" in row.basis

    def test_unknown_coverage_serialises_as_null_never_zero(self):
        payload = expectation(observed=9).to_dict()
        assert payload["coverage"] is None
        assert json.dumps(payload["coverage"]) == "null"
        assert payload["expected"] is None


# ── the five states are kept apart ───────────────────────────────────────────

class TestTheFiveStates:

    def test_not_assessed_is_not_unknown(self):
        assert expectation(assessed=False).state is CoverageState.NOT_ASSESSED
        assert expectation(observed=9).state is CoverageState.UNKNOWN

    def test_not_assessed_never_renders_as_unknown_coverage(self):
        rendered = expectation(dimension="drift", assessed=False).render()
        assert "NOT_ASSESSED" in rendered
        assert "coverage UNKNOWN" not in rendered

    def test_an_expectation_with_nothing_arrived_is_expected(self):
        row = expectation(expected=10, observed=0)
        assert row.state is CoverageState.EXPECTED
        assert row.known_missing == 10

    def test_everything_arriving_is_observed(self):
        assert expectation(expected=10, observed=10).state is CoverageState.OBSERVED

    def test_a_zero_expectation_met_is_observed(self):
        assert expectation(expected=0, observed=0).state is CoverageState.OBSERVED

    def test_every_state_is_reachable(self):
        seen = {expectation(assessed=False).state,
                expectation(observed=9).state,
                expectation(expected=10, observed=0).state,
                expectation(expected=10, observed=9).state,
                expectation(expected=10, observed=10).state}
        assert seen == set(CoverageState)


# ── never calculate false completeness ───────────────────────────────────────

class TestNoFalseCompleteness:

    def test_an_over_count_is_unknown_not_clamped_to_complete(self):
        row = expectation(expected=10, observed=11)
        assert row.over_count
        assert row.state is CoverageState.UNKNOWN
        assert row.coverage is None
        assert row.known_missing is None

    def test_the_over_count_basis_explains_why_no_ratio_exists(self):
        assert "cannot be computed" in expectation(expected=10, observed=11).basis

    def test_an_expectation_never_bounds_completeness(self):
        row = expectation(expected=10, observed=10)
        assert row.bounds_completeness is False
        assert row.to_dict()["bounds_completeness"] is False

    def test_the_ledger_never_bounds_completeness(self):
        assert CoverageLedger().bounds_completeness is False

    def test_no_overall_percentage_is_ever_offered(self):
        ledger = CoverageLedger((expectation(expected=10, observed=10),
                                 expectation(dimension="other", observed=5)))
        assert ledger.overall_coverage is None
        assert ledger.summary()["overall_coverage"] is None

    def test_the_ledger_render_says_why_there_is_no_overall_number(self):
        ledger = CoverageLedger((expectation(expected=10, observed=10),
                                 expectation(dimension="other", observed=5)))
        assert "no overall percentage is offered" in ledger.render()

    def test_a_denominator_from_nowhere_is_refused(self):
        with pytest.raises(ExpectationError) as exc:
            EvidenceExpectation(dimension="d", expected=10, observed=9)
        assert "false completeness" in str(exc.value)

    def test_a_source_must_name_who_declared_it(self):
        with pytest.raises(ExpectationError):
            ExpectationSource(kind=ExpectationSourceKind.CI_PLAN, declared_by="  ")


# ── who is counting ──────────────────────────────────────────────────────────

class TestStanding:

    def test_an_independent_source_is_established(self):
        assert expectation(expected=10, observed=10).standing \
            is ExpectationStanding.ESTABLISHED

    def test_the_producer_counting_itself_is_self_reported(self):
        row = expectation(expected=10, observed=10,
                          source=source(by="agent-fleet"), observed_from="agent-fleet")
        assert row.standing is ExpectationStanding.SELF_REPORTED
        assert row.self_certified

    def test_no_source_is_not_established(self):
        assert expectation(observed=9).standing is ExpectationStanding.NOT_ESTABLISHED

    def test_a_self_report_still_reports_its_ratio(self):
        row = expectation(expected=10, observed=10,
                          source=source(by="agent-fleet"), observed_from="agent-fleet")
        assert row.coverage == 1.0
        assert row.state is CoverageState.OBSERVED

    def test_but_a_self_report_never_matches_expectation(self):
        row = expectation(expected=10, observed=10,
                          source=source(by="agent-fleet"), observed_from="agent-fleet")
        assert not row.matches_expectation

    def test_signing_does_not_make_a_self_report_independent(self):
        row = expectation(expected=10, observed=10,
                          source=source(by="agent-fleet", authenticated=True),
                          observed_from="agent-fleet")
        assert row.self_certified
        assert "not evidence that the number is right" in row.source.identity_basis

    def test_an_established_full_expectation_matches(self):
        assert expectation(expected=10, observed=10).matches_expectation

    def test_the_basis_says_a_self_report_cannot_detect_omission(self):
        row = expectation(expected=10, observed=10,
                          source=source(by="agent-fleet"), observed_from="agent-fleet")
        assert "cannot detect an omission" in row.basis


# ── enumeration beats a count ────────────────────────────────────────────────

class TestEnumeratedExpectations:

    def test_an_enumeration_names_which_record_is_missing(self):
        row = expectation(dimension="experiment_matrix",
                          expected_ids=("run-1", "run-2", "run-3", "run-4"),
                          observed_ids=("run-1", "run-2", "run-4"))
        assert row.known_missing_ids == ("run-3",)
        assert row.known_missing == 1
        assert row.coverage == 0.75

    def test_an_enumeration_separates_the_unplanned_from_the_missing(self):
        row = expectation(dimension="experiment_matrix",
                          expected_ids=("run-1", "run-2", "run-3"),
                          observed_ids=("run-1", "run-2", "run-X"))
        assert row.known_missing_ids == ("run-3",)
        assert row.unexpected_ids == ("run-X",)

    def test_an_unplanned_arrival_does_not_make_an_enumeration_unknown(self):
        # A count could not tell these apart; an enumeration can, so coverage of
        # the plan stays computable.
        row = expectation(dimension="m", expected_ids=("a", "b"),
                          observed_ids=("a", "b", "c"))
        assert row.state is CoverageState.OBSERVED
        assert row.coverage == 1.0
        assert row.unexpected_ids == ("c",)
        assert not row.over_count

    def test_the_enumerated_basis_counts_arrivals_against_the_plan(self):
        row = expectation(dimension="m", expected_ids=("a", "b", "c"),
                          observed_ids=("a", "b", "x"))
        assert "expected 3, of which 2 arrived" in row.basis
        assert "did not name" in row.basis

    def test_an_enumeration_sets_its_own_count(self):
        row = expectation(dimension="m", expected_ids=("a", "b", "c"),
                          observed_ids=("a",))
        assert row.expected == 3
        assert row.observed == 1
        assert row.enumerated

    def test_a_bare_count_knows_no_ids(self):
        row = expectation(expected=10, observed=9)
        assert row.known_missing_ids == ()
        assert not row.enumerated


# ── the ledger ───────────────────────────────────────────────────────────────

class TestLedger:

    def test_rows_are_selectable_by_state(self):
        ledger = CoverageLedger((
            expectation(expected=10, observed=9),
            expectation(dimension="b", observed=5),
            expectation(dimension="c", assessed=False)))
        assert len(ledger.known_missing()) == 1
        assert len(ledger.unknown()) == 1
        assert len(ledger.not_assessed()) == 1

    def test_of_finds_a_dimension(self):
        ledger = CoverageLedger((expectation(expected=1, observed=1),))
        assert ledger.of("verifier_results") is not None
        assert ledger.of("absent") is None

    def test_with_expectation_counts_only_real_denominators(self):
        ledger = CoverageLedger((expectation(expected=10, observed=9),
                                 expectation(dimension="b", observed=5)))
        assert len(ledger.with_expectation()) == 1

    def test_the_summary_breaks_down_by_state(self):
        ledger = CoverageLedger((expectation(expected=10, observed=9),
                                 expectation(dimension="b", observed=5)))
        assert ledger.summary()["by_state"]["KNOWN_MISSING"] == 1
        assert ledger.summary()["by_state"]["UNKNOWN"] == 1
        assert ledger.summary()["known_missing_total"] == 1

    def test_an_empty_ledger_renders_without_claiming_anything(self):
        assert "No coverage dimensions" in CoverageLedger().render()

    def test_round_trip_through_dicts(self):
        row = expectation(expected=10, observed=9)
        assert EvidenceExpectation.from_dict(row.to_dict()).coverage == row.coverage


# ── the analyser ─────────────────────────────────────────────────────────────

class TestAnalyser:

    def test_known_missing_evidence_holds(self):
        rows = _analyse_expectation(CoverageLedger((
            expectation(expected=10, observed=9),)))
        row = next(f for f in rows if f.rule_id == "RG-EXPECT-001")
        assert row.effect is RequirementEffect.HOLD
        assert "known to be absent" in row.detail

    def test_unknown_coverage_is_advisory_not_a_fault(self):
        rows = _analyse_expectation(CoverageLedger((expectation(observed=9),)))
        row = next(f for f in rows if f.rule_id == "RG-EXPECT-002")
        assert row.effect is RequirementEffect.ADVISORY
        assert "not a fault" in row.detail
        assert row.observed["overall_coverage"] is None

    def test_an_over_count_holds(self):
        rows = _analyse_expectation(CoverageLedger((
            expectation(expected=10, observed=11),)))
        row = next(f for f in rows if f.rule_id == "RG-EXPECT-003")
        assert row.effect is RequirementEffect.HOLD
        assert "clamped to 100%" in row.detail

    def test_an_over_count_is_not_double_reported_as_unknown(self):
        rows = _analyse_expectation(CoverageLedger((
            expectation(expected=10, observed=11),)))
        assert "RG-EXPECT-002" not in {f.rule_id for f in rows}

    def test_unplanned_arrivals_are_advisory(self):
        rows = _analyse_expectation(CoverageLedger((
            expectation(dimension="m", expected_ids=("a",), observed_ids=("a", "b")),)))
        row = next(f for f in rows if f.rule_id == "RG-EXPECT-004")
        assert row.effect is RequirementEffect.ADVISORY

    def test_self_certified_coverage_is_reported(self):
        rows = _analyse_expectation(CoverageLedger((
            expectation(expected=10, observed=10, source=source(by="agent-fleet"),
                        observed_from="agent-fleet"),)))
        row = next(f for f in rows if f.rule_id == "RG-EXPECT-005")
        assert row.effect is RequirementEffect.ADVISORY
        assert "Invariant 13" in row.detail
        assert "Signing does not change this" in row.detail

    def test_an_empty_ledger_produces_no_findings(self):
        assert _analyse_expectation(CoverageLedger()) == []
        assert _analyse_expectation(None) == []


# ── ingest and the zero-config path ──────────────────────────────────────────

class TestZeroConfig:

    def test_the_envelope_ingests_a_declared_expectation(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "expectation", "dimension": "verifier_results",
             "expected": 10, "observed": 9,
             "source": {"kind": "ORCHESTRATION_MANIFEST",
                        "declared_by": "orchestrator"},
             "observed_from": "agent-fleet"}])
        assert len(outcome.normalisation.expectations) == 1
        row = outcome.analysis.coverage_ledger.of("verifier_results")
        assert row.coverage == 0.9
        assert row.state is CoverageState.KNOWN_MISSING

    def test_known_missing_evidence_holds_the_decision(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "expectation", "dimension": "verifier_results",
             "expected": 10, "observed": 9,
             "source": {"kind": "CI_PLAN", "declared_by": "orchestrator"},
             "observed_from": "fleet"}])
        assert "RG-EXPECT-001" in {f.rule_id for f in outcome.analysis.holding}

    def test_an_expectation_with_no_named_source_reads_self_reported(
            self, assure_envelope):
        # Not a generous default: where the envelope names nobody, the document's
        # own producer is used and the row says so.
        outcome = assure_envelope([
            {"record_type": "expectation", "dimension": "d", "expected": 3,
             "observed": 3}])
        assert outcome.analysis.coverage_ledger.of("d").self_certified

    def test_every_coverage_row_carries_the_five_state_answer(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "statement": "s"}])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        assert rows
        for row in rows:
            assert row["state"] in {s.value for s in CoverageState}
            assert row["bounds_completeness"] is False
            assert "coverage" in row

    def test_record_mapping_gains_a_self_reported_denominator(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "statement": "s"}])
        row = outcome.analysis.coverage_ledger.of("record_mapping")
        assert row.expected is not None
        assert row.self_certified

    def test_an_unexamined_dimension_stays_not_assessed(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "statement": "s"}])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        assert any(r["state"] == "NOT_ASSESSED" for r in rows)

    def test_an_independent_expectation_outranks_the_built_in_row(self,
                                                                  assure_envelope):
        outcome = assure_envelope([
            {"record_type": "expectation", "dimension": "record_mapping",
             "expected": 99, "observed": 1,
             "source": {"kind": "ORCHESTRATION_MANIFEST", "declared_by": "orch"},
             "observed_from": "envelope"}])
        row = outcome.analysis.coverage_ledger.of("record_mapping")
        assert row.expected == 99
        assert not row.self_certified


# ── the methodology hook ─────────────────────────────────────────────────────

class TestExpectationDeclared:

    def test_a_missing_dimension_is_not_assessed(self, case_with):
        found = ExpectationDeclared(dimension="absent").evaluate(
            case_with(expectation(expected=10, observed=9)))
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def test_an_undeclared_expectation_is_unsatisfied(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results").evaluate(
            case_with(expectation(observed=9)))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "coverage is UNKNOWN" in found.detail

    def test_a_declared_expectation_satisfies(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results").evaluate(
            case_with(expectation(expected=10, observed=9)))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_a_minimum_coverage_can_refuse(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results",
                                    minimum_coverage=0.95).evaluate(
            case_with(expectation(expected=10, observed=9)))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "1 known missing" in found.detail

    def test_independence_can_be_required(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results",
                                    require_independent=True).evaluate(
            case_with(expectation(expected=10, observed=10,
                                  source=source(by="agent-fleet"),
                                  observed_from="agent-fleet")))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "Invariant 13" in found.detail

    def test_a_self_report_is_otherwise_reported_not_refused(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results").evaluate(
            case_with(expectation(expected=10, observed=10,
                                  source=source(by="agent-fleet"),
                                  observed_from="agent-fleet")))
        assert found.outcome is RequirementOutcome.SATISFIED
        assert "does not refuse" in found.detail

    def test_an_over_count_cannot_satisfy(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results").evaluate(
            case_with(expectation(expected=10, observed=11)))
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_unexpected_arrivals_can_be_forbidden(self, case_with):
        found = ExpectationDeclared(dimension="m", allow_unexpected=False).evaluate(
            case_with(expectation(dimension="m", expected_ids=("a",),
                                  observed_ids=("a", "b"))))
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_satisfying_it_is_never_a_completeness_finding(self, case_with):
        found = ExpectationDeclared(dimension="verifier_results").evaluate(
            case_with(expectation(expected=10, observed=10)))
        assert found.observed["bounds_completeness"] is False

    def test_a_nameless_dimension_is_refused(self):
        with pytest.raises(MethodologyError):
            ExpectationDeclared(dimension="  ")

    def test_an_out_of_range_minimum_is_refused(self):
        with pytest.raises(MethodologyError):
            ExpectationDeclared(dimension="d", minimum_coverage=1.5)

    def test_the_predicate_round_trips(self):
        predicate = ExpectationDeclared(dimension="verifier_results",
                                        require_independent=True,
                                        minimum_coverage=0.9,
                                        allow_unexpected=False)
        assert predicate_from_dict(predicate.to_dict()) == predicate


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def case_with():
    def build(row):
        from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
        from release_gate.assurance.evidence import ContentReference, ReferenceKind
        from release_gate.assurance.records import SimpleRecord
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
        builder.declare_present("coverage", "test")
        builder.add("coverage", SimpleRecord(
            record_type="coverage", record_id=f"cov_{row.dimension}",
            payload=row.to_dict()))
        return builder.build()
    return build


@pytest.fixture
def assure_envelope(tmp_path):
    def run(rows):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "envelope.json"
        path.write_text(json.dumps(rows))
        return assure(str(path))
    return run
