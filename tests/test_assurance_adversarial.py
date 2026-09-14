"""Adversarial verification: verifiers whose job is to make the candidate fail."""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.adversarial import (
    AdversarialError, AdversarialFinding, AdversarialOutcome, AdversarialReview,
    AdversarialRole, AdversarialStance, AdversarialStatus, analyse_adversarial)
from release_gate.assurance.analysis import AnalysisDomain, _analyse_adversarial
from release_gate.assurance.attention import AttentionReason
from release_gate.assurance.counterexample import (
    CounterexampleAttempt, CounterexampleResult, CounterexampleStatus,
    CounterexampleLedger)
from release_gate.assurance.evidence import VerificationMethod
from release_gate.assurance.methodology import (
    AdversarialReviewRequired, MethodologyError, RequirementEffect,
    RequirementOutcome, predicate_from_dict)


def finding(**kw):
    kw.setdefault("target_claim", "C-main")
    kw.setdefault("role", AdversarialRole.RED_TEAM)
    kw.setdefault("adversary", "redteam-1")
    kw.setdefault("outcome", AdversarialOutcome.CANDIDATE_REFUTED)
    kw.setdefault("status", AdversarialStatus.OPEN)
    kw.setdefault("attempted_at", "2026-01-01T00:00:00Z")
    return AdversarialFinding(**kw)


# ── adversaries are never required ───────────────────────────────────────────

class TestNeverRequired:

    def test_an_empty_review_is_not_a_shortfall(self):
        review = analyse_adversarial([])
        assert not review.present
        assert "never required" in review.basis

    def test_an_empty_review_produces_no_findings(self):
        assert _analyse_adversarial(analyse_adversarial([]), {"C-main"}) == []

    def test_an_empty_review_renders_as_not_a_finding(self):
        assert "not a finding against this case" in analyse_adversarial([]).render()

    def test_a_methodology_reports_absence_as_not_assessed(self, case_with):
        found = AdversarialReviewRequired().evaluate(case_with(None))
        assert found.outcome is RequirementOutcome.NOT_ASSESSED


# ── breaking the argument is not breaking the claim ──────────────────────────

class TestArgumentVersusClaim:

    def test_an_argument_defect_does_not_refute(self):
        critic = finding(role=AdversarialRole.PROOF_CRITIC, adversary="critic-a",
                         outcome=AdversarialOutcome.ARGUMENT_DEFECT)
        assert not critic.refutes
        assert critic.to_counterexample() is None

    def test_a_refutation_refutes(self):
        assert finding().refutes
        assert finding().to_counterexample() is not None

    def test_a_weakness_refutes_nothing_but_stays_open(self):
        weak = finding(outcome=AdversarialOutcome.WEAKNESS_FOUND)
        assert not weak.refutes
        assert weak.is_open
        assert weak.to_counterexample() is None

    def test_an_open_argument_defect_on_a_critical_claim_blocks(self):
        review = analyse_adversarial([
            finding(role=AdversarialRole.PROOF_CRITIC, adversary="critic-a",
                    outcome=AdversarialOutcome.ARGUMENT_DEFECT)])
        found = _analyse_adversarial(review, {"C-main"})
        blocking = [f for f in found if f.effect is RequirementEffect.BLOCK]
        assert [f.rule_id for f in blocking] == ["RG-ADV-001"]
        assert "does not say the claim is false" in blocking[0].detail

    def test_a_defect_elsewhere_holds_rather_than_blocks(self):
        review = analyse_adversarial([
            finding(target_claim="C-side", role=AdversarialRole.PROOF_CRITIC,
                    adversary="critic-a", outcome=AdversarialOutcome.ARGUMENT_DEFECT)])
        found = _analyse_adversarial(review, {"C-main"})
        row = next(f for f in found if f.rule_id == "RG-ADV-002")
        assert row.effect is RequirementEffect.HOLD
        assert "RG-ADV-001" not in {f.rule_id for f in found}

    def test_refutations_are_not_reported_twice(self):
        # A refutation travels the counterexample path; the adversarial analyser
        # must not file the same fact under a second rule id.
        review = analyse_adversarial([finding()])
        found = _analyse_adversarial(review, {"C-main"})
        assert "RG-ADV-001" not in {f.rule_id for f in found}
        assert "RG-ADV-002" not in {f.rule_id for f in found}


# ── an empty attack proves nothing ───────────────────────────────────────────

class TestEmptySearches:

    def test_nothing_found_never_proves_absence(self):
        empty = AdversarialFinding.nothing_found(
            "C-main", adversary="fuzz-1", role=AdversarialRole.FALSIFICATION_AGENT,
            attacked="10^6 inputs")
        assert empty.proves_absence is False
        assert not empty.is_open

    def test_the_set_never_proves_absence_either(self):
        review = analyse_adversarial([
            AdversarialFinding.nothing_found(f"C-{i}", adversary=f"a{i}",
                                             role=AdversarialRole.RED_TEAM)
            for i in range(50)])
        assert review.proves_absence is False
        assert review.summary()["proves_absence"] is False

    def test_the_search_bound_names_what_the_role_cannot_cover(self):
        empty = AdversarialFinding.nothing_found(
            "C-main", adversary="rt", role=AdversarialRole.RED_TEAM,
            attacked="the tool surface")
        assert "the tool surface" in empty.search_bound
        assert "attacks this team did not think of" in empty.search_bound

    def test_an_unrecorded_extent_says_so(self):
        empty = AdversarialFinding.nothing_found("C-main", adversary="rt",
                                                 role=AdversarialRole.RED_TEAM)
        assert "was not recorded" in empty.search_bound

    def test_empty_searches_are_advisory_and_credited_with_nothing(self):
        review = analyse_adversarial([
            AdversarialFinding.nothing_found("C-main", adversary="fuzz-1",
                                             role=AdversarialRole.FALSIFICATION_AGENT)])
        found = _analyse_adversarial(review, {"C-main"})
        row = next(f for f in found if f.rule_id == "RG-ADV-006")
        assert row.effect is RequirementEffect.ADVISORY
        assert row.observed["proves_absence"] is False
        assert row.observed["unbounded"] == 1

    def test_an_empty_search_cannot_be_open_or_addressed(self):
        with pytest.raises(AdversarialError):
            finding(outcome=AdversarialOutcome.NO_FINDING,
                    status=AdversarialStatus.OPEN)


# ── an adversary sharing origin is not an adversary ──────────────────────────

class TestStance:

    def test_the_builder_reviewing_itself_is_self_review(self):
        f = finding(adversary="builder-team")
        assert f.stance(["builder-team"], []) is AdversarialStance.SELF_REVIEW

    def test_a_shared_lineage_is_shared_origin(self):
        f = finding(independence_lineage=("platform-x",))
        assert f.stance(["builder"], ["platform-x"]) is AdversarialStance.SHARED_ORIGIN

    def test_a_disjoint_lineage_is_independent(self):
        f = finding(independence_lineage=("sec-team",))
        assert f.stance(["builder"], ["blue-team"]) is AdversarialStance.INDEPENDENT

    def test_recording_nothing_is_never_independent(self):
        assert finding().stance([], []) is AdversarialStance.UNDETERMINED
        assert finding(independence_lineage=("x",)).stance([], []) \
            is AdversarialStance.UNDETERMINED

    def test_undetermined_is_not_counted_as_related(self):
        review = analyse_adversarial([finding()])
        assert review.non_independent() == ()
        assert review.independent() == ()

    def test_related_adversaries_are_advisory_not_blocking(self):
        review = analyse_adversarial(
            [finding(adversary="builder-team")],
            claim_producers={"C-main": ["builder-team"]})
        row = next(f for f in _analyse_adversarial(review, {"C-main"})
                   if f.rule_id == "RG-ADV-005")
        assert row.effect is RequirementEffect.ADVISORY
        assert "miss what the builder missed" in row.detail

    def test_a_self_declared_independent_label_is_not_read(self):
        # Nothing on the record lets an adversary assert its own independence;
        # the only inputs are its lineage and who produced the candidate.
        f = finding(adversary="redteam-1", detail="fully independent engagement")
        assert f.stance(["redteam-1"], []) is AdversarialStance.SELF_REVIEW


# ── a finding closed by the party it was against ─────────────────────────────

class TestSelfClearing:

    def test_the_builder_closing_its_own_finding_is_self_cleared(self):
        closed = finding().address("not exploitable", ["E-2"], by="builder-team")
        assert closed.self_cleared(["builder-team"])

    def test_another_party_closing_it_is_not(self):
        closed = finding().address("fixed", ["E-2"], by="sec-team")
        assert not closed.self_cleared(["builder-team"])

    def test_an_open_finding_is_never_self_cleared(self):
        assert not finding().self_cleared(["builder-team"])

    def test_an_accepted_risk_can_be_self_cleared(self):
        accepted = finding().accept_risk("low likelihood", by="builder-team")
        assert accepted.self_cleared(["builder-team"])

    def test_self_clearing_on_a_critical_claim_blocks(self):
        closed = finding().address("not exploitable", ["E-2"], by="builder-team")
        review = analyse_adversarial([closed],
                                     claim_producers={"C-main": ["builder-team"]})
        row = next(f for f in _analyse_adversarial(review, {"C-main"})
                   if f.rule_id == "RG-ADV-004")
        assert row.effect is RequirementEffect.BLOCK
        assert "has not been independently answered" in row.detail

    def test_self_clearing_elsewhere_holds(self):
        closed = finding(target_claim="C-side").address("ok", ["E-2"], by="builder")
        review = analyse_adversarial([closed],
                                     claim_producers={"C-side": ["builder"]})
        row = next(f for f in _analyse_adversarial(review, {"C-main"})
                   if f.rule_id == "RG-ADV-004")
        assert row.effect is RequirementEffect.HOLD

    def test_unknown_producers_mean_undetermined_not_clean(self):
        closed = finding().address("ok", ["E-2"], by="builder-team")
        review = analyse_adversarial([closed])
        assert review.self_cleared() == ()
        assert review.stances[closed.finding_id] is AdversarialStance.UNDETERMINED


# ── accepting a risk is not resolving it ─────────────────────────────────────

class TestAcceptedRisk:

    def test_an_accepted_risk_stays_open(self):
        accepted = finding().accept_risk("mitigations in place", by="vp-eng")
        assert accepted.accepted
        assert accepted.is_open
        assert not accepted.addressed

    def test_accepting_must_name_who_accepted(self):
        with pytest.raises(AdversarialError) as exc:
            finding(status=AdversarialStatus.ACCEPTED_RISK, resolution="fine")
        assert "answerable" in str(exc.value)

    def test_accepting_must_state_a_basis(self):
        with pytest.raises(AdversarialError):
            finding(status=AdversarialStatus.ACCEPTED_RISK, accepted_by="vp")

    def test_an_accepted_refutation_converts_to_an_open_counterexample(self):
        accepted = finding().accept_risk("shipping anyway", by="vp-eng")
        converted = accepted.to_counterexample()
        assert converted.status is CounterexampleStatus.OPEN

    def test_accepted_risks_reach_a_finding_even_when_deliberate(self):
        review = analyse_adversarial(
            [finding().accept_risk("known, accepted", by="vp-eng")])
        row = next(f for f in _analyse_adversarial(review, {"C-main"})
                   if f.rule_id == "RG-ADV-003")
        assert row.effect is RequirementEffect.HOLD
        assert "not a resolution" in row.detail

    def test_an_accepted_risk_off_the_critical_path_is_advisory(self):
        review = analyse_adversarial(
            [finding(target_claim="C-side").accept_risk("ok", by="vp")])
        row = next(f for f in _analyse_adversarial(review, {"C-main"})
                   if f.rule_id == "RG-ADV-003")
        assert row.effect is RequirementEffect.ADVISORY


# ── the record refuses states that would misreport ───────────────────────────

class TestRecordDiscipline:

    def test_a_live_finding_cannot_be_filed_as_nothing_to_do(self):
        with pytest.raises(AdversarialError):
            finding(status=AdversarialStatus.NOT_APPLICABLE)

    def test_a_finding_must_name_its_adversary(self):
        with pytest.raises(AdversarialError) as exc:
            finding(adversary="")
        assert "answerable" in str(exc.value)

    def test_a_finding_must_name_what_it_attacked(self):
        with pytest.raises(AdversarialError):
            finding(target_claim="  ")

    def test_addressing_requires_evidence_not_assertion(self):
        with pytest.raises(AdversarialError) as exc:
            finding(status=AdversarialStatus.ADDRESSED, resolution="looked at it")
        assert "never by assertion" in str(exc.value)

    def test_dismissing_requires_a_reason(self):
        with pytest.raises(AdversarialError):
            finding(status=AdversarialStatus.INVALID)

    def test_invalidating_with_a_reason_is_allowed(self):
        assert finding().invalidate("misread the spec").addressed

    def test_the_id_is_stable_and_ignores_later_handling(self):
        one = finding()
        assert one.finding_id == finding().finding_id
        assert one.address("fixed", ["E"], by="x").finding_id == one.finding_id

    def test_the_role_selects_a_method_and_nothing_else(self):
        assert finding(role=AdversarialRole.PROOF_CRITIC).method \
            is VerificationMethod.HUMAN_REVIEW
        assert finding(role=AdversarialRole.INDEPENDENT_TESTER).method \
            is VerificationMethod.TEST_SUITE

    def test_an_explicit_method_overrides_the_role_default(self):
        assert finding(method=VerificationMethod.SIMULATION).method \
            is VerificationMethod.SIMULATION

    def test_serialisation_round_trips(self):
        one = finding(evidence=("E-1",), independence_lineage=("sec",),
                      attacked="the tool surface", detail="d")
        assert AdversarialFinding.from_dict(one.to_dict()) == one

    def test_the_dict_never_offers_a_proves_absence_true(self):
        assert finding().to_dict()["proves_absence"] is False


# ── the review ───────────────────────────────────────────────────────────────

class TestReview:

    def test_refutations_convert_for_the_existing_path(self):
        review = analyse_adversarial([
            finding(),
            finding(role=AdversarialRole.PROOF_CRITIC, adversary="c",
                    outcome=AdversarialOutcome.ARGUMENT_DEFECT)])
        assert len(review.to_counterexamples()) == 1

    def test_converted_refutations_are_deduplicated_against_declared_ones(self):
        one = finding()
        converted = one.to_counterexample()
        duplicate = CounterexampleAttempt(
            target_claim="C-main", producer="redteam-1",
            method=VerificationMethod.EXPERIMENT,
            result=CounterexampleResult.FOUND, status=CounterexampleStatus.OPEN,
            attempted_at="2026-01-01T00:00:00Z")
        assert len(CounterexampleLedger([converted, duplicate])) == 1

    def test_unattacked_claims_are_reported_not_charged(self):
        review = analyse_adversarial([finding(target_claim="C-side")])
        assert review.unattacked(["C-main", "C-side"]) == ("C-main",)
        row = next(f for f in _analyse_adversarial(review, {"C-main"})
                   if f.rule_id == "RG-ADV-007")
        assert row.effect is RequirementEffect.ADVISORY
        assert "never required" in row.detail

    def test_the_review_serialises_as_a_record(self):
        review = analyse_adversarial([finding()])
        payload = review.to_dict()
        assert payload["record_type"] == "adversarial_review"
        assert payload["record_id"] == review.record_id
        assert payload["claims_attacked_ids"] == ["C-main"]

    def test_the_digest_is_stable(self):
        one, two = finding(), finding(target_claim="C-side")
        assert analyse_adversarial([one, two]).digest() == \
            analyse_adversarial([two, one]).digest()

    def test_for_claim_selects(self):
        review = analyse_adversarial([finding(), finding(target_claim="C-side")])
        assert len(review.for_claim("C-main")) == 1

    def test_open_findings_sort_first(self):
        closed = finding(target_claim="C-a").address("f", ["E"], by="x")
        live = finding(target_claim="C-z")
        assert analyse_adversarial([closed, live]).findings[0] == live


# ── human attention ──────────────────────────────────────────────────────────

class TestHumanAttention:

    def test_an_unresolved_adversarial_failure_reaches_attention(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "builder"},
             "supports_claims": ["C-main"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "C-main", "is_root": True,
             "statement": "the agent cannot exfiltrate secrets",
             "supported_by": ["E-1"]},
            {"record_type": "adversarial", "target_claim": "C-main",
             "role": "PROOF_CRITIC", "adversary": "critic-a",
             "outcome": "ARGUMENT_DEFECT", "detail": "step 7 does not follow"},
        ])
        reasons = {i.reason for i in outcome.attention.items}
        assert AttentionReason.ADVERSARIAL_FINDING in reasons
        assert outcome.attention.blocking

    def test_a_self_cleared_finding_reaches_attention_under_its_own_reason(
            self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "builder"},
             "supports_claims": ["C-main"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "C-main", "is_root": True,
             "statement": "s", "supported_by": ["E-1"]},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "WEAKNESS_FOUND", "status": "ADDRESSED",
             "resolution": "not exploitable", "resolution_evidence": ["E-1"],
             "resolved_by": "builder"},
        ])
        item = next(i for i in outcome.attention.items
                    if i.reason is AttentionReason.SELF_CLEARED)
        assert item.focus_kind == "adversarial_finding"

    def test_an_accepted_risk_reaches_attention_under_its_own_reason(
            self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "is_root": True,
             "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "WEAKNESS_FOUND", "status": "ACCEPTED_RISK",
             "resolution": "low likelihood", "accepted_by": "vp-eng"},
        ])
        assert any(i.reason is AttentionReason.ACCEPTED_RISK
                   for i in outcome.attention.items)

    def test_a_clean_adversarial_result_is_never_settled_by_arrival(
            self, assure_envelope):
        from release_gate.assurance.attention import _NON_MONOTONE_RULES
        assert {"RG-ADV-001", "RG-ADV-002", "RG-ADV-003",
                "RG-ADV-004"} <= _NON_MONOTONE_RULES


# ── ingest and the zero-config path ──────────────────────────────────────────

class TestZeroConfig:

    def test_the_envelope_ingests_adversarial_records(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main",
             "role": "SECURITY_ADVERSARY", "adversary": "pentest-1",
             "outcome": "WEAKNESS_FOUND", "attacked": "the auth surface"},
        ])
        assert len(outcome.normalisation.adversarial) == 1
        assert outcome.adversarial.present

    def test_a_found_outcome_defaults_to_open(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "WEAKNESS_FOUND"},
        ])
        assert outcome.normalisation.adversarial[0].status is AdversarialStatus.OPEN

    def test_an_empty_outcome_defaults_to_not_applicable(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "NO_FINDING"},
        ])
        assert outcome.normalisation.adversarial[0].status \
            is AdversarialStatus.NOT_APPLICABLE

    def test_a_refutation_reaches_the_counterexample_path(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "is_root": True,
             "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "CANDIDATE_REFUTED",
             "detail": "exfiltrated a secret"},
        ])
        assert len(outcome.counterexamples) == 1
        assert outcome.decision.value == "BLOCK"

    def test_the_review_is_stored_on_the_case(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "NO_FINDING"},
        ])
        stored = [r for r in outcome.case.records("evidence")
                  if r.to_dict().get("record_type") == "adversarial_review"]
        assert len(stored) == 1

    def test_coverage_is_not_assessed_when_nobody_attacked(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"}])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "adversarial_review")
        assert row["status"] == "NOT_ASSESSED"
        assert "never required" in row["note"]

    def test_coverage_never_reads_as_cleared(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"},
            {"record_type": "adversarial", "target_claim": "C-main", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "NO_FINDING", "attacked": "the tool surface"},
        ])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "adversarial_review")
        assert row["proves_absence"] is False
        assert "bounds the search, not the claim" in row["note"]

    def test_an_empty_review_is_not_stored_as_a_zero(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "C-main", "statement": "s"}])
        stored = [r for r in outcome.case.records("evidence")
                  if r.to_dict().get("record_type") == "adversarial_review"]
        assert stored == []


# ── the methodology hook ─────────────────────────────────────────────────────

class TestAdversarialReviewRequired:

    def test_too_few_attacks_is_unsatisfied(self, case_with):
        review = analyse_adversarial([finding()])
        found = AdversarialReviewRequired(minimum_attacks=2).evaluate(case_with(review))
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_an_independent_attack_satisfies(self, case_with):
        review = analyse_adversarial(
            [finding(independence_lineage=("sec",))],
            claim_producers={"C-main": ["builder"]},
            claim_lineage={"C-main": ["blue"]})
        found = AdversarialReviewRequired().evaluate(case_with(review))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_undetermined_independence_does_not_satisfy(self, case_with):
        review = analyse_adversarial([finding()])
        found = AdversarialReviewRequired().evaluate(case_with(review))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "could be derived" in found.detail

    def test_self_cleared_findings_are_refused(self, case_with):
        closed = finding().address("ok", ["E"], by="builder")
        review = analyse_adversarial([closed],
                                     claim_producers={"C-main": ["builder"]})
        found = AdversarialReviewRequired(require_independent=False).evaluate(
            case_with(review))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "closed by the party" in found.detail

    def test_a_missing_required_role_is_unsatisfied(self, case_with):
        review = analyse_adversarial(
            [finding(independence_lineage=("sec",))],
            claim_producers={"C-main": ["b"]}, claim_lineage={"C-main": ["blue"]})
        found = AdversarialReviewRequired(
            required_roles=("PROOF_CRITIC",)).evaluate(case_with(review))
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_a_present_required_role_is_satisfied(self, case_with):
        review = analyse_adversarial(
            [finding(independence_lineage=("sec",))],
            claim_producers={"C-main": ["b"]}, claim_lineage={"C-main": ["blue"]})
        found = AdversarialReviewRequired(
            required_roles=("RED_TEAM",)).evaluate(case_with(review))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_accepted_risks_are_reported_not_refused(self, case_with):
        review = analyse_adversarial(
            [finding(independence_lineage=("sec",)).accept_risk("ok", by="vp")],
            claim_producers={"C-main": ["b"]}, claim_lineage={"C-main": ["blue"]})
        found = AdversarialReviewRequired().evaluate(case_with(review))
        assert found.outcome is RequirementOutcome.SATISFIED
        assert "accepted as risk" in found.detail

    def test_a_requirement_for_zero_attacks_is_refused(self):
        with pytest.raises(MethodologyError):
            AdversarialReviewRequired(minimum_attacks=0)

    def test_the_predicate_round_trips(self):
        predicate = AdversarialReviewRequired(
            minimum_attacks=2, required_roles=("red_team", "proof_critic"),
            require_independent=False, require_critical_coverage=True)
        assert predicate_from_dict(predicate.to_dict()) == predicate

    def test_critical_coverage_refuses_an_unattacked_root(self, case_with):
        review = analyse_adversarial(
            [finding(target_claim="C-side", independence_lineage=("sec",))],
            claim_producers={"C-side": ["b"]}, claim_lineage={"C-side": ["blue"]})
        found = AdversarialReviewRequired(
            require_critical_coverage=True).evaluate(
                case_with(review, root_claim="C-main"))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "not attacked by any adversary" in found.detail

    def test_critical_coverage_passes_when_the_root_was_attacked(self, case_with):
        review = analyse_adversarial(
            [finding(independence_lineage=("sec",))],
            claim_producers={"C-main": ["b"]}, claim_lineage={"C-main": ["blue"]})
        found = AdversarialReviewRequired(
            require_critical_coverage=True).evaluate(
                case_with(review, root_claim="C-main"))
        assert found.outcome is RequirementOutcome.SATISFIED


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def case_with():
    def build(review, root_claim=None):
        from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
        from release_gate.assurance.claims import Claim
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
        if review is not None:
            builder.add("evidence", review)
        builder.declare_present("claims", "test")
        if root_claim:
            builder.add("claims", Claim(claim_id=root_claim, statement="s",
                                        is_root=True))
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
