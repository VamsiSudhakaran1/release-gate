"""Human override — proceeding despite unresolved issues, on the record.

Every case here runs against real engine output. The methodologies that permit
a waiver are built with `extend`, because no built-in methodology declares an
override rule — which is the correct default (silence is a no) and means the
whole feature is opt-in by an organisation that writes one.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_gate.assurance.approval import (
    ApprovalDecision, AuthSource, offer_approval, submit_approval,
)
from release_gate.assurance.approval_view import build_view
from release_gate.assurance.case import Decision
from release_gate.assurance.methodologies import (
    GENERAL_AUTONOMOUS_ACTION_V1, RESEARCH_MATHEMATICS_V1,
)
from release_gate.assurance.methodology import (
    CoverageExpectation, OverrideRule, RequirementEffect,
)
from release_gate.assurance.override import (
    Authorization, AuthorizationState, Override, OverrideError, OverrideOutcome,
    OverrideRequest, OverrideReview, UnresolvedIssue, authorisation_of,
    request_override, unresolved_issues,
)
from release_gate.assurance.verdict import explain_verdict
from release_gate.assurance.zero_config import assure
from release_gate.demos import frontier_research, single_agent

WAIVABLE = "coverage.load_testing"

#: A methodology that expects a load test this case does not carry, so exactly
#: one of its own requirements is unmet.
STRICT = GENERAL_AUTONOMOUS_ACTION_V1.extend(
    methodology_id="ops-strict", version="1.0.0",
    add_coverage_expectations=(CoverageExpectation(
        dimension="load_testing",
        expected_source="a load test report from the staging replica",
        rationale="irreversible migrations are load-tested before promotion",
        effect=RequirementEffect.HOLD),))

#: The same, plus a waiver a named release manager may exercise.
WAIVER = STRICT.extend(
    methodology_id="ops-waiver", version="1.0.0",
    add_override_rules=(OverrideRule(
        requirement_id=WAIVABLE, permitted=True, requires_role="release-manager",
        notes="a named release manager may proceed without a load test"),))


@pytest.fixture
def held(tmp_path):
    """The single-agent migration under a methodology it does not fully satisfy."""
    path = tmp_path / "case.json"
    path.write_text(json.dumps(single_agent.build_document()))
    return assure(str(path), methodology=WAIVER)


@pytest.fixture
def promoted():
    return single_agent.run().outcome


@pytest.fixture
def blocked():
    return frontier_research.run(
        scenario=frontier_research.ResearchScenario(workers=400)).outcome


def ask(outcome, *, methodology=WAIVER, **kw):
    issues = unresolved_issues(outcome)
    base = dict(approver="dr.reed",
                reason="the release window closes tonight and the rollback has "
                       "been rehearsed twice against a staging replica",
                scope="this migration, this deploy, nothing else",
                acknowledged=tuple(i.requirement_id for i in issues),
                role="release-manager")
    base.update(kw)
    return request_override(outcome.case, outcome, OverrideRequest(**base),
                            methodology=methodology)


# ── what is open ─────────────────────────────────────────────────────────────

class TestUnresolvedIssues:

    def test_it_reads_three_id_namespaces(self, held):
        """The assessment, the attention set and the fired rules are different
        vocabularies and none contains the others."""
        ids = {i.requirement_id for i in unresolved_issues(held)}
        assert WAIVABLE in ids                    # methodology assessment
        assert any(i.startswith("RG-ZC-") for i in ids)   # zero-config policy
        assert any(i.startswith("RG-VERIF") or i.startswith("RG-") and
                   not i.startswith("RG-ZC-") for i in ids)  # analysis finding

    def test_an_issue_must_name_a_requirement(self):
        with pytest.raises(OverrideError) as exc:
            UnresolvedIssue(requirement_id="  ", summary="something")
        assert "cannot be put to a methodology" in str(exc.value)

    def test_a_promoted_case_can_still_hold_open_items(self, promoted):
        """PROMOTE is bounded by the methodology and by known coverage, not by
        there being nothing left open. This case promoted with nothing verified."""
        ids = {i.requirement_id for i in unresolved_issues(promoted)}
        assert "RG-VERIF-001" in ids

    def test_a_promote_does_not_report_its_own_reasoning_as_open(self, promoted):
        """`fired_rules` on a PROMOTE is what produced it, not what went against
        it, so those ids are not open issues."""
        ids = {i.requirement_id for i in unresolved_issues(promoted)}
        assert set(promoted.case.verdict.fired_rules) & ids == set()

    def test_a_blocked_case_holds_its_blocking_requirements(self, blocked):
        issues = {i.requirement_id: i for i in unresolved_issues(blocked)}
        assert "contradictions.resolved" in issues
        assert issues["contradictions.resolved"].blocking


# ── only where the methodology permits ───────────────────────────────────────

class TestPermission:

    def test_a_permitted_waiver_is_granted(self, held):
        review = ask(held)
        assert review.granted
        assert review.override.waived == (WAIVABLE,)

    def test_the_same_case_is_refused_without_the_waiver_rule(self, tmp_path):
        path = tmp_path / "case.json"
        path.write_text(json.dumps(single_agent.build_document()))
        outcome = assure(str(path), methodology=STRICT)
        review = ask(outcome, methodology=STRICT)
        assert review.outcome is OverrideOutcome.REFUSED_NOT_PERMITTED
        assert any("absent an explicit waiver rule" in r for r in review.reasons)

    def test_silence_from_a_methodology_is_a_no(self, held):
        """Not an omission to be read around — the default has to be refusal."""
        assert not WAIVER.can_override("RG-ACT-002").permitted

    def test_a_methodology_ref_cannot_answer_and_says_so(self, held):
        with pytest.raises(OverrideError) as exc:
            request_override(held.case, held,
                             OverrideRequest(approver="a", reason="b", scope="c",
                                             acknowledged=("d",)),
                             methodology=held.case.methodology)
        assert "MethodologyRef" in str(exc.value)
        assert "no override without one" in str(exc.value)

    def test_there_is_no_default_methodology(self, held):
        with pytest.raises(OverrideError):
            request_override(held.case, held,
                             OverrideRequest(approver="a", reason="b", scope="c",
                                             acknowledged=("d",)),
                             methodology=None)

    def test_a_required_role_must_be_stated(self, held):
        review = ask(held, role="")
        assert review.outcome is OverrideOutcome.REFUSED_ROLE
        assert any("release-manager" in r for r in review.reasons)

    def test_a_methodology_that_permits_none_of_it_refuses(self, tmp_path):
        """The general profile defines neither the policy rule nor the finding
        that hold this case, so it permits waiving nothing."""
        outcome = single_agent.run(
            scenario=single_agent.MigrationScenario(
                reversibility="IRREVERSIBLE")).outcome
        review = ask(outcome, methodology=GENERAL_AUTONOMOUS_ACTION_V1)
        assert review.outcome is OverrideOutcome.REFUSED_UNKNOWN_REQUIREMENT
        assert any("AcceptedFinding" in r for r in review.reasons)


# ── some BLOCK conditions may be non-overridable ─────────────────────────────

class TestNonOverridable:

    def test_a_declared_non_overridable_condition_refuses(self, blocked):
        review = ask(blocked, methodology=RESEARCH_MATHEMATICS_V1)
        assert review.outcome is OverrideOutcome.REFUSED_NON_OVERRIDABLE
        assert review.permanently_refused

    def test_no_resubmission_makes_it_a_grant(self, blocked):
        first = ask(blocked, methodology=RESEARCH_MATHEMATICS_V1)
        second = ask(blocked, methodology=RESEARCH_MATHEMATICS_V1,
                     reason="a much better reason, at length, with justification",
                     role="department-chair")
        assert first.outcome is second.outcome is OverrideOutcome.REFUSED_NON_OVERRIDABLE

    def test_the_refusal_names_which_conditions(self, blocked):
        review = ask(blocked, methodology=RESEARCH_MATHEMATICS_V1)
        refused = {r["requirement_id"] for r in review.refused_issues}
        assert "contradictions.resolved" in refused
        assert "counterexamples.resolved" in refused

    def test_unrecognised_is_not_the_same_as_refused(self):
        """Two different facts that both answer `permitted=False`."""
        defined = GENERAL_AUTONOMOUS_ACTION_V1.can_override("RG-ACT-002")
        foreign = GENERAL_AUTONOMOUS_ACTION_V1.can_override("RG-ZC-003")
        assert not defined.permitted and not foreign.permitted
        assert defined.recognised and not foreign.recognised
        assert "wrong authority" in foreign.reason


# ── the record ───────────────────────────────────────────────────────────────

class TestRecord:

    def test_it_carries_every_required_field(self, held):
        payload = ask(held).override.to_dict()
        for field in ("approver", "reason", "issues", "scope", "subject_digest",
                      "case_digest", "timestamp"):
            assert payload.get(field), field

    @pytest.mark.parametrize("field", ["approver", "reason", "scope"])
    def test_a_missing_field_is_refused(self, held, field):
        review = ask(held, **{field: "   "})
        assert review.outcome is OverrideOutcome.REFUSED_INCOMPLETE
        assert field in review.reasons[0]

    def test_release_gate_cannot_override_its_own_finding(self, held):
        granted = ask(held).override
        with pytest.raises(OverrideError) as exc:
            dataclasses.replace(granted, auth_source=AuthSource.RELEASE_GATE)
        assert "cannot override its own finding" in str(exc.value)

    def test_a_blanket_waiver_is_refused(self, held):
        granted = ask(held).override
        with pytest.raises(OverrideError) as exc:
            dataclasses.replace(granted, issues=())
        assert "signature on an unread page" in str(exc.value)

    def test_an_override_on_a_promote_is_refused_at_construction(self, held):
        granted = ask(held).override
        with pytest.raises(OverrideError) as exc:
            dataclasses.replace(granted, machine_verdict="PROMOTE")
        assert "nothing to override on a PROMOTE" in str(exc.value)

    def test_the_id_is_content_derived(self, held):
        one = ask(held).override
        two = dataclasses.replace(one, timestamp=one.timestamp)
        assert one.override_id == two.override_id

    def test_it_round_trips(self, held):
        one = ask(held).override
        two = Override.from_dict(one.to_dict())
        assert two.override_id == one.override_id
        assert two.waived == one.waived
        assert two.unauthorised == one.unauthorised

    def test_identity_is_not_established_by_assertion(self, held):
        assert not ask(held).override.identity_established
        assert "not an established one" in ask(held).override.render()


# ── never a silent conversion ────────────────────────────────────────────────

class TestVerdictPreserved:

    def test_the_machine_verdict_is_recorded_verbatim(self, held):
        granted = ask(held).override
        assert granted.machine_verdict == held.case.verdict.decision.value == "HOLD"

    def test_the_effective_decision_is_the_machine_verdict(self, held):
        granted = ask(held).override
        assert granted.effective_decision == granted.machine_verdict

    def test_the_case_verdict_is_untouched_by_a_grant(self, held):
        before = held.case.verdict.decision
        ask(held)
        assert held.case.verdict.decision is before is Decision.HOLD

    def test_the_exit_code_is_untouched(self, held):
        ask(held)
        assert held.case.verdict.decision.exit_code == 10

    @pytest.mark.parametrize("name", ["converts_verdict", "resolves_issues",
                                      "establishes_truth", "authorises"])
    def test_the_refusals_are_unconditional(self, held, name):
        granted = ask(held).override
        assert getattr(granted, name) is False
        assert granted.to_dict()[name] is False

    def test_an_override_is_not_an_approval(self, held):
        """It makes an authorisation permissible. The act is still a person's."""
        assert ask(held).override.authorises is False


# ── everything open must be named ────────────────────────────────────────────

class TestNoOmission:

    def test_naming_fewer_issues_than_the_case_holds_is_refused(self, held):
        review = ask(held, acknowledged=(WAIVABLE,))
        assert review.outcome is OverrideOutcome.REFUSED_UNDER_NAMED
        assert review.unacknowledged
        assert any("smaller case than the one in hand" in r for r in review.reasons)

    def test_the_unnamed_ones_are_reported(self, held):
        review = ask(held, acknowledged=(WAIVABLE,))
        open_ids = {i.requirement_id for i in unresolved_issues(held)}
        assert set(review.unacknowledged) == open_ids - {WAIVABLE}

    def test_naming_extra_ids_does_not_waive_them(self, held):
        review = ask(held, acknowledged=tuple(
            i.requirement_id for i in unresolved_issues(held)) + ("invented.rule",))
        assert review.granted
        assert "invented.rule" not in review.override.waived
        assert "invented.rule" not in review.override.unauthorised

    def test_issues_outside_the_methodology_are_disclosed_not_dropped(self, held):
        granted = ask(held).override
        assert granted.unauthorised
        assert not granted.fully_authorised
        assert "NOT AUTHORISED" in granted.render()

    def test_waived_means_permitted_not_merely_listed(self, held):
        granted = ask(held).override
        assert set(granted.waived) < {i.requirement_id for i in granted.issues}


# ── nothing to override ──────────────────────────────────────────────────────

class TestNotRequired:

    def test_a_promote_needs_no_override(self, promoted):
        review = ask(promoted, methodology=GENERAL_AUTONOMOUS_ACTION_V1)
        assert review.outcome is OverrideOutcome.NOT_REQUIRED
        assert review.override is None

    def test_and_says_why_recording_one_would_be_worse(self, promoted):
        review = ask(promoted, methodology=GENERAL_AUTONOMOUS_ACTION_V1)
        assert "did not need one" in review.reasons[0]


# ── bound to exact state ─────────────────────────────────────────────────────

class TestBinding:

    def test_it_binds_to_the_case_it_was_granted_against(self, held):
        assert ask(held).override.binds_to(held.case)

    def test_it_does_not_carry_to_another_case(self, held, blocked):
        granted = ask(held).override
        assert not granted.binds_to(blocked.case)
        assert granted.stale_against(blocked.case)

    def test_submitting_with_a_foreign_override_is_refused(self, held, blocked):
        foreign = ask(held).override
        submission = submit_approval(
            blocked.case, offer_approval(blocked.case).acknowledgement(),
            approver="dr.reed", override=foreign)
        assert not submission.accepted
        assert any("permits nothing here" in r for r in submission.reasons)

    def test_an_approval_carries_the_override_id(self, held):
        granted = ask(held).override
        submission = submit_approval(
            held.case, offer_approval(held.case).acknowledgement(),
            approver="dr.reed", override=granted)
        assert submission.accepted
        assert submission.approval.override_id == granted.override_id
        assert submission.approval.proceeds_under_override

    def test_an_approval_without_one_says_so(self, held):
        submission = submit_approval(
            held.case, offer_approval(held.case).acknowledgement(),
            approver="dr.reed")
        assert submission.approval.overrides_recommendation
        assert not submission.approval.proceeds_under_override
        assert "no override is on record" in submission.approval.render()

    def test_adding_an_override_does_not_change_existing_approval_ids(self, held):
        """The key joins `identity()` only when it carries a fact."""
        plain = submit_approval(held.case,
                                offer_approval(held.case).acknowledgement(),
                                approver="dr.reed").approval
        assert "override_id" not in plain.identity()


# ── the separate authorization state ─────────────────────────────────────────

class TestAuthorizationState:

    def test_a_verdict_alone_authorises_nothing(self, promoted):
        state = authorisation_of(promoted.case)
        assert state.state is AuthorizationState.NOT_AUTHORISED
        assert not state.authorised
        assert "A verdict is not an authorization" in state.notes[0]

    def test_an_approval_over_a_cleared_case_is_authorised(self, promoted):
        approval = submit_approval(
            promoted.case, offer_approval(promoted.case).acknowledgement(),
            approver="dr.reed").approval
        assert authorisation_of(promoted.case,
                                approval=approval).state is AuthorizationState.AUTHORISED

    def test_an_approval_under_an_override_is_its_own_state(self, held):
        granted = ask(held).override
        approval = submit_approval(
            held.case, offer_approval(held.case).acknowledgement(),
            approver="dr.reed", override=granted).approval
        state = authorisation_of(held.case, approval=approval, override=granted)
        assert state.state is AuthorizationState.AUTHORISED_BY_OVERRIDE
        assert state.proceeds_over_open_issues

    def test_that_state_is_never_promote(self, held):
        granted = ask(held).override
        approval = submit_approval(
            held.case, offer_approval(held.case).acknowledgement(),
            approver="dr.reed", override=granted).approval
        state = authorisation_of(held.case, approval=approval, override=granted)
        assert state.machine_verdict == "HOLD"
        assert "PROMOTE" not in state.state.value
        assert any("is not PROMOTE" in n for n in state.notes)

    def test_no_authorization_state_is_a_verdict(self):
        assert not set(a.value for a in AuthorizationState) & {
            d.value for d in Decision}

    def test_a_rejection_is_its_own_state(self, held):
        approval = submit_approval(
            held.case, offer_approval(held.case).acknowledgement(),
            approver="dr.reed", decision=ApprovalDecision.REJECTED).approval
        assert authorisation_of(held.case,
                                approval=approval).state is AuthorizationState.REFUSED

    def test_a_refused_override_is_recorded_as_such(self, blocked):
        review = ask(blocked, methodology=RESEARCH_MATHEMATICS_V1)
        state = authorisation_of(blocked.case, review=review)
        assert state.state is AuthorizationState.OVERRIDE_REFUSED
        assert not state.authorised

    def test_a_stale_override_does_not_carry_over(self, held, blocked):
        granted = ask(held).override
        approval = submit_approval(
            blocked.case, offer_approval(blocked.case).acknowledgement(),
            approver="dr.reed").approval
        state = authorisation_of(blocked.case, approval=approval, override=granted)
        assert state.state is AuthorizationState.AUTHORISED
        assert any("does not carry over" in n for n in state.notes)

    def test_approving_over_a_hold_with_no_override_is_named(self, held):
        approval = submit_approval(
            held.case, offer_approval(held.case).acknowledgement(),
            approver="dr.reed").approval
        state = authorisation_of(held.case, approval=approval)
        assert any("never asked" in n for n in state.notes)

    def test_the_state_never_certifies_truth(self, promoted):
        approval = submit_approval(
            promoted.case, offer_approval(promoted.case).acknowledgement(),
            approver="dr.reed").approval
        state = authorisation_of(promoted.case, approval=approval)
        assert state.establishes_truth is False
        assert state.machine_verdict_preserved is True


# ── the view ─────────────────────────────────────────────────────────────────

class TestApprovalView:

    def test_an_override_adds_a_display_not_a_fourth_action(self, held):
        granted = ask(held).override
        view = build_view(held, override=granted)
        assert "override" in view.displays
        assert len(view.actions) == 3

    def test_the_approve_action_names_what_is_being_proceeded_over(self, held):
        granted = ask(held).override
        view = build_view(held, override=granted)
        caution = next(a.caution for a in view.actions if a.action.value == "APPROVE")
        assert granted.override_id in caution
        assert "remain open" in caution

    def test_a_stale_override_is_shown_as_not_applying(self, held, blocked):
        granted = ask(held).override
        view = build_view(blocked, override=granted)
        assert view.displays["override"]["applies"] is False
        assert "does not carry over" in view.displays["override"]["note"]

    def test_no_override_means_no_display(self, held):
        assert "override" not in build_view(held).displays


# ── the verdict statement reads the same distinction ─────────────────────────

class TestVerdictStatement:

    def test_a_block_on_declared_conditions_is_fully_non_overridable(self, blocked):
        statement = explain_verdict(blocked, methodology=RESEARCH_MATHEMATICS_V1)
        assert statement.block_is_fully_non_overridable
        assert not statement.unrecognised_reasons

    def test_an_unrecognised_reason_is_not_counted_as_a_refusal(self, blocked):
        """Asking a methodology that does not govern this case must not make its
        silence look like a refusal it issued."""
        statement = explain_verdict(blocked, methodology=GENERAL_AUTONOMOUS_ACTION_V1)
        assert statement.unrecognised_reasons
        assert not statement.block_is_fully_non_overridable
        assert "never asked" in statement.note()
