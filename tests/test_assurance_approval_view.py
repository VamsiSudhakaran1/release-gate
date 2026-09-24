"""The last surface before a person acts, and the one question it answers.

    What exactly am I taking responsibility for if I click Approve?

Three properties carry this file. Every one of the nine required displays is
present and carries real content — a display that reads as a stated absence on a
case that has the data is worse than a missing one, because it looks like a fact.
Nothing blocking or on the critical path can sit below the evidence or below the
actions, and that is a constructor error rather than a rendering convention.
And all three actions are offered together, each bound to exact state, because
showing approve without request-evidence makes declining look like obstruction.
"""

from __future__ import annotations

import dataclasses

import pytest

from release_gate.assurance.approval import (
    ApprovalDecision, SubmissionOutcome, submit_approval, AuthSource)
from release_gate.assurance.approval_view import (
    REQUIRED_DISPLAYS, ActionOffer, ApprovalAction, ApprovalView,
    ApprovalViewError, build_view, render_view)
from release_gate.assurance.completeness import SourceStream, StreamLedger
from release_gate.demos.frontier_research import DEFAULT_SCENARIO as FRONTIER
from release_gate.demos.frontier_research import run as run_frontier
from release_gate.demos.single_agent import run as run_single


@pytest.fixture(scope="module")
def promoted():
    return build_view(run_single().outcome)


@pytest.fixture(scope="module")
def blocked():
    result = run_frontier(FRONTIER.scaled(400))
    return build_view(result.outcome, completeness=result.completeness)


# ── the nine displays ───────────────────────────────────────────────────────

@pytest.mark.parametrize("key", REQUIRED_DISPLAYS)
def test_every_required_display_is_present(promoted, key):
    assert promoted.display(key) is not None


def test_a_view_missing_a_display_is_refused(promoted):
    thinned = {k: v for k, v in promoted.displays.items() if k != "coverage"}
    with pytest.raises(ApprovalViewError, match="must show coverage"):
        dataclasses.replace(promoted, displays=thinned)


@pytest.mark.parametrize("label", [
    "EXPECTED EFFECT", "WHAT IT RESTS ON", "WHAT WAS NOT ASSESSED"])
def test_the_displays_carry_real_content_not_a_stated_absence(promoted, label):
    """The failure this guards against was real: `outcome.packet` is a method,
    taking it as an attribute yielded a bound method, and a swallowed
    AttributeError rendered every section as "not produced" — a wiring bug
    presented as a fact about the case."""
    lines = render_view(promoted).splitlines()
    body = lines[lines.index(label) + 1].strip()
    assert body
    assert "not produced" not in body
    assert body not in ("(not stated)", "(none recorded)", "(nothing recorded)")


def test_the_two_subject_digests_are_shown_apart(promoted):
    digests = promoted.display("subject_digest")
    assert digests["content"]
    assert digests["binds_to"]
    assert digests["content"] != digests["binds_to"]
    text = render_view(promoted)
    assert "your approval binds to" in text


def test_the_exact_case_and_evidence_state_is_shown(promoted):
    state = promoted.display("case_state")
    assert state["case_digest"] and state["evidence_digest"]
    text = render_view(promoted)
    assert state["case_digest"] in text
    assert state["evidence_digest"] in text


def test_completeness_unasked_is_shown_as_unanswered_not_clean(promoted):
    """`AnalysisResult` has no completeness field; a ledger is caller-supplied.
    Saying nothing would read as nothing wrong."""
    completeness = promoted.display("completeness")
    assert completeness["status"] == "NOT_ASSESSED"
    assert "not a clean answer" in completeness["note"]


def test_a_supplied_ledger_is_shown(blocked):
    assert blocked.display("completeness")["status"] == "COMPLETENESS_UNKNOWN"
    assert "S-4" in blocked.display("completeness")["uncheckable_streams"]


# ── nothing high-impact can be buried ───────────────────────────────────────

def test_blocking_items_appear_above_the_evidence_and_the_actions(blocked):
    text = render_view(blocked)
    unresolved_at = text.index("UNRESOLVED — READ BEFORE ANYTHING BELOW")
    assert unresolved_at < text.index("WHAT IT RESTS ON")
    assert unresolved_at < text.index("[APPROVE]")


def test_every_blocking_item_is_in_the_unresolved_block(blocked):
    shown = {i["id"] for i in blocked.unresolved}
    for item in blocked.display("unresolved")["undroppable"]:
        assert item["id"] in shown


def test_a_view_that_omits_an_undroppable_item_cannot_be_built(blocked):
    """A convention drifts the first time someone adds a section; a constructor
    error does not."""
    undroppable = blocked.display("unresolved")["undroppable"]
    assert undroppable, "the fixture must carry something undroppable"
    with pytest.raises(ApprovalViewError, match="not in the unresolved block"):
        dataclasses.replace(blocked, unresolved=())


def test_blocking_items_are_marked_so_the_eye_catches_them(blocked):
    text = render_view(blocked)
    assert "!!" in text


def test_an_empty_unresolved_block_says_what_it_means():
    """"Nothing found" is a report of what was looked for, never a guarantee."""
    view = build_view(run_single().outcome)
    empty = dataclasses.replace(
        view, unresolved=(),
        displays={**view.displays,
                  "unresolved": {**view.displays["unresolved"], "undroppable": []}})
    text = render_view(empty)
    assert "not a guarantee that nothing exists" in text


# ── three actions, each bound ───────────────────────────────────────────────

def test_all_three_actions_are_offered(promoted):
    assert {a.action for a in promoted.actions} == set(ApprovalAction)


def test_offering_fewer_than_three_is_refused(promoted):
    with pytest.raises(ApprovalViewError, match="all three actions"):
        dataclasses.replace(
            promoted,
            actions=tuple(a for a in promoted.actions
                          if a.action is not ApprovalAction.REQUEST_EVIDENCE))


def test_request_evidence_is_deferral_with_a_work_order(promoted):
    offer = promoted.action(ApprovalAction.REQUEST_EVIDENCE)
    assert offer.decision is ApprovalDecision.DEFERRED
    assert "required_evidence" in offer.payload


def test_every_action_states_what_taking_it_means():
    with pytest.raises(ApprovalViewError, match="must say what taking it means"):
        ActionOffer(action=ApprovalAction.APPROVE,
                    decision=ApprovalDecision.APPROVED, means="")


def test_each_action_binds_to_the_same_exact_state(promoted):
    binds = [a.binds_to for a in promoted.actions]
    assert all(b == binds[0] for b in binds)
    assert binds[0]["case_digest"] and binds[0]["subject_digest"]


def test_approving_over_a_hold_says_so(blocked):
    caution = blocked.action(ApprovalAction.APPROVE).caution
    assert "recorded as having made" in caution


# ── the acknowledgement is the real one ─────────────────────────────────────

def test_the_acknowledgement_is_accepted_by_the_engine():
    """Not a token: the values a client acknowledges are the ones
    `submit_approval` verifies against the live case."""
    outcome = run_single().outcome
    view = build_view(outcome)
    submission = submit_approval(
        outcome.case, view.acknowledgement, approver="human://alice",
        auth_source=AuthSource.API_KEY, scope="apply migration.sql to prod-eu")
    assert submission.outcome is SubmissionOutcome.ACCEPTED, submission.reasons


def test_a_stale_acknowledgement_is_refused():
    outcome = run_single().outcome
    view = build_view(outcome)
    stale = dataclasses.replace(view.acknowledgement, case_version=99)
    submission = submit_approval(
        outcome.case, stale, approver="human://alice",
        auth_source=AuthSource.API_KEY)
    assert submission.outcome is not SubmissionOutcome.ACCEPTED


# ── the view never authorises ───────────────────────────────────────────────

def test_the_view_never_authorises(promoted):
    assert promoted.authorises is False
    assert promoted.establishes_truth is False
    assert promoted.to_dict()["authorises"] is False


def test_the_render_says_whose_the_act_is(promoted):
    assert "The authorisation is yours." in render_view(promoted)


def test_a_view_needs_a_decided_outcome():
    with pytest.raises(ApprovalViewError, match="needs a decided outcome"):
        build_view(object())


def test_a_view_refuses_something_that_is_not_a_packet():
    """A wiring error must raise rather than render as an absent section."""
    outcome = run_single().outcome

    class Broken:
        case = outcome.case
        analysis = outcome.analysis
        attention = outcome.attention
        required_evidence = outcome.required_evidence

        def packet(self):
            return "not a packet"

    with pytest.raises(ApprovalViewError, match="not an approval packet"):
        build_view(Broken())
