"""What the three verdicts mean, checked rather than asserted.

The definitions used to live only in prose a caller never reads: `Decision` was
three bare strings, PROMOTE's four refusals were a paragraph in a docstring, and
"a HOLD should return required evidence" was a convention nothing enforced.

So the tests here are about the semantics being *load-bearing*. The four
refusals are properties other code can assert on. A HOLD that names nothing is
reported as the shrug it is. A BLOCK is asked whether its reasons are actually
non-overridable, because its definition turns on that. And the exit codes do not
move, because CI jobs depend on them.
"""

from __future__ import annotations

import dataclasses

import pytest

from release_gate.assurance.case import Decision
from release_gate.assurance.methodologies import (
    GENERAL_AUTONOMOUS_ACTION_V1, RESEARCH_MATHEMATICS_V1)
from release_gate.assurance.verdict import (
    VerdictError, VerdictStatement, explain_verdict)
from release_gate.assurance.zero_config import exit_code_for
from release_gate.demos.frontier_research import DEFAULT_SCENARIO as FRONTIER
from release_gate.demos.frontier_research import run as run_frontier
from release_gate.demos.single_agent import DEFAULT_SCENARIO as MIGRATION
from release_gate.demos.single_agent import run as run_single


@pytest.fixture(scope="module")
def promoted():
    return explain_verdict(run_single().outcome,
                           methodology=GENERAL_AUTONOMOUS_ACTION_V1)


@pytest.fixture(scope="module")
def held():
    raised = dataclasses.replace(MIGRATION, reversibility="IRREVERSIBLE")
    return explain_verdict(run_single(raised).outcome,
                           methodology=GENERAL_AUTONOMOUS_ACTION_V1)


@pytest.fixture(scope="module")
def blocked():
    return explain_verdict(run_frontier(FRONTIER.scaled(400)).outcome,
                           methodology=RESEARCH_MATHEMATICS_V1)


# ── the three are preserved ─────────────────────────────────────────────────

def test_there_are_exactly_three_verdicts():
    assert [d.value for d in Decision] == ["PROMOTE", "HOLD", "BLOCK"]


def test_the_exit_codes_are_unchanged():
    """CI jobs depend on these. 0 PROMOTE · 10 HOLD · 1 BLOCK."""
    assert Decision.PROMOTE.exit_code == 0
    assert Decision.HOLD.exit_code == 10
    assert Decision.BLOCK.exit_code == 1


def test_the_decision_delegates_rather_than_restating_the_mapping():
    """Two copies of a CI contract drift, and the one that drifts is the one
    nobody is running."""
    for decision in Decision:
        assert decision.exit_code == exit_code_for(decision)


def test_each_verdict_carries_its_definition():
    assert "next authorization boundary" in Decision.PROMOTE.definition
    assert "More evidence, verification, methodology or resolution" in (
        Decision.HOLD.definition)
    assert "non-overridable violation" in Decision.BLOCK.definition


# ── PROMOTE does not mean four things ───────────────────────────────────────

def test_promote_states_the_four_things_it_does_not_mean():
    stated = " ".join(Decision.PROMOTE.does_not_mean)
    assert "executed automatically" in stated
    assert "is true" in stated
    assert "is safe" in stated
    assert "human approval already exists" in stated


def test_the_other_two_claim_nothing_to_deny():
    assert Decision.HOLD.does_not_mean == ()
    assert Decision.BLOCK.does_not_mean == ()


@pytest.mark.parametrize("fixture", ["promoted", "held", "blocked"])
def test_the_four_refusals_hold_for_every_verdict(fixture, request):
    """Properties, not prose. A paragraph can be skipped by the code that
    matters; a property can be asserted on."""
    statement = request.getfixturevalue(fixture)
    assert statement.authorises_execution is False
    assert statement.establishes_truth is False
    assert statement.establishes_safety is False
    assert statement.human_approval_exists is False


def test_the_refusals_are_in_the_serialised_form(promoted):
    payload = promoted.to_dict()
    for key in ("authorises_execution", "establishes_truth",
                "establishes_safety", "human_approval_exists"):
        assert payload[key] is False


def test_a_promote_reads_as_reaching_a_boundary_not_crossing_it(promoted):
    assert promoted.decision is Decision.PROMOTE
    assert "does not mean" in promoted.note()
    assert "executed automatically" in promoted.note()


# ── a HOLD should say what would resolve it ─────────────────────────────────

def test_a_hold_returns_required_evidence(held):
    assert held.decision is Decision.HOLD
    assert held.required_evidence
    assert held.resolution_is_actionable
    assert not held.is_a_shrug


def test_the_required_evidence_names_a_target_and_a_requirement(held):
    first = held.required_evidence[0]
    assert first.get("target")
    assert first.get("requirement")
    assert first.get("reason")


def test_a_hold_that_names_nothing_is_reported_as_a_shrug(held):
    """"More evidence is required" without saying which is the answer this
    engine exists to stop giving."""
    empty = dataclasses.replace(held, required_evidence=())
    assert empty.is_a_shrug
    assert not empty.resolution_is_actionable
    assert "exists to stop giving" in empty.note()


def test_the_question_does_not_arise_for_the_other_two(promoted, blocked):
    for statement in (promoted, blocked):
        assert not statement.resolution_is_actionable
        assert not statement.is_a_shrug


# ── a BLOCK claims non-overridability, so it is asked ───────────────────────

def test_a_block_states_whether_its_reasons_can_be_waived(blocked):
    assert blocked.decision is Decision.BLOCK
    assert blocked.non_overridable_reasons
    assert blocked.block_is_fully_non_overridable
    assert "does not permit waiving" in blocked.note()


def test_an_overridable_reason_is_named_rather_than_implied(blocked):
    """The difference between "nobody may proceed" and "somebody with the right
    role may" is one a reader should not have to guess at."""
    softened = dataclasses.replace(
        blocked, overridable_reasons=("coverage.lemma verification",))
    assert not softened.block_is_fully_non_overridable
    assert "would permit waiving" in softened.note()


def test_overridability_is_left_empty_when_nobody_asked():
    """"No methodology said this was waivable" and "nobody asked" are different
    facts, and only the first is about the case."""
    statement = explain_verdict(run_single().outcome)
    assert statement.overridable_reasons == ()
    assert statement.non_overridable_reasons == ()


def test_silence_in_a_methodology_reads_as_not_waivable(blocked):
    """`can_override` already takes the conservative direction; this pins it."""
    for rule_id in blocked.non_overridable_reasons:
        assert not RESEARCH_MATHEMATICS_V1.can_override(rule_id).permitted


# ── construction discipline ─────────────────────────────────────────────────

def test_a_statement_must_name_the_rules_behind_it():
    with pytest.raises(VerdictError, match="must name the rules"):
        VerdictStatement(decision=Decision.PROMOTE, fired_rules=())


def test_a_case_with_no_verdict_cannot_be_explained():
    from release_gate.assurance.session import AssuranceSession

    session = AssuranceSession.open()
    with pytest.raises(VerdictError, match="carries no verdict"):
        explain_verdict(session.case if hasattr(session, "case") else object())


def test_the_statement_round_trips_its_meaning(promoted):
    payload = promoted.to_dict()
    assert payload["definition"] == Decision.PROMOTE.definition
    assert payload["exit_code"] == 0
    assert len(payload["does_not_mean"]) == 4


def test_methodology_ref_is_refused_by_name_not_by_attribute_error():
    """`case.methodology` is a ref, not the document, and it is what a caller
    reaches for first. It must say which one is wanted."""
    run = run_single()
    with pytest.raises(VerdictError) as excinfo:
        explain_verdict(run.outcome, methodology=run.outcome.case.methodology)
    message = str(excinfo.value)
    assert "MethodologyRef" in message
    assert "AssuranceMethodology" in message
