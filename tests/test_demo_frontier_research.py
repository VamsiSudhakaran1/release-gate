"""The flagship demo, checked rather than admired.

Three things are asserted here and none of them is that the demo produces
pleasing output.

**Detection, never generation.** The scenario puts eleven phenomena in
deliberately; the demo is worth nothing unless the engine finds them without
being told where to look. Every phenomenon test asserts what the engine
concluded, not what the generator wrote.

**Every rendered line comes from the engine.** `render()` contains no literal
count, and each number in its output is re-derived here from an independent
engine call and compared. A report that drifts from the engine is worse than no
report, because it reads exactly like a true one.

**The reduction is real.** Ten thousand workers and two million records come out
as a number of things a person can actually read, and the verdict is never
PROMOTE on a case carrying an open contradiction, a live counterexample and an
unstated load-bearing assumption.

Most tests run a reduced scale. `test_the_full_scale_run` is the flagship and
runs the real thing; the shape assertions are written so they hold at both,
which is itself a property rather than an assumption.
"""

from __future__ import annotations

import re

import pytest

from release_gate.assurance.case import Decision
from release_gate.assurance.completeness import StreamCompleteness
from release_gate.assurance.verification import VerificationStatus
from release_gate.demos.frontier_research import (
    ASSUMPTION_ID, COPIED_CLAIM, DEFAULT_SCENARIO, RESULT_ID, STALE_CHECK_CLAIM,
    SUBJECT_DIGEST, SUPERSEDED_DIGEST, FrontierRun, ResearchScenario, render, run)

SMALL = DEFAULT_SCENARIO.scaled(400)


@pytest.fixture(scope="module")
def small() -> FrontierRun:
    return run(SMALL)


# ── the eleven phenomena, each DETECTED ─────────────────────────────────────

def test_ten_thousand_workers_are_observed_as_parties():
    """Not asserted by the scenario — counted by the independence analysis."""
    result = run(DEFAULT_SCENARIO)
    assert result.analysis.independence.contributors > 10_000


def test_shared_source_copying_collapses_to_one_lineage():
    """The central claim of the system, at the scale it is made for.

    Thousands of workers agreeing is one source observed thousands of times, and
    the engine reaches that from ancestry rather than from being told.
    """
    result = run(DEFAULT_SCENARIO)
    profile = result.analysis.independence
    assert profile.largest_ancestry_cluster > 8_000
    assert profile.concentration.value == "HIGH"


def test_multiple_independent_derivations_are_distinguished(small):
    """The copies collapse; genuinely separate work does not."""
    profile = small.analysis.independence
    assert profile.independent_roots > 1
    assert profile.largest_ancestry_cluster < profile.contributors


def test_formal_checker_output_is_credited_as_machine_checking(small):
    """`verification.machine_checked` is BLOCK and non-overridable in this
    methodology; a passing theorem prover must satisfy it."""
    result = next(r for r in small.outcome.assessment.results
                  if r.requirement_id == "verification.machine_checked")
    assert result.is_met, result.detail


def test_independent_verification_is_credited(small):
    result = next(r for r in small.outcome.assessment.results
                  if r.requirement_id == "independence.verification")
    assert result.is_met, result.detail


def test_a_counterexample_search_that_found_something_stays_open(small):
    ledger = small.analysis.counterexamples
    assert len(ledger.open()) == 1
    assert ledger.open()[0].target_claim == COPIED_CLAIM


def test_searches_that_found_nothing_are_not_counted_as_outstanding(small):
    """Seven searches, one of which found something. A blunt reading of
    `resolved` counted all seven."""
    ledger = small.analysis.counterexamples
    assert len(tuple(ledger.attempts)) > 1
    result = next(r for r in small.outcome.assessment.results
                  if r.requirement_id == "counterexamples.resolved")
    assert "1 unresolved" in result.detail


def test_failed_branches_are_retained(small):
    assert small.outcome.failed_branches
    assert len(small.outcome.failed_branches) > 1


def test_the_unstated_assumption_is_found_and_is_load_bearing(small):
    graph = small.analysis.assumptions
    unstated = [a for a in graph.load_bearing() if not a.source.stated]
    assert unstated, "an assumption named by a claim and described nowhere"
    assert any(ASSUMPTION_ID in str(a.to_dict()) for a in graph.assumptions)


def test_the_hidden_contradiction_is_detected(small):
    """Nothing tells the engine where it is; it falls out of evidence pointing
    both ways at one claim."""
    open_ones = small.analysis.contradictions.open()
    assert len(open_ones) == 1
    assert COPIED_CLAIM in open_ones[0].to_dict()["target_claims"]


def test_the_formal_check_against_a_superseded_digest_is_visible(small):
    """One prover run names a digest the derivation has moved past. The engine is
    not told; it compares what the check ran against with what the case holds."""
    graph = small.analysis.verification_graph
    stale = [a for a in graph.attempts
             if a.target_digest == SUPERSEDED_DIGEST]
    assert stale, "the scenario did not produce the stale check"
    assert stale[0].target.target_id == STALE_CHECK_CLAIM
    assert SUPERSEDED_DIGEST != SUBJECT_DIGEST


def test_the_incomplete_telemetry_source_prevents_a_completeness_claim(small):
    """S-4 emitted no sequence numbers, so a hole in it would leave no trace.
    Every stream the manifest names arrived, and the ledger still refuses
    COMPLETE."""
    assert small.completeness.status is StreamCompleteness.COMPLETENESS_UNKNOWN
    assert "S-4" in small.completeness.uncheckable_streams


# ── the reduction ───────────────────────────────────────────────────────────

def test_the_execution_reduces_to_between_three_and_eight_items(small):
    shown = small.outcome.attention.top(8)
    assert 3 <= len(shown) <= 8


def test_the_reduction_holds_at_full_scale():
    result = run(DEFAULT_SCENARIO)
    shown = result.outcome.attention.top(8)
    assert 3 <= len(shown) <= 8
    assert result.outcome.normalisation.records_seen > 2_000_000


def test_nothing_undroppable_is_dropped_to_make_the_list_fit(small):
    shown = small.outcome.attention.top(8)
    for item in small.outcome.attention.undroppable:
        assert item in shown


def test_the_verdict_is_never_promote(small):
    assert small.case.verdict.decision is not Decision.PROMOTE
    assert small.case.verdict.fired_rules


def test_the_report_refuses_to_claim_the_result_is_true(small):
    text = render(small)
    assert "has not evaluated whether the result is true" in text
    assert "Candidate Research Result" in text


# ── every rendered line comes from the engine ───────────────────────────────

def _value_after(text: str, label: str) -> str:
    lines = text.splitlines()
    return lines[lines.index(label) + 1].strip()


def test_the_renderer_contains_no_literal_count():
    """A number written into the renderer is a number that was true once."""
    import inspect

    from release_gate.demos import frontier_research

    source = inspect.getsource(frontier_research.render)
    # Only formatting literals and slice bounds may appear; any bare integer of
    # two digits or more would be a count.
    assert not re.search(r"(?<![\w:.>{])\d{2,}(?![\w}])", source), (
        "render() contains a literal number; every figure must be read from the "
        "engine")


def test_workers_observed_matches_the_independence_analysis(small):
    text = render(small)
    assert _value_after(text, "Workers observed:") == (
        f"{small.analysis.independence.contributors:,}")


def test_records_seen_matches_the_normalisation(small):
    text = render(small)
    assert _value_after(text, "Records seen at ingest:") == (
        f"{small.outcome.normalisation.records_seen:,}")


def test_the_dependency_graph_size_matches_the_claim_graph(small):
    text = render(small)
    assert _value_after(text, "Claims in final dependency graph:") == (
        f"{len(small.analysis.claim_graph):,}")


def test_critical_claims_matches_the_criticality_set(small):
    text = render(small)
    assert _value_after(text, "Critical claims:") == (
        str(len(small.analysis.criticality.critical_ids)))


def test_open_contradictions_matches_the_ledger(small):
    text = render(small)
    assert _value_after(text, "Open contradictions:") == (
        str(len(small.analysis.contradictions.open())))


def test_open_counterexamples_matches_the_ledger(small):
    text = render(small)
    assert _value_after(text, "Open counterexamples:") == (
        str(len(small.analysis.counterexamples.open())))


def test_completeness_matches_the_stream_ledger(small):
    text = render(small)
    assert _value_after(text, "Execution completeness:") == (
        small.completeness.status.value)


def test_the_verification_ratios_match_the_verification_graph(small):
    text = render(small)
    critical_ids = set(small.analysis.criticality.critical_ids)
    critical = len(critical_ids)
    passed = {a.target.target_id for a in small.analysis.verification_graph.attempts
              if a.status is VerificationStatus.PASSED
              and a.target.target_id in critical_ids}
    formal = {a.target.target_id for a in small.analysis.verification_graph.attempts
              if a.status is VerificationStatus.PASSED
              and a.target.target_id in critical_ids
              and a.method.value in ("FORMAL_PROOF", "THEOREM_PROVER")}
    assert _value_after(text, "Critical verification:") == f"{len(passed)} / {critical}"
    assert _value_after(text, "Formal verification:") == f"{len(formal)} / {critical}"


def test_the_verdict_line_matches_the_case(small):
    text = render(small)
    assert f"VERDICT: {small.case.verdict.decision.value}" in text


# ── determinism ─────────────────────────────────────────────────────────────

def test_the_same_scenario_produces_the_same_case_digest():
    assert run(SMALL).case.case_digest == run(SMALL).case.case_digest


def test_a_different_seed_produces_a_different_case():
    import dataclasses
    other = dataclasses.replace(SMALL, critical_claims=SMALL.critical_claims - 1)
    assert run(other).case.case_digest != run(SMALL).case.case_digest


def test_the_scale_divisor_is_validated():
    with pytest.raises(ValueError):
        DEFAULT_SCENARIO.scaled(0)


# ── the flagship ────────────────────────────────────────────────────────────

def test_the_full_scale_run():
    """Ten thousand workers, two million records, and a list a person can read."""
    result = run(DEFAULT_SCENARIO)
    text = render(result)

    assert result.analysis.independence.contributors > 10_000
    assert result.outcome.normalisation.records_seen > 2_000_000
    assert 3 <= len(result.outcome.attention.top(8)) <= 8
    assert result.case.verdict.decision is not Decision.PROMOTE
    assert RESULT_ID in text


def test_the_same_input_assured_a_second_later_is_the_same_case():
    """Identity is content, not clock.

    Records the engine derives — a contradiction it detected, a coverage row it
    wrote — stamp themselves with the engine's clock. Folding those stamps into
    the collection digests meant the same input assured one second apart produced
    two different `case_digest`s: §15's requirement that a local case and an API
    case agree could never hold, a re-assurance of identical input looked like a
    changed case to an approval, and the digest was useless as the thing two
    parties compare.
    """
    import time

    first = run(SMALL).case.case_digest
    time.sleep(1.1)
    assert run(SMALL).case.case_digest == first


def test_a_resolution_still_moves_the_digest():
    """The exclusion is clocks only.

    Anything else a record says — a contradiction's status, a coverage verdict —
    must still move the digest, because that is what the record is for.
    """
    from release_gate.assurance.contradiction import (
        Contradiction, ContradictionLedger, ContradictionSide)

    contradiction = Contradiction(
        target_claims=("c1",),
        sides=(ContradictionSide(label="for"), ContradictionSide(label="against")))
    resolved = contradiction.resolve("the numerical check was mis-scaled", ("ev_1",))
    assert ContradictionLedger((contradiction,)).digest() != (
        ContradictionLedger((resolved,)).digest())
