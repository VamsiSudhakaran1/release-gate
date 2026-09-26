"""Why this verdict — the whole walk, and the two places it used to break.

    verdict → condition/rule → subject/claim/action → evidence → source

The guard that matters is not that a trace exists; it is that no reason a
verdict names escapes it. A trace covering four of five reasons is worse than
none, because a reader would stop looking.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.corpus import _clean_release, _evidence, build_corpus, run_case
from release_gate.assurance.trace import (
    TRACE_SCHEMA_VERSION, Level, ReasonKind, TraceError, TraceStep, VerdictTrace,
    explain_hold, trace_verdict,
)


def _zero_config(document):
    """A case with no methodology at all — the shape that used to explain nothing."""
    from release_gate.assurance.ingest import detect_document, normalise
    from release_gate.assurance.zero_config import assure_normalisation
    rows = [dict(r) for r in document]
    content = ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()
    return assure_normalisation(
        normalise(rows, detect_document(rows, filename="why.jsonl"),
                  source="why.jsonl", content=content),
        source_name="why.jsonl", objective="Why HOLD?")


@pytest.fixture(scope="module")
def contradicted():
    """A HOLD a reviewer would actually ask about."""
    document = list(_clean_release())
    document.append(_evidence("counter-run", "TEST_RESULT", "ci://nightly", "",
                              contradicts_claims=["c-behaviour"]))
    return _zero_config(document)


@pytest.fixture(scope="module")
def frontier():
    from release_gate.demos import frontier_research
    return frontier_research.run().outcome


# ── the walk reaches the bottom ──────────────────────────────────────────────

class TestTheFiveLevels:

    def test_a_hold_traces_verdict_to_source(self, contradicted):
        trace = trace_verdict(contradicted)
        levels = {step.level for chain in trace.chains for step in chain}
        assert levels == {Level.VERDICT, Level.CONDITION, Level.SUBJECT,
                          Level.EVIDENCE, Level.SOURCE}

    def test_the_levels_appear_in_order_within_a_chain(self, contradicted):
        """A step that sat between two rungs would make the walk unreadable."""
        order = [Level.VERDICT, Level.CONDITION, Level.SUBJECT, Level.EVIDENCE,
                 Level.SOURCE]
        for chain in trace_verdict(contradicted).chains:
            seen = [order.index(step.level) for step in chain]
            assert seen[0] == 0, "every chain starts at the verdict"
            for earlier, later in zip(seen, seen[1:]):
                assert later <= earlier + 1, (
                    "a chain may descend one rung at a time or climb back up to "
                    "a sibling, never skip a rung")

    def test_it_names_the_producer_at_the_bottom(self, contradicted):
        sources = [step for chain in trace_verdict(contradicted).chains
                   for step in chain if step.level is Level.SOURCE]
        assert any("ci://nightly" in step.label for step in sources)

    def test_and_it_works_at_ten_thousand_agents(self, frontier):
        """The scale case. A walk that only works on a small case is not a walk
        anybody can rely on."""
        trace = trace_verdict(frontier)
        assert trace.decision == "BLOCK"
        assert trace.reaches_source
        sources = [step.label for chain in trace.chains for step in chain
                   if step.level is Level.SOURCE]
        assert any(label.startswith("worker://") for label in sources)


# ── nothing escapes it ───────────────────────────────────────────────────────

class TestNothingEscapes:

    def test_every_reason_on_every_corpus_case_is_accounted_for(self):
        """Either walked, or named in `unexplained` with why. Measured across
        all sixteen constructions rather than on one convenient case."""
        gaps = {}
        for case in build_corpus():
            outcome = run_case(case).outcome
            trace = trace_verdict(outcome)
            missing = [r for r in outcome.case.verdict.fired_rules
                       if r not in trace.walked and r not in trace.unexplained]
            if missing:
                gaps[case.case_id] = missing
        assert gaps == {}

    def test_and_every_non_promote_case_reaches_a_source(self):
        """A PROMOTE names only a policy clause and has no unresolved subject to
        descend to. Anything held or blocked must get to a producer."""
        for case in build_corpus():
            outcome = run_case(case).outcome
            if outcome.case.verdict.decision.value == "PROMOTE":
                continue
            assert trace_verdict(outcome).reaches_source, case.case_id

    def test_an_unownable_reason_is_named_not_dropped(self, contradicted):
        """A reason nobody can look up is not a reason — and it must not be
        quietly absent from the answer either."""
        import dataclasses
        broken = dataclasses.replace(
            contradicted.case.verdict,
            fired_rules=tuple(contradicted.case.verdict.fired_rules) + ("RG-NOPE-001",))
        case = dataclasses.replace(contradicted.case, verdict=broken)
        outcome = dataclasses.replace(contradicted, case=case)
        trace = trace_verdict(outcome)
        assert "RG-NOPE-001" in trace.unexplained
        assert trace.complete is False

    def test_a_subject_with_no_evidence_says_so(self, frontier):
        """Level 3 reached and level 4 empty looked identical to a chain nobody
        had walked. "No evidence bears on this" is the finding (Invariant 3)."""
        empties = [step for chain in trace_verdict(frontier).chains
                   for step in chain
                   if step.level is Level.EVIDENCE and step.identifier == "(none)"]
        assert empties
        assert "no evidence" in empties[0].label

    def test_a_case_with_no_verdict_is_refused_rather_than_traced(self):
        import dataclasses
        outcome = run_case(build_corpus()[0]).outcome
        undecided = dataclasses.replace(
            dataclasses.replace(outcome.case, verdict=None))
        with pytest.raises(TraceError, match="nothing to explain"):
            trace_verdict(dataclasses.replace(outcome, case=undecided))


# ── no opaque link ───────────────────────────────────────────────────────────

class TestNoOpaqueLink:
    """"No opaque classifier may break that path." Enforced structurally rather
    than asserted in prose."""

    def test_every_step_names_the_record_it_was_read_from(self, contradicted,
                                                          frontier):
        for outcome in (contradicted, frontier):
            for chain in trace_verdict(outcome).chains:
                for step in chain:
                    assert step.basis.strip(), (step.level, step.identifier)

    def test_a_step_without_a_basis_is_refused(self):
        with pytest.raises(TraceError, match="names no basis"):
            TraceStep(level=Level.EVIDENCE, identifier="ev_1", basis="")

    def test_a_computed_step_says_it_was_computed(self, contradicted):
        """Not a weakness — most interesting steps are derived — but a reader is
        entitled to know which rungs were read and which were worked out."""
        subjects = [step for chain in trace_verdict(contradicted).chains
                    for step in chain if step.level is Level.SUBJECT]
        assert subjects and all(step.derived for step in subjects)

    def test_no_model_assisted_record_appears_as_a_link(self, contradicted,
                                                        frontier):
        """A semantic proposal is a candidate permanently (§10r); it is evidence
        about a case, never a rung on the path that justifies a verdict."""
        for outcome in (contradicted, frontier):
            for chain in trace_verdict(outcome).chains:
                for step in chain:
                    assert "semantic_proposal" not in str(step.detail).lower()
                    assert step.detail.get("epistemic_status") != "PROPOSED"


# ── the two defects this found ───────────────────────────────────────────────

class TestTheDefectsFound:

    def test_a_hold_names_the_findings_that_caused_it(self, contradicted):
        """`decide()` extended `fired_rules` with every *blocking* rule id and
        not with the holding ones, so a BLOCK was traceable to its findings and
        a HOLD was not. `RG-ZC-003` said "structure held this" and a reviewer
        asking *which* structure had nowhere to go, because the ids only ever
        appeared inside prose."""
        fired = set(contradicted.case.verdict.fired_rules)
        holding = {f.rule_id for f in contradicted.analysis.holding}
        assert holding, "this fixture is meant to hold on structural findings"
        assert holding <= fired, holding - fired

    def test_and_those_findings_walk_all_the_way_down(self, contradicted):
        trace = trace_verdict(contradicted)
        holding = {f.rule_id for f in contradicted.analysis.holding}
        assert holding & set(trace.reaches_source), (
            "the findings that caused the HOLD reach no source")

    def test_a_predicate_names_what_it_counted(self, frontier):
        """"1 unresolved" without naming which one is a finding nobody can cite.
        The trace reached the requirement, had nothing to descend to, and
        stopped at the action node."""
        result = next(r for r in frontier.assessment.results
                      if r.requirement_id == "contradictions.resolved")
        named = [v for k, v in result.observed.items()
                 if k.startswith("unresolved_id_")]
        assert named, dict(result.observed)
        assert result.observed["unresolved"] == 1

    def test_and_the_id_it_names_is_followed_through_the_ledger(self, frontier):
        """One real hop: the contradiction is not evidence, and the record names
        the claims it is about. Reading that link is not guessing one from the
        requirement's name."""
        trace = trace_verdict(frontier)
        bases = [step.basis for chain in trace.chains for step in chain
                 if step.level is Level.SUBJECT]
        assert any("target claim of contra_" in basis for basis in bases), bases


# ── shape and rendering ──────────────────────────────────────────────────────

class TestShape:

    def test_a_policy_clause_stops_at_the_condition_and_is_not_a_gap(self):
        """It states how the decision was reached rather than being *about* a
        subject, so there is nothing below it. Reported apart from
        `unexplained`, because "nothing under this by its nature" and "I could
        not get under this" are different answers."""
        promoted = run_case(next(c for c in build_corpus()
                                 if c.case_id == "valid-release")).outcome
        trace = trace_verdict(promoted)
        assert trace.stopped_at_condition == ("RG-ZC-004",)
        assert trace.complete is True

    def test_the_trace_round_trips(self, contradicted):
        data = json.loads(json.dumps(trace_verdict(contradicted).to_dict()))
        assert data["schema_version"] == TRACE_SCHEMA_VERSION
        assert data["decision"] == "HOLD"
        assert data["chains"]

    def test_why_hold_reads_as_a_walk(self, contradicted):
        text = explain_hold(contradicted)
        assert text.startswith("VERDICT HOLD")
        assert text.count("VERDICT HOLD") == 1, "the verdict rung is printed once"
        for word in ("CONDITION", "SUBJECT", "EVIDENCE", "SOURCE", "via "):
            assert word in text

    def test_the_schema_is_registered(self):
        from release_gate.assurance.protocol import PROTOCOL
        assert any(s.constant == "TRACE_SCHEMA_VERSION" for s in PROTOCOL.schemas)

    def test_the_reason_kinds_are_the_four_a_verdict_can_name(self):
        assert {k.value for k in ReasonKind} == {
            "REQUIREMENT", "STRUCTURAL", "POLICY_CLAUSE", "LEDGER_ENTRY",
            "UNRECOGNISED"}
