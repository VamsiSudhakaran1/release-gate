"""The one-screen case review, and the four ways it could mislead a reviewer.

What is under test is not that the layout is pleasant. It is that the screen
cannot say something the engine did not:

**No number is computed in the renderer.** Every digit run in the rendered text
is matched back to a field on the `CaseReview`. A report that recomputes a figure
is a second engine, and when the two disagree nothing on the page says which one
was wrong.

**A zero is never printed where nothing was established.** The three lines a
reader scans for reassurance — critical claims, verified, coverage — each have a
case where the truthful answer is "nobody assessed this", and printing `0` there
would be an assertion.

**The engine's words, not new ones.** Bands come from `RequirementPressure`;
coverage states from the ledger. No severity scale is invented on this screen.

**It cannot be read as a safety claim.** Four refusals, unconditional.
"""

from __future__ import annotations

import json
import re

import pytest

from release_gate.assurance.chaos import _assure, _base
from release_gate.assurance.compression import Basis
from release_gate.assurance.review import (
    REVIEW_SCHEMA_VERSION, AttentionLine, CaseReview, CoverageLine, Figure,
    ReviewError, SubjectLine, build_review, render_review,
)


@pytest.fixture(scope="module")
def outcome():
    return _assure(_base())


@pytest.fixture(scope="module")
def review(outcome):
    return build_review(outcome)


@pytest.fixture(scope="module")
def text(review):
    return render_review(review)


@pytest.fixture(scope="module")
def frontier():
    from release_gate.demos import frontier_research as fr
    return fr.run(fr.DEFAULT_SCENARIO.scaled(400)).outcome


# ── no number is computed in the renderer ────────────────────────────────────

_NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")


def _numbers(blob: str):
    return [m.group(0) for m in _NUMBER.finditer(blob)]


def _known(review: CaseReview):
    """Every number the review itself holds, as the renderer would print it."""
    known = set()
    for figure in review.figures():
        if figure.value is not None:
            known.add(f"{figure.value:,}")
            known.add(str(figure.value))
    for line in review.coverage:
        known.add(line.shown.rstrip("%"))
        for value in (line.expected, line.observed):
            if value is not None:
                known.add(f"{value:,}")
                known.add(str(value))
    return known


def _strings(review: CaseReview):
    """Text the review carries verbatim: identifiers, prose, digests.

    A digit inside one of these is part of a name the engine supplied, not a
    figure the renderer worked out.
    """
    parts = [review.case_id, review.objective, review.requested_decision,
             review.methodology, review.subject.digest, review.subject.basis,
             review.subject.method, review.subject.status, review.withheld,
             review.decision, *review.fired_rules, *review.not_assessed,
             *review.limits]
    for figure in review.figures():
        parts += [figure.label, figure.detail]
    for line in review.coverage:
        parts += [line.dimension, line.state]
    for item in review.attention:
        parts += [item.band, item.focus, item.why, item.criticality,
                  *item.resolves]
    parts.append(review.candidate)
    for line in review.state_lines:
        parts += [line.record_id, line.match, line.reason]
    parts.append(review.claim_policy)
    for line in review.claim_lines:
        parts += [line.claim_id, line.status, line.rule, line.statement, line.basis]
    return "\n".join(p for p in parts if p)


class TestEveryFigureIsAField:

    @pytest.mark.parametrize("case", ["simple", "frontier"])
    def test_no_number_in_the_text_is_the_renderers_own(self, case, review,
                                                        frontier):
        """The property this whole module is shaped around.

        Any digit run in the output must be a figure the review holds or part of
        a string it holds. A count, ratio or sum worked out in `render_review`
        would be in neither, and would be a number no other part of the engine
        can be checked against.
        """
        subject = review if case == "simple" else build_review(frontier)
        rendered = render_review(subject)
        known, strings = _known(subject), _strings(subject)
        for number in _numbers(rendered):
            assert number in known or number in strings, (
                f"{number!r} appears in the rendered review and is not a figure "
                f"the CaseReview holds — the renderer computed it")

    def test_the_layout_constants_are_the_only_literals(self):
        """`render_review`'s own numbers are padding widths, nothing else."""
        import ast
        import inspect

        from release_gate.assurance import review as module

        source = inspect.getsource(module.render_review)
        literals = [n.value for n in ast.walk(ast.parse(source.lstrip()))
                    if isinstance(n, ast.Constant) and isinstance(n.value, (int, float))
                    and not isinstance(n.value, bool)]
        assert literals == [], f"render_review contains numeric literals: {literals}"

    def test_a_figure_formats_itself_so_there_is_one_place_it_is_text(self):
        assert Figure("Claims", 2_184_992).shown == "2,184,992"
        assert Figure("Claims", None, Basis.NOT_ASSESSED).shown == "not assessed"
        assert Figure("Claims", 5, Basis.DECLARED).shown == "5 [DECLARED]"


# ── a zero is never printed where nothing was established ───────────────────

class TestUnknownIsNotZero:

    def test_a_figure_cannot_carry_a_count_nobody_established(self):
        with pytest.raises(ReviewError) as exc:
            Figure("Critical claims", 0, Basis.NOT_ASSESSED)
        assert "nobody assessed" in str(exc.value)

    def test_nor_claim_somebody_counted_and_show_no_count(self):
        with pytest.raises(ReviewError):
            Figure("Critical claims", None, Basis.OBSERVED)

    def test_a_negative_figure_is_refused(self):
        with pytest.raises(ReviewError):
            Figure("Claims", -1)

    def test_undeterminable_criticality_reads_not_assessed_not_zero(self):
        """The most damaging number this screen could print.

        `0 critical claims` on a case where reachability could not be derived
        reads as "nothing is load-bearing", which is the one thing a reviewer
        would act on (Invariant 3).
        """
        document = [r for r in _base() if r.get("record_type") != "claim"]
        figures = {f.label: f for f in build_review(_assure(document)).critical_path}
        critical = figures["Critical claims"]
        if not critical.known:
            assert critical.basis is Basis.NOT_ASSESSED
            assert "not assessed" in render_review(build_review(_assure(document)))

    def test_a_dimension_nobody_examined_is_named_not_given_a_percentage(self, review):
        """A plausible percentage over an unmeasured dimension is the worst
        single thing this file could print, because that is the number a reader
        scans for reassurance."""
        assert review.not_assessed
        shown = {line.dimension for line in review.coverage}
        assert not shown & set(review.not_assessed)
        for line in review.coverage:
            if line.ratio is None:
                assert "%" not in line.shown

    def test_a_figure_that_could_only_ever_read_zero_reads_not_assessed(self, frontier):
        """These three were counts that could not be anything but zero.

        The engine records a current digest for artifacts and for the subject —
        things with content to hash — and never for a claim, which is a statement
        rather than a blob. So no attempt on a claim is ever applicable, and
        `Verified: 0` was arithmetic wearing the clothes of a finding. A reader
        scanning the critical path saw three zeros and had no way to know none of
        them had been assessed (Invariant 3).
        """
        figures = {f.label: f for f in build_review(frontier).critical_path}
        for label in ("Verified", "Independently corroborated", "Formally verified"):
            assert not figures[label].known, f"{label} reads a number"
            assert figures[label].basis is Basis.NOT_ASSESSED
            assert "not computable here" in figures[label].detail

    def test_and_the_count_that_can_be_established_still_reads(self, frontier):
        """`Verification undetermined` is the one figure with real information on
        this case, and it must stay a number."""
        figures = {f.label: f for f in build_review(frontier).critical_path}
        assert figures["Verification undetermined"].value > 0

    def test_claim_targets_really_cannot_be_assessed(self, frontier):
        """The premise of the two tests above, re-derived from the graph.

        If this ever stops holding — if something starts recording a claim's
        current state — those figures become real counts and the tests above
        should fail rather than quietly keep asserting an absence.
        """
        graph = frontier.analysis.verification_graph
        claims = [t for t in graph.targets() if t.kind.value == "CLAIM"]
        assert claims
        assert all(graph.current_digest(t) is None for t in claims)
        assert all(graph.assess(t).applies == 0 for t in claims)


# ── formal verification means the checks that currently apply ────────────────

class TestFormalVerificationIsCurrent:

    def test_a_superseded_prover_run_is_not_current_verification(self):
        """`methods` lists what was ever tried; `passing_methods` what holds now.

        Reading the first for "formally verified" credits a prover run against a
        state the target has since left, which is precisely what recording
        `target_digest` exists to catch (Invariant 5).
        """
        from release_gate.assurance.verification import (
            VerificationAttempt, VerificationGraph, VerificationMethod,
            VerificationStatus, VerificationTarget)

        target = VerificationTarget.claim("C-1")
        graph = VerificationGraph((VerificationAttempt(
            method=VerificationMethod.THEOREM_PROVER, target=target,
            verifier="lean@4.8.0", target_digest="sha256:" + "a" * 64,
            status=VerificationStatus.PASSED),), digests={target.key: "sha256:" + "b" * 64})
        reading = graph.assess(target)
        assert "THEOREM_PROVER" in reading.methods
        assert reading.passing_methods == ()
        assert reading.verified is False

    def test_and_an_applicable_one_is(self):
        from release_gate.assurance.verification import (
            VerificationAttempt, VerificationGraph, VerificationMethod,
            VerificationStatus, VerificationTarget)

        digest = "sha256:" + "a" * 64
        target = VerificationTarget.claim("C-1")
        graph = VerificationGraph((VerificationAttempt(
            method=VerificationMethod.THEOREM_PROVER, target=target,
            verifier="lean@4.8.0", target_digest=digest,
            status=VerificationStatus.PASSED),), digests={target.key: digest})
        reading = graph.assess(target)
        assert reading.passing_methods == ("THEOREM_PROVER",)
        assert reading.verified is True


# ── the engine's words, not new ones ────────────────────────────────────────

class TestNoNewVocabulary:

    def test_bands_are_requirement_pressure(self, frontier):
        """Not a HIGH/MEDIUM severity. `BLOCKS` says a requirement of the stated
        methodology turns on this item; how bad that is remains the reviewer's
        judgement, and release-gate derives no such ranking."""
        from release_gate.assurance.attention import RequirementPressure

        bands = {line.band for line in build_review(frontier).attention}
        allowed = {p.value for p in RequirementPressure} | {"ADVISORY"}
        assert bands <= allowed
        assert not bands & {"HIGH", "MEDIUM", "LOW", "CRITICAL"}

    def test_coverage_states_are_the_ledgers(self, review, outcome):
        states = {line.state for line in review.coverage}
        ledger = {row.state.value for row in outcome.analysis.coverage_ledger.rows}
        assert states <= ledger

    def test_expert_judgment_counts_the_kinds_no_machine_closes(self):
        """A closed set read off the engine's own enum, so a new rule cannot
        quietly fall outside the count."""
        from release_gate.assurance.required_evidence import EvidenceRequirementKind
        from release_gate.assurance.review import _JUDGEMENT_KINDS

        values = {k.value for k in EvidenceRequirementKind}
        assert _JUDGEMENT_KINDS <= values
        assert "human_review" in _JUDGEMENT_KINDS
        assert "unspecified" in _JUDGEMENT_KINDS

    def test_and_it_is_a_real_count_not_a_placeholder(self):
        """`HUMAN_REVIEW` is reachable: five rules map to it. A field that could
        only ever read zero would be a distinction present in an enum and absent
        from the system."""
        from release_gate.assurance.required_evidence import (
            EvidenceRequirementKind, _RULE_KIND)

        mapped = [r for r, k in _RULE_KIND.items()
                  if k is EvidenceRequirementKind.HUMAN_REVIEW]
        assert mapped


# ── it cannot be read as a safety claim ─────────────────────────────────────

class TestTheRefusals:

    @pytest.mark.parametrize("claim", [
        "is_a_safety_assessment", "establishes_that_the_subject_is_correct",
        "a_shorter_attention_list_is_a_better_case",
        "completeness_of_this_report_implies_complete_evidence"])
    def test_they_are_unconditional(self, claim, review):
        assert getattr(review, claim) is False
        assert getattr(CaseReview(), claim) is False

    def test_the_shorter_list_refusal_is_the_one_that_would_do_damage(self, text):
        """A short list can mean the argument narrowed cleanly or that detection
        found less, and nothing on the screen tells them apart (Invariant 6)."""
        assert "A shorter list is not a better case." in text

    def test_the_screen_says_it_has_not_evaluated_correctness(self, text):
        assert "has not evaluated whether the subject is correct" in text

    def test_and_that_not_assessed_is_not_a_clean_bill(self, text):
        assert "not the same as measured and found clean" in text

    def test_the_serialised_form_carries_the_refusals_too(self, review):
        data = json.loads(json.dumps(review.to_dict()))
        assert data["is_a_safety_assessment"] is False
        assert data["establishes_that_the_subject_is_correct"] is False
        assert data["schema_version"] == REVIEW_SCHEMA_VERSION


# ── the review reads, and only reads ────────────────────────────────────────

class TestItOnlyReads:

    def test_building_twice_gives_the_same_review(self, outcome):
        assert build_review(outcome).to_dict() == build_review(outcome).to_dict()

    def test_it_reaches_for_no_clock(self):
        """A figure that moved between two builds of one outcome would make the
        review unreproducible, and a review that cannot be reproduced cannot be
        the thing an approval was taken against (Invariant 4)."""
        import ast
        import inspect

        from release_gate.assurance import review as module

        tree = ast.parse(inspect.getsource(module))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert not names & {"monotonic", "time", "now", "perf_counter"}
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                   for a in n.names}
        assert "time" not in imports and "random" not in imports

    def test_an_outcome_with_no_case_is_refused(self):
        class Bare:
            case = None
        with pytest.raises(ReviewError) as exc:
            build_review(Bare())
        assert "no case" in str(exc.value)

    def test_an_empty_review_renders_without_asserting_anything(self):
        rendered = render_review(CaseReview())
        assert "ASSURANCE CASE" in rendered
        assert "VERDICT" in rendered


# ── the ingest tally the execution figures rest on ──────────────────────────

class TestTheTallyReconciles:

    def test_the_breakdown_accounts_for_the_total(self, outcome):
        normalisation = outcome.normalisation
        assert normalisation.records_unaccounted == (
            normalisation.records_seen
            - sum(normalisation.records_seen_by_kind.values()))

    def test_an_unclassifiable_row_is_counted_but_not_by_kind(self):
        """The one honest reason the two numbers differ.

        A row naming no `record_type` arrived — release-gate saw it — and no kind
        can account for it. That difference is reported as a figure rather than
        left as a shortfall for a reader to discover by subtracting.
        """
        document = list(_base()) + [{"no_record_type": True}]
        normalisation = _assure(document).normalisation
        assert normalisation.records_unaccounted > 0
        labels = {f.label for f in build_review(_assure(document)).execution}
        assert "Records no kind accounts for" in labels

    def test_and_that_line_is_absent_when_there_is_nothing_to_explain(self, outcome):
        labels = {f.label for f in build_review(outcome).execution}
        if outcome.normalisation.records_unaccounted == 0:
            assert "Records no kind accounts for" not in labels

    def test_an_absent_kind_is_not_read_as_a_count_of_zero(self):
        """Only the envelope path counts by kind, so a missing key means nobody
        counted rather than that there were none (Invariant 3)."""
        from release_gate.assurance.review import _tally

        class Bare:
            class normalisation:
                records_seen_by_kind = {"claim": 3}
        assert _tally(Bare(), "execution") is None
        assert _tally(Bare(), "claim") == 3


# ── what the live demo showed for a real Phoenix export ─────────────────────

class TestTheReviewDoesNotUnderstateOrOverstate:
    """Three lines of the one-screen review, each found misleading on a real
    agent trace (Arize's published Phoenix export of a LangGraph run)."""

    def _trace_review(self):
        import pathlib

        from release_gate.assurance.zero_config import assure
        root = pathlib.Path(__file__).resolve().parent.parent
        return build_review(assure(str(root / "examples" / "agents"
                                       / "01-coding-agent-otel.json")))

    def test_an_item_holding_the_case_is_never_banded_advisory(self):
        """With no methodology there is no requirement pressure, and the band
        read ADVISORY on the items the verdict fired on. The item's own effect
        is the floor."""
        review = self._trace_review()
        assert review.decision == "HOLD"
        bands = {line.focus: line.band for line in review.attention}
        assert bands["METHODOLOGY_REQUIRED"] == "HOLDS"
        assert bands["RG-VERIF-001"] == "HOLDS"
        assert "ADVISORY" not in bands.values()

    def test_a_ratio_over_nothing_is_not_printed_as_a_percentage(self):
        from release_gate.assurance.review import CoverageLine
        empty = CoverageLine("record_mapping", "OBSERVED", ratio=1.0,
                             expected=0, observed=0)
        assert empty.shown == "0 of 0"
        full = CoverageLine("record_mapping", "OBSERVED", ratio=1.0,
                            expected=12, observed=12)
        assert full.shown == "100.0%"

    def test_a_traces_spans_are_execution_records_not_unclassified_ones(self):
        review = self._trace_review()
        figures = {f.label: f.value for f in review.execution}
        assert figures["Execution records"] == 9
        assert "Records no kind accounts for" not in figures
