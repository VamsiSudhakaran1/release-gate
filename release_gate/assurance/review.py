"""The case review — one screen a person reads before authorising, or not.

    ASSURANCE CASE
    Publish candidate research result RG-1842 as verified

    EXECUTION
    Workers observed                         10,248
    Execution records                     2,184,992
    ...

**Every figure printed here is a field on `CaseReview`.** `render_review` formats
and aligns; it computes nothing, holds no literal count, and derives no ratio.
That is not a style preference — a report that quietly recomputes a number is a
second engine, and when the two disagree the reader has no way to tell which one
was wrong. `tests/test_assurance_review.py` extracts every digit run from the
rendered text and fails if one of them is not in the review's own figures.

**A figure carries who established it.** The three-way `Basis` from the
compression funnel is reused rather than restated: OBSERVED means release-gate
counted it, DECLARED means somebody else stated it and we are repeating it in
their name, NOT_ASSESSED means nobody established it and the line shows no
number. A stage with no number prints `not assessed`, never `0` (Invariant 3).

**The attention band is the engine's word, not a severity.** Items are banded by
`RequirementPressure` — BLOCKS, HOLDS, UNASSESSED — because that is what the
engine derived. A `[HIGH]`/`[MEDIUM]` scale would read as a judgement about how
bad something is, which is a claim release-gate is not in a position to make: an
item BLOCKS because a requirement of the stated methodology turns on it, and
whether that matters more than something else is the reviewer's call.

**Coverage is whatever the ledger holds.** A percentage appears only where an
expectation supplied a denominator. Dimensions the ledger examined without
finding one read UNKNOWN; dimensions nobody examined are listed under NOT
ASSESSED by name. A review that printed a plausible percentage for a dimension
the case never measured would be the single most damaging thing in this file,
because that is the number a reader scans for reassurance.

**What this is not.** It is not a safety assessment, it does not establish that
the subject is correct, and a shorter attention list is not a better case — each
refused below as an unconditional property rather than discouraged in prose,
because the shape of a one-screen summary invites all three readings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from release_gate.assurance.compression import Basis

__all__ = [
    "REVIEW_SCHEMA_VERSION",
    "AttentionLine",
    "CaseReview",
    "CoverageLine",
    "Figure",
    "ReviewError",
    "SubjectLine",
    "build_review",
    "render_review",
]

REVIEW_SCHEMA_VERSION = 1

#: Width of the horizontal rules, and the column the figures are right-aligned
#: to. Named so that the only numbers `render_review` contains are layout.
RULE_WIDTH = 52
VALUE_COLUMN = 44


class ReviewError(ValueError):
    """A review line that cannot be shown honestly."""


@dataclass(frozen=True)
class Figure:
    """One labelled count, and who established it.

    `value` is `None` exactly when `basis` is NOT_ASSESSED, and the pair is
    checked rather than trusted: the two ways this type could lie are a count
    with nobody behind it and a basis claiming somebody counted with no count to
    show.
    """

    label: str
    value: Optional[int]
    basis: Basis = Basis.OBSERVED
    #: What the count is of, where the label alone would be read too widely.
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "basis", Basis(self.basis))
        if self.value is not None and self.value < 0:
            raise ReviewError(f"{self.label}: a figure cannot hold {self.value}")
        if self.basis is Basis.NOT_ASSESSED and self.value is not None:
            raise ReviewError(
                f"{self.label}: nobody assessed this, so it cannot also carry "
                f"{self.value}. If something established it, say who")
        if self.basis is not Basis.NOT_ASSESSED and self.value is None:
            raise ReviewError(
                f"{self.label}: basis {self.basis.value} says somebody counted "
                "this, so it needs a count")

    @property
    def known(self) -> bool:
        return self.value is not None

    @property
    def shown(self) -> str:
        """The exact text the renderer prints. Formatted here, not there."""
        if self.value is None:
            return "not assessed"
        mark = "" if self.basis is Basis.OBSERVED else f" [{self.basis.value}]"
        return f"{self.value:,}{mark}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "review_figure", "record_id": self.label,
                "label": self.label, "value": self.value,
                "basis": self.basis.value, "detail": self.detail,
                "shown": self.shown}


@dataclass(frozen=True)
class SubjectLine:
    """What the decision is about, and how firmly that is pinned.

    The digest and its status travel together always. A digest release-gate
    computed and a digest a producer asserted look identical on the page, and the
    difference is whether an approval can bind to it at all (Invariant 5).
    """

    digest: str = ""
    method: str = ""
    status: str = ""
    basis: str = ""

    @property
    def shown(self) -> str:
        if not self.digest:
            return "no digest — the subject is not pinned to any exact state"
        return f"{self.digest}  [{self.status or 'UNKNOWN'}]"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "review_subject", "record_id": self.digest,
                "digest": self.digest, "method": self.method,
                "status": self.status, "basis": self.basis, "shown": self.shown}


@dataclass(frozen=True)
class CoverageLine:
    """One coverage dimension as the ledger has it.

    `shown` is computed here so the renderer never turns a ratio into a
    percentage: rounding is arithmetic, and arithmetic in a renderer is how two
    parts of a system come to print different numbers for the same thing.
    """

    dimension: str
    state: str
    ratio: Optional[float] = None
    expected: Optional[int] = None
    observed: Optional[int] = None

    @property
    def shown(self) -> str:
        if self.ratio is None:
            return self.state
        return f"{self.ratio * 100:.1f}%"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "review_coverage", "record_id": self.dimension,
                "dimension": self.dimension, "state": self.state,
                "ratio": self.ratio, "expected": self.expected,
                "observed": self.observed, "shown": self.shown}


@dataclass(frozen=True)
class AttentionLine:
    """One thing a person has to look at, and what would settle it."""

    band: str
    focus: str
    why: str = ""
    resolves: Tuple[str, ...] = ()
    undroppable: bool = False
    criticality: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "review_attention", "record_id": self.focus,
                "band": self.band, "focus": self.focus, "why": self.why,
                "resolves": list(self.resolves), "undroppable": self.undroppable,
                "criticality": self.criticality}


@dataclass(frozen=True)
class CaseReview:
    """The whole screen, typed. Nothing in `render_review` is not in here."""

    case_id: str = ""
    objective: str = ""
    requested_decision: str = ""
    methodology: str = ""
    subject: SubjectLine = field(default_factory=SubjectLine)
    execution: Tuple[Figure, ...] = ()
    critical_path: Tuple[Figure, ...] = ()
    coverage: Tuple[CoverageLine, ...] = ()
    #: Dimensions nobody examined, by name. Listed rather than counted: "3
    #: dimensions not assessed" tells a reviewer nothing they can act on.
    not_assessed: Tuple[str, ...] = ()
    attention: Tuple[AttentionLine, ...] = ()
    #: Items the ranking held back, in the engine's own words, or empty.
    withheld: str = ""
    review_items: Figure = field(
        default_factory=lambda: Figure("Human review items", 0))
    #: What the review-item count was taken over, so a reduction is legible
    #: without inviting the reading that a bigger one is better.
    counted_over: Optional[Figure] = None
    decision: str = ""
    fired_rules: Tuple[str, ...] = ()
    required_evidence: Figure = field(
        default_factory=lambda: Figure("Required evidence", 0))
    expert_judgment: Figure = field(
        default_factory=lambda: Figure("Expert judgment items", 0))
    limits: Tuple[str, ...] = ()

    # ── what a one-screen summary must not be read as ────────────────────────
    @property
    def is_a_safety_assessment(self) -> bool:
        """Unconditionally false. It reports what the evidence establishes."""
        return False

    @property
    def establishes_that_the_subject_is_correct(self) -> bool:
        """Unconditionally false (Invariant 10). No verdict certifies truth."""
        return False

    @property
    def a_shorter_attention_list_is_a_better_case(self) -> bool:
        """Unconditionally false (Invariant 6).

        A short list can mean the argument narrowed cleanly or that detection
        found less, and nothing on this screen tells them apart.
        """
        return False

    @property
    def completeness_of_this_report_implies_complete_evidence(self) -> bool:
        """Unconditionally false. Every section can be filled over a case with
        gaps, which is why the gaps are named on it."""
        return False

    def figures(self) -> Tuple[Figure, ...]:
        """Every `Figure` the review holds, in the order they are printed."""
        tail = [self.review_items, self.required_evidence, self.expert_judgment]
        if self.counted_over is not None:
            tail.insert(1, self.counted_over)
        return tuple(self.execution) + tuple(self.critical_path) + tuple(tail)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "case_review", "record_id": self.case_id,
            "schema_version": REVIEW_SCHEMA_VERSION,
            "case_id": self.case_id, "objective": self.objective,
            "requested_decision": self.requested_decision,
            "methodology": self.methodology, "subject": self.subject.to_dict(),
            "execution": [f.to_dict() for f in self.execution],
            "critical_path": [f.to_dict() for f in self.critical_path],
            "coverage": [c.to_dict() for c in self.coverage],
            "not_assessed": list(self.not_assessed),
            "attention": [a.to_dict() for a in self.attention],
            "withheld": self.withheld,
            "review_items": self.review_items.to_dict(),
            "counted_over": (self.counted_over.to_dict()
                             if self.counted_over is not None else None),
            "decision": self.decision, "fired_rules": list(self.fired_rules),
            "required_evidence": self.required_evidence.to_dict(),
            "expert_judgment": self.expert_judgment.to_dict(),
            "limits": list(self.limits),
            "is_a_safety_assessment": self.is_a_safety_assessment,
            "establishes_that_the_subject_is_correct":
                self.establishes_that_the_subject_is_correct,
            "a_shorter_attention_list_is_a_better_case":
                self.a_shorter_attention_list_is_a_better_case,
            "completeness_of_this_report_implies_complete_evidence":
                self.completeness_of_this_report_implies_complete_evidence,
        }


# ── reading the engine ───────────────────────────────────────────────────────

#: Requirement kinds no machine closes. `HUMAN_REVIEW` is a rule saying so;
#: `UNSPECIFIED` is release-gate seeing a gap and not being able to name a
#: closer for it. Both land on a person, and grouping them is the honest answer
#: to "how much of this needs judgement" — a closed set read off the engine's own
#: enum, so a new rule cannot quietly fall outside the count.
_JUDGEMENT_KINDS = frozenset({"human_review", "unspecified"})

#: Methods that establish a claim by proof rather than by trial. Read against
#: `passing_methods`, never `methods`: a prover run against a state the claim has
#: since left is history, not current verification.
_FORMAL_METHODS = frozenset({"FORMAL_PROOF", "THEOREM_PROVER"})

#: `RequirementPressure` → the band shown. The engine's word, deliberately: a
#: HIGH/MEDIUM scale would state how bad something is, which release-gate does
#: not derive and cannot.
_BANDS: Mapping[str, str] = {
    "BLOCKS": "BLOCKS", "HOLDS": "HOLDS", "UNASSESSED": "UNASSESSED",
    "NONE": "ADVISORY",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _enum(value: Any, default: str = "") -> str:
    return _text(getattr(value, "value", value)) or default


def _tally(outcome: Any, kind: str) -> Optional[int]:
    """A per-kind ingest count, or `None` where the ingest did not count.

    An absent key is never read as zero: only the envelope path counts by kind,
    so a trace input can carry a whole execution without a row naming itself one
    (§10av). `0` would assert there were none.
    """
    tally = getattr(getattr(outcome, "normalisation", None),
                    "records_seen_by_kind", None)
    if not isinstance(tally, Mapping):
        return None
    value = tally.get(kind)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _figure(label: str, value: Optional[int], detail: str = "") -> Figure:
    """A figure that is OBSERVED when there is a number and honest when not."""
    if value is None:
        return Figure(label, None, Basis.NOT_ASSESSED, detail)
    return Figure(label, value, Basis.OBSERVED, detail)


def _execution_figures(outcome: Any) -> Tuple[Figure, ...]:
    """What arrived, counted by the ingest or by the analyses over it."""
    independence = getattr(outcome, "independence", None)
    contributors = getattr(independence, "contributors", None)
    graph = getattr(getattr(outcome, "analysis", None), "verification_graph", None)
    attempts = len(getattr(graph, "attempts", ()) or ()) if graph is not None else None

    figures = [
        _figure("Workers observed",
                contributors if isinstance(contributors, int) else None,
                "distinct producers the case actually holds a record from"),
        _figure("Execution records", _tally(outcome, "execution"),
                "counted at ingest; no ordering or completeness is claimed"),
        _figure("Claims", _tally(outcome, "claim")),
        _figure("Evidence records", _tally(outcome, "evidence")),
        _figure("Artifacts", _tally(outcome, "artifact")),
        _figure("Verification attempts", attempts,
                "every attempt held, including ones that no longer apply"),
    ]
    unaccounted = getattr(getattr(outcome, "normalisation", None),
                          "records_unaccounted", 0)
    if isinstance(unaccounted, int) and unaccounted > 0:
        # Shown only when there is something to explain. A reader summing the
        # lines above against `records_seen` finds the difference here rather
        # than discovering an unexplained shortfall.
        figures.append(_figure(
            "Records no kind accounts for", unaccounted,
            "arrived and could not be classified; each is counted in the "
            "ingest's skip reasons"))
    return tuple(figures)


def _critical_figures(outcome: Any) -> Tuple[Figure, ...]:
    """The critical path, and how much of it carries a check.

    Every count here is taken from `VerificationGraph.assess`, which is the
    engine's own reading of what the attempts on a target add up to against its
    *current* digest. Recounting the attempts here instead would produce a second
    answer that ignores supersession — the exact defect `target_digest` exists to
    catch.
    """
    analysis = getattr(outcome, "analysis", None)
    criticality = getattr(analysis, "criticality", None)
    graph = getattr(analysis, "verification_graph", None)
    determinable = bool(getattr(criticality, "determinable", False))

    if not determinable:
        # A `0` here is the most damaging number this screen could print: it
        # reads as "nothing is critical" where the truth is that reachability
        # could not be derived (Invariant 3).
        critical_ids: Tuple[str, ...] = ()
        critical = Figure("Critical claims", None, Basis.NOT_ASSESSED,
                          "reachability could not be derived from the claim graph")
    else:
        ids = getattr(criticality, "critical_ids", None)
        critical_ids = tuple(sorted(ids() if callable(ids) else (ids or ())))
        critical = _figure("Critical claims", len(critical_ids),
                           "reachable from the decision claim; no count of "
                           "records or producers enters this")

    verified = corroborated = formal = undetermined_verification = None
    if determinable and graph is not None and critical_ids:
        from release_gate.assurance.verification import VerificationTarget
        verified = corroborated = formal = undetermined_verification = 0
        for claim_id in critical_ids:
            # No digest argument: the graph records each target's own current
            # state, and handing it the case's subject digest instead made every
            # attempt read as superseded. The graph is the authority on what a
            # target's current state is; a caller supplying one overrides it.
            reading = graph.assess(VerificationTarget.claim(claim_id))
            if reading.verified:
                verified += 1
            if reading.corroborated:
                corroborated += 1
            if any(_enum(m) in _FORMAL_METHODS
                   for m in (reading.passing_methods or ())):
                formal += 1
            if not reading.applies and reading.undetermined:
                undetermined_verification += 1

    contradictions = getattr(analysis, "contradictions", None)
    counterexamples = getattr(analysis, "counterexamples", None)
    assumptions = getattr(analysis, "assumptions", None)

    return (
        critical,
        _figure("Verified", verified,
                "at least one passing check that applies to the claim's current "
                "state; a superseded check counts for nothing"),
        # Beside `Verified` always. Zero verified with every attempt of unknown
        # applicability is a different case from zero verified with checks that
        # ran and failed, and the first reads as the second without this line.
        _figure("Verification undetermined", undetermined_verification,
                "checks exist and nothing establishes whether they still apply, "
                "so they are reported and not counted — 'cannot tell' is not "
                "'still holds'"),
        _figure("Independently corroborated", corroborated,
                "confirmed across more than one lineage — one group checking "
                "twice is one check twice"),
        _figure("Formally verified", formal,
                "by a proof method, among the checks that currently apply"),
        _figure("Open contradictions",
                len(contradictions.open()) if contradictions is not None else None),
        _figure("Unresolved load-bearing assumptions",
                len([a for a in assumptions.load_bearing() if not a.source.stated])
                if assumptions is not None else None),
        _figure("Open counterexamples",
                len(counterexamples.open()) if counterexamples is not None else None),
    )


def _coverage_lines(outcome: Any) -> Tuple[Tuple[CoverageLine, ...], Tuple[str, ...]]:
    """The ledger's rows, split into ones with something to say and the rest.

    A percentage appears only where an expectation supplied a denominator.
    Nothing here invents one: the brief's shape wants four coverage figures, and
    a case that carries one gets one, with the other dimensions named under NOT
    ASSESSED where a reviewer can see what was never measured.
    """
    ledger = getattr(getattr(outcome, "analysis", None), "coverage_ledger", None)
    rows = tuple(getattr(ledger, "rows", ()) or ()) if ledger is not None else ()
    shown: List[CoverageLine] = []
    absent: List[str] = []
    for row in rows:
        dimension = _text(getattr(row, "dimension", ""))
        if not dimension:
            continue
        if not bool(getattr(row, "assessed", False)):
            absent.append(dimension)
            continue
        coverage = getattr(row, "coverage", None)
        shown.append(CoverageLine(
            dimension=dimension, state=_enum(getattr(row, "state", None), "UNKNOWN"),
            ratio=float(coverage) if isinstance(coverage, (int, float)) else None,
            expected=getattr(row, "expected", None),
            observed=getattr(row, "observed", None)))
    return tuple(shown), tuple(absent)


def _attention_lines(outcome: Any, limit: int) -> Tuple[AttentionLine, ...]:
    """The ranked items, banded by the pressure the engine derived."""
    attention = getattr(outcome, "attention", None)
    if attention is None:
        return ()
    top = attention.top(limit) if hasattr(attention, "top") else attention.items
    lines: List[AttentionLine] = []
    for item in top:
        payload = item.to_dict()
        ranking = payload.get("ranking") or {}
        pressure = _text(ranking.get("requirement_pressure")) or "NONE"
        resolves = payload.get("what_evidence_would_resolve_it") or ()
        lines.append(AttentionLine(
            band=_BANDS.get(pressure, pressure),
            focus=_text(payload.get("focus")),
            why=_text(payload.get("why_it_matters") or payload.get("what")),
            resolves=tuple(_text(r) for r in resolves if _text(r)),
            undroppable=bool(payload.get("undroppable")),
            criticality=_text(ranking.get("criticality"))))
    return tuple(lines)


def build_review(outcome: Any, *, attention_limit: int = 8) -> CaseReview:
    """Read one assurance outcome into the shape a person reads.

    Reads only; computes no verdict, changes no state, and reaches for no clock.
    Every figure comes from an analysis that already ran, so a review can be
    built twice from the same outcome and be identical both times.

    `attention_limit` is a floor, not a ceiling: the ranking will return more than
    asked for rather than drop an item it marked undroppable, and the review
    reports what it was given. A summary that could shorten itself by discarding a
    blocking item is the one thing this screen must not be able to do.
    """
    case = getattr(outcome, "case", None)
    if case is None:
        raise ReviewError("an outcome with no case cannot be reviewed")

    subject = getattr(case, "subject", None)
    methodology = getattr(case, "methodology", None)
    verdict = getattr(case, "verdict", None)
    required = getattr(outcome, "required_evidence", None)
    attention = getattr(outcome, "attention", None)

    items = tuple(getattr(attention, "items", ()) or ()) if attention else ()
    judgement = tuple(
        i for i in (getattr(required, "items", ()) or ())
        if _enum(getattr(i, "kind", None)) in _JUDGEMENT_KINDS) if required else ()

    coverage, absent = _coverage_lines(outcome)
    executions = _tally(outcome, "execution")
    withheld = getattr(attention, "withheld_note", "") if attention else ""

    return CaseReview(
        case_id=_text(getattr(case, "case_id", "")),
        objective=_text(getattr(case, "objective", "")),
        requested_decision=_text(getattr(case, "requested_decision", "")),
        methodology=(f"{_text(getattr(methodology, 'methodology_id', ''))}"
                     f"-v{_text(getattr(methodology, 'version', ''))}"
                     if methodology is not None else ""),
        subject=SubjectLine(
            digest=_text(getattr(subject, "digest", "")),
            method=_enum(getattr(subject, "digest_method", None)),
            status=_enum(getattr(subject, "digest_status", None)),
            basis=_text(getattr(subject, "digest_basis", ""))),
        execution=_execution_figures(outcome),
        critical_path=_critical_figures(outcome),
        coverage=coverage,
        not_assessed=absent,
        attention=_attention_lines(outcome, attention_limit),
        withheld=_text(withheld() if callable(withheld) else withheld),
        review_items=_figure("Human review items", len(items)),
        counted_over=(_figure("execution records", executions)
                      if executions is not None else None),
        decision=_enum(getattr(verdict, "decision", None), "UNKNOWN"),
        fired_rules=tuple(_text(r) for r in (getattr(verdict, "fired_rules", ()) or ())),
        required_evidence=_figure(
            "Required evidence",
            len(getattr(required, "items", ()) or ()) if required else None),
        expert_judgment=_figure(
            "Expert judgment items", len(judgement) if required else None,
            "no machine closes these: a rule asks for human review, or "
            "release-gate can see the gap and cannot name a closer"),
        limits=(
            "Release-gate has not evaluated whether the subject is correct. It "
            "reports what the evidence establishes and what it does not.",
            "A verdict is an authorisation decision about an exact state, not a "
            "certification of truth.",
            "Dimensions listed as not assessed were never measured; that is not "
            "the same as measured and found clean.",
        ),
    )


# ── rendering ────────────────────────────────────────────────────────────────

def _rule() -> str:
    return "─" * RULE_WIDTH


def _row(label: str, shown: str) -> str:
    """One label/value line. The only arithmetic is the padding."""
    pad = max(1, VALUE_COLUMN - len(label))
    return f"{label}{' ' * pad}{shown:>8}"


def _section(title: str, rows: Tuple[str, ...]) -> List[str]:
    if not rows:
        return []
    return ["", _rule(), "", title, ""] + list(rows)


def render_review(review: CaseReview) -> str:
    """Format a `CaseReview`. Reads its fields and nothing else.

    Every number in the output is a `Figure.value`, a `CoverageLine.shown`, or
    part of an identifier the review already holds. Nothing is counted, summed,
    divided or rounded here — `Figure.shown` and `CoverageLine.shown` do their own
    formatting so there is exactly one place each number is turned into text.
    """
    lines: List[str] = ["ASSURANCE CASE"]
    if review.objective:
        lines.append(review.objective)
    if review.case_id:
        lines.append(review.case_id)

    if review.subject.digest or review.subject.method:
        lines += ["", "SUBJECT", "", review.subject.shown]
        if review.subject.basis:
            lines.append(review.subject.basis)
    if review.requested_decision:
        lines += ["", "REQUESTED DECISION", "", review.requested_decision]
    if review.methodology:
        lines += ["", "METHODOLOGY", "", review.methodology]

    lines += _section("EXECUTION", tuple(
        _row(f.label, f.shown) for f in review.execution))
    lines += _section("CRITICAL PATH", tuple(
        _row(f.label, f.shown) for f in review.critical_path))

    coverage_rows = tuple(_row(c.dimension, c.shown) for c in review.coverage)
    lines += _section("COVERAGE", coverage_rows)
    if review.not_assessed:
        if not coverage_rows:
            lines += ["", _rule(), "", "COVERAGE", ""]
        lines += ["", "NOT ASSESSED"] + [f"  {d}" for d in review.not_assessed]

    if review.attention:
        lines += ["", _rule(), "", "HUMAN ATTENTION", ""]
        for item in review.attention:
            # Only the engine's own word. Its negation is "not marked
            # undroppable", which is not the same as "may be deferred" — that
            # would be the review giving a reviewer permission it cannot give.
            mark = "  (must not be dropped)" if item.undroppable else ""
            lines.append(f"[{item.band}] {item.focus}{mark}")
            if item.why:
                lines.append(item.why)
            if item.resolves:
                lines.append("")
                lines.append("Required evidence:")
                lines += [f"  {r}" for r in item.resolves]
            lines.append("")
        if review.withheld:
            lines += [review.withheld, ""]
        lines.append(_rule())
        lines.append("")
        counted = review.review_items.shown
        if review.counted_over is not None:
            lines.append(f"{counted} human review items, from "
                         f"{review.counted_over.shown} "
                         f"{review.counted_over.label}")
        else:
            lines.append(f"{counted} human review items")
        lines.append("A shorter list is not a better case.")

    lines += ["", _rule(), "", "VERDICT", "", review.decision, ""]
    lines.append(_row(review.required_evidence.label,
                      review.required_evidence.shown))
    lines.append(_row(review.expert_judgment.label,
                      review.expert_judgment.shown))
    if review.fired_rules:
        lines += ["", "Fired: " + ", ".join(review.fired_rules)]
    if review.limits:
        lines.append("")
        lines += list(review.limits)
    return "\n".join(lines)
