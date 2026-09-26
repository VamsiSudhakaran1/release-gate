"""How long the engine took to answer, and what that number is not allowed to mean.

A human asks for finalization. Some time later a verdict exists. This module
measures that interval and attributes it to the stages that consumed it, because
an operator running ten thousand workers behind one gate needs to know whether
the gate is the bottleneck — and because you cannot stop rebuilding things
unnecessarily until you know what is being rebuilt. Every reuse decision in
`incremental` was chosen against numbers this module produced, and the first
hypothesis those numbers destroyed was mine: the analysis, which looked like the
expensive part, is three percent of a finalization.

## The boundary is the finalization request, not the beginning of the work

Latency here starts when somebody asks for a decision, not when the agents
started producing evidence. Release-gate does not control the second one. A case
that sat open for nine hours while a swarm worked and then finalized in 40ms did
not take nine hours to decide; it took 40ms to decide and nine hours to
accumulate, and folding those together would produce a number release-gate has no
standing to report. `span_ms` is the interval this engine is answerable for.

## What this number may not be used for

**A faster verdict is not a sounder one.** This is the same refusal as
`scale != confidence`, pointed at the clock instead of the record count, and it
matters more here because latency is the one assurance number that has an obvious
optimisation: assess less. Every stage that could be dropped would make the
figure better and the case weaker, so the metric carries its coverage with it —
`render()` prints what was NOT_ASSESSED next to the milliseconds, and a fast
number can never be read on its own (Invariant 9). `is_a_safety_metric`,
`establishes_sufficiency`, `lower_is_more_trustworthy`,
`is_comparable_across_cases` and `authorises_reduced_assessment` are all
unconditionally `False`.

A `LatencyBudget` exists because an operator legitimately needs to know when the
gate has become the slow part of their pipeline. Exceeding one is a finding about
*the engine*. It is never a reason to decide on less evidence, which is why
`LatencyBudget.authorises_reduced_assessment` cannot return anything but `False`.

## The clock stays out of identity

`time.monotonic`, not `time.time`: a wall clock stepped backwards by NTP produces
a negative duration, and a duration is the one thing this module must never get
wrong. More importantly, nothing measured here enters a digest. A `DecisionLatency`
is not a case record, is not folded into any collection, and does not appear in
`case_digest` — the same discipline `verification.stamped_on_arrival` enforces for
an arrival timestamp, arrived at the hard way when a clock inside a digest made
identical input produce two different case digests a second apart. Measuring a
finalization and not measuring it produce the same verdict, and there is a test
that says so.

## Attribution is partial, and says so

`span_ms` is measured end to end; the stages account for as much of it as is
instrumented. `unattributed_ms` is the remainder, reported rather than
distributed, because silently spreading unmeasured time across the stages that
were measured is how a profile starts lying about where the work is.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.incremental import ReuseDecision, spec_for

LATENCY_SCHEMA_VERSION = 1


class LatencyError(ValueError):
    """A timing that cannot be true, or a report that would overstate itself."""


class Stage(str, Enum):
    """The stages of a finalization, named exactly as `incremental.STAGES` names them.

    One vocabulary for both modules: a stage that can be timed is a stage whose
    reuse has been classified, and a test holds the two lists to each other so
    neither can grow a stage the other has never heard of.
    """

    DETECT = "detect"
    NORMALISE = "normalise"
    FOLD = "fold"
    SUBJECT = "subject"
    CONSEQUENCE = "consequence"
    ANALYSE = "analyse"
    ASSESS = "assess"
    ATTENTION = "attention"
    DECIDE = "decide"
    SEAL = "seal"
    FINALIZATION = "finalization"

    def describe(self) -> str:
        return _STAGE_NOTE[self]


_STAGE_NOTE: Mapping[Stage, str] = {
    Stage.DETECT: "working out what kind of document arrived",
    Stage.NORMALISE: "mapping records to their typed forms",
    Stage.FOLD: "committing the records to the case's collections",
    Stage.SUBJECT: "identifying and digesting the thing being judged",
    Stage.CONSEQUENCE: "reading what the stakes were declared to be",
    Stage.ANALYSE: "structural analysis over the evidence",
    Stage.ASSESS: "holding the case against the methodology",
    Stage.ATTENTION: "what a human would have to look at, and what would resolve it",
    Stage.DECIDE: "composing findings and assessment into one verdict",
    Stage.SEAL: "digesting the decided case and rating its level",
    Stage.FINALIZATION: "the whole path, when it is reused or measured as one unit",
}


@dataclass(frozen=True)
class StageTiming:
    """One stage's contribution to a finalization.

    `decision` carries whether the time was spent or avoided, so a profile of a
    reusing run reads as "this stage cost nothing because it was reused" rather
    than as a stage that mysteriously got fast.
    """

    stage: Stage
    elapsed_ms: float
    decision: ReuseDecision = ReuseDecision.RECOMPUTED
    records: int = 0
    note: str = ""

    def __post_init__(self) -> None:
        if self.elapsed_ms < 0:
            raise LatencyError(
                f"{self.stage.value}: elapsed_ms is {self.elapsed_ms}, which cannot "
                "happen on a monotonic clock. A negative duration means the clock "
                "went backwards, and a measurement that can go backwards is not a "
                "measurement")
        if self.records < 0:
            raise LatencyError(f"{self.stage.value}: records cannot be negative")

    @property
    def reused(self) -> bool:
        return self.decision is ReuseDecision.REUSED

    @property
    def stability(self) -> str:
        return spec_for(self.stage.value).stability.value

    def share_of(self, total_ms: float) -> Optional[float]:
        """This stage's fraction of a total, or None when there is no total to divide."""
        if total_ms <= 0:
            return None
        return self.elapsed_ms / total_ms

    def per_record_us(self) -> Optional[float]:
        """Microseconds per record, where a record count was supplied."""
        if self.records <= 0:
            return None
        return (self.elapsed_ms * 1000.0) / self.records

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "stage_timing", "record_id": self.stage.value,
                "stage": self.stage.value, "elapsed_ms": round(self.elapsed_ms, 3),
                "decision": self.decision.value, "records": self.records,
                "reused": self.reused, "stability": self.stability,
                "note": self.note, "schema_version": LATENCY_SCHEMA_VERSION}


@dataclass(frozen=True)
class DecisionLatency:
    """The interval from a finalization request to a verdict, and where it went.

    Not a record. This is never folded into a collection and never reaches
    `case_digest`: a case assured twice must have one identity, and it would have
    two if how long the engine took were part of what it said.
    """

    span_ms: float
    stages: Tuple[StageTiming, ...] = ()
    records: int = 0
    not_assessed: Tuple[str, ...] = ()
    clock: str = "monotonic"

    def __post_init__(self) -> None:
        if self.span_ms < 0:
            raise LatencyError(
                "span_ms cannot be negative; a monotonic clock does not run backwards")
        attributed = sum(s.elapsed_ms for s in self.stages)
        if attributed > self.span_ms + 1.0:
            raise LatencyError(
                f"the stages account for {attributed:.1f}ms of a {self.span_ms:.1f}ms "
                "span. Either a stage was timed twice or the span was not measured "
                "around them, and either way the attribution is not describing this "
                "finalization")

    # ── the numbers ─────────────────────────────────────────────────────────

    @property
    def attributed_ms(self) -> float:
        return sum(s.elapsed_ms for s in self.stages)

    @property
    def unattributed_ms(self) -> float:
        """Measured span the stages do not account for. Reported, never distributed."""
        return max(0.0, self.span_ms - self.attributed_ms)

    @property
    def computed_ms(self) -> float:
        return sum(s.elapsed_ms for s in self.stages if not s.reused)

    @property
    def reused_stages(self) -> Tuple[StageTiming, ...]:
        return tuple(s for s in self.stages if s.reused)

    @property
    def dominant(self) -> Optional[StageTiming]:
        """The stage that consumed the most time, which is where reuse is worth having."""
        timed = [s for s in self.stages if s.elapsed_ms > 0]
        if not timed:
            return None
        return max(timed, key=lambda s: (s.elapsed_ms, s.stage.value))

    def per_record_us(self) -> Optional[float]:
        if self.records <= 0:
            return None
        return (self.span_ms * 1000.0) / self.records

    # ── what this is not ────────────────────────────────────────────────────

    @property
    def is_a_safety_metric(self) -> bool:
        """Unconditionally False. This measures the engine, not the release."""
        return False

    @property
    def establishes_sufficiency(self) -> bool:
        """Unconditionally False. No duration says the evidence was enough."""
        return False

    @property
    def lower_is_more_trustworthy(self) -> bool:
        """Unconditionally False, and the most important refusal here.

        The cheapest way to make this number smaller is to assess less, so a
        reading in which smaller is better converts directly into coverage gaps.
        """
        return False

    @property
    def is_comparable_across_cases(self) -> bool:
        """Unconditionally False. Twelve records and ten million are not a comparison."""
        return False

    @property
    def authorises_reduced_assessment(self) -> bool:
        """Unconditionally False. A slow verdict is a slow verdict, not a lighter one."""
        return False

    # ── rendering ───────────────────────────────────────────────────────────

    def render(self) -> str:
        lines = ["DECISION LATENCY"]
        span = f"{self.span_ms:,.1f} ms"
        over = f" over {self.records:,} records" if self.records else ""
        lines.append(f"  finalization request to verdict: {span}{over}")
        lines.append("")
        for timing in self.stages:
            share = timing.share_of(self.span_ms)
            pct = f"{100 * share:5.1f}%" if share is not None else "     —"
            flag = "REUSED" if timing.reused else ""
            lines.append(f"    {timing.stage.value:13s} {timing.elapsed_ms:9.1f} ms "
                         f"{pct}  {flag}")
        if self.unattributed_ms > 0.05:
            share = self.unattributed_ms / self.span_ms if self.span_ms else None
            pct = f"{100 * share:5.1f}%" if share is not None else "     —"
            lines.append(f"    {'unattributed':13s} {self.unattributed_ms:9.1f} ms {pct}")
        if self.reused_stages:
            names = ", ".join(s.stage.value for s in self.reused_stages)
            lines.append("")
            lines.append(f"  reused rather than recomputed: {names}")
        lines.append("")
        if self.not_assessed:
            lines.append(f"  not assessed: {', '.join(self.not_assessed)}")
        else:
            lines.append("  not assessed: nothing was left unassessed on this run")
        lines.append("")
        lines.append("  A faster verdict is not a sounder one. This measures the engine, not")
        lines.append("  the evidence: it establishes no sufficiency, it does not compare")
        lines.append("  between cases, and no latency target may be met by assessing less.")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "decision_latency",
                "record_id": short_id("lat", digest_object(
                    [s.to_dict() for s in self.stages])),
                "span_ms": round(self.span_ms, 3),
                "attributed_ms": round(self.attributed_ms, 3),
                "unattributed_ms": round(self.unattributed_ms, 3),
                "records": self.records,
                "stages": [s.to_dict() for s in self.stages],
                "dominant": self.dominant.stage.value if self.dominant else None,
                "not_assessed": list(self.not_assessed),
                "clock": self.clock,
                "is_a_safety_metric": self.is_a_safety_metric,
                "lower_is_more_trustworthy": self.lower_is_more_trustworthy,
                "is_comparable_across_cases": self.is_comparable_across_cases,
                "authorises_reduced_assessment": self.authorises_reduced_assessment,
                "schema_version": LATENCY_SCHEMA_VERSION}


@dataclass(frozen=True)
class LatencyBudget:
    """A duration an operator stated they need decisions inside of.

    Deliberately thin. It answers one question — has the gate become the slow part
    of this pipeline — and it is forbidden from answering any other, because the
    only way to make a verdict arrive sooner than the evidence permits is to look
    at less of the evidence.
    """

    ms: float
    declared_by: str = ""

    def __post_init__(self) -> None:
        if self.ms <= 0:
            raise LatencyError("a latency budget must be a positive number of milliseconds")

    @property
    def authorises_reduced_assessment(self) -> bool:
        """Unconditionally False. Exceeding a budget is a finding about the engine."""
        return False

    def met_by(self, latency: DecisionLatency) -> bool:
        return latency.span_ms <= self.ms

    def finding(self, latency: DecisionLatency) -> str:
        """What to say when the budget was missed. Names the stage, asks for nothing."""
        if self.met_by(latency):
            return ""
        who = f" (declared by {self.declared_by})" if self.declared_by else ""
        dominant = self.dominant_note(latency)
        return (f"this finalization took {latency.span_ms:,.1f}ms against a "
                f"{self.ms:,.1f}ms budget{who}.{dominant} The budget does not "
                "authorise deciding on less evidence.")

    @staticmethod
    def dominant_note(latency: DecisionLatency) -> str:
        top = latency.dominant
        if top is None:
            return ""
        share = top.share_of(latency.span_ms)
        pct = f" ({100 * share:.0f}% of the span)" if share is not None else ""
        return f" Most of it was {top.stage.value}{pct}."

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "latency_budget", "record_id": f"budget:{self.ms:g}",
                "ms": self.ms, "declared_by": self.declared_by,
                "authorises_reduced_assessment": self.authorises_reduced_assessment,
                "schema_version": LATENCY_SCHEMA_VERSION}


class LatencyRecorder:
    """Accumulates stage timings across one finalization.

    Mutable, single-use, and thrown away: it models one run. `disabled()` returns
    one that measures nothing, so the pipeline can be written with the recorder
    always present rather than guarded at every stage — a guard per stage is how
    an instrumented path and an uninstrumented path drift apart.
    """

    def __init__(self, clock: Optional[Callable[[], float]] = None,
                 *, enabled: bool = True) -> None:
        # monotonic, not time(): a wall clock stepped by NTP mid-finalization
        # produces a negative duration, and `StageTiming` refuses those on the
        # grounds that a measurement able to run backwards is not one.
        self._clock = clock or time.monotonic
        self.enabled = enabled
        self._timings: List[StageTiming] = []
        self._started: Optional[float] = None
        self._finished: Optional[float] = None

    @classmethod
    def disabled(cls) -> "LatencyRecorder":
        return cls(enabled=False)

    @property
    def clock_name(self) -> str:
        return getattr(self._clock, "__name__", "supplied")

    def begin(self) -> "LatencyRecorder":
        """Mark the finalization request. Idempotent; the first call is the boundary."""
        if self._started is None:
            self._started = self._clock()
        return self

    @contextmanager
    def stage(self, stage: Stage, *, records: int = 0,
              decision: ReuseDecision = ReuseDecision.RECOMPUTED,
              note: str = "") -> Iterator[None]:
        """Time one stage. A no-op when disabled, including the clock reads."""
        if not self.enabled:
            yield
            return
        self.begin()
        start = self._clock()
        try:
            yield
        finally:
            self.record(stage, (self._clock() - start) * 1000.0,
                        records=records, decision=decision, note=note)

    def record(self, stage: Stage, elapsed_ms: float, *, records: int = 0,
               decision: ReuseDecision = ReuseDecision.RECOMPUTED,
               note: str = "") -> "LatencyRecorder":
        """Add a stage measured elsewhere — an ingest the caller timed itself.

        A stage recorded twice is merged into one row holding the total time spent
        in it. The pipeline folds records at two points, and two `fold` rows would
        read as two different stages while one row attributed to `analyse` would be
        worse: it would say the analysis cost what the folding cost. Merging keeps
        one row per stage without moving time between them.

        A merged row is REUSED only if every part of it was. Any recomputed part
        means the stage did work, and a row claiming otherwise would understate it.
        """
        if not self.enabled:
            return self
        self.begin()
        elapsed_ms = max(0.0, elapsed_ms)
        for index, existing in enumerate(self._timings):
            if existing.stage is stage:
                self._timings[index] = StageTiming(
                    stage=stage, elapsed_ms=existing.elapsed_ms + elapsed_ms,
                    decision=(ReuseDecision.REUSED
                              if existing.reused and decision is ReuseDecision.REUSED
                              else ReuseDecision.RECOMPUTED),
                    records=max(existing.records, records),
                    note=existing.note or note)
                return self
        self._timings.append(StageTiming(
            stage=stage, elapsed_ms=elapsed_ms, decision=decision,
            records=records, note=note))
        return self

    def finish(self, *, records: int = 0,
               not_assessed: Sequence[str] = ()) -> DecisionLatency:
        """Close the span and produce the report. Safe to call on a disabled recorder."""
        if self._started is None:
            self._started = self._clock()
        if self._finished is None:
            self._finished = self._clock()
        span = max(0.0, (self._finished - self._started) * 1000.0)
        attributed = sum(t.elapsed_ms for t in self._timings)
        # The span is measured around the stages, so it should bound them. On a
        # coarse clock it can round just under; taking the larger keeps the
        # report internally consistent rather than raising over a rounding edge.
        return DecisionLatency(
            span_ms=max(span, attributed), stages=tuple(self._timings),
            records=records, not_assessed=tuple(not_assessed),
            clock=self.clock_name)


def coverage_gaps(outcome: Any) -> Tuple[str, ...]:
    """Dimensions this run did not assess, read off the coverage ledger.

    The companion every latency figure is rendered with. A 40ms verdict over a
    case where four dimensions were never looked at is a fact about what was
    skipped, and the number on its own would not say so (Invariant 9).
    """
    ledger = getattr(getattr(outcome, "analysis", None), "coverage_ledger", None)
    if ledger is None:
        return ()
    rows = getattr(ledger, "not_assessed", None)
    if not callable(rows):
        return ()
    return tuple(sorted(str(getattr(row, "dimension", "") or "?") for row in rows()))


def measure_finalization(session: Any, *,
                         clock: Optional[Callable[[], float]] = None
                         ) -> Tuple[Any, DecisionLatency]:
    """Finalize a session and report what it cost. The documented entry point.

    Returns the outcome alongside the latency rather than attaching one to the
    other, because a `DecisionLatency` is not part of a case and giving an outcome
    a `.latency` would put a clock one attribute away from a digest.
    """
    recorder = LatencyRecorder(clock=clock).begin()
    outcome = session.finalize(recorder=recorder)
    return outcome, recorder.finish(
        records=len(getattr(session, "records", ()) or ()),
        not_assessed=coverage_gaps(outcome))


__all__ = [
    "LATENCY_SCHEMA_VERSION",
    "DecisionLatency",
    "LatencyBudget",
    "LatencyError",
    "LatencyRecorder",
    "Stage",
    "StageTiming",
    "coverage_gaps",
    "measure_finalization",
]
