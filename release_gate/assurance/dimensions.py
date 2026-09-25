"""Eight dimensions, reported side by side, with no total.

The 0–100 score is preserved and unchanged. It remains useful for the job it was
built for — ranking safeguard-checklist completeness across repositories, which
is what the badge and the outreach paths need — and it is measurably misleading
outside it:

    all safeguards present, three high-severity findings
        score = 100   ·   decision = BLOCK

The decision is already non-compensatory: findings hard-gate it whatever the
checklist says. The score is not. It sits at 100 while the verdict is BLOCK, and
one of its members (`loop_boundary`) carries weight 0 — a safeguard the number
can never express at all. So the score stays, scoped and labelled as *checklist
coverage*, and stops being the thing anyone reads for assurance.

This is what replaces it for assurance, and the first thing to say is what it is
not: **there is no total.** No weighted blend, no composite grade, no letter, no
percentage-of-dimensions-passed. A new blended number would be the old mistake
with better inputs — the whole failure of a score is that it lets a strong
showing on seven dimensions pay for a fatal one on the eighth, and no choice of
weights fixes that because averaging *is* the defect.

**Critical conditions are gates, not weights.** A `FATAL` standing on any
dimension is fatal against any background. `DimensionProfile.combines_into_a_score`
is unconditionally `False` — §10q's refusal on `FactSheet`, applied one level up,
because the temptation at this level is stronger: eight tidy readings look like
they are asking to be averaged.

**Nothing assessed is not zero.** A dimension nothing could reach reads
`NOT_ASSESSED`. A zero is a measurement and an absence is not, and a profile that
scored an unexamined dimension as zero would report ignorance as failure — which
is the same error as reporting it as success, in the other direction (Invariant
3).

Nothing here computes a dimension. All eight already exist as objects on a
decided outcome: the verification graph, the coverage collection, artifact
lineage, `IndependenceProfile`, `ContradictionLedger`, `CriticalitySet`, the
mutation status and `MethodologyAssessment`. This reads them and puts them next to
each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "DIMENSIONS",
    "DIMENSIONS_SCHEMA_VERSION",
    "Dimension",
    "DimensionError",
    "DimensionProfile",
    "DimensionReading",
    "Standing",
    "profile_of",
]

DIMENSIONS_SCHEMA_VERSION = 1


class DimensionError(ValueError):
    """A profile was built in a way that would let one dimension pay for another."""


class Dimension(str, Enum):
    """The eight an advanced assurance reading is made of."""

    VERIFICATION_COVERAGE = "VERIFICATION_COVERAGE"
    EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"
    LINEAGE_COVERAGE = "LINEAGE_COVERAGE"
    INDEPENDENCE = "INDEPENDENCE"
    CONTRADICTION_STATE = "CONTRADICTION_STATE"
    CRITICAL_CLAIM_COVERAGE = "CRITICAL_CLAIM_COVERAGE"
    ARTIFACT_INTEGRITY = "ARTIFACT_INTEGRITY"
    METHODOLOGY_SATISFACTION = "METHODOLOGY_SATISFACTION"


#: Ordered, so a profile is always read in the same order and "is one missing" is
#: a comparison rather than a count.
DIMENSIONS: Tuple[Dimension, ...] = tuple(Dimension)


class Standing(str, Enum):
    """Where one dimension stands. Deliberately not a number.

    A number invites arithmetic, and arithmetic across dimensions is the thing
    this module exists to prevent. `FATAL` is a gate: it is reported as fatal
    whatever the other seven say.
    """

    #: Assessed, and nothing here argues against the case.
    SOUND = "SOUND"
    #: Assessed, with something a reviewer should read. Not fatal, not clean.
    QUALIFIED = "QUALIFIED"
    #: Assessed, and it defeats the case on its own. Non-compensatory.
    FATAL = "FATAL"
    #: Nobody could assess it. Not a zero, not a pass.
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True)
class DimensionReading:
    """One dimension, where it stands, and the facts behind it.

    `detail` holds counts because counts are what a reviewer checks. It holds no
    normalised fraction and no rating: a `0.82` on one dimension beside a `0.41`
    on another is an invitation to average them, and there is no defensible
    exchange rate between an unresolved contradiction and a missing signature.
    """

    dimension: Dimension
    standing: Standing
    headline: str
    detail: Mapping[str, Any] = field(default_factory=dict)
    #: Why this is fatal, when it is. Required for FATAL, because a dimension
    #: that ends a case has to say what ended it.
    because: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "dimension", Dimension(self.dimension))
        object.__setattr__(self, "standing", Standing(self.standing))
        object.__setattr__(self, "detail", dict(self.detail))
        object.__setattr__(self, "because", tuple(self.because))
        if self.standing is Standing.FATAL and not self.because:
            raise DimensionError(
                f"{self.dimension.value} is FATAL and says nothing about why. A "
                "dimension that ends a case has to name what ended it, or a "
                "reviewer is told the answer and not the reason")
        if not str(self.headline or "").strip():
            raise DimensionError(
                f"{self.dimension.value}: a reading must say what it found")

    @property
    def is_fatal(self) -> bool:
        return self.standing is Standing.FATAL

    @property
    def assessed(self) -> bool:
        return self.standing is not Standing.NOT_ASSESSED

    @property
    def scores(self) -> bool:
        """Unconditionally False. A reading has a standing, never a value."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "dimension_reading",
                "record_id": self.dimension.value,
                "dimension": self.dimension.value,
                "standing": self.standing.value, "headline": self.headline,
                "detail": dict(self.detail), "because": list(self.because),
                "assessed": self.assessed, "is_fatal": self.is_fatal,
                "scores": False}


@dataclass(frozen=True)
class DimensionProfile:
    """All eight, side by side, with nothing summed."""

    case_id: str
    readings: Tuple[DimensionReading, ...] = ()
    schema_version: int = DIMENSIONS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "readings", tuple(self.readings))
        present = [r.dimension for r in self.readings]
        missing = [d.value for d in DIMENSIONS if d not in set(present)]
        if missing:
            raise DimensionError(
                "a profile must report all eight; missing "
                + ", ".join(missing)
                + ". A dimension left out reads as one with nothing against it, "
                  "which is exactly the compensation this exists to prevent")
        if len(set(present)) != len(present):
            raise DimensionError("a dimension appears twice; it has no standing then")

    def reading(self, dimension: Any) -> DimensionReading:
        wanted = Dimension(dimension)
        return next(r for r in self.readings if r.dimension is wanted)

    # ── the refusals ────────────────────────────────────────────────────────

    @property
    def combines_into_a_score(self) -> bool:
        """Unconditionally False.

        There is no total here and no way to ask for one. A strong showing on
        seven dimensions does not pay for a fatal eighth, and no choice of
        weights would fix that, because averaging is the defect rather than a
        detail of it.
        """
        return False

    @property
    def is_compensatory(self) -> bool:
        """Unconditionally False. A fatal dimension is fatal against any
        background."""
        return False

    # ── what it does say ────────────────────────────────────────────────────

    @property
    def fatal(self) -> Tuple[DimensionReading, ...]:
        return tuple(r for r in self.readings if r.is_fatal)

    @property
    def qualified(self) -> Tuple[DimensionReading, ...]:
        return tuple(r for r in self.readings
                     if r.standing is Standing.QUALIFIED)

    @property
    def not_assessed(self) -> Tuple[DimensionReading, ...]:
        return tuple(r for r in self.readings if not r.assessed)

    @property
    def defeated(self) -> bool:
        """Whether any dimension defeats the case on its own.

        Not a threshold and not a count — one is enough, and eight would be no
        more so.
        """
        return bool(self.fatal)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "dimension_profile", "record_id": self.case_id,
                "case_id": self.case_id,
                "readings": [r.to_dict() for r in self.readings],
                "fatal": [r.dimension.value for r in self.fatal],
                "not_assessed": [r.dimension.value for r in self.not_assessed],
                "defeated": self.defeated,
                "combines_into_a_score": False, "is_compensatory": False,
                "schema_version": self.schema_version}

    def render(self) -> str:
        lines = [f"ASSURANCE DIMENSIONS — case {self.case_id}"]
        for reading in self.readings:
            lines.append(f"  {reading.standing.value:13} "
                         f"{reading.dimension.value:26} {reading.headline}")
            for because in reading.because:
                lines.append(f"      ↳ {because}")
        if self.defeated:
            lines.append("  This case is defeated by "
                         + ", ".join(r.dimension.value for r in self.fatal)
                         + ". No standing on any other dimension offsets that.")
        if self.not_assessed:
            lines.append("  Not assessed: "
                         + ", ".join(r.dimension.value for r in self.not_assessed)
                         + " — unexamined, which is neither a pass nor a zero.")
        lines.append("  There is no total. These are eight separate questions "
                     "and no exchange rate between them exists.")
        return "\n".join(lines)


# ── reading them off a decided outcome ───────────────────────────────────────

def _rows(owner: Any, name: str) -> Tuple[Any, ...]:
    """Read a collection that may be a property on one type and a method on
    another.

    `VerificationGraph.attempts` is a property while `invalidated` and `not_run`
    are methods; `ContradictionLedger.open` and `CriticalitySet.critical` are
    methods too. Guessing wrong raises `'method' object is not iterable`, which
    is the loud failure — the quiet one is a caller that catches it and reports
    an empty collection, turning "I read this wrong" into "there were none".
    """
    found = getattr(owner, name, None)
    if found is None:
        return ()
    if callable(found):
        found = found()
    return tuple(found or ())


def _verification(outcome: Any) -> DimensionReading:
    graph = getattr(outcome, "verification", None)
    if graph is None:
        return DimensionReading(
            Dimension.VERIFICATION_COVERAGE, Standing.NOT_ASSESSED,
            "no verification graph was produced")
    attempts = _rows(graph, "attempts")
    invalidated = _rows(graph, "invalidated")
    not_run = _rows(graph, "not_run")
    if not attempts:
        return DimensionReading(
            Dimension.VERIFICATION_COVERAGE, Standing.NOT_ASSESSED,
            "nothing in this case was verified",
            detail={"attempts": 0, "not_run": len(not_run)})
    if invalidated:
        return DimensionReading(
            Dimension.VERIFICATION_COVERAGE, Standing.FATAL,
            f"{len(invalidated)} verification(s) no longer apply",
            detail={"attempts": len(attempts), "invalidated": len(invalidated)},
            because=("a verification that ran against content which has since "
                     "changed establishes nothing about what is here now",))
    standing = Standing.QUALIFIED if not_run else Standing.SOUND
    return DimensionReading(
        Dimension.VERIFICATION_COVERAGE, standing,
        f"{len(attempts)} verification(s), {len(not_run)} not run",
        detail={"attempts": len(attempts), "not_run": len(not_run)})


def _completeness(outcome: Any, ledger: Any) -> DimensionReading:
    if ledger is None:
        return DimensionReading(
            Dimension.EVIDENCE_COMPLETENESS, Standing.NOT_ASSESSED,
            "no stream ledger was supplied, so whether the evidence arrived "
            "whole was not asked")
    status = getattr(getattr(ledger, "status", None), "value", str(ledger))
    if status == "COMPLETE":
        return DimensionReading(
            Dimension.EVIDENCE_COMPLETENESS, Standing.SOUND,
            "the evidence stream is accounted for", detail={"status": status})
    return DimensionReading(
        Dimension.EVIDENCE_COMPLETENESS, Standing.QUALIFIED,
        f"the evidence stream is {status}", detail={"status": status})


def _lineage(outcome: Any) -> DimensionReading:
    artifacts = tuple(getattr(getattr(outcome, "normalisation", None),
                              "artifacts", ()) or ())
    if not artifacts:
        return DimensionReading(
            Dimension.LINEAGE_COVERAGE, Standing.NOT_ASSESSED,
            "no artifacts were reconstructed, so nothing has a lineage to cover")
    with_parents = sum(1 for a in artifacts if getattr(a, "derived_from", ()))
    standing = Standing.SOUND if with_parents else Standing.QUALIFIED
    return DimensionReading(
        Dimension.LINEAGE_COVERAGE, standing,
        f"{with_parents} of {len(artifacts)} artifact(s) name what they came from",
        detail={"artifacts": len(artifacts), "with_lineage": with_parents})


def _independence(outcome: Any) -> DimensionReading:
    profile = getattr(outcome, "independence", None)
    if profile is None or not getattr(profile, "determinable", False):
        return DimensionReading(
            Dimension.INDEPENDENCE, Standing.NOT_ASSESSED,
            "independence could not be determined from what arrived")
    roots = getattr(profile, "independent_roots", 0)
    largest = getattr(profile, "largest_ancestry_cluster", 0)
    contributors = getattr(profile, "contributors", 0)
    if getattr(profile, "cycles_detected", 0):
        return DimensionReading(
            Dimension.INDEPENDENCE, Standing.FATAL,
            "the ancestry graph contains a cycle",
            detail={"contributors": contributors, "roots": roots},
            because=("evidence that supports itself through a cycle corroborates "
                     "nothing, however many contributors carry it",))
    standing = Standing.SOUND if roots > 1 else Standing.QUALIFIED
    return DimensionReading(
        Dimension.INDEPENDENCE, standing,
        f"{roots} independent root(s) across {contributors} contributor(s)",
        detail={"contributors": contributors, "independent_roots": roots,
                "largest_ancestry_cluster": largest})


def _contradiction(outcome: Any) -> DimensionReading:
    ledger = getattr(outcome, "contradictions", None)
    if ledger is None:
        return DimensionReading(
            Dimension.CONTRADICTION_STATE, Standing.NOT_ASSESSED,
            "no contradiction ledger was produced")
    unresolved_critical = _rows(ledger, "unresolved_critical")
    open_items = _rows(ledger, "open")
    if unresolved_critical:
        return DimensionReading(
            Dimension.CONTRADICTION_STATE, Standing.FATAL,
            f"{len(unresolved_critical)} unresolved contradiction(s) on critical "
            "claims",
            detail={"open": len(open_items),
                    "unresolved_critical": len(unresolved_critical)},
            because=("a case that contradicts itself on something the decision "
                     "rests on is not a weaker case, it is one that has not been "
                     "made",))
    standing = Standing.QUALIFIED if open_items else Standing.SOUND
    return DimensionReading(
        Dimension.CONTRADICTION_STATE, standing,
        f"{len(open_items)} open contradiction(s), none on a critical claim",
        detail={"open": len(open_items)})


def _critical_claims(outcome: Any) -> DimensionReading:
    found = getattr(outcome, "criticality", None)
    if found is None or not getattr(found, "determinable", True):
        return DimensionReading(
            Dimension.CRITICAL_CLAIM_COVERAGE, Standing.NOT_ASSESSED,
            "which claims are critical could not be determined")
    critical = _rows(found, "critical")
    broken = _rows(found, "broken_chains")
    examined = getattr(found, "claims_examined", 0)
    if not critical:
        return DimensionReading(
            Dimension.CRITICAL_CLAIM_COVERAGE, Standing.NOT_ASSESSED,
            f"no claim among {examined} examined was identified as critical",
            detail={"claims_examined": examined})
    if broken:
        return DimensionReading(
            Dimension.CRITICAL_CLAIM_COVERAGE, Standing.FATAL,
            f"{len(broken)} critical claim(s) rest on a broken chain",
            detail={"critical": len(critical), "broken_chains": len(broken)},
            because=("a critical claim whose support does not reach it is "
                     "unsupported, and the decision rests on it",))
    return DimensionReading(
        Dimension.CRITICAL_CLAIM_COVERAGE, Standing.SOUND,
        f"{len(critical)} critical claim(s), each with an intact chain",
        detail={"critical": len(critical), "claims_examined": examined})


def _integrity(outcome: Any) -> DimensionReading:
    subject = getattr(getattr(outcome, "case", None), "subject", None)
    digest = getattr(subject, "digest", "") if subject is not None else ""
    status = getattr(getattr(subject, "digest_status", None), "value", "")
    if not digest:
        return DimensionReading(
            Dimension.ARTIFACT_INTEGRITY, Standing.NOT_ASSESSED,
            "the subject carries no digest, so mutation is not detectable")
    artifacts = tuple(getattr(getattr(outcome, "normalisation", None),
                              "artifacts", ()) or ())
    undigested = sum(1 for a in artifacts if not getattr(a, "digest", ""))
    if undigested:
        return DimensionReading(
            Dimension.ARTIFACT_INTEGRITY, Standing.QUALIFIED,
            f"{undigested} of {len(artifacts)} artifact(s) carry no digest",
            detail={"subject_digest_status": status, "artifacts": len(artifacts),
                    "undigested": undigested})
    return DimensionReading(
        Dimension.ARTIFACT_INTEGRITY, Standing.SOUND,
        f"the subject and {len(artifacts)} artifact(s) are digest-addressed",
        detail={"subject_digest_status": status, "artifacts": len(artifacts)})


def _methodology(outcome: Any) -> DimensionReading:
    assessment = getattr(outcome, "assessment", None)
    if assessment is None:
        return DimensionReading(
            Dimension.METHODOLOGY_SATISFACTION, Standing.NOT_ASSESSED,
            "no methodology was applied, so domain sufficiency was not assessed")
    status = getattr(getattr(assessment, "status", None), "value", "")
    if status != "ASSESSED":
        return DimensionReading(
            Dimension.METHODOLOGY_SATISFACTION, Standing.NOT_ASSESSED,
            f"the methodology assessment is {status or 'absent'}",
            detail={"status": status})
    unmet = tuple(assessment.unmet())
    blocking = tuple(r for r in unmet
                     if getattr(getattr(r, "effect", None), "value", "") == "BLOCK")
    if blocking:
        return DimensionReading(
            Dimension.METHODOLOGY_SATISFACTION, Standing.FATAL,
            f"{len(blocking)} blocking requirement(s) unmet under "
            f"{assessment.methodology_ref}",
            detail={"unmet": len(unmet), "blocking": len(blocking),
                    "methodology": assessment.methodology_ref},
            because=tuple(f"{r.requirement_id} is unmet and its effect is BLOCK"
                          for r in blocking))
    standing = Standing.QUALIFIED if unmet else Standing.SOUND
    return DimensionReading(
        Dimension.METHODOLOGY_SATISFACTION, standing,
        f"{len(unmet)} requirement(s) unmet under {assessment.methodology_ref}",
        detail={"unmet": len(unmet), "methodology": assessment.methodology_ref})


def profile_of(outcome: Any, *, completeness: Any = None) -> DimensionProfile:
    """Read all eight dimensions off a decided outcome.

    Computes nothing: every dimension already exists as an object on the
    outcome. This puts them next to each other and refuses to add them up.
    """
    case = getattr(outcome, "case", None)
    if case is None or getattr(case, "verdict", None) is None:
        raise DimensionError(
            "a dimension profile needs a decided outcome; a profile of an "
            "undecided case would report standings nobody reached")
    return DimensionProfile(case_id=case.case_id, readings=(
        _verification(outcome),
        _completeness(outcome, completeness),
        _lineage(outcome),
        _independence(outcome),
        _contradiction(outcome),
        _critical_claims(outcome),
        _integrity(outcome),
        _methodology(outcome),
    ))
