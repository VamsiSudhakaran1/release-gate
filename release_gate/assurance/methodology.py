"""AssuranceMethodology — what evidence a class of decision is expected to have.

The abstraction that keeps release-gate from either fabricating domain standards
or being useless without configuration. A case says *what happened*; a
methodology says *what should have happened for this kind of decision*, and the
gap between them is the assurance question.

**This is not governance.yaml renamed.** They are different concepts with
different lifecycles, and conflating them would collapse the whole design:

    governance.yaml   a team's declaration about one deployed agent — budget
                      ceiling, kill switch, owner. It is EVIDENCE, ingested as
                      DECLARED, and it says nothing about what a decision needs.
    methodology       the yardstick a class of decision is argued against, and
                      the thing the verdict is relative to. It is versioned,
                      content-addressed, and travels inside case_digest.

A methodology is **code-first and API-native**. Requirements are typed predicates
that evaluate themselves against a case and report what they actually saw —
`from_dict` exists for JSON transport, but no file is required anywhere, and
nothing in this module imports a YAML parser. A methodology that could only be
printed would be a config file with a new name.

Three properties carry the requirements of the contract:

* **Versioned and content-addressed.** `id@version` identifies it; a sha256 over
  its content proves it. An organisation that edits a methodology in place keeps
  the version string and changes the digest, and the registry refuses the
  redefinition rather than letting an existing case be re-graded by a yardstick
  that silently moved.
* **Honest under partial data.** A predicate that cannot see enough of the case
  to answer returns `NOT_ASSESSED`, never `SATISFIED` (Invariant 3). Where a
  collection was materialised in part, a negative answer that more records could
  overturn is `NOT_ASSESSED` too — a requirement must not fail on evidence nobody
  looked at, nor pass on it.
* **Extension means at least as strict.** `extend()` may add requirements and
  narrow admissible verification, and may not drop a parent's requirements or its
  non-overridable conditions. Otherwise "extends the regulated methodology" would
  be a claim anyone could make while removing the parts they disliked.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import (
    CanonicalisationError,
    digest_object,
    freeze_value,
    thaw_value,
)
from release_gate.assurance.case import (
    COLLECTION_KINDS,
    AssuranceCase,
    CaseType,
    MethodologyRef,
)
from release_gate.assurance.records import Presence
from release_gate.assurance.subject import SubjectType

METHODOLOGY_MODEL_VERSION = 1

#: Record field names the predicates read. Declared here so the evidence and
#: claim types defined by later prompts land on the same names rather than
#: inventing parallel ones.
FIELD_VERIFICATION_METHOD = "verification_method"
FIELD_EPISTEMIC_STATUS = "epistemic_status"
FIELD_INDEPENDENCE_GROUP = "independence_group"
FIELD_RESOLVED = "resolved"
FIELD_DIMENSION = "dimension"

ALL_CASE_TYPES: Tuple[CaseType, ...] = tuple(CaseType)

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$")


class MethodologyError(ValueError):
    """A methodology was defined or extended in a way that cannot be honoured."""


class MethodologyDriftError(MethodologyError):
    """A methodology changed content without changing its version.

    The failure this whole abstraction exists to make impossible: an existing
    case must never be re-graded by a yardstick that moved underneath it.
    """


class Criticality(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_CRITICALITY_ORDER = {Criticality.LOW: 0, Criticality.MEDIUM: 1,
                      Criticality.HIGH: 2, Criticality.CRITICAL: 3}


class RequirementEffect(str, Enum):
    """What an unmet requirement costs. Composition into a verdict is policy's job."""

    BLOCK = "BLOCK"
    HOLD = "HOLD"
    ADVISORY = "ADVISORY"


class RequirementOutcome(str, Enum):
    """How a requirement came out.

    `NOT_ASSESSED` and `UNKNOWN` are both distinct from `UNSATISFIED`, and neither
    ever counts as met. The first means the case does not carry the data to
    evaluate; the second means the data is there and indeterminate.
    """

    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"
    UNKNOWN = "UNKNOWN"


class AssessmentStatus(str, Enum):
    """Whether the sufficiency question could be answered at all."""

    ASSESSED = "ASSESSED"
    METHODOLOGY_REQUIRED = "METHODOLOGY_REQUIRED"
    CASE_TYPE_NOT_COVERED = "CASE_TYPE_NOT_COVERED"


# ── predicates ──────────────────────────────────────────────────────────────
#
# A small, closed algebra over the case model. Closed on purpose: a requirement
# holding an arbitrary callable could not be serialised, transported to an API
# client, or shown to the person whose release it blocked.

_PREDICATE_TYPES: Dict[str, type] = {}


def _predicate(cls):
    _PREDICATE_TYPES[cls.KIND] = cls
    return cls


@dataclass(frozen=True)
class _Finding:
    outcome: RequirementOutcome
    detail: str
    observed: Mapping[str, Any] = field(default_factory=dict)


def _threshold_outcome(met: bool, incomplete: bool, *, met_detail: str,
                       unmet_detail: str, observed: Mapping[str, Any]) -> _Finding:
    """Resolve a 'at least N' style check against partially materialised data.

    Monotone reasoning: more records can satisfy an at-least check but cannot
    un-satisfy it, so a positive answer stands. A negative answer that unheld
    records could overturn is NOT_ASSESSED — a requirement must not fail on
    evidence nobody looked at.
    """
    if met:
        return _Finding(RequirementOutcome.SATISFIED, met_detail, observed)
    if incomplete:
        return _Finding(
            RequirementOutcome.NOT_ASSESSED,
            unmet_detail + " — and records were counted but not materialised, so "
            "this cannot be settled from what the case holds",
            observed)
    return _Finding(RequirementOutcome.UNSATISFIED, unmet_detail, observed)


def _absence_outcome(violations: Sequence[Any], incomplete: bool, *,
                     clean_detail: str, violation_detail: str,
                     observed: Mapping[str, Any]) -> _Finding:
    """Resolve a 'none of these exist' check. The mirror of `_threshold_outcome`.

    A violation found is definitive. Finding none is only meaningful when
    everything was looked at.
    """
    if violations:
        return _Finding(RequirementOutcome.UNSATISFIED, violation_detail, observed)
    if incomplete:
        return _Finding(
            RequirementOutcome.NOT_ASSESSED,
            "none found among the records held, but records were counted and not "
            "materialised — 'not observed' is not 'does not exist'",
            observed)
    return _Finding(RequirementOutcome.SATISFIED, clean_detail, observed)


def _records(case: AssuranceCase, kind: str) -> Tuple[List[Dict[str, Any]], bool, int]:
    """Materialised record dicts for a collection, plus whether any were withheld."""
    collection = case.collection(kind)
    dicts = [r.to_dict() for r in collection.materialised]
    return dicts, collection.not_materialised > 0, collection.total_count


@dataclass(frozen=True)
class Predicate:
    """Base class. Subclasses are frozen, serialisable and self-evaluating."""

    KIND = "predicate"

    def evaluate(self, case: AssuranceCase) -> _Finding:  # pragma: no cover - abstract
        raise NotImplementedError

    def describe(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return {"kind": self.KIND, **{k: _plain(v) for k, v in asdict(self).items()}}


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    return value


@_predicate
@dataclass(frozen=True)
class CollectionSupplied(Predicate):
    """This part of the argument must have been supplied at all."""

    KIND = "collection_supplied"
    collection: str

    def describe(self) -> str:
        return f"the {self.collection} collection is supplied"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        observed = {"presence": coll.presence.value, "total_count": coll.total_count}
        if coll.presence is Presence.PRESENT:
            return _Finding(RequirementOutcome.SATISFIED,
                            f"{self.collection} was supplied ({coll.total_count} record(s))",
                            observed)
        return _Finding(RequirementOutcome.UNSATISFIED,
                        f"{self.collection} was never supplied, so nothing about it was assessed",
                        observed)


@_predicate
@dataclass(frozen=True)
class MinimumRecords(Predicate):
    """At least N records exist in a collection. Counts, not contents."""

    KIND = "minimum_records"
    collection: str
    minimum: int = 1

    def describe(self) -> str:
        return f"at least {self.minimum} record(s) in {self.collection}"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        if coll.presence is not Presence.PRESENT:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            f"{self.collection} was never supplied",
                            {"presence": coll.presence.value})
        # total_count covers records that were counted but not held, so this is
        # answerable at any scale.
        met = coll.total_count >= self.minimum
        return _threshold_outcome(
            met, incomplete=False,
            met_detail=f"{coll.total_count} record(s) in {self.collection}",
            unmet_detail=f"{coll.total_count} record(s) in {self.collection}, "
                         f"{self.minimum} expected",
            observed={"total_count": coll.total_count, "minimum": self.minimum})


@_predicate
@dataclass(frozen=True)
class SubjectIdentified(Predicate):
    """The subject carries a digest, and optionally one we can re-check."""

    KIND = "subject_identified"
    require_mutation_detectable: bool = False

    def describe(self) -> str:
        return ("the subject is cryptographically identified and re-checkable"
                if self.require_mutation_detectable
                else "the subject is cryptographically identified")

    def evaluate(self, case: AssuranceCase) -> _Finding:
        subject = case.subject
        observed = {"digest": subject.digest, "digest_status": subject.digest_status.value,
                    "mutation_detectable": subject.mutation_detectable}
        if subject.digest is None:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            "the subject has no digest, so nobody can prove later what "
                            "was approved", observed)
        if self.require_mutation_detectable and not subject.mutation_detectable:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            "the subject's content cannot be re-checked from here, so "
                            "mutation after approval would go undetected", observed)
        return _Finding(RequirementOutcome.SATISFIED, "the subject is identified", observed)


@_predicate
@dataclass(frozen=True)
class VerificationPresent(Predicate):
    """At least N records verified by an admissible method (Invariant 8)."""

    KIND = "verification_present"
    methods: Tuple[str, ...] = ()
    minimum: int = 1
    collection: str = "verification"

    def describe(self) -> str:
        methods = ", ".join(self.methods) if self.methods else "any accepted method"
        return f"at least {self.minimum} verification(s) of type: {methods}"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        if coll.presence is not Presence.PRESENT:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            f"{self.collection} was never supplied, so no verification "
                            "of any type is on record", {"presence": coll.presence.value})
        records, incomplete, total = _records(case, self.collection)
        allowed = set(self.methods)
        typed = [r for r in records if r.get(FIELD_VERIFICATION_METHOD)]
        matching = [r for r in typed
                    if not allowed or r.get(FIELD_VERIFICATION_METHOD) in allowed]
        untyped = len(records) - len(typed)
        observed = {"matching": len(matching), "minimum": self.minimum,
                    "records_held": len(records), "total_count": total,
                    "untyped_records": untyped}
        if untyped and len(matching) < self.minimum:
            # Invariant 8: an untyped "verified" is not a verification. Say that,
            # rather than counting it or silently ignoring it.
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                f"{untyped} record(s) claim verification without naming a method; "
                "an untyped verification cannot be credited to a typed requirement",
                observed)
        return _threshold_outcome(
            len(matching) >= self.minimum, incomplete,
            met_detail=f"{len(matching)} admissible verification(s) on record",
            unmet_detail=f"{len(matching)} admissible verification(s), "
                         f"{self.minimum} expected",
            observed=observed)


@_predicate
@dataclass(frozen=True)
class IndependenceThreshold(Predicate):
    """Support must come from N structurally independent groups (Invariant 6)."""

    KIND = "independence_threshold"
    minimum_groups: int = 2
    collection: str = "verification"

    def describe(self) -> str:
        return (f"support in {self.collection} spans at least {self.minimum_groups} "
                "independent groups")

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        if coll.presence is not Presence.PRESENT:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            f"{self.collection} was never supplied",
                            {"presence": coll.presence.value})
        records, incomplete, total = _records(case, self.collection)
        grouped = [r for r in records if r.get(FIELD_INDEPENDENCE_GROUP)]
        groups = {r[FIELD_INDEPENDENCE_GROUP] for r in grouped}
        ungrouped = len(records) - len(grouped)
        observed = {"records_held": len(records), "total_count": total,
                    "independent_groups": len(groups), "minimum": self.minimum_groups,
                    "ungrouped_records": ungrouped}
        if ungrouped:
            # Records with no group attribution cannot be assumed independent, and
            # must not be assumed identical either.
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                f"{ungrouped} record(s) carry no independence attribution; agreement "
                "without established independence is not corroboration (Invariant 6)",
                observed)
        return _threshold_outcome(
            len(groups) >= self.minimum_groups, incomplete,
            met_detail=f"{len(records)} record(s) across {len(groups)} independent group(s)",
            unmet_detail=f"{len(records)} record(s) collapse to {len(groups)} independent "
                         f"group(s), {self.minimum_groups} expected",
            observed=observed)


@_predicate
@dataclass(frozen=True)
class NoUnresolved(Predicate):
    """Nothing in this collection may be left open (Invariant 7)."""

    KIND = "no_unresolved"
    collection: str = "contradictions"

    def describe(self) -> str:
        return f"no unresolved {self.collection}"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        if coll.presence is not Presence.PRESENT:
            # Nobody looked. That is a coverage gap, not a clean bill of health.
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                f"{self.collection} was never supplied; absence of recorded "
                f"{self.collection} is not evidence that none exist",
                {"presence": coll.presence.value})
        records, incomplete, total = _records(case, self.collection)
        unresolved = [r for r in records if not r.get(FIELD_RESOLVED)]
        untracked = [r for r in records if FIELD_RESOLVED not in r]
        observed = {"records_held": len(records), "total_count": total,
                    "unresolved": len(unresolved), "untracked": len(untracked)}
        return _absence_outcome(
            unresolved, incomplete,
            clean_detail=f"all {len(records)} {self.collection} record(s) are marked resolved",
            violation_detail=f"{len(unresolved)} unresolved {self.collection} record(s) remain",
            observed=observed)


@_predicate
@dataclass(frozen=True)
class RecordFieldRequired(Predicate):
    """Every record in a collection must carry a field (e.g. epistemic status)."""

    KIND = "record_field_required"
    collection: str
    field_name: str

    def describe(self) -> str:
        return f"every {self.collection} record carries {self.field_name}"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        if coll.presence is not Presence.PRESENT:
            return _Finding(RequirementOutcome.NOT_APPLICABLE,
                            f"{self.collection} was never supplied",
                            {"presence": coll.presence.value})
        records, incomplete, total = _records(case, self.collection)
        missing = [r.get("record_id") for r in records if not r.get(self.field_name)]
        return _absence_outcome(
            missing, incomplete,
            clean_detail=f"all {len(records)} record(s) carry {self.field_name}",
            violation_detail=f"{len(missing)} record(s) lack {self.field_name}, "
                             f"e.g. {missing[0] if missing else ''}",
            observed={"records_held": len(records), "total_count": total,
                      "missing": len(missing)})


@_predicate
@dataclass(frozen=True)
class CoverageDimensionDeclared(Predicate):
    """A named coverage dimension must be stated (Invariant 9)."""

    KIND = "coverage_dimension_declared"
    dimension: str

    def describe(self) -> str:
        return f"coverage states the {self.dimension!r} dimension"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection("coverage")
        if coll.presence is not Presence.PRESENT:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            "no coverage was supplied; a verdict without coverage is "
                            "invalid (Invariant 9)", {"presence": coll.presence.value})
        records, incomplete, total = _records(case, "coverage")
        found = [r for r in records if r.get(FIELD_DIMENSION) == self.dimension]
        return _threshold_outcome(
            bool(found), incomplete,
            met_detail=f"coverage states {self.dimension!r}",
            unmet_detail=f"coverage does not state {self.dimension!r}",
            observed={"dimension": self.dimension, "rows_held": len(records),
                      "total_count": total})


@_predicate
@dataclass(frozen=True)
class ConsequenceDeclared(Predicate):
    """Named consequence dimensions must not be UNKNOWN.

    This is how consequence reaches the authorization boundary without
    release-gate inventing a threshold. The engine never decides that an
    irreversible change needs a second approver — a methodology does, by naming
    the dimensions a decision of this kind cannot be taken without.

    Reads the consequence profile folded into the case's evidence collection. A
    case with no profile at all is UNSATISFIED rather than NOT_ASSESSED: the
    requirement asks whether the stakes were stated, and "nobody stated them" is
    a clear no.
    """

    KIND = "consequence_declared"
    dimensions: Tuple[str, ...] = ()
    collection: str = "evidence"

    def describe(self) -> str:
        named = ", ".join(self.dimensions) if self.dimensions else "any dimension"
        return f"consequence is stated for: {named}"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, self.collection)
        profiles = [r for r in records if r.get("record_type") == "consequence"]
        if not profiles:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                "no consequence profile is recorded on this case, so nothing is "
                "stated about what this action would do",
                {"profiles": 0, "records_held": len(records),
                 "materialisation_incomplete": incomplete})

        stated: Dict[str, str] = {}
        for profile in profiles:
            for name, descriptor in (profile.get("dimensions") or {}).items():
                value = (descriptor or {}).get("value", "UNKNOWN")
                if value != "UNKNOWN":
                    stated[name] = value

        wanted = tuple(d.upper() for d in self.dimensions) or tuple(stated)
        missing = sorted(d for d in wanted if d not in stated)
        observed = {"stated": {d: stated[d] for d in sorted(stated)},
                    "required": list(wanted), "missing": missing}
        if not wanted:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            "a consequence profile exists but every dimension is "
                            "UNKNOWN", observed)
        if missing:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                "consequence is not stated for: " + ", ".join(missing), observed)
        return _Finding(RequirementOutcome.SATISFIED,
                        "every required consequence dimension is stated", observed)


@_predicate
@dataclass(frozen=True)
class AncestryIndependence(Predicate):
    """Support must rest on N distinct evidence lineages, derived not declared.

    The counterpart to `IndependenceThreshold`, and a different question.
    `IndependenceThreshold` reads the `independence_group` a producer *declared*;
    this reads the lineage its evidence *turned out* to have, traced through
    `parent_evidence` to roots. Ten thousand agents that all declare distinct
    groups still collapse to one root here, which is the whole point.

    This is also the only place concentration becomes blocking. The analyser
    reports it and never penalises it, because many parties legitimately relying
    on one authoritative source is a normal workflow — so a methodology has to
    say it needs independence before a shortfall costs anything.
    """

    KIND = "ancestry_independence"
    minimum_roots: int = 2
    maximum_concentration: Optional[float] = None
    collection: str = "evidence"

    def describe(self) -> str:
        parts = [f"support rests on at least {self.minimum_roots} distinct evidence lineage(s)"]
        if self.maximum_concentration is not None:
            parts.append(f"with no more than {self.maximum_concentration:.0%} of "
                         "contributors in one lineage")
        return ", ".join(parts)

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, self.collection)
        profiles = [r for r in records if r.get("record_type") == "independence"]
        if not profiles:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no independence profile is recorded on this case, so the ancestry of "
                "its support has not been derived",
                {"profiles": 0, "materialisation_incomplete": incomplete})

        profile = profiles[0]
        roots = int(profile.get("independent_roots") or 0)
        concentration = profile.get("shared_ancestry_concentration")
        observed = {"independent_roots": roots, "minimum_roots": self.minimum_roots,
                    "shared_ancestry_concentration": concentration,
                    "maximum_concentration": self.maximum_concentration,
                    "unknown_ancestry": profile.get("unknown_ancestry"),
                    "concentration_band": profile.get("concentration")}

        if not profile.get("determinable", False):
            # Ancestry nobody recorded cannot be assumed independent, and must not
            # be assumed identical either (Invariant 6).
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                f"ancestry is not determinable: {profile.get('basis', '')}", observed)

        if roots < self.minimum_roots:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"support rests on {roots} distinct lineage(s), {self.minimum_roots} "
                "required; agreement without established independence is not "
                "corroboration (Invariant 6)",
                observed)
        if (self.maximum_concentration is not None and concentration is not None
                and concentration > self.maximum_concentration):
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{concentration:.1%} of contributors sit in one lineage, above the "
                f"{self.maximum_concentration:.0%} this methodology allows",
                observed)
        return _Finding(
            RequirementOutcome.SATISFIED,
            f"support rests on {roots} distinct lineage(s)", observed)


def predicate_from_dict(data: Mapping[str, Any]) -> Predicate:
    kind = data.get("kind")
    cls = _PREDICATE_TYPES.get(kind)
    if cls is None:
        raise MethodologyError(
            f"unknown predicate kind {kind!r}; known: {', '.join(sorted(_PREDICATE_TYPES))}")
    fields = {k: v for k, v in data.items() if k != "kind"}
    for name, value in list(fields.items()):
        if isinstance(value, list):
            fields[name] = tuple(value)
    return cls(**fields)


# ── requirements and supporting rules ───────────────────────────────────────

@dataclass(frozen=True)
class Requirement:
    """One expectation, its predicate, and what failing it costs."""

    requirement_id: str
    description: str
    predicate: Predicate
    effect: RequirementEffect = RequirementEffect.HOLD
    remedy: str = ""
    rationale: str = ""
    applies_to_case_types: Tuple[CaseType, ...] = ()
    applies_to_subject_types: Tuple[SubjectType, ...] = ()

    def __post_init__(self) -> None:
        if not self.requirement_id.strip():
            raise MethodologyError("requirement_id is required")
        if not self.description.strip():
            raise MethodologyError(
                f"{self.requirement_id}: a requirement must describe itself — it is "
                "shown to the person whose release it holds")
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "applies_to_case_types",
                           tuple(CaseType(c) for c in self.applies_to_case_types))
        object.__setattr__(self, "applies_to_subject_types",
                           tuple(SubjectType(s) for s in self.applies_to_subject_types))

    def applies_to(self, case: AssuranceCase) -> bool:
        """Empty filters mean no ADDITIONAL restriction beyond the methodology's own."""
        if self.applies_to_case_types and case.case_type not in self.applies_to_case_types:
            return False
        if (self.applies_to_subject_types
                and case.subject.subject_type not in self.applies_to_subject_types):
            return False
        return True

    def evaluate(self, case: AssuranceCase) -> "RequirementResult":
        if not self.applies_to(case):
            return RequirementResult(
                requirement_id=self.requirement_id, outcome=RequirementOutcome.NOT_APPLICABLE,
                effect=self.effect, description=self.description,
                detail="does not apply to this case type or subject type",
                observed={}, remedy="")
        finding = self.predicate.evaluate(case)
        return RequirementResult(
            requirement_id=self.requirement_id, outcome=finding.outcome, effect=self.effect,
            description=self.description, detail=finding.detail, observed=dict(finding.observed),
            remedy=("" if finding.outcome is RequirementOutcome.SATISFIED else self.remedy))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "description": self.description,
            "predicate": self.predicate.to_dict(),
            "expects": self.predicate.describe(),
            "effect": self.effect.value,
            "remedy": self.remedy,
            "rationale": self.rationale,
            "applies_to_case_types": [c.value for c in self.applies_to_case_types],
            "applies_to_subject_types": [s.value for s in self.applies_to_subject_types],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Requirement":
        return cls(
            requirement_id=data["requirement_id"], description=data["description"],
            predicate=predicate_from_dict(data["predicate"]),
            effect=RequirementEffect(data.get("effect", RequirementEffect.HOLD.value)),
            remedy=data.get("remedy", ""), rationale=data.get("rationale", ""),
            applies_to_case_types=tuple(data.get("applies_to_case_types", ())),
            applies_to_subject_types=tuple(data.get("applies_to_subject_types", ())))


@dataclass(frozen=True)
class RequirementResult:
    """What one requirement found, and what would fix it."""

    requirement_id: str
    outcome: RequirementOutcome
    effect: RequirementEffect
    description: str
    detail: str
    observed: Mapping[str, Any] = field(default_factory=dict)
    remedy: str = ""

    @property
    def is_met(self) -> bool:
        """Only SATISFIED and NOT_APPLICABLE count as met.

        NOT_ASSESSED and UNKNOWN are explicitly not met: a requirement nobody
        could evaluate has not been satisfied (Invariant 3).
        """
        return self.outcome in (RequirementOutcome.SATISFIED, RequirementOutcome.NOT_APPLICABLE)

    def to_dict(self) -> Dict[str, Any]:
        return {"requirement_id": self.requirement_id, "outcome": self.outcome.value,
                "effect": self.effect.value, "description": self.description,
                "detail": self.detail, "observed": dict(self.observed), "remedy": self.remedy}


@dataclass(frozen=True)
class CriticalityRule:
    """How consequence weight is assigned to records of a given shape."""

    rule_id: str
    collection: str
    field_name: str
    values: Tuple[str, ...]
    criticality: Criticality
    rationale: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "criticality", Criticality(self.criticality))
        object.__setattr__(self, "values", tuple(self.values))

    def matches(self, collection: str, record: Mapping[str, Any]) -> bool:
        return collection == self.collection and record.get(self.field_name) in self.values

    def to_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "collection": self.collection,
                "field_name": self.field_name, "values": list(self.values),
                "criticality": self.criticality.value, "rationale": self.rationale}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CriticalityRule":
        return cls(rule_id=data["rule_id"], collection=data["collection"],
                   field_name=data["field_name"], values=tuple(data["values"]),
                   criticality=Criticality(data["criticality"]),
                   rationale=data.get("rationale", ""))


@dataclass(frozen=True)
class EvidenceExpectation:
    """A floor: what must exist before a clean assessment is even reachable."""

    collection: str
    minimum: int = 1
    rationale: str = ""
    effect: RequirementEffect = RequirementEffect.HOLD

    def __post_init__(self) -> None:
        if self.collection not in COLLECTION_KINDS:
            raise MethodologyError(
                f"unknown collection {self.collection!r} in an evidence expectation")
        object.__setattr__(self, "effect", RequirementEffect(self.effect))

    def to_requirement(self) -> Requirement:
        return Requirement(
            requirement_id=f"evidence.{self.collection}.minimum",
            description=f"at least {self.minimum} {self.collection} record(s)",
            predicate=MinimumRecords(collection=self.collection, minimum=self.minimum),
            effect=self.effect, rationale=self.rationale,
            remedy=f"supply at least {self.minimum} {self.collection} record(s)")

    def to_dict(self) -> Dict[str, Any]:
        return {"collection": self.collection, "minimum": self.minimum,
                "rationale": self.rationale, "effect": self.effect.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceExpectation":
        return cls(collection=data["collection"], minimum=int(data.get("minimum", 1)),
                   rationale=data.get("rationale", ""),
                   effect=RequirementEffect(data.get("effect", RequirementEffect.HOLD.value)))


@dataclass(frozen=True)
class IndependenceRequirement:
    """Where corroboration must come from genuinely distinct sources."""

    scope: str = "verification"
    minimum_groups: int = 2
    rationale: str = ""
    effect: RequirementEffect = RequirementEffect.HOLD

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", RequirementEffect(self.effect))

    def to_requirement(self) -> Requirement:
        return Requirement(
            requirement_id=f"independence.{self.scope}",
            description=(f"{self.scope} support spans at least {self.minimum_groups} "
                         "structurally independent groups"),
            predicate=IndependenceThreshold(minimum_groups=self.minimum_groups,
                                            collection=self.scope),
            effect=self.effect, rationale=self.rationale,
            remedy=(f"obtain {self.scope} from a producer structurally independent of "
                    "the existing ones, and record its independence attribution"))

    def to_dict(self) -> Dict[str, Any]:
        return {"scope": self.scope, "minimum_groups": self.minimum_groups,
                "rationale": self.rationale, "effect": self.effect.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IndependenceRequirement":
        return cls(scope=data.get("scope", "verification"),
                   minimum_groups=int(data.get("minimum_groups", 2)),
                   rationale=data.get("rationale", ""),
                   effect=RequirementEffect(data.get("effect", RequirementEffect.HOLD.value)))


@dataclass(frozen=True)
class CoverageExpectation:
    """A dimension whose coverage must be stated, and where its denominator comes from.

    `expected_source` is what makes a percentage legitimate: without a manifest,
    a declaration or an enumeration there is no real denominator, and coverage is
    `UNKNOWN` rather than a fabricated ratio (Invariant 9).
    """

    dimension: str
    expected_source: str = ""
    rationale: str = ""
    effect: RequirementEffect = RequirementEffect.HOLD

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", RequirementEffect(self.effect))

    def to_requirement(self) -> Requirement:
        return Requirement(
            requirement_id=f"coverage.{self.dimension}",
            description=f"coverage states the {self.dimension!r} dimension",
            predicate=CoverageDimensionDeclared(dimension=self.dimension),
            effect=self.effect, rationale=self.rationale,
            remedy=(f"state coverage for {self.dimension!r}"
                    + (f"; the denominator comes from {self.expected_source}"
                       if self.expected_source else
                       "; if no denominator can be established, record it as UNKNOWN")))

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension, "expected_source": self.expected_source,
                "rationale": self.rationale, "effect": self.effect.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CoverageExpectation":
        return cls(dimension=data["dimension"], expected_source=data.get("expected_source", ""),
                   rationale=data.get("rationale", ""),
                   effect=RequirementEffect(data.get("effect", RequirementEffect.HOLD.value)))


@dataclass(frozen=True)
class OverrideRule:
    """Whether a named requirement may be waived, and on what terms."""

    requirement_id: str
    permitted: bool = False
    requires_role: str = ""
    requires_rationale: bool = True
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"requirement_id": self.requirement_id, "permitted": self.permitted,
                "requires_role": self.requires_role,
                "requires_rationale": self.requires_rationale, "notes": self.notes}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OverrideRule":
        return cls(requirement_id=data["requirement_id"], permitted=bool(data.get("permitted")),
                   requires_role=data.get("requires_role", ""),
                   requires_rationale=bool(data.get("requires_rationale", True)),
                   notes=data.get("notes", ""))


@dataclass(frozen=True)
class OverrideDecision:
    """The answer to 'may this be waived here?', with its reason."""

    requirement_id: str
    permitted: bool
    reason: str
    requires_role: str = ""
    requires_rationale: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"requirement_id": self.requirement_id, "permitted": self.permitted,
                "reason": self.reason, "requires_role": self.requires_role,
                "requires_rationale": self.requires_rationale}


# ── the methodology ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AssuranceMethodology:
    """What evidence a class of decision is expected to have.

    Immutable and content-addressed. `digest` is over everything below, so an
    edit in place is detectable even when the version string is unchanged.
    """

    methodology_id: str
    version: str
    domain: str
    case_types: Tuple[CaseType, ...]
    description: str = ""
    requirements: Tuple[Requirement, ...] = ()
    criticality_rules: Tuple[CriticalityRule, ...] = ()
    accepted_verification_types: Tuple[str, ...] = ()
    minimum_evidence_expectations: Tuple[EvidenceExpectation, ...] = ()
    independence_requirements: Tuple[IndependenceRequirement, ...] = ()
    coverage_expectations: Tuple[CoverageExpectation, ...] = ()
    override_rules: Tuple[OverrideRule, ...] = ()
    non_overridable_conditions: Tuple[str, ...] = ()
    provenance: str = "builtin"          # builtin | plugin | api | organization
    derived_from: Optional[str] = None   # "id@version#digest" of the parent
    metadata: Mapping[str, Any] = field(default_factory=dict)

    digest: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if not _VERSION_RE.match(self.version or ""):
            raise MethodologyError(
                f"version {self.version!r} must be MAJOR.MINOR.PATCH (optionally with a "
                "-suffix); an unordered version cannot be resolved to 'the latest' "
                "without guessing")
        if not (self.methodology_id or "").strip():
            raise MethodologyError("methodology_id is required")
        if not self.case_types:
            raise MethodologyError(
                f"{self.methodology_id}: case_types must be explicit — a methodology that "
                "silently applies to everything cannot be reviewed. Use ALL_CASE_TYPES to "
                "cover them all deliberately.")

        object.__setattr__(self, "case_types", tuple(CaseType(c) for c in self.case_types))
        for name in ("requirements", "criticality_rules", "accepted_verification_types",
                     "minimum_evidence_expectations", "independence_requirements",
                     "coverage_expectations", "override_rules", "non_overridable_conditions"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

        ids = [r.requirement_id for r in self.all_requirements()]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise MethodologyError(
                f"{self.methodology_id}: duplicate requirement id(s) {sorted(duplicates)}; "
                "a requirement must be citable to exactly one expectation")

        known = set(ids)
        for rule in self.override_rules:
            if rule.requirement_id not in known:
                raise MethodologyError(
                    f"{self.methodology_id}: override rule names unknown requirement "
                    f"{rule.requirement_id!r}")
        for condition in self.non_overridable_conditions:
            if condition not in known:
                raise MethodologyError(
                    f"{self.methodology_id}: non-overridable condition names unknown "
                    f"requirement {condition!r}")
        conflict = set(self.non_overridable_conditions) & {
            r.requirement_id for r in self.override_rules if r.permitted}
        if conflict:
            raise MethodologyError(
                f"{self.methodology_id}: {sorted(conflict)} are declared both overridable "
                "and non-overridable; a waiver rule that contradicts itself would be "
                "resolved by whichever check ran first")

        try:
            object.__setattr__(self, "metadata", freeze_value(self.metadata or {}, "metadata"))
        except CanonicalisationError as exc:
            raise MethodologyError(f"{self.methodology_id} metadata: {exc}") from exc

        object.__setattr__(self, "digest", digest_object(self.content()))

    # ── identity ────────────────────────────────────────────────────────────

    @property
    def ref_string(self) -> str:
        return f"{self.methodology_id}@{self.version}"

    def ref(self) -> MethodologyRef:
        """A reference that carries the content digest, not just the version.

        The version says which yardstick; the digest proves it is still the same
        one. Both travel inside `case_digest`.
        """
        return MethodologyRef(methodology_id=self.methodology_id, version=self.version,
                              provenance=self.provenance, digest=self.digest)

    def version_tuple(self) -> Tuple[int, int, int, str]:
        core, _, suffix = self.version.partition("-")
        major, minor, patch = (int(p) for p in core.split("."))
        # A release sorts above its own pre-releases, matching semver intent.
        return (major, minor, patch, suffix or "~")

    def all_requirements(self) -> Tuple[Requirement, ...]:
        """Explicit requirements plus those compiled from the expectations.

        The expectations are sugar, not a second mechanism: they compile down to
        ordinary requirements so there is exactly one thing to evaluate, cite and
        override.
        """
        compiled = [e.to_requirement() for e in self.minimum_evidence_expectations]
        compiled += [i.to_requirement() for i in self.independence_requirements]
        compiled += [c.to_requirement() for c in self.coverage_expectations]
        return tuple(self.requirements) + tuple(compiled)

    def requirement(self, requirement_id: str) -> Optional[Requirement]:
        return next((r for r in self.all_requirements()
                     if r.requirement_id == requirement_id), None)

    # ── semantics ───────────────────────────────────────────────────────────

    def applies_to(self, case: AssuranceCase) -> bool:
        return case.case_type in self.case_types

    def admits(self, verification_method: str) -> bool:
        """Is this a verification type this methodology will credit? (Invariant 8)"""
        return (not self.accepted_verification_types
                or verification_method in self.accepted_verification_types)

    def criticality_for(self, collection: str, record: Mapping[str, Any]) -> Optional[Criticality]:
        """The highest criticality any rule assigns, or None.

        None means no rule matched — unknown criticality stays unknown rather
        than defaulting to a comfortable middle value (Invariant 3).
        """
        matches = [r.criticality for r in self.criticality_rules if r.matches(collection, record)]
        if not matches:
            return None
        return max(matches, key=lambda c: _CRITICALITY_ORDER[c])

    def can_override(self, requirement_id: str) -> OverrideDecision:
        """May this requirement be waived? Default is no.

        Silence means no: a requirement nobody wrote a waiver rule for is not
        waivable, because the safe reading of an unanswered question is the
        conservative one.
        """
        if requirement_id in self.non_overridable_conditions:
            return OverrideDecision(
                requirement_id, False,
                f"{requirement_id} is non-overridable under {self.ref_string}; no waiver "
                "by any role can satisfy it")
        rule = next((r for r in self.override_rules
                     if r.requirement_id == requirement_id), None)
        if rule is None:
            return OverrideDecision(
                requirement_id, False,
                f"{self.ref_string} declares no override rule for {requirement_id}; "
                "absent an explicit waiver rule, a requirement stands")
        if not rule.permitted:
            return OverrideDecision(requirement_id, False,
                                    f"{self.ref_string} forbids overriding {requirement_id}"
                                    + (f": {rule.notes}" if rule.notes else ""))
        return OverrideDecision(requirement_id, True,
                                f"{self.ref_string} permits an override of {requirement_id}"
                                + (f": {rule.notes}" if rule.notes else ""),
                                requires_role=rule.requires_role,
                                requires_rationale=rule.requires_rationale)

    # ── extension ───────────────────────────────────────────────────────────

    def extend(self, *, methodology_id: str, version: str,
               add_requirements: Iterable[Requirement] = (),
               add_criticality_rules: Iterable[CriticalityRule] = (),
               add_evidence_expectations: Iterable[EvidenceExpectation] = (),
               add_independence_requirements: Iterable[IndependenceRequirement] = (),
               add_coverage_expectations: Iterable[CoverageExpectation] = (),
               add_override_rules: Iterable[OverrideRule] = (),
               add_non_overridable: Iterable[str] = (),
               restrict_verification_types: Optional[Iterable[str]] = None,
               domain: Optional[str] = None, description: str = "",
               provenance: str = "organization",
               metadata: Optional[Mapping[str, Any]] = None) -> "AssuranceMethodology":
        """Derive a stricter methodology from this one.

        Extension can only tighten. Requirements and non-overridable conditions
        are inherited and cannot be dropped, and `restrict_verification_types`
        must be a subset of the parent's. Without that rule, "extends the
        regulated methodology" would be a claim anyone could make while removing
        the parts they found inconvenient; an organisation that wants a looser
        bar writes its own methodology and owns that fact.
        """
        accepted = tuple(self.accepted_verification_types)
        if restrict_verification_types is not None:
            narrowed = tuple(restrict_verification_types)
            if accepted and not set(narrowed) <= set(accepted):
                added = sorted(set(narrowed) - set(accepted))
                raise MethodologyError(
                    f"extending {self.ref_string} cannot ADD verification types {added}; "
                    "an extension may only narrow what it credits. Define an independent "
                    "methodology if a different bar is intended.")
            accepted = narrowed

        override_rules = tuple(self.override_rules) + tuple(add_override_rules)
        non_overridable = tuple(dict.fromkeys(
            tuple(self.non_overridable_conditions) + tuple(add_non_overridable)))
        # An inherited non-overridable condition outranks a child's permissive rule.
        override_rules = tuple(r for r in override_rules
                               if not (r.permitted and r.requirement_id in non_overridable))

        return AssuranceMethodology(
            methodology_id=methodology_id, version=version,
            domain=domain or self.domain, description=description or self.description,
            case_types=self.case_types,
            requirements=tuple(self.requirements) + tuple(add_requirements),
            criticality_rules=tuple(self.criticality_rules) + tuple(add_criticality_rules),
            accepted_verification_types=accepted,
            minimum_evidence_expectations=(tuple(self.minimum_evidence_expectations)
                                           + tuple(add_evidence_expectations)),
            independence_requirements=(tuple(self.independence_requirements)
                                       + tuple(add_independence_requirements)),
            coverage_expectations=(tuple(self.coverage_expectations)
                                   + tuple(add_coverage_expectations)),
            override_rules=override_rules, non_overridable_conditions=non_overridable,
            provenance=provenance,
            derived_from=f"{self.ref_string}#{self.digest}",
            metadata=dict(metadata or {}))

    # ── inspection and transport ────────────────────────────────────────────

    def content(self) -> Dict[str, Any]:
        """Everything the digest covers. No timestamps, nothing volatile."""
        return {
            "model_version": METHODOLOGY_MODEL_VERSION,
            "methodology_id": self.methodology_id,
            "version": self.version,
            "domain": self.domain,
            "description": self.description,
            "case_types": [c.value for c in self.case_types],
            "requirements": [r.to_dict() for r in self.requirements],
            "criticality_rules": [r.to_dict() for r in self.criticality_rules],
            "accepted_verification_types": list(self.accepted_verification_types),
            "minimum_evidence_expectations": [e.to_dict()
                                              for e in self.minimum_evidence_expectations],
            "independence_requirements": [i.to_dict() for i in self.independence_requirements],
            "coverage_expectations": [c.to_dict() for c in self.coverage_expectations],
            "override_rules": [o.to_dict() for o in self.override_rules],
            "non_overridable_conditions": list(self.non_overridable_conditions),
            "provenance": self.provenance,
            "derived_from": self.derived_from,
            "metadata": thaw_value(self.metadata),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_methodology", "digest": self.digest, **self.content()}

    def explain(self) -> Dict[str, Any]:
        """A human-readable view: every requirement, what it expects, what it costs.

        Inspectability is a hard requirement, not a nicety. A person told their
        release is held must be able to read the rule that held it, in the words
        of the methodology that owns it.
        """
        return {
            "methodology": self.ref_string,
            "digest": self.digest,
            "domain": self.domain,
            "description": self.description,
            "applies_to_case_types": [c.value for c in self.case_types],
            "accepted_verification_types": list(self.accepted_verification_types) or ["ANY"],
            "requirements": [
                {"requirement_id": r.requirement_id, "expects": r.predicate.describe(),
                 "description": r.description, "effect": r.effect.value,
                 "remedy": r.remedy, "rationale": r.rationale,
                 "overridable": self.can_override(r.requirement_id).permitted}
                for r in self.all_requirements()],
            "non_overridable_conditions": list(self.non_overridable_conditions),
            "derived_from": self.derived_from,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AssuranceMethodology":
        """Build from a plain mapping — JSON over an API, or a parsed file.

        Deliberately dict-in: nothing here imports a YAML parser, and no file
        format is privileged. A methodology can exist entirely in code.
        """
        methodology = cls(
            methodology_id=data["methodology_id"], version=data["version"],
            domain=data.get("domain", ""), description=data.get("description", ""),
            case_types=tuple(CaseType(c) for c in data["case_types"]),
            requirements=tuple(Requirement.from_dict(r) for r in data.get("requirements", ())),
            criticality_rules=tuple(CriticalityRule.from_dict(r)
                                    for r in data.get("criticality_rules", ())),
            accepted_verification_types=tuple(data.get("accepted_verification_types", ())),
            minimum_evidence_expectations=tuple(
                EvidenceExpectation.from_dict(e)
                for e in data.get("minimum_evidence_expectations", ())),
            independence_requirements=tuple(
                IndependenceRequirement.from_dict(i)
                for i in data.get("independence_requirements", ())),
            coverage_expectations=tuple(CoverageExpectation.from_dict(c)
                                        for c in data.get("coverage_expectations", ())),
            override_rules=tuple(OverrideRule.from_dict(o) for o in data.get("override_rules", ())),
            non_overridable_conditions=tuple(data.get("non_overridable_conditions", ())),
            provenance=data.get("provenance", "api"),
            derived_from=data.get("derived_from"),
            metadata=data.get("metadata") or {})
        stored = data.get("digest")
        if stored and stored != methodology.digest:
            raise MethodologyDriftError(
                f"methodology digest in the document ({stored}) does not match the value "
                f"recomputed from its content ({methodology.digest}) — the definition was "
                "modified after it was written")
        return methodology


# ── assessment ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MethodologyAssessment:
    """What a methodology found when held against a case.

    Not a verdict. This reports which expectations are met, unmet, or
    unevaluable, and what would resolve each gap; composing that into
    PROMOTE/HOLD/BLOCK is the policy engine's job, with other analyses alongside.
    """

    status: AssessmentStatus
    methodology_ref: Optional[str] = None
    methodology_digest: Optional[str] = None
    results: Tuple[RequirementResult, ...] = ()
    detail: str = ""

    def by_outcome(self, outcome: RequirementOutcome) -> Tuple[RequirementResult, ...]:
        return tuple(r for r in self.results if r.outcome is outcome)

    def unmet(self, effect: Optional[RequirementEffect] = None) -> Tuple[RequirementResult, ...]:
        """Everything not met — including what could not be evaluated."""
        return tuple(r for r in self.results
                     if not r.is_met and (effect is None or r.effect is effect))

    @property
    def required_evidence(self) -> Tuple[Dict[str, Any], ...]:
        """What would resolve each gap — the raw material of RequiredEvidence."""
        return tuple({"requirement_id": r.requirement_id, "outcome": r.outcome.value,
                      "effect": r.effect.value, "needed": r.remedy or r.description,
                      "because": r.detail}
                     for r in self.unmet() if r.remedy or r.description)

    @property
    def all_met(self) -> bool:
        """True only for a fully assessed case with nothing outstanding."""
        return self.status is AssessmentStatus.ASSESSED and not self.unmet()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "methodology": self.methodology_ref,
            "methodology_digest": self.methodology_digest,
            "detail": self.detail,
            "results": [r.to_dict() for r in self.results],
            "summary": {outcome.value: len(self.by_outcome(outcome))
                        for outcome in RequirementOutcome},
            "required_evidence": list(self.required_evidence),
        }


def assess(case: AssuranceCase, methodology: Optional[AssuranceMethodology],
           *, hypothetical: bool = False) -> MethodologyAssessment:
    """Hold a case against a methodology, or report why that cannot be done.

    With no methodology the answer is `METHODOLOGY_REQUIRED`, not a pass: the
    structural analyses still have plenty to say about a case, but sufficiency is
    a question that only a stated yardstick can answer, and inventing one would
    be release-gate claiming a domain standard it does not have (Invariant 10).

    If the case already records a methodology, the one passed here must be it.
    Assessing a case under a yardstick other than the one it records is the same
    failure as a methodology changing in place, arrived at from the other
    direction, so it raises. Pass `hypothetical=True` for a deliberate what-if —
    the result says so in its detail and must not be presented as the case's
    assessment.
    """
    if methodology is not None and case.methodology is not None and not hypothetical:
        recorded = case.methodology
        if (recorded.methodology_id != methodology.methodology_id
                or recorded.version != methodology.version):
            raise MethodologyError(
                f"this case is argued under {recorded.ref}, not {methodology.ref_string}; "
                "assessing it under a different yardstick would produce a result that "
                "does not describe the case. Pass hypothetical=True for a what-if.")
        if recorded.digest and recorded.digest != methodology.digest:
            raise MethodologyDriftError(
                f"the case records {recorded.ref} with digest {recorded.digest}, but the "
                f"methodology supplied digests to {methodology.digest} — it changed "
                "content without changing its version.")
    if methodology is None:
        return MethodologyAssessment(
            status=AssessmentStatus.METHODOLOGY_REQUIRED,
            detail=("No methodology is in force for this case, so no statement about "
                    "evidence sufficiency can be made. Structural findings still apply."))
    if not methodology.applies_to(case):
        return MethodologyAssessment(
            status=AssessmentStatus.CASE_TYPE_NOT_COVERED,
            methodology_ref=methodology.ref_string, methodology_digest=methodology.digest,
            detail=(f"{methodology.ref_string} covers "
                    f"{', '.join(c.value for c in methodology.case_types)} and this case is "
                    f"{case.case_type.value}; assessing it anyway would apply a yardstick "
                    "built for a different class of decision."))
    results = tuple(r.evaluate(case) for r in methodology.all_requirements())
    detail = f"{len(results)} requirement(s) evaluated under {methodology.ref_string}"
    if hypothetical:
        detail += (" — HYPOTHETICAL: this is a what-if against a methodology the case does "
                   "not record, and is not the case's assessment")
    return MethodologyAssessment(
        status=AssessmentStatus.ASSESSED, methodology_ref=methodology.ref_string,
        methodology_digest=methodology.digest, results=results, detail=detail)


def assess_case(case: AssuranceCase,
                registry: "MethodologyRegistry") -> MethodologyAssessment:
    """Assess a case against the methodology it actually records.

    The API-native path: the case names its yardstick, the registry resolves it
    (checking the content digest on the way through), and there is no opportunity
    for a caller to pair a case with the wrong one.
    """
    if case.methodology is None:
        return assess(case, None)
    return assess(case, registry.resolve(case.methodology))


# ── registry ────────────────────────────────────────────────────────────────

class MethodologyRegistry:
    """Resolves `id@version` to an exact, content-checked methodology.

    The registry is where "must never silently change for an existing case"
    becomes mechanical: registering different content under a version that
    already exists is refused outright, so a case's recorded ref keeps meaning
    what it meant when the case was argued.
    """

    def __init__(self) -> None:
        self._by_key: Dict[str, AssuranceMethodology] = {}
        self._sources: Dict[str, str] = {}

    def register(self, methodology: AssuranceMethodology, *, source: str = "") -> AssuranceMethodology:
        key = methodology.ref_string
        existing = self._by_key.get(key)
        if existing is not None:
            if existing.digest != methodology.digest:
                raise MethodologyDriftError(
                    f"{key} is already registered with different content "
                    f"({existing.digest} vs {methodology.digest}). A methodology's content "
                    "is fixed by its version: publish a new version rather than editing one "
                    "that cases have already been argued against.")
            return existing
        self._by_key[key] = methodology
        self._sources[key] = source or methodology.provenance
        return methodology

    def resolve(self, ref: Any) -> AssuranceMethodology:
        """Resolve a `MethodologyRef`, an `id@version` string, or a methodology.

        A bare id is refused: resolving "the latest" implicitly is how an existing
        case silently acquires a different bar. Callers who want the newest must
        ask for it by name through `latest()` and record what they got.
        """
        if isinstance(ref, AssuranceMethodology):
            return ref
        key = ref.ref if isinstance(ref, MethodologyRef) else str(ref)
        if "@" not in key:
            available = ", ".join(sorted(self.versions(key))) or "none registered"
            raise MethodologyError(
                f"{key!r} names no version. Pin one as '{key}@X.Y.Z' (available: "
                f"{available}), or call latest() and record the version it returned.")
        methodology = self._by_key.get(key)
        if methodology is None:
            raise MethodologyError(
                f"unknown methodology {key!r}; registered: "
                f"{', '.join(sorted(self._by_key)) or 'none'}")
        if isinstance(ref, MethodologyRef) and ref.digest and ref.digest != methodology.digest:
            raise MethodologyDriftError(
                f"{key} is registered with digest {methodology.digest}, but the case "
                f"references {ref.digest}. The methodology changed content without "
                "changing its version; this case cannot be re-assessed against it.")
        return methodology

    def latest(self, methodology_id: str) -> AssuranceMethodology:
        candidates = [m for m in self._by_key.values() if m.methodology_id == methodology_id]
        if not candidates:
            raise MethodologyError(f"no methodology registered under {methodology_id!r}")
        return max(candidates, key=lambda m: m.version_tuple())

    def versions(self, methodology_id: str) -> Tuple[str, ...]:
        return tuple(sorted(m.version for m in self._by_key.values()
                            if m.methodology_id == methodology_id))

    def ids(self) -> Tuple[str, ...]:
        return tuple(sorted({m.methodology_id for m in self._by_key.values()}))

    def source_of(self, ref: str) -> str:
        return self._sources.get(ref, "")

    def list(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(
            {"methodology": key, "digest": m.digest, "domain": m.domain,
             "provenance": m.provenance, "source": self._sources.get(key, ""),
             "case_types": [c.value for c in m.case_types],
             "requirements": len(m.all_requirements())}
            for key, m in sorted(self._by_key.items()))

    def load_plugin(self, methodology: AssuranceMethodology, *, name: str) -> AssuranceMethodology:
        """Register a plugin-supplied methodology, explicitly and attributed.

        Explicit because a plugin that could auto-register would be able to lower
        an organisation's assurance bar by being installed. The provenance is
        recorded so a packet can say where the yardstick came from.
        """
        return self.register(dataclasses.replace(methodology, provenance="plugin"),
                             source=f"plugin:{name}")
