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
from release_gate.assurance.expectation import CoverageState
from release_gate.assurance.records import Presence
from release_gate.assurance.subject import SubjectType

#: Bumped to 2 when `CoverageDimensionDeclared` gained `require_assessed`. A
#: methodology serialised under v1 still loads — the field defaults to False,
#: which is exactly the old behaviour — but its *digest* changes, because the
#: predicate now serialises one more key. Anything that pinned a v1 methodology
#: digest must re-pin. Reported rather than hidden: a digest that silently
#: changes meaning is the failure content addressing exists to prevent.
METHODOLOGY_MODEL_VERSION = 2

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
    """A named coverage dimension must be stated (Invariant 9).

    `require_assessed` is the difference between "somebody answered the question"
    and "the answer was yes". Stating a dimension as NOT_ASSESSED satisfies this
    predicate by default, and should: a case that says plainly what it did not
    look at has met the coverage obligation, and a methodology that refused it
    would be pressuring cases to stay silent rather than declare a gap.

    A methodology whose decision genuinely cannot be taken without a dimension
    sets `require_assessed=True`, which is a domain judgement about sufficiency
    and not a structural one — the layering this module keeps throughout.
    """

    KIND = "coverage_dimension_declared"
    dimension: str
    require_assessed: bool = False

    def describe(self) -> str:
        return (f"coverage states the {self.dimension!r} dimension"
                + (" and it was actually assessed" if self.require_assessed else ""))

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection("coverage")
        if coll.presence is not Presence.PRESENT:
            return _Finding(RequirementOutcome.UNSATISFIED,
                            "no coverage was supplied; a verdict without coverage is "
                            "invalid (Invariant 9)", {"presence": coll.presence.value})
        records, incomplete, total = _records(case, "coverage")
        found = [r for r in records if r.get(FIELD_DIMENSION) == self.dimension]
        observed = {"dimension": self.dimension, "rows_held": len(records),
                    "total_count": total, "require_assessed": self.require_assessed}
        if found:
            observed["state"] = found[0].get("state")
            observed["note"] = found[0].get("note")
        if not (found and self.require_assessed):
            return _threshold_outcome(
                bool(found), incomplete,
                met_detail=f"coverage states {self.dimension!r}",
                unmet_detail=f"coverage does not state {self.dimension!r}",
                observed=observed)

        row = found[0]
        if str(row.get("state")) == CoverageState.NOT_ASSESSED.value:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{self.dimension!r} is stated as NOT_ASSESSED, and this decision "
                "cannot be taken without it: "
                + str(row.get("note") or "no basis was recorded"),
                observed)
        return _Finding(
            RequirementOutcome.SATISFIED,
            f"coverage states {self.dimension!r} as {row.get('state')}", observed)


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


@_predicate
@dataclass(frozen=True)
class ExpectationDeclared(Predicate):
    """A named coverage dimension must have a real denominator.

    The sufficiency layer over `RG-EXPECT-002`, which is advisory because most
    dimensions genuinely have nobody to state a total. This is where a decision
    that turns on a particular dimension says that "we observed nine and nobody
    knows of what" is not good enough for it.

    `require_independent` is the one worth setting. An expectation written by the
    party that produced the evidence cannot detect an omission — whatever was
    dropped from the evidence was dropped from the denominator with it — so a
    methodology guarding against silent omission has to ask for a denominator
    from somewhere else (Invariant 13). Signing does not substitute: it
    establishes which party wrote the number, not that they were disinterested.
    """

    KIND = "expectation_declared"
    dimension: str = ""
    require_independent: bool = False
    minimum_coverage: Optional[float] = None
    allow_unexpected: bool = True

    def __post_init__(self) -> None:
        if not (self.dimension or "").strip():
            raise MethodologyError(
                "expectation_declared must name the dimension it is about")
        object.__setattr__(self, "dimension", self.dimension.strip())
        if self.minimum_coverage is not None and not 0 <= self.minimum_coverage <= 1:
            raise MethodologyError("minimum_coverage must be a ratio between 0 and 1")

    def describe(self) -> str:
        parts = [f"the {self.dimension!r} dimension states how much evidence to expect"]
        if self.require_independent:
            parts.append("from a party other than the one that produced it")
        if self.minimum_coverage is not None:
            parts.append(f"with at least {self.minimum_coverage:.0%} of it observed")
        if not self.allow_unexpected:
            parts.append("and nothing arriving that the expectation did not name")
        return ", ".join(parts)

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, "coverage")
        rows = [r for r in records if r.get(FIELD_DIMENSION) == self.dimension]
        if not rows:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                f"no coverage row states the {self.dimension!r} dimension, so whether "
                "anything was expected of it has not been assessed",
                {"dimension": self.dimension, "rows_held": len(records),
                 "materialisation_incomplete": incomplete})

        row = rows[0]
        observed = {"dimension": self.dimension, "state": row.get("state"),
                    "expected": row.get("expected"), "observed": row.get("observed"),
                    "known_missing": row.get("known_missing"),
                    "coverage": row.get("coverage"),
                    "expectation_standing": row.get("expectation_standing"),
                    "self_certified": row.get("self_certified"),
                    "unexpected": len(row.get("unexpected_ids") or ()),
                    # Restated at the point of judgement: satisfying this predicate
                    # is not a completeness finding, because the expectation it
                    # reads is itself a declaration.
                    "bounds_completeness": False,
                    "materialisation_incomplete": incomplete}

        if row.get("expected") is None:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{row.get('observed')} {self.dimension} record(s) were observed and "
                "nothing states how many there should have been, so coverage is "
                "UNKNOWN and no proportion of this dimension has been established",
                observed)

        if self.require_independent and row.get("self_certified"):
            source = (row.get("source") or {}).get("declared_by") or "its producer"
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"the {self.dimension!r} expectation was declared by {source}, which "
                "also produced the evidence; a denominator written by the counted "
                "party cannot detect an omission (Invariant 13)",
                observed)

        coverage = row.get("coverage")
        if coverage is None:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"coverage of {self.dimension!r} could not be computed: "
                + str(row.get("basis") or "the denominator is not usable"),
                observed)

        if self.minimum_coverage is not None and float(coverage) < self.minimum_coverage:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{float(coverage):.0%} of the expected {self.dimension} arrived, "
                f"below the {self.minimum_coverage:.0%} this methodology requires; "
                f"{row.get('known_missing')} known missing",
                observed)

        if not self.allow_unexpected and (row.get("unexpected_ids") or ()):
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{len(row.get('unexpected_ids') or ())} {self.dimension} record(s) "
                "arrived that the expectation did not name",
                observed)

        return _Finding(
            RequirementOutcome.SATISFIED,
            f"{float(coverage):.0%} of the {row.get('expected')} expected "
            f"{self.dimension} arrived" +
            ("; the expectation is self-reported, which this predicate reports and "
             "does not refuse" if row.get("self_certified") else ""),
            observed)


def _critical_ids(case: AssuranceCase, collection: str = "evidence"
                  ) -> Tuple[frozenset, Optional["_Finding"], bool]:
    """The load-bearing claim ids, or the finding that says why they are unknown.

    Extracted so every predicate about load-bearing claims reads one criticality
    profile through one set of refusals. A second copy of this would be a second
    definition of "load-bearing", and two definitions that drift is precisely the
    failure Invariant 12 is about.

    Returns `(ids, refusal, incomplete)`. When `refusal` is not None the caller
    must return it unchanged: it carries the reason the set could not be derived,
    and every one of those reasons is NOT_ASSESSED rather than a pass, because
    reporting "all clear" over a set that could not be built is the vacuous pass
    these predicates exist to prevent (Invariant 3).
    """
    records, incomplete, _total = _records(case, collection)
    derived = [r for r in records if r.get("record_type") == "criticality"]
    if not derived:
        return frozenset(), _Finding(
            RequirementOutcome.NOT_ASSESSED,
            "no criticality analysis is recorded, so which claims the decision "
            "rests on has not been derived and this cannot be assessed",
            {"materialisation_incomplete": incomplete}), incomplete
    profile = derived[0]
    if not profile.get("determinable"):
        return frozenset(), _Finding(
            RequirementOutcome.NOT_ASSESSED,
            "what this decision rests on could not be derived: " +
            str(profile.get("basis") or ""),
            {"determinable": False}), incomplete

    critical = frozenset(profile.get("critical_ids") or ())
    truncated = int(profile.get("critical_ids_truncated") or 0)
    if truncated:
        return critical, _Finding(
            RequirementOutcome.NOT_ASSESSED,
            f"{truncated} load-bearing claim(s) were not listed, so what rests on "
            "this decision cannot be established from what is held",
            {"critical": len(critical), "critical_ids_truncated": truncated}), incomplete
    if not critical:
        return critical, _Finding(
            RequirementOutcome.NOT_ASSESSED,
            "no claim is load-bearing on this case, so there is nothing for this "
            "requirement to be about", {"critical": 0}), incomplete
    return critical, None, incomplete


def _claim_graph(case: AssuranceCase) -> Optional[Any]:
    """The case's claim graph, or None when it declares no claims.

    Imported at call time for the same reason `_attempts_of` does it: the claims
    module reaches back into this one, and a module-level import would close the
    cycle.
    """
    try:
        from release_gate.assurance.claims import ClaimGraph
        return ClaimGraph.from_case(case)
    except Exception:
        return None


def _attempts_of(case: AssuranceCase) -> Tuple[Any, ...]:
    """Every verification attempt the case holds, from both places they live.

    Read through `VerificationGraph.from_case`, which already folds the
    `verification` collection together with the attempts embedded on claims. A
    predicate that scanned one collection would silently miss the other — and did,
    until a case whose attempts hung off its claims reported NOT_ASSESSED for
    three separate rules that had the evidence in front of them.
    """
    try:
        from release_gate.assurance.verification import VerificationGraph
        return tuple(VerificationGraph.from_case(case).attempts)
    except Exception:
        return ()


@_predicate
@dataclass(frozen=True)
class CriticalClaimsVerified(Predicate):
    """Every claim the decision rests on carries an applicable verification.

    `VerificationPresent` counts verification *records* across a case, which
    answers "was anything checked". This answers "was everything load-bearing
    checked", and the two come apart exactly where it matters: a case with three
    hundred verifications and one unverified lemma the conclusion rests on passes
    the first and fails this.

    `methods` narrows what counts. A research profile that accepts a theorem
    prover and refuses cross-model review is making a typing claim about
    verification (Invariant 8), not a claim about which tools are fashionable:
    models agreeing about a proof is agreement, not verification.
    """

    KIND = "critical_claims_verified"
    methods: Tuple[str, ...] = ()
    require_applicable: bool = True
    collection: str = "evidence"

    def __post_init__(self) -> None:
        object.__setattr__(self, "methods",
                           tuple(sorted({str(m).upper() for m in self.methods})))

    def describe(self) -> str:
        methods = (", ".join(m.lower().replace("_", " ") for m in self.methods)
                   if self.methods else "any accepted method")
        return (f"every load-bearing claim carries a verification by {methods}"
                + (", applicable to its current state" if self.require_applicable
                   else ""))

    def evaluate(self, case: AssuranceCase) -> _Finding:
        # Without criticality there is no set of load-bearing claims to check
        # against, and reporting "all verified" over an empty set would be the
        # vacuous pass this predicate exists to prevent (Invariant 3).
        critical, refusal, incomplete = _critical_ids(case, self.collection)
        if refusal is not None:
            return refusal

        verified: Dict[str, List[str]] = {}
        for attempt in _attempts_of(case):
            target = getattr(attempt, "target", None)
            if target is None or target.kind.value != "CLAIM":
                continue
            if attempt.status.value != "PASSED":
                continue
            method = attempt.method.value
            if self.methods and method not in self.methods:
                continue
            if self.require_applicable and not attempt.target_digest:
                # No digest means applicability is UNDETERMINED, and UNDETERMINED
                # is emphatically not APPLIES (Invariant 5).
                continue
            verified.setdefault(target.target_id, []).append(method)

        unverified = sorted(critical - set(verified))
        observed = {"critical": len(critical), "verified": len(critical) - len(unverified),
                    "unverified": unverified[:12],
                    "methods": list(self.methods),
                    "require_applicable": self.require_applicable,
                    "materialisation_incomplete": incomplete}
        if unverified:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{len(unverified)} of {len(critical)} load-bearing claim(s) carry no "
                + ("applicable " if self.require_applicable else "")
                + "verification by an accepted method: "
                + ", ".join(unverified[:4]),
                observed)
        return _Finding(
            RequirementOutcome.SATISFIED,
            f"all {len(critical)} load-bearing claim(s) are verified", observed)


@_predicate
@dataclass(frozen=True)
class NoClaimInStatus(Predicate):
    """No claim may stand in one of the named statuses (Invariant 7).

    `NoUnresolved` reads a collection of *recorded disagreements*. This reads the
    status the claim graph *computes*, and they catch different failures. A claim
    with evidence on both sides is a contradiction and gets a record. A claim with
    nothing but evidence against it is not a disagreement at all — it is refuted,
    and no contradiction record is ever written for it.

    That gap is not hypothetical. Static analysis finding a taint path to an
    execution sink, with nothing answering it, produces exactly the second shape:
    the claim "this code is safe" comes out REFUTED while the contradictions
    collection is empty. A profile guarding only the first reports a clean bill of
    health on it, which is the false-clean this predicate exists to close.

    `scope="critical"` asks only about claims the decision rests on, so a refuted
    claim nothing depends on does not block — dependency criticality decides what
    matters here, not count (Invariant 12).
    """

    KIND = "no_claim_in_status"
    statuses: Tuple[str, ...] = ("REFUTED",)
    scope: str = "critical"

    def __post_init__(self) -> None:
        statuses = tuple(sorted({str(s).strip().upper() for s in self.statuses
                                 if str(s).strip()}))
        if not statuses:
            raise MethodologyError(
                "no_claim_in_status must name at least one status to forbid")
        object.__setattr__(self, "statuses", statuses)
        scope = str(self.scope).strip().lower()
        if scope not in ("critical", "all"):
            raise MethodologyError(
                "no_claim_in_status scope must be 'critical' or 'all', "
                f"not {self.scope!r}")
        object.__setattr__(self, "scope", scope)

    def describe(self) -> str:
        statuses = ", ".join(s.lower() for s in self.statuses)
        subject = ("no load-bearing claim" if self.scope == "critical"
                   else "no claim")
        return f"{subject} is {statuses}"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        collection = case.collection("claims")
        if collection.presence is not Presence.PRESENT:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no claims were supplied, so whether any stands refuted has not "
                "been assessed", {"presence": collection.presence.value})
        graph = _claim_graph(case)
        if graph is None:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "the claims collection could not be modelled as a graph, so no "
                "claim status has been computed", {"presence": "PRESENT"})

        incomplete = collection.not_materialised > 0
        if self.scope == "critical":
            candidates, refusal, crit_incomplete = _critical_ids(case)
            if refusal is not None:
                return refusal
            incomplete = incomplete or crit_incomplete
        else:
            candidates = frozenset(c.claim_id for c in graph.claims)

        forbidden = set(self.statuses)
        offending = sorted(
            cid for cid in candidates
            if getattr(graph.status(cid), "value", None) in forbidden)
        observed = {"scope": self.scope, "statuses": list(self.statuses),
                    "examined": len(candidates), "offending": offending[:12],
                    "offending_count": len(offending),
                    "materialisation_incomplete": incomplete}
        subject = ("load-bearing claim(s)" if self.scope == "critical"
                   else "claim(s)")
        return _absence_outcome(
            offending, incomplete,
            clean_detail=(f"none of the {len(candidates)} {subject} examined is "
                          + " or ".join(s.lower() for s in self.statuses)),
            violation_detail=(
                f"{len(offending)} {subject} stand(s) "
                + " or ".join(s.lower() for s in self.statuses)
                + ", with nothing recorded that answers the evidence against "
                  "them: " + ", ".join(offending[:4])),
            observed=observed)


@_predicate
@dataclass(frozen=True)
class DeclaredIndependenceHolds(Predicate):
    """Independence a producer *asserted* must survive tracing its lineage.

    Reads `independence_lineage` on verification attempts, which is a producer
    saying "this check rests on these and nothing else" — a falsifiable claim
    about the world. It deliberately does **not** read `independence_group` on
    evidence records: that is release-gate's own fingerprint over source and
    producer, so comparing it against release-gate's own ancestry tracing would
    fire on any case with two producers and one upstream, which is the normal and
    often correct shape the independence analyser reports and never penalises.

    Nothing here accuses anyone of bad faith: a shared upstream nobody noticed
    produces exactly the same shape. What it refuses is letting an assertion win
    over the derivation (Invariant 1).
    """

    KIND = "declared_independence_holds"
    tolerance: int = 0
    collection: str = "evidence"

    def __post_init__(self) -> None:
        if self.tolerance < 0:
            raise MethodologyError("tolerance cannot be negative")

    def describe(self) -> str:
        return ("asserted verification lineages are borne out by traced ancestry"
                + (f", allowing {self.tolerance} more asserted than derived"
                   if self.tolerance else ""))

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, self.collection)
        profiles = [r for r in records if r.get("record_type") == "independence"]
        attempts = _attempts_of(case)

        asserted: Set[str] = set()
        for attempt in attempts:
            asserted |= {str(x) for x in (attempt.independence_lineage or ())}
        if not asserted:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no verification attempt asserts an independence lineage, so there is "
                "no claim of independence to hold against the ancestry",
                {"asserted_lineages": 0, "attempts": len(attempts),
                 "materialisation_incomplete": incomplete})
        if not profiles:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no independence profile is recorded, so asserted lineages cannot be "
                "compared against traced ancestry",
                {"asserted_lineages": len(asserted)})

        profile = profiles[0]
        if not profile.get("determinable"):
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "ancestry is not determinable: " + str(profile.get("basis") or ""),
                {"asserted_lineages": len(asserted), "determinable": False})

        derived = int(profile.get("independent_roots") or 0)
        observed = {"asserted_lineages": len(asserted),
                    "derived_lineages": derived, "tolerance": self.tolerance,
                    "unknown_ancestry": profile.get("unknown_ancestry"),
                    "materialisation_incomplete": incomplete}
        if len(asserted) - derived > self.tolerance:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{len(asserted)} independence lineage(s) are asserted across the "
                f"verification attempts and the evidence traces to {derived} "
                "lineage(s); the assertion claims more independence than the "
                "derivation supports, and the derivation wins (Invariant 1)",
                observed)
        return _Finding(
            RequirementOutcome.SATISFIED,
            f"{len(asserted)} asserted lineage(s) against {derived} traced", observed)


@_predicate
@dataclass(frozen=True)
class AppliesToCurrentState(Predicate):
    """What the argument rests on must still apply to the state in front of you.

    One shape, three questions: a verification whose target moved, evidence
    produced against a superseded digest, and an artifact mutated after being
    verified are the same failure seen from three sides — something the argument
    rests on is no longer the thing it was about (Invariant 5).

    `scope` selects which side. Keeping them one predicate rather than three
    means the rule that decides "does this still apply" is written once, and a
    case cannot pass one side while failing the identical test on another.
    """

    KIND = "applies_to_current_state"
    scope: str = "verification"      # verification | evidence | artifact
    collection: str = "evidence"

    _SCOPES = ("verification", "evidence", "artifact")

    def __post_init__(self) -> None:
        if self.scope not in self._SCOPES:
            raise MethodologyError(
                f"scope must be one of {', '.join(self._SCOPES)}; got {self.scope!r}")

    def describe(self) -> str:
        return {
            "verification": "no verification applies to a state its target has left",
            "evidence": "no evidence in use was produced against a superseded digest",
            "artifact": "no verified artifact has been mutated since",
        }[self.scope]

    def evaluate(self, case: AssuranceCase) -> _Finding:
        current: Dict[str, str] = {}
        for record in case.records("artifacts"):
            payload = record.to_dict() if hasattr(record, "to_dict") else {}
            logical = str(payload.get("logical_id") or payload.get("artifact_id") or "")
            digest = str(payload.get("digest") or "")
            if logical and digest:
                current[logical] = digest
        if not current and self.scope in ("evidence", "artifact"):
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no artifact carries a digest, so whether anything was produced "
                "against a superseded state cannot be asked", {"artifacts": 0})

        records, incomplete, _total = _records(case, self.collection)
        known = set(current.values())
        stale: List[str] = []

        if self.scope == "verification":
            attempts = _attempts_of(case)
            if not attempts:
                return _Finding(
                    RequirementOutcome.NOT_ASSESSED,
                    "no verification attempts are recorded, so whether any has gone "
                    "stale cannot be asked", {"attempts": 0})
            for attempt in attempts:
                digest = attempt.target_digest or ""
                target = getattr(attempt, "target", None)
                logical = target.target_id if target is not None else ""
                if digest and logical in current and current[logical] != digest:
                    stale.append(attempt.verification_id)
        elif self.scope == "evidence":
            for record in (r for r in records if r.get("record_type") == "evidence"):
                applies = str(record.get("applies_to_digest") or "")
                if applies and applies not in known:
                    stale.append(str(record.get("record_id") or ""))
        else:
            for record in case.records("artifacts"):
                payload = record.to_dict() if hasattr(record, "to_dict") else {}
                if payload.get("verified_digest") and (
                        payload.get("verified_digest") != payload.get("digest")):
                    stale.append(str(payload.get("logical_id") or ""))

        observed = {"scope": self.scope, "stale": stale[:12], "count": len(stale),
                    "artifacts": len(current),
                    "materialisation_incomplete": incomplete}
        if stale:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{len(stale)} {self.scope} record(s) no longer apply to the current "
                "state: " + ", ".join(stale[:4]) +
                ". What the argument rests on has moved since it was established",
                observed)
        return _Finding(
            RequirementOutcome.SATISFIED,
            f"every {self.scope} record applies to the current state", observed)


@_predicate
@dataclass(frozen=True)
class CriticalClaimsIdentified(Predicate):
    """What this decision rests on must be established before it can be taken.

    The sufficiency layer over `RG-CRIT-001`, and the only predicate whose
    absence disables other predicates. Every critical-claim guard in the analysis
    — unresolved counterexamples, adversarial argument defects, divergent
    replication, the contradiction a verdict may not omit — asks whether a claim
    is critical. Where criticality could not be derived they all answer no, and
    the case comes out clean because nothing was checked. A methodology for any
    consequential decision should say that is not acceptable.

    `require_supported` additionally asks that nothing load-bearing is left
    resting on nothing at all. It is off by default: a case can legitimately
    rest on a claim whose support is still arriving, and that is a hold for the
    coverage analysers to report rather than a malformed methodology.
    """

    KIND = "critical_claims_identified"
    require_determinable: bool = True
    require_supported: bool = False
    forbid_broken_chains: bool = True
    maximum_declared_disagreements: Optional[int] = 0
    #: How many load-bearing claims may rest on a single producer. `None` allows
    #: any number, which is the right default: thinness is a fact to show a
    #: reviewer, not a fault, and only a domain that genuinely needs corroboration
    #: on what it rests on should make it blocking (Invariant 12).
    maximum_thin: Optional[int] = None
    collection: str = "evidence"

    def describe(self) -> str:
        parts = []
        if self.require_determinable:
            parts.append("what this decision rests on is derivable from the claim graph")
        if self.forbid_broken_chains:
            parts.append("no load-bearing claim depends on a claim the case does not hold")
        if self.maximum_declared_disagreements is not None:
            parts.append(f"at most {self.maximum_declared_disagreements} claim(s) "
                         "declared critical that nothing the decision rests on needs")
        if self.maximum_thin is not None:
            parts.append(f"at most {self.maximum_thin} load-bearing claim(s) resting "
                         "on a single producer")
        if self.require_supported:
            parts.append("every load-bearing claim cites some support")
        return ", ".join(parts) or "criticality is recorded"

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, self.collection)
        sets = [r for r in records if r.get("record_type") == "criticality"]
        if not sets:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no criticality analysis is recorded on this case, so what the "
                "decision rests on has not been derived",
                {"materialisation_incomplete": incomplete})

        derived = sets[0]
        observed = {"determinable": derived.get("determinable"),
                    "link": derived.get("link"),
                    "claims": derived.get("claims_examined"),
                    "critical": derived.get("critical"),
                    "max_depth": derived.get("max_depth"),
                    "broken_chains": derived.get("broken_chains"),
                    "disagreements": derived.get("disagreements"),
                    "thin_critical": derived.get("thin_critical"),
                    # Restated at the point of judgement, not only at the point of
                    # measurement: nothing in this predicate reads a volume either.
                    "volume_affects_criticality": False,
                    "materialisation_incomplete": incomplete}

        if self.require_determinable and not derived.get("determinable"):
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                "what this decision rests on could not be established, so no claim is "
                "known to be critical and every critical-claim guard was inactive; "
                "a clean result here would mean nothing was checked",
                observed)

        if self.forbid_broken_chains and int(derived.get("broken_chains") or 0):
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{derived.get('broken_chains')} load-bearing claim(s) depend on "
                "claims this case does not hold, so part of what the decision rests "
                "on is outside the case entirely",
                observed)

        limit = self.maximum_declared_disagreements
        if limit is not None and int(derived.get("disagreements") or 0) > limit:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{derived.get('disagreements')} claim(s) are declared critical that "
                "nothing the decision rests on depends on; either the labels are "
                "wrong or dependency edges are missing, and this methodology does "
                "not accept the ambiguity",
                observed)

        if self.maximum_thin is not None and \
                int(derived.get("thin_critical") or 0) > self.maximum_thin:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{derived.get('thin_critical')} load-bearing claim(s) rest on a "
                f"single producer, above the {self.maximum_thin} this methodology "
                "allows; a claim one party emitted once is exactly as load-bearing "
                "as one many parties discussed, and this domain requires the "
                "support to be corroborated rather than merely present",
                observed)

        if self.require_supported:
            unsupported = [e.get("claim_id") for e in (derived.get("entries") or ())
                           if e.get("critical") and not e.get("supporting_records")]
            if unsupported or int(derived.get("entries_truncated") or 0):
                observed["unsupported_critical"] = unsupported[:12]
                return _Finding(
                    RequirementOutcome.UNSATISFIED,
                    f"{len(unsupported)} load-bearing claim(s) cite no supporting "
                    "evidence: " + ", ".join(str(c) for c in unsupported[:4]),
                    observed)

        return _Finding(
            RequirementOutcome.SATISFIED,
            f"the decision rests on {derived.get('critical')} of "
            f"{derived.get('claims_examined')} claim(s), reached through up to "
            f"{derived.get('max_depth')} dependency link(s)" +
            (f"; {derived.get('thin_critical')} of them rest on a single producer, "
             "which this predicate reports and does not penalise"
             if int(derived.get("thin_critical") or 0) else ""),
            observed)


@_predicate
@dataclass(frozen=True)
class AdversarialReviewRequired(Predicate):
    """Something must have set out to disprove this, and got a fair hearing.

    The only place the absence of adversaries costs anything. Release-Gate never
    requires them — most decisions have none and are not worse for it — so a
    methodology has to say that *this* class of decision needs somebody trying to
    break it before an empty adversarial review becomes a verdict.

    Three separate things are checked, because passing one is not passing the
    others. Enough attacks happened; they came from adversaries not shown to
    share origin with what they attacked; and nothing they found was closed by
    the party it was against. The last is the one that catches the realistic
    failure: a case with a full red-team report where every finding was waved
    through by the team that built the thing.
    """

    KIND = "adversarial_review_required"
    minimum_attacks: int = 1
    required_roles: Tuple[str, ...] = ()
    require_independent: bool = True
    forbid_self_cleared: bool = True
    require_critical_coverage: bool = False
    collection: str = "evidence"

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_roles",
                           tuple(sorted({str(r).upper() for r in self.required_roles})))
        if self.minimum_attacks < 1:
            raise MethodologyError(
                "minimum_attacks must be at least 1; a requirement for zero "
                "adversarial review is not a requirement")

    def describe(self) -> str:
        parts = [f"at least {self.minimum_attacks} adversarial attack(s) on this case"]
        if self.required_roles:
            parts.append("including " + ", ".join(r.lower().replace("_", " ")
                                                  for r in self.required_roles))
        if self.require_independent:
            parts.append("from an adversary independent of what it attacked")
        if self.forbid_self_cleared:
            parts.append("with no finding closed by the party it was against")
        if self.require_critical_coverage:
            parts.append("covering every critical claim")
        return ", ".join(parts)

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, self.collection)
        reviews = [r for r in records if r.get("record_type") == "adversarial_review"]
        if not reviews:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no adversarial review is recorded on this case; nothing set out to "
                "disprove the candidate, so whether it survives being attacked has "
                "not been assessed",
                {"attacks": 0, "materialisation_incomplete": incomplete})

        review = reviews[0]
        attacks = int(review.get("total") or 0)
        observed = {"attacks": attacks, "minimum_attacks": self.minimum_attacks,
                    "independent": review.get("independent"),
                    "non_independent": review.get("non_independent"),
                    "self_cleared": review.get("self_cleared"),
                    "open": review.get("open"),
                    "accepted_risks": review.get("accepted_risks"),
                    "claims_attacked": review.get("claims_attacked"),
                    "required_roles": list(self.required_roles),
                    "materialisation_incomplete": incomplete}

        if attacks < self.minimum_attacks:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{attacks} adversarial attack(s) recorded, {self.minimum_attacks} "
                "required by this methodology",
                observed)

        if self.forbid_self_cleared and int(review.get("self_cleared") or 0):
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{review.get('self_cleared')} adversarial finding(s) were closed by "
                "the party they were against; a finding answered by what it argues "
                "against has not been independently answered",
                observed)

        if self.require_independent and not int(review.get("independent") or 0):
            unknown = int(review.get("by_stance", {}).get("UNDETERMINED") or 0)
            extra = (f"; {unknown} attack(s) record nothing from which independence "
                     "could be derived" if unknown else "")
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                "no adversarial attack came from an adversary shown independent of "
                f"what it attacked{extra}. An adversary that shares origin with the "
                "candidate misses what the builder missed (Invariant 6)",
                observed)

        if self.required_roles:
            present = {str(f.get("role")) for f in (review.get("findings") or ())}
            missing = sorted(set(self.required_roles) - present)
            if missing:
                return _Finding(
                    RequirementOutcome.UNSATISFIED,
                    "no attack came from " + ", ".join(r.lower().replace("_", " ")
                                                       for r in missing),
                    observed)

        if self.require_critical_coverage:
            # Root claims are what the case is about; an adversarial programme that
            # attacked everything except the conclusion has covered nothing that
            # matters. Truncation is treated as not-covered rather than assumed
            # fine: a list that was cut short cannot establish what is in it.
            claims, _incomplete, _n = _records(case, "claims")
            critical = {str(c.get("claim_id")) for c in claims if c.get("is_root")}
            attacked = set(review.get("claims_attacked_ids") or ())
            missing = sorted(critical - attacked)
            if missing or int(review.get("claims_attacked_truncated") or 0):
                observed["unattacked_critical"] = missing[:12]
                return _Finding(
                    RequirementOutcome.UNSATISFIED,
                    f"{len(missing)} claim(s) this case rests on were not attacked by "
                    "any adversary: " + ", ".join(missing[:4]) +
                    ". Adversarial review elsewhere in a case is not coverage of the "
                    "claim the decision turns on",
                    observed)

        return _Finding(
            RequirementOutcome.SATISFIED,
            f"{attacks} adversarial attack(s), "
            f"{review.get('independent')} from an independent adversary" +
            (f"; {review.get('accepted_risks')} finding(s) accepted as risk rather "
             "than answered, which this predicate reports and does not refuse"
             if int(review.get("accepted_risks") or 0) else ""),
            observed)


@_predicate
@dataclass(frozen=True)
class ReplicationEstablished(Predicate):
    """A result must have been reproduced by paths that could fail differently.

    The methodology hook for "independently reproduced". Everything the analyser
    reports about replication is advisory, because a workflow that rests on one
    path is normal and often correct; this is where a decision that genuinely
    needs reproduction says so and a shortfall costs something.

    `required_axes` is what makes the examples distinguishable. "Same result via
    a different proof strategy" is `METHOD`; "same simulation via an independent
    implementation" is `IMPLEMENTATION`; "same experiment via an independent run"
    is `INPUT` or `LINEAGE`. Naming none of them accepts any axis.

    Paths are counted after copies collapse and unattributed paths are set aside,
    so there is no arrangement of self-declared replications that satisfies this
    without something recorded to derive independence from.
    """

    KIND = "replication_established"
    minimum_paths: int = 2
    required_axes: Tuple[str, ...] = ()
    require_result_equivalence: bool = False
    collection: str = "evidence"

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_axes",
                           tuple(sorted({str(a).upper() for a in self.required_axes})))
        if self.minimum_paths < 1:
            raise MethodologyError(
                "minimum_paths must be at least 1; a requirement for zero "
                "independent paths is not a requirement")

    def describe(self) -> str:
        parts = [f"the result is reproduced by at least {self.minimum_paths} "
                 "independently established path(s)"]
        if self.required_axes:
            parts.append("differing in " + ", ".join(a.lower()
                                                     for a in self.required_axes))
        if self.require_result_equivalence:
            parts.append("agreeing on the result, not only on the verdict")
        return ", ".join(parts)

    def evaluate(self, case: AssuranceCase) -> _Finding:
        records, incomplete, _total = _records(case, self.collection)
        profiles = [r for r in records if r.get("record_type") == "replication"]
        if not profiles:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no replication profile is recorded on this case, so whether anything "
                "was independently reproduced has not been derived",
                {"profiles": 0, "materialisation_incomplete": incomplete})

        profile = profiles[0]
        targets = profile.get("by_target") or []
        if not targets:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                "no verification attempt names a target, so there is nothing whose "
                "reproduction could be assessed",
                {"targets": 0, "materialisation_incomplete": incomplete})

        # The weakest target decides. A methodology that asks for reproduction is
        # asking about the result the decision rests on, and satisfying it with the
        # best-reproduced target would be exactly the "looks like its best branch"
        # failure the case model exists to prevent (Invariant 7).
        divergent = [t for t in targets if t.get("outcome") == "DIVERGENT"]
        if divergent:
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{len(divergent)} target(s) have paths that disagree; a result whose "
                "reproductions contradict each other has not been reproduced, and the "
                "paths that agree do not settle it",
                {"divergent": len(divergent),
                 "targets": [t.get("target", {}).get("target_id") for t in divergent[:8]]})

        weakest = min(targets, key=lambda t: int(t.get("established_paths") or 0))
        paths = int(weakest.get("established_paths") or 0)
        observed = {"established_paths": paths, "minimum_paths": self.minimum_paths,
                    "target": weakest.get("target", {}).get("target_id"),
                    "outcome": weakest.get("outcome"),
                    "unattributed_paths": weakest.get("unattributed_paths"),
                    "copies_collapsed": weakest.get("copies_collapsed"),
                    "axes_established": weakest.get("axes_established"),
                    "required_axes": list(self.required_axes),
                    "equivalence": weakest.get("equivalence"),
                    "materialisation_incomplete": incomplete}

        if paths < self.minimum_paths:
            unattributed = int(weakest.get("unattributed_paths") or 0)
            extra = (f"; {unattributed} further path(s) record nothing that could "
                     "establish their independence" if unattributed else "")
            return _Finding(
                RequirementOutcome.UNSATISFIED,
                f"{observed['target']} rests on {paths} established path(s), "
                f"{self.minimum_paths} required{extra}. Copies do not count as "
                "replication (Invariant 6)",
                observed)

        if self.required_axes:
            established = set(weakest.get("axes_established") or ())
            missing = sorted(set(self.required_axes) - established)
            if missing:
                return _Finding(
                    RequirementOutcome.UNSATISFIED,
                    f"the paths on {observed['target']} are not shown to differ in "
                    + ", ".join(a.lower() for a in missing) +
                    "; an axis nobody recorded is not an axis that differs",
                    observed)

        if self.require_result_equivalence:
            equivalence = str(weakest.get("equivalence") or "UNDETERMINED")
            if equivalence in ("VERDICT_ONLY", "UNDETERMINED", "DIVERGENT"):
                return _Finding(
                    RequirementOutcome.UNSATISFIED,
                    f"the paths on {observed['target']} agree on the verdict but their "
                    f"results are {equivalence}; this methodology requires the results "
                    "themselves to agree, and equivalence has to be declared because "
                    "release-gate cannot decide it",
                    observed)

        return _Finding(
            RequirementOutcome.SATISFIED,
            f"{observed['target']} is reproduced by {paths} established path(s)",
            observed)


@_predicate
@dataclass(frozen=True)
class AssumptionsExamined(Predicate):
    """Load-bearing assumptions must be stated, and something must bear on them.

    The methodology hook for "if this assumption fails, what collapses?". The
    analyser reports unexamined assumptions; only a methodology can decide that a
    decision of this kind may not be taken while a conclusion rests on something
    nobody looked at.
    """

    KIND = "assumptions_examined"
    require_stated: bool = True
    require_checked: bool = True
    collection: str = "assumptions"

    def describe(self) -> str:
        wants = []
        if self.require_stated:
            wants.append("stated")
        if self.require_checked:
            wants.append("supported by evidence or verification")
        return "load-bearing assumptions are " + " and ".join(wants or ["present"])

    def evaluate(self, case: AssuranceCase) -> _Finding:
        coll = case.collection(self.collection)
        if coll.presence is not Presence.PRESENT:
            return _Finding(
                RequirementOutcome.NOT_ASSESSED,
                f"{self.collection} was never supplied; absence of recorded "
                "assumptions is not evidence that an argument makes none",
                {"presence": coll.presence.value})
        records, incomplete, total = _records(case, self.collection)
        load_bearing = [r for r in records if r.get("criticality") == "LOAD_BEARING"]
        unstated = [r for r in load_bearing if not r.get("stated", True)]
        unchecked = [r for r in load_bearing if not r.get("checked", False)]
        observed = {"records_held": len(records), "total_count": total,
                    "load_bearing": len(load_bearing), "unstated": len(unstated),
                    "unchecked": len(unchecked)}

        problems: List[str] = []
        if self.require_stated and unstated:
            problems.append(f"{len(unstated)} load-bearing assumption(s) are never stated")
        if self.require_checked and unchecked:
            problems.append(f"{len(unchecked)} load-bearing assumption(s) have nothing "
                            "bearing on whether they hold")
        return _absence_outcome(
            problems, incomplete,
            clean_detail=(f"all {len(load_bearing)} load-bearing assumption(s) are "
                          "stated and examined"),
            violation_detail="; ".join(problems), observed=observed)


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
                requirement_id=self.requirement_id, predicate_kind=self.predicate.KIND,
                outcome=RequirementOutcome.NOT_APPLICABLE,
                effect=self.effect, description=self.description,
                detail="does not apply to this case type or subject type",
                observed={}, remedy="")
        finding = self.predicate.evaluate(case)
        return RequirementResult(
            requirement_id=self.requirement_id, predicate_kind=self.predicate.KIND,
            outcome=finding.outcome, effect=self.effect,
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
    #: The predicate that produced this. Carried so an unmet requirement can say
    #: what *kind* of evidence would satisfy it: a methodology names a standard,
    #: and a machine reading a HOLD needs the standard to be dispatchable rather
    #: than a sentence it has to parse.
    predicate_kind: str = ""

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
