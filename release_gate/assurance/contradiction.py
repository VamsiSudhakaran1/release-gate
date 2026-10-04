"""Contradictions, kept.

The failure this module exists to prevent is quiet: a system gathers evidence
pointing both ways, synthesises a confident summary, and the disagreement never
reaches the person signing. Nothing was falsified. Something was just not
mentioned.

So a contradiction here is a first-class object with an identity, both sides of
the argument, who is on each side, and how many independent lineages back each.
It is never deleted, never collapsed into a majority, and never closed without a
statement of what closed it:

* `resolve()` demands `resolution_evidence`. A contradiction cannot be marked
  RESOLVED by assertion, only by something that answers it.
* `invalidate()` demands a reason. "That was not really a contradiction" is a
  claim someone has to make and be answerable for.
* `supersede()` demands a reason. A contradiction about claims that moved on is
  closed by *that fact*, stated.

The counting is deliberately inert. Seven independent roots on one side and one
on the other is reported and never adjudicated — more sources is not more true,
and a module that resolved disagreements by weight would be doing exactly the
silent erasure it was built to stop. release-gate's job here is to make sure a
human sees the disagreement, not to settle it.

**Not every disagreement is a contradiction.** Two records pointing opposite ways
at one claim contradict each other only if they are about the same thing. Each
disagreement is classified by comparing what its sides declare — the state of
the release they ran against, the part of the system they cover, the data they
used, the environment they ran in:

* `GENUINE` — comparable on everything both sides state, and opposite. One of
  them is wrong, and a person has to find out which.
* `STALE` — the sides were produced against different states of the release, or
  one of them against a state other than the candidate's. A proof of tool_v2
  says nothing about tool_v3; an approval of build abc123 cannot satisfy
  def456.
* `SCOPE_MISMATCH` — they cover different parts: refund passed, email failed.
* `POPULATION_MISMATCH` — different datasets.
* `ENVIRONMENT_MISMATCH` — different environments.
* `AMBIGUOUS` — both sides qualify what they cover, in terms that cannot be
  compared (a static path on one side, a tool name on the other). Whether they
  disagree is unresolved, and unresolved is not settled.

The rule for what a side did not state follows the candidate binding (§10ba): a
record that names no state is taken to be about the candidate, and a side that
does not qualify its scope speaks to the claim as stated — so an unqualified
"all authorization tests pass" and a "privilege escalation succeeded" are a
genuine contradiction, because the first claims what the second refutes.

A mismatch is not called a contradiction, and it is not dropped either: the
failing side still stands against the claim on its own terms, the claim
resolution still reads it, and the disagreement stays open until something
answers it. The classification changes what a reviewer is told and what would
resolve it — re-verify on the candidate, cover the missing scope — never whether
it is seen. It is derived from the sides, so it is outside the identity.

`to_dict()` exposes `resolved`, so the existing `NoUnresolved` methodology
predicate reads these objects unchanged.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.evidence import EvidenceRecord
from release_gate.assurance.independence import analyse_independence

__all__ = [
    "CONTRADICTION_SCHEMA_VERSION",
    "ConflictClass",
    "Contradiction",
    "ContradictionError",
    "ContradictionKind",
    "ContradictionLedger",
    "ContradictionSide",
    "ContradictionStatus",
    "ConflictEdge",
    "ConflictGraph",
    "DimensionComparison",
    "classify_sides",
    "conflict_graph",
    "detect_contradictions",
]

CONTRADICTION_SCHEMA_VERSION = 1


class ContradictionError(ValueError):
    """A contradiction was closed in a way that would hide it."""


class ContradictionStatus(str, Enum):
    OPEN = "OPEN"              # stands, unanswered
    RESOLVED = "RESOLVED"      # something answered it, and that something is named
    SUPERSEDED = "SUPERSEDED"  # the claims it was about moved on
    INVALID = "INVALID"        # it was not a real conflict, and someone said why
    UNKNOWN = "UNKNOWN"        # whether it stands cannot be determined


#: OPEN and UNKNOWN are both open. "We cannot tell whether this still stands" is
#: not a closed contradiction, and treating it as one is the erasure in miniature.
_OPEN_STATUSES = frozenset({ContradictionStatus.OPEN, ContradictionStatus.UNKNOWN})


class ContradictionKind(str, Enum):
    CLAIM_EVIDENCE_CONFLICT = "CLAIM_EVIDENCE_CONFLICT"  # evidence for and against one claim
    VERIFICATION_CONFLICT = "VERIFICATION_CONFLICT"      # checks that disagree
    RECORD_SELF_CONFLICT = "RECORD_SELF_CONFLICT"        # one record, both ways
    CLAIM_CLAIM_CONFLICT = "CLAIM_CLAIM_CONFLICT"        # two claims that cannot both hold


class ConflictClass(str, Enum):
    """What a disagreement is, once its sides are compared. Derived, never declared."""

    GENUINE = "GENUINE"                            # comparable, and opposite
    STALE = "STALE"                                # different states of the release
    SCOPE_MISMATCH = "SCOPE_MISMATCH"              # different parts of the system
    POPULATION_MISMATCH = "POPULATION_MISMATCH"    # different datasets
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"  # different environments
    AMBIGUOUS = "AMBIGUOUS"                        # comparability cannot be determined


#: The classes that are not contradictions: both sides can be true at once.
MISMATCHES = frozenset({ConflictClass.STALE, ConflictClass.SCOPE_MISMATCH,
                        ConflictClass.POPULATION_MISMATCH,
                        ConflictClass.ENVIRONMENT_MISMATCH})

_DESCRIBED = {
    ConflictClass.GENUINE: "genuine contradiction: comparable, and opposite",
    ConflictClass.STALE: "not a contradiction: the sides are about different states "
                         "of the release",
    ConflictClass.SCOPE_MISMATCH: "not a contradiction: the sides cover different "
                                  "parts of the system",
    ConflictClass.POPULATION_MISMATCH: "not a contradiction: the sides used different "
                                       "datasets",
    ConflictClass.ENVIRONMENT_MISMATCH: "not a contradiction: the sides ran in "
                                        "different environments",
    ConflictClass.AMBIGUOUS: "unresolved ambiguity: whether the sides are comparable "
                             "cannot be determined",
}


class Comparison(str, Enum):
    SAME = "SAME"
    OVERLAP = "OVERLAP"
    DIFFERENT = "DIFFERENT"
    ONE_SIDED = "ONE_SIDED"            # stated by one side; the other speaks to all of it
    NOT_COMPARABLE = "NOT_COMPARABLE"  # both qualified, in terms that do not meet


@dataclass(frozen=True)
class DimensionComparison:
    """One dimension, as each side states it, and whether they meet."""

    dimension: str
    family: str          # STATE | SCOPE | POPULATION | ENVIRONMENT
    comparison: Comparison
    left: Tuple[str, ...] = ()
    right: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "comparison", Comparison(self.comparison))
        object.__setattr__(self, "left", tuple(self.left))
        object.__setattr__(self, "right", tuple(self.right))

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension, "family": self.family,
                "comparison": self.comparison.value, "left": list(self.left),
                "right": list(self.right)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DimensionComparison":
        return cls(dimension=str(data.get("dimension") or ""),
                   family=str(data.get("family") or ""),
                   comparison=Comparison(str(data.get("comparison") or "SAME")),
                   left=tuple(str(v) for v in data.get("left") or ()),
                   right=tuple(str(v) for v in data.get("right") or ()))

    def render(self) -> str:
        left = ", ".join(self.left) or "unstated"
        right = ", ".join(self.right) or "unstated"
        return f"{self.dimension}: {left} vs {right} ({self.comparison.value.lower()})"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ContradictionSide:
    """One position in a disagreement, and what stands behind it."""

    label: str
    evidence: Tuple[str, ...] = ()
    participants: Tuple[str, ...] = ()
    independent_roots: int = 0
    roots: Tuple[str, ...] = ()
    note: str = ""
    #: What sort of evidence stands here — evidence types, or check methods — so
    #: a static finding against a runtime trace reads as exactly that.
    kinds: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))
        object.__setattr__(self, "participants", tuple(sorted(set(self.participants))))
        object.__setattr__(self, "roots", tuple(sorted(set(self.roots))))
        object.__setattr__(self, "kinds", tuple(sorted(set(self.kinds))))

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "evidence": list(self.evidence),
                "participants": list(self.participants),
                "independent_roots": self.independent_roots,
                "roots": list(self.roots), "note": self.note, "kinds": list(self.kinds)}

    @classmethod
    def from_evidence(cls, label: str, records: Sequence[EvidenceRecord],
                      note: str = "") -> "ContradictionSide":
        """Build a side, deriving its lineage count from the evidence itself."""
        profile = analyse_independence(records)
        roots: Set[str] = set()
        for cluster in profile.clusters:
            roots |= set(cluster.roots)
        return cls(label=label,
                   evidence=tuple(r.evidence_id for r in records),
                   participants=tuple(r.producer.producer_id for r in records),
                   independent_roots=profile.independent_roots,
                   roots=tuple(roots), note=note,
                   kinds=tuple(r.evidence_type.value for r in records))


@dataclass(frozen=True)
class Contradiction:
    """A disagreement, preserved with both sides intact."""

    target_claims: Tuple[str, ...]
    sides: Tuple[ContradictionSide, ...] = ()
    kind: ContradictionKind = ContradictionKind.CLAIM_EVIDENCE_CONFLICT
    status: ContradictionStatus = ContradictionStatus.OPEN
    resolution: str = ""
    resolution_evidence: Tuple[str, ...] = ()
    affects_critical: bool = False
    critical_basis: str = ""
    detected_by: str = "release-gate/assurance/contradiction"
    detected_at: str = field(default_factory=_utc_now)
    detail: str = ""
    #: What the disagreement is once its sides are compared, and on what. Derived
    #: from the sides, so it is outside the identity.
    classification: ConflictClass = ConflictClass.GENUINE
    comparability: Tuple[DimensionComparison, ...] = ()
    classification_basis: str = ""
    schema_version: int = CONTRADICTION_SCHEMA_VERSION

    contradiction_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ContradictionKind(self.kind))
        object.__setattr__(self, "status", ContradictionStatus(self.status))
        object.__setattr__(self, "classification", ConflictClass(self.classification))
        object.__setattr__(self, "comparability", tuple(self.comparability))
        object.__setattr__(self, "target_claims", tuple(sorted(set(self.target_claims))))
        object.__setattr__(self, "sides", tuple(self.sides))
        object.__setattr__(self, "resolution_evidence",
                           tuple(sorted(set(self.resolution_evidence))))

        if not self.target_claims:
            raise ContradictionError(
                "a contradiction must name what it is about; one attached to nothing "
                "cannot be surfaced to anybody")

        if self.status is ContradictionStatus.RESOLVED:
            if not self.resolution.strip():
                raise ContradictionError(
                    "a RESOLVED contradiction must state its resolution — otherwise "
                    "closing it is the silent erasure this object exists to prevent")
            if not self.resolution_evidence:
                raise ContradictionError(
                    "a RESOLVED contradiction must cite resolution_evidence; a "
                    "disagreement is closed by evidence that answers it, never by "
                    "assertion that it is closed")
        if self.status in (ContradictionStatus.INVALID, ContradictionStatus.SUPERSEDED) \
                and not self.resolution.strip():
            raise ContradictionError(
                f"a {self.status.value} contradiction must say why; dismissing a "
                "recorded disagreement is a claim somebody has to be answerable for")

        object.__setattr__(self, "contradiction_id",
                           short_id("contra", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct disagreement — never its resolution.

        The id is stable across the whole life of the contradiction, so resolving
        one does not silently produce a different object that no longer matches
        what a reviewer was shown.
        """
        return {"schema_version": CONTRADICTION_SCHEMA_VERSION,
                "kind": self.kind.value,
                "target_claims": list(self.target_claims),
                "sides": [{"label": s.label, "evidence": list(s.evidence)}
                          for s in self.sides]}

    # ── standing ────────────────────────────────────────────────────────────

    @property
    def is_open(self) -> bool:
        return self.status in _OPEN_STATUSES

    @property
    def is_contradiction(self) -> bool:
        """Only a genuine one. A mismatch is a disagreement both sides can survive."""
        return self.classification is ConflictClass.GENUINE

    @property
    def cross_source(self) -> bool:
        """Do the sides come from different kinds of evidence?"""
        kinds = {frozenset(side.kinds) for side in self.sides if side.kinds}
        return len(kinds) > 1

    @property
    def described(self) -> str:
        return _DESCRIBED[self.classification]

    @property
    def resolved(self) -> bool:
        """What `NoUnresolved` reads. Open and unknown are both unresolved."""
        return not self.is_open

    @property
    def participants(self) -> Tuple[str, ...]:
        seen: Set[str] = set()
        for side in self.sides:
            seen |= set(side.participants)
        return tuple(sorted(seen))

    @property
    def independent_roots(self) -> int:
        """Distinct lineages across the whole disagreement.

        Reported, never adjudicated. A side with more roots is not thereby right,
        and nothing here compares the two.
        """
        roots: Set[str] = set()
        for side in self.sides:
            roots |= set(side.roots)
        return len(roots)

    @property
    def one_sided_lineage(self) -> bool:
        """Does every side trace to a single shared lineage?

        When it does, the disagreement is internal to one source rather than a
        clash between independent ones — which changes what a reviewer is looking
        at, without changing who is right.
        """
        return bool(self.sides) and self.independent_roots <= 1

    # ── transitions ─────────────────────────────────────────────────────────

    def resolve(self, resolution: str, evidence: Iterable[str]) -> "Contradiction":
        """Close it by naming what answered it."""
        return dataclasses.replace(
            self, status=ContradictionStatus.RESOLVED, resolution=resolution,
            resolution_evidence=tuple(evidence))

    def invalidate(self, reason: str) -> "Contradiction":
        """Record that this was not a real conflict, and why."""
        return dataclasses.replace(self, status=ContradictionStatus.INVALID,
                                   resolution=reason)

    def supersede(self, reason: str) -> "Contradiction":
        """Record that the claims it was about have moved on."""
        return dataclasses.replace(self, status=ContradictionStatus.SUPERSEDED,
                                   resolution=reason)

    def mark_critical(self, basis: str) -> "Contradiction":
        return dataclasses.replace(self, affects_critical=True, critical_basis=basis)

    # ── serialisation ───────────────────────────────────────────────────────

    @property
    def record_type(self) -> str:
        return "contradiction"

    @property
    def record_id(self) -> str:
        return self.contradiction_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "contradiction",
            "record_id": self.contradiction_id,
            "contradiction_id": self.contradiction_id,
            "kind": self.kind.value,
            "target_claims": list(self.target_claims),
            "evidence_on_each_side": [s.to_dict() for s in self.sides],
            "participants": list(self.participants),
            "independent_roots": self.independent_roots,
            "one_sided_lineage": self.one_sided_lineage,
            "resolution": self.resolution,
            "resolution_evidence": list(self.resolution_evidence),
            "status": self.status.value,
            # `NoUnresolved` reads this; it is derived, never stored, so a caller
            # cannot mark a contradiction resolved without moving its status.
            "resolved": self.resolved,
            "affects_critical": self.affects_critical,
            "critical_basis": self.critical_basis,
            "detected_by": self.detected_by,
            "detected_at": self.detected_at,
            "detail": self.detail,
            "classification": self.classification.value,
            "is_contradiction": self.is_contradiction,
            "cross_source": self.cross_source,
            "comparability": [c.to_dict() for c in self.comparability],
            "classification_basis": self.classification_basis,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Contradiction":
        return cls(
            target_claims=tuple(data.get("target_claims") or ()),
            sides=tuple(ContradictionSide(**{k: (tuple(v) if isinstance(v, list) else v)
                                             for k, v in side.items()})
                        for side in data.get("evidence_on_each_side") or ()),
            kind=ContradictionKind(data.get("kind",
                                            ContradictionKind.CLAIM_EVIDENCE_CONFLICT.value)),
            status=ContradictionStatus(data.get("status", ContradictionStatus.OPEN.value)),
            resolution=data.get("resolution", ""),
            resolution_evidence=tuple(data.get("resolution_evidence") or ()),
            affects_critical=bool(data.get("affects_critical")),
            critical_basis=data.get("critical_basis", ""),
            detected_by=data.get("detected_by", "unknown"),
            detected_at=data.get("detected_at") or _utc_now(),
            detail=data.get("detail", ""),
            classification=ConflictClass(data.get("classification",
                                                  ConflictClass.GENUINE.value)),
            comparability=tuple(DimensionComparison.from_dict(c)
                                for c in data.get("comparability") or ()),
            classification_basis=data.get("classification_basis", ""))

    def render(self) -> str:
        """The shape a reviewer reads."""
        lines = [f"{self.contradiction_id}  [{self.status.value}]  "
                 f"{', '.join(self.target_claims)}"]
        if self.affects_critical:
            lines.append(f"    CRITICAL: {self.critical_basis}")
        lines.append(f"    {self.described}"
                     + (f" — {self.classification_basis}" if self.classification_basis
                        else ""))
        for side in self.sides:
            lines.append(
                f"    {side.label}: {len(side.evidence)} record(s), "
                f"{len(side.participants)} participant(s), "
                f"{side.independent_roots} independent lineage(s)"
                + (f" [{', '.join(side.kinds)}]" if side.kinds else ""))
        if self.resolution:
            lines.append(f"    resolution: {self.resolution}")
            if self.resolution_evidence:
                lines.append(f"    resolved by: {', '.join(self.resolution_evidence)}")
        return "\n".join(lines)


class ContradictionLedger:
    """Every disagreement found, and what became of each.

    Append-only in spirit: `with_resolution` returns a new ledger rather than
    mutating, so a ledger someone has been shown cannot change underneath them.
    """

    def __init__(self, contradictions: Iterable[Contradiction] = ()) -> None:
        held = list(contradictions)
        held.sort(key=lambda c: (not c.affects_critical, not c.is_open,
                                 c.contradiction_id))
        self._held: Tuple[Contradiction, ...] = tuple(held)

    def __iter__(self):
        return iter(self._held)

    def __len__(self) -> int:
        return len(self._held)

    @property
    def contradictions(self) -> Tuple[Contradiction, ...]:
        return self._held

    def open(self) -> Tuple[Contradiction, ...]:
        return tuple(c for c in self._held if c.is_open)

    def unresolved_critical(self) -> Tuple[Contradiction, ...]:
        """The ones a final synthesis must not be allowed to omit."""
        return tuple(c for c in self._held if c.is_open and c.affects_critical)

    def of_class(self, classification: ConflictClass) -> Tuple[Contradiction, ...]:
        return tuple(c for c in self._held
                     if c.classification is ConflictClass(classification))

    def by_claim(self, claim_id: str) -> Tuple[Contradiction, ...]:
        return tuple(c for c in self._held if claim_id in c.target_claims)

    def of_status(self, status: ContradictionStatus) -> Tuple[Contradiction, ...]:
        return tuple(c for c in self._held if c.status is ContradictionStatus(status))

    def with_resolution(self, contradiction_id: str,
                        resolved: Contradiction) -> "ContradictionLedger":
        return ContradictionLedger(
            resolved if c.contradiction_id == contradiction_id else c
            for c in self._held)

    def digest(self) -> str:
        """Clock-free, for the reason `records.CLOCK_FIELDS` gives.

        A ledger digest travels inside coverage rows, so a `detected_at` in here
        moves a case digest two levels up: the same input assured a second later
        looked like a different case.
        """
        from release_gate.assurance.records import strip_clocks
        return digest_object({
            "contradictions": [strip_clocks(c.to_dict()) for c in self._held],
            "schema_version": CONTRADICTION_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self._held), "open": len(self.open()),
                "unresolved_critical": len(self.unresolved_critical()),
                "by_status": {s.value: len(self.of_status(s))
                              for s in ContradictionStatus},
                "by_kind": {k.value: sum(1 for c in self._held if c.kind is k)
                            for k in ContradictionKind},
                "by_classification": {k.value: len(self.of_class(k))
                                      for k in ConflictClass},
                "cross_source": sum(1 for c in self._held if c.cross_source),
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(),
                "detail": [c.to_dict() for c in self._held]}

    def render(self) -> str:
        if not self._held:
            return "No contradictions recorded."
        return "\n".join(c.render() for c in self._held)


# ── classification ───────────────────────────────────────────────────────────

_FAMILY_ORDER = ("STATE", "SCOPE", "POPULATION", "ENVIRONMENT")
_CLASS_OF_FAMILY = {"STATE": ConflictClass.STALE, "SCOPE": ConflictClass.SCOPE_MISMATCH,
                    "POPULATION": ConflictClass.POPULATION_MISMATCH,
                    "ENVIRONMENT": ConflictClass.ENVIRONMENT_MISMATCH}
#: State components that are a dimension of their own: where, and on what data.
_STATE_AS_CONDITION = {"environment", "dataset"}


@dataclass(frozen=True)
class _Profile:
    """What one member of a side declares it is about. Hashable, so equal
    members are compared once."""

    covers: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    state: Tuple[Tuple[str, str], ...] = ()
    #: How the candidate binding set it aside: "" when it did not.
    bound: str = ""
    bound_family: str = "STATE"


def _member_id(member: Any) -> str:
    return str(getattr(member, "evidence_id", "") or getattr(member, "verification_id", ""))


def _profile(member: Any, bindings: Mapping[str, Any]) -> _Profile:
    from release_gate.assurance.candidate import (WITHHELD, CandidateError, canonical_key,
                                                  canonical_value)
    from release_gate.assurance.claim_coverage import conditions_of, declared_field
    covers = conditions_of(member)
    state: Dict[str, str] = {}
    raw = declared_field(member, "state")
    for key, value in (raw.items() if isinstance(raw, Mapping) else ()):
        canonical = canonical_key(key)
        if canonical is None or canonical in _STATE_AS_CONDITION:
            continue
        try:
            state[canonical] = canonical_value(canonical, value)
        except CandidateError:
            continue
    bound, family = "", "STATE"
    binding = bindings.get(_member_id(member))
    if binding is not None and binding.match in WITHHELD:
        bound = binding.match.value
        components = {c.component for c in binding.mismatches()}
        family = ("ENVIRONMENT" if "environment" in components
                  else "POPULATION" if "dataset" in components
                  else "SCOPE" if "repository" in components else "STATE")
    return _Profile(covers=tuple(sorted((d, tuple(sorted(v))) for d, v in covers.items())),
                    state=tuple(sorted(state.items())), bound=bound, bound_family=family)


def _compare_values(dimension: str, family: str, left: Tuple[str, ...],
                    right: Tuple[str, ...]) -> DimensionComparison:
    if not left or not right:
        verdict = Comparison.ONE_SIDED
    elif set(left) == set(right):
        verdict = Comparison.SAME
    elif set(left) & set(right):
        verdict = Comparison.OVERLAP
    else:
        verdict = Comparison.DIFFERENT
    return DimensionComparison(dimension, family, verdict, left, right)


def _compare(a: _Profile, b: _Profile) -> Tuple[ConflictClass, Tuple[DimensionComparison, ...]]:
    from release_gate.assurance.candidate import values_equal
    from release_gate.assurance.claim_coverage import family_of_dimension
    rows: List[DimensionComparison] = []
    if a.bound or b.bound:
        rows.append(DimensionComparison(
            "candidate", a.bound_family if a.bound else b.bound_family,
            Comparison.DIFFERENT, (a.bound or "the candidate",),
            (b.bound or "the candidate",)))
    left, right = dict(a.state), dict(b.state)
    for key in sorted(set(left) | set(right)):
        family = "SCOPE" if key == "repository" else "STATE"
        if key in left and key in right:
            same = values_equal(key, left[key], right[key])
            rows.append(DimensionComparison(key, family,
                                            Comparison.SAME if same else Comparison.DIFFERENT,
                                            (left[key],), (right[key],)))
        else:
            rows.append(DimensionComparison(key, family, Comparison.ONE_SIDED,
                                            (left[key],) if key in left else (),
                                            (right[key],) if key in right else ()))
    lc, rc = dict(a.covers), dict(b.covers)
    scope_left = {d for d in lc if family_of_dimension(d).value == "SCOPE"}
    scope_right = {d for d in rc if family_of_dimension(d).value == "SCOPE"}
    if scope_left and scope_right and not scope_left & scope_right:
        # Both qualified what they cover, along dimensions that never meet: a
        # static path and a tool name. Whether they disagree is not decidable here.
        rows.append(DimensionComparison("scope", "SCOPE", Comparison.NOT_COMPARABLE,
                                        tuple(sorted(scope_left)),
                                        tuple(sorted(scope_right))))
    for dimension in sorted(set(lc) | set(rc)):
        rows.append(_compare_values(dimension, family_of_dimension(dimension).value,
                                    lc.get(dimension, ()), rc.get(dimension, ())))
    for family in _FAMILY_ORDER:
        if any(r.family == family and r.comparison is Comparison.DIFFERENT for r in rows):
            return _CLASS_OF_FAMILY[family], tuple(rows)
    if any(r.comparison is Comparison.NOT_COMPARABLE for r in rows):
        return ConflictClass.AMBIGUOUS, tuple(rows)
    return ConflictClass.GENUINE, tuple(rows)


_RANK = {ConflictClass.GENUINE: 0, ConflictClass.AMBIGUOUS: 1, ConflictClass.STALE: 2,
         ConflictClass.SCOPE_MISMATCH: 3, ConflictClass.POPULATION_MISMATCH: 4,
         ConflictClass.ENVIRONMENT_MISMATCH: 5}


def _basis(classification: ConflictClass, rows: Sequence[DimensionComparison]) -> str:
    if classification is ConflictClass.GENUINE:
        met = [r for r in rows if r.comparison in (Comparison.SAME, Comparison.OVERLAP)]
        one = [r for r in rows if r.comparison is Comparison.ONE_SIDED]
        if not met and not one:
            return ("neither side qualifies the state or scope it is about, so both "
                    "speak to the claim as stated")
        parts = [f"both state {r.dimension} {', '.join(sorted(set(r.left) & set(r.right)))}"
                 for r in met]
        parts += [f"{r.dimension} is stated by one side only, and the other speaks to "
                  "all of it" for r in one]
        return "; ".join(parts)
    if classification is ConflictClass.AMBIGUOUS:
        row = next(r for r in rows if r.comparison is Comparison.NOT_COMPARABLE)
        return (f"one side qualifies its scope by {', '.join(row.left)} and the other by "
                f"{', '.join(row.right)}; nothing they state can be compared")
    family = next(f for f, c in _CLASS_OF_FAMILY.items() if c is classification)
    differ = [r for r in rows if r.family == family and r.comparison is Comparison.DIFFERENT]
    parts = []
    for row in differ:
        if row.dimension == "candidate":
            parts.append("one side is bound to a state other than the candidate's"
                         if "the candidate" in row.left + row.right
                         else "both sides are bound to states other than the candidate's")
        else:
            parts.append(row.render())
    return "; ".join(parts)


def classify_sides(left: Sequence[Any], right: Sequence[Any],
                   bindings: Optional[Mapping[str, Any]] = None
                   ) -> Tuple[ConflictClass, Tuple[DimensionComparison, ...], str]:
    """What a disagreement between two sides is, and why.

    Every pairing of a member from each side is compared; members that declare
    the same things are compared once. If any pairing is comparable the
    disagreement is GENUINE — somewhere, the two sides speak to the same thing
    and disagree. Failing that, an undecidable pairing makes it AMBIGUOUS, and
    only when every pairing differs is it a mismatch, named by the first family
    that differs: state, scope, population, environment.
    """
    bindings = bindings or {}
    lefts = sorted({_profile(m, bindings) for m in left}, key=repr)
    rights = sorted({_profile(m, bindings) for m in right}, key=repr)
    if not lefts or not rights:
        return ConflictClass.GENUINE, (), ""
    best: Optional[Tuple[ConflictClass, Tuple[DimensionComparison, ...]]] = None
    for a in lefts:
        for b in rights:
            found = _compare(a, b)
            if best is None or _RANK[found[0]] < _RANK[best[0]]:
                best = found
            if best[0] is ConflictClass.GENUINE:
                break
        if best is not None and best[0] is ConflictClass.GENUINE:
            break
    classification, rows = best
    return classification, rows, _basis(classification, rows)


def _classified(contradiction: Contradiction, left: Sequence[Any], right: Sequence[Any],
                bindings: Mapping[str, Any]) -> Contradiction:
    classification, rows, basis = classify_sides(left, right, bindings)
    return dataclasses.replace(contradiction, classification=classification,
                               comparability=rows, classification_basis=basis)


# ── detection ────────────────────────────────────────────────────────────────

def _critical_basis(claim_id: str, claim_graph: Any) -> Optional[str]:
    """Why this claim matters structurally, or None.

    Deliberately structural: a claim is critical here because it is the
    proposition the case is about, or because something else rests on it. Neither
    is release-gate judging importance — that would be inventing a threshold.
    A producer-declared criticality is honoured too, and labelled as declared.
    """
    if claim_graph is None:
        return None
    claim = claim_graph.claim(claim_id)
    if claim is None:
        return None
    if getattr(claim, "is_root", False):
        return "a root claim: the proposition this case is about"
    try:
        load_bearing = set(claim_graph.load_bearing())
    except Exception:
        load_bearing = set()
    if claim_id in load_bearing:
        return "load-bearing: other claims depend on it"
    declared = getattr(claim, "criticality", None)
    if declared and str(declared).upper() in ("CRITICAL", "HIGH"):
        return f"declared criticality {declared}"
    return None


def detect_contradictions(*, claim_graph: Any = None,
                          evidence: Sequence[EvidenceRecord] = (),
                          verification_graph: Any = None,
                          bindings: Any = None) -> ContradictionLedger:
    """Find the disagreements the case already contains, and classify each.

    Detection is structural throughout: evidence pointing both ways at one claim,
    checks that disagree, a single record arguing with itself. Classification
    compares what each side declares (`classify_sides`), using the candidate
    binding when there is one (`bindings`, a `StateBindingReport`). Nothing here
    reads meaning, and nothing decides who is right.
    """
    bound: Dict[str, Any] = {b.record_id: b for b in
                             (getattr(bindings, "bindings", None) or ())}
    by_id = {r.evidence_id: r for r in evidence}
    found: List[Contradiction] = []

    # Evidence may name a claim from its own side, so both directions have to be
    # read. Indexed once rather than rescanned per claim: the second form cost a
    # full pass over every record for every claim, which is fine at a hundred
    # claims and is ninety thousand passes over ninety thousand records at the
    # scale this engine is built for.
    supports_index: Dict[str, List[EvidenceRecord]] = {}
    contradicts_index: Dict[str, List[EvidenceRecord]] = {}
    for record in evidence:
        for claim_id in record.supports_claims:
            supports_index.setdefault(claim_id, []).append(record)
        for claim_id in record.contradicts_claims:
            contradicts_index.setdefault(claim_id, []).append(record)

    # One claim, evidence on both sides.
    if claim_graph is not None:
        for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
            supporting = [by_id[e] for e in claim.supporting_evidence if e in by_id]
            against = [by_id[e] for e in claim.contradicting_evidence if e in by_id]
            held = {x.evidence_id for x in supporting}
            supporting += [r for r in supports_index.get(claim.claim_id, ())
                           if r.evidence_id not in held]
            held = {x.evidence_id for x in against}
            against += [r for r in contradicts_index.get(claim.claim_id, ())
                        if r.evidence_id not in held]
            if not (supporting and against):
                continue
            contradiction = Contradiction(
                target_claims=(claim.claim_id,),
                kind=ContradictionKind.CLAIM_EVIDENCE_CONFLICT,
                sides=(ContradictionSide.from_evidence("supports", supporting),
                       ContradictionSide.from_evidence("contradicts", against)),
                detail=(f"{len(supporting)} record(s) support {claim.claim_id} and "
                        f"{len(against)} contradict it, with nothing recorded that "
                        "settles which prevails"))
            contradiction = _classified(contradiction, supporting, against, bound)
            basis = _critical_basis(claim.claim_id, claim_graph)
            found.append(contradiction.mark_critical(basis) if basis else contradiction)

        # Checks that disagree about one claim.
        for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
            outcomes = {a.status.value for a in claim.verification_attempts}
            if not {"PASSED", "FAILED"} <= outcomes:
                continue
            passed = [a for a in claim.verification_attempts
                      if a.status.value == "PASSED"]
            failed = [a for a in claim.verification_attempts
                      if a.status.value == "FAILED"]
            contradiction = Contradiction(
                target_claims=(claim.claim_id,),
                kind=ContradictionKind.VERIFICATION_CONFLICT,
                sides=(
                    ContradictionSide(
                        label="passed",
                        evidence=tuple(e for a in passed for e in a.evidence),
                        participants=tuple(a.verifier for a in passed if a.verifier),
                        note=f"{len(passed)} passing attempt(s)",
                        kinds=tuple(a.method.value for a in passed)),
                    ContradictionSide(
                        label="failed",
                        evidence=tuple(e for a in failed for e in a.evidence),
                        participants=tuple(a.verifier for a in failed if a.verifier),
                        note=f"{len(failed)} failing attempt(s)",
                        kinds=tuple(a.method.value for a in failed))),
                detail=(f"{claim.claim_id} was checked more than once with different "
                        "outcomes, and nothing records which supersedes the other"))
            contradiction = _classified(contradiction, passed, failed, bound)
            basis = _critical_basis(claim.claim_id, claim_graph)
            found.append(contradiction.mark_critical(basis) if basis else contradiction)

    # A record that arrived declaring both sides of one claim is split at the
    # ingest boundary into two halves, which the claim/evidence pass above then
    # finds disagreeing. The halves carry a marker, so the disagreement is labelled
    # for what it is rather than looking like two independent parties.
    split_claims: Set[str] = set()
    for record in evidence:
        content = dict(record.content or {})
        if content.get("split_from_self_conflict"):
            split_claims |= set(content.get("self_conflict_claims") or ())
    if split_claims:
        found = [dataclasses.replace(c, kind=ContradictionKind.RECORD_SELF_CONFLICT,
                                     detail=(c.detail + " (one producer declared both "
                                             "sides in a single record, which was split "
                                             "so the disagreement survives)"))
                 if set(c.target_claims) & split_claims
                 and c.kind is ContradictionKind.CLAIM_EVIDENCE_CONFLICT else c
                 for c in found]

    return ContradictionLedger(found)


# ── the graph ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ConflictEdge:
    """One relationship that puts evidence at odds — with other evidence, or with
    the release being admitted. An edge, with an id, never a footnote."""

    edge_id: str
    relation: str                 # DISAGREES | STATE_MISMATCH
    classification: ConflictClass
    source: Tuple[str, ...]       # evidence on one side, or the record that is off-state
    target: Tuple[str, ...]       # evidence on the other side, or ("candidate",)
    claims: Tuple[str, ...]
    open: bool
    critical: bool = False
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"edge_id": self.edge_id, "relation": self.relation,
                "classification": self.classification.value,
                "source": list(self.source), "target": list(self.target),
                "claims": list(self.claims), "open": self.open,
                "critical": self.critical, "detail": self.detail}


@dataclass(frozen=True)
class ConflictGraph:
    """Every disagreement and every state mismatch, as edges over the same ids."""

    edges: Tuple[ConflictEdge, ...] = ()

    def of(self, relation: str) -> Tuple[ConflictEdge, ...]:
        return tuple(e for e in self.edges if e.relation == relation)

    def to_dict(self) -> Dict[str, Any]:
        nodes = sorted({i for e in self.edges for i in e.source + e.target + e.claims})
        return {"schema_version": CONTRADICTION_SCHEMA_VERSION, "nodes": nodes,
                "edges": [e.to_dict() for e in self.edges],
                "by_classification": {k.value: sum(1 for e in self.edges
                                                   if e.classification is k)
                                      for k in ConflictClass},
                "digest": digest_object([e.to_dict() for e in self.edges])}


_BINDING_CLASS = {"environment": ConflictClass.ENVIRONMENT_MISMATCH,
                  "dataset": ConflictClass.POPULATION_MISMATCH,
                  "repository": ConflictClass.SCOPE_MISMATCH}


def conflict_graph(ledger: Optional[ContradictionLedger],
                   bindings: Any = None) -> ConflictGraph:
    """The disagreements in a ledger and the state mismatches in a binding report.

    A proof of tool_v2 offered for a tool_v3 candidate, and an approval of build
    abc123 offered for def456, contradict no other record — they contradict the
    release. They are edges here from the record to the candidate, classified
    the same way, so the graph holds every relationship that keeps evidence from
    counting, not only the ones between two records.
    """
    edges: List[ConflictEdge] = []
    for c in (ledger.contradictions if ledger is not None else ()):
        left, right = (c.sides + (ContradictionSide(label=""),) * 2)[:2]
        edges.append(ConflictEdge(
            edge_id=c.contradiction_id, relation="DISAGREES",
            classification=c.classification, source=left.evidence, target=right.evidence,
            claims=c.target_claims, open=c.is_open, critical=c.affects_critical,
            detail=f"{c.described}" + (f" — {c.classification_basis}"
                                       if c.classification_basis else "")))
    from release_gate.assurance.candidate import WITHHELD
    for binding in (getattr(bindings, "bindings", None) or ()):
        if binding.match not in WITHHELD:
            continue
        components = {m.component for m in binding.mismatches()}
        classification = next((_BINDING_CLASS[k] for k in ("environment", "dataset",
                                                           "repository")
                               if k in components), ConflictClass.STALE)
        edges.append(ConflictEdge(
            edge_id=short_id("state", digest_object({"record": binding.record_id,
                                                     "match": binding.match.value})),
            relation="STATE_MISMATCH", classification=classification,
            source=(binding.record_id,), target=("candidate",),
            claims=tuple(sorted(set(binding.bears_on))),
            # Open while it keeps the record from counting; a refutation it
            # carries still stands, which the binding's reason says.
            open=True, detail=binding.reason))
    return ConflictGraph(edges=tuple(sorted(edges, key=lambda e: (e.relation, e.edge_id))))
