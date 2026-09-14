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
    "Contradiction",
    "ContradictionError",
    "ContradictionKind",
    "ContradictionLedger",
    "ContradictionSide",
    "ContradictionStatus",
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))
        object.__setattr__(self, "participants", tuple(sorted(set(self.participants))))
        object.__setattr__(self, "roots", tuple(sorted(set(self.roots))))

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "evidence": list(self.evidence),
                "participants": list(self.participants),
                "independent_roots": self.independent_roots,
                "roots": list(self.roots), "note": self.note}

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
                   roots=tuple(roots), note=note)


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
    schema_version: int = CONTRADICTION_SCHEMA_VERSION

    contradiction_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ContradictionKind(self.kind))
        object.__setattr__(self, "status", ContradictionStatus(self.status))
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
            detail=data.get("detail", ""))

    def render(self) -> str:
        """The shape a reviewer reads."""
        lines = [f"{self.contradiction_id}  [{self.status.value}]  "
                 f"{', '.join(self.target_claims)}"]
        if self.affects_critical:
            lines.append(f"    CRITICAL: {self.critical_basis}")
        for side in self.sides:
            lines.append(
                f"    {side.label}: {len(side.evidence)} record(s), "
                f"{len(side.participants)} participant(s), "
                f"{side.independent_roots} independent lineage(s)")
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
        return digest_object({"contradictions": [c.to_dict() for c in self._held],
                              "schema_version": CONTRADICTION_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self._held), "open": len(self.open()),
                "unresolved_critical": len(self.unresolved_critical()),
                "by_status": {s.value: len(self.of_status(s))
                              for s in ContradictionStatus},
                "by_kind": {k.value: sum(1 for c in self._held if c.kind is k)
                            for k in ContradictionKind},
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(),
                "detail": [c.to_dict() for c in self._held]}

    def render(self) -> str:
        if not self._held:
            return "No contradictions recorded."
        return "\n".join(c.render() for c in self._held)


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
                          verification_graph: Any = None) -> ContradictionLedger:
    """Find the disagreements the case already contains.

    Detection is structural throughout: evidence pointing both ways at one claim,
    checks that disagree, a single record arguing with itself. Nothing here reads
    meaning, and nothing decides who is right.
    """
    by_id = {r.evidence_id: r for r in evidence}
    found: List[Contradiction] = []

    # One claim, evidence on both sides.
    if claim_graph is not None:
        for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
            supporting = [by_id[e] for e in claim.supporting_evidence if e in by_id]
            against = [by_id[e] for e in claim.contradicting_evidence if e in by_id]
            # Evidence may also name the claim from its own side.
            supporting += [r for r in evidence
                           if claim.claim_id in r.supports_claims
                           and r.evidence_id not in {x.evidence_id for x in supporting}]
            against += [r for r in evidence
                        if claim.claim_id in r.contradicts_claims
                        and r.evidence_id not in {x.evidence_id for x in against}]
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
                        note=f"{len(passed)} passing attempt(s)"),
                    ContradictionSide(
                        label="failed",
                        evidence=tuple(e for a in failed for e in a.evidence),
                        participants=tuple(a.verifier for a in failed if a.verifier),
                        note=f"{len(failed)} failing attempt(s)")),
                detail=(f"{claim.claim_id} was checked more than once with different "
                        "outcomes, and nothing records which supersedes the other"))
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
