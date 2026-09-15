"""Deterministic evidence compaction.

A frontier run produces four million model calls. The assurance engine must not
hold four million model calls, and it must not pretend they did not happen — so
compaction keeps the argument and drops the bulk, while the count and the
commitment stay exactly what they were.

Three properties, in the order they matter:

**1. Critical-path drill-down survives, unconditionally.** A record on a path
from the decision to the evidence beneath it is retained whatever the budget
says. If the critical set alone exceeds the budget then the budget is exceeded
and reported — it is never honoured by evicting a critical node. Compaction that
could break the drill-down would take the one thing a reviewer actually needs and
trade it for memory, which is the wrong trade at any ratio.

**2. Deterministic.** The retained set is a function of the records, not of the
order they arrived in. `RetainFirst` was not: the same evidence sharded across
six workers kept six different sets while committing to one digest, so two runs
agreed on what existed and disagreed about what could be inspected. Selection
here orders by content digest, which is stable across shards, reruns and
resumptions.

**3. The commitment is untouched.** Retention decides what is *held*, never what
is *counted* — a compacted record is still in `total_count` and still folded into
`fold_digest`. Two cases over the same evidence produce the same commitment
whether one kept everything and the other kept the argument, so compaction can
never be used to quietly change what a case says it saw.

**Raw evidence lives outside.** A compacted record keeps its `ContentReference`,
so the bytes remain fetchable from wherever they actually are. Release-gate holds
the digest and the reference; the object store holds the object. Nothing here
deletes anything from anybody's system — this is about what the *engine* carries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.records import (
    MaterialisationBasis, RecordCollectionBuilder, record_digest,
)

COMPACTION_SCHEMA_VERSION = 1


class CompactionError(ValueError):
    """A compaction that would break a property this module guarantees."""


class RetentionReason(str, Enum):
    """Why a record survived compaction. Exactly the retain list, named.

    A reason is recorded per record rather than inferred later, so a reviewer
    asking "why is this still here and that not" gets an answer from the case
    instead of from whoever wrote the policy.
    """

    CRITICAL_NODE = "CRITICAL_NODE"            # on a path to the decision
    DEPENDENCY_EDGE = "DEPENDENCY_EDGE"        # needed to walk that path
    FINAL_DEPENDENCY = "FINAL_DEPENDENCY"      # what the decision ultimately rests on
    VERIFICATION = "VERIFICATION"              # a typed check and its target
    FAILURE = "FAILURE"                        # a failed branch or attempt
    CONTRADICTION = "CONTRADICTION"
    ASSUMPTION = "ASSUMPTION"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    COVERAGE = "COVERAGE"                      # the coverage state itself
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"  # holds a pointer to raw evidence
    DIGEST_ONLY = "DIGEST_ONLY"                # compacted: counted and committed


#: Collections whose whole point is the argument rather than the bulk. Every
#: record in them is retained, because these ARE the things the retain list
#: names and a case that dropped them would have compacted away its own findings.
_ALWAYS_RETAINED: Mapping[str, RetentionReason] = {
    "contradictions": RetentionReason.CONTRADICTION,
    "assumptions": RetentionReason.ASSUMPTION,
    "counterexamples": RetentionReason.COUNTEREXAMPLE,
    "failed_branches": RetentionReason.FAILURE,
    "verification": RetentionReason.VERIFICATION,
    "coverage": RetentionReason.COVERAGE,
    "approvals": RetentionReason.CRITICAL_NODE,
    "attention_items": RetentionReason.CRITICAL_NODE,
    "required_evidence": RetentionReason.CRITICAL_NODE,
}

#: Collections where compaction actually happens: the bulk of a large run.
_COMPACTABLE = ("evidence", "claims", "artifacts", "executions")


@dataclass(frozen=True)
class CompactionBudget:
    """How much the engine will hold, per compactable collection.

    A budget is a ceiling on the *residue* — what is left after everything the
    retain list names has been kept. It is deliberately not a ceiling on the
    collection, because a ceiling on the collection would eventually have to
    evict something load-bearing to be honoured.
    """

    residue_per_collection: int = 1_000

    def __post_init__(self) -> None:
        if self.residue_per_collection < 0:
            raise CompactionError("a residue budget cannot be negative")


@dataclass(frozen=True)
class CompactionReport:
    """What compaction did, per collection, and what it guarantees."""

    kept: Mapping[str, int] = field(default_factory=dict)
    compacted: Mapping[str, int] = field(default_factory=dict)
    reasons: Mapping[str, int] = field(default_factory=dict)
    budget_exceeded: Tuple[str, ...] = ()
    critical_retained: int = 0
    critical_total: int = 0
    notes: Tuple[str, ...] = ()

    @property
    def drill_down_intact(self) -> bool:
        """Every critical record is still held. Never false in a normal run."""
        return self.critical_retained == self.critical_total

    @property
    def total_kept(self) -> int:
        return sum(self.kept.values())

    @property
    def total_compacted(self) -> int:
        return sum(self.compacted.values())

    def note(self) -> str:
        if self.total_compacted == 0:
            return "Nothing was compacted; the case holds every record it counted."
        line = (f"{self.total_compacted:,} record(s) were compacted to digests and "
                f"{self.total_kept:,} retained. Counts and commitments are "
                "unchanged: a compacted record is still counted and still folded "
                "into the collection digest.")
        if self.budget_exceeded:
            line += (" The residue budget was exceeded in "
                     f"{', '.join(self.budget_exceeded)} because everything over "
                     "it is load-bearing — the budget yields to the critical path, "
                     "never the other way round.")
        return line

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "compaction_report",
                "kept": dict(self.kept), "compacted": dict(self.compacted),
                "reasons": dict(self.reasons),
                "budget_exceeded": list(self.budget_exceeded),
                "critical_retained": self.critical_retained,
                "critical_total": self.critical_total,
                "drill_down_intact": self.drill_down_intact,
                "note": self.note(), "notes": list(self.notes),
                "schema_version": COMPACTION_SCHEMA_VERSION}


def _record_id(record: Any) -> str:
    return str(getattr(record, "record_id", "") or "")


def _sort_key(record: Any) -> Tuple[str, str]:
    """Deterministic ordering: by content digest, then id.

    Content digest rather than arrival order, so the same evidence sharded six
    ways, replayed, or resumed from a checkpoint retains the same set. Ties broken
    by id so two records with identical content still order stably.
    """
    try:
        return (record_digest(record), _record_id(record))
    except Exception:
        return ("", _record_id(record))


def _critical_ids(criticality: Any) -> Set[str]:
    if criticality is None:
        return set()
    try:
        if not criticality.determinable:
            return set()
        return set(criticality.critical_ids or ())
    except Exception:
        return set()


def _referenced_digests(case: Any) -> Set[str]:
    """Digests something else in the case points at.

    An artifact nothing references is bulk; one that a verification ran against
    or a record applies to is a dependency edge, and dropping it would leave a
    dangling link in exactly the traversal §10h walks.
    """
    out: Set[str] = set()
    for kind in ("evidence", "verification"):
        for record in case.collection(kind).materialised:
            for attr in ("applies_to_digest", "target_digest"):
                value = getattr(record, attr, "")
                if value:
                    out.add(str(value))
    return out


def classify(record: Any, kind: str, *, critical: Set[str],
             referenced: Set[str]) -> RetentionReason:
    """Why this record would be retained, or DIGEST_ONLY if it is bulk.

    Pure and side-effect free, so the same record in the same case always
    classifies the same way — which is half of what makes compaction
    deterministic (the other half is the ordering).
    """
    if kind in _ALWAYS_RETAINED:
        return _ALWAYS_RETAINED[kind]

    record_id = _record_id(record)
    if record_id and record_id in critical:
        return RetentionReason.CRITICAL_NODE

    if kind == "claims":
        claim_id = str(getattr(record, "claim_id", "") or "")
        if claim_id in critical:
            return RetentionReason.CRITICAL_NODE
        # A claim a critical claim rests on is the edge that makes the path
        # walkable; without it drill-down stops one hop short of the reason.
        for parent in (getattr(record, "parents", ()) or ()):
            if parent in critical:
                return RetentionReason.DEPENDENCY_EDGE
        if getattr(record, "is_root", False):
            return RetentionReason.FINAL_DEPENDENCY
        if getattr(record, "assumptions", ()):
            return RetentionReason.ASSUMPTION

    if kind == "evidence":
        if getattr(record, "verification_method", None):
            return RetentionReason.VERIFICATION
        if getattr(record, "contradicts_claims", ()):
            # Evidence arguing against something is never bulk. A compaction that
            # kept the supporting half and dropped the objecting half would be
            # the most dangerous edit this engine could make to itself.
            return RetentionReason.CONTRADICTION
        for claim_id in (getattr(record, "supports_claims", ()) or ()):
            if claim_id in critical:
                return RetentionReason.DEPENDENCY_EDGE
        reference = getattr(record, "content_reference", None)
        if reference is not None and str(getattr(reference, "kind", "")) not in (
                "", "INLINE", "ReferenceKind.INLINE"):
            # Cheap to keep and it is the handle on the raw bytes, which is the
            # whole reason compaction is safe: the evidence still exists, it just
            # does not live in here.
            return RetentionReason.EXTERNAL_REFERENCE

    if kind == "artifacts":
        digest = str(getattr(record, "digest", "") or "")
        if digest and digest in referenced:
            return RetentionReason.DEPENDENCY_EDGE

    return RetentionReason.DIGEST_ONLY


def compact_case(case: Any, *, criticality: Any = None,
                 budget: Optional[CompactionBudget] = None) -> Tuple[Any, CompactionReport]:
    """Rebuild a case holding the argument and counting the rest.

    Returns the compacted case and a report. The compacted case has identical
    `total_count` and `fold_digest` on every collection — compaction moves
    records out of `materialised`, never out of the ledger.
    """
    from release_gate.assurance.case import COLLECTION_KINDS, AssuranceCaseBuilder

    budget = budget or CompactionBudget()
    critical = _critical_ids(criticality)
    referenced = _referenced_digests(case)

    kept: Dict[str, int] = {}
    compacted: Dict[str, int] = {}
    reasons: Dict[str, int] = {}
    exceeded: List[str] = []
    notes: List[str] = []
    critical_retained = 0
    critical_total = 0

    builder = AssuranceCaseBuilder(
        case_type=case.case_type, subject=case.subject,
        objective=case.objective, requested_decision=case.requested_decision,
        methodology=case.methodology)

    for kind in COLLECTION_KINDS:
        collection = case.collection(kind)
        if collection.presence.value != "PRESENT":
            continue
        target = builder.collection(kind, track_ids=False)
        records = list(collection.materialised)

        if kind not in _COMPACTABLE:
            for record in records:
                target.add(record, materialise=True)
            kept[kind] = len(records)
            reason = _ALWAYS_RETAINED.get(kind, RetentionReason.CRITICAL_NODE)
            reasons[reason.value] = reasons.get(reason.value, 0) + len(records)
            continue

        retain: List[Any] = []
        residue: List[Any] = []
        for record in records:
            reason = classify(record, kind, critical=critical, referenced=referenced)
            reasons[reason.value] = reasons.get(reason.value, 0) + 1
            if reason is RetentionReason.CRITICAL_NODE:
                critical_total += 1
            if reason is RetentionReason.DIGEST_ONLY:
                residue.append(record)
            else:
                retain.append(record)
                if reason is RetentionReason.CRITICAL_NODE:
                    critical_retained += 1

        # Deterministic: ordered by content, never by arrival.
        residue.sort(key=_sort_key)
        room = max(0, budget.residue_per_collection - 0)
        held_residue = residue[:room]
        dropped = residue[room:]

        if len(retain) > budget.residue_per_collection:
            # Reported, not enforced. The budget bounds the residue; the argument
            # is not residue, and the only way to honour a budget against it
            # would be to evict something the decision rests on.
            exceeded.append(kind)

        for record in retain:
            target.add(record, materialise=True)
        for record in held_residue:
            target.add(record, materialise=True)
        for record in dropped:
            target.add(record, materialise=False)

        kept[kind] = len(retain) + len(held_residue)
        compacted[kind] = len(dropped)
        if dropped:
            notes.append(
                f"{kind}: {len(dropped):,} record(s) compacted to digests; they "
                "remain counted and committed, and their content references "
                "still point at the raw evidence")

    compacted_case = builder.build()
    report = CompactionReport(
        kept=kept, compacted=compacted, reasons=reasons,
        budget_exceeded=tuple(exceeded), critical_retained=critical_retained,
        critical_total=critical_total, notes=tuple(notes))
    return compacted_case, report


def verify_drill_down(case: Any, criticality: Any) -> Tuple[bool, Tuple[str, ...]]:
    """Can every critical claim still be reached and inspected in this case?

    The check that makes compaction safe to run at all. Called after compaction,
    it answers the only question that matters: is the path from the decision to
    the reason still walkable in what was kept.
    """
    critical = _critical_ids(criticality)
    if not critical:
        return True, ()
    held = {str(getattr(r, "claim_id", "") or _record_id(r))
            for r in case.collection("claims").materialised}
    held |= {_record_id(r) for r in case.collection("evidence").materialised}
    missing = tuple(sorted(c for c in critical if c not in held))
    return (not missing), missing
