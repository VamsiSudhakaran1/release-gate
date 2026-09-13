"""Record collections — how an AssuranceCase holds one record or ten million.

The case model has one genuinely hard engineering requirement: the same object
must serve an engineer approving a single migration and a research organisation
approving a result derived from millions of model calls. Those are not two
implementations; they are one container with three properties.

**Absent is not empty.** A case with no execution graph because nobody supplied
one is a different statement from a case whose execution graph was supplied and
turned out to be empty. The first is `NOT_ASSESSED`; the second is a finding.
Collapsing them is how "we did not look" becomes "there was nothing there"
(Invariants 3 and 14), so `Presence` is carried explicitly.

**Counted is not dropped.** At frontier scale most records are irrelevant to the
proposition and must not be materialised. They are still *seen*: every record
folds into the collection's commitment whether or not it is kept, and the
collection reports how many it holds against how many exist. Silent truncation
would make the case digest a statement about a subset while reading as a
statement about the whole.

**Order does not matter.** Ingest is parallel and unordered at scale, so the
commitment is a multiset fold (see `canonical.multiset_add`) rather than a
sorted hash. Shuffled input, split input, merged partial folds — same digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Protocol, Tuple

from release_gate.assurance.canonical import (
    MULTISET_ALGO,
    canonical_json,
    digest_object,
    multiset_add,
    multiset_digest,
    multiset_merge,
)


class Presence(str, Enum):
    """Was this part of the case supplied at all?"""

    ABSENT = "ABSENT"    # never supplied — reports as NOT_ASSESSED, never as clean
    PRESENT = "PRESENT"  # supplied; may legitimately contain zero records


class MaterialisationBasis(str, Enum):
    """Why the collection holds what it holds."""

    COMPLETE = "COMPLETE"                      # every record seen is held
    RELEVANCE_DIRECTED = "RELEVANCE_DIRECTED"  # held if on a path to the proposition
    SAMPLED = "SAMPLED"                        # a stated sampling method was applied
    CAPPED = "CAPPED"                          # a hard limit was hit
    SUMMARY_ONLY = "SUMMARY_ONLY"              # counted and folded, nothing held


class DedupeBasis(str, Enum):
    """What uniqueness the collection actually guarantees, rather than implies."""

    ALL_RECORDS = "ALL_RECORDS"          # ids tracked for everything seen
    MATERIALISED_ONLY = "MATERIALISED_ONLY"  # ids tracked only for held records
    NONE = "NONE"                        # caller owns deduplication


class RecordError(ValueError):
    """A record cannot be placed in a case collection."""


class CaseRecord(Protocol):
    """What a case collection requires of anything it stores.

    Deliberately minimal. Evidence records, claims, artifacts, coverage rows and
    approvals are defined by their own prompts and will satisfy this without
    changing this file — the container must not need to know what it contains.
    """

    record_id: str
    record_type: str

    def to_dict(self) -> Dict[str, Any]:  # pragma: no cover - structural only
        ...


@dataclass(frozen=True)
class SimpleRecord:
    """A dict-shaped record, for producers that have no class of their own.

    The escape hatch that keeps the container honest: a caller with raw JSON can
    put it in a case today without waiting for a typed record class.
    """

    record_type: str
    record_id: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": self.record_type, "record_id": self.record_id,
                **dict(self.payload)}


def record_digest(record: CaseRecord) -> str:
    """Content digest of one record, through the canonical form."""
    return digest_object(_record_dict(record))


def _record_dict(record: CaseRecord) -> Dict[str, Any]:
    for attr in ("record_id", "record_type"):
        if not isinstance(getattr(record, attr, None), str) or not getattr(record, attr):
            raise RecordError(
                f"a case record needs a non-empty string {attr}; got "
                f"{type(record).__name__} with {attr}={getattr(record, attr, None)!r}")
    to_dict = getattr(record, "to_dict", None)
    if not callable(to_dict):
        raise RecordError(f"{type(record).__name__} has no to_dict(); a record must be "
                          "serialisable to be digested and stored")
    data = to_dict()
    if not isinstance(data, Mapping):
        raise RecordError(f"{type(record).__name__}.to_dict() must return a mapping")
    try:
        canonical_json(data)
    except Exception as exc:
        raise RecordError(f"record {record.record_id!r} is not canonically serialisable: {exc}") from exc
    return dict(data)


@dataclass(frozen=True)
class RecordCollection:
    """One typed slice of a case: its held records, its counts, its commitment."""

    kind: str
    presence: Presence = Presence.ABSENT
    materialised: Tuple[CaseRecord, ...] = ()
    total_count: int = 0
    fold_digest: str = ""
    basis: MaterialisationBasis = MaterialisationBasis.COMPLETE
    dedupe_basis: DedupeBasis = DedupeBasis.ALL_RECORDS
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.total_count < len(self.materialised):
            raise RecordError(
                f"{self.kind}: total_count {self.total_count} is below the "
                f"{len(self.materialised)} records held — a collection cannot hold "
                "more than it has seen")
        if self.presence is Presence.ABSENT and (self.materialised or self.total_count):
            raise RecordError(f"{self.kind}: records were added but presence is ABSENT")
        if not self.fold_digest:
            object.__setattr__(self, "fold_digest", multiset_digest(0, self.total_count))

    # ── what the collection actually claims ─────────────────────────────────

    @property
    def held_count(self) -> int:
        return len(self.materialised)

    @property
    def not_materialised(self) -> int:
        return self.total_count - len(self.materialised)

    @property
    def is_complete_in_memory(self) -> bool:
        """True only when every record seen is also held."""
        return self.presence is Presence.PRESENT and self.not_materialised == 0

    def __iter__(self) -> Iterator[CaseRecord]:
        return iter(self.materialised)

    def __len__(self) -> int:
        """The number of records HELD. Use `total_count` for how many exist.

        Named this way on purpose: `len()` should never quietly report a number
        the collection cannot produce records for.
        """
        return len(self.materialised)

    def __bool__(self) -> bool:
        """Always true.

        Without this, `__len__` would make a collection holding no materialised
        records falsy — and a PRESENT-but-empty collection, or one whose records
        were all counted rather than kept, would read as missing at any `if coll:`
        or `x or fallback`. Presence is a field; it is not truthiness.
        """
        return True

    def by_id(self, record_id: str) -> Optional[CaseRecord]:
        return next((r for r in self.materialised if r.record_id == record_id), None)

    def summary(self) -> Dict[str, Any]:
        """The honest header: what exists, what is held, and what that rests on."""
        return {
            "kind": self.kind,
            "presence": self.presence.value,
            "total_count": self.total_count,
            "materialised_count": self.held_count,
            "not_materialised": self.not_materialised,
            "basis": self.basis.value,
            "dedupe_basis": self.dedupe_basis.value,
            "fold_algo": MULTISET_ALGO,
            "fold_digest": self.fold_digest,
            "notes": list(self.notes),
        }

    def to_dict(self, include_records: bool = True) -> Dict[str, Any]:
        data = self.summary()
        if include_records:
            data["records"] = [_record_dict(r) for r in self.materialised]
        return data

    def digest_component(self) -> Dict[str, Any]:
        """What this collection contributes to the case digest.

        The fold covers every record seen, so a case digest stays a statement
        about the whole collection even when most of it was never materialised.
        """
        return {"presence": self.presence.value, "total_count": self.total_count,
                "fold_digest": self.fold_digest, "basis": self.basis.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any],
                  record_factory: Optional[Callable[[Mapping[str, Any]], CaseRecord]] = None
                  ) -> "RecordCollection":
        factory = record_factory or _default_record_factory
        records = tuple(factory(r) for r in data.get("records", ()))
        return cls(
            kind=data["kind"],
            presence=Presence(data.get("presence", Presence.ABSENT.value)),
            materialised=records,
            total_count=int(data.get("total_count", len(records))),
            fold_digest=data.get("fold_digest", ""),
            basis=MaterialisationBasis(data.get("basis", MaterialisationBasis.COMPLETE.value)),
            dedupe_basis=DedupeBasis(data.get("dedupe_basis", DedupeBasis.ALL_RECORDS.value)),
            notes=tuple(data.get("notes", ())),
        )


def _default_record_factory(data: Mapping[str, Any]) -> CaseRecord:
    payload = {k: v for k, v in data.items() if k not in ("record_type", "record_id")}
    return SimpleRecord(record_type=data["record_type"], record_id=data["record_id"],
                        payload=payload)


class RecordCollectionBuilder:
    """Accumulates records into a `RecordCollection`.

    Streaming-shaped on purpose: `add()` may be called from any number of
    producers in any order, and `merge()` combines partial folds, so a frontier
    ingest can fan out and still produce one deterministic commitment.
    """

    def __init__(self, kind: str, *, basis: MaterialisationBasis = MaterialisationBasis.COMPLETE,
                 track_ids: bool = True) -> None:
        self.kind = kind
        self.basis = basis
        # Tracking every id catches double-ingest, and costs memory proportional
        # to the stream. At frontier scale a caller turns it off and the
        # collection says so through `dedupe_basis` rather than implying a
        # uniqueness guarantee it is not providing.
        self._track_ids = track_ids
        self._seen_ids: set = set()
        self._materialised: List[CaseRecord] = []
        self._accumulator = 0
        self._total = 0
        self._present = False
        self._notes: List[str] = []

    # ── presence ────────────────────────────────────────────────────────────

    def declare_present(self, note: str = "") -> "RecordCollectionBuilder":
        """Mark the collection supplied even if it turns out to hold nothing.

        "We looked and found none" is a finding; "nobody supplied this" is a
        coverage gap. Only the producer knows which, so only the producer can say.
        """
        self._present = True
        if note:
            self.note(note)
        return self

    def note(self, message: str) -> "RecordCollectionBuilder":
        if message and message not in self._notes:
            self._notes.append(message)
        return self

    # ── records ─────────────────────────────────────────────────────────────

    def add(self, record: CaseRecord, *, materialise: bool = True) -> "RecordCollectionBuilder":
        """Fold a record in, holding it unless told not to.

        `materialise=False` is relevance-directed ingest: the record counts
        toward the total and toward the commitment, and is not kept.
        """
        digest = record_digest(record)
        if self._track_ids:
            if record.record_id in self._seen_ids:
                raise RecordError(
                    f"{self.kind}: duplicate record_id {record.record_id!r}; ids must be "
                    "unique within a collection so evidence cannot be counted twice")
            self._seen_ids.add(record.record_id)
        elif materialise and any(r.record_id == record.record_id for r in self._materialised):
            raise RecordError(f"{self.kind}: duplicate record_id {record.record_id!r}")

        self._present = True
        self._accumulator = multiset_add(self._accumulator, digest)
        self._total += 1
        if materialise:
            self._materialised.append(record)
        return self

    def extend(self, records: Iterable[CaseRecord], *, materialise: bool = True
               ) -> "RecordCollectionBuilder":
        for record in records:
            self.add(record, materialise=materialise)
        return self

    def merge(self, other: "RecordCollectionBuilder") -> "RecordCollectionBuilder":
        """Combine a partial fold produced elsewhere (another thread, another shard)."""
        if other.kind != self.kind:
            raise RecordError(f"cannot merge a {other.kind} fold into {self.kind}")
        if self._track_ids and other._track_ids:
            clash = self._seen_ids & other._seen_ids
            if clash:
                raise RecordError(
                    f"{self.kind}: {len(clash)} record id(s) appear in both folds, "
                    f"e.g. {sorted(clash)[0]!r}")
            self._seen_ids |= other._seen_ids
        elif self._track_ids or other._track_ids:
            # One side cannot vouch for its ids, so the merged collection must
            # not claim more than the weaker half.
            self._track_ids = False
            self._seen_ids = set()
        self._accumulator = multiset_merge(self._accumulator, other._accumulator)
        self._total += other._total
        self._materialised.extend(other._materialised)
        self._present = self._present or other._present
        for note in other._notes:
            self.note(note)
        return self

    # ── result ──────────────────────────────────────────────────────────────

    def build(self) -> RecordCollection:
        if not self._present:
            return RecordCollection(kind=self.kind, presence=Presence.ABSENT,
                                    notes=tuple(self._notes))
        basis = self.basis
        if basis is MaterialisationBasis.COMPLETE and len(self._materialised) < self._total:
            # A collection that dropped records cannot describe itself as complete.
            basis = (MaterialisationBasis.SUMMARY_ONLY if not self._materialised
                     else MaterialisationBasis.CAPPED)
        return RecordCollection(
            kind=self.kind,
            presence=Presence.PRESENT,
            materialised=tuple(self._materialised),
            total_count=self._total,
            fold_digest=multiset_digest(self._accumulator, self._total),
            basis=basis,
            dedupe_basis=(DedupeBasis.ALL_RECORDS if self._track_ids
                          else DedupeBasis.MATERIALISED_ONLY),
            notes=tuple(self._notes),
        )
