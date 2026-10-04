"""Evidence origin — whose account each record is, and what release-gate did with it.

Release-gate decides from evidence it mostly did not produce. A report that says
"12 findings, 3 eval cases, 1 proof, 2 approvals" without saying who produced
each invites the reading that release-gate found, ran, proved or approved them.
It did none of that: it read a SARIF log, an eval harness's results, a model
checker's output and a reviewer's record, and decided from them under a
declared policy. This module says so, producer by producer, on every report.

Three origins, read from what each record already carries — its producer, the
producer's kind and identity basis, and its epistemic status. Nothing is
inferred from a name.

    COMPUTED_HERE   release-gate computed it in this run from its input: the
                    input's digest, a derived capability, its own analysis
    OBTAINED_HERE   produced in this run by another system at release-gate's
                    request — a model the semantic verifier asked. The other
                    system's reading, made now
    READ            a producer's own account, read from what was submitted.
                    Release-gate did not run the producer, re-run its checks or
                    re-grade its results. A document attributed to release-gate
                    itself (an `audit.json` handed in) is READ too: this run did
                    not produce it

The report is a statement of fact about the case, never an input to the
verdict: no rule reads it, and it cannot soften or harden anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from release_gate.assurance.evidence import (
    EpistemicStatus, EvidenceRecord, EvidenceType, ProducerKind)

__all__ = [
    "ORIGIN_SCHEMA_VERSION",
    "EvidenceOriginReport",
    "OriginEntry",
    "OriginKind",
    "evidence_origin",
]

ORIGIN_SCHEMA_VERSION = 1


class OriginKind(str, Enum):
    COMPUTED_HERE = "COMPUTED_HERE"
    OBTAINED_HERE = "OBTAINED_HERE"
    READ = "READ"


def _origin_of(record: EvidenceRecord) -> OriginKind:
    producer = record.producer
    if producer.kind is ProducerKind.RELEASE_GATE and producer.identity_basis == "in-process":
        return OriginKind.COMPUTED_HERE
    if record.epistemic_status in (EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED):
        return OriginKind.OBTAINED_HERE
    return OriginKind.READ


@dataclass(frozen=True)
class OriginEntry:
    """One producer's evidence in this case, and how release-gate came to hold it."""

    producer_id: str
    origin: OriginKind
    version: Optional[str] = None
    producer_types: Tuple[str, ...] = ()
    described_as: Tuple[str, ...] = ()
    identity_basis: str = ""
    records: int = 0
    evidence_types: Mapping[str, int] = field(default_factory=dict)
    statuses: Mapping[str, int] = field(default_factory=dict)
    sources: Tuple[str, ...] = ()
    #: A person, by the producer's stated kind or because everything they
    #: produced is a review or an approval.
    person: bool = False

    @property
    def who(self) -> str:
        """The producer and its version, once — a verifier's id may already carry it."""
        if not self.version or self.producer_id.endswith(f"@{self.version}"):
            return self.producer_id
        return f"{self.producer_id}@{self.version}"

    @property
    def statement(self) -> str:
        who = self.who
        if self.origin is OriginKind.COMPUTED_HERE:
            return "computed by release-gate in this run, from the input it was given"
        if self.origin is OriginKind.OBTAINED_HERE:
            return (f"produced in this run by {who} at release-gate's request; "
                    f"{who}'s reading, not release-gate's")
        if self.producer_id.startswith("release-gate/"):
            return ("a document attributed to release-gate, read as submitted; this "
                    "run did not produce it")
        if self.person:
            return (f"{who}'s review as recorded, read from what was submitted; "
                    "release-gate did not perform, repeat or check the review")
        return (f"{who}'s own account, read from what was submitted; release-gate did "
                f"not run {self.producer_id}, re-run its checks or re-grade its results")

    def to_dict(self) -> Dict[str, Any]:
        return {"producer_id": self.producer_id, "version": self.version,
                "origin": self.origin.value,
                "release_gate_ran_it": self.origin is OriginKind.COMPUTED_HERE,
                "producer_types": list(self.producer_types),
                "described_as": list(self.described_as),
                "identity_basis": self.identity_basis, "records": self.records,
                "evidence_types": dict(self.evidence_types),
                "statuses": dict(self.statuses),
                "sources": list(self.sources), "person": self.person,
                "statement": self.statement}


@dataclass(frozen=True)
class EvidenceOriginReport:
    entries: Tuple[OriginEntry, ...] = ()

    def of(self, origin: OriginKind) -> Tuple[OriginEntry, ...]:
        return tuple(e for e in self.entries if e.origin is origin)

    @property
    def read_only(self) -> Tuple[str, ...]:
        """Producers whose evidence release-gate read and did not produce."""
        return tuple(sorted({e.producer_id for e in self.of(OriginKind.READ)}))

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": ORIGIN_SCHEMA_VERSION,
                "read_not_run": list(self.read_only),
                "obtained_in_this_run": sorted({e.producer_id for e in
                                                self.of(OriginKind.OBTAINED_HERE)}),
                "computed_by_release_gate": sum(e.records for e in
                                                self.of(OriginKind.COMPUTED_HERE)),
                "entries": [e.to_dict() for e in self.entries]}

    def render(self) -> str:
        lines: List[str] = []
        for entry in self.entries:
            who = entry.who
            kinds = ", ".join(f"{n} {t}" for t, n in sorted(entry.evidence_types.items()))
            via = f" via {', '.join(entry.producer_types)}" if entry.producer_types else ""
            lines.append(f"[{entry.origin.value:>13}]  {who}{via}: {entry.records} "
                         f"record(s) ({kinds})")
            lines.append(f"                 {entry.statement}")
        return "\n".join(lines)


_PERSONAL = frozenset({EvidenceType.HUMAN_REVIEW.value, EvidenceType.APPROVAL.value})


def evidence_origin(records: Iterable[Any]) -> EvidenceOriginReport:
    """Group a case's evidence by producer and say how each producer's arrived."""
    groups: Dict[Tuple[str, Optional[str], OriginKind], List[EvidenceRecord]] = {}
    for record in records:
        if not isinstance(record, EvidenceRecord):
            continue
        key = (record.producer.producer_id, record.producer.version, _origin_of(record))
        groups.setdefault(key, []).append(record)

    entries: List[OriginEntry] = []
    for (producer_id, version, origin), held in groups.items():
        types: Dict[str, int] = {}
        statuses: Dict[str, int] = {}
        kinds, described, sources = set(), set(), set()
        for record in held:
            types[record.evidence_type.value] = types.get(record.evidence_type.value, 0) + 1
            statuses[record.epistemic_status.value] = \
                statuses.get(record.epistemic_status.value, 0) + 1
            metadata = record.metadata or {}
            if metadata.get("producer_type"):
                kinds.add(str(metadata["producer_type"]))
            if metadata.get("origin"):
                described.add(str(metadata["origin"]))
            if record.source:
                sources.add(str(record.source))
        person = (any(r.producer.kind is ProducerKind.HUMAN for r in held)
                  or set(types) <= _PERSONAL)
        entries.append(OriginEntry(
            producer_id=producer_id, origin=origin, version=version,
            producer_types=tuple(sorted(kinds)), described_as=tuple(sorted(described)),
            identity_basis=held[0].producer.identity_basis, records=len(held),
            evidence_types=types, statuses=statuses, sources=tuple(sorted(sources)),
            person=person))
    order = {OriginKind.READ: 0, OriginKind.OBTAINED_HERE: 1, OriginKind.COMPUTED_HERE: 2}
    entries.sort(key=lambda e: (order[e.origin], e.producer_id, e.version or ""))
    return EvidenceOriginReport(entries=tuple(entries))
