"""Independence — whether agreement is corroboration or an echo.

Ten thousand verifier agents that all derive from one upstream artifact are not
ten thousand independent validations. They are one validation, observed ten
thousand times, and a system that counts them as ten thousand has turned a single
point of failure into apparent overwhelming consensus. That is the failure this
module exists to make visible.

It works by **derived ancestry**, not by asking. Evidence records carry
`parent_evidence`; following those chains to their roots says where support
actually comes from, regardless of what any producer claims about its own
independence. That is a different question from the one
`methodology.IndependenceThreshold` asks — which reads a *declared*
`independence_group` — and both are kept, for the same reason DECLARED and
OBSERVED capability are kept apart: what a producer says about its provenance and
what its provenance turns out to be are two facts, not one.

Two rules constrain what comes out.

**No probability of truth.** This module computes structure: how many roots, how
big the largest lineage cluster, what share of contributors sit in it. It emits
no confidence, no likelihood, no trust score, and no number that could be read as
one. Seven independent roots do not make a claim 7/8ths true, and concentration
is not a error rate. A structural measure dressed as a probability would be the
most persuasive wrong number this system could produce.

**Concentration is reported, never penalised.** Many agents legitimately relying
on one authoritative source is a normal, often correct workflow. Every finding
here is advisory. Only a methodology that actually requires independent evidence
can turn concentration into a verdict, through `AncestryIndependence`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.evidence import EvidenceRecord, ProducerKind

__all__ = [
    "INDEPENDENCE_SCHEMA_VERSION",
    "AncestryCluster",
    "IndependenceProfile",
    "LineageConcentration",
    "analyse_independence",
]

INDEPENDENCE_SCHEMA_VERSION = 1

#: Share of contributors sitting in the largest single lineage cluster. Cut points
#: are stated rather than tuned: HIGH means more than half of everything that
#: agrees traces to one lineage. The ratio is always reported alongside the band,
#: because the band is a reading aid and the ratio is the measurement.
_LOW_CEILING = 0.25
_MODERATE_CEILING = 0.5


class LineageConcentration(str, Enum):
    """How much of the support traces to one lineage.

    A description of shape, not of risk. `HIGH` on a workflow that deliberately
    rests on one authoritative source is the correct and expected reading, and
    means nothing is wrong.
    """

    NONE = "NONE"          # one contributor, or nothing to concentrate
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"    # too much ancestry unrecorded for the ranking to hold


@dataclass(frozen=True)
class AncestryCluster:
    """One connected lineage, and everything that grew from it."""

    cluster_id: str
    roots: Tuple[str, ...] = ()
    contributors: Tuple[str, ...] = ()
    record_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "roots", tuple(sorted(self.roots)))
        object.__setattr__(self, "contributors", tuple(sorted(self.contributors)))
        object.__setattr__(self, "record_ids", tuple(sorted(self.record_ids)))

    @property
    def size(self) -> int:
        """Contributors, not records. The question is how many *parties* agree."""
        return len(self.contributors)

    def to_dict(self) -> Dict[str, Any]:
        return {"cluster_id": self.cluster_id, "size": self.size,
                "roots": list(self.roots), "root_count": len(self.roots),
                "contributors": list(self.contributors[:32]),
                "contributors_truncated": max(0, len(self.contributors) - 32),
                "records": len(self.record_ids)}


@dataclass(frozen=True)
class IndependenceProfile:
    """What the ancestry of a body of evidence actually looks like."""

    contributors: int = 0
    root_evidence_count: int = 0
    largest_ancestry_cluster: int = 0
    shared_ancestry_concentration: Optional[float] = None
    unknown_ancestry: int = 0
    clusters: Tuple[AncestryCluster, ...] = ()
    concentration: LineageConcentration = LineageConcentration.UNKNOWN
    records_examined: int = 0
    cycles_detected: Tuple[str, ...] = ()
    basis: str = ""

    @property
    def independent_roots(self) -> int:
        """Distinct lineages, which is what "independent validations" can mean here."""
        return len(self.clusters)

    @property
    def determinable(self) -> bool:
        return self.concentration is not LineageConcentration.UNKNOWN

    def cluster(self, cluster_id: str) -> Optional[AncestryCluster]:
        return next((c for c in self.clusters if c.cluster_id == cluster_id), None)

    def digest(self) -> str:
        return digest_object({"summary": self.summary(),
                              "clusters": [c.to_dict() for c in self.clusters],
                              "schema_version": INDEPENDENCE_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {
            "contributors": self.contributors,
            "root_evidence_count": self.root_evidence_count,
            "largest_ancestry_cluster": self.largest_ancestry_cluster,
            "shared_ancestry_concentration": self.shared_ancestry_concentration,
            "unknown_ancestry": self.unknown_ancestry,
            "independent_roots": self.independent_roots,
            "concentration": self.concentration.value,
            "records_examined": self.records_examined,
            "determinable": self.determinable,
            "basis": self.basis,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "independence", "record_id": f"indep_{self.digest()[7:23]}",
                **self.summary(),
                "clusters": [c.to_dict() for c in self.clusters[:16]],
                "clusters_truncated": max(0, len(self.clusters) - 16),
                "cycles_detected": list(self.cycles_detected[:8]),
                "schema_version": INDEPENDENCE_SCHEMA_VERSION}

    @property
    def record_type(self) -> str:
        return "independence"

    @property
    def record_id(self) -> str:
        return f"indep_{self.digest()[7:23]}"

    def render(self) -> str:
        """The shape the reader actually needs, in four lines."""
        if not self.contributors:
            return "No contributing evidence, so independence cannot be assessed."
        concentration = (f"{self.shared_ancestry_concentration:.1%}"
                         if self.shared_ancestry_concentration is not None else "unknown")
        return "\n".join([
            f"Supporting contributors: {self.contributors:,}",
            f"Independent evidence roots: {self.independent_roots:,}",
            f"Largest shared lineage: {self.largest_ancestry_cluster:,} contributors "
            f"({concentration})",
            f"Result: {self.concentration.value} lineage concentration",
        ])


# ── ancestry ─────────────────────────────────────────────────────────────────

class _UnionFind:
    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:          # path compression, iterative
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra


def _root_sets(records: Sequence[EvidenceRecord]
               ) -> Tuple[Dict[str, Set[str]], Tuple[str, ...]]:
    """Every record's transitive root ancestry, computed iteratively.

    Iterative rather than recursive because a ten-thousand-deep derivation chain
    is a legitimate input and a stack overflow is not an analysis result.

    A record whose parents are not held by the case is its own root: we can see
    that it derives from something, and we cannot see what, so treating it as
    original would overstate independence and dropping it would understate the
    evidence. Being its own root does both jobs honestly — it is one lineage, and
    it is not merged with anyone else's.
    """
    by_id = {r.evidence_id: r for r in records}
    roots: Dict[str, Set[str]] = {}
    cycles: Set[str] = set()

    for record in records:
        if record.evidence_id in roots:
            continue
        # Explicit stack: (node, parents_expanded)
        stack: List[Tuple[str, bool]] = [(record.evidence_id, False)]
        on_path: Set[str] = set()
        while stack:
            node, expanded = stack.pop()
            if expanded:
                on_path.discard(node)
                current = by_id.get(node)
                parents = [p for p in (current.parent_evidence if current else ())
                           if p in by_id]
                if not parents:
                    roots[node] = {node}
                else:
                    collected: Set[str] = set()
                    for parent in parents:
                        collected |= roots.get(parent, {parent})
                    roots[node] = collected or {node}
                continue
            if node in roots:
                continue
            if node in on_path:
                # A derivation cycle. Each member becomes its own root rather than
                # the loop being followed forever or silently flattened.
                cycles.add(node)
                roots[node] = {node}
                continue
            on_path.add(node)
            stack.append((node, True))
            current = by_id.get(node)
            for parent in (current.parent_evidence if current else ()):
                if parent in by_id and parent not in roots:
                    stack.append((parent, False))
    return roots, tuple(sorted(cycles))


def _band(concentration: Optional[float], largest: int, unknown: int,
          contributors: int) -> Tuple[LineageConcentration, str]:
    """Read the ratio into a band, or refuse to.

    The refusal rule is structural rather than a tuned threshold: when the
    contributors whose ancestry nobody recorded are at least as numerous as the
    largest known cluster, that unrecorded group could itself be the largest
    lineage, so the ranking is not determined and no band is honest.
    """
    if contributors <= 1:
        return (LineageConcentration.NONE,
                "a single contributor; there is nothing to concentrate")
    if concentration is None:
        return (LineageConcentration.UNKNOWN,
                "no contributor has recorded ancestry, so concentration cannot be "
                "computed at all")
    if unknown >= largest:
        return (LineageConcentration.UNKNOWN,
                f"{unknown} contributor(s) have no recorded ancestry, which is at least "
                f"as many as the largest known lineage ({largest}); the unrecorded group "
                "could itself be the largest, so the ranking is not determined")
    if concentration < _LOW_CEILING:
        band = LineageConcentration.LOW
    elif concentration < _MODERATE_CEILING:
        band = LineageConcentration.MODERATE
    else:
        band = LineageConcentration.HIGH
    return (band, f"{largest} of {contributors} contributor(s) share one lineage")


def analyse_independence(records: Iterable[Any]) -> IndependenceProfile:
    """Derive the ancestry structure of a body of evidence.

    Clusters are connected components over root ancestry: two records are in one
    cluster when their root sets overlap, transitively. A contributor appears in
    every cluster its records touch, so cluster sizes may sum to more than the
    contributor count — a party that drew on two independent lineages genuinely
    sits in both, and hiding that by forcing a partition would misreport it.

    Linear in records and parent edges, so the ten-thousand-agent case is a normal
    input rather than a stress test.
    """
    # release-gate's own records are excluded. Independence is about external
    # corroboration, and the engine observing the file it was handed is not a
    # second opinion — counting it would add a spurious root to every case and
    # quietly inflate the very measure this module exists to deflate. The
    # provenance analyser excludes self-produced records for the same reason.
    held = [r for r in records
            if isinstance(r, EvidenceRecord)
            and r.producer.kind is not ProducerKind.RELEASE_GATE]
    if not held:
        return IndependenceProfile(
            concentration=LineageConcentration.UNKNOWN,
            basis="no external evidence records were supplied, so there is nothing "
                  "whose independence could be assessed")

    roots, cycles = _root_sets(held)

    # Union roots that co-occur on any record: that is what makes a lineage shared.
    union = _UnionFind()
    for record in held:
        record_roots = sorted(roots.get(record.evidence_id, {record.evidence_id}))
        for other in record_roots[1:]:
            union.union(record_roots[0], other)

    # A record that others derive from is a *demonstrated* origin: we can see it
    # functioning as the root of an observed lineage. A record with neither parents
    # nor dependents is the genuinely ambiguous one — nothing establishes whether
    # its producer observed something first-hand or copied it. Only the second kind
    # counts as unknown ancestry, or every case with several real lineages would
    # report as undeterminable purely for having roots.
    held_ids = {r.evidence_id for r in held}
    has_dependents: Set[str] = set()
    for record in held:
        for parent in record.parent_evidence:
            if parent in held_ids:
                has_dependents.add(parent)

    members: Dict[str, Dict[str, Set[str]]] = {}
    isolated_contributors: Set[str] = set()
    connected_contributors: Set[str] = set()
    all_contributors: Set[str] = set()

    for record in held:
        contributor = record.producer.producer_id
        all_contributors.add(contributor)
        record_roots = roots.get(record.evidence_id, {record.evidence_id})
        held_parents = [p for p in record.parent_evidence if p in held_ids]
        if held_parents or record.evidence_id in has_dependents:
            connected_contributors.add(contributor)
        else:
            isolated_contributors.add(contributor)
        key = union.find(sorted(record_roots)[0])
        bucket = members.setdefault(key, {"roots": set(), "contributors": set(),
                                          "records": set()})
        bucket["roots"] |= record_roots
        bucket["contributors"].add(contributor)
        bucket["records"].add(record.evidence_id)

    clusters = tuple(sorted(
        (AncestryCluster(cluster_id=f"lin_{key[:24]}", roots=tuple(v["roots"]),
                         contributors=tuple(v["contributors"]),
                         record_ids=tuple(v["records"]))
         for key, v in members.items()),
        key=lambda c: (-c.size, c.cluster_id)))

    contributors = len(all_contributors)
    # A contributor counts as unknown only when *every* record of theirs is
    # isolated; one connected record is enough to place them in a lineage.
    unknown_ancestry = len(isolated_contributors - connected_contributors)

    largest = clusters[0].size if clusters else 0
    known = contributors - unknown_ancestry
    concentration = (largest / contributors) if contributors and known else None
    band, basis = _band(concentration, largest, unknown_ancestry, contributors)

    root_ids: Set[str] = set()
    for cluster in clusters:
        root_ids |= set(cluster.roots)

    return IndependenceProfile(
        contributors=contributors,
        root_evidence_count=len(root_ids),
        largest_ancestry_cluster=largest,
        shared_ancestry_concentration=(round(concentration, 4)
                                       if concentration is not None else None),
        unknown_ancestry=unknown_ancestry,
        clusters=clusters,
        concentration=band,
        records_examined=len(held),
        cycles_detected=cycles,
        basis=basis)
