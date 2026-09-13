"""EvidenceGraph — how evidence rests on other evidence.

Three different dependencies run through an assurance case and conflating any
two of them destroys the ability to answer questions about either:

    ExecutionGraph   what happened, in what order, caused by what
    ClaimGraph       which propositions rest on which other propositions
    EvidenceGraph    which EVIDENCE rests on, verifies, replicates, invalidates
                     or supersedes which other EVIDENCE

This is the third. A claim appears here only as an opaque reference node: the
graph records that a piece of evidence supports `cl_887`, and says nothing about
what `cl_887` means or what it depends on. That is the ClaimGraph's work, and
keeping the boundary sharp is what lets a reviewer ask "what is the evidentiary
basis for this?" without the answer silently turning into "what does this
logically follow from?".

**The trace is the point.** The graph exists so a person or a program can walk

    verdict → unresolved condition → claim or action → evidence → source

and arrive at a named producer. `explain_verdict()` walks it in one call; the
lower three levels come from the graph and the top two from the verdict and the
methodology assessment the caller supplies, because a graph of evidence should
not store what a policy engine decided.

**Nothing is ever removed.** Superseded evidence, invalidated evidence, and
refutations all stay in the graph, marked. A graph that drops what was later
contradicted reads cleaner than the case actually is (Invariant 7). References to
evidence that is absent become explicit `MISSING` nodes rather than vanishing,
because a broken lineage chain is a finding rather than a tidy-up.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, Iterator, List, Mapping, Optional,
                    Sequence, Set, Tuple)

from release_gate.assurance.canonical import canonical_json, digest_object
from release_gate.assurance.case import AssuranceCase, COLLECTION_KINDS
from release_gate.assurance.evidence import EpistemicStatus, EvidenceRecord
from release_gate.assurance.records import Presence

GRAPH_SCHEMA_VERSION = 1


class NodeKind(str, Enum):
    """What a node stands for.

    `CLAIM` and `ACTION` are *references*, not modelled objects: this graph knows
    their ids and nothing else about them.
    """

    EVIDENCE = "EVIDENCE"
    CLAIM = "CLAIM"        # opaque reference into claim-space
    ACTION = "ACTION"      # the subject and its requested action
    SOURCE = "SOURCE"      # a producer
    MISSING = "MISSING"    # referenced but not present in the case


class EdgeType(str, Enum):
    """Evidentiary relations, plus the one structural edge that reaches a source."""

    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    DERIVED_FROM = "DERIVED_FROM"
    VERIFIES = "VERIFIES"
    INVALIDATES = "INVALIDATES"
    REPLICATES = "REPLICATES"
    ATTESTS = "ATTESTS"
    SUPERSEDES = "SUPERSEDES"
    DEPENDS_ON = "DEPENDS_ON"
    PRODUCED_BY = "PRODUCED_BY"   # evidence → source; the last hop of every trace


class AnomalyKind(str, Enum):
    """Structural problems, recorded rather than raised.

    Evidence arrives from the wild. A graph that refuses to build because one
    producer emitted a bad reference tells a reviewer nothing; a graph that
    builds and names the problem tells them exactly what to look at.
    """

    DANGLING_REFERENCE = "DANGLING_REFERENCE"
    SELF_REFERENCE = "SELF_REFERENCE"
    CYCLE = "CYCLE"
    ORPHAN_EVIDENCE = "ORPHAN_EVIDENCE"


#: Relations that must not form a cycle: evidence cannot descend from itself.
_ACYCLIC = (EdgeType.DERIVED_FROM, EdgeType.DEPENDS_ON, EdgeType.SUPERSEDES)

#: Metadata keys an adapter may use to declare edges this graph cannot infer.
#: Documented rather than magic: each holds a list of evidence ids.
LINK_METADATA_KEYS: Mapping[str, EdgeType] = {
    "replicates": EdgeType.REPLICATES,
    "attests": EdgeType.ATTESTS,
    "supersedes": EdgeType.SUPERSEDES,
    "invalidates": EdgeType.INVALIDATES,
    "depends_on": EdgeType.DEPENDS_ON,
    "verifies": EdgeType.VERIFIES,
    "contradicts_evidence": EdgeType.CONTRADICTS,
}


class GraphError(ValueError):
    """The graph was asked for something it cannot represent."""


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: NodeKind
    label: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", NodeKind(self.kind))
        if not (self.node_id or "").strip():
            raise GraphError("node_id is required")
        object.__setattr__(self, "attributes", dict(self.attributes or {}))

    def to_dict(self) -> Dict[str, Any]:
        return {"node_id": self.node_id, "kind": self.kind.value, "label": self.label,
                "attributes": dict(self.attributes)}


@dataclass(frozen=True)
class GraphEdge:
    """A directed, typed relation. `basis` says why the edge exists."""

    edge_type: EdgeType
    from_id: str
    to_id: str
    basis: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_type", EdgeType(self.edge_type))
        object.__setattr__(self, "attributes", dict(self.attributes or {}))

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.edge_type.value, self.from_id, self.to_id)

    def to_dict(self) -> Dict[str, Any]:
        return {"edge_type": self.edge_type.value, "from": self.from_id, "to": self.to_id,
                "basis": self.basis, "attributes": dict(self.attributes)}


@dataclass(frozen=True)
class Anomaly:
    kind: AnomalyKind
    detail: str
    nodes: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "detail": self.detail, "nodes": list(self.nodes)}


@dataclass(frozen=True)
class GraphCoverage:
    """What the graph is built from, and what it could not see.

    A traversal over a graph built from 12,431 of 4,120,884 records is a true
    statement about 12,431 records. Saying so is the difference between a partial
    answer and a wrong one.
    """

    evidence_materialised: int = 0
    records_total: int = 0
    collections_read: Tuple[str, ...] = ()
    collections_absent: Tuple[str, ...] = ()
    non_evidence_records: int = 0

    @property
    def not_materialised(self) -> int:
        """Records the case counted but does not hold, so the graph never saw them."""
        return max(0, self.records_total
                   - self.evidence_materialised - self.non_evidence_records)

    @property
    def complete(self) -> bool:
        """True when every record in the collections read was inspected.

        Records that were inspected and turned out not to be evidence do not make
        a graph incomplete — they were seen and skipped for a stated reason. Only
        records nobody looked at do.
        """
        return self.not_materialised == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_materialised": self.evidence_materialised,
            "records_total": self.records_total,
            "not_materialised": self.not_materialised,
            "complete": self.complete,
            "collections_read": list(self.collections_read),
            "collections_absent": list(self.collections_absent),
            "non_evidence_records": self.non_evidence_records,
            "note": ("every record in the collections read was inspected"
                     if self.complete else
                     "this graph covers the materialised evidence only; traversals are "
                     "true statements about what is held, not about what exists"),
        }


class EvidenceGraph:
    """A typed, immutable graph of evidentiary relations."""

    def __init__(self, nodes: Iterable[GraphNode], edges: Iterable[GraphEdge],
                 *, anomalies: Iterable[Anomaly] = (),
                 coverage: Optional[GraphCoverage] = None) -> None:
        self._nodes: Dict[str, GraphNode] = {n.node_id: n for n in nodes}
        # Sorted so the graph, its digest and every traversal are reproducible
        # regardless of the order records happened to arrive.
        self._edges: Tuple[GraphEdge, ...] = tuple(sorted(
            {e.key: e for e in edges}.values(), key=lambda e: e.key))
        self.coverage = coverage or GraphCoverage()

        self._out: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._in: Dict[str, List[GraphEdge]] = defaultdict(list)
        for edge in self._edges:
            self._out[edge.from_id].append(edge)
            self._in[edge.to_id].append(edge)

        self.anomalies: Tuple[Anomaly, ...] = tuple(anomalies) + self._detect_cycles()

    # ── access ──────────────────────────────────────────────────────────────

    @property
    def nodes(self) -> Tuple[GraphNode, ...]:
        return tuple(self._nodes[k] for k in sorted(self._nodes))

    @property
    def edges(self) -> Tuple[GraphEdge, ...]:
        return self._edges

    def node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def nodes_of(self, kind: NodeKind) -> Tuple[GraphNode, ...]:
        return tuple(n for n in self.nodes if n.kind is kind)

    def out_edges(self, node_id: str, *types: EdgeType) -> Tuple[GraphEdge, ...]:
        edges = self._out.get(node_id, ())
        return tuple(e for e in edges if not types or e.edge_type in types)

    def in_edges(self, node_id: str, *types: EdgeType) -> Tuple[GraphEdge, ...]:
        edges = self._in.get(node_id, ())
        return tuple(e for e in edges if not types or e.edge_type in types)

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    # ── evidentiary queries ─────────────────────────────────────────────────

    def evidence_for(self, target_id: str) -> Dict[str, Tuple[str, ...]]:
        """What bears on a claim or action, split by direction.

        Supporting and contradicting evidence come back separately and both are
        always returned. A helper that answered only "what supports this" would
        make the refutation easy to not ask about.
        """
        incoming = self.in_edges(target_id)
        return {
            "supports": tuple(sorted(e.from_id for e in incoming
                                     if e.edge_type is EdgeType.SUPPORTS)),
            "contradicts": tuple(sorted(e.from_id for e in incoming
                                        if e.edge_type is EdgeType.CONTRADICTS)),
            "verifies": tuple(sorted(e.from_id for e in incoming
                                     if e.edge_type is EdgeType.VERIFIES)),
        }

    def sources_of(self, evidence_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.to_id for e in self.out_edges(evidence_id, EdgeType.PRODUCED_BY)))

    def lineage(self, evidence_id: str) -> Tuple[str, ...]:
        """Everything this evidence descends from, transitively and cycle-safely."""
        return self._closure(evidence_id, (EdgeType.DERIVED_FROM, EdgeType.DEPENDS_ON))

    def descendants(self, evidence_id: str) -> Tuple[str, ...]:
        """Everything that rests on this evidence — what falls if it does."""
        seen: Set[str] = set()
        frontier = [evidence_id]
        while frontier:
            current = frontier.pop()
            for edge in self.in_edges(current, EdgeType.DERIVED_FROM, EdgeType.DEPENDS_ON):
                if edge.from_id not in seen:
                    seen.add(edge.from_id)
                    frontier.append(edge.from_id)
        return tuple(sorted(seen))

    def _closure(self, start: str, types: Sequence[EdgeType]) -> Tuple[str, ...]:
        seen: Set[str] = set()
        frontier = [start]
        while frontier:
            current = frontier.pop()
            for edge in self.out_edges(current, *types):
                if edge.to_id not in seen:
                    seen.add(edge.to_id)
                    frontier.append(edge.to_id)
        return tuple(sorted(seen))

    def superseded(self) -> Tuple[str, ...]:
        """Evidence a later record replaced. Still present, and still readable."""
        return tuple(sorted({e.to_id for e in self._edges
                             if e.edge_type is EdgeType.SUPERSEDES}))

    def invalidated(self) -> Tuple[str, ...]:
        return tuple(sorted({e.to_id for e in self._edges
                             if e.edge_type is EdgeType.INVALIDATES}))

    def is_current(self, evidence_id: str) -> bool:
        """False once something supersedes or invalidates it — never removed, just marked."""
        return evidence_id not in set(self.superseded()) | set(self.invalidated())

    def replication_groups(self, evidence_id: str) -> Tuple[str, ...]:
        """Records claiming to replicate this one. A claim of replication, not a finding.

        Whether those replications are actually independent is the independence
        analyser's question; this only reports who said they replicated what
        (Invariant 6).
        """
        return tuple(sorted({e.from_id for e in self.in_edges(evidence_id, EdgeType.REPLICATES)}
                            | {e.to_id for e in self.out_edges(evidence_id, EdgeType.REPLICATES)}))

    def contradiction_pairs(self) -> Tuple[Tuple[str, str], ...]:
        """Every recorded conflict, evidence-to-evidence and evidence-to-target."""
        return tuple(sorted((e.from_id, e.to_id) for e in self._edges
                            if e.edge_type is EdgeType.CONTRADICTS))

    # ── structural integrity ────────────────────────────────────────────────

    def _detect_cycles(self) -> Tuple[Anomaly, ...]:
        """Find cycles in the relations that must be acyclic.

        Iterative rather than recursive: a lineage chain from a frontier-scale
        ingest can be deep enough to exhaust the stack, and a graph that crashes
        on large input is not a graph that handles large input.
        """
        found: List[Anomaly] = []
        colour: Dict[str, int] = {}   # 0 = visiting, 1 = done
        for start in sorted(self._nodes):
            if colour.get(start) == 1:
                continue
            stack: List[Tuple[str, Iterator[GraphEdge]]] = [
                (start, iter(self.out_edges(start, *_ACYCLIC)))]
            path: List[str] = [start]
            colour[start] = 0
            while stack:
                node, edges = stack[-1]
                advanced = False
                for edge in edges:
                    state = colour.get(edge.to_id)
                    if state == 0:
                        cycle = path[path.index(edge.to_id):] + [edge.to_id]
                        found.append(Anomaly(
                            AnomalyKind.CYCLE,
                            "evidence descends from itself through "
                            f"{' → '.join(cycle)}; a derivation cycle means the chain "
                            "cannot be grounded in anything",
                            tuple(cycle)))
                        continue
                    if state is None:
                        colour[edge.to_id] = 0
                        path.append(edge.to_id)
                        stack.append((edge.to_id, iter(self.out_edges(edge.to_id, *_ACYCLIC))))
                        advanced = True
                        break
                if not advanced:
                    colour[node] = 1
                    stack.pop()
                    if path and path[-1] == node:
                        path.pop()
        # De-duplicate: one cycle is reachable from every node on it.
        unique: Dict[frozenset, Anomaly] = {}
        for anomaly in found:
            unique.setdefault(frozenset(anomaly.nodes), anomaly)
        return tuple(unique.values())

    @property
    def missing_nodes(self) -> Tuple[GraphNode, ...]:
        """Referenced evidence the case does not hold. Explicit, never dropped."""
        return self.nodes_of(NodeKind.MISSING)

    # ── the trace ───────────────────────────────────────────────────────────

    def trace_target(self, target_id: str, *, max_evidence: int = 0) -> Dict[str, Any]:
        """From a claim or action down to evidence and the sources that produced it."""
        node = self.node(target_id)
        related = self.evidence_for(target_id)
        evidence_ids: List[str] = []
        for direction in ("verifies", "supports", "contradicts"):
            for evidence_id in related[direction]:
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
        shown = evidence_ids[:max_evidence] if max_evidence else evidence_ids

        return {
            "target": target_id,
            "kind": node.kind.value if node else NodeKind.MISSING.value,
            "label": node.label if node else "",
            "evidence_count": len(evidence_ids),
            "evidence_shown": len(shown),
            "evidence": [self._describe_evidence(e, related) for e in shown],
        }

    def _describe_evidence(self, evidence_id: str,
                           related: Mapping[str, Sequence[str]]) -> Dict[str, Any]:
        node = self.node(evidence_id)
        attributes = dict(node.attributes) if node else {}
        direction = next((d for d in ("verifies", "supports", "contradicts")
                          if evidence_id in related.get(d, ())), "relates_to")
        return {
            "evidence_id": evidence_id,
            "present": node is not None and node.kind is not NodeKind.MISSING,
            "direction": direction,
            "label": node.label if node else "",
            "epistemic_status": attributes.get("epistemic_status"),
            "verification_method": attributes.get("verification_method"),
            "current": self.is_current(evidence_id),
            "superseded_by": tuple(sorted(
                e.from_id for e in self.in_edges(evidence_id, EdgeType.SUPERSEDES))),
            "lineage": self.lineage(evidence_id),
            "sources": [self._describe_source(s) for s in self.sources_of(evidence_id)],
        }

    def _describe_source(self, source_id: str) -> Dict[str, Any]:
        node = self.node(source_id)
        attributes = dict(node.attributes) if node else {}
        return {
            "source_id": source_id,
            "label": node.label if node else "",
            "identity_basis": attributes.get("identity_basis"),
            "trust_status": attributes.get("trust_status"),
            "independence_basis": attributes.get("independence_basis"),
        }

    def explain_verdict(self, verdict: Any, assessment: Any = None, *,
                        max_evidence_per_target: int = 5) -> Dict[str, Any]:
        """The full walk: verdict → unresolved condition → claim/action → evidence → source.

        The verdict and the unmet conditions are supplied by the caller — a
        `CaseVerdict` and a `MethodologyAssessment` — because a graph of evidence
        should not hold what a policy engine decided. Everything below the
        condition comes from the graph.

        A condition that names no target descends to the action node, which is
        the honest shape for a case with no declared claims: the evidence bears
        on the action itself.
        """
        action_ids = [n.node_id for n in self.nodes_of(NodeKind.ACTION)]
        unresolved: List[Dict[str, Any]] = []

        for result in _unmet_results(assessment):
            targets = _targets_for(result, self, action_ids)
            unresolved.append({
                "condition": getattr(result, "requirement_id", str(result)),
                "outcome": _value_of(getattr(result, "outcome", None)),
                "effect": _value_of(getattr(result, "effect", None)),
                "description": getattr(result, "description", ""),
                "detail": getattr(result, "detail", ""),
                "remedy": getattr(result, "remedy", ""),
                "concerns": [self.trace_target(t, max_evidence=max_evidence_per_target)
                             for t in targets],
            })

        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "verdict": _value_of(getattr(verdict, "decision", verdict)),
            "fired_rules": list(getattr(verdict, "fired_rules", ()) or ()),
            "unresolved": unresolved,
            "unresolved_count": len(unresolved),
            "anomalies": [a.to_dict() for a in self.anomalies],
            "coverage": self.coverage.to_dict(),
        }

    def render_trace(self, explanation: Mapping[str, Any]) -> str:
        """The same walk as indented text, for a terminal or a packet."""
        lines = [f"VERDICT {explanation.get('verdict')}"]
        for condition in explanation.get("unresolved", ()):
            lines.append(f"  └─ CONDITION {condition['condition']} "
                         f"[{condition.get('outcome')}/{condition.get('effect')}]")
            if condition.get("detail"):
                lines.append(f"       {condition['detail']}")
            for concern in condition.get("concerns", ()):
                lines.append(f"     └─ {concern['kind']} {concern['target']}"
                             + (f" — {concern['label']}" if concern.get("label") else ""))
                if not concern["evidence"]:
                    lines.append("          (no evidence on record bears on this)")
                for item in concern["evidence"]:
                    marker = "" if item["current"] else " [SUPERSEDED]"
                    method = (f" via {item['verification_method']}"
                              if item.get("verification_method") else "")
                    lines.append(f"        └─ EVIDENCE {item['evidence_id']} "
                                 f"{item['direction'].upper()} "
                                 f"({item.get('epistemic_status')}{method}){marker}")
                    for source in item["sources"]:
                        lines.append(f"           └─ SOURCE {source['label'] or source['source_id']} "
                                     f"(identity: {source.get('identity_basis')}, "
                                     f"trust: {source.get('trust_status')})")
                hidden = concern["evidence_count"] - concern["evidence_shown"]
                if hidden > 0:
                    lines.append(f"        └─ … {hidden} further record(s) not shown")
        if not explanation.get("unresolved"):
            lines.append("  (no unresolved conditions)")
        return "\n".join(lines)

    # ── serialisation ───────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "evidence_graph",
            "schema_version": GRAPH_SCHEMA_VERSION,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "coverage": self.coverage.to_dict(),
            "digest": self.digest(),
        }

    def digest(self) -> str:
        """Content digest over the structure, independent of construction order."""
        return digest_object({
            "schema_version": GRAPH_SCHEMA_VERSION,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        })

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = defaultdict(int)
        for node in self.nodes:
            counts[node.kind.value] += 1
        edge_counts: Dict[str, int] = defaultdict(int)
        for edge in self._edges:
            edge_counts[edge.edge_type.value] += 1
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_node_kind": dict(sorted(counts.items())),
            "by_edge_type": dict(sorted(edge_counts.items())),
            "superseded": len(self.superseded()),
            "invalidated": len(self.invalidated()),
            "missing_references": len(self.missing_nodes),
            "anomalies": [a.to_dict() for a in self.anomalies],
            "coverage": self.coverage.to_dict(),
        }

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_case(cls, case: AssuranceCase, *,
                  collections: Sequence[str] = ("evidence", "verification",
                                                "contradictions", "counterexamples",
                                                "artifacts")) -> "EvidenceGraph":
        """Build from every `EvidenceRecord` a case holds.

        Records that are not `EvidenceRecord`s are counted and skipped rather
        than coerced: a graph built from records whose fields were guessed at
        would answer questions it cannot actually answer.
        """
        builder = EvidenceGraphBuilder()
        materialised = total = other = 0
        read: List[str] = []
        absent: List[str] = []

        for kind in collections:
            if kind not in COLLECTION_KINDS:
                raise GraphError(f"unknown collection {kind!r}")
            collection = case.collection(kind)
            if collection.presence is not Presence.PRESENT:
                absent.append(kind)
                continue
            read.append(kind)
            total += collection.total_count
            for record in collection.materialised:
                if isinstance(record, EvidenceRecord):
                    builder.add_record(record)
                    materialised += 1
                else:
                    other += 1

        subject = case.subject
        builder.add_action(
            node_id=f"action:{subject.subject_id}",
            label=subject.requested_action,
            attributes={"subject_id": subject.subject_id, "digest": subject.digest,
                        "subject_type": subject.subject_type.value})
        builder.link_verifications_to(subject.digest, f"action:{subject.subject_id}")

        return builder.build(coverage=GraphCoverage(
            evidence_materialised=materialised, records_total=total,
            collections_read=tuple(read), collections_absent=tuple(absent),
            non_evidence_records=other))


class EvidenceGraphBuilder:
    """Accumulates nodes and edges, then resolves references once at the end."""

    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._anomalies: List[Anomaly] = []
        self._evidence_ids: Set[str] = set()
        self._referenced: Dict[str, List[str]] = defaultdict(list)
        self._by_digest: Dict[str, List[str]] = defaultdict(list)

    # ── nodes ───────────────────────────────────────────────────────────────

    def _node(self, node_id: str, kind: NodeKind, label: str = "",
              attributes: Optional[Mapping[str, Any]] = None) -> str:
        existing = self._nodes.get(node_id)
        if existing is None or (existing.kind is NodeKind.MISSING and kind is not NodeKind.MISSING):
            self._nodes[node_id] = GraphNode(node_id=node_id, kind=kind, label=label,
                                             attributes=attributes or {})
        return node_id

    def add_action(self, *, node_id: str, label: str,
                   attributes: Optional[Mapping[str, Any]] = None) -> str:
        return self._node(node_id, NodeKind.ACTION, label, attributes)

    def add_claim_ref(self, claim_id: str) -> str:
        """A reference into claim-space. This graph knows the id and nothing more."""
        return self._node(claim_id, NodeKind.CLAIM, claim_id)

    def add_record(self, record: EvidenceRecord) -> str:
        """Add one evidence record and every edge derivable from its own fields."""
        node_id = self._node(
            record.evidence_id, NodeKind.EVIDENCE,
            label=f"{record.evidence_type.value} from {record.source}",
            attributes={
                "evidence_type": record.evidence_type.value,
                "epistemic_status": record.epistemic_status.value,
                "verification_method": (record.verification_method.value
                                        if record.verification_method else None),
                "applies_to_digest": record.applies_to_digest,
                "digest": record.digest,
                "coverage_status": record.coverage_status.value,
                "timestamp": record.timestamp,
            })
        self._evidence_ids.add(node_id)
        if record.digest:
            self._by_digest[record.digest].append(node_id)

        source_id = self._node(
            f"source:{record.source}:{record.producer.producer_id}", NodeKind.SOURCE,
            label=record.producer.producer_id,
            attributes={
                "source": record.source,
                "producer_kind": record.producer.kind.value,
                "identity_basis": record.producer.identity_basis,
                "source_identity": record.source_identity,
                "trust_status": record.trust_status.value,
                "provenance_status": record.provenance_status.value,
                "independence_group": record.independence_fingerprint(),
                "independence_basis": record.independence_basis,
                "model": record.producer.model,
            })
        self._edges.append(GraphEdge(EdgeType.PRODUCED_BY, node_id, source_id,
                                     basis="producer recorded on the evidence"))

        for claim_id in record.supports_claims:
            self.add_claim_ref(claim_id)
            self._edges.append(GraphEdge(EdgeType.SUPPORTS, node_id, claim_id,
                                         basis="supports_claims"))
        for claim_id in record.contradicts_claims:
            self.add_claim_ref(claim_id)
            self._edges.append(GraphEdge(EdgeType.CONTRADICTS, node_id, claim_id,
                                         basis="contradicts_claims"))

        for parent in record.parent_evidence:
            if parent == node_id:
                self._anomalies.append(Anomaly(
                    AnomalyKind.SELF_REFERENCE,
                    f"{node_id} names itself as its own parent", (node_id,)))
                continue
            self._referenced[parent].append(node_id)
            self._edges.append(GraphEdge(EdgeType.DERIVED_FROM, node_id, parent,
                                         basis="parent_evidence"))

        for key, edge_type in LINK_METADATA_KEYS.items():
            for target in (record.metadata or {}).get(key, ()) or ():
                if not isinstance(target, str) or target == node_id:
                    continue
                self._referenced[target].append(node_id)
                self._edges.append(GraphEdge(edge_type, node_id, target,
                                             basis=f"metadata.{key}"))

        return node_id

    def link(self, edge_type: EdgeType, from_id: str, to_id: str, basis: str = "") -> None:
        """Declare an edge the records themselves do not express."""
        self._referenced[to_id].append(from_id)
        self._edges.append(GraphEdge(edge_type, from_id, to_id, basis=basis or "declared"))

    def link_verifications_to(self, digest: Optional[str], target_id: str) -> None:
        """Point every verification of `digest` at the node that digest identifies.

        This is what makes `applies_to_digest` navigable: a verification of the
        exact subject becomes an edge to the action, and a verification of some
        other revision does not.
        """
        if not digest:
            return
        for node_id in sorted(self._evidence_ids):
            node = self._nodes[node_id]
            if node.attributes.get("applies_to_digest") == digest:
                self._edges.append(GraphEdge(
                    EdgeType.VERIFIES, node_id, target_id,
                    basis=f"applies_to_digest matches {digest[:23]}…"))

    # ── result ──────────────────────────────────────────────────────────────

    def build(self, *, coverage: Optional[GraphCoverage] = None) -> EvidenceGraph:
        # Resolve references last: a record may name a parent that arrives later,
        # and only once everything is in can a reference be called dangling.
        for referenced_id, referrers in sorted(self._referenced.items()):
            if referenced_id in self._nodes or not referrers:
                continue
            if self._by_digest.get(referenced_id):
                continue
            self._node(referenced_id, NodeKind.MISSING,
                       label="referenced but not present in this case",
                       attributes={"referenced_by": sorted(set(referrers))})
            self._anomalies.append(Anomaly(
                AnomalyKind.DANGLING_REFERENCE,
                f"{referenced_id} is referenced by {len(set(referrers))} record(s) and is "
                "not in the case — the chain cannot be followed past this point",
                tuple(sorted(set(referrers)))))

        for node_id in sorted(self._evidence_ids):
            if not any(e.from_id == node_id and e.edge_type is not EdgeType.PRODUCED_BY
                       for e in self._edges):
                self._anomalies.append(Anomaly(
                    AnomalyKind.ORPHAN_EVIDENCE,
                    f"{node_id} bears on nothing recorded in this case",
                    (node_id,)))

        return EvidenceGraph(self._nodes.values(), self._edges,
                             anomalies=self._anomalies, coverage=coverage)


def _value_of(value: Any) -> Any:
    return getattr(value, "value", value)


def _unmet_results(assessment: Any) -> Tuple[Any, ...]:
    if assessment is None:
        return ()
    unmet = getattr(assessment, "unmet", None)
    if callable(unmet):
        return tuple(unmet())
    return tuple(assessment)


def _targets_for(result: Any, graph: "EvidenceGraph",
                 action_ids: Sequence[str]) -> Tuple[str, ...]:
    """Which claim or action a condition concerns.

    A requirement may name claims explicitly through `observed["claims"]`. When it
    does not, the condition concerns the action itself — which is the honest shape
    for a case with no declared claims rather than a dead end in the trace.
    """
    observed = getattr(result, "observed", None) or {}
    named = tuple(c for c in (observed.get("claims") or ()) if isinstance(c, str))
    if named:
        return named
    return tuple(action_ids)
