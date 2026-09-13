"""ExecutionGraph — what the autonomous system actually did.

Reconstructed from telemetry teams already emit. There is no registration step
and no SDK to adopt: agents, tools, verifiers and artifacts are inferred from
span and resource attributes, and every node records *why* it was classified the
way it was, so a reviewer can disagree with a call rather than wonder about it.

The same OTLP export the trace adapter reads becomes a richer object here.
`release_gate/adapters/otel.py` deliberately skips `invoke_agent` spans as
structural, because a trace policy gates on behaviour rather than shape; this
graph wants exactly that structure, because the shape is who did what. Same
input, different projection, one parser — the helpers in `adapters/common.py`
are reused rather than reimplemented.

Three properties make it work from one agent to ten thousand:

**The skeleton is kept, the leaves collapse.** Agents, tasks, tools, artifacts,
humans and verifiers are structure and are always materialised. Model calls are
the millions, and past a budget they fold into per-agent aggregate nodes carrying
counts and token totals. A ten-thousand-agent run keeps its full shape and stops
holding four million individual calls.

**Completeness is never claimed.** The status vocabulary has no COMPLETE value.
Absence of observed gaps is not evidence of completeness (Invariant 13), so a
graph with nothing visibly missing still reports `UNKNOWN` unless a source
manifest or sequence range gives something real to check against — and when one
does, what arrived is compared to it and the delta is reported.

**Missing telemetry is visible.** A span naming a parent that never arrived
produces an `UNOBSERVED` node rather than a silently reparented orphan. The gap
in the record is part of the record.

The graph is optional. A case with no execution telemetry has no ExecutionGraph,
which reports as NOT_ASSESSED rather than as an empty run (Invariant 14).
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.adapters.common import (
    as_int,
    iter_otlp_spans,
    otlp_attributes,
    span_start_ns,
)
from release_gate.assurance.canonical import digest_object
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.records import Presence

EXECUTION_SCHEMA_VERSION = 1

#: Past this many model-call nodes the builder folds them into per-agent
#: aggregates. Chosen so a 100-agent run keeps every call and a 10,000-agent run
#: keeps its shape; override per build when a case warrants it.
DEFAULT_MAX_LEAF_NODES = 50_000


class ExecutionNodeKind(str, Enum):
    AGENT = "AGENT"
    TASK = "TASK"
    TOOL = "TOOL"
    ACTION = "ACTION"
    MODEL_CALL = "MODEL_CALL"
    ARTIFACT = "ARTIFACT"
    EXTERNAL_SYSTEM = "EXTERNAL_SYSTEM"
    HUMAN = "HUMAN"
    VERIFIER = "VERIFIER"
    UNOBSERVED = "UNOBSERVED"   # referenced by something that arrived; never itself arrived


class ExecutionEdgeType(str, Enum):
    SPAWNED = "SPAWNED"
    DELEGATED = "DELEGATED"
    CALLED = "CALLED"
    PRODUCED = "PRODUCED"
    CONSUMED = "CONSUMED"
    MODIFIED = "MODIFIED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    AUTHORIZED = "AUTHORIZED"
    DERIVED_FROM = "DERIVED_FROM"


class CompletenessStatus(str, Enum):
    """What can be said about whether the record is whole.

    There is deliberately no `COMPLETE`. Nothing a graph can observe about
    telemetry it received establishes that nothing was withheld, and a status
    value saying otherwise would be the single most load-bearing lie in the
    system (Invariant 13).
    """

    UNKNOWN = "UNKNOWN"                      # no expectation to check against
    GAPS_DETECTED = "GAPS_DETECTED"          # missing parents or sequence gaps
    MATCHES_DECLARATION = "MATCHES_DECLARATION"  # a declaration exists and what arrived fits it


class ExecutionGraphError(ValueError):
    """Telemetry could not be turned into a graph."""


#: How span attributes classify a node. A table rather than a chain of ifs so it
#: can be read, extended and argued with; every node records which rule fired.
MODEL_CALL_OPERATIONS = frozenset({"chat", "text_completion", "generate_content",
                                   "embeddings", "completion"})
TOOL_OPERATIONS = frozenset({"execute_tool", "tool"})
AGENT_OPERATIONS = frozenset({"invoke_agent", "create_agent", "agent"})

AGENT_ID_KEYS = ("gen_ai.agent.id", "gen_ai.agent.name", "agent.id", "agent.name",
                 "openinference.agent.name")
TOOL_NAME_KEYS = ("gen_ai.tool.name", "tool.name", "tool", "function.name")
MODEL_KEYS = ("gen_ai.request.model", "gen_ai.response.model", "llm.model_name", "model")
HUMAN_KEYS = ("human.id", "approval.by", "approver", "reviewed_by")
VERIFIER_KEYS = ("verifier.id", "verifier.name", "verification.by")
ACTION_KEYS = ("action.name", "action.id")
EXTERNAL_KEYS = ("http.url", "url.full", "db.system", "peer.service", "server.address")
ARTIFACT_PRODUCED_KEYS = ("artifact.digest", "output.digest", "artifact.id")
ARTIFACT_CONSUMED_KEYS = ("input.digest", "input.artifact.id")
ARTIFACT_MODIFIED_KEYS = ("artifact.modified", "modified.digest")
TOKEN_KEYS = ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
              "gen_ai.usage.prompt_tokens", "gen_ai.usage.completion_tokens",
              "llm.token_count.total")

#: Structural parent→child edge, chosen by what the child turned out to be.
_CHILD_EDGE: Mapping[ExecutionNodeKind, ExecutionEdgeType] = {
    ExecutionNodeKind.AGENT: ExecutionEdgeType.SPAWNED,
    ExecutionNodeKind.TASK: ExecutionEdgeType.DELEGATED,
    ExecutionNodeKind.MODEL_CALL: ExecutionEdgeType.CALLED,
    ExecutionNodeKind.TOOL: ExecutionEdgeType.CALLED,
    ExecutionNodeKind.EXTERNAL_SYSTEM: ExecutionEdgeType.CALLED,
    ExecutionNodeKind.ACTION: ExecutionEdgeType.CALLED,
    ExecutionNodeKind.VERIFIER: ExecutionEdgeType.DELEGATED,
    ExecutionNodeKind.HUMAN: ExecutionEdgeType.DELEGATED,
    ExecutionNodeKind.ARTIFACT: ExecutionEdgeType.PRODUCED,
}

#: Kinds that are structure. Always materialised, however large the run.
_STRUCTURAL = frozenset({ExecutionNodeKind.AGENT, ExecutionNodeKind.TASK,
                         ExecutionNodeKind.TOOL, ExecutionNodeKind.ARTIFACT,
                         ExecutionNodeKind.EXTERNAL_SYSTEM, ExecutionNodeKind.HUMAN,
                         ExecutionNodeKind.VERIFIER, ExecutionNodeKind.ACTION,
                         ExecutionNodeKind.UNOBSERVED})


@dataclass(frozen=True)
class ExecutionNode:
    node_id: str
    kind: ExecutionNodeKind
    label: str = ""
    started_at: Optional[int] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    aggregate_of: int = 0   # >0 when this node stands for that many observed nodes

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ExecutionNodeKind(self.kind))
        object.__setattr__(self, "attributes", dict(self.attributes or {}))
        if not (self.node_id or "").strip():
            raise ExecutionGraphError("node_id is required")

    @property
    def is_aggregate(self) -> bool:
        return self.aggregate_of > 0

    def to_dict(self) -> Dict[str, Any]:
        return {"node_id": self.node_id, "kind": self.kind.value, "label": self.label,
                "started_at": self.started_at, "aggregate_of": self.aggregate_of,
                "attributes": dict(self.attributes)}


@dataclass(frozen=True)
class ExecutionEdge:
    edge_type: ExecutionEdgeType
    from_id: str
    to_id: str
    count: int = 1
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_type", ExecutionEdgeType(self.edge_type))

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.edge_type.value, self.from_id, self.to_id)

    def to_dict(self) -> Dict[str, Any]:
        return {"edge_type": self.edge_type.value, "from": self.from_id, "to": self.to_id,
                "count": self.count, "basis": self.basis}


@dataclass(frozen=True)
class ExecutionCompleteness:
    """What is known about whether this record is whole.

    Every field here exists to stop one sentence being written: "the agents did
    nothing else." Nothing observable about received telemetry establishes that.
    """

    spans_seen: int = 0
    nodes_materialised: int = 0
    nodes_aggregated: int = 0
    unobserved_parents: Tuple[str, ...] = ()
    sequence_gaps: Tuple[Mapping[str, Any], ...] = ()
    declared_sources: Tuple[str, ...] = ()
    observed_sources: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()

    @property
    def missing_sources(self) -> Tuple[str, ...]:
        """Sources a manifest promised that never reported."""
        return tuple(sorted(set(self.declared_sources) - set(self.observed_sources)))

    @property
    def status(self) -> CompletenessStatus:
        if self.unobserved_parents or self.sequence_gaps or self.missing_sources:
            return CompletenessStatus.GAPS_DETECTED
        if self.declared_sources:
            return CompletenessStatus.MATCHES_DECLARATION
        return CompletenessStatus.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        status = self.status
        note = {
            CompletenessStatus.UNKNOWN: (
                "No source manifest or sequence range was supplied, so there is nothing "
                "to check arrival against. Nothing observed is missing; that is not the "
                "same as nothing being missing."),
            CompletenessStatus.GAPS_DETECTED: (
                "Parts of the record were referenced but never arrived. What is below "
                "describes what was received, not what happened."),
            CompletenessStatus.MATCHES_DECLARATION: (
                "What arrived matches the declaration supplied with it. The declaration "
                "is itself a claim by the producing system, not proof of completeness."),
        }[status]
        return {
            "status": status.value,
            "spans_seen": self.spans_seen,
            "nodes_materialised": self.nodes_materialised,
            "nodes_aggregated": self.nodes_aggregated,
            "unobserved_parents": list(self.unobserved_parents),
            "sequence_gaps": [dict(g) for g in self.sequence_gaps],
            "declared_sources": list(self.declared_sources),
            "observed_sources": list(self.observed_sources),
            "missing_sources": list(self.missing_sources),
            "notes": list(self.notes),
            "note": note,
        }


class ExecutionGraph:
    """An immutable, typed graph of what ran."""

    def __init__(self, nodes: Iterable[ExecutionNode], edges: Iterable[ExecutionEdge],
                 *, completeness: Optional[ExecutionCompleteness] = None) -> None:
        self._nodes: Dict[str, ExecutionNode] = {n.node_id: n for n in nodes}
        self._edges: Tuple[ExecutionEdge, ...] = tuple(sorted(
            {e.key: e for e in edges}.values(), key=lambda e: e.key))
        self.completeness = completeness or ExecutionCompleteness()

        self._out: Dict[str, List[ExecutionEdge]] = defaultdict(list)
        self._in: Dict[str, List[ExecutionEdge]] = defaultdict(list)
        for edge in self._edges:
            self._out[edge.from_id].append(edge)
            self._in[edge.to_id].append(edge)

    # ── access ──────────────────────────────────────────────────────────────

    @property
    def nodes(self) -> Tuple[ExecutionNode, ...]:
        return tuple(self._nodes[k] for k in sorted(self._nodes))

    @property
    def edges(self) -> Tuple[ExecutionEdge, ...]:
        return self._edges

    def node(self, node_id: str) -> Optional[ExecutionNode]:
        return self._nodes.get(node_id)

    def nodes_of(self, kind: ExecutionNodeKind) -> Tuple[ExecutionNode, ...]:
        return tuple(n for n in self.nodes if n.kind is kind)

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    def out_edges(self, node_id: str, *types: ExecutionEdgeType) -> Tuple[ExecutionEdge, ...]:
        return tuple(e for e in self._out.get(node_id, ())
                     if not types or e.edge_type in types)

    def in_edges(self, node_id: str, *types: ExecutionEdgeType) -> Tuple[ExecutionEdge, ...]:
        return tuple(e for e in self._in.get(node_id, ())
                     if not types or e.edge_type in types)

    # ── who did what ────────────────────────────────────────────────────────

    def agents(self) -> Tuple[ExecutionNode, ...]:
        return self.nodes_of(ExecutionNodeKind.AGENT)

    def tools(self) -> Tuple[ExecutionNode, ...]:
        return self.nodes_of(ExecutionNodeKind.TOOL)

    def artifacts(self) -> Tuple[ExecutionNode, ...]:
        return self.nodes_of(ExecutionNodeKind.ARTIFACT)

    def humans(self) -> Tuple[ExecutionNode, ...]:
        return self.nodes_of(ExecutionNodeKind.HUMAN)

    def verifiers(self) -> Tuple[ExecutionNode, ...]:
        return self.nodes_of(ExecutionNodeKind.VERIFIER)

    def roots(self) -> Tuple[ExecutionNode, ...]:
        """Nodes nothing structural points at — where the run began, as recorded."""
        structural = (ExecutionEdgeType.SPAWNED, ExecutionEdgeType.DELEGATED,
                      ExecutionEdgeType.CALLED)
        return tuple(n for n in self.nodes if not self.in_edges(n.node_id, *structural))

    def children(self, node_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.to_id for e in self.out_edges(node_id)))

    def ancestors(self, node_id: str) -> Tuple[str, ...]:
        """Everything that led to this node, cycle-safe and iterative."""
        seen: Set[str] = set()
        frontier = [node_id]
        while frontier:
            current = frontier.pop()
            for edge in self.in_edges(current, ExecutionEdgeType.SPAWNED,
                                      ExecutionEdgeType.DELEGATED, ExecutionEdgeType.CALLED):
                if edge.from_id not in seen:
                    seen.add(edge.from_id)
                    frontier.append(edge.from_id)
        return tuple(sorted(seen))

    def produced_by(self, artifact_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.from_id for e in self.in_edges(artifact_id,
                                                             ExecutionEdgeType.PRODUCED)))

    def consumed_by(self, artifact_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.from_id for e in self.in_edges(artifact_id,
                                                             ExecutionEdgeType.CONSUMED)))

    def authorised_by(self, node_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.from_id for e in self.in_edges(node_id,
                                                             ExecutionEdgeType.AUTHORIZED)))

    def actions_without_recorded_authorisation(self) -> Tuple[str, ...]:
        """Actions no AUTHORIZED edge reaches.

        A factual statement about the telemetry, not a finding: an action can be
        legitimately pre-authorised somewhere this graph never saw. Whether that
        matters is a methodology question.
        """
        return tuple(sorted(n.node_id for n in self.nodes_of(ExecutionNodeKind.ACTION)
                            if not self.authorised_by(n.node_id)))

    def verification_outcomes(self) -> Dict[str, Tuple[str, ...]]:
        return {
            "verified": tuple(sorted(e.to_id for e in self._edges
                                     if e.edge_type is ExecutionEdgeType.VERIFIED)),
            "rejected": tuple(sorted(e.to_id for e in self._edges
                                     if e.edge_type is ExecutionEdgeType.REJECTED)),
        }

    def fan_out(self, agent_id: str) -> int:
        return sum(e.count for e in self.out_edges(agent_id, ExecutionEdgeType.SPAWNED,
                                                   ExecutionEdgeType.DELEGATED))

    def delegation_depth(self) -> int:
        """Longest chain of spawn/delegation. Iterative; a deep run cannot blow the stack."""
        depth: Dict[str, int] = {}
        order = self._topological_order()
        for node_id in order:
            incoming = self.in_edges(node_id, ExecutionEdgeType.SPAWNED,
                                     ExecutionEdgeType.DELEGATED)
            depth[node_id] = max((depth.get(e.from_id, 0) + 1 for e in incoming), default=0)
        return max(depth.values(), default=0)

    def _topological_order(self) -> List[str]:
        """Kahn's algorithm over spawn/delegation; cycles fall to the end."""
        relevant = [e for e in self._edges
                    if e.edge_type in (ExecutionEdgeType.SPAWNED, ExecutionEdgeType.DELEGATED)]
        indegree: Dict[str, int] = {n: 0 for n in self._nodes}
        for edge in relevant:
            indegree[edge.to_id] = indegree.get(edge.to_id, 0) + 1
        queue = [n for n, d in indegree.items() if d == 0]
        heapq.heapify(queue)   # sorted for determinism, without re-sorting a list
        order: List[str] = []
        while queue:
            node_id = heapq.heappop(queue)
            order.append(node_id)
            for edge in self.out_edges(node_id, ExecutionEdgeType.SPAWNED,
                                       ExecutionEdgeType.DELEGATED):
                indegree[edge.to_id] -= 1
                if indegree[edge.to_id] == 0:
                    heapq.heappush(queue, edge.to_id)
        order.extend(sorted(set(self._nodes) - set(order)))
        return order

    # ── output ──────────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = defaultdict(int)
        for node in self.nodes:
            by_kind[node.kind.value] += 1
        by_edge: Dict[str, int] = defaultdict(int)
        for edge in self._edges:
            by_edge[edge.edge_type.value] += edge.count
        aggregated = sum(n.aggregate_of for n in self.nodes if n.is_aggregate)
        return {
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_node_kind": dict(sorted(by_kind.items())),
            "by_edge_type": dict(sorted(by_edge.items())),
            "agents": len(self.agents()),
            "tools": len(self.tools()),
            "model_calls_represented": aggregated + len(
                [n for n in self.nodes_of(ExecutionNodeKind.MODEL_CALL) if not n.is_aggregate]),
            "delegation_depth": self.delegation_depth(),
            "actions_without_recorded_authorisation":
                len(self.actions_without_recorded_authorisation()),
            "completeness": self.completeness.to_dict(),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "execution_graph",
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "completeness": self.completeness.to_dict(),
            "digest": self.digest(),
        }

    def digest(self) -> str:
        return digest_object({"schema_version": EXECUTION_SCHEMA_VERSION,
                              "nodes": [n.to_dict() for n in self.nodes],
                              "edges": [e.to_dict() for e in self.edges]})

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_otlp(cls, document: Any, **kwargs: Any) -> "ExecutionGraph":
        """Build from an OTLP/JSON export. No registration, no SDK, no cooperation."""
        builder = ExecutionGraphBuilder(**kwargs)
        builder.add_otlp(document)
        return builder.build()

    @classmethod
    def from_native_trace(cls, trace: Mapping[str, Any], **kwargs: Any) -> "ExecutionGraph":
        """Build from release-gate's own `{trace_id, steps[]}` trace.

        The degenerate case of this graph: one root and a linear spine. The format
        predates the graph and keeps working unchanged.
        """
        builder = ExecutionGraphBuilder(**kwargs)
        builder.add_native_trace(trace)
        return builder.build()

    @classmethod
    def from_case(cls, case: AssuranceCase, **kwargs: Any) -> Optional["ExecutionGraph"]:
        """Build from a case's `executions` collection, or return None.

        `None` rather than an empty graph: a case with no execution telemetry has
        not been shown to have done nothing, and an empty graph would read exactly
        that way (Invariant 14).
        """
        collection = case.collection("executions")
        if collection.presence is not Presence.PRESENT:
            return None
        builder = ExecutionGraphBuilder(**kwargs)
        for record in collection.materialised:
            builder.add_span_record(record.to_dict())
        builder.note(
            f"built from {collection.held_count} of {collection.total_count} execution "
            "record(s) the case holds")
        if collection.not_materialised:
            builder.note(
                f"{collection.not_materialised} execution record(s) were counted but not "
                "materialised; they are absent from this graph")
        return builder.build()


class ExecutionGraphBuilder:
    """Turns telemetry into a graph, collapsing leaves once the run gets large."""

    def __init__(self, *, max_leaf_nodes: int = DEFAULT_MAX_LEAF_NODES,
                 declared_sources: Iterable[str] = ()) -> None:
        self.max_leaf_nodes = max(0, int(max_leaf_nodes))
        self._nodes: Dict[str, ExecutionNode] = {}
        self._edges: Dict[Tuple[str, str, str], ExecutionEdge] = {}
        self._declared_sources = tuple(declared_sources)
        self._observed_sources: Set[str] = set()
        self._spans_seen = 0
        self._leaf_count = 0
        self._aggregates: Dict[str, Dict[str, Any]] = {}
        self._parent_of: Dict[str, str] = {}
        # span id → the node it actually became. An agent span and the agent it
        # names are one agent, not two, and children referencing either id must
        # land on the same node or every delegation question is wrong.
        self._alias: Dict[str, str] = {}
        self._referenced_parents: Set[str] = set()
        self._sequences: Dict[str, Set[int]] = defaultdict(set)
        self._notes: List[str] = []

    def note(self, message: str) -> "ExecutionGraphBuilder":
        if message and message not in self._notes:
            self._notes.append(message)
        return self

    def declare_sources(self, sources: Iterable[str]) -> "ExecutionGraphBuilder":
        """Supply the manifest of sources expected to report.

        The only thing that turns "nothing looks missing" into a checkable
        statement. The manifest is itself a claim by the producing system, and the
        completeness record says so.
        """
        self._declared_sources = tuple(dict.fromkeys(self._declared_sources + tuple(sources)))
        return self

    # ── nodes and edges ─────────────────────────────────────────────────────

    def _node(self, node_id: str, kind: ExecutionNodeKind, label: str = "",
              started_at: Optional[int] = None,
              attributes: Optional[Mapping[str, Any]] = None) -> str:
        existing = self._nodes.get(node_id)
        if existing is not None and existing.kind is not ExecutionNodeKind.UNOBSERVED:
            return node_id
        self._nodes[node_id] = ExecutionNode(node_id=node_id, kind=kind, label=label,
                                             started_at=started_at,
                                             attributes=dict(attributes or {}))
        return node_id

    def _edge(self, edge_type: ExecutionEdgeType, from_id: str, to_id: str,
              basis: str = "") -> None:
        key = (edge_type.value, from_id, to_id)
        existing = self._edges.get(key)
        if existing is None:
            self._edges[key] = ExecutionEdge(edge_type, from_id, to_id, basis=basis)
        else:
            # Repeated invocations of the same tool become a count, not a node
            # per call: the fact worth keeping is that it happened 412 times.
            self._edges[key] = ExecutionEdge(edge_type, from_id, to_id,
                                             count=existing.count + 1, basis=existing.basis)

    # ── telemetry ───────────────────────────────────────────────────────────

    def add_otlp(self, document: Any) -> "ExecutionGraphBuilder":
        """Read an OTLP/JSON document through the existing span helpers.

        Holds the document, because it was handed one. A caller streaming spans
        from disk calls `add_span()` per span and never materialises the whole
        export; the graph itself stays bounded either way.
        """
        spans = list(iter_otlp_spans(document))
        # Time order so a parent is usually in place before its children, which
        # keeps UNOBSERVED placeholders to genuine gaps rather than orderings.
        spans.sort(key=lambda pair: span_start_ns(pair[0]))
        for span, resource_attrs in spans:
            self.add_span(span, resource_attrs)
        return self

    def add_span(self, span: Mapping[str, Any],
                 resource_attrs: Optional[Mapping[str, Any]] = None
                 ) -> "ExecutionGraphBuilder":
        """Classify one OTLP span and attach it to the graph."""
        attrs = otlp_attributes(span.get("attributes", []))
        resource = dict(resource_attrs or {})
        merged = {**resource, **attrs}
        span_id = str(span.get("spanId") or span.get("span_id") or "")
        parent_id = str(span.get("parentSpanId") or span.get("parent_span_id") or "")
        name = str(span.get("name") or "")
        started = span_start_ns(span)
        self._spans_seen += 1
        self._record_source(merged)
        self._record_sequence(merged)
        self._ingest(span_id or f"span:{self._spans_seen}", parent_id, name, merged, started)
        return self

    def add_span_record(self, record: Mapping[str, Any]) -> "ExecutionGraphBuilder":
        """Attach an already-flat execution record (the envelope's `execution` shape)."""
        attrs = dict(record.get("attributes") or {})
        for key in ("tool", "model", "agent", "action", "artifact"):
            if key in record:
                attrs.setdefault(key, record[key])
        node_kind_hint = record.get("node_kind") or record.get("type")
        if node_kind_hint:
            attrs.setdefault("_kind_hint", node_kind_hint)
        self._spans_seen += 1
        self._record_source(attrs)
        if record.get("sequence") is not None:
            self._sequences[str(record.get("stream_id") or "default")].add(
                as_int(record.get("sequence")))
        self._ingest(str(record.get("node_id") or record.get("record_id")
                         or f"record:{self._spans_seen}"),
                     str(record.get("parent_id") or ""), str(record.get("label") or ""),
                     attrs, as_int(record.get("started_at")) or None)
        return self

    def add_native_trace(self, trace: Mapping[str, Any]) -> "ExecutionGraphBuilder":
        """Attach a release-gate native trace: one root, a linear spine."""
        trace_id = str(trace.get("trace_id") or "trace")
        agent_id = f"agent:{trace_id}"
        self._node(agent_id, ExecutionNodeKind.AGENT, label=trace_id,
                   attributes={"classified_by": "native trace root"})
        self._observed_sources.add(agent_id)

        for index, step in enumerate(trace.get("steps") or ()):
            if not isinstance(step, Mapping):
                continue
            self._spans_seen += 1
            step_type = str(step.get("type") or "")
            if step_type == "llm_call":
                self._add_model_call(agent_id, f"{trace_id}:call:{index}",
                                     model=step.get("model"),
                                     tokens=as_int(step.get("tokens")),
                                     basis="native trace step type llm_call")
            elif step_type == "tool_call":
                tool = str(step.get("tool") or "unknown-tool")
                tool_id = self._node(f"tool:{tool}", ExecutionNodeKind.TOOL, label=tool,
                                     attributes={"classified_by": "native trace step "
                                                                 "type tool_call"})
                self._edge(ExecutionEdgeType.CALLED, agent_id, tool_id,
                           basis="native trace tool_call")
            else:
                task_id = self._node(f"{trace_id}:step:{index}", ExecutionNodeKind.TASK,
                                     label=step_type or "step",
                                     attributes={"classified_by": "native trace step",
                                                 "step_type": step_type})
                self._edge(ExecutionEdgeType.DELEGATED, agent_id, task_id,
                           basis="native trace step")
        return self

    # ── classification ──────────────────────────────────────────────────────

    def _ingest(self, node_id: str, parent_id: str, name: str,
                attrs: Mapping[str, Any], started: Optional[int]) -> None:
        kind, label, basis = _classify(name, attrs)

        if kind is ExecutionNodeKind.AGENT:
            # One agent, however many spans mention it: the attribute is the
            # identity, and the span id becomes an alias to it.
            named = _first(attrs, AGENT_ID_KEYS)
            actor = self._node(f"agent:{named}" if named else node_id,
                               ExecutionNodeKind.AGENT, label=str(named or label or name),
                               started_at=started,
                               attributes={"classified_by": basis, **_carry(attrs)})
            self._observed_sources.add(actor)
            self._link_from_parent(actor, parent_id, ExecutionNodeKind.AGENT, basis)
        else:
            agent_id = self._agent_for(attrs, parent_id)
            if kind is ExecutionNodeKind.MODEL_CALL:
                self._add_model_call(parent_id or agent_id or node_id, node_id,
                                     model=_first(attrs, MODEL_KEYS),
                                     tokens=_tokens(attrs), basis=basis, started=started)
                actor = node_id
            elif kind is ExecutionNodeKind.TOOL:
                actor = self._node(f"tool:{label}", ExecutionNodeKind.TOOL, label=label,
                                   attributes={"classified_by": basis})
                self._link_from_parent(actor, parent_id or agent_id,
                                       ExecutionNodeKind.TOOL, basis)
            else:
                actor = self._node(node_id, kind, label=label or name, started_at=started,
                                   attributes={"classified_by": basis, **_carry(attrs)})
                self._link_from_parent(actor, parent_id, kind, basis)
                if parent_id:
                    self._parent_of[actor] = parent_id

        self._alias[node_id] = actor
        self._attach_artifacts(actor, attrs)
        self._attach_people(actor, attrs)
        self._attach_verification(actor, attrs)

    def _resolve(self, node_id: str) -> str:
        """Follow a span id to the node it became."""
        return self._alias.get(node_id, node_id)

    def _link_from_parent(self, node_id: str, parent_id: str,
                          kind: ExecutionNodeKind, basis: str) -> None:
        """Record the parent relation without needing the parent to have arrived.

        Spans arrive in whatever order the exporter chose, so the edge is stored
        against the raw id and resolved at build time. Deciding anything here
        would make the graph depend on arrival order.
        """
        if not parent_id:
            return
        self._referenced_parents.add(parent_id)
        self._edge(_CHILD_EDGE.get(kind, ExecutionEdgeType.DELEGATED),
                   parent_id, node_id, basis=basis)

    def _add_model_call(self, parent_id: str, node_id: str, *, model: Any, tokens: int,
                        basis: str, started: Optional[int] = None) -> None:
        """Materialise a model call, or fold it into the parent's aggregate."""
        self._leaf_count += 1
        if self._leaf_count > self.max_leaf_nodes:
            bucket = self._aggregates.setdefault(
                parent_id, {"calls": 0, "tokens": 0, "models": set()})
            bucket["calls"] += 1
            bucket["tokens"] += tokens
            if model:
                bucket["models"].add(str(model))
            return
        self._node(node_id, ExecutionNodeKind.MODEL_CALL, label=str(model or "model call"),
                   started_at=started,
                   attributes={"classified_by": basis, "model": model, "tokens": tokens})
        if parent_id:
            self._referenced_parents.add(parent_id)
            self._edge(ExecutionEdgeType.CALLED, parent_id, node_id, basis=basis)

    def _agent_for(self, attrs: Mapping[str, Any], parent_id: str) -> str:
        """Infer the acting agent from attributes — never from a registration."""
        name = _first(attrs, AGENT_ID_KEYS)
        if not name:
            return ""
        node_id = f"agent:{name}"
        self._node(node_id, ExecutionNodeKind.AGENT, label=str(name),
                   attributes={"classified_by": "agent attribute on the span"})
        self._observed_sources.add(node_id)
        return node_id

    def _attach_artifacts(self, actor_id: str, attrs: Mapping[str, Any]) -> None:
        for key in ARTIFACT_PRODUCED_KEYS:
            if attrs.get(key):
                artifact = self._node(f"artifact:{attrs[key]}", ExecutionNodeKind.ARTIFACT,
                                      label=str(attrs[key]),
                                      attributes={"classified_by": f"attribute {key}"})
                self._edge(ExecutionEdgeType.PRODUCED, actor_id, artifact, basis=key)
        for key in ARTIFACT_CONSUMED_KEYS:
            if attrs.get(key):
                artifact = self._node(f"artifact:{attrs[key]}", ExecutionNodeKind.ARTIFACT,
                                      label=str(attrs[key]),
                                      attributes={"classified_by": f"attribute {key}"})
                self._edge(ExecutionEdgeType.CONSUMED, actor_id, artifact, basis=key)
        for key in ARTIFACT_MODIFIED_KEYS:
            if attrs.get(key):
                artifact = self._node(f"artifact:{attrs[key]}", ExecutionNodeKind.ARTIFACT,
                                      label=str(attrs[key]),
                                      attributes={"classified_by": f"attribute {key}"})
                self._edge(ExecutionEdgeType.MODIFIED, actor_id, artifact, basis=key)
        derived = attrs.get("derived_from")
        if derived and attrs.get(ARTIFACT_PRODUCED_KEYS[0]):
            source = self._node(f"artifact:{derived}", ExecutionNodeKind.ARTIFACT,
                                label=str(derived),
                                attributes={"classified_by": "attribute derived_from"})
            self._edge(ExecutionEdgeType.DERIVED_FROM,
                       f"artifact:{attrs[ARTIFACT_PRODUCED_KEYS[0]]}", source,
                       basis="derived_from")

    def _attach_people(self, node_id: str, attrs: Mapping[str, Any]) -> None:
        person = _first(attrs, HUMAN_KEYS)
        if not person:
            return
        human = self._node(f"human:{person}", ExecutionNodeKind.HUMAN, label=str(person),
                           attributes={"classified_by": "human/approval attribute"})
        self._edge(ExecutionEdgeType.AUTHORIZED, human, node_id, basis="approval attribute")

    def _attach_verification(self, node_id: str, attrs: Mapping[str, Any]) -> None:
        verifier = _first(attrs, VERIFIER_KEYS)
        result = attrs.get("verification.result")
        if not verifier:
            return
        verifier_id = self._node(f"verifier:{verifier}", ExecutionNodeKind.VERIFIER,
                                 label=str(verifier),
                                 attributes={"classified_by": "verifier attribute"})
        if result is None:
            return
        passed = str(result).strip().lower() in ("pass", "passed", "true", "ok", "success")
        self._edge(ExecutionEdgeType.VERIFIED if passed else ExecutionEdgeType.REJECTED,
                   verifier_id, node_id, basis="verification.result attribute")

    def _record_source(self, attrs: Mapping[str, Any]) -> None:
        for key in ("service.name", "service.instance.id"):
            if attrs.get(key):
                self._observed_sources.add(str(attrs[key]))

    def _record_sequence(self, attrs: Mapping[str, Any]) -> None:
        if attrs.get("sequence") is not None:
            self._sequences[str(attrs.get("stream_id") or "default")].add(
                as_int(attrs["sequence"]))

    # ── result ──────────────────────────────────────────────────────────────

    def _sequence_gaps(self) -> Tuple[Dict[str, Any], ...]:
        """Numbers a stream skipped. The one gap detectable without a manifest."""
        gaps: List[Dict[str, Any]] = []
        for stream, numbers in sorted(self._sequences.items()):
            if len(numbers) < 2:
                continue
            low, high = min(numbers), max(numbers)
            missing = sorted(set(range(low, high + 1)) - numbers)
            if missing:
                gaps.append({"stream_id": stream, "from": low, "to": high,
                             "missing_count": len(missing),
                             "missing_sample": missing[:10]})
        return tuple(gaps)

    def build(self) -> ExecutionGraph:
        edges = self._resolved_edges()
        edges = self._add_aggregates(edges)
        unobserved = self._materialise_unobserved(edges)
        edges = self._promote_agent_spawns(edges)

        if self._aggregates:
            self.note(
                f"model calls past the first {self.max_leaf_nodes} were folded into "
                "per-parent aggregates; the run's structure is intact and individual "
                "calls beyond the budget are counted rather than held")

        completeness = ExecutionCompleteness(
            spans_seen=self._spans_seen,
            nodes_materialised=len(self._nodes),
            nodes_aggregated=sum(b["calls"] for b in self._aggregates.values()),
            unobserved_parents=unobserved,
            sequence_gaps=self._sequence_gaps(),
            declared_sources=self._declared_sources,
            observed_sources=tuple(sorted(self._observed_sources)),
            notes=tuple(self._notes))
        return ExecutionGraph(self._nodes.values(), edges.values(),
                              completeness=completeness)

    def _resolved_edges(self) -> Dict[Tuple[str, str, str], ExecutionEdge]:
        """Rewrite every endpoint through the alias map, merging counts.

        Two raw span ids can name the same agent; their edges are one edge with
        the counts added, not two edges that look like twice the work.
        """
        resolved: Dict[Tuple[str, str, str], ExecutionEdge] = {}
        for edge in self._edges.values():
            from_id, to_id = self._resolve(edge.from_id), self._resolve(edge.to_id)
            if from_id == to_id:
                continue   # a span that aliases onto its own parent is not a relation
            key = (edge.edge_type.value, from_id, to_id)
            existing = resolved.get(key)
            count = edge.count + (existing.count if existing else 0)
            resolved[key] = ExecutionEdge(edge.edge_type, from_id, to_id, count=count,
                                          basis=edge.basis)
        return resolved

    def _add_aggregates(self, edges: Dict[Tuple[str, str, str], ExecutionEdge]
                        ) -> Dict[Tuple[str, str, str], ExecutionEdge]:
        merged: Dict[str, Dict[str, Any]] = {}
        for raw_parent, bucket in self._aggregates.items():
            target = merged.setdefault(self._resolve(raw_parent),
                                       {"calls": 0, "tokens": 0, "models": set()})
            target["calls"] += bucket["calls"]
            target["tokens"] += bucket["tokens"]
            target["models"] |= bucket["models"]

        for parent_id, bucket in sorted(merged.items()):
            node_id = f"{parent_id}#model_calls"
            self._nodes[node_id] = ExecutionNode(
                node_id=node_id, kind=ExecutionNodeKind.MODEL_CALL,
                label=f"{bucket['calls']} model call(s)",
                aggregate_of=bucket["calls"],
                attributes={"classified_by": "aggregated past the leaf budget",
                            "call_count": bucket["calls"], "total_tokens": bucket["tokens"],
                            "models": sorted(bucket["models"])})
            edges[(ExecutionEdgeType.CALLED.value, parent_id, node_id)] = ExecutionEdge(
                ExecutionEdgeType.CALLED, parent_id, node_id, count=bucket["calls"],
                basis="aggregated model calls")
        return edges

    def _materialise_unobserved(self, edges: Mapping[Tuple[str, str, str], ExecutionEdge]
                                ) -> Tuple[str, ...]:
        """Give every unresolved reference a node of its own.

        An explicit gap beats a silently reparented orphan, which would make the
        run look shallower than it was.
        """
        unresolved: Set[str] = set()
        for edge in edges.values():
            for endpoint in (edge.from_id, edge.to_id):
                if endpoint not in self._nodes:
                    unresolved.add(endpoint)
        for node_id in sorted(unresolved):
            self._node(node_id, ExecutionNodeKind.UNOBSERVED,
                       label="referenced but never observed",
                       attributes={"classified_by": "referenced by an observed span"})
        return tuple(sorted(unresolved & {self._resolve(p) for p in self._referenced_parents}
                            | (unresolved & self._referenced_parents)))

    def _promote_agent_spawns(self, edges: Dict[Tuple[str, str, str], ExecutionEdge]
                              ) -> Dict[Tuple[str, str, str], ExecutionEdge]:
        """An agent under an agent was spawned by it, not delegated a task."""
        promoted: Dict[Tuple[str, str, str], ExecutionEdge] = {}
        for key, edge in edges.items():
            if (edge.edge_type is ExecutionEdgeType.DELEGATED
                    and self._kind_of(edge.from_id) is ExecutionNodeKind.AGENT
                    and self._kind_of(edge.to_id) is ExecutionNodeKind.AGENT):
                edge = ExecutionEdge(ExecutionEdgeType.SPAWNED, edge.from_id, edge.to_id,
                                     count=edge.count, basis=edge.basis)
                key = edge.key
            promoted[key] = edge
        return promoted

    def _kind_of(self, node_id: str) -> Optional[ExecutionNodeKind]:
        node = self._nodes.get(node_id)
        return node.kind if node else None


# ── classification helpers ──────────────────────────────────────────────────

def _first(attrs: Mapping[str, Any], keys: Sequence[str]) -> Optional[Any]:
    for key in keys:
        value = attrs.get(key)
        if value not in (None, ""):
            return value
    return None


def _tokens(attrs: Mapping[str, Any]) -> int:
    return sum(as_int(attrs.get(key)) for key in TOKEN_KEYS)


def _carry(attrs: Mapping[str, Any]) -> Dict[str, Any]:
    """The few attributes worth keeping on a node, so it stays small at scale."""
    keep = ("gen_ai.operation.name", "service.name", "sequence", "stream_id")
    return {k: attrs[k] for k in keep if k in attrs}


def _classify(name: str, attrs: Mapping[str, Any]) -> Tuple[ExecutionNodeKind, str, str]:
    """Decide what a span is, and record why.

    Deliberately conservative: anything unrecognised becomes a TASK rather than
    being guessed into a more specific kind. A wrong AGENT node would distort
    every independence and delegation question asked of the graph afterwards.
    """
    hint = attrs.get("_kind_hint")
    if hint:
        try:
            return (ExecutionNodeKind(str(hint).upper()), str(name or hint),
                    "kind declared on the record")
        except ValueError:
            pass

    operation = str(attrs.get("gen_ai.operation.name") or "").strip().lower()
    lowered = name.strip().lower()

    if operation in MODEL_CALL_OPERATIONS or any(k.startswith("gen_ai.usage.") for k in attrs):
        return ExecutionNodeKind.MODEL_CALL, str(_first(attrs, MODEL_KEYS) or name), \
            f"gen_ai.operation.name={operation or 'inferred from usage attributes'}"
    if operation in TOOL_OPERATIONS or _first(attrs, TOOL_NAME_KEYS):
        return (ExecutionNodeKind.TOOL, str(_first(attrs, TOOL_NAME_KEYS) or name),
                "tool name attribute" if _first(attrs, TOOL_NAME_KEYS)
                else f"gen_ai.operation.name={operation}")
    if operation in AGENT_OPERATIONS or _first(attrs, AGENT_ID_KEYS):
        return (ExecutionNodeKind.AGENT, str(_first(attrs, AGENT_ID_KEYS) or name),
                "agent attribute or operation")
    if _first(attrs, VERIFIER_KEYS):
        return ExecutionNodeKind.VERIFIER, str(_first(attrs, VERIFIER_KEYS)), "verifier attribute"
    if _first(attrs, ACTION_KEYS):
        return ExecutionNodeKind.ACTION, str(_first(attrs, ACTION_KEYS)), "action attribute"
    if _first(attrs, HUMAN_KEYS) and "approval" in lowered:
        return ExecutionNodeKind.HUMAN, str(_first(attrs, HUMAN_KEYS)), "human approval span"
    if _first(attrs, EXTERNAL_KEYS):
        return (ExecutionNodeKind.EXTERNAL_SYSTEM, str(_first(attrs, EXTERNAL_KEYS)),
                "http/db/peer attribute")
    return ExecutionNodeKind.TASK, name, "no classifying attribute; recorded as a task"
