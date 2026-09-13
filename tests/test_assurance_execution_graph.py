"""ExecutionGraph — what the system did, reconstructed from telemetry.

The properties under test: nothing has to register, completeness is never
claimed, missing telemetry stays visible, and the shape of a ten-thousand-agent
run survives while its four million leaves collapse.
"""

import json

import pytest

from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
from release_gate.assurance.execution_graph import (
    CompletenessStatus,
    ExecutionEdgeType,
    ExecutionGraph,
    ExecutionGraphBuilder,
    ExecutionNodeKind,
)
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.subject import AssuranceSubject, SubjectType


def _span(span_id, parent_id="", name="span", **attrs):
    return {"spanId": span_id, "parentSpanId": parent_id, "name": name,
            "startTimeUnixNano": "0",
            "attributes": [{"key": k, "value": {"stringValue": str(v)}}
                           for k, v in attrs.items()]}


def _otlp(*spans, resource=None):
    return {"resourceSpans": [{
        "resource": {"attributes": [{"key": k, "value": {"stringValue": str(v)}}
                                    for k, v in (resource or {}).items()]},
        "scopeSpans": [{"spans": list(spans)}]}]}


def _case(*records, present=True):
    b = AssuranceCaseBuilder(
        case_type=CaseType.AUTONOMOUS_ACTION, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("result", SubjectType.GENERAL_RESULT, "accept"))
    if present and not records:
        b.declare_present("executions")
    for record in records:
        b.add("executions", record)
    return b.build()


# ── taxonomies ──────────────────────────────────────────────────────────────

def test_all_contract_node_kinds_exist():
    assert {k.value for k in ExecutionNodeKind} >= {
        "AGENT", "TASK", "TOOL", "ACTION", "MODEL_CALL", "ARTIFACT",
        "EXTERNAL_SYSTEM", "HUMAN", "VERIFIER"}


def test_all_contract_edge_types_exist():
    assert {e.value for e in ExecutionEdgeType} == {
        "SPAWNED", "DELEGATED", "CALLED", "PRODUCED", "CONSUMED", "MODIFIED",
        "VERIFIED", "REJECTED", "AUTHORIZED", "DERIVED_FROM"}


# ── construction from telemetry, without registration ───────────────────────

def test_agents_are_inferred_from_telemetry_with_no_registration():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="invoke_agent", **{"gen_ai.agent.id": "planner"}),
        _span("s2", "s1", name="invoke_agent", **{"gen_ai.agent.id": "researcher"})))
    assert {a.label for a in graph.agents()} == {"planner", "researcher"}
    assert graph.fan_out("agent:planner") == 1


def test_one_agent_named_by_many_spans_is_one_agent():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="invoke_agent", **{"gen_ai.agent.id": "planner"}),
        _span("s2", "s1", name="chat", **{"gen_ai.operation.name": "chat",
                                          "gen_ai.agent.id": "planner"}),
        _span("s3", "s1", name="chat", **{"gen_ai.operation.name": "chat",
                                          "gen_ai.agent.id": "planner"})))
    assert len(graph.agents()) == 1


def test_every_node_records_why_it_was_classified_that_way():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="chat", **{"gen_ai.operation.name": "chat",
                                    "gen_ai.request.model": "m-1"})))
    for node in graph.nodes:
        assert node.attributes.get("classified_by")


def test_an_unrecognised_span_becomes_a_task_not_a_guess():
    # A wrong AGENT node would distort every delegation and independence
    # question asked of the graph afterwards.
    graph = ExecutionGraph.from_otlp(_otlp(_span("s1", name="do_something_opaque")))
    node = graph.nodes_of(ExecutionNodeKind.TASK)[0]
    assert "no classifying attribute" in node.attributes["classified_by"]


def test_tools_external_systems_and_models_are_told_apart():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="agent", **{"gen_ai.agent.id": "a"}),
        _span("s2", "s1", name="execute_tool", **{"gen_ai.tool.name": "search_docs"}),
        _span("s3", "s1", name="chat", **{"gen_ai.operation.name": "chat",
                                          "gen_ai.request.model": "m-1"}),
        _span("s4", "s1", name="GET", **{"http.url": "https://api.example.com/v1"})))
    assert [t.label for t in graph.tools()] == ["search_docs"]
    assert len(graph.nodes_of(ExecutionNodeKind.MODEL_CALL)) == 1
    assert len(graph.nodes_of(ExecutionNodeKind.EXTERNAL_SYSTEM)) == 1


def test_repeated_tool_calls_become_one_node_and_a_count():
    # The fact worth keeping is that it happened N times, not N nodes.
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="agent", **{"gen_ai.agent.id": "a"}),
        *[_span(f"t{i}", "s1", name="execute_tool", **{"gen_ai.tool.name": "search"})
          for i in range(12)]))
    assert len(graph.tools()) == 1
    called = graph.out_edges("agent:a", ExecutionEdgeType.CALLED)
    assert sum(e.count for e in called) == 12


def test_the_native_trace_format_is_the_linear_degenerate_case():
    graph = ExecutionGraph.from_native_trace({"trace_id": "t1", "steps": [
        {"type": "llm_call", "model": "gpt-4.1", "tokens": 800},
        {"type": "tool_call", "tool": "search_docs"},
        {"type": "retry"}]})
    assert len(graph.agents()) == 1
    assert len(graph.tools()) == 1
    assert len(graph.nodes_of(ExecutionNodeKind.MODEL_CALL)) == 1
    assert len(graph.nodes_of(ExecutionNodeKind.TASK)) == 1   # the retry


# ── artifacts, people, verifiers ────────────────────────────────────────────

def test_artifacts_are_produced_consumed_and_modified():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="agent", **{"gen_ai.agent.id": "a",
                                     "artifact.digest": "sha256:out",
                                     "input.digest": "sha256:in",
                                     "artifact.modified": "sha256:table"})))
    assert graph.produced_by("artifact:sha256:out") == ("agent:a",)
    assert graph.consumed_by("artifact:sha256:in") == ("agent:a",)
    assert any(e.edge_type is ExecutionEdgeType.MODIFIED for e in graph.edges)


def test_artifact_lineage_is_recorded():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="agent", **{"gen_ai.agent.id": "a",
                                     "artifact.digest": "sha256:v2",
                                     "derived_from": "sha256:v1"})))
    derived = [e for e in graph.edges if e.edge_type is ExecutionEdgeType.DERIVED_FROM]
    assert (derived[0].from_id, derived[0].to_id) == ("artifact:sha256:v2", "artifact:sha256:v1")


def test_a_human_approval_becomes_an_authorisation_edge():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="apply", **{"action.name": "apply-migration",
                                     "approval.by": "alice"})))
    action = graph.nodes_of(ExecutionNodeKind.ACTION)[0]
    assert graph.authorised_by(action.node_id) == ("human:alice",)
    assert graph.actions_without_recorded_authorisation() == ()


def test_an_unauthorised_action_is_reported_as_a_fact_not_a_finding():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="send", **{"action.name": "send-emails"})))
    assert graph.actions_without_recorded_authorisation() == ("s1",)


def test_verifiers_record_both_outcomes():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="check", **{"verifier.id": "lean", "verification.result": "pass"}),
        _span("s2", name="check", **{"verifier.id": "lean", "verification.result": "fail"})))
    outcomes = graph.verification_outcomes()
    assert outcomes["verified"] and outcomes["rejected"]


# ── completeness is never claimed (Invariant 13) ────────────────────────────

def test_there_is_no_complete_status_to_claim():
    assert "COMPLETE" not in {s.value for s in CompletenessStatus}


def test_nothing_missing_still_reports_unknown():
    # Absence of observed gaps is not evidence of completeness.
    graph = ExecutionGraph.from_otlp(_otlp(_span("s1", name="agent",
                                                 **{"gen_ai.agent.id": "a"})))
    assert graph.completeness.status is CompletenessStatus.UNKNOWN
    assert "not the same as nothing being missing" in graph.completeness.to_dict()["note"]


def test_a_referenced_parent_that_never_arrived_is_visible():
    graph = ExecutionGraph.from_otlp(_otlp(_span("child", "parent_never_sent", name="chat",
                                                 **{"gen_ai.operation.name": "chat"})))
    assert graph.completeness.status is CompletenessStatus.GAPS_DETECTED
    assert "parent_never_sent" in graph.completeness.unobserved_parents
    assert graph.node("parent_never_sent").kind is ExecutionNodeKind.UNOBSERVED


def test_an_orphan_is_never_silently_reparented():
    # Reparenting would make the run look shallower than it was.
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("root", name="agent", **{"gen_ai.agent.id": "a"}),
        _span("child", "gone", name="agent", **{"gen_ai.agent.id": "b"})))
    assert graph.in_edges("agent:b")[0].from_id == "gone"


def test_sequence_gaps_are_detected():
    spans = [_span(f"s{i}", name="task", sequence=i, stream_id="run-1")
             for i in (1, 2, 3, 7, 8)]
    graph = ExecutionGraph.from_otlp(_otlp(*spans))
    gaps = graph.completeness.sequence_gaps
    assert gaps and gaps[0]["missing_count"] == 3
    assert graph.completeness.status is CompletenessStatus.GAPS_DETECTED


def test_a_source_manifest_turns_nothing_looks_missing_into_something_checkable():
    builder = ExecutionGraphBuilder(declared_sources=("agent:a", "agent:b", "agent:c"))
    builder.add_otlp(_otlp(_span("s1", name="agent", **{"gen_ai.agent.id": "a"}),
                           _span("s2", name="agent", **{"gen_ai.agent.id": "b"})))
    graph = builder.build()
    assert graph.completeness.missing_sources == ("agent:c",)
    assert graph.completeness.status is CompletenessStatus.GAPS_DETECTED


def test_a_matching_declaration_is_still_only_a_declaration():
    builder = ExecutionGraphBuilder(declared_sources=("agent:a",))
    builder.add_otlp(_otlp(_span("s1", name="agent", **{"gen_ai.agent.id": "a"})))
    graph = builder.build()
    assert graph.completeness.status is CompletenessStatus.MATCHES_DECLARATION
    assert "not proof of completeness" in graph.completeness.to_dict()["note"]


# ── scale: keep the skeleton, collapse the leaves ───────────────────────────

def test_a_large_run_keeps_its_shape_and_counts_its_leaves():
    spans = [_span("root", name="agent", **{"gen_ai.agent.id": "orchestrator"})]
    for a in range(50):
        spans.append(_span(f"ag{a}", "root", name="invoke_agent",
                           **{"gen_ai.agent.id": f"worker-{a}"}))
        for c in range(40):
            spans.append(_span(f"c{a}_{c}", f"ag{a}", name="chat",
                               **{"gen_ai.operation.name": "chat",
                                  "gen_ai.request.model": "m-1",
                                  "gen_ai.usage.input_tokens": "100"}))
    graph = ExecutionGraph.from_otlp(_otlp(*spans), max_leaf_nodes=100)
    summary = graph.summary()

    assert summary["agents"] == 51                       # structure intact
    assert summary["model_calls_represented"] == 2000    # every call accounted for
    assert summary["completeness"]["nodes_aggregated"] == 1900
    assert summary["nodes"] < 400                        # leaves collapsed
    aggregates = [n for n in graph.nodes_of(ExecutionNodeKind.MODEL_CALL) if n.is_aggregate]
    assert aggregates and aggregates[0].attributes["total_tokens"] > 0


def test_aggregation_says_that_it_happened():
    spans = [_span("root", name="agent", **{"gen_ai.agent.id": "a"})]
    spans += [_span(f"c{i}", "root", name="chat", **{"gen_ai.operation.name": "chat"})
              for i in range(20)]
    graph = ExecutionGraph.from_otlp(_otlp(*spans), max_leaf_nodes=5)
    notes = " ".join(graph.completeness.notes)
    assert "folded into" in notes and "counted rather than held" in notes


def test_delegation_depth_is_measured_not_estimated():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("a", name="agent", **{"gen_ai.agent.id": "l0"}),
        _span("b", "a", name="agent", **{"gen_ai.agent.id": "l1"}),
        _span("c", "b", name="agent", **{"gen_ai.agent.id": "l2"}),
        _span("d", "c", name="agent", **{"gen_ai.agent.id": "l3"})))
    assert graph.delegation_depth() == 3


def test_a_deep_delegation_chain_does_not_exhaust_the_stack():
    spans = [_span("a0", name="agent", **{"gen_ai.agent.id": "a0"})]
    spans += [_span(f"a{i}", f"a{i-1}", name="agent", **{"gen_ai.agent.id": f"a{i}"})
              for i in range(1, 2000)]
    graph = ExecutionGraph.from_otlp(_otlp(*spans))
    assert graph.delegation_depth() == 1999
    assert len(graph.ancestors("agent:a1999")) == 1999


# ── the graph is optional (Invariant 14) ────────────────────────────────────

def test_a_case_with_no_execution_telemetry_has_no_graph():
    # None, not an empty graph: a case with no telemetry has not been shown to
    # have done nothing, and an empty graph would read exactly that way.
    b = AssuranceCaseBuilder(
        case_type=CaseType.DATA_CHANGE, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("x", SubjectType.DATA_CHANGE, "apply"))
    assert ExecutionGraph.from_case(b.build()) is None


def test_a_case_that_looked_and_found_nothing_gets_an_empty_graph():
    graph = ExecutionGraph.from_case(_case())
    assert graph is not None
    assert len(graph) == 0


def test_a_case_graph_says_how_much_of_the_collection_it_read():
    b = AssuranceCaseBuilder(
        case_type=CaseType.AUTONOMOUS_ACTION, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("x", SubjectType.GENERAL_RESULT, "accept"))
    for i in range(100):
        b.add("executions", SimpleRecord("execution", f"ex_{i}",
                                         {"node_kind": "TASK", "label": f"step {i}"}),
              materialise=(i < 4))
    graph = ExecutionGraph.from_case(b.build())
    notes = " ".join(graph.completeness.notes)
    assert "4 of 100" in notes
    assert "96 execution record(s) were counted but not materialised" in notes


def test_a_flat_execution_record_can_declare_its_own_kind():
    record = SimpleRecord("execution", "ex_1", {"node_kind": "VERIFIER", "label": "lean"})
    graph = ExecutionGraph.from_case(_case(record))
    assert len(graph.nodes_of(ExecutionNodeKind.VERIFIER)) == 1


# ── determinism and output ──────────────────────────────────────────────────

def test_the_digest_does_not_depend_on_span_order():
    spans = [_span("s1", name="agent", **{"gen_ai.agent.id": "a"}),
             _span("s2", "s1", name="execute_tool", **{"gen_ai.tool.name": "search"})]
    assert (ExecutionGraph.from_otlp(_otlp(*spans)).digest()
            == ExecutionGraph.from_otlp(_otlp(*reversed(spans))).digest())


def test_the_graph_serialises_whole():
    graph = ExecutionGraph.from_otlp(_otlp(_span("s1", name="agent",
                                                 **{"gen_ai.agent.id": "a"})))
    payload = json.loads(json.dumps(graph.to_dict()))
    assert payload["schema_version"] == 1
    assert payload["digest"] == graph.digest()
    assert payload["completeness"]["status"] == "UNKNOWN"


def test_the_summary_is_readable_without_the_nodes():
    graph = ExecutionGraph.from_otlp(_otlp(
        _span("s1", name="agent", **{"gen_ai.agent.id": "a"}),
        _span("s2", "s1", name="execute_tool", **{"gen_ai.tool.name": "search"})))
    summary = graph.summary()
    assert summary["by_node_kind"]["AGENT"] == 1
    assert summary["by_edge_type"]["CALLED"] == 1
    # The header carries counts, never the node list itself.
    assert "node_list" not in summary["completeness"]
    assert all(not isinstance(v, dict) for v in summary["completeness"].values()
               if not isinstance(v, list))


def test_shuffled_arrival_produces_the_same_graph():
    # Exporters emit spans in whatever order they like, and a parent often
    # arrives after its children. Resolution happens once, at the end.
    import random

    spans = [_span("root", name="agent", **{"gen_ai.agent.id": "orchestrator"})]
    for a in range(20):
        spans.append(_span(f"ag{a}", "root", name="invoke_agent",
                           **{"gen_ai.agent.id": f"worker-{a}"}))
        spans.append(_span(f"t{a}", f"ag{a}", name="execute_tool",
                           **{"gen_ai.tool.name": "search"}))
    ordered = ExecutionGraph.from_otlp(_otlp(*spans))
    random.Random(0).shuffle(spans)
    shuffled = ExecutionGraph.from_otlp(_otlp(*spans))
    assert ordered.digest() == shuffled.digest()
    assert ordered.completeness.unobserved_parents == ()
    assert shuffled.completeness.unobserved_parents == ()
