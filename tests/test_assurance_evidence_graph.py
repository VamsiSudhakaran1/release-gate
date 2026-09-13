"""EvidenceGraph — evidentiary dependency, kept separate from logical dependency.

The properties under test: the graph never drops what was superseded or
contradicted, a reference it cannot resolve becomes visible rather than silent,
and the five-level trace from verdict to source actually arrives at a producer.
"""

import json

import pytest

from release_gate.assurance.case import (AssuranceCaseBuilder, CaseType, CaseVerdict,
                                         Decision)
from release_gate.assurance.evidence import (EvidenceRecord, EvidenceType, Producer,
                                             ProducerKind, TrustStatus, VerificationMethod)
from release_gate.assurance.evidence_graph import (
    AnomalyKind,
    EdgeType,
    EvidenceGraph,
    EvidenceGraphBuilder,
    GraphError,
    NodeKind,
)
from release_gate.assurance.methodologies import PRODUCTION_DATABASE_CHANGE_V1
from release_gate.assurance.methodology import assess
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.subject import AssuranceSubject, SubjectType

AGENT = Producer("agent://planner/7", ProducerKind.AGENT, identity_basis="none")
CI = Producer("ci://github/acme/run/8821", ProducerKind.TOOL, identity_basis="github-oidc")
PROVER = Producer("prover://lean/1", ProducerKind.TOOL, identity_basis="in-process")


def _subject():
    return AssuranceSubject.from_text("CREATE INDEX CONCURRENTLY idx ON orders(id);",
                                      SubjectType.DATA_CHANGE, "apply this migration to prod-eu")


def _declared(producer=AGENT, **kw):
    kw.setdefault("evidence_type", EvidenceType.TOOL_RESULT)
    kw.setdefault("source", "agent-log")
    return EvidenceRecord.declared(producer=producer, **kw)


def _verified(subject_digest, producer=CI, **kw):
    kw.setdefault("evidence_type", EvidenceType.SIMULATION_RESULT)
    kw.setdefault("source", "github-actions")
    kw.setdefault("method", VerificationMethod.SIMULATION)
    kw.setdefault("coverage_note", "schema only")
    return EvidenceRecord.verification(producer=producer, applies_to_digest=subject_digest, **kw)


def _case(*records, subject=None, collection="evidence", **kw):
    subject = subject or _subject()
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=subject, **kw)
    for record in records:
        b.add(collection, record)
    return b.build()


def _graph(*records, subject=None, **kw):
    return EvidenceGraph.from_case(_case(*records, subject=subject, **kw))


# ── the taxonomies ──────────────────────────────────────────────────────────

def test_all_contract_edge_types_exist():
    assert {e.value for e in EdgeType} >= {
        "SUPPORTS", "CONTRADICTS", "DERIVED_FROM", "VERIFIES", "INVALIDATES",
        "REPLICATES", "ATTESTS", "SUPERSEDES", "DEPENDS_ON"}


def test_claims_are_references_not_modelled_objects():
    # The boundary with the ClaimGraph: this graph knows the id and nothing else.
    graph = _graph(_declared(supports_claims=("cl_887",)))
    claim = graph.nodes_of(NodeKind.CLAIM)[0]
    assert claim.node_id == "cl_887"
    assert claim.attributes == {}
    # No logical structure between claims lives here.
    assert not graph.out_edges("cl_887")


# ── edges derived from the records themselves ───────────────────────────────

def test_support_and_contradiction_become_edges():
    record = _declared(supports_claims=("cl_1",), contradicts_claims=("cl_2",))
    graph = _graph(record)
    assert graph.evidence_for("cl_1")["supports"] == (record.evidence_id,)
    assert graph.evidence_for("cl_2")["contradicts"] == (record.evidence_id,)


def test_evidence_for_always_returns_both_directions():
    # A helper that answered only "what supports this" would make the
    # refutation easy to not ask about.
    graph = _graph(_declared(supports_claims=("cl_1",)))
    assert set(graph.evidence_for("cl_1")) == {"supports", "contradicts", "verifies"}


def test_parent_evidence_becomes_a_derivation_edge():
    parent = _declared(content={"n": 1})
    child = _declared(content={"n": 2}, parent_evidence=(parent.evidence_id,))
    graph = _graph(parent, child)
    assert graph.lineage(child.evidence_id) == (parent.evidence_id,)
    assert graph.descendants(parent.evidence_id) == (child.evidence_id,)


def test_every_record_reaches_a_named_source():
    record = _declared()
    graph = _graph(record)
    sources = graph.sources_of(record.evidence_id)
    assert len(sources) == 1
    assert graph.node(sources[0]).label == "agent://planner/7"


def test_a_verification_of_the_exact_subject_points_at_the_action():
    subject = _subject()
    record = _verified(subject.digest)
    graph = _graph(record, subject=subject)
    action = graph.nodes_of(NodeKind.ACTION)[0]
    assert record.evidence_id in graph.evidence_for(action.node_id)["verifies"]


def test_a_verification_of_a_different_revision_does_not():
    # This is what applies_to_digest buys: a proof about one artifact is not
    # evidence about another, and the graph shows that as a missing edge.
    subject = _subject()
    other = AssuranceSubject.from_text("DROP TABLE orders;", SubjectType.DATA_CHANGE, "apply")
    graph = _graph(_verified(other.digest), subject=subject)
    action = graph.nodes_of(NodeKind.ACTION)[0]
    assert graph.evidence_for(action.node_id)["verifies"] == ()


def test_declared_link_metadata_becomes_typed_edges():
    original = _declared(content={"run": 1})
    replication = _declared(producer=PROVER, content={"run": 2},
                            metadata={"replicates": [original.evidence_id]})
    graph = _graph(original, replication)
    assert original.evidence_id in graph.replication_groups(replication.evidence_id)
    kinds = {e.edge_type for e in graph.out_edges(replication.evidence_id)}
    assert EdgeType.REPLICATES in kinds


def test_a_replication_claim_is_not_an_independence_finding():
    # Whether replications are genuinely independent is the analyser's question.
    original = _declared(content={"run": 1})
    clone = _declared(content={"run": 2}, metadata={"replicates": [original.evidence_id]})
    graph = _graph(original, clone)
    sources = {graph.node(s).attributes["independence_group"]
               for r in (original, clone) for s in graph.sources_of(r.evidence_id)}
    assert len(sources) == 1  # same producer: one group, whatever it claims


# ── nothing is removed (Invariant 7) ────────────────────────────────────────

def test_superseded_evidence_stays_in_the_graph_and_is_marked():
    old = _declared(content={"estimate": 100})
    new = _declared(content={"estimate": 250}, metadata={"supersedes": [old.evidence_id]})
    graph = _graph(old, new)
    assert old.evidence_id in graph  # still present
    assert graph.is_current(old.evidence_id) is False
    assert graph.is_current(new.evidence_id) is True


def test_invalidated_evidence_stays_too():
    stale = _declared(content={"checked": "v1"})
    drift = _declared(producer=Producer.release_gate("drift"),
                      metadata={"invalidates": [stale.evidence_id]})
    graph = _graph(stale, drift)
    assert stale.evidence_id in graph
    assert stale.evidence_id in graph.invalidated()


def test_a_contradiction_between_two_records_is_recorded_not_resolved():
    a = _declared(content={"cost": 100})
    b = _declared(producer=PROVER, content={"cost": 400},
                  metadata={"contradicts_evidence": [a.evidence_id]})
    graph = _graph(a, b)
    assert (b.evidence_id, a.evidence_id) in graph.contradiction_pairs()


# ── references it cannot resolve ────────────────────────────────────────────

def test_a_dangling_reference_becomes_a_visible_node():
    # A broken lineage chain is a finding, not a tidy-up.
    orphan = _declared(parent_evidence=("ev_never_supplied",))
    graph = _graph(orphan)
    missing = graph.missing_nodes
    assert [n.node_id for n in missing] == ["ev_never_supplied"]
    assert any(a.kind is AnomalyKind.DANGLING_REFERENCE for a in graph.anomalies)


def test_a_reference_resolved_by_a_later_record_is_not_dangling():
    # References are resolved once at the end, so arrival order cannot matter.
    parent = _declared(content={"n": 1})
    child = _declared(content={"n": 2}, parent_evidence=(parent.evidence_id,))
    graph = _graph(child, parent)
    assert graph.missing_nodes == ()
    assert graph.anomalies == () or all(a.kind is not AnomalyKind.DANGLING_REFERENCE
                                        for a in graph.anomalies)


def test_self_parenting_is_recorded_not_followed():
    builder = EvidenceGraphBuilder()
    record = _declared()
    builder.add_record(record)
    builder.link(EdgeType.DERIVED_FROM, record.evidence_id, record.evidence_id)
    graph = builder.build()
    assert any(a.kind is AnomalyKind.CYCLE for a in graph.anomalies)


def test_a_derivation_cycle_is_reported_rather_than_looping_forever():
    a, b, c = _declared(content={"i": 1}), _declared(content={"i": 2}), _declared(content={"i": 3})
    builder = EvidenceGraphBuilder()
    for record in (a, b, c):
        builder.add_record(record)
    builder.link(EdgeType.DERIVED_FROM, a.evidence_id, b.evidence_id)
    builder.link(EdgeType.DERIVED_FROM, b.evidence_id, c.evidence_id)
    builder.link(EdgeType.DERIVED_FROM, c.evidence_id, a.evidence_id)
    graph = builder.build()
    cycles = [x for x in graph.anomalies if x.kind is AnomalyKind.CYCLE]
    assert len(cycles) == 1
    assert len(graph.lineage(a.evidence_id)) == 3  # terminates


def test_a_deep_chain_does_not_exhaust_the_stack():
    builder = EvidenceGraphBuilder()
    previous = None
    for i in range(3000):
        record = _declared(content={"step": i},
                           parent_evidence=(previous,) if previous else ())
        builder.add_record(record)
        previous = record.evidence_id
    graph = builder.build()
    assert len(graph.lineage(previous)) == 2999


def test_evidence_bearing_on_nothing_is_flagged():
    graph = _graph(_declared())
    assert any(a.kind is AnomalyKind.ORPHAN_EVIDENCE for a in graph.anomalies)


# ── the trace: verdict -> condition -> claim/action -> evidence -> source ────

def _traceable_case():
    subject = _subject()
    claim = _declared(evidence_type=EvidenceType.OTHER,
                      content={"statement": "backward compatible"},
                      supports_claims=("cl_compat",))
    dryrun = _verified(subject.digest, supports_claims=("cl_compat",),
                       parent_evidence=(claim.evidence_id,))
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=subject,
                             methodology=PRODUCTION_DATABASE_CHANGE_V1.ref())
    b.add("evidence", claim)
    b.add("verification", dryrun)
    b.add("coverage", SimpleRecord("coverage", "cov_1", {"dimension": "overall"}))
    case = b.build().seal()
    verdict = CaseVerdict(decision=Decision.HOLD, fired_rules=["RG-DECIDE-014"],
                          reasons=["No rollback path."])
    return case.render_verdict(verdict), verdict, claim, dryrun


def test_the_trace_reaches_a_named_source():
    case, verdict, _claim, dryrun = _traceable_case()
    graph = EvidenceGraph.from_case(case)
    explanation = graph.explain_verdict(verdict, assess(case, PRODUCTION_DATABASE_CHANGE_V1))

    assert explanation["verdict"] == "HOLD"
    assert explanation["unresolved_count"] >= 1
    condition = explanation["unresolved"][0]
    assert condition["condition"] and condition["remedy"]
    concern = condition["concerns"][0]
    assert concern["kind"] == "ACTION"
    evidence = concern["evidence"][0]
    assert evidence["evidence_id"] == dryrun.evidence_id
    assert evidence["sources"][0]["identity_basis"] == "github-oidc"
    assert evidence["sources"][0]["trust_status"] == TrustStatus.NOT_ESTABLISHED.value


def test_the_trace_renders_as_readable_text():
    case, verdict, _c, _d = _traceable_case()
    graph = EvidenceGraph.from_case(case)
    rendered = graph.render_trace(
        graph.explain_verdict(verdict, assess(case, PRODUCTION_DATABASE_CHANGE_V1)))
    for level in ("VERDICT", "CONDITION", "ACTION", "EVIDENCE", "SOURCE"):
        assert level in rendered


def test_the_trace_is_json_serialisable_for_a_machine():
    case, verdict, _c, _d = _traceable_case()
    graph = EvidenceGraph.from_case(case)
    payload = graph.explain_verdict(verdict, assess(case, PRODUCTION_DATABASE_CHANGE_V1))
    assert json.loads(json.dumps(payload))["verdict"] == "HOLD"


def test_a_condition_with_no_evidence_says_so_rather_than_going_quiet():
    case, verdict, _c, _d = _traceable_case()
    graph = EvidenceGraph.from_case(case)
    explanation = graph.explain_verdict(verdict, assess(case, PRODUCTION_DATABASE_CHANGE_V1))
    # Force the empty branch by tracing a claim nothing bears on.
    empty = graph.trace_target("cl_nothing")
    assert empty["evidence"] == []
    assert "(no evidence on record bears on this)" in graph.render_trace(
        {**explanation, "unresolved": [{"condition": "x", "concerns": [empty]}]})


def test_hidden_evidence_is_counted_not_dropped():
    subject = _subject()
    builder = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                                   requested_decision="d", subject=subject)
    for i in range(12):
        builder.add("verification", _verified(subject.digest, content={"run": i}))
    graph = EvidenceGraph.from_case(builder.build())
    action = graph.nodes_of(NodeKind.ACTION)[0]
    traced = graph.trace_target(action.node_id, max_evidence=3)
    assert traced["evidence_count"] == 12
    assert traced["evidence_shown"] == 3


def test_a_superseded_record_is_marked_in_the_trace():
    subject = _subject()
    old = _verified(subject.digest, content={"run": 1})
    new = _verified(subject.digest, content={"run": 2},
                    metadata={"supersedes": [old.evidence_id]})
    graph = _graph(old, new, subject=subject, collection="verification")
    action = graph.nodes_of(NodeKind.ACTION)[0]
    traced = graph.trace_target(action.node_id)
    by_id = {e["evidence_id"]: e for e in traced["evidence"]}
    assert by_id[old.evidence_id]["current"] is False
    assert by_id[old.evidence_id]["superseded_by"] == (new.evidence_id,)


def test_a_verdict_with_nothing_unresolved_traces_cleanly():
    graph = _graph(_declared(supports_claims=("cl_1",)))
    explanation = graph.explain_verdict(
        CaseVerdict(decision=Decision.PROMOTE, fired_rules=["RG-DECIDE-001"]), None)
    assert explanation["unresolved"] == []
    assert "(no unresolved conditions)" in graph.render_trace(explanation)


# ── scale and honesty ───────────────────────────────────────────────────────

def test_a_graph_built_from_part_of_a_case_says_so():
    subject = _subject()
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=subject)
    for i in range(100):
        b.add("evidence", _declared(content={"i": i}), materialise=(i < 5))
    graph = EvidenceGraph.from_case(b.build())
    coverage = graph.coverage.to_dict()
    assert coverage["records_total"] == 100
    assert coverage["evidence_materialised"] == 5
    assert coverage["complete"] is False
    assert "true statements about what is held" in coverage["note"]


def test_a_complete_graph_says_that_too():
    graph = _graph(_declared())
    assert graph.coverage.complete is True
    assert "every record in the collections read" in graph.coverage.to_dict()["note"]


def test_records_that_are_not_evidence_are_counted_not_coerced():
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=_subject())
    b.add("evidence", SimpleRecord("evidence", "raw_1", {"whatever": True}))
    graph = EvidenceGraph.from_case(b.build())
    assert graph.coverage.non_evidence_records == 1
    assert graph.nodes_of(NodeKind.EVIDENCE) == ()
    # Inspected and skipped for a stated reason is not the same as never looked at.
    assert graph.coverage.not_materialised == 0
    assert graph.coverage.complete is True


def test_absent_collections_are_reported():
    graph = _graph(_declared())
    assert "counterexamples" in graph.coverage.collections_absent


def test_an_unknown_collection_is_refused():
    with pytest.raises(GraphError, match="unknown collection"):
        EvidenceGraph.from_case(_case(_declared()), collections=("vibes",))


# ── determinism and serialisation ───────────────────────────────────────────

def test_the_graph_digest_does_not_depend_on_insertion_order():
    a = _declared(content={"i": 1})
    b = _declared(content={"i": 2}, parent_evidence=())
    forward = _graph(a, b)
    reverse = _graph(b, a)
    assert forward.digest() == reverse.digest()


def test_duplicate_edges_collapse():
    record = _declared(supports_claims=("cl_1",))
    builder = EvidenceGraphBuilder()
    builder.add_record(record)
    builder.link(EdgeType.SUPPORTS, record.evidence_id, "cl_1")
    graph = builder.build()
    supports = [e for e in graph.edges if e.edge_type is EdgeType.SUPPORTS]
    assert len(supports) == 1


def test_the_graph_serialises_whole():
    graph = _graph(_declared(supports_claims=("cl_1",)))
    payload = json.loads(json.dumps(graph.to_dict()))
    assert payload["schema_version"] == 1
    assert payload["digest"] == graph.digest()
    assert {n["kind"] for n in payload["nodes"]} >= {"EVIDENCE", "CLAIM", "SOURCE", "ACTION"}


def test_the_summary_counts_by_kind_and_type():
    summary = _graph(_declared(supports_claims=("cl_1",))).summary()
    assert summary["by_node_kind"]["EVIDENCE"] == 1
    assert summary["by_edge_type"]["SUPPORTS"] == 1
    assert summary["by_edge_type"]["PRODUCED_BY"] == 1
