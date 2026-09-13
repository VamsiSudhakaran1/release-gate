"""ArtifactGraph — where a thing came from, and whether it is still that thing.

The six questions the prompt names are the test plan. The sharpest is the last,
and it is the reason content identity and logical identity are separate.
"""

import json

import pytest

from release_gate.assurance.artifacts import (
    Artifact,
    ArtifactEdgeType,
    ArtifactError,
    ArtifactGraph,
    ArtifactGraphBuilder,
    ArtifactKind,
    CurrencyStatus,
)
from release_gate.assurance.canonical import digest_bytes
from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
from release_gate.assurance.claims import Claim, ClaimGraph
from release_gate.assurance.evidence import (
    EvidenceRecord,
    EvidenceType,
    Producer,
    ProducerKind,
    VerificationMethod,
)
from release_gate.assurance.execution_graph import ExecutionGraph
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.subject import (
    AssuranceSubject,
    DigestMethod,
    DigestStatus,
    SubjectType,
)

CI = Producer("ci://github/acme/run/1", ProducerKind.TOOL, identity_basis="github-oidc")
PATH = "migrations/2026_09_12_add_index.sql"


def _artifact(content=b"v1", logical_id=PATH, **kw):
    kw.setdefault("artifact_kind", ArtifactKind.MIGRATION)
    kw.setdefault("digest_method", DigestMethod.SHA256_CONTENT)
    kw.setdefault("digest_status", DigestStatus.OBSERVED)
    return Artifact(logical_id=logical_id, digest=digest_bytes(content), **kw)


def _verification(digest, **kw):
    kw.setdefault("method", VerificationMethod.SIMULATION)
    kw.setdefault("coverage_note", "schema only")
    return EvidenceRecord.verification(EvidenceType.SIMULATION_RESULT, source="ci",
                                       producer=CI, applies_to_digest=digest, **kw)


def _graph(*artifacts, evidence=(), links=()):
    builder = ArtifactGraphBuilder()
    for artifact in artifacts:
        builder.add(artifact)
    for record in evidence:
        builder.add_evidence(record)
    for link in links:
        builder.link(*link)
    return builder.build()


# ── artifact kinds and identity ─────────────────────────────────────────────

def test_the_kinds_cover_what_the_contract_names():
    assert {k.value for k in ArtifactKind} >= {
        "SOURCE_CODE", "PROOF", "DATASET", "QUERY_OUTPUT", "DOCUMENT",
        "SIMULATION_OUTPUT", "MODEL_CHECKPOINT", "REPORT", "PAYMENT_BATCH",
        "DEPLOYMENT_PLAN", "CONFIGURATION"}


def test_content_identity_is_the_digest():
    assert _artifact(b"v1").artifact_id == digest_bytes(b"v1")


def test_a_logical_id_is_required():
    # Without a stable handle, successive versions of one thing cannot be
    # recognised as versions of one thing.
    with pytest.raises(ArtifactError, match="logical_id is required"):
        Artifact(logical_id="  ")


def test_an_unhashed_artifact_is_still_a_node_and_says_so():
    artifact = Artifact(logical_id="s3://warehouse/live-table",
                        artifact_kind=ArtifactKind.DATASET)
    assert artifact.content_identified is False
    assert artifact.artifact_id == "unhashed:s3://warehouse/live-table"


def test_a_missing_digest_is_never_an_unchanged_one():
    with pytest.raises(ArtifactError, match="Invariant 3"):
        Artifact(logical_id="x", digest_status=DigestStatus.OBSERVED)


def test_an_attested_digest_must_name_its_attestor():
    with pytest.raises(ArtifactError, match="attestor"):
        Artifact(logical_id="x", digest=digest_bytes(b"a"),
                 digest_method=DigestMethod.EXTERNAL_ATTESTED,
                 digest_status=DigestStatus.DECLARED)


def test_an_artifact_cannot_revise_itself():
    with pytest.raises(ArtifactError, match="cannot revise itself"):
        Artifact(logical_id="x", digest=digest_bytes(b"a"),
                 digest_method=DigestMethod.SHA256_CONTENT,
                 digest_status=DigestStatus.OBSERVED, revises=digest_bytes(b"a"))


# ── question 1: what created this? ──────────────────────────────────────────

def test_what_created_this():
    graph = _graph(_artifact(created_by="agent://planner/7"))
    assert graph.created_by(digest_bytes(b"v1")) == ("agent://planner/7",)


# ── question 2: what inputs contributed? ────────────────────────────────────

def test_direct_inputs_and_transitive_lineage():
    base = _artifact(b"schema", logical_id="schema.sql")
    mid = _artifact(b"plan", logical_id="plan.json", inputs=(base.digest,))
    top = _artifact(b"migration", inputs=(mid.digest,))
    graph = _graph(base, mid, top)
    assert graph.inputs(top.artifact_id) == (mid.digest,)
    assert graph.lineage(top.artifact_id) == tuple(sorted((mid.digest, base.digest)))


def test_dependents_are_what_would_need_re_examining():
    base = _artifact(b"schema", logical_id="schema.sql")
    derived = _artifact(b"migration", inputs=(base.digest,))
    graph = _graph(base, derived)
    assert graph.dependents(base.artifact_id) == (derived.artifact_id,)


def test_a_lineage_cycle_terminates():
    a = _artifact(b"a", logical_id="a", inputs=(digest_bytes(b"b"),))
    b = _artifact(b"b", logical_id="b", inputs=(digest_bytes(b"a"),))
    graph = _graph(a, b)
    assert len(graph.lineage(a.artifact_id)) == 2


# ── question 3: what modified it? ───────────────────────────────────────────

def test_what_modified_it():
    graph = _graph(_artifact(modified_by=("agent://editor/2",)))
    assert graph.modified_by(digest_bytes(b"v1")) == ("agent://editor/2",)


def test_the_revision_chain_follows_what_replaced_what():
    v1 = _artifact(b"v1", created_at="2026-09-10T09:00:00Z")
    v2 = _artifact(b"v2", revises=v1.digest, created_at="2026-09-11T09:00:00Z")
    v3 = _artifact(b"v3", revises=v2.digest, created_at="2026-09-12T09:00:00Z")
    # Insertion order deliberately scrambled: the links decide, not arrival.
    graph = _graph(v3, v1, v2)
    assert graph.revision_chain(PATH) == (v1.digest, v2.digest, v3.digest)
    assert graph.current_version(PATH).digest == v3.digest


# ── question 4: what verified it? ───────────────────────────────────────────

def test_a_verification_attaches_to_the_exact_content():
    v1 = _artifact(b"v1")
    record = _verification(v1.digest)
    graph = _graph(v1, evidence=[record])
    assert graph.verifications(v1.artifact_id) == (record.evidence_id,)


def test_a_verification_of_one_revision_says_nothing_about_another():
    # Invariant 2, as a missing edge rather than a caveat.
    v1 = _artifact(b"v1")
    v2 = _artifact(b"v2", revises=v1.digest)
    graph = _graph(v1, v2, evidence=[_verification(v1.digest)])
    assert graph.verifications(v1.artifact_id)
    assert graph.verifications(v2.artifact_id) == ()


def test_a_non_verification_record_creates_no_verification_edge():
    v1 = _artifact(b"v1")
    declared = EvidenceRecord.declared(EvidenceType.OTHER, source="agent-log",
                                       producer=Producer("agent://a", ProducerKind.AGENT))
    assert _graph(v1, evidence=[declared]).verifications(v1.artifact_id) == ()


# ── question 5: what decision depends on it? ────────────────────────────────

def test_the_subject_is_where_the_graph_meets_the_decision():
    subject = AssuranceSubject.from_text("CREATE INDEX x;", SubjectType.DATA_CHANGE,
                                         "apply to prod-eu")
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=subject)
    case = b.build()
    graph = ArtifactGraph.from_case(case)
    decisions = graph.decisions_depending_on(subject.digest)
    assert decisions == (f"decision:{case.case_id}",)


def test_an_input_reaches_the_decision_through_what_it_produced():
    subject = AssuranceSubject.from_text("CREATE INDEX x;", SubjectType.DATA_CHANGE,
                                         "apply to prod-eu")
    schema = Artifact(logical_id="schema.sql", digest=digest_bytes(b"schema"),
                      digest_method=DigestMethod.SHA256_CONTENT,
                      digest_status=DigestStatus.OBSERVED)
    derived = Artifact(logical_id="inline", digest=subject.digest,
                       digest_method=DigestMethod.SHA256_CONTENT,
                       digest_status=DigestStatus.OBSERVED, inputs=(schema.digest,))
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=subject)
    b.add("artifacts", schema)
    b.add("artifacts", derived)
    case = b.build()
    graph = ArtifactGraph.from_case(case)
    assert f"decision:{case.case_id}" in graph.decisions_depending_on(schema.digest)


def test_a_claim_resting_on_a_verified_artifact_is_reachable_from_it():
    subject = AssuranceSubject.from_text("proof", SubjectType.RESEARCH_RESULT, "publish")
    record = _verification(subject.digest, supports_claims=("cl_1",))
    b = AssuranceCaseBuilder(case_type=CaseType.RESEARCH_RESULT, objective="o",
                             requested_decision="d", subject=subject)
    b.add("verification", record)
    b.add("claims", Claim("cl_1", "the result holds"))
    case = b.build()
    graph = ArtifactGraph.from_case(case, claim_graph=ClaimGraph.from_case(case))
    assert "cl_1" in graph.decisions_depending_on(subject.digest)


# ── question 6: has it changed since verification? ──────────────────────────

def test_verified_and_unchanged():
    v1 = _artifact(b"v1")
    currency = _graph(v1, evidence=[_verification(v1.digest)]).verification_currency(PATH)
    assert currency.status is CurrencyStatus.VERIFIED_CURRENT
    assert currency.current is True


def test_verified_then_changed_is_stale():
    v1 = _artifact(b"v1", created_at="2026-09-10T09:00:00Z")
    v2 = _artifact(b"v2", revises=v1.digest, created_at="2026-09-12T09:00:00Z")
    currency = _graph(v1, v2, evidence=[_verification(v1.digest)]).verification_currency(PATH)
    assert currency.status is CurrencyStatus.VERIFIED_STALE
    assert currency.current is False
    assert currency.revisions_since_verification == 1
    assert "no longer in front of you" in currency.detail


def test_two_revisions_since_verification_are_counted():
    v1 = _artifact(b"v1", created_at="2026-09-10T09:00:00Z")
    v2 = _artifact(b"v2", revises=v1.digest, created_at="2026-09-11T09:00:00Z")
    v3 = _artifact(b"v3", revises=v2.digest, created_at="2026-09-12T09:00:00Z")
    currency = _graph(v1, v2, v3,
                      evidence=[_verification(v1.digest)]).verification_currency(PATH)
    assert currency.revisions_since_verification == 2


def test_never_verified_is_distinct_from_stale():
    currency = _graph(_artifact(b"v1")).verification_currency(PATH)
    assert currency.status is CurrencyStatus.NEVER_VERIFIED
    assert currency.current is False


def test_an_unhashed_artifact_cannot_answer_the_question():
    # "I cannot tell" must never read as "unchanged".
    graph = _graph(Artifact(logical_id="s3://warehouse/table",
                            artifact_kind=ArtifactKind.DATASET))
    currency = graph.verification_currency("s3://warehouse/table")
    assert currency.status is CurrencyStatus.UNVERIFIABLE
    assert currency.current is False


def test_re_verifying_the_new_revision_makes_it_current_again():
    v1 = _artifact(b"v1", created_at="2026-09-10T09:00:00Z")
    v2 = _artifact(b"v2", revises=v1.digest, created_at="2026-09-12T09:00:00Z")
    graph = _graph(v1, v2, evidence=[_verification(v1.digest), _verification(v2.digest)])
    assert graph.verification_currency(PATH).status is CurrencyStatus.VERIFIED_CURRENT


def test_stale_verifications_are_listed_across_the_whole_graph():
    a1 = _artifact(b"a1", logical_id="a", created_at="2026-09-10T09:00:00Z")
    a2 = _artifact(b"a2", logical_id="a", revises=a1.digest,
                   created_at="2026-09-12T09:00:00Z")
    b1 = _artifact(b"b1", logical_id="b")
    graph = _graph(a1, a2, b1, evidence=[_verification(a1.digest),
                                         _verification(b1.digest)])
    stale = graph.stale_verifications()
    assert [c.logical_id for c in stale] == ["a"]
    assert graph.summary()["stale_verifications"][0]["status"] == "VERIFIED_STALE"


# ── reading what other graphs already extracted ─────────────────────────────

def test_artifacts_are_read_from_execution_telemetry_not_re_derived():
    def span(span_id, parent, name, **attrs):
        return {"spanId": span_id, "parentSpanId": parent, "name": name,
                "startTimeUnixNano": "0",
                "attributes": [{"key": k, "value": {"stringValue": str(v)}}
                               for k, v in attrs.items()]}

    digest = digest_bytes(b"generated")
    document = {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": [
        span("s1", "", "agent", **{"gen_ai.agent.id": "writer",
                                   "artifact.digest": digest})]}]}]}
    execution = ExecutionGraph.from_otlp(document)

    subject = AssuranceSubject.from_text("x", SubjectType.GENERAL_RESULT, "accept")
    b = AssuranceCaseBuilder(case_type=CaseType.GENERAL_DECISION, objective="o",
                             requested_decision="d", subject=subject)
    graph = ArtifactGraph.from_case(b.build(), execution_graph=execution)
    assert digest in graph
    assert graph.created_by(digest) == ("agent:writer",)
    # Telemetry attests the digest; release-gate did not compute it.
    assert graph.artifact(digest).digest_status is DigestStatus.DECLARED


def test_records_that_are_not_artifacts_are_counted_not_coerced():
    subject = AssuranceSubject.from_text("x", SubjectType.GENERAL_RESULT, "accept")
    b = AssuranceCaseBuilder(case_type=CaseType.GENERAL_DECISION, objective="o",
                             requested_decision="d", subject=subject)
    b.add("artifacts", SimpleRecord("artifact", "raw_1", {"path": "x"}))
    graph = ArtifactGraph.from_case(b.build())
    assert "not Artifacts" in " ".join(graph.notes)


def test_a_case_always_has_at_least_the_subject():
    subject = AssuranceSubject.from_text("x", SubjectType.DOCUMENT, "publish")
    b = AssuranceCaseBuilder(case_type=CaseType.GENERAL_DECISION, objective="o",
                             requested_decision="d", subject=subject)
    assert len(ArtifactGraph.from_case(b.build())) == 1


# ── the whole story, and output ─────────────────────────────────────────────

def test_provenance_answers_all_six_questions_at_once():
    base = _artifact(b"schema", logical_id="schema.sql")
    v1 = _artifact(b"v1", created_by="agent://planner/7", inputs=(base.digest,),
                   modified_by=("agent://editor/2",), created_at="2026-09-10T09:00:00Z")
    v2 = _artifact(b"v2", revises=v1.digest, created_at="2026-09-12T09:00:00Z")
    graph = _graph(base, v1, v2, evidence=[_verification(v1.digest)],
                   links=[(ArtifactEdgeType.DEPENDED_ON_BY, v2.artifact_id, "decision:x")])
    story = graph.provenance(v1.artifact_id)
    assert story["created_by"] == ("agent://planner/7",)
    assert story["inputs"] == (base.digest,)
    assert story["modified_by"] == ("agent://editor/2",)
    assert len(story["verified_by"]) == 1
    assert story["currency"]["status"] == "VERIFIED_STALE"
    assert len(story["revision_chain"]) == 2


def test_provenance_for_something_not_in_the_case_says_so():
    story = _graph(_artifact()).provenance("sha256:" + "f" * 64)
    assert story["present"] is False


def test_the_summary_names_what_has_no_digest():
    graph = _graph(_artifact(), Artifact(logical_id="s3://live", artifact_kind=ArtifactKind.DATASET))
    assert graph.summary()["without_digest"] == ["s3://live"]


def test_the_graph_serialises_whole():
    graph = _graph(_artifact(), evidence=[_verification(digest_bytes(b"v1"))])
    payload = json.loads(json.dumps(graph.to_dict()))
    assert payload["schema_version"] == 1
    assert payload["digest"] == graph.digest()


def test_the_digest_does_not_depend_on_insertion_order():
    a, b = _artifact(b"a", logical_id="a"), _artifact(b"b", logical_id="b")
    assert _graph(a, b).digest() == _graph(b, a).digest()


def test_round_trip_preserves_an_artifact():
    artifact = _artifact(b"v1", created_by="agent://a", inputs=("sha256:" + "1" * 64,))
    back = Artifact.from_dict(json.loads(json.dumps(artifact.to_dict())))
    assert back.artifact_id == artifact.artifact_id
    assert back.inputs == artifact.inputs


def test_a_forked_history_is_reported_rather_than_resolved_by_guessing():
    # Two versions nothing revises: "the current one" is not a single thing.
    v1 = _artifact(b"v1", created_at="2026-09-10T09:00:00Z")
    fork_a = _artifact(b"a", revises=v1.digest, created_at="2026-09-11T09:00:00Z")
    fork_b = _artifact(b"b", revises=v1.digest, created_at="2026-09-12T09:00:00Z")
    graph = _graph(v1, fork_a, fork_b, evidence=[_verification(fork_b.digest)])
    currency = graph.verification_currency(PATH)

    assert len(graph.heads(PATH)) == 2
    assert set(currency.ambiguous_heads) == {fork_a.digest, fork_b.digest}
    # One branch verified is not the artifact verified.
    assert currency.status is CurrencyStatus.VERIFIED_STALE
    assert "forked" in currency.detail


def test_a_fork_with_every_branch_verified_is_current():
    v1 = _artifact(b"v1", created_at="2026-09-10T09:00:00Z")
    fork_a = _artifact(b"a", revises=v1.digest, created_at="2026-09-11T09:00:00Z")
    fork_b = _artifact(b"b", revises=v1.digest, created_at="2026-09-12T09:00:00Z")
    graph = _graph(v1, fork_a, fork_b,
                   evidence=[_verification(fork_a.digest), _verification(fork_b.digest)])
    assert graph.verification_currency(PATH).status is CurrencyStatus.VERIFIED_CURRENT


def test_an_inline_subject_does_not_collide_with_a_file_called_inline():
    subject = AssuranceSubject.from_text("x", SubjectType.DOCUMENT, "publish")
    artifact = Artifact.from_subject(subject)
    assert artifact.logical_id.startswith("subject:DOCUMENT:")
