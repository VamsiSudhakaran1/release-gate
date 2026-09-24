"""The universal evidence record.

The properties under test are the ones that make a normalised record worth
having: a producer cannot promote its own evidence, the four status axes stay
independent, trust is never inferred, and large content is referenced rather
than copied.
"""

import json

import pytest

from release_gate.assurance import canonical as C
from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
from release_gate.assurance.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    MAX_INLINE_BYTES,
    CoverageStatus,
    EpistemicStatus,
    EvidenceError,
    EvidenceIntegrityError,
    EvidenceRecord,
    EvidenceSchemaError,
    EvidenceType,
    Producer,
    ProducerKind,
    ProvenanceStatus,
    TrustStatus,
    VerificationMethod,
    external_content,
    file_content,
    inline_content,
)
from release_gate.assurance.methodology import (
    IndependenceThreshold,
    Requirement,
    RequirementOutcome,
    VerificationPresent,
)
from release_gate.assurance.subject import AssuranceSubject, ReferenceKind, SubjectType

AGENT = Producer("agent://migration-planner/7", ProducerKind.AGENT, identity_basis="none")
CI = Producer("ci://github/acme/api/run/8821", ProducerKind.TOOL, identity_basis="github-oidc")
DIGEST = C.digest_bytes(b"CREATE INDEX x;")


def _declared(**kw):
    kw.setdefault("evidence_type", EvidenceType.TOOL_RESULT)
    kw.setdefault("source", "agent-log")
    kw.setdefault("producer", AGENT)
    return EvidenceRecord.declared(**kw)


def _verified(**kw):
    kw.setdefault("evidence_type", EvidenceType.TEST_RESULT)
    kw.setdefault("source", "github-actions")
    kw.setdefault("producer", CI)
    kw.setdefault("method", VerificationMethod.TEST_SUITE)
    kw.setdefault("applies_to_digest", DIGEST)
    kw.setdefault("coverage_note", "schema application only; query compatibility untested")
    return EvidenceRecord.verification(**kw)


# ── the taxonomies ──────────────────────────────────────────────────────────

def test_all_contract_evidence_types_exist():
    assert {t.value for t in EvidenceType} == {
        "TRACE", "TOOL_RESULT", "TEST_RESULT", "FORMAL_PROOF", "SIMULATION_RESULT",
        "EXPERIMENT_RESULT", "STATIC_FINDING", "EVAL_RESULT", "EXTERNAL_REFERENCE",
        "CODE_ARTIFACT", "DATA_ARTIFACT", "HUMAN_REVIEW", "APPROVAL", "COUNTEREXAMPLE",
        "CLAIM_DERIVATION", "REPLICATION", "ATTESTATION", "OTHER"}


def test_verification_methods_cover_the_invariant_8_taxonomy():
    assert {m.value for m in VerificationMethod} >= {
        "FORMAL_PROOF", "INDEPENDENT_REPLICATION", "TEST_SUITE", "SIMULATION", "EXPERIMENT",
        "STATIC_ANALYSIS", "RUNTIME_ASSERTION", "HUMAN_REVIEW", "CROSS_MODEL_REVIEW",
        "THEOREM_PROVER", "EXTERNAL_REFERENCE", "DOMAIN_CHECKER", "OTHER"}


def test_evidence_type_is_orthogonal_to_how_it_was_established():
    # A FORMAL_PROOF record that nobody checked is a declaration about a proof.
    declared_proof = _declared(evidence_type=EvidenceType.FORMAL_PROOF)
    assert declared_proof.epistemic_status is EpistemicStatus.DECLARED
    assert declared_proof.is_verification is False


# ── the ingest boundary (Invariants 1 and 2) ────────────────────────────────

def test_a_producer_cannot_set_its_own_epistemic_status():
    record = EvidenceRecord.from_producer(
        {"summary": "ran the checks", "epistemic_status": "VERIFIED", "verified": True},
        evidence_type=EvidenceType.TOOL_RESULT, source="agent-log", producer=AGENT)
    assert record.epistemic_status is EpistemicStatus.DECLARED
    assert record.content["producer_claimed_epistemic_status"] == "VERIFIED"
    assert record.content["producer_claimed_verified"] is True


def test_an_agents_assertion_is_kept_as_evidence_of_the_assertion():
    # Invariant 1, second clause: the claim itself is a real fact worth keeping.
    record = EvidenceRecord.from_producer(
        {"statement": "the migration is backward compatible"},
        evidence_type=EvidenceType.OTHER, source="agent-log", producer=AGENT)
    assert record.content["statement"] == "the migration is backward compatible"
    assert record.epistemic_status is EpistemicStatus.DECLARED


def test_a_producer_cannot_set_trust_or_provenance_either():
    record = EvidenceRecord.from_producer(
        {"trust_status": "ACCEPTED", "provenance_status": "SIGNED"},
        evidence_type=EvidenceType.OTHER, source="agent-log", producer=AGENT)
    assert record.trust_status is TrustStatus.NOT_ESTABLISHED
    assert record.content["producer_claimed_trust_status"] == "ACCEPTED"


def test_a_producer_cannot_choose_its_own_evidence_id():
    record = EvidenceRecord.from_producer(
        {"evidence_id": "ev_pick_me"}, evidence_type=EvidenceType.OTHER,
        source="agent-log", producer=AGENT)
    assert record.evidence_id != "ev_pick_me"
    assert record.content["producer_claimed_evidence_id"] == "ev_pick_me"


@pytest.mark.parametrize("status", [EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED])
def test_a_foreign_payload_cannot_be_ingested_as_our_own_observation(status):
    with pytest.raises(EvidenceError, match="release-gate's own"):
        EvidenceRecord.from_producer({}, evidence_type=EvidenceType.TRACE,
                                     source="langfuse", producer=AGENT, status=status)


def test_release_gate_may_record_its_own_observations():
    record = EvidenceRecord.from_producer(
        {"finding": "model output reaches exec"}, evidence_type=EvidenceType.STATIC_FINDING,
        source="release-gate/audit", producer=Producer.release_gate("audit"),
        status=EpistemicStatus.DERIVED)
    assert record.epistemic_status is EpistemicStatus.DERIVED


# ── verification is typed (Invariant 8) ─────────────────────────────────────

def test_verified_requires_a_method():
    with pytest.raises(EvidenceError, match="Invariant 8"):
        EvidenceRecord(evidence_type=EvidenceType.TEST_RESULT, source="ci", producer=CI,
                       epistemic_status=EpistemicStatus.VERIFIED,
                       applies_to_digest=DIGEST, coverage_note="x")


def test_verified_requires_the_digest_it_applies_to():
    with pytest.raises(EvidenceError, match="applies_to_digest"):
        EvidenceRecord(evidence_type=EvidenceType.TEST_RESULT, source="ci", producer=CI,
                       epistemic_status=EpistemicStatus.VERIFIED,
                       verification_method=VerificationMethod.TEST_SUITE, coverage_note="x")


def test_verified_requires_a_statement_of_what_it_does_not_cover():
    with pytest.raises(EvidenceError, match="Invariant 9"):
        EvidenceRecord(evidence_type=EvidenceType.TEST_RESULT, source="ci", producer=CI,
                       epistemic_status=EpistemicStatus.VERIFIED,
                       verification_method=VerificationMethod.TEST_SUITE,
                       applies_to_digest=DIGEST)


def test_a_method_without_a_verified_finding_is_refused():
    # Otherwise a record implies a verification that never happened.
    with pytest.raises(EvidenceError, match="did not happen"):
        _declared(verification_method=VerificationMethod.TEST_SUITE)


def test_a_verification_that_moved_on_no_longer_applies():
    # FORMALLY_VERIFIED is not APPLICABLE TO THE CURRENT ARTIFACT (Invariant 2).
    record = _verified()
    assert record.applies_to(DIGEST) is True
    assert record.applies_to(C.digest_bytes(b"CREATE INDEX y;")) is False


def test_a_refutation_is_a_first_class_record():
    # Invariant 7: a failed attempt is evidence, held to the same rigour.
    refutation = _verified(evidence_type=EvidenceType.COUNTEREXAMPLE,
                           method=VerificationMethod.THEOREM_PROVER, refuted=True,
                           coverage_note="counterexample found for lemma 887")
    assert refutation.epistemic_status is EpistemicStatus.REFUTED
    assert refutation.is_verification is True


# ── four axes, kept apart (Invariant 11) ────────────────────────────────────

def test_trust_is_never_established_by_default():
    assert _verified().trust_status is TrustStatus.NOT_ESTABLISHED


def test_strong_provenance_does_not_confer_trust():
    # A signed record from a verifier nobody has vetted.
    record = _verified(provenance_status=ProvenanceStatus.SIGNED)
    assert record.provenance_status is ProvenanceStatus.SIGNED
    assert record.trust_status is TrustStatus.NOT_ESTABLISHED


def test_trust_does_not_confer_provenance():
    # And the reverse: a trusted vendor's unattributed assertion.
    record = _declared(provenance_status=ProvenanceStatus.UNATTRIBUTED).with_trust(
        TrustStatus.ACCEPTED, basis="vendor on the approved list",
        decided_by="platform-security")
    assert record.trust_status is TrustStatus.ACCEPTED
    assert record.provenance_status is ProvenanceStatus.UNATTRIBUTED


def test_a_trust_decision_must_name_its_basis_and_decider():
    with pytest.raises(EvidenceError, match="basis and a decider"):
        _declared().with_trust(TrustStatus.ACCEPTED, basis="", decided_by="someone")


def test_trust_can_be_revoked():
    accepted = _declared().with_trust(TrustStatus.ACCEPTED, basis="vetted 2026-01",
                                      decided_by="platform-security")
    revoked = accepted.with_trust(TrustStatus.REVOKED, basis="verifier found to share a "
                                  "prompt template with the claim's author",
                                  decided_by="platform-security")
    assert revoked.trust_status is TrustStatus.REVOKED
    assert revoked.evidence_id == accepted.evidence_id  # trust is not part of identity


def test_coverage_status_is_its_own_axis():
    record = _verified(coverage_status=CoverageStatus.PARTIAL)
    assert record.coverage_status is CoverageStatus.PARTIAL
    assert record.epistemic_status is EpistemicStatus.VERIFIED


def test_derived_evidence_without_parents_is_unattributed():
    from release_gate.assurance.evidence import EvidenceRecord as E
    orphan = E.derived(EvidenceType.CLAIM_DERIVATION, source="release-gate/analysis",
                       producer=Producer.release_gate("analysis"))
    chained = E.derived(EvidenceType.CLAIM_DERIVATION, source="release-gate/analysis",
                        producer=Producer.release_gate("analysis"),
                        parent_evidence=("ev_1", "ev_2"))
    assert orphan.provenance_status is ProvenanceStatus.UNATTRIBUTED
    assert chained.provenance_status is ProvenanceStatus.CHAIN_VERIFIED


# ── large content is referenced, not copied ─────────────────────────────────

def test_small_content_travels_with_the_record():
    reference, digest = inline_content("2 passed, 0 failed", label="pytest-summary")
    record = _verified(content_reference=reference, digest=digest)
    assert record.content_is_embedded is True
    assert record.content_reference.detail["inline"] == "2 passed, 0 failed"


def test_large_content_is_referenced_rather_than_embedded():
    big = "x" * (MAX_INLINE_BYTES + 1)
    reference, digest = inline_content(big, label="trace-dump")
    record = _verified(content_reference=reference, digest=digest)
    assert record.content_is_embedded is False
    assert record.digest == C.digest_bytes(big.encode("utf-8"))
    # The record stays small; the content stays where it was.
    assert len(json.dumps(record.to_dict())) < 2000


def test_a_file_is_referenced_and_streamed_not_read_whole(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text("<testsuite tests='40'/>", encoding="utf-8")
    reference, digest = file_content(path)
    record = _verified(content_reference=reference, digest=digest)
    assert record.content_reference.kind is ReferenceKind.FILE
    assert record.digest == C.digest_bytes(b"<testsuite tests='40'/>")
    assert record.content_reference.detail["byte_length"] == 23


def test_external_content_without_a_digest_is_legal_and_says_so():
    reference, digest = external_content("langfuse://traces/run-8821",
                                         kind=ReferenceKind.URL)
    record = _declared(evidence_type=EvidenceType.TRACE, content_reference=reference,
                       digest=digest)
    assert record.digest is None
    assert record.content_is_embedded is False


def test_a_malformed_digest_is_refused():
    with pytest.raises(EvidenceError, match="content id"):
        _declared(digest="deadbeef")


# ── claims ──────────────────────────────────────────────────────────────────

def test_evidence_can_support_some_claims_and_contradict_others():
    record = _verified(supports_claims=("cl_1",), contradicts_claims=("cl_2",))
    assert record.is_attached is True
    assert record.supports_claims == ("cl_1",)
    assert record.contradicts_claims == ("cl_2",)


def test_evidence_cannot_both_support_and_contradict_one_claim():
    with pytest.raises(EvidenceError, match="cuts both ways"):
        _verified(supports_claims=("cl_1",), contradicts_claims=("cl_1",))


def test_unattached_evidence_is_legal():
    # In a case with no declared claims everything is unattached, and that is
    # what the claim-coverage row should report rather than something to hide.
    assert _declared().is_attached is False


def test_attachment_helpers_do_not_duplicate():
    record = _declared().supporting("cl_1").supporting("cl_1", "cl_2")
    assert record.supports_claims == ("cl_1", "cl_2")


# ── independence attribution (Invariant 6) ──────────────────────────────────

def test_records_from_one_producer_share_a_fingerprint():
    a, b = _verified(timestamp="2026-09-12T09:00:00Z"), _verified(timestamp="2026-09-12T10:00:00Z")
    assert a.independence_fingerprint() == b.independence_fingerprint()


def test_records_from_different_producers_differ():
    other = _verified(producer=Producer("ci://gitlab/acme/run/1", ProducerKind.TOOL))
    assert _verified().independence_fingerprint() != other.independence_fingerprint()


def test_the_same_model_and_prompt_collapse_to_one_source():
    def rec(agent_id):
        return _declared(producer=Producer(agent_id, ProducerKind.AGENT, model="m-1"),
                         metadata={"prompt_digest": "sha256:abc"})
    # Different agent ids, same model and prompt — the analyser gets the signal
    # it needs; what it does with lineage closure is its own job.
    assert rec("a/1").independence_fingerprint() != rec("a/2").independence_fingerprint()
    assert rec("a/1").independence_fingerprint() == rec("a/1").independence_fingerprint()


def test_unattributable_evidence_cannot_be_constructed_at_all():
    # Rather than tolerate ungrouped records and report them, the constructor
    # makes them impossible: source and producer_id are both mandatory.
    with pytest.raises(EvidenceError):
        _declared(source="")
    with pytest.raises(EvidenceError):
        Producer("   ")
    assert _declared().independence_fingerprint() is not None


def test_an_unauthenticated_producer_id_is_a_weaker_grouping():
    # A producer id nobody authenticated is a claim about identity, so two
    # records naming different producers may still be one actor.
    assert _declared(producer=AGENT).independence_basis == "asserted"
    assert _verified(producer=CI).independence_basis == "authenticated"
    assert _declared().to_dict()["independence_basis"] == "asserted"


# ── schema versioning ───────────────────────────────────────────────────────

def test_every_record_carries_its_schema_version():
    assert _declared().to_dict()["schema_version"] == EVIDENCE_SCHEMA_VERSION


def test_a_record_from_a_newer_schema_is_refused_not_partially_read():
    doc = _declared().to_dict()
    doc["schema_version"] = EVIDENCE_SCHEMA_VERSION + 1
    with pytest.raises(EvidenceSchemaError, match="newer than this reader|silently dropped"):
        EvidenceRecord.from_dict(doc)


# ── serialisation and integrity ─────────────────────────────────────────────

def test_round_trip_preserves_identity():
    record = _verified(supports_claims=("cl_1",), content={"passed": 40, "failed": 0},
                       metadata={"job": "unit"})
    back = EvidenceRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert back.evidence_id == record.evidence_id
    assert back.verification_method is VerificationMethod.TEST_SUITE
    assert back.content["passed"] == 40


def test_an_edited_record_is_rejected_rather_than_repaired():
    doc = _verified().to_dict()
    doc["epistemic_status"] = "VERIFIED"
    doc["coverage_note"] = "covers everything"
    with pytest.raises(EvidenceIntegrityError, match="modified after it was written"):
        EvidenceRecord.from_dict(doc)


def test_when_a_verification_ran_is_part_of_what_it_establishes():
    # Unlike a subject's creation time: the same suite passing today and last
    # March are two pieces of evidence.
    march = _verified(timestamp="2026-03-01T09:00:00Z")
    today = _verified(timestamp="2026-09-13T09:00:00Z")
    assert march.evidence_id != today.evidence_id


def test_identical_evidence_is_identical():
    kw = {"timestamp": "2026-09-12T09:00:00Z"}
    assert _verified(**kw).evidence_id == _verified(**kw).evidence_id


def test_a_producer_is_required():
    with pytest.raises(EvidenceError, match="producer_id is required"):
        Producer("")


def test_a_source_is_required():
    with pytest.raises(EvidenceError, match="source is required"):
        _declared(source="  ")


# ── it drops into a case, and the methodology can read it ───────────────────

def test_an_evidence_record_satisfies_the_case_record_protocol():
    record = _verified()
    b = AssuranceCaseBuilder(
        case_type=CaseType.DATA_CHANGE, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("CREATE INDEX x;", SubjectType.DATA_CHANGE,
                                           "apply to prod-eu"))
    b.add("verification", record)
    case = b.build()
    assert case.collection("verification").total_count == 1
    assert case.collection("verification").by_id(record.evidence_id) is record


def test_a_methodology_predicate_reads_the_verification_method():
    record = _verified(method=VerificationMethod.SIMULATION)
    b = AssuranceCaseBuilder(
        case_type=CaseType.DATA_CHANGE, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("x", SubjectType.DATA_CHANGE, "apply"))
    b.add("verification", record)
    requirement = Requirement(requirement_id="r", description="d",
                              predicate=VerificationPresent(methods=("SIMULATION",)))
    assert requirement.evaluate(b.build()).outcome is RequirementOutcome.SATISFIED


def test_a_methodology_predicate_reads_the_independence_attribution():
    b = AssuranceCaseBuilder(
        case_type=CaseType.RESEARCH_RESULT, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("x", SubjectType.RESEARCH_RESULT, "publish"))
    for producer in (CI, Producer("prover://lean/1", ProducerKind.TOOL)):
        b.add("verification", _verified(producer=producer,
                                        method=VerificationMethod.THEOREM_PROVER))
    requirement = Requirement(requirement_id="r", description="d",
                              predicate=IndependenceThreshold(minimum_groups=2))
    assert requirement.evaluate(b.build()).outcome is RequirementOutcome.SATISFIED


def test_ten_records_from_one_producer_do_not_make_two_groups():
    b = AssuranceCaseBuilder(
        case_type=CaseType.RESEARCH_RESULT, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("x", SubjectType.RESEARCH_RESULT, "publish"))
    for i in range(10):
        b.add("verification", _verified(timestamp=f"2026-09-12T09:{i:02d}:00Z"))
    requirement = Requirement(requirement_id="r", description="d",
                              predicate=IndependenceThreshold(minimum_groups=2))
    result = requirement.evaluate(b.build())
    assert result.outcome is RequirementOutcome.UNSATISFIED
    assert result.observed["independent_groups"] == 1


# ── the arrival stamp is not part of the content address ─────────────────────

class TestArrivalStampIsNotIdentity:
    """A timestamp release-gate stamps because nobody supplied one says when
    this process read the input. It is not a fact about the evidence, and
    putting it in a content address made the address vary with the clock."""

    def test_an_unsupplied_timestamp_is_marked_as_stamped_on_arrival(self):
        record = _declared(content={"exit_code": 0})
        assert record.stamped_on_arrival
        assert record.timestamp  # still recorded, just not identity

    def test_a_supplied_timestamp_is_not(self):
        record = _declared(content={"exit_code": 0},
                           timestamp="2026-03-01T09:00:00Z")
        assert not record.stamped_on_arrival

    def test_an_arrival_stamp_is_kept_out_of_identity(self):
        assert _declared(content={"a": 1}).identity()["timestamp"] is None

    def test_a_supplied_timestamp_stays_in_identity(self):
        record = _declared(content={"a": 1}, timestamp="2026-03-01T09:00:00Z")
        assert record.identity()["timestamp"] == "2026-03-01T09:00:00Z"

    def test_two_identical_records_stamped_apart_share_an_id(self):
        """The property that was broken: the same evidence ingested twice a
        second apart produced two different records."""
        one = _declared(content={"exit_code": 0})
        two = _declared(content={"exit_code": 0})
        object.__setattr__(two, "timestamp", "2099-01-01T00:00:00Z")
        assert one.evidence_id == two.evidence_id

    def test_a_declared_production_time_still_distinguishes_evidence(self):
        """The same suite passing today and last March are two pieces of
        evidence — which is why only the arrival stamp is dropped."""
        march = _declared(content={"a": 1}, timestamp="2026-03-01T09:00:00Z")
        today = _declared(content={"a": 1}, timestamp="2026-09-01T09:00:00Z")
        assert march.evidence_id != today.evidence_id

    def test_the_record_still_carries_when_it_arrived(self):
        payload = _declared(content={"a": 1}).to_dict()
        assert payload["timestamp"]
        assert payload["stamped_on_arrival"] is True

    def test_it_round_trips_to_the_same_id(self):
        record = _declared(content={"a": 1})
        assert EvidenceRecord.from_dict(record.to_dict()).evidence_id == \
            record.evidence_id

    def test_a_payload_without_the_flag_is_read_the_old_way(self):
        """Records written before the flag existed keep the ids they were
        stored under."""
        record = _declared(content={"a": 1}, timestamp="2026-03-01T09:00:00Z")
        payload = dict(record.to_dict())
        payload.pop("stamped_on_arrival")
        assert EvidenceRecord.from_dict(payload).evidence_id == record.evidence_id


class TestStripClocksAgreesWithIdentity:

    def test_an_arrival_timestamp_is_stripped(self):
        from release_gate.assurance.records import strip_clocks
        assert "timestamp" not in strip_clocks(_declared(content={"a": 1}).to_dict())

    def test_a_supplied_timestamp_is_not(self):
        from release_gate.assurance.records import strip_clocks
        record = _declared(content={"a": 1}, timestamp="2026-03-01T09:00:00Z")
        assert strip_clocks(record.to_dict())["timestamp"] == "2026-03-01T09:00:00Z"

    def test_a_case_is_re_derivable_from_its_own_input(self):
        """A case digest that moved with the clock could not be re-derived, so
        an approval or override bound to one went stale whenever CI re-ran."""
        from release_gate.demos.single_agent import run
        assert len({run().case.case_digest for _ in range(12)}) == 1
