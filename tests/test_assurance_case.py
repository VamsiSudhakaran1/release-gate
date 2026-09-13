"""AssuranceCase — the container that must serve one migration and ten million calls.

As with the subject tests, each test names the property it protects rather than
the implementation detail it exercises.
"""

import json

import pytest

from release_gate.assurance import canonical as C
from release_gate.assurance.case import (
    COLLECTION_KINDS,
    EVIDENCE_KINDS,
    AssuranceCase,
    AssuranceCaseBuilder,
    CaseIntegrityError,
    CaseState,
    CaseStateError,
    CaseType,
    CaseValidationError,
    CaseVerdict,
    Decision,
    MethodologyRef,
    default_case_type,
)
from release_gate.assurance.records import (
    DedupeBasis,
    MaterialisationBasis,
    Presence,
    RecordCollectionBuilder,
    RecordError,
    SimpleRecord,
)
from release_gate.assurance.subject import AssuranceSubject, SubjectType

OBJECTIVE = "add an index to orders without taking write downtime"
DECISION = "authorise applying this migration to prod-eu"


def _subject(text="CREATE INDEX CONCURRENTLY idx ON orders(id);"):
    return AssuranceSubject.from_text(text, SubjectType.DATA_CHANGE,
                                      "apply this migration to prod-eu")


def _builder(**kw):
    kw.setdefault("case_type", CaseType.DATA_CHANGE)
    kw.setdefault("objective", OBJECTIVE)
    kw.setdefault("requested_decision", DECISION)
    kw.setdefault("subject", _subject())
    return AssuranceCaseBuilder(**kw)


def _rec(kind, i, **payload):
    return SimpleRecord(record_type=kind, record_id=f"{kind}_{i}", payload=payload)


def _coverage_case():
    """A sealed case carrying coverage — the minimum a verdict may attach to."""
    b = _builder()
    b.add("coverage", _rec("coverage", 1, dimension="staging dry-run", status="OBSERVED"))
    return b.build().seal()


def _verdict(decision=Decision.HOLD):
    return CaseVerdict(decision=decision, fired_rules=["RG-DECIDE-014"],
                       reasons=["No rollback path for an irreversible action."],
                       engine_version="0.11.0", ruleset_version="2026.09")


# ── the simplest possible case ──────────────────────────────────────────────

def test_a_case_needs_only_a_subject_an_objective_and_a_decision():
    case = _builder().build()
    assert case.state is CaseState.DRAFT
    assert case.is_sparse is True
    assert case.total_records == 0
    assert len(case.absent_collections) == len(COLLECTION_KINDS)


def test_all_contract_case_types_exist():
    assert {t.value for t in CaseType} == {
        "DEPLOYMENT", "AUTONOMOUS_ACTION", "RESEARCH_RESULT", "CODE_CHANGE",
        "DATA_CHANGE", "FINANCIAL_ACTION", "INFRASTRUCTURE_CHANGE",
        "GENERAL_DECISION", "CUSTOM"}


@pytest.mark.parametrize("missing", ["objective", "requested_decision"])
def test_objective_and_requested_decision_are_both_required(missing):
    with pytest.raises(CaseValidationError, match=missing):
        _builder(**{missing: "   "}).build()


def test_custom_case_type_requires_a_label():
    with pytest.raises(CaseValidationError, match="custom_type"):
        _builder(case_type=CaseType.CUSTOM).build()


def test_case_type_selects_no_behaviour():
    # The core must stay domain-neutral: the same records under a different case
    # type produce the same argument, with only the type itself differing.
    made = {}
    for case_type in CaseType:
        kw = {"case_type": case_type}
        if case_type is CaseType.CUSTOM:
            kw["custom_type"] = "clinical-recommendation"
        b = _builder(**kw)
        b.add("coverage", _rec("coverage", 1, dimension="x", status="OBSERVED"))
        case = b.build()
        made[case_type] = case
        assert case.collection("coverage").total_count == 1
        assert case.absent_collections == tuple(k for k in COLLECTION_KINDS if k != "coverage")
    # Every case type reaches an identical evidentiary state.
    assert len({c.evidence_digest for c in made.values()}) == 1


def test_default_case_type_is_a_suggestion_not_a_constraint():
    assert default_case_type(SubjectType.FINANCIAL_ACTION) is CaseType.FINANCIAL_ACTION
    assert default_case_type(SubjectType.DOCUMENT) is CaseType.GENERAL_DECISION
    # Nothing enforces the pairing: a document may be argued as a research result.
    case = _builder(case_type=CaseType.RESEARCH_RESULT,
                    subject=AssuranceSubject.from_text("x", SubjectType.DOCUMENT, "publish")).build()
    assert case.case_type is CaseType.RESEARCH_RESULT


# ── absent is not empty (Invariants 3 and 14) ───────────────────────────────

def test_an_unsupplied_collection_is_absent_not_empty():
    case = _builder().build()
    execs = case.collection("executions")
    assert execs.presence is Presence.ABSENT
    assert execs.total_count == 0
    assert "executions" in case.absent_collections


def test_a_supplied_but_empty_collection_is_present():
    # "We looked and found none" is a finding; "nobody supplied this" is a gap.
    b = _builder()
    b.declare_present("contradictions", "adversarial review ran; no contradictions found")
    case = b.build()
    coll = case.collection("contradictions")
    assert coll.presence is Presence.PRESENT
    assert coll.total_count == 0
    assert "contradictions" not in case.absent_collections
    assert coll.notes


def test_absent_and_empty_have_different_evidence_digests():
    plain = _builder().build()
    declared = _builder()
    declared.declare_present("contradictions")
    assert plain.evidence_digest != declared.build().evidence_digest


def test_asking_for_an_unpopulated_collection_returns_a_collection():
    # Not None, not an exception: callers must get an explicit "not supplied".
    case = _builder().build()
    for kind in COLLECTION_KINDS:
        assert case.collection(kind).kind == kind
    with pytest.raises(KeyError):
        case.collection("nonsense")


# ── scale: counted is not dropped ───────────────────────────────────────────

def test_records_can_be_counted_without_being_materialised():
    b = _builder()
    for i in range(1000):
        b.add("executions", _rec("execution", i, step=i), materialise=(i < 10))
    case = b.build()
    execs = case.collection("executions")
    assert execs.total_count == 1000
    assert execs.held_count == 10
    assert execs.not_materialised == 990
    assert execs.is_complete_in_memory is False
    assert execs.basis is MaterialisationBasis.CAPPED


def test_a_collection_that_dropped_records_cannot_call_itself_complete():
    b = RecordCollectionBuilder("executions", basis=MaterialisationBasis.COMPLETE)
    b.add(_rec("execution", 1), materialise=False)
    assert b.build().basis is not MaterialisationBasis.COMPLETE


def test_the_commitment_covers_records_that_were_never_held():
    # The point of the fold: a case digest stays a statement about the whole
    # collection even when almost none of it is in memory.
    def case_with(payload_of_990):
        b = _builder()
        for i in range(1000):
            rec = _rec("execution", i, step=(payload_of_990 if i == 990 else i))
            b.add("executions", rec, materialise=(i < 10))
        return b.build()

    a, c = case_with(990), case_with("tampered")
    assert a.collection("executions").held_count == c.collection("executions").held_count == 10
    assert a.evidence_digest != c.evidence_digest


def test_ingest_order_does_not_change_the_case():
    records = [_rec("evidence", i, value=i) for i in range(200)]
    first, second = _builder(), _builder()
    first.extend("evidence", records)
    second.extend("evidence", list(reversed(records)))
    assert first.build().evidence_digest == second.build().evidence_digest


def test_partial_folds_from_separate_shards_merge_to_the_same_commitment():
    records = [_rec("evidence", i, value=i) for i in range(100)]
    whole = RecordCollectionBuilder("evidence")
    whole.extend(records)

    left, right = RecordCollectionBuilder("evidence"), RecordCollectionBuilder("evidence")
    left.extend(records[:40])
    right.extend(records[40:])
    merged = left.merge(right)
    assert merged.build().fold_digest == whole.build().fold_digest


def test_a_merge_that_repeats_a_record_is_refused():
    a, b = RecordCollectionBuilder("evidence"), RecordCollectionBuilder("evidence")
    a.add(_rec("evidence", 1))
    b.add(_rec("evidence", 1))
    with pytest.raises(RecordError, match="both folds"):
        a.merge(b)


def test_duplicate_ids_within_a_collection_are_refused():
    b = _builder()
    b.add("evidence", _rec("evidence", 1))
    with pytest.raises(RecordError, match="duplicate record_id"):
        b.add("evidence", _rec("evidence", 1))


def test_a_collection_states_the_uniqueness_it_actually_guarantees():
    # At frontier scale a caller turns id tracking off. The collection must then
    # say so rather than imply a guarantee it is no longer providing.
    b = _builder()
    b.collection("executions", track_ids=False)
    for i in range(50):
        b.add("executions", _rec("execution", i), materialise=False)
    coll = b.build().collection("executions")
    assert coll.dedupe_basis is DedupeBasis.MATERIALISED_ONLY


def test_len_reports_what_is_held_not_what_exists():
    # len() must never report a number the collection cannot produce records for.
    b = _builder()
    for i in range(500):
        b.add("evidence", _rec("evidence", i), materialise=(i < 3))
    coll = b.build().collection("evidence")
    assert len(coll) == 3
    assert coll.total_count == 500
    assert len(list(coll)) == 3


def test_a_large_case_is_inspectable_without_loading_records():
    b = _builder()
    for i in range(5000):
        b.add("executions", _rec("execution", i), materialise=False)
    b.add("coverage", _rec("coverage", 1, dimension="execution", status="OBSERVED",
                           note="5,000 nodes counted; 0 materialised"))
    case = b.build()
    summary = case.summary()
    assert summary["total_records"] == 5001
    assert summary["materialised_records"] == 1
    assert summary["collections"]["executions"]["not_materialised"] == 5000
    # No record bodies anywhere in the summary — that is what makes a case of
    # this size readable at all.
    assert all("records" not in c for c in summary["collections"].values())


# ── identity, versions and digests ──────────────────────────────────────────

def test_case_id_is_the_question_and_survives_new_evidence():
    bare = _builder().build()
    with_evidence = _builder()
    with_evidence.add("evidence", _rec("evidence", 1))
    assert with_evidence.build().case_id == bare.case_id
    assert with_evidence.build().case_digest != bare.case_digest


def test_a_different_subject_is_a_different_case():
    a = _builder().build()
    b = _builder(subject=_subject("DROP TABLE orders;")).build()
    assert a.case_id != b.case_id


def test_case_digest_ignores_wall_clock():
    a = _builder().build(created_at="2026-09-12T09:00:00Z", updated_at="2026-09-12T09:00:00Z")
    b = _builder().build(created_at="2026-09-13T23:00:00Z", updated_at="2026-09-13T23:59:00Z")
    assert a.case_digest == b.case_digest


def test_methodology_travels_inside_the_case_digest():
    # Tightening a methodology must invalidate prior approvals, not silently re-grade.
    v1 = _builder(methodology=MethodologyRef("production-database-change", "1.0.0")).build()
    v2 = _builder(methodology=MethodologyRef("production-database-change", "2.0.0")).build()
    assert v1.case_digest != v2.case_digest
    assert v1.summary()["methodology"] == "production-database-change@1.0.0"


def test_a_case_without_a_methodology_says_none_rather_than_guessing():
    assert _builder().build().summary()["methodology"] == "NONE"


def test_subject_digest_is_the_subject_state_digest():
    subject = _subject()
    assert _builder(subject=subject).build().subject_digest == subject.state_digest


def test_evidence_digest_covers_only_evidentiary_collections():
    base = _builder().build()
    with_attention = _builder()
    with_attention.add("attention_items", _rec("attention", 1, why="load-bearing assumption"))
    # Attention items are derived output, not evidence: they change the case
    # state but not the evidentiary state.
    assert with_attention.build().evidence_digest == base.evidence_digest
    assert with_attention.build().case_digest != base.case_digest
    assert "coverage" not in EVIDENCE_KINDS


# ── lifecycle ───────────────────────────────────────────────────────────────

def test_a_draft_case_cannot_carry_a_verdict():
    with pytest.raises(CaseStateError, match="SEALED"):
        _builder().build().render_verdict(_verdict())


def test_a_verdict_requires_coverage():
    # Invariant 9, made structural: there is no code path to a verdict without
    # a statement of what was and was not assessed.
    sealed = _builder().build().seal()
    with pytest.raises(CaseValidationError, match="Invariant 9"):
        sealed.render_verdict(_verdict())


def test_a_sealed_case_with_coverage_can_be_decided():
    case = _coverage_case().render_verdict(_verdict(Decision.HOLD))
    assert case.verdict.decision is Decision.HOLD
    assert case.verdict.fired_rules == ("RG-DECIDE-014",)


def test_a_verdict_must_name_the_rules_that_produced_it():
    with pytest.raises(CaseValidationError, match="unattributed"):
        CaseVerdict(decision=Decision.PROMOTE, fired_rules=[])


def test_a_case_cannot_return_to_draft():
    sealed = _coverage_case()
    with pytest.raises(CaseStateError, match="cannot move a SEALED case to DRAFT"):
        sealed._transition(CaseState.DRAFT)


def test_approval_requires_a_verdict_first():
    sealed = _coverage_case()
    with pytest.raises(CaseStateError, match="before a verdict"):
        sealed.with_approval(_rec("approval", 1, approver="alice"))


def test_approval_moves_the_case_to_approved():
    case = _coverage_case().render_verdict(_verdict(Decision.PROMOTE))
    approved = case.with_approval(_rec("approval", 1, approver="alice"))
    assert approved.state is CaseState.APPROVED
    assert approved.collection("approvals").total_count == 1


def test_approvals_stay_outside_the_case_digest():
    # An approval binds TO the case digest; folding it back in would make the
    # digest depend on the thing that depends on it.
    case = _coverage_case().render_verdict(_verdict(Decision.PROMOTE))
    approved = case.with_approval(_rec("approval", 1, approver="alice"))
    assert approved.case_digest == case.case_digest


def test_a_second_approval_does_not_re_transition():
    case = _coverage_case().render_verdict(_verdict(Decision.PROMOTE))
    two = (case.with_approval(_rec("approval", 1, approver="alice"))
               .with_approval(_rec("approval", 2, approver="bob")))
    assert two.state is CaseState.APPROVED
    assert two.collection("approvals").total_count == 2


def test_an_invalidated_case_is_terminal_and_records_why():
    dead = _coverage_case().invalidate("subject digest no longer matches the artifact")
    assert dead.state is CaseState.INVALIDATED
    assert "no longer matches" in dead.metadata["invalidation_reason"]
    with pytest.raises(CaseStateError):
        dead.seal()
    with pytest.raises(CaseStateError):
        dead.supersede()


def test_a_revision_opens_as_a_draft_and_drops_approvals():
    approved = (_coverage_case().render_verdict(_verdict(Decision.PROMOTE))
                .with_approval(_rec("approval", 1, approver="alice")))
    v2 = approved.revise()
    assert v2.state is CaseState.DRAFT
    assert v2.case_version == 2
    assert v2.verdict is None
    assert v2.supersedes == f"{approved.case_id}@v1"
    assert v2.collection("approvals").presence is Presence.ABSENT
    # Same question, different argument.
    assert v2.case_id == approved.case_id
    assert v2.case_digest != approved.case_digest


def test_version_one_cannot_claim_to_supersede_anything():
    with pytest.raises(CaseValidationError, match="at least version 2"):
        _builder().build(supersedes="case_abc@v1")


# ── serialisation and tamper detection ──────────────────────────────────────

def test_round_trip_preserves_every_digest():
    b = _builder(methodology=MethodologyRef("general-agent-action", "1.0.0"))
    b.add("evidence", _rec("evidence", 1, summary="dry run clean"))
    b.add("coverage", _rec("coverage", 1, dimension="staging", status="OBSERVED"))
    b.add("executions", _rec("execution", 1), materialise=False)
    case = b.build().seal().render_verdict(_verdict())

    back = AssuranceCase.from_dict(json.loads(json.dumps(case.to_dict())))
    assert back.case_id == case.case_id
    assert back.subject_digest == case.subject_digest
    assert back.evidence_digest == case.evidence_digest
    assert back.case_digest == case.case_digest
    assert back.state is CaseState.SEALED
    assert back.verdict.decision is case.verdict.decision
    assert back.collection("executions").not_materialised == 1


def test_an_edited_case_is_rejected_rather_than_repaired():
    case = _coverage_case()
    tampered = case.to_dict()
    tampered["objective"] = "something else entirely"
    with pytest.raises(CaseIntegrityError, match="modified after it was written"):
        AssuranceCase.from_dict(tampered)


def test_a_record_removed_after_the_fact_is_detected():
    b = _builder()
    b.add("evidence", _rec("evidence", 1, finding="counterexample found"))
    b.add("evidence", _rec("evidence", 2, finding="dry run clean"))
    case = b.build()
    tampered = case.to_dict()
    tampered["collections"]["evidence"]["records"] = [
        r for r in tampered["collections"]["evidence"]["records"]
        if r["record_id"] != "evidence_1"]
    tampered["collections"]["evidence"]["total_count"] = 1
    with pytest.raises(CaseIntegrityError):
        AssuranceCase.from_dict(tampered)


def test_a_summary_only_export_still_carries_the_commitments():
    b = _builder()
    b.add("coverage", _rec("coverage", 1, dimension="x", status="OBSERVED"))
    for i in range(20):
        b.add("evidence", _rec("evidence", i))
    case = b.build()
    slim = case.to_dict(include_records=False)
    assert all("records" not in c for c in slim["collections"].values())
    assert slim["evidence_digest"] == case.evidence_digest
    assert slim["collections"]["evidence"]["total_count"] == 20


# ── records ─────────────────────────────────────────────────────────────────

def test_a_record_needs_an_id_and_a_type():
    class Nameless:
        record_id = ""
        record_type = "evidence"

        def to_dict(self):
            return {}

    with pytest.raises(RecordError, match="record_id"):
        _builder().add("evidence", Nameless())


def test_a_record_must_be_canonically_serialisable():
    class Awkward:
        record_id = "ev_1"
        record_type = "evidence"

        def to_dict(self):
            return {"value": object()}

    with pytest.raises(RecordError, match="not canonically serialisable"):
        _builder().add("evidence", Awkward())


def test_a_collection_cannot_be_filed_under_the_wrong_kind():
    built = RecordCollectionBuilder("claims").declare_present().build()
    with pytest.raises(CaseValidationError, match="declares itself"):
        AssuranceCase(case_type=CaseType.DATA_CHANGE, objective=OBJECTIVE,
                      requested_decision=DECISION, subject=_subject(),
                      collections={"evidence": built})


def test_a_collection_cannot_hold_more_than_it_has_seen():
    from release_gate.assurance.records import RecordCollection
    with pytest.raises(RecordError, match="below the"):
        RecordCollection(kind="evidence", presence=Presence.PRESENT,
                         materialised=(_rec("evidence", 1),), total_count=0)


def test_records_are_never_silently_reordered_within_a_collection():
    records = [_rec("claim", i) for i in range(5)]
    b = _builder()
    b.extend("claims", records)
    held = b.build().records("claims")
    assert [r.record_id for r in held] == [r.record_id for r in records]


def test_case_metadata_is_frozen_all_the_way_down():
    # A mutable nested value would let a caller change what the human saw while
    # case_digest went on saying otherwise.
    case = _builder(metadata={"ticket": "OPS-1", "ctx": {"env": "prod"}}).build()
    with pytest.raises(Exception):
        case.metadata["ctx"]["env"] = "staging"


def test_rewording_a_verdict_changes_what_was_approved():
    # The stated reasons are what a person relied on, so they are inside the digest.
    base = _coverage_case()
    a = base.render_verdict(CaseVerdict(decision=Decision.HOLD, fired_rules=["RG-DECIDE-014"],
                                        reasons=["No rollback path."]))
    b = base.render_verdict(CaseVerdict(decision=Decision.HOLD, fired_rules=["RG-DECIDE-014"],
                                        reasons=["Rollback is fine actually."]))
    assert a.case_digest != b.case_digest


def test_when_the_engine_ran_is_not_part_of_the_decision():
    base = _coverage_case()
    a = base.render_verdict(CaseVerdict(decision=Decision.HOLD, fired_rules=["RG-DECIDE-014"],
                                        decided_at="2026-09-12T09:00:00Z"))
    b = base.render_verdict(CaseVerdict(decision=Decision.HOLD, fired_rules=["RG-DECIDE-014"],
                                        decided_at="2026-09-13T23:00:00Z"))
    assert a.case_digest == b.case_digest


def test_a_case_can_ask_whether_its_subject_still_matches(tmp_path):
    path = tmp_path / "plan.tf"
    path.write_text("resource a {}", encoding="utf-8")
    subject = AssuranceSubject.from_file(path, SubjectType.INFRASTRUCTURE_CHANGE,
                                         "apply this plan to prod")
    case = _builder(case_type=CaseType.INFRASTRUCTURE_CHANGE, subject=subject).build()
    assert case.check_subject().unchanged is True

    path.write_text("resource a {}\nresource evil {}", encoding="utf-8")
    check = case.check_subject()
    assert check.unchanged is False
    # Acting on it stays the caller's decision; the case only reports.
    assert case.state is CaseState.DRAFT
    assert case.invalidate(check.detail).state is CaseState.INVALIDATED
