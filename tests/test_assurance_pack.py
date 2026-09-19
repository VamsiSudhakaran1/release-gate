"""Assurance Evidence Pack v3: what was decided, on what, and is this still that.

Four properties carry this file.

Every one of the twenty-four fields is present or explicitly accounted for — a
pack missing a section is refused at construction, because a section that is
simply not there reads as one that was fine.

Absent, empty and not-assessed stay three different answers. A bare case
produces a pack that is mostly ABSENT with a stated reason each time, not one
that is mostly empty and looks thorough.

The digest covers what it appears to. Tampering with any section is detected,
building the same pack twice gives one digest, and `built_at` is excluded so two
parties can show they hold the same artefact.

And the pack never carries raw evidence. A case with five thousand records and
one with ten produce packs of the same order, because what travels is digests
and handles.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.completeness import SourceStream, StreamLedger
from release_gate.assurance.methodologies import SOFTWARE_AGENT_ASSURANCE_V1 as SW
from release_gate.assurance.pack import (
    PACK_SCHEMA_VERSION, SECTION_KEYS, AssuranceEvidencePack, ExternalReference,
    PackError, PackSection, SectionState, build_pack, verify_pack)
from release_gate.assurance.session import AssuranceSession

DIGEST = "sha256:" + "bb" * 32

RICH = [
    {"record_type": "artifact", "artifact_id": "payments", "kind": "CODE",
     "digest": DIGEST, "producer": {"producer_id": "agent://c/1", "kind": "agent"}},
    {"record_type": "claim", "claim_id": "c1",
     "proposition": "the refund path cannot double-charge",
     "producer": {"producer_id": "agent://c/1", "kind": "agent"},
     "supporting_evidence": ["e1"], "contradicting_evidence": ["e2"]},
    {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://pytest", "kind": "tool"},
     "supports_claims": ["c1"], "applies_to_digest": DIGEST,
     "coverage_note": "suite green"},
    {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
     "producer": {"producer_id": "agent://c/1", "kind": "agent"},
     "contradicts_claims": ["c1"], "coverage_note": "double-fires under retry"},
    {"record_type": "counterexample", "target_claim": "c1", "result": "FOUND",
     "method": "PROPERTY_TEST", "detail": "refund fires twice",
     "producer": {"producer_id": "agent://fuzz", "kind": "agent"}},
    {"record_type": "consequence", "REVERSIBILITY": "IRREVERSIBLE",
     "SCOPE": "MULTI_SUBJECT", "FINANCIAL_IMPACT": "MATERIAL",
     "DATA_IMPACT": "WRITE", "SECURITY_IMPACT": "NONE", "LEGAL_IMPACT": "NONE"},
]


def outcome_for(records, methodology=SW):
    return AssuranceSession.open(methodology=methodology).extend(
        list(records)).finalize()


@pytest.fixture
def pack():
    return build_pack(outcome_for(RICH))


# ── the twenty-four fields ──────────────────────────────────────────────────

def test_the_pack_answers_every_section(pack):
    assert {s.key for s in pack.sections} == set(SECTION_KEYS)


def test_a_pack_missing_a_section_is_refused(pack):
    with pytest.raises(PackError, match="must account for every section"):
        AssuranceEvidencePack(
            case_id="c", case_version=1, case_digest="d", objective="o",
            requested_authorization="a",
            sections=tuple(s for s in pack.sections if s.key != "verdict"))


def test_case_identity_version_and_objective_travel(pack):
    outcome = outcome_for(RICH)
    assert pack.case_id == outcome.case.case_id
    assert pack.case_version == outcome.case.case_version
    assert pack.case_digest == outcome.case.case_digest
    assert pack.objective == outcome.case.objective
    assert pack.requested_authorization == outcome.case.requested_decision


def test_the_methodology_travels_with_a_readable_ref_and_a_digest(pack):
    """`ref` is a property and absent from MethodologyRef.to_dict, so an auditor
    reading the JSON would have to concatenate two fields to learn which
    methodology decided this."""
    assert pack.methodology["ref"] == SW.ref_string
    assert pack.methodology["digest"] == SW.digest


def test_both_subject_digests_travel_and_are_distinguishable(pack):
    """Identity and what-the-human-saw are two digests, not one.

    `subject_digest` is content identity; `subject_state_digest` is identity plus
    metadata and the only thing an approval binds to. Carrying one and calling it
    "the subject digest" is a mistake this codebase has already made once.
    """
    assert pack.subject_id
    assert pack.subject_digest
    assert pack.subject_state_digest
    assert pack.subject_digest != pack.subject_state_digest

    outcome = outcome_for(RICH)
    binding = outcome.case.binding_state()["state"]["subject_state"]
    assert pack.subject_state_digest == binding["state_digest"]


def test_the_engine_version_schema_and_timestamps_travel(pack):
    assert pack.schema_version == PACK_SCHEMA_VERSION == 3
    assert pack.engine_version
    assert pack.built_at
    assert pack.case_created_at


def test_the_verdict_travels_with_its_fired_rules(pack):
    verdict = pack.verdict
    assert verdict["decision"] == pack.decision
    assert verdict["fired_rules"], "a verdict without its rules is unattributed"
    assert verdict["reasons"]


@pytest.mark.parametrize("key", [
    "claim_graph", "artifact_manifest", "critical_claims", "assumptions",
    "verification", "replications", "counterexamples", "contradictions",
    "coverage", "human_attention", "required_evidence", "verdict"])
def test_each_derived_section_is_present_and_digested_on_a_rich_case(pack, key):
    section = pack.section(key)
    assert section.state is SectionState.PRESENT, section.note
    assert section.digest


def test_the_artifact_manifest_lists_handles_and_digests(pack):
    section = pack.section("artifact_manifest")
    manifest = section.summary["artifacts"]
    assert any(row["logical_id"] == "payments" and row["digest"] == DIGEST
               for row in manifest)


def test_required_evidence_states_it_does_not_satisfy_the_decision(pack):
    assert pack.section("required_evidence").summary["satisfies_decision"] is False


# ── absent, empty and not-assessed are three answers ────────────────────────

def test_a_bare_case_is_mostly_absent_with_a_reason_each_time():
    """Not mostly empty. A pack that looks thorough over a case that is not is
    the failure mode this whole artefact exists to prevent."""
    pack = build_pack(outcome_for([]))
    assert len(pack.absent_sections) + len(pack.unassessed_sections) >= 4
    for section in pack.absent_sections + pack.unassessed_sections:
        assert section.note, f"{section.key} is absent without saying why"


def test_an_absent_section_must_explain_itself():
    with pytest.raises(PackError, match="must say why"):
        PackSection(key="claim_graph", state=SectionState.ABSENT)


def test_a_present_section_must_carry_a_digest():
    with pytest.raises(PackError, match="must carry a digest"):
        PackSection(key="claim_graph", state=SectionState.PRESENT)


def test_no_execution_telemetry_is_absent_not_a_record_of_nothing_happening(pack):
    section = pack.section("execution_graph")
    assert section.state is SectionState.ABSENT
    assert "not a record of nothing happening" in section.note


def test_the_evidence_graph_absence_names_the_true_reason(pack):
    """Not a plausible one.

    `AnalysisResult` declares this field and nothing populates it, so it is None
    for every case. Saying "this case carries no evidence-to-evidence relations"
    would be a statement about the case that is not so — the kind of confident
    wrong answer a pack must never hand an auditor.
    """
    section = pack.section("evidence_graph")
    assert section.state is SectionState.ABSENT
    assert "nothing populates that component today" in section.note
    assert "says nothing about whether such relations exist" in section.note


def test_completeness_is_not_assessed_without_a_ledger_and_present_with_one(pack):
    """`AnalysisResult` has no completeness field; it is caller-supplied, the same
    way `facts_for()` takes it. Reading it off the analysis would leave this
    permanently NOT_ASSESSED with nothing to say it was unreachable."""
    assert pack.section("completeness").state is SectionState.NOT_ASSESSED

    ledger = StreamLedger(
        streams=(SourceStream(stream_id="s", producer_id="agent://7",
                              observed_sequences=(1, 2, 3)),),
        expected_streams=("s",), enumeration_independent=True)
    with_ledger = build_pack(outcome_for(RICH), completeness=ledger)
    assert with_ledger.section("completeness").state is SectionState.PRESENT


def test_an_approval_collection_that_was_never_supplied_is_not_assessed(pack):
    """Different from a case nobody has approved: only the second is a fact about
    the decision."""
    section = pack.section("approval_state")
    assert section.state is SectionState.NOT_ASSESSED
    assert "was not asked here" in section.note


# ── the digest covers what it appears to ────────────────────────────────────

def test_building_the_same_pack_twice_gives_one_digest():
    outcome = outcome_for(RICH)
    assert build_pack(outcome).pack_digest == build_pack(outcome).pack_digest


def test_built_at_is_excluded_from_the_digest(pack):
    """Two parties holding the same artefact must be able to show that."""
    assert "built_at" not in pack.content()
    assert pack.built_at in pack.to_dict()["built_at"]


def test_a_different_case_gives_a_different_pack_digest(pack):
    other = build_pack(outcome_for(RICH + [
        {"record_type": "evidence", "evidence_id": "e9", "kind": "OBSERVATION",
         "producer": {"producer_id": "agent://z", "kind": "agent"},
         "coverage_note": "one more"}]))
    assert other.pack_digest != pack.pack_digest


def test_a_clean_pack_verifies(pack):
    report = verify_pack(pack)
    assert report["intact"] and report["digest_matches"]
    assert not report["missing_sections"]


def test_verification_survives_a_json_round_trip(pack):
    assert verify_pack(json.loads(json.dumps(pack.to_dict())))["intact"]


@pytest.mark.parametrize("key", ["claim_graph", "verdict", "artifact_manifest"])
def test_tampering_with_a_section_digest_is_detected(pack, key):
    payload = json.loads(json.dumps(pack.to_dict()))
    for section in payload["sections"]:
        if section["key"] == key:
            section["digest"] = "sha256:" + "00" * 32
    assert not verify_pack(payload)["digest_matches"]


def test_tampering_with_the_verdict_is_detected(pack):
    payload = json.loads(json.dumps(pack.to_dict()))
    for section in payload["sections"]:
        if section["key"] == "verdict":
            section["summary"]["decision"] = "PROMOTE"
    assert not verify_pack(payload)["digest_matches"]


def test_verification_states_what_it_does_not_establish(pack):
    report = verify_pack(pack)
    assert any("signature" in claim for claim in report["does_not_establish"])
    assert any("correct" in claim for claim in report["does_not_establish"])


def test_an_expected_digest_can_be_checked(pack):
    assert verify_pack(pack, expected_digest=pack.pack_digest)["matches_expected"]
    assert not verify_pack(pack, expected_digest="sha256:" + "11" * 32
                           )["matches_expected"]


# ── raw evidence is referenced, never carried ───────────────────────────────

EXTERNAL = [
    {"record_type": "claim", "claim_id": "c1", "proposition": "the run is clean",
     "producer": {"producer_id": "a://1", "kind": "agent"},
     "supporting_evidence": ["e1"]},
    {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
     "producer": {"producer_id": "otel://collector", "kind": "tool"},
     "supports_claims": ["c1"], "digest": "sha256:" + "ab" * 32,
     "content_reference": {"kind": "OBJECT_STORE",
                           "locator": "s3://traces/run-8812.parquet",
                           "detail": {"byte_length": 4_100_000_000}},
     "coverage_note": "4.1M spans"},
]


def test_externally_held_evidence_becomes_a_resolvable_handle():
    pack = build_pack(outcome_for(EXTERNAL))
    references = [r for r in pack.external_references
                  if r.locator.startswith("s3://")]
    assert references, "a producer's content reference did not reach the pack"
    reference = references[0]
    assert reference.kind == "OBJECT_STORE"
    assert reference.resolvable, "a locator without a digest cannot be checked"
    assert reference.byte_length == 4_100_000_000


def test_a_reference_without_a_digest_says_it_is_not_resolvable():
    pack = build_pack(outcome_for([
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
         "producer": {"producer_id": "otel://c", "kind": "tool"},
         "content_reference": {"kind": "URL", "locator": "https://ci/logs/1"},
         "coverage_note": "no digest"}]))
    reference = next(r for r in pack.external_references
                     if r.locator.startswith("https://"))
    assert not reference.resolvable


def test_an_unknown_reference_kind_keeps_the_locator_and_is_noted():
    outcome = outcome_for([
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
         "producer": {"producer_id": "otel://c", "kind": "tool"},
         "content_reference": {"kind": "WORMHOLE", "locator": "weird://x"},
         "coverage_note": "odd"}])
    pack = build_pack(outcome)
    assert any(r.locator == "weird://x" and r.kind == "EXTERNAL"
               for r in pack.external_references)
    assert any("not one release-gate models" in note
               for note in outcome.normalisation.notes)


def test_a_malformed_declared_digest_keeps_the_reference_and_drops_the_digest():
    outcome = outcome_for([
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
         "producer": {"producer_id": "otel://c", "kind": "tool"},
         "content_reference": {"kind": "URL", "locator": "https://ci/logs/1"},
         "digest": "not-a-digest", "coverage_note": "bad digest"}])
    pack = build_pack(outcome)
    reference = next(r for r in pack.external_references
                     if r.locator == "https://ci/logs/1")
    assert not reference.resolvable
    assert any("not a sha256 content digest" in note
               for note in outcome.normalisation.notes)


def test_a_reference_that_points_nowhere_is_refused():
    with pytest.raises(PackError, match="points nowhere"):
        ExternalReference(record_id="e1", kind="URL", locator="")


def test_the_pack_does_not_grow_with_the_evidence_it_describes():
    """Ten records and five thousand produce packs of the same order, because
    what travels is digests and handles."""
    def size(n):
        records = [{"record_type": "claim", "claim_id": "c1", "proposition": "p",
                    "producer": {"producer_id": "a://1", "kind": "agent"}}]
        records += [{"record_type": "evidence", "evidence_id": f"e{i}",
                     "kind": "OBSERVATION",
                     "producer": {"producer_id": f"a://{i % 50}", "kind": "agent"},
                     "supports_claims": ["c1"], "coverage_note": f"row {i}"}
                    for i in range(n)]
        return len(json.dumps(build_pack(outcome_for(records)).to_dict()))

    small, large = size(10), size(2000)
    assert large < small * 2, (
        f"{small} bytes for 10 records, {large} for 2000 — the pack is carrying "
        "evidence rather than describing it")


def test_the_pack_says_it_carries_no_raw_evidence(pack):
    assert pack.to_dict()["carries_raw_evidence"] is False


# ── a pack is not an approval ───────────────────────────────────────────────

def test_a_pack_never_authorises(pack):
    assert pack.authorises is False
    assert pack.establishes_truth is False
    assert pack.bounds_completeness is False
    payload = pack.to_dict()
    assert payload["authorises"] is False
    assert payload["establishes_truth"] is False


def test_the_render_says_so_in_words(pack):
    assert "It is not one" in pack.render()


def test_every_section_refuses_to_bound_completeness(pack):
    for section in pack.sections:
        assert section.to_dict()["bounds_completeness"] is False


def test_a_section_says_whether_its_digest_was_folded_or_recomputed(pack):
    """A folded digest commits to what the component decided its identity was; a
    serialised one commits to this pack's view of it. An auditor comparing two
    packs should be able to see which they have."""
    assert pack.section("claim_graph").summary["digest_source"] == "component"

    ledger = StreamLedger(
        streams=(SourceStream(stream_id="s", producer_id="agent://7",
                              observed_sequences=(1, 2, 3)),),
        expected_streams=("s",), enumeration_independent=True)
    with_ledger = build_pack(outcome_for(RICH), completeness=ledger)
    section = with_ledger.section("completeness")
    assert section.state is SectionState.PRESENT
    assert section.summary["digest_source"] == "serialised"
