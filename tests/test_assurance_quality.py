"""Evidence quality as facts, and the absence of a score.

Two things carry this file. Every fact must reach all of its states on real
cases — a fact that can only ever answer NOT_ASSESSED is a dead branch that
reads like diligence, and this codebase has shipped that defect before from a
mistyped lookup. And there must be no number: not in the public surface, not in
`to_dict()`, and not reconstructible by counting polarities, because a score
assembled by addition is still a score.

The third thread is the model seam. A model may classify evidence; its output is
DERIVED and stays there, and no argument to the constructor can move it.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.case import (
    AssuranceCaseBuilder, CaseType, declared_digests, held_digests)
from release_gate.assurance.completeness import SourceStream, StreamLedger
from release_gate.assurance.evidence import (
    EpistemicStatus, EvidenceRecord, EvidenceType, Producer, ProducerKind,
    TrustDecision, TrustStatus)
from release_gate.assurance.methodologies import SOFTWARE_AGENT_ASSURANCE_V1 as SW
from release_gate.assurance.quality import (
    EvidenceFact, FactFinding, FactPolarity, FactSheet, FactState, QualityError,
    facts_for, model_assisted_evidence, sheets_for_case)
from release_gate.assurance.session import AssuranceSession
from release_gate.assurance.subject import (
    AssuranceSubject, ContentReference, DigestMethod, DigestStatus, ReferenceKind,
    SubjectType)

DIGEST = "sha256:" + "cc" * 32
OTHER = "sha256:" + "dd" * 32

CLAIM = {"record_type": "claim", "claim_id": "c1",
         "proposition": "the refund path cannot double-charge",
         "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
         "supporting_evidence": ["e1"]}
EVIDENCE = {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
            "producer": {"producer_id": "ci://pytest", "kind": "tool"},
            "supports_claims": ["c1"], "coverage_note": "suite green"}
ARTIFACT = {"record_type": "artifact", "artifact_id": "payments", "kind": "CODE",
            "digest": DIGEST,
            "producer": {"producer_id": "agent://coder/1", "kind": "agent"}}


def assure(records):
    return AssuranceSession.open(methodology=SW).extend(list(records)).finalize()


def state(records, fact, subject="claim:c1", **kwargs):
    outcome = assure(records)
    sheet = facts_for(subject, case=outcome.case, analysis=outcome.analysis, **kwargs)
    finding = sheet.finding(fact)
    assert finding is not None, f"{fact} is missing from the sheet entirely"
    return finding


# ── the refusals ────────────────────────────────────────────────────────────

def test_a_sheet_refuses_to_be_a_grade():
    sheet = facts_for("case", case=assure([CLAIM, EVIDENCE]).case)
    assert sheet.establishes_quality is False
    assert sheet.ranks_evidence is False
    assert sheet.combines_into_a_score is False


def test_the_serialised_form_states_the_absence_of_a_score():
    """Stated, not merely missing — a consumer looking for a number must find a
    refusal rather than a gap it might fill in itself."""
    payload = facts_for("case", case=assure([CLAIM, EVIDENCE]).case).to_dict()
    assert payload["score"] is None
    assert payload["grade"] is None
    assert payload["composite_score"] is None
    assert payload["establishes_quality"] is False


def test_no_public_value_is_a_number_that_could_be_read_as_a_grade():
    outcome = assure([ARTIFACT, CLAIM, EVIDENCE])
    sheet = facts_for("case", case=outcome.case, analysis=outcome.analysis)
    payload = sheet.to_dict()
    numeric = {k: v for k, v in payload.items()
               if isinstance(v, (int, float)) and not isinstance(v, bool)}
    # schema_version is the only number, and it is a version.
    assert set(numeric) == {"schema_version"}
    for attribute in dir(sheet):
        if attribute.startswith("_"):
            continue
        value = getattr(sheet, attribute)
        assert not isinstance(value, float), (
            f"{attribute} is a float; the one thing this module must not grow")


def test_polarities_are_not_a_hidden_tally():
    """Grouping is presentation. If holding facts were weighed, a case with many
    weak supporting facts would outrank one with a single fatal finding."""
    outcome = assure([ARTIFACT, CLAIM, EVIDENCE])
    sheet = facts_for("case", case=outcome.case, analysis=outcome.analysis)
    assert isinstance(sheet.standing_behind, tuple)
    assert isinstance(sheet.standing_against, tuple)
    assert not hasattr(sheet, "net"), "a net of the two would be the score again"
    assert not hasattr(sheet, "balance")
    assert not hasattr(sheet, "total")


def test_two_sheets_are_not_comparable():
    thin = facts_for("case", case=assure([CLAIM, EVIDENCE]).case)
    rich = facts_for("case", case=assure([ARTIFACT, CLAIM, EVIDENCE]).case)
    with pytest.raises(TypeError):
        thin < rich          # noqa: B015 — asserting the ordering does not exist


# ── every fact reaches its states ───────────────────────────────────────────

def test_provenance_available_holds_and_fails():
    assert state([ARTIFACT, CLAIM, EVIDENCE],
                 EvidenceFact.PROVENANCE_AVAILABLE).state is FactState.HOLDS


def test_provenance_ignores_release_gates_own_derived_records():
    """The evidence collection also holds consequence and independence profiles.
    Counting those as producers with no provenance made most of a case read as
    unattributed — a finding about records that were never claiming one."""
    finding = state([ARTIFACT, CLAIM, EVIDENCE],
                    EvidenceFact.PROVENANCE_AVAILABLE, subject="case")
    assert finding.state is FactState.HOLDS


def test_digest_matches_distinguishes_bound_matched_and_unbound():
    bound = dict(EVIDENCE, applies_to_digest=DIGEST)
    assert state([ARTIFACT, CLAIM, bound],
                 EvidenceFact.DIGEST_MATCHES).state is FactState.HOLDS

    elsewhere = dict(EVIDENCE, applies_to_digest=OTHER)
    assert state([ARTIFACT, CLAIM, elsewhere],
                 EvidenceFact.DIGEST_MATCHES).state is FactState.DOES_NOT_HOLD

    assert state([ARTIFACT, CLAIM, EVIDENCE],
                 EvidenceFact.DIGEST_MATCHES).state is FactState.NOT_ASSESSED


def test_contradiction_unresolved_holds_when_one_is_open():
    records = [dict(CLAIM, contradicting_evidence=["e2"]), EVIDENCE,
               {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
                "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
                "contradicts_claims": ["c1"], "coverage_note": "double-fires"}]
    finding = state(records, EvidenceFact.CONTRADICTION_UNRESOLVED)
    assert finding.state is FactState.HOLDS
    assert finding.refs, "the contradiction should be named, not merely counted"


def test_contradiction_reads_target_claims_not_a_field_that_does_not_exist():
    """`participants` holds producer ids and there is no `claim_id`. Matching
    evidence ids against participants never fires, and every sheet comes back
    clean — the exact shape of a defect this codebase has had before."""
    records = [dict(CLAIM, contradicting_evidence=["e2"]), EVIDENCE,
               {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
                "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
                "contradicts_claims": ["c1"], "coverage_note": "double-fires"}]
    outcome = assure(records)
    contradiction = tuple(outcome.analysis.contradictions)[0]
    assert not hasattr(contradiction, "claim_id")
    assert contradiction.target_claims == ("c1",)
    assert all(p.startswith(("agent://", "ci://")) for p in contradiction.participants)


def test_an_empty_ledger_with_no_claim_graph_is_unassessed_not_clean():
    finding = state([EVIDENCE], EvidenceFact.CONTRADICTION_UNRESOLVED, subject="case")
    assert finding.state is FactState.NOT_ASSESSED
    assert "never ran" in finding.basis


def test_counterexample_unresolved_reaches_all_three_states():
    found = [CLAIM, EVIDENCE,
             {"record_type": "counterexample", "target_claim": "c1", "result": "FOUND",
              "method": "PROPERTY_TEST", "detail": "refund fires twice under retry",
              "producer": {"producer_id": "agent://fuzz", "kind": "agent"}}]
    finding = state(found, EvidenceFact.COUNTEREXAMPLE_UNRESOLVED)
    assert finding.state is FactState.HOLDS
    assert finding.refs and all(r.startswith("cex_") for r in finding.refs)

    searched = [CLAIM, EVIDENCE,
                {"record_type": "counterexample", "target_claim": "c1",
                 "result": "NOT_FOUND", "method": "PROPERTY_TEST",
                 "searched": "10k retry interleavings",
                 "producer": {"producer_id": "agent://fuzz", "kind": "agent"}}]
    finding = state(searched, EvidenceFact.COUNTEREXAMPLE_UNRESOLVED)
    assert finding.state is FactState.DOES_NOT_HOLD
    assert "not the same as none existing" in finding.basis

    assert state([CLAIM, EVIDENCE], EvidenceFact.COUNTEREXAMPLE_UNRESOLVED
                 ).state is FactState.NOT_ASSESSED


def test_formal_verifier_passed_holds_on_a_real_proof(tmp_path):
    import json
    from release_gate.assurance.zero_config import assure as zero_config_assure
    report = tmp_path / "proof.json"
    report.write_text(json.dumps({
        "verifier": {"name": "lean", "version": "4.8.0", "family": "PROOF_ASSISTANT"},
        "results": [{"target": "c1", "target_digest": DIGEST, "result": "proved",
                     "covers": ["the stated theorem"], "does_not_cover": ["meaning"]}]}))
    outcome = zero_config_assure(str(report), methodology=SW)
    finding = facts_for("case", case=outcome.case, analysis=outcome.analysis).finding(
        EvidenceFact.FORMAL_VERIFIER_PASSED)
    assert finding.state is FactState.HOLDS


def test_formal_verifier_compares_the_enum_not_a_string():
    """`VerificationStatus` is PASSED. A hand-written "PASS" matched nothing, and
    a passing theorem prover read as no formal verification at all."""
    from release_gate.assurance.verification import VerificationStatus
    assert VerificationStatus.PASSED.value == "PASSED"
    assert "PASS" not in {s.value for s in VerificationStatus}


def test_a_test_suite_is_not_a_formal_method():
    finding = state([ARTIFACT, CLAIM, EVIDENCE],
                    EvidenceFact.FORMAL_VERIFIER_PASSED, subject="case")
    assert finding.state is not FactState.HOLDS


def test_completeness_established_reaches_all_three_states():
    case = assure([CLAIM, EVIDENCE]).case
    complete = StreamLedger(
        streams=(SourceStream(stream_id="s", producer_id="agent://7",
                              observed_sequences=(1, 2, 3)),),
        expected_streams=("s",), enumeration_independent=True,
        enumeration_source="the orchestrator's manifest")
    assert facts_for("case", case=case, completeness=complete).state(
        EvidenceFact.COMPLETENESS_ESTABLISHED) is FactState.HOLDS

    gapped = StreamLedger(
        streams=(SourceStream(stream_id="s", producer_id="agent://7",
                              observed_sequences=(1, 2, 4)),),
        expected_streams=("s",), enumeration_independent=True)
    assert facts_for("case", case=case, completeness=gapped).state(
        EvidenceFact.COMPLETENESS_ESTABLISHED) is FactState.DOES_NOT_HOLD

    assert facts_for("case", case=case).state(
        EvidenceFact.COMPLETENESS_ESTABLISHED) is FactState.NOT_ASSESSED


def test_completeness_is_supplied_by_the_caller_not_read_off_the_analysis():
    """AnalysisResult has no completeness field; reading one would have made this
    fact permanently NOT_ASSESSED with nothing to say it was unreachable."""
    from release_gate.assurance.analysis import AnalysisResult
    assert not hasattr(AnalysisResult(), "completeness")


def _trust_sheet(trust):
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="ship",
        content_reference=ContentReference(kind=ReferenceKind.FILE, locator="p.py"),
        digest=DIGEST, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED, digest_basis="hashed here")
    builder = AssuranceCaseBuilder(case_type=CaseType.CODE_CHANGE, subject=subject,
                                   objective="o", requested_decision="ship")
    builder.add("evidence", EvidenceRecord.declared(
        EvidenceType.TEST_RESULT, source="ci",
        producer=Producer(producer_id="ci://pytest", kind=ProducerKind.TOOL),
        coverage_note="suite", trust=trust))
    return facts_for("case", case=builder.build())


def test_verifier_trusted_separates_ruled_against_from_nobody_ruled():
    """The distinction a score erases: NOT_ESTABLISHED would render as "low"
    alongside a source somebody actively rejected."""
    accepted = TrustDecision(status=TrustStatus.ACCEPTED, basis="on the allowlist",
                             decided_by="human://sec-lead")
    assert _trust_sheet(accepted).state(
        EvidenceFact.VERIFIER_TRUSTED) is FactState.HOLDS

    revoked = TrustDecision(status=TrustStatus.REVOKED, basis="key compromised",
                            decided_by="human://sec-lead")
    assert _trust_sheet(revoked).state(
        EvidenceFact.VERIFIER_TRUSTED) is FactState.DOES_NOT_HOLD

    assert _trust_sheet(None).state(
        EvidenceFact.VERIFIER_TRUSTED) is FactState.NOT_ASSESSED


def test_target_changed_holds_when_one_handle_carries_two_contents():
    other = dict(ARTIFACT, digest=OTHER)
    finding = state([ARTIFACT, other, CLAIM, EVIDENCE],
                    EvidenceFact.TARGET_CHANGED, subject="case")
    assert finding.state is FactState.HOLDS
    assert "more than one digest" in finding.basis


def test_coverage_known_distinguishes_stated_from_silent():
    assert state([ARTIFACT, CLAIM, EVIDENCE],
                 EvidenceFact.COVERAGE_KNOWN).state is FactState.HOLDS
    silent = {k: v for k, v in EVIDENCE.items() if k != "coverage_note"}
    assert state([ARTIFACT, CLAIM, silent],
                 EvidenceFact.COVERAGE_KNOWN).state is FactState.DOES_NOT_HOLD


def test_independent_root_exists_reports_a_single_lineage_as_such():
    records = [ARTIFACT, CLAIM, EVIDENCE]
    records += [{"record_type": "evidence", "evidence_id": f"c{i}",
                 "kind": "OBSERVATION",
                 "producer": {"producer_id": f"agent://w/{i}", "kind": "agent"},
                 "parent_evidence": ["e1"], "supports_claims": ["c1"],
                 "coverage_note": "confirms"} for i in range(8)]
    finding = state(records, EvidenceFact.INDEPENDENT_ROOT_EXISTS, subject="case")
    assert finding.state is FactState.DOES_NOT_HOLD
    assert "one thing being wrong makes all of them wrong" in finding.basis


# ── honest degradation ──────────────────────────────────────────────────────

def test_without_an_analysis_the_derived_facts_say_so():
    sheet = facts_for("case", case=assure([ARTIFACT, CLAIM, EVIDENCE]).case)
    assert any("no analysis was supplied" in note for note in sheet.notes)
    for fact in (EvidenceFact.INDEPENDENT_ROOT_EXISTS,
                 EvidenceFact.REPLICATION_SUCCEEDED,
                 EvidenceFact.COUNTEREXAMPLE_UNRESOLVED):
        assert sheet.state(fact) is FactState.NOT_ASSESSED


def test_a_fact_the_sheet_does_not_carry_is_unassessed_never_a_pass():
    sheet = FactSheet(subject="case", findings=())
    for fact in EvidenceFact:
        assert sheet.state(fact) is FactState.NOT_ASSESSED


def test_every_fact_is_answered_on_every_sheet():
    outcome = assure([ARTIFACT, CLAIM, EVIDENCE])
    sheet = facts_for("case", case=outcome.case, analysis=outcome.analysis)
    assert {f.fact for f in sheet.findings} == set(EvidenceFact)


def test_a_finding_without_a_basis_is_refused():
    with pytest.raises(QualityError):
        FactFinding(EvidenceFact.DIGEST_MATCHES, FactState.HOLDS, "", "somewhere")
    with pytest.raises(QualityError):
        FactFinding(EvidenceFact.DIGEST_MATCHES, FactState.HOLDS, "because", "")


def test_a_sheet_refuses_two_answers_to_one_question():
    twice = (FactFinding(EvidenceFact.DIGEST_MATCHES, FactState.HOLDS, "a", "x"),
             FactFinding(EvidenceFact.DIGEST_MATCHES, FactState.DOES_NOT_HOLD, "b", "x"))
    with pytest.raises(QualityError):
        FactSheet(subject="case", findings=twice)


def test_a_subject_the_case_does_not_hold_is_refused():
    case = assure([CLAIM, EVIDENCE]).case
    with pytest.raises(QualityError):
        facts_for("evidence:nothing-like-this", case=case)
    with pytest.raises(QualityError):
        facts_for("not-a-subject-kind:x", case=case)


def test_sheets_for_case_covers_the_case_and_every_claim():
    outcome = assure([ARTIFACT, CLAIM, EVIDENCE])
    sheets = sheets_for_case(outcome)
    assert "case" in sheets and "claim:c1" in sheets
    assert all(isinstance(s, FactSheet) for s in sheets.values())


# ── the model seam ──────────────────────────────────────────────────────────

def test_a_models_classification_is_derived_evidence():
    record = model_assisted_evidence(
        model="classifier-v2",
        classification="this diff touches the settlement path",
        content={"model_reported_confidence": 0.97})
    assert record.epistemic_status is EpistemicStatus.DERIVED
    assert not record.is_verification
    assert record.producer.model == "classifier-v2"
    # The model's confidence is kept where a reader can see it and moves nothing.
    assert record.content["model_reported_confidence"] == 0.97


@pytest.mark.parametrize("field", ["epistemic_status", "status", "verified"])
def test_a_model_cannot_argue_its_way_to_a_better_status(field):
    with pytest.raises(QualityError):
        model_assisted_evidence(model="m", classification="c",
                                **{field: EpistemicStatus.VERIFIED})


def test_an_anonymous_classification_is_refused():
    with pytest.raises(QualityError):
        model_assisted_evidence(model="   ", classification="c")


def test_a_models_output_gets_a_sheet_showing_what_it_is():
    """No special case, no warning banner: the model's record is read in the same
    vocabulary as everything else, and the thinness shows."""
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="ship",
        content_reference=ContentReference(kind=ReferenceKind.FILE, locator="p.py"),
        digest=DIGEST, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED, digest_basis="hashed here")
    builder = AssuranceCaseBuilder(case_type=CaseType.CODE_CHANGE, subject=subject,
                                   objective="o", requested_decision="ship")
    record = model_assisted_evidence(model="classifier-v2", classification="touches pay")
    builder.add("evidence", record)
    sheet = facts_for(f"evidence:{record.evidence_id}", case=builder.build())
    assert sheet.state(EvidenceFact.FORMAL_VERIFIER_PASSED) is FactState.NOT_ASSESSED
    assert sheet.state(EvidenceFact.DIGEST_MATCHES) is FactState.NOT_ASSESSED
    assert sheet.establishes_quality is False


# ── the shared digest helpers ───────────────────────────────────────────────

def test_declared_digests_keeps_every_content_under_one_handle():
    case = assure([ARTIFACT, dict(ARTIFACT, digest=OTHER)]).case
    assert declared_digests(case)["payments"] == {DIGEST, OTHER}


def test_held_digests_spans_collections_not_just_artifacts():
    case = assure([ARTIFACT, CLAIM, EVIDENCE]).case
    assert DIGEST in held_digests(case)


# ── a disagreement must not disable the machinery that reports disagreements ─

DISPUTED = [
    # The claim's author lists e2 as supporting it; e2 says it contradicts it.
    {"record_type": "claim", "claim_id": "c1", "proposition": "p",
     "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
     "supporting_evidence": ["e1", "e2"]},
    EVIDENCE,
    {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
     "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
     "contradicts_claims": ["c1"], "coverage_note": "refund double-fires"},
]


def test_two_accounts_of_one_record_do_not_destroy_the_claim_graph():
    """The loudest disagreement a case can hold used to silently disable every
    claim-level analysis.

    `link_evidence` folded both accounts onto one claim, `Claim` rightly refused
    to list one record as both supporting and contradicting, and the caller's
    bare `except Exception` turned that refusal into `claim_graph = None` — so
    contradiction detection, claim status and criticality all reported nothing on
    the one case where they had the most to say.
    """
    outcome = assure(DISPUTED)
    assert outcome.analysis.claim_graph is not None, (
        "a disagreement between two producers cost the case its claim graph")
    assert len(outcome.analysis.contradictions) == 1


def test_the_records_own_account_wins_and_the_dispute_is_named():
    """First-hand beats second-hand (Invariant 1) — and the disagreement is itself
    reported rather than quietly resolved."""
    outcome = assure(DISPUTED)
    graph = outcome.analysis.claim_graph
    claim = graph.claim("c1")
    assert len(claim.contradicting_evidence) == 1
    assert len(claim.supporting_evidence) == 1
    disputes = [a for a in graph.anomalies if a.kind == "EVIDENCE_SIDE_DISPUTED"]
    assert disputes, "the disagreement was resolved without being reported"
    assert "first-hand" in disputes[0].detail


def test_the_disputed_case_still_reports_its_contradiction_as_a_fact():
    finding = state(DISPUTED, EvidenceFact.CONTRADICTION_UNRESOLVED)
    assert finding.state is FactState.HOLDS
