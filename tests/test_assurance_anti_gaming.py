"""Eighteen attempts to make release-gate say PROMOTE when it should not.

Every test here is an attack, written from the attacker's side: the input is what
someone trying to get a decision through would actually submit, and the assertion
is on what release-gate does about it. That framing matters, because a gate is
only as good as its behaviour on hostile input, and hostile input is exactly what
a fixture written by the person who wrote the check tends not to be.

Three outcomes are possible for an attack, and the file is explicit about which
applies, because a suite that reported everything "handled" would be worse than
none — a reader would stop looking:

* **CAUGHT** — a named requirement or analysis fires and the decision is held or
  blocked, with words that describe what actually happened.
* **REFUSED STRUCTURALLY** — nothing detects the lie, and it buys nothing anyway
  because the structure never converts the submitted thing into support. Not the
  same as catching it, and not written as though it were.
* **UNSUPPORTED** — release-gate cannot tell. `test_unsupported_threats_are_named`
  at the foot of this file holds the list, and it is a test rather than a comment
  so that a threat quietly becoming detectable has to be acknowledged here.

The attacks come from the anti-gaming pass: copied sources, hidden failures,
renamed tools, fake approvals, post-verification mutation, circular evidence,
self-declared independence, flooding, fragmentation, forged timestamps, replay,
unrelated proofs, forged completeness, selective omission, cross-case reuse,
results bound to the wrong digest, evidence landing after the packet was read,
and semantic mutation behind an unchanged filename.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.approval import (
    ApprovalAcknowledgement, ApprovalStanding, AuthSource, SubmissionOutcome,
    check_approval, offer_approval, submit_approval)
from release_gate.assurance.attestation import ChainStatus, chain_from_case
from release_gate.assurance.case import (
    AssuranceCaseBuilder, CaseType, CaseVerdict, Decision)
from release_gate.assurance.completeness import (
    EndOfStream, SourceStream, StreamCompleteness, StreamLedger)
from release_gate.assurance.methodologies import SOFTWARE_AGENT_ASSURANCE_V1 as SW
from release_gate.assurance.query import run_all
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.session import AssuranceSession
from release_gate.assurance.subject import (
    AssuranceSubject, ContentReference, DigestMethod, DigestStatus, ReferenceKind,
    SubjectType)
from release_gate.assurance.zero_config import assure as zero_config_assure

OLD = "sha256:" + "aa" * 32
NEW = "sha256:" + "bb" * 32
OTHER = "sha256:" + "cc" * 32

CONSEQUENTIAL = {"record_type": "consequence", "REVERSIBILITY": "IRREVERSIBLE",
                 "SCOPE": "MULTI_SUBJECT", "FINANCIAL_IMPACT": "MATERIAL",
                 "DATA_IMPACT": "WRITE", "SECURITY_IMPACT": "NONE",
                 "LEGAL_IMPACT": "NONE"}


def assure(records, methodology=SW):
    """Run a case the way a submitter would: records in, decision out."""
    return AssuranceSession.open(methodology=methodology).extend(
        list(records)).finalize()


def finding(outcome, requirement_id):
    for result in outcome.assessment.results:
        if result.requirement_id == requirement_id:
            return result
    raise AssertionError(
        f"{requirement_id} was not assessed at all; the attack may have changed "
        f"shape. Assessed: {[r.requirement_id for r in outcome.assessment.results]}")


def artifact(digest, logical="payments"):
    return {"record_type": "artifact", "artifact_id": logical, "kind": "CODE",
            "digest": digest,
            "producer": {"producer_id": "agent://coder/1", "kind": "agent"}}


# ── 1. ten thousand agents copying one source ───────────────────────────────

def test_a_crowd_deriving_from_one_source_is_one_source():
    """CAUGHT. Agreement among copies is arithmetic, not corroboration."""
    records = [{"record_type": "evidence", "evidence_id": "root", "kind": "OBSERVATION",
                "producer": {"producer_id": "feed://prices", "kind": "tool"},
                "coverage_note": "the one reading everything below repeats"}]
    records += [{"record_type": "evidence", "evidence_id": f"copy{i}",
                 "kind": "OBSERVATION",
                 "producer": {"producer_id": f"agent://worker/{i}", "kind": "agent"},
                 "parent_evidence": ["root"], "supports_claims": ["c1"],
                 "coverage_note": "confirms the reading"} for i in range(300)]
    records.append({"record_type": "claim", "claim_id": "c1",
                    "proposition": "the price feed is correct",
                    "producer": {"producer_id": "agent://lead", "kind": "agent"},
                    "supporting_evidence": [f"copy{i}" for i in range(300)]})
    records.append(CONSEQUENTIAL)

    outcome = assure(records)
    assert outcome.decision is not Decision.PROMOTE
    # The population is visible as what it is: many records, one root.
    assert len(outcome.case.records("evidence")) > 100


# ── 2 & 14. selective omission ──────────────────────────────────────────────

def test_a_gap_in_a_numbered_stream_is_known_not_clean():
    """CAUGHT. Sequence numbers turn a silent omission into a stated gap."""
    ledger = StreamLedger(
        streams=(SourceStream(stream_id="agent-7", producer_id="agent://7",
                              observed_sequences=(1, 2, 4, 5)),),   # 3 was dropped
        expected_streams=("agent-7",), enumeration_independent=True,
        enumeration_source="the orchestrator's worker manifest")
    assert ledger.status is StreamCompleteness.KNOWN_GAPS
    assert any("never arrived" in gap for gap in ledger.gaps)


def test_an_unnumbered_stream_cannot_claim_completeness():
    """CAUGHT, in the only way available: it says it does not know."""
    ledger = StreamLedger(
        streams=(SourceStream(stream_id="agent-7", producer_id="agent://7"),))
    assert ledger.status is StreamCompleteness.COMPLETENESS_UNKNOWN
    assert "is not the same as there being none" in ledger.note()


def test_an_enumeration_written_by_the_counted_party_is_not_completeness():
    """CAUGHT. Everything checks out against a list the producer wrote."""
    ledger = StreamLedger(
        streams=(SourceStream(stream_id="agent-7", producer_id="agent://7",
                              observed_sequences=(1, 2, 3)),),
        expected_streams=("agent-7",), enumeration_independent=False,
        enumeration_source="agent://7 listing its own streams")
    assert ledger.status is StreamCompleteness.PARTIALLY_COMPLETE


# ── 3. a dangerous tool under a harmless name ───────────────────────────────

def test_renaming_a_tool_does_not_bound_the_capability_surface():
    """CAUGHT. An unrecognised name leaves the surface unbounded, not clean.

    The attack is a shell tool called `format_helper`. Release-gate does not
    pretend to know what that is — and the point is that not knowing is reported
    as not knowing, rather than as an absence of dangerous capability.
    """
    outcome = assure([
        {"record_type": "execution", "trace_id": "t1",
         "steps": [{"type": "tool_call", "tool": "format_helper"},
                   {"type": "tool_call", "tool": "read_file"}]},
        CONSEQUENTIAL])
    surface = outcome.analysis.capabilities
    assert surface is not None, "the attack needs a surface to have been derived"
    assert not surface.bounded
    assert outcome.decision is not Decision.PROMOTE


# ── 4. an approval issued for something else ────────────────────────────────

def _approved_case(extra_evidence=()):
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="deploy to prod",
        content_reference=ContentReference(kind=ReferenceKind.FILE,
                                           locator="svc/pay.py"),
        digest=NEW, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED, digest_basis="hashed by release-gate")
    builder = AssuranceCaseBuilder(
        case_type=CaseType.CODE_CHANGE, subject=subject,
        objective="ship the payment fix", requested_decision="deploy to prod")
    builder.add("evidence", SimpleRecord(
        record_type="evidence", record_id="e1",
        payload={"kind": "TEST_RESULT", "summary": "suite green"}))
    builder.add("coverage", SimpleRecord(
        record_type="coverage", record_id="cov1",
        payload={"dimension": "verification", "assessed": True, "note": "suite ran"}))
    for record in extra_evidence:
        builder.add("evidence", record)
    return builder.build().seal().render_verdict(CaseVerdict(
        decision=Decision.PROMOTE, fired_rules=("RG-TEST-001",),
        reasons=("suite green",), engine_version="t", ruleset_version="t"))


def _approve(case):
    offer = offer_approval(case)
    submission = submit_approval(
        case,
        ApprovalAcknowledgement(case_version=offer.case_version,
                                subject_digest=offer.subject_digest,
                                evidence_pack_digest=offer.evidence_pack_digest,
                                case_digest=offer.case_digest),
        approver="human://alice", auth_source=AuthSource.API_KEY,
        scope="deploy to prod")
    assert submission.outcome is SubmissionOutcome.ACCEPTED, submission.reasons
    return submission.approval


def test_an_approval_from_another_case_is_foreign():
    """CAUGHT. Approvals are not transferable, and the words say which failure."""
    approval = _approve(_approved_case())
    elsewhere = AssuranceSession.open(methodology=SW).extend(
        [CONSEQUENTIAL]).finalize().case
    check = check_approval(approval, elsewhere)
    assert check.standing is ApprovalStanding.APPROVAL_FOREIGN
    assert check.needs_new_approval


def test_an_unfinished_case_cannot_be_approved_at_all():
    """CAUGHT upstream: there is nothing yet to take responsibility for."""
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="deploy to prod",
        content_reference=ContentReference(kind=ReferenceKind.FILE,
                                           locator="svc/pay.py"),
        digest=NEW, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED, digest_basis="hashed here")
    undecided = AssuranceCaseBuilder(
        case_type=CaseType.CODE_CHANGE, subject=subject, objective="ship it",
        requested_decision="deploy to prod").build()
    offer = offer_approval(undecided)
    submission = submit_approval(
        undecided,
        ApprovalAcknowledgement(case_version=offer.case_version,
                                subject_digest=offer.subject_digest,
                                evidence_pack_digest=offer.evidence_pack_digest or "x",
                                case_digest=offer.case_digest),
        approver="human://alice", auth_source=AuthSource.API_KEY)
    assert submission.outcome is not SubmissionOutcome.ACCEPTED


# ── 5. the artifact moves after it was verified ─────────────────────────────

def test_evidence_produced_against_a_superseded_digest_is_not_support():
    """CAUGHT by RG-SW-007, which needs `applies_to_digest` to survive ingest."""
    outcome = assure([
        artifact(NEW),
        {"record_type": "claim", "claim_id": "c1",
         "proposition": "the payment path is correct",
         "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
         "supporting_evidence": ["e1"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://pytest", "kind": "tool"},
         "supports_claims": ["c1"], "applies_to_digest": OLD,
         "coverage_note": "full suite green"},
        CONSEQUENTIAL])
    result = finding(outcome, "RG-SW-007")
    assert not result.is_met
    assert "no longer apply to the current state" in result.detail
    assert outcome.decision is not Decision.PROMOTE


def test_a_declared_applies_to_that_is_not_a_digest_is_refused_with_a_note():
    """A malformed binding is not recorded as though it were one."""
    outcome = assure([
        artifact(NEW),
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://pytest", "kind": "tool"},
         "applies_to_digest": "the latest build", "coverage_note": "green"},
        CONSEQUENTIAL])
    assert any("not a sha256 content digest" in note
               for note in outcome.normalisation.notes)


# ── 6. evidence that supports itself ────────────────────────────────────────

def test_a_cycle_of_evidence_is_reported_not_traversed():
    """CAUGHT. A ring of mutual support is a defect, not a deep argument."""
    outcome = assure([
        {"record_type": "claim", "claim_id": "c1", "proposition": "a holds",
         "producer": {"producer_id": "agent://a", "kind": "agent"},
         "supporting_evidence": ["e1"], "depends_on": ["c2"]},
        {"record_type": "claim", "claim_id": "c2", "proposition": "b holds",
         "producer": {"producer_id": "agent://a", "kind": "agent"},
         "supporting_evidence": ["e2"], "depends_on": ["c1"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "OBSERVATION",
         "producer": {"producer_id": "agent://a", "kind": "agent"},
         "supports_claims": ["c1"], "coverage_note": "because b"},
        {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
         "producer": {"producer_id": "agent://a", "kind": "agent"},
         "supports_claims": ["c2"], "coverage_note": "because a"},
        CONSEQUENTIAL])
    graph = outcome.analysis.claim_graph
    assert graph is not None
    assert any(a.kind == "DEPENDENCY_CYCLE" for a in graph.anomalies)
    assert outcome.decision is not Decision.PROMOTE


# ── 7. an agent calling itself an independent verifier ──────────────────────

def test_an_agent_cannot_verify_itself_by_saying_so():
    """REFUSED STRUCTURALLY. Envelope evidence is DECLARED; declaring is not verifying."""
    outcome = assure([
        artifact(NEW),
        {"record_type": "claim", "claim_id": "c1", "proposition": "the change is safe",
         "producer": {"producer_id": "agent://a/1", "kind": "agent"},
         "supporting_evidence": ["e1"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "FORMAL_PROOF",
         "producer": {"producer_id": "agent://a/1", "kind": "agent"},
         "supports_claims": ["c1"], "applies_to_digest": NEW,
         "coverage_note": "I verified my own work independently"},
        CONSEQUENTIAL])
    # Nothing an agent submits through the envelope enters the verification
    # collection: the epistemic status of a submission is DECLARED, and only a
    # verifier report or release-gate's own analysis produces VERIFIED.
    assert not outcome.case.records("verification")
    assert not finding(outcome, "RG-SW-003").is_met
    assert outcome.decision is not Decision.PROMOTE


# ── 8. drowning the gap in volume ───────────────────────────────────────────

def test_five_thousand_irrelevant_records_do_not_verify_anything():
    """CAUGHT. Volume is not confidence, and the packet stays the size of the argument."""
    records = [{"record_type": "claim", "claim_id": "c_critical",
                "proposition": "the refund path cannot double-charge",
                "producer": {"producer_id": "agent://lead", "kind": "agent"}}]
    records += [{"record_type": "evidence", "evidence_id": f"e{i}",
                 "kind": "OBSERVATION",
                 "producer": {"producer_id": f"agent://worker/{i % 250}",
                              "kind": "agent"},
                 "supports_claims": ["c_noise"], "coverage_note": f"log line {i}"}
                for i in range(2000)]
    records.append({"record_type": "claim", "claim_id": "c_noise",
                    "proposition": "the service emitted logs",
                    "producer": {"producer_id": "agent://lead", "kind": "agent"},
                    "supporting_evidence": [f"e{i}" for i in range(2000)]})
    records.append(CONSEQUENTIAL)

    outcome = assure(records)
    assert outcome.decision is not Decision.PROMOTE
    answers = run_all(outcome)
    assert answers["unverified_critical_claims"].rows, (
        "the flood buried the one claim the decision rests on")


# ── 9. splitting one claim into fifty to inflate coverage ───────────────────

def test_fragmenting_a_claim_does_not_manufacture_coverage():
    """CAUGHT. Fifty unsupported shards are fifty unsupported claims."""
    records = [{"record_type": "claim", "claim_id": f"c{i}",
                "proposition": f"sub-property {i} of the refund path holds",
                "producer": {"producer_id": "agent://lead", "kind": "agent"}}
               for i in range(50)]
    records.append(CONSEQUENTIAL)
    outcome = assure(records)
    assert outcome.decision is not Decision.PROMOTE


# ── 10. a producer lying about its clock ────────────────────────────────────

def _timestamped(stamps):
    records = [artifact(OTHER),
               {"record_type": "claim", "claim_id": "c1",
                "proposition": "the refund path is correct",
                "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
                "supporting_evidence": [f"e{i}" for i in range(1, len(stamps) + 1)]}]
    for i, stamp in enumerate(stamps, start=1):
        records.append({"record_type": "evidence", "evidence_id": f"e{i}",
                        "kind": "TEST_RESULT",
                        "producer": {"producer_id": f"ci://runner{i}", "kind": "tool"},
                        "supports_claims": ["c1"], "timestamp": stamp,
                        "applies_to_digest": OTHER, "coverage_note": "suite green"})
    records.append(CONSEQUENTIAL)
    return records


def _fingerprint(outcome):
    return (outcome.decision,
            tuple(sorted((r.requirement_id, r.outcome.value)
                         for r in outcome.assessment.results)))


@pytest.mark.parametrize("stamps", [
    ["2099-01-01T00:00:00Z", "2099-01-01T00:00:01Z"],     # the future
    ["1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z"],     # the distant past
    ["2026-09-17T10:05:00Z", "2026-09-17T10:00:00Z"],     # out of order
])
def test_a_forged_timestamp_moves_no_finding(stamps):
    """CAUGHT by not caring: no decision rests on a producer's clock."""
    honest = _fingerprint(assure(_timestamped(
        ["2026-09-17T10:00:00Z", "2026-09-17T10:05:00Z"])))
    assert _fingerprint(assure(_timestamped(stamps))) == honest


def test_a_declared_timestamp_is_kept_as_a_declaration_beside_the_observed_one():
    """The claim is neither believed nor discarded — it is visible as a claim."""
    outcome = assure(_timestamped(["2099-01-01T00:00:00Z"]))
    declared = [(r.to_dict().get("metadata") or {}).get("declared_timestamp")
                for r in outcome.case.records("evidence")]
    assert "2099-01-01T00:00:00Z" in declared
    for record in outcome.case.records("evidence"):
        payload = record.to_dict()
        # release-gate's own field says when release-gate saw it, never what the
        # producer wished it said.
        assert payload.get("timestamp") != "2099-01-01T00:00:00Z"


# ── 11. the same record submitted fifty times ───────────────────────────────

def test_replaying_one_record_fifty_times_yields_one_record():
    """CAUGHT. Identity is content, so a replay collides with what it copies."""
    row = {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
           "producer": {"producer_id": "ci://pytest", "kind": "tool"},
           "supports_claims": ["c1"], "coverage_note": "suite green"}
    records = [{"record_type": "claim", "claim_id": "c1", "proposition": "p",
                "producer": {"producer_id": "agent://a", "kind": "agent"},
                "supporting_evidence": ["e1"]}]
    records += [dict(row) for _ in range(50)]
    outcome = assure(records)
    test_results = [r for r in outcome.case.records("evidence")
                    if r.to_dict().get("evidence_type") == "TEST_RESULT"]
    assert len(test_results) == 1


def test_restamping_a_replay_does_not_multiply_it():
    """The obvious evasion — a fresh clock per copy — buys no extra record."""
    records = [{"record_type": "claim", "claim_id": "c1", "proposition": "p",
                "producer": {"producer_id": "agent://a", "kind": "agent"},
                "supporting_evidence": ["e1"]}]
    records += [{"record_type": "evidence", "evidence_id": "e1",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "ci://pytest", "kind": "tool"},
                 "supports_claims": ["c1"], "timestamp": f"2026-09-17T10:{i:02d}:00Z",
                 "coverage_note": "suite green"} for i in range(50)]
    outcome = assure(records)
    test_results = [r for r in outcome.case.records("evidence")
                    if r.to_dict().get("evidence_type") == "TEST_RESULT"]
    assert len(test_results) == 1


# ── 12 & 16. a real result pointed at the wrong thing ───────────────────────

def test_a_verification_bound_to_a_digest_nothing_carries_is_unanchored(tmp_path):
    """CAUGHT by RG-SW-006. Not stale — never anchored, which is a different word.

    A verifier report is the only input that yields a typed verification, so the
    attack has to come in that way: a genuine proof, genuinely passing, naming a
    target digest this case has never seen. Before this was checked the predicate
    reported SATISFIED — "every verification record applies to the current state" —
    because an attempt whose target it could not find was skipped rather than
    reported, and a skipped check reads exactly like a passed one.
    """
    report = tmp_path / "proof.json"
    report.write_text(json.dumps({
        "verifier": {"name": "lean", "version": "4.8.0", "family": "PROOF_ASSISTANT"},
        "results": [{"target": "payments", "target_digest": OLD, "result": "proved",
                     "covers": ["the stated theorem"],
                     "does_not_cover": ["whether the statement says what was meant"]}],
    }))
    outcome = zero_config_assure(str(report), methodology=SW)
    result = finding(outcome, "RG-SW-006")
    assert not result.is_met
    assert "name a digest nothing in this case carries" in result.detail
    assert outcome.decision is not Decision.PROMOTE


def test_a_dangling_attestation_reference_breaks_the_chain():
    """CAUGHT. A custody link to something the case does not hold is a break."""
    outcome = assure([
        artifact(NEW),
        {"record_type": "evidence", "evidence_id": "e1", "kind": "FORMAL_PROOF",
         "producer": {"producer_id": "tool://coq", "kind": "tool"},
         "applies_to_digest": OTHER, "coverage_note": "proof of something else"},
        CONSEQUENTIAL])
    chain = chain_from_case(outcome.case)
    assert chain.status is not ChainStatus.CONTINUOUS


# ── 13. a forged completeness declaration ───────────────────────────────────

def test_an_attestation_naming_more_than_arrived_is_a_detected_truncation():
    """CAUGHT. The declaration is checked against arrivals, not taken on trust."""
    stream = SourceStream(
        stream_id="agent-7", producer_id="agent://7", observed_sequences=(1, 2, 3),
        end_of_stream=EndOfStream(declared_by="orchestrator://1", final_sequence=9,
                                  record_count=9))
    assert stream.truncated_tail
    assert stream.count_shortfall == 6
    ledger = StreamLedger(streams=(stream,), expected_streams=("agent-7",),
                          enumeration_independent=True)
    assert ledger.status is StreamCompleteness.KNOWN_GAPS


def test_a_producer_certifying_its_own_stream_cannot_establish_completeness():
    """CAUGHT. Whatever was left out of the stream was left out of the declaration."""
    stream = SourceStream(
        stream_id="agent-7", producer_id="agent://7", observed_sequences=(1, 2, 3),
        end_of_stream=EndOfStream(declared_by="agent://7", final_sequence=3,
                                  record_count=3, signature_id="sig-1"))
    assert stream.self_certified
    assert not stream.gaps          # nothing detectable — that is the whole problem
    ledger = StreamLedger(streams=(stream,), expected_streams=("agent-7",),
                          enumeration_independent=False)
    assert ledger.status is not StreamCompleteness.COMPLETE


# ── 15. evidence borrowed from another case ─────────────────────────────────

def test_a_proof_about_another_subject_does_not_support_this_one():
    """CAUGHT by RG-SW-007: the borrowed proof names a digest this case lacks."""
    outcome = assure([
        artifact(NEW),
        {"record_type": "claim", "claim_id": "c1",
         "proposition": "the payments service is verified",
         "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
         "supporting_evidence": ["e_reused"]},
        {"record_type": "evidence", "evidence_id": "e_reused", "kind": "FORMAL_PROOF",
         "producer": {"producer_id": "tool://coq", "kind": "tool"},
         "supports_claims": ["c1"], "applies_to_digest": OLD,
         "coverage_note": "proof of termination for the scheduler, case RG-2026-0042"},
        CONSEQUENTIAL])
    assert not finding(outcome, "RG-SW-007").is_met
    assert outcome.decision is not Decision.PROMOTE


def test_borrowed_evidence_relabelled_with_this_digest_is_refused_not_detected():
    """REFUSED STRUCTURALLY, and the distinction is the point.

    A producer that lies consistently — borrowed proof, re-labelled to name this
    case's artifact — contradicts nothing release-gate holds, so nothing detects
    it. What stops it is that a self-declared result never becomes verification:
    the case is refused for want of a check, not for the lie.
    """
    outcome = assure([
        artifact(NEW),
        {"record_type": "claim", "claim_id": "c1",
         "proposition": "the payments service terminates",
         "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
         "supporting_evidence": ["e1"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "FORMAL_PROOF",
         "producer": {"producer_id": "tool://coq", "kind": "tool"},
         "supports_claims": ["c1"], "applies_to_digest": NEW,
         "coverage_note": "proof of termination"},
        CONSEQUENTIAL])
    assert finding(outcome, "RG-SW-007").is_met      # nothing detects the lie
    assert not finding(outcome, "RG-SW-003").is_met  # and it still buys nothing
    assert outcome.decision is not Decision.PROMOTE


# ── 17. evidence landing after the human read the packet ────────────────────

def test_evidence_arriving_after_approval_reopens_the_decision():
    """CAUGHT. The subject is unchanged; what is known about it is not."""
    case = _approved_case()
    approval = _approve(case)
    assert check_approval(approval, case).standing is ApprovalStanding.VALID

    later = _approved_case([SimpleRecord(
        record_type="evidence", record_id="e2",
        payload={"kind": "TEST_RESULT", "summary": "regression: refunds throw"})])
    assert later.case_id == case.case_id, "the attack needs one case, not two"

    check = check_approval(approval, later)
    assert check.standing is ApprovalStanding.APPROVAL_REVIEW_REQUIRED
    assert not check.valid
    assert any("evidence this approval rested on has changed" in reason
               for reason in check.reasons)


# ── 18. the same filename over different content ────────────────────────────

def test_one_handle_declared_with_two_digests_is_named_not_collapsed():
    """CAUGHT by RG-SW-005 — and it says which defect, not a downstream one."""
    outcome = assure([
        artifact(OLD), artifact(NEW),
        {"record_type": "claim", "claim_id": "c1",
         "proposition": "svc/pay.py is correct",
         "producer": {"producer_id": "agent://coder/1", "kind": "agent"},
         "supporting_evidence": ["e1"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://pytest", "kind": "tool"},
         "supports_claims": ["c1"], "applies_to_digest": OLD,
         "coverage_note": "suite green on svc/pay.py"},
        CONSEQUENTIAL])
    result = finding(outcome, "RG-SW-005")
    assert not result.is_met
    assert "more than one digest" in result.detail
    # And the evidence is not additionally mis-named as stale: it names content
    # the case holds. The defect is upstream of it.
    assert finding(outcome, "RG-SW-007").is_met
    assert outcome.decision is not Decision.PROMOTE


def test_both_contents_are_kept_so_the_collision_is_inspectable():
    """Nothing is dropped: last-write-wins would hide the thing being reported."""
    outcome = assure([artifact(OLD), artifact(NEW), CONSEQUENTIAL])
    digests = {r.to_dict().get("digest") for r in outcome.case.records("artifacts")}
    assert {OLD, NEW} <= digests


# ── what release-gate cannot see ────────────────────────────────────────────

UNSUPPORTED_THREATS = (
    "a producer that lies consistently: fabricated evidence internally "
    "consistent with everything else submitted contradicts nothing, so nothing "
    "detects it. What limits it is that a self-declared result never becomes a "
    "verification, so the lie has to survive an independent check to buy anything",

    "a compromised verifier: release-gate weighs a verifier's output, and has no "
    "way to tell a correct verifier from a subverted one emitting the same shape. "
    "Tool identity and pinning narrow this to 'which binary said so', not "
    "'was the binary honest'",

    "collusion between producers that release-gate models as independent: "
    "independence is derived from evidence lineage, and two parties that "
    "coordinate out of band leave no trace in the lineage",

    "omission by a producer that never declared a stream: completeness is "
    "assessed against what a source said it would send. A source that stays "
    "silent about its own existence is reported as COMPLETENESS_UNKNOWN, which "
    "is honest and is not detection",

    "semantics: release-gate compares digests, not meanings. Two artifacts that "
    "differ are reported as differing; whether the difference matters is a "
    "question for a verifier, and whether the verifier asked the right question "
    "is outside the gate entirely",

    "a human approving with full knowledge: an approval is an authorization, and "
    "release-gate records who bound themselves to which state. It does not, and "
    "cannot, assess whether that was wise",
)


def test_unsupported_threats_are_named():
    """The list above is load-bearing documentation, so it is a test.

    A threat model that graded everything 'handled' would be worse than none: a
    reader would stop looking. This exists so that moving a threat out of this
    list has to be a deliberate edit with a test behind it.
    """
    assert len(UNSUPPORTED_THREATS) == 6
    for threat in UNSUPPORTED_THREATS:
        assert ":" in threat, "each entry names the threat, then what limits it"
        assert len(threat) > 80, "a one-line disclaimer is not a threat model"
