"""The approval endpoint: read the exact bound state, acknowledge it, then submit."""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_gate.assurance.approval import (
    ApprovalAcknowledgement, ApprovalDecision, ApprovalOffer, AuthSource,
    SubmissionOutcome, offer_approval, submit_approval)


# ── the read half returns the exact bound state ──────────────────────────────

class TestTheOffer:

    def test_it_returns_what_would_be_approved(self, outcome):
        offer = offer_approval(outcome.case)
        state = outcome.case.binding_state()
        assert offer.case_id == state["case_id"]
        assert offer.case_version == state["case_version"]
        assert offer.case_digest == state["case_digest"]

    def test_it_names_what_must_be_acknowledged(self, outcome):
        assert offer_approval(outcome.case).required_acknowledgement == (
            "case_version", "subject_digest", "evidence_pack_digest")

    def test_it_carries_the_packet_the_human_reads(self, outcome):
        offer = offer_approval(outcome.case, outcome)
        assert offer.packet is not None
        assert len(offer.packet.sections) == 11

    def test_the_values_and_the_document_come_from_one_snapshot(self, outcome):
        # Two calls could straddle a change; one call cannot.
        offer = offer_approval(outcome.case, outcome)
        assert offer.packet.case_digest == offer.case_digest

    def test_it_reports_the_recommendation_without_being_one(self, outcome):
        offer = offer_approval(outcome.case)
        assert offer.recommendation == outcome.decision.value

    def test_an_offer_is_not_a_lock_and_says_so(self, outcome):
        payload = offer_approval(outcome.case).to_dict()
        assert payload["is_a_lock"] is False
        assert "reserves nothing" in payload["note"]

    def test_two_offers_on_one_state_both_succeed(self, outcome):
        # Optimistic concurrency reserves nothing; the conflict surfaces at
        # submission, not at read.
        first = offer_approval(outcome.case)
        second = offer_approval(outcome.case)
        assert first.case_digest == second.case_digest


# ── the acknowledgement must be complete ─────────────────────────────────────

class TestAcknowledgement:

    def test_all_three_fields_are_required(self):
        assert not ApprovalAcknowledgement(case_version=1).complete
        assert not ApprovalAcknowledgement(
            case_version=1, subject_digest="d").complete
        assert ApprovalAcknowledgement(
            case_version=1, subject_digest="d",
            evidence_pack_digest="e").complete

    def test_a_partial_acknowledgement_is_refused_not_weakened(self, outcome):
        found = submit_approval(
            outcome.case, ApprovalAcknowledgement(case_version=1),
            approver="alice")
        assert found.outcome is SubmissionOutcome.INCOMPLETE_ACKNOWLEDGEMENT
        assert "not a weaker one" in found.reasons[0]

    def test_it_names_exactly_what_was_missing(self, outcome):
        found = submit_approval(
            outcome.case, ApprovalAcknowledgement(case_version=1),
            approver="alice")
        assert set(found.mismatched) == {"subject_digest", "evidence_pack_digest"}

    def test_an_empty_string_does_not_count_as_acknowledged(self):
        assert not ApprovalAcknowledgement(
            case_version=1, subject_digest="  ",
            evidence_pack_digest="e").complete

    def test_the_offer_can_produce_a_matching_acknowledgement(self, outcome):
        offer = offer_approval(outcome.case)
        assert offer.acknowledgement().complete


# ── there is no "approve latest" ─────────────────────────────────────────────

class TestNoApproveLatest:

    def test_submission_requires_an_acknowledgement(self):
        # The signature has no way to express "approve whatever is current":
        # acknowledgement is positional and required.
        import inspect
        params = inspect.signature(submit_approval).parameters
        assert "acknowledgement" in params
        assert params["acknowledgement"].default is inspect.Parameter.empty

    def test_an_empty_acknowledgement_never_assumes_current(self, outcome):
        found = submit_approval(outcome.case, ApprovalAcknowledgement(),
                                approver="alice")
        assert found.outcome is SubmissionOutcome.INCOMPLETE_ACKNOWLEDGEMENT
        assert found.approval is None

    def test_the_docstring_states_the_refusal(self):
        assert "no way to express" in submit_approval.__doc__


# ── TOCTOU: the state moved between read and write ───────────────────────────

class TestConflict:

    def test_a_moved_evidence_state_conflicts(self, outcome):
        stale = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(),
            evidence_pack_digest="sha256:" + "0" * 64)
        found = submit_approval(outcome.case, stale, approver="alice")
        assert found.outcome is SubmissionOutcome.CONFLICT
        assert "evidence_pack_digest" in found.mismatched
        assert found.approval is None

    def test_a_moved_subject_conflicts(self, outcome):
        stale = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(),
            subject_digest="sha256:" + "0" * 64)
        assert submit_approval(outcome.case, stale,
                               approver="alice").outcome is SubmissionOutcome.CONFLICT

    def test_a_moved_version_conflicts(self, outcome):
        stale = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(), case_version=99)
        assert submit_approval(outcome.case, stale,
                               approver="alice").outcome is SubmissionOutcome.CONFLICT

    def test_the_conflict_returns_the_current_state(self, outcome):
        stale = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(),
            evidence_pack_digest="sha256:" + "0" * 64)
        found = submit_approval(outcome.case, stale, approver="alice")
        assert found.current is not None
        assert found.current.case_digest == \
            outcome.case.binding_state()["case_digest"]

    def test_an_evidentiary_conflict_sends_the_human_back(self, outcome):
        stale = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(),
            subject_digest="sha256:" + "0" * 64)
        found = submit_approval(outcome.case, stale, approver="alice")
        assert found.evidentiary_change
        assert found.human_must_re_read

    def test_a_derived_only_conflict_does_not(self, outcome):
        # Release-gate found different things to say about the same evidence: the
        # thing the person approved is unchanged, so re-acknowledging is honest.
        stale = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(),
            case_digest="sha256:" + "0" * 64)
        found = submit_approval(outcome.case, stale, approver="alice")
        assert found.outcome is SubmissionOutcome.CONFLICT
        assert not found.evidentiary_change
        assert not found.human_must_re_read
        assert "only release-gate's own output moved" in found.reasons[0]

    def test_an_optional_case_digest_is_enforced_when_supplied(self, outcome):
        good = offer_approval(outcome.case).acknowledgement()
        assert submit_approval(outcome.case, good, approver="alice").accepted
        bad = dataclasses.replace(good, case_digest="sha256:" + "1" * 64)
        assert not submit_approval(outcome.case, bad, approver="alice").accepted

    def test_omitting_the_optional_case_digest_is_fine(self, outcome):
        partial = dataclasses.replace(
            offer_approval(outcome.case).acknowledgement(), case_digest=None)
        assert submit_approval(outcome.case, partial, approver="alice").accepted


# ── the offer is a convenience, never an authority ───────────────────────────

class TestOfferIsNotAuthority:

    def test_a_fabricated_offer_cannot_authorise(self, outcome):
        forged = dataclasses.replace(
            offer_approval(outcome.case),
            subject_digest="sha256:" + "f" * 64,
            evidence_pack_digest="sha256:" + "f" * 64)
        found = submit_approval(outcome.case, forged.acknowledgement(),
                                approver="mallory")
        assert found.outcome is SubmissionOutcome.CONFLICT
        assert found.approval is None

    def test_verification_is_against_the_live_case(self, two_cases):
        first, second = two_cases
        # An acknowledgement read from one case, submitted against another.
        found = submit_approval(second.case,
                                offer_approval(first.case).acknowledgement(),
                                approver="alice")
        assert found.outcome is SubmissionOutcome.CONFLICT


# ── acceptance produces a bound approval ─────────────────────────────────────

class TestAcceptance:

    def test_an_honest_submission_is_accepted(self, outcome):
        found = submit_approval(outcome.case,
                                offer_approval(outcome.case).acknowledgement(),
                                approver="alice@example.com",
                                auth_source=AuthSource.OIDC, scope="staging")
        assert found.accepted
        assert found.approval is not None
        assert found.approval.scope == "staging"

    def test_the_approval_binds_to_the_acknowledged_state(self, outcome):
        offer = offer_approval(outcome.case)
        found = submit_approval(outcome.case, offer.acknowledgement(),
                                approver="alice")
        assert found.approval.case_digest == offer.case_digest
        assert found.approval.subject_digest == offer.subject_digest

    def test_a_case_with_no_verdict_is_refused(self, outcome):
        draft = outcome.case.revise()
        found = submit_approval(draft, offer_approval(draft).acknowledgement(),
                                approver="alice")
        assert found.outcome is SubmissionOutcome.REFUSED
        assert "nothing yet for a human" in found.reasons[0]

    def test_release_gate_cannot_approve_through_the_endpoint_either(self, outcome):
        found = submit_approval(outcome.case,
                                offer_approval(outcome.case).acknowledgement(),
                                approver="release-gate",
                                auth_source=AuthSource.RELEASE_GATE)
        assert found.outcome is SubmissionOutcome.REFUSED
        assert "cannot approve" in found.reasons[0]

    def test_a_rejection_is_recordable_too(self, outcome):
        found = submit_approval(outcome.case,
                                offer_approval(outcome.case).acknowledgement(),
                                approver="alice",
                                decision=ApprovalDecision.REJECTED)
        assert found.accepted
        assert not found.approval.authorises

    def test_the_submission_serialises(self, outcome):
        payload = submit_approval(outcome.case,
                                  offer_approval(outcome.case).acknowledgement(),
                                  approver="alice").to_dict()
        assert payload["record_type"] == "approval_submission"
        assert json.loads(json.dumps(payload))["accepted"] is True


# ── fixtures ─────────────────────────────────────────────────────────────────

_BASE = [
    {"record_type": "evidence", "evidence_id": "E-1", "evidence_type": "TOOL_RESULT",
     "producer": {"producer_id": "agent-A"}, "supports_claims": ["A"],
     "content": {"ok": True}},
    {"record_type": "claim", "claim_id": "A", "is_root": True,
     "statement": "the migration is safe", "supported_by": ["E-1"]},
]


def _assure(tmp_path, name, rows):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return assure(str(path))


@pytest.fixture
def outcome(tmp_path):
    return _assure(tmp_path, "case.json", _BASE)


@pytest.fixture
def two_cases(tmp_path):
    return (_assure(tmp_path, "one.json", _BASE),
            _assure(tmp_path, "two.json", _BASE + [
                {"record_type": "claim", "claim_id": "B", "statement": "other"}]))
