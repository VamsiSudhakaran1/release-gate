"""Human approval: attributable, bound to exact state, and unable to outlive either."""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_gate.assurance.approval import (
    ApprovalCheck, ApprovalDecision, ApprovalError, ApprovalStanding, AuthSource,
    BoundApproval, check_approval)


def approval(case, **kw):
    kw.setdefault("approver", "alice@example.com")
    kw.setdefault("auth_source", AuthSource.OIDC)
    return BoundApproval.for_case(case, **kw)


# ── the record is attributable ───────────────────────────────────────────────

class TestAttribution:

    def test_release_gate_cannot_approve(self, outcome):
        with pytest.raises(ApprovalError) as exc:
            approval(outcome.case, auth_source=AuthSource.RELEASE_GATE)
        assert "release-gate cannot approve" in str(exc.value)
        assert "signing its own homework" in str(exc.value)

    def test_an_approval_must_name_its_approver(self, outcome):
        with pytest.raises(ApprovalError) as exc:
            approval(outcome.case, approver="   ")
        assert "answerable" in str(exc.value)

    def test_an_authenticated_source_establishes_identity(self, outcome):
        assert approval(outcome.case, auth_source=AuthSource.OIDC).identity_established

    def test_an_asserted_source_does_not(self, outcome):
        # Attributable to a claim of identity, which is a weaker and different
        # fact from an established one.
        found = approval(outcome.case, auth_source=AuthSource.ASSERTED)
        assert not found.identity_established
        assert "not an established one" in found.render()

    def test_an_api_key_is_possession_not_a_person(self, outcome):
        assert not approval(outcome.case,
                            auth_source=AuthSource.API_KEY).identity_established

    def test_the_id_is_content_derived(self, outcome):
        one = approval(outcome.case, timestamp="2026-01-01T00:00:00Z")
        two = approval(outcome.case, timestamp="2026-01-01T00:00:00Z")
        assert one.approval_id == two.approval_id


# ── the record binds to exact state ──────────────────────────────────────────

class TestBinding:

    def test_it_reads_the_digests_from_the_case(self, outcome):
        found = approval(outcome.case)
        state = outcome.case.binding_state()
        assert found.case_digest == state["case_digest"]
        assert found.case_id == state["case_id"]

    def test_a_binding_with_no_digest_is_refused(self):
        with pytest.raises(ApprovalError) as exc:
            BoundApproval(case_id="c", case_version=1, approver="a",
                          subject_digest="", case_digest="d")
        assert "binds to whatever that state becomes" in str(exc.value)

    def test_it_records_per_collection_digests(self, outcome):
        assert "evidence" in approval(outcome.case).bound_collections

    def test_an_expiry_before_the_approval_is_refused(self, outcome):
        with pytest.raises(ApprovalError):
            approval(outcome.case, timestamp="2026-06-01T00:00:00Z",
                     expires_at="2026-01-01T00:00:00Z")

    def test_absent_expiry_is_stated_not_silent(self, outcome):
        assert "does not lapse on its own" in approval(outcome.case).expiry_basis

    def test_it_round_trips(self, outcome):
        one = approval(outcome.case, scope="staging", comment="looked at it")
        assert BoundApproval.from_dict(one.to_dict()) == one


# ── an approval never rewrites a verdict ─────────────────────────────────────

class TestNeverRewritesTheVerdict:

    def test_approving_over_a_hold_is_recorded_as_an_override(self, outcome):
        found = approval(outcome.case)
        assert outcome.decision.value != "PROMOTE"
        assert found.overrides_recommendation
        assert "OVERRIDE" in found.render()

    def test_the_override_names_what_was_recommended(self, outcome):
        found = approval(outcome.case)
        assert found.case_decision == outcome.decision.value
        assert found.to_dict()["case_decision"] == outcome.decision.value

    def test_a_rejection_is_not_an_override(self, outcome):
        found = approval(outcome.case, decision=ApprovalDecision.REJECTED)
        assert not found.authorises
        assert not found.overrides_recommendation

    def test_a_deferral_authorises_nothing(self, outcome):
        assert not approval(outcome.case,
                            decision=ApprovalDecision.DEFERRED).authorises


# ── behaviour 1: the subject changed ─────────────────────────────────────────

class TestSubjectChanged:

    def test_a_moved_subject_invalidates(self, outcome):
        moved = dataclasses.replace(approval(outcome.case),
                                    subject_digest="sha256:" + "f" * 64)
        found = check_approval(moved, outcome.case)
        assert found.standing is ApprovalStanding.APPROVAL_INVALIDATED
        assert "no re-check repairs that" in found.reasons[0]

    def test_it_needs_a_new_human_act(self, outcome):
        moved = dataclasses.replace(approval(outcome.case),
                                    subject_digest="sha256:" + "f" * 64)
        assert check_approval(moved, outcome.case).needs_new_approval

    def test_a_revision_invalidates_rather_than_reading_as_a_replay(self, outcome):
        # A revised case is a lifecycle event, not a security one. Reporting it as
        # FOREIGN would send a reviewer hunting an attacker when a colleague
        # opened the next version.
        found = check_approval(approval(outcome.case), outcome.case.revise())
        assert found.standing is ApprovalStanding.APPROVAL_INVALIDATED
        assert "applies to the previous version only" in found.reasons[0]


# ── behaviour 2: relevant evidence changed ───────────────────────────────────

class TestEvidenceChanged:

    def test_moved_evidence_requires_review(self, outcome):
        moved = self._move(outcome, "evidence")
        found = check_approval(moved, outcome.case)
        assert found.standing is ApprovalStanding.APPROVAL_REVIEW_REQUIRED
        assert "evidence" in found.moved_collections

    def test_review_required_is_not_a_new_approval(self, outcome):
        # What was authorised has not changed; what is known about it has. A
        # person looking again may reasonably let the approval stand.
        found = check_approval(self._move(outcome, "evidence"), outcome.case)
        assert not found.needs_new_approval
        assert "what was authorised is unchanged" in found.reasons[0]

    def test_a_derived_collection_moving_is_not_an_evidence_change(self, outcome):
        # Release-gate's own outputs move whenever it finds different things to
        # say; raising review on that would train people to ignore review.
        found = check_approval(self._move(outcome, "attention_items"), outcome.case)
        assert found.standing is ApprovalStanding.VALID
        assert "attention_items" in found.derived_only_changes
        assert "not the evidence moving" in found.render()

    def test_every_evidentiary_collection_counts(self, outcome):
        for kind in ("claims", "verification", "contradictions"):
            found = check_approval(self._move(outcome, kind), outcome.case)
            assert found.standing is ApprovalStanding.APPROVAL_REVIEW_REQUIRED, kind

    def _move(self, outcome, kind):
        base = approval(outcome.case)
        return dataclasses.replace(
            base, bound_collections={**base.bound_collections,
                                     kind: "sha256:" + "0" * 64})


# ── behaviour 3: verification targets went stale ─────────────────────────────

class TestStaleVerification:

    def test_the_check_names_superseded_attempts(self, outcome):
        found = check_approval(approval(outcome.case), outcome.case)
        assert isinstance(found.stale_verifications, tuple)

    def test_staleness_is_read_from_the_graph_not_recomputed(self, outcome):
        from release_gate.assurance.verification import VerificationGraph
        graph = VerificationGraph.from_case(outcome.case)
        found = check_approval(approval(outcome.case), outcome.case)
        assert set(found.stale_verifications) == {
            a.verification_id for a in graph.superseded_attempts()}


# ── behaviour 4: replayed against another case ───────────────────────────────

class TestReplay:

    def test_an_approval_for_another_case_is_rejected(self, two_cases):
        first, second = two_cases
        found = check_approval(approval(first.case), second.case)
        assert found.standing is ApprovalStanding.APPROVAL_FOREIGN
        assert "not transferable between cases" in found.reasons[0]

    def test_replay_outranks_every_other_condition(self, two_cases):
        first, second = two_cases
        stale = dataclasses.replace(
            approval(first.case), subject_digest="sha256:" + "f" * 64,
            timestamp="2025-01-01T00:00:00Z", expires_at="2026-01-01T00:00:00Z")
        found = check_approval(stale, second.case, now="2026-06-01T00:00:00Z")
        assert found.standing is ApprovalStanding.APPROVAL_FOREIGN

    def test_it_needs_a_new_approval(self, two_cases):
        first, second = two_cases
        assert check_approval(approval(first.case), second.case).needs_new_approval


# ── expiry and scope ─────────────────────────────────────────────────────────

class TestExpiryAndScope:

    def test_an_expired_approval_is_not_valid(self, outcome):
        expiring = approval(outcome.case, timestamp="2025-01-01T00:00:00Z",
                            expires_at="2026-01-01T00:00:00Z")
        found = check_approval(expiring, outcome.case, now="2026-06-01T00:00:00Z")
        assert found.standing is ApprovalStanding.APPROVAL_EXPIRED

    def test_it_is_valid_before_it_expires(self, outcome):
        expiring = approval(outcome.case, timestamp="2025-01-01T00:00:00Z",
                            expires_at="2026-01-01T00:00:00Z")
        assert check_approval(expiring, outcome.case,
                              now="2025-06-01T00:00:00Z").valid

    def test_a_scope_mismatch_is_refused(self, outcome):
        found = check_approval(approval(outcome.case, scope="staging"),
                               outcome.case, scope="production")
        assert found.standing is ApprovalStanding.APPROVAL_SCOPE_MISMATCH
        assert "production" in found.reasons[0]

    def test_a_matching_scope_passes(self, outcome):
        assert check_approval(approval(outcome.case, scope="staging"),
                              outcome.case, scope="staging").valid

    def test_scope_is_only_checked_when_asked(self, outcome):
        assert check_approval(approval(outcome.case, scope="staging"),
                              outcome.case).valid


# ── the check reports everything, and repairs nothing ────────────────────────

class TestCheckDiscipline:

    def test_every_applicable_condition_is_reported(self, outcome):
        both = dataclasses.replace(
            approval(outcome.case), subject_digest="sha256:" + "f" * 64,
            timestamp="2025-01-01T00:00:00Z", expires_at="2026-01-01T00:00:00Z")
        found = check_approval(both, outcome.case, now="2026-06-01T00:00:00Z")
        assert set(found.conditions) == {ApprovalStanding.APPROVAL_INVALIDATED,
                                         ApprovalStanding.APPROVAL_EXPIRED}
        assert len(found.reasons) == 2

    def test_the_worst_condition_names_the_standing(self, outcome):
        both = dataclasses.replace(
            approval(outcome.case), subject_digest="sha256:" + "f" * 64,
            timestamp="2025-01-01T00:00:00Z", expires_at="2026-01-01T00:00:00Z")
        found = check_approval(both, outcome.case, now="2026-06-01T00:00:00Z")
        assert found.standing is ApprovalStanding.APPROVAL_INVALIDATED

    def test_checking_never_refreshes_the_approval(self, outcome):
        expiring = approval(outcome.case, timestamp="2025-01-01T00:00:00Z",
                            expires_at="2026-01-01T00:00:00Z")
        check_approval(expiring, outcome.case, now="2026-06-01T00:00:00Z")
        assert expiring.expires_at == "2026-01-01T00:00:00Z"
        assert check_approval(expiring, outcome.case,
                              now="2026-06-01T00:00:00Z").standing \
            is ApprovalStanding.APPROVAL_EXPIRED

    def test_a_valid_check_says_what_it_verified(self, outcome):
        found = check_approval(approval(outcome.case), outcome.case)
        assert found.valid
        assert "unchanged" in found.reasons[0]

    def test_the_check_serialises(self, outcome):
        payload = check_approval(approval(outcome.case), outcome.case).to_dict()
        assert payload["record_type"] == "approval_check"
        assert json.loads(json.dumps(payload))["valid"] is True


# ── it attaches to a sealed case ─────────────────────────────────────────────

class TestAttachment:

    def test_an_approval_attaches_to_a_sealed_case(self, outcome):
        approved = outcome.case.with_approval(approval(outcome.case))
        assert approved.state.value == "APPROVED"
        assert len(approved.records("approvals")) == 1

    def test_it_stays_outside_the_case_digest(self, outcome):
        before = outcome.case.binding_state()["case_digest"]
        approved = outcome.case.with_approval(approval(outcome.case))
        assert approved.binding_state()["case_digest"] == before

    def test_an_approval_still_checks_after_attachment(self, outcome):
        found = approval(outcome.case)
        approved = outcome.case.with_approval(found)
        assert check_approval(found, approved).valid


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
    first = _assure(tmp_path, "one.json", _BASE)
    second = _assure(tmp_path, "two.json", _BASE + [
        {"record_type": "claim", "claim_id": "B", "statement": "something else"}])
    return first, second
