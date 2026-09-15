"""Long-running cases: phases observed, never directed.

The constraint that shapes this file is "release-gate must not become the
orchestrator". So the tests that matter most are the ones asserting what this
module does NOT do: it commands nothing, it changes nothing when read, and it
cannot refuse a transition it disagrees with.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.session import AssuranceSession
from release_gate.assurance.streaming import (
    STREAMING_SCHEMA_VERSION, AssurancePhase, PhaseObservation, PhaseTransition,
    observe_phase, observe_session,
)

CLAIM = {"record_type": "claim", "claim_id": "c1", "proposition": "migration is safe",
         "is_root": True, "producer": {"producer_id": "a://1", "kind": "agent"}}
TRACE = {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
         "producer": {"producer_id": "a://1", "kind": "agent"},
         "coverage_note": "step 1"}


def session(records=()):
    s = AssuranceSession.open(methodology=PROFILE)
    if records:
        s.extend(list(records))
    return s


def with_attempt(outcome):
    claim = dict(CLAIM)
    claim["verification_attempts"] = [
        {"evidence_id": "ev1", "method": "TEST_SUITE", "outcome": outcome}]
    return session([claim, {"record_type": "evidence", "evidence_id": "ev1",
                            "kind": "TEST_RESULT",
                            "producer": {"producer_id": "ci://1", "kind": "tool"},
                            "supports_claims": ["c1"], "coverage_note": "suite"}])


# ── release-gate is not the orchestrator ────────────────────────────────────

class TestNotTheOrchestrator:
    """The constraint the whole module is shaped by."""

    def test_an_observation_never_directs_work(self):
        for phase in AssurancePhase:
            assert PhaseObservation(phase).directs_work is False

    def test_the_dict_carries_the_refusal(self):
        assert observe_session(session([TRACE])).to_dict()["directs_work"] is False

    def test_the_module_exposes_no_command(self):
        """No `begin_verification`, no `request_review`, nothing imperative."""
        import release_gate.assurance.streaming as module
        for name in dir(module):
            assert not name.startswith(("start_", "begin_", "request_", "schedule_",
                                        "trigger_", "retry_", "pause_", "stop_")), name

    def test_observing_does_not_finalize_a_session(self):
        live = session([TRACE])
        observe_session(live)
        observe_session(live)
        assert not live.finalized

    def test_observing_does_not_change_the_phase(self):
        """Pure: the same case always reads the same way."""
        live = session([CLAIM, TRACE])
        assert observe_session(live).phase is observe_session(live).phase

    def test_a_regression_is_reported_not_refused(self):
        """Release-gate does not control the world. If evidence arrived after a
        human started reviewing, that happened."""
        transition = PhaseTransition(AssurancePhase.HUMAN_REVIEW,
                                     AssurancePhase.EVIDENCE_ACCUMULATING)
        assert transition.regressed
        assert "moved backwards" in transition.note()

    def test_there_is_no_way_to_forbid_a_transition(self):
        import release_gate.assurance.streaming as module
        assert not hasattr(module, "enforce_transition")
        assert not hasattr(PhaseTransition, "permitted")


# ── the eight phases ────────────────────────────────────────────────────────

class TestPhases:

    def test_all_eight_are_defined(self):
        assert len(list(AssurancePhase)) == 8

    def test_an_empty_case_is_open(self):
        """Release-gate records its own work — the input container it hashed and
        the profiles it derived — so counting raw evidence made every session
        report CANDIDATE_READY before anyone had sent anything."""
        assert observe_session(session()).phase is AssurancePhase.OPEN

    def test_raw_evidence_is_accumulating_not_a_candidate(self):
        assert observe_session(session([TRACE])).phase \
            is AssurancePhase.EVIDENCE_ACCUMULATING

    def test_an_asserted_claim_is_a_candidate(self):
        """What makes a candidate is somebody asserting something, not the
        subject digest — release-gate always sets one of those."""
        assert observe_session(session([CLAIM])).phase is AssurancePhase.CANDIDATE_READY

    def test_an_unsettled_check_is_verifying(self):
        observation = observe_session(with_attempt("NOT_RUN"))
        assert observation.phase is AssurancePhase.VERIFYING
        assert "not settled" in observation.basis

    def test_a_settled_check_on_an_open_case_is_still_verifying(self):
        """Attempts arrive embedded on claims, so the `verification` collection
        stays empty; counting it reported 'nothing has checked it' on a case
        carrying a passed suite."""
        observation = observe_session(with_attempt("PASSED"))
        assert observation.phase is AssurancePhase.VERIFYING
        assert observation.observed["verifications"] == 1

    def test_a_finalized_case_awaits_a_person(self):
        live = with_attempt("PASSED")
        live.finalize()
        assert observe_session(live).phase is AssurancePhase.HUMAN_REVIEW

    def test_an_invalidated_record_is_terminal(self):
        class Case:
            class state:
                value = "INVALIDATED"
            def collection(self, kind):
                raise KeyError(kind)
            subject = None
        assert observe_phase(Case()).phase is AssurancePhase.INVALIDATED

    def test_an_approval_decision_is_read_not_inferred(self):
        live = session([CLAIM])
        case = live.provisional().case

        class Approval:
            def __init__(self, decision):
                self.decision = decision
                self.standing = "VALID"
        assert observe_phase(case, finalized=True,
                             approval=Approval("APPROVED")).phase \
            is AssurancePhase.APPROVED
        assert observe_phase(case, finalized=True,
                             approval=Approval("REJECTED")).phase \
            is AssurancePhase.REJECTED

    def test_an_invalidated_approval_outranks_its_decision(self):
        live = session([CLAIM])

        class Approval:
            decision = "APPROVED"
            standing = "APPROVAL_INVALIDATED"
        assert observe_phase(live.provisional().case, finalized=True,
                             approval=Approval()).phase \
            is AssurancePhase.INVALIDATED

    def test_terminal_phases_are_marked(self):
        terminal = {p for p in AssurancePhase if p.terminal}
        assert terminal == {AssurancePhase.APPROVED, AssurancePhase.REJECTED,
                            AssurancePhase.INVALIDATED}

    def test_every_phase_describes_itself(self):
        for phase in AssurancePhase:
            assert phase.describe()


# ── weaknesses while the work continues ─────────────────────────────────────

class TestLiveExposure:
    """A weakness at minute three is worth more than the same one at hour six."""

    CONFLICTED = [
        {"record_type": "claim", "claim_id": "c1", "proposition": "safe",
         "is_root": True, "producer": {"producer_id": "a://1", "kind": "agent"},
         "supporting_evidence": ["ok"], "contradicting_evidence": ["bad"]},
        {"record_type": "evidence", "evidence_id": "ok", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://1", "kind": "tool"},
         "supports_claims": ["c1"], "coverage_note": "passed"},
        {"record_type": "evidence", "evidence_id": "bad", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://2", "kind": "tool"},
         "contradicts_claims": ["c1"], "coverage_note": "failed"},
    ]

    def test_concerns_surface_before_the_work_finishes(self):
        live = session(self.CONFLICTED)
        observation = observe_session(live)
        assert not live.finalized
        assert observation.open_concerns

    def test_a_contradiction_is_visible_mid_flight(self):
        live = session(self.CONFLICTED)
        assert list(live.provisional().case.collection("contradictions").materialised)

    def test_the_note_says_concerns_do_not_need_the_work_to_finish(self):
        assert "do not need the work to finish" in observe_session(
            session(self.CONFLICTED)).note()

    def test_more_evidence_can_arrive_after_a_reading(self):
        live = session([TRACE])
        observe_session(live)
        live.add(dict(CLAIM))
        assert observe_session(live).phase is AssurancePhase.CANDIDATE_READY


# ── transitions ─────────────────────────────────────────────────────────────

class TestTransitions:

    def test_forward_movement_is_not_a_regression(self):
        assert not PhaseTransition(AssurancePhase.OPEN,
                                   AssurancePhase.CANDIDATE_READY).regressed

    def test_invalidation_from_anywhere_is_not_a_regression(self):
        """The subject moving is new information, not a step backwards."""
        for phase in AssurancePhase:
            assert not PhaseTransition(phase, AssurancePhase.INVALIDATED).regressed

    def test_reopening_a_settled_case_is_flagged(self):
        transition = PhaseTransition(AssurancePhase.APPROVED,
                                     AssurancePhase.EVIDENCE_ACCUMULATING)
        assert transition.reopens_a_settled_case
        assert "no longer holds" in transition.note()

    def test_standing_still_is_neither(self):
        transition = PhaseTransition(AssurancePhase.VERIFYING, AssurancePhase.VERIFYING)
        assert not transition.regressed
        assert transition.note() == "still VERIFYING"

    def test_it_serialises(self):
        payload = PhaseTransition(AssurancePhase.OPEN,
                                  AssurancePhase.VERIFYING).to_dict()
        assert payload["previous"] == "OPEN" and payload["current"] == "VERIFYING"


class TestSerialisation:

    def test_an_observation_serialises(self):
        payload = observe_session(session([CLAIM])).to_dict()
        assert payload["record_type"] == "assurance_phase"
        assert payload["phase"] == "CANDIDATE_READY"
        assert payload["schema_version"] == STREAMING_SCHEMA_VERSION

    def test_the_observation_shows_what_it_was_read_from(self):
        observed = observe_session(session([CLAIM, TRACE])).observed
        assert observed["claims"] == 1
        assert observed["candidate_present"] is True

    def test_case_state_and_phase_stay_separate_axes(self):
        """A long-running case is routinely both 'evidence still arriving' and
        'this snapshot is sealed and digested'."""
        live = session([TRACE])
        outcome = live.provisional()
        assert outcome.case.state.value == "SEALED"
        assert observe_session(live).phase is AssurancePhase.EVIDENCE_ACCUMULATING
