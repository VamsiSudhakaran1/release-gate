"""Trust boundaries: five axes held apart, eight threats modelled honestly.

Two properties carry this file. The five axes must not be collapsible into one
number, because a signed record from an unvetted verifier and an unsigned
assertion from a trusted vendor would land on the same score while being opposite
situations. And the threat model must say which threats release-gate cannot see —
a model that graded everything "handled" would be worse than none, because a
reader would stop looking.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.completeness import (
    EndOfStream, SourceStream, StreamLedger)
from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.session import AssuranceSession
from release_gate.assurance.trust import (
    TRUST_SCHEMA_VERSION, Detectability, IntegrityStatus, Threat,
    ThreatAssessment, TrustBoundary, TrustBoundaryError, TrustSurface,
    assess_threats, boundaries_from_case, trust_surface,
)

SOLO = [{"record_type": "evidence", "evidence_id": f"e{i}", "kind": "TRACE",
         "producer": {"producer_id": "agent://solo", "kind": "agent"},
         "coverage_note": f"step {i}"} for i in range(3)]

CORROBORATED = SOLO + [
    {"record_type": "evidence", "evidence_id": "v1", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://independent", "kind": "tool"},
     "coverage_note": "suite"}]


def case(records):
    return AssuranceSession.open(methodology=PROFILE).extend(
        list(records)).finalize().case


# ── five axes, no score ─────────────────────────────────────────────────────

class TestAxesStayApart:

    def test_there_is_no_overall_score(self):
        """Any such method would be called, its result stored, and the four axes
        it flattened would stop travelling with it."""
        for name in ("score", "level", "ok", "verdict", "rating", "overall"):
            assert not hasattr(TrustBoundary, name), name

    def test_all_five_axes_are_present(self):
        boundary = TrustBoundary(source="a://1")
        assert set(boundary.axes) == {"source", "provenance", "trust",
                                      "integrity", "completeness"}

    def test_provenance_does_not_establish_trust(self):
        """A signature proves who wrote something, not that they were right."""
        signed = TrustBoundary(source="a://1", provenance="SIGNED")
        assert signed.attributed
        assert not signed.relied_upon

    def test_trust_does_not_establish_provenance(self):
        trusted = TrustBoundary(source="a://1", trust="ACCEPTED")
        assert trusted.relied_upon
        assert not trusted.attributed

    def test_integrity_is_independent_of_provenance(self):
        """A record can be signed by exactly the right party and truncated in
        transit; an unattributed one can arrive byte-perfect."""
        assert TrustBoundary(source="a", provenance="SIGNED",
                             integrity=IntegrityStatus.BROKEN).attributed
        assert TrustBoundary(source="a", provenance="UNATTRIBUTED",
                             integrity=IntegrityStatus.VERIFIED).integrity \
            is IntegrityStatus.VERIFIED

    def test_a_boundary_must_name_its_source(self):
        with pytest.raises(TrustBoundaryError, match="statements about nobody"):
            TrustBoundary(source="  ")

    def test_the_note_says_five_answers_not_one(self):
        assert "five separate answers, not one verdict" in \
            TrustBoundary(source="a://1").note()

    def test_it_serialises_every_axis(self):
        payload = TrustBoundary(source="a://1").to_dict()
        for axis in ("source", "provenance", "trust", "integrity", "completeness"):
            assert axis in payload
        assert payload["schema_version"] == TRUST_SCHEMA_VERSION


# ── the threat model is honest ──────────────────────────────────────────────

class TestThreatModel:

    def test_all_eight_threats_are_modelled(self):
        assessed = {t.threat for t in assess_threats()}
        assert assessed == set(Threat)

    def test_some_threats_are_admitted_as_invisible(self):
        """A model that graded everything 'handled' would be worse than none."""
        invisible = [t for t in assess_threats()
                     if t.detectability is Detectability.OUTSIDE_VISIBILITY]
        assert invisible
        assert all(not t.release_gate_can_catch_it for t in invisible)

    def test_poisoned_tool_output_is_outside_visibility(self):
        """Release-gate has no model of what the tool should have reported."""
        threat = next(t for t in assess_threats()
                      if t.threat is Threat.TOOL_OUTPUT_POISONED)
        assert threat.detectability is Detectability.OUTSIDE_VISIBILITY

    def test_a_lone_consistent_liar_is_only_mitigated(self):
        """There is no structural signal in a well-formed falsehood."""
        threat = next(t for t in assess_threats() if t.threat is Threat.AGENT_LIES)
        assert threat.detectability is Detectability.MITIGATED_ONLY
        assert "nothing to disagree with" in threat.basis

    def test_stale_approval_is_genuinely_detected(self):
        threat = next(t for t in assess_threats()
                      if t.threat is Threat.HUMAN_APPROVES_STALE_STATE)
        assert threat.detectability is Detectability.DETECTED
        assert threat.release_gate_can_catch_it

    def test_stale_verification_is_genuinely_detected(self):
        threat = next(t for t in assess_threats()
                      if t.threat is Threat.VERIFICATION_APPLIES_TO_OLD_ARTIFACT)
        assert threat.detectability is Detectability.DETECTED

    def test_every_threat_states_a_mitigation(self):
        for threat in assess_threats():
            assert threat.mitigation, threat.threat
            assert threat.basis, threat.threat

    def test_the_orchestrator_omission_threat_names_the_hard_part(self):
        threat = next(t for t in assess_threats()
                      if t.threat is Threat.ORCHESTRATOR_OMITS_FAILURES)
        assert "cannot detect its own omission" in threat.basis


# ── the case sharpens the model ─────────────────────────────────────────────

class TestCaseObservations:

    def test_one_producer_removes_the_mitigation(self):
        """The mitigation for those threats IS corroboration, and there is none."""
        surface = trust_surface(case(SOLO))
        assert surface.single_producer
        unmitigated = [t for t in surface.mitigated_only
                       if any("does not exist in this case" in o for o in t.observed)]
        assert len(unmitigated) == len(surface.mitigated_only)

    def test_a_second_producer_restores_it(self):
        surface = trust_surface(case(CORROBORATED))
        assert not surface.single_producer
        assert not [t for t in surface.mitigated_only
                    if any("does not exist" in o for o in t.observed)]

    def test_the_surface_note_spells_out_the_consequence(self):
        note = trust_surface(case(SOLO)).note()
        assert "internally consistent and invisible" in note

    def test_a_gapped_ledger_upgrades_telemetry_detection(self):
        ledger = StreamLedger(
            streams=(SourceStream(stream_id="s1", producer_id="a://1",
                                  observed_sequences=(1, 3)),),
            expected_streams=("s1",))
        threat = next(t for t in assess_threats(ledger=ledger)
                      if t.threat is Threat.TELEMETRY_INCOMPLETE)
        assert threat.detectability is Detectability.DETECTED

    def test_self_certified_completeness_is_observed_against_omission(self):
        ledger = StreamLedger(
            streams=(SourceStream(stream_id="s1", producer_id="a://1",
                                  observed_sequences=(1, 2),
                                  end_of_stream=EndOfStream(declared_by="a://1")),),
            expected_streams=("s1",))
        threat = next(t for t in assess_threats(ledger=ledger)
                      if t.threat is Threat.ORCHESTRATOR_OMITS_FAILURES)
        assert any("cannot detect its own omission" in o for o in threat.observed)

    def test_an_unnumbered_stream_is_observed_as_shapeless(self):
        ledger = StreamLedger(streams=(SourceStream(stream_id="s1",
                                                    producer_id="a://1"),))
        threat = next(t for t in assess_threats(ledger=ledger)
                      if t.threat is Threat.TELEMETRY_INCOMPLETE)
        assert any("no trace" in o for o in threat.observed)


# ── reading producers off a case ────────────────────────────────────────────

class TestBoundariesFromCase:

    def test_one_boundary_per_producer(self):
        boundaries = boundaries_from_case(case(CORROBORATED))
        assert {b.source for b in boundaries} == {"agent://solo", "ci://independent"}

    def test_release_gate_is_not_a_producer_being_weighed(self):
        """Including it would put a self-attested row in every surface."""
        assert not any("release-gate" in b.source
                       for b in boundaries_from_case(case(SOLO)))

    def test_records_are_counted_per_producer(self):
        boundaries = {b.source: b for b in boundaries_from_case(case(CORROBORATED))}
        assert boundaries["agent://solo"].records == 3
        assert boundaries["ci://independent"].records == 1

    def test_an_input_release_gate_hashed_itself_is_verified_integrity(self):
        from release_gate.assurance.trust import _integrity_of

        class Ref:
            kind = "FILE"

        class Record:
            digest = "sha256:" + "a" * 64
            content_reference = Ref()
        assert _integrity_of(Record()) is IntegrityStatus.VERIFIED

    def test_a_digest_nobody_rechecked_is_declared_not_verified(self):
        """A digest supplied alongside its own content establishes only that the
        producer is consistent with itself."""
        from release_gate.assurance.trust import _integrity_of

        class Ref:
            kind = "EXTERNAL"

        class Record:
            digest = "sha256:" + "a" * 64
            content_reference = Ref()
        assert _integrity_of(Record()) is IntegrityStatus.DECLARED

    def test_no_digest_is_not_assessed_rather_than_fine(self):
        from release_gate.assurance.trust import _integrity_of

        class Record:
            digest = ""
            content_reference = None
        assert _integrity_of(Record()) is IntegrityStatus.NOT_ASSESSED

    def test_the_worst_integrity_in_a_group_wins(self):
        from release_gate.assurance.trust import _worst_integrity
        assert _worst_integrity([IntegrityStatus.VERIFIED,
                                 IntegrityStatus.BROKEN]) is IntegrityStatus.BROKEN
        assert _worst_integrity([IntegrityStatus.VERIFIED,
                                 IntegrityStatus.DECLARED]) is IntegrityStatus.DECLARED


class TestSurface:

    def test_it_serialises(self):
        payload = trust_surface(case(CORROBORATED)).to_dict()
        assert payload["record_type"] == "trust_surface"
        assert len(payload["boundaries"]) == 2
        assert len(payload["threats"]) == 8

    def test_the_invisible_threats_are_listed_by_name(self):
        payload = trust_surface(case(SOLO)).to_dict()
        assert "TOOL_OUTPUT_POISONED" in payload["outside_visibility"]

    def test_an_empty_case_has_no_boundaries_and_still_has_the_model(self):
        surface = trust_surface(case([]))
        assert surface.boundaries == ()
        assert len(surface.threats) == 8
