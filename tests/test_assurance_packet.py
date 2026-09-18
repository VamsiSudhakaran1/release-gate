"""The approval packet: eleven questions, answered in the order a person asks them."""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.packet import (
    CORE_SECTIONS,
    ApprovalPacket, AssuranceDelta, PacketSection, SectionKey, build_packet,
    compare_cases, render_packet)
from release_gate.assurance.records import MaterialisationBasis


# ── all eleven, always ───────────────────────────────────────────────────────

class TestTheElevenQuestions:

    def test_every_section_is_present(self, packet):
        """The core eleven, in order. DOMAIN is not one of them — it is appended
        zero or more times by whatever plugins are installed, so asserting
        against the whole enum would make the core set depend on them."""
        assert [s.key for s in packet.sections] == list(CORE_SECTIONS)
        assert SectionKey.DOMAIN not in CORE_SECTIONS

    def test_they_are_numbered_in_the_order_a_reviewer_asks(self, packet):
        assert [s.number for s in packet.sections] == list(range(1, 12))

    def test_each_asks_its_question_verbatim(self, packet):
        assert packet.section(SectionKey.SUBJECT).question == \
            "What exactly am I being asked to authorize?"
        assert packet.section(SectionKey.NOT_ASSESSED).question == \
            "What has not been assessed?"
        assert packet.section(SectionKey.BINDING).question == \
            "What exact digests will approval bind to?"

    def test_a_packet_missing_a_section_is_refused(self):
        with pytest.raises(ValueError) as exc:
            ApprovalPacket(sections=(PacketSection(key=SectionKey.SUBJECT),))
        assert "all eleven" in str(exc.value)
        assert "an absent one reads" in str(exc.value)

    def test_a_section_with_nothing_to_say_still_appears(self, empty_packet):
        found = empty_packet.section(SectionKey.VERIFICATION)
        assert found.answer
        assert "No typed verification" in found.answer

    def test_the_render_carries_all_eleven_headings(self, packet):
        rendered = render_packet(packet)
        for number in range(1, 12):
            assert f"## {number}." in rendered


# ── the packet binds; it does not approve ────────────────────────────────────

class TestNeverAuthorises:

    def test_authorises_is_unconditionally_false(self, packet):
        assert packet.authorises is False
        assert packet.to_dict()["authorises"] is False

    def test_the_recommendation_says_it_is_not_an_authorisation(self, packet):
        note = packet.section(SectionKey.RECOMMENDATION).note
        assert "not an authorisation" in note
        assert "responsibility for it, is yours" in note

    def test_the_header_says_so_before_anything_else(self, packet):
        assert "does not authorise anything" in render_packet(packet)

    def test_no_section_claims_completeness(self, packet):
        for section in packet.sections:
            assert section.to_dict()["bounds_completeness"] is False


# ── section 8: a first run is not an unchanged run ───────────────────────────

class TestAssuranceDelta:

    def test_no_previous_state_says_so_rather_than_nothing_changed(self, packet):
        found = packet.section(SectionKey.DELTA)
        assert "No previous verified state was supplied" in found.answer
        assert "not the same as nothing having changed" in found.answer

    def test_an_unchanged_case_is_reported_as_unchanged(self, outcome):
        delta = compare_cases(outcome.case, outcome.case)
        assert delta.has_previous
        assert not delta.case_changed
        assert "byte-identical" in delta.render()

    def test_a_grown_case_names_what_grew(self, two_versions):
        first, second = two_versions
        delta = compare_cases(first.case, second.case)
        assert delta.case_changed
        assert "evidence" in delta.grew

    def test_evidence_disappearing_is_called_out(self, two_versions):
        first, second = two_versions
        delta = compare_cases(second.case, first.case)
        assert "evidence" in delta.shrank
        assert "LOST evidence" in delta.render()

    def test_release_gates_own_outputs_shrinking_is_not_a_disclosure_signal(
            self, two_versions):
        first, second = two_versions
        delta = compare_cases(first.case, second.case)
        assert "attention_items" not in delta.shrank
        assert "not evidence going missing" in delta.render()

    def test_approval_never_carries_across_a_change(self, two_versions):
        first, second = two_versions
        delta = compare_cases(first.case, second.case)
        assert delta.approval_carryover_permitted is False
        assert delta.to_dict()["approval_carryover_permitted"] is False

    def test_a_subject_change_with_no_named_field_still_reads(self, two_versions):
        first, second = two_versions
        rendered = compare_cases(first.case, second.case).render()
        assert "()" not in rendered
        assert "content digest moved" in rendered

    def test_a_stored_binding_state_works_as_the_previous(self, two_versions):
        first, second = two_versions
        from_case = compare_cases(first.case, second.case)
        from_dict = compare_cases(first.case.binding_state(), second.case)
        assert from_case.previous_case_digest == from_dict.previous_case_digest

    def test_an_empty_delta_reports_no_previous(self):
        delta = AssuranceDelta()
        assert not delta.has_previous
        assert not delta.case_changed


# ── section 9 carries the weight of section 3 ────────────────────────────────

class TestNotAssessed:

    def test_it_separates_never_examined_from_no_denominator(self, packet):
        found = packet.section(SectionKey.NOT_ASSESSED)
        labels = [str(r["label"]) for r in found.rows]
        assert any(l.startswith("NOT ASSESSED —") for l in labels)
        assert "never examined" in found.answer or "were never examined" in found.answer

    def test_never_examined_is_listed_before_no_denominator(self, packet):
        states = [r.get("state") for r in packet.section(SectionKey.NOT_ASSESSED).rows]
        if "NOT_ASSESSED" in states and "UNKNOWN" in states:
            assert states.index("NOT_ASSESSED") < states.index("UNKNOWN")

    def test_it_reads_the_sealed_case_not_the_running_analysis(self, outcome):
        # The analysis carries a ledger built while it was still running, so the
        # dimensions the analysers fill in are NOT_ASSESSED in it whatever they
        # went on to find. The case is authoritative.
        found = build_packet(outcome.case, outcome).section(SectionKey.NOT_ASSESSED)
        unexamined = {str(r["label"]).replace("NOT ASSESSED — ", "")
                      for r in found.rows if r.get("state") == "NOT_ASSESSED"}
        assessed = {r.to_dict()["dimension"] for r in outcome.case.records("coverage")
                    if r.to_dict().get("state") not in ("NOT_ASSESSED",)}
        assert not (unexamined & assessed)

    def test_the_note_says_it_weighs_the_same_as_the_evidence(self, packet):
        assert "same weight as section 3" in \
            packet.section(SectionKey.NOT_ASSESSED).note


# ── drill-down never implies completeness ────────────────────────────────────

class TestDrillDown:

    def test_sections_name_the_collections_to_open(self, packet):
        assert packet.section(SectionKey.SUPPORTING_EVIDENCE).drill_down
        assert "evidence" in packet.section(SectionKey.SUPPORTING_EVIDENCE).drill_down

    def test_a_capped_section_declares_the_cap(self):
        rows = tuple({"label": f"r{i}"} for i in range(40))
        section = PacketSection(key=SectionKey.SUPPORTING_EVIDENCE, rows=rows[:12],
                                truncated=28, total=40,
                                basis=MaterialisationBasis.CAPPED)
        assert not section.complete
        assert "28 more not shown of 40" in section.render()

    def test_a_complete_section_says_so_without_claiming_more(self):
        section = PacketSection(key=SectionKey.SUBJECT, rows=({"label": "a"},), total=1)
        assert section.complete
        assert section.to_dict()["bounds_completeness"] is False

    def test_truncated_sections_are_enumerable(self, packet):
        assert all(not s.complete for s in packet.truncated_sections)


# ── section 11 binds to an exact state ───────────────────────────────────────

class TestBinding:

    def test_it_states_the_case_digest(self, packet, outcome):
        found = packet.section(SectionKey.BINDING)
        assert outcome.case.binding_state()["case_digest"] in found.answer

    def test_it_names_the_binding_algorithm(self, packet):
        details = [str(r["detail"]) for r in packet.section(SectionKey.BINDING).rows]
        assert "rg-bind-1" in details

    def test_the_packet_knows_its_own_case(self, packet, outcome):
        assert packet.matches(outcome.case)

    def test_a_packet_detects_that_it_is_stale(self, two_versions):
        first, second = two_versions
        assert not build_packet(first.case, first).matches(second.case)

    def test_the_note_says_an_approval_does_not_carry(self, packet):
        assert "does not carry" in packet.section(SectionKey.BINDING).note

    def test_the_packet_id_is_content_derived(self, outcome):
        assert build_packet(outcome.case, outcome).packet_id == \
            build_packet(outcome.case, outcome).packet_id


# ── the substantive sections ─────────────────────────────────────────────────

class TestSectionContent:

    def test_the_subject_section_names_the_exact_digest(self, packet, outcome):
        found = packet.section(SectionKey.SUBJECT)
        assert outcome.case.subject.digest in found.answer

    def test_unknown_consequence_is_listed_not_omitted(self, packet):
        found = packet.section(SectionKey.CONSEQUENCE)
        assert "UNKNOWN" in found.answer
        assert any("UNKNOWN" in str(r["detail"]) for r in found.rows)
        assert "not a small one" in found.note

    def test_critical_evidence_is_ordered_first(self, outcome):
        found = build_packet(outcome.case, outcome).section(
            SectionKey.SUPPORTING_EVIDENCE)
        criticals = [bool(r.get("critical")) for r in found.rows]
        assert criticals == sorted(criticals, reverse=True)

    def test_an_absent_verification_is_a_fact_about_the_case(self, packet):
        found = packet.section(SectionKey.VERIFICATION)
        assert "No typed verification is recorded" in found.answer
        assert "a fact about the case, not about the subject" in found.note

    def test_verification_flags_an_attempt_with_no_target_digest(self, verified):
        found = build_packet(verified.case, verified).section(SectionKey.VERIFICATION)
        assert found.total >= 1
        assert any("applicability undetermined" in str(r["detail"])
                   for r in found.rows)
        assert "UNDETERMINED is not APPLIES" in found.note

    def test_unresolved_gathers_every_open_kind(self, refuted_outcome):
        found = build_packet(refuted_outcome.case, refuted_outcome).section(
            SectionKey.UNRESOLVED)
        assert found.total >= 1
        assert "resolved by being listed" in found.note

    def test_independence_refuses_to_be_a_probability(self, packet):
        assert "Structure, not probability" in \
            packet.section(SectionKey.INDEPENDENCE).note

    def test_failures_never_hide_a_load_bearing_one(self, packet):
        found = packet.section(SectionKey.FAILURES)
        assert "load-bearing" in found.note or found.truncated == 0

    def test_the_recommendation_names_the_fired_rules(self, refuted_outcome):
        found = build_packet(refuted_outcome.case, refuted_outcome).section(
            SectionKey.RECOMMENDATION)
        assert found.rows
        assert refuted_outcome.decision.value in found.answer


# ── serialisation ────────────────────────────────────────────────────────────

class TestSerialisation:

    def test_the_packet_serialises_whole(self, packet):
        payload = packet.to_dict()
        assert payload["record_type"] == "approval_packet"
        assert len(payload["sections"]) == 11
        assert payload["binds_to"]["case_digest"] == packet.case_digest

    def test_it_is_json_serialisable(self, packet):
        assert json.loads(json.dumps(packet.to_dict()))["authorises"] is False

    def test_the_outcome_builds_one_on_demand(self, outcome):
        built = outcome.packet()
        assert len(built.sections) == 11
        assert built.matches(outcome.case)

    def test_the_outcome_passes_a_previous_state_through(self, two_versions):
        first, second = two_versions
        found = second.packet(previous=first.case).section(SectionKey.DELTA)
        assert "No previous verified state" not in found.answer


# ── fixtures ─────────────────────────────────────────────────────────────────

def _assure(tmp_path, name, rows):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return assure(str(path))


_BASE = [
    {"record_type": "evidence", "evidence_id": "E-1", "evidence_type": "TOOL_RESULT",
     "producer": {"producer_id": "agent-A"}, "supports_claims": ["A"],
     "content": {"ok": True}},
    {"record_type": "claim", "claim_id": "A", "is_root": True,
     "statement": "the migration is safe", "supported_by": ["E-1"]},
]


@pytest.fixture
def outcome(tmp_path):
    return _assure(tmp_path, "case.json", _BASE)


@pytest.fixture
def packet(outcome):
    return build_packet(outcome.case, outcome)


@pytest.fixture
def empty_packet(tmp_path):
    return build_packet(*(lambda o: (o.case, o))(
        _assure(tmp_path, "bare.json", [
            {"record_type": "claim", "claim_id": "A", "statement": "s"}])))


@pytest.fixture
def two_versions(tmp_path):
    first = _assure(tmp_path, "v1.json", _BASE)
    second = _assure(tmp_path, "v2.json", _BASE + [
        {"record_type": "evidence", "evidence_id": "E-2",
         "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "agent-B"},
         "supports_claims": ["A"], "content": {"ok": True}}])
    return first, second


@pytest.fixture
def refuted_outcome(tmp_path):
    return _assure(tmp_path, "refuted.json", _BASE + [
        {"record_type": "adversarial", "target_claim": "A", "role": "RED_TEAM",
         "adversary": "rt", "outcome": "CANDIDATE_REFUTED", "detail": "broke it"}])


@pytest.fixture
def verified(tmp_path):
    # A verifier report whose results carry no target digest: the attempts exist
    # and cannot be shown to apply to the current state.
    return _assure(tmp_path, "verified.json", {
        "verifier": {"name": "lean", "version": "4.8.0", "family": "PROOF_ASSISTANT"},
        "results": [{"target": "A", "result": "proved"}]})
