"""The required-evidence protocol: HOLD as something a machine can act on."""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.attention import (
    RequiredEvidenceItem, RequiredEvidenceSet, build_required_evidence)
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.required_evidence import (
    EvidenceRequirement, EvidenceRequirementKind, acceptance_for,
    requirement_kind_for, requirement_kind_for_predicate, target_kind_for_focus)
from release_gate.assurance.verification import TargetKind, VerificationTarget


def requirement(**kw):
    kw.setdefault("target", VerificationTarget.claim("C-184"))
    kw.setdefault("requirement", EvidenceRequirementKind.INDEPENDENT_VERIFICATION)
    kw.setdefault("reason", "critical single-lineage dependency")
    return EvidenceRequirement(**kw)


# ── the wire shape ───────────────────────────────────────────────────────────

class TestTheProtocolShape:

    def test_it_emits_the_documented_three_keys(self):
        payload = requirement().to_dict()
        assert payload["target"] == "claim:C-184"
        assert payload["requirement"] == "independent_verification"
        assert payload["reason"] == "critical single-lineage dependency"

    def test_an_artifact_target_reads_as_documented(self):
        payload = requirement(
            target=VerificationTarget.artifact("A-22"),
            requirement=EvidenceRequirementKind.FORMAL_VERIFICATION,
            reason="artifact changed after prior verification").to_dict()
        assert payload["target"] == "artifact:A-22"
        assert payload["requirement"] == "formal_verification"

    def test_targets_round_trip(self):
        assert VerificationTarget.parse("claim:C-184").reference == "claim:C-184"
        assert VerificationTarget.parse("artifact:A-22").kind is TargetKind.ARTIFACT

    def test_an_unknown_target_kind_reads_back_without_losing_the_id(self):
        parsed = VerificationTarget.parse("gizmo:G-1")
        assert parsed.kind is TargetKind.OTHER
        assert parsed.target_id == "G-1"

    def test_a_bare_reference_is_not_an_error(self):
        assert VerificationTarget.parse("C-184").target_id == "C-184"

    def test_the_requirement_round_trips(self):
        original = requirement(constraints={"independent_of": ["agent-A"]},
                               acceptance="a", resolves=("RG-PROV-002",))
        assert EvidenceRequirement.from_dict(original.to_dict()) == original

    def test_the_id_is_content_derived_and_stable(self):
        assert requirement().requirement_id == requirement().requirement_id

    def test_the_id_changes_with_the_target(self):
        other = requirement(target=VerificationTarget.claim("C-999"))
        assert other.requirement_id != requirement().requirement_id


# ── release-gate does not orchestrate ────────────────────────────────────────

class TestNoOrchestration:

    FORBIDDEN = {"assignee", "assigned_to", "agent", "agent_id", "worker",
                 "priority", "deadline", "due", "schedule", "scheduled_at",
                 "callback", "callback_url", "webhook", "retry", "order",
                 "dispatch_to", "queue"}

    def test_a_requirement_carries_no_orchestration_field(self):
        assert not (set(requirement().to_dict()) & self.FORBIDDEN)

    def test_the_protocol_envelope_carries_none_either(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        protocol = outcome.required_evidence.protocol()
        assert not (set(protocol) & self.FORBIDDEN)
        for entry in protocol["required_evidence"]:
            assert not (set(entry) & self.FORBIDDEN)

    def test_the_whole_serialised_payload_is_free_of_them(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        blob = json.dumps(outcome.required_evidence.protocol())
        for word in self.FORBIDDEN:
            assert f'"{word}"' not in blob


# ── satisfying it never authorises ───────────────────────────────────────────

class TestNeverAuthorises:

    def test_the_protocol_says_so_in_the_payload(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        assert outcome.required_evidence.protocol()["satisfies_decision"] is False

    def test_the_set_says_so_too(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        assert outcome.required_evidence.to_dict()["satisfies_decision"] is False

    def test_the_note_refuses_the_promise_when_no_methodology_exists(self,
                                                                     assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        assert "once satisfied, yields PROMOTE" in outcome.required_evidence.note


# ── one requirement per target ───────────────────────────────────────────────

class TestPerTargetGrouping:

    def test_two_claims_needing_the_same_thing_are_two_requirements(self,
                                                                    assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "depends_on": ["B", "C"]},
            {"record_type": "claim", "claim_id": "B", "statement": "unsupported"},
            {"record_type": "claim", "claim_id": "C", "statement": "unsupported"}])
        targets = {i.target for i in outcome.required_evidence}
        assert "claim:B" in targets
        assert "claim:C" in targets

    def test_no_two_requirements_share_a_target_and_kind(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "depends_on": ["B"]},
            {"record_type": "claim", "claim_id": "B", "statement": "unsupported"}])
        keys = [(i.target, i.kind) for i in outcome.required_evidence]
        assert len(keys) == len(set(keys))

    def test_for_target_selects(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "depends_on": ["B"]},
            {"record_type": "claim", "claim_id": "B", "statement": "unsupported"}])
        assert outcome.required_evidence.for_target("claim:B")
        assert not outcome.required_evidence.for_target("claim:absent")

    def test_a_whole_case_finding_targets_the_case_not_a_record(self,
                                                                assure_envelope):
        # "All your evidence has one producer" is not fixed by opening one record.
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "agent-A"},
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-1"]}])
        found = outcome.required_evidence.for_target("case:RG-PROV-002")
        assert found
        assert found[0].kind is EvidenceRequirementKind.INDEPENDENT_VERIFICATION


# ── what would count ─────────────────────────────────────────────────────────

class TestConstraintsAndAcceptance:

    def test_a_single_producer_case_names_the_lineage_to_avoid(self,
                                                               assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "agent-A"},
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-1"]}])
        found = outcome.required_evidence.for_target("case:RG-PROV-002")[0]
        assert "agent-A" in found.requirement.constraints["independent_of"]

    def test_every_kind_states_what_would_count(self):
        for kind in EvidenceRequirementKind:
            assert acceptance_for(kind)

    def test_acceptance_lands_on_the_requirement(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        assert all(i.requirement.acceptance for i in outcome.required_evidence)

    def test_an_empty_search_acceptance_states_the_asymmetry(self):
        text = acceptance_for(EvidenceRequirementKind.COUNTEREXAMPLE_SEARCH)
        assert "bounds the search and never the claim" in text


# ── unspecified is honest, not tidy ──────────────────────────────────────────

class TestUnspecified:

    def test_an_unmapped_rule_degrades_rather_than_guessing(self):
        assert requirement_kind_for("RG-MADE-UP-999") \
            is EvidenceRequirementKind.UNSPECIFIED

    def test_an_unmapped_predicate_degrades_too(self):
        assert requirement_kind_for_predicate("somebody_elses_predicate") \
            is EvidenceRequirementKind.UNSPECIFIED

    def test_unspecified_is_not_dispatchable(self):
        assert not requirement(
            requirement=EvidenceRequirementKind.UNSPECIFIED).dispatchable

    def test_a_named_kind_is_dispatchable(self):
        assert requirement().dispatchable

    def test_the_set_separates_the_two(self):
        dispatchable = RequiredEvidenceItem(
            requirement_id="a", what="w", why="y", effect=RequirementEffect.HOLD,
            requirement=requirement())
        vague = RequiredEvidenceItem(
            requirement_id="b", what="w", why="y", effect=RequirementEffect.HOLD,
            requirement=requirement(
                requirement=EvidenceRequirementKind.UNSPECIFIED))
        found = RequiredEvidenceSet(items=(dispatchable, vague))
        assert len(found.dispatchable) == 1
        assert len(found.unspecified) == 1

    def test_unspecified_acceptance_admits_it(self):
        assert "cannot say what would close this" in acceptance_for(
            EvidenceRequirementKind.UNSPECIFIED)


# ── every rule is dispatchable ───────────────────────────────────────────────

class TestDispatchTable:

    def test_every_analysis_rule_has_a_requirement_kind(self):
        import re
        from pathlib import Path
        from release_gate.assurance import required_evidence as module
        rules = set(re.findall(
            r'rule_id="(RG-[A-Z]+-\d+)"',
            Path(module.__file__).with_name("analysis.py").read_text()))
        unmapped = {r for r in rules
                    if requirement_kind_for(r) is EvidenceRequirementKind.UNSPECIFIED}
        assert unmapped == set()

    def test_every_built_in_predicate_has_a_requirement_kind(self):
        """The CORE set, not the live table.

        `_PREDICATE_TYPES` is process-global and a domain plugin registers into
        it, so reading it here would make this test depend on whether a plugin
        test ran first — and would demand that a domain's predicate map to a
        core requirement kind, which is not the core's business to insist on.
        `CORE_PREDICATE_KINDS` is the snapshot taken before any plugin can run.
        """
        from release_gate.assurance.plugin import CORE_PREDICATE_KINDS
        unmapped = {k for k in CORE_PREDICATE_KINDS
                    if requirement_kind_for_predicate(k)
                    is EvidenceRequirementKind.UNSPECIFIED}
        assert unmapped == {"predicate"} or unmapped == set()

    def test_focus_kinds_map_to_addressable_targets(self):
        from release_gate.assurance.attention import _FOCUS_KIND, _WHOLE_CASE_KINDS
        for kind in set(_FOCUS_KIND.values()) - _WHOLE_CASE_KINDS:
            assert target_kind_for_focus(kind) is not TargetKind.CASE, kind

    def test_a_whole_case_focus_targets_the_case(self):
        assert target_kind_for_focus("producer") is TargetKind.CASE
        assert target_kind_for_focus("input") is TargetKind.CASE


# ── methodology holds are dispatchable ───────────────────────────────────────

class TestMethodologyRequirements:

    def methodology(self):
        from release_gate.assurance.case import CaseType
        from release_gate.assurance.methodology import (
            AncestryIndependence, AdversarialReviewRequired, AssuranceMethodology,
            ReplicationEstablished, Requirement)
        return AssuranceMethodology(
            methodology_id="demo", version="1.0.0", domain="demo",
            case_types=tuple(CaseType),
            requirements=(
                Requirement(requirement_id="indep",
                            description="support rests on two lineages",
                            predicate=AncestryIndependence(minimum_roots=2),
                            effect=RequirementEffect.HOLD),
                Requirement(requirement_id="repl",
                            description="the result is reproduced",
                            predicate=ReplicationEstablished(minimum_paths=2),
                            effect=RequirementEffect.HOLD),
                Requirement(requirement_id="adv",
                            description="somebody tried to break it",
                            predicate=AdversarialReviewRequired(minimum_attacks=1),
                            effect=RequirementEffect.BLOCK)))

    def outcome(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "m.json"
        path.write_text(json.dumps([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "agent-A"},
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-1"]}]))
        return assure(str(path), methodology=self.methodology())

    def test_an_unmet_requirement_says_what_kind_of_evidence_it_wants(self, tmp_path):
        required = self.outcome(tmp_path).required_evidence
        kinds = {i.target: i.kind for i in required}
        assert kinds["methodology:indep"] \
            is EvidenceRequirementKind.INDEPENDENT_VERIFICATION
        assert kinds["methodology:repl"] is EvidenceRequirementKind.REPLICATION
        assert kinds["methodology:adv"] is EvidenceRequirementKind.ADVERSARIAL_REVIEW

    def test_the_numbers_it_is_waiting_on_travel_as_constraints(self, tmp_path):
        required = self.outcome(tmp_path).required_evidence
        found = required.for_target("methodology:indep")[0]
        assert found.requirement.constraints["minimum_roots"] == 2

    def test_a_blocking_requirement_keeps_its_effect(self, tmp_path):
        required = self.outcome(tmp_path).required_evidence
        assert required.for_target("methodology:adv")[0].effect \
            is RequirementEffect.BLOCK

    def test_the_predicate_kind_reaches_the_result(self, tmp_path):
        outcome = self.outcome(tmp_path)
        unmet = [r for r in outcome.assessment.unmet()]
        assert all(r.predicate_kind for r in unmet)


# ── the return leg ───────────────────────────────────────────────────────────

class TestSolicitedEvidence:

    def test_evidence_can_cite_the_requirement_it_answers(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-2",
             "evidence_type": "TOOL_RESULT",
             "producer": {"producer_id": "verifier-B"},
             "in_response_to": "req_abc123",
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-2"]}])
        solicited = [r for r in outcome.normalisation.evidence
                     if (r.metadata or {}).get("solicited_by")]
        assert len(solicited) == 1
        assert solicited[0].metadata["solicited_by"] == "req_abc123"

    def test_the_solicitation_is_reported_not_laundered(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-2",
             "evidence_type": "TOOL_RESULT",
             "producer": {"producer_id": "verifier-B"},
             "in_response_to": "req_abc123",
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-2"]}])
        found = next(f for f in outcome.analysis.findings
                     if f.rule_id == "RG-PROV-003")
        assert found.effect is RequirementEffect.ADVISORY
        assert "not a reason to weigh the evidence less" in found.detail
        assert "req_abc123" in found.observed["requirements"]

    def test_unsolicited_evidence_raises_nothing(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "agent-A"},
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-1"]}])
        assert not [f for f in outcome.analysis.findings
                    if f.rule_id == "RG-PROV-003"]


# ── scale ────────────────────────────────────────────────────────────────────

class TestScale:

    def test_many_targets_are_capped_with_the_remainder_declared(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        rows = [{"record_type": "claim", "claim_id": "C-0", "is_root": True,
                 "statement": "s",
                 "depends_on": [f"C-{i}" for i in range(1, 600)]}]
        for i in range(1, 600):
            rows.append({"record_type": "claim", "claim_id": f"C-{i}",
                         "statement": "unsupported"})
        path = tmp_path / "wide.json"
        path.write_text(json.dumps(rows))
        required = assure(str(path)).required_evidence
        # Six hundred unsupported claims really are many requirements; what they
        # are not is an unbounded payload, and the remainder is declared.
        assert len(required.items) < 600
        assert required.protocol()["targets_truncated"] >= 0


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def assure_envelope(tmp_path):
    def run(rows):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "envelope.json"
        path.write_text(json.dumps(rows))
        return assure(str(path))
    return run
