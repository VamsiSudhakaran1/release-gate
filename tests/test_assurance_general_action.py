"""The ordinary case: one agent, one action, whatever evidence exists.

Two halves. `AcceptedFinding` is the mechanism — a methodology declaring up
front that a named structural HOLD is not disqualifying for the class of
decision it covers. `GENERAL_AUTONOMOUS_ACTION_V1` is the profile that uses it.

The mechanism is the part that needs guarding, because a careless version of it
is a suppression channel. The tests that matter most here are the ones that
prove it cannot become one: structural BLOCKs are never acceptable, an UNKNOWN
consequence never satisfies a ceiling, and an accepted finding is still shown.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_gate.assurance.case import Decision
from release_gate.assurance.methodologies import (
    GENERAL_AUTONOMOUS_ACTION_V1, default_registry)
from release_gate.assurance.methodology import (
    AcceptedFinding, AssuranceMethodology, MethodologyError, RequirementEffect,
    RequirementOutcome)

#: Consequence inside the profile's bounds — the "send a reminder email" shape.
BOUNDED = {"REVERSIBILITY": "REVERSIBLE_WITH_EFFORT", "SCOPE": "SINGLE_SUBJECT",
           "FINANCIAL_IMPACT": "NONE", "DATA_IMPACT": "READ",
           "SECURITY_IMPACT": "NONE", "LEGAL_IMPACT": "NONE",
           "USER_IMPACT": "DIRECT", "PRODUCTION_IMPACT": "PRODUCTION"}


def action(consequence=BOUNDED, **over):
    """The minimal case from the prompt: objective, action, execution evidence."""
    doc = {"traces": [{
        "trace_id": "t-1",
        "objective": "Send the Q3 invoice reminder to the customer on file",
        "steps": [
            {"tool": "crm.lookup", "input": {"account": "acct_88"},
             "output": {"email": "ops@example.com"}},
            {"tool": "email.send",
             "input": {"to": "ops@example.com", "subject": "Q3 invoice"},
             "output": {"status": "sent", "message_id": "m-9912"}}]}]}
    if consequence is not None:
        doc["consequence"] = dict(consequence)
    doc.update(over)
    return doc


def outcome_for(tmp_path, doc, methodology=GENERAL_AUTONOMOUS_ACTION_V1,
                name="action.json"):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return assure(str(path), methodology=methodology)


def result(outcome, rule):
    return next(r for r in outcome.assessment.results if r.requirement_id == rule)


# ── the mechanism ───────────────────────────────────────────────────────────

class TestAcceptedFinding:

    def test_a_rationale_is_mandatory(self):
        with pytest.raises(MethodologyError):
            AcceptedFinding(rule_id="RG-PROV-002", rationale="   ")

    def test_a_rule_id_is_mandatory(self):
        with pytest.raises(MethodologyError):
            AcceptedFinding(rule_id="", rationale="because")

    def test_unknown_cannot_appear_in_a_ceiling(self):
        """An unstated consequence is an unassessed one, never a small one."""
        with pytest.raises(MethodologyError):
            AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={"REVERSIBILITY": ("REVERSIBLE", "UNKNOWN")})

    def test_an_empty_ceiling_is_refused(self):
        """It would accept every value, UNKNOWN included, by saying nothing."""
        with pytest.raises(MethodologyError):
            AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={"REVERSIBILITY": ()})

    def test_dimensions_and_values_are_normalised(self):
        a = AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={" reversibility ": ["reversible"]})
        assert a.max_consequence == {"REVERSIBILITY": ("REVERSIBLE",)}

    def test_a_stated_value_inside_the_ceiling_applies(self):
        a = AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={"REVERSIBILITY": ("REVERSIBLE",)})
        assert a.applies_to({"REVERSIBILITY": "REVERSIBLE"})

    def test_a_stated_value_outside_the_ceiling_does_not(self):
        a = AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={"REVERSIBILITY": ("REVERSIBLE",)})
        assert not a.applies_to({"REVERSIBILITY": "IRREVERSIBLE"})

    def test_an_unstated_dimension_does_not_apply(self):
        """The case that makes the whole mechanism safe: silence is not consent."""
        a = AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={"REVERSIBILITY": ("REVERSIBLE",)})
        assert not a.applies_to({})
        assert not a.applies_to({"REVERSIBILITY": "UNKNOWN"})

    def test_an_unconditional_acceptance_applies_with_nothing_stated(self):
        assert AcceptedFinding(rule_id="R", rationale="r").applies_to({})

    def test_it_round_trips_through_its_dict(self):
        a = AcceptedFinding(rule_id="R", rationale="r",
                            max_consequence={"SCOPE": ("BOUNDED_SET",)})
        assert AcceptedFinding.from_dict(a.to_dict()) == a

    def test_acceptance_for_respects_the_ceiling(self):
        m = GENERAL_AUTONOMOUS_ACTION_V1
        assert m.acceptance_for("RG-PROV-002", BOUNDED) is not None
        assert m.acceptance_for("RG-PROV-002",
                                dict(BOUNDED, REVERSIBILITY="IRREVERSIBLE")) is None
        assert m.acceptance_for("RG-PROV-002", {}) is None

    def test_acceptance_for_an_unlisted_rule_is_none(self):
        assert GENERAL_AUTONOMOUS_ACTION_V1.acceptance_for("RG-NOPE-001", BOUNDED) is None

    def test_a_methodology_carries_its_acceptances_through_serialisation(self):
        m = GENERAL_AUTONOMOUS_ACTION_V1
        restored = AssuranceMethodology.from_dict(m.to_dict())
        assert restored.accepted_findings == m.accepted_findings
        assert restored.digest == m.digest

    def test_acceptances_change_the_methodology_digest(self):
        """A methodology that accepts more is a different yardstick."""
        m = GENERAL_AUTONOMOUS_ACTION_V1
        stripped = dataclasses.replace(m, accepted_findings=())
        assert stripped.digest != m.digest

    def test_defaults_are_empty_so_existing_methodologies_are_unchanged(self):
        for other in ("general-agent-action", "research-assurance",
                      "software-agent-assurance"):
            assert default_registry().latest(other).accepted_findings == ()


# ── the mechanism cannot become a suppression channel ───────────────────────

class TestAcceptanceIsNarrow:

    REFUTED = [
        {"record_type": "claim", "claim_id": "cl_root",
         "proposition": "the migration is safe", "is_root": True,
         "producer": {"producer_id": "agent://p/1", "kind": "agent"},
         "contradicting_evidence": ["ev_bad"],
         "verification_attempts": [
             {"evidence_id": "ev_bad", "method": "TEST_SUITE", "outcome": "FAILED"}]},
        {"record_type": "evidence", "evidence_id": "ev_bad", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://run/1", "kind": "tool"},
         "contradicts_claims": ["cl_root"], "coverage_note": "integration suite"},
    ]

    def _refuted(self, tmp_path, methodology):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "refuted.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in self.REFUTED))
        return assure(str(path), methodology=methodology)

    def test_a_structural_block_can_never_be_accepted(self, tmp_path):
        """The property the whole design rests on.

        A methodology that names every structural BLOCK on the case as accepted
        still gets BLOCK. `decide()` never consults acceptance for blocking
        findings: they are facts about the evidence that no yardstick waves
        through.
        """
        base = self._refuted(tmp_path, GENERAL_AUTONOMOUS_ACTION_V1)
        blocking = [f.rule_id for f in base.analysis.blocking]
        assert blocking, "fixture must produce a structural BLOCK"

        greedy = dataclasses.replace(GENERAL_AUTONOMOUS_ACTION_V1, accepted_findings=tuple(
            AcceptedFinding(rule_id=rid, rationale="attempting to accept a block")
            for rid in blocking))
        assert self._refuted(tmp_path, greedy).decision is Decision.BLOCK

    def test_an_accepted_finding_is_still_shown_to_the_human(self, tmp_path):
        """Acceptance narrows what blocks, never what is shown."""
        out = outcome_for(tmp_path, action())
        assert out.decision is Decision.PROMOTE
        shown = {i.summary for i in out.attention.items}
        assert any("single producer" in s for s in shown)
        assert any("verified" in s for s in shown)

    def test_the_finding_is_not_deleted_from_the_analysis(self, tmp_path):
        out = outcome_for(tmp_path, action())
        assert {"RG-PROV-002", "RG-VERIF-001"} <= {f.rule_id for f in out.analysis.holding}

    def test_the_verdict_records_each_acceptance_and_its_rationale(self, tmp_path):
        out = outcome_for(tmp_path, action())
        reasons = " ".join(out.case.verdict.reasons)
        assert "RG-PROV-002: accepted by general-autonomous-action" in reasons
        assert "one producer by construction" in reasons
        assert "RG-ZC-005" in out.case.verdict.fired_rules

    def test_promote_without_a_methodology_still_raises(self, tmp_path):
        from release_gate.assurance.zero_config import ZeroConfigError, decide
        out = outcome_for(tmp_path, action())
        with pytest.raises(ZeroConfigError):
            decide(out.analysis, out.assessment, has_methodology=False,
                   methodology=GENERAL_AUTONOMOUS_ACTION_V1,
                   consequence=out.consequence)


# ── the profile ─────────────────────────────────────────────────────────────

class TestGeneralAutonomousAction:

    def test_the_minimal_case_promotes(self, tmp_path):
        """One agent, one action, execution evidence, bounded stated consequence.

        No claims, no claim graph, no replication, no adversarial review, no
        second producer. This is the case the prompt is about.
        """
        out = outcome_for(tmp_path, action())
        assert out.decision is Decision.PROMOTE

    def test_it_promotes_without_any_claims(self, tmp_path):
        out = outcome_for(tmp_path, action())
        assert not list(out.case.collection("claims").materialised)

    def test_an_undeclared_consequence_holds(self, tmp_path):
        out = outcome_for(tmp_path, action(consequence=None))
        assert out.decision is Decision.HOLD
        assert result(out, "RG-ACT-002").outcome is RequirementOutcome.UNSATISFIED

    def test_an_irreversible_action_holds(self, tmp_path):
        out = outcome_for(tmp_path, action(dict(BOUNDED, REVERSIBILITY="IRREVERSIBLE")))
        assert out.decision is Decision.HOLD

    def test_an_action_that_grants_access_holds(self, tmp_path):
        out = outcome_for(tmp_path,
                          action(dict(BOUNDED, SECURITY_IMPACT="GRANTS_ACCESS")))
        assert out.decision is Decision.HOLD

    def test_an_unbounded_financial_action_holds(self, tmp_path):
        out = outcome_for(tmp_path,
                          action(dict(BOUNDED, FINANCIAL_IMPACT="UNBOUNDED")))
        assert out.decision is Decision.HOLD

    def test_a_broad_scope_action_holds(self, tmp_path):
        out = outcome_for(tmp_path, action(dict(BOUNDED, SCOPE="BROAD")))
        assert out.decision is Decision.HOLD

    def test_a_held_case_says_what_would_resolve_it(self, tmp_path):
        out = outcome_for(tmp_path, action(consequence=None))
        assert out.required_evidence.items
        assert any("RG-ACT-002" in i.to_dict()["target"]
                   for i in out.required_evidence.items)

    def test_execution_evidence_is_required_and_cannot_be_waived(self, tmp_path):
        """A document with no execution record has nothing to promote on."""
        out = outcome_for(tmp_path, {"consequence": dict(BOUNDED), "score": 90,
                                     "notes": "trust me"}, name="bare.json")
        assert out.decision is Decision.BLOCK
        assert "RG-ACT-001" in GENERAL_AUTONOMOUS_ACTION_V1.non_overridable_conditions

    def test_a_contradiction_still_blocks(self, tmp_path):
        """The profile is permissive about scale, never about disagreement.

        Asserts the requirement outcome rather than only the decision: an
        envelope carries no execution record either, so a decision-only
        assertion would pass on RG-ACT-001 and prove nothing about
        contradictions.
        """
        from release_gate.assurance.zero_config import assure
        envelope = [
            {"record_type": "claim", "claim_id": "c1",
             "proposition": "the address on file is current",
             "producer": {"producer_id": "agent://p/1", "kind": "agent"},
             "supporting_evidence": ["e1"], "contradicting_evidence": ["e2"]},
            {"record_type": "evidence", "evidence_id": "e1", "kind": "OBSERVATION",
             "producer": {"producer_id": "crm://1", "kind": "tool"},
             "supports_claims": ["c1"], "coverage_note": "crm record"},
            {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
             "producer": {"producer_id": "mail://2", "kind": "tool"},
             "contradicts_claims": ["c1"], "coverage_note": "bounce log"},
        ]
        path = tmp_path / "conflict.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in envelope))
        out = assure(str(path), methodology=GENERAL_AUTONOMOUS_ACTION_V1)

        assert list(out.case.collection("contradictions").materialised), (
            "fixture must actually produce a contradiction")
        assert (result(out, "contradictions.resolved").outcome
                is RequirementOutcome.UNSATISFIED)
        assert out.decision is Decision.BLOCK

    def test_it_ships_in_the_default_registry(self):
        assert "general-autonomous-action" in set(default_registry().ids())

    def test_every_rule_carries_a_remedy_and_a_rationale(self):
        for req in GENERAL_AUTONOMOUS_ACTION_V1.requirements:
            assert req.remedy, req.requirement_id
            assert req.rationale, req.requirement_id

    def test_every_non_overridable_condition_names_a_real_requirement(self):
        ids = {r.requirement_id for r in GENERAL_AUTONOMOUS_ACTION_V1.requirements}
        for cond in GENERAL_AUTONOMOUS_ACTION_V1.non_overridable_conditions:
            assert cond in ids, cond

    def test_it_credits_any_typed_verification(self):
        """A general profile has no standing to rule a method out."""
        assert GENERAL_AUTONOMOUS_ACTION_V1.accepted_verification_types == ()
        assert GENERAL_AUTONOMOUS_ACTION_V1.admits("TEST_SUITE")
        assert GENERAL_AUTONOMOUS_ACTION_V1.admits("HUMAN_REVIEW")
