"""The software/agent profile, and the audit bridge that feeds it.

Two halves, and the seam between them is the point. The bridge turns a
release-gate audit report into claims with evidence for and against them; the
profile grades that structure. Neither half re-implements a check — every rule
is a sufficiency judgement over findings the existing engine already produced.

Each rule is tested three ways where the distinction exists: what fires it, what
does NOT fire it, and what NOT_ASSESSED looks like. A rule that cannot tell
"unsatisfied" from "not looked at" is the failure this system exists to prevent
(Invariant 3).
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.methodologies import (
    SOFTWARE_AGENT_ASSURANCE_V1, default_registry)
from release_gate.assurance.methodology import (
    CoverageDimensionDeclared, MethodologyError, NoClaimInStatus,
    RequirementEffect, RequirementOutcome, predicate_from_dict)


def audit(**over):
    """A report shaped the way `release_gate.audit` actually emits one.

    Shapes matter here and are not invented: `coverage` is a list of
    {dimension, status, note} from `compute_coverage`, and `code_safety` carries
    the `applicable` flag from `compute_code_safety` that separates "the scanner
    ran and found nothing" from "the scanner could not run at all". A fixture
    that guessed either shape would test the bridge against a report no version
    of release-gate has ever produced.
    """
    doc = {
        "decision": "PASS",
        "score": 95,
        "code_findings": [],
        "code_safety": {"score": 95, "decision": "PASS", "applicable": True,
                        "high": 0, "medium": 0, "low": 0, "total": 0},
        "safeguards": {"rate_limit": {"present": True, "detail": "token bucket"}},
        "coverage": [
            {"dimension": "Agent code (static analysis)", "status": "assessed",
             "note": "Python assessed in depth (AST + taint)."},
            {"dimension": "Runtime safeguard behavior", "status": "not_assessed",
             "note": "A static scan doesn't run the agent."},
        ],
        "frameworks": ["OWASP-LLM"],
    }
    doc.update(over)
    return doc


def outcome_for(tmp_path, doc, name="audit.json"):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return assure(str(path), methodology=SOFTWARE_AGENT_ASSURANCE_V1)


def result(outcome, rule):
    return next(r for r in outcome.assessment.results if r.requirement_id == rule)


def claim(outcome, claim_id):
    for record in outcome.case.collection("claims").materialised:
        if getattr(record, "claim_id", None) == claim_id:
            return record
    return None


# ── the bridge ──────────────────────────────────────────────────────────────

class TestAuditBridge:
    """An audit report is an assurance argument, not a second product."""

    def test_an_audit_report_is_detected_as_one(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        assert out.normalisation.detection.kind.value == "AUDIT_REPORT"

    def test_findings_become_evidence_against_the_safety_claim(self, tmp_path):
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-TAINT-001", "severity": "high",
             "message": "user input reaches subprocess",
             "file": "app/run.py", "line": 42}]))
        safety = claim(out, "sw:code-safety")
        assert safety is not None
        assert len(safety.contradicting_evidence) == 1
        assert not safety.supporting_evidence

    def test_a_failing_safeguard_is_not_ingested_as_a_present_one(self, tmp_path):
        """The bug this bridge was rebuilt around.

        Safeguards arrive as dicts. `if not present: continue` on a non-empty
        dict is always falsy, so eight *failing* safeguards ingested as eight
        *declared-present* ones — the exact inversion of the finding.
        """
        out = outcome_for(tmp_path, audit(safeguards={
            "kill_switch": {"present": False, "detail": "no interrupt path"},
            "rate_limit": {"present": True, "detail": "token bucket"}}))
        absent = claim(out, "sw:safeguard:kill_switch")
        present = claim(out, "sw:safeguard:rate_limit")
        assert absent.contradicting_evidence and not absent.supporting_evidence
        assert present.supporting_evidence and not present.contradicting_evidence

    def test_the_rule_id_a_finding_carries_survives_ingest(self, tmp_path):
        """The bridge copied `rule` while findings emit `rule_id`, so every rule
        id was silently dropped and findings arrived anonymous."""
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-PII-003", "severity": "medium", "message": "leak",
             "file": "a.py", "line": 1}]))
        blob = json.dumps(out.case.to_dict(), default=str)
        assert "RG-PII-003" in blob

    def test_a_report_with_findings_does_not_crash_ingest(self, tmp_path):
        """`EvidenceRecord.derived(..., verification_method=STATIC_ANALYSIS)`
        raises, so any audit report carrying a finding used to fail outright."""
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-TAINT-001", "severity": "high", "message": "sink",
             "file": "a.py", "line": 1}]))
        assert out.case is not None

    def test_audit_coverage_rows_become_case_coverage(self, tmp_path):
        """The audit's own account of what it did not reach has to survive.

        An audit dimension that is dropped on the way in is invisible to every
        methodology predicate downstream, which is the difference between a
        case that says "runtime was not assessed" and one that simply never
        mentions runtime (Invariant 3).
        """
        out = outcome_for(tmp_path, audit())
        rows = {r.to_dict().get("dimension"): r.to_dict()
                for r in out.case.collection("coverage").materialised}
        assert "agent_code_(static_analysis)" in rows
        assert "runtime_safeguard_behavior" in rows
        assert rows["runtime_safeguard_behavior"]["state"] == "NOT_ASSESSED"

    def test_a_partial_dimension_is_not_recorded_as_assessed(self, tmp_path):
        """`partial` is not `assessed`. Rounding it up would be exactly the
        false completeness this engine refuses."""
        out = outcome_for(tmp_path, audit(coverage=[
            {"dimension": "Agent code (static analysis)", "status": "partial",
             "note": "JS/TS with lighter heuristics."}]))
        rows = {r.to_dict().get("dimension"): r.to_dict()
                for r in out.case.collection("coverage").materialised}
        assert rows["agent_code_(static_analysis)"]["state"] == "NOT_ASSESSED"

    def test_the_root_claim_rests_on_the_dimension_claims(self, tmp_path):
        out = outcome_for(tmp_path, audit(safeguards={
            "kill_switch": {"present": True, "detail": "ok"}}))
        root = claim(out, "sw:admissible")
        assert root.is_root
        assert "sw:code-safety" in root.parents
        assert "sw:safeguard:kill_switch" in root.parents

    def test_a_clean_scan_asserts_code_safety_rather_than_staying_silent(self, tmp_path):
        """`code_findings: []` with an applicable scan means the scanner ran and
        found nothing, which is a claim WITH evidence for it — not the absence
        of a claim. A scan that could not run at all is the other case."""
        out = outcome_for(tmp_path, audit())
        safety = claim(out, "sw:code-safety")
        assert safety is not None
        assert safety.supporting_evidence and not safety.contradicting_evidence

    def test_an_inapplicable_scan_asserts_nothing(self, tmp_path):
        """No agent detected, or a language the analyser cannot parse. Inventing
        a code-safety claim here would assert something nobody established."""
        out = outcome_for(tmp_path, audit(
            code_safety={"score": None, "decision": "N/A", "applicable": False,
                         "reason": "language_not_static"}))
        assert claim(out, "sw:code-safety") is None

    def test_a_refuted_dimension_caps_the_root(self, tmp_path):
        """Criticality is what makes the bridge worth building: a refuted
        safeguard has to reach the thing being asked about."""
        out = outcome_for(tmp_path, audit(safeguards={
            "kill_switch": {"present": False, "detail": "absent"}}))
        assert out.criticality.determinable
        assert "sw:admissible" in set(out.criticality.critical_ids)


# ── RG-SW-001: an unanswered finding ────────────────────────────────────────

class TestUnresolvedCodeFinding:

    def test_fires_when_a_finding_stands_unanswered(self, tmp_path):
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-TAINT-001", "severity": "high",
             "message": "user input reaches subprocess", "file": "a.py", "line": 1}]))
        assert result(out, "RG-SW-001").outcome is RequirementOutcome.UNSATISFIED

    def test_does_not_fire_on_a_clean_report(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        assert result(out, "RG-SW-001").outcome is RequirementOutcome.SATISFIED

    def test_a_contradictions_predicate_would_have_missed_it(self, tmp_path):
        """Why RG-SW-001 does not read the contradictions collection.

        A contradiction record is written only where evidence points BOTH ways
        at one claim. A finding nothing answers is unanimous, so the collection
        stays empty and `NoUnresolved` reports a clean bill of health on a live
        taint path. This test pins the gap so the rule is never "simplified"
        back onto that predicate.
        """
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-TAINT-001", "severity": "high",
             "message": "reaches subprocess", "file": "a.py", "line": 1}]))
        assert not list(out.case.collection("contradictions").materialised)
        assert result(out, "RG-SW-001").outcome is RequirementOutcome.UNSATISFIED

    def test_it_blocks_and_cannot_be_overridden(self):
        req = next(r for r in SOFTWARE_AGENT_ASSURANCE_V1.requirements
                   if r.requirement_id == "RG-SW-001")
        assert req.effect is RequirementEffect.BLOCK
        assert "RG-SW-001" in SOFTWARE_AGENT_ASSURANCE_V1.non_overridable_conditions


# ── the NoClaimInStatus predicate itself ────────────────────────────────────

class TestNoClaimInStatus:

    def test_it_names_the_statuses_it_forbids(self):
        assert NoClaimInStatus().describe() == "no load-bearing claim is refuted"
        assert (NoClaimInStatus(statuses=("REFUTED", "DISPUTED"), scope="all")
                .describe() == "no claim is disputed, refuted")

    def test_statuses_are_normalised_and_deduped(self):
        p = NoClaimInStatus(statuses=("refuted", "REFUTED", " disputed "))
        assert p.statuses == ("DISPUTED", "REFUTED")

    def test_an_empty_status_list_is_refused(self):
        with pytest.raises(MethodologyError):
            NoClaimInStatus(statuses=())

    def test_an_unknown_scope_is_refused(self):
        with pytest.raises(MethodologyError):
            NoClaimInStatus(scope="important")

    def test_it_round_trips_through_its_dict(self):
        p = NoClaimInStatus(statuses=("REFUTED",), scope="all")
        assert predicate_from_dict(p.to_dict()) == p

    def test_no_claims_is_not_assessed_rather_than_clean(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "trace.json"
        path.write_text(json.dumps({"traces": [{"steps": [{"tool": "read"}]}]}))
        out = assure(str(path), methodology=SOFTWARE_AGENT_ASSURANCE_V1)
        assert result(out, "RG-SW-001").outcome is RequirementOutcome.NOT_ASSESSED


# ── RG-SW-004: capability declaration ───────────────────────────────────────

class TestCapabilityUndeclared:

    def test_fires_when_capability_discovery_was_not_assessed(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        r = result(out, "RG-SW-004")
        assert r.outcome is RequirementOutcome.UNSATISFIED
        assert "NOT_ASSESSED" in r.detail

    def test_a_bare_presence_check_would_have_passed(self, tmp_path):
        """Why RG-SW-004 sets `require_assessed`.

        Zero-config emits a capability_discovery row for every input, including
        one that says plainly it discovered nothing. Presence alone is therefore
        satisfied on exactly the case the rule is written for.
        """
        out = outcome_for(tmp_path, audit())
        bare = CoverageDimensionDeclared(dimension="capability_discovery")
        assert bare.evaluate(out.case).outcome is RequirementOutcome.SATISFIED

    def test_require_assessed_defaults_off_so_existing_rules_are_unchanged(self):
        assert CoverageDimensionDeclared(dimension="overall").require_assessed is False

    def test_it_round_trips_through_its_dict(self):
        p = CoverageDimensionDeclared(dimension="runtime", require_assessed=True)
        assert predicate_from_dict(p.to_dict()) == p


# ── RG-SW-009: whose denominator ────────────────────────────────────────────

class TestSubmissionDenominator:

    def test_fires_when_the_document_is_its_own_denominator(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        r = result(out, "RG-SW-009")
        assert r.outcome is RequirementOutcome.UNSATISFIED
        assert "also produced the evidence" in r.detail

    def test_it_is_advisory_and_does_not_block(self, tmp_path):
        req = next(r for r in SOFTWARE_AGENT_ASSURANCE_V1.requirements
                   if r.requirement_id == "RG-SW-009")
        assert req.effect is RequirementEffect.ADVISORY
        assert "RG-SW-009" not in SOFTWARE_AGENT_ASSURANCE_V1.non_overridable_conditions

    def test_an_advisory_does_not_raise_required_evidence(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        targets = {i.to_dict()["target"] for i in out.required_evidence.items}
        assert "methodology:RG-SW-009" not in targets


# ── RG-SW-003 / 005 / 006 / 007 / 010 ───────────────────────────────────────

class TestRemainingRules:

    def test_runtime_evidence_absent_holds(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        r = result(out, "RG-SW-003")
        assert r.outcome is RequirementOutcome.UNSATISFIED
        req = next(x for x in SOFTWARE_AGENT_ASSURANCE_V1.requirements
                   if x.requirement_id == "RG-SW-003")
        assert req.effect is RequirementEffect.HOLD

    def test_stale_verification_is_not_assessed_without_attempts(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        assert result(out, "RG-SW-006").outcome is RequirementOutcome.NOT_ASSESSED

    def test_mutation_and_evidence_drift_pass_on_a_single_build(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        assert result(out, "RG-SW-005").outcome is RequirementOutcome.SATISFIED
        assert result(out, "RG-SW-007").outcome is RequirementOutcome.SATISFIED

    def test_consequence_must_be_stated(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        assert result(out, "RG-SW-010").outcome is RequirementOutcome.UNSATISFIED

    def test_coverage_is_stated_overall(self, tmp_path):
        out = outcome_for(tmp_path, audit())
        assert result(out, "RG-SW-008").outcome is RequirementOutcome.SATISFIED


# ── the profile as a whole ──────────────────────────────────────────────────

class TestProfileShape:

    def test_it_ships_in_the_default_registry(self):
        assert "software-agent-assurance" in set(default_registry().ids())

    def test_every_rule_carries_a_remedy_and_a_rationale(self):
        for req in SOFTWARE_AGENT_ASSURANCE_V1.requirements:
            assert req.remedy, req.requirement_id
            assert req.rationale, req.requirement_id

    def test_rule_ids_are_unique(self):
        ids = [r.requirement_id for r in SOFTWARE_AGENT_ASSURANCE_V1.requirements]
        assert len(ids) == len(set(ids))

    def test_every_non_overridable_condition_names_a_real_requirement(self):
        ids = {r.requirement_id for r in SOFTWARE_AGENT_ASSURANCE_V1.requirements}
        for cond in SOFTWARE_AGENT_ASSURANCE_V1.non_overridable_conditions:
            assert cond in ids, cond

    def test_it_round_trips_through_its_dict(self):
        from release_gate.assurance.methodology import AssuranceMethodology
        restored = AssuranceMethodology.from_dict(
            SOFTWARE_AGENT_ASSURANCE_V1.to_dict())
        assert restored.digest == SOFTWARE_AGENT_ASSURANCE_V1.digest

    def test_a_failing_report_blocks_and_raises_dispatchable_evidence(self, tmp_path):
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-TAINT-001", "severity": "high", "message": "sink",
             "file": "a.py", "line": 1}]))
        assert out.decision.value == "BLOCK"
        assert out.required_evidence.items
        assert out.required_evidence.dispatchable

    def test_the_human_is_shown_the_finding_first(self, tmp_path):
        out = outcome_for(tmp_path, audit(code_findings=[
            {"rule_id": "RG-TAINT-001", "severity": "high", "message": "sink",
             "file": "a.py", "line": 1}]))
        assert "unanswered" in out.attention.top(1)[0].summary
