"""Progressive assurance: how deep a case goes, and how deep it needs to go.

The tests that matter most here are the ones proving the level is *not* a gate.
A level that could stop release-gate from looking, or soften what it found,
would be a way to launder a finding out of a case — so a Level 4 problem planted
in a Level 0 case must still be found, still rank into attention, and still
block, and that is asserted directly rather than assumed.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.case import CaseType, Decision
from release_gate.assurance.level import (
    AssuranceLevel, LevelAssessment, assess_level, dimension_level,
    requirement_level)
from release_gate.assurance.methodologies import (
    GENERAL_AUTONOMOUS_ACTION_V1, RESEARCH_ASSURANCE_V1,
    SOFTWARE_AGENT_ASSURANCE_V1, default_registry)

BOUNDED = {"REVERSIBILITY": "REVERSIBLE", "SCOPE": "SINGLE_SUBJECT",
           "FINANCIAL_IMPACT": "NONE", "DATA_IMPACT": "READ",
           "SECURITY_IMPACT": "NONE", "LEGAL_IMPACT": "NONE"}


def action(consequence=BOUNDED, **over):
    doc = {"traces": [{"trace_id": "t-1", "objective": "Send an invoice reminder",
                       "steps": [{"tool": "email.send",
                                  "input": {"to": "ops@example.com"},
                                  "output": {"status": "sent"}}]}]}
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


# ── the level is not a gate ─────────────────────────────────────────────────

class TestTheLevelNeverSuppresses:
    """The property the whole design rests on."""

    CONTRADICTED = [
        {"record_type": "claim", "claim_id": "c1",
         "proposition": "the recipient address is current",
         "producer": {"producer_id": "agent://a/1", "kind": "agent"},
         "supporting_evidence": ["e1"], "contradicting_evidence": ["e2"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "OBSERVATION",
         "producer": {"producer_id": "crm://1", "kind": "tool"},
         "supports_claims": ["c1"], "coverage_note": "crm record"},
        {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
         "producer": {"producer_id": "mail://2", "kind": "tool"},
         "contradicts_claims": ["c1"], "coverage_note": "hard bounce"},
        {"record_type": "consequence", **BOUNDED},
    ]

    def _trap(self, tmp_path):
        """A Level 0/1 question with a Level 3 problem planted inside it."""
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "trap.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in self.CONTRADICTED))
        return assure(str(path), methodology=GENERAL_AUTONOMOUS_ACTION_V1)

    def test_a_low_level_case_still_blocks_on_a_high_level_finding(self, tmp_path):
        out = self._trap(tmp_path)
        assert out.level.required <= AssuranceLevel.ATTRIBUTED
        assert out.decision is Decision.BLOCK

    def test_the_finding_is_still_made(self, tmp_path):
        out = self._trap(tmp_path)
        assert list(out.case.collection("contradictions").materialised)

    def test_the_finding_still_reaches_human_attention(self, tmp_path):
        out = self._trap(tmp_path)
        assert any("contradict" in i.summary.lower() or "disagree" in i.summary.lower()
                   for i in out.attention.items)

    def test_scope_does_not_depend_on_what_was_found(self, tmp_path):
        """Scope is a statement about depth, never about results.

        Partitioning on coverage state instead made this backwards: `assessed`
        means "settled" for the ledger dimensions, so an OPEN contradiction read
        as NOT_ASSESSED and the case carrying a live contradiction was the one
        reporting that dimension as unexamined.
        """
        clean = outcome_for(tmp_path, action())
        trapped = self._trap(tmp_path)
        assert set(clean.level.out_of_scope) == set(trapped.level.out_of_scope)

    def test_an_out_of_scope_dimension_keeps_its_coverage_row(self, tmp_path):
        """Grouped, never dropped. NOT_ASSESSED stays first-class."""
        out = outcome_for(tmp_path, action())
        dimensions = {str(r.to_dict().get("dimension"))
                      for r in out.case.collection("coverage").materialised}
        assert set(out.level.out_of_scope) <= dimensions

    def test_every_dimension_is_accounted_for(self, tmp_path):
        out = outcome_for(tmp_path, action())
        rows = [str(r.to_dict().get("dimension"))
                for r in out.case.collection("coverage").materialised]
        assert len(out.level.in_scope) + len(out.level.out_of_scope) == len(rows)


# ── derivation ──────────────────────────────────────────────────────────────

class TestRequiredLevel:

    def test_nothing_stated_is_minimal(self):
        assert assess_level().required is AssuranceLevel.MINIMAL

    def test_case_type_sets_a_floor(self):
        assert (assess_level(case_type=CaseType.RESEARCH_RESULT).required
                is AssuranceLevel.FRONTIER)
        assert (assess_level(case_type=CaseType.CODE_CHANGE).required
                is AssuranceLevel.ATTRIBUTED)
        assert (assess_level(case_type=CaseType.GENERAL_DECISION).required
                is AssuranceLevel.MINIMAL)

    def test_an_irreversible_action_is_never_minimal(self):
        """A one-agent case with thin evidence is still not a small question
        when what it does cannot be undone."""
        level = assess_level(consequence=_consequence({"REVERSIBILITY": "IRREVERSIBLE"}))
        assert level.required >= AssuranceLevel.CORROBORATED

    def test_granting_access_raises_the_floor(self):
        level = assess_level(consequence=_consequence({"SECURITY_IMPACT": "GRANTS_ACCESS"}))
        assert level.required >= AssuranceLevel.CORROBORATED

    def test_an_unknown_consequence_never_raises_or_lowers(self):
        """Invariant 3: an unstated consequence is unassessed, not small."""
        stated = assess_level(consequence=_consequence({"REVERSIBILITY": "UNKNOWN"}))
        assert stated.required is AssuranceLevel.MINIMAL

    def test_a_methodology_that_demands_replication_is_frontier(self):
        assert (assess_level(methodology=RESEARCH_ASSURANCE_V1).required
                is AssuranceLevel.FRONTIER)

    def test_the_general_profile_is_not_frontier(self):
        """The whole point: do not force Level 4 onto Level 0."""
        assert (assess_level(methodology=GENERAL_AUTONOMOUS_ACTION_V1).required
                is AssuranceLevel.ATTRIBUTED)

    def test_the_software_profile_sits_between_them(self):
        assert (assess_level(methodology=SOFTWARE_AGENT_ASSURANCE_V1).required
                is AssuranceLevel.CORROBORATED)

    def test_the_floor_is_the_highest_of_its_inputs(self):
        level = assess_level(case_type=CaseType.GENERAL_DECISION,
                             methodology=RESEARCH_ASSURANCE_V1)
        assert level.required is AssuranceLevel.FRONTIER

    def test_a_basis_is_always_given(self):
        for level in (assess_level(),
                      assess_level(case_type=CaseType.RESEARCH_RESULT),
                      assess_level(methodology=RESEARCH_ASSURANCE_V1)):
            assert level.required_basis


class TestSupportedLevel:

    def test_empty_ledgers_do_not_demonstrate_frontier_structure(self):
        """Presence means "this was looked for", not "something was found".

        Every case marks the frontier ledgers PRESENT, so reading presence here
        rated a one-agent email send as FRONTIER-supported on five empty ledgers.
        """
        assert (assess_level(populated_collections={"evidence": 5, "coverage": 21}).supported
                is AssuranceLevel.MINIMAL)

    def test_one_artifact_is_not_artifact_provenance(self):
        """Level 2 is about how things relate, and one node is not a relation.

        Every zero-config run creates an artifact for the input file itself.
        """
        assert (assess_level(populated_collections={"artifacts": 1}).supported
                is AssuranceLevel.MINIMAL)
        assert (assess_level(populated_collections={"artifacts": 2}).supported
                is AssuranceLevel.ORCHESTRATED)

    def test_one_claim_is_a_claim_graph(self):
        """Levels 3 and 4 are about a kind of evidence existing at all."""
        assert (assess_level(populated_collections={"claims": 1}).supported
                is AssuranceLevel.FRONTIER)

    def test_level_one_is_demonstrated_by_signals_not_a_collection(self):
        """No collection represents "action provenance and subject integrity",
        so it is asserted from named facts rather than inferred from a count."""
        assert assess_level(signals={"subject_digest": True}).supported \
            is AssuranceLevel.ATTRIBUTED
        assert assess_level(signals={"subject_digest": False}).supported \
            is AssuranceLevel.MINIMAL

    def test_an_unrecognised_signal_is_ignored(self):
        assert assess_level(signals={"vibes": True}).supported is AssuranceLevel.MINIMAL


class TestGapAndExcess:

    def test_a_gap_is_never_negative(self):
        level = assess_level(populated_collections={"claims": 1})
        assert level.supported > level.required
        assert level.gap == 0
        assert level.exceeds_required

    def test_carrying_more_than_needed_is_not_a_deficiency(self):
        level = assess_level(populated_collections={"claims": 1})
        assert level.meets_required
        assert "not a deficiency" in level.note()

    def test_a_shortfall_is_reported_as_a_gap(self):
        level = assess_level(case_type=CaseType.RESEARCH_RESULT)
        assert level.gap == 4
        assert not level.meets_required


# ── dimension and requirement mapping ───────────────────────────────────────

class TestMapping:

    def test_frontier_dimensions_are_frontier(self):
        for dimension in ("replication", "adversarial_review", "counterexamples",
                          "failed_branches", "criticality"):
            assert dimension_level(dimension) is AssuranceLevel.FRONTIER

    def test_an_unclassified_dimension_is_minimal_so_it_stays_visible(self):
        """A dimension nobody has classified should appear everywhere and be
        noticed, not vanish from every small case."""
        assert dimension_level("a_brand_new_dimension") is AssuranceLevel.MINIMAL

    def test_replication_is_a_frontier_ask(self):
        assert requirement_level("replication") is AssuranceLevel.FRONTIER

    def test_declaring_consequence_is_a_cheap_ask(self):
        assert requirement_level("consequence_declaration") <= AssuranceLevel.ATTRIBUTED


# ── ordering ────────────────────────────────────────────────────────────────

class TestRequirementOrdering:

    def test_a_low_level_case_is_asked_for_the_proportionate_thing_first(self, tmp_path):
        """A one-agent email send that just needs a consequence declaration was
        told to find an independently-operated producer first."""
        out = outcome_for(tmp_path, action(consequence=None))
        assert out.decision is Decision.HOLD
        kinds = [i.to_dict()["requirement"] for i in out.required_evidence.items]
        assert kinds[0] == "consequence_declaration"

    def test_above_level_asks_are_kept_not_dropped(self, tmp_path):
        out = outcome_for(tmp_path, action(consequence=None))
        kinds = {i.to_dict()["requirement"] for i in out.required_evidence.items}
        assert "independent_verification" in kinds

    def test_ordering_is_stable_within_a_band(self, tmp_path):
        out = outcome_for(tmp_path, action(consequence=None))
        first = [i.requirement_id for i in out.required_evidence.items]
        again = outcome_for(tmp_path, action(consequence=None))
        assert [i.requirement_id for i in again.required_evidence.items] == first


# ── reporting ───────────────────────────────────────────────────────────────

class TestReporting:

    def test_a_level_one_case_is_not_reported_as_nine_failures(self, tmp_path):
        out = outcome_for(tmp_path, action())
        section = next(s for s in out.packet().sections
                       if s.key.value == "NOT_ASSESSED")
        assert "not expected at this depth" in section.answer

    def test_in_depth_gaps_are_listed_before_out_of_depth_ones(self, tmp_path):
        out = outcome_for(tmp_path, action())
        section = next(s for s in out.packet().sections
                       if s.key.value == "NOT_ASSESSED")
        flags = [bool(r.get("above_level")) for r in section.rows
                 if r.get("state") == "NOT_ASSESSED"]
        assert flags == sorted(flags), "in-depth gaps must come first"

    def test_the_note_names_the_level_and_what_it_does_not_mean(self, tmp_path):
        out = outcome_for(tmp_path, action())
        note = out.level.out_of_scope_note()
        assert out.level.required.label in note
        assert "still counts" in note

    def test_it_serialises(self, tmp_path):
        out = outcome_for(tmp_path, action())
        payload = out.level.to_dict()
        assert payload["record_type"] == "assurance_level"
        assert payload["required_label"] == out.level.required.label
        assert isinstance(payload["gap"], int)

    def test_levels_are_ordered(self):
        assert AssuranceLevel.MINIMAL < AssuranceLevel.FRONTIER
        assert max(AssuranceLevel) is AssuranceLevel.FRONTIER

    def test_every_level_describes_itself(self):
        for level in AssuranceLevel:
            assert level.describe()
            assert level.label.startswith("L")


def _consequence(values):
    """A ConsequenceProfile carrying the given declared dimensions."""
    from release_gate.assurance.consequence import (
        ConsequenceProfile, descriptors_from_mapping)
    return ConsequenceProfile(
        descriptors={d.dimension: d
                     for d in descriptors_from_mapping(values, source="test")})
