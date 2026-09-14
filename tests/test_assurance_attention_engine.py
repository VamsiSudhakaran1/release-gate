"""The human attention engine: many events in, the few things a person must see out."""

from __future__ import annotations

import json
import time

import pytest

from release_gate.assurance.analysis import AnalysisDomain, AnalysisResult, Finding
from release_gate.assurance.attention import (
    AttentionCriticality, AttentionItem, AttentionRanking, AttentionReason,
    ConsequenceWeight, HumanAttentionSet, RequirementPressure, build_attention)
from release_gate.assurance.methodology import RequirementEffect


def item(**kw):
    kw.setdefault("item_id", "att_claim_C-1")
    kw.setdefault("reason", AttentionReason.NOT_VERIFIED)
    kw.setdefault("effect", RequirementEffect.HOLD)
    kw.setdefault("focus", "C-1")
    kw.setdefault("focus_kind", "claim")
    kw.setdefault("summary", "s")
    kw.setdefault("why_it_matters", "w")
    kw.setdefault("remedy", "r")
    return AttentionItem(**kw)


def ranking(criticality=AttentionCriticality.OFF_PATH,
            pressure=RequirementPressure.NONE,
            consequence=ConsequenceWeight.BOUNDED):
    return AttentionRanking(criticality=criticality, pressure=pressure,
                            consequence=consequence)


# ── every item answers the nine questions ────────────────────────────────────

class TestTheNineQuestions:

    def test_an_item_carries_all_nine(self):
        payload = item(depends_on=("A",), supporting_evidence=("e1",),
                       contradicting_evidence=("e2",), status="OPEN",
                       epistemic_status="DECLARED",
                       resolving_evidence=("a proof of C-1",)).to_dict()
        for field in ("what", "why_it_matters", "what_depends_on_it",
                      "supporting_evidence", "contradicting_evidence", "status",
                      "epistemic_status", "what_the_human_can_do",
                      "what_evidence_would_resolve_it"):
            assert field in payload

    def test_the_render_asks_them_in_order(self):
        rendered = item(depends_on=("A",)).render()
        order = ["WHY IT MATTERS", "WHAT DEPENDS ON IT", "SUPPORTING EVIDENCE",
                 "CONTRADICTING EVIDENCE", "STATUS", "EPISTEMIC STATUS",
                 "WHAT YOU CAN DO", "WHAT WOULD RESOLVE IT"]
        positions = [rendered.index(label) for label in order]
        assert positions == sorted(positions)

    def test_an_unrecorded_answer_says_so_rather_than_implying_none(self):
        # "(none recorded)" is not "nothing depends on it".
        assert "WHAT DEPENDS ON IT: (none recorded)" in item().render()

    def test_the_old_field_names_still_read(self):
        payload = item().to_dict()
        assert payload["summary"] == payload["what"]
        assert payload["remedy"] == payload["what_the_human_can_do"]


# ── ranking is three factors, not a score ────────────────────────────────────

class TestRanking:

    def test_no_composite_score_is_offered(self):
        assert item().ranking.to_dict()["composite_score"] is None

    def test_the_ranking_explains_itself_component_by_component(self):
        explained = ranking(AttentionCriticality.ON_CRITICAL_PATH,
                            RequirementPressure.BLOCKS,
                            ConsequenceWeight.IRREVERSIBLE).explain()
        assert "dependency: ON_CRITICAL_PATH" in explained
        assert "requirement: BLOCKS" in explained
        assert "consequence: IRREVERSIBLE" in explained

    def test_dependency_outranks_everything_else(self):
        on_path = item(item_id="a", ranking=ranking(AttentionCriticality.ON_CRITICAL_PATH))
        off_path = item(item_id="b", ranking=ranking(
            AttentionCriticality.OFF_PATH, RequirementPressure.BLOCKS,
            ConsequenceWeight.IRREVERSIBLE))
        assert on_path.sort_key < off_path.sort_key

    def test_requirement_pressure_outranks_consequence(self):
        pressured = item(item_id="a", ranking=ranking(
            AttentionCriticality.OFF_PATH, RequirementPressure.BLOCKS,
            ConsequenceWeight.BOUNDED))
        consequential = item(item_id="b", ranking=ranking(
            AttentionCriticality.OFF_PATH, RequirementPressure.NONE,
            ConsequenceWeight.IRREVERSIBLE))
        assert pressured.sort_key < consequential.sort_key

    def test_leverage_never_outranks_a_dependency(self):
        # Volume is the weakest thing on the list (Invariant 12).
        on_path = item(item_id="a", leverage=1,
                       ranking=ranking(AttentionCriticality.ON_CRITICAL_PATH))
        noisy = item(item_id="b", leverage=400,
                     ranking=ranking(AttentionCriticality.OFF_PATH))
        assert on_path.sort_key < noisy.sort_key

    def test_undetermined_criticality_ranks_above_off_path(self):
        # Not knowing whether something bears on the decision is a reason to look,
        # and sorting unknowns to the bottom is how a case looks calm (Invariant 3).
        unknown = item(item_id="a", ranking=ranking(AttentionCriticality.UNDETERMINED))
        known_irrelevant = item(item_id="b", ranking=ranking(AttentionCriticality.OFF_PATH))
        assert unknown.sort_key < known_irrelevant.sort_key

    def test_unknown_consequence_ranks_above_bounded(self):
        unknown = item(item_id="a", ranking=ranking(consequence=ConsequenceWeight.UNKNOWN))
        bounded = item(item_id="b", ranking=ranking(consequence=ConsequenceWeight.BOUNDED))
        assert unknown.sort_key < bounded.sort_key

    def test_the_set_states_how_it_ranked(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True, "statement": "s"}])
        assert "no composite score is computed" in outcome.attention.basis


# ── never hide critical issues for compression ───────────────────────────────

class TestNeverHides:

    def test_a_blocking_item_is_undroppable(self):
        assert item(effect=RequirementEffect.BLOCK).undroppable

    def test_a_critical_path_item_is_undroppable_even_when_advisory(self):
        assert item(effect=RequirementEffect.ADVISORY,
                    ranking=ranking(AttentionCriticality.ON_CRITICAL_PATH)).undroppable

    def test_an_off_path_advisory_is_droppable(self):
        assert not item(effect=RequirementEffect.ADVISORY,
                        ranking=ranking(AttentionCriticality.OFF_PATH)).undroppable

    def test_top_returns_more_than_asked_rather_than_hiding_a_blocker(self):
        items = tuple(item(item_id=f"b{i}", effect=RequirementEffect.BLOCK)
                      for i in range(11))
        found = HumanAttentionSet(items=items)
        assert len(found.top(7)) == 11
        assert found.withheld(7) == ()

    def test_the_note_says_why_the_list_is_longer_than_asked(self):
        items = tuple(item(item_id=f"b{i}", effect=RequirementEffect.BLOCK)
                      for i in range(11))
        note = HumanAttentionSet(items=items).withheld_note(7)
        assert "11 item(s) are shown rather than 7" in note
        assert "a shorter list would have to hide one" in note

    def test_what_is_withheld_is_named_by_reason(self):
        items = (item(item_id="b0", effect=RequirementEffect.BLOCK),) + tuple(
            item(item_id=f"a{i}", effect=RequirementEffect.ADVISORY,
                 reason=AttentionReason.COVERAGE_GAP,
                 ranking=ranking(AttentionCriticality.OFF_PATH)) for i in range(9))
        note = HumanAttentionSet(items=items).withheld_note(3)
        assert "7 further item(s) are not shown" in note
        assert "COVERAGE_GAP (7)" in note
        assert "none of them blocking, none on the critical path" in note

    def test_withheld_never_contains_anything_undroppable(self):
        items = tuple(item(item_id=f"b{i}", effect=RequirementEffect.BLOCK)
                      for i in range(5)) + tuple(
            item(item_id=f"a{i}", effect=RequirementEffect.ADVISORY,
                 ranking=ranking(AttentionCriticality.OFF_PATH)) for i in range(20))
        found = HumanAttentionSet(items=items)
        assert not any(i.undroppable for i in found.withheld(3))

    def test_serialising_with_a_limit_reports_what_it_left_out(self):
        items = tuple(item(item_id=f"a{i}", effect=RequirementEffect.ADVISORY,
                           ranking=ranking(AttentionCriticality.OFF_PATH))
                      for i in range(10))
        payload = HumanAttentionSet(items=items).to_dict(limit=3)
        assert payload["count"] == 10
        assert payload["shown"] == 3
        assert payload["withheld"] == 7
        assert "not shown" in payload["withheld_note"]

    def test_serialising_without_a_limit_shows_everything(self):
        items = tuple(item(item_id=f"a{i}") for i in range(10))
        payload = HumanAttentionSet(items=items).to_dict()
        assert payload["shown"] == 10
        assert payload["withheld"] == 0

    def test_an_advisory_on_a_load_bearing_claim_reaches_attention(self,
                                                                   assure_envelope):
        outcome = assure_envelope([
            {"record_type": "evidence", "evidence_id": "E-1",
             "evidence_type": "TOOL_RESULT", "producer": {"producer_id": "solo"},
             "supports_claims": ["A"], "content": {"ok": True}},
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "supported_by": ["E-1"]}])
        advisory = [i for i in outcome.attention
                    if i.effect is RequirementEffect.ADVISORY]
        assert advisory
        assert all(i.ranking.criticality is AttentionCriticality.ON_CRITICAL_PATH
                   for i in advisory)


# ── a finding about a critical claim ranks on the critical path ──────────────

class TestCriticalPathDetection:

    def test_a_counterexample_against_a_critical_claim_is_on_the_path(self,
                                                                     assure_envelope):
        # Its refs are counterexample ids, not claim ids; the ranking must not
        # depend on the shape of a ref.
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "the agent cannot exfiltrate secrets"},
            {"record_type": "adversarial", "target_claim": "A", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "CANDIDATE_REFUTED", "detail": "broke it"}])
        found = next(i for i in outcome.attention
                     if i.reason is AttentionReason.LIVE_COUNTEREXAMPLE)
        assert found.ranking.criticality is AttentionCriticality.ON_CRITICAL_PATH
        assert found.undroppable

    def test_an_item_about_a_claim_the_decision_needs_is_on_the_path(self,
                                                                    assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "depends_on": ["B"]},
            {"record_type": "claim", "claim_id": "B", "statement": "unsupported"}])
        found = [i for i in outcome.attention if "B" in i.refs or i.focus == "B"]
        assert found
        assert any(i.ranking.criticality is AttentionCriticality.ON_CRITICAL_PATH
                   for i in found)

    def test_undeterminable_criticality_does_not_read_as_off_path(self,
                                                                  assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "X", "statement": "s",
             "depends_on": ["Y"]},
            {"record_type": "claim", "claim_id": "Y", "statement": "s",
             "depends_on": ["X"]}])
        assert not outcome.criticality.determinable
        assert all(i.ranking.criticality is not AttentionCriticality.ON_CRITICAL_PATH
                   or i.undroppable for i in outcome.attention)
        assert any(i.ranking.criticality is AttentionCriticality.UNDETERMINED
                   for i in outcome.attention)


# ── every rule reaches attention ─────────────────────────────────────────────

class TestEveryRuleIsMapped:

    def test_no_analysis_rule_is_missing_a_focus_mapping(self):
        import re
        from pathlib import Path
        from release_gate.assurance import attention as module
        source = Path(module.__file__).read_text()
        rules = set(re.findall(
            r'rule_id="(RG-[A-Z]+-\d+)"',
            Path(module.__file__).with_name("analysis.py").read_text()))
        mapped = set(re.findall(r'"(RG-[A-Z]+-\d+)":',
                                source.split("class AttentionReason")[0]))
        assert rules - mapped == set()

    def test_the_prompt_item_kinds_are_all_expressible(self):
        for name in ("NOT_VERIFIED", "CONTRADICTION", "NOT_CORROBORATED",
                     "FAILED_VERIFICATION", "LIVE_COUNTEREXAMPLE",
                     "APPROVAL_MISMATCH", "STALE_VERIFICATION",
                     "UNKNOWN_PROVENANCE", "COVERAGE_GAP",
                     "UNDECLARED_CAPABILITY", "CONSEQUENTIAL_ACTION",
                     "SELECTIVE_EVIDENCE", "EVIDENCE_KNOWN_MISSING",
                     "UNEXAMINED_ASSUMPTION", "SUBJECT_CHANGED"):
            assert AttentionReason(name)


# ── what would resolve it lands on the item ──────────────────────────────────

class TestResolvingEvidence:

    def test_an_item_says_what_would_resolve_it(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        assert all(i.resolving_evidence for i in outcome.attention)

    def test_the_methodology_item_names_its_own_resolution(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s"}])
        found = next(i for i in outcome.attention
                     if i.reason is AttentionReason.METHODOLOGY_ABSENT)
        assert "methodology" in found.resolving_evidence[0]

    def test_a_claim_item_names_what_depends_on_it(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "depends_on": ["B"]},
            {"record_type": "claim", "claim_id": "B", "statement": "unsupported"}])
        found = [i for i in outcome.attention if i.focus == "B"]
        if found:
            assert "A" in found[0].depends_on


# ── the objective ────────────────────────────────────────────────────────────

class TestTheObjective:

    def test_thousands_of_claims_become_a_handful_of_items(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        rows = [{"record_type": "claim", "claim_id": "C-0", "is_root": True,
                 "statement": "the release is safe",
                 "depends_on": [f"C-{i}" for i in range(1, 20)]}]
        for i in range(1, 4000):
            rows.append({"record_type": "claim", "claim_id": f"C-{i}",
                         "statement": f"lemma {i}",
                         "depends_on": [f"C-{i * 2}"] if i * 2 < 4000 else [],
                         "supporting_evidence": [f"E-{i}"]})
        for i in range(1, 4000):
            rows.append({"record_type": "evidence", "evidence_id": f"E-{i}",
                         "evidence_type": "TOOL_RESULT",
                         "producer": {"producer_id": f"agent-{i % 500}",
                                      "kind": "AGENT"},
                         "supports_claims": [f"C-{i}"], "content": {"n": i}})
        path = tmp_path / "scale.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows))

        started = time.time()
        outcome = assure(str(path))
        assert time.time() - started < 120
        # Eight thousand records in; a list a person can actually read out.
        assert len(outcome.attention) <= 20
        assert len(outcome.attention.top(7)) >= len(outcome.attention.undroppable)

    def test_compression_never_loses_a_blocking_item(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        rows = [{"record_type": "claim", "claim_id": "C-0", "is_root": True,
                 "statement": "s", "depends_on": ["C-1"]},
                {"record_type": "claim", "claim_id": "C-1", "statement": "s"}]
        for i in range(400):
            rows.append({"record_type": "evidence", "evidence_id": f"E-{i}",
                         "evidence_type": "TOOL_RESULT",
                         "producer": {"producer_id": "one-agent", "kind": "AGENT"},
                         "supports_claims": ["C-1"], "content": {"n": i}})
        rows.append({"record_type": "evidence", "evidence_id": "E-bad",
                     "evidence_type": "TOOL_RESULT",
                     "producer": {"producer_id": "other", "kind": "AGENT"},
                     "contradicts_claims": ["C-1"], "content": {"no": True}})
        path = tmp_path / "loud.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows))
        outcome = assure(str(path))
        blocking = outcome.attention.blocking
        shown = {i.item_id for i in outcome.attention.top(1)}
        assert all(i.item_id in shown for i in blocking)


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def assure_envelope(tmp_path):
    def run(rows):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "envelope.json"
        path.write_text(json.dumps(rows))
        return assure(str(path))
    return run
