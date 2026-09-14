"""Assumptions, and what falls over if one of them is wrong.

Every argument rests on things nobody checked. The danger is not that assumptions
exist — it is that they are invisible, so the reviewer approving a conclusion
cannot ask the only question that matters: if this fails, what collapses?
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.assumptions import (
    Assumption,
    AssumptionCriticality,
    AssumptionGraph,
    AssumptionSource,
    CollapseSet,
)
from release_gate.assurance.attention import AttentionReason
from release_gate.assurance.claims import (
    Claim, ClaimGraph, ClaimProvenance, ClaimStatus, ClaimType,
)
from release_gate.assurance.evidence import Producer, VerificationMethod
from release_gate.assurance.methodology import (
    ALL_CASE_TYPES, AssumptionsExamined, AssuranceMethodology, Requirement,
    RequirementEffect, RequirementOutcome,
)
from release_gate.assurance.verification import (
    VerificationAttempt, VerificationStatus,
)
from release_gate.assurance.zero_config import assure, render_text

P = Producer(producer_id="agent://planner")


def claim(claim_id, **kwargs):
    kwargs.setdefault("statement", f"statement of {claim_id}")
    kwargs.setdefault("producer", P)
    return Claim(claim_id=claim_id, **kwargs)


CHAIN = [
    claim("as_clock", statement="the replica clock is within 50ms of primary",
          claim_type=ClaimType.ASSUMPTION),
    claim("cl_ordering", statement="writes apply in commit order",
          assumptions=("as_clock",)),
    claim("cl_noloss", statement="no rows are lost", parents=("cl_ordering",)),
    claim("cl_root", statement="the migration is safe", is_root=True,
          parents=("cl_noloss",)),
    claim("cl_side", statement="the dashboard renders", assumptions=("as_theme",)),
]


def _write(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(path)


ENVELOPE = [
    {"record_type": "claim", "claim_id": "as_clock", "claim_type": "ASSUMPTION",
     "proposition": "the replica clock is within 50ms of primary",
     "producer": {"producer_id": "agent://planner", "kind": "agent"}},
    {"record_type": "claim", "claim_id": "cl_ordering",
     "proposition": "writes apply in commit order",
     "producer": {"producer_id": "agent://planner", "kind": "agent"},
     "assumptions": ["as_clock"]},
    {"record_type": "claim", "claim_id": "cl_root", "is_root": True,
     "proposition": "the migration is safe to apply",
     "producer": {"producer_id": "agent://planner", "kind": "agent"},
     "depends_on": ["cl_ordering"], "assumptions": ["as_backup"]},
]


# ── the question ─────────────────────────────────────────────────────────────

class TestIfThisFailsWhatCollapses:

    @pytest.fixture
    def graph(self):
        return AssumptionGraph.from_claim_graph(ClaimGraph(CHAIN))

    def test_collapse_follows_the_chain(self, graph):
        collapse = graph.collapse("as_clock")
        assert collapse.direct == ("cl_ordering",)
        assert set(collapse.transitive) == {"cl_noloss", "cl_root"}
        assert collapse.size == 3

    def test_it_names_the_conclusion_that_falls(self, graph):
        collapse = graph.collapse("as_clock")
        assert collapse.conclusion_collapses is True
        assert collapse.roots_affected == ("cl_root",)

    def test_criticality_is_the_collapse_set_not_a_scale(self, graph):
        assert graph.assumption("as_clock").criticality \
            is AssumptionCriticality.LOAD_BEARING
        assert graph.assumption("as_theme").criticality \
            is AssumptionCriticality.SUPPORTING

    def test_an_assumption_nothing_rests_on_is_isolated(self):
        lonely = [claim("as_x", claim_type=ClaimType.ASSUMPTION),
                  claim("cl_root", is_root=True)]
        graph = AssumptionGraph.from_claim_graph(ClaimGraph(lonely))
        assert graph.assumption("as_x").criticality is AssumptionCriticality.ISOLATED
        assert graph.collapse("as_x").size == 0

    def test_the_explanation_answers_the_question_in_its_own_words(self, graph):
        text = graph.explain("as_clock")
        assert "If it fails, 3 claim(s) collapse" in text
        assert "THE CONCLUSION FALLS: cl_root" in text

    def test_load_bearing_assumptions_sort_first(self, graph):
        assert graph.assumptions[0].criticality is AssumptionCriticality.LOAD_BEARING

    def test_a_cycle_does_not_hang_the_collapse_walk(self):
        looped = [claim("as_x", claim_type=ClaimType.ASSUMPTION),
                  claim("cl_a", assumptions=("as_x",), parents=("cl_b",)),
                  claim("cl_b", parents=("cl_a",))]
        graph = AssumptionGraph.from_claim_graph(ClaimGraph(looped))
        assert graph.collapse("as_x").size >= 1

    def test_claims_with_their_own_verification_are_flagged_not_excused(self):
        checked = [
            claim("as_x", claim_type=ClaimType.ASSUMPTION),
            claim("cl_a", assumptions=("as_x",), verification_attempts=(
                VerificationAttempt(method=VerificationMethod.TEST_SUITE,
                                    verifier="ci://1",
                                    status=VerificationStatus.PASSED),)),
        ]
        collapse = AssumptionGraph.from_claim_graph(ClaimGraph(checked)).collapse("as_x")
        assert "cl_a" in collapse.all, "it still collapses"
        assert "cl_a" in collapse.verified_among_collapsed, "and is flagged for judgement"


# ── an assumption nobody wrote down ──────────────────────────────────────────

class TestUnstatedAssumptions:

    @pytest.fixture
    def graph(self):
        return AssumptionGraph.from_claim_graph(ClaimGraph(CHAIN))

    def test_a_referenced_but_undescribed_assumption_is_materialised(self, graph):
        """The claim graph could not see this at all."""
        found = graph.assumption("as_theme")
        assert found is not None
        assert found.stated is False

    def test_it_records_who_referenced_it(self, graph):
        assert graph.assumption("as_theme").referenced_by == ("cl_side",)

    def test_it_still_gets_a_collapse_set(self, graph):
        assert graph.collapse("as_theme").direct == ("cl_side",)

    def test_the_explanation_says_it_was_never_stated(self, graph):
        assert "NOT STATED" in graph.explain("as_theme")

    def test_unstated_is_listed_separately(self, graph):
        assert [a.assumption_id for a in graph.unstated()] == ["as_theme"]

    def test_a_stated_assumption_is_not_flagged(self, graph):
        assert graph.assumption("as_clock").stated is True


# ── the seven fields ─────────────────────────────────────────────────────────

class TestRecordShape:

    @pytest.fixture
    def graph(self):
        return AssumptionGraph.from_claim_graph(ClaimGraph(CHAIN))

    def test_every_named_field_is_present(self, graph):
        payload = graph.assumption("as_clock").to_dict()
        for name in ("assumption_id", "source", "dependent_claims",
                     "supporting_evidence", "verification", "status", "criticality"):
            assert name in payload, name

    def test_source_carries_provenance_and_attribution(self, graph):
        source = graph.assumption("as_clock").source
        assert source.producer_id == "agent://planner"
        assert source.attributable is True

    def test_a_model_extracted_assumption_is_derived(self):
        # `Claim` refuses the construction outright unless provenance is DERIVED,
        # so the invariant is enforced where the record is made, not here.
        extracted = [claim("as_x", claim_type=ClaimType.ASSUMPTION,
                           extracted_by_model="some-model",
                           provenance=ClaimProvenance.DERIVED),
                     claim("cl_a", assumptions=("as_x",))]
        graph = AssumptionGraph.from_claim_graph(ClaimGraph(extracted))
        source = graph.assumption("as_x").source
        assert source.model_extracted == "some-model"
        assert source.provenance == ClaimProvenance.DERIVED.value

    def test_dependent_claims_are_the_direct_dependents(self, graph):
        assert graph.assumption("as_clock").dependent_claims == ("cl_ordering",)

    def test_status_comes_from_the_claim_graph(self, graph):
        """Nothing bears on it, so the graph says UNKNOWN rather than UNVERIFIED."""
        assert graph.assumption("as_clock").status is ClaimStatus.UNKNOWN

    def test_a_model_extracted_claim_cannot_claim_declared_provenance(self):
        from release_gate.assurance.claims import ClaimError

        with pytest.raises(ClaimError, match="DERIVED provenance"):
            claim("as_x", claim_type=ClaimType.ASSUMPTION,
                  extracted_by_model="some-model",
                  provenance=ClaimProvenance.DECLARED)

    def test_declared_criticality_is_kept_apart_from_derived(self):
        declared = [claim("as_x", claim_type=ClaimType.ASSUMPTION, criticality="HIGH"),
                    claim("cl_root", is_root=True, assumptions=("as_x",))]
        found = AssumptionGraph.from_claim_graph(ClaimGraph(declared)).assumption("as_x")
        assert found.declared_criticality == "HIGH"
        assert found.criticality is AssumptionCriticality.LOAD_BEARING

    def test_unexamined_means_load_bearing_and_unchecked(self, graph):
        assert graph.assumption("as_clock").unexamined is True
        assert graph.assumption("as_theme").unexamined is False

    def test_the_digest_is_stable(self):
        first = AssumptionGraph.from_claim_graph(ClaimGraph(CHAIN))
        second = AssumptionGraph.from_claim_graph(ClaimGraph(CHAIN))
        assert first.digest() == second.digest()

    def test_it_serialises(self, graph):
        payload = json.loads(json.dumps(graph.to_dict()))
        assert payload["load_bearing"] == 1
        assert payload["unstated"] == 1

    def test_an_empty_graph_is_valid(self):
        empty = AssumptionGraph.from_claim_graph(None)
        assert len(empty) == 0
        assert empty.explain() == "No assumptions recorded."


# ── it is not a parallel model ───────────────────────────────────────────────

class TestBuiltOnClaims:

    def test_an_assumption_is_a_typed_claim_not_a_new_record(self):
        assert ClaimType.ASSUMPTION in set(ClaimType)

    def test_status_already_propagates_through_assumption_edges(self):
        """`depends_on` folds assumptions in beside parents, so a conclusion
        cannot outrank the assumption it rests on."""
        chain = [claim("as_x", claim_type=ClaimType.ASSUMPTION),
                 claim("cl_root", is_root=True, assumptions=("as_x",))]
        graph = ClaimGraph(chain)
        assert "as_x" in graph.claim("cl_root").depends_on

    def test_the_graph_is_a_view_not_a_store(self):
        """Nothing is created that the claim graph did not already imply."""
        graph = AssumptionGraph.from_claim_graph(ClaimGraph(CHAIN))
        stated = {a.assumption_id for a in graph if a.stated}
        assert stated <= {c.claim_id for c in CHAIN}


# ── findings ─────────────────────────────────────────────────────────────────

class TestFindings:

    @pytest.fixture
    def envelope(self, tmp_path):
        return _write(tmp_path, "a.jsonl", ENVELOPE)

    def _rules(self, path):
        return {f.rule_id: f for f in assure(path).analysis.findings}

    def test_an_unexamined_load_bearing_assumption_holds(self, envelope):
        finding = self._rules(envelope)["RG-ASSUME-001"]
        assert finding.effect is RequirementEffect.HOLD
        assert finding.domain is AnalysisDomain.ASSUMPTION

    def test_the_finding_says_what_would_collapse(self, envelope):
        finding = self._rules(envelope)["RG-ASSUME-001"]
        assert "collapse" in finding.detail
        assert "cl_root" in finding.detail

    def test_an_unstated_assumption_holds(self, envelope):
        finding = self._rules(envelope)["RG-ASSUME-002"]
        assert finding.effect is RequirementEffect.HOLD
        assert "as_backup" in finding.refs

    def test_a_case_with_no_assumptions_fires_nothing(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
                 "proposition": "p",
                 "producer": {"producer_id": "agent://x", "kind": "agent"}}]
        rules = self._rules(_write(tmp_path, "none.jsonl", rows))
        assert "RG-ASSUME-001" not in rules
        assert "RG-ASSUME-002" not in rules

    def test_it_becomes_an_attention_item(self, envelope):
        reasons = {i.reason for i in assure(envelope).attention}
        assert AttentionReason.UNEXAMINED_ASSUMPTION in reasons


# ── the ingest must carry assumption edges ───────────────────────────────────

class TestIngestCarriesEdges:
    """Dropping `assumptions` would make every assumption look isolated."""

    @pytest.fixture
    def envelope(self, tmp_path):
        return _write(tmp_path, "a.jsonl", ENVELOPE)

    def test_declared_assumptions_reach_the_claim(self, envelope):
        from release_gate.assurance.ingest import ingest_path

        claims = {c.claim_id: c for c in ingest_path(envelope).claims}
        assert claims["cl_ordering"].assumptions == ("as_clock",)

    def test_the_assumption_is_therefore_load_bearing(self, envelope):
        found = assure(envelope).assumptions.assumption("as_clock")
        assert found.criticality is AssumptionCriticality.LOAD_BEARING
        assert found.collapse.roots_affected == ("cl_root",)


# ── the case and the report ──────────────────────────────────────────────────

class TestPipeline:

    @pytest.fixture
    def envelope(self, tmp_path):
        return _write(tmp_path, "a.jsonl", ENVELOPE)

    def test_the_outcome_carries_the_graph(self, envelope):
        assert len(assure(envelope).assumptions) == 2

    def test_assumptions_land_in_their_own_collection(self, envelope):
        records = [r.to_dict() for r in assure(envelope).case.records("assumptions")]
        assert {r["record_type"] for r in records} == {"assumption"}

    def test_the_collection_is_present_even_when_empty(self, tmp_path):
        """Nobody declaring assumptions is different from nobody looking."""
        rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
                 "proposition": "p",
                 "producer": {"producer_id": "agent://x", "kind": "agent"}}]
        case = assure(_write(tmp_path, "none.jsonl", rows)).case
        assert "assumptions" not in case.absent_collections

    def test_coverage_never_claims_the_list_is_complete(self, envelope):
        rows = [r.to_dict() for r in assure(envelope).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "assumptions")
        assert "only declared assumptions are visible here" in row["note"]

    def test_coverage_is_not_assessed_while_any_is_unexamined(self, envelope):
        rows = [r.to_dict() for r in assure(envelope).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "assumptions")
        assert row["status"] == "NOT_ASSESSED"
        assert row["unexamined"] == 2

    def test_the_report_answers_the_question(self, envelope):
        text = render_text(assure(envelope))
        assert "WHAT THIS RESTS ON" in text
        assert "THE CONCLUSION FALLS" in text

    def test_the_outcome_serialises(self, envelope):
        payload = json.loads(json.dumps(assure(envelope).to_dict()))
        assert payload["assumptions"]["load_bearing"] == 2


class TestMethodologyHook:

    def _methodology(self, **kwargs):
        return AssuranceMethodology(
            methodology_id="examined", version="1.0.0", domain="test",
            case_types=ALL_CASE_TYPES,
            description="load-bearing assumptions must be examined",
            requirements=(Requirement(
                requirement_id="assumptions.examined",
                description="load-bearing assumptions are stated and examined",
                predicate=AssumptionsExamined(**kwargs),
                effect=RequirementEffect.HOLD,
                remedy="examine them"),))

    @pytest.fixture
    def envelope(self, tmp_path):
        return _write(tmp_path, "a.jsonl", ENVELOPE)

    def test_an_unexamined_assumption_is_unsatisfied(self, envelope):
        outcome = assure(envelope, methodology=self._methodology())
        result = outcome.assessment.results[0]
        assert result.outcome is RequirementOutcome.UNSATISFIED
        assert result.observed["unchecked"] == 2

    def test_a_methodology_may_require_only_that_they_are_stated(self, envelope):
        outcome = assure(envelope,
                         methodology=self._methodology(require_checked=False))
        result = outcome.assessment.results[0]
        assert result.outcome is RequirementOutcome.UNSATISFIED
        assert result.observed["unstated"] == 1

    def test_a_case_with_examined_assumptions_satisfies_it(self, tmp_path):
        rows = [
            {"record_type": "claim", "claim_id": "as_x", "claim_type": "ASSUMPTION",
             "proposition": "the clock is synced",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "supporting_evidence": ["ev_1"]},
            {"record_type": "claim", "claim_id": "cl_root", "is_root": True,
             "proposition": "p", "assumptions": ["as_x"],
             "producer": {"producer_id": "agent://x", "kind": "agent"}},
            {"record_type": "evidence", "evidence_id": "ev_1", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://1", "kind": "tool"},
             "supports_claims": ["as_x"]},
        ]
        outcome = assure(_write(tmp_path, "ok.jsonl", rows),
                         methodology=self._methodology())
        assert outcome.assessment.results[0].outcome is RequirementOutcome.SATISFIED

    def test_the_predicate_serialises(self):
        payload = json.loads(json.dumps(AssumptionsExamined().to_dict()))
        assert payload["kind"] == "assumptions_examined"
