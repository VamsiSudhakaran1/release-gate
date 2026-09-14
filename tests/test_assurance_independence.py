"""Independence — whether agreement is corroboration or an echo.

The scenario the prompt names is the test plan: ten thousand agents deriving from
one upstream artifact are one validation seen many times. Several tests below do
nothing but try to get that to read as many validations, or to get a probability
of truth out of a structural measure.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind,
)
from release_gate.assurance.independence import (
    AncestryCluster,
    IndependenceProfile,
    LineageConcentration,
    analyse_independence,
)
from release_gate.assurance.methodology import (
    ALL_CASE_TYPES, AncestryIndependence, AssuranceMethodology, Requirement,
    RequirementEffect, RequirementOutcome,
)
from release_gate.assurance.zero_config import assure, render_text


def rec(producer, parents=(), note=""):
    return EvidenceRecord.declared(
        EvidenceType.OTHER, source="s",
        producer=Producer(producer_id=producer, kind=ProducerKind.AGENT),
        parent_evidence=tuple(parents), content={"n": note})


def fan_out(n, *, root_producer="upstream://authoritative", prefix="agent"):
    """One authoritative root, `n` agents derived from it."""
    root = rec(root_producer)
    records = [root]
    for i in range(n):
        records.append(rec(f"{prefix}://{i}", parents=(root.evidence_id,), note=str(i)))
    return root, records


def _write(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(path)


# ── the scenario the prompt names ────────────────────────────────────────────

class TestTenThousandAgentsOneArtifact:

    def test_many_agents_on_one_root_are_one_lineage(self):
        _root, records = fan_out(10_000)
        profile = analyse_independence(records)
        assert profile.independent_roots == 1
        assert profile.contributors == 10_001
        assert profile.largest_ancestry_cluster == 10_001

    def test_that_is_not_ten_thousand_independent_validations(self):
        _root, records = fan_out(10_000)
        profile = analyse_independence(records)
        assert profile.root_evidence_count == 1
        assert profile.shared_ancestry_concentration == 1.0
        assert profile.concentration is LineageConcentration.HIGH

    def test_the_prompts_example_shape(self):
        root, records = fan_out(7_991)
        for k in range(6):
            lab = rec(f"lab://{k}")
            records.append(lab)
            for j in range(73):
                records.append(rec(f"agent://other-{k}-{j}",
                                   parents=(lab.evidence_id,), note=f"{k}-{j}"))
        profile = analyse_independence(records)
        assert profile.independent_roots == 7
        assert profile.largest_ancestry_cluster == 7_992
        assert profile.concentration is LineageConcentration.HIGH
        rendered = profile.render()
        assert "Independent evidence roots: 7" in rendered
        assert "HIGH lineage concentration" in rendered

    def test_ten_thousand_records_is_a_normal_input(self):
        import time

        _root, records = fan_out(10_000)
        start = time.time()
        analyse_independence(records)
        assert time.time() - start < 5.0

    def test_a_ten_thousand_deep_chain_does_not_exhaust_the_stack(self):
        chain = [rec("a://0")]
        for i in range(1, 10_000):
            chain.append(rec(f"a://{i}", parents=(chain[-1].evidence_id,), note=str(i)))
        profile = analyse_independence(chain)
        assert profile.independent_roots == 1
        assert profile.records_examined == 10_000


# ── no probability of truth ──────────────────────────────────────────────────

class TestNoProbabilityOfTruth:

    def test_the_output_carries_no_confidence_or_likelihood(self):
        _root, records = fan_out(20)
        blob = json.dumps(analyse_independence(records).to_dict()).lower()
        for banned in ("confidence", "probability", "likelihood", "certainty",
                       "trust_score", "credence"):
            assert banned not in blob, banned

    def test_concentration_is_a_share_of_contributors_not_a_score(self):
        root = rec("src://1")
        records = [root] + [rec(f"d://{i}", parents=(root.evidence_id,), note=str(i))
                            for i in range(3)]
        profile = analyse_independence(records)
        assert profile.shared_ancestry_concentration == 1.0
        assert profile.largest_ancestry_cluster == profile.contributors

    def test_more_roots_does_not_produce_a_truth_value(self):
        profile = analyse_independence([rec(f"a://{i}") for i in range(8)])
        payload = profile.to_dict()
        assert isinstance(payload["independent_roots"], int)
        assert "verified" not in payload
        assert "score" not in payload


# ── ancestry derivation ──────────────────────────────────────────────────────

class TestAncestry:

    def test_disjoint_roots_are_separate_lineages(self):
        a, b = rec("a://root"), rec("b://root")
        records = [a, b,
                   rec("a://child", parents=(a.evidence_id,)),
                   rec("b://child", parents=(b.evidence_id,))]
        assert analyse_independence(records).independent_roots == 2

    def test_a_shared_ancestor_merges_lineages(self):
        shared = rec("shared://root")
        left = rec("left://1", parents=(shared.evidence_id,))
        right = rec("right://1", parents=(shared.evidence_id,))
        assert analyse_independence([shared, left, right]).independent_roots == 1

    def test_a_record_drawing_on_two_roots_joins_them(self):
        a, b = rec("a://root"), rec("b://root")
        joined = rec("j://1", parents=(a.evidence_id, b.evidence_id))
        profile = analyse_independence([a, b, joined])
        assert profile.independent_roots == 1
        assert profile.root_evidence_count == 2

    def test_an_unheld_parent_makes_the_record_its_own_root(self):
        """We can see it derives from something and cannot see what."""
        orphan = rec("o://1", parents=("ev_not_in_this_case",))
        profile = analyse_independence([orphan, rec("x://1")])
        assert profile.independent_roots == 2

    def test_a_derivation_cycle_is_reported_not_followed(self):
        first = rec("c://1")
        second = rec("c://2", parents=(first.evidence_id,))
        looped = EvidenceRecord.declared(
            EvidenceType.OTHER, source="s",
            producer=Producer(producer_id="c://1", kind=ProducerKind.AGENT),
            parent_evidence=(second.evidence_id,), content={"n": "loop"})
        profile = analyse_independence([first, second, looped])
        assert profile.records_examined == 3

    def test_transitive_ancestry_is_followed_to_the_root(self):
        a = rec("a://0")
        b = rec("a://1", parents=(a.evidence_id,))
        c = rec("a://2", parents=(b.evidence_id,))
        profile = analyse_independence([a, b, c])
        assert profile.root_evidence_count == 1
        assert profile.independent_roots == 1


# ── unknown ancestry ─────────────────────────────────────────────────────────

class TestUnknownAncestry:

    def test_records_citing_no_parents_count_as_unknown_ancestry(self):
        profile = analyse_independence([rec(f"x://{i}") for i in range(5)])
        assert profile.unknown_ancestry == 5

    def test_all_unknown_cannot_be_banded(self):
        profile = analyse_independence([rec(f"x://{i}") for i in range(5)])
        assert profile.concentration is LineageConcentration.UNKNOWN
        assert profile.determinable is False

    def test_the_unknown_group_can_undetermine_the_ranking(self):
        """If the unrecorded group could itself be the largest, nothing is settled."""
        root = rec("src://1")
        records = [root] + [rec(f"d://{i}", parents=(root.evidence_id,), note=str(i))
                            for i in range(3)]
        records += [rec(f"u://{i}", note=f"u{i}") for i in range(20)]
        profile = analyse_independence(records)
        assert profile.concentration is LineageConcentration.UNKNOWN
        assert profile.unknown_ancestry >= profile.largest_ancestry_cluster

    def test_unknown_ancestry_is_neither_independent_nor_identical(self):
        profile = analyse_independence([rec(f"x://{i}") for i in range(5)])
        # Counted apart, so a population of unattributed records cannot masquerade
        # as many independent roots.
        assert profile.unknown_ancestry == 5
        assert not profile.determinable

    def test_a_single_contributor_has_nothing_to_concentrate(self):
        profile = analyse_independence([rec("only://1")])
        assert profile.concentration is LineageConcentration.NONE

    def test_no_evidence_at_all(self):
        profile = analyse_independence([])
        assert profile.contributors == 0
        assert profile.concentration is LineageConcentration.UNKNOWN


# ── the bands ────────────────────────────────────────────────────────────────

class TestBands:

    def _spread(self, in_cluster, singletons):
        root = rec("root://1")
        records = [root]
        for i in range(in_cluster - 1):
            records.append(rec(f"c://{i}", parents=(root.evidence_id,), note=str(i)))
        for j in range(singletons):
            other = rec(f"s://{j}", note=f"s{j}")
            records.append(other)
            records.append(rec(f"s://{j}-child", parents=(other.evidence_id,),
                               note=f"sc{j}"))
        return analyse_independence(records)

    def test_a_dominant_lineage_reads_high(self):
        assert self._spread(60, 10).concentration is LineageConcentration.HIGH

    def test_a_spread_population_reads_low(self):
        assert self._spread(4, 40).concentration is LineageConcentration.LOW

    def test_the_band_always_ships_with_the_ratio(self):
        profile = self._spread(60, 10)
        assert profile.shared_ancestry_concentration is not None
        assert profile.summary()["shared_ancestry_concentration"] is not None


# ── it reports, it does not penalise ─────────────────────────────────────────

class TestReportedNotPenalised:

    @pytest.fixture
    def concentrated(self, tmp_path):
        rows = [{"record_type": "evidence", "evidence_id": "ev_root",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "upstream://source", "kind": "tool"}}]
        for i in range(12):
            rows.append({"record_type": "evidence", "evidence_id": f"ev_{i}",
                         "kind": "TEST_RESULT", "parent_evidence": ["ev_root"],
                         "producer": {"producer_id": f"agent://{i}", "kind": "agent"}})
        return _write(tmp_path, "fan.jsonl", rows)

    def test_high_concentration_is_advisory(self, concentrated):
        findings = [f for f in assure(concentrated).analysis.findings
                    if f.domain is AnalysisDomain.INDEPENDENCE]
        assert findings
        assert all(f.effect is RequirementEffect.ADVISORY for f in findings)

    def test_no_independence_finding_ever_blocks_or_holds(self, concentrated):
        for finding in assure(concentrated).analysis.findings:
            if finding.domain is AnalysisDomain.INDEPENDENCE:
                assert finding.effect is RequirementEffect.ADVISORY, finding.rule_id

    def test_the_remedy_says_none_required(self, concentrated):
        finding = next(f for f in assure(concentrated).analysis.findings
                       if f.rule_id == "RG-INDEP-001")
        assert "none required" in finding.remedy

    def test_a_single_root_is_reported(self, concentrated):
        rules = {f.rule_id for f in assure(concentrated).analysis.findings}
        assert "RG-INDEP-002" in rules

    def test_the_report_says_it_is_not_a_penalty(self, concentrated):
        text = render_text(assure(concentrated))
        assert "WHERE THE SUPPORT COMES FROM" in text
        assert "not penalised" in text


# ── the methodology hook ─────────────────────────────────────────────────────

class TestMethodologyHook:
    """The only place concentration becomes a verdict."""

    def _methodology(self, **kwargs):
        return AssuranceMethodology(
            methodology_id="needs-independence", version="1.0.0", domain="test",
            case_types=ALL_CASE_TYPES,
            description="requires independently rooted support",
            requirements=(Requirement(
                requirement_id="independence.ancestry",
                description="support rests on independent lineages",
                predicate=AncestryIndependence(**kwargs),
                effect=RequirementEffect.HOLD,
                remedy="obtain support from an independently rooted source"),))

    @pytest.fixture
    def concentrated(self, tmp_path):
        rows = [{"record_type": "evidence", "evidence_id": "ev_root",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "upstream://source", "kind": "tool"}}]
        for i in range(12):
            rows.append({"record_type": "evidence", "evidence_id": f"ev_{i}",
                         "kind": "TEST_RESULT", "parent_evidence": ["ev_root"],
                         "producer": {"producer_id": f"agent://{i}", "kind": "agent"}})
        return _write(tmp_path, "fan.jsonl", rows)

    def test_a_methodology_requiring_independence_is_unsatisfied(self, concentrated):
        outcome = assure(concentrated, methodology=self._methodology(minimum_roots=2))
        result = outcome.assessment.results[0]
        assert result.outcome is RequirementOutcome.UNSATISFIED
        assert "corroboration" in result.detail

    def test_the_same_case_passes_when_one_root_is_enough(self, concentrated):
        outcome = assure(concentrated, methodology=self._methodology(minimum_roots=1))
        assert outcome.assessment.results[0].outcome is RequirementOutcome.SATISFIED

    def test_a_concentration_ceiling_can_be_set(self, concentrated):
        outcome = assure(concentrated,
                         methodology=self._methodology(minimum_roots=1,
                                                       maximum_concentration=0.5))
        result = outcome.assessment.results[0]
        assert result.outcome is RequirementOutcome.UNSATISFIED
        assert "one lineage" in result.detail

    def test_undeterminable_ancestry_is_not_assessed_not_failed(self, tmp_path):
        rows = [{"record_type": "evidence", "evidence_id": f"ev_{i}",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": f"agent://{i}", "kind": "agent"}}
                for i in range(6)]
        path = _write(tmp_path, "flat.jsonl", rows)
        outcome = assure(path, methodology=self._methodology(minimum_roots=2))
        assert outcome.assessment.results[0].outcome is RequirementOutcome.NOT_ASSESSED

    def test_the_predicate_serialises_for_transport(self):
        predicate = AncestryIndependence(minimum_roots=3, maximum_concentration=0.4)
        payload = json.loads(json.dumps(predicate.to_dict()))
        assert payload["kind"] == "ancestry_independence"
        assert payload["minimum_roots"] == 3

    def test_derived_ancestry_is_a_different_question_from_declared_groups(self):
        """Ten thousand agents declaring distinct groups still collapse to one root."""
        from release_gate.assurance.methodology import IndependenceThreshold

        assert AncestryIndependence.KIND != IndependenceThreshold.KIND


# ── case integration ─────────────────────────────────────────────────────────

class TestCaseIntegration:

    @pytest.fixture
    def concentrated(self, tmp_path):
        rows = [{"record_type": "evidence", "evidence_id": "ev_root",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "upstream://source", "kind": "tool"}}]
        for i in range(12):
            rows.append({"record_type": "evidence", "evidence_id": f"ev_{i}",
                         "kind": "TEST_RESULT", "parent_evidence": ["ev_root"],
                         "producer": {"producer_id": f"agent://{i}", "kind": "agent"}})
        return _write(tmp_path, "fan.jsonl", rows)

    def test_the_outcome_carries_the_profile(self, concentrated):
        profile = assure(concentrated).independence
        assert profile is not None
        assert profile.independent_roots == 1

    def test_the_profile_lands_on_the_case(self, concentrated):
        records = [r.to_dict() for r in assure(concentrated).case.records("evidence")]
        profiles = [r for r in records if r.get("record_type") == "independence"]
        assert len(profiles) == 1

    def test_independence_coverage_is_stated(self, concentrated):
        rows = [r.to_dict() for r in assure(concentrated).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "independence")
        assert row["status"] == "ASSESSED"
        assert row["largest_ancestry_cluster"] == 13

    def test_undeterminable_ancestry_is_not_assessed_coverage(self, tmp_path):
        rows = [{"record_type": "evidence", "evidence_id": f"ev_{i}",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": f"agent://{i}", "kind": "agent"}}
                for i in range(6)]
        path = _write(tmp_path, "flat.jsonl", rows)
        coverage = [r.to_dict() for r in assure(path).case.records("coverage")]
        row = next(r for r in coverage if r["dimension"] == "independence")
        assert row["status"] == "NOT_ASSESSED"

    def test_the_profile_digest_is_stable(self, concentrated):
        assert (assure(concentrated).independence.digest()
                == assure(concentrated).independence.digest())

    def test_the_outcome_serialises(self, concentrated):
        payload = json.loads(json.dumps(assure(concentrated).to_dict()))
        assert payload["independence"]["independent_roots"] == 1
