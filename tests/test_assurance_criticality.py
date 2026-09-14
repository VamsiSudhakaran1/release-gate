"""Criticality: what the human decision rests on, by dependency and never by volume."""

from __future__ import annotations

import json
import time

import pytest

from release_gate.assurance.analysis import (
    AnalysisDomain, _analyse_criticality)
from release_gate.assurance.assumptions import AssumptionCriticality
from release_gate.assurance.claims import Claim, ClaimGraph
from release_gate.assurance.criticality import (
    ClaimCriticality, CriticalPath, CriticalitySet, DecisionLink, LoadBearing,
    analyse_criticality)
from release_gate.assurance.methodology import (
    CriticalClaimsIdentified, RequirementEffect, RequirementOutcome,
    predicate_from_dict)


def graph(*claims):
    return ClaimGraph(claims)


def chain(depth, **root_kw):
    """Decision -> c0 -> c1 -> ... -> c{depth}."""
    claims = [Claim(claim_id="c0", statement="s", is_root=True,
                    parents=("c1",) if depth else (), **root_kw)]
    claims += [Claim(claim_id=f"c{i}", statement="s",
                     parents=(f"c{i + 1}",) if i < depth else ())
               for i in range(1, depth + 1)]
    return ClaimGraph(claims)


# ── dependency propagation ───────────────────────────────────────────────────

class TestPropagation:

    def test_the_prompt_chain_makes_the_deepest_claim_critical(self):
        # FinalDecision -> A -> B -> C
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True, parents=("B",)),
            Claim(claim_id="B", statement="b", parents=("C",)),
            Claim(claim_id="C", statement="c")))
        assert sorted(found.critical_ids) == ["A", "B", "C"]
        assert found.of("C").critical
        assert found.of("C").depth == 2

    def test_depth_is_reported_and_never_discounts(self):
        found = analyse_criticality(chain(6))
        assert all(e.critical for e in found.entries)
        assert found.of("c6").standing is found.of("c0").standing
        assert found.max_depth == 6

    def test_the_path_names_the_route_from_the_decision(self):
        found = analyse_criticality(chain(3))
        assert found.path_to("c3").render() == "decision -> c0 -> c1 -> c2 -> c3"

    def test_criticality_propagates_through_assumptions(self):
        # `depends_on` unifies parents and assumptions: an assumption the
        # conclusion rests on is load-bearing in exactly this sense.
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True, assumptions=("ASM",)),
            Claim(claim_id="ASM", statement="the clock is monotonic")))
        assert found.of("ASM").critical

    def test_a_corroborating_claim_is_not_load_bearing(self):
        # `supports` corroborates without carrying, so it is not a dependency.
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="S", statement="s", supports=("A",))))
        assert not found.of("S").critical
        assert found.of("S").standing is LoadBearing.ISOLATED

    def test_a_claim_nothing_rests_on_is_isolated(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Z", statement="z")))
        assert found.of("Z").standing is LoadBearing.ISOLATED

    def test_a_claim_others_rest_on_without_a_conclusion_is_supporting(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Y", statement="y", parents=("X",)),
            Claim(claim_id="X", statement="x")))
        assert found.of("X").standing is LoadBearing.SUPPORTING
        assert not found.of("X").critical

    def test_the_decision_claim_itself_is_critical_at_depth_zero(self):
        found = analyse_criticality(chain(0))
        assert found.of("c0").critical
        assert found.of("c0").depth == 0
        assert found.of("c0").via is None


# ── volume is never an input ─────────────────────────────────────────────────

class TestVolumeIsNeverAnInput:

    def test_a_claim_with_ten_thousand_records_off_the_path_is_not_critical(self):
        noisy = graph(
            Claim(claim_id="A", statement="a", is_root=True, parents=("B",)),
            Claim(claim_id="B", statement="b"),
            Claim(claim_id="D", statement="d",
                  supporting_evidence=tuple(f"e{i}" for i in range(10_000))))
        found = analyse_criticality(
            noisy, evidence_producers={f"e{i}": f"agent-{i}" for i in range(10_000)})
        assert sorted(found.critical_ids) == ["A", "B"]
        assert found.of("D").supporting_records == 10_000
        assert found.of("D").supporting_producers == 10_000
        assert not found.of("D").critical

    def test_a_claim_one_agent_emitted_once_at_depth_five_is_critical(self):
        deep = chain(5)
        found = analyse_criticality(deep)
        assert found.of("c5").critical
        assert found.of("c5").supporting_records == 0

    def test_the_producers_map_changes_no_verdict(self):
        built = chain(4)
        bare = analyse_criticality(built)
        loaded = analyse_criticality(
            built, evidence_producers={f"e{i}": f"p{i}" for i in range(500)})
        assert bare.critical_ids == loaded.critical_ids

    def test_the_record_states_that_volume_is_not_an_input(self):
        found = analyse_criticality(chain(2))
        assert found.summary()["volume_affects_criticality"] is False
        assert found.of("c1").to_dict()["volume_affects_criticality"] is False

    def test_thin_support_is_reported_and_never_a_discount(self):
        found = analyse_criticality(
            graph(Claim(claim_id="A", statement="a", is_root=True,
                        supporting_evidence=("e1",))),
            evidence_producers={"e1": "one-agent"})
        entry = found.of("A")
        assert entry.thin
        assert entry.critical
        assert entry.standing is LoadBearing.LOAD_BEARING

    def test_an_unsupported_claim_is_not_reported_as_thin(self):
        # Zero producers is an unsupported claim, which coverage owns; folding it
        # in here would blur a sharp signal into a common one.
        found = analyse_criticality(chain(2))
        assert found.thin() == ()


# ── a label is not a dependency ──────────────────────────────────────────────

class TestDeclaredVersusDerived:

    def test_a_declared_critical_claim_does_not_become_critical(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Z", statement="z", criticality="CRITICAL")))
        assert not found.of("Z").critical
        assert found.of("Z").declared_critical
        assert found.of("Z").disagrees_with_declaration

    def test_an_undeclared_claim_is_still_critical_if_depended_on(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True, parents=("B",)),
            Claim(claim_id="B", statement="b")))
        assert found.of("B").critical
        assert found.of("B").declared is None

    def test_agreement_is_not_reported_as_a_disagreement(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True, parents=("B",)),
            Claim(claim_id="B", statement="b", criticality="CRITICAL")))
        assert found.disagreements() == ()

    def test_a_low_declaration_on_a_load_bearing_claim_is_not_a_disagreement(self):
        # The refusal runs one way: the graph overrides a label that overclaims,
        # and a label that underclaims simply loses.
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True, parents=("B",)),
            Claim(claim_id="B", statement="b", criticality="LOW")))
        assert found.of("B").critical
        assert not found.of("B").disagrees_with_declaration


# ── undeterminable is not "nothing is critical" ──────────────────────────────

class TestUndeterminable:

    def test_a_pure_cycle_is_undeterminable(self):
        found = analyse_criticality(graph(
            Claim(claim_id="X", statement="x", parents=("Y",)),
            Claim(claim_id="Y", statement="y", parents=("X",))))
        assert not found.determinable
        assert found.link is DecisionLink.NONE
        assert found.critical_ids == frozenset()

    def test_is_critical_returns_none_rather_than_false(self):
        found = analyse_criticality(graph(
            Claim(claim_id="X", statement="x", parents=("Y",)),
            Claim(claim_id="Y", statement="y", parents=("X",))))
        assert found.is_critical("X") is None

    def test_a_determinable_case_answers_the_question(self):
        found = analyse_criticality(chain(1))
        assert found.is_critical("c1") is True
        assert found.is_critical("nope") is False

    def test_the_render_says_it_is_not_the_same_as_none_being_critical(self):
        found = analyse_criticality(graph(
            Claim(claim_id="X", statement="x", parents=("Y",)),
            Claim(claim_id="Y", statement="y", parents=("X",))))
        assert "not the same as none being critical" in found.render()

    def test_an_empty_graph_is_undeterminable(self):
        found = analyse_criticality(None)
        assert not found.determinable
        assert found.claims_examined == 0

    def test_undeterminable_criticality_holds(self):
        found = analyse_criticality(graph(
            Claim(claim_id="X", statement="x", parents=("Y",)),
            Claim(claim_id="Y", statement="y", parents=("X",))))
        rows = _analyse_criticality(found)
        assert [f.rule_id for f in rows] == ["RG-CRIT-001"]
        assert rows[0].effect is RequirementEffect.HOLD
        assert "nothing was checked" in rows[0].detail

    def test_a_case_with_no_claims_raises_nothing(self):
        assert _analyse_criticality(analyse_criticality(None)) == []


# ── structure the graph cannot resolve ───────────────────────────────────────

class TestStructuralGaps:

    def test_a_dangling_dependency_is_reported_not_silently_included(self):
        found = analyse_criticality(graph(
            Claim(claim_id="R", statement="r", is_root=True, parents=("GONE",))))
        assert found.of("R").missing_dependencies == ("GONE",)
        assert "GONE" not in found.critical_ids
        row = next(f for f in _analyse_criticality(found)
                   if f.rule_id == "RG-CRIT-002")
        assert row.effect is RequirementEffect.HOLD

    def test_an_unreachable_second_conclusion_is_reported(self):
        found = analyse_criticality(graph(
            Claim(claim_id="R", statement="r", is_root=True),
            Claim(claim_id="Other", statement="o")))
        assert found.unreachable_conclusions == ("Other",)
        row = next(f for f in _analyse_criticality(found)
                   if f.rule_id == "RG-CRIT-004")
        assert row.effect is RequirementEffect.ADVISORY

    def test_a_declared_disagreement_holds(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Z", statement="z", criticality="CRITICAL")))
        row = next(f for f in _analyse_criticality(found)
                   if f.rule_id == "RG-CRIT-003")
        assert row.effect is RequirementEffect.HOLD
        assert "cannot settle which" in row.detail

    def test_thin_critical_claims_are_advisory(self):
        found = analyse_criticality(
            graph(Claim(claim_id="A", statement="a", is_root=True,
                        supporting_evidence=("e1",))),
            evidence_producers={"e1": "solo"})
        row = next(f for f in _analyse_criticality(found)
                   if f.rule_id == "RG-CRIT-005")
        assert row.effect is RequirementEffect.ADVISORY
        assert row.observed["volume_affects_criticality"] is False
        assert "not as a discount" in row.detail

    def test_a_cycle_inside_a_reachable_chain_still_propagates(self):
        found = analyse_criticality(graph(
            Claim(claim_id="R", statement="r", is_root=True, parents=("A",)),
            Claim(claim_id="A", statement="a", parents=("B",)),
            Claim(claim_id="B", statement="b", parents=("A",))))
        assert sorted(found.critical_ids) == ["A", "B", "R"]
        assert found.path_to("B").render() == "decision -> R -> A -> B"


# ── the decision link ────────────────────────────────────────────────────────

class TestDecisionLink:

    def test_a_declared_root_wins(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="B", statement="b")))
        assert found.link is DecisionLink.DECLARED_ROOT
        assert found.decision_claims == ("A",)

    def test_graph_sinks_are_the_fallback(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", parents=("B",)),
            Claim(claim_id="B", statement="b")))
        assert found.link is DecisionLink.GRAPH_SINK
        assert found.decision_claims == ("A",)
        assert sorted(found.critical_ids) == ["A", "B"]

    def test_several_declared_roots_all_propagate(self):
        found = analyse_criticality(graph(
            Claim(claim_id="R1", statement="r", is_root=True, parents=("S",)),
            Claim(claim_id="R2", statement="r", is_root=True, parents=("T",)),
            Claim(claim_id="S", statement="s"), Claim(claim_id="T", statement="t")))
        assert sorted(found.critical_ids) == ["R1", "R2", "S", "T"]


# ── serialisation and scale ──────────────────────────────────────────────────

class TestRecordAndScale:

    def test_the_set_serialises_as_a_record(self):
        found = analyse_criticality(chain(2))
        payload = found.to_dict()
        assert payload["record_type"] == "criticality"
        assert payload["record_id"] == found.record_id
        assert payload["critical_ids"] == ["c0", "c1", "c2"]
        assert payload["paths"]

    def test_the_digest_is_stable(self):
        assert analyse_criticality(chain(3)).digest() \
            == analyse_criticality(chain(3)).digest()

    def test_a_ten_thousand_deep_chain_stays_linear(self):
        built = chain(9_999)
        started = time.time()
        found = analyse_criticality(built)
        assert time.time() - started < 10
        assert len(found.critical_ids) == 10_000
        assert found.max_depth == 9_999

    def test_a_deep_path_walks_and_elides(self):
        found = analyse_criticality(chain(9_999))
        route = found.path_to("c9999")
        assert len(route.claims) == 10_000
        assert "more ..." in route.render()
        assert route.depth == 9_999

    def test_a_ten_thousand_wide_fan_in_stays_linear(self):
        wide = [Claim(claim_id="root", statement="s", is_root=True,
                      parents=tuple(f"w{i}" for i in range(10_000)))]
        wide += [Claim(claim_id=f"w{i}", statement="s") for i in range(10_000)]
        started = time.time()
        found = analyse_criticality(ClaimGraph(wide))
        assert time.time() - started < 10
        assert len(found.critical_ids) == 10_001

    def test_path_to_returns_none_for_a_non_critical_claim(self):
        found = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Z", statement="z")))
        assert found.path_to("Z") is None
        assert found.path_to("absent") is None


# ── the shared vocabulary ────────────────────────────────────────────────────

class TestSharedVocabulary:

    def test_assumption_criticality_is_the_same_enum(self):
        # An assumption the decision rests on and a claim the decision rests on
        # are the same fact about the same graph; two vocabularies for it would
        # eventually disagree.
        assert AssumptionCriticality is LoadBearing
        assert AssumptionCriticality.LOAD_BEARING is LoadBearing.LOAD_BEARING


# ── the analysis consolidates on one definition ──────────────────────────────

class TestConsolidation:

    def test_every_guard_reads_the_derived_set(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "the migration is safe", "depends_on": ["B"]},
            {"record_type": "claim", "claim_id": "B", "statement": "no data loss",
             "depends_on": ["C"]},
            {"record_type": "claim", "claim_id": "C", "statement": "backups verified"},
            {"record_type": "adversarial", "target_claim": "C", "role": "RED_TEAM",
             "adversary": "rt", "outcome": "ARGUMENT_DEFECT",
             "detail": "the backup check never ran"},
        ])
        # C sits three links from the decision and is attacked there; the guard
        # must treat it as critical, which only happens if it reads the
        # propagated set rather than the root claims.
        assert "C" in outcome.criticality.critical_ids
        blocking = {f.rule_id for f in outcome.analysis.blocking}
        assert "RG-ADV-001" in blocking

    def test_criticality_is_stored_on_the_case(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True, "statement": "s"}])
        stored = [r for r in outcome.case.records("evidence")
                  if r.to_dict().get("record_type") == "criticality"]
        assert len(stored) == 1

    def test_coverage_reports_criticality(self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "A", "is_root": True,
             "statement": "s", "depends_on": ["B"]},
            {"record_type": "claim", "claim_id": "B", "statement": "s"}])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "criticality")
        assert row["status"] == "ASSESSED"
        assert row["volume_affects_criticality"] is False
        assert row["critical"] == 2

    def test_coverage_says_the_guards_were_inactive_when_undeterminable(
            self, assure_envelope):
        outcome = assure_envelope([
            {"record_type": "claim", "claim_id": "X", "statement": "s",
             "depends_on": ["Y"]},
            {"record_type": "claim", "claim_id": "Y", "statement": "s",
             "depends_on": ["X"]}])
        rows = [r.to_dict() for r in outcome.case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "criticality")
        assert row["status"] == "NOT_ASSESSED"
        assert "inactive" in row["note"]


# ── the methodology hook ─────────────────────────────────────────────────────

class TestCriticalClaimsIdentified:

    def test_absence_is_not_assessed(self, case_with):
        found = CriticalClaimsIdentified().evaluate(case_with(None))
        assert found.outcome is RequirementOutcome.NOT_ASSESSED

    def test_a_derivable_case_satisfies(self, case_with):
        found = CriticalClaimsIdentified().evaluate(
            case_with(analyse_criticality(chain(3))))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_undeterminable_criticality_is_unsatisfied(self, case_with):
        derived = analyse_criticality(graph(
            Claim(claim_id="X", statement="x", parents=("Y",)),
            Claim(claim_id="Y", statement="y", parents=("X",))))
        found = CriticalClaimsIdentified().evaluate(case_with(derived))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "nothing was checked" in found.detail

    def test_a_broken_chain_is_unsatisfied(self, case_with):
        derived = analyse_criticality(graph(
            Claim(claim_id="R", statement="r", is_root=True, parents=("GONE",))))
        found = CriticalClaimsIdentified().evaluate(case_with(derived))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "outside the case" in found.detail

    def test_a_declared_disagreement_is_unsatisfied_by_default(self, case_with):
        derived = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Z", statement="z", criticality="CRITICAL")))
        found = CriticalClaimsIdentified().evaluate(case_with(derived))
        assert found.outcome is RequirementOutcome.UNSATISFIED

    def test_disagreements_can_be_allowed(self, case_with):
        derived = analyse_criticality(graph(
            Claim(claim_id="A", statement="a", is_root=True),
            Claim(claim_id="Z", statement="z", criticality="CRITICAL")))
        found = CriticalClaimsIdentified(
            maximum_declared_disagreements=None).evaluate(case_with(derived))
        assert found.outcome is RequirementOutcome.SATISFIED

    def test_require_supported_refuses_an_unsupported_load_bearing_claim(
            self, case_with):
        found = CriticalClaimsIdentified(require_supported=True).evaluate(
            case_with(analyse_criticality(chain(2))))
        assert found.outcome is RequirementOutcome.UNSATISFIED
        assert "cite no supporting evidence" in found.detail

    def test_thin_support_is_reported_not_penalised(self, case_with):
        derived = analyse_criticality(
            graph(Claim(claim_id="A", statement="a", is_root=True,
                        supporting_evidence=("e1",))),
            evidence_producers={"e1": "solo"})
        found = CriticalClaimsIdentified().evaluate(case_with(derived))
        assert found.outcome is RequirementOutcome.SATISFIED
        assert "does not penalise" in found.detail

    def test_the_predicate_round_trips(self):
        predicate = CriticalClaimsIdentified(
            require_supported=True, forbid_broken_chains=False,
            maximum_declared_disagreements=3)
        assert predicate_from_dict(predicate.to_dict()) == predicate

    def test_describe_names_what_it_checks(self):
        assert "derivable" in CriticalClaimsIdentified().describe()


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def case_with():
    def build(derived):
        from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
        from release_gate.assurance.evidence import ContentReference, ReferenceKind
        from release_gate.assurance.subject import (
            AssuranceSubject, DigestMethod, DigestStatus, SubjectType)
        subject = AssuranceSubject(
            subject_type=SubjectType.RESEARCH_RESULT, requested_action="publish",
            content_reference=ContentReference(kind=ReferenceKind.INLINE, locator="x",
                                               detail={"inline": "x"}),
            digest="sha256:" + "a" * 64, digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED, digest_basis="test")
        builder = AssuranceCaseBuilder(
            case_type=CaseType.RESEARCH_RESULT, objective="o",
            requested_decision="d", subject=subject)
        builder.declare_present("evidence", "test")
        if derived is not None:
            builder.add("evidence", derived)
        return builder.build()
    return build


@pytest.fixture
def assure_envelope(tmp_path):
    def run(rows):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "envelope.json"
        path.write_text(json.dumps(rows))
        return assure(str(path))
    return run
