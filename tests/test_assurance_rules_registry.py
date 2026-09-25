"""Rule families, aliases, and the seven questions.

The point of this file is not that the registry has entries; it is that the
registry cannot quietly disagree with the engine. Three guards do that work:
every rule either demo fires must resolve to a family, every decision-procedure
constant in `zero_config` must be described, and every fired rule must answer
all seven questions or say which it cannot and why.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from release_gate.assurance import zero_config
from release_gate.assurance.methodologies import (
    RESEARCH_MATHEMATICS_V1, default_registry,
)
from release_gate.assurance.rules_registry import (
    ALIASES, FAMILIES, POLICY_RULES, QUESTIONS, RULES_SCHEMA_VERSION,
    Answer, Origin, PolicyRule, RuleAnswers, RuleFamily, RuleKind,
    RuleRegistryError, answers_for, family_of, resolve_family,
)
from release_gate.demos import frontier_research, single_agent


@pytest.fixture(scope="module")
def blocked():
    return frontier_research.run(
        scenario=frontier_research.ResearchScenario(workers=120)).outcome


@pytest.fixture(scope="module")
def promoted():
    return single_agent.run().outcome


def _methodology_for(outcome):
    if outcome.case.methodology is None:
        return None
    return default_registry().resolve(outcome.case.methodology)


def _fired_ids(outcome):
    """Every rule id this run named, from all three places one can appear."""
    got = list(outcome.case.verdict.fired_rules)
    got += [r.requirement_id for r in (outcome.assessment.results or ())]
    for item in outcome.attention.items:
        got += list(getattr(item, "rule_ids", ()) or ())
    return list(dict.fromkeys(got))


# ── the taxonomy ─────────────────────────────────────────────────────────────

class TestFamilies:

    def test_the_registry_cannot_disagree_with_itself(self):
        """Built from one list, so the keys are the prefixes by construction."""
        assert all(prefix == family.prefix for prefix, family in FAMILIES.items())

    def test_no_alias_shadows_a_family(self):
        """An alias that is also a family name would resolve two ways, and which
        one you got would depend on lookup order."""
        assert set(ALIASES) & set(FAMILIES) == set()

    def test_every_alias_points_at_a_registered_family(self):
        assert all(target in FAMILIES for target in ALIASES.values())

    def test_the_proposed_vocabulary_all_resolves(self):
        """The nine names PROMPT 65 proposed. Eight are existing concerns under
        another spelling; resolving them as aliases is what keeps one concern
        from acquiring two families and halving every grep."""
        proposed = ("RG-SWARM", "RG-CLAIM", "RG-EVIDENCE", "RG-VERIFY",
                    "RG-APPROVAL", "RG-LINEAGE", "RG-ARTIFACT", "RG-COVERAGE",
                    "RG-ATTEST")
        assert all(resolve_family(name) is not None for name in proposed)

    def test_the_nine_split_three_ways(self):
        """Measured, not asserted, because the split is the whole argument for
        aliasing: seven of the nine are existing concerns under a longer
        spelling, one already existed under exactly that name, and one is
        genuinely absent."""
        proposed = {"RG-SWARM", "RG-CLAIM", "RG-EVIDENCE", "RG-VERIFY",
                    "RG-APPROVAL", "RG-LINEAGE", "RG-ARTIFACT", "RG-COVERAGE",
                    "RG-ATTEST"}
        aliased = {n for n in proposed if n in ALIASES}
        families = {n for n in proposed if n in FAMILIES}
        assert aliased == {"RG-SWARM", "RG-EVIDENCE", "RG-VERIFY", "RG-LINEAGE",
                           "RG-ARTIFACT", "RG-COVERAGE", "RG-ATTEST"}
        assert families == {"RG-CLAIM", "RG-APPROVAL"}
        assert aliased | families == proposed

    def test_and_rg_claim_was_not_the_absent_one(self):
        """`RG-CLAIM` was proposed as new and is not: it is raised throughout
        the package already. Adding it a second time would have been the exact
        fork this registry exists to prevent."""
        package = pathlib.Path("release_gate")
        hits = [p for p in package.rglob("*.py")
                if "RG-CLAIM-" in p.read_text()]
        assert hits, "RG-CLAIM is raised nowhere; the premise here has changed"

    def test_whereas_rg_approval_is_raised_nowhere(self):
        """The one genuine gap, and it stays a gap: there is nothing to alias it
        to because the approval work produces records and refusals, not rules."""
        package = pathlib.Path("release_gate")
        hits = [p for p in package.rglob("*.py")
                if "RG-APPROVAL-" in p.read_text()]
        assert hits == []

    def test_rg_approval_is_a_namespace_with_nothing_in_it(self, blocked, promoted):
        """Deliberately empty. Inventing rules to populate a new family would be
        manufacturing findings, which is the opposite of what it is for."""
        fired = set(_fired_ids(blocked)) | set(_fired_ids(promoted))
        assert not [r for r in fired if r.startswith("RG-APPROVAL")]
        assert resolve_family("RG-APPROVAL").prefix == "RG-APPROVAL"

    def test_a_family_must_be_greppable(self):
        with pytest.raises(RuleRegistryError, match="prefixed RG-"):
            RuleFamily("VERIF", "not greppable")

    def test_a_dotted_family_is_a_root_not_a_whole_id(self):
        with pytest.raises(RuleRegistryError, match="the root"):
            RuleFamily("contradictions.resolved", "a whole id", dotted=True)

    def test_an_unknown_prefix_is_refused_by_name(self):
        """Named, so the message tells a reader what to register rather than
        that something went wrong."""
        with pytest.raises(RuleRegistryError, match="RG-NOPE"):
            resolve_family("RG-NOPE")

    def test_and_so_is_an_unknown_rule_id(self):
        with pytest.raises(RuleRegistryError, match="RG-NOPE-001"):
            family_of("RG-NOPE-001")

    def test_families_round_trip_as_records(self):
        for family in FAMILIES.values():
            assert json.loads(json.dumps(family.to_dict()))["prefix"] == family.prefix


class TestNotationsBothResolve:
    """Rule ids and methodology requirement ids are two notations, and a
    registry that knew only the first would refuse half of what fires."""

    def test_a_hyphenated_rule_id_resolves(self):
        assert family_of("RG-VERIF-001").prefix == "RG-VERIF"

    def test_a_dotted_requirement_id_resolves(self):
        assert family_of("contradictions.resolved").prefix == "contradictions"

    def test_a_dotted_id_with_a_space_in_it_still_resolves(self):
        """`coverage.lemma verification` is real — a methodology names its own
        requirements and is not obliged to like our identifiers."""
        assert family_of("coverage.lemma verification").prefix == "coverage"

    def test_a_dotted_family_does_not_own_its_bare_root(self):
        """`coverage` alone is the family, not a requirement in it."""
        assert not FAMILIES["coverage"].owns("coverage")

    def test_a_hyphenated_family_does_not_claim_a_dotted_id(self):
        assert not FAMILIES["RG-COV"].owns("coverage.overall")


# ── the guards that can actually fire ────────────────────────────────────────

class TestNoDrift:

    def test_every_rule_both_demos_fire_is_placed(self, blocked, promoted):
        """The guard that matters. A rule outside every family is one nobody can
        look up, and a reviewer who cannot place a rule cannot weigh it."""
        unplaced = []
        for outcome in (blocked, promoted):
            for rule_id in _fired_ids(outcome):
                try:
                    family_of(rule_id)
                except RuleRegistryError:
                    unplaced.append(rule_id)
        assert unplaced == []

    def test_every_decision_clause_in_the_engine_is_described(self):
        """`POLICY_RULES` is written out as literals so it *can* disagree with
        `zero_config`. This is the test that makes the literals worth their
        cost: add an RG-ZC-006 and it fails here rather than shipping a verdict
        clause the registry describes as unassessable."""
        declared = {v for k, v in vars(zero_config).items()
                    if k.startswith("RULE_") and isinstance(v, str)}
        assert declared, "the engine's rule constants moved; this guard is blind"
        assert declared == set(POLICY_RULES)

    def test_and_the_registry_is_not_reading_them_from_the_engine(self):
        """A table derived from the code could not disagree with it, which is
        another way of saying it could never catch a drift. Checked in the AST,
        because a comment saying so is not a guarantee (§10ae)."""
        source = pathlib.Path(
            "release_gate/assurance/rules_registry.py").read_text()
        imported = {n.module for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.ImportFrom) and n.module}
        imported |= {a.name for n in ast.walk(ast.parse(source))
                     if isinstance(n, ast.Import) for a in n.names}
        assert not any("zero_config" in m for m in imported)

    def test_the_policy_family_is_the_only_one(self):
        """Findings are the norm; decision clauses are the exception. If that
        stops being true the asymmetry in `RuleKind` needs revisiting."""
        policy = {f.prefix for f in FAMILIES.values()
                  if f.kind is RuleKind.POLICY}
        assert policy == {"RG-ZC"}


# ── the seven questions ──────────────────────────────────────────────────────

class TestSevenQuestions:

    def test_every_rule_both_demos_fire_answers_all_seven(self, blocked, promoted):
        """The prompt's actual requirement, measured against real runs rather
        than a fixture. Thirty rule ids across two decisions; a rule that cannot
        answer all seven is incompletely specified."""
        gaps = []
        for outcome, methodology in ((blocked, RESEARCH_MATHEMATICS_V1),
                                     (promoted, _methodology_for(promoted))):
            for rule_id in _fired_ids(outcome):
                answers = answers_for(rule_id, outcome, methodology=methodology)
                if answers.unanswered:
                    gaps.append((rule_id, answers.unanswered))
        assert gaps == []

    def test_and_there_are_enough_of_them_for_that_to_mean_something(
            self, blocked, promoted):
        """A guard on the guard: if the demos stopped firing rules the test
        above would pass by vacuity."""
        assert len(_fired_ids(blocked)) >= 15
        assert len(_fired_ids(promoted)) >= 8

    def test_the_seven_must_each_have_an_entry(self):
        with pytest.raises(RuleRegistryError, match="missing"):
            RuleAnswers(rule_id="RG-VERIF-001", family="RG-VERIF",
                        answers={"triggering_fact": "x"})

    def test_an_answer_is_about_the_instance_not_the_id(self, blocked, promoted):
        """Two runs, one rule id, different answers — which is why there is no
        per-id table: it would have to say something generic, and the thing a
        reviewer needs here is what *this* methodology said about it."""
        here = answers_for("RG-VERIF-001", blocked,
                           methodology=RESEARCH_MATHEMATICS_V1)
        there = answers_for("RG-VERIF-001", promoted,
                            methodology=_methodology_for(promoted))
        assert here.answers["methodology_dependent"]["accepted_by"] is None
        assert there.answers["methodology_dependent"]["accepted_by"] == \
            "general-autonomous-action@1.0.0"


class TestAbsenceFindings:
    """A finding about what is *missing* cites no record, because the record is
    what is missing. Reading that as "no evidence" turns a measurement of
    nothing into nothing measured."""

    def test_the_finding_carries_what_it_measured(self, promoted):
        verif = [f for f in promoted.analysis.findings
                 if f.rule_id == "RG-VERIF-001"]
        assert verif and verif[0].refs == ()
        assert verif[0].observed == {"verification_records": 0}

    def test_and_the_attention_item_no_longer_drops_it(self, promoted):
        item = next(i for i in promoted.attention.items
                    if "RG-VERIF-001" in i.rule_ids)
        assert item.supporting_evidence == ()
        assert item.observed["RG-VERIF-001"] == {"verification_records": 0}

    def test_so_the_reviewer_reads_a_measurement_not_a_blank(self, promoted):
        """What changed for a person: "(none recorded)" became a count."""
        item = next(i for i in promoted.attention.items
                    if "RG-VERIF-001" in i.rule_ids)
        rendered = item.render()
        assert "SUPPORTING EVIDENCE: RG-VERIF-001 measured verification_records=0" \
            in rendered

    def test_and_the_measurement_is_what_answers_question_two(self, promoted):
        answers = answers_for("RG-VERIF-001", promoted,
                              methodology=_methodology_for(promoted))
        proving = answers.answers["proving_evidence"]
        assert proving["observed_by_predicate"] == {"verification_records": 0}
        assert "proving_evidence" not in answers.unanswered

    def test_but_a_record_still_wins_where_one_exists(self, blocked):
        """The measurement is a fallback, not a replacement: counts appended to
        real evidence would be noise."""
        item = next(i for i in blocked.attention.items if i.supporting_evidence)
        assert "measured" not in item.render().split("CONTRADICTING")[0].split(
            "SUPPORTING EVIDENCE:")[1]

    def test_every_finding_in_both_demos_measured_something(self, blocked, promoted):
        """Which is why the fallback is worth having: there is no finding whose
        predicate recorded nothing at all."""
        for outcome in (blocked, promoted):
            assert all(f.observed for f in outcome.analysis.findings)


class TestDecisionClauses:
    """`RG-ZC-*` are clauses of the decision procedure, not findings. Asking a
    clause "what evidence proves it" the way one asks a finding got
    NOT_ASSESSED five times over, which reads as five holes in the assessment."""

    def test_they_are_named_on_the_verdict_and_nowhere_else(self, promoted):
        fired = set(promoted.case.verdict.fired_rules)
        assert {"RG-ZC-004", "RG-ZC-005"} <= fired
        assert not [r for r in (promoted.assessment.results or ())
                    if r.requirement_id.startswith("RG-ZC")]
        assert not [i for i in promoted.attention.items
                    if any(r.startswith("RG-ZC") for r in i.rule_ids)]

    def test_a_fired_clause_answers_the_first_five_from_the_verdict(self, promoted):
        answers = answers_for("RG-ZC-004", promoted,
                              methodology=_methodology_for(promoted))
        first_five = QUESTIONS[:5]
        assert not (set(answers.unanswered) & set(first_five))
        assert answers.answers["triggering_fact"]["decision"] == "PROMOTE"
        assert answers.answers["affects"]["effect"] == "THE_DECISION"

    def test_its_evidence_is_the_reasons_the_verdict_states(self, promoted):
        """Not a paraphrase of the decision — `digest_component` already treats
        the reasons as part of what was approved, so they are the decision."""
        answers = answers_for("RG-ZC-004", promoted,
                              methodology=_methodology_for(promoted))
        stated = answers.answers["proving_evidence"]["verdict_reasons"]
        assert stated == list(promoted.case.verdict.reasons)

    def test_a_clause_that_reports_a_state_has_nothing_to_resolve(self, promoted):
        """NOT_APPLICABLE, not NOT_ASSESSED. Reporting a satisfied clause as
        unassessable counts a met condition as a hole."""
        answers = answers_for("RG-ZC-004", promoted,
                              methodology=_methodology_for(promoted))
        assert answers.answers["resolution"]["state"] == Answer.NOT_APPLICABLE.value
        assert "resolution" not in answers.unanswered

    def test_but_a_clause_that_raises_one_names_the_remedy(self, promoted):
        """RG-ZC-001 is the honest opposite: no methodology was supplied, and
        supplying one is what resolves it."""
        answers = answers_for("RG-ZC-001", promoted, methodology=None)
        assert "supply a methodology" in answers.answers["resolution"]["remedy"]

    def test_a_clause_that_did_not_fire_says_so_rather_than_shrugging(self, promoted):
        """An absence, not a gap: RG-ZC-001 never fired on a run that promoted."""
        answers = answers_for("RG-ZC-001", promoted, methodology=None)
        assert "RG-ZC-001" not in promoted.case.verdict.fired_rules
        for question in ("triggering_fact", "proving_evidence",
                         "epistemic_status", "affects"):
            assert answers.answers[question]["state"] == Answer.NOT_APPLICABLE.value
            assert question not in answers.unanswered

    def test_a_clause_is_DERIVED_and_says_from_what(self, promoted):
        answers = answers_for("RG-ZC-005", promoted,
                              methodology=_methodology_for(promoted))
        status = answers.answers["epistemic_status"]
        assert status["status"] == "DERIVED"
        assert promoted.case.verdict.ruleset_version in status["basis"]


class TestQuestionsSixAndSeven:
    """Three states, because a methodology that was never asked has no position
    and recording one as a refusal credits it with an opinion it does not hold."""

    def test_no_methodology_means_not_assessed_not_no(self, promoted):
        answers = answers_for("RG-VERIF-001", promoted, methodology=None)
        assert set(answers.unanswered) == {"methodology_dependent", "overridable"}
        assert "was not asked" in answers.answers["overridable"]

    def test_a_methodology_that_defines_a_rule_says_so(self, blocked):
        answers = answers_for("contradictions.resolved", blocked,
                              methodology=RESEARCH_MATHEMATICS_V1)
        dependent = answers.answers["methodology_dependent"]
        assert dependent["recognised"] is True
        assert dependent["defined_by"] == RESEARCH_MATHEMATICS_V1.ref_string

    def test_a_structural_rule_is_not_methodology_dependent(self, blocked):
        answers = answers_for("RG-DRIFT-002", blocked,
                              methodology=RESEARCH_MATHEMATICS_V1)
        assert answers.answers["methodology_dependent"]["recognised"] is False
        assert answers.answers["methodology_dependent"]["defined_by"] is None

    def test_refused_and_never_heard_of_are_different_answers(self, blocked):
        """§10y, reused. Both say `permitted: False`; only one is a position."""
        unknown = answers_for("RG-DRIFT-002", blocked,
                              methodology=RESEARCH_MATHEMATICS_V1)
        known = answers_for("contradictions.resolved", blocked,
                            methodology=RESEARCH_MATHEMATICS_V1)
        assert unknown.answers["overridable"]["recognised"] is False
        assert known.answers["overridable"]["recognised"] is True

    def test_a_decision_clause_goes_through_the_same_path(self, promoted):
        """Deliberately: a methodology that does not define RG-ZC-004 genuinely
        has no position on it, and that is the honest answer rather than a
        bespoke one."""
        answers = answers_for("RG-ZC-004", promoted,
                              methodology=_methodology_for(promoted))
        assert answers.answers["overridable"]["recognised"] is False


class TestRendering:

    def test_answers_round_trip_as_a_record(self, promoted):
        answers = answers_for("RG-ZC-004", promoted,
                              methodology=_methodology_for(promoted))
        data = json.loads(json.dumps(answers.to_dict()))
        assert data["rule_id"] == "RG-ZC-004"
        assert data["family"] == "RG-ZC"
        assert sorted(data["answers"]) == sorted(QUESTIONS)

    def test_the_render_marks_what_was_not_assessed(self, promoted):
        rendered = answers_for("RG-VERIF-001", promoted,
                               methodology=None).render()
        assert rendered.count("[NOT ASSESSED]") == 2
        assert "RG-VERIF-001  (RG-VERIF)" in rendered

    def test_complete_is_ordinary_not_a_pass_mark(self, promoted):
        """`complete` says every question was answerable, never that the case is
        in good shape: this rule answers all seven and the answer to two of them
        is that nothing was verified."""
        answers = answers_for("RG-VERIF-001", promoted,
                              methodology=_methodology_for(promoted))
        assert answers.complete is True
        assert answers.answers["proving_evidence"][
            "observed_by_predicate"] == {"verification_records": 0}


class TestAnAcceptanceIsAPosition:
    """`recognises` excludes accepted findings on purpose: an acceptance does
    not make a structural finding one of the methodology's requirements, and
    `extend` refuses a waiver naming one. That is right — and it left this
    report saying "the methodology has no position on it" about a rule the same
    methodology had accepted by name on the same verdict."""

    def test_the_verdict_says_the_methodology_accepted_it(self, promoted):
        assert "RG-ZC-005" in promoted.case.verdict.fired_rules
        assert any("RG-VERIF-001: accepted by" in reason
                   for reason in promoted.case.verdict.reasons)

    def test_and_recognises_still_says_no_which_is_correct(self, promoted):
        """The authority is not what changed. An acceptance is not a
        requirement, and `extend` depends on that staying true."""
        methodology = _methodology_for(promoted)
        assert methodology.recognises("RG-VERIF-001") is False

    def test_but_the_report_no_longer_claims_it_has_no_position(self, promoted):
        answers = answers_for("RG-VERIF-001", promoted,
                              methodology=_methodology_for(promoted))
        note = answers.answers["methodology_dependent"]["note"]
        assert "no position" not in note
        assert "accepts this finding" in note

    def test_it_names_the_methodology_and_quotes_its_reason(self, promoted):
        """Unspliced. A rationale is an argument someone wrote, and paraphrasing
        it into a sentence of ours is how a stated reason quietly becomes our
        reading of it."""
        methodology = _methodology_for(promoted)
        answers = answers_for("RG-VERIF-001", promoted, methodology=methodology)
        dependent = answers.answers["methodology_dependent"]
        assert dependent["accepted_by"] == methodology.ref_string
        stated = {d.dimension.value: d.value for d in promoted.consequence.known}
        accepted = methodology.acceptance_for("RG-VERIF-001", stated)
        assert dependent["accepted_because"] == accepted.rationale

    def test_an_acceptance_is_not_a_waiver_and_question_seven_says_so(
            self, promoted):
        """An acceptance is decided in advance and applies to everyone; an
        override is one person deciding to proceed anyway. Only the second needs
        an approver, and a reader must not mistake this promote for one."""
        answers = answers_for("RG-VERIF-001", promoted,
                              methodology=_methodology_for(promoted))
        overridable = answers.answers["overridable"]
        assert overridable["permitted"] is False
        assert overridable["accepted_not_waived"] is True

    def test_an_unaccepted_rule_carries_neither_key(self, blocked):
        answers = answers_for("RG-DRIFT-002", blocked,
                              methodology=RESEARCH_MATHEMATICS_V1)
        assert answers.answers["methodology_dependent"]["accepted_by"] is None
        assert answers.answers["methodology_dependent"]["accepted_because"] == ""
        assert "accepted_not_waived" not in answers.answers["overridable"]

    def test_the_ceiling_is_consulted_not_assumed(self, promoted):
        """An acceptance whose consequence ceiling does not hold is not in
        force, so the report must ask with the case's stated consequence rather
        than just by rule id."""
        methodology = _methodology_for(promoted)
        beyond = {d.value: "CATASTROPHIC"
                  for d in type(next(iter(promoted.consequence.known)).dimension)}
        assert methodology.acceptance_for("RG-VERIF-001", beyond) is None
        assert methodology.acceptance_for(
            "RG-VERIF-001",
            {d.dimension.value: d.value
             for d in promoted.consequence.known}) is not None
