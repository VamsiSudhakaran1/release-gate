"""The assurance benchmark corpus, and the guards that keep it honest.

Three things are under test here, and only the third is the engine:

1. The corpus is complete and well-formed — sixteen kinds, every expected rule
   id registered, every behaviour check named.
2. **The scorer can fail.** A benchmark that cannot come out wrong measures
   nothing, so this file breaks each expectation deliberately and checks the
   score moves.
3. The engine passes it.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_gate.assurance.corpus import (
    BEHAVIOURS, CORPUS_SCHEMA_VERSION, GENERATORS, KINDS, BenchmarkScope,
    CaseClass, CorpusCase, CorpusError, build_corpus, run_case, score,
)
from release_gate.assurance.rules_registry import family_of


@pytest.fixture(scope="module")
def corpus():
    return build_corpus()


@pytest.fixture(scope="module")
def result():
    return score()


# ── the corpus is complete and well-formed ───────────────────────────────────

class TestCorpus:

    def test_every_named_kind_has_a_case(self, corpus):
        assert {c.kind for c in corpus} == set(KINDS)

    def test_case_ids_are_unique(self, corpus):
        ids = [c.case_id for c in corpus]
        assert len(ids) == len(set(ids))

    def test_every_expected_rule_id_is_registered(self, corpus):
        """Reuses §10aj's family registry. An expectation naming a rule that
        cannot exist scores a permanent miss and reads as an engine failure."""
        for case in corpus:
            for rule_id in case.expect_rules:
                assert family_of(rule_id) is not None

    def test_every_case_states_what_it_builds_in(self, corpus):
        """Including the quiet ones. A quiet case with no stated construction is
        indistinguishable from a case nobody thought about."""
        assert all(len(c.defect.strip()) > 20 for c in corpus)

    def test_a_detection_case_must_name_rules(self):
        with pytest.raises(CorpusError, match="scored against nothing"):
            CorpusCase(case_id="x", kind="invalid_release",
                       case_class=CaseClass.DETECTION,
                       defect="a defect long enough to be a sentence",
                       document=({"record_type": "evidence"},))

    def test_a_quiet_case_may_not_name_rules(self):
        """Naming an expected rule on a clean case would score a false positive
        as a hit."""
        with pytest.raises(CorpusError, match="no defect to detect"):
            CorpusCase(case_id="x", kind="valid_release", case_class=CaseClass.QUIET,
                       defect="a defect long enough to be a sentence",
                       document=({"record_type": "evidence"},),
                       expect_rules=("RG-VERIF-001",))

    def test_a_behaviour_case_must_name_checks(self):
        with pytest.raises(CorpusError, match="scored by nothing"):
            CorpusCase(case_id="x", kind="unknown_completeness",
                       case_class=CaseClass.BEHAVIOUR,
                       defect="a defect long enough to be a sentence",
                       document=({"record_type": "evidence"},))

    def test_an_unknown_kind_is_refused(self):
        with pytest.raises(CorpusError, match="sixteen named kinds"):
            CorpusCase(case_id="x", kind="vibes", case_class=CaseClass.QUIET,
                       defect="a defect long enough to be a sentence",
                       document=({"record_type": "evidence"},))

    def test_an_unknown_behaviour_check_is_refused(self):
        with pytest.raises(CorpusError, match="unknown behaviour check"):
            CorpusCase(case_id="x", kind="valid_release", case_class=CaseClass.QUIET,
                       defect="a defect long enough to be a sentence",
                       document=({"record_type": "evidence"},),
                       behaviours=("vibes_were_good",))

    def test_the_generators_are_the_shipped_demos(self):
        """Not a second implementation: a corpus that built its own
        ten-thousand-agent workflow would score a generator, not the product."""
        assert set(GENERATORS) == {"frontier_research", "single_agent"}

    def test_cases_round_trip_as_records(self, corpus):
        for case in corpus:
            assert json.loads(json.dumps(case.to_dict()))["kind"] == case.kind


# ── every case runs through the shipping path ────────────────────────────────

class TestItExercisesWhatShips:

    def test_documents_go_through_ingest_not_a_shortcut(self, corpus):
        """A corpus that built an AssuranceCase directly would score an engine
        the product does not ship, and every boundary defect found in this
        architecture so far lived in exactly that gap."""
        import inspect
        from release_gate.assurance import corpus as module
        source = inspect.getsource(module._assure)
        assert "normalise" in source and "assure_normalisation" in source

    def test_the_approval_goes_through_the_real_two_step(self):
        stale = next(c for c in build_corpus() if c.case_id == "stale-approval")
        run = run_case(stale)
        assert run.approval is not None
        assert run.standing is not None

    def test_the_mutation_is_derived_not_declared(self):
        """A mutation the corpus asserted would test the assertion, not the
        engine. These events are computed by comparing the two cases."""
        case = next(c for c in build_corpus() if c.case_id == "artifact-mutation")
        run = run_case(case)
        assert run.invalidation is not None
        assert run.invalidation.events
        assert all(e.describes_a_change for e in run.invalidation.events)


# ── the scorer can fail ──────────────────────────────────────────────────────

class TestTheScorerCanFail:
    """The guard that makes every number above mean something. A benchmark that
    cannot come out wrong measures nothing."""

    def _swap(self, case_id, **changes):
        return tuple(dataclasses.replace(c, **changes) if c.case_id == case_id else c
                     for c in build_corpus())

    def test_a_wrong_expected_rule_is_scored_a_miss(self):
        broken = self._swap("invalid-release", expect_rules=("RG-CEX-003",))
        result = score(broken)
        assert [f.case_id for f in result.failures] == ["invalid-release"]
        assert result.by_class["DETECTION"].fn == 1
        assert result.by_class["DETECTION"].recall < 1.0

    def test_an_unregistered_rule_id_is_refused_rather_than_scored(self):
        broken = self._swap("invalid-release", expect_rules=("RG-NOPE-001",))
        with pytest.raises(CorpusError, match="no rule family owns"):
            score(broken)

    def test_a_wrong_expected_decision_fails(self):
        broken = self._swap("invalid-release", expect_decision="PROMOTE")
        assert [f.case_id for f in score(broken).failures] == ["invalid-release"]

    def test_a_quiet_case_with_a_real_defect_shows_a_false_positive(self):
        """Reclassifying a genuinely broken case as clean must be caught, or
        the clean cases prove nothing."""
        broken = self._swap("open-contradiction", case_class=CaseClass.QUIET,
                            expect_rules=(), behaviours=("coverage_reported",))
        result = score(broken)
        failure = next(f for f in result.failures if f.case_id == "open-contradiction")
        assert failure.false_positives
        assert result.flagged_without_defect == 1
        assert result.precision < 1.0

    def test_a_failing_behaviour_check_fails_the_case(self):
        broken = self._swap("valid-release",
                            behaviours=("did_not_promote",))  # it does promote
        failure = next(f for f in score(broken).failures
                       if f.case_id == "valid-release")
        assert failure.behaviours["did_not_promote"][0] is False

    def test_a_behaviour_check_that_raises_fails_rather_than_passes(self):
        from release_gate.assurance.corpus import BehaviourCheck, CaseRun
        def explode(run):
            raise RuntimeError("boom")
        ok, detail = BehaviourCheck("x", "?", explode).run(
            CaseRun(case=build_corpus()[0], outcome=None))
        assert ok is False and "boom" in detail


# ── what may be claimed ──────────────────────────────────────────────────────

class TestScope:
    """"Do not publish broader claims than benchmark scope supports" is the
    brief's own last line. Prose does not enforce anything, so the refusals are
    unconditional properties."""

    @pytest.mark.parametrize("claim", [
        "measures_release_safety", "measures_the_scanner",
        "generalises_to_unseen_shapes", "is_a_third_party_audit",
        "establishes_that_a_promote_was_correct"])
    def test_the_refusals_are_unconditional(self, claim):
        assert getattr(BenchmarkScope(), claim) is False
        assert getattr(BenchmarkScope(cases=10_000, kinds=99), claim) is False

    def test_there_is_no_per_class_precision(self, result):
        """It would be 1.0 by construction — a number that can only come out
        perfect, which is worse than no number."""
        assert all(s.precision is None for s in result.by_class.values())

    def test_precision_lives_where_the_clean_cases_can_break_it(self, result):
        assert result.precision is not None
        assert (result.flagged_with_defect + result.flagged_without_defect) > 0

    def test_recall_is_none_where_there_is_nothing_to_recall(self, result):
        assert result.by_class["QUIET"].recall is None
        assert result.by_class["BEHAVIOUR"].recall is None

    def test_the_scope_travels_with_the_result(self, result):
        data = json.loads(json.dumps(result.to_dict()))
        assert data["scope"]["measures_release_safety"] is False
        assert data["scope"]["cases"] == len(result.results)


# ── the engine passes it ─────────────────────────────────────────────────────

class TestTheEnginePassesIt:

    def test_every_case_passes(self, result):
        assert [f.case_id for f in result.failures] == []

    def test_nothing_clean_was_stopped(self, result):
        assert result.flagged_without_defect == 0

    def test_every_constructed_defect_was_found(self, result):
        assert result.by_class["DETECTION"].fn == 0

    def test_and_detection_is_reported_apart_from_gating(self, result):
        """Three defects are found and promoted anyway. Reported, not folded
        away: a table showing detection alone would let a rule that fires read
        as a rule that stopped something."""
        assert set(result.detected_but_not_gated) == {
            "false-independence", "fake-verifier", "missing-provenance"}

    def test_total_omission_holds_the_case(self):
        """The defect this corpus found. Four of five arriving held the case;
        none of five arriving promoted it, because the ledger routed total
        absence to a state no rule read (Invariant 13)."""
        partial = next(c for c in build_corpus() if c.case_id == "incomplete-evidence")
        total = next(c for c in build_corpus() if c.case_id == "evidence-omission")
        for case in (partial, total):
            outcome = run_case(case).outcome
            fired = {f.rule_id for f in outcome.analysis.findings}
            assert "RG-EXPECT-001" in fired, case.case_id
            assert outcome.case.verdict.decision.value == "HOLD", case.case_id

    def test_and_losing_more_evidence_never_improves_the_verdict(self):
        """The monotonicity the inversion broke. Measured across the range
        rather than at the two endpoints, so a fix that only patched the ends
        would not pass."""
        from release_gate.assurance.corpus import _clean_release
        seen = []
        for observed in (5, 4, 3, 2, 1, 0):
            case = CorpusCase(
                case_id="mono", kind="evidence_omission", case_class=CaseClass.QUIET,
                defect="a declared five-job matrix with a varying number arriving",
                document=[*_clean_release(),
                          {"record_type": "expectation", "dimension": "ci jobs",
                           "expected": 5, "observed": observed,
                           "source": {"kind": "CI_PLAN", "declared_by": "ci://github",
                                      "authenticated": True, "detail": "matrix"}}],
                methodology="general-autonomous-action")
            seen.append((observed, run_case(case).outcome.case.verdict.decision.value))
        assert seen[0] == (5, "PROMOTE")
        assert all(decision == "HOLD" for _n, decision in seen[1:]), seen


class TestSchema:

    def test_the_schema_version_is_registered(self):
        from release_gate.assurance.protocol import PROTOCOL
        assert any(s.constant == "CORPUS_SCHEMA_VERSION" for s in PROTOCOL.schemas)

    def test_the_result_round_trips(self, result):
        data = json.loads(json.dumps(result.to_dict()))
        assert data["schema_version"] == CORPUS_SCHEMA_VERSION
        assert len(data["results"]) == len(KINDS)

    def test_every_behaviour_check_is_used_by_some_case(self, corpus):
        """An unused check is one nothing proves works."""
        used = {name for case in corpus for name in case.behaviours}
        assert set(BEHAVIOURS) - used == set()


class TestThePublishedResults:
    """The document a reader sees must be the document a run produces."""

    def _runner(self):
        import importlib.util
        import pathlib
        path = (pathlib.Path(__file__).resolve().parent.parent
                / "benchmark" / "assurance.py")
        spec = importlib.util.spec_from_file_location("_assurance_bench", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_assurance_md_is_in_sync(self, result):
        import pathlib
        doc = (pathlib.Path(__file__).resolve().parent.parent
               / "benchmark" / "ASSURANCE.md")
        assert doc.read_text(encoding="utf-8").strip() == \
            self._runner().render_md(result).strip(), \
            "benchmark/ASSURANCE.md is stale — run: python benchmark/assurance.py --md"

    def test_it_publishes_the_refusals_rather_than_only_the_numbers(self):
        import pathlib
        text = (pathlib.Path(__file__).resolve().parent.parent
                / "benchmark" / "ASSURANCE.md").read_text(encoding="utf-8")
        assert "measures release safety | **False**" in text
        assert "measures the static scanner | **False**" in text

    def test_the_scanner_benchmark_says_what_it_does_not_cover(self):
        """A reader who finds 100% precision there and assumes it covers
        assurance has been over-claimed at."""
        import pathlib
        text = (pathlib.Path(__file__).resolve().parent.parent
                / "benchmark" / "RESULTS.md").read_text(encoding="utf-8")
        assert "ASSURANCE.md" in text
        assert "says nothing about the assurance layer" in text

    def test_the_runner_exits_nonzero_when_a_case_fails(self):
        """So CI can use it as a gate rather than a report nobody reads."""
        import inspect
        source = inspect.getsource(self._runner().main)
        assert "return 0 if not result.failures else 1" in source
