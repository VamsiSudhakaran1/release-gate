"""How long a finalization took, and everything that number is not allowed to be.

The load-bearing test in this file is the dull-looking one: measuring a
finalization and not measuring it produce the same verdict and the same
`case_digest`. A clock inside a digest already broke this engine once — identical
input assured a second apart produced two different case digests — so an
instrument that reads a clock has to be provably outside the identity an approval
binds to, not merely intended to be.

The rest guards the reading. Latency is the one assurance number with an obvious
way to improve it: assess less. So the refusals are unconditional and the coverage
gaps are rendered next to the milliseconds, every time.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.corpus import _clean_release
from release_gate.assurance.incremental import SPECS, ReuseDecision, Stability
from release_gate.assurance.latency import (
    DecisionLatency, LatencyBudget, LatencyError, LatencyRecorder, Stage,
    StageTiming, coverage_gaps, measure_finalization,
)
from release_gate.assurance.session import AssuranceSession


class FakeClock:
    """A clock that only moves when told, so a timing assertion can be exact."""

    def __init__(self, step: float = 0.001) -> None:
        self.now = 1000.0
        self.step = step
        self.reads = 0

    def __call__(self) -> float:
        self.reads += 1
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def session(records=None) -> AssuranceSession:
    open_session = AssuranceSession.open(source_name="s.jsonl")
    open_session.extend([dict(r) for r in (records or _clean_release())])
    return open_session


# ── the vocabulary ───────────────────────────────────────────────────────────

class TestStages:

    def test_every_timed_stage_has_a_reuse_classification(self):
        """One vocabulary for both modules, so neither can grow a stage alone."""
        assert {s.value for s in Stage} <= set(SPECS)

    def test_every_classified_stage_can_be_timed(self):
        assert set(SPECS) <= {s.value for s in Stage}

    def test_each_stage_describes_itself(self):
        for stage in Stage:
            assert len(stage.describe()) > 15

    def test_a_timing_reports_the_stability_of_what_it_timed(self):
        timing = StageTiming(stage=Stage.ASSESS, elapsed_ms=1.0)
        assert timing.stability == Stability.RETRACTABLE.value


class TestStageTiming:

    def test_a_negative_duration_is_refused(self):
        """A measurement that can run backwards is not a measurement."""
        with pytest.raises(LatencyError, match="clock went backwards"):
            StageTiming(stage=Stage.FOLD, elapsed_ms=-0.1)

    def test_negative_records_are_refused(self):
        with pytest.raises(LatencyError, match="records cannot be negative"):
            StageTiming(stage=Stage.FOLD, elapsed_ms=1.0, records=-1)

    def test_a_share_needs_a_total(self):
        timing = StageTiming(stage=Stage.FOLD, elapsed_ms=1.0)
        assert timing.share_of(0) is None
        assert timing.share_of(4.0) == 0.25

    def test_per_record_cost_needs_a_record_count(self):
        assert StageTiming(stage=Stage.FOLD, elapsed_ms=1.0).per_record_us() is None
        assert StageTiming(stage=Stage.FOLD, elapsed_ms=1.0,
                           records=1000).per_record_us() == 1.0

    def test_a_reused_stage_says_so(self):
        timing = StageTiming(stage=Stage.FINALIZATION, elapsed_ms=0.0,
                             decision=ReuseDecision.REUSED)
        assert timing.reused
        assert timing.to_dict()["reused"] is True

    def test_zero_is_a_legitimate_duration(self):
        assert StageTiming(stage=Stage.DECIDE, elapsed_ms=0.0).elapsed_ms == 0.0


# ── the report ───────────────────────────────────────────────────────────────

class TestDecisionLatency:

    def _latency(self, **kwargs) -> DecisionLatency:
        base = dict(
            span_ms=100.0,
            stages=(StageTiming(stage=Stage.NORMALISE, elapsed_ms=20.0, records=500),
                    StageTiming(stage=Stage.ASSESS, elapsed_ms=60.0, records=500)),
            records=500)
        base.update(kwargs)
        return DecisionLatency(**base)

    def test_a_negative_span_is_refused(self):
        with pytest.raises(LatencyError, match="cannot be negative"):
            DecisionLatency(span_ms=-1.0)

    def test_stages_may_not_exceed_the_span_they_sit_inside(self):
        """Attribution that overflows its own measurement is not describing this run."""
        with pytest.raises(LatencyError, match="the stages account for"):
            DecisionLatency(span_ms=10.0, stages=(
                StageTiming(stage=Stage.ASSESS, elapsed_ms=50.0),))

    def test_unmeasured_time_is_reported_not_distributed(self):
        latency = self._latency()
        assert latency.attributed_ms == 80.0
        assert latency.unattributed_ms == 20.0
        assert "unattributed" in latency.render()

    def test_the_dominant_stage_is_where_reuse_would_pay(self):
        assert self._latency().dominant.stage is Stage.ASSESS

    def test_there_is_no_dominant_stage_without_timings(self):
        assert DecisionLatency(span_ms=1.0).dominant is None

    def test_a_tie_is_broken_deterministically(self):
        latency = DecisionLatency(span_ms=10.0, stages=(
            StageTiming(stage=Stage.SEAL, elapsed_ms=1.0),
            StageTiming(stage=Stage.DECIDE, elapsed_ms=1.0)))
        assert latency.dominant.stage is Stage.SEAL
        assert latency.dominant.stage is DecisionLatency(span_ms=10.0, stages=(
            StageTiming(stage=Stage.DECIDE, elapsed_ms=1.0),
            StageTiming(stage=Stage.SEAL, elapsed_ms=1.0))).dominant.stage

    def test_reused_time_is_separated_from_computed_time(self):
        latency = DecisionLatency(span_ms=10.0, stages=(
            StageTiming(stage=Stage.FOLD, elapsed_ms=5.0),
            StageTiming(stage=Stage.FINALIZATION, elapsed_ms=0.0,
                        decision=ReuseDecision.REUSED)))
        assert latency.computed_ms == 5.0
        assert [s.stage for s in latency.reused_stages] == [Stage.FINALIZATION]

    def test_a_per_record_cost_needs_records(self):
        assert DecisionLatency(span_ms=10.0).per_record_us() is None
        assert self._latency().per_record_us() == 200.0


class TestWhatLatencyIsNot:
    """Five refusals, each unconditional. The clock measures the engine only."""

    CASES = (
        DecisionLatency(span_ms=0.0),
        DecisionLatency(span_ms=1.0, records=1),
        DecisionLatency(span_ms=10_000.0, records=10_000_000,
                        not_assessed=("independence",)),
        DecisionLatency(span_ms=5.0, stages=(
            StageTiming(stage=Stage.FINALIZATION, elapsed_ms=0.0,
                        decision=ReuseDecision.REUSED),)),
    )

    def test_it_is_never_a_safety_metric(self):
        assert all(c.is_a_safety_metric is False for c in self.CASES)

    def test_it_never_establishes_sufficiency(self):
        assert all(c.establishes_sufficiency is False for c in self.CASES)

    def test_faster_is_never_more_trustworthy(self):
        """The refusal that matters: the cheapest way to get faster is to assess less."""
        assert all(c.lower_is_more_trustworthy is False for c in self.CASES)

    def test_it_is_never_comparable_between_cases(self):
        assert all(c.is_comparable_across_cases is False for c in self.CASES)

    def test_it_never_authorises_assessing_less(self):
        assert all(c.authorises_reduced_assessment is False for c in self.CASES)

    def test_the_refusals_survive_serialisation(self):
        data = self.CASES[2].to_dict()
        assert data["is_a_safety_metric"] is False
        assert data["lower_is_more_trustworthy"] is False
        assert data["authorises_reduced_assessment"] is False


class TestRendering:

    def test_the_coverage_gaps_are_always_shown(self):
        """Invariant 9. A fast number may never be read on its own."""
        with_gaps = DecisionLatency(span_ms=1.0, not_assessed=("independence", "replication"))
        assert "not assessed: independence, replication" in with_gaps.render()

    def test_a_case_with_no_gaps_says_that_rather_than_going_quiet(self):
        text = DecisionLatency(span_ms=1.0).render()
        assert "nothing was left unassessed" in text

    def test_the_refusal_is_printed_next_to_the_number(self):
        text = DecisionLatency(span_ms=40.0, records=2_000_000).render()
        assert "A faster verdict is not a sounder one" in text
        assert "assessing less" in text

    def test_a_reused_stage_is_named_in_the_report(self):
        text = DecisionLatency(span_ms=1.0, stages=(
            StageTiming(stage=Stage.FINALIZATION, elapsed_ms=0.0,
                        decision=ReuseDecision.REUSED),)).render()
        assert "reused rather than recomputed: finalization" in text

    def test_the_boundary_is_named_as_the_finalization_request(self):
        assert "finalization request to verdict" in DecisionLatency(span_ms=1.0).render()


# ── the recorder ─────────────────────────────────────────────────────────────

class TestRecorder:

    def test_a_supplied_clock_gives_exact_numbers(self):
        clock = FakeClock()
        recorder = LatencyRecorder(clock=clock).begin()
        with recorder.stage(Stage.ASSESS):
            clock.advance(0.250)
        clock.advance(0.050)
        latency = recorder.finish(records=7)
        assert latency.stages[0].elapsed_ms == pytest.approx(250.0)
        assert latency.span_ms == pytest.approx(300.0)
        assert latency.records == 7

    def test_a_disabled_recorder_never_reads_the_clock(self):
        """Uninstrumented is free, which is what lets the pipeline always carry one."""
        clock = FakeClock()
        recorder = LatencyRecorder(clock=clock, enabled=False)
        with recorder.stage(Stage.ASSESS):
            pass
        recorder.record(Stage.FOLD, 5.0)
        latency = recorder.finish()
        assert latency.stages == ()
        assert clock.reads == 2, "only finish() may read a disabled recorder's clock"

    def test_begin_is_idempotent_so_the_first_call_is_the_boundary(self):
        clock = FakeClock()
        recorder = LatencyRecorder(clock=clock).begin()
        clock.advance(1.0)
        recorder.begin()
        assert recorder.finish().span_ms == pytest.approx(1000.0)

    def test_a_stage_is_timed_even_when_it_raises(self):
        clock = FakeClock()
        recorder = LatencyRecorder(clock=clock)
        with pytest.raises(ValueError):
            with recorder.stage(Stage.ANALYSE):
                clock.advance(0.100)
                raise ValueError("the analysers fell over")
        assert recorder.finish().stages[0].elapsed_ms == pytest.approx(100.0)

    def test_a_pre_measured_stage_can_be_handed_in(self):
        recorder = LatencyRecorder(clock=FakeClock()).begin()
        recorder.record(Stage.NORMALISE, 12.5, records=99)
        timing = recorder.finish().stages[0]
        assert timing.elapsed_ms == 12.5 and timing.records == 99

    def test_the_span_never_reads_as_less_than_its_stages(self):
        """A coarse clock must not make the report contradict itself."""
        clock = FakeClock()
        recorder = LatencyRecorder(clock=clock).begin()
        recorder.record(Stage.FOLD, 500.0)
        assert recorder.finish().span_ms >= 500.0

    def test_a_stage_recorded_twice_becomes_one_row_holding_the_total(self):
        """The pipeline folds at two points; two `fold` rows would read as two stages."""
        recorder = LatencyRecorder(clock=FakeClock()).begin()
        recorder.record(Stage.FOLD, 10.0, records=100)
        recorder.record(Stage.FOLD, 5.0, records=400)
        latency = recorder.finish()
        assert len(latency.stages) == 1
        assert latency.stages[0].elapsed_ms == 15.0
        assert latency.stages[0].records == 400

    def test_a_merged_row_is_reused_only_if_every_part_was(self):
        """Any recomputed part means the stage did work; claiming otherwise understates it."""
        recorder = LatencyRecorder(clock=FakeClock()).begin()
        recorder.record(Stage.FOLD, 1.0, decision=ReuseDecision.REUSED)
        recorder.record(Stage.FOLD, 1.0, decision=ReuseDecision.RECOMPUTED)
        assert not recorder.finish().stages[0].reused

        both = LatencyRecorder(clock=FakeClock()).begin()
        both.record(Stage.FOLD, 0.0, decision=ReuseDecision.REUSED)
        both.record(Stage.FOLD, 0.0, decision=ReuseDecision.REUSED)
        assert both.finish().stages[0].reused

    def test_merging_moves_no_time_between_stages(self):
        recorder = LatencyRecorder(clock=FakeClock()).begin()
        recorder.record(Stage.FOLD, 4.0)
        recorder.record(Stage.ANALYSE, 1.0)
        recorder.record(Stage.FOLD, 6.0)
        by_stage = {t.stage: t.elapsed_ms for t in recorder.finish().stages}
        assert by_stage == {Stage.FOLD: 10.0, Stage.ANALYSE: 1.0}

    def test_finish_on_an_untouched_recorder_is_safe(self):
        assert LatencyRecorder(clock=FakeClock()).finish().span_ms == 0.0

    def test_the_clock_it_used_is_named(self):
        assert LatencyRecorder().finish().clock == "monotonic"


# ── the property the whole module depends on ─────────────────────────────────

class TestMeasuringChangesNothing:

    def test_a_measured_finalization_decides_what_an_unmeasured_one_decides(self):
        plain = session().finalize()
        measured, latency = measure_finalization(session())
        assert measured.decision is plain.decision
        assert measured.case.case_digest == plain.case.case_digest
        assert latency.span_ms >= 0

    def test_the_duration_reaches_no_digest(self):
        """The `stamped_on_arrival` discipline, applied to a measurement."""
        outcome, _ = measure_finalization(session())
        state = repr(outcome.case.binding_state())
        for leak in ("span_ms", "elapsed_ms", "latency", "monotonic"):
            assert leak not in state

    def test_two_measured_runs_of_one_input_agree(self):
        first, _ = measure_finalization(session())
        second, _ = measure_finalization(session())
        assert first.case.case_digest == second.case.case_digest

    def test_a_slow_clock_does_not_change_the_verdict(self):
        clock = FakeClock()
        outcome, latency = measure_finalization(session(), clock=clock)
        assert outcome.case.case_digest == session().finalize().case.case_digest
        assert latency.span_ms == 0.0, "a frozen clock measures nothing and decides the same"


# ── the whole path, attributed ───────────────────────────────────────────────

class TestMeasuringAFinalization:

    def test_a_cold_finalization_is_attributed_to_its_stages(self):
        _, latency = measure_finalization(session())
        named = {t.stage for t in latency.stages}
        assert {Stage.DETECT, Stage.NORMALISE, Stage.FOLD, Stage.ANALYSE,
                Stage.ASSESS, Stage.DECIDE, Stage.SEAL} <= named
        assert latency.attributed_ms > 0

    def test_each_stage_appears_once(self):
        """Folding happens twice in the pipeline and must still read as one stage."""
        _, latency = measure_finalization(session())
        stages = [t.stage for t in latency.stages]
        assert len(stages) == len(set(stages))

    def test_a_finalization_after_a_provisional_read_reuses_it(self):
        """Where decision latency is actually won: the work was already done."""
        open_session = session()
        open_session.required_evidence()
        _, latency = measure_finalization(open_session)
        assert [t.stage for t in latency.reused_stages] == [Stage.FINALIZATION]
        assert Stage.ASSESS not in {t.stage for t in latency.stages}

    def test_the_reuse_is_the_same_verdict_a_cold_run_reaches(self):
        warm = session()
        warm.required_evidence()
        assert warm.finalize().case.case_digest == session().finalize().case.case_digest

    def test_a_record_arriving_after_a_read_forces_a_recompute(self):
        open_session = session()
        open_session.required_evidence()
        open_session.add({"record_type": "claim", "claim_id": "c-late",
                          "proposition": "one more thing"})
        _, latency = measure_finalization(open_session)
        assert latency.reused_stages == ()
        assert Stage.ASSESS in {t.stage for t in latency.stages}

    def test_a_reuse_hit_does_not_pay_for_the_detection_it_skips(self):
        """A reuse path that still does the work is not a reuse path."""
        open_session = session()
        open_session.required_evidence()
        _, latency = measure_finalization(open_session)
        detect = next(t for t in latency.stages if t.stage is Stage.DETECT)
        assert Stage.NORMALISE not in {t.stage for t in latency.stages}
        assert detect.elapsed_ms < latency.span_ms

    def test_the_session_reports_why_it_reused(self):
        open_session = session()
        open_session.required_evidence()
        open_session.finalize()
        report = open_session.reuse_report()
        assert [d.decision.value for d in report.decisions] == ["REUSED"]
        assert report.cache["hits"] == 1
        assert "unchanged" in report.render()

    def test_a_session_nothing_was_read_from_reports_no_reuse(self):
        fresh = session()
        assert fresh.reuse_report().decisions == ()
        assert "nothing was offered" in fresh.reuse_report().render()

    def test_records_are_counted_in_the_report(self):
        open_session = session()
        _, latency = measure_finalization(open_session)
        assert latency.records == len(open_session.records)

    def test_measuring_an_already_decided_case_reports_no_stages(self):
        """Honest rather than zero-filled: the decision existed before the request."""
        settled = session()
        settled.finalize()
        outcome, latency = measure_finalization(settled)
        assert latency.stages == ()
        assert outcome.decision is settled.outcome.decision

    def test_a_case_with_no_records_still_finalizes_and_is_attributed(self):
        outcome, latency = measure_finalization(AssuranceSession.open(source_name="e.jsonl"))
        assert outcome.decision is not None
        assert latency.records == 0
        assert latency.per_record_us() is None
        assert Stage.FOLD in {t.stage for t in latency.stages}

    def test_the_gaps_are_read_off_the_case_that_was_decided(self):
        outcome, latency = measure_finalization(session())
        assert latency.not_assessed == coverage_gaps(outcome)


class TestCoverageGaps:

    def test_an_object_with_no_analysis_has_no_gaps(self):
        assert coverage_gaps(object()) == ()

    def test_a_ledger_that_cannot_be_asked_yields_nothing(self):
        class NoLedger:
            class analysis:
                coverage_ledger = object()

        assert coverage_gaps(NoLedger()) == ()

    def test_the_gaps_come_back_sorted(self):
        outcome, _ = measure_finalization(session())
        assert list(coverage_gaps(outcome)) == sorted(coverage_gaps(outcome))


# ── budgets ──────────────────────────────────────────────────────────────────

class TestLatencyBudget:

    def test_a_budget_must_be_a_positive_duration(self):
        with pytest.raises(LatencyError, match="positive number of milliseconds"):
            LatencyBudget(ms=0)

    def test_a_budget_is_met_or_it_is_not(self):
        budget = LatencyBudget(ms=100.0)
        assert budget.met_by(DecisionLatency(span_ms=50.0))
        assert not budget.met_by(DecisionLatency(span_ms=150.0))

    def test_a_met_budget_produces_no_finding(self):
        assert LatencyBudget(ms=100.0).finding(DecisionLatency(span_ms=10.0)) == ""

    def test_a_missed_budget_names_the_stage_and_refuses_to_buy_anything(self):
        latency = DecisionLatency(span_ms=200.0, stages=(
            StageTiming(stage=Stage.ASSESS, elapsed_ms=180.0),))
        finding = LatencyBudget(ms=100.0, declared_by="platform-eng").finding(latency)
        assert "assess" in finding and "platform-eng" in finding
        assert "does not authorise deciding on less evidence" in finding

    def test_a_budget_never_authorises_assessing_less(self):
        assert LatencyBudget(ms=1.0).authorises_reduced_assessment is False
        assert LatencyBudget(ms=1e9).authorises_reduced_assessment is False

    def test_a_finding_over_an_unattributed_span_still_reads(self):
        finding = LatencyBudget(ms=1.0).finding(DecisionLatency(span_ms=2.0))
        assert "against a" in finding

    def test_a_budget_serialises_its_refusal(self):
        assert LatencyBudget(ms=5.0).to_dict()["authorises_reduced_assessment"] is False
