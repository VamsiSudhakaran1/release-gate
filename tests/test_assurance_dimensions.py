"""Eight dimensions, no total — and the old score preserved beside them.

The score's behaviour is pinned here as a regression guard, not to criticise it:
it does one job well and this file records what that job is and is not.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.dimensions import (
    DIMENSIONS, DIMENSIONS_SCHEMA_VERSION, Dimension, DimensionError,
    DimensionProfile, DimensionReading, Standing, profile_of,
)
from release_gate.demos import frontier_research, single_agent


@pytest.fixture(scope="module")
def blocked():
    return frontier_research.run(
        scenario=frontier_research.ResearchScenario(workers=120)).outcome


@pytest.fixture(scope="module")
def promoted():
    return single_agent.run().outcome


# ── the existing score is preserved, and scoped ──────────────────────────────

class TestExistingScore:
    """Kept, unchanged, and useful for exactly one job: ranking safeguard
    checklist completeness. These pin what it does."""

    def test_it_still_computes(self):
        from release_gate.audit import compute_score, SAFEGUARDS
        present = {s["id"]: True for s in SAFEGUARDS}
        assert compute_score(present, None) == (100, "PROMOTE")

    def test_the_weights_are_unchanged(self):
        from release_gate.audit import SAFEGUARDS
        assert sum(s["weight"] for s in SAFEGUARDS) == 100

    def test_the_thresholds_are_unchanged(self):
        from release_gate.audit import PROMOTE_THRESHOLD, HOLD_THRESHOLD
        assert (PROMOTE_THRESHOLD, HOLD_THRESHOLD) == (90, 50)

    def test_findings_already_hard_gate_the_decision(self):
        """The decision is non-compensatory. This is what works today."""
        from release_gate.audit import compute_score, SAFEGUARDS
        present = {s["id"]: True for s in SAFEGUARDS}
        high = [{"severity": "high"}]
        assert compute_score(present, high)[1] == "HOLD"
        assert compute_score(present, high * 3)[1] == "BLOCK"

    def test_but_the_score_itself_is_not(self):
        """Measured, and the reason it is not an assurance signal: 100 out of
        100 while the decision is BLOCK."""
        from release_gate.audit import compute_score, SAFEGUARDS
        present = {s["id"]: True for s in SAFEGUARDS}
        score, decision = compute_score(present, [{"severity": "high"}] * 3)
        assert (score, decision) == (100, "BLOCK")

    def test_one_safeguard_cannot_affect_it_at_all(self):
        """`loop_boundary` carries weight 0, so the score cannot express it."""
        from release_gate.audit import compute_score, SAFEGUARDS
        zero = [s["id"] for s in SAFEGUARDS if s["weight"] == 0]
        assert zero == ["loop_boundary"]
        present = {s["id"]: True for s in SAFEGUARDS}
        present["loop_boundary"] = False
        assert compute_score(present, None)[0] == 100


# ── there is no total ────────────────────────────────────────────────────────

class TestNoTotal:

    def test_the_profile_refuses_to_combine(self, blocked):
        profile = profile_of(blocked)
        assert profile.combines_into_a_score is False
        assert profile.is_compensatory is False

    def test_the_payload_says_so(self, blocked):
        payload = profile_of(blocked).to_dict()
        assert payload["combines_into_a_score"] is False
        assert payload["is_compensatory"] is False

    def test_no_reading_carries_a_value(self, blocked):
        for reading in profile_of(blocked).readings:
            assert reading.scores is False

    def test_the_payload_contains_no_total_key(self, blocked):
        payload = json.dumps(profile_of(blocked).to_dict()).lower()
        for word in ('"score"', '"total"', '"overall"', '"grade"', '"rating"',
                     '"average"', '"weighted"', '"percentage"'):
            assert word not in payload, word

    def test_a_standing_is_not_a_number(self):
        for standing in Standing:
            assert not standing.value.isdigit()

    def test_the_render_says_there_is_no_total(self, blocked):
        assert "There is no total" in profile_of(blocked).render()


# ── a fatal dimension is not offset ──────────────────────────────────────────

class TestNonCompensatory:

    def test_the_frontier_case_is_defeated(self, blocked):
        profile = profile_of(blocked)
        assert profile.defeated
        assert Dimension.CRITICAL_CLAIM_COVERAGE in {
            r.dimension for r in profile.fatal}

    def test_seven_sound_dimensions_do_not_offset_one_fatal(self):
        readings = []
        for dimension in DIMENSIONS:
            if dimension is Dimension.INDEPENDENCE:
                readings.append(DimensionReading(
                    dimension, Standing.FATAL, "a cycle in the ancestry graph",
                    because=("evidence that supports itself corroborates nothing",)))
            else:
                readings.append(DimensionReading(dimension, Standing.SOUND,
                                                 "nothing against the case"))
        profile = DimensionProfile(case_id="c", readings=tuple(readings))
        assert profile.defeated
        assert len(profile.fatal) == 1
        assert "No standing on any other dimension offsets that" in profile.render()

    def test_a_fatal_reading_must_say_why(self):
        """A dimension that ends a case has to name what ended it."""
        with pytest.raises(DimensionError) as exc:
            DimensionReading(Dimension.INDEPENDENCE, Standing.FATAL, "bad")
        assert "told the answer and not the reason" in str(exc.value)

    def test_every_fatal_reading_in_a_real_case_says_why(self, blocked):
        for reading in profile_of(blocked).fatal:
            assert reading.because

    def test_defeated_is_not_a_threshold(self):
        """One is enough, and eight would be no more so."""
        readings = [DimensionReading(d, Standing.SOUND, "ok") for d in DIMENSIONS]
        readings[0] = DimensionReading(readings[0].dimension, Standing.FATAL,
                                       "x", because=("y",))
        assert DimensionProfile(case_id="c", readings=tuple(readings)).defeated


# ── unassessed is not zero ───────────────────────────────────────────────────

class TestNotAssessed:

    def test_a_promoted_case_can_have_unassessed_dimensions(self, promoted):
        """A blended score would have averaged these away or scored them zero."""
        profile = profile_of(promoted)
        assert promoted.case.verdict.decision.value == "PROMOTE"
        assert len(profile.not_assessed) >= 3

    def test_unassessed_is_neither_sound_nor_fatal(self, promoted):
        for reading in profile_of(promoted).not_assessed:
            assert reading.standing is Standing.NOT_ASSESSED
            assert not reading.is_fatal
            assert not reading.assessed

    def test_it_does_not_defeat_the_case(self, promoted):
        """Ignorance is not failure, any more than it is success."""
        assert not profile_of(promoted).defeated

    def test_the_render_names_them(self, promoted):
        rendered = profile_of(promoted).render()
        assert "neither a pass nor a zero" in rendered

    def test_no_verification_reads_as_unassessed_not_as_failure(self, promoted):
        reading = profile_of(promoted).reading(Dimension.VERIFICATION_COVERAGE)
        assert reading.standing is Standing.NOT_ASSESSED
        assert "nothing in this case was verified" in reading.headline


# ── all eight, always ────────────────────────────────────────────────────────

class TestCompleteness:

    def test_there_are_eight(self):
        assert len(DIMENSIONS) == len(Dimension) == 8

    @pytest.mark.parametrize("dimension", list(Dimension))
    def test_each_is_reported(self, dimension, blocked):
        assert profile_of(blocked).reading(dimension) is not None

    def test_one_left_out_is_refused(self, blocked):
        """A dimension left out reads as one with nothing against it, which is
        exactly the compensation this prevents."""
        full = profile_of(blocked)
        with pytest.raises(DimensionError) as exc:
            DimensionProfile(case_id="c", readings=tuple(
                r for r in full.readings
                if r.dimension is not Dimension.INDEPENDENCE))
        assert "compensation this exists to prevent" in str(exc.value)

    def test_a_duplicate_is_refused(self, blocked):
        full = profile_of(blocked)
        with pytest.raises(DimensionError):
            DimensionProfile(case_id="c",
                             readings=full.readings + (full.readings[0],))

    def test_a_reading_must_say_what_it_found(self):
        with pytest.raises(DimensionError) as exc:
            DimensionReading(Dimension.LINEAGE_COVERAGE, Standing.SOUND, "  ")
        assert "must say what it found" in str(exc.value)

    def test_an_undecided_case_has_no_profile(self):
        class Bare:
            case = None
        with pytest.raises(DimensionError) as exc:
            profile_of(Bare())
        assert "standings nobody reached" in str(exc.value)


# ── the readings are read, not computed ──────────────────────────────────────

class TestReadsExistingObjects:

    def test_methodology_satisfaction_cites_the_methodology(self, blocked):
        reading = profile_of(blocked).reading(Dimension.METHODOLOGY_SATISFACTION)
        assert reading.detail["methodology"] == \
            blocked.assessment.methodology_ref

    def test_independence_reports_the_real_contributor_count(self, blocked):
        reading = profile_of(blocked).reading(Dimension.INDEPENDENCE)
        assert reading.detail["contributors"] == blocked.independence.contributors

    def test_contradiction_state_reads_the_ledger(self, blocked):
        reading = profile_of(blocked).reading(Dimension.CONTRADICTION_STATE)
        assert reading.detail["open"] == len(blocked.contradictions.open())

    def test_verification_reads_the_graph(self, blocked):
        reading = profile_of(blocked).reading(Dimension.VERIFICATION_COVERAGE)
        assert reading.detail["attempts"] == len(blocked.verification.attempts)

    def test_completeness_takes_a_ledger_or_says_it_was_not_asked(self, promoted):
        from release_gate.assurance.completeness import StreamLedger
        without = profile_of(promoted).reading(Dimension.EVIDENCE_COMPLETENESS)
        assert without.standing is Standing.NOT_ASSESSED
        with_ledger = profile_of(
            promoted, completeness=StreamLedger()).reading(
            Dimension.EVIDENCE_COMPLETENESS)
        assert with_ledger.standing is not Standing.NOT_ASSESSED

    def test_a_method_accessor_is_not_read_as_a_collection(self, blocked):
        """`invalidated`, `not_run`, `open`, `critical` and `broken_chains` are
        methods; `attempts` is a property. Reading one as the other raised
        'method object is not iterable' — the loud failure. The quiet one would
        be a caller that swallowed it and reported an empty collection, turning
        'I read this wrong' into 'there were none'."""
        reading = profile_of(blocked).reading(Dimension.CRITICAL_CLAIM_COVERAGE)
        assert reading.detail.get("broken_chains", 0) == \
            len(blocked.criticality.broken_chains())
