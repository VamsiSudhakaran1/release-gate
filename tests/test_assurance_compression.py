"""Human Attention Compression — and the three ways it could mislead.

The metric itself is arithmetic over numbers that already exist. What is under
test is the honesty around it: that a stage nobody counted yields no number, that
somebody else's count is labelled as theirs, that retained critical issues are
never compressed away, and that nothing here can be read as a safety claim.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.chaos import _assure, _base
from release_gate.assurance.compression import (
    COMPRESSION_SCHEMA_VERSION, Basis, CompressionError, FunnelStage,
    HumanAttentionCompression, measure_compression,
)


@pytest.fixture(scope="module")
def frontier():
    from release_gate.demos import frontier_research
    return measure_compression(frontier_research.run().outcome)


@pytest.fixture(scope="module")
def single_agent():
    from release_gate.demos import single_agent as demo
    return measure_compression(demo.run().outcome)


# ── it is not a safety metric, and cannot be read as one ─────────────────────

class TestTheRefusals:

    @pytest.mark.parametrize("claim", [
        "is_a_safety_metric", "establishes_sufficiency", "higher_is_better",
        "is_comparable_across_cases"])
    def test_they_are_unconditional(self, claim, frontier):
        assert getattr(frontier, claim) is False
        assert getattr(HumanAttentionCompression(), claim) is False

    def test_higher_is_better_is_the_one_that_would_do_damage(self, frontier):
        """A larger ratio can mean the argument narrowed cleanly or that
        detection got worse, and nothing in the number tells them apart.
        Optimising it is optimising for a shorter list, which is available by
        finding less (Invariant 6)."""
        assert frontier.higher_is_better is False
        assert "not a better case" in frontier.render()

    def test_the_rendered_funnel_says_what_it_is_not(self, frontier):
        text = frontier.render()
        assert "not a safety metric" in text
        assert "does not" in text and "sufficiency" in text

    def test_and_so_does_the_serialised_form(self, frontier):
        data = json.loads(json.dumps(frontier.to_dict()))
        assert data["is_a_safety_metric"] is False
        assert data["higher_is_better"] is False


# ── a stage nobody counted yields no number ──────────────────────────────────

class TestUnknownIsNotZero:

    def test_undeterminable_criticality_is_not_reported_as_zero(self, single_agent):
        """The single most damaging number this funnel could produce, because it
        is the stage a reader scans for reassurance."""
        stage = next(s for s in single_agent.stages if s.name == "critical_claims")
        assert stage.count is None
        assert stage.basis is Basis.NOT_ASSESSED
        assert "not zero" in stage.detail

    def test_it_renders_as_not_assessed_rather_than_a_figure(self, single_agent):
        assert "not assessed  critical claims" in single_agent.render()

    def test_a_stage_with_no_count_cannot_claim_a_basis(self):
        with pytest.raises(CompressionError, match="needs a count"):
            FunnelStage(name="events", count=None, basis=Basis.OBSERVED)

    def test_and_a_stage_nobody_assessed_cannot_carry_one(self):
        with pytest.raises(CompressionError, match="cannot also carry a count"):
            FunnelStage(name="events", count=5, basis=Basis.NOT_ASSESSED)

    def test_no_ratio_where_nothing_was_counted(self):
        empty = HumanAttentionCompression(
            stages=(FunnelStage(name="events", count=None,
                                basis=Basis.NOT_ASSESSED),), review_items=3)
        assert empty.ratio is None
        assert "no ratio" in empty.render()

    def test_no_ratio_where_there_is_nothing_to_divide_by(self):
        quiet = HumanAttentionCompression(
            stages=(FunnelStage(name="claims", count=900, basis=Basis.OBSERVED,
                                of="claims"),), review_items=0)
        assert quiet.ratio is None


# ── somebody else's count is labelled as theirs ──────────────────────────────

class TestWhoseNumberItIs:
    """Two of the obvious headline figures are not release-gate's. The frontier
    scenario declares 2,184,992 events and the case observed none of them."""

    def test_an_unobserved_event_count_is_not_borrowed(self, frontier):
        stage = next(s for s in frontier.stages if s.name == "events")
        assert stage.count is None
        assert stage.basis is Basis.NOT_ASSESSED

    def test_but_a_declared_count_is_reported_as_declared(self):
        document = [r for r in _base() if r.get("record_type") != "execution"]
        document.append({
            "record_type": "expectation", "dimension": "events",
            "expected": 2_184_992, "observed": 0,
            "source": {"kind": "ORCHESTRATION_MANIFEST",
                       "declared_by": "orchestrator://swarm",
                       "authenticated": False, "detail": "the orchestrator's tally"}})
        metric = measure_compression(_assure(document))
        stage = next(s for s in metric.stages if s.name == "events")
        assert stage.count == 2_184_992
        assert stage.basis is Basis.DECLARED
        assert "orchestrator://swarm" in stage.detail
        assert "not ours" in stage.detail

    def test_and_the_ratio_says_which_stage_it_was_taken_over(self):
        document = [r for r in _base() if r.get("record_type") != "execution"]
        document.append({
            "record_type": "expectation", "dimension": "events",
            "expected": 2_184_992, "observed": 0,
            "source": {"kind": "ORCHESTRATION_MANIFEST",
                       "declared_by": "orchestrator://swarm",
                       "authenticated": False, "detail": "tally"}})
        metric = measure_compression(_assure(document))
        assert "DECLARED" in (metric.basis_of_ratio or "")
        assert "DECLARED" in metric.render()

    def test_the_declared_basis_is_reachable_at_all(self):
        """It was not, at first: a distinction the whole module is built on,
        present only in an enum nothing could produce."""
        import inspect
        from release_gate.assurance import compression
        source = inspect.getsource(compression)
        assert "Basis.DECLARED" in source
        assert "_declared_count" in source

    def test_an_observed_stage_names_how_it_was_counted(self, frontier):
        stage = next(s for s in frontier.stages if s.name == "evidence")
        assert stage.basis is Basis.OBSERVED
        assert "counted at ingest" in stage.detail


# ── retained critical issues are never compressed away ───────────────────────

class TestRetainedCritical:

    def test_they_are_shown_beside_the_number_always(self, frontier):
        assert frontier.retained_critical > 0
        assert "may never be dropped" in frontier.render()

    def test_and_they_can_be_opened_rather_than_trusted(self, frontier):
        assert len(frontier.retained_ids) == frontier.retained_critical

    def test_they_are_a_subset_of_what_is_shown(self, frontier):
        assert frontier.retained_critical <= frontier.review_items

    def test_a_retained_count_exceeding_the_shown_list_is_refused(self):
        """That would mean something was dropped that should not have been."""
        with pytest.raises(CompressionError, match="subset of what is shown"):
            HumanAttentionCompression(review_items=2, retained_critical=3)

    def test_zero_retained_is_a_real_answer_not_a_missing_one(self, single_agent):
        assert single_agent.retained_critical == 0
        assert "0  of those may never be dropped" in single_agent.render()


# ── the funnel is read, not computed ─────────────────────────────────────────

class TestItCountsNothingNew:

    def test_every_stage_comes_off_the_case_or_the_analysis(self, frontier):
        from release_gate.demos import frontier_research
        outcome = frontier_research.run().outcome
        held = {s.name: s.count for s in frontier.stages}
        assert held["evidence"] == outcome.case.collection("evidence").total_count
        assert held["claims"] == outcome.case.collection("claims").total_count
        assert held["critical_claims"] == len(outcome.analysis.criticality.critical_ids)

    def test_review_items_are_the_attention_set(self, frontier):
        from release_gate.demos import frontier_research
        outcome = frontier_research.run().outcome
        assert frontier.review_items == len(outcome.attention.items)

    def test_an_undecided_case_is_refused(self):
        import dataclasses
        outcome = _assure(_base())
        undecided = dataclasses.replace(outcome.case, verdict=None)
        with pytest.raises(CompressionError, match="not been decided"):
            measure_compression(dataclasses.replace(outcome, case=undecided))

    def test_the_schema_is_registered(self):
        from release_gate.assurance.protocol import PROTOCOL
        assert any(s.constant == "COMPRESSION_SCHEMA_VERSION"
                   for s in PROTOCOL.schemas)

    def test_it_round_trips(self, frontier):
        data = json.loads(json.dumps(frontier.to_dict()))
        assert data["schema_version"] == COMPRESSION_SCHEMA_VERSION
        assert len(data["stages"]) == 4
        assert data["retained_critical"] == frontier.retained_critical


class TestTheBriefsExampleWasIllustrative:
    """The brief showed 2,184,992 → 91,481 → 47 → 4. Two of those four are the
    scenario's own declarations and the case never observed them, and the other
    two are derived and come out differently. Recorded so nobody later reads the
    example as a target and tunes toward it."""

    def test_the_claim_count_is_what_the_case_holds_not_what_was_declared(self,
                                                                          frontier):
        claims = next(s for s in frontier.stages if s.name == "claims")
        assert claims.count == 2_420, (
            "the scenario declares 91,481; the case holds what it holds")
        assert claims.basis is Basis.OBSERVED

    def test_and_the_derived_stages_are_whatever_they_are(self, frontier):
        critical = next(s for s in frontier.stages if s.name == "critical_claims")
        assert critical.count == 48
        assert frontier.review_items == 13
