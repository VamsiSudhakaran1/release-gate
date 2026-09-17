"""Assurance delta: what changed, so nobody rereads a case they have read.

The test that carries this file is the one proving a row cannot go from FOUND to
NOT_ASSESSED and be reported as resolved. "3 contradictions resolved" when
contradiction detection simply did not run this time is the most flattering
possible way to describe getting worse, and it is the one thing a delta must
never say.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.progress import (
    PROGRESS_SCHEMA_VERSION, AssuranceProgress, ProgressError, QueryDelta,
    compare, diff_query,
)
from release_gate.assurance.query import QUERIES, QueryOutcome, QueryResult
from release_gate.assurance.session import AssuranceSession

DIGEST = "sha256:" + "a" * 64


def result(query, outcome, rows=(), basis=""):
    return QueryResult(query, outcome, tuple(rows), "test", basis)


def case(records):
    return AssuranceSession.open(methodology=PROFILE).extend(list(records)).finalize()


UNVERIFIED = [
    {"record_type": "claim", "claim_id": "C-184", "proposition": "bound holds",
     "is_root": True, "producer": {"producer_id": "a://1", "kind": "agent"}},
    {"record_type": "claim", "claim_id": "C-311", "proposition": "no data loss",
     "producer": {"producer_id": "a://1", "kind": "agent"},
     "supporting_evidence": ["ok"], "contradicting_evidence": ["bad"]},
    {"record_type": "evidence", "evidence_id": "ok", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://1", "kind": "tool"},
     "supports_claims": ["C-311"], "coverage_note": "passed"},
    {"record_type": "evidence", "evidence_id": "bad", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://2", "kind": "tool"},
     "contradicts_claims": ["C-311"], "coverage_note": "failed"},
]

VERIFIED = [
    dict(UNVERIFIED[0], verification_attempts=[
        {"evidence_id": "pf", "method": "FORMAL_PROOF", "outcome": "PASSED",
         "target_digest": DIGEST}]),
    {"record_type": "claim", "claim_id": "C-311", "proposition": "no data loss",
     "producer": {"producer_id": "a://1", "kind": "agent"},
     "supporting_evidence": ["ok"],
     "verification_attempts": [{"evidence_id": "ok", "method": "TEST_SUITE",
                                "outcome": "PASSED", "target_digest": DIGEST}]},
    UNVERIFIED[2],
    {"record_type": "evidence", "evidence_id": "pf", "kind": "FORMAL_PROOF",
     "producer": {"producer_id": "lean://1", "kind": "tool"},
     "supports_claims": ["C-184"], "coverage_note": "proof"},
]


@pytest.fixture(scope="module")
def progress():
    return compare(case(UNVERIFIED), case(VERIFIED))


# ── the lie this module refuses ─────────────────────────────────────────────

class TestLostVisibilityIsNotProgress:

    def _lost(self):
        return diff_query(
            result("open_contradictions", QueryOutcome.FOUND,
                   [{"contradiction_id": "contra_1", "target_claims": ["C-311"]}]),
            result("open_contradictions", QueryOutcome.NOT_ASSESSED, [],
                   "contradiction detection did not run"))

    def test_a_row_that_became_invisible_is_not_resolved(self):
        assert self._lost().resolved == ()

    def test_it_is_reported_as_lost_visibility(self):
        assert self._lost().lost_visibility

    def test_the_headline_says_invisible_not_gone(self):
        assert "invisible, not gone" in self._lost().headline()

    def test_losing_visibility_counts_as_a_regression(self):
        """A case that can no longer tell whether it has contradictions has not
        improved by losing the ability to tell."""
        progress = AssuranceProgress(deltas={"open_contradictions": self._lost()})
        assert progress.regressed

    def test_it_is_not_an_improvement(self):
        assert not self._lost().improved

    def test_newly_visible_findings_are_not_blamed_on_this_run(self):
        """NOT_ASSESSED → FOUND is newly visible breakage, possibly long-standing."""
        delta = diff_query(
            result("open_contradictions", QueryOutcome.NOT_ASSESSED, []),
            result("open_contradictions", QueryOutcome.FOUND,
                   [{"contradiction_id": "contra_9"}]))
        assert delta.gained_visibility
        assert "possibly long-standing" in delta.headline()

    def test_the_render_explains_what_stopped(self):
        progress = AssuranceProgress(deltas={"open_contradictions": self._lost()})
        rendered = progress.render()
        assert "No longer visible" in rendered
        assert "invisible rather than resolved" in rendered


# ── real movement ───────────────────────────────────────────────────────────

class TestRealProgress:

    def test_a_verified_claim_leaves_the_unverified_query(self, progress):
        delta = progress.deltas["unverified_critical_claims"]
        assert delta.previous_count > delta.current_count
        assert any(r["claim_id"] == "C-184" for r in delta.resolved)

    def test_the_resolution_reason_is_stated(self, progress):
        assert progress.deltas["unverified_critical_claims"].resolution_reason() \
            == "now carries a passed verification"

    def test_a_resolved_contradiction_is_named(self, progress):
        assert any(query == "open_contradictions"
                   for query, _ in progress.resolved)

    def test_the_render_carries_counts_reasons_and_new_items(self, progress):
        rendered = progress.render()
        assert "unverified_critical_claims: 1 → 0" in rendered
        assert "Resolved" in rendered
        assert "now carries a passed verification" in rendered

    def test_something_new_is_reported_as_new(self, progress):
        assert progress.introduced

    def test_it_serialises(self, progress):
        payload = progress.to_dict()
        assert payload["record_type"] == "assurance_progress"
        assert payload["schema_version"] == PROGRESS_SCHEMA_VERSION
        assert set(payload["deltas"]) == set(QUERIES)


# ── the narrative stays short ───────────────────────────────────────────────

class TestNarrativeIsShort:
    """Humans should not reread entire cases."""

    def test_derived_queries_do_not_echo_the_same_fact(self):
        """`blockers`, `missing_evidence` and `hold_resolution` restate the
        findings underneath them. Itemising all three turned two real changes
        into nine lines, each a different phrasing of the same two.
        """
        progress = compare(case(UNVERIFIED), case(VERIFIED))
        itemised = {query for query, _ in progress.resolved}
        assert "blockers" not in itemised
        assert "missing_evidence" not in itemised

    def test_the_full_diff_is_still_available(self):
        progress = compare(case(UNVERIFIED), case(VERIFIED))
        assert len(progress.resolved_everywhere) >= len(progress.resolved)

    def test_derived_movement_still_shows_as_counts(self):
        progress = compare(case(UNVERIFIED), case(VERIFIED))
        assert "missing_evidence" in progress.render()

    def test_an_unchanged_case_says_so_in_one_line(self):
        unchanged = case(UNVERIFIED)
        progress = compare(unchanged, unchanged)
        assert progress.quiet
        assert progress.render() == "No assurance-relevant state changed."

    def test_row_identity_survives_a_row_gaining_a_field(self):
        """Keyed on identity, not equality: a claim that gained a verification
        must not read as one row vanishing and another appearing."""
        delta = diff_query(
            result("unverified_critical_claims", QueryOutcome.FOUND,
                   [{"claim_id": "C-1", "verified": False}]),
            result("unverified_critical_claims", QueryOutcome.FOUND,
                   [{"claim_id": "C-1", "verified": False, "note": "still working"}]))
        assert delta.resolved == () and delta.introduced == ()
        assert len(delta.persisting) == 1

    def test_blocker_rows_of_two_shapes_key_cleanly(self):
        """`blockers` emits rule rows and reason rows; joining both key fields
        produced keys like `x|` and `|y` that diffed as churn."""
        from release_gate.assurance.progress import _key
        assert _key("blockers", {"rule_id": "RG-ZC-002"}) == "RG-ZC-002"
        assert _key("blockers", {"reason": "because"}) == "because"


# ── contract ────────────────────────────────────────────────────────────────

class TestContract:

    def test_every_query_is_diffed(self):
        progress = compare(case(UNVERIFIED), case(VERIFIED))
        assert set(progress.deltas) == set(QUERIES)

    def test_a_query_unanswered_on_both_sides_still_appears(self):
        progress = compare(case(UNVERIFIED), case(VERIFIED))
        assert "stale_approvals" in progress.deltas

    def test_mismatched_queries_are_refused(self):
        with pytest.raises(ProgressError, match="cannot diff"):
            diff_query(result("blockers", QueryOutcome.FOUND),
                       result("open_contradictions", QueryOutcome.FOUND))

    def test_a_first_reading_has_no_delta(self):
        """A first reading should be reported as one, not diffed against nothing."""
        with pytest.raises(ProgressError, match="first reading"):
            compare(None, case(UNVERIFIED))

    def test_a_decision_change_is_reported(self):
        progress = AssuranceProgress(deltas={}, previous_decision="PROMOTE",
                                     current_decision="BLOCK")
        assert progress.regressed
        assert "PROMOTE → BLOCK" in progress.render()

    def test_improvement_requires_nothing_new_and_nothing_lost(self):
        clean = diff_query(
            result("open_contradictions", QueryOutcome.FOUND,
                   [{"contradiction_id": "c1"}]),
            result("open_contradictions", QueryOutcome.NONE_FOUND, []))
        assert clean.improved
        mixed = diff_query(
            result("open_contradictions", QueryOutcome.FOUND,
                   [{"contradiction_id": "c1"}]),
            result("open_contradictions", QueryOutcome.FOUND,
                   [{"contradiction_id": "c2"}]))
        assert not mixed.improved

    def test_comparing_a_case_to_itself_is_quiet(self):
        same = case(VERIFIED)
        assert compare(same, same).quiet
