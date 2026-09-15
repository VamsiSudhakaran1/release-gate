"""The eleven queries.

The property this file exists to protect: **an empty answer must never be able
to mean "the analysis never ran".** A query reporting "no contradictions" on a
case holding one is the most comfortable lie this system could tell, and that is
not hypothetical — it happened, because a `getattr(ledger, "unresolved", ...)`
default turned a wrong method name into a clean bill of health.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.query import (
    QUERIES, QUERY_SCHEMA_VERSION, QueryError, QueryOutcome, QueryResult,
    run_all, run_query,
)
from release_gate.assurance.session import AssuranceSession

CONFLICTED = [
    {"record_type": "claim", "claim_id": "c_lemma",
     "proposition": "the migration reverses", "is_root": True,
     "producer": {"producer_id": "a://1", "kind": "agent"},
     "supporting_evidence": ["ok"], "contradicting_evidence": ["bad"],
     "verification_attempts": [
         {"evidence_id": "bad", "method": "TEST_SUITE", "outcome": "FAILED"}]},
    {"record_type": "evidence", "evidence_id": "ok", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://1", "kind": "tool"},
     "supports_claims": ["c_lemma"], "coverage_note": "passed"},
    {"record_type": "evidence", "evidence_id": "bad", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://2", "kind": "tool"},
     "contradicts_claims": ["c_lemma"], "coverage_note": "rollback failed"},
]

BARE = [{"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
         "producer": {"producer_id": "a://1", "kind": "agent"},
         "coverage_note": "did a thing"}]


def outcome_for(records):
    return AssuranceSession.open(methodology=PROFILE).extend(list(records)).finalize()


@pytest.fixture(scope="module")
def conflicted():
    return outcome_for(CONFLICTED)


@pytest.fixture(scope="module")
def bare():
    return outcome_for(BARE)


# ── the property that matters ───────────────────────────────────────────────

class TestEmptyIsNeverUnknown:

    def test_a_real_contradiction_is_reported(self, conflicted):
        """The regression that motivated this file.

        A `getattr(ledger, "unresolved", lambda: ())` default silently returned
        nothing because the method is called `open`, so a case holding a live
        contradiction reported none.
        """
        result = run_query("open_contradictions", conflicted)
        assert result.outcome is QueryOutcome.FOUND
        assert result.rows[0]["target_claims"] == ["c_lemma"]

    def test_the_case_really_holds_it(self, conflicted):
        """Pins the fixture, so the test above cannot pass vacuously."""
        assert list(conflicted.case.collection("contradictions").materialised)

    def test_an_unsupplied_analysis_answers_not_assessed(self, conflicted):
        """Not none. Nobody handed this case an approval to check."""
        result = run_query("stale_approvals", conflicted)
        assert result.outcome is QueryOutcome.NOT_ASSESSED
        assert not result.answered

    def test_not_assessed_says_it_is_unknown_not_none(self, conflicted):
        assert "unknown, not none" in run_query("stale_approvals", conflicted).note()

    def test_an_analysis_that_ran_and_found_nothing_is_none_found(self, bare):
        """Assumption analysis always runs, so an empty result means it looked
        and found none — which is a different answer from nobody looking, and
        the basis still refuses the overclaim."""
        result = run_query("assumptions_affecting_result", bare)
        assert result.outcome is QueryOutcome.NONE_FOUND
        assert "not an argument without any" in result.basis

    def test_none_found_and_not_assessed_are_distinct(self, conflicted, bare):
        found = run_query("open_contradictions", conflicted)
        unknown = run_query("stale_approvals", conflicted)
        assert found.outcome is not unknown.outcome
        assert found.answered and not unknown.answered

    def test_truthiness_tracks_found_only(self, conflicted, bare):
        assert run_query("open_contradictions", conflicted)
        assert not run_query("stale_approvals", conflicted)

    def test_a_clean_empty_answer_refuses_the_overclaim(self, bare):
        result = run_query("open_contradictions", bare)
        assert result.outcome is QueryOutcome.NONE_FOUND
        assert "not the same as none existing" in result.basis


# ── each of the eleven ──────────────────────────────────────────────────────

class TestTheEleven:

    def test_all_eleven_are_registered(self):
        assert len(QUERIES) == 11

    def test_unverified_critical_claims(self, conflicted):
        result = run_query("unverified_critical_claims", conflicted)
        assert result.outcome is QueryOutcome.FOUND
        assert any(r["claim_id"] == "c_lemma" for r in result.rows)

    def test_blockers_reads_the_rendered_verdict(self, conflicted):
        """The answer to "why is this not promoting" must be the reasons the gate
        actually used, not a second opinion computed here."""
        result = run_query("blockers", conflicted)
        assert result.outcome is QueryOutcome.FOUND
        fired = {r.get("rule_id") for r in result.rows if "rule_id" in r}
        assert fired & set(conflicted.case.verdict.fired_rules)

    def test_missing_evidence(self, conflicted):
        assert run_query("missing_evidence", conflicted).answered

    def test_missing_evidence_refuses_to_imply_completeness(self, bare):
        result = run_query("missing_evidence", bare)
        if result.outcome is QueryOutcome.NONE_FOUND:
            assert "not the same as nothing being missing" in result.basis

    def test_artifacts_changed_after_verification(self, conflicted):
        result = run_query("artifacts_changed_after_verification", conflicted)
        assert result.outcome in (QueryOutcome.NONE_FOUND, QueryOutcome.FOUND,
                                  QueryOutcome.NOT_ASSESSED)

    def test_single_root_claims(self, conflicted):
        """`supporting_producers` is a count, not a collection — calling len() on
        it raised, and the sweep's guard turned that into NOT_ASSESSED."""
        result = run_query("single_root_claims", conflicted)
        assert result.outcome is QueryOutcome.FOUND
        assert result.rows[0]["producers"] == 1

    def test_unresolved_verifier_failures(self, conflicted):
        result = run_query("unresolved_verifier_failures", conflicted)
        assert result.outcome is QueryOutcome.FOUND
        assert result.rows[0]["status"] == "FAILED"

    def test_stale_approvals_without_an_approval_is_not_assessed(self, conflicted):
        """A case does not go looking for approvals it was not given."""
        result = run_query("stale_approvals", conflicted)
        assert result.outcome is QueryOutcome.NOT_ASSESSED
        assert "not supplied" in result.basis or "no approval" in result.basis

    def test_unknown_completeness_without_a_ledger_is_not_assessed(self, conflicted):
        assert run_query("unknown_completeness_sources", conflicted).outcome \
            is QueryOutcome.NOT_ASSESSED

    def test_unknown_completeness_reads_a_supplied_ledger(self, conflicted):
        from release_gate.assurance.completeness import (
            EndOfStream, SourceStream, StreamLedger)
        ledger = StreamLedger(
            streams=(SourceStream(stream_id="s1", producer_id="a://1",
                                  observed_sequences=(1, 2),
                                  end_of_stream=EndOfStream(declared_by="a://1")),),
            expected_streams=("s1",))
        result = run_query("unknown_completeness_sources", conflicted, ledger=ledger)
        assert result.outcome is QueryOutcome.FOUND
        assert result.rows[0]["self_certified"] is True

    def test_hold_resolution_on_a_blocked_case_says_so(self, conflicted):
        result = run_query("hold_resolution", conflicted)
        if conflicted.decision.value != "HOLD":
            assert result.outcome is QueryOutcome.NONE_FOUND
            assert "not on hold" in result.basis

    def test_hold_resolution_names_what_would_lift_it(self):
        held = outcome_for([
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
             "producer": {"producer_id": "a://1", "kind": "agent"},
             "coverage_note": "step"},
            {"record_type": "claim", "claim_id": "c1", "proposition": "fine",
             "is_root": True, "producer": {"producer_id": "a://1", "kind": "agent"}}])
        result = run_query("hold_resolution", held)
        if held.decision.value == "HOLD":
            assert result.answered


# ── contract ────────────────────────────────────────────────────────────────

class TestContract:

    def test_every_query_answers_every_case_without_raising(self, conflicted, bare):
        for name in QUERIES:
            for outcome in (conflicted, bare):
                assert isinstance(run_query(name, outcome), QueryResult)

    def test_the_sweep_covers_every_query(self, conflicted):
        assert set(run_all(conflicted)) == set(QUERIES)

    def test_the_sweep_never_omits_a_query_it_could_not_answer(self, bare):
        """A caller reading the sweep must see the question was asked and could
        not be answered, not find it missing and assume it did not apply."""
        results = run_all(bare)
        assert "stale_approvals" in results
        assert results["stale_approvals"].outcome is QueryOutcome.NOT_ASSESSED

    def test_an_unknown_query_is_refused_with_the_known_names(self, conflicted):
        with pytest.raises(QueryError, match="Known:"):
            run_query("which_ones_look_dodgy", conflicted)

    def test_results_serialise(self, conflicted):
        payload = run_query("open_contradictions", conflicted).to_dict()
        assert payload["record_type"] == "assurance_query"
        assert payload["schema_version"] == QUERY_SCHEMA_VERSION
        assert payload["answered"] is True
        assert payload["count"] == len(payload["rows"])

    def test_every_result_names_where_it_read_from(self, conflicted):
        for name, result in run_all(conflicted).items():
            assert result.source or not result.answered, name

    def test_every_result_gives_a_readable_note(self, conflicted):
        for name, result in run_all(conflicted).items():
            assert result.note(), name

    def test_queries_do_not_recompute_the_verdict(self, conflicted):
        """Reading a query must not change the case or its decision."""
        before = conflicted.case.case_digest
        run_all(conflicted)
        assert conflicted.case.case_digest == before
