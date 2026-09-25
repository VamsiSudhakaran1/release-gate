"""Fault injection, and what deterministic recovery actually means.

The faults live in `release_gate/assurance/chaos.py` so they can be run outside
the suite; this file asserts the properties they establish, and — more
importantly — that each fault genuinely perturbs its input. A fault that changes
nothing passes every test and proves nothing.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.chaos import (
    CHAOS_SCHEMA_VERSION, FAULTS, ChaosError, Fault, Recovery, chaos_report,
    run_fault,
)


@pytest.fixture(scope="module")
def report():
    return chaos_report()


# ── the harness itself ───────────────────────────────────────────────────────

class TestTheHarness:

    def test_every_named_fault_is_covered(self):
        """The thirteen the brief names, by the brief's own vocabulary."""
        assert set(FAULTS) == {
            "ingestion_interruption", "duplicate_batches", "reordered_events",
            "missing_telemetry", "clock_skew", "restart", "duplicate_case",
            "concurrent_mutation", "approval_during_update",
            "verifier_arriving_late", "subject_mutation_during_review",
            "external_evidence_unavailable", "stale_digest"}

    def test_every_fault_actually_perturbs_its_input(self, report):
        """The meta-guard. A fault that leaves the input alone would recover
        IDENTICALLY every time and measure nothing at all."""
        inert = [r["name"] for r in report["results"] if not r["perturbed"]]
        assert inert == []

    def test_anything_short_of_identical_must_say_why(self):
        """So "it told us" never becomes the unexamined answer to everything."""
        for fault in FAULTS.values():
            if fault.expected is not Recovery.IDENTICAL:
                assert len(fault.why.strip()) > 40, fault.name

    def test_a_fault_without_a_reason_is_refused(self):
        with pytest.raises(ChaosError, match="must say why"):
            Fault("x", "something broke", Recovery.DECLARED, lambda: None)

    def test_an_unknown_fault_is_refused_by_name(self):
        with pytest.raises(ChaosError, match="not a known fault"):
            run_fault("the_sun_explodes")

    def test_the_report_round_trips(self, report):
        data = json.loads(json.dumps(report))
        assert data["schema_version"] == CHAOS_SCHEMA_VERSION
        assert len(data["results"]) == len(FAULTS)

    def test_every_fault_recovers_the_way_its_nature_permits(self, report):
        wrong = [(r["name"], r["expected"], r["recovery"])
                 for r in report["results"] if not r["as_expected"]]
        assert wrong == []


# ── absorbed: the fault changes nothing ──────────────────────────────────────

class TestAbsorbed:

    def test_a_skewed_clock_is_never_adopted_as_our_own(self):
        """A producer's clock is a producer's claim. 2099, 1970 and outright
        garbage all leave release-gate's own stamp alone, and all three are kept
        beside it so a reviewer can see what was claimed."""
        result = run_fault("clock_skew")
        assert result.recovery is Recovery.IDENTICAL
        assert result.detail["adopted"] == []
        assert all(v["producer_claim_kept"]
                   for v in result.detail["per_stamp"].values())

    def test_the_arrival_clock_does_not_leak_into_the_digest(self):
        """The other half: if it did, the same evidence would produce a
        different case every time it was read."""
        from unittest import mock
        import release_gate.assurance.evidence as evidence_module
        from release_gate.assurance.chaos import _assure, _base
        document = _base()
        with mock.patch.object(evidence_module, "_utc_now",
                               return_value="2026-01-01T00:00:00Z"):
            first = _assure(document)
        with mock.patch.object(evidence_module, "_utc_now",
                               return_value="2031-11-09T04:05:06Z"):
            second = _assure(document)
        assert first.case.case_digest == second.case.case_digest

    def test_a_restart_lands_where_an_uninterrupted_run_would(self):
        result = run_fault("restart")
        assert result.recovery is Recovery.IDENTICAL
        assert result.detail["shape_identical"] is True

    def test_the_same_evidence_is_the_same_case(self):
        result = run_fault("duplicate_case")
        assert result.recovery is Recovery.IDENTICAL
        assert result.detail["same_id"] and result.detail["same_digest"]


# ── declared: different, and it says so ──────────────────────────────────────

class TestDeclared:

    def test_a_truncated_stream_never_promotes(self):
        """The failure this whole file looks for is a fault that makes a case
        *cleaner*. A half-delivered case must not be an easier one."""
        result = run_fault("ingestion_interruption")
        assert result.detail["promoted_while_truncated"] == []
        assert result.detail["complete"] == "PROMOTE"

    def test_a_redelivered_batch_changes_nothing_a_reviewer_reads(self):
        result = run_fault("duplicate_batches")
        assert result.detail["verdict_and_findings_identical"] is True
        assert result.detail["evidence_identical"] is True

    def test_reordering_moves_only_records_that_cite_a_position(self):
        """Verdict, findings and every producer record's *content* survive. What
        moves is where records say they came from — which is accurate, because
        in a reordered document they came from somewhere else."""
        result = run_fault("reordered_events")
        assert result.detail["values_stable"] is True
        assert len(result.detail["verdicts"]) == 1
        assert result.detail["ids_moved"] > 0

    def test_absent_telemetry_is_reported_absent_and_not_filled_in(self):
        result = run_fault("missing_telemetry")
        assert result.detail["state"] == "NOT_ASSESSED"
        assert result.detail["graph_built"] is False
        assert result.detail["verdict_without"] != "PROMOTE"

    def test_two_writers_neither_absorbs_the_other(self):
        result = run_fault("concurrent_mutation")
        assert result.detail["distinct_digests"] is True
        assert result.detail["distinct_ids"] is True

    def test_a_subject_that_moved_says_so(self):
        result = run_fault("subject_mutation_during_review")
        assert result.detail["before"] == "UNCHANGED"
        assert result.detail["mutated"] == "MUTATED"
        assert result.detail["deleted"] == "UNVERIFIABLE"
        assert result.detail["unchanged_reads_false_when_mutated"] is True

    def test_an_unreachable_store_is_unverifiable_not_a_crash(self):
        """`recheck` promises that anything it cannot confirm is UNVERIFIABLE.
        A resolver that raised used to propagate instead — turning "is this still
        the thing?" into an exception in the one path that asks it."""
        result = run_fault("external_evidence_unavailable")
        assert result.detail["statuses"] == {
            "no_resolver": "UNVERIFIABLE",
            "connection_refused": "UNVERIFIABLE",
            "timeout": "UNVERIFIABLE"}
        assert result.detail["read_as_unchanged"] == []

    def test_and_it_names_the_failure_rather_than_swallowing_it(self):
        """"The store was unreachable" and "the reference resolves to nothing"
        are different problems with different fixes."""
        assert run_fault("external_evidence_unavailable").detail[
            "named_the_failure"] is True


# ── refused: the engine declines ─────────────────────────────────────────────

class TestRefused:

    def test_a_revision_does_not_inherit_its_approval(self):
        result = run_fault("approval_during_update")
        assert result.recovery is Recovery.REFUSED
        assert result.detail["valid"] is False
        assert result.detail["approvals_on_revision"] == 0

    def test_a_late_verifier_cannot_change_a_decided_case(self):
        result = run_fault("verifier_arriving_late")
        assert result.detail["refused_with"] == "SessionError"
        assert result.detail["reopened_differs"] is True

    def test_an_approval_stops_counting_when_the_subject_moves(self):
        result = run_fault("stale_digest")
        assert result.recovery is Recovery.REFUSED
        assert result.detail["valid"] is False
        assert result.detail["reasons"]


# ── the regressions these faults found ───────────────────────────────────────

class TestTheDefectsFound:
    """Each of these failed when it was first run."""

    def test_a_redelivered_batch_does_not_crash_the_run(self):
        """`_ordered_evidence` collapsed rows on their declared id — correctly,
        since a replay must buy no extra record — but counted the collapsed rows
        as neither mapped nor skipped. `records_mapped` came out below
        `records_seen`, the record_mapping coverage row reported a shortfall for
        records that had not gone missing, and a retried delivery degraded the
        verdict. Claims and artifacts had no collapse at all and reached the
        collection builder, whose duplicate-id refusal is fatal to the run."""
        from release_gate.assurance.chaos import _assure, _base
        document = _base()
        for copies in (2, 3, 4):
            outcome = _assure(list(document) * copies)
            assert outcome.case.verdict.decision.value == "PROMOTE", copies

    def test_and_the_accounting_adds_up(self):
        from release_gate.assurance.chaos import _base
        from release_gate.assurance.ingest import detect_document, normalise
        document = list(_base()) * 3
        content = ("\n".join(json.dumps(r, sort_keys=True)
                             for r in document) + "\n").encode()
        result = normalise(document, detect_document(document, filename="x.jsonl"),
                           source="x.jsonl", content=content)
        assert result.records_mapped + result.skipped_total == result.records_seen

    def test_a_replay_still_buys_no_extra_record(self):
        """The property the collapse exists for, kept while fixing the
        accounting: fifty copies of one result, each restamped with a fresh
        clock, are one record."""
        from release_gate.assurance.chaos import _assure
        records = [{"record_type": "claim", "claim_id": "c1", "proposition": "p",
                    "producer": {"producer_id": "agent://a", "kind": "agent"},
                    "supporting_evidence": ["e1"]}]
        records += [{"record_type": "evidence", "evidence_id": "e1",
                     "kind": "TEST_RESULT",
                     "producer": {"producer_id": "ci://pytest", "kind": "tool"},
                     "supports_claims": ["c1"],
                     "timestamp": f"2026-09-17T10:{i:02d}:00Z",
                     "coverage_note": "suite green"} for i in range(50)]
        outcome = _assure(records)
        held = [r for r in outcome.case.records("evidence")
                if r.to_dict().get("evidence_type") == "TEST_RESULT"]
        assert len(held) == 1

    def test_the_first_copy_wins_not_the_last(self):
        """The collapse used to keep whichever arrived latest, so a later copy
        quietly replaced an earlier one. The rest of that function already said
        references resolve to the first record."""
        from release_gate.assurance.chaos import _assure
        records = [
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://first", "kind": "tool"},
             "coverage_note": "the first arrival"},
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://second", "kind": "tool"},
             "coverage_note": "the second arrival"}]
        outcome = _assure(records)
        producers = {(r.to_dict().get("producer") or {}).get("producer_id")
                     for r in outcome.case.records("evidence")}
        assert "ci://first" in producers
        assert "ci://second" not in producers
