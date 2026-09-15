"""Deterministic evidence compaction.

Three properties, and the first is not negotiable: a record on the path from the
decision to the reason is retained whatever the budget says. Compaction that
could break the drill-down would trade the one thing a reviewer needs for memory.
"""

from __future__ import annotations

import dataclasses
import random

import pytest

from release_gate.assurance.compaction import (
    COMPACTION_SCHEMA_VERSION, CompactionBudget, CompactionError, CompactionReport,
    RetentionReason, classify, compact_case, verify_drill_down,
)
from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.session import AssuranceSession

ARGUMENT = [
    {"record_type": "claim", "claim_id": "c_root", "proposition": "safe to ship",
     "is_root": True, "parents": ["c_lemma"],
     "producer": {"producer_id": "agent://1", "kind": "agent"}},
    {"record_type": "claim", "claim_id": "c_lemma",
     "proposition": "the migration is reversible",
     "producer": {"producer_id": "agent://1", "kind": "agent"},
     "supporting_evidence": ["ev_ok"], "contradicting_evidence": ["ev_bad"]},
    {"record_type": "evidence", "evidence_id": "ev_ok", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://1", "kind": "tool"},
     "supports_claims": ["c_lemma"], "coverage_note": "suite passed"},
    {"record_type": "evidence", "evidence_id": "ev_bad", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://2", "kind": "tool"},
     "contradicts_claims": ["c_lemma"], "coverage_note": "rollback failed"},
]


def bulk(n, prefix="b"):
    return [{"record_type": "evidence", "evidence_id": f"{prefix}{i}", "kind": "TRACE",
             "producer": {"producer_id": f"a://{i % 16}", "kind": "agent"},
             "coverage_note": f"model call {i}"} for i in range(n)]


def run(records):
    return AssuranceSession.open(methodology=PROFILE).extend(records).finalize()


def compacted(outcome, residue=20):
    return compact_case(outcome.case, criticality=outcome.criticality,
                        budget=CompactionBudget(residue_per_collection=residue))


def notes_of(case, kind="evidence"):
    return {str(getattr(r, "coverage_note", "")) for r in case.collection(kind).materialised}


# ── the property that is not negotiable ─────────────────────────────────────

class TestDrillDownSurvives:

    def test_the_argument_survives_a_sea_of_bulk(self):
        outcome = run(bulk(2_000) + ARGUMENT)
        small, report = compacted(outcome, residue=5)
        assert report.drill_down_intact
        assert verify_drill_down(small, outcome.criticality)[0]

    def test_evidence_arguing_against_a_claim_is_never_compacted(self):
        """Keeping the supporting half and dropping the objecting half would be
        the most dangerous edit this engine could make to itself."""
        outcome = run(bulk(2_000) + ARGUMENT)
        small, _ = compacted(outcome, residue=1)
        assert "rollback failed" in notes_of(small)

    def test_a_contradiction_record_classifies_as_retained(self):
        record = SimpleRecord(record_type="evidence", record_id="x", payload={})
        object.__setattr__(record, "contradicts_claims", ("c1",))
        assert classify(record, "evidence", critical=set(), referenced=set()) \
            is RetentionReason.CONTRADICTION

    def test_a_verification_is_never_compacted(self):
        record = SimpleRecord(record_type="evidence", record_id="v", payload={})
        object.__setattr__(record, "verification_method", "TEST_SUITE")
        assert classify(record, "verification", critical=set(), referenced=set()) \
            is RetentionReason.VERIFICATION

    def test_the_budget_yields_to_the_critical_path(self):
        """A budget bounds the residue, never the argument."""
        outcome = run(bulk(500) + ARGUMENT)
        small, report = compacted(outcome, residue=0)
        assert report.drill_down_intact
        assert "rollback failed" in notes_of(small)

    def test_a_zero_budget_still_keeps_the_roles_the_retain_list_names(self):
        outcome = run(bulk(500) + ARGUMENT)
        small, _ = compacted(outcome, residue=0)
        assert "suite passed" in notes_of(small)

    def test_the_report_states_whether_drill_down_is_intact(self):
        outcome = run(bulk(100) + ARGUMENT)
        assert compacted(outcome)[1].to_dict()["drill_down_intact"] is True

    def test_a_negative_budget_is_refused(self):
        with pytest.raises(CompactionError):
            CompactionBudget(residue_per_collection=-1)


# ── deterministic ───────────────────────────────────────────────────────────

class TestDeterminism:

    def _permuted(self, case, seed, kind="evidence"):
        collection = case.collection(kind)
        shuffled = list(collection.materialised)
        random.seed(seed)
        random.shuffle(shuffled)
        permuted = dataclasses.replace(collection, materialised=tuple(shuffled))
        return dataclasses.replace(
            case, collections={**case.collections, kind: permuted})

    def test_the_retained_set_does_not_depend_on_arrival_order(self):
        """`RetainFirst` kept a different set per shard while committing to one
        digest, so two runs agreed on what existed and disagreed on what could
        be inspected. Selection here orders by content digest."""
        outcome = run(bulk(400))
        base = notes_of(compacted(outcome, residue=12)[0])
        for seed in (1, 2, 3):
            permuted = self._permuted(outcome.case, seed)
            other, _ = compact_case(permuted, criticality=outcome.criticality,
                                    budget=CompactionBudget(residue_per_collection=12))
            assert notes_of(other) == base

    def test_selection_is_by_content_not_by_id_order(self):
        outcome = run(bulk(200))
        kept = sorted(notes_of(compacted(outcome, residue=10)[0]))
        naive = sorted(f"model call {i}" for i in range(10))
        assert kept != naive, "content ordering must not coincide with insertion order"

    def test_compaction_is_idempotent(self):
        outcome = run(bulk(300) + ARGUMENT)
        once, _ = compacted(outcome, residue=10)
        twice, _ = compact_case(once, criticality=outcome.criticality,
                                budget=CompactionBudget(residue_per_collection=10))
        assert notes_of(twice) == notes_of(once)


# ── the commitment is untouched ─────────────────────────────────────────────

class TestLedgerPreserved:

    def test_totals_are_unchanged(self):
        outcome = run(bulk(1_000) + ARGUMENT)
        small, _ = compacted(outcome, residue=10)
        for kind in ("evidence", "claims"):
            assert (small.collection(kind).total_count
                    == outcome.case.collection(kind).total_count)

    def test_the_fold_digest_is_unchanged(self):
        """Compaction can never quietly change what a case says it saw."""
        outcome = run(bulk(1_000) + ARGUMENT)
        small, _ = compacted(outcome, residue=10)
        assert (small.collection("evidence").fold_digest
                == outcome.case.collection("evidence").fold_digest)

    def test_a_compacted_collection_stops_calling_itself_complete(self):
        outcome = run(bulk(1_000) + ARGUMENT)
        small, _ = compacted(outcome, residue=10)
        assert small.collection("evidence").basis.value != "COMPLETE"

    def test_nothing_is_compacted_when_everything_fits(self):
        outcome = run(ARGUMENT)
        small, report = compacted(outcome, residue=10_000)
        assert report.total_compacted == 0
        assert "Nothing was compacted" in report.note()

    def test_the_report_counts_what_it_did(self):
        outcome = run(bulk(500) + ARGUMENT)
        _, report = compacted(outcome, residue=10)
        assert report.total_compacted > 0
        assert report.to_dict()["schema_version"] == COMPACTION_SCHEMA_VERSION


# ── raw evidence stays outside ──────────────────────────────────────────────

class TestExternalEvidence:

    def test_a_record_holding_an_external_reference_is_retained(self):
        """The handle on the raw bytes is what makes compaction safe: the
        evidence still exists, it just does not live in the engine."""
        class Ref:
            kind = "FILE"
        record = SimpleRecord(record_type="evidence", record_id="x", payload={})
        object.__setattr__(record, "content_reference", Ref())
        assert classify(record, "evidence", critical=set(), referenced=set()) \
            is RetentionReason.EXTERNAL_REFERENCE

    def test_an_inline_record_is_ordinary_bulk(self):
        class Ref:
            kind = "INLINE"
        record = SimpleRecord(record_type="evidence", record_id="x", payload={})
        object.__setattr__(record, "content_reference", Ref())
        assert classify(record, "evidence", critical=set(), referenced=set()) \
            is RetentionReason.DIGEST_ONLY

    def test_an_artifact_something_points_at_is_a_dependency_edge(self):
        digest = "sha256:" + "a" * 64
        record = SimpleRecord(record_type="artifact", record_id="art", payload={})
        object.__setattr__(record, "digest", digest)
        assert classify(record, "artifacts", critical=set(), referenced={digest}) \
            is RetentionReason.DEPENDENCY_EDGE

    def test_an_unreferenced_artifact_is_bulk(self):
        record = SimpleRecord(record_type="artifact", record_id="art", payload={})
        object.__setattr__(record, "digest", "sha256:" + "b" * 64)
        assert classify(record, "artifacts", critical=set(), referenced=set()) \
            is RetentionReason.DIGEST_ONLY


# ── the retain list ─────────────────────────────────────────────────────────

class TestRetainList:

    @pytest.mark.parametrize("kind,reason", [
        ("contradictions", RetentionReason.CONTRADICTION),
        ("assumptions", RetentionReason.ASSUMPTION),
        ("counterexamples", RetentionReason.COUNTEREXAMPLE),
        ("failed_branches", RetentionReason.FAILURE),
        ("verification", RetentionReason.VERIFICATION),
        ("coverage", RetentionReason.COVERAGE),
    ])
    def test_every_named_collection_is_retained_whole(self, kind, reason):
        record = SimpleRecord(record_type=kind, record_id="x", payload={})
        assert classify(record, kind, critical=set(), referenced=set()) is reason

    def test_a_critical_claim_is_a_critical_node(self):
        record = SimpleRecord(record_type="claim", record_id="c1", payload={})
        object.__setattr__(record, "claim_id", "c1")
        assert classify(record, "claims", critical={"c1"}, referenced=set()) \
            is RetentionReason.CRITICAL_NODE

    def test_a_parent_of_a_critical_claim_is_a_dependency_edge(self):
        """Without it drill-down stops one hop short of the reason."""
        record = SimpleRecord(record_type="claim", record_id="c2", payload={})
        object.__setattr__(record, "claim_id", "c2")
        object.__setattr__(record, "parents", ("c1",))
        assert classify(record, "claims", critical={"c1"}, referenced=set()) \
            is RetentionReason.DEPENDENCY_EDGE

    def test_a_root_claim_is_a_final_dependency(self):
        record = SimpleRecord(record_type="claim", record_id="r", payload={})
        object.__setattr__(record, "claim_id", "r")
        object.__setattr__(record, "is_root", True)
        assert classify(record, "claims", critical=set(), referenced=set()) \
            is RetentionReason.FINAL_DEPENDENCY

    def test_the_coverage_state_survives_compaction(self):
        outcome = run(bulk(1_000) + ARGUMENT)
        small, _ = compacted(outcome, residue=1)
        before = outcome.case.collection("coverage")
        assert len(small.collection("coverage").materialised) == len(before.materialised)


class TestScale:

    def test_a_large_case_compacts_to_a_bounded_hold(self):
        outcome = run(bulk(20_000) + ARGUMENT)
        small, report = compacted(outcome, residue=50)
        held = len(small.collection("evidence").materialised)
        assert held < 200, f"held {held} records after compaction"
        assert small.collection("evidence").total_count > 20_000
        assert report.drill_down_intact
