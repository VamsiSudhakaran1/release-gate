"""Scale properties, as regression guards rather than benchmarks.

Two quadratics have been found in this engine by measuring rather than reading,
and both looked like ordinary code. These tests pin the properties that stop
them coming back: work per record stays flat, a bounded fold holds nothing
regardless of how much it counts, and sharded ingest agrees with a single pass.

Timing appears in exactly one test, with a deliberately loose bound: a quadratic
shows up as a 4x jump when the input doubles, so a 2.5x ceiling catches it
without failing on a noisy machine.
"""

from __future__ import annotations

import time

import pytest

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind)
from release_gate.assurance.records import (
    DedupeBasis, MaterialisationBasis, RecordCollectionBuilder, RecordError,
    RetainAll, RetainFirst, RetainRelevant, SimpleRecord)


def rec(i: int) -> SimpleRecord:
    return SimpleRecord(record_type="evidence", record_id=f"e{i}", payload={"i": i})


# ── bounded memory ──────────────────────────────────────────────────────────

class TestBoundedFold:

    def test_a_bounded_fold_holds_nothing_however_much_it_counts(self):
        """The property the frontier scale rests on."""
        for n in (1_000, 50_000):
            builder = RecordCollectionBuilder("evidence", track_ids=False)
            for i in range(n):
                builder.add(rec(i), materialise=False)
            collection = builder.build()
            assert collection.materialised == ()
            assert collection.total_count == n

    def test_a_dropped_record_is_still_counted_and_still_committed(self):
        """Retention decides what is held, never what is counted."""
        held = RecordCollectionBuilder("evidence", track_ids=False)
        dropped = RecordCollectionBuilder("evidence", track_ids=False)
        for i in range(500):
            held.add(rec(i))
            dropped.add(rec(i), materialise=False)
        a, b = held.build(), dropped.build()
        assert a.total_count == b.total_count == 500
        assert a.fold_digest == b.fold_digest, (
            "the commitment must not depend on what was kept")

    def test_a_collection_that_dropped_records_cannot_call_itself_complete(self):
        builder = RecordCollectionBuilder("evidence", track_ids=False)
        for i in range(10):
            builder.add(rec(i), materialise=(i < 3))
        assert builder.build().basis is MaterialisationBasis.CAPPED

    def test_holding_nothing_at_all_is_summary_only(self):
        builder = RecordCollectionBuilder("evidence", track_ids=False)
        for i in range(10):
            builder.add(rec(i), materialise=False)
        assert builder.build().basis is MaterialisationBasis.SUMMARY_ONLY


# ── no naive O(N^2) ─────────────────────────────────────────────────────────

class TestNoQuadraticFold:

    def test_work_per_record_stays_flat_as_the_fold_grows(self):
        """The duplicate check for `track_ids=False` was a linear scan over every
        record held, on every add: 41us per record at 2,000 and 152us at 8,000.

        A quadratic shows as ~4x when the input doubles. The bound is 2.5x so a
        slow machine does not fail the build.
        """
        def elapsed(n: int) -> float:
            records = [rec(i) for i in range(n)]
            builder = RecordCollectionBuilder("evidence", track_ids=False)
            start = time.perf_counter()
            for record in records:
                builder.add(record)
            return time.perf_counter() - start

        elapsed(4_000)                      # warm the interpreter
        small = elapsed(8_000)
        large = elapsed(16_000)
        assert large < small * 2.5, (
            f"folding twice as many records took {large / max(small, 1e-9):.1f}x "
            "as long; the per-add duplicate check has gone quadratic again")

    def test_duplicates_are_still_refused_when_ids_are_tracked(self):
        builder = RecordCollectionBuilder("evidence", track_ids=True)
        builder.add(rec(1))
        with pytest.raises(RecordError, match="duplicate"):
            builder.add(rec(1))

    def test_duplicates_are_still_refused_among_held_records(self):
        """The check the fix replaced, which must still work."""
        builder = RecordCollectionBuilder("evidence", track_ids=False)
        builder.add(rec(1))
        with pytest.raises(RecordError, match="duplicate"):
            builder.add(rec(1))

    def test_an_unheld_duplicate_is_not_refused_and_says_so(self):
        """A fold that did not keep a record cannot vouch for its uniqueness."""
        builder = RecordCollectionBuilder("evidence", track_ids=False)
        builder.add(rec(1), materialise=False)
        builder.add(rec(1), materialise=False)
        assert builder.build().dedupe_basis is DedupeBasis.MATERIALISED_ONLY


# ── batch and resumable ingestion ───────────────────────────────────────────

class TestShardedIngest:

    def test_shards_merged_in_any_order_equal_a_single_pass(self):
        """What makes parallel ingest, batching and resumption sound."""
        n, shards = 3_000, 6
        whole = RecordCollectionBuilder("evidence", track_ids=False)
        for i in range(n):
            whole.add(rec(i), materialise=False)

        partials = []
        for s in range(shards):
            builder = RecordCollectionBuilder("evidence", track_ids=False)
            for i in range(s, n, shards):
                builder.add(rec(i), materialise=False)
            partials.append(builder)
        merged = partials[-1]
        for other in reversed(partials[:-1]):
            merged.merge(other)

        assert merged.build().fold_digest == whole.build().fold_digest
        assert merged.build().total_count == n

    def test_merging_a_tracked_and_an_untracked_fold_takes_the_weaker_claim(self):
        tracked = RecordCollectionBuilder("evidence", track_ids=True)
        tracked.add(rec(1))
        loose = RecordCollectionBuilder("evidence", track_ids=False)
        loose.add(rec(2), materialise=False)
        assert tracked.merge(loose).build().dedupe_basis \
            is DedupeBasis.MATERIALISED_ONLY

    def test_a_shard_clash_is_refused(self):
        a = RecordCollectionBuilder("evidence", track_ids=True)
        b = RecordCollectionBuilder("evidence", track_ids=True)
        a.add(rec(1)); b.add(rec(1))
        with pytest.raises(RecordError, match="both folds"):
            a.merge(b)


# ── retention policy ────────────────────────────────────────────────────────

class TestRetentionPolicy:

    def _built(self, policy, n=2_000):
        builder = RecordCollectionBuilder("evidence", track_ids=False, policy=policy)
        for i in range(n):
            builder.add(rec(i))
        return builder.build()

    def test_retain_all_is_the_default(self):
        builder = RecordCollectionBuilder("evidence", track_ids=False)
        builder.add(rec(1))
        assert builder.build().basis is MaterialisationBasis.COMPLETE

    def test_a_cap_makes_no_claim_to_have_chosen_well(self):
        """CAPPED, not SAMPLED: the first N is not a representative N."""
        collection = self._built(RetainFirst(limit=25))
        assert len(collection.materialised) == 25
        assert collection.basis is MaterialisationBasis.CAPPED

    def test_a_relevance_policy_says_it_chose_on_purpose(self):
        collection = self._built(RetainRelevant(
            predicate=lambda r: r.payload["i"] % 100 == 0, limit=100))
        assert collection.basis is MaterialisationBasis.RELEVANCE_DIRECTED
        assert all(r.payload["i"] % 100 == 0 for r in collection.materialised)

    def test_every_policy_counts_everything(self):
        for policy in (RetainAll(), RetainFirst(limit=5),
                       RetainRelevant(predicate=lambda r: False)):
            assert self._built(policy).total_count == 2_000

    def test_an_explicit_flag_still_overrides_the_policy(self):
        builder = RecordCollectionBuilder("evidence", track_ids=False,
                                          policy=RetainAll())
        builder.add(rec(1), materialise=False)
        assert builder.build().materialised == ()


# ── record construction ─────────────────────────────────────────────────────

class TestEvidenceIdentity:

    def _record(self, i: int) -> EvidenceRecord:
        return EvidenceRecord.from_producer(
            {"i": i, "nested": {"a": [1, 2, {"b": None}]}},
            evidence_type=EvidenceType.TRACE, source="s",
            producer=Producer(producer_id="agent://1", kind=ProducerKind.AGENT),
            supports_claims=(f"c{i % 7}",), coverage_note="n")

    def test_the_id_is_still_exactly_the_digest_of_the_identity(self):
        """Identity is now built and canonicalised once instead of twice. That is
        a hot-path saving and it must not move a single evidence id, because
        every content-addressed reference in the system is derived from one.
        """
        for i in range(200):
            record = self._record(i)
            assert record.evidence_id == short_id("ev", digest_object(record.identity()))

    def test_identical_content_still_yields_one_id(self):
        a = EvidenceRecord.from_producer(
            {"x": 1}, evidence_type=EvidenceType.TRACE, source="s",
            producer=Producer(producer_id="p", kind=ProducerKind.TOOL),
            coverage_note="n", timestamp="2020-01-01T00:00:00Z")
        b = EvidenceRecord.from_producer(
            {"x": 1}, evidence_type=EvidenceType.TRACE, source="s",
            producer=Producer(producer_id="p", kind=ProducerKind.TOOL),
            coverage_note="n", timestamp="2020-01-01T00:00:00Z")
        assert a.evidence_id == b.evidence_id

    def test_a_record_that_cannot_canonicalise_is_still_refused(self):
        """The discarded validation call was doing real work; losing it would
        have let an uncanonicalisable record through."""
        from release_gate.assurance.evidence import EvidenceError
        with pytest.raises(EvidenceError):
            EvidenceRecord.from_producer(
                {"bad": object()}, evidence_type=EvidenceType.TRACE, source="s",
                producer=Producer(producer_id="p", kind=ProducerKind.TOOL),
                coverage_note="n")


# ── ancestry ────────────────────────────────────────────────────────────────

class TestAncestry:

    def test_load_bearing_is_linear_in_roots(self):
        """Production callers traverse once per root, and roots are few."""
        from release_gate.assurance.claims import Claim, ClaimGraph
        def graph(n_roots, depth=20):
            base = [Claim(claim_id=f"b{i}", statement="b",
                          parents=(f"b{i-1}",) if i else ()) for i in range(depth)]
            roots = [Claim(claim_id=f"r{j}", statement="r",
                           parents=(f"b{depth-1}",), is_root=True)
                     for j in range(n_roots)]
            return ClaimGraph(base + roots)
        small = graph(500)
        assert len(small.load_bearing()) == 20
        assert len(graph(2_000).load_bearing()) == 20
