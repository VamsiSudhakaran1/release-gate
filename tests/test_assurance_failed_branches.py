"""Failed branches — kept as structure, not as transcript.

A case that records only its successes looks exactly like its best branch. But
retaining every token of a frontier run would make the case unreadable and add
nothing anyone can act on, so the test plan is about the line between the two:
the aggregate is never sampled, the examples are, and the shortfall is counted.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.attention import AttentionReason
from release_gate.assurance.case import COLLECTION_KINDS, EVIDENCE_KINDS
from release_gate.assurance.evidence import VerificationMethod
from release_gate.assurance.failed_branches import (
    MAX_INLINE_DETAIL,
    BranchOutcome,
    FailedBranch,
    FailedBranchError,
    FailedBranchLedger,
    FailedBranchRecorder,
    FailureLocus,
    RetentionReason,
    branches_from_verification,
)
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.records import MaterialisationBasis
from release_gate.assurance.subject import ContentReference, ReferenceKind
from release_gate.assurance.verification import (
    VerificationAttempt, VerificationGraph, VerificationStatus, VerificationTarget,
)
from release_gate.assurance.zero_config import assure, render_text


def branch(**kwargs):
    kwargs.setdefault("outcome", BranchOutcome.PROOF_FAILED)
    kwargs.setdefault("locus", FailureLocus(step="lemma 48", ordinal=48))
    kwargs.setdefault("produced_by", "prover://1")
    return FailedBranch(**kwargs)


def _write(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(path)


def envelope(count=400, extra=()):
    rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
             "proposition": "the theorem holds",
             "producer": {"producer_id": "agent://m", "kind": "agent"}}]
    for i in range(count):
        rows.append({"record_type": "failed_branch", "outcome": "PROOF_FAILED",
                     "locus": {"step": "lemma 48", "ordinal": 48},
                     "produced_by": f"prover://{i % 5}", "depth": 48,
                     "reference": f"s3://proofs/branch-{i}.lean"})
    return rows + list(extra)


# ── the aggregate is never sampled ───────────────────────────────────────────

class TestAggregateSurvivesRetention:

    def _recorder(self, n=8000):
        recorder = FailedBranchRecorder()
        for i in range(n):
            recorder.record(branch(produced_by=f"prover://{i % 7}", depth=48))
        return recorder

    def test_counts_are_exact_however_few_are_kept(self):
        ledger = self._recorder().build()
        assert ledger.observed == 8000
        assert ledger.retained < 10
        point = ledger.failure_points[0]
        assert point.count == 8000, "losing a branch costs an example, not the count"

    def test_the_deepest_reach_survives(self):
        recorder = self._recorder(100)
        recorder.record(branch(produced_by="prover://deep", depth=51))
        ledger = recorder.build()
        assert ledger.failure_points[0].deepest == 51

    def test_the_shortfall_is_counted_and_named(self):
        ledger = self._recorder().build()
        assert ledger.dropped == ledger.observed - ledger.retained
        assert ledger.basis is MaterialisationBasis.CAPPED
        assert ledger.complete is False
        assert any("never the aggregate" in note for note in ledger.notes)

    def test_a_small_run_retains_everything(self):
        recorder = FailedBranchRecorder()
        recorder.record(branch(depth=1))
        ledger = recorder.build()
        assert ledger.complete is True
        assert ledger.basis is MaterialisationBasis.COMPLETE

    def test_producers_are_aggregated_not_lost(self):
        ledger = self._recorder().build()
        assert len(ledger.failure_points[0].producers) == 7

    def test_folding_is_constant_memory_per_branch(self):
        import time

        recorder = FailedBranchRecorder()
        start = time.time()
        for i in range(50_000):
            recorder.record(branch(produced_by=f"p://{i % 9}", depth=i % 60))
        ledger = recorder.build()
        assert time.time() - start < 10.0
        assert ledger.observed == 50_000
        assert ledger.retained <= 3


# ── the cap actually binds ───────────────────────────────────────────────────

class TestRetentionIsBounded:

    def test_monotonically_deeper_branches_do_not_defeat_the_cap(self):
        """Each new branch being the deepest so far must not retain all of them."""
        recorder = FailedBranchRecorder(per_locus_cap=3)
        for depth in range(200):
            recorder.record(branch(produced_by=f"p://{depth}", depth=depth))
        ledger = recorder.build()
        assert ledger.retained == 3
        assert ledger.failure_points[0].deepest == 199

    def test_the_deepest_is_among_those_kept(self):
        recorder = FailedBranchRecorder(per_locus_cap=3)
        for depth in range(200):
            recorder.record(branch(produced_by=f"p://{depth}", depth=depth))
        ledger = recorder.build()
        assert max(b.depth for b in ledger) == 199

    def test_claim_bearing_branches_outrank_deeper_ones(self):
        recorder = FailedBranchRecorder(per_locus_cap=2)
        for depth in range(50):
            recorder.record(branch(produced_by=f"p://{depth}", depth=depth))
        recorder.record(branch(produced_by="p://claim", depth=0,
                               bears_on_claims=("cl_root",)))
        ledger = recorder.build()
        assert ledger.retained == 2
        assert any(b.bears_on_claims for b in ledger)

    def test_claim_bearing_branches_are_still_bounded(self):
        recorder = FailedBranchRecorder(per_locus_cap=3)
        for i in range(500):
            recorder.record(branch(produced_by=f"p://{i}", depth=i,
                                   bears_on_claims=("cl_root",)))
        assert recorder.build().retained == 3

    def test_each_locus_gets_its_own_budget(self):
        recorder = FailedBranchRecorder(per_locus_cap=2)
        for i in range(50):
            recorder.record(branch(locus=FailureLocus(step="lemma 48"), depth=i))
            recorder.record(branch(locus=FailureLocus(step="lemma 12"), depth=i))
        ledger = recorder.build()
        assert ledger.retained == 4
        assert len(ledger.failure_points) == 2

    def test_a_cap_of_zero_is_refused(self):
        with pytest.raises(FailedBranchError, match="at least one example"):
            FailedBranchRecorder(per_locus_cap=0)

    def test_retention_reasons_are_attributed(self):
        recorder = FailedBranchRecorder(per_locus_cap=3)
        for depth in range(20):
            recorder.record(branch(produced_by=f"p://{depth}", depth=depth))
        recorder.record(branch(produced_by="p://c", depth=1,
                               bears_on_claims=("cl_root",)))
        reasons = {b.retained_because for b in recorder.build()}
        assert RetentionReason.BEARS_ON_CLAIM in reasons
        assert RetentionReason.DEEPEST_AT_LOCUS in reasons


# ── not every token ──────────────────────────────────────────────────────────

class TestStructureNotTranscript:

    def test_oversized_inline_detail_is_refused(self):
        with pytest.raises(FailedBranchError, match="belongs behind `reference`"):
            branch(detail="x" * (MAX_INLINE_DETAIL + 1))

    def test_detail_at_the_limit_is_allowed(self):
        assert branch(detail="x" * MAX_INLINE_DETAIL) is not None

    def test_the_envelope_truncates_rather_than_dropping_the_failure(self, tmp_path):
        """A producer that pasted a transcript still gets its failure recorded."""
        rows = envelope(0, extra=[{
            "record_type": "failed_branch", "outcome": "TEST_FAILED",
            "step": "regression", "detail": "y" * (MAX_INLINE_DETAIL * 3)}])
        outcome = assure(_write(tmp_path, "big.jsonl", rows))
        assert outcome.failed_branches.observed == 1
        kept = outcome.failed_branches.branches[0]
        assert len(kept.detail) <= MAX_INLINE_DETAIL
        assert "put the full record behind" in kept.detail

    def test_a_reference_makes_the_branch_reopenable(self):
        reference = ContentReference(kind=ReferenceKind.EXTERNAL,
                                     locator="s3://proofs/b.lean")
        assert branch(reference=reference).reachable is True

    def test_a_branch_with_no_reference_says_so(self):
        assert branch().reachable is False
        assert "cannot be reopened" in branch().render()

    def test_evidence_ids_also_make_it_reachable(self):
        assert branch(evidence=("ev_1",)).reachable is True


# ── the record ───────────────────────────────────────────────────────────────

class TestRecordShape:

    def test_the_locus_groups_on_what_identifies_it(self):
        assert FailureLocus(step="lemma 48").key == "lemma 48"
        assert FailureLocus(step="simulation", invariant="X").key == "simulation / X"

    def test_an_unidentified_locus_says_so(self):
        locus = FailureLocus()
        assert locus.identified is False
        assert locus.key == "unidentified failure point"

    def test_negative_depth_is_refused(self):
        with pytest.raises(FailedBranchError, match="depth cannot be negative"):
            branch(depth=-1)

    def test_the_id_is_derived(self):
        assert branch().branch_id.startswith("branch_")

    def test_it_round_trips(self):
        original = branch(depth=48, evidence=("ev_1",),
                          occurred_at="2026-01-01T00:00:00Z")
        restored = FailedBranch.from_dict(json.loads(json.dumps(original.to_dict())))
        assert restored.branch_id == original.branch_id

    def test_the_ledger_digest_is_stable(self):
        def build():
            recorder = FailedBranchRecorder()
            recorder.record(branch(occurred_at="2026-01-01T00:00:00Z", depth=48))
            return recorder.build()

        assert build().digest() == build().digest()

    def test_an_empty_ledger_is_valid(self):
        ledger = FailedBranchLedger()
        assert ledger.observed == 0
        assert ledger.render() == "No failed branches recorded."


# ── lifting from what is already there ───────────────────────────────────────

class TestLiftingFromVerification:

    def _graph(self, status=VerificationStatus.FAILED,
               method=VerificationMethod.FORMAL_PROOF):
        target = VerificationTarget.claim("cl_root")
        return VerificationGraph([VerificationAttempt(
            method=method, target=target, verifier="prover://1", status=status,
            detail="diverged at lemma 48")])

    def test_a_failed_attempt_becomes_a_branch(self):
        lifted = branches_from_verification(self._graph())
        assert len(lifted) == 1
        assert lifted[0].outcome is BranchOutcome.PROOF_FAILED

    def test_a_passing_attempt_does_not(self):
        assert branches_from_verification(
            self._graph(status=VerificationStatus.PASSED)) == ()

    def test_the_method_chooses_the_outcome(self):
        assert branches_from_verification(
            self._graph(method=VerificationMethod.SIMULATION))[0].outcome \
            is BranchOutcome.INVARIANT_VIOLATED
        assert branches_from_verification(
            self._graph(method=VerificationMethod.TYPE_CHECKER))[0].outcome \
            is BranchOutcome.ARTIFACT_REJECTED

    def test_it_carries_the_claim_it_bore_on(self):
        assert branches_from_verification(self._graph())[0].bears_on_claims \
            == ("cl_root",)

    def test_no_graph_yields_nothing(self):
        assert branches_from_verification(None) == ()


# ── reachable from the case ──────────────────────────────────────────────────

class TestReachableFromTheCase:

    def test_failed_branches_is_a_first_class_collection(self):
        assert "failed_branches" in COLLECTION_KINDS
        assert "failed_branches" in EVIDENCE_KINDS, (
            "failed branches are evidence, not a footnote")

    @pytest.fixture
    def many(self, tmp_path):
        return _write(tmp_path, "branches.jsonl", envelope(400))

    def test_retained_branches_land_in_the_collection(self, many):
        records = [r.to_dict() for r in assure(many).case.records("failed_branches")]
        assert records
        assert {r["record_type"] for r in records} == {"failed_branch"}

    def test_the_collection_states_how_it_came_to_hold_what_it_holds(self, many):
        collection = assure(many).case.collection("failed_branches")
        assert collection.basis is MaterialisationBasis.CAPPED

    def test_the_collection_is_present_even_when_nothing_failed(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
                 "proposition": "p",
                 "producer": {"producer_id": "agent://x", "kind": "agent"}}]
        case = assure(_write(tmp_path, "none.jsonl", rows)).case
        assert "failed_branches" not in case.absent_collections

    def test_the_outcome_carries_the_ledger(self, many):
        ledger = assure(many).failed_branches
        assert ledger.observed == 400
        assert ledger.retained < 400

    def test_a_branch_bearing_on_a_claim_is_findable_by_it(self, tmp_path):
        rows = envelope(50, extra=[{
            "record_type": "failed_branch", "outcome": "INVARIANT_VIOLATED",
            "locus": {"step": "simulation", "invariant": "monotonicity"},
            "produced_by": "sim://3", "depth": 12, "bears_on_claims": ["cl_root"],
            "reference": "s3://sims/run-3.json"}])
        ledger = assure(_write(tmp_path, "b.jsonl", rows)).failed_branches
        assert len(ledger.for_claim("cl_root")) == 1


# ── findings and coverage ────────────────────────────────────────────────────

class TestFindings:

    @pytest.fixture
    def many(self, tmp_path):
        return _write(tmp_path, "branches.jsonl", envelope(400))

    def _rules(self, path):
        return {f.rule_id: f for f in assure(path).analysis.findings}

    def test_a_recurring_failure_point_is_reported(self, many):
        finding = self._rules(many)["RG-BRANCH-001"]
        assert finding.domain is AnalysisDomain.FAILED_BRANCH
        assert "lemma 48" in finding.detail

    def test_nothing_here_blocks_or_holds(self, many):
        """Penalising a run for recording failures would teach producers to stop."""
        findings = [f for f in assure(many).analysis.findings
                    if f.domain is AnalysisDomain.FAILED_BRANCH]
        assert findings
        assert all(f.effect is RequirementEffect.ADVISORY for f in findings)

    def test_the_retention_shortfall_is_reported(self, many):
        finding = self._rules(many)["RG-BRANCH-002"]
        assert finding.observed["dropped"] > 0

    def test_unreferenced_branches_are_reported(self, tmp_path):
        rows = envelope(0, extra=[{
            "record_type": "failed_branch", "outcome": "TEST_FAILED",
            "step": "regression", "produced_by": "ci://1"}])
        assert "RG-BRANCH-003" in self._rules(_write(tmp_path, "bare.jsonl", rows))

    def test_it_becomes_an_attention_item_only_at_advisory(self, many):
        reasons = {i.reason for i in assure(many).attention}
        assert AttentionReason.RECURRING_FAILURE not in reasons, (
            "advisory findings do not consume a reviewer's attention budget")

    def test_coverage_distinguishes_nothing_failed_from_nothing_recorded(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
                 "proposition": "p",
                 "producer": {"producer_id": "agent://x", "kind": "agent"}}]
        coverage = [r.to_dict() for r in
                    assure(_write(tmp_path, "none.jsonl", rows)).case.records("coverage")]
        row = next(r for r in coverage if r["dimension"] == "failed_branches")
        assert row["status"] == "NOT_ASSESSED"
        assert "nothing here distinguishes them" in row["note"]

    def test_coverage_reports_the_retention_basis(self, many):
        rows = [r.to_dict() for r in assure(many).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "failed_branches")
        assert row["status"] == "NOT_ASSESSED"
        assert row["basis"] == "CAPPED"
        assert row["observed"] == 400

    def test_the_report_shows_the_failure_points(self, many):
        text = render_text(assure(many))
        assert "WHAT DID NOT WORK" in text
        assert "400 at lemma 48" in text
        assert "counted but not retained" in text

    def test_the_outcome_serialises(self, many):
        payload = json.loads(json.dumps(assure(many).to_dict()))
        assert payload["failed_branches"]["observed"] == 400
        assert payload["failed_branches"]["dropped"] > 0
