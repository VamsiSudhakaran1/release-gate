"""Counterexamples — the searches that try to break a claim.

The asymmetry is the whole content. Finding one is decisive; finding none is
almost nothing. Most of these tests try to get an empty search to count as proof,
or to get a live refutation past a verdict quietly.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.attention import AttentionReason
from release_gate.assurance.case import Decision
from release_gate.assurance.counterexample import (
    CounterexampleAttempt,
    CounterexampleError,
    CounterexampleLedger,
    CounterexampleResult,
    CounterexampleStatus,
    counterexamples_from_evidence,
)
from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind, VerificationMethod,
)
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.zero_config import assure, render_text


def attempt(**kwargs):
    kwargs.setdefault("target_claim", "cl_root")
    kwargs.setdefault("producer", "fuzz://1")
    return CounterexampleAttempt(**kwargs)


def found(**kwargs):
    kwargs.setdefault("result", CounterexampleResult.FOUND)
    kwargs.setdefault("status", CounterexampleStatus.OPEN)
    return attempt(**kwargs)


def _write(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(path)


BROKEN = [
    {"record_type": "claim", "claim_id": "cl_root", "is_root": True,
     "proposition": "the scheduler never double-books a slot",
     "producer": {"producer_id": "agent://planner", "kind": "agent"}},
    {"record_type": "evidence", "evidence_id": "ev_cex", "kind": "COUNTEREXAMPLE",
     "producer": {"producer_id": "fuzz://2", "kind": "tool"},
     "contradicts_claims": ["cl_root"],
     "coverage_note": "seed 41 books slot 7 twice"},
]

SEARCHED = [
    {"record_type": "claim", "claim_id": "cl_root", "is_root": True,
     "proposition": "the scheduler never double-books",
     "producer": {"producer_id": "agent://planner", "kind": "agent"}},
    {"record_type": "counterexample", "target_claim": "cl_root",
     "producer_id": "fuzz://1", "method": "PROPERTY_TEST", "result": "NOT_FOUND",
     "searched": "10^6 random schedules"},
]


# ── an empty search proves nothing ───────────────────────────────────────────

class TestAbsenceIsNeverProven:

    def test_proves_absence_is_always_false(self):
        empty = CounterexampleAttempt.not_found(
            "cl_root", producer="fuzz://1", searched="10^6 schedules")
        assert empty.proves_absence is False

    def test_it_is_false_however_exhaustive_the_search_sounds(self):
        empty = CounterexampleAttempt.not_found(
            "cl_root", producer="prover://1",
            method=VerificationMethod.FORMAL_PROOF,
            searched="the entire input space")
        assert empty.proves_absence is False

    def test_a_thousand_empty_searches_still_prove_nothing(self):
        ledger = CounterexampleLedger([
            CounterexampleAttempt.not_found("cl_root", producer=f"fuzz://{i}",
                                            searched=f"batch {i}")
            for i in range(1000)])
        assert ledger.summary()["absence_proven"] is False
        assert all(a.proves_absence is False for a in ledger)

    def test_the_summary_states_it_flatly(self):
        ledger = CounterexampleLedger([
            CounterexampleAttempt.not_found("cl_root", producer="f")])
        assert ledger.summary()["absence_proven"] is False

    def test_an_unrecorded_search_space_says_so(self):
        empty = CounterexampleAttempt.not_found("cl_root", producer="fuzz://1")
        assert "not recorded" in empty.search_bound

    def test_the_render_says_what_it_bounds(self):
        empty = CounterexampleAttempt.not_found(
            "cl_root", producer="fuzz://1", searched="10^6 schedules")
        assert "bounds the search, not the claim" in empty.render()


# ── result and status are different fields ───────────────────────────────────

class TestResultAndStatusAreDistinct:

    def test_an_empty_search_has_nothing_to_resolve(self):
        empty = CounterexampleAttempt.not_found("cl_root", producer="f")
        assert empty.status is CounterexampleStatus.NOT_APPLICABLE

    def test_an_empty_search_cannot_be_marked_resolved(self):
        """'We looked and found nothing' must not read as 'we dealt with it'."""
        with pytest.raises(CounterexampleError, match="nothing to be"):
            attempt(result=CounterexampleResult.NOT_FOUND,
                    status=CounterexampleStatus.RESOLVED,
                    resolution="x", resolution_evidence=("ev_1",))

    def test_an_empty_search_cannot_be_marked_open(self):
        with pytest.raises(CounterexampleError, match="nothing to be"):
            attempt(result=CounterexampleResult.NOT_FOUND,
                    status=CounterexampleStatus.OPEN)

    def test_a_found_counterexample_cannot_be_not_applicable(self):
        with pytest.raises(CounterexampleError, match="always has something to resolve"):
            attempt(result=CounterexampleResult.FOUND,
                    status=CounterexampleStatus.NOT_APPLICABLE)

    def test_a_found_counterexample_must_name_its_producer(self):
        with pytest.raises(CounterexampleError, match="answerable"):
            CounterexampleAttempt(target_claim="cl_root", producer="",
                                  result=CounterexampleResult.FOUND,
                                  status=CounterexampleStatus.OPEN)

    def test_all_five_results_exist(self):
        assert {r.value for r in CounterexampleResult} == {
            "FOUND", "NOT_FOUND", "INCONCLUSIVE", "NOT_RUN", "UNKNOWN"}


# ── closing one requires saying what closed it ───────────────────────────────

class TestCannotBeClosedSilently:

    def test_resolved_requires_a_resolution(self):
        with pytest.raises(CounterexampleError, match="state its resolution"):
            found(status=CounterexampleStatus.RESOLVED,
                  resolution_evidence=("ev_9",))

    def test_resolved_requires_resolution_evidence(self):
        with pytest.raises(CounterexampleError, match="resolution_evidence"):
            found(status=CounterexampleStatus.RESOLVED, resolution="the fixture was bad")

    def test_invalid_requires_a_reason(self):
        with pytest.raises(CounterexampleError, match="say why"):
            found(status=CounterexampleStatus.INVALID)

    def test_resolve_carries_both(self):
        closed = found().resolve("the spec was misread", ("ev_9",))
        assert closed.status is CounterexampleStatus.RESOLVED
        assert closed.is_open is False

    def test_unknown_status_counts_as_open(self):
        pending = found(status=CounterexampleStatus.UNKNOWN)
        assert pending.is_open is True


# ── the seven fields ─────────────────────────────────────────────────────────

class TestRecordShape:

    def test_every_named_field_is_present(self):
        payload = found(evidence=("ev_1",)).to_dict()
        for name in ("target_claim", "producer", "method", "result", "evidence",
                     "resolution", "status"):
            assert name in payload, name

    def test_the_id_is_derived(self):
        assert found().counterexample_id.startswith("cex_")

    def test_a_target_claim_is_required(self):
        with pytest.raises(CounterexampleError, match="target_claim is required"):
            CounterexampleAttempt(target_claim="  ")

    def test_it_round_trips(self):
        original = found(evidence=("ev_1",), searched="10^6")
        restored = CounterexampleAttempt.from_dict(
            json.loads(json.dumps(original.to_dict())))
        assert restored.counterexample_id == original.counterexample_id

    def test_the_ledger_digest_is_stable(self):
        a = CounterexampleLedger([found(attempted_at="2026-01-01T00:00:00Z")])
        b = CounterexampleLedger([found(attempted_at="2026-01-01T00:00:00Z")])
        assert a.digest() == b.digest()

    def test_open_attempts_sort_first(self):
        ledger = CounterexampleLedger([
            CounterexampleAttempt.not_found("cl_a", producer="f"),
            found(target_claim="cl_b")])
        assert ledger.attempts[0].is_open is True


# ── lifting from evidence already in the case ────────────────────────────────

class TestLiftingFromEvidence:

    def _record(self, claim_id="cl_root"):
        return EvidenceRecord.declared(
            EvidenceType.COUNTEREXAMPLE, source="s",
            producer=Producer(producer_id="fuzz://2", kind=ProducerKind.TOOL),
            contradicts_claims=(claim_id,))

    def test_counterexample_evidence_becomes_an_attempt(self):
        lifted = counterexamples_from_evidence([self._record()])
        assert len(lifted) == 1
        assert lifted[0].result is CounterexampleResult.FOUND

    def test_it_is_open_because_silence_is_not_a_resolution(self):
        assert counterexamples_from_evidence([self._record()])[0].is_open is True

    def test_other_evidence_types_are_ignored(self):
        other = EvidenceRecord.declared(
            EvidenceType.TEST_RESULT, source="s",
            producer=Producer(producer_id="ci://1"), contradicts_claims=("cl_root",))
        assert counterexamples_from_evidence([other]) == ()

    def test_it_carries_the_evidence_id(self):
        record = self._record()
        assert counterexamples_from_evidence([record])[0].evidence \
            == (record.evidence_id,)


# ── the case cannot silently appear clean ────────────────────────────────────

class TestCannotAppearClean:

    @pytest.fixture
    def broken(self, tmp_path):
        return _write(tmp_path, "broken.jsonl", BROKEN)

    def test_a_live_counterexample_against_a_critical_claim_blocks(self, broken):
        outcome = assure(broken)
        assert outcome.decision is Decision.BLOCK
        finding = next(f for f in outcome.analysis.findings
                       if f.rule_id == "RG-CEX-001")
        assert finding.effect is RequirementEffect.BLOCK

    def test_it_becomes_a_contradiction_the_verdict_must_name(self, broken):
        """Reusing the existing guard rather than adding a second one."""
        outcome = assure(broken)
        critical = outcome.contradictions.unresolved_critical()
        assert len(critical) == 1
        spoken = " ".join(outcome.case.verdict.fired_rules
                          + outcome.case.verdict.reasons)
        assert critical[0].contradiction_id in spoken

    def test_the_contradiction_says_a_counterexample_caused_it(self, broken):
        contradiction = assure(broken).contradictions.unresolved_critical()[0]
        assert "counterexample" in contradiction.critical_basis

    def test_the_report_shows_the_attempt(self, broken):
        text = render_text(assure(broken))
        assert "ATTEMPTS TO BREAK IT" in text
        assert "FOUND / OPEN" in text

    def test_it_becomes_an_attention_item(self, broken):
        reasons = {i.reason for i in assure(broken).attention}
        assert AttentionReason.LIVE_COUNTEREXAMPLE in reasons

    def test_the_same_disagreement_is_not_filed_twice(self, tmp_path):
        """A claim with both support and a counterexample yields one contradiction."""
        rows = BROKEN + [
            {"record_type": "evidence", "evidence_id": "ev_ok", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://1", "kind": "tool"},
             "supports_claims": ["cl_root"]}]
        outcome = assure(_write(tmp_path, "both.jsonl", rows))
        targets = [c.target_claims for c in outcome.contradictions]
        assert targets.count(("cl_root",)) == 1

    def test_a_resolved_counterexample_does_not_block(self, tmp_path):
        rows = [
            {"record_type": "claim", "claim_id": "cl_root", "is_root": True,
             "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"}},
            {"record_type": "counterexample", "target_claim": "cl_root",
             "producer_id": "fuzz://1", "result": "FOUND", "status": "RESOLVED",
             "resolution": "the fixture used a stale schema",
             "resolution_evidence": ["ev_fix"]},
        ]
        outcome = assure(_write(tmp_path, "fixed.jsonl", rows))
        assert "RG-CEX-001" not in {f.rule_id for f in outcome.analysis.findings}


# ── empty searches in the pipeline ───────────────────────────────────────────

class TestEmptySearchInPipeline:

    @pytest.fixture
    def searched(self, tmp_path):
        return _write(tmp_path, "searched.jsonl", SEARCHED)

    def test_the_envelope_can_record_a_search_that_found_nothing(self, searched):
        ledger = assure(searched).counterexamples
        assert len(ledger.searched_without_finding()) == 1

    def test_it_does_not_block(self, searched):
        assert assure(searched).decision is not Decision.BLOCK

    def test_it_is_reported_as_advisory(self, searched):
        finding = next(f for f in assure(searched).analysis.findings
                       if f.rule_id == "RG-CEX-003")
        assert finding.effect is RequirementEffect.ADVISORY
        assert "bounds what was looked at" in finding.detail

    def test_coverage_never_counts_it_as_proof(self, searched):
        rows = [r.to_dict() for r in assure(searched).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "counterexamples")
        assert row["absence_proven"] is False
        assert "absence is never established here" in row["note"]

    def test_a_clean_search_does_not_make_coverage_assessed_by_itself(self, searched):
        rows = [r.to_dict() for r in assure(searched).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "counterexamples")
        assert row["status"] == "ASSESSED"
        assert row["found"] == 0

    def test_the_search_bound_survives_into_the_report(self, searched):
        assert "10^6 random schedules" in render_text(assure(searched))


# ── the case ─────────────────────────────────────────────────────────────────

class TestCaseIntegration:

    @pytest.fixture
    def broken(self, tmp_path):
        return _write(tmp_path, "broken.jsonl", BROKEN)

    def test_attempts_land_in_their_own_collection(self, broken):
        records = [r.to_dict() for r in assure(broken).case.records("counterexamples")]
        assert {r["record_type"] for r in records} == {"counterexample"}

    def test_the_collection_is_present_even_when_nobody_tried(self, tmp_path):
        """Nobody trying is different from nobody looking for attempts."""
        rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
                 "proposition": "p",
                 "producer": {"producer_id": "agent://x", "kind": "agent"}}]
        case = assure(_write(tmp_path, "none.jsonl", rows)).case
        assert "counterexamples" not in case.absent_collections

    def test_no_search_at_all_is_not_assessed(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "cl_root", "is_root": True,
                 "proposition": "p",
                 "producer": {"producer_id": "agent://x", "kind": "agent"}}]
        coverage = [r.to_dict() for r in
                    assure(_write(tmp_path, "none.jsonl", rows)).case.records("coverage")]
        row = next(r for r in coverage if r["dimension"] == "counterexamples")
        assert row["status"] == "NOT_ASSESSED"
        assert "nobody tried to break the claims" in row["note"]

    def test_the_outcome_serialises(self, broken):
        payload = json.loads(json.dumps(assure(broken).to_dict()))
        assert payload["counterexamples"]["open"] == 1
        assert payload["counterexamples"]["absence_proven"] is False
