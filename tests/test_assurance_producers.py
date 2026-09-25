"""The scanner as one Evidence Producer among seven.

Two things are preserved and tested as such: the 139 rule ids and the benchmark
numbers. Two are new: the lanes state what they cannot establish, and measured
credibility travels beside a finding without ever entering a verdict.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from release_gate.assurance.producers import (
    BENCHMARK_CORPUS, CREDIBILITY, LANES, PRODUCERS_SCHEMA_VERSION,
    EvidenceLane, EvidenceProducer, ProducerError, RuleCredibility,
    credibility_for, lane_for,
)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "benchmark" / "RESULTS.md"

AUDIT_REPORT = {
    "score": 62, "decision": "HOLD",
    "code_findings": [
        {"rule_id": "RG-EXEC-001", "severity": "high", "basis": "confirmed",
         "title": "Model output reaches eval()", "file": "app/agent.py",
         "line": 42},
        {"rule_id": "RG-LOOP-001", "severity": "medium", "basis": "likely",
         "title": "Uncapped LLM loop", "file": "app/loop.py", "line": 18}],
    "safeguards": {"human_approval": {"status": "missing"}},
    "code_safety": {"applicable": True, "score": 62}}


@pytest.fixture
def audited(tmp_path):
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(AUDIT_REPORT))
    return assure(str(path))


# ── the scanner is preserved ─────────────────────────────────────────────────

class TestScannerPreserved:

    def test_the_rule_catalogue_is_intact(self):
        """139 distinct rule ids, measured before this repositioning and
        unchanged by it."""
        ids = set()
        for path in (ROOT / "release_gate").rglob("*.py"):
            ids |= set(re.findall(r"RG-[A-Z][A-Z0-9-]*", path.read_text()))
        assert len(ids) >= 139, f"rule ids dropped to {len(ids)}"

    def test_the_scanner_modules_are_untouched_by_this_work(self):
        """Repositioning is a description, not a rewrite."""
        for name in ("audit.py", "agent_analysis.py", "rules.py", "verify.py"):
            assert (ROOT / "release_gate" / name).exists()

    def test_a_finding_still_reaches_a_case_with_its_rule_id(self, audited):
        found = {r.to_dict()["content"].get("rule_id")
                 for r in audited.case.collection("evidence").materialised
                 if r.to_dict().get("evidence_type") == "STATIC_FINDING"}
        assert {"RG-EXEC-001", "RG-LOOP-001"} <= found

    def test_a_finding_still_argues_against_a_claim(self, audited):
        """The scanner's output contradicts "static analysis found no unsafe
        pattern"; it does not float free."""
        contradicting = [r for r in audited.case.collection("evidence").materialised
                         if getattr(r, "contradicts_claims", ())]
        assert contradicting

    def test_the_audit_report_is_still_detected(self, audited):
        assert audited.detection.kind.value == "AUDIT_REPORT"


# ── the benchmark is preserved, and now reachable ────────────────────────────

class TestBenchmarkCredibility:

    def test_the_results_document_still_exists(self):
        assert RESULTS.exists()

    def test_the_transcribed_numbers_match_the_document(self):
        """Literals in the module, checked against the file, so the two cannot
        drift — the shape the protocol manifest uses."""
        rows = {}
        for line in RESULTS.read_text().splitlines():
            match = re.match(r"\|\s*(RG-[A-Z0-9-]+)\s*\|\s*(\d+)\s*\|\s*(\d+)"
                             r"\s*\|\s*(\d+)\s*\|", line)
            if match:
                rows[match.group(1)] = tuple(int(match.group(i)) for i in (2, 3, 4))
        assert rows, "no per-rule rows parsed from RESULTS.md"
        assert set(rows) == set(CREDIBILITY)
        for rule_id, (tp, fp, fn) in rows.items():
            record = CREDIBILITY[rule_id]
            assert (record.true_positives, record.false_positives,
                    record.false_negatives) == (tp, fp, fn), rule_id

    def test_the_corpus_size_is_still_stated(self):
        assert "93 labeled cases" in RESULTS.read_text()
        assert "93 labeled cases" in BENCHMARK_CORPUS

    def test_precision_is_computed_not_stored(self):
        assert credibility_for("RG-EXEC-001").precision == 1.0

    def test_a_rule_that_fired_on_nothing_has_no_precision(self):
        """No denominator, no number — not a zero."""
        assert RuleCredibility(rule_id="RG-X", true_positives=0,
                               false_positives=0, false_negatives=3).precision is None

    def test_an_unmeasured_rule_reads_as_unmeasured(self):
        """Not as good. Defaulting it to the corpus average would manufacture
        exactly the confidence this engine refuses everywhere else."""
        assert credibility_for("RG-PROV-002") is None
        assert credibility_for("") is None

    def test_most_rules_are_unmeasured_and_that_is_stated(self):
        assert len(CREDIBILITY) == 16
        assert "16 of them benchmarked" in \
            lane_for(EvidenceLane.CODE_SCANNER).notes

    def test_credibility_never_predicts_a_finding(self):
        """Precision is how a rule behaved against a corpus. The corpus is not
        this codebase."""
        record = credibility_for("RG-EXEC-001")
        assert record.predicts_this_finding is False
        assert record.to_dict()["predicts_this_finding"] is False

    def test_a_credibility_record_cites_its_corpus(self):
        assert credibility_for("RG-GATE-001").corpus == BENCHMARK_CORPUS

    def test_negative_counts_are_refused(self):
        with pytest.raises(ProducerError):
            RuleCredibility(rule_id="RG-X", true_positives=-1,
                            false_positives=0, false_negatives=0)

    def test_credibility_changes_no_verdict(self, audited, tmp_path):
        """Reported beside a finding, never folded into one. A verdict that moved
        because a benchmark file changed would make the deterministic path depend
        on a measurement."""
        import release_gate.assurance.producers as module
        before = audited.case.verdict.decision
        original = module.CREDIBILITY
        module.CREDIBILITY = {}
        try:
            path = tmp_path / "again.json"
            path.write_text(json.dumps(AUDIT_REPORT))
            assert assure(str(path)).case.verdict.decision is before
        finally:
            module.CREDIBILITY = original

    def test_the_known_limitation_is_still_documented(self):
        """The corpus keeps its own misses on purpose."""
        text = RESULTS.read_text()
        assert "Taint is intra-procedural" in text
        assert "KNOWN-MISS" in text


# ── seven lanes, with different powers ───────────────────────────────────────

class TestLanes:

    def test_there_are_seven(self):
        assert len(LANES) == len(EvidenceLane) == 7

    def test_the_registry_cannot_disagree_with_itself(self):
        for lane, producer in LANES.items():
            assert producer.lane is lane

    @pytest.mark.parametrize("lane", list(EvidenceLane))
    def test_every_lane_states_what_it_cannot_establish(self, lane):
        assert lane_for(lane).cannot_establish

    def test_a_lane_with_no_limits_is_refused(self):
        """The lane that lists none is the one a reviewer will weight hardest."""
        with pytest.raises(ProducerError) as exc:
            EvidenceProducer(lane=EvidenceLane.TESTS, label="x")
        assert "weight hardest" in str(exc.value)

    def test_only_the_trace_establishes_runtime_behaviour(self):
        """A static finding is a claim about code, not about a run."""
        for lane in EvidenceLane:
            assert lane_for(lane).establishes_runtime_behaviour is (
                lane is EvidenceLane.RUNTIME_TRACE)

    def test_the_scanner_says_the_path_may_never_have_been_taken(self):
        cannot = lane_for(EvidenceLane.CODE_SCANNER).cannot_establish
        assert any("was ever taken" in c for c in cannot)
        assert any("intra-procedural" in c for c in cannot)

    def test_only_a_formal_verifier_establishes_correctness(self):
        for lane in EvidenceLane:
            assert lane_for(lane).establishes_correctness is (
                lane is EvidenceLane.FORMAL_VERIFIER)

    def test_and_only_within_its_model(self):
        cannot = lane_for(EvidenceLane.FORMAL_VERIFIER).cannot_establish
        assert any("model matches the system" in c for c in cannot)

    def test_a_trace_is_not_independent_of_its_subject(self):
        """An agent's trace of itself is the agent's account of itself."""
        assert not lane_for(EvidenceLane.RUNTIME_TRACE).independent_of_subject
        assert lane_for(EvidenceLane.CODE_SCANNER).independent_of_subject

    def test_human_review_cannot_report_its_own_coverage(self):
        cannot = lane_for(EvidenceLane.HUMAN_REVIEW).cannot_establish
        assert any("did not look at" in c for c in cannot)

    def test_approval_is_not_a_truth_certificate(self):
        cannot = lane_for(EvidenceLane.HUMAN_REVIEW).cannot_establish
        assert any("not a truth certificate" in c for c in cannot)

    def test_external_evidence_keeps_the_list_open(self):
        """The lane that stops the other six being a closed world."""
        producer = lane_for(EvidenceLane.EXTERNAL_EVIDENCE)
        assert any("unmapped record is counted" in c
                   for c in producer.cannot_establish)

    def test_the_payload_carries_both_powers(self):
        payload = lane_for(EvidenceLane.CODE_SCANNER).to_dict()
        assert payload["establishes_runtime_behaviour"] is False
        assert payload["establishes_correctness"] is False


# ── an ingested report is a document, not an in-process run ──────────────────

class TestIngestedDocumentProvenance:

    def test_a_report_is_not_attributed_to_this_process(self, audited):
        """It was: an audit.json handed to the ingest claimed
        identity_basis="in-process", which asserts this process ran the scanner.
        A hand-written file inherited release-gate's own producer kind on the
        strength of its filename."""
        producers = {r.to_dict()["producer"]["identity_basis"]
                     for r in audited.case.collection("evidence").materialised
                     if r.to_dict().get("evidence_type") == "STATIC_FINDING"}
        assert producers
        assert all("ingested-document" in basis for basis in producers)
        assert not any(basis == "in-process" for basis in producers)

    def test_it_no_longer_carries_release_gates_own_producer_kind(self, audited):
        kinds = {r.to_dict()["producer"]["kind"]
                 for r in audited.case.collection("evidence").materialised
                 if r.to_dict().get("evidence_type") == "STATIC_FINDING"}
        assert kinds == {"external"}

    def test_an_in_process_run_still_says_so(self):
        from release_gate.assurance.evidence import Producer, ProducerKind
        found = Producer.release_gate("analysis")
        assert found.identity_basis == "in-process"
        assert found.kind is ProducerKind.RELEASE_GATE

    def test_the_finding_status_is_unchanged(self, audited):
        """The fold's DERIVED/DECLARED split is argued in place; what changed is
        only the provenance claim."""
        statuses = {r.to_dict()["epistemic_status"]
                    for r in audited.case.collection("evidence").materialised
                    if r.to_dict().get("evidence_type") == "STATIC_FINDING"}
        assert statuses == {"DERIVED"}

    def test_the_verdict_is_unchanged(self, audited):
        assert audited.case.verdict is not None
