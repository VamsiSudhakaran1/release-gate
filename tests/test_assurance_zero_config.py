"""Zero-config assurance — real structural answers from one file, and a hard limit.

The limit is the point of the test plan. Zero configuration must be able to say
BLOCK and must be able to say "I cannot tell you"; it must never say PROMOTE,
because authorising requires a yardstick nobody supplied. Several tests below do
nothing but try to reach PROMOTE without a methodology.
"""

import json

import pytest

from release_gate.assurance.analysis import (
    AnalysisDomain, Finding, analyse,
)
from release_gate.assurance.attention import (
    AttentionReason, build_attention, build_required_evidence,
)
from release_gate.assurance.case import Decision
from release_gate.assurance.evidence import EpistemicStatus, ProducerKind
from release_gate.assurance.ingest import (
    Detection, IngestError, InputKind, detect_document, ingest_path, subject_type_for,
)
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.methodology import AssessmentStatus, RequirementEffect
from release_gate.assurance.zero_config import (
    ZERO_CONFIG_RULESET_VERSION, AssuranceOutcome, ZeroConfigError, assure,
    exit_code_for, render_text,
)


# ── fixtures ─────────────────────────────────────────────────────────────────

OTLP = {
    "resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "planner-agent"}}]},
        "scopeSpans": [{"spans": [
            {"traceId": "aa", "spanId": "01", "name": "invoke_agent",
             "startTimeUnixNano": "1000", "endTimeUnixNano": "2000",
             "attributes": [
                 {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}},
                 {"key": "gen_ai.agent.id", "value": {"stringValue": "planner"}}]},
            {"traceId": "aa", "spanId": "02", "parentSpanId": "01", "name": "chat",
             "startTimeUnixNano": "1100", "endTimeUnixNano": "1500",
             "attributes": [
                 {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                 {"key": "gen_ai.request.model", "value": {"stringValue": "some-model"}}]},
        ]}],
    }]
}

# A case that clears every structural analyser: two independent producers, typed
# verification that passed, and a claim whose support the case actually holds.
CLEAN_ENVELOPE = [
    {"record_type": "claim", "claim_id": "cl_root",
     "proposition": "the migration applies without data loss", "is_root": True,
     "producer": {"producer_id": "agent://planner/7", "kind": "agent"},
     "supporting_evidence": ["ev_sim", "ev_review"],
     "verification_attempts": [
         {"evidence_id": "ev_sim", "method": "SIMULATION", "outcome": "PASSED"},
         {"evidence_id": "ev_review", "method": "HUMAN_REVIEW", "outcome": "PASSED"}]},
    {"record_type": "evidence", "evidence_id": "ev_sim", "kind": "SIMULATION_RESULT",
     "producer": {"producer_id": "ci://sim/44", "kind": "tool"},
     "supports_claims": ["cl_root"], "coverage_note": "schema and row counts"},
    {"record_type": "evidence", "evidence_id": "ev_review", "kind": "HUMAN_REVIEW",
     "producer": {"producer_id": "person://dba", "kind": "human"},
     "supports_claims": ["cl_root"], "coverage_note": "reviewed by hand"},
]

REFUTED_ENVELOPE = [
    {"record_type": "claim", "claim_id": "cl_root", "proposition": "the migration is safe",
     "is_root": True, "producer": {"producer_id": "agent://planner/7", "kind": "agent"},
     "contradicting_evidence": ["ev_bad"],
     "verification_attempts": [
         {"evidence_id": "ev_bad", "method": "TEST_SUITE", "outcome": "FAILED"}]},
    {"record_type": "evidence", "evidence_id": "ev_bad", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://run/1", "kind": "tool"},
     "contradicts_claims": ["cl_root"], "coverage_note": "integration suite"},
]


def _write(tmp_path, name, payload):
    path = tmp_path / name
    if name.endswith(".jsonl"):
        path.write_text("\n".join(json.dumps(row) for row in payload) + "\n")
    else:
        path.write_text(json.dumps(payload))
    return str(path)


@pytest.fixture
def otlp_file(tmp_path):
    return _write(tmp_path, "trace.json", OTLP)


@pytest.fixture
def clean_file(tmp_path):
    return _write(tmp_path, "clean.jsonl", CLEAN_ENVELOPE)


@pytest.fixture
def refuted_file(tmp_path):
    return _write(tmp_path, "refuted.jsonl", REFUTED_ENVELOPE)


@pytest.fixture
def general_methodology():
    return default_registry().latest("general-agent-action")


# ── the limit ────────────────────────────────────────────────────────────────

class TestZeroConfigNeverAuthorises:
    """The single most important property in this module."""

    def test_a_flawless_case_still_holds_without_a_methodology(self, clean_file):
        outcome = assure(clean_file)
        assert outcome.analysis.blocking == ()
        assert outcome.analysis.holding == ()
        assert outcome.decision is Decision.HOLD
        assert "RG-ZC-001" in outcome.case.verdict.fired_rules

    def test_the_same_case_can_promote_once_a_methodology_is_supplied(
            self, clean_file, general_methodology):
        outcome = assure(clean_file, methodology=general_methodology)
        assert outcome.decision is Decision.PROMOTE, (
            "the PROMOTE branch must be reachable; a gate that can only refuse is "
            "not a gate, it is an outage")

    def test_no_input_reaches_promote_without_a_methodology(
            self, clean_file, otlp_file, refuted_file, tmp_path):
        mystery = _write(tmp_path, "mystery.json", {"hello": "world"})
        for path in (clean_file, otlp_file, refuted_file, mystery):
            assert assure(path).decision is not Decision.PROMOTE

    def test_the_decision_function_refuses_to_promote_unbacked(self, clean_file):
        from release_gate.assurance import zero_config

        outcome = assure(clean_file, methodology=default_registry().latest(
            "general-agent-action"))
        with pytest.raises(ZeroConfigError, match="cannot authorise"):
            zero_config.decide(outcome.analysis, outcome.assessment,
                               has_methodology=False)

    def test_methodology_required_is_reported_verbatim(self, clean_file):
        outcome = assure(clean_file)
        assert outcome.assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED
        assert any("METHODOLOGY_REQUIRED" in r for r in outcome.case.verdict.reasons)
        assert "METHODOLOGY_REQUIRED" in render_text(outcome)

    def test_refusal_needs_no_methodology(self, refuted_file):
        """BLOCK is a fact about the evidence; PROMOTE is a claim about a domain."""
        outcome = assure(refuted_file)
        assert outcome.decision is Decision.BLOCK
        assert "RG-CONTRA-002" in outcome.case.verdict.fired_rules


# ── detection ────────────────────────────────────────────────────────────────

class TestDetection:

    def test_otlp_is_recognised(self):
        detection = detect_document(OTLP)
        assert detection.kind is InputKind.OTLP_TRACE
        assert detection.confidence >= 50
        assert detection.recognised

    def test_envelope_is_recognised(self):
        detection = detect_document(CLEAN_ENVELOPE)
        assert detection.kind is InputKind.ASSURANCE_ENVELOPE

    def test_audit_report_is_recognised(self):
        detection = detect_document({"score": 82, "decision": "PROMOTE",
                                     "code_findings": [], "safeguards": {}})
        assert detection.kind is InputKind.AUDIT_REPORT

    def test_an_unknown_document_is_not_forced_into_a_format(self):
        detection = detect_document({"hello": "world"}, filename="x.json")
        assert detection.kind is InputKind.UNRECOGNISED
        assert not detection.recognised

    def test_detection_always_states_its_basis(self):
        for doc in (OTLP, CLEAN_ENVELOPE, {"hello": "world"}):
            assert detect_document(doc).basis.strip()

    def test_unrecognised_is_not_an_error(self, tmp_path):
        path = _write(tmp_path, "mystery.json", {"hello": "world"})
        outcome = assure(path)
        assert outcome.detection.kind is InputKind.UNRECOGNISED
        assert outcome.case.verdict is not None

    def test_unreadable_input_is_an_error(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not json at all")
        with pytest.raises(IngestError):
            ingest_path(str(path))

    def test_missing_file_is_an_error(self):
        with pytest.raises(IngestError):
            ingest_path("/nonexistent/nowhere.json")

    def test_every_input_kind_maps_to_a_subject_type(self):
        for kind in InputKind:
            assert subject_type_for(kind) is not None


# ── the epistemic boundary ───────────────────────────────────────────────────

class TestIngestBoundary:

    def test_a_producer_cannot_declare_its_own_evidence_verified(self, tmp_path):
        path = _write(tmp_path, "claimy.jsonl", [
            {"record_type": "evidence", "evidence_id": "ev_1", "kind": "TEST_RESULT",
             "epistemic_status": "VERIFIED", "verified": True,
             "producer": {"producer_id": "agent://x", "kind": "agent"}}])
        normalisation = ingest_path(path)
        ingested = [r for r in normalisation.evidence
                    if r.producer.kind is not ProducerKind.RELEASE_GATE]
        assert ingested, "the record should be kept, not discarded"
        record = ingested[0]
        assert record.epistemic_status is EpistemicStatus.DECLARED
        assert record.content["producer_claimed_epistemic_status"] == "VERIFIED"
        assert record.content["producer_claimed_verified"] is True

    def test_the_file_digest_is_observed_not_declared(self, otlp_file):
        normalisation = ingest_path(otlp_file)
        own = [r for r in normalisation.evidence
               if r.producer.kind is ProducerKind.RELEASE_GATE]
        assert own and own[0].epistemic_status is EpistemicStatus.OBSERVED

    def test_trace_contents_are_declared_not_observed(self, otlp_file):
        """We read the file. We did not watch the run."""
        normalisation = ingest_path(otlp_file)
        traces = [r for r in normalisation.evidence
                  if r.evidence_type.value == "TRACE"]
        assert traces
        assert all(r.epistemic_status is EpistemicStatus.DECLARED for r in traces)

    def test_a_payload_cannot_declare_itself_release_gate(self, tmp_path):
        path = _write(tmp_path, "spoof.jsonl", [
            {"record_type": "evidence", "evidence_id": "ev_1", "kind": "TEST_RESULT",
             "producer": {"producer_id": "release-gate/audit", "kind": "release_gate"}}])
        normalisation = ingest_path(path)
        spoofed = [r for r in normalisation.evidence
                   if r.producer.producer_id == "release-gate/audit"]
        assert spoofed and spoofed[0].producer.kind is ProducerKind.EXTERNAL

    def test_producer_identity_is_never_authenticated_from_a_file(self, clean_file):
        normalisation = ingest_path(clean_file)
        external = [r for r in normalisation.evidence
                    if r.producer.kind is not ProducerKind.RELEASE_GATE]
        assert external
        assert all(r.producer.identity_basis == "unauthenticated" for r in external)

    def test_per_record_producers_are_read(self, clean_file):
        normalisation = ingest_path(clean_file)
        ids = {r.producer.producer_id for r in normalisation.evidence}
        assert {"ci://sim/44", "person://dba"} <= ids, (
            "a file is a container, not an author")

    def test_declared_evidence_ids_resolve_to_real_records(self, clean_file):
        """Otherwise a supported claim would look unsupported."""
        normalisation = ingest_path(clean_file)
        held = {r.evidence_id for r in normalisation.evidence}
        claim = normalisation.claims[0]
        assert set(claim.supporting_evidence) <= held
        assert all(a.evidence_id in held for a in claim.verification_attempts)

    def test_unmappable_records_are_counted_not_dropped_silently(self, tmp_path):
        path = _write(tmp_path, "mixed.jsonl", CLEAN_ENVELOPE + [
            {"record_type": "nonsense", "x": 1}])
        normalisation = ingest_path(path)
        assert normalisation.skipped_total == 1
        assert any("nonsense" in reason for reason in normalisation.skipped)


# ── analysers ────────────────────────────────────────────────────────────────

class TestStructuralAnalysis:

    def _rules(self, outcome):
        return {f.rule_id for f in outcome.analysis.findings}

    def test_refuted_claim_blocks(self, refuted_file):
        outcome = assure(refuted_file)
        assert "RG-CONTRA-002" in self._rules(outcome)
        assert outcome.analysis.blocking

    def test_failed_verification_is_evidence_not_absence(self, refuted_file):
        outcome = assure(refuted_file)
        finding = next(f for f in outcome.analysis.findings if f.rule_id == "RG-VERIF-002")
        assert finding.effect is RequirementEffect.BLOCK
        assert "cl_root" in finding.refs

    def test_conflicting_verification_attempts_are_reported(self, tmp_path):
        path = _write(tmp_path, "conflict.jsonl", [
            {"record_type": "claim", "claim_id": "cl_a", "proposition": "p",
             "producer": {"producer_id": "agent://x", "kind": "agent"},
             "verification_attempts": [
                 {"evidence_id": "", "method": "TEST_SUITE", "outcome": "PASSED"},
                 {"evidence_id": "", "method": "TEST_SUITE", "outcome": "FAILED"}]}])
        assert "RG-VERIF-003" in self._rules(assure(path))

    def test_nothing_verified_is_a_hold(self, otlp_file):
        outcome = assure(otlp_file)
        assert "RG-VERIF-001" in self._rules(outcome)

    def test_single_producer_is_not_corroboration(self, otlp_file):
        outcome = assure(otlp_file)
        finding = next(f for f in outcome.analysis.findings if f.rule_id == "RG-PROV-002")
        assert finding.effect is RequirementEffect.HOLD

    def test_multiple_producers_clear_the_independence_finding(self, clean_file):
        assert "RG-PROV-002" not in self._rules(assure(clean_file))

    def test_unauthenticated_producers_are_advisory_not_blocking(self, clean_file):
        finding = next(f for f in assure(clean_file).analysis.findings
                       if f.rule_id == "RG-PROV-001")
        assert finding.effect is RequirementEffect.ADVISORY

    def test_unsupported_claim_is_a_gap_not_a_falsehood(self, tmp_path):
        path = _write(tmp_path, "orphan.jsonl", [
            {"record_type": "claim", "claim_id": "cl_orphan", "proposition": "unbacked",
             "producer": {"producer_id": "agent://x", "kind": "agent"}}])
        finding = next(f for f in assure(path).analysis.findings
                       if f.rule_id == "RG-COV-003")
        assert finding.effect is RequirementEffect.HOLD
        assert "cl_orphan" in finding.refs

    def test_unrecognised_input_is_a_coverage_finding(self, tmp_path):
        path = _write(tmp_path, "mystery.json", {"hello": "world"})
        assert "RG-COV-001" in self._rules(assure(path))

    def test_skipped_records_surface_as_coverage(self, tmp_path):
        path = _write(tmp_path, "mixed.jsonl", CLEAN_ENVELOPE + [
            {"record_type": "nonsense", "x": 1}])
        assert "RG-COV-002" in self._rules(assure(path))

    def test_execution_completeness_unknown_is_advisory_not_a_failure(self, otlp_file):
        outcome = assure(otlp_file)
        finding = next((f for f in outcome.analysis.findings
                        if f.rule_id == "RG-COV-004"), None)
        assert finding is not None
        assert finding.effect is RequirementEffect.ADVISORY

    def test_a_moved_subject_blocks(self, tmp_path):
        path = _write(tmp_path, "trace.json", OTLP)
        outcome = assure(path)
        assert "RG-DRIFT-001" not in {f.rule_id for f in outcome.analysis.findings}
        # Change the file underneath the sealed case and re-check.
        (tmp_path / "trace.json").write_text(json.dumps({"resourceSpans": []}))
        recheck = outcome.case.check_subject()
        assert recheck.status.value == "MUTATED"

    def test_every_finding_names_a_remedy(self, refuted_file, otlp_file, clean_file):
        for path in (refuted_file, otlp_file, clean_file):
            for finding in assure(path).analysis.findings:
                assert finding.remedy.strip(), f"{finding.rule_id} has no remedy"

    def test_findings_are_ordered_deterministically(self, refuted_file):
        first = [f.rule_id for f in assure(refuted_file).analysis.findings]
        second = [f.rule_id for f in assure(refuted_file).analysis.findings]
        assert first == second == sorted(
            first, key=lambda r: (r.split("-")[1], r))


# ── attention ────────────────────────────────────────────────────────────────

class TestHumanAttention:

    def test_findings_on_one_thing_collapse_to_one_inspection(self, refuted_file):
        outcome = assure(refuted_file)
        item = next(i for i in outcome.attention if i.focus == "cl_root")
        assert item.leverage >= 2
        assert {"RG-CONTRA-002", "RG-VERIF-002"} <= set(item.rule_ids)

    def test_the_hardest_item_comes_first(self, refuted_file):
        items = list(assure(refuted_file).attention)
        assert items[0].effect is RequirementEffect.BLOCK

    def test_advisory_findings_do_not_create_attention_items(self, clean_file):
        outcome = assure(clean_file)
        assert any(f.effect is RequirementEffect.ADVISORY
                   for f in outcome.analysis.findings)
        assert all(i.effect is not RequirementEffect.ADVISORY for i in outcome.attention)

    def test_a_missing_methodology_is_itself_an_attention_item(self, clean_file):
        outcome = assure(clean_file)
        item = next(i for i in outcome.attention
                    if i.reason is AttentionReason.METHODOLOGY_ABSENT)
        assert item.effect is RequirementEffect.HOLD

    def test_producer_findings_point_at_the_producer_not_a_record(self, otlp_file):
        item = next(i for i in assure(otlp_file).attention
                    if "RG-PROV-002" in i.rule_ids)
        assert item.focus_kind == "producer"
        assert item.focus == "RG-PROV-002"

    def test_unmet_requirements_become_attention_items(self, otlp_file,
                                                       general_methodology):
        outcome = assure(otlp_file, methodology=general_methodology)
        reasons = {i.reason for i in outcome.attention}
        assert AttentionReason.METHODOLOGY_ABSENT not in reasons

    def test_attention_is_deterministic(self, refuted_file):
        a = [i.item_id for i in assure(refuted_file).attention]
        b = [i.item_id for i in assure(refuted_file).attention]
        assert a == b


class TestRequiredEvidence:

    def test_a_methodology_is_the_first_thing_required(self, clean_file):
        required = assure(clean_file).required_evidence
        assert required.methodology_required
        assert list(required)[0].requirement_id == "req_methodology"

    def test_it_never_promises_that_supplying_them_yields_promote(self, clean_file):
        note = assure(clean_file).required_evidence.note
        assert "not a list that, once satisfied, yields PROMOTE" in note

    def test_two_findings_with_one_remedy_are_one_errand(self, tmp_path):
        path = _write(tmp_path, "two.jsonl", [
            {"record_type": "claim", "claim_id": "cl_a", "proposition": "a",
             "producer": {"producer_id": "agent://x", "kind": "agent"}},
            {"record_type": "claim", "claim_id": "cl_b", "proposition": "b",
             "producer": {"producer_id": "agent://x", "kind": "agent"}}])
        required = assure(path).required_evidence
        whats = [i.what for i in required]
        assert len(whats) == len(set(whats))

    def test_non_monotone_items_are_flagged(self, refuted_file):
        required = assure(refuted_file).required_evidence
        contradiction = next(i for i in required if "RG-CONTRA-002" in i.resolves)
        assert contradiction.monotone is False, (
            "resolving a contradiction can be undone by later evidence")

    def test_at_least_checks_are_monotone(self, clean_file):
        required = assure(clean_file).required_evidence
        assert next(i for i in required
                    if i.requirement_id == "req_methodology").monotone is True


# ── the case that comes out ──────────────────────────────────────────────────

class TestOutcomeCase:

    def test_the_case_is_sealed_and_carries_a_verdict(self, otlp_file):
        case = assure(otlp_file).case
        assert case.state.value == "SEALED"
        assert case.verdict is not None

    def test_coverage_is_always_present(self, otlp_file, clean_file, tmp_path):
        mystery = _write(tmp_path, "m.json", {"hello": "world"})
        for path in (otlp_file, clean_file, mystery):
            coverage = assure(path).case.collection("coverage")
            assert coverage.total_count > 0

    def test_domain_sufficiency_is_always_recorded_as_not_assessed(self, clean_file):
        rows = [r.to_dict() for r in assure(clean_file).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "domain_sufficiency")
        assert row["status"] == "NOT_ASSESSED"

    def test_overall_coverage_is_stated_as_partial(self, clean_file):
        rows = [r.to_dict() for r in assure(clean_file).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "overall")
        assert row["status"] == "NOT_ASSESSED"
        assert "domain_sufficiency" in row["not_assessed_dimensions"]

    def test_the_verdict_names_its_rules(self, otlp_file, refuted_file):
        for path in (otlp_file, refuted_file):
            assert assure(path).case.verdict.fired_rules

    def test_the_same_file_produces_the_same_case_digest(self, clean_file):
        assert assure(clean_file).case.case_digest == assure(clean_file).case.case_digest

    def test_a_different_file_produces_a_different_subject(self, clean_file, otlp_file):
        assert assure(clean_file).case.subject_digest != assure(otlp_file).case.subject_digest

    def test_the_case_records_that_it_was_built_with_no_config(self, otlp_file):
        metadata = dict(assure(otlp_file).case.metadata)
        assert metadata["zero_config"] is True
        assert metadata["ruleset_version"] == ZERO_CONFIG_RULESET_VERSION

    def test_a_default_objective_is_labelled_as_a_default(self, otlp_file):
        assert dict(assure(otlp_file).case.metadata)["objective_basis"] == "default"
        supplied = assure(otlp_file, objective="Ship the planner change")
        assert dict(supplied.case.metadata)["objective_basis"] == "supplied"

    def test_present_but_empty_is_not_absent(self, otlp_file):
        """Nobody supplied claims, but the ingest looked — that is a finding."""
        case = assure(otlp_file).case
        assert "claims" not in case.absent_collections
        assert case.collection("claims").total_count == 0

    def test_the_case_round_trips_through_json(self, clean_file):
        case = assure(clean_file).case
        assert json.loads(json.dumps(case.to_dict()))["case_id"] == case.case_id


class TestOutputs:

    def test_exit_codes_follow_the_cli_convention(self):
        assert exit_code_for(Decision.PROMOTE) == 0
        assert exit_code_for(Decision.HOLD) == 10
        assert exit_code_for(Decision.BLOCK) == 1

    def test_the_outcome_serialises(self, refuted_file):
        payload = json.loads(json.dumps(assure(refuted_file).to_dict()))
        assert payload["decision"] == "BLOCK"
        assert payload["ruleset_version"] == ZERO_CONFIG_RULESET_VERSION

    def test_the_report_states_coverage_beside_the_decision(self, otlp_file):
        text = render_text(assure(otlp_file))
        assert "WHAT WAS ASSESSED" in text
        assert "NOT_ASSESSED" in text
        assert "Decision:" in text

    def test_advisory_findings_are_hidden_until_asked_for(self, clean_file):
        outcome = assure(clean_file)
        assert "RG-PROV-001" not in render_text(outcome)
        assert "RG-PROV-001" in render_text(outcome, full=True)


PROMPTFOO = {
    "evalId": "eval-1",
    "results": [
        {"success": True, "gradingResult": {"pass": True},
         "testCase": {"description": "refuses harmful request",
                      "metadata": {"severity": "critical"}}},
        {"success": False, "gradingResult": {"pass": False, "reason": "drifted"},
         "testCase": {"description": "stays on topic"}},
    ],
}


class TestEvalIngestion:
    """A failing eval case must reach the verdict, not vanish into an aggregate."""

    @pytest.fixture
    def eval_file(self, tmp_path):
        return _write(tmp_path, "evals.json", PROMPTFOO)

    def test_eval_runs_are_recognised(self, eval_file):
        assert ingest_path(eval_file).detection.kind is InputKind.PROMPTFOO_EVAL

    def test_every_case_becomes_a_claim(self, eval_file):
        normalisation = ingest_path(eval_file)
        assert normalisation.records_seen == 2
        assert normalisation.records_mapped == 2
        assert len(normalisation.claims) == 2

    def test_a_failing_case_blocks(self, eval_file):
        outcome = assure(eval_file)
        assert outcome.decision is Decision.BLOCK
        assert "RG-VERIF-002" in {f.rule_id for f in outcome.analysis.findings}

    def test_the_failing_case_is_what_a_human_is_pointed_at(self, eval_file):
        item = list(assure(eval_file).attention)[0]
        assert item.focus == "cl_eval_1"
        assert item.leverage >= 2

    def test_eval_outcomes_are_declared_not_verified(self, eval_file):
        """release-gate did not re-run the suite; it read a report of it."""
        records = [r for r in ingest_path(eval_file).evidence
                   if r.evidence_type.value == "EVAL_RESULT"]
        assert records
        assert all(r.epistemic_status is EpistemicStatus.DECLARED for r in records)

    def test_verification_attempts_resolve_to_held_records(self, eval_file):
        normalisation = ingest_path(eval_file)
        held = {r.evidence_id for r in normalisation.evidence}
        for claim in normalisation.claims:
            for attempt in claim.verification_attempts:
                assert attempt.evidence_id in held
