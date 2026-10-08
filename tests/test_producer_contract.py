"""The evidence producer contract.

Release-gate reads evidence from systems it does not control and will never
enumerate. These tests hold the boundary those systems meet:

  * a producer states what its evidence means before any arrives, and a
    declaration without limits is refused;
  * an adapter reports what the producer said, and only the normaliser writes a
    record — so no adapter can upgrade an epistemic status, translate a severity,
    turn a count into a percentage or a decision into a verdict;
  * source fields an adapter did not map are kept, bounded, and named when they
    do not fit;
  * a new producer is a registration, never an edit to the ingest or the
    decision path.

The three semantic cases named when this was asked for are pinned as tests:
promptfoo's `47 / 50` stays "47 of 50 declared" and never becomes 94%; a review
bot's "review" stays that bot's decision and never becomes HOLD; a SonarQube
`CRITICAL` stays SonarQube's `CRITICAL`.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from release_gate.assurance.evidence import EpistemicStatus, EvidenceType, TrustStatus
from release_gate.assurance.producer_adapters import (
    EXTERNAL_DECISION_DECLARATION, PROMPTFOO_DECLARATION, SARIF_DECLARATION)
from release_gate.assurance.producer_contract import (
    MAX_NATIVE_FIELDS, MAX_NATIVE_STRING, AdapterOutput, ConfidenceSemantics,
    CoverageSemantics, Determinism, EvidenceAdapter, Measurement, NativeResult,
    ProducerContractError, ProducerDeclaration, ProducerIdentity, ProducerRegistry,
    ResultKind, check_adapter_contract, default_producer_registry, normalise_output)
from release_gate.assurance.producers import EvidenceLane

ROOT = Path(__file__).resolve().parent.parent


# ── samples, one per built-in adapter ────────────────────────────────────────

def promptfoo_run(passed: int = 47, total: int = 50, *, stats: bool = True,
                  extra: Any = None) -> dict:
    rows = []
    for i in range(total):
        row = {"success": i < passed, "score": 1 if i < passed else 0,
               "testCase": {"description": f"case {i}"},
               "provider": {"id": "openai:gpt-4o"},
               "prompt": {"raw": "You are a support agent.", "label": "support"},
               "latencyMs": 812 + i, "cost": 0.0004}
        if extra:
            row.update(extra)
        rows.append(row)
    inner = {"version": 3, "timestamp": "2026-10-01T10:00:00Z", "results": rows}
    if stats:
        inner["stats"] = {"successes": passed, "failures": total - passed, "errors": 0}
    return {"evalId": "eval-2026-10-01", "results": inner}


SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "SonarQube", "version": "10.6",
                            "organization": "SonarSource"}},
        "versionControlProvenance": [{"repositoryUri": "https://github.com/acme/agent",
                                      "revisionId": "9F2C1A7"}],
        "results": [{
            "ruleId": "python:S5332", "level": "error", "kind": "fail",
            "message": {"text": "Using http protocol is insecure."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/client.py"},
                "region": {"startLine": 12}}}],
            "properties": {"severity": "CRITICAL", "sonarType": "VULNERABILITY"}}]}]}


def decision(word: str) -> dict:
    return {"external_decision": {
        "producer": {"id": "proofagent", "version": "1.4.0"},
        "decision": word, "subject": "PR #418",
        "vocabulary": ["approve", "review", "reject"],
        "rationale": "two findings need a human",
        "state": {"commit": "9f2c1a7"},
        "issued_at": "2026-10-01T09:12:00Z",
        "reviewer_queue": "payments"}}


def _example(name: str) -> dict:
    return json.loads((ROOT / "examples" / "evidence" / name).read_text(encoding="utf-8"))


SAMPLES = {
    "promptfoo": promptfoo_run(),
    "sarif": SARIF,
    "external_decision": decision("review"),
    # The five generic contracts (reference_adapters.py), read from the shipped
    # examples so the documented fixtures are the ones held to the contract.
    "eval": _example("eval.json"),
    "red_team": _example("red-team.json"),
    "sast": _example("sast.json"),
    "human_review": _example("review.json"),
    "behavior": _example("behavior.json"),
}


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _assure(tmp_path, doc, name="input.json", producers=None, methodology=None):
    from release_gate.assurance.zero_config import assure
    return assure(str(_write(tmp_path, name, doc)), producers=producers,
                  methodology=methodology)


def _records(outcome, producer_type):
    return [e for e in outcome.normalisation.evidence
            if (e.metadata or {}).get("producer_type") == producer_type]


def _walk(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _walk(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _walk(v)
    else:
        yield value


# ── the declaration ──────────────────────────────────────────────────────────

def _declaration(**over) -> ProducerDeclaration:
    fields = dict(
        producer_type="acme_risk", label="Acme risk engine", origin="Acme Corp",
        modality=EvidenceLane.EXTERNAL_EVIDENCE, determinism=Determinism.DETERMINISTIC,
        evidence_types=(EvidenceType.ATTESTATION,),
        supported_claims=("that Acme scored a change",),
        confidence=ConfidenceSemantics.PRODUCER_SCORE,
        coverage=CoverageSemantics.UNSTATED,
        limitations=("that the score measures risk",))
    fields.update(over)
    return ProducerDeclaration(**fields)


class TestTheDeclaration:

    def test_every_field_the_contract_names_is_declared(self):
        d = _declaration().to_dict()
        for key in ("producer_type", "origin", "modality", "determinism",
                    "evidence_types", "supported_claims", "confidence", "coverage",
                    "limitations", "independence", "default_producer_id"):
            assert key in d, key

    def test_a_producer_with_no_limits_is_refused(self):
        with pytest.raises(ProducerContractError, match="cannot establish"):
            _declaration(limitations=())

    def test_a_producer_that_may_emit_anything_is_refused(self):
        with pytest.raises(ProducerContractError):
            _declaration(evidence_types=())

    def test_the_type_is_a_key_not_a_label(self):
        with pytest.raises(ProducerContractError):
            _declaration(producer_type="Acme Risk Engine!")

    def test_the_modality_is_an_existing_lane(self):
        assert _declaration().lane.lane is EvidenceLane.EXTERNAL_EVIDENCE

    def test_a_document_cannot_declare_an_unknown_modality(self):
        with pytest.raises(ProducerContractError):
            ProducerDeclaration.from_dict({**_declaration().to_dict(),
                                           "modality": "VIBES"})

    def test_it_round_trips_and_its_digest_is_stable(self):
        d = _declaration()
        back = ProducerDeclaration.from_dict(d.to_dict())
        assert back == d and back.digest() == d.digest()

    def test_independence_unstated_is_not_either_answer(self):
        assert _declaration().independence.independent_of_subject is None


class TestTheMeasurement:

    def test_it_reads_as_the_producers_declared_count(self):
        m = Measurement(count=47, of=50, unit="test cases", outcome="passed")
        assert m.statement("promptfoo") == (
            "promptfoo reported 47 of 50 declared test cases passed")

    def test_an_undeclared_total_is_said(self):
        m = Measurement(count=3, of=None, unit="findings", outcome="reported")
        assert "an undeclared number of" in m.statement("x")

    def test_it_carries_no_ratio(self):
        assert set(Measurement(47, 50, "test cases", "passed").to_dict()) == {
            "count", "of", "unit", "outcome", "denominator_basis"}

    @pytest.mark.parametrize("count,of", [(51, 50), (-1, 5), (True, 5), (1.5, 2)])
    def test_an_impossible_count_is_refused(self, count, of):
        with pytest.raises(ProducerContractError):
            Measurement(count=count, of=of, unit="x", outcome="y")


# ── the three named cases ───────────────────────────────────────────────────

class TestPromptfooStaysACount:

    def test_47_of_50_is_47_of_50_declared(self, tmp_path):
        outcome = _assure(tmp_path, promptfoo_run(47, 50))
        [measured] = [e for e in _records(outcome, "promptfoo")
                      if e.content["result_kind"] == "MEASUREMENT"]
        assert measured.content["measurement"]["count"] == 47
        assert measured.content["measurement"]["of"] == 50
        assert measured.content["observation"] == (
            "promptfoo reported 47 of 50 declared test cases passed")

    def test_no_percentage_or_rate_is_derived_anywhere(self, tmp_path):
        outcome = _assure(tmp_path, promptfoo_run(47, 50))
        for record in _records(outcome, "promptfoo"):
            content = json.loads(json.dumps(record.to_dict()["content"], default=str))
            values = list(_walk({k: v for k, v in content.items() if k != "native"}))
            assert 0.94 not in values and 94 not in values and 94.0 not in values
            assert not any("%" in str(v) for v in values)
            assert not any("safe" in str(v).lower() for v in values
                           if isinstance(v, str) and "does not" not in v.lower())

    def test_without_the_producers_totals_no_count_is_invented(self, tmp_path):
        """47 of 50 is promptfoo's figure only when promptfoo states it."""
        outcome = _assure(tmp_path, promptfoo_run(47, 50, stats=False))
        assert not [e for e in _records(outcome, "promptfoo")
                    if e.content["result_kind"] == "MEASUREMENT"]

    def test_a_disagreeing_total_is_kept_and_said(self, tmp_path):
        doc = promptfoo_run(47, 50)
        doc["results"]["stats"]["failures"] = 5
        outcome = _assure(tmp_path, doc)
        assert any("promptfoo's own totals count 52" in n
                   for n in outcome.normalisation.notes)

    def test_each_case_is_still_its_own_declared_check(self, tmp_path):
        outcome = _assure(tmp_path, promptfoo_run(2, 3))
        checks = [e for e in _records(outcome, "promptfoo")
                  if e.content["result_kind"] == "CHECK"]
        assert len(checks) == 3
        assert all(e.epistemic_status is EpistemicStatus.DECLARED for e in checks)
        assert [c.claim_id for c in outcome.normalisation.claims] == [
            "cl_eval_0", "cl_eval_1", "cl_eval_2"]

    def test_the_results_schema_is_not_reported_as_the_tools_version(self, tmp_path):
        outcome = _assure(tmp_path, promptfoo_run(1, 1))
        assert all(e.producer.version is None for e in _records(outcome, "promptfoo"))


class TestAnExternalDecisionIsNotAVerdict:

    def test_review_is_recorded_as_proofagents_decision(self, tmp_path):
        outcome = _assure(tmp_path, decision("review"))
        [record] = _records(outcome, "external_decision")
        assert record.producer.producer_id == "proofagent"
        assert record.producer.version == "1.4.0"
        assert record.evidence_type is EvidenceType.ATTESTATION
        assert record.epistemic_status is EpistemicStatus.DECLARED
        assert record.content["external_decision"] == {
            "decision": "review", "decided_by": "proofagent",
            "is_release_gate_verdict": False}
        assert not record.supports_claims and not record.contradicts_claims

    def test_the_decisions_word_never_moves_release_gates(self, tmp_path):
        """Same document, three words. One verdict, because none is adopted."""
        verdicts = {word: _assure(tmp_path, decision(word), f"{word}.json"
                                  ).case.verdict.decision.value
                    for word in ("approve", "review", "reject", "HOLD", "BLOCK")}
        assert len(set(verdicts.values())) == 1, verdicts

    def test_a_decision_cannot_propose_a_claim(self):
        with pytest.raises(ProducerContractError, match="not adopting"):
            NativeResult(kind=ResultKind.DECISION, native_id="d1",
                         native_outcome="approve", claim_statement="it is fine")

    def test_its_clock_is_kept_as_its_claim(self, tmp_path):
        [record] = _records(_assure(tmp_path, decision("review")), "external_decision")
        assert record.metadata["declared_timestamp"] == "2026-10-01T09:12:00Z"
        assert record.stamped_on_arrival


class TestASonarFindingStaysSonars:

    def test_it_keeps_its_tool_rule_and_severity(self, tmp_path):
        [record] = _records(_assure(tmp_path, SARIF, "scan.sarif.json"), "sarif")
        assert record.producer.producer_id == "SonarQube"
        assert record.producer.version == "10.6"
        assert record.content["native_id"] == "python:S5332"
        assert record.content["native_severity"] == "CRITICAL"
        assert record.content["native"]["level"] == "error"
        assert "CRITICAL" in record.content["observation"]

    def test_no_release_gate_severity_or_rule_is_assigned(self, tmp_path):
        [record] = _records(_assure(tmp_path, SARIF, "scan.sarif.json"), "sarif")
        assert "severity" not in record.content and "rule_id" not in record.content

    def test_it_argues_about_no_release_gate_claim(self, tmp_path):
        outcome = _assure(tmp_path, SARIF, "scan.sarif.json")
        [record] = _records(outcome, "sarif")
        assert not record.supports_claims and not record.contradicts_claims
        assert not outcome.normalisation.claims

    def test_it_carries_the_state_the_tool_says_it_scanned(self, tmp_path):
        [record] = _records(_assure(tmp_path, SARIF, "scan.sarif.json"), "sarif")
        assert record.content["state"] == {
            "repository": "https://github.com/acme/agent", "commit": "9f2c1a7"}

    def test_two_tools_in_one_log_stay_two_producers(self, tmp_path):
        doc = json.loads(json.dumps(SARIF))
        second = json.loads(json.dumps(SARIF["runs"][0]))
        second["tool"]["driver"] = {"name": "Semgrep", "semanticVersion": "1.80.0"}
        doc["runs"].append(second)
        records = _records(_assure(tmp_path, doc, "two.sarif.json"), "sarif")
        assert {(r.producer.producer_id, r.producer.version) for r in records} == {
            ("SonarQube", "10.6"), ("Semgrep", "1.80.0")}


# ── unknown fields are kept ──────────────────────────────────────────────────

class TestSourceFieldsAreKept:

    def test_fields_no_adapter_maps_travel_as_native(self, tmp_path):
        doc = promptfoo_run(1, 1, extra={"x_acme_ticket": "RISK-81",
                                         "namedScores": {"tone": 0.9}})
        [check] = [e for e in _records(_assure(tmp_path, doc), "promptfoo")
                   if e.content["result_kind"] == "CHECK"]
        native = check.content["native"]
        assert native["x_acme_ticket"] == "RISK-81"
        assert native["namedScores"] == {"tone": 0.9}
        assert native["latencyMs"] == 812

    def test_an_oversized_field_is_truncated_and_marked(self, tmp_path):
        doc = promptfoo_run(1, 1, extra={"x_acme_trace": {"id": "x" * (MAX_NATIVE_STRING + 50)}})
        [check] = [e for e in _records(_assure(tmp_path, doc), "promptfoo")
                   if e.content["result_kind"] == "CHECK"]
        kept = check.content["native"]["x_acme_trace"]["id"]
        assert kept.endswith("[truncated 50 chars]")

    def test_content_fields_are_kept_as_digests_not_text(self, tmp_path):
        """The field travels; its text does not. A prompt, a completion, the
        test's vars and the grader's reasoning are each recorded as a digest, so
        a persisted case holds none of them and still shows they were there."""
        secret = "alice@corp.example said the pin is 4417"
        doc = promptfoo_run(1, 1, extra={
            "prompt": {"raw": secret, "label": "p"},
            "response": {"output": secret},
            "vars": {"customer": secret},
            "gradingResult": {"pass": True, "score": 1, "reason": secret}})
        outcome = _assure(tmp_path, doc)
        [check] = [e for e in _records(outcome, "promptfoo")
                   if e.content["result_kind"] == "CHECK"]
        native = check.content["native"]
        assert {"prompt", "response", "vars", "gradingResult"} <= set(native)
        assert native["response"]["redacted"] == "COMPLETION"
        assert native["vars"]["redacted"] == "PROMPT"
        assert native["gradingResult"]["score"] == 1
        assert native["gradingResult"]["reason"]["digest"].startswith("sha256:")
        assert check.content["response"]["redacted"] == "COMPLETION"
        assert secret not in json.dumps(outcome.case.to_dict(), default=str)
        assert secret not in json.dumps(outcome.to_dict(), default=str)

    def test_an_undescribed_case_is_named_without_its_inputs(self, tmp_path):
        """`release-gate score` names it after its vars; a persisted case may not."""
        doc = promptfoo_run(1, 1)
        row = doc["results"]["results"][0]
        row.pop("description", None)
        row.setdefault("testCase", {}).pop("description", None)
        row["prompt"] = {"raw": "You are a support agent."}
        row["testCase"]["vars"] = {"email": "bob@corp.example"}
        row["vars"] = {"email": "bob@corp.example"}
        outcome = _assure(tmp_path, doc)
        [check] = [e for e in _records(outcome, "promptfoo")
                   if e.content["result_kind"] == "CHECK"]
        assert check.content["name"].startswith("promptfoo case 0 (vars ")
        assert "bob@corp.example" not in json.dumps(outcome.case.to_dict(), default=str)
        again = _assure(tmp_path, doc)
        [same] = [e for e in _records(again, "promptfoo")
                  if e.content["result_kind"] == "CHECK"]
        assert same.content["name"] == check.content["name"]

    def test_fields_that_do_not_fit_are_named_not_dropped(self, tmp_path):
        many = {f"f{i:03d}": i for i in range(MAX_NATIVE_FIELDS + 5)}
        doc = promptfoo_run(1, 1, extra=many)
        [check] = [e for e in _records(_assure(tmp_path, doc), "promptfoo")
                   if e.content["result_kind"] == "CHECK"]
        kept = set(check.content["native"])
        omitted = set(check.content["native_omitted"])
        row_keys = set(doc["results"]["results"][0])
        assert kept | omitted == row_keys and not kept & omitted

    def test_a_status_claimed_in_the_source_buys_nothing(self, tmp_path):
        doc = promptfoo_run(1, 1, extra={"epistemic_status": "VERIFIED",
                                         "verified": True, "trust_status": "ACCEPTED"})
        for record in _records(_assure(tmp_path, doc), "promptfoo"):
            assert record.epistemic_status is EpistemicStatus.DECLARED
            assert record.trust_status is TrustStatus.NOT_ESTABLISHED


# ── registration ─────────────────────────────────────────────────────────────

class AcmeAdapter(EvidenceAdapter):
    """A producer this build has never heard of, registered by a caller."""

    declaration = _declaration()

    def detect(self, doc):
        return 97 if isinstance(doc, dict) and "acme_risk" in doc else 0

    def read(self, doc):
        rows = doc["acme_risk"]["scores"]
        return AdapterOutput(
            identity=ProducerIdentity("acme-risk-engine", version="7.2",
                                      origin="Acme Corp",
                                      source_identity=doc["acme_risk"].get("run")),
            results=tuple(NativeResult(kind=ResultKind.ATTESTATION, native_id=r["id"],
                                       native_outcome=str(r["score"]),
                                       native_confidence=r["score"], native=r)
                          for r in rows),
            records_seen=len(rows))


ACME = {"acme_risk": {"run": "r-19", "scores": [
    {"id": "change-1", "score": 0.31, "model": "risk-v4", "region": "eu"}]}}


class TestRegistration:

    def test_a_new_producer_reaches_a_case_by_registration_alone(self, tmp_path):
        registry = default_producer_registry().register(AcmeAdapter())
        outcome = _assure(tmp_path, ACME, producers=registry)
        assert outcome.normalisation.detection.kind.value == "PRODUCER_EXPORT"
        assert outcome.normalisation.detection.adapter == "acme_risk"
        [record] = _records(outcome, "acme_risk")
        assert record.producer.producer_id == "acme-risk-engine"
        assert record.content["confidence"] == {
            "value": 0.31, "semantics": "PRODUCER_SCORE"}
        assert record.metadata["declaration_digest"] == AcmeAdapter.declaration.digest()
        assert outcome.normalisation.records_mapped == outcome.normalisation.records_seen

    def test_without_registration_the_same_file_is_unrecognised(self, tmp_path):
        assert _assure(tmp_path, ACME).normalisation.detection.kind.value == "UNRECOGNISED"

    def test_the_ingest_names_no_registry_producer(self):
        """The seam is real only if the central code does not know who is behind it."""
        source = (ROOT / "release_gate/assurance/ingest.py").read_text(encoding="utf-8")
        strings = {n.value for n in ast.walk(ast.parse(source))
                   if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for producer_type in ("sarif", "external_decision", "acme_risk"):
            assert producer_type not in strings, producer_type

    def test_a_second_adapter_for_one_producer_is_refused(self):
        with pytest.raises(ProducerContractError, match="already registered"):
            default_producer_registry().register(AcmeAdapter()).register(AcmeAdapter())

    def test_a_built_in_cannot_be_replaced(self):
        class Impostor(AcmeAdapter):
            declaration = _declaration(producer_type="sarif",
                                       limitations=("nothing much",))
        with pytest.raises(ProducerContractError):
            default_producer_registry().register(Impostor())

    def test_a_changed_declaration_for_a_known_producer_is_refused(self):
        registry = ProducerRegistry(include_builtin=False).declare(_declaration())
        with pytest.raises(ProducerContractError, match="change what its evidence means"):
            registry.declare(_declaration(limitations=("something else",)))

    def test_registration_order_cannot_change_who_reads_a_document(self):
        class Rival(AcmeAdapter):
            declaration = _declaration(producer_type="acme_rival")

        first = ProducerRegistry(include_builtin=False).register(AcmeAdapter()).register(Rival())
        second = ProducerRegistry(include_builtin=False).register(Rival()).register(AcmeAdapter())
        assert first.detect(ACME) == second.detect(ACME)
        assert first.read(ACME)[0].name == second.read(ACME)[0].name

    def test_an_object_that_is_not_an_adapter_is_refused(self):
        with pytest.raises(ProducerContractError):
            default_producer_registry().register(object())

    def test_the_static_scanner_is_declared_in_the_same_terms(self):
        from release_gate.assurance.producers import lane_for
        from release_gate.assurance.static_producer import STATIC_DECLARATION
        held = default_producer_registry().declaration("release_gate_static")
        assert held == STATIC_DECLARATION
        assert held.limitations == lane_for(EvidenceLane.CODE_SCANNER).cannot_establish


# ── the contract, run over every adapter ─────────────────────────────────────

def _all_adapters():
    return list(default_producer_registry().adapters) + [AcmeAdapter()]


def _sample(adapter):
    return SAMPLES.get(adapter.name) or ACME


class TestEveryAdapterHoldsTheContract:

    def test_every_built_in_has_a_sample_here(self):
        assert {a.name for a in default_producer_registry().adapters} <= set(SAMPLES)

    @pytest.mark.parametrize("adapter", _all_adapters(), ids=lambda a: a.name)
    def test_it_holds(self, adapter):
        report = check_adapter_contract(adapter, _sample(adapter))
        assert report.holds, report.violations

    @pytest.mark.parametrize("adapter", _all_adapters(), ids=lambda a: a.name)
    def test_every_record_is_declared_and_says_what_it_cannot_establish(self, adapter):
        output = adapter.read(_sample(adapter))
        result = normalise_output(output, adapter.declaration, source="s.json")
        assert result.evidence
        for record in result.evidence:
            assert record.epistemic_status is EpistemicStatus.DECLARED
            assert list(record.content["does_not_establish"]) == list(
                adapter.declaration.limitations)
            assert record.metadata["producer_type"] == adapter.name
            assert record.metadata["determinism"] == adapter.declaration.determinism.value


class TestTheContractCatchesBreaches:
    """The check is only worth running if a broken adapter fails it."""

    def _breach(self, **behaviour):
        class Broken(AcmeAdapter):
            declaration = _declaration(producer_type="broken")

            def detect(self, doc):
                if behaviour.get("raise_on_none") and doc is None:
                    raise TypeError("boom")
                return 97 if isinstance(doc, dict) and "acme_risk" in doc else 0

            def read(self, doc):
                out = super().read(doc)
                if behaviour.get("wrong_type"):
                    out = AdapterOutput(out.identity, tuple(
                        NativeResult(kind=r.kind, native_id=r.native_id,
                                     native=r.native,
                                     evidence_type=EvidenceType.FORMAL_PROOF)
                        for r in out.results), out.records_seen)
                if behaviour.get("lose_records"):
                    out = AdapterOutput(out.identity, out.results, records_seen=5)
                if behaviour.get("drop_source"):
                    out = AdapterOutput(out.identity, tuple(
                        NativeResult(kind=r.kind, native_id=r.native_id)
                        for r in out.results), out.records_seen)
                return out
        return check_adapter_contract(Broken(), ACME)

    def test_a_detect_that_raises(self):
        assert any("detect raised" in v for v in self._breach(raise_on_none=True).violations)

    def test_an_undeclared_evidence_type(self):
        assert any("normaliser refused" in v and "does not list" in v
                   for v in self._breach(wrong_type=True).violations)

    def test_records_seen_but_never_accounted_for(self):
        assert any("neither mapped nor counted" in v
                   for v in self._breach(lose_records=True).violations)

    def test_a_result_that_kept_none_of_its_source(self):
        assert any("none of its source fields" in v
                   for v in self._breach(drop_source=True).violations)


# ── a submission can declare its own producers ──────────────────────────────

class TestEnvelopeDeclarations:

    def _envelope(self, *declarations):
        return [*declarations,
                {"record_type": "evidence", "evidence_id": "e1", "kind": "ATTESTATION",
                 "producer": {"producer_id": "acme-risk-engine", "kind": "tool"},
                 "coverage_note": "scored change-1", "score": 0.31}]

    def _declaration_row(self, **over):
        row = {**_declaration().to_dict(), "producer_id": "acme-risk-engine"}
        row.update(over)
        return row

    def test_the_declaration_travels_with_that_producers_evidence(self, tmp_path):
        outcome = _assure(tmp_path, self._envelope(self._declaration_row()), "e.json")
        [record] = [e for e in outcome.normalisation.evidence
                    if e.producer.producer_id == "acme-risk-engine"]
        assert record.metadata["producer_type"] == "acme_risk"
        assert list(record.metadata["declared_limitations"]) == ["that the score measures risk"]
        assert record.epistemic_status is EpistemicStatus.DECLARED
        n = outcome.normalisation
        assert n.records_mapped == n.records_seen and not n.skipped

    def test_two_meanings_for_one_producer_are_refused_not_chosen(self, tmp_path):
        outcome = _assure(tmp_path, self._envelope(
            self._declaration_row(),
            self._declaration_row(limitations=["something else"])), "e.json")
        assert any("declared twice" in n for n in outcome.normalisation.notes)
        [record] = [e for e in outcome.normalisation.evidence
                    if e.producer.producer_id == "acme-risk-engine"]
        assert list(record.metadata["declared_limitations"]) == ["that the score measures risk"]

    def test_a_declaration_without_limits_is_refused_and_counted(self, tmp_path):
        outcome = _assure(tmp_path, self._envelope(self._declaration_row(limitations=[])),
                          "e.json")
        n = outcome.normalisation
        assert any("ProducerContractError" in k for k in n.skipped)
        [record] = [e for e in n.evidence if e.producer.producer_id == "acme-risk-engine"]
        assert "producer_type" not in (record.metadata or {})
