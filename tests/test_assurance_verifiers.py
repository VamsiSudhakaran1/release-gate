"""Adapters for machine-verifiable systems — the interface, not one prover.

The tests that matter most are about the result vocabulary. `unknown` is not a
pass, a bare `unsat` proves nothing, and a tool that gave up has established
exactly as much as a tool that never ran.
"""

import json

import pytest

from release_gate.assurance.evidence import (
    EpistemicStatus, EvidenceType, TrustStatus, VerificationMethod,
)
from release_gate.assurance.verification import (
    TargetKind, VerificationStatus, VerificationTarget,
)
from release_gate.assurance.verifiers import (
    DETECT_FLOOR,
    GenericVerifierAdapter,
    QueryPolarity,
    SmtLibAdapter,
    ToolFamily,
    ToolIdentity,
    VerifierAdapter,
    VerifierCoverage,
    VerifierError,
    VerifierRegistry,
    VerifierReport,
    default_verifier_registry,
)
from release_gate.assurance.zero_config import assure

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def envelope(*results, **tool):
    tool.setdefault("name", "lean")
    tool.setdefault("family", "PROOF_ASSISTANT")
    return {"verifier": tool, "results": list(results)}


# ── the mapping that must not be got backwards ───────────────────────────────

class TestUnknownIsNotAPass:

    def test_unknown_is_inconclusive(self):
        assert VerifierAdapter.status_for("unknown") is VerificationStatus.INCONCLUSIVE

    def test_a_timeout_is_inconclusive(self):
        for word in ("timeout", "timed_out", "resource_limit", "gave_up"):
            assert VerifierAdapter.status_for(word) is VerificationStatus.INCONCLUSIVE, word

    def test_an_unrecognised_word_is_unknown_never_passed(self):
        for word in ("banana", "", None, "mostly fine"):
            assert VerifierAdapter.status_for(word) is VerificationStatus.UNKNOWN, word

    def test_skipped_is_not_run_not_passed(self):
        assert VerifierAdapter.status_for("skipped") is VerificationStatus.NOT_RUN

    def test_retracted_is_invalidated(self):
        assert VerifierAdapter.status_for("retracted") is VerificationStatus.INVALIDATED

    def test_the_table_is_shared_so_no_adapter_redecides_it(self):
        """One table, so one adapter cannot get `unknown` wrong on its own."""
        assert SmtLibAdapter.RESULT_WORDS is VerifierAdapter.RESULT_WORDS
        assert GenericVerifierAdapter.RESULT_WORDS is VerifierAdapter.RESULT_WORDS


class TestSmtPolarity:
    """A bare `unsat` proves nothing; which way depends on what was asserted."""

    def _convert(self, result, **kwargs):
        return default_verifier_registry().convert(
            {"format": "smtlib", "solver": "z3", "result": result}, **kwargs)

    def test_undeclared_polarity_establishes_nothing(self):
        report = self._convert("unsat")
        assert report.attempts[0].status is VerificationStatus.UNKNOWN
        assert "polarity" in report.attempts[0].detail

    def test_negation_asserted_makes_unsat_a_proof(self):
        report = self._convert("unsat", polarity=QueryPolarity.NEGATION_OF_PROPERTY)
        assert report.attempts[0].status is VerificationStatus.PASSED

    def test_negation_asserted_makes_sat_a_refutation(self):
        report = self._convert("sat", polarity=QueryPolarity.NEGATION_OF_PROPERTY)
        assert report.attempts[0].status is VerificationStatus.FAILED

    def test_a_direct_unsat_is_a_broken_encoding_not_a_proof(self):
        """Asserting the property and getting unsat means it is contradictory."""
        report = self._convert("unsat", polarity=QueryPolarity.DIRECT)
        assert report.attempts[0].status is VerificationStatus.FAILED
        assert "vacuous" in report.attempts[0].detail

    def test_a_direct_sat_shows_only_consistency(self):
        report = self._convert("sat", polarity=QueryPolarity.DIRECT)
        assert report.attempts[0].status is VerificationStatus.INCONCLUSIVE
        assert "not that it always holds" in report.attempts[0].detail

    def test_unknown_is_inconclusive_whatever_the_polarity(self):
        for polarity in QueryPolarity:
            report = self._convert("unknown", polarity=polarity)
            assert report.attempts[0].status is VerificationStatus.INCONCLUSIVE

    def test_the_polarity_can_be_declared_in_the_document(self):
        report = default_verifier_registry().convert(
            {"format": "smtlib", "result": "unsat",
             "query_polarity": "NEGATION_OF_PROPERTY"})
        assert report.attempts[0].status is VerificationStatus.PASSED

    def test_undeclared_polarity_is_stated_in_the_coverage(self):
        report = self._convert("unsat")
        assert "anything at all" in report.coverage.does_not_cover[0]

    def test_raw_solver_text_is_read(self):
        report = default_verifier_registry().convert(
            "unsat\n", polarity=QueryPolarity.NEGATION_OF_PROPERTY)
        assert report.attempts[0].status is VerificationStatus.PASSED

    def test_the_encoding_gap_is_always_stated(self):
        assert "not a proof of the property" in self._convert("unsat").coverage.encoding_note


# ── what a result does not cover ─────────────────────────────────────────────

class TestCoverageIsStated:

    def test_every_family_states_what_it_does_not_cover(self):
        for family in ToolFamily:
            coverage = VerifierCoverage.for_family(family)
            assert coverage.does_not_cover, family

    def test_a_proof_does_not_cover_whether_the_statement_says_what_was_meant(self):
        coverage = VerifierCoverage.for_family(ToolFamily.PROOF_ASSISTANT)
        assert any("says what its author meant" in c for c in coverage.does_not_cover)

    def test_a_type_checker_does_not_cover_runtime_behaviour(self):
        coverage = VerifierCoverage.for_family(ToolFamily.TYPE_CHECKER)
        assert "runtime behaviour" in coverage.does_not_cover

    def test_a_property_checker_does_not_prove_absence(self):
        coverage = VerifierCoverage.for_family(ToolFamily.PROPERTY_CHECKER)
        assert any("outside the search" in c for c in coverage.does_not_cover)

    def test_an_unknown_family_says_nothing_is_recorded(self):
        coverage = VerifierCoverage.for_family(ToolFamily.OTHER)
        assert coverage.covers == ()

    def test_completeness_is_false_without_a_declared_total(self):
        assert VerifierCoverage(targets_checked=5).complete is False

    def test_completeness_needs_the_declared_total_met(self):
        assert VerifierCoverage(targets_checked=5, targets_declared=5).complete is True
        assert VerifierCoverage(targets_checked=4, targets_declared=5).complete is False

    def test_per_result_coverage_is_merged_with_the_family(self):
        report = default_verifier_registry().convert(envelope(
            {"target": "t", "result": "proved",
             "does_not_cover": ["the axiom set was not audited"]}))
        assert "the axiom set was not audited" in report.coverage.does_not_cover
        assert any("formalised model" in c for c in report.coverage.does_not_cover)


# ── tool identity ────────────────────────────────────────────────────────────

class TestToolIdentity:

    def test_a_verifier_must_be_named(self):
        with pytest.raises(VerifierError, match="must be named"):
            ToolIdentity(name="  ")

    def test_a_digest_must_be_a_content_identifier(self):
        with pytest.raises(VerifierError, match="pins nothing"):
            ToolIdentity(name="lean", digest="whatever")

    def test_pinning_identifies_the_kernel(self):
        pinned = ToolIdentity(name="lean", version="4.8.0", digest=DIGEST_A)
        assert pinned.pinned is True
        assert pinned.reference == "lean@4.8.0"

    def test_pinning_establishes_identity_not_correctness(self):
        """A pinned prover is a known prover, not a correct one."""
        assert ToolIdentity(name="lean", digest=DIGEST_A).trust_status \
            is TrustStatus.PROVISIONAL

    def test_an_unpinned_tool_has_no_established_trust(self):
        assert ToolIdentity(name="lean").trust_status is TrustStatus.NOT_ESTABLISHED

    def test_the_unpinned_kernel_is_named_as_a_gap(self):
        coverage = VerifierCoverage.for_family(ToolFamily.PROOF_ASSISTANT)
        assert any("kernel unless its digest is pinned" in c
                   for c in coverage.does_not_cover)


# ── no prover is hardcoded ───────────────────────────────────────────────────

class TestNoProverIsHardcoded:

    class LeanAdapter(VerifierAdapter):
        name = "lean-shim"
        label = "Lean via lake"
        family = ToolFamily.PROOF_ASSISTANT

        def detect(self, doc):
            return 99 if isinstance(doc, dict) and "leanResults" in doc else 0

        def convert(self, doc, **kwargs):
            tool = ToolIdentity(name="lean", version="4.8.0",
                                family=ToolFamily.PROOF_ASSISTANT)
            from release_gate.assurance.verification import VerificationAttempt

            attempts = tuple(
                VerificationAttempt(
                    method=VerificationMethod.THEOREM_PROVER,
                    target=VerificationTarget.claim(row["name"]),
                    verifier=tool.reference,
                    status=self.status_for(row["status"]))
                for row in doc["leanResults"])
            return VerifierReport(
                tool=tool, attempts=attempts, adapter=self.name,
                coverage=VerifierCoverage.for_family(ToolFamily.PROOF_ASSISTANT),
                records_seen=len(attempts), records_mapped=len(attempts))

    def test_an_organisation_can_register_its_own(self):
        registry = default_verifier_registry().register(self.LeanAdapter())
        report = registry.convert({"leanResults": [{"name": "thm", "status": "proved"}]})
        assert report.adapter == "lean-shim"
        assert report.attempts[0].status is VerificationStatus.PASSED

    def test_a_purpose_built_adapter_beats_the_generic_envelope(self):
        registry = default_verifier_registry().register(self.LeanAdapter())
        doc = {"leanResults": [{"name": "thm", "status": "proved"}],
               "results": [{"target": "thm", "result": "proved"}]}
        assert registry.detect(doc)[0][0] == "lean-shim"

    def test_registering_the_same_name_twice_is_refused(self):
        registry = default_verifier_registry().register(self.LeanAdapter())
        with pytest.raises(VerifierError, match="already registered"):
            registry.register(self.LeanAdapter())

    def test_a_non_adapter_is_refused(self):
        with pytest.raises(VerifierError):
            default_verifier_registry().register(object())

    def test_the_registry_is_fresh_per_call(self):
        default_verifier_registry().register(self.LeanAdapter())
        assert all(a.name != "lean-shim"
                   for a in default_verifier_registry().adapters)

    def test_a_registry_can_ship_with_nothing_built_in(self):
        assert VerifierRegistry(include_builtin=False).adapters == ()

    def test_unrecognised_output_is_refused_not_guessed(self):
        with pytest.raises(VerifierError, match="recognised"):
            default_verifier_registry().convert({"something": "else"})

    def test_an_adapter_can_be_named_explicitly(self):
        report = default_verifier_registry().convert(
            envelope({"target": "t", "result": "ok"}), source="generic")
        assert report.adapter == "generic"

    def test_naming_an_unknown_adapter_says_what_is_registered(self):
        with pytest.raises(VerifierError, match="registered:"):
            default_verifier_registry().convert({}, source="nope")

    def test_a_detect_that_raises_does_not_break_detection(self):
        class Broken(VerifierAdapter):
            name = "broken"

            def detect(self, doc):
                raise RuntimeError("boom")

        registry = default_verifier_registry().register(Broken())
        assert registry.detect(envelope({"target": "t", "result": "ok"}))


# ── the generic envelope ─────────────────────────────────────────────────────

class TestGenericEnvelope:

    def test_it_reads_a_proof_assistant_run(self):
        report = default_verifier_registry().convert(envelope(
            {"target": "thm_main", "result": "proved", "target_digest": DIGEST_B},
            {"target": "thm_aux", "result": "timeout"},
            version="4.8.0", digest=DIGEST_A))
        assert len(report.attempts) == 2
        assert {a.status for a in report.attempts} == {
            VerificationStatus.PASSED, VerificationStatus.INCONCLUSIVE}

    def test_the_attempt_binds_to_the_artifact_version(self):
        report = default_verifier_registry().convert(envelope(
            {"target": "thm", "result": "proved", "target_digest": DIGEST_B}))
        assert report.attempts[0].target_digest == DIGEST_B

    def test_the_family_chooses_the_method(self):
        report = default_verifier_registry().convert(envelope(
            {"target": "t", "result": "ok"}, name="mypy",
            family=ToolFamily.TYPE_CHECKER.value))
        assert report.attempts[0].method is VerificationMethod.TYPE_CHECKER

    def test_a_result_naming_no_target_is_counted_not_guessed(self):
        report = default_verifier_registry().convert(envelope({"result": "proved"}))
        assert report.attempts == ()
        assert report.skipped_total == 1

    def test_a_malformed_row_is_counted(self):
        report = default_verifier_registry().convert(
            {"verifier": {"name": "x"}, "results": ["not an object"]})
        assert report.skipped_total == 1

    def test_a_non_object_document_is_refused(self):
        with pytest.raises(VerifierError):
            GenericVerifierAdapter().convert(["not", "an", "object"])

    def test_the_report_digest_is_stable(self):
        doc = envelope({"target": "t", "result": "ok"})
        a = default_verifier_registry().convert(doc)
        b = default_verifier_registry().convert(doc)
        assert a.digest() == b.digest()

    def test_it_serialises(self):
        report = default_verifier_registry().convert(envelope(
            {"target": "t", "result": "proved"}))
        payload = json.loads(json.dumps(report.to_dict()))
        assert payload["by_status"]["PASSED"] == 1


# ── release-gate does not replace these tools ────────────────────────────────

class TestDoesNotReplaceTheTools:

    @pytest.fixture
    def lean_file(self, tmp_path):
        path = tmp_path / "lean.json"
        path.write_text(json.dumps(envelope(
            {"target": "thm_main", "result": "proved", "target_digest": DIGEST_B},
            {"target": "thm_aux", "result": "timeout"},
            version="4.8.0", digest=DIGEST_A)))
        return str(path)

    def test_a_verifier_report_is_a_recognised_input(self, lean_file):
        from release_gate.assurance.ingest import InputKind

        assert assure(lean_file).detection.kind is InputKind.VERIFIER_REPORT

    def test_the_attempts_reach_the_case(self, lean_file):
        graph = assure(lean_file).verification
        assert len(graph.attempts) == 2

    def test_the_result_is_declared_not_observed(self, lean_file):
        """release-gate read the file; it did not watch the prover run."""
        records = [r for r in assure(lean_file).normalisation.evidence
                   if r.evidence_type is EvidenceType.FORMAL_PROOF]
        assert records
        assert all(r.epistemic_status is EpistemicStatus.DECLARED for r in records)

    def test_the_tool_is_the_producer(self, lean_file):
        record = next(r for r in assure(lean_file).normalisation.evidence
                      if r.evidence_type is EvidenceType.FORMAL_PROOF)
        assert record.producer.producer_id == "lean@4.8.0"
        assert record.producer.identity_basis == "pinned-digest"

    def test_the_coverage_limits_ride_along_as_the_coverage_note(self, lean_file):
        record = next(r for r in assure(lean_file).normalisation.evidence
                      if r.evidence_type is EvidenceType.FORMAL_PROOF)
        assert "formalised model" in record.coverage_note

    def test_a_timeout_does_not_verify_anything(self, lean_file):
        graph = assure(lean_file).verification
        aux = VerificationTarget.claim("thm_aux")
        assert graph.assess(aux).verified is False

    def test_the_outcome_serialises(self, lean_file):
        payload = json.loads(json.dumps(assure(lean_file).to_dict()))
        assert payload["verification"]["attempts"] == 2

    def test_an_undeclared_smt_result_verifies_nothing_end_to_end(self, tmp_path):
        path = tmp_path / "smt.json"
        path.write_text(json.dumps({"format": "smtlib", "solver": "z3",
                                    "result": "unsat"}))
        graph = assure(str(path)).verification
        assert all(a.status is VerificationStatus.UNKNOWN for a in graph.attempts)
