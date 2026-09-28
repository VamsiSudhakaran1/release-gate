"""The product surface, and the four ways a convenience layer could cheat.

The two samples in the brief are run verbatim, including `type=`. The rest of the
file guards the things a simpler API is most likely to buy its simplicity with:
inventing a verification nobody stated, dropping a record the caller handed over,
returning a verdict without its coverage, and holding ten million events in memory.

`TestTheFacadeChangesNothing` is the load-bearing one. The same records through
this surface and through `assure_normalisation` must reach the same verdict on the
same collections — otherwise "the same conceptual system" is a slogan.
"""

from __future__ import annotations

import json
import resource
import sys

import pytest

from release_gate.assurance.api import (
    API_SCHEMA_VERSION, STREAM_RETAIN, ApiError, Case, CaseDecision, create_case,
)
from release_gate.assurance.subject import DigestStatus
from release_gate.assurance.verdict import Decision


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


@pytest.fixture
def migration(tmp_path):
    path = tmp_path / "0041_add_index.sql"
    path.write_text("CREATE INDEX CONCURRENTLY idx ON orders (created_at);\n")
    return path


def clean_rows():
    from release_gate.assurance.corpus import _clean_release

    return [dict(r) for r in _clean_release()]


def load(case: Case, rows) -> Case:
    """The corpus's records through the facade's own adders."""
    for row in rows:
        kind = row.get("record_type")
        if kind == "execution":
            case.add_execution(row)
        elif kind == "artifact":
            case.add_artifact(row)
        elif kind == "claim":
            case.add_claim(row)
        else:
            case.add_evidence(row)
    return case


# ── the brief, verbatim ──────────────────────────────────────────────────────

class TestTheBriefsSamples:

    def test_the_minimal_sample_runs_as_written(self, migration):
        trace = {"trace_id": "run-01",
                 "steps": [{"type": "tool_call", "tool": "write_file"}]}
        test_result = {"suite": "migrations", "passed": True, "tests": 41}

        case = create_case(
            objective="Deploy generated migration",
            subject=migration
        )

        case.add_execution(trace)
        case.add_verification(test_result)

        decision = case.finalize()
        assert isinstance(decision, CaseDecision)
        assert decision.value in {"PROMOTE", "HOLD", "BLOCK"}

    def test_the_frontier_sample_runs_as_written(self, tmp_path):
        candidate_result = tmp_path / "result.txt"
        candidate_result.write_text("proposition X holds for all n > 2\n")
        events = ({"event": i, "kind": "llm_call"} for i in range(5_000))
        lean_result = {"theorem": "prop_X", "checked": True}
        independent_run = {"by": "team-b", "agrees": True}
        counterexample_search = {"searched": 10_000, "found": 0}

        case = create_case(
            type="research_result",
            objective="Establish proposition X",
            subject=candidate_result,
            methodology="research-mathematics-v1"
        )

        case.stream(events)
        case.add_verification(lean_result)
        case.add_replication(independent_run)
        case.add_counterexample(counterexample_search)

        decision = case.finalize()
        assert isinstance(decision, CaseDecision)
        assert case.streamed == 5_000

    def test_the_two_samples_are_one_class_and_one_path(self, migration):
        """"The same conceptual system" as something checkable."""
        minimal = create_case(objective="a", subject=migration)
        frontier = create_case(type="research_result", objective="b",
                               subject=migration,
                               methodology="research-mathematics-v1")
        assert type(minimal) is type(frontier) is Case
        assert type(minimal.session) is type(frontier.session)

    def test_a_methodology_version_suffix_resolves(self):
        """The brief writes `research-mathematics-v1`; the registry id has no suffix."""
        for reference in ("research-mathematics-v1", "research-mathematics"):
            case = create_case(objective="x", methodology=reference)
            assert case.session.methodology is not None
            assert case.session.methodology.methodology_id == "research-mathematics"

    def test_an_empty_case_is_not_falsy(self):
        """`__len__` is 0 on a new case, and `if case:` must not read as "invalid"."""
        case = create_case(objective="x")
        assert len(case) == 0
        assert bool(case) is True

    def test_a_mistyped_methodology_does_not_quietly_become_none(self):
        with pytest.raises(ApiError, match="not a registered methodology"):
            create_case(objective="x", methodology="reserch-mathematics")

    def test_a_case_needs_an_objective(self):
        with pytest.raises(ApiError, match="needs an objective"):
            create_case(objective="  ")


# ── the facade must not change the answer ────────────────────────────────────

class TestTheFacadeChangesNothing:

    def _direct(self, rows, methodology):
        from release_gate.assurance.ingest import detect_document, normalise
        from release_gate.assurance.methodologies import default_registry
        from release_gate.assurance.zero_config import assure_normalisation

        content = ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()
        return assure_normalisation(
            normalise(rows, detect_document(rows, filename="valid.jsonl"),
                      source="valid.jsonl", content=content),
            source_name="valid.jsonl", objective="o",
            methodology=default_registry().latest(methodology))

    def test_the_same_records_reach_the_same_verdict(self):
        rows = clean_rows()
        direct = self._direct(rows, "software-agent-assurance")
        via = load(create_case(objective="o", type="code_change",
                               methodology="software-agent-assurance"),
                   rows).finalize()
        assert via.value == direct.decision.value
        assert via.fired_rules == tuple(direct.case.verdict.fired_rules)

    def test_the_same_records_build_the_same_collections(self):
        rows = clean_rows()
        direct = self._direct(rows, "software-agent-assurance")
        via = load(create_case(objective="o", type="code_change",
                               methodology="software-agent-assurance"),
                   rows).finalize()
        for kind in ("evidence", "claims", "artifacts", "executions", "coverage"):
            assert (via.outcome.case.collection(kind).total_count
                    == direct.case.collection(kind).total_count), kind

    def test_the_same_verification_attempts_reach_the_graph(self):
        rows = clean_rows()
        direct = self._direct(rows, "software-agent-assurance")
        via = load(create_case(objective="o", methodology="software-agent-assurance"),
                   rows).finalize()
        assert (len(via.outcome.analysis.verification_graph.attempts)
                == len(direct.analysis.verification_graph.attempts))

    def test_this_surface_can_reach_promote(self):
        """An API that could only ever hold would be useless."""
        decision = load(create_case(objective="Ship the payment change",
                                    type="code_change",
                                    methodology="general-autonomous-action"),
                        clean_rows()).finalize()
        assert decision.promoted
        assert bool(decision) is True

    def test_a_case_with_no_methodology_holds_and_says_why(self):
        """The minimal sample's answer, and it must read as an answer."""
        decision = load(create_case(objective="o"), clean_rows()).finalize()
        assert decision.held
        assert any("METHODOLOGY_REQUIRED" in r for r in decision.reasons)
        assert any("methodology" in r for r in decision.required_evidence)


# ── nothing is silently dropped, nothing is invented ────────────────────────

class TestNothingIsLostOrInvented:

    def _probe(self) -> Case:
        case = create_case(objective="drop check", subject="thing-1")
        case.add_execution({"trace_id": "t",
                            "steps": [{"type": "tool_call", "tool": "x"}]})
        case.add_verification({"a": 1}, method="TEST_SUITE", outcome="PASSED",
                              verifier="ci://x")
        case.add_verification({"b": 2})
        case.add_replication({"by": "team-b"})
        case.add_counterexample({"searched": 10})
        case.add_counterexample({"searched": 10}, against="c-1")
        case.add_claim({"claim_id": "c-1", "proposition": "it holds"})
        case.add_artifact({"logical_id": "a-1", "digest": "sha256:" + "ab" * 32})
        case.add_evidence({"evidence_id": "e-1", "kind": "TEST_RESULT"})
        return case

    def test_no_adder_hands_the_engine_something_it_rejects(self):
        """Every adder, and the ingest's own skipped tally must stay empty."""
        normalisation = self._probe().session.provisional().normalisation
        assert dict(getattr(normalisation, "skipped", {}) or {}) == {}

    def test_an_untargeted_counterexample_is_kept_and_named(self):
        """Ingest rejects one naming no claim, so it must not be sent as one."""
        case = create_case(objective="o", subject="s")
        case.add_counterexample({"searched": 10, "found": 0})
        decision = case.finalize()
        assert dict(getattr(decision.outcome.normalisation, "skipped", {}) or {}) == {}
        assert any("name the claim" in r for r in decision.required_evidence)

    def test_a_targeted_counterexample_reaches_the_ledger(self):
        case = create_case(objective="o", subject="s")
        case.add_claim({"claim_id": "c-1", "proposition": "it holds"})
        case.add_counterexample({"searched": 10, "found": 0}, against="c-1")
        decision = case.finalize()
        assert decision.outcome.case.collection("counterexamples").total_count == 1

    def test_a_payload_naming_its_own_target_needs_no_keyword(self):
        case = create_case(objective="o", subject="s")
        case.add_claim({"claim_id": "c-9", "proposition": "p"})
        case.add_counterexample({"target_claim": "c-9", "searched": 1})
        assert case.finalize().outcome.case.collection(
            "counterexamples").total_count == 1

    def test_a_verification_with_no_outcome_stated_establishes_nothing(self):
        """`{"passed": True}` is the producer's vocabulary, not release-gate's."""
        case = create_case(objective="o", subject="s")
        case.add_verification({"suite": "payments", "passed": True})
        decision = case.finalize()
        assert decision.outcome.analysis.verification_graph.attempts == ()
        assert any("state the method, outcome and verifier" in r
                   for r in decision.required_evidence)

    def test_a_stated_verification_reaches_the_graph(self):
        case = create_case(objective="o", subject="s")
        case.add_verification({"suite": "payments"}, method="TEST_SUITE",
                              outcome="PASSED", verifier="ci://pytest")
        attempts = case.finalize().outcome.analysis.verification_graph.attempts
        assert len(attempts) == 1
        assert attempts[0].verifier == "ci://pytest"

    def test_the_documented_envelope_is_read_without_being_guessed_at(self):
        """Reading a documented format is not a guess about a tool's vocabulary."""
        envelope = {"verifier": {"name": "lean", "version": "4"},
                    "results": [{"target": "prop_X", "outcome": "passed"}]}
        case = create_case(objective="o", subject="s")
        case.add_verification(envelope)
        decision = case.finalize()
        assert not any("state the method, outcome and verifier" in r
                       for r in decision.required_evidence)

    def test_a_producers_claimed_status_cannot_survive(self):
        """Ingest strips these; this pins that the facade did not find a way round."""
        case = create_case(objective="o", subject="s")
        case.add_evidence({"evidence_id": "e-1", "kind": "TEST_RESULT",
                           "epistemic_status": "VERIFIED",
                           "trust_status": "ACCEPTED"})
        # The evidence collection also holds records release-gate derived — the
        # consequence profile, the input artifact — so filter to actual evidence.
        held = [r for r in case.finalize().outcome.case.collection(
            "evidence").materialised
            if str(getattr(r, "evidence_id", "")).startswith("ev")]
        assert held
        assert all(r.epistemic_status.value != "VERIFIED" for r in held)
        assert all(r.trust is None for r in held)

    def test_a_typed_record_object_passes_through_untouched(self):
        from release_gate.assurance.records import SimpleRecord

        record = SimpleRecord(record_type="evidence", record_id="e-typed",
                              payload={"kind": "TEST_RESULT"})
        case = create_case(objective="o", subject="s")
        case.add_evidence(record)
        assert record in case.session.records


# ── the subject is the subject ───────────────────────────────────────────────

class TestTheSubject:

    def test_a_file_is_hashed_here_and_reads_as_observed(self, migration):
        case = create_case(objective="o", subject=migration)
        subject = case.finalize().outcome.case.subject
        assert subject.digest_status is DigestStatus.OBSERVED
        assert "computed by release-gate" in subject.digest_basis
        assert migration.name in case.subject_basis

    def test_bytes_are_hashed_here_too(self):
        case = create_case(objective="o", subject=b"CREATE INDEX idx ON t (c);")
        subject = case.finalize().outcome.case.subject
        assert subject.digest_status is DigestStatus.OBSERVED

    def test_a_supplied_digest_is_declared_and_not_observed(self):
        """Somebody else computed it, however trustworthy they are."""
        from release_gate.assurance.artifacts import Artifact, ArtifactKind
        from release_gate.assurance.subject import DigestMethod

        artifact = Artifact(logical_id="model.bin", artifact_kind=ArtifactKind.OTHER,
                            digest="sha256:" + "cd" * 32,
                            digest_method=DigestMethod.EXTERNAL_ATTESTED,
                            digest_status=DigestStatus.DECLARED,
                            digest_attested_by="the model registry")
        case = create_case(objective="o", subject=artifact)
        subject = case.finalize().outcome.case.subject
        assert subject.digest_status is DigestStatus.DECLARED
        assert "did not compute it" in subject.digest_basis
        assert subject.digest_attested_by == "the model registry"

    def test_a_supplied_digest_naming_no_attestor_is_refused(self):
        """`AssuranceSubject` requires the attestor; the API surfaces that rather
        than inventing one."""
        class Bare:
            logical_id = "model.bin"
            digest = "sha256:" + "ef" * 32

        with pytest.raises(ApiError, match="names nobody who attested it"):
            create_case(objective="o", subject=Bare())

    def test_an_identifier_has_no_digest_and_says_so(self):
        case = create_case(objective="o", subject="migration-0041")
        subject = case.finalize().outcome.case.subject
        assert subject.digest_status is DigestStatus.UNKNOWN
        assert "nothing was hashed" in case.subject_basis

    def test_a_pathlike_string_that_is_not_a_file_is_refused(self):
        """A typo must not hand back an unhashed subject that reads like a hashed one."""
        for bad in ("./migrations/0041.sql", "out/result.json", "notes.md"):
            with pytest.raises(ApiError, match="looks like a path and is not a file"):
                create_case(objective="o", subject=bad)

    def test_a_subject_nobody_named_leaves_the_old_behaviour_alone(self):
        case = create_case(objective="o")
        assert case.session.subject is None
        assert "no subject was named" in case.subject_basis

    def test_the_case_type_reaches_the_subject_type(self):
        case = create_case(objective="o", subject="r-1", type="research_result")
        assert case.finalize().outcome.case.subject.subject_type.value == "RESEARCH_RESULT"

    def test_an_unknown_case_type_is_general_rather_than_a_guess(self):
        case = create_case(objective="o", subject="r-1", type="something_new")
        assert case.finalize().outcome.case.subject.subject_type.value == "GENERAL_RESULT"

    def test_an_unusable_subject_is_refused_by_type(self):
        with pytest.raises(ApiError, match="subject must be"):
            create_case(objective="o", subject=object())

    def test_against_subject_is_the_callers_assertion_not_an_inference(self, migration):
        case = create_case(objective="o", subject=migration)
        case.add_verification({"suite": "s"}, method="TEST_SUITE", outcome="PASSED",
                              verifier="ci://x", against_subject=True)
        attempt = case.finalize().outcome.analysis.verification_graph.attempts[0]
        assert attempt.target_digest == case.session.subject.digest

    def test_a_check_with_no_target_names_none(self):
        """Filling it in from the subject would assert currency nobody established."""
        case = create_case(objective="o", subject="s-1")
        case.add_verification({"suite": "s"}, method="TEST_SUITE", outcome="PASSED",
                              verifier="ci://x")
        assert case.finalize().outcome.analysis.verification_graph.attempts[
            0].target_digest is None

    def test_against_subject_refuses_a_case_with_no_digest(self):
        case = create_case(objective="o", subject="an-identifier")
        with pytest.raises(ApiError, match="needs a subject with a digest"):
            case.add_verification({"s": 1}, method="TEST_SUITE", outcome="PASSED",
                                  verifier="ci://x", against_subject=True)


# ── streaming ────────────────────────────────────────────────────────────────

class TestStreaming:

    def test_a_million_events_do_not_enter_memory(self):
        """`extend` costs about 850 MB per million; this must cost nothing like it."""
        case = create_case(objective="frontier", subject="result-1")
        before = rss_mb()
        case.stream({"event": i, "kind": "llm_call"} for i in range(1_000_000))
        grew = rss_mb() - before
        assert case.streamed == 1_000_000
        assert grew < 100, f"stream grew RSS by {grew:.0f} MB"

    def test_the_case_holds_a_bounded_set_and_commits_to_all_of_it(self):
        case = create_case(objective="o", subject="r-1")
        case.stream({"event": i} for i in range(20_000))
        decision = case.finalize()
        summary = self._summary(decision)
        assert summary["observed_events"] == 20_000
        assert summary["retained"] == STREAM_RETAIN
        assert str(summary["fold_digest"]).startswith("sha256:")

    def test_the_commitment_is_readable_rather_than_a_repr(self):
        """It was a stringified dict until the counts moved to the row's top level."""
        case = create_case(objective="o", subject="r-1")
        case.stream({"event": i} for i in range(5))
        summary = self._summary(case.finalize())
        assert isinstance(summary["observed_events"], int)

    def test_the_unretained_content_lands_as_a_coverage_gap(self):
        """A note would leave a reviewer reading a complete collection over a truncated stream."""
        from release_gate.assurance.expectation import CoverageState

        case = create_case(objective="o", subject="r-1")
        case.stream({"event": i} for i in range(5_000))
        ledger = case.finalize().outcome.analysis.coverage_ledger
        row = ledger.of("stream.event_content")
        assert row is not None
        assert row.state is CoverageState.NOT_ASSESSED

    def test_a_fully_retained_stream_costs_no_coverage(self):
        case = create_case(objective="o", subject="r-1")
        case.stream({"event": i} for i in range(3))
        ledger = case.finalize().outcome.analysis.coverage_ledger
        assert ledger.of("stream.event_content") is None

    def test_streaming_twice_produces_one_commitment_over_both(self):
        case = create_case(objective="o", subject="r-1")
        case.stream({"event": i} for i in range(10))
        case.stream({"event": i} for i in range(10, 25))
        assert self._summary(case.finalize())["observed_events"] == 25

    def test_the_retention_cap_is_the_callers_to_set(self):
        case = create_case(objective="o", subject="r-1")
        case.stream(({"event": i} for i in range(500)), retain=5)
        assert self._summary(case.finalize())["retained"] == 5

    def test_retaining_none_still_counts_and_commits(self):
        case = create_case(objective="o", subject="r-1")
        case.stream(({"event": i} for i in range(50)), retain=0)
        summary = self._summary(case.finalize())
        assert summary["observed_events"] == 50 and summary["retained"] == 0

    def test_a_negative_cap_is_refused(self):
        case = create_case(objective="o", subject="r-1")
        with pytest.raises(ApiError, match="cannot be negative"):
            case.stream([], retain=-1)

    def test_an_empty_stream_adds_nothing(self):
        case = create_case(objective="o", subject="r-1")
        case.stream([])
        assert case.streamed == 0
        producers = [str(getattr(getattr(r, "producer", None), "producer_id", ""))
                     for r in case.finalize().outcome.case.collection(
                         "evidence").materialised]
        assert not any("api.stream" in p for p in producers)

    @staticmethod
    def _summary(decision: CaseDecision) -> dict:
        for record in decision.outcome.case.collection("evidence").materialised:
            producer = str(getattr(getattr(record, "producer", None),
                                   "producer_id", ""))
            if "release_gate://api.stream" in producer:
                return dict(record.content)
        raise AssertionError("no stream commitment record in the case")


# ── the decision handed back ─────────────────────────────────────────────────

class TestCaseDecision:

    def _decision(self) -> CaseDecision:
        return load(create_case(objective="o"), clean_rows()).finalize()

    def test_it_carries_its_coverage(self):
        """Invariant 9: a verdict may not be read without what was not assessed."""
        decision = self._decision()
        assert "not assessed" in decision.render()

    def test_only_promote_is_truthy(self):
        assert not bool(CaseDecision(decision=Decision.HOLD))
        assert not bool(CaseDecision(decision=Decision.BLOCK))
        assert bool(CaseDecision(decision=Decision.PROMOTE))

    def test_the_three_predicates_agree_with_the_value(self):
        for value, flags in ((Decision.PROMOTE, (True, False, False)),
                             (Decision.HOLD, (False, True, False)),
                             (Decision.BLOCK, (False, False, True))):
            built = CaseDecision(decision=value)
            assert (built.promoted, built.held, built.blocked) == flags
            assert built.value == value.value

    def test_requirements_are_sentences_and_not_reprs(self):
        """Every line of the headline output was a dataclass repr until this was fixed."""
        for line in self._decision().required_evidence:
            assert "RequiredEvidenceItem(" not in line
            assert "requirement_id=" not in line

    def test_attention_items_are_sentences_too(self):
        for line in self._decision().attention:
            assert "AttentionItem(" not in line

    def test_a_case_with_nothing_unassessed_says_that_rather_than_going_quiet(self):
        assert "nothing was left unassessed" in CaseDecision(
            decision=Decision.PROMOTE).render()

    def test_the_whole_outcome_is_reachable(self):
        """Everything else in the package takes this."""
        from release_gate.assurance.compression import measure_compression

        decision = self._decision()
        assert decision.outcome is not None
        assert measure_compression(decision.outcome) is not None

    def test_str_is_the_render(self):
        decision = self._decision()
        assert str(decision) == decision.render()

    def test_it_serialises(self):
        data = self._decision().to_dict()
        assert data["record_type"] == "case_decision"
        assert data["schema_version"] == API_SCHEMA_VERSION


# ── while the case is open ───────────────────────────────────────────────────

class TestWhileOpen:

    def test_required_evidence_reads_before_finalizing(self):
        case = create_case(objective="o", subject="s-1")
        case.add_verification({"a": 1})
        assert any("state the method" in r for r in case.required_evidence())
        assert not case.session.finalized

    def test_attention_reads_before_finalizing(self):
        case = create_case(objective="o", subject="s-1")
        assert isinstance(case.attention(), tuple)
        assert not case.session.finalized

    def test_len_counts_records_added(self):
        case = create_case(objective="o", subject="s-1")
        assert len(case) == 0
        case.add_evidence({"evidence_id": "e-1", "kind": "TEST_RESULT"})
        assert len(case) == 1

    def test_adders_chain(self):
        case = create_case(objective="o", subject="s-1")
        assert (case.add_evidence({"evidence_id": "e-1", "kind": "TEST_RESULT"})
                    .add_claim({"claim_id": "c", "proposition": "p"})) is case

    def test_finalize_is_idempotent(self):
        case = load(create_case(objective="o"), clean_rows())
        first, second = case.finalize(), case.finalize()
        assert first.case_digest == second.case_digest


# ── the entry point ──────────────────────────────────────────────────────────

class TestTheTopLevelSurface:

    def test_rg_create_case_resolves(self):
        import release_gate as rg

        assert rg.create_case is create_case
        assert {"create_case", "Case", "CaseDecision", "ApiError"} <= set(dir(rg))

    def test_an_unknown_attribute_still_raises(self):
        import release_gate as rg

        with pytest.raises(AttributeError, match="has no attribute"):
            rg.definitely_not_a_thing

    def test_importing_the_package_does_not_import_the_engine(self):
        """36ms against 237ms: the old surface must not pay for a package it never touches."""
        import subprocess

        probe = subprocess.run(
            [sys.executable, "-c",
             "import release_gate, sys; "
             "print('release_gate.assurance.api' in sys.modules)"],
            capture_output=True, text=True, check=True)
        assert probe.stdout.strip() == "False"

    def test_the_surface_is_four_names(self):
        import release_gate.assurance.api as api

        assert set(api.__all__) == {
            "API_SCHEMA_VERSION", "STREAM_RETAIN", "ApiError", "Case",
            "CaseDecision", "create_case"}
