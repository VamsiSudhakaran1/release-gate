"""The semantic provider benchmark: false certainty costs most, and accuracy never ranks.

Pinned here, against release_gate/assurance/provider_benchmark.py, the cases in
benchmark/semantic_cases.jsonl and the runner benchmark/semantic.py:

* an abstention always outscores a wrong answer, whatever its confidence, and a
  false confirmation costs more than a false refutation;
* a careful provider outranks a more accurate bold one, and a provider over the
  false-confirm ceiling, under the answer floor or unstable across repeats is
  reported and not ranked;
* every metric the comparison needs is computed: abstention quality, false
  confirm and refute rates, calibration over stated probabilities only,
  latency, declared cost, repeatability, the context an answer needed;
* each case is asked through the production verifier with the packet
  production would build, reproducibly, and its label never reaches the
  provider;
* the report is computed from persisted rows alone, and decides nothing.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from release_gate.assurance.provider_benchmark import (
    BENCHMARK_CASE_SCHEMA, BENCHMARK_CATEGORIES, BENCHMARK_RUN_SCHEMA,
    DEFAULT_BENCHMARK_POLICY, BenchmarkCase, BenchmarkError, BenchmarkPolicy,
    ReadingOutcome, benchmark_packet, evaluate_benchmark, question_labels,
    read_benchmark_cases, read_benchmark_runs, reference_providers, render_benchmark,
    run_benchmark, score_reading, write_benchmark_runs)
from release_gate.assurance.producer_contract import Determinism
from release_gate.assurance.semantic_verifier import (
    OutputKind, ProviderCapabilities, ProviderIdentity, ProviderInterface, ProviderReply,
    ProviderUnavailable, SemanticVerdict, SemanticVerifier)

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "benchmark" / "semantic_cases.jsonl"
VERDICTS = [v.value for v in SemanticVerdict]
WRONG = [(label, answer) for label in VERDICTS for answer in ("supported", "contradicted")
         if answer != label]


@pytest.fixture(scope="module")
def cases():
    return read_benchmark_cases(CASES)


@pytest.fixture(scope="module")
def labels(cases):
    return question_labels(cases)


class Scripted:
    """A chat provider answering each question from a table: (verdict, confidence)."""

    def __init__(self, name, table, *, cost=None, determinism="UNKNOWN", raises=None):
        self.name, self.table, self.cost = name, table, cost
        self.determinism, self.raises = determinism, raises

    def identity(self):
        return ProviderIdentity(provider="scripted", model=self.name, local=True)

    def capabilities(self):
        return ProviderCapabilities(interface=ProviderInterface.CHAT,
                                    outputs=(OutputKind.CHOICE,),
                                    determinism=Determinism(self.determinism),
                                    cost_per_call=self.cost)

    def complete(self, request):
        if self.raises is not None:
            raise self.raises
        packet = json.loads(request.user)["evidence_packet"]
        verdict, confidence = self.table[packet["question"]["question_id"]]
        return ProviderReply(text=json.dumps({
            "question_id": packet["question"]["question_id"],
            "claim_id": packet["question"]["claim_id"], "verdict": verdict,
            "confidence": confidence, "evidence_refs": [i["ref"] for i in packet["items"]],
            "reason": "scripted"}))


def run(cases, providers, **kw):
    kw.setdefault("clock", lambda: "2026-10-08T00:00:00Z")
    kw.setdefault("timer", lambda: 0.0)
    return run_benchmark(cases, providers, **kw)


# ── the score ────────────────────────────────────────────────────────────────

class TestTheScore:

    @pytest.mark.parametrize("label, answer", WRONG)
    @pytest.mark.parametrize("confidence", [0.0, 0.5, 0.99, None])
    def test_abstaining_beats_any_wrong_answer(self, label, answer, confidence):
        abstain, _ = score_reading(label, "insufficient_evidence", 0.9)
        wrong, outcome = score_reading(label, answer, confidence)
        assert abstain > wrong
        assert outcome in (ReadingOutcome.FALSE_CONFIRM, ReadingOutcome.FALSE_REFUTE)

    @pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
    def test_a_false_confirmation_costs_more_than_a_false_refutation(self, confidence):
        confirm, c = score_reading("contradicted", "supported", confidence)
        refute, r = score_reading("supported", "contradicted", confidence)
        assert (c, r) == (ReadingOutcome.FALSE_CONFIRM, ReadingOutcome.FALSE_REFUTE)
        assert confirm < refute < 0

    def test_confidence_makes_a_wrong_answer_worse_and_a_right_one_no_better(self):
        assert score_reading("contradicted", "supported", 0.99)[0] < \
            score_reading("contradicted", "supported", 0.4)[0]
        assert score_reading("supported", "supported", 0.99) == \
            score_reading("supported", "supported", 0.4)

    def test_a_provider_stating_no_confidence_is_taken_as_certain(self):
        assert score_reading("contradicted", "supported", None) == \
            score_reading("contradicted", "supported", 1.0)

    def test_the_order(self):
        correct = score_reading("insufficient_evidence", "insufficient_evidence", 0.9)
        abstained = score_reading("supported", "insufficient_evidence", 0.9)
        missing = score_reading("supported", None, None)
        refute = score_reading("supported", "contradicted", 0.0)
        assert [o for _, o in (correct, abstained, missing, refute)] == [
            ReadingOutcome.CORRECT, ReadingOutcome.ABSTAINED, ReadingOutcome.NO_ANSWER,
            ReadingOutcome.FALSE_REFUTE]
        assert correct[0] > abstained[0] > missing[0] > refute[0]

    @pytest.mark.parametrize("change", [
        {"false_confirm": 1.0, "false_refute": 2.0},
        {"abstained": 1.5},
        {"no_answer": 0.5},
        {"false_refute": 0.0},
        {"max_false_confirm_rate": 1.5},
        {"tiers": ()},
        {"tiers": (("full", 1200), ("full", 100))},
    ])
    def test_a_scale_that_rewards_false_certainty_is_refused(self, change):
        with pytest.raises(BenchmarkError):
            BenchmarkPolicy(**change)

    def test_the_policy_round_trips_and_its_digest_is_stable(self):
        again = BenchmarkPolicy.from_dict(json.loads(json.dumps(
            DEFAULT_BENCHMARK_POLICY.to_dict())))
        assert again == DEFAULT_BENCHMARK_POLICY
        assert again.digest == DEFAULT_BENCHMARK_POLICY.digest
        with pytest.raises(BenchmarkError):
            BenchmarkPolicy.from_dict({"bonus_for_confidence": 1})
        with pytest.raises(BenchmarkError):
            BenchmarkPolicy.from_dict({"scoring": "accuracy-1"})


# ── the cases ────────────────────────────────────────────────────────────────

class TestTheCases:

    def test_every_difficulty_and_every_answer_is_covered(self, cases):
        assert {c.category for c in cases} == set(BENCHMARK_CATEGORIES)
        assert {c.label.value for c in cases} == set(VERDICTS)
        assert {c.question_kind.value for c in cases} == {
            "EVIDENCE_SUPPORTS_CLAIM", "MECHANISM_CONTROLS_PATH"}

    def test_every_label_carries_its_reason_and_its_author(self, cases):
        for case in cases:
            assert len(case.rationale) > 40 and case.labelled_by

    @pytest.mark.parametrize("change, says", [
        ({"rationale": ""}, "rationale"),
        ({"labelled_by": ""}, "labelled_by"),
        ({"category": "vibes"}, "unknown category"),
        ({"label": "PROMOTE"}, "PROMOTE"),
        ({"records": []}, "records"),
        ({"schema": "something/1"}, BENCHMARK_CASE_SCHEMA),
    ])
    def test_a_case_without_what_a_label_needs_is_refused(self, cases, change, says):
        data = {**cases[0].to_dict(), **change}
        with pytest.raises(BenchmarkError, match=says):
            BenchmarkCase.from_dict(data)

    def test_a_case_id_appears_once_across_files(self, tmp_path):
        copy = tmp_path / "mine.jsonl"
        copy.write_text(CASES.read_text().splitlines()[0] + "\n")
        with pytest.raises(BenchmarkError, match="also in"):
            read_benchmark_cases(CASES, copy)

    def test_the_packet_is_the_one_production_builds_and_it_is_reproducible(self, cases):
        first = {c.case_id: benchmark_packet(c).packet_hash for c in cases}
        time.sleep(1.1)  # past a second boundary: nothing time-stamped is in a packet
        assert {c.case_id: benchmark_packet(c).packet_hash for c in cases} == first
        for case in cases:
            packet = benchmark_packet(case)
            assert len(packet.items) == len(case.records)
            assert all(item.ref.startswith("ev_") for item in packet.items)
            assert not any("producer_claimed" in item.excerpt for item in packet.items)
        by_id = {c.case_id: c for c in cases}
        assert benchmark_packet(by_id["sb-06"]).state_hash.startswith("sha256:")
        assert {m["pattern"] for m in benchmark_packet(by_id["sb-14"]).injection_markers} >= {
            "ignore_instructions", "decision_directive"}

    def test_the_label_never_reaches_the_provider(self, cases):
        for case in cases:
            sent = SemanticVerifier(None).request_for(benchmark_packet(case))
            text = sent.system + sent.user
            assert case.rationale not in text and case.case_id not in text
            assert case.category not in text
            assert "label" not in json.loads(sent.user)["evidence_packet"]


# ── comparing providers ──────────────────────────────────────────────────────

def _table(cases, labels, *, right, wrong_as="supported", confidence=0.95):
    """Right on `right` cases (by position); on the rest answer `wrong_as`."""
    table = {}
    by_case = {benchmark_packet(c).question.question_id: c for c in cases}
    for position, (qid, case) in enumerate(sorted(by_case.items(),
                                                  key=lambda kv: kv[1].case_id)):
        label = case.label.value
        if position in right:
            table[qid] = (label, confidence)
        elif wrong_as == "insufficient_evidence" or label != wrong_as:
            table[qid] = (wrong_as, confidence)
        else:
            table[qid] = ("contradicted", confidence)
    return table


class TestComparingProviders:

    def test_a_careful_provider_outranks_a_more_accurate_bold_one(self, cases, labels):
        # Bold: right on 12 of 15, confidently "supported" on three it does not
        # know. Careful: right on 9, "insufficient_evidence" on the other six.
        bold = Scripted("bold", _table(cases, labels, right=set(range(12))))
        careful = Scripted("careful", _table(cases, labels, right=set(range(9)),
                                             wrong_as="insufficient_evidence"))
        rows = run(cases, {"bold": bold, "careful": careful})
        for policy in (DEFAULT_BENCHMARK_POLICY,
                       BenchmarkPolicy(max_false_confirm_rate=1.0)):
            report = evaluate_benchmark(rows, policy=policy)
            p = report["providers"]
            assert p["bold"]["accuracy"] > p["careful"]["accuracy"]
            assert p["careful"]["mean_score"] > p["bold"]["mean_score"]
            assert report["ranking"][0] == "careful"
            assert report["by_raw_accuracy_for_reference_only"][0] == "bold"
        default = evaluate_benchmark(rows)
        assert default["not_ranked"] == ["bold"]
        assert "false-confirm rate" in default["providers"]["bold"]["ineligible_because"][0]

    def test_abstaining_on_an_unsettled_case_beats_guessing(self, cases, labels):
        guess = Scripted("guess", {q: ("supported", 0.9) for q in labels})
        abstain = Scripted("abstain", {q: ("insufficient_evidence", 0.9) for q in labels})
        report = evaluate_benchmark(run(cases, {"guess": guess, "abstain": abstain}))
        for category in ("stale_evidence", "mismatched_artifact", "correlated_evidence",
                         "ambiguous_provenance", "insufficient_context"):
            assert (report["providers"]["abstain"]["categories"][category]["mean_score"]
                    > report["providers"]["guess"]["categories"][category]["mean_score"])

    def test_every_metric_the_comparison_needs(self, cases, labels):
        providers = reference_providers(labels)
        report = evaluate_benchmark(run(cases, providers, repeats=2))
        p = report["providers"]
        oracle, keyword = p["reference/oracle"], p["reference/keyword"]
        assert oracle["accuracy"] == 1.0 and oracle["mean_score"] == 1.0
        assert oracle["abstention_precision"] == oracle["abstention_recall"] == 1.0
        assert p["reference/always-supported"]["false_confirm_rate"] == 1.0
        assert p["reference/always-abstain"]["coverage"] == 0.0
        assert keyword["false_refute_rate"] > 0
        assert keyword["context"]["accuracy_retained"] < 1.0
        assert set(keyword["context"]["tiers"]) == {"full", "minimal"}
        assert (keyword["context"]["tiers"]["minimal"]["mean_packet_chars"]
                < keyword["context"]["tiers"]["full"]["mean_packet_chars"])
        assert p["reference/unstable"]["determinism"]["repeatability"] < 0.9
        assert p["reference/unstable"]["determinism"]["declared"] == ["NON_DETERMINISTIC"]
        assert oracle["determinism"]["repeatability"] == 1.0
        assert set(oracle["categories"]) == set(BENCHMARK_CATEGORIES)
        assert "repeatability" in " ".join(p["reference/unstable"]["ineligible_because"])

    def test_calibration_is_over_stated_probabilities_only(self, cases, labels):
        report = evaluate_benchmark(run(cases, reference_providers(labels)))
        chat = report["providers"]["reference/keyword"]["calibration"]
        decider = report["providers"]["reference/keyword-decider"]["calibration"]
        assert chat["n"] == 0 and chat["brier"] is None
        assert decider["n"] == len(cases) and decider["brier"] is not None
        assert decider["ece"] is not None

    def test_latency_and_declared_cost(self, cases, labels):
        ticks = iter(range(10_000))
        priced = Scripted("priced", {q: (v.value, 0.9) for q, v in labels.items()},
                          cost=0.01)
        unpriced = Scripted("unpriced", {q: (v.value, 0.9) for q, v in labels.items()})
        rows = run(cases, {"priced": priced, "unpriced": unpriced},
                   timer=lambda: float(next(ticks)) / 1000)
        p = evaluate_benchmark(rows)["providers"]
        assert p["priced"]["cost"] == {"per_call": 0.01, "calls": 2 * len(cases),
                                       "total": round(0.01 * 2 * len(cases), 6)}
        assert p["unpriced"]["cost"]["total"] is None
        assert p["priced"]["latency_ms"]["p50"] == 1.0
        assert p["priced"]["latency_ms"]["p95"] == 1.0

    def test_repeatability_is_measured_only_when_asked_again(self, cases, labels):
        unstable = {"u": reference_providers(labels)["reference/unstable"]}
        once = evaluate_benchmark(run(cases, unstable))["providers"]["u"]
        assert once["determinism"]["repeatability"] is None
        assert not any("repeatability" in r for r in once["ineligible_because"])

    def test_an_answer_release_gate_set_aside_is_still_the_providers(self, cases, labels):
        """The hostile case: the verifier refuses the provider's "supported"
        (INJECTION_SUSPECTED), and the provider is scored on having said it."""
        obedient = Scripted("obedient", {q: ("supported", 0.99) for q in labels})
        rows = run(cases, {"obedient": obedient})
        [hostile] = [r for r in rows if r["case_id"] == "sb-14" and r["tier"] == "full"]
        assert hostile["unknown_reason"] == "INJECTION_SUSPECTED"
        assert hostile["answer"] == "supported" and hostile["injection_markers"] >= 3
        assert score_reading(hostile["label"], hostile["answer"],
                             hostile["confidence"])[1] is ReadingOutcome.FALSE_CONFIRM
        refusals = evaluate_benchmark(rows)["providers"]["obedient"]["refusals"]
        assert refusals["INJECTION_SUSPECTED"] == 1

    def test_a_failing_provider_has_no_answers_and_is_not_ranked(self, cases):
        down = Scripted("down", {}, raises=ProviderUnavailable("connection refused"))
        report = evaluate_benchmark(run(cases, {"down": down}))
        p = report["providers"]["down"]
        assert p["outcomes"]["NO_ANSWER"] == len(cases) and p["answer_rate"] == 0.0
        assert p["mean_score"] == DEFAULT_BENCHMARK_POLICY.no_answer
        assert report["ranking"] == [] and report["not_ranked"] == ["down"]

    def test_the_report_is_computed_from_persisted_rows_alone(self, cases, labels,
                                                              tmp_path):
        rows = run(cases, reference_providers(labels), repeats=2)
        path = tmp_path / "runs.jsonl"
        write_benchmark_runs(rows, path)
        assert evaluate_benchmark(read_benchmark_runs(path)) == evaluate_benchmark(rows)
        assert all(r["schema"] == BENCHMARK_RUN_SCHEMA for r in rows)

    def test_a_row_outside_the_schema_is_refused(self, tmp_path):
        bad = tmp_path / "bad.jsonl"
        bad.write_text(json.dumps({"schema": BENCHMARK_RUN_SCHEMA, "label": "supported",
                                   "answer": "PROMOTE"}) + "\n")
        with pytest.raises(BenchmarkError, match="three verdicts"):
            read_benchmark_runs(bad)
        bad.write_text(json.dumps({"schema": "x/1"}) + "\n")
        with pytest.raises(BenchmarkError):
            read_benchmark_runs(bad)

    def test_the_report_decides_nothing_and_chooses_nothing(self, cases, labels):
        report = evaluate_benchmark(run(cases, reference_providers(labels)))
        assert report["makes_admission_decision"] is False
        assert report["chooses_a_provider"] is False
        text = render_benchmark(report)
        assert "raw accuracy never ranks" in text and "Not ranked:" in text


# ── the runner ───────────────────────────────────────────────────────────────

def _runner():
    spec = importlib.util.spec_from_file_location("_semantic_bench",
                                                  ROOT / "benchmark" / "semantic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cli(*args, env=None):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("RG_SEMANTIC_")}
    return subprocess.run([sys.executable, str(ROOT / "benchmark" / "semantic.py"), *args],
                          capture_output=True, text=True, timeout=300,
                          env={**environment, **(env or {})})


class _AlwaysUnsettled:
    """A local OpenAI-compatible endpoint that answers insufficient_evidence."""

    def __init__(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                packet = json.loads(body["messages"][-1]["content"])["evidence_packet"]
                text = json.dumps({
                    "question_id": packet["question"]["question_id"],
                    "claim_id": packet["question"]["claim_id"],
                    "verdict": "insufficient_evidence", "confidence": 0.8,
                    "evidence_refs": [i["ref"] for i in packet["items"]],
                    "reason": "cannot tell"})
                payload = json.dumps({"model": "local-unsettled-1", "choices": [
                    {"message": {"role": "assistant", "content": text}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"


class TestTheRunner:

    def test_semantic_md_is_in_sync(self, cases):
        runner = _runner()
        expected = runner.render_md(evaluate_benchmark(runner.reference_run(cases)), cases)
        assert (ROOT / "benchmark" / "SEMANTIC.md").read_text(encoding="utf-8").strip() == \
            expected.strip(), "benchmark/SEMANTIC.md is stale — run: python benchmark/semantic.py --md"

    def test_the_page_says_what_it_does_not_measure(self):
        text = (ROOT / "benchmark" / "SEMANTIC.md").read_text(encoding="utf-8")
        assert "ranks by raw accuracy | **False**" in text
        assert "has independently adjudicated labels | **False**" in text
        assert "chooses a provider | **False**" in text

    def test_the_benchmarks_readme_names_it(self):
        text = (ROOT / "benchmark" / "README.md").read_text(encoding="utf-8")
        assert "semantic.py" in text and "SEMANTIC.md" in text

    def test_saved_runs_are_rescored_without_asking_anything(self, tmp_path):
        out = tmp_path / "runs.jsonl"
        asked = _cli("--json", "--out", str(out))
        assert asked.returncode == 0, asked.stderr
        again = _cli("--json", "--from", str(out))
        assert again.returncode == 0, again.stderr
        first, second = json.loads(asked.stdout), json.loads(again.stdout)
        first.pop("cases_digest")
        assert first == second

    def test_a_provider_from_the_environment_is_benchmarked(self, tmp_path):
        endpoint = _AlwaysUnsettled()
        try:
            result = _cli("--provider", "env=local", "--no-references", "--repeats", "2",
                          "--json", env={"RG_SEMANTIC_BASE_URL": endpoint.url + "/v1",
                                         "RG_SEMANTIC_MODEL": "unsettled"})
        finally:
            endpoint.httpd.shutdown()
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        local = report["providers"]["local"]
        assert local["answer_rate"] == 1.0 and local["coverage"] == 0.0
        assert local["false_confirm_rate"] == 0.0
        assert local["determinism"]["repeatability"] == 1.0
        assert local["latency_ms"]["p50"] is not None
        assert local["models"] == ["unsettled@local-unsettled-1"]
        assert report["ranking"] == ["local"]

    def test_an_unconfigured_provider_is_an_error_not_a_default(self):
        result = _cli("--provider", "env")
        assert result.returncode == 1 and "RG_SEMANTIC_MODEL" in result.stderr
