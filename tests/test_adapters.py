"""
Tests for the ingest adapters (Langfuse / promptfoo / OpenTelemetry / Arize).

Two things are under test, and the second matters as much as the first:

1. The mapping is correct — the right steps, tokens, and tool names come out.
2. The adapter refuses to invent evidence. A span it cannot map with evidence
   is skipped *and counted*, never guessed into a release decision. A gate that
   silently drops half a trace launders a gap into a clean verdict.
"""

import json
from pathlib import Path

import pytest

from release_gate.adapters import (
    ADAPTERS,
    IngestError,
    convert,
    detect,
    get_adapter,
    ingest_file,
)
from release_gate.adapters.common import as_int, coerce_args, otlp_attributes

FIXTURES = Path(__file__).resolve().parent.parent / "integrations"


def _steps(traces, kind=None):
    out = [s for t in traces for s in t["steps"]]
    return [s for s in out if kind is None or s["type"] == kind]


def _tools(traces):
    return [s["tool"] for s in _steps(traces, "tool_call")]


# ------------------------------------------------------------------ Langfuse


class TestLangfuse:
    @pytest.fixture
    def doc(self):
        return json.loads((FIXTURES / "langfuse" / "example-trace.json").read_text())

    def test_detected(self, doc):
        assert detect(doc)[0][0] == "langfuse"

    def test_generations_become_llm_calls_with_tokens(self, doc):
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        llm = _steps(traces, "llm_call")
        assert [s["tokens"] for s in llm] == [2100, 16100]
        assert all(s["model"] == "gpt-4o" for s in llm)

    def test_leaf_spans_become_tool_calls(self, doc):
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert _tools(traces) == ["get_order", "issue_refund", "send_email_external"]

    def test_parent_span_is_not_a_tool_call(self, doc):
        """The agent wrapper span must not be counted as a tool the agent called."""
        traces, cov = ADAPTERS["langfuse"].convert(doc)
        assert "refund-agent" not in _tools(traces)
        assert cov.skipped_total == 1
        assert "structural span (has child observations)" in cov.skipped

    def test_steps_are_ordered_by_start_time(self, doc):
        """Order decides retry-storm and tool-loop detection, so it must hold."""
        doc["observations"].reverse()
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert _tools(traces) == ["get_order", "issue_refund", "send_email_external"]

    def test_usage_details_spelling(self):
        doc = {
            "id": "t1",
            "observations": [
                {"id": "o1", "type": "GENERATION", "model": "claude", "usageDetails": {"input": 10, "output": 5}}
            ],
        }
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert _steps(traces, "llm_call")[0]["tokens"] == 15

    def test_openai_token_spelling(self):
        doc = {
            "id": "t1",
            "observations": [
                {"id": "o1", "type": "GENERATION", "usage": {"promptTokens": 7, "completionTokens": 3}}
            ],
        }
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert _steps(traces, "llm_call")[0]["tokens"] == 10

    def test_metadata_override_forces_tool_call(self):
        """A parent span the team knows is a tool can be tagged as one."""
        doc = {
            "id": "t1",
            "observations": [
                {
                    "id": "o1",
                    "type": "SPAN",
                    "name": "charge_card",
                    "metadata": {"release_gate": {"type": "tool_call"}},
                },
                {"id": "o2", "parentObservationId": "o1", "type": "SPAN", "name": "child"},
            ],
        }
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert "charge_card" in _tools(traces)

    def test_metadata_override_can_skip(self):
        doc = {
            "id": "t1",
            "observations": [
                {"id": "o1", "type": "SPAN", "name": "noise",
                 "metadata": {"release_gate": {"type": "skip"}}}
            ],
        }
        traces, cov = ADAPTERS["langfuse"].convert(doc)
        assert traces == []
        assert cov.skipped_total == 1

    def test_retry_and_fallback_overrides(self):
        doc = {
            "id": "t1",
            "observations": [
                {"id": "o1", "type": "SPAN", "name": "r", "metadata": {"release_gate_type": "retry"}},
                {"id": "o2", "type": "SPAN", "name": "f", "metadata": {"release_gate_type": "fallback"}},
            ],
        }
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert [s["type"] for s in traces[0]["steps"]] == ["retry", "fallback"]

    def test_api_list_page_shape(self, doc):
        traces, _ = ADAPTERS["langfuse"].convert({"data": [doc], "meta": {"page": 1}})
        assert len(traces) == 1

    def test_bare_observation_list_is_grouped_by_trace(self):
        doc = [
            {"id": "o1", "traceId": "tA", "type": "GENERATION", "usage": {"total": 5}},
            {"id": "o2", "traceId": "tB", "type": "GENERATION", "usage": {"total": 7}},
        ]
        traces, _ = ADAPTERS["langfuse"].convert(doc)
        assert {t["trace_id"] for t in traces} == {"tA", "tB"}


# ----------------------------------------------------------------- Promptfoo


class TestPromptfoo:
    @pytest.fixture
    def doc(self):
        return json.loads((FIXTURES / "promptfoo" / "example-results.json").read_text())

    def test_detected(self, doc):
        assert detect(doc)[0][0] == "promptfoo"

    def test_tallies_match_the_run(self, doc):
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        assert (agg["total"], agg["passed"], agg["failed"]) == (6, 4, 2)
        assert agg["pass_rate"] == 66.7

    def test_declared_severity_drives_critical_count(self, doc):
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        assert agg["critical_failed"] == 2

    def test_failure_reason_cites_the_failing_assertion(self, doc):
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        failed = [r for r in agg["results"] if not r["passed"]]
        assert any("not-contains" in r["failure_reason"] for r in failed)

    def test_passing_case_has_no_failure_reason(self, doc):
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        assert all(r["failure_reason"] is None for r in agg["results"] if r["passed"])

    def test_severity_is_never_guessed_upward(self):
        """No declared severity must not silently become 'critical'."""
        doc = {"results": [{"success": False, "testCase": {"description": "x"}}]}
        agg, cov = ADAPTERS["promptfoo"].convert(doc)
        assert agg["results"][0]["severity"] == "medium"
        assert agg["critical_failed"] == 0
        assert any("severity" in n for n in cov.notes)

    def test_default_severity_is_configurable(self):
        doc = {"results": [{"success": False, "testCase": {"description": "x"}}]}
        agg, _ = ADAPTERS["promptfoo"].convert(doc, default_severity="critical")
        assert agg["critical_failed"] == 1

    def test_severity_from_tags(self):
        doc = {
            "results": [
                {"success": False, "testCase": {"description": "x", "tags": ["severity:critical"]}}
            ]
        }
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        assert agg["critical_failed"] == 1

    def test_flat_results_nesting(self, doc):
        """Newer promptfoo puts rows at the top level; both shapes must work."""
        flat = {"evalId": doc["evalId"], "results": doc["results"]["results"]}
        agg, _ = ADAPTERS["promptfoo"].convert(flat)
        assert agg["total"] == 6

    def test_unnamed_case_gets_a_stable_identifiable_name(self):
        doc = {"results": [{"success": True, "testCase": {"vars": {"query": "hello there"}}}]}
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        assert "query=hello there" in agg["results"][0]["name"]

    def test_error_row_counts_as_failure(self):
        doc = {"results": [{"error": "provider timed out", "testCase": {"description": "x"}}]}
        agg, _ = ADAPTERS["promptfoo"].convert(doc)
        assert agg["failed"] == 1
        assert "timed out" in agg["results"][0]["failure_reason"]

    def test_empty_run_does_not_divide_by_zero(self):
        agg, _ = ADAPTERS["promptfoo"].convert({"evalId": "e", "results": []})
        assert agg["total"] == 0 and agg["pass_rate"] == 0


# ------------------------------------------------------------ OpenTelemetry


class TestOpenTelemetry:
    @pytest.fixture
    def doc(self):
        return json.loads((FIXTURES / "opentelemetry" / "example-spans.json").read_text())

    def test_detected(self, doc):
        assert detect(doc)[0][0] == "otel"

    def test_chat_spans_become_llm_calls(self, doc):
        traces, _ = ADAPTERS["otel"].convert(doc)
        assert [s["tokens"] for s in _steps(traces, "llm_call")] == [2100, 3520]

    def test_legacy_prompt_completion_token_names(self, doc):
        """Pre-1.27 instrumentation is still in the wild and must still count."""
        traces, _ = ADAPTERS["otel"].convert(doc)
        assert _steps(traces, "llm_call")[1]["tokens"] == 3100 + 420

    def test_execute_tool_becomes_tool_call(self, doc):
        traces, _ = ADAPTERS["otel"].convert(doc)
        assert _tools(traces) == ["get_order", "charge_card"]

    def test_non_genai_span_is_skipped_and_counted(self, doc):
        """An HTTP span is real work but not a gated agent action."""
        traces, cov = ADAPTERS["otel"].convert(doc)
        assert "HTTP POST /internal/orders" not in _tools(traces)
        assert cov.skipped["non-GenAI span (no gen_ai.* attributes)"] == 1

    def test_invoke_agent_is_structural(self, doc):
        traces, cov = ADAPTERS["otel"].convert(doc)
        assert cov.skipped["structural 'invoke_agent' span"] == 1

    def test_string_encoded_int_attributes(self):
        """OTLP/JSON encodes 64-bit ints as strings — a classic silent-zero bug."""
        attrs = otlp_attributes(
            [{"key": "gen_ai.usage.input_tokens", "value": {"intValue": "4096"}}]
        )
        assert attrs["gen_ai.usage.input_tokens"] == 4096

    def test_snake_case_otlp_spelling(self, doc):
        renamed = {
            "resource_spans": [
                {
                    "resource": doc["resourceSpans"][0]["resource"],
                    "scope_spans": doc["resourceSpans"][0]["scopeSpans"],
                }
            ]
        }
        traces, _ = ADAPTERS["otel"].convert(renamed)
        assert _tools(traces) == ["get_order", "charge_card"]

    def test_spans_grouped_per_trace_id(self):
        doc = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {"traceId": "A", "name": "chat", "attributes": [
                                    {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}}]},
                                {"traceId": "B", "name": "chat", "attributes": [
                                    {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}}]},
                            ]
                        }
                    ]
                }
            ]
        }
        traces, _ = ADAPTERS["otel"].convert(doc)
        assert {t["trace_id"] for t in traces} == {"A", "B"}

    def test_plain_otlp_without_genai_is_not_claimed(self):
        """Valid OTLP with no agent semantics must not auto-detect into a gate."""
        doc = {
            "resourceSpans": [
                {"scopeSpans": [{"spans": [{"traceId": "A", "name": "GET /", "attributes": [
                    {"key": "http.request.method", "value": {"stringValue": "GET"}}]}]}]}
            ]
        }
        assert ADAPTERS["otel"].detect(doc) < 50
        with pytest.raises(IngestError):
            convert(doc)


# ------------------------------------------------------------ Arize/Phoenix


class TestArize:
    @pytest.fixture
    def doc(self):
        return json.loads((FIXTURES / "arize" / "example-spans.json").read_text())

    def test_detected(self, doc):
        assert detect(doc)[0][0] == "arize"

    def test_llm_spans_use_openinference_token_counts(self, doc):
        traces, _ = ADAPTERS["arize"].convert(doc)
        assert [s["tokens"] for s in _steps(traces, "llm_call")] == [2100, 3280]

    def test_tool_and_retriever_spans_become_tool_calls(self, doc):
        traces, _ = ADAPTERS["arize"].convert(doc)
        assert _tools(traces) == ["policy_docs", "issue_refund", "delete_database"]

    def test_guardrail_span_is_not_credited_as_a_safeguard(self, doc):
        """A runtime guardrail must not vote on a pre-deploy verdict."""
        traces, cov = ADAPTERS["arize"].convert(doc)
        assert "prompt_injection_filter" not in _tools(traces)
        assert cov.skipped["guardrail span"] == 1
        assert any("guardrail" in n.lower() for n in cov.notes)

    def test_agent_span_is_structural(self, doc):
        _, cov = ADAPTERS["arize"].convert(doc)
        assert cov.skipped["structural 'agent' span"] == 1

    def test_otlp_shape_with_openinference_attributes(self):
        doc = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "T1",
                                    "name": "tool",
                                    "attributes": [
                                        {"key": "openinference.span.kind", "value": {"stringValue": "TOOL"}},
                                        {"key": "tool.name", "value": {"stringValue": "wire_transfer"}},
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        assert detect(doc)[0][0] == "arize"
        traces, _ = ADAPTERS["arize"].convert(doc)
        assert _tools(traces) == ["wire_transfer"]

    def test_dotted_column_export(self):
        """Phoenix's dataframe export flattens attributes onto the row."""
        doc = [
            {
                "name": "ChatCompletion",
                "context.trace_id": "T9",
                "span_kind": "LLM",
                "llm.model_name": "gpt-4o",
                "llm.token_count.total": 900,
            }
        ]
        traces, _ = ADAPTERS["arize"].convert(doc)
        assert _steps(traces, "llm_call")[0] == {
            "type": "llm_call", "tokens": 900, "model": "gpt-4o"
        }

    def test_nested_data_page_shape(self, doc):
        traces, _ = ADAPTERS["arize"].convert({"data": doc})
        assert _tools(traces) == ["policy_docs", "issue_refund", "delete_database"]


# ------------------------------------------------------------------ Registry


class TestRegistry:
    def test_every_adapter_declares_its_contract(self):
        for name, adapter in ADAPTERS.items():
            assert adapter.NAME == name
            assert adapter.KIND in ("traces", "eval_results")
            assert isinstance(adapter.LABEL, str) and adapter.LABEL

    @pytest.mark.parametrize(
        "alias,expected",
        [
            ("phoenix", "arize"),
            ("openinference", "arize"),
            ("opentelemetry", "otel"),
            ("otlp", "otel"),
            ("LANGFUSE", "langfuse"),
        ],
    )
    def test_aliases_resolve(self, alias, expected):
        assert get_adapter(alias).NAME == expected

    def test_unknown_source_is_rejected(self):
        with pytest.raises(IngestError):
            get_adapter("datadog")

    def test_unidentifiable_input_refuses_rather_than_guesses(self):
        with pytest.raises(IngestError) as exc:
            convert({"hello": "world"})
        assert "--from" in str(exc.value)

    def test_explicit_source_bypasses_detection(self):
        result = convert({"results": []}, source="promptfoo")
        assert result["source"] == "promptfoo"
        assert result["detected"] == []

    def test_wrong_explicit_source_does_not_crash(self):
        """Forcing the wrong adapter yields an empty conversion, not a traceback."""
        doc = json.loads((FIXTURES / "promptfoo" / "example-results.json").read_text())
        result = convert(doc, source="langfuse")
        assert result["payload"] == []

    @pytest.mark.parametrize(
        "doc",
        [
            {"resourceSpans": "not-a-list"},
            {"observations": "not-a-list"},
            {"results": {"results": "not-a-list"}},
            [None, 42, "text"],
            None,
        ],
    )
    def test_detection_survives_a_malformed_document(self, doc):
        """A corrupt export must fail to match, not crash the gate."""
        scores = detect(doc)
        assert all(confidence < 50 for _, confidence in scores)

    @pytest.mark.parametrize(
        "path,kind,source",
        [
            ("langfuse/example-trace.json", "traces", "langfuse"),
            ("promptfoo/example-results.json", "eval_results", "promptfoo"),
            ("opentelemetry/example-spans.json", "traces", "otel"),
            ("arize/example-spans.json", "traces", "arize"),
        ],
    )
    def test_shipped_examples_ingest(self, path, kind, source):
        """Every example in integrations/ must actually work as documented."""
        result = ingest_file(str(FIXTURES / path))
        assert result["source"] == source
        assert result["kind"] == kind
        assert result["coverage"]["records_mapped"] > 0

    def test_missing_file_raises_filenotfound(self):
        with pytest.raises(FileNotFoundError):
            ingest_file("does-not-exist.json")


# ----------------------------------------------------------------- CLI wiring


class TestCliWiring:
    """The documented commands must work as documented.

    These shell out on purpose: the README promises `release-gate score
    governance.yaml --traces <langfuse-export>` works with no conversion step,
    and only the real entry point proves that.
    """

    GOVERNANCE = str(FIXTURES / "governance.yaml")

    def _run(self, *args):
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "-m", "release_gate.cli", *args],
            capture_output=True,
            text=True,
            cwd=str(FIXTURES.parent),
        )

    def test_ingest_writes_native_traces(self, tmp_path):
        out = tmp_path / "traces.json"
        proc = self._run(
            "ingest", str(FIXTURES / "langfuse" / "example-trace.json"), "-o", str(out)
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        traces = json.loads(out.read_text())
        assert traces[0]["steps"][0]["type"] == "llm_call"

    def test_ingest_json_mode_is_machine_readable(self):
        proc = self._run(
            "ingest", str(FIXTURES / "arize" / "example-spans.json"), "--json"
        )
        assert proc.returncode == 0
        payload = json.loads(proc.stdout)
        assert payload["source"] == "arize"
        assert payload["coverage"]["records_skipped"] == 2

    def test_ingest_reports_what_it_could_not_map(self):
        proc = self._run("ingest", str(FIXTURES / "opentelemetry" / "example-spans.json"))
        assert "Not mapped" in proc.stdout
        assert "non-GenAI span" in proc.stdout

    def test_score_accepts_a_raw_platform_export_for_traces(self):
        """No conversion step: the export goes straight into the gate."""
        proc = self._run(
            "score", self.GOVERNANCE,
            "--traces", str(FIXTURES / "langfuse" / "example-trace.json"),
        )
        assert "Ingested traces from Langfuse" in proc.stdout
        assert "BLOCK" in proc.stdout
        assert proc.returncode == 1  # BLOCK

    def test_forbidden_tool_in_a_trace_blocks_the_release(self):
        proc = self._run(
            "score", self.GOVERNANCE,
            "--traces", str(FIXTURES / "langfuse" / "example-trace.json"),
            "--full",
        )
        assert "send_email_external" in proc.stdout

    def test_score_ingests_promptfoo_results_without_regrading(self):
        proc = self._run(
            "score", self.GOVERNANCE,
            "--eval-results", str(FIXTURES / "promptfoo" / "example-results.json"),
        )
        assert "ingested:promptfoo" in proc.stdout
        assert proc.returncode == 1  # two critical eval failures -> BLOCK

    def test_critical_eval_failures_are_cited_by_name(self):
        proc = self._run(
            "score", self.GOVERNANCE,
            "--eval-results", str(FIXTURES / "promptfoo" / "example-results.json"),
            "--full",
        )
        assert "refuses to reveal the system prompt" in proc.stdout

    def test_evals_and_eval_results_are_mutually_exclusive(self):
        proc = self._run(
            "score", self.GOVERNANCE,
            "--evals", str(FIXTURES.parent / "examples" / "evals.yaml"),
            "--eval-results", str(FIXTURES / "promptfoo" / "example-results.json"),
        )
        assert proc.returncode == 1
        assert "mutually exclusive" in proc.stdout

    def test_native_trace_files_still_work_unchanged(self):
        """The adapters must not regress the pre-existing native path."""
        proc = self._run(
            "score", str(FIXTURES.parent / "examples" / "governance-working.yaml"),
            "--traces", str(FIXTURES.parent / "examples" / "traces" / "safe-trace.json"),
        )
        assert "Ingested traces" not in proc.stdout
        assert "Traces checked" in proc.stdout

    def test_trace_export_passed_to_eval_results_is_rejected_clearly(self):
        proc = self._run(
            "score", self.GOVERNANCE,
            "--eval-results", str(FIXTURES / "langfuse" / "example-trace.json"),
        )
        assert proc.returncode == 1
        assert "--traces instead" in proc.stdout

    def test_ingest_help_is_listed(self):
        proc = self._run("--help-not-a-command")
        assert "release-gate ingest" in proc.stdout


# -------------------------------------------------------------------- Common


class TestCommonHelpers:
    @pytest.mark.parametrize(
        "value,expected",
        [("120", 120), (120, 120), (120.7, 120), (None, 0), ("nope", 0), (True, 0), ("", 0)],
    )
    def test_as_int_never_raises(self, value, expected):
        assert as_int(value) == expected

    def test_coerce_args_parses_json_strings(self):
        assert coerce_args('{"a": 1}') == {"a": 1}

    def test_coerce_args_preserves_non_json_text(self):
        assert coerce_args("just text") == {"value": "just text"}

    def test_coerce_args_handles_empty(self):
        assert coerce_args(None) == {} and coerce_args("") == {}

    def test_otlp_attributes_accepts_flat_dict(self):
        assert otlp_attributes({"a": 1}) == {"a": 1}
