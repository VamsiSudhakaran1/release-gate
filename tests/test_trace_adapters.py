"""OTel / Langfuse / OpenInference -> release-gate trace steps.

The runtime gate could always answer "did it call a forbidden tool", "did it
spin", "did it blow the budget". It just demanded a bespoke JSONL nobody had,
while every deployed agent was already emitting the same facts through its
tracer. These tests pin the mapping — and, more importantly, pin the two ways a
mapping like this goes wrong: inventing data that wasn't in the span, and
losing the order that makes a sequence mean anything.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from release_gate.trace_adapters import (
    detect_format, load_trace, load_trace_file, span_to_step, to_native,
)
from release_gate.trace_validator import TraceValidator

_S = lambda s: {"stringValue": s}          # noqa: E731 — OTLP AnyValue boxes
_I = lambda i: {"intValue": str(i)}        # noqa: E731 — ints arrive as strings


def _span(name, t, attrs, trace_id="t1"):
    return {"traceId": trace_id, "spanId": f"s{t}", "name": name,
            "startTimeUnixNano": str(t),
            "attributes": [{"key": k, "value": v} for k, v in attrs.items()]}


def _otlp(*spans):
    return {"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]}


# ── Format detection ────────────────────────────────────────────────────────

def test_detects_each_supported_format():
    assert detect_format({"steps": []}) == "native"
    assert detect_format({"type": "tool_call", "tool": "x"}) == "native_steps"
    assert detect_format(_otlp()) == "otlp"
    assert detect_format({"observations": []}) == "langfuse"
    assert detect_format({"traceId": "a", "attributes": {}}) == "otel_spans"
    assert detect_format({"nothing": 1}) == "unknown"


def test_unknown_payload_yields_nothing_rather_than_guessing():
    assert to_native({"metrics": [{"name": "cpu"}]}) == []


# ── OTLP ────────────────────────────────────────────────────────────────────

def test_otlp_llm_and_tool_spans():
    doc = _otlp(
        _span("chat gpt-4o", 1, {"gen_ai.operation.name": _S("chat"),
                                 "gen_ai.request.model": _S("gpt-4o"),
                                 "gen_ai.usage.input_tokens": _I(1500),
                                 "gen_ai.usage.output_tokens": _I(548)}),
        _span("execute_tool search_docs", 2, {"gen_ai.tool.name": _S("search_docs")}),
    )
    traces = to_native(doc)
    assert len(traces) == 1
    assert traces[0]["steps"] == [
        {"type": "llm_call", "model": "gpt-4o", "tokens": 2048},
        {"type": "tool_call", "tool": "search_docs", "args": {}},
    ]


def test_legacy_token_attribute_names_are_read():
    """The convention renamed prompt/completion to input/output tokens. Plenty
    of shipped instrumentation predates that; reading only the new names would
    silently zero out real usage and widen everyone's budget headroom."""
    doc = _otlp(_span("chat m", 1, {"gen_ai.operation.name": _S("chat"),
                                    "gen_ai.usage.prompt_tokens": _I(100),
                                    "gen_ai.usage.completion_tokens": _I(50)}))
    assert to_native(doc)[0]["steps"][0]["tokens"] == 150


def test_non_agent_spans_are_dropped_not_defaulted():
    """A span we cannot place is dropped. Defaulting it into a tool_call would
    put a phantom entry in the sequence and corrupt the repeat detection."""
    doc = _otlp(
        _span("GET /healthz", 1, {"http.method": _S("GET")}),
        _span("execute_tool search_docs", 2, {"gen_ai.tool.name": _S("search_docs")}),
        _span("SELECT users", 3, {"db.system": _S("postgresql")}),
    )
    steps = to_native(doc)[0]["steps"]
    assert steps == [{"type": "tool_call", "tool": "search_docs", "args": {}}]


def test_tool_name_falls_back_to_span_naming_convention():
    """`execute_tool {name}` is the convention's span name, so a tool is still
    identifiable when the attribute is absent."""
    doc = _otlp(_span("execute_tool send_email", 1,
                      {"gen_ai.operation.name": _S("execute_tool")}))
    assert to_native(doc)[0]["steps"][0]["tool"] == "send_email"


# ── Honesty: never invent a fact ────────────────────────────────────────────

def test_missing_tokens_is_absent_not_zero():
    """None is not 0. TraceValidator SUMS tokens against a declared ceiling, so
    a fabricated zero reads as free headroom on a run we know nothing about —
    a clean report that is worse than no report."""
    doc = _otlp(_span("chat m", 1, {"gen_ai.operation.name": _S("chat"),
                                    "gen_ai.request.model": _S("m")}))
    step = to_native(doc)[0]["steps"][0]
    assert step == {"type": "llm_call", "model": "m"}
    assert "tokens" not in step


def test_retry_needs_an_explicit_signal():
    """Two similar spans are not a retry. Inferring one would manufacture
    policy violations out of coincidence, since `max_retries` gates on count."""
    doc = _otlp(
        _span("chat m", 1, {"gen_ai.operation.name": _S("chat")}),
        _span("chat m", 2, {"gen_ai.operation.name": _S("chat")}),
    )
    assert all(s["type"] != "retry" for s in to_native(doc)[0]["steps"])

    flagged = _otlp(_span("retry chat", 3, {"retry.attempt": _I(2)}))
    assert to_native(flagged)[0]["steps"] == [{"type": "retry"}]


# ── Order and grouping ──────────────────────────────────────────────────────

def test_steps_are_ordered_by_start_time():
    """Sequence is not cosmetic — the consecutive-repeat check that detects a
    stuck agent is meaningless if the steps arrive out of order."""
    doc = _otlp(
        _span("execute_tool c", 30, {"gen_ai.tool.name": _S("c")}),
        _span("execute_tool a", 10, {"gen_ai.tool.name": _S("a")}),
        _span("execute_tool b", 20, {"gen_ai.tool.name": _S("b")}),
    )
    assert [s["tool"] for s in to_native(doc)[0]["steps"]] == ["a", "b", "c"]


def test_spans_are_grouped_into_one_trace_per_run():
    doc = _otlp(
        _span("execute_tool a", 1, {"gen_ai.tool.name": _S("a")}, trace_id="A"),
        _span("execute_tool z", 2, {"gen_ai.tool.name": _S("z")}, trace_id="B"),
        _span("execute_tool b", 3, {"gen_ai.tool.name": _S("b")}, trace_id="A"),
    )
    got = {t["trace_id"]: [s["tool"] for s in t["steps"]] for t in to_native(doc)}
    assert got == {"A": ["a", "b"], "B": ["z"]}


# ── Langfuse and OpenInference ──────────────────────────────────────────────

def test_langfuse_observations():
    doc = {"observations": [
        {"traceId": "r1", "type": "GENERATION", "name": "gen", "model": "gemini-3.5-flash-lite",
         "usage": {"input": 900, "output": 300}, "startTime": "100"},
        {"traceId": "r1", "type": "SPAN", "name": "execute_tool get_stock_price",
         "startTime": "200", "attributes": {"gen_ai.tool.name": "get_stock_price"}},
    ]}
    steps = to_native(doc)[0]["steps"]
    assert steps[0] == {"type": "llm_call", "model": "gemini-3.5-flash-lite", "tokens": 1200}
    assert steps[1]["tool"] == "get_stock_price"


def test_openinference_spans_with_json_string_args():
    doc = [
        {"trace_id": "x", "name": "llm", "start_time": 1,
         "attributes": {"openinference.span.kind": "LLM",
                        "llm.model_name": "gpt-4o", "llm.token_count.total": 700}},
        {"trace_id": "x", "name": "tool", "start_time": 2,
         "attributes": {"openinference.span.kind": "TOOL", "tool.name": "tavily_search",
                        "tool.parameters": '{"q": "rbi"}'}},
    ]
    steps = to_native(doc)[0]["steps"]
    assert steps[0] == {"type": "llm_call", "model": "gpt-4o", "tokens": 700}
    assert steps[1] == {"type": "tool_call", "tool": "tavily_search", "args": {"q": "rbi"}}


# ── Back-compat: the native shapes must keep working ────────────────────────

def test_native_trace_passes_through_unchanged():
    native = {"trace_id": "abc", "steps": [{"type": "tool_call", "tool": "x", "args": {}}]}
    assert to_native(native) == [native]


def test_native_bare_steps_are_wrapped_as_one_run():
    steps = [{"type": "llm_call", "tokens": 10}, {"type": "tool_call", "tool": "x"}]
    out = to_native(steps)
    assert len(out) == 1 and out[0]["steps"] == steps


def test_load_trace_file_reads_native_jsonl_and_otlp_json():
    with tempfile.TemporaryDirectory() as d:
        jl = Path(d, "t.jsonl")
        jl.write_text('{"type": "tool_call", "tool": "a"}\n{"type": "tool_call", "tool": "b"}\n')
        assert [s["tool"] for s in load_trace_file(str(jl))[0]["steps"]] == ["a", "b"]

        js = Path(d, "t.json")
        js.write_text(json.dumps(_otlp(
            _span("execute_tool q", 1, {"gen_ai.tool.name": _S("q")}))))
        assert load_trace_file(str(js))[0]["steps"][0]["tool"] == "q"


def test_load_trace_flattens_multiple_runs_rather_than_dropping_them():
    """The per-iteration verifier judges one run, but silently keeping only the
    first would let a violation in run 2 pass a gate that never read it."""
    doc = _otlp(
        _span("execute_tool a", 1, {"gen_ai.tool.name": _S("a")}, trace_id="A"),
        _span("execute_tool bad", 2, {"gen_ai.tool.name": _S("bad")}, trace_id="B"),
    )
    with tempfile.TemporaryDirectory() as d:
        p = Path(d, "multi.json")
        p.write_text(json.dumps(doc))
        tools = [s["tool"] for s in load_trace(str(p))["steps"]]
    assert set(tools) == {"a", "bad"}


# ── End to end through the validator that consumes this ─────────────────────

def test_otlp_export_drives_real_policy_violations():
    doc = _otlp(
        _span("chat gpt-4o", 1, {"gen_ai.operation.name": _S("chat"),
                                 "gen_ai.usage.input_tokens": _I(1500),
                                 "gen_ai.usage.output_tokens": _I(548)}),
        _span("execute_tool search_docs", 2, {"gen_ai.tool.name": _S("search_docs")}),
        _span("execute_tool search_docs", 3, {"gen_ai.tool.name": _S("search_docs")}),
        _span("execute_tool search_docs", 4, {"gen_ai.tool.name": _S("search_docs")}),
        _span("execute_tool send_email", 5, {"gen_ai.tool.name": _S("send_email")}),
    )
    with tempfile.TemporaryDirectory() as d:
        p = Path(d, "run.json")
        p.write_text(json.dumps(doc))
        res = TraceValidator().validate_file(str(p), {
            "forbidden_tools": ["send_email"],
            "allowed_tools": ["search_docs"],
            "max_tokens_per_run": 20000,
        })
    assert res["status"] == "FAIL"
    assert any("send_email" in v for v in res["violations"])
    # The practitioner's #1 manual check — "same tool repeatedly without
    # progressing" — now answered from telemetry the app already emits. These
    # spans carry no tool arguments (the usual OTel default), so the warning
    # correctly makes the hedged claim rather than asserting identical input.
    warn = " ".join(res["warnings"])
    assert "arguments were not recorded" in warn
    assert res["per_trace"][0]["total_tokens"] == 2048


def test_otlp_with_tool_arguments_distinguishes_stuck_from_iterating():
    """When the exporter DOES capture tool input, the adapter carries it through
    and the loop check can separate a stuck agent from multi-query retrieval."""
    def call(t, q):
        return _span(f"execute_tool search", t, {
            "gen_ai.tool.name": _S("search"),
            "gen_ai.tool.call.arguments": _S(json.dumps({"q": q}))})

    def warns(*queries):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.json")
            p.write_text(json.dumps(_otlp(*[call(i, q) for i, q in enumerate(queries)])))
            return TraceValidator().validate_file(str(p), {})["warnings"]

    assert any("identical arguments" in w for w in warns("tax", "tax", "tax"))
    assert warns("tax", "gst", "tds") == []


def test_empty_and_unparseable_files_report_clearly():
    with tempfile.TemporaryDirectory() as d:
        empty = Path(d, "e.json")
        empty.write_text("")
        assert TraceValidator().validate_file(str(empty), {})["status"] == "ERROR"

        junk = Path(d, "j.json")
        junk.write_text("{not json")
        assert TraceValidator().validate_file(str(junk), {})["status"] == "ERROR"
