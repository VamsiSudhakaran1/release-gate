"""
OpenTelemetry → release-gate trace adapter.

Consumes OTLP/JSON spans carrying the **GenAI semantic conventions**
(`gen_ai.*`) and emits release-gate traces. This is the vendor-neutral path:
any backend that can export OTLP JSON — a collector `file` exporter, Grafana
Tempo, Honeycomb, Jaeger, Datadog, or an SDK's `ConsoleSpanExporter` — becomes
a release-gate input without a per-vendor adapter.

What maps to what
-----------------
  gen_ai.operation.name                  release-gate step
  -----------------------------------    ----------------------------------
  chat / text_completion / generate_      llm_call  (model + token usage)
    content / embeddings
  execute_tool                           tool_call (gen_ai.tool.name)
  invoke_agent / create_agent            skipped   (structural)

Spans with no `gen_ai.*` attributes are skipped and counted: an HTTP or DB span
from the same trace is real work, but it is not agent behaviour a trace policy
gates on, and silently folding it in would corrupt `max_tool_calls`.

Token attributes follow the current convention
(`gen_ai.usage.input_tokens` / `output_tokens`) and the pre-1.27 spelling
(`prompt_tokens` / `completion_tokens`), because instrumentation in the wild
still emits both.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .common import (
    Coverage,
    as_int,
    coerce_args,
    drop_empty_traces,
    iter_otlp_spans,
    llm_step,
    make_trace,
    otlp_attributes,
    span_start_ns,
    tool_step,
)

NAME = "otel"
KIND = "traces"
LABEL = "OpenTelemetry"

_LLM_OPS = {
    "chat",
    "text_completion",
    "generate_content",
    "embeddings",
    "completion",
}
_TOOL_OPS = {"execute_tool", "tool"}
_AGENT_OPS = {"invoke_agent", "create_agent", "agent"}


def detect(doc: Any) -> int:
    """Confidence 0-100 that `doc` is OTLP/JSON with GenAI conventions."""
    spans = list(iter_otlp_spans(doc))
    if not spans:
        return 0

    has_gen_ai = False
    has_openinference = False
    for span, _ in spans[:50]:
        attrs = otlp_attributes(span.get("attributes", []))
        if any(k.startswith("gen_ai.") for k in attrs):
            has_gen_ai = True
        if any(k.startswith("openinference.") or k.startswith("llm.") for k in attrs):
            has_openinference = True

    if has_gen_ai and not has_openinference:
        return 95
    if has_gen_ai:
        # Both namespaces present: the Arize/OpenInference adapter models this
        # richer shape better, so yield to it while staying a valid fallback.
        return 60
    if has_openinference:
        return 0
    # Valid OTLP, but nothing agent-shaped to gate on.
    return 20


def convert(doc: Any) -> Tuple[List[Dict[str, Any]], Coverage]:
    cov = Coverage(NAME)
    grouped: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
    order: List[str] = []

    for span, _resource in iter_otlp_spans(doc):
        cov.seen += 1
        attrs = otlp_attributes(span.get("attributes", []))
        trace_id = str(span.get("traceId") or span.get("trace_id") or "otel-trace")

        step = _map_span(span, attrs, cov)
        if step is None:
            continue

        if trace_id not in grouped:
            grouped[trace_id] = []
            order.append(trace_id)
        grouped[trace_id].append((span_start_ns(span), step))
        cov.mapped += 1

    traces_out = []
    for trace_id in order:
        steps = [step for _, step in sorted(grouped[trace_id], key=lambda pair: pair[0])]
        traces_out.append(make_trace(trace_id, steps))

    traces_out = drop_empty_traces(traces_out)
    if not traces_out:
        cov.note(
            "No gen_ai.* spans found. release-gate reads the OpenTelemetry GenAI "
            "semantic conventions — check your instrumentation emits them."
        )
    return traces_out, cov


# ---------------------------------------------------------------- internals


def _map_span(
    span: Dict[str, Any], attrs: Dict[str, Any], cov: Coverage
) -> Optional[Dict[str, Any]]:
    operation = str(attrs.get("gen_ai.operation.name", "")).lower().strip()

    if not operation and not any(k.startswith("gen_ai.") for k in attrs):
        cov.skip("non-GenAI span (no gen_ai.* attributes)")
        return None

    if operation in _TOOL_OPS or attrs.get("gen_ai.tool.name"):
        name = attrs.get("gen_ai.tool.name") or _span_name(span) or "unknown_tool"
        return tool_step(str(name), coerce_args(attrs.get("gen_ai.tool.call.arguments")))

    if operation in _AGENT_OPS:
        cov.skip(f"structural '{operation}' span")
        return None

    if operation in _LLM_OPS or _has_model(attrs):
        return llm_step(_model(attrs), _tokens(attrs))

    # gen_ai.* present but the operation is one we do not model. Say so rather
    # than guessing a step type into a release decision.
    cov.skip(f"unmapped gen_ai operation '{operation or 'missing'}'")
    return None


def _span_name(span: Dict[str, Any]) -> Optional[str]:
    name = span.get("name")
    if not name:
        return None
    text = str(name)
    # OTel names tool spans "execute_tool {tool.name}" by convention.
    for prefix in ("execute_tool ", "tool "):
        if text.lower().startswith(prefix):
            return text[len(prefix):].strip() or text
    return text


def _has_model(attrs: Dict[str, Any]) -> bool:
    return bool(
        attrs.get("gen_ai.request.model")
        or attrs.get("gen_ai.response.model")
        or attrs.get("gen_ai.usage.input_tokens")
        or attrs.get("gen_ai.usage.output_tokens")
        or attrs.get("gen_ai.usage.prompt_tokens")
        or attrs.get("gen_ai.usage.completion_tokens")
    )


def _model(attrs: Dict[str, Any]) -> Optional[str]:
    for key in ("gen_ai.response.model", "gen_ai.request.model", "gen_ai.system"):
        if attrs.get(key):
            return str(attrs[key])
    return None


def _tokens(attrs: Dict[str, Any]) -> int:
    total = as_int(attrs.get("gen_ai.usage.total_tokens"))
    if total:
        return total
    input_tokens = as_int(attrs.get("gen_ai.usage.input_tokens")) or as_int(
        attrs.get("gen_ai.usage.prompt_tokens")
    )
    output_tokens = as_int(attrs.get("gen_ai.usage.output_tokens")) or as_int(
        attrs.get("gen_ai.usage.completion_tokens")
    )
    return input_tokens + output_tokens
