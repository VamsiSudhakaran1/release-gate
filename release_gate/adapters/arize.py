"""
Arize / Phoenix → release-gate trace adapter.

Consumes spans carrying the **OpenInference semantic conventions** — the
tracing standard behind Arize AX and Arize Phoenix — and emits release-gate
traces.

Three export shapes are accepted, because Phoenix and Arize each produce a
different one:

  1. OTLP/JSON with OpenInference attributes (collector / OTLP file export)
  2. A flat list of Phoenix span dicts — `px.Client().get_spans_dataframe()`
     written out with `.to_json(orient="records")`, where attributes are
     flattened into dotted keys on the row itself
  3. `{"data": [span, ...]}` — the Phoenix REST span page

What maps to what
-----------------
  openinference.span.kind    release-gate step
  ------------------------   -----------------------------------------
  LLM                        llm_call  (llm.model_name + token counts)
  TOOL                       tool_call (tool.name)
  RETRIEVER                  tool_call (retrieval is a tool call to gate)
  AGENT / CHAIN              skipped   (structural)
  EMBEDDING / RERANKER       skipped   (not agent actions a policy gates)
  GUARDRAIL                  skipped, and *noted* — see below

A GUARDRAIL span is deliberately not folded into the trace. A guardrail that
fired is a runtime mitigation, not a release-time safeguard, and counting it as
either a tool call or a pass would let a runtime filter vote on a pre-deploy
verdict. It is reported in coverage so the gap is visible instead of assumed.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from .common import (
    Coverage,
    as_int,
    coerce_args,
    drop_empty_traces,
    first_of,
    iso_to_sort_key,
    iter_otlp_spans,
    llm_step,
    make_trace,
    otlp_attributes,
    span_start_ns,
    tool_step,
)

NAME = "arize"
KIND = "traces"
LABEL = "Arize / Phoenix"

_LLM_KINDS = {"LLM"}
_TOOL_KINDS = {"TOOL", "RETRIEVER"}
_STRUCTURAL_KINDS = {"AGENT", "CHAIN", "UNKNOWN"}
_IGNORED_KINDS = {"EMBEDDING", "RERANKER", "EVALUATOR"}


def detect(doc: Any) -> int:
    """Confidence 0-100 that `doc` carries OpenInference spans."""
    best = 0
    for _span_id, attrs, _start, _trace_id, _name in _iter_spans(doc):
        if attrs.get("openinference.span.kind") or attrs.get("span_kind"):
            best = max(best, 95)
        elif any(k.startswith("llm.token_count") or k == "llm.model_name" for k in attrs):
            best = max(best, 85)
        elif any(k.startswith("openinference.") for k in attrs):
            best = max(best, 80)
        if best >= 95:
            break
    return best


def convert(doc: Any) -> Tuple[List[Dict[str, Any]], Coverage]:
    cov = Coverage(NAME)
    grouped: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
    order: List[str] = []

    for _span_id, attrs, start, trace_id, name in _iter_spans(doc):
        cov.seen += 1
        step = _map_span(attrs, name, cov)
        if step is None:
            continue
        if trace_id not in grouped:
            grouped[trace_id] = []
            order.append(trace_id)
        grouped[trace_id].append((start, step))
        cov.mapped += 1

    traces_out = []
    for trace_id in order:
        steps = [step for _, step in sorted(grouped[trace_id], key=lambda pair: pair[0])]
        traces_out.append(make_trace(trace_id, steps))

    traces_out = drop_empty_traces(traces_out)
    if not traces_out:
        cov.note(
            "No OpenInference spans mapped. Check the export carries "
            "openinference.span.kind (Arize AX / Phoenix instrumentation)."
        )
    return traces_out, cov


# ---------------------------------------------------------------- internals


def _iter_spans(doc: Any) -> Iterator[Tuple[str, Dict[str, Any], int, str, str]]:
    """Yield `(span_id, attributes, start_sort_key, trace_id, name)`.

    Normalizes the OTLP shape and Phoenix's flat-row shape into one stream so
    `convert` does not care which export it was handed.
    """
    otlp_spans = list(iter_otlp_spans(doc))
    if otlp_spans:
        for span, _resource in otlp_spans:
            attrs = otlp_attributes(span.get("attributes", []))
            trace_id = str(span.get("traceId") or span.get("trace_id") or "arize-trace")
            span_id = str(span.get("spanId") or span.get("span_id") or "")
            yield span_id, attrs, span_start_ns(span), trace_id, str(span.get("name", ""))
        return

    for row in _flat_rows(doc):
        attrs = _flat_attributes(row)
        trace_id = str(_flat_trace_id(row) or "arize-trace")
        span_id = str(first_of(row, "span_id", "spanId", "id") or "")
        start = iso_to_sort_key(first_of(row, "start_time", "startTime", "timestamp"))
        if not start:
            start = as_int(first_of(row, "start_time_unix_nano", "startTimeUnixNano"))
        yield span_id, attrs, start, trace_id, str(first_of(row, "name") or "")


def _flat_rows(doc: Any) -> List[Dict[str, Any]]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("data", "spans", "records"):
            value = doc.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        if "attributes" in doc or "span_kind" in doc:
            return [doc]
    return []


def _flat_attributes(row: Dict[str, Any]) -> Dict[str, Any]:
    """Collect attributes from a Phoenix row.

    Phoenix writes attributes either as a nested `attributes` object or as
    dotted columns on the row itself (`attributes.llm.model_name`, or bare
    `llm.model_name`), depending on how the dataframe was serialized.
    """
    attrs: Dict[str, Any] = {}

    nested = row.get("attributes")
    if isinstance(nested, dict):
        attrs.update(_flatten(nested))
    elif isinstance(nested, list):
        attrs.update(otlp_attributes(nested))

    for key, value in row.items():
        if key == "attributes":
            continue
        if key.startswith("attributes."):
            attrs[key[len("attributes."):]] = value
        elif "." in key and key.split(".", 1)[0] in ("llm", "tool", "openinference", "retrieval", "input", "output"):
            attrs[key] = value

    # `span_kind` is a first-class column in the dataframe export.
    if row.get("span_kind") and "openinference.span.kind" not in attrs:
        attrs["openinference.span.kind"] = row["span_kind"]

    return attrs


def _flatten(obj: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flatten a nested attribute object into dotted keys."""
    out: Dict[str, Any] = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            # Keep the nested dict too — `tool.parameters` is consumed whole.
            out[path] = value
            out.update(_flatten(value, prefix=f"{path}."))
        else:
            out[path] = value
    return out


def _flat_trace_id(row: Dict[str, Any]) -> Optional[str]:
    direct = first_of(row, "trace_id", "traceId")
    if direct:
        return str(direct)
    context = row.get("context")
    if isinstance(context, dict):
        value = first_of(context, "trace_id", "traceId")
        if value:
            return str(value)
    value = row.get("context.trace_id")
    return str(value) if value else None


def _map_span(attrs: Dict[str, Any], name: str, cov: Coverage) -> Optional[Dict[str, Any]]:
    kind = str(
        attrs.get("openinference.span.kind") or attrs.get("span_kind") or ""
    ).upper().strip()

    if kind in _LLM_KINDS:
        return llm_step(_model(attrs), _tokens(attrs))

    if kind in _TOOL_KINDS:
        tool_name = attrs.get("tool.name") or name or "unknown_tool"
        if kind == "RETRIEVER" and not attrs.get("tool.name"):
            tool_name = name or "retriever"
        return tool_step(str(tool_name), coerce_args(attrs.get("tool.parameters")))

    if kind == "GUARDRAIL":
        cov.skip("guardrail span")
        cov.note(
            "Guardrail spans were not counted as safeguards. A guardrail is a runtime "
            "mitigation; release-gate rules pre-deploy and does not credit it as a "
            "declared control. Declare the guardrail in governance.yaml to get credit."
        )
        return None

    if kind in _STRUCTURAL_KINDS:
        cov.skip(f"structural '{kind.lower()}' span")
        return None

    if kind in _IGNORED_KINDS:
        cov.skip(f"'{kind.lower()}' span (not a gated agent action)")
        return None

    # No declared kind — fall back to attribute evidence rather than guessing.
    if attrs.get("tool.name"):
        return tool_step(str(attrs["tool.name"]), coerce_args(attrs.get("tool.parameters")))
    if attrs.get("llm.model_name") or _tokens(attrs):
        return llm_step(_model(attrs), _tokens(attrs))

    cov.skip(f"unmapped span kind '{kind or 'missing'}'")
    return None


def _model(attrs: Dict[str, Any]) -> Optional[str]:
    for key in ("llm.model_name", "llm.invocation_parameters.model", "llm.system"):
        if attrs.get(key):
            return str(attrs[key])
    return None


def _tokens(attrs: Dict[str, Any]) -> int:
    total = as_int(attrs.get("llm.token_count.total"))
    if total:
        return total
    prompt = as_int(attrs.get("llm.token_count.prompt"))
    completion = as_int(attrs.get("llm.token_count.completion"))
    return prompt + completion
