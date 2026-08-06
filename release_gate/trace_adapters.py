"""OpenTelemetry / Langfuse / OpenInference traces -> release-gate trace steps.

WHY THIS EXISTS. The runtime half of the gate (TraceValidator, LoopVerifier)
already answers the questions practitioners run by hand — did the agent call a
tool it shouldn't have, did it spin on the same tool, did it blow the token
budget. It just asked for a bespoke JSONL nobody has:

    {"steps": [{"type": "tool_call", "tool": "search_docs", "args": {}}, ...]}

Meanwhile every deployed agent is *already* emitting this data. OpenTelemetry
has GenAI semantic conventions, Langfuse ships observations, LlamaIndex and
Arize emit OpenInference. The instrumentation problem was solved by the
ecosystem; the only thing missing was a mapping. That is all this module is —
no model, no inference, no heuristics beyond naming conventions the emitters
themselves publish.

DESIGN RULE: never invent a fact. If a span carries no token count we emit no
token count rather than a zero, because a fabricated zero would silently widen
someone's budget headroom. Anything we cannot classify is dropped, not guessed
into a tool_call — a phantom tool in the sequence would corrupt the
consecutive-repeat check that makes the loop warning meaningful.

Supported inputs (auto-detected, so `--trace` just works):
  * native      — release-gate's own {"steps": [...]} (passthrough, unchanged)
  * otlp        — OTLP/JSON export: {"resourceSpans": [{"scopeSpans": [...]}]}
  * otel_spans  — a bare list / JSONL of spans with an `attributes` map
  * langfuse    — {"observations": [...]} or a bare list of observations
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ── GenAI semantic-convention attribute names ────────────────────────────────
# Both spellings are live in the wild: the convention renamed prompt/completion
# to input/output tokens, and plenty of shipped instrumentation predates that.
# Reading only the current names would silently zero out real token counts.
_MODEL_KEYS = (
    "gen_ai.request.model", "gen_ai.response.model", "gen_ai.model",
    "llm.model_name", "llm.request.model", "model",
)
_INPUT_TOKEN_KEYS = (
    "gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens",
    "llm.token_count.prompt", "llm.usage.prompt_tokens",
)
_OUTPUT_TOKEN_KEYS = (
    "gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens",
    "llm.token_count.completion", "llm.usage.completion_tokens",
)
_TOTAL_TOKEN_KEYS = (
    "gen_ai.usage.total_tokens", "llm.token_count.total", "llm.usage.total_tokens",
)
_TOOL_NAME_KEYS = (
    "gen_ai.tool.name", "tool.name", "traceloop.entity.name",
)
_TOOL_ARG_KEYS = (
    "gen_ai.tool.call.arguments", "tool.parameters", "tool.args",
    "input.value", "gen_ai.tool.input",
)
# Operation values that mean "a model was called" vs "a tool was executed".
_LLM_OPS = {"chat", "text_completion", "generate_content", "generate", "completion"}
_TOOL_OPS = {"execute_tool", "tool", "invoke_tool"}


def _attr_value(v: Any) -> Any:
    """Unwrap an OTLP AnyValue ({"stringValue": "x"}) or return a plain value.

    OTLP JSON boxes every attribute by type; SDK-native and Langfuse payloads
    do not. Handling both here keeps the callers free of format checks.
    """
    if not isinstance(v, dict):
        return v
    for k in ("stringValue", "boolValue", "arrayValue", "kvlistValue", "bytesValue"):
        if k in v:
            inner = v[k]
            if k == "arrayValue" and isinstance(inner, dict):
                return [_attr_value(x) for x in inner.get("values", [])]
            return inner
    # Ints/doubles arrive as strings in OTLP JSON — coerce so budgets compare.
    for k in ("intValue", "doubleValue"):
        if k in v:
            try:
                return int(v[k]) if k == "intValue" else float(v[k])
            except (TypeError, ValueError):
                return v[k]
    return v


def _attrs_of(span: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a span's attributes to {key: value} from either encoding."""
    raw = span.get("attributes")
    out: Dict[str, Any] = {}
    if isinstance(raw, list):                      # OTLP: [{"key":…, "value":…}]
        for a in raw:
            if isinstance(a, dict) and "key" in a:
                out[a["key"]] = _attr_value(a.get("value"))
    elif isinstance(raw, dict):                    # SDK-native: {"key": value}
        out = {k: _attr_value(v) for k, v in raw.items()}
    # Some exporters hoist these to the top level instead of into attributes.
    for k in ("model", "name"):
        if k in span and k not in out:
            out.setdefault(k, span[k])
    return out


def _first(d: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _as_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _start_ns(span: Dict[str, Any]) -> int:
    """Sort key. Sequence is not cosmetic: the consecutive-repeat check that
    detects a stuck agent is meaningless if the steps are out of order."""
    for k in ("startTimeUnixNano", "start_time_unix_nano", "startTime", "start_time"):
        v = span.get(k)
        n = _as_int(v)
        if n is not None:
            return n
    return 0


def _classify(span: Dict[str, Any], attrs: Dict[str, Any]) -> Optional[str]:
    """'llm_call' | 'tool_call' | 'retry' | 'fallback' | None (drop).

    Returning None for the unrecognised case is deliberate. A span we cannot
    place is dropped rather than defaulted, because a phantom entry in the
    sequence would corrupt the repeat detection downstream.
    """
    op = str(attrs.get("gen_ai.operation.name") or attrs.get("operation.name") or "").lower()
    kind = str(attrs.get("openinference.span.kind") or attrs.get("span.kind") or "").lower()
    name = str(span.get("name") or attrs.get("name") or "").lower()
    lf_type = str(span.get("type") or "").upper()     # Langfuse observation type

    if op in _TOOL_OPS or kind == "tool" or _first(attrs, _TOOL_NAME_KEYS):
        return "tool_call"
    if op in _LLM_OPS or kind in ("llm", "chain") or lf_type == "GENERATION":
        return "llm_call"
    # Retry/fallback have no GenAI convention, so we only accept an EXPLICIT
    # signal — an attribute or a span named for it. Inferring a retry from two
    # similar spans would manufacture policy violations out of coincidence.
    if attrs.get("retry.attempt") is not None or attrs.get("gen_ai.retry") is not None \
            or name.startswith("retry") or name.endswith(".retry"):
        return "retry"
    if "fallback" in name or attrs.get("gen_ai.fallback") is not None:
        return "fallback"
    # A model is named but the operation isn't — still a model call.
    if _first(attrs, _MODEL_KEYS) and (
            _first(attrs, _INPUT_TOKEN_KEYS) or _first(attrs, _OUTPUT_TOKEN_KEYS)
            or _first(attrs, _TOTAL_TOKEN_KEYS)):
        return "llm_call"
    return None


def _tokens_of(attrs: Dict[str, Any], span: Dict[str, Any]) -> Optional[int]:
    """Total tokens for a model call, or None when the span never carried one.

    None is not 0. TraceValidator sums tokens against a declared ceiling, so a
    fabricated zero reads as free headroom on a run we actually know nothing
    about — the failure mode where a clean report is worse than no report.
    """
    total = _as_int(_first(attrs, _TOTAL_TOKEN_KEYS))
    if total is not None:
        return total
    tin = _as_int(_first(attrs, _INPUT_TOKEN_KEYS))
    tout = _as_int(_first(attrs, _OUTPUT_TOKEN_KEYS))
    if tin is not None or tout is not None:
        return (tin or 0) + (tout or 0)
    usage = span.get("usage")                      # Langfuse shape
    if isinstance(usage, dict):
        t = _as_int(usage.get("total") or usage.get("totalTokens"))
        if t is not None:
            return t
        i, o = _as_int(usage.get("input")), _as_int(usage.get("output"))
        if i is not None or o is not None:
            return (i or 0) + (o or 0)
    return None


def _tool_name(span: Dict[str, Any], attrs: Dict[str, Any]) -> str:
    """The tool's name — what the allow/forbid policy is written against."""
    n = _first(attrs, _TOOL_NAME_KEYS)
    if n:
        return str(n)
    # Convention names the span `execute_tool {tool}`; Langfuse uses the bare name.
    name = str(span.get("name") or "")
    for prefix in ("execute_tool ", "tool ", "tool."):
        if name.lower().startswith(prefix):
            return name[len(prefix):].strip()
    return name.strip()


def _tool_args(attrs: Dict[str, Any], span: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort arguments. Often absent by design — the conventions treat
    tool input as potentially sensitive — so {} is the honest common case."""
    raw = _first(attrs, _TOOL_ARG_KEYS)
    if raw is None:
        raw = span.get("input")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except (ValueError, TypeError):
            return {"value": raw}
    return {}


def _trace_id_of(span: Dict[str, Any]) -> str:
    for k in ("traceId", "trace_id", "traceID"):
        v = span.get(k)
        if v:
            return str(v)
    return "unknown"


def span_to_step(span: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One span -> one release-gate step, or None if it isn't agent activity."""
    attrs = _attrs_of(span)
    kind = _classify(span, attrs)
    if kind is None:
        return None
    if kind == "llm_call":
        step: Dict[str, Any] = {"type": "llm_call"}
        model = _first(attrs, _MODEL_KEYS) or span.get("model")
        if model:
            step["model"] = str(model)
        tokens = _tokens_of(attrs, span)
        if tokens is not None:
            step["tokens"] = tokens
        return step
    if kind == "tool_call":
        return {"type": "tool_call", "tool": _tool_name(span, attrs),
                "args": _tool_args(attrs, span)}
    return {"type": kind}


# ── Format detection + extraction ────────────────────────────────────────────

#: The step types release-gate speaks natively. A JSONL of these — one *step*
#: per line rather than one trace — is what `release-gate verify --trace` has
#: always accepted, so it stays a first-class input.
NATIVE_STEP_TYPES = {"llm_call", "tool_call", "retry", "fallback"}


def detect_format(obj: Any) -> str:
    """'native' | 'native_steps' | 'otlp' | 'langfuse' | 'otel_spans' | 'unknown'."""
    if isinstance(obj, dict):
        if "steps" in obj:
            return "native"
        if str(obj.get("type", "")) in NATIVE_STEP_TYPES:
            return "native_steps"
        if "resourceSpans" in obj or "resource_spans" in obj:
            return "otlp"
        if "observations" in obj:
            return "langfuse"
        if "spans" in obj:
            return "otel_spans"
        if "attributes" in obj or "spanId" in obj or "span_id" in obj:
            return "otel_spans"
        if str(obj.get("type", "")).upper() in ("GENERATION", "SPAN", "EVENT"):
            return "langfuse"
    if isinstance(obj, list) and obj:
        return detect_format(obj[0])
    return "unknown"


def _spans_from_otlp(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    spans: List[Dict[str, Any]] = []
    for rs in obj.get("resourceSpans") or obj.get("resource_spans") or []:
        for ss in (rs.get("scopeSpans") or rs.get("scope_spans")
                   or rs.get("instrumentationLibrarySpans") or []):
            spans.extend(ss.get("spans") or [])
    return spans


def _extract_spans(obj: Any, fmt: str) -> List[Dict[str, Any]]:
    if fmt == "otlp":
        return _spans_from_otlp(obj)
    if fmt == "langfuse":
        if isinstance(obj, dict):
            return list(obj.get("observations") or [])
        return [o for o in obj if isinstance(o, dict)]
    if fmt == "otel_spans":
        if isinstance(obj, dict):
            return list(obj.get("spans") or [obj])
        return [s for s in obj if isinstance(s, dict)]
    return []


def to_native(obj: Any) -> List[Dict[str, Any]]:
    """Convert any supported payload into release-gate trace dicts.

    Spans are grouped by trace id — one agent run per trace — and ordered by
    start time, because every sequence-sensitive check downstream assumes the
    steps are in the order they actually happened.
    """
    fmt = detect_format(obj)
    if fmt == "native":
        return [obj] if isinstance(obj, dict) else list(obj)
    if fmt == "native_steps":
        # Bare steps are already in order and already one run.
        steps = [obj] if isinstance(obj, dict) else [s for s in obj if isinstance(s, dict)]
        return [{"trace_id": "unknown", "steps": steps}]
    if fmt == "unknown":
        return []
    spans = _extract_spans(obj, fmt)
    grouped: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
    for sp in spans:
        step = span_to_step(sp)
        if step is None:
            continue
        grouped.setdefault(_trace_id_of(sp), []).append((_start_ns(sp), step))
    out: List[Dict[str, Any]] = []
    for tid, pairs in grouped.items():
        pairs.sort(key=lambda p: p[0])
        out.append({"trace_id": tid, "steps": [s for _, s in pairs]})
    return out


def load_trace_file(path: str) -> List[Dict[str, Any]]:
    """Read a trace file in any supported format and return native traces.

    JSONL is read as a stream of records; a file of individual OTLP spans is as
    common as a single wrapped document, and both must work without the user
    having to say which they have.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if p.suffix == ".jsonl" or (text[0] != "[" and "\n" in text and text.rstrip()[-1] != "}"):
        records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    else:
        try:
            records = json.loads(text)
        except json.JSONDecodeError:
            records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    if isinstance(records, dict):
        return to_native(records)
    if not isinstance(records, list) or not records:
        return []
    # A JSONL of native traces stays one-trace-per-line; a JSONL of raw spans
    # has to be reassembled across lines before it means anything.
    if detect_format(records[0]) == "native":
        return [r for r in records if isinstance(r, dict)]
    return to_native(records)


def load_trace(path: str) -> Optional[Dict[str, Any]]:
    """A single trace for the per-iteration LoopVerifier, or None if empty.

    The verifier judges one run at a time, so multi-trace files are flattened
    in emitted order rather than silently reduced to the first — dropping the
    rest would let a violation in run 2 pass a gate that only read run 1.
    """
    traces = load_trace_file(path)
    if not traces:
        return None
    if len(traces) == 1:
        return traces[0]
    steps: List[Dict[str, Any]] = []
    for t in traces:
        steps.extend(t.get("steps", []))
    return {"trace_id": f"{len(traces)} traces", "steps": steps}
