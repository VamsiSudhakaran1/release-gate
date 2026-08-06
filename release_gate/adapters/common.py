"""
Shared helpers for the ingest adapters.

Stdlib only, on purpose: `pip install release-gate` pulls three small libraries
and an adapter must never add a fourth. We parse each platform's *exported
JSON*, we do not import its SDK. That is what keeps "works with your Langfuse
setup" a one-line install instead of a dependency negotiation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Step types understood by release_gate.trace_validator.TraceValidator.
LLM_CALL = "llm_call"
TOOL_CALL = "tool_call"
RETRY = "retry"
FALLBACK = "fallback"


class Coverage:
    """What an adapter mapped, and — more importantly — what it did not.

    release-gate's register is "meets the declared policy, with these gaps not
    assessed." An adapter that silently drops half a trace would launder a gap
    into a clean verdict, so every skip is counted and surfaced.
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self.seen = 0
        self.mapped = 0
        self._skipped: Dict[str, int] = {}
        self.notes: List[str] = []

    def skip(self, reason: str, n: int = 1) -> None:
        self._skipped[reason] = self._skipped.get(reason, 0) + n

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)

    @property
    def skipped(self) -> Dict[str, int]:
        return dict(self._skipped)

    @property
    def skipped_total(self) -> int:
        return sum(self._skipped.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "records_seen": self.seen,
            "records_mapped": self.mapped,
            "records_skipped": self.skipped_total,
            "skipped_by_reason": self.skipped,
            "notes": list(self.notes),
        }


def load_document(path: str) -> Any:
    """Read a JSON or JSONL export.

    JSONL is returned as a list of objects — every platform here can emit
    line-delimited spans, and callers treat both the same way.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Ingest input not found: {path}")

    text = p.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"Ingest input is empty: {path}")

    if p.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # A .json file that is actually line-delimited is common enough
        # (`promptfoo eval -o out.json` on some versions, span dumps) that
        # falling back beats failing.
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) > 1:
            return [json.loads(line) for line in lines]
        raise


def as_int(value: Any) -> int:
    """Coerce a token count to int.

    OTLP/JSON encodes 64-bit ints as *strings* (`{"intValue": "120"}`), and
    several SDKs emit floats. Returns 0 for anything uncoercible so a malformed
    usage block cannot crash a release gate.
    """
    if value is None or isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except (ValueError, AttributeError):
            return 0
    return 0


def unwrap_otlp_value(value: Any) -> Any:
    """Unwrap one OTLP/JSON AnyValue into a plain Python value."""
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "string_value"):
        if key in value:
            return value[key]
    for key in ("intValue", "int_value"):
        if key in value:
            return as_int(value[key])
    for key in ("doubleValue", "double_value"):
        if key in value:
            return value[key]
    for key in ("boolValue", "bool_value"):
        if key in value:
            return value[key]
    for key in ("arrayValue", "array_value"):
        if key in value:
            values = (value[key] or {}).get("values", [])
            return [unwrap_otlp_value(v) for v in values]
    for key in ("kvlistValue", "kvlist_value"):
        if key in value:
            return otlp_attributes((value[key] or {}).get("values", []))
    return value


def otlp_attributes(attributes: Any) -> Dict[str, Any]:
    """Flatten OTLP `[{key, value:{...}}]` into `{key: value}`.

    Also accepts an already-flat dict, which is how Phoenix's dataframe export
    and several collector exporters render the same attributes.
    """
    if isinstance(attributes, dict):
        return {k: unwrap_otlp_value(v) for k, v in attributes.items()}
    out: Dict[str, Any] = {}
    if not isinstance(attributes, list):
        return out
    for item in attributes:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if key is None:
            continue
        out[key] = unwrap_otlp_value(item.get("value"))
    return out


def iter_otlp_spans(doc: Any) -> Iterator[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Yield `(span, resource_attributes)` from an OTLP/JSON document.

    Handles both the camelCase (`resourceSpans`/`scopeSpans`) and snake_case
    (`resource_spans`/`scope_spans`) spellings, plus the legacy
    `instrumentationLibrarySpans` name still emitted by older collectors.
    """
    if isinstance(doc, list):
        for item in doc:
            yield from iter_otlp_spans(item)
        return
    if not isinstance(doc, dict):
        return

    resource_spans = doc.get("resourceSpans") or doc.get("resource_spans") or []
    for rs in resource_spans:
        if not isinstance(rs, dict):
            continue
        resource_attrs = otlp_attributes((rs.get("resource") or {}).get("attributes", []))
        scope_spans = (
            rs.get("scopeSpans")
            or rs.get("scope_spans")
            or rs.get("instrumentationLibrarySpans")
            or rs.get("instrumentation_library_spans")
            or []
        )
        for ss in scope_spans:
            if not isinstance(ss, dict):
                continue
            for span in ss.get("spans", []) or []:
                if isinstance(span, dict):
                    yield span, resource_attrs


def span_start_ns(span: Dict[str, Any]) -> int:
    """Best-effort start timestamp for ordering spans within a trace."""
    for key in ("startTimeUnixNano", "start_time_unix_nano", "startTime", "start_time"):
        if key in span:
            value = span[key]
            if isinstance(value, str) and not value.isdigit():
                return iso_to_sort_key(value)
            return as_int(value)
    return 0


def iso_to_sort_key(value: Any) -> int:
    """Turn an ISO-8601 timestamp into a sortable integer (nanoseconds).

    Returns 0 when unparseable — ordering then falls back to document order,
    which is what every export we have seen already uses.
    """
    if not isinstance(value, str) or not value:
        return 0
    from datetime import datetime

    text = value.strip().replace("Z", "+00:00")
    try:
        return int(datetime.fromisoformat(text).timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def make_trace(trace_id: str, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"trace_id": trace_id or "unknown", "steps": steps}


def llm_step(model: Optional[str], tokens: int) -> Dict[str, Any]:
    step: Dict[str, Any] = {"type": LLM_CALL, "tokens": max(0, as_int(tokens))}
    if model:
        step["model"] = str(model)
    return step


def tool_step(name: str, args: Any = None) -> Dict[str, Any]:
    step: Dict[str, Any] = {"type": TOOL_CALL, "tool": str(name)}
    step["args"] = args if isinstance(args, dict) else {}
    return step


def first_of(mapping: Dict[str, Any], *keys: str) -> Any:
    """Return the first present, non-None key — for camelCase/snake_case drift."""
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def coerce_args(value: Any) -> Dict[str, Any]:
    """Normalize a tool-argument blob into a dict.

    Tool args arrive as a dict, a JSON string, or free text depending on the
    platform. Non-dict payloads are preserved under `value` rather than dropped:
    trace policies match on the tool *name*, but a human reading the evidence
    wants the arguments that were actually passed.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        return {"value": value} if text else {}
    if value is None:
        return {}
    return {"value": value}


def drop_empty_traces(traces: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop traces that produced no steps — an empty trace gates on nothing."""
    return [t for t in traces if t.get("steps")]
