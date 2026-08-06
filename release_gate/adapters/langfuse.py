"""
Langfuse → release-gate trace adapter.

Consumes a Langfuse trace export — the JSON returned by
`GET /api/public/traces/{id}`, `GET /api/public/traces` (a `{data: [...]}`
page), or `langfuse.api.trace.get(...)` dumped to disk — and emits traces in
release-gate's native step format, ready for `release-gate score --traces`.

What maps to what
-----------------
  Langfuse observation      release-gate step
  ----------------------    -----------------------------------------
  type=GENERATION           llm_call   (model + token usage)
  type=SPAN/EVENT, leaf     tool_call  (tool = observation name)
  type=SPAN, has children   skipped    (structural: an agent/chain wrapper)

A *leaf* span is the honest definition of a tool call in Langfuse: the standard
integrations wrap each tool invocation in its own span, while agent and chain
wrappers are parents. Mapping every span to a tool call would invent tool calls
that never happened and fail a `max_tool_calls` policy on structure alone.

Overrides, when the heuristic is wrong for your instrumentation:

    langfuse.span(name="charge_card", metadata={"release_gate": {"type": "tool_call"}})

Accepted `release_gate.type` values: `tool_call`, `llm_call`, `retry`,
`fallback`, `skip`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .common import (
    Coverage,
    coerce_args,
    drop_empty_traces,
    first_of,
    iso_to_sort_key,
    llm_step,
    make_trace,
    tool_step,
    as_int,
)

NAME = "langfuse"
KIND = "traces"
LABEL = "Langfuse"

_OBS_TYPES = {"GENERATION", "SPAN", "EVENT", "AGENT", "TOOL", "CHAIN", "RETRIEVER", "EMBEDDING"}
_EXPLICIT = {"tool_call", "llm_call", "retry", "fallback", "skip"}


def detect(doc: Any) -> int:
    """Confidence 0-100 that `doc` is a Langfuse export."""
    traces = _as_traces(doc)
    if not traces:
        return 0

    score = 0
    for trace in traces[:5]:
        observations = _observations(trace)
        if not observations:
            continue
        # `observations` carrying Langfuse's uppercase type enum is the
        # signature no other supported platform emits.
        types = {str(o.get("type", "")).upper() for o in observations if isinstance(o, dict)}
        if types & _OBS_TYPES:
            score = max(score, 85)
        if any(k in trace for k in ("htmlPath", "projectId", "sessionId")):
            score = max(score, 95)
        if any("traceId" in o or "trace_id" in o for o in observations if isinstance(o, dict)):
            score = max(score, 90)
    return score


def convert(doc: Any) -> Tuple[List[Dict[str, Any]], Coverage]:
    cov = Coverage(NAME)
    traces_out: List[Dict[str, Any]] = []

    for trace in _as_traces(doc):
        observations = _observations(trace)
        if not observations:
            continue

        parent_ids = {
            o.get("parentObservationId") or o.get("parent_observation_id")
            for o in observations
            if isinstance(o, dict)
        }
        parent_ids.discard(None)

        ordered = sorted(
            (o for o in observations if isinstance(o, dict)),
            key=lambda o: iso_to_sort_key(first_of(o, "startTime", "start_time")),
        )

        steps: List[Dict[str, Any]] = []
        for obs in ordered:
            cov.seen += 1
            step = _map_observation(obs, parent_ids, cov)
            if step is not None:
                steps.append(step)
                cov.mapped += 1

        trace_id = str(first_of(trace, "id", "traceId", "trace_id") or "langfuse-trace")
        traces_out.append(make_trace(trace_id, steps))

    traces_out = drop_empty_traces(traces_out)
    if not traces_out:
        cov.note("No Langfuse observations mapped to steps — check the export contains `observations`.")
    return traces_out, cov


# ---------------------------------------------------------------- internals


def _as_traces(doc: Any) -> List[Dict[str, Any]]:
    """Normalize the several shapes a Langfuse export arrives in."""
    if isinstance(doc, dict):
        # API list page: {"data": [trace, ...], "meta": {...}}
        data = doc.get("data")
        if isinstance(data, list):
            return [t for t in data if isinstance(t, dict)]
        if _observations(doc):
            return [doc]
        return []

    if isinstance(doc, list):
        items = [t for t in doc if isinstance(t, dict)]
        if any(_observations(t) for t in items):
            return [t for t in items if _observations(t)]
        # A bare list of observations — group it into synthetic traces by traceId.
        if items and any(str(o.get("type", "")).upper() in _OBS_TYPES for o in items):
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for obs in items:
                key = str(first_of(obs, "traceId", "trace_id") or "langfuse-trace")
                grouped.setdefault(key, []).append(obs)
            return [{"id": k, "observations": v} for k, v in grouped.items()]
    return []


def _observations(trace: Any) -> List[Dict[str, Any]]:
    if not isinstance(trace, dict):
        return []
    obs = first_of(trace, "observations", "spans")
    return [o for o in obs if isinstance(o, dict)] if isinstance(obs, list) else []


def _map_observation(
    obs: Dict[str, Any], parent_ids: set, cov: Coverage
) -> Optional[Dict[str, Any]]:
    name = str(first_of(obs, "name") or "unnamed")
    obs_type = str(obs.get("type", "")).upper()

    override = _explicit_type(obs)
    if override == "skip":
        cov.skip("explicitly skipped via metadata.release_gate.type")
        return None
    if override == "retry":
        return {"type": "retry"}
    if override == "fallback":
        return {"type": "fallback"}
    if override == "tool_call":
        return tool_step(_tool_name(obs, name), _tool_args(obs))
    if override == "llm_call":
        return llm_step(_model(obs), _tokens(obs))

    if obs_type == "GENERATION":
        return llm_step(_model(obs), _tokens(obs))

    if obs_type in ("TOOL", "RETRIEVER"):
        # Langfuse's newer OTel-backed ingestion carries these kinds directly.
        return tool_step(_tool_name(obs, name), _tool_args(obs))

    if obs_type in ("SPAN", "EVENT", "AGENT", "CHAIN"):
        obs_id = first_of(obs, "id")
        if obs_id is not None and obs_id in parent_ids:
            cov.skip("structural span (has child observations)")
            cov.note(
                "Parent spans were treated as structure, not tool calls. Tag a parent with "
                "metadata={'release_gate': {'type': 'tool_call'}} if it really is one."
            )
            return None
        if obs_type in ("AGENT", "CHAIN"):
            cov.skip(f"{obs_type.lower()} wrapper span")
            return None
        return tool_step(_tool_name(obs, name), _tool_args(obs))

    cov.skip(f"unmapped observation type '{obs_type or 'missing'}'")
    return None


def _explicit_type(obs: Dict[str, Any]) -> Optional[str]:
    meta = obs.get("metadata")
    if not isinstance(meta, dict):
        return None
    rg = meta.get("release_gate")
    if isinstance(rg, dict):
        value = str(rg.get("type", "")).lower()
        if value in _EXPLICIT:
            return value
    value = str(meta.get("release_gate_type", "")).lower()
    return value if value in _EXPLICIT else None


def _tool_name(obs: Dict[str, Any], fallback: str) -> str:
    meta = obs.get("metadata")
    if isinstance(meta, dict):
        for key in ("tool_name", "toolName", "tool"):
            if meta.get(key):
                return str(meta[key])
    return fallback


def _tool_args(obs: Dict[str, Any]) -> Dict[str, Any]:
    return coerce_args(obs.get("input"))


def _model(obs: Dict[str, Any]) -> Optional[str]:
    model = first_of(obs, "model", "modelName", "model_name")
    if model:
        return str(model)
    meta = obs.get("metadata")
    if isinstance(meta, dict) and meta.get("model"):
        return str(meta["model"])
    return None


def _tokens(obs: Dict[str, Any]) -> int:
    """Total tokens for a generation, across Langfuse's usage spellings.

    v2 used `usage: {input, output, total, unit}`; v3 added `usageDetails`
    (and keeps `usage` for compatibility). Some SDK versions emit OpenAI's
    `promptTokens`/`completionTokens` names instead.
    """
    for key in ("usage", "usageDetails", "usage_details"):
        usage = obs.get(key)
        if not isinstance(usage, dict):
            continue
        total = as_int(first_of(usage, "total", "totalTokens", "total_tokens"))
        if total:
            return total
        prompt = as_int(first_of(usage, "input", "promptTokens", "prompt_tokens", "input_tokens"))
        completion = as_int(
            first_of(usage, "output", "completionTokens", "completion_tokens", "output_tokens")
        )
        if prompt or completion:
            return prompt + completion
    return 0
