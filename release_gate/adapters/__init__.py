"""
Ingest adapters — turn what your AI platform already records into release-gate
evidence.

release-gate does not build observability and does not build quality evals. It
consumes them. These adapters are that consumption, made concrete: one command
converts a Langfuse trace, an OpenTelemetry span export, an Arize/Phoenix span
export, or a promptfoo eval run into the native format the gate rules on.

    release-gate ingest langfuse-export.json -o traces.json
    release-gate score governance.yaml --traces traces.json

Design constraints, in priority order:

1. **No new dependencies.** Adapters parse exported JSON; they never import a
   vendor SDK. `pip install release-gate` stays a three-library install.
2. **Never invent a step.** A span that cannot be mapped with evidence is
   skipped and counted, not guessed into a release decision.
3. **Report the gap.** Every conversion returns a `Coverage` record of what was
   skipped and why, so "meets the declared policy, with these gaps not
   assessed" stays literally true.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import arize, langfuse, otel, promptfoo
from .common import Coverage, load_document

__all__ = [
    "ADAPTERS",
    "Coverage",
    "IngestError",
    "convert",
    "detect",
    "get_adapter",
    "ingest_file",
    "load_document",
]

# Registry order is also tie-break order in `detect`: the more specific
# platform adapters are consulted before the vendor-neutral OTel one.
ADAPTERS = {
    langfuse.NAME: langfuse,
    promptfoo.NAME: promptfoo,
    arize.NAME: arize,
    otel.NAME: otel,
}

# Minimum confidence before auto-detection will commit to an adapter. Below
# this we raise and ask for an explicit --from rather than gate on a guess.
DETECT_THRESHOLD = 50


class IngestError(Exception):
    """Raised when an input cannot be identified or converted."""


def get_adapter(name: str):
    key = (name or "").strip().lower()
    aliases = {
        "phoenix": "arize",
        "arize-phoenix": "arize",
        "openinference": "arize",
        "opentelemetry": "otel",
        "otlp": "otel",
        "gen_ai": "otel",
        "promptfoo": "promptfoo",
        "langfuse": "langfuse",
    }
    key = aliases.get(key, key)
    if key not in ADAPTERS:
        known = ", ".join(sorted(set(list(ADAPTERS) + list(aliases))))
        raise IngestError(f"Unknown ingest source {name!r}. Known sources: {known}")
    return ADAPTERS[key]


def detect(doc: Any) -> List[Tuple[str, int]]:
    """Score every adapter against `doc`, best first."""
    scores: List[Tuple[str, int]] = []
    for name, adapter in ADAPTERS.items():
        try:
            confidence = int(adapter.detect(doc))
        except Exception:
            # A malformed document must not crash detection — it should simply
            # fail to match, and the caller gets an actionable error.
            confidence = 0
        if confidence > 0:
            scores.append((name, confidence))
    scores.sort(key=lambda pair: pair[1], reverse=True)
    return scores


def convert(
    doc: Any, source: Optional[str] = None, default_severity: str = "medium"
) -> Dict[str, Any]:
    """Convert a loaded export into release-gate's native evidence format.

    Returns a dict with:
      source   — the adapter that ran
      kind     — "traces" or "eval_results"
      payload  — the native payload, ready to write and feed to `score`
      coverage — what was mapped and what was skipped
      detected — the ranked detection scores (empty when `source` was explicit)
    """
    detected: List[Tuple[str, int]] = []

    if source and source.lower() != "auto":
        adapter = get_adapter(source)
    else:
        detected = detect(doc)
        if not detected or detected[0][1] < DETECT_THRESHOLD:
            hint = (
                f" Best guess was '{detected[0][0]}' at {detected[0][1]}% confidence."
                if detected
                else ""
            )
            raise IngestError(
                "Could not identify the export format."
                + hint
                + " Pass --from langfuse|promptfoo|otel|arize to convert it explicitly."
            )
        adapter = ADAPTERS[detected[0][0]]

    if adapter.KIND == "eval_results":
        payload, coverage = adapter.convert(doc, default_severity=default_severity)
    else:
        payload, coverage = adapter.convert(doc)

    return {
        "source": adapter.NAME,
        "label": adapter.LABEL,
        "kind": adapter.KIND,
        "payload": payload,
        "coverage": coverage.to_dict(),
        "detected": detected,
    }


def ingest_file(
    path: str, source: Optional[str] = None, default_severity: str = "medium"
) -> Dict[str, Any]:
    """Load a JSON/JSONL export from disk and convert it."""
    return convert(load_document(path), source=source, default_severity=default_severity)
