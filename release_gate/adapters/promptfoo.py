"""
Promptfoo → release-gate eval-results adapter.

Consumes `promptfoo eval -o results.json` and emits the eval-results aggregate
that `ReadinessScorer` consumes, for `release-gate score --eval-results`.

Why ingest instead of re-run
----------------------------
release-gate does not build quality evals and does not re-grade them. Promptfoo
already ran the suite and graded it; re-running would produce a second, weaker
opinion about the same question. We take promptfoo's verdict as *evidence* and
rule on it — the release decision is ours, the grading stays theirs.

Which is the whole point: **a green promptfoo run is an input to the gate, not
the gate.** A suite where every assertion passes still yields HOLD or BLOCK when
the failures that did occur are `critical`, or when the code/governance axes
fail. Passing evals earn a release; they do not authorize one.

Severity
--------
Promptfoo has no severity concept, and release-gate gates on `critical`. Rather
than guess, severity is read (in order) from:

  1. `testCase.metadata.severity`   — the explicit, recommended route
  2. a `severity:<level>` entry in the test's `tags`
  3. `--default-severity` (default: `medium`)

so nothing is silently promoted to critical. Declare it in promptfooconfig.yaml:

    tests:
      - description: refuses to leak the system prompt
        metadata: {severity: critical, category: safety}
        assert: [{type: llm-rubric, value: does not reveal instructions}]
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .common import Coverage

NAME = "promptfoo"
KIND = "eval_results"
LABEL = "Promptfoo"

_VALID_SEVERITIES = ("critical", "high", "medium", "low")


def detect(doc: Any) -> int:
    """Confidence 0-100 that `doc` is a promptfoo eval output."""
    if not isinstance(doc, dict):
        return 0

    score = 0
    if "evalId" in doc or "shareableUrl" in doc:
        score = max(score, 70)

    results = _result_rows(doc)
    if results:
        row = results[0]
        keys = set(row.keys())
        # `gradingResult` + `testCase` together are promptfoo's signature; no
        # other supported export pairs them.
        if "gradingResult" in keys or ("testCase" in keys and "success" in keys):
            score = max(score, 95)
        elif {"success", "prompt"} <= keys or {"success", "vars"} <= keys:
            score = max(score, 75)

    if isinstance(doc.get("config"), dict) and "providers" in doc["config"]:
        score = max(score, 80)
    return score


def convert(doc: Any, default_severity: str = "medium") -> Tuple[Dict[str, Any], Coverage]:
    cov = Coverage(NAME)
    if default_severity not in _VALID_SEVERITIES:
        default_severity = "medium"

    rows = _result_rows(doc)
    results: List[Dict[str, Any]] = []

    for row in rows:
        cov.seen += 1
        if not isinstance(row, dict):
            cov.skip("non-object result row")
            continue
        results.append(_map_row(row, default_severity))
        cov.mapped += 1

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    critical_failed = sum(
        1 for r in results if not r["passed"] and r.get("severity") == "critical"
    )

    if total and not _has_declared_severity(rows):
        cov.note(
            f"No test declared a severity; all {total} case(s) defaulted to "
            f"'{default_severity}'. release-gate gates on 'critical' — declare "
            "metadata.severity in promptfooconfig.yaml so a real safety failure blocks."
        )

    aggregate = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "critical_failed": critical_failed,
        "pass_rate": round(passed / total * 100, 1) if total else 0,
        "results": results,
        "mode": "ingested:promptfoo",
        "source": {
            "platform": "promptfoo",
            "eval_id": doc.get("evalId") if isinstance(doc, dict) else None,
        },
    }
    return aggregate, cov


# ---------------------------------------------------------------- internals


def _result_rows(doc: Any) -> List[Any]:
    """Find the result rows across promptfoo's output nestings.

    Older versions nest as `{results: {results: [...], stats: {...}}}`; newer
    ones put the rows at `{results: [...]}`. Both are still in the wild.
    """
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return []

    results = doc.get("results")
    if isinstance(results, list):
        return results
    if isinstance(results, dict):
        inner = results.get("results")
        if isinstance(inner, list):
            return inner
    return []


def _map_row(row: Dict[str, Any], default_severity: str) -> Dict[str, Any]:
    test_case = row.get("testCase") if isinstance(row.get("testCase"), dict) else {}
    grading = row.get("gradingResult") if isinstance(row.get("gradingResult"), dict) else {}

    passed = _passed(row, grading)
    return {
        "name": _name(row, test_case),
        "severity": _severity(test_case, default_severity),
        "category": _category(test_case),
        "passed": passed,
        "failure_reason": None if passed else _failure_reason(row, grading),
        "response": _response(row),
        "expected": _expected(test_case),
    }


def _passed(row: Dict[str, Any], grading: Dict[str, Any]) -> bool:
    if isinstance(row.get("success"), bool):
        return row["success"]
    if isinstance(grading.get("pass"), bool):
        return grading["pass"]
    # An explicit error field means the case did not pass, whatever else is set.
    if row.get("error"):
        return False
    score = row.get("score", grading.get("score"))
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        return score > 0
    return False


def _name(row: Dict[str, Any], test_case: Dict[str, Any]) -> str:
    for candidate in (
        test_case.get("description"),
        row.get("description"),
        (row.get("prompt") or {}).get("label") if isinstance(row.get("prompt"), dict) else None,
    ):
        if candidate:
            return str(candidate)

    # No description: build a stable, readable name from the test vars so a
    # failing case is still identifiable in the evidence pack.
    variables = test_case.get("vars") or row.get("vars")
    if isinstance(variables, dict) and variables:
        rendered = ", ".join(
            f"{k}={_truncate(str(v), 40)}" for k, v in list(variables.items())[:2]
        )
        return f"promptfoo case ({rendered})"
    return "promptfoo case"


def _severity(test_case: Dict[str, Any], default_severity: str) -> str:
    metadata = test_case.get("metadata")
    if isinstance(metadata, dict):
        value = str(metadata.get("severity", "")).lower()
        if value in _VALID_SEVERITIES:
            return value

    for tag in _tags(test_case):
        text = str(tag).lower()
        if text.startswith("severity:"):
            value = text.split(":", 1)[1].strip()
            if value in _VALID_SEVERITIES:
                return value

    return default_severity


def _category(test_case: Dict[str, Any]) -> str:
    metadata = test_case.get("metadata")
    if isinstance(metadata, dict) and metadata.get("category"):
        return str(metadata["category"])

    for tag in _tags(test_case):
        text = str(tag).lower()
        if text.startswith("category:"):
            return text.split(":", 1)[1].strip() or "general"

    asserts = test_case.get("assert")
    if isinstance(asserts, list) and asserts:
        kinds = [a.get("type") for a in asserts if isinstance(a, dict) and a.get("type")]
        if kinds:
            return str(kinds[0])
    return "general"


def _tags(test_case: Dict[str, Any]) -> List[Any]:
    """Promptfoo tags are a list on some versions, a dict on others."""
    tags = test_case.get("tags")
    if isinstance(tags, list):
        return tags
    if isinstance(tags, dict):
        return [f"{k}:{v}" for k, v in tags.items()]
    metadata = test_case.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("tags"), list):
        return metadata["tags"]
    return []


def _failure_reason(row: Dict[str, Any], grading: Dict[str, Any]) -> str:
    if row.get("error"):
        return str(row["error"])

    # Prefer the specific failing assertion over the summary line.
    components = grading.get("componentResults")
    if isinstance(components, list):
        failed = [
            c for c in components
            if isinstance(c, dict) and c.get("pass") is False
        ]
        if failed:
            reasons = []
            for c in failed[:3]:
                kind = (c.get("assertion") or {}).get("type") if isinstance(c.get("assertion"), dict) else None
                reason = str(c.get("reason", "assertion failed")).strip()
                reasons.append(f"[{kind}] {reason}" if kind else reason)
            return "; ".join(reasons)

    if grading.get("reason"):
        return str(grading["reason"])
    return "promptfoo reported the case as failed"


def _response(row: Dict[str, Any]) -> Optional[str]:
    response = row.get("response")
    if isinstance(response, dict):
        output = response.get("output")
        if output is not None:
            return _stringify(output)
    if row.get("output") is not None:
        return _stringify(row["output"])
    return None


def _expected(test_case: Dict[str, Any]) -> str:
    asserts = test_case.get("assert")
    if isinstance(asserts, list) and asserts:
        parts = []
        for a in asserts[:3]:
            if not isinstance(a, dict):
                continue
            kind = a.get("type", "assert")
            value = a.get("value")
            parts.append(f"{kind}: {_truncate(_stringify(value), 60)}" if value is not None else str(kind))
        if parts:
            return "; ".join(parts)
    return "promptfoo assertions"


def _has_declared_severity(rows: List[Any]) -> bool:
    for row in rows:
        if not isinstance(row, dict):
            continue
        test_case = row.get("testCase")
        if not isinstance(test_case, dict):
            continue
        metadata = test_case.get("metadata")
        if isinstance(metadata, dict) and str(metadata.get("severity", "")).lower() in _VALID_SEVERITIES:
            return True
        for tag in _tags(test_case):
            if str(tag).lower().startswith("severity:"):
                return True
    return False


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _truncate(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
