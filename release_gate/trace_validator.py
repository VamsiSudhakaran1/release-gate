"""
Trace Validator for release-gate.

Validates agent execution traces against declared policies.
Detects: unauthorized tool calls, retry storms, loop behavior,
token budget overruns, missing fallback paths.

Accepts a trace file in JSONL format (one JSON object per line) or
a single JSON file with a "steps" array.

Example trace (JSON):
  {
    "trace_id": "abc-123",
    "steps": [
      {"type": "llm_call",  "model": "gpt-4.1", "tokens": 2048},
      {"type": "tool_call", "tool": "send_email", "args": {"to": "user@corp.com"}},
      {"type": "tool_call", "tool": "search_docs", "args": {}},
      {"type": "llm_call",  "model": "gpt-4.1", "tokens": 800}
    ]
  }

Example trace_policies in governance.yaml:
  trace_policies:
    forbidden_tools: [delete_database, send_email_external]
    allowed_tools:   [search_docs, get_order, create_ticket]
    max_tool_calls:  10
    max_retries:     3
    max_tokens_per_run: 20000
    require_fallback_step: false
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class TraceValidator:
    """Validate one or more agent traces against a policy."""

    def validate(self, trace: Dict[str, Any], policies: Dict[str, Any]) -> Dict[str, Any]:
        steps = trace.get("steps", [])
        violations: List[str] = []
        warnings:   List[str] = []
        unauth_tools: List[str] = []

        forbidden = set(policies.get("forbidden_tools", []))
        allowed   = set(policies.get("allowed_tools", []))
        max_tools = policies.get("max_tool_calls")
        max_retry = policies.get("max_retries")
        max_tok   = policies.get("max_tokens_per_run")
        req_fb    = policies.get("require_fallback_step", False)

        tool_calls   = [s for s in steps if s.get("type") == "tool_call"]
        llm_calls    = [s for s in steps if s.get("type") == "llm_call"]
        total_tokens = sum(s.get("tokens", 0) for s in llm_calls)
        retries      = sum(1 for s in steps if s.get("type") == "retry")
        has_fallback = any(s.get("type") == "fallback" for s in steps)

        for step in tool_calls:
            tool = step.get("tool", "")
            if tool in forbidden:
                violations.append(f"Forbidden tool called: {tool}")
                unauth_tools.append(tool)

        if allowed:
            for step in tool_calls:
                tool = step.get("tool", "")
                if tool not in allowed and tool not in unauth_tools:
                    violations.append(f"Tool not in allowed list: {tool}")
                    unauth_tools.append(tool)

        if max_tools is not None and len(tool_calls) > max_tools:
            violations.append(f"Tool call limit exceeded: {len(tool_calls)} > {max_tools}")

        if max_retry is not None and retries > max_retry:
            violations.append(f"Retry limit exceeded: {retries} > {max_retry}")
        elif retries > 0:
            warnings.append(f"Agent retried {retries} time(s)")

        if max_tok is not None and total_tokens > max_tok:
            violations.append(f"Token budget exceeded: {total_tokens:,} > {max_tok:,}")

        tool_seq = [s.get("tool") for s in tool_calls]
        for i in range(len(tool_seq) - 2):
            if tool_seq[i] == tool_seq[i+1] == tool_seq[i+2]:
                warnings.append(f"Possible tool loop detected: '{tool_seq[i]}' called 3+ times consecutively")
                break

        if req_fb and not has_fallback:
            violations.append("Required fallback step was never triggered")

        status = "FAIL" if violations else ("WARN" if warnings else "PASS")

        return {
            "status":                 status,
            "trace_id":               trace.get("trace_id", "unknown"),
            "total_steps":            len(steps),
            "tool_calls":             len(tool_calls),
            "total_tokens":           total_tokens,
            "retries":                retries,
            "violations":             violations,
            "warnings":               warnings,
            "unauthorized_tool_calls": unauth_tools,
            "has_fallback_step":      has_fallback,
        }

    def validate_file(self, trace_path: str, policies: Dict[str, Any]) -> Dict[str, Any]:
        path = Path(trace_path)
        if not path.exists():
            return {"status": "ERROR", "error": f"Trace file not found: {trace_path}"}

        text = path.read_text(encoding="utf-8").strip()

        if path.suffix == ".jsonl":
            traces = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            obj = json.loads(text)
            traces = obj if isinstance(obj, list) else [obj]

        results = [self.validate(t, policies) for t in traces]

        all_violations = [v for r in results for v in r.get("violations", [])]
        all_warnings   = [w for r in results for w in r.get("warnings", [])]
        all_unauth     = list({t for r in results for t in r.get("unauthorized_tool_calls", [])})

        overall = "FAIL" if all_violations else ("WARN" if all_warnings else "PASS")

        return {
            "status":                 overall,
            "trace_count":            len(traces),
            "violations":             all_violations,
            "warnings":               all_warnings,
            "unauthorized_tool_calls": all_unauth,
            "per_trace":              results,
        }
