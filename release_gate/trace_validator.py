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
    max_identical_tool_calls: 3   # repeats of the SAME tool with the SAME args
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


#: Repeats of an identical call before we call it non-progress. Override with
#: `trace_policies: max_identical_tool_calls`.
DEFAULT_IDENTICAL_CALL_LIMIT = 3


def _arg_key(step: Dict[str, Any]) -> Optional[str]:
    """A canonical key for a tool call's arguments, or None if not recorded.

    None is the honest answer, not `{}`: the GenAI conventions treat tool input
    as potentially sensitive and most exporters omit it. Collapsing "no
    arguments" and "arguments unknown" into the same key would let an unknown
    match an unknown and turn three legitimately different searches into a
    fabricated loop.
    """
    args = step.get("args")
    if not isinstance(args, dict) or not args:
        return None
    try:
        return json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(sorted(args.items(), key=lambda kv: str(kv[0])))


class TraceValidator:
    """Validate one or more agent traces against a policy."""

    def _non_progress_warnings(self, tool_calls: List[Dict[str, Any]],
                               policies: Dict[str, Any]) -> List[str]:
        """Detect an agent that is repeating itself rather than progressing.

        The signal is the one practitioners actually watch for by hand: the same
        tool called with the *same arguments*. Keying on the tool NAME alone —
        which this did originally — cannot tell a stuck agent from a working
        one, because `search_docs("tax")`, `search_docs("gst")`,
        `search_docs("tds")` is multi-query retrieval doing exactly its job.
        Identical arguments mean the call returned the same thing and the agent
        learned nothing; that is what makes it a loop rather than iteration.

        How hard we look scales with the evidence in the trace:

        * arguments recorded → count identical calls ANYWHERE in the run, which
          also catches an agent oscillating A→B→A→B→A between two tools.
        * arguments absent   → fall back to consecutive same-name calls only,
          and say so in the message. Without arguments we cannot distinguish
          repetition from iteration, so we make the weaker claim rather than
          dress a guess up as a finding.
        """
        limit = policies.get("max_identical_tool_calls") or DEFAULT_IDENTICAL_CALL_LIMIT
        keys = [(s.get("tool", ""), _arg_key(s)) for s in tool_calls]

        # Arguments recorded: identical call repeated anywhere is non-progress.
        counts: Dict[Any, int] = {}
        for k in keys:
            if k[1] is not None:
                counts[k] = counts.get(k, 0) + 1
        worst = max((c for c in counts.values()), default=0)
        if worst >= limit:
            tool, argk = max(counts, key=lambda k: counts[k])
            shown = argk if len(argk) <= 120 else argk[:117] + "..."
            return [f"Possible tool loop detected: '{tool}' called {worst} times "
                    f"with identical arguments {shown} — the call returns the "
                    f"same result each time, so the agent is not progressing"]

        # Arguments absent: only a consecutive run of the same name is usable,
        # and the claim is hedged to match what the trace actually proves.
        run = 1
        for i in range(1, len(keys)):
            same_name = keys[i][0] == keys[i - 1][0]
            both_unknown = keys[i][1] is None and keys[i - 1][1] is None
            run = run + 1 if (same_name and both_unknown) else 1
            if run >= limit:
                return [f"Possible tool loop detected: '{keys[i][0]}' called "
                        f"{run}+ times consecutively; arguments were not recorded "
                        f"in the trace, so this may be legitimate iteration — "
                        f"enable tool-argument capture to tell them apart"]
        return []

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

        warnings.extend(self._non_progress_warnings(tool_calls, policies))

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
