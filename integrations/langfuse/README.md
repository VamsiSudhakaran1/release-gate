# release-gate × Langfuse

**Turn Langfuse traces into a release decision.**

Langfuse tells you what your agent did. This integration decides whether what it
did is allowed to ship.

---

## Install (2 minutes)

```bash
pip install release-gate
```

That's it. No Langfuse SDK required — release-gate reads Langfuse's *exported
JSON*, so there is nothing to configure on the Langfuse side and no version
coupling between the two projects.

## Use it

**1. Export a trace** — any of these produce a file release-gate accepts:

```bash
# Public API
curl -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" \
  "$LANGFUSE_HOST/api/public/traces/$TRACE_ID" > trace.json

# Or a page of recent traces
curl -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" \
  "$LANGFUSE_HOST/api/public/traces?limit=50" > traces.json
```

```python
# Or from the SDK
from langfuse import Langfuse
import json

trace = Langfuse().api.trace.get("trace-id")
json.dump(trace.dict(), open("trace.json", "w"), default=str)
```

**2. Gate on it:**

```bash
release-gate score governance.yaml --traces trace.json
```

There is no conversion step. `--traces` detects Langfuse and converts in place.

## What you get

Run the shipped example:

```bash
release-gate score integrations/governance.yaml \
  --traces integrations/langfuse/example-trace.json --full
```

```
Ingested traces from Langfuse (5/6 span(s) mapped).
  Note: Parent spans were treated as structure, not tool calls.

  Project          refund-agent
  Traces checked   1  (2 violations)

  Score            91 / 100   confidence: medium

  Critical failures:
    ✗ unauthorized_tool_call [trace] — Unauthorized tool called: send_email_external

  Decision:  ✗  BLOCK  (score 91/100)
```

Every span in that trace succeeded. Latency was normal, no errors, nothing red in
the Langfuse UI. The agent looked up an order, issued a refund, and emailed the
customer — and one of those tools is forbidden by the release policy, and the run
burned 18,200 tokens against a 12,000 ceiling.

Observability showed you all of that. It had no opinion about it. That opinion is
the gate.

## Declare the policy

The verdict comes from `trace_policies` in your `governance.yaml`:

```yaml
trace_policies:
  allowed_tools:   [get_order, search_docs, issue_refund, lookup_customer]
  forbidden_tools: [send_email_external, delete_database, charge_card]
  max_tool_calls:  10
  max_retries:     2
  max_tokens_per_run: 12000
  require_fallback_step: false
```

`forbidden_tools` produces a **critical failure** — it blocks regardless of score.
`allowed_tools` is the stricter form: anything not on the list is unauthorized,
which catches tools you didn't know your agent had.

See [`../governance.yaml`](../governance.yaml) for the full working example.

## How Langfuse observations map

| Langfuse observation | release-gate step | Why |
|---|---|---|
| `type: GENERATION` | `llm_call` (model + tokens) | Model calls drive the token ceiling |
| `type: SPAN`/`EVENT`, **leaf** | `tool_call` (tool = span name) | Langfuse integrations wrap each tool in its own span |
| `type: SPAN`, **has children** | *skipped, counted* | It's an agent/chain wrapper, not a tool the agent called |
| `type: TOOL`/`RETRIEVER` | `tool_call` | Langfuse's OTel-backed ingestion sets these directly |
| `type: AGENT`/`CHAIN` | *skipped, counted* | Structural |

**Why leaf-only?** Because the alternative invents evidence. Your root
`refund-agent` span is not a tool your agent called; counting it as one would add
a phantom `refund-agent` tool call and could trip `max_tool_calls` on structure
alone. A gate that blocks releases for imaginary reasons gets switched off within
a week.

Token counts are read from `usage`, `usageDetails`, and the OpenAI-style
`promptTokens`/`completionTokens` spelling, because Langfuse v2, v3, and several
SDK versions each emit a different one.

### When the heuristic is wrong for you

If your instrumentation wraps a real tool in a parent span, say so explicitly:

```python
langfuse.span(
    name="charge_card",
    metadata={"release_gate": {"type": "tool_call"}},
)
```

Accepted values: `tool_call`, `llm_call`, `retry`, `fallback`, `skip`. The
override always wins over the heuristic.

Use `retry` and `fallback` to make those policies enforceable — `max_retries` and
`require_fallback_step` can only gate on steps they can see:

```python
langfuse.event(name="llm-retry",  metadata={"release_gate": {"type": "retry"}})
langfuse.event(name="human-escalation", metadata={"release_gate": {"type": "fallback"}})
```

## Inspect the conversion

To see exactly what release-gate read before you gate on it:

```bash
release-gate ingest trace.json -o traces.json
```

It prints what mapped, what didn't, and why — then writes the native trace file.
Commit that file if you want the converted evidence reviewable in the PR.

## In CI

See [`workflow.yml`](workflow.yml) for a complete GitHub Actions job that pulls
recent traces from Langfuse and gates the deploy on them.

## Limits, stated plainly

- **A trace is evidence of one run, not of the next one.** Gating on production
  traces tells you what the *current* version did. Pair it with
  `release-gate audit` (static agent-risk on the code) and `release-gate pr`
  (what a diff introduced) to cover the version that hasn't run yet.
- **Sampled tracing means sampled evidence.** If Langfuse sees 1% of traffic, the
  gate rules on 1%. release-gate reports the trace count so the sample size is
  visible in the verdict; it cannot know your sampling rate.
- **Tool *arguments* are captured but not policed.** Policies match on tool name.
  `issue_refund` for $9,000,000 passes a name-based allowlist — that class of
  check belongs in your agent's own guardrails, and release-gate does not pretend
  to cover it.
