# release-gate × Arize / Phoenix

**Turn OpenInference spans into a release decision.**

Works with both Arize AX and open-source Arize Phoenix — they share the
[OpenInference](https://github.com/Arize-ai/openinference) semantic conventions,
and that's what release-gate reads.

---

## Install (2 minutes)

```bash
pip install release-gate
```

No Arize or Phoenix SDK dependency. release-gate reads exported spans.

## Use it

```bash
release-gate score governance.yaml --traces spans.json
```

## Getting spans out

**From Phoenix** (the dataframe export — most common):

```python
import phoenix as px

df = px.Client().get_spans_dataframe()
df.to_json("spans.json", orient="records")
```

**From Phoenix, a single trace:**

```python
df = px.Client().get_spans_dataframe(
    f"trace_id == '{trace_id}'"
)
df.to_json("spans.json", orient="records")
```

**From Arize AX**: export spans via the platform's export API, or point an OTLP
file exporter at the same pipeline. Both OTLP/JSON and flat span records work —
release-gate accepts three shapes and picks automatically:

1. OTLP/JSON with OpenInference attributes
2. A flat list of span records with dotted attribute columns (the dataframe export)
3. `{"data": [span, ...]}` (the Phoenix REST span page)

## What you get

```bash
release-gate score integrations/governance.yaml \
  --traces integrations/arize/example-spans.json --full
```

```
Ingested traces from Arize / Phoenix (5/7 span(s) mapped).
  Note: Guardrail spans were not counted as safeguards.

  Traces checked   1  (1 violation)

  Critical failures:
    ✗ unauthorized_tool_call [trace] — Unauthorized tool called: delete_database

  Decision:  ✗  BLOCK  (score 87/100)
```

## How OpenInference spans map

| `openinference.span.kind` | release-gate step | Notes |
|---|---|---|
| `LLM` | `llm_call` | `llm.model_name` + `llm.token_count.*` |
| `TOOL` | `tool_call` | `tool.name`, args from `tool.parameters` |
| `RETRIEVER` | `tool_call` | Retrieval *is* a tool call worth gating |
| `AGENT`, `CHAIN` | *skipped, counted* | Structural |
| `EMBEDDING`, `RERANKER`, `EVALUATOR` | *skipped, counted* | Not gated agent actions |
| `GUARDRAIL` | *skipped, counted, **and noted*** | See below |

Token counts prefer `llm.token_count.total`, falling back to
`prompt` + `completion`. When a span declares no kind, release-gate falls back to
attribute evidence (`tool.name` → tool call, `llm.model_name` → LLM call) rather
than guessing from the span name.

### Why RETRIEVER counts as a tool call

Retrieval is where indirect prompt injection enters an agent. A run that pulled
from a vector store took an action with a blast radius, and a release policy
should be able to say so:

```yaml
trace_policies:
  allowed_tools: [policy_docs, issue_refund]   # retriever span names included
```

If you'd rather not gate on retrievers, just list them in `allowed_tools`.

### Why GUARDRAIL spans are deliberately not credited

A `GUARDRAIL` span is skipped, and release-gate says so out loud:

```
  Note: Guardrail spans were not counted as safeguards. A guardrail is a runtime
  mitigation; release-gate rules pre-deploy and does not credit it as a declared
  control. Declare the guardrail in governance.yaml to get credit.
```

This is a deliberate category line, not an oversight. A guardrail that fired
proves something was caught *at runtime, in one run*. It is not evidence that the
control exists, is enabled in the environment you're about to deploy to, or will
fire next time. Counting it as a passed safeguard would let a runtime filter vote
on a pre-deploy verdict — and would quietly reward an agent for needing to be
saved.

To get credit for a guardrail, **declare it** as policy:

```yaml
checks:
  identity_boundary:
    enabled: true
    authentication:
      required: true
      type: oauth2
```

Declared and enforceable beats observed-once. That distinction is most of what
the governance layer is for.

## In CI

See [`workflow.yml`](workflow.yml) for a GitHub Actions job that gates a deploy
on Phoenix spans.

## Limits, stated plainly

- **Phoenix's dataframe export flattens attributes in several ways** depending on
  pandas version and options. release-gate handles nested `attributes` objects,
  `attributes.`-prefixed columns, and bare dotted columns — but if your export
  produces a shape none of those cover, `release-gate ingest --json` will show
  zero mapped spans rather than a wrong verdict. Please open an issue with the
  shape; adapters are ~200 lines and easy to extend.
- **Evaluations attached to Phoenix spans are not read.** Arize's own eval
  annotations are a separate surface from OpenInference spans. If you want eval
  results in the verdict, export them and pass `--eval-results`, or use
  [promptfoo](../promptfoo/).
- **Sampled tracing means sampled evidence** — same caveat as every trace-based
  gate. The trace count is reported; the sampling rate is not visible to us.
