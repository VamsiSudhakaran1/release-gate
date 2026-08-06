# release-gate × OpenTelemetry

**The vendor-neutral path: if your agent emits GenAI spans, it already works.**

This is the integration that scales without a per-vendor adapter. Any backend
that can export OTLP/JSON — a collector file exporter, Grafana Tempo, Honeycomb,
Jaeger, Datadog, or an SDK's `ConsoleSpanExporter` — becomes a release-gate
input.

---

## Install (2 minutes)

```bash
pip install release-gate
```

No OpenTelemetry SDK dependency. release-gate parses exported OTLP/JSON, so it
sits entirely outside your tracing pipeline and cannot perturb it.

## Use it

```bash
release-gate score governance.yaml --traces spans.json
```

`--traces` detects OTLP and converts in place. To see the conversion first:

```bash
release-gate ingest spans.json -o traces.json
```

## Getting OTLP/JSON out

**From the Collector** — add a file exporter:

```yaml
# otel-collector-config.yaml
exporters:
  file:
    path: /var/log/otel/spans.json

service:
  pipelines:
    traces:
      receivers:  [otlp]
      processors: [batch]
      exporters:  [file]        # alongside your real backend
```

**From a Python SDK**, straight to disk:

```python
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# ... or point ConsoleSpanExporter at a file for a quick local check
```

**From a backend**: Tempo, Honeycomb, and Jaeger all expose trace-by-ID APIs that
return OTLP/JSON. Any of those responses works as-is.

## What you get

```bash
release-gate score integrations/governance.yaml \
  --traces integrations/opentelemetry/example-spans.json --full
```

```
Ingested traces from OpenTelemetry (4/6 span(s) mapped).

  Traces checked   1  (1 violation)

  Critical failures:
    ✗ unauthorized_tool_call [trace] — Unauthorized tool called: charge_card

  Decision:  ✗  BLOCK  (score 91/100)
```

## How GenAI spans map

release-gate reads the [OpenTelemetry GenAI semantic
conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/).

| `gen_ai.operation.name` | release-gate step | Notes |
|---|---|---|
| `chat`, `text_completion`, `generate_content`, `embeddings` | `llm_call` | Model from `gen_ai.response.model` → `gen_ai.request.model` |
| `execute_tool` | `tool_call` | Tool from `gen_ai.tool.name` |
| `invoke_agent`, `create_agent` | *skipped, counted* | Structural |
| *(no `gen_ai.*` attributes)* | *skipped, counted* | HTTP/DB spans are real work, but not gated agent actions |

Token counts read both the current spelling
(`gen_ai.usage.input_tokens` / `output_tokens`) and the pre-1.27 one
(`prompt_tokens` / `completion_tokens`), since instrumentation in the wild still
emits both. Both camelCase (`resourceSpans`) and snake_case (`resource_spans`)
OTLP/JSON are accepted, as is the legacy `instrumentationLibrarySpans`.

**A note on integer encoding.** OTLP/JSON encodes 64-bit integers as *strings* —
`{"intValue": "4096"}`. A naive parser reads that as a truthy non-number and
silently scores every run at zero tokens, so every token-ceiling policy passes
forever. release-gate coerces explicitly and [tests for
it](../../tests/test_adapters.py). If you write your own OTLP consumer, this is
the bug to check for first.

### Non-GenAI spans are deliberately dropped

Your trace almost certainly contains HTTP client spans, DB spans, and framework
internals. Those are real work, but they are not agent actions a release policy
gates on — folding them in would corrupt `max_tool_calls` and make the ceiling
meaningless. They are skipped *and counted*, so the omission is visible:

```
  Not mapped (2) — stated, not silently dropped:
    ·   1  structural 'invoke_agent' span
    ·   1  non-GenAI span (no gen_ai.* attributes)
```

### If your spans aren't GenAI-conventional

Auto-detection deliberately refuses valid OTLP with no agent semantics rather
than gate on a guess:

```
Error: Could not identify the export format. Best guess was 'otel' at 20% confidence.
       Pass --from langfuse|promptfoo|otel|arize to convert it explicitly.
```

Either add GenAI attributes to your instrumentation (recommended — it's the
standard, and it makes your traces portable across every tool in the ecosystem),
or force the adapter with `--from otel` and check the mapped/skipped counts.

## Which adapter when both apply

If your spans carry **OpenInference** attributes (`openinference.span.kind`,
`llm.model_name`), use **[Arize / Phoenix](../arize/)** instead — it models that
richer shape better. Auto-detection handles this for you: the OTel adapter
lowers its own confidence to 60 when it sees both namespaces, so the Arize
adapter wins the tie.

## In CI

See [`workflow.yml`](workflow.yml) for a GitHub Actions job that gates a deploy
on spans pulled from a collector.

## Limits, stated plainly

- **Sampling is invisible to us.** If your tail sampler keeps 1% of traces, the
  gate rules on 1%. The trace count is reported so sample size shows up in the
  verdict; the sampling rate itself is not something release-gate can see.
- **Span *events* and *links* are not read.** Only spans and their attributes are
  mapped today. If you record retries as span events rather than spans, use
  `max_retries` with caution — see the Langfuse README for the explicit-tagging
  pattern.
- **Convention drift is real.** The GenAI semconv is still evolving. release-gate
  reads the current and previous spellings; if a future revision renames these
  again, the adapter needs a patch, and the mapped/skipped counts are how you'll
  notice.
