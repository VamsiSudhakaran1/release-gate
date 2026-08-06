# release-gate integrations

**Turn what your AI platform already records into a release decision.**

release-gate does not build observability, and it does not build quality evals.
Those layers are mature, crowded, and better served by the platforms below. What
is still missing is the layer *after* them: the thing that reads their output and
answers a different question.

> Observability answers **"what happened?"**
> Evaluation answers **"was the output good?"**
> Neither answers **"should this ship?"**

These integrations exist so the third question can be answered from evidence you
are already collecting — no new instrumentation, no new SDK, no new dependency.

| Integration | You already have | release-gate turns it into |
|---|---|---|
| **[Langfuse](langfuse/)** | Traces of what your agent did | A trace-policy verdict: forbidden tools, token ceilings, retry storms |
| **[Promptfoo](promptfoo/)** | A graded eval suite | A release verdict that weighs *which* evals failed, not how many |
| **[OpenTelemetry](opentelemetry/)** | GenAI-semconv spans, any backend | The same verdict, vendor-neutral |
| **[Arize / Phoenix](arize/)** | OpenInference spans | The same verdict, from AX or Phoenix |
| **[GitHub Actions](github-actions/)** | A CI pipeline | All of the above, blocking a merge |

## The 60-second version

```bash
pip install release-gate     # three dependencies, no vendor SDKs

# Export a trace from your platform, then:
release-gate score governance.yaml --traces langfuse-export.json
```

That is the whole integration. There is no conversion step to run first —
`--traces` and `--eval-results` auto-detect the platform and convert in place.
`release-gate ingest` exists if you want to inspect or commit the converted
evidence, but you never *have* to call it.

Try it right now against the shipped examples:

```bash
git clone https://github.com/VamsiSudhakaran1/release-gate && cd release-gate

release-gate score integrations/governance.yaml --traces integrations/langfuse/example-trace.json --full
release-gate score integrations/governance.yaml --eval-results integrations/promptfoo/example-results.json --full
release-gate score integrations/governance.yaml --traces integrations/opentelemetry/example-spans.json --full
release-gate score integrations/governance.yaml --traces integrations/arize/example-spans.json --full
```

All four gate against the same [`governance.yaml`](governance.yaml), so you can
watch one policy render verdicts on four different kinds of evidence.

## What this looks like

Here is the Langfuse example. Nothing in the trace errored. Latency was fine.
Every span is green in the Langfuse UI. And it still does not ship:

```
Ingested traces from Langfuse (5/6 span(s) mapped).

  Project          refund-agent
  Traces checked   1  (2 violations)

  Score            91 / 100   confidence: medium

  Critical failures:
    ✗ unauthorized_tool_call [trace] — Unauthorized tool called: send_email_external

  Decision:  ✗  BLOCK  (score 91/100)
```

91/100 and blocked. That is not a bug — it is the point. A score is an average,
and averages hide the one thing that matters. The agent emailed a customer from a
tool the release policy forbids. No amount of good behaviour elsewhere buys that
back, so the gate does not trade it away.

## Three design rules every adapter follows

These are what make the integrations safe to put in front of a deploy.

**1. No new dependencies.** Adapters parse your platform's *exported JSON*. They
never import its SDK. `pip install release-gate` remains a three-library install
(`pyyaml`, `jsonschema`, `cryptography`) whether you use one integration or all
of them — which is what makes this reviewable by a security team in an afternoon.

**2. Never invent a step.** A span that cannot be mapped with evidence is skipped,
not guessed. Mapping every Langfuse span to a tool call would invent tool calls
that never happened and fail a `max_tool_calls` policy on structure alone. A gate
that cries wolf gets disabled, and a disabled gate protects nothing.

**3. Report the gap.** Every conversion states what it could not map and why:

```
  Not mapped (2) — stated, not silently dropped:
    ·   1  structural 'agent' span
    ·   1  guardrail span

  Note: Guardrail spans were not counted as safeguards. A guardrail is a runtime
  mitigation; release-gate rules pre-deploy and does not credit it as a declared
  control. Declare the guardrail in governance.yaml to get credit.
```

Silently dropping half a trace would launder a coverage gap into a clean verdict.
release-gate's register is *"meets the declared policy, with these gaps not
assessed"* — never *"safe to deploy."* The skip counts are how that stays literally
true instead of merely well-intentioned.

## Which integration do I want?

- **You use Langfuse, Arize, or Phoenix** → use that adapter. It reads the
  platform's own export and understands its span kinds.
- **You use something else** (Braintrust, LangSmith, Honeycomb, Datadog, Tempo,
  Jaeger, a raw collector) → use **[OpenTelemetry](opentelemetry/)**. If your
  instrumentation emits the GenAI semantic conventions, it already works. This is
  the path that scales without a per-vendor adapter.
- **You grade with promptfoo** → use **[Promptfoo](promptfoo/)**. Note it feeds
  `--eval-results`, not `--traces`: eval verdicts and execution traces are
  different evidence and are scored on different axes.

You can pass both at once — traces *and* eval results — and get one verdict over
the combined evidence. That is the intended shape:

```bash
release-gate score governance.yaml \
  --traces        langfuse-export.json \
  --eval-results  promptfoo-results.json
```

## Adding another platform

An adapter is one file exposing three names — `NAME`, `KIND`, `detect(doc)`,
`convert(doc)` — registered in
[`release_gate/adapters/__init__.py`](../release_gate/adapters/__init__.py).
`detect` returns a 0-100 confidence so auto-detection can rank it; anything below
50 refuses rather than guesses. The existing four are each under 250 lines and
are the best specification of the contract. Ports welcome.
