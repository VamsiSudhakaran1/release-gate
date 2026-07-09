# The State of Agent Code Safety

*A scan of 30+ of the most-starred open-source AI-agent frameworks — and an
honest account of what a scanner should, and shouldn't, tell you.*

---

## The one-sentence problem

A static analyzer sees `eval(x)` and asks *"is `x` tainted by SQL or an HTTP
parameter?"* It has no concept of *"`x` is the model's reply."* That blind spot
— **model output reaching a code, shell, or deserialization sink** — is the
entire agent layer, and it is invisible to the tools most teams already run.

We went looking for how common it is. We scanned **30+ of the most-starred
open-source agent frameworks** (most with 1,000+ GitHub stars) with a static
analyzer that traces model/user input into dangerous sinks, then **hand-verified
every high-severity finding** against the actual source. This is what we found —
including, deliberately, the things we decided *not* to report.

---

## What's actually out there

### 1. Model output reaching `eval` / `exec` is real, and one is a published CVE

In roughly **one in five** of the frameworks we scanned, model-generated text
flows into `eval`, `exec`, `new Function`, or a shell — the remote-code-execution
surface SAST can't model.

Most of these are **code-writing agents by design**: a Minecraft skill-writer, a
browser-automation agent, a coding agent. The model writes code and the framework
runs it. That's the product, not a bug — but the *only* thing standing between a
prompt injection and code execution is a sandbox the scanner can't see. When a
maintainer says "that's intentional, it's sandboxed," the right follow-up is a
**blast-radius** question — *is the sandbox actually isolated, and can influenced
model output escape it?* — not a "you have a hidden RCE" accusation.

One case is unambiguous and already public: **SuperAGI's `eval()` on the
assistant's own reply ([CVE-2025-51472](https://www.gecko.security/blog/cve-2025-51472))**. A prompt
injection that slips past an input guardrail becomes code execution — *after* an
output evaluator has already scored the text as safe. Guardrails filter one
input; evaluators score one output; **neither blocks the release.**

### 2. Nobody bounds their output tokens

In our prevalence sample, **11 of 15 frameworks (73%)** assemble the LLM request
parameters in a dict and spread them (`create(**params)`) with **no
`max_tokens` / `max_completion_tokens`** anywhere in the path — 27 call sites in
total. On its own this is cost hygiene, not a vulnerability (every provider caps
output at the model's max). It becomes a real runaway-cost path only when it
co-occurs with an unbounded agent loop. But the ubiquity is the story: it's a
near-universal blind spot, and most scanners can't even *see* it because the
parameters are passed indirectly through `**kwargs`.

### 3. Deserialization is everywhere — and mostly fine

Frameworks pickle constantly: over local IPC pipes, in caches, to persist agent
state. A naive scanner flags every `pickle.loads()` as "RCE from untrusted
input." **Almost none of them are.** Which brings us to the part of this report
that matters more than the findings.

---

## The part nobody publishes: what we refused to flag

A scanner that cries wolf gets demoted to advisory and ignored. The hardest — and
most valuable — engineering in this space is **not flagging the things that look
scary but aren't.** Auditing these 30+ repos, we found and *removed* whole classes
of false positive. Each one is a real pattern in a real, well-engineered
framework that a lazy scanner would report as a critical vulnerability:

| Looks like… | Is actually… | Where we found it |
|---|---|---|
| `pickle.loads(data)` "RCE from user input" | a `LogRecord` off a **local multiprocessing pipe** — trusted internal transport | a top-tier voice-agent framework |
| `pickle.loads(message_ser)` "RCE" | the framework round-tripping **its own serialized objects** (state persistence) | a leading multi-agent framework |
| `HEADER_WORKER_TOKEN = "X-…-Token"` "hardcoded secret" | an **HTTP header name**, not a value | a top-tier voice-agent framework |
| `gas_token = "0x0000…0000"` "hardcoded secret" | the **Ethereum zero address** — a constant, not a key | an on-chain agent framework |
| `JWT_SECRET = "sk-proj-abc123…"` "leaked key" | fake data in an **archived example** | an agent framework's `examples/` |
| `search_key = "YOUR-AZURE-…-KEY"` "secret" | a **placeholder** in integration code | a major data-framework |
| 57 findings, `HOLD` | all in a **`cookbook/` of 256 tutorial files**; the core is clean | a minimalist agent framework |

That last row is the pattern that quietly wrecks trust: grading a framework on
its *tutorials* instead of its *code*. We now exclude `cookbook/`, `examples/`,
`tests/`, and demo paths from the score entirely — and surface them separately,
labelled as unscored — so the grade reflects the deployed framework, not its
teaching material.

**The discipline in one rule:** we assert **HIGH / confirmed** only when we can
*see* the dangerous input's source — a value assigned from an LLM call in scope,
or an unambiguous external name like `request.body`. When the danger is only
*inferred* from a variable's name (`data`, `message_ser`), we say so:
**MEDIUM / inferred — "confirm the source is trusted."** A judge rules on the
evidence in front of it, not on what a name suggests.

---

## How we verified (and what we're *not* claiming)

Every high-severity finding in this report was traced to the exact line and read
in context before we trusted it. That process is what produced the
false-positive table above — several findings that *looked* confirmed collapsed
under a two-minute read (the local-IPC pickle and the header-name "secret" both
came from a marquee framework, and both were wrong).

We are **not** publishing a precision/recall number yet. That requires a labeled
benchmark with true negatives, and we're building it — every verified verdict now
feeds a calibration corpus. What this report *is*: a methodology and a set of
hand-checked findings across the real ecosystem, plus a public account of the
false-positive classes we eliminated. Honesty about the second is the point.

---

## Confirmed in the wild

Credible means acted-on. Every entry here is a release-gate finding that a
maintainer of a real, shipping framework fixed and merged — verifiable, not
asserted. The list grows as findings land.

- **LightAgent** — unbounded streaming tool-call loop (the inner `while True`
  wasn't bounded by `max_retry`; a runaway under tool failure or prompt
  injection). Fixed & merged, with a regression test:
  [PR #71](https://github.com/wanxingai/LightAgent/pull/71).
<!-- Add each new confirmed fix as one bullet: framework — finding — merged PR link. -->

That's the bar — a click, not a claim.

---

## What this means if you ship an agent

- The risks that actually bite agents — model output reaching a sink,
  cross-agent trust, runaway loops — are **structurally invisible** to the SAST,
  guardrails, and evaluators you already run. They live in the seam between them.
- The blind spot is near-universal, not exotic: uncapped output in 73% of the
  frameworks we sampled, model-code execution in ~1 in 5.
- But a scanner is only worth putting in blocking CI if it **doesn't cry wolf.**
  The engineering that matters is refusing to flag the local IPC pipe, the header
  name, the tutorial folder — the exact places a grep-based tool embarrasses you.

Scan your own agent — free, no config — at **[release-gate.com](https://release-gate.com)**,
or:

```bash
pip install release-gate
release-gate audit .            # two honest scores + a PROMOTE/HOLD/BLOCK verdict
```

Every finding cites its evidence and its confidence. And if you maintain one of
the frameworks in that ~1-in-5, we'll send you the specific line privately — no
public callout.

---

*Methodology, the analyzer, and the full false-positive test suite are open
source. Findings were hand-verified; only publicly-disclosed vulnerabilities
(the SuperAGI CVE) and maintainer-confirmed fixes (LightAgent) are named — every
other pattern is reported in aggregate, by design.*
