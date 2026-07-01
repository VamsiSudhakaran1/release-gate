# release-gate — Roadmap & Direction

> The judge rules on **evidence**, not circumstance. This document is the
> north star, not a commitment: each frontier item ships only when a **real
> user's pain** validates it — not on our hypothesis.

## The principle: armor the engine, not the wings

Wald's WWII bombers: you reinforce where the planes that *didn't* come back
were hit — not where the returning planes have visible bullet holes.

- **Bullet holes on returning planes** = the findings we can already see and
  everyone checks (`eval(model_output)`, uncapped loops, injection surfaces).
  Survivable. Visible. Commoditizing — SAST tools and guardrails will catch up.
- **The planes that don't come back** = catastrophic agent failures that leave
  **no code fingerprint** — money wired wrong, prod data deleted, secrets
  exfiltrated through a poisoned tool, a defamatory email sent. They show up as
  *incidents*, not as grep-able patterns. That a repo scans clean is often the
  survivorship bias, not proof of safety.

So the durable value is **not** more static rules. It is checking the volatile,
un-standardized, necessary-before-production risks that static analysis,
guardrails, and evaluators structurally cannot see.

## Where we sit (and why we complement, not duplicate)

| Layer | Job | Blind spot we cover |
|---|---|---|
| SAST (SonarQube, Bandit, Snyk) | code-layer vulns | can't tell a value came from an LLM |
| Guardrails (Lakera, NeMo, Llama Guard) | filter one request at runtime | injection that succeeds *inside* the model; the action *after* the filter |
| Evaluators (Ragas, DeepEval, Braintrust) | score an output's quality | damage happens *before/regardless of* the score |
| **release-gate** | **verdict on readiness, from evidence, pre-deploy** | *"can this agent hurt you, and is the hurt gated?"* |

## What exists today (the standard-conformance layer — necessary, table-stakes)

- **`audit`** — AST + taint static scan (Python-deep). Agent-specific: flags a
  sink **only when model/user input reaches it**; silent on generic code.
  Findings cite evidence (`source → sink`). Two axes: Agent Code Safety +
  Governance.
- **`agent-score` / live scan** — the language-agnostic behavioral judge. Runs
  any agent (Python/TS/Go/HTTP/closed-source), plants a canary, fires a tiered
  injection/exfiltration battery, cites the attack + leaked response as evidence.
- **`loop-sim`** — cost/convergence simulation (the AutoGPT $400-for-$5 class).
- **Governance** — declared, enforceable safeguards (budget, kill switch, owner,
  evals, trace policy). "Undeclared, not unsafe."
- **Reports** — two-axis scorecard + evidence, web + PDF; CLI drives to the web.

This layer is correct and worth having — but it is the *wings*. It measures
returning planes.

## The frontier (the engine — validated-by-users backlog)

None of these are in any SAST rulebook or guardrail today. All are volatile
(the surfaces are <18 months old), all are necessary before production, and all
are invisible to static analysis. **Build order is set by user evidence, not by
this list.**

### 1. Action blast-radius / gating  *(most likely first)*
The output→consequential-action boundary. The agent's decision was *plausible
but wrong* and triggered something **irreversible** — every line of code fine.
- **Check:** enumerate what the agent can *do* (tools, MCP servers), classify
  impact (read / write / **irreversible**: pay, delete, send, deploy), and flag
  irreversible actions with **no confirmation, dry-run, or human-in-loop gate**.
- **Why now-invisible:** no taxonomy of tool impact exists; new tools/MCP servers
  appear daily.

### 2. MCP tool trust (tool poisoning)
- **Check (behavioral):** does the agent obey instructions embedded in a tool's
  *description* or *output*? Connect a hostile MCP tool and observe.
- **Why:** MCP has no trust model yet.

### 3. Inter-agent trust (A2A)
- **Check (behavioral):** does agent A act on agent B's output without
  verifying it? Inject a poisoned upstream message and watch it propagate.
- **Why:** no provenance/attestation standard for agent-to-agent messages.

### 4. Memory poisoning persistence
- **Check (behavioral):** can a **single** poisoned input corrupt persistent
  memory so it affects **future** runs? Poison once, run clean, check carryover.
- **Why:** RAG/agent-memory trust is unsolved.

### 5. Behavior drift
- **Check:** did behavior change since the last release even though **code
  didn't**? (providers silently update models). The regression gate extended to
  behavior over time.
- **Why:** volatile by definition; no one gates on it.

### 6. Output→action grounding
- **Check:** before an output triggers a consequential action, is there
  **evidence it's grounded/verified**? ("the output may or may not be true.")
- **Why:** the deepest version of the judge — ruling on whether it's safe to
  *act*, not just whether the text scores well.

## The discipline

1. **Get one real user** on what exists.
2. **Listen** for the fatal boundary they actually fear.
3. **Build that specific armor** — reinforcing where a real plane went down, not
   where we guessed.

Distribution, not capability, is the current bottleneck. More building — however
visionary — is the wing when the engine that isn't returning home is *users*.
