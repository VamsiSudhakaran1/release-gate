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

## Near-term engineering backlog (deferred — subordinate to distribution)

Captured so nothing is lost, but explicitly *not* prioritized over getting real
users. Each is pulled forward only when a user's need (or a merge blocker) makes
it the shortest path — not on its own.

- **Packaging split — lean core, optional extras.** The base install pulls in
  more than the local static gate needs (the tool that preaches lean shipping a
  heavy tree). Split into a minimal CLI + `[api]`/`[pdf]`/`[mcp]` extras.
  *Risk gate:* Vercel builds from `pyproject.toml` and does not install extras —
  must be prepped and verified on a branch before it can touch `main`, or the
  site breaks. Highest-risk item here; do last.
- **Deeper TS/JS parity.** First increment (model-output taint into exec sinks)
  shipped. Remaining: model output into a *system prompt* (extend the taint pass
  to the injection surface), and LangChain.js `.invoke()`/`.stream()` chains —
  each only if it can hold 100% precision. Validate against a real TS-first repo
  before investing; don't chase Python-depth on spec.
- **Split `audit.py`.** It carries scoring + decision modes + baseline compare +
  the `pr` verdict + SARIF + PR-comment rendering. Extract cohesive modules to
  shrink the change-surface and make contribution easier (bus-factor).
- **Third-party security audit.** The benchmark is self-run evidence; an external
  review is the credibility step for enterprise adoption. Cost/timing decision,
  not an engineering one — trigger when a real prospect asks for it.
- **`publish.yml` via PyPI Trusted Publishing.** Remove the manual release step
  so a bad/manual publish can't happen; ties into the SUPPORT.md release-cadence
  promise.
- **"Non-agent repo → governance N/A" precision fix.** A repo with no agent code
  should read *not applicable*, not a low governance score — avoids penalizing
  the wrong thing on a first scan.
- **Declared trust-boundary / accepted-risk annotation.** *(user-validated —
  build when a scanned team asks for it.)* A finding the maintainer has reviewed
  and *intentionally accepted* should read as **acknowledged**, not re-surface as
  an unreviewed medium on every scan. Mechanism: let a repo declare an exception
  — in `governance.yaml` (e.g. `accepted_risks: [{rule: RG-EXEC-003, path:
  ".../hybrid-browser-toolkit.ts", reason: "...", ref: "PR #4157"}]`) or an inline
  annotation at the sink — that the gate reads and renders as *accepted (declared)*
  with the reason and reference, still listed for the audit trail but not counted
  as an open risk. *Motivating evidence (real, not hypothetical):* we raised
  camel-ai/camel #4155 on the `eval()` in `hybrid-browser-toolkit.ts`; the
  maintainers resolved it via **PR #4157 (merged into master 2026-07-17)** —
  documentation only, the `eval()` intact, a source comment + tool-schema wording
  declaring *"this intentionally executes caller-provided JavaScript ... not a
  sandbox"*, plus a test asserting the schema says so. The gate today still flags
  it medium/inferred despite that formal, tested declaration — it reads code, not
  declared intent. This is the exact gap: the difference between a gate teams keep
  and a gate teams mute. *Guardrail:* an accepted-risk must be **declared and
  attributable** (who accepted it, why, ref) — never a silent suppression, never
  auto-applied by the gate; the finding stays visible, only its *status* changes.
  Ties into governance (a declared exception is itself a governance signal) and to
  the "declaration-aware" theme the coverage matrix already gestures at.
- **Live scratch-PR Action test.** End-to-end dogfood of the published Action's
  `command: pr` on a throwaway PR (unblocked now that 0.8.5 + the `v0.8.5` tag
  are on PyPI).
- **Retrieval / context-bloat hygiene (a new `RG-COST` rule, not a new product).**
  A static pass over RAG / external-source usage: retrieval calls with no result
  cap (`top_k`/`k` absent or very high), retrieved or tool output flowing into a
  prompt with no truncation, and the compounding case (retrieval **+** no
  `max_tokens`). Emits an inventory too — N retrieval sites, M external-source
  calls, K unbounded. It's both a **cost** signal (token bloat → denial-of-wallet)
  and a **prompt-injection** signal (more untrusted context = wider surface), so
  it unifies two things the engine already cares about.
  *Scope line (honesty):* static analysis sees whether a **bound is present**, not
  whether the value is right, and **never the actual runtime token count/cost** —
  that stays in the behavioral layer (`loop-sim` / `agent-score`). The static rule
  **feeds** the runtime eval (it flags the sites worth running); it does not
  replace or duplicate it. Coverage matrix must mark actual token/cost as
  "not assessed — run the behavioral scan."
  *Gate:* validate with a real user first — build it when a design partner says
  "my RAG agent's token bill is the pain," not on spec.

## Phase-2 candidate — the Efficiency pillar (AI performance / architecture auditor)

A proposed sixth axis beyond correctness / safety / governance / compliance /
cost: **AI Efficiency** — not latency or GPU util, but *token & context*
efficiency. release-gate as a deterministic, explainable, **review-only** auditor
(`release-gate optimize` / `efficiency`) that says *"you could cut inference cost
~40%, prompts ~37%, retrieval overfetch ~85%."* This **subsumes** the
retrieval/context-bloat item above and is the bigger vision of it.

Why it's compelling: efficiency is **dollar-denominated** — a far more ROI-legible
and universal sell than "you missed a fallback," and genuinely differentiating (a
pre-deploy *architecture reviewer*, not just a gate). Fits the existing
review-don't-change philosophy. Real opportunity.

**The honesty split — this is THREE tiers, and conflating them is the whole trap:**

- **Tier 1 — statically detectable (deterministic, CI-friendly, build FIRST).**
  `PROMPT_DUPLICATION` / `SYSTEM_PROMPT_REUSE` (string similarity across files),
  `PROMPT_ENTROPY` (repetitive low-info instructions), RAG overfetch (`top_k`
  absent/high), `CACHEABLE_PROMPTS` (static/repeated prefixes), loop bounds
  (already `RG-LOOP`), coarse `MODEL_SELECTION` heuristics. These hold the
  precision bar. This is the shippable, credible slice — the token-budget profile
  (`efficiency:` thresholds that can HOLD a correct-but-wasteful deploy) enforces
  only these; advisory on the rest.
- **Tier 2 — needs RUNTIME TRACES (behavioral layer + trace ingestion).** Actual
  loop iterations / wasted iterations / cost-per-loop, real token usage, live
  cache-hit potential. Doable, but the input is *traces*, not code — an extension
  of `loop-sim`/`agent-score`, not the static gate.
- **Tier 3 — HARD / research-grade / often IMPOSSIBLE with closed APIs. Handle
  with extreme care or DO NOT claim.** "Context utilization" (which paragraphs the
  model actually used), the token heatmap (per-token used/ignored), "referenced 3
  of 20 chunks", precision@k. These need **per-token attribution that hosted model
  APIs don't expose** — you cannot measure them deterministically. Presenting "18%
  context utilization" as a *fact* is exactly the false precision the external
  reviews (rightly) punished ("safe to deploy", "100% precision"). If surfaced at
  all: label **ESTIMATE**, state the method, never a hard number.

**The dollar-figure landmine.** "$18,240/month saved" requires the team's real
traffic volume + live pricing. A static pass can produce *per-call token-waste %*,
**not** a monthly $ — without usage input the dollar figure is fiction, and a
wrong estimate destroys trust faster than no estimate. Gate all $ claims behind
real usage data (traces or a supplied volume).

**Gate:** validate with a real user first. Build **Tier 1** (deterministic,
credible) when a design partner's pain is cost/token bloat; treat Tier 2/3 as
later, trace-fed, and estimate-labeled. The pillar is real and worth it — the
discipline is refusing to claim precision on what a static (or even runtime) pass
genuinely can't see. That refusal is the moat, not a limitation.
