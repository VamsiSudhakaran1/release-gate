# release-gate

**The pre-deploy release gate for AI agents.** It renders an evidence-based **PROMOTE / HOLD / BLOCK** verdict — catching the agent-layer risks that SAST, guardrails, and evaluators structurally miss.

[![PyPI version](https://badge.fury.io/py/release-gate.svg)](https://badge.fury.io/py/release-gate)
[![GitHub stars](https://img.shields.io/github/stars/VamsiSudhakaran1/release-gate)](https://github.com/VamsiSudhakaran1/release-gate)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)
[![Benchmark: 93-case corpus](https://img.shields.io/badge/benchmark-93--case_corpus_%C2%B7_100%25_precision_%C2%B7_100%25_recall-blue.svg)](benchmark/RESULTS.md)

> **v0.10.1** — the release where the gate stopped being static-only. **`RG-PII-001`**: sensitive context reaching the model **unmasked on one path** while an equivalent path redacts it — reported only on *divergence*, so your repo supplies its own oracle, a project that masks centrally stays silent, and the rule is structurally unable to punish the fix it recommends. **Platform evidence ingestion** (`release-gate ingest`, and now `verify --trace` too): Langfuse / OpenTelemetry / Arize-Phoenix / Promptfoo exports convert in place, so both the pre-deploy score and a *running* loop can be gated on telemetry you already emit — no bespoke file, no new instrumentation, no LLM in the loop, so runtime verdicts stay as reproducible as static ones. The **loop check now keys on tool name + arguments**, so multi-query retrieval is no longer mistaken for a stuck agent and an agent oscillating between two tools now is. A project's **own model wrapper counts as LLM usage**, so a production LangGraph app whose only model call goes through a local `httpx` helper is no longer waved through as "not a deployed agent". [93-case benchmark](benchmark/RESULTS.md) at 100% precision / 100% recall.
>
> **v0.9.4** — a **lean, three-dependency CLI** (`pip install release-gate` no longer pulls a web/SaaS stack) and a **reproducible [93-case benchmark](benchmark/RESULTS.md)** that covers every rule (≥2 vulnerable + ≥2 clean look-alikes each), so the zero-false-positive claim can be checked, not just read. Both sit on top of the **v0.9.0** agent-safety catalog (9 new rules + 2 precision upgrades), holding the precision bar at **0 false positives** on that labeled benchmark and a framework dogfood (llama_index / crewAI / langgraph / open-interpreter): indirect prompt injection from RAG/tool/HTTP provenance (`RG-PROMPT-002`), model-driven **SSRF / filesystem / SQL** sinks (`RG-ACTION-002/003/004`), **secret/PII → prompt** data-egress to the provider (`RG-SECRET-002`, an agent-aware egress path conventional SAST lacks context to model), taint-aware deserialization (`RG-EXEC-004`), unvalidated model-output parses (`RG-PARSE-001`), and **tool blast-radius + irreversibility gates** (`RG-TOOL-001` / `RG-GATE-001`) — plus confirmed taint through the canonical `resp.choices[0].message.content` extraction and a reproducible PR-gate demo. See [the catalog below](#what-it-detects--the-agent-safety-rule-catalog). Builds on **0.8.5**'s **`release-gate pr`**, the AI-change review gate: one PROMOTE/HOLD/BLOCK on what a pull request *introduced* (net-new agent risk + lockfile/behaviour drift), plus a GitHub Action `command: pr`; **0.8.4**'s security-hardened **MCP server** (`pip install 'release-gate[mcp]'`); and **0.8.0–0.8.2**'s AST-based evidence-citing analysis, deserialization calibration, and team-adoption workflow (`--mode` / `--baseline` / `--pr-comment`).

**Why it's not SonarQube:** a SAST tool sees `eval(x)` and asks *"is x tainted by SQL/HTTP?"* — it has no concept of *"x is the model's reply."* That blind spot is the entire agent layer: `eval`/`pickle` of model output (the [CVE-2025-51472](https://www.gecko.security/blog/cve-2025-51472) RCE class), user input reaching a system prompt, LLM loops with no cost ceiling. Guardrails filter one input; evaluators score one output; **neither blocks a release.** release-gate is the gate.

## Try it in 30 seconds

```bash
pip install release-gate

# ── The wedge: gate a pull request on what IT introduced ──
# One PROMOTE / HOLD / BLOCK on net-new agent risk only (inherited debt is
# shown, never gated) + prompt/model drift. Runs in CI on the PR branch.
git checkout my-feature-branch
release-gate pr --base origin/main
release-gate pr --base origin/main --comment   # GitHub-ready PR comment

# ── Or audit a whole repo (the broader lens) ──
release-gate audit . --mode ci                                    # your repo, in CI
release-gate audit https://github.com/org/repo --mode public-advisory  # any public repo, advisory
```

> **Lean by design.** `pip install release-gate` pulls **three** small, well-audited
> libraries — `pyyaml`, `jsonschema`, `cryptography` — and nothing else. No web
> framework, no database driver, no auth stack in the CLI's dependency tree. The
> release-gate.com server stack is an opt-in extra (`pip install 'release-gate[api]'`),
> and the MCP server is another (`'release-gate[mcp]'`).

Output:

```
  Repo    https://github.com/your-org/your-ai-agent
  Agents  OpenAI / Agents SDK (4 files), LangChain (12 files)

  Readiness Score   42 / 100   ████░░░░░░

  Agent Code Safety  28/100  BLOCK   4 high · 18 med · 0 low
     Driving the score: Dangerous execution sink ×4; LLM call with no token ceiling ×18
  Governance         50/100  Partial   4/8 safeguards declared

  Decision:  ✗  BLOCK
```

Two axes, on purpose:

- **Agent Code Safety** — an *objective* score from the code itself: prompt-injection
  surfaces, `exec`/shell sinks fed by model output, LLM calls with no token ceiling,
  hardcoded keys. It moves per repo and doesn't depend on adopting anything. These are
  the agent-layer risks generic SAST/SonarQube don't model — release-gate is the layer
  on top, not a replacement.
- **Governance** — maturity of your *declared, enforceable* safeguards (budget ceiling,
  kill switch, owner, evals, trace policy…). Low here means **undeclared, not unsafe**.

Run `--full` for the per-finding breakdown, or scaffold a ready-to-commit governance
config from the scan:

```bash
release-gate audit . --emit-config -o governance.yaml
# Fill in the TODO lines, then gate every deploy:
release-gate score governance.yaml
```

## What is release-gate?

release-gate sits between your tests and your deployment. It scans your agent code for
the failure modes that only exist once an LLM is in the loop, runs evals, validates
execution traces, checks cost budgets — then gives you two honest scores and one
decision: **PROMOTE / HOLD / BLOCK**.

**SonarQube checks your _code_. release-gate checks whether your _agent_ change meets its
release policy.** They're complementary — keep your SAST suite; release-gate covers the agent layer
it was never built to see (prompt-injection surfaces, cost-runaway loops, missing kill
switches).

```
$ release-gate score governance.yaml --evals evals.yaml

  release-gate  |  Readiness Scorer  v0.10.1

  Project          customer-support-agent  v1.0.0
  Checks run       5  (5 pass, 0 warn, 0 fail)
  Evals run        7  (7 pass, 0 fail)  pass rate 100%
  Traces checked   1  (0 violations)

  Score            94 / 100   confidence: high

  Dimension Breakdown:
    safety          100  ██████████  (wt 30%)
    cost             90  █████████░  (wt 20%)
    access_control  100  ██████████  (wt 20%)
    fallback        100  ██████████  (wt 15%)
    eval_quality     85  ████████░░  (wt 10%)
    observability    80  ████████░░  (wt 5%)

  Critical failures  none

  Decision:  ✓  PROMOTE  (score 94/100)  exit 0
```

---

## What it detects — the agent-safety rule catalog

Every finding carries a **stable, citable rule id** (`RG-EXEC-001`) that never changes when we
reword a title, a one-line rationale, and a mapping to the frameworks you already answer to
(OWASP LLM Top 10, NIST AI RMF). "Why did this block my release?" resolves to a rule, not a code
dive. Full catalog with fixes and compliance tags: **[`docs/RULES.md`](docs/RULES.md)**.

Two disciplines run through every rule:

- **Precision over recall — we don't cry wolf.** When the analyzer can't *prove* a real risk it
  stays quiet. **Zero false positives on the current labeled benchmark and framework dogfood set** —
  the [93-case corpus](benchmark/RESULTS.md) now carries ≥2 vulnerable and ≥2 clean look-alikes for
  *every* rule (including the v0.9.0 catalog), so that result is reproducible per rule (run
  `python benchmark/run.py`), not just asserted; and the engine stayed correctly silent across a
  framework dogfood (llama_index, crewAI, langgraph, open-interpreter).
- **Three evidence tiers — a HIGH is watertight or it isn't a HIGH.** The tier is decided by
  *provenance we can point at*, never by how a variable is spelled. CI can gate on confirmed-only.

  | Tier | Max severity | What it requires |
  |---|---|---|
  | `confirmed` | **high** | A traced origin visible in the file, with a citable chain |
  | `inferred` | **medium** | Real dangerous structure, origin guessed from a name — "confirm the source" |
  | `heuristic` | **low** | Pattern present in agent code; no flow established |

  Every HIGH carries the chain a reviewer can open and check —
  `request.json (L7) -> payload -> os.system() (L8)` — and the benchmark
  machine-checks that **every** HIGH in the corpus is confirmed and
  provenance-backed (`HIGH-tier integrity violations: 0`). This came out of a real
  failure: a variable *named* `payload` used to be enough to assert confirmed RCE,
  and in AutoGPT that variable was its own HMAC-signed cache. One bad HIGH costs
  more trust than ten missed MEDIUMs, so a name can no longer produce one.
- **How far taint reaches, and where it stops.** A value is followed across a **local function
  call**, across **module boundaries** (a whole-program summary index resolves `from x import f`,
  and the chain names the defining file), and through the **filesystem** — model output written to
  a script that is later executed. Labeled corpus: **100% precision, 100% recall**.

  It also resolves **methods on classes** (`ai.start(...)` → `AI.start` → `AI.next` →
  `self.llm.invoke`, transitively and across modules), clients held on attributes
  (`self.llm = ChatOpenAI(...)`), and **container mutation** (`messages.append(reply)`).

  **Where it still stops, measured:** a client built by a *factory method*, and model output
  marshalled through project-specific container/store classes — which is why `gpt-engineer`
  (a ten-hop chain) stays silent. Across the [20-repo deployed-agent corpus](benchmark/corpus-agents.md)
  the taint rules produce **0 confirmed HIGHs** (72 findings, all medium/low); the rule that
  *does* fire there is blast
  radius (`RG-GATE-001`) — irreversible tools with no code-level gate. Following the rest needs
  whole-program type inference, which we'd rather disclose than fake. We publish the numbers that
  didn't move, not just the ones that did.

| Rule | Detects | Severity |
|---|---|---|
| **`RG-EXEC-001`** | Model/user output → `eval`/`exec`/`os.system`/a shell/`subprocess` — the [CVE-2025-51472](https://www.gecko.security/blog/cve-2025-51472) RCE class | HIGH |
| **`RG-EXEC-002`** | `pickle`/`marshal`/`dill` deserialization of unverified data | MED |
| **`RG-EXEC-003`** | A dynamic exec/shell call in agent code, reachability unproven | LOW |
| **`RG-PROMPT-001`** | Untrusted text interpolated into a **system prompt** (OWASP LLM01) | HIGH |
| **`RG-PROMPT-002`** | **Indirect prompt injection** — retrieval/RAG, an HTTP body, or a tool return reaching the system/instruction channel, keyed on real *provenance* | HIGH |
| **`RG-ACTION-002`** | **SSRF / egress** — a model-controlled URL into an HTTP client | HIGH |
| **`RG-ACTION-003`** | **Filesystem write/delete** from model output (irreversible) | HIGH |
| **`RG-ACTION-004`** | **SQL** built by interpolating model output (agent-driven SQLi) | HIGH |
| **`RG-SECRET-001`** | Hardcoded secret / API key in source | HIGH |
| **`RG-SECRET-002`** | **Secret/PII → prompt → third-party model** — an agent-aware data-egress path (a secret in prompt *content*, distinct from a key used as auth) that conventional SAST often lacks the context to model | HIGH |
| **`RG-COST-001/002`** | LLM call / param dict with no `max_tokens` ceiling | LOW |
| **`RG-LOOP-001`** | Unbounded loop around an LLM call — the AutoGPT runaway | HIGH |
| **`RG-PARSE-001`** | Unvalidated model-output parse (`json.loads` with no `try/except`) — reliability | LOW |
| **`RG-TOOL-001`** | An agent tool's irreversible blast radius is undeclared | LOW |
| **`RG-GATE-001`** | An irreversible **tool** action with no confirmation / dry-run / human-in-loop gate | MED |
| **`RG-PII-001`** | **Sensitive context reaches the model unmasked on one path** while an equivalent path redacts it — the refactor regression a passing smoke test can't catch, because it goes through the old path | HIGH |

**Why a SAST tool can't do this:** SonarQube sees `eval(x)` and asks *"is x tainted by SQL/HTTP?"*
— it has no concept of *"x is the model's reply."* That blind spot is the entire agent layer:
`eval`/`pickle` of model output, a retrieved document reaching the system role, a model-chosen URL
or SQL query, a secret leaking into a prompt. Guardrails filter one input; evaluators score one
output; **neither blocks a release.** release-gate is the gate.

### See a rule fire — the reproducible demo

[**`examples/demo-code-risk/`**](examples/demo-code-risk/) is a runnable before/after: a data-analysis
agent that does `expr = resp.choices[0].message.content; eval(expr, {"df": df})` vs. an allowlisted-
aggregation fix.

```bash
pip install release-gate
git clone https://github.com/VamsiSudhakaran1/release-gate && cd release-gate
./examples/demo-code-risk/build_demo.sh            # print the demo
./examples/demo-code-risk/build_demo.sh --check    # …and assert every claim below
```

It builds a throwaway git repo and runs the real gate on the PR:

```
🔴 release-gate — AI-change review: BLOCK

Agent Code Safety: 100 → 76 (▼ -24)

Introduced by this change (not pre-existing):
  HIGH (high · confirmed)  Dangerous execution sink   agent.py:25
    ↳ eval() executes `expr`, which we traced to the model's own output at line 17.
```

Then it scans the same service to show **both tiers side by side** — the point of the product:

```
  • HIGH    high confidence · confirmed   Dangerous execution sink        agent.py:25
     Evidence: client.chat.completions.create() (L17) -> `expr` -> eval() (L25)

  • MEDIUM  medium confidence · inferred  Deserialization of unverified data   cache.py:26
     Evidence: `payload` -> pickle.loads() (L26) — origin unknown (name suggests external input)
```

Same danger shape, two different claims. The HIGH names the line the value came from, so you can
open it and check us. `cache.py`'s `pickle.loads(payload)` is where a name-matching scanner asserts
confirmed RCE — we won't, because `payload` is a bare parameter and **a name is not evidence**
(in AutoGPT that same variable held the cache's own HMAC-signed bytes).

No mockup: `--check` asserts every line quoted here, and [CI runs it on every push](.github/workflows/tests.yml),
so the published demo can't drift from the engine. **Live walkthrough:** [release-gate.com/demo.html](https://release-gate.com/demo.html).

---

## Stop debugging AI-generated code you can't trust — `release-gate pr`

AI writes the diff in seconds. Then a human burns an hour deciding whether to
trust it — reading every changed file, hunting for the one dangerous line,
wondering if a prompt or model changed under the hood. That **verification tax**
is where the productivity goes. Token usage is at an all-time high; shipping
velocity isn't keeping up, because *reviewing and trusting* generated code is now
the bottleneck, not writing it.

`release-gate pr` pays that tax down. It runs in CI on the pull request and
answers one question, **from evidence, not vibes**: *what did this change
introduce that a reviewer would otherwise have to find by hand?*

```bash
release-gate pr --base origin/main            # in CI, on the PR branch
release-gate pr --base origin/main --comment  # GitHub-ready markdown comment
release-gate pr --base origin/main --json     # machine output for a bot
```

```
🔴 release-gate — AI-change review: BLOCK
this change made things net-worse — see reasons

Agent Code Safety: 100 → 88 (▼ -12)

Introduced by this change (not pre-existing):
- ⚠ HIGH (high · confirmed): Dangerous execution sink   src/agent/tools.py:88
  ↳ eval() executes `reply` — the model's own output.
- ⚠ prompt changed `prompts/system.txt` — release-gate.lock not updated

Context (advisory, not blocking):
- 11 source file(s) changed, 0 test files touched
- agent code-safety -12

Inherited debt ignored (not this change's fault): 4 finding(s).

exit 1   (0 PROMOTE · 10 HOLD · 1 BLOCK)
```

### Why you can trust this gate — and not have to debug *it*

This is a security tool; it's held to the standard it audits. Four properties
make the verdict trustworthy on its own:

1. **Every line is a fact derived from your diff — never a prediction.** There is
   no "debug-debt score" guessing from file counts. It reports what *is*:
   this file now reaches `eval()` with model output; this prompt changed without
   a lockfile update. Facts don't cry wolf.
2. **It blocks only on net-new regressions, never inherited debt.** Pre-existing
   findings from the base branch are shown as *ignored* — a PR is judged on what
   *it* changed. A gate that nags about old debt gets muted, and a muted gate
   helps no one.
3. **It's precision-calibrated.** The static engine is AST + taint (not grep): it
   flags a sink only when model/user input can actually reach it, and grades
   severity by proof (`confirmed` vs `inferred`). We validated it against 18
   popular agent frameworks and spent as much effort killing false positives as
   finding bugs — because one bad flag is how a scanner loses your trust.
4. **It sees what a human diff-review structurally can't.** A model or prompt
   change has *no code fingerprint*. The lockfile (AIBOM) drift check surfaces
   "the behavior changed but nothing in the diff shows it" — the exact class of
   silent change that causes 2am incidents.

**What it does NOT do:** it is not an AI reviewer, debugger, or fixer, and it
does not add 40 inline comments. It gives one decision and the short list of
things worth your attention. It's release discipline, not more noise.

Drop it into GitHub Actions — either the raw CLI:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # full history so the diff can be scoped
- run: pip install release-gate
- run: release-gate pr --base origin/${{ github.base_ref }} --comment >> $GITHUB_STEP_SUMMARY
```

…or the published Action, which also posts a sticky PR comment:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: VamsiSudhakaran1/release-gate@v0.10.1
  with:
    command: pr
    base: origin/${{ github.base_ref }}
    pr-comment: true            # create/update one sticky comment on the PR
```

---

## Works with what you already run — the integrations

release-gate does not build observability and does not build quality evals. Those
layers are mature and well served. It **consumes** them and answers the question
neither one asks: *should this ship?*

> Observability answers **"what happened?"** · Evaluation answers **"was the output good?"**
> Neither answers **"should this ship?"**

| Integration | You already have | release-gate turns it into |
|---|---|---|
| **[Langfuse](integrations/langfuse/)** | Traces of what your agent did | A trace-policy verdict: forbidden tools, token ceilings, retry storms |
| **[Promptfoo](integrations/promptfoo/)** | A graded eval suite | A verdict weighing *which* evals failed, not how many |
| **[OpenTelemetry](integrations/opentelemetry/)** | GenAI-semconv spans, any backend | The same verdict, vendor-neutral |
| **[Arize / Phoenix](integrations/arize/)** | OpenInference spans | The same verdict, from AX or Phoenix |
| **[GitHub Actions](integrations/github-actions/)** | A CI pipeline | All of the above, blocking a merge |

There is no conversion step to run first — `--traces` and `--eval-results`
auto-detect the platform and convert in place:

```bash
release-gate score governance.yaml --traces langfuse-export.json
release-gate score governance.yaml --eval-results promptfoo-results.json

# Or combine them — one verdict over both kinds of evidence:
release-gate score governance.yaml \
  --traces langfuse-export.json --eval-results promptfoo-results.json
```

Run it right now against the shipped examples:

```bash
release-gate score integrations/governance.yaml \
  --traces integrations/langfuse/example-trace.json --full
```

```
Ingested traces from Langfuse (5/6 span(s) mapped).

  Traces checked   1  (2 violations)
  Score            91 / 100   confidence: medium

  Critical failures:
    ✗ unauthorized_tool_call [trace] — Unauthorized tool called: send_email_external

  Decision:  ✗  BLOCK  (score 91/100)
```

**91/100 and blocked** — that's the design, not a bug. Nothing in that trace
errored; every span is green in the Langfuse UI. But the agent called a tool the
release policy forbids, and critical failures are **non-compensatory**: a score is
an average, and averages let strength in one dimension buy down catastrophe in
another.

Three rules every adapter follows, which are what make them safe in front of a deploy:

1. **No new dependencies.** Adapters parse exported JSON; they never import a
   vendor SDK. `pip install release-gate` stays a three-library install whether
   you use one integration or all five.
2. **Never invent a step.** A span that can't be mapped with evidence is skipped,
   not guessed. A gate that cries wolf gets disabled, and a disabled gate protects
   nothing.
3. **Report the gap.** Every conversion states what it could not map and why, so
   *"meets the declared policy, with these gaps not assessed"* stays literally
   true instead of merely well-intentioned.

Details, CI workflows, and per-platform mapping tables:
**[`integrations/`](integrations/)**. Background on why this layer exists:
**["Why AI observability isn't enough"](docs/articles/why-observability-isnt-enough.md)**.

---

## Full command & feature reference

The sections above are the whole story a new visitor needs: the problem, one
command, one real finding, one GitHub Action, and how it's different. Everything
else — the complete command reference, MCP server, AIBOM/drift gate, loop
verification, live agent scoring, governance checks, CI recipes, evidence packs,
the impact simulator, cryptographic governance, and supported model profiles —
lives in **[`docs/REFERENCE.md`](docs/REFERENCE.md)**, so this page stays a
landing page, not a manual.

---

## Development

```bash
git clone https://github.com/VamsiSudhakaran1/release-gate
cd release-gate
pip install -e ".[dev]"
pytest tests/
```

594 tests · all passing.

---

## Contributing

Found a bug? Have a feature request? Open an [issue](https://github.com/VamsiSudhakaran1/release-gate/issues).

---

## License

MIT — See [LICENSE](LICENSE)

---

**Contact:** vamsi.sudhakaran@gmail.com · [GitHub](https://github.com/VamsiSudhakaran1/release-gate) · [Website](https://release-gate.com)
