# release-gate

**The pre-deploy release gate for AI agents.** It renders an evidence-based **PROMOTE / HOLD / BLOCK** verdict — catching the agent-layer risks that SAST, guardrails, and evaluators structurally miss.

[![PyPI version](https://badge.fury.io/py/release-gate.svg)](https://badge.fury.io/py/release-gate)
[![GitHub stars](https://img.shields.io/github/stars/VamsiSudhakaran1/release-gate)](https://github.com/VamsiSudhakaran1/release-gate)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)
[![Benchmark: 53-case corpus](https://img.shields.io/badge/benchmark-53--case_corpus_%C2%B7_26_TP_%C2%B7_0_FP_%C2%B7_2_known--miss-blue.svg)](benchmark/RESULTS.md)

> **v0.9.2** — a **lean, three-dependency CLI** (`pip install release-gate` no longer pulls a web/SaaS stack) and a **reproducible [53-case benchmark](benchmark/RESULTS.md)** that covers every rule (≥2 vulnerable + ≥2 clean look-alikes each), so the zero-false-positive claim can be checked, not just read. Both sit on top of the **v0.9.0** agent-safety catalog (9 new rules + 2 precision upgrades), holding the precision bar at **0 false positives** on that labeled benchmark and a framework dogfood (llama_index / crewAI / langgraph / open-interpreter): indirect prompt injection from RAG/tool/HTTP provenance (`RG-PROMPT-002`), model-driven **SSRF / filesystem / SQL** sinks (`RG-ACTION-002/003/004`), **secret/PII → prompt** data-egress to the provider (`RG-SECRET-002`, an agent-aware egress path conventional SAST lacks context to model), taint-aware deserialization (`RG-EXEC-004`), unvalidated model-output parses (`RG-PARSE-001`), and **tool blast-radius + irreversibility gates** (`RG-TOOL-001` / `RG-GATE-001`) — plus confirmed taint through the canonical `resp.choices[0].message.content` extraction and a reproducible PR-gate demo. See [the catalog below](#what-it-detects--the-agent-safety-rule-catalog). Builds on **0.8.5**'s **`release-gate pr`**, the AI-change review gate: one PROMOTE/HOLD/BLOCK on what a pull request *introduced* (net-new agent risk + lockfile/behaviour drift), plus a GitHub Action `command: pr`; **0.8.4**'s security-hardened **MCP server** (`pip install 'release-gate[mcp]'`); and **0.8.0–0.8.2**'s AST-based evidence-citing analysis, deserialization calibration, and team-adoption workflow (`--mode` / `--baseline` / `--pr-comment`).

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

  release-gate  |  Readiness Scorer  v0.9.2

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
  the [53-case corpus](benchmark/RESULTS.md) now carries ≥2 vulnerable and ≥2 clean look-alikes for
  *every* rule (including the v0.9.0 catalog), so that result is reproducible per rule (run
  `python benchmark/run.py`), not just asserted; and the engine stayed correctly silent across a
  framework dogfood (llama_index, crewAI, langgraph, open-interpreter).
- **Confirmed vs inferred is explicit.** A finding whose untrusted source is *visible in scope* is
  a HIGH you can put in front of a maintainer; a source only *inferred from a name* stays
  MEDIUM. CI can gate on confirmed-only.
- **Known limitation, disclosed up front:** taint is **intra-procedural** — a tainted value that
  crosses a function boundary (a helper returns model output; the caller sinks it) is *not*
  followed. The benchmark keeps labeled `*-cross-function-KNOWN-MISS` cases so this shows as a
  recall miss rather than being hidden. Precision-first: we'd rather miss a cross-function flow than
  infer one. Inter-procedural analysis is on the roadmap.

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

**Why a SAST tool can't do this:** SonarQube sees `eval(x)` and asks *"is x tainted by SQL/HTTP?"*
— it has no concept of *"x is the model's reply."* That blind spot is the entire agent layer:
`eval`/`pickle` of model output, a retrieved document reaching the system role, a model-chosen URL
or SQL query, a secret leaking into a prompt. Guardrails filter one input; evaluators score one
output; **neither blocks a release.** release-gate is the gate.

### See a rule fire — the reproducible demo

[**`examples/demo-code-risk/`**](examples/demo-code-risk/) is a runnable before/after: a data-analysis
agent that does `expr = resp.choices[0].message.content; eval(expr, {"df": df})` vs. an allowlisted-
aggregation fix. `./build_demo.sh` builds a throwaway git repo and runs the real gate:

```
🔴 release-gate — AI-change review: BLOCK

Agent Code Safety: 100 → 76 (▼ -24)

Introduced by this change (not pre-existing):
  HIGH (high · confirmed)  Dangerous execution sink   agent.py:25
    ↳ eval() executes `expr` — the model's own output.
```

No mockup — that's the live output, which is exactly how building the demo caught (and let us fix)
a real taint-tracking under-grade. **Live walkthrough:** [release-gate.com/demo.html](https://release-gate.com/demo.html).

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
- uses: VamsiSudhakaran1/release-gate@v0.9.2
  with:
    command: pr
    base: origin/${{ github.base_ref }}
    pr-comment: true            # create/update one sticky comment on the PR
```

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
