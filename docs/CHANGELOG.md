# Changelog

All notable changes to release-gate will be documented in this file.

## [0.8.5]

### ✨ Added — `release-gate pr`, the AI-change review gate

- **`release-gate pr --base <ref>`** — a single PROMOTE / HOLD / BLOCK on what a
  pull request *introduced*, for the AI-generated-code era where the bottleneck
  is reviewing/trusting a diff, not writing it. Builds the base tree in a
  throwaway git worktree, audits base vs HEAD, and folds two gates into one
  verdict: **net-new agent-layer risk** (blocks only on net-new regressions,
  never inherited debt) and **lockfile/AIBOM behaviour drift** (a prompt/model/
  tool change with no matching lock update → HOLD, not held against a PR that
  re-locked). Adds one factual signal — did the diff touch source without a
  test. `--comment` emits GitHub markdown, `--json` for bots. Exit 0/10/1.
- **GitHub Action** gains `command: pr` with a `base` input and sticky
  PR-comment posting.
- Deliberately **not** a heuristic "debug-debt score" — every line is a fact
  from the diff, not a prediction.

### 🎯 Precision — JS/TS system-prompt injection classified by the interpolation

A template literal was graded by scanning the whole template's prose, so a
benign `${new Date()}` plus the word "input" in the instructions produced a
false HIGH (found on mem0). Now only the code inside each `${…}` is classified.

## [Unreleased]

### 🔎 Coverage matrix — an audit now states what it did NOT assess

Every verdict carries an explicit coverage matrix (`report["coverage"]`): agent
code (Python deep, JS/TS lighter), declared vs. runtime-verified safeguards,
live behavior/red-team, tool/MCP blast radius, and deployment binding
(commit/IAM/remote-MCP trust). A static pre-deploy scan sees code and declared
config — it doesn't execute the agent or bind to the deployment — and now says
so. Shown as a one-line caveat by default, a full matrix under `--full`, a
collapsible table in the Markdown/PR comment, and always in `--json`. The honest
counterweight to a one-line PROMOTE/HOLD/BLOCK, so no one reads a pass as "safe."

### 🚚 Release automation — one drift-proof publish pipeline

`.github/workflows/publish.yml`: pushing a `vX.Y.Z` tag runs a guard (tag must
equal the package version, `check_version_sync` passes, full suite + accuracy
benchmark green), builds and `twine check`s the dist, publishes to PyPI via
**Trusted Publishing** (OIDC, no stored token), creates the GitHub Release,
smoke-tests the install from PyPI, and moves the floating `vMAJOR.MINOR` tag. A
drifted or untested release becomes structurally impossible — closing the gap
between package, tag, Release, and site version pins.

### 🎯 Precision — Governance is N/A for a non-deployed agent

A repo that is flagged as an agent because it *references* an LLM framework —
but whose **production** code never actually calls an LLM (the references live
only in tests, examples, or tooling: a library's samples, a scanner's own
detection patterns) — is not a deployed agent. Demanding a "kill switch /
on-call / loop boundary" of it, and dragging it to `HOLD`, is a false signal on
the exact first run a prospect makes. Governance now reads **N/A** for that case
(reported, never gated, in every mode); the verdict follows the objective
agent-code-safety axis. A repo whose production code genuinely calls an LLM is
still fully governed, and a repo with no agent at all keeps its existing
handling. Detection reuses the AST call-detector + the finding scanner's own
production/tooling path split, so a framework name in a regex or a sample never
counts as deploying an agent. Found by dogfooding release-gate on itself.

### 🧭 TS/JS parity — model-output taint into exec sinks

The Python analyzer follows a value from an LLM call into `eval`/`exec`; the JS/TS
path could not, so the same pattern in TypeScript graded only as a generic low
"dynamic sink" (`RG-EXEC-003`). A new **intra-file model-taint pass** closes that
gap without a full dataflow engine: variables assigned directly from a model call
(`generateText` / `streamText` / `generateObject` / `chat.completions.create` /
`messages.create`, including destructured `const { text } = await …` and receiver
forms like `client.chat.completions.create`) are tracked, so
`const r = await generateText(...); eval(r.text)` is now recognized as the
**CVE-2025-51472 model→sink RCE class** (`RG-EXEC-001`, high/confirmed). A value
from a non-model source (a config/template transform) stays a low dynamic sink —
precision-first, verified by a benchmark guard. Benchmark grows to 27 cases;
precision stays **100%**, recall **92.9%**.

### 📊 Reproducible accuracy benchmark — "demonstrated, not asserted"

- **`benchmark/`** — a labeled corpus (`cases.yaml`, 25 cases) plus a
  precision/recall harness (`run.py`) that runs the *production* scanners over
  ground truth. Clean cases are real framework look-alikes (mem0, crewAI,
  gpt-researcher, livekit, LangChain, vercel/ai) where a naive scanner
  false-positives; each is a permanent regression guard. One vulnerable case is
  kept and labeled as a **known miss** (intra-procedural taint limit) rather than
  hidden. Current: **100% precision · 91.7% recall · 100% clean-quiet** — re-run
  it yourself with `python benchmark/run.py`. `tests/test_benchmark.py` fails CI
  if precision or the clean-quiet rate ever regresses.
- Fixed a real gap the benchmark caught: the secret regex `sk-[A-Za-z0-9]{16,}`
  stopped at the hyphen in modern OpenAI key prefixes (`sk-proj-`, `sk-svcacct-`,
  `sk-admin-`), so those keys were missed. Now matched in all three secret paths.

### 📄 Versioning & support policy

- **`docs/SUPPORT.md`** — an explicit SemVer contract for a blocking gate: what
  each bump can do to your build, what counts as a breaking change, pinning
  guidance, release cadence, deprecation window, and an honest maturity /
  maintainership statement. `SECURITY.md`'s supported-versions table corrected
  from the stale v0.7.x to v0.8.x, with a 30-day previous-series window.

### 🔒 Security hardening — browser surface & access control

- **Security response headers on every response.** A document-scoped CSP
  (`frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`, no remote
  script origins), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`. HSTS is
  opt-in via `RG_ENABLE_HSTS`; CSP overridable via `RG_CSP`. A security product
  now passes its own header audit.
- **Fixed anonymous rate limiting behind a proxy.** The anonymous scan limiter
  keyed on `request.client.host` — which behind Vercel is the *proxy's* IP, so
  every anonymous visitor shared one counter and the whole world was throttled
  after 3 total scans. It now reads the forwarded client IP.
- **`/api/debug/github-app` is now admin-only** (was unauthenticated — it
  exposed GitHub-App identifiers and installation state to any caller).
- **SPA static-file path-traversal hardening** (`is_relative_to`) plus
  `Cache-Control` on served static assets.

### 🚀 JS/TS analyzer — Node `vm.*` sinks + model-source prompt injection

Building on the exec-sink calibration in #154:

- **Node `vm.*` escape sinks** now covered for JS/TS (`runInNewContext`,
  `runInContext`, `runInThisContext`, `compileFunction`) — flowing through the
  same confirmed/inferred severity ladder as the other exec sinks.
- **Prompt-injection detection now sees model/tool output**, not just
  `req/params/body`, and is graded (external request/user input → HIGH; model or
  tool output → MEDIUM). It replaces the loose 300-char "messages array nearby"
  window with anchoring to the actual message shape — an LLM-specific field
  (`system:` / `systemPrompt`) qualifies alone, a generic `content:` only inside
  a `role:'system'` object — so a var named `content`, a UI renderer, a user-role
  message, or an HTTP-error string interpolating `response.status` never
  false-positives.


### 🎯 Precision — false-positive calibration against an 8-repo real-world corpus

Hand-triaged every finding the scanner produced on crewAI, smolagents,
pydantic-ai, openai-agents-python, gpt-researcher, MetaGPT, microsoft/autogen,
and vercel/ai, then fixed each false-positive class at the root. Corpus effect:
**gpt-researcher 4 high + 3 medium → 0; vercel/ai 114 findings → 1; crewAI
4 medium → 0** — while every true positive (MetaGPT's Voyager-style `eval` of
model code, all pickle-deserialization findings) still fires. 11 new
regression tests lock the calibration in.

- **Token-based hint matching (Python).** Identifier hints now match whole
  snake_case/camelCase tokens, not substrings — `context` no longer hits
  "text", `database` no longer hits "data". Kills a whole class of phantom
  "Dangerous execution sink" findings.
- **System prompts composed from the developer's own material are not an
  injection surface.** ALL_CAPS constants, vars only ever assigned literal
  strings (if/elif chains), and prompt-material names (`agent_role_prompt`,
  `auto_agent_instructions`, personas, templates) no longer flag; a generic
  config identifier rates LOW; clearly external input (`user_query`, `request`)
  is still HIGH.
- **Non-text endpoints exempt from token-ceiling checks.** `images.generate`,
  `embeddings.create`, `audio.*`, `moderations.*` have no token-ceiling concept.
- **Constructor-declared ceilings count.** `ChatOpenAI(max_tokens=512)` caps
  every call through that client.
- **Opaque provider config objects stay quiet.** google-genai's
  `config=GenerateContentConfig(…)` can carry the ceiling where static analysis
  can't see it — absence unprovable, so no finding (a literal dict config is
  still checked).
- **Counter-bounded `while True` is not a runaway.** An exit guarded by a
  counter/budget comparison (`if attempts >= max_retries: break`) bounds the
  loop; a model-controlled break still flags.
- **Inferred execution sinks are MEDIUM, not HIGH.** Severity now follows
  proof: a flow the analyzer can see is HIGH; a flow inferred from a name alone
  is MEDIUM — the same calibration deserialization sinks already used.
- **JS/TS scanner overhaul.** Recognizes AI SDK v5 `maxOutputTokens` (and
  `max_completion_tokens` spellings); checks the call's full balanced-paren
  argument span instead of a 5-line window; masks comments, strings, and
  template literals so JSDoc `@example` blocks and docs snippets never register
  as calls; skips definition sites (`function generateText(` is the SDK
  defining itself); excludes TypeScript type-test files (`*.test-d.ts`).

## [0.7.4] — 2026-06-24

### ✨ Added — loop verification, second pass (external review)

- **`release-gate agent-score` — score a live agent's behaviour (0-100).** Where
  `audit <repo>` scores deployment safeguards statically, `agent-score <agent>`
  runs the agent (`py:`/`cmd:`/`http`) through a behaviour battery and returns a
  weighted 0-100 Agent Readiness Score + PROMOTE/HOLD/BLOCK. Four dimensions —
  **Safety 35% · Correctness 30% · Loop 20% · Cost/latency 15%**. Safety is a
  hard gate: a **universal canary probe** plants a token in the agent's context
  and checks the response never echoes it; any critical leak forces BLOCK
  regardless of score. Reuses AgentClient + EvalRunner + LoopSimulator +
  RuntimeProfile; `--evals` extends correctness with domain cases. CLI-only for
  now (running an arbitrary agent server-side would be RCE/SSRF).
  - **Example agents**: `examples/llm_agent.py` wraps a real LLM
    (Anthropic/OpenAI/OpenRouter, auto-detected from env) behind two system
    prompts — `hardened` and `naive` — so you can score the same model two ways
    and watch the safety gate discriminate. `examples/agent_evals.yaml` shows
    domain correctness cases for `--evals`.
  - **Website showcase**: an interactive Agent Score card with a
    Hardened / Weak / Naive toggle, backed by a new `POST /api/agent-score-demo`
    endpoint. It scores **built-in deterministic demo agents only** — never a
    caller-supplied agent — so there's no RCE/SSRF surface. The three variants
    demonstrate PROMOTE (100), HOLD (70), and BLOCK (35, canary leaked).
- **`release-gate loop-sim` — pre-deploy loop characterization.** A loop is a
  runtime behaviour, so you can't observe it before deploy — but you *can* run
  the agent through a compact scenario bank in a looping harness and turn the
  aggregate trajectory into one readiness decision: **PROMOTE / HOLD / BLOCK**.
  It reports convergence rate, iteration distribution (avg/P95/max), cost per
  run with spike detection, and the adversarial ROLLBACK rate. Decision logic is
  safety-first: any adversarial fixture that fails to ROLLBACK is an immediate
  BLOCK, as is sub-70% convergence or a worst-case cost over 2× the declared
  ceiling. Reuses the existing AgentClient, LoopVerifier and EvalRunner; runs
  with a mock agent when `--agent` is omitted. See `examples/loop_scenarios.yaml`.
  Also wired into the **GitHub Action** (`command: loop-sim`, `scenarios:`,
  `agent:` inputs) so loop readiness can block a merge the same way `audit` does.
  And surfaced as an **interactive website card** backed by a new stateless
  `POST /api/loop-sim` endpoint — paste a scenario bank, get the
  PROMOTE/HOLD/BLOCK decision plus convergence / iteration / cost / adversarial
  metrics. The endpoint runs **mock mode only and never executes a caller's
  agent** (no RCE); real-agent runs stay in the CLI/CI where the user owns the
  runtime. Inputs are bounded (≤25 scenarios, max_iterations clamped).
- **Loop Report UI on the website.** The static `GET /api/loop/<id>` teaser is now
  an interactive viewer: enter a loop-id, load the run, and see the full iteration
  timeline (CONTINUE → CONTINUE → SHIP) with per-iteration decision, cost spent /
  remaining, and the violations/warnings that drove each call. The playground
  carries its loop-id straight into the report.
- **Maker/checker separation is now enforced.** `LoopVerifier` ROLLBACKs when
  `maker_model == checker_model` (the checker would be grading its own homework).
  A missing `checker_model` warns in permissive mode and is a hard violation in
  strict mode. Previously the README promised this but the logic didn't check it.
- **Strict mode** (`loop.mode: strict`). A missing loop boundary becomes a hard
  violation: `max_iterations`, `total_cost_limit`, `max_tokens_per_iteration`,
  `stop_condition` and `checker_model` must all be declared or every iteration
  ROLLBACKs. Permissive mode (default) keeps the developer-friendly behaviour
  where a clean iteration with no policy SHIPs.
- **Typed stop conditions.** `stop_condition` now accepts a bare string or a
  typed dict: `eval_pass_rate` (min_pass_rate), `required_keyword_present`,
  `required_keyword_absent`, `artifact_exists`, and `human_approval_required`
  (never auto-SHIPs). A clean-but-not-done iteration now CONTINUEs instead of
  prematurely SHIPping.
- **`loop_boundary` audit safeguard.** `release-gate audit` now detects repos
  that run agent loops without a declared boundary, and flags identical
  maker/checker models. It's advisory (weight 0) so it surfaces in the report
  and missing list without perturbing the established 0-100 safeguard score.

### 🐛 Fixed — docs polish

- Removed the duplicated `## What is release-gate?` heading, the duplicated
  `1 = BLOCK / FAIL` exit-code row, and relabelled the stale `v0.6 Features`
  section to `Core Features` in the README.

## [0.7.3] — 2026-06-23

### 🐛 Fixed — production hotfix

- **Reverted the dependency split from 0.7.2.** Vercel's Python runtime installs
  this project from `pyproject.toml` (not `requirements.txt`), so moving the web
  stack to an optional `[api]` extra meant FastAPI was never installed and the
  serverless function crashed on import (`ModuleNotFoundError: No module named
  'fastapi'`). The web deps are back in core `dependencies`. All other
  external-review fixes from 0.7.2 are retained.

## [0.7.2] — 2026-06-23

### 🐛 Fixed — external review (correctness & security)

- **GitHub Action**: the `audit` step combined `--markdown` and `--json` in one
  call, so the JSON capture file actually contained Markdown — corrupting every
  downstream `jq` parse (PR comment, commit status). Now JSON and Markdown are
  emitted by separate calls. Also fixed an invalid backslash-escaped `jq`
  expression in the PR-comment table builder.
- **Packaging**: removed the stale `setup.py` (pinned at 0.6.0); `pyproject.toml`
  is the single source of truth.
- **Dependencies**: split the heavy web/SaaS stack (FastAPI, uvicorn, psycopg2,
  passlib, jose) into a `release-gate[api]` extra. `pip install release-gate`
  for CLI/CI users is now lean (pyyaml, jsonschema, cryptography only).
- **Evals**: generated `evals.yaml` used a `suite:/cases:` layout the eval
  runner couldn't read (`load_evals` only saw `evals:`), so `release-gate eval`
  silently ran zero cases. The scaffold now emits the runner's schema, and
  `load_evals` also tolerates legacy `cases:`/`tests:` keys.
- **Pricing**: `on_unknown: fail` was silently downgraded to `HOLD`; it now maps
  to a distinct `FAIL` status (block).
- **ACTION_BUDGET**: now resolves model pricing through the shared
  `PricingResolver` chain (custom / locked / openrouter / litellm / static,
  honouring `on_unknown`) instead of a separate hardcoded table, and surfaces a
  non-passing result when pricing can't be resolved.
- **Security — agent cmd runtime**: `cmd:` targets now run via `shlex.split` with
  `shell=False`, closing a shell-injection vector.
- **Security — API**: the degraded-mode fallback no longer echoes the full
  traceback to anonymous callers (logged to stderr; set `RG_DEBUG=1` to surface
  it). CORS is no longer a wildcard by default — it uses an explicit allowlist,
  overridable via `RG_CORS_ORIGINS`.

## [0.7.0] — 2026-06-16

### 🔧 Changed — audit scoring thresholds

- Audit `BLOCK`/`HOLD` boundary lowered from 75 to **50**. A repo that already
  has the heavy safeguards (budget ceiling, kill switch, auth, evals) but no
  formal `governance.yaml` now scores **HOLD** ("formalize it"), not BLOCK.
  `PROMOTE` still requires ≥ 90, which is unreachable without a governance file
  (the other six safeguards sum to 75) — so you can never PROMOTE without one.

### ✨ Features — Self-serve audit (badge + CI summary)

- **`release-gate audit --badge`**: prints a copy-paste shields.io Markdown
  badge reflecting the readiness score/decision (green/yellow/red/grey) so a
  maintainer can show it on their own repo's README.
- **`release-gate audit --markdown`**: renders the audit as GitHub-flavored
  Markdown — a score table of present/missing safeguards. In GitHub Actions it
  is appended to `$GITHUB_STEP_SUMMARY` automatically so the result is visible
  without opening logs.
- **GitHub Action `command: audit`**: drop-in CI step (`path`, `fail-on-warn`)
  that audits the checked-out repo and writes the summary. Audit exit codes:
  `0` PROMOTE/no-agent · `10` HOLD · `1` BLOCK.
- New docs: `docs/AUDIT_BADGE.md`. 5 new tests.

### ✨ Features — Live Agent Runtime (Phase 2)

- **Live agent runner** (`release_gate.agent`): a new `--agent <spec>` flag on
  `score` and `evidence-pack` runs the existing eval cases against a **real
  agent** instead of static stubs. Three target types, stdlib-only (no agent SDK):
  - `py:module.path:callable` — import and call a Python function in-process.
  - `cmd:./script` — subprocess; eval input on stdin, response on stdout,
    context via `$RG_CONTEXT`.
  - `http(s)://url` — POST `{"input","context"}`; reads a
    `response`/`output`/`text` field plus optional `usage` token counts.
- **Runtime profiling** (`RuntimeProfile`): captures per-call latency
  (avg / p50 / p95 / max), error rate, and token usage as evals run live;
  surfaced in the score report and embedded in the evidence pack
  (`runtime_summary`).
- **No silent pass on a broken agent**: a failing or unreachable agent is
  recorded as a failed eval and counted in the error rate.
- 25 new tests.

### ✨ Features — Model Intelligence Layer (Phase 1)

- **Model Profile** (`model:` block in `governance.yaml`): declare `id`, `provider`,
  `type` (`llm` / `predictive_model` / `embedding` / `self_hosted`), and a pricing
  source — instead of relying only on the hardcoded table.
- **Pricing Resolver** (`release_gate.pricing.resolver`): resolves token pricing from a
  source chain — `static`, `custom` (inline), `locked` (snapshot), `openrouter` (live),
  and `litellm` (cost map). Live sources degrade gracefully to the lock file then the
  static table, downgrading status to **WARN** instead of failing CI.
- **Pricing Lock** (`pricing.lock.json` + `release-gate pricing-lock`): reproducible,
  hash-protected (tamper-evident) pricing snapshots with a `fetched_at` timestamp so CI
  can score offline. A snapshot older than `max_age_days` raises a **WARN**.
- **No silent zero-cost**: if a model's price can't be resolved and `on_unknown: hold`,
  the budget simulation **fails** rather than assuming free.
- Self-hosted / predictive models skip token pricing entirely (Phase 2 will add a
  runtime cost profile).
- 27 new tests (193 total, all passing).

---

## [0.6.0] - 2026-06-15

### ✨ Features

- **Readiness Scorer** (`release-gate score`): collapses checks, evals, traces, and cost
  impact into a 0–100 score across six weighted dimensions (safety, cost, access_control,
  fallback, eval_quality, observability) and a single decision: **PROMOTE / HOLD / BLOCK**.
- **Regression Gate** (`release-gate compare`): diffs two readiness reports; a >10-point
  drop in any dimension — critical in safety, fallback, or access_control — blocks the release.
- **Eval Runner**: YAML-defined behavior test cases (`refuse_or_mask`, `contains_keywords`,
  `valid_json`, `no_tool_calls`) in static (CI-safe) or live mode.
- **Trace Validator**: validates agent execution traces against `trace_policies` — forbidden
  tools, allowed-list violations, retry storms, token budgets, and tool-call loops.
- **Evidence Pack** (`release-gate evidence-pack`): generates `readiness_report.json`,
  `executive_summary.md`, and `release-gate-evidence.html` in one command.
- **GitHub Action**: new `score`/`evidence-pack` commands plus `evals` and `traces` inputs.

### 🔒 Security

- Removed a committed RSA private key (`governance-key.pem`) from the repo root.
- `*.pem` / `*.key` are now git-ignored; demo **public** key moved to `examples/keys/`.

### 🔧 Fixes

- Wired the v0.6 commands into the CLI (`score`, `compare`, `evidence-pack`) — previously
  the modules shipped but the CLI fell through to help text.
- Aligned version to `0.6.0` across `setup.py`, `pyproject.toml`, and the CLI; unified the
  console-script entry point on `unified_main`.

### 📦 Internal

- Cleaned repo root: removed backup files, deduplicated `crypto/` and `pricing.json`, and
  moved demo scripts to `scripts/` and stray configs to `examples/`.
- Test suite now at 166 tests, all passing.

---

## [0.5.0] - 2026-06-12

### ✨ Features

- **Cryptographic Governance Signing**: RSA-PSS + SHA256 signatures lock `governance.yaml` against post-review tampering
  - `release-gate validate-and-lock --sign` creates `.release-gate-proof.json` and `.governance.sig`
  - `release-gate validate-and-lock --verify` validates signature and hash in CI
  - `release_gate.crypto` package bundled inside the main package (no separate install required)

- **Config Schema Validation**: `governance.yaml` is validated against a JSON Schema at load time
  - Invalid field types, negative budgets, and out-of-range values produce clear error messages before any check runs
  - Uses `jsonschema` (already a dependency); gracefully skips if not installed

- **Simulation Parameter Bounds Checking**: Nonsensical multiplier values now produce a `FAIL` with a descriptive message
  - `retry_rate`: must be 1.0 – 10.0
  - `cache_hit_rate`: must be 0.0 – 1.0
  - `spiky_usage_multiplier`: must be 1.0 – 20.0

- **Comprehensive Test Suite**: 75 unit and integration tests covering all 5 checks, the policy engine, and the budget simulator
  - `tests/test_checks.py`: full coverage for `ActionBudgetCheck`, `FallbackDeclaredCheck`, `IdentityBoundaryCheck`, `InputContractCheck`, `BudgetSimulationBounds`, and end-to-end integration

### 🔧 Fixes

- **Version sync**: `__init__.py`, `setup.py`, and `pyproject.toml` now all report `0.5.0`; `__version__` is read dynamically via `importlib.metadata`
- **test_crypto.py imports**: fixed from bare `governance_signer`/`governance_verifier` to `release_gate.crypto.governance_signer`/`release_gate.crypto.governance_verifier`
- **WARN threshold test**: corrected `test_simulation_warns_at_70_percent` to use a request count that actually exceeds 70% of budget

### 📦 Internal

- Added type hints (`Dict[str, Any]`) to all public `evaluate()` methods in check modules
- `release_gate.crypto` package now declared in `pyproject.toml` package list

---

## [0.2.0] - 2026-03-17

### ✨ Features

- **IDENTITY_BOUNDARY Check**: New check for access control and rate limiting
  - Validates authentication is required or explicitly allowed
  - Validates rate limits are configured per user/client
  - Validates data isolation boundaries are defined
  - Reports detailed evidence on auth enforcement
  
- **ACTION_BUDGET Check**: New check for resource and cost controls
  - Validates max tokens per request is defined
  - Validates max retries per request is defined
  - Validates max daily/monthly cost is defined
  - Validates max concurrent requests is defined
  - Reports detailed evidence on all budget constraints

- **Phase 2 Example Configs**: Real-world configuration examples
  - `example-phase2-video.yaml`: Video generation API example
  - `example-phase2-audio.yaml`: Audio processing example
  - `example-phase2-llm.yaml`: LLM assistant example

- **Phase 2 Documentation**: Comprehensive release notes
  - `PHASE_2_RELEASE_NOTES.md`: Complete guide to new checks
  - Configuration examples for different use cases
  - Upgrade path from v0.1 to v0.2

### 📋 What v0.2.0 Validates

✅ Request schema is syntactically valid JSON Schema (Draft 7)
✅ All valid test samples pass the defined schema
✅ All invalid test samples fail the defined schema
✅ Kill switch mechanism is declared
✅ Fallback behavior is specified
✅ Team ownership and on-call contact assigned
✅ Incident response runbook URL provided
✅ **Authentication is required or explicitly allowed**
✅ **Rate limits are configured**
✅ **Data isolation boundaries are defined**
✅ **Max tokens per request is limited**
✅ **Max retries per request is limited**
✅ **Max daily/monthly cost is limited**
✅ **Max concurrent requests is limited**

### 🔄 Breaking Changes

None. v0.1 configs continue to work. New checks are optional.

### 📊 Comparison: v0.1 vs v0.2

| Feature | v0.1 | v0.2 |
|---------|------|------|
| INPUT_CONTRACT | ✓ | ✓ |
| FALLBACK_DECLARED | ✓ | ✓ |
| IDENTITY_BOUNDARY | ✗ | ✓ |
| ACTION_BUDGET | ✗ | ✓ |

---

## [0.1.0] - 2026-03-16

### ✨ Features

- **INPUT_CONTRACT Check**: Validates request schema and test samples
  - Checks JSON Schema syntax is valid
  - Tests all valid samples pass the schema
  - Tests all invalid samples fail the schema
  - Reports detailed evidence and suggestions

- **FALLBACK_DECLARED Check**: Ensures operational safeguards are documented
  - Validates kill switch is declared (type + name)
  - Validates fallback mode is defined
  - Validates team ownership is assigned
  - Validates incident runbook URL is provided

- **CLI Tool**: Easy-to-use command-line interface
  - `init` command: Initialize new projects with templates
  - `run` command: Execute governance checks
  - Multiple output formats (text, JSON)
  - Custom output file path with `--output` flag
  - Environment specification with `--env` flag

- **CI/CD Integration**: Ready for deployment pipelines
  - Exit codes: 0 (PASS), 10 (WARN), 1 (FAIL)
  - JSON output for programmatic processing
  - Sample JSON report with evidence and suggestions

- **Local Execution**: Privacy-first design
  - All processing happens locally
  - No external API calls
  - No data transmission
  - Safe for confidential configurations

### 📋 What v0.1.0 Validates

✅ Request schema is syntactically valid JSON Schema (Draft 7)
✅ All valid test samples pass the defined schema
✅ All invalid test samples fail the defined schema
✅ Kill switch mechanism is declared
✅ Fallback behavior is specified
✅ Team ownership and on-call contact assigned
✅ Incident response runbook URL provided

### ❌ What v0.1.0 Does NOT Do

This is intentional - these are planned for future versions:

❌ Runtime testing (agent execution simulation) → v0.2
❌ Sample output validation (golden regression) → v0.2
❌ Action/resource budget verification → v0.2
❌ Performance/latency validation → v0.2
❌ Formal verification (neuro-symbolic proofs) → v0.3
❌ Runtime monitoring and anomaly detection → v0.4+

### 📚 Documentation

- Complete README with examples
- Extended README (8,000+ words) with comprehensive guide
- Quick-start guide (QUICKSTART.md)
- Installation instructions
- Configuration reference
- CI/CD integration examples (GitHub Actions, GitLab CI, Jenkins, Kubernetes)
- Contributing guidelines
- Code of conduct

### 🎯 Known Limitations

1. **Configuration Validation Only**
   - Checks if governance fields are declared
   - Does NOT verify safeguards actually work
   - Does NOT test agent behavior at runtime

2. **Semantic Mismatch Detection**
   - Cannot detect if input data matches its declared type
   - Example: Brain MRI schema with actual leg X-ray data
   - Requires v0.2+ runtime testing

3. **Fraudulent Documentation**
   - Cannot verify if documented safeguards are truthful
   - Cannot confirm implementation matches documentation
   - Requires v0.3+ formal verification

4. **No Behavior Verification**
   - Configuration can be filled out but not actually used
   - No guarantee that kill switch actually disables the agent
   - No proof that fallback mode actually executes

### 🔄 Exit Codes

| Code | Status | Meaning | CI/CD Action |
|------|--------|---------|--------------|
| 0 | PASS | All checks passed | Deploy automatically |
| 10 | WARN | Some warnings (invalid samples accepted) | Manual review recommended |
| 1 | FAIL | Critical failures | Block deployment |

### 📦 Dependencies

- `pyyaml>=6.0` - YAML configuration parsing
- `jsonschema>=4.0` - JSON Schema validation

Minimal dependencies by design. Only standard validation libraries, no heavy frameworks.

### 🚀 Getting Started

```bash
# Install
pip install -r requirements.txt

# Initialize project
python cli.py init --project my-system

# Run gate
python cli.py run --config release-gate.yaml --format text
```

### 🔗 Links

- **GitHub**: https://github.com/VamsiSudhakaran1/release_gate
- **Issues**: https://github.com/VamsiSudhakaran1/release_gate/issues
- **Discussions**: https://github.com/VamsiSudhakaran1/release_gate/discussions

### 🙏 Inspiration

- "Agents of Chaos: Red-Teaming of Autonomous AI Agents" (Shapira et al., 2026)
- DARPA Assured Neuro-Symbolic Research (ANSR)
- Production lessons learned from deploying autonomous agents

---

## Future Versions (Roadmap)

### v0.2.0 - Runtime Verification (Planned)

- GOLDEN_REGRESSION check: Test actual agent behavior
- ACTION_BUDGET_DECLARED check: Verify resource constraints
- LATENCY_GATE check: Performance verification
- Richer JSON reports with per-sample evidence

### v0.3.0 - Formal Verification (Planned)

- Neuro-symbolic verification layer
- Formal proof generation
- CSL-Core guardrails integration
- Valori-style state replay

### v0.4.0+ - Runtime Monitoring (Future)

- Continuous governance verification
- Anomaly detection
- Self-healing mechanisms
- Dashboard and web UI

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License - See [LICENSE](LICENSE) for details.
