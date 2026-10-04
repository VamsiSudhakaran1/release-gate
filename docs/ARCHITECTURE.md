# release-gate — Architecture

## What it is

release-gate is the **pre-deploy release gate for AI agents**. It renders one
evidence-based decision — **PROMOTE / HOLD / BLOCK** — from two independent axes:

- **Agent Code Safety** — an *objective* score derived from the code itself, via
  AST + light taint analysis: model/user output reaching `eval`/`exec`/a shell
  (the CVE-2025-51472 RCE class), untrusted input interpolated into a system
  prompt, LLM calls with no token ceiling, unbounded loops around LLM calls,
  hardcoded secrets. It moves per repo and depends on adopting nothing.
- **Governance** — *maturity* of the declared, enforceable safeguards
  (budget ceiling, kill switch, owner, evals, trace policy, auth/rate-limit).
  Low here means **undeclared, not unsafe**.

Every finding carries evidence (`source → sink`), a `confirmed`/`inferred`
basis, and a **stable rule id** (`RG-EXEC-001`) mapped to OWASP LLM Top 10 /
NIST AI RMF / EU AI Act. Precision is the design constraint: a finding is
emitted only when it can be defended to a maintainer.

## Where it sits in the pipeline

release-gate is the **pre-deploy / admission** plane — the layer *above* the
tools it complements, and *before* the runtime ones:

```
SAST (SonarQube/Snyk)    →  code-layer vulns; blind to "x came from the model"
Guardrails (Lakera/NeMo) →  filter one request at runtime
Evaluators (Ragas/…)     →  score one output's quality
release-gate             →  PRE-DEPLOY: can this agent version ship at all?
Runtime governance       →  enforce policy on tool calls of a DEPLOYED agent
(AGT / agent-passport)      (release-gate's signed evidence pack + AIBOM lock
                             are the natural attestation / behaviour manifest it
                             hands to that layer)
```

It never sits in the runtime request path. It answers the question that comes
before identity, authorization, and runtime policy: *is this version fit to be
admitted?*

## Components

| Module | Responsibility |
|---|---|
| `release_gate/agent_analysis.py` | The AST engine — resolves which objects are LLM clients, does intra-procedural taint, classifies exec/deserialization/prompt/loop/token-ceiling risks. Precision-first (not grep). |
| `release_gate/verify.py` | File scanners (Python + JS/TS), the secret scan, and governance-safeguard verification; produces `code_findings` + safeguard results. |
| `release_gate/rules.py` | The **rule registry** — the single source of truth for stable rule ids, rationale, and compliance mappings. Generates `docs/RULES.md`. |
| `release_gate/audit.py` | Report assembly + two-axis scoring, decision modes, **baseline comparison** (net-new vs inherited), the **AI-change `pr` verdict**, SARIF emit, PR-comment rendering, badge/markdown. Records the report's `evidence_provenance` block (repository, commit, tree state, scanner/rule/analyser digests, a digest of the exact bytes scanned). |
| `release_gate/assurance/producer_contract.py` | The **evidence producer contract**: what every producer declares (modality, determinism, confidence and coverage semantics, independence, limitations), the adapter interface, the one normaliser that writes records, and the registry new producers are added to without engine changes. Built-in adapters (promptfoo, SARIF, external decisions) in `producer_adapters.py`. |
| `release_gate/assurance/candidate.py` | **Candidate state**: the exact release being admitted (repository, commit, tree, image, model, prompt, tool manifest, governance, evals, deployment config, dataset, environment, artifacts), and how each piece of evidence binds to it. Support from a different state of the release does not count toward a claim about this one. |
| `release_gate/assurance/resolution.py` | **Claim resolution**: every claim gets one of seven statuses (ESTABLISHED … NOT_ASSESSED), the rule that reached it, and the evidence for it, against it and set aside. An ordered rule list with no weighing, so a counterexample outranks any amount of support and a proof about the wrong artifact does not count. What establishes a claim is a declared policy, and the case records it. |
| `release_gate/assurance/correlation.py` | **Evidence independence**: places each source in a correlation group by what it states produced it (provider, model family, session, agent, reviewer, toolchain, prompt, dataset, generated artifacts) and by what it relied on. Five outputs of one model session are one group. A source that states nothing is `INDEPENDENCE_UNKNOWN`, never independent, and there is no score. |
| `release_gate/assurance/semantic_verifier.py` | **The semantic verifier**: asks a model only the questions the claim resolution left open, about only the records that bear on each claim (minimised, bounded, hashed), and turns the answer into a bounded assertion — supported, contradicted, insufficient evidence, or UNKNOWN. Never a verdict: the resolution policy decides what an assertion does, and every provider failure is an UNKNOWN that moves nothing. Network transports in `release_gate/semantic_providers.py`, outside the core. |
| `release_gate/assurance/escalation.py` | **Semantic escalation**: decides, before any model is asked, which questions go to one. Every rule declares an adjudication mode (DETERMINISTIC, HYBRID, SEMANTIC, EXTERNAL_ONLY). Completeness, criticality, policy, prior readings, availability and budget are each weighed, in a fixed order. A claim the rules contradicted, which covers every HIGH static finding, is never asked about, and a model existing is never a reason to ask. |
| `release_gate/decision_providers/` | **Decision-model transports**: the `release-gate-decision/1` protocol (STATE, QUESTION, CHOICES in; choice, scores or probabilities out) and the optional `laya` and `jev` modules, imported only when named. Outside the core; sends through `semantic_providers.exchange_json`. |
| `release_gate/assurance/claim_coverage.py` | **Claim coverage**: a claim declares its surface (tools, paths, environments, datasets, model versions, authorization levels, failure modes, adversarial classes, obligations), evidence declares which elements it covers, and each element is assessed and supported, assessed and failed, not assessed, inaccessible, not applicable or unknown. Evidence that names nothing covers nothing; there is no percentage of safety, and a required claim's missing surface holds the case. |
| `release_gate/assurance/reference_adapters.py` | **Generic external-evidence contracts**: `release-gate.eval/1`, `red-team/1`, `sast/1` and `review/1`, each a registrant of the producer contract (the formal-verification schema is read by `verifiers.py`). A succeeded attack is a counterexample to its target; a blocked one supports and never establishes; a review's expiry is checked against a stated time, never a clock. Detected by schema name only. |
| `release_gate/assurance/origin.py` | **Evidence origin**: for every producer in a case, whether release-gate computed its evidence, obtained it in this run, or read it without running the producer. On every report; no rule reads it. |
| `release_gate/assurance/authorship.py` | **Authorship and verification correlation**: who did each piece of the work, as CI, a commit or a person states it, compared with who checked it. "Verification independence low" when every counted check shares the author's provenance. About independence, never a judgement of AI-written code; unknown authorship stays UNKNOWN. |
| `release_gate/assurance/static_producer.py` | The scanner as a **first-class evidence producer** (`release_gate_static`): turns an audit report into Universal Evidence. Each finding becomes a scoped observation with what it does *not* establish and its source→sink path, bound to the scanned code. `assure audit.json` and `audit --evidence-out` both go through it. |
| `release_gate/lockfile.py` | The **AIBOM / context lock** — pins model + prompts + governance + evals + MCP/tool config with a TTL; `compare_lock()` detects behaviour drift. |
| `release_gate/loop_verifier.py`, `loop_sim.py`, `agent_score.py` | The *behavioural* half — actually run an agent/loop for SHIP/CONTINUE/ROLLBACK and a 0-100 score. (Advanced; complements the static gate.) |
| `release_gate/trace_validator.py` | Judges one execution trace against `trace_policies` — forbidden tools, retry storms, token overruns, and an agent repeating an *identical* call instead of progressing. |
| `release_gate/adapters/` | Turns the telemetry teams already emit (OpenTelemetry, Langfuse, Arize/Phoenix, Promptfoo) into native traces and eval results, reporting what it could **not** map. The static→dynamic bridge is a mapping, not a model: no LLM, so runtime verdicts stay as reproducible as static ones. |
| `release_gate/evidence_pack.py` | Signed, machine-readable evidence bundle for compliance/attestation. |
| `release_gate_api/` | The optional hosted platform (FastAPI) — history, dashboard, PDF reports. Not required for the CLI. |
| `release_gate/mcp_server.py` | Exposes the auditor as a read-only MCP server so a coding agent can gate itself before opening a PR. |

## The two primary flows

### `audit` — score a repo

```
repo path / GitHub URL
  → detect frameworks + LLM usage        (is this an agent? which stack?)
  → scan_code_findings()                 AST + taint → code_findings (+ rule_id)
      · production vs example/test partitioned (examples never touch the score)
  → verify governance safeguards         declared, enforceable checks
  → compute two axes + apply_decision_mode(audit|ci|strict|public-advisory)
  → record evidence_provenance           what the findings were raised against
  → PROMOTE / HOLD / BLOCK  (+ badge, SARIF, markdown, evidence pack)
  → optional: --evidence-out             the findings as Universal Evidence
```

### The scanner as an evidence producer

The static scanner's findings are **evidence of what the analyser saw, not
conclusions about the world**. Each rule has a profile, kept as data, that says
what it observed and what it does not establish. A rule that reports a
*missing* mitigation (no gate, no token ceiling, no iteration cap) says what
static analysis did not identify, and where it looked. So RG-GATE-001 reads
*"static analysis did not identify a code-level approval gate on this path"*,
never "no human approval exists". Each record carries:

- the producer and its type, and the scanner version;
- the rule and its digest, and its framework mappings;
- the source→sink path and the lines it spans, with a digest of each;
- the repository, the commit and whether the tree was clean;
- a digest of every file the analyser read, which is what the evidence is
  bound to.

The `audit` verdict and every rendering are unchanged. The evidence feeds an
assurance case alongside traces, evals, tests and human review, and the scanner
has no special standing there.

### `pr` — the AI-change review gate

```
--base <ref>
  → git worktree of the base ref         (audit base and HEAD)
  → compare_to_baseline(head, base)      net-new findings ONLY (ignore inherited debt)
  → compare_lock()                       behaviour drift vs release-gate.lock
  → unify_verdict()                      one PROMOTE / HOLD / BLOCK
  → render_ai_pr_comment()               "introduced by this change" + what to ignore
```

Both drop into CI with **exit codes `0` PROMOTE · `10` HOLD · `1` BLOCK**.

## Design principles

1. **Evidence, not vibes.** Every finding cites its flow; no heuristic "risk
   scores" from proxies. A verdict must be inspectable.
2. **Precision over recall.** When reachability can't be proven, stay quiet or
   grade down (`inferred`, lower severity). One bad flag loses a maintainer.
3. **Block only on net-new regressions.** A PR is judged on what *it* changed;
   inherited debt is shown and ignored. A gate that nags gets muted.
4. **Auditable, not infallible.** Stable rule ids + a public rationale catalog +
   honest `NOT_ASSESSED` where a thing isn't tested.
5. **Local-first CLI.** The static audit makes no model calls and reads only the
   directory it's pointed at.

## Rule identity & compliance

Findings resolve to a permanent rule id (`release_gate/rules.py`), each with a
one-line rationale and a mapping to OWASP LLM Top 10 / NIST AI RMF / EU AI Act.
The catalog is published at `docs/RULES.md` (generated — run
`python scripts/gen_rules_doc.py`) and surfaced in SARIF via `helpUri`, so
GitHub Code Scanning groups by stable identity and links to the rationale. This
is what lets "why did this block my release?" resolve to a URL, not a code dive.

## Testing & CI

- ~600 tests, deterministic core, run in seconds (`pytest tests/`).
- `scripts/check_version_sync.py` enforces version consistency across
  pyproject / package / API / Action pins.
- `.github/workflows/release-gate-pr.yml` dogfoods the `pr` gate on every PR to
  this repo.

## Where this is going — the universal assurance architecture

Everything above describes the **admission** plane: one question (*may this agent
version ship?*) with the repo audit at the centre. The designed next step keeps all
of it and changes what sits at the centre: the root object becomes an
**AssuranceCase** — a proposition a named human is about to authorise — and the
audit becomes one evidence producer feeding it, alongside traces, evals, behavioural
probes, the AIBOM lock, formal verification and human review.

That adds a second first-class plane, **decision** assurance (*is there enough
evidence for a human to authorise this exact machine-generated result or action?*),
on the same evidence substrate, and with it a human attention set: the smallest
number of things a person must inspect before accepting responsibility.

- Design and rationale: [`docs/specs/universal-assurance-architecture.md`](specs/universal-assurance-architecture.md)
- Data model, wire protocol, binding algorithm: [`docs/specs/assurance-data-model.md`](specs/assurance-data-model.md)
- Hosted endpoint — intake, idempotency, concurrency, versioning: [`docs/specs/assurance-protocol.md`](specs/assurance-protocol.md)

The engine ships as `release-gate assure` (since 0.11.0), and the audit feeds
it through the static evidence producer above. Admission there is a decision
about claims: each one is resolved against evidence bound to the exact candidate,
and corroboration is counted in independent groups of sources, not in records. The migration plan in the spec
(§15) keeps every command, JSON key, SARIF field, Action output and exit code on
this page working unchanged; what the static producer added is listed in §15.3a.
