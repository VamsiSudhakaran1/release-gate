# release-gate — Architecture

## What it is

release-gate is the **independent admission controller for AI systems**. It
combines code-level agent risk, external evaluations, runtime traces, governance
evidence, verification results and human approvals into an auditable
**PROMOTE / HOLD / BLOCK** decision about one exact candidate, against one
declared release policy, without requiring teams to replace the tools that
produced the evidence.

A PROMOTE says the candidate **meets the declared release policy with the
evidence and gaps it lists**. The engine holds no truth about whether a release
is safe, and no output says so ([POSITIONING](POSITIONING.md)).

The decision is deterministic from the declared policy and the normalised
evidence:

- every piece of evidence is attributed to its producer and bound, or not, to
  the candidate state;
- every claim is resolved by an ordered rule list, with no weighing;
- every condition that holds or blocks names its dimension, its claims and the
  policy that raised it;
- unknown is never a pass, and `NOT_ASSESSED` is reported, never omitted;
- a model can be asked to read evidence; its reading never decides, and no
  reading moves a decision toward admission.

## Where it sits in the pipeline

Each tool in a release pipeline answers a different question. release-gate reads
their results as evidence and answers the last one:

| Tool | The question it answers |
|---|---|
| Linter | Is the code well written? |
| SAST | Does the code contain known vulnerability patterns? |
| Guardrail | Should this live interaction be allowed? |
| Evaluator | How did the agent behave in these tests? |
| Observability | What happened when the system ran? |
| **release-gate** | **Does the evidence establish that this exact candidate satisfies its release policy?** |

```text
 linters, SAST ────────────┐
 release-gate's own scanner ┤
 evaluators, red teams ─────┤   attributed evidence     release-gate assure      PROMOTE / HOLD / BLOCK
 observability, traces ─────┼──────────────────────▶   candidate state,     ─▶ + the Admission Report
 provers, test suites ──────┤   (read, never re-run)    claim graph, policy      (exit 0 / 10 / 1)
 governance, AIBOM lock ────┤
 human reviews, approvals ──┘
```

It never sits in the runtime request path: a guardrail decides one live
interaction, and release-gate decides whether a version is admitted at all. Its
signed evidence pack and AIBOM lock are what it hands to runtime governance as
the attestation of what was admitted.

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
| `release_gate/assurance/semantic_verifier.py` | **The semantic verifier**: asks a model only the questions the claim resolution left open, about only the records that bear on each claim (minimised, bounded, hashed), and turns the answer into a bounded assertion — supported, contradicted, insufficient evidence, or UNKNOWN. Never a verdict: the resolution policy decides what an assertion does, and every provider failure is an UNKNOWN that moves nothing. Evidence is data, never instructions: it is sent as one JSON value under fixed instructions, with no tools offered and the reply held to a schema. Text in it addressed to the reader is recorded, and a "supported" reading of it is refused. Network transports in `release_gate/semantic_providers.py`, outside the core. |
| `release_gate/assurance/escalation.py` | **Semantic escalation**: decides, before any model is asked, which questions go to one. Every rule declares an adjudication mode (DETERMINISTIC, HYBRID, SEMANTIC, EXTERNAL_ONLY). Completeness, criticality, policy, prior readings, availability and budget are each weighed, in a fixed order. A claim the rules contradicted, which covers every HIGH static finding, is never asked about, and a model existing is never a reason to ask. |
| `release_gate/decision_providers/` | **Decision-model transports**: the `release-gate-decision/1` protocol (STATE, QUESTION, CHOICES in; choice, scores or probabilities out) and the optional `laya` and `jev` modules, imported only when named. Outside the core; sends through `semantic_providers.exchange_json`. |
| `release_gate/assurance/claim_coverage.py` | **Claim coverage**: a claim declares its surface (tools, paths, environments, datasets, model versions, authorization levels, failure modes, adversarial classes, obligations), evidence declares which elements it covers, and each element is assessed and supported, assessed and failed, not assessed, inaccessible, not applicable or unknown. Evidence that names nothing covers nothing; there is no percentage of safety, and a required claim's missing surface holds the case. |
| `release_gate/assurance/admission.py` | **The admission decision**: every structural finding, methodology requirement, open disagreement on a critical claim and documented exception as a condition with its admission dimension, its claims and the policy that declared it. The worst condition decides PROMOTE, HOLD or BLOCK; `decide()` is this. No score is an input. |
| `release_gate/assurance/admission_report.py` | **The Admission Report** (`assure --admission`): candidate, state hash, policy and decision; critical claims by status; what stands in the way; evidence sources split into generated by Release-Gate and imported. Reads the outcome and computes nothing. |
| `ingest.compose_inputs` · `action.yml` · `ci-templates/admission/` | **Admission in CI.** `assure --evidence` composes a release's claims file and every tool's output into one case. The Action's `command: assure` and the five CI templates run it. The CLI's exit codes stay 0 / 10 / 1; each template reads the Admission Report's own decision and applies a declared hold policy, so HOLD routes to a person (`normal`) or stops pending approval (`strict`), and never becomes BLOCK. `examples/demo-admission/` is a release decided this way, checked in CI. |
| `release_gate/assurance/calibration.py` | **Calibration data for a future decision model**: one flat, versioned row per semantic adjudication (what was asked of which model, what came back, what the deterministic engine did), with labels people later supply. Hash-only by default; redacted or full text only by choice; never an input to a decision. `scripts/evaluate_decision_models.py` compares models over it and trains nothing. |
| `release_gate/assurance/semantic_panel.py` | **Several semantic verifiers**: a panel asks several verifiers the same question and records each answer as its own reading. Independence is read from stated provenance (provider, model family, model, declared lineage), never assumed. Readings that disagree are a CONTRADICTION or REQUIRES_REVIEW for a person (RG-SEM-007), never averaged. A declared corroboration policy (`resolution.SemanticCorroboration`) decides when a "supported" on a critical claim counts. |
| `release_gate/assurance/provider_benchmark.py` | **The semantic provider benchmark**: labelled Release-Gate questions asked through the production verifier, scored so that false certainty costs most (a false confirmation costs four times one plus its confidence), and ranked among eligible providers by mean score, never by raw accuracy. It also reports abstention quality, calibration over stated probabilities, latency, cost, repeatability and context requirement. Run by `benchmark/semantic.py`; chooses nothing. |
| `release_gate/assurance/reference_adapters.py` | **Generic external-evidence contracts**: `release-gate.eval/1`, `red-team/1`, `sast/1`, `review/1` and `behavior/1`, each a registrant of the producer contract (the formal-verification schema is read by `verifiers.py`). A succeeded attack is a counterexample to its target; a blocked one supports and never establishes; a review's expiry is checked against a stated time, never a clock. Detected by schema name only. |
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

## The flows

### `assure` — the admission decision

```
release claims (release.jsonl) + --evidence: every tool's output
  → detect each document's shape; read it through its producer contract
        (OTel, Langfuse, promptfoo, SARIF, verifier reports, eval/red-team/
         review/behaviour contracts, release-gate's own audit reports)
  → bind each record to the stated candidate state      stale support counts for nothing
  → resolve every claim (CR-01 … CR-11)                 a counterexample outranks any support
  → correlation groups, contradictions, coverage, authorship
  → optional: semantic escalation and readings          recorded; never decide
  → evaluate admission under the declared policy        the worst condition decides
  → PROMOTE / HOLD / BLOCK + Admission Report + required evidence
```

### `audit` — code-level agent risk, as evidence

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
6. **The decision is the declared policy's.** PROMOTE / HOLD / BLOCK follows
   deterministically from the methodology, the resolution policy, the
   organisation configuration and the evidence. No score is an input, and a
   model's reading never decides.
7. **Read, never re-run.** Another tool's result is recorded as its producer
   reported it and attributed to that producer. release-gate does not re-grade
   an evaluation, re-scan a SARIF finding or re-derive a proof.
8. **Unknown is never a pass.** A claim nothing bears on is `NOT_ASSESSED`, a
   source that states nothing about its origin is never counted as independent,
   and a count of sources is never confidence.

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

## The universal assurance architecture

The admission controller is built on an **AssuranceCase**: a proposition about an
exact candidate, the evidence bearing on it from every producer, and the claims
the decision rests on. The repo audit started as the centre of the product and is
now one evidence producer feeding the case, alongside traces, evaluations,
behavioural probes, the AIBOM lock, formal verification and human review.

The same substrate carries **decision** assurance: whether there is enough
evidence for a person to authorise an exact machine-generated result or action.
It yields a human attention set, the smallest number of things a person must
inspect before accepting responsibility.

- Design and rationale: [`docs/specs/universal-assurance-architecture.md`](specs/universal-assurance-architecture.md)
- Data model, wire protocol, binding algorithm: [`docs/specs/assurance-data-model.md`](specs/assurance-data-model.md)
- Hosted endpoint — intake, idempotency, concurrency, versioning: [`docs/specs/assurance-protocol.md`](specs/assurance-protocol.md)

The engine ships as `release-gate assure` (since 0.11.0). Admission is a decision
about claims: each one is resolved against evidence bound to the exact candidate,
and corroboration is counted in independent groups of sources, not in records. The
migration plan in the spec (§15) keeps every command, JSON key, SARIF field, Action
output and exit code of the audit working unchanged; what the static producer
added is listed in §15.3a.
