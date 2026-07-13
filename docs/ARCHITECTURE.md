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
| `release_gate/audit.py` | Report assembly + two-axis scoring, decision modes, **baseline comparison** (net-new vs inherited), the **AI-change `pr` verdict**, SARIF emit, PR-comment rendering, badge/markdown. |
| `release_gate/lockfile.py` | The **AIBOM / context lock** — pins model + prompts + governance + evals + MCP/tool config with a TTL; `compare_lock()` detects behaviour drift. |
| `release_gate/loop_verifier.py`, `loop_sim.py`, `agent_score.py` | The *behavioural* half — actually run an agent/loop for SHIP/CONTINUE/ROLLBACK and a 0-100 score. (Advanced; complements the static gate.) |
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
  → PROMOTE / HOLD / BLOCK  (+ badge, SARIF, markdown, evidence pack)
```

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
