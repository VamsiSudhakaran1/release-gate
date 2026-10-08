# release-gate Quick Start

release-gate is the independent admission controller for AI systems. You give it
the release's claims and the evidence your tools already produce. It returns
PROMOTE, HOLD or BLOCK against your declared release policy, with the evidence and
the gaps behind it.

## 1. Install

```bash
pip install release-gate
```

No account, no config file, no network access needed for the decision.

## 2. Decide a release that ships with the repository

```bash
git clone https://github.com/VamsiSudhakaran1/release-gate && cd release-gate
release-gate assure examples/evidence/release.jsonl --evidence examples/evidence \
  --methodology general-agent-action@1.0.0 --admission
```

`release.jsonl` states the candidate (repository, commit, environment) and the
claims the release makes. `examples/evidence/` holds what six kinds of tool
reported about it: an eval harness, a red team, a SAST scanner, a formal
verifier, a review and a behavioural evaluation. The Admission Report shows:

- **the candidate and its state hash**: every piece of evidence is bound to
  this exact state, or set aside;
- **the policy**: the methodology and resolution policy, with their digests;
- **the decision**: here BLOCK, because a red-team attack succeeded against a
  critical claim, and a counterexample outranks any amount of support;
- **the critical claims by status**, **what stands in the way**, and **every
  evidence source**, split into what release-gate produced and what it read.

Exit codes: 0 PROMOTE · 10 HOLD · 1 BLOCK.

## 3. What a decision says, and does not

| | Meaning |
|---|---|
| **PROMOTE** | the candidate meets the declared release policy with the evidence listed, and the gaps listed are ones the policy accepts |
| **HOLD** | something a person must settle first, named with the evidence that would settle it |
| **BLOCK** | the policy is violated: a failed check, a valid counterexample, a contradiction the policy blocks on |

A PROMOTE is not a statement that the release is safe, and release-gate never
makes one: what it establishes is bounded by the policy and the evidence, and the
report lists both. Without a methodology the run holds with
`METHODOLOGY_REQUIRED`, because "is this enough?" is a domain question.

## 4. Your own release

Write `release.jsonl`: one row for the candidate, one per claim.

```json
{"record_type": "candidate", "components": {"repository": "github.com/you/agent", "commit": "abc1234"}}
{"record_type": "claim", "claim_id": "cl_approval", "is_root": true, "proposition": "No refund above 500 is issued without a person's approval", "producer": {"producer_id": "payments-team", "kind": "human"}}
```

Put whatever your pipeline produced into a directory: promptfoo results,
OpenTelemetry or Langfuse exports, SARIF from your scanner, verifier reports,
and documents in the contracts under [`examples/evidence/`](../examples/evidence/README.md).
Then:

```bash
release-gate assure release.jsonl --evidence evidence/ \
  --methodology general-agent-action@1.0.0 --admission
```

`release-gate assure --list-methodologies` lists the built-in methodologies. The
[reference](REFERENCE.md#assure--the-assurance-engine) covers resolution policies,
organisation configuration, and the optional semantic verification.

## 5. In CI

Copy a template from [`ci-templates/admission/`](../ci-templates/admission/)
(GitHub Actions, GitLab, Jenkins, CircleCI, Azure Pipelines), or use the
GitHub Action with `command: assure`. Each template reads the Admission Report's
decision and applies a declared hold policy: a HOLD routes to a person, or
stops pending approval, and never becomes a BLOCK.

## 6. Add release-gate's own evidence

release-gate also produces evidence itself. Its agent-code scanner is one producer
among the others:

```bash
release-gate audit . --evidence-out evidence/static-analysis.json
```

The findings are written as Universal Evidence, which `assure --evidence` reads
beside everything else.

## Governance-file checks

The earlier governance-file lane still works. `release-gate init` starts a
`governance.yaml`, and `release-gate run governance.yaml` checks the declared
safeguards (input contract, kill switch, fallback, ownership, runbook):

### ✓ PASS (Exit Code 0)
Every check this lane runs passed — nothing it looks for was found. That is not the
same as safe to deploy, and release-gate will not say the second thing: what a pass
establishes is bounded by what was checked, and the coverage note on each result says
what that was.

### ⚠ WARN (Exit Code 10)
Some warnings found. Review before deploying.

### ✗ FAIL (Exit Code 1)
Critical issues found. Fix before deploying.

---

Next: [the README](../README.md) for the whole picture, and
[POSITIONING](POSITIONING.md) for what release-gate claims and will not claim.
