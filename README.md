# release-gate

**The independent admission controller for AI systems.**

Release-Gate combines code-level agent risk, external evaluations, runtime
traces, governance evidence, verification results and human approvals into an
auditable **PROMOTE / HOLD / BLOCK** decision, without requiring teams to
replace the tools that produced the evidence.

A PROMOTE means the candidate **meets the declared release policy, with the
evidence and the gaps the decision lists**. It is never a statement that a
release is safe.

[![PyPI version](https://badge.fury.io/py/release-gate.svg)](https://badge.fury.io/py/release-gate)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Benchmarks](https://img.shields.io/badge/benchmarks-scanner_%C2%B7_assurance_%C2%B7_semantic_providers-blue.svg)](benchmark/README.md)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

```text
 code-level agent risk     SARIF from your scanner, or release-gate's own ──┐
 external evaluations      promptfoo, ProofAgent, red teams, eval harnesses ─┤
 runtime traces            OpenTelemetry, Langfuse, Arize-Phoenix ───────────┤   one candidate state,
 verification results      tests, provers, model checkers ───────────────────┼─▶ one claim graph,      ─▶ PROMOTE / HOLD / BLOCK
 governance evidence       governance.yaml, the pinned AIBOM ────────────────┤   one declared policy      + the Admission Report
 human approvals           reviews and approvals of this exact candidate ───┘
```

## Where it sits

Each of these answers a different question. Release-gate reads the others'
results as attributed evidence and answers the last one.

| Tool | The question it answers |
|---|---|
| Linter | Is the code well written? |
| SAST | Does the code contain known vulnerability patterns? |
| Guardrail | Should this live interaction be allowed? |
| Evaluator | How did the agent behave in these tests? |
| Observability | What happened when the system ran? |
| **Release-Gate** | **Does the evidence establish that this exact candidate satisfies its release policy?** |

It does not re-run, re-grade or replace any of them. A promptfoo result stays
promptfoo's, a scanner's finding stays the scanner's, and the Admission Report
says which evidence release-gate produced itself and which it read from another
tool. Its own agent-code scanner is one producer among them, not the product.

## What a decision says

| | Meaning |
|---|---|
| **PROMOTE** | the candidate meets the declared release policy with the evidence listed, and the gaps listed are ones the policy accepts |
| **HOLD** | something a person has to settle first, named, with the evidence that would settle it |
| **BLOCK** | the policy is violated: a failed check, a valid counterexample, a contradiction the policy blocks on |

Unknown is never a pass. Every decision states what was **not** assessed, and
evidence about another state of the release does not count for this one. The
decision is deterministic from the declared policy and the evidence. Models can
be asked to read evidence, and their readings never decide.

## Try it

```bash
pip install release-gate
release-gate assure your-run.jsonl        # no config file, no YAML, no account
```

That works on an OpenTelemetry trace, a Langfuse export, a promptfoo result, or
release-gate's own record format: the shape is detected, not declared. You get a
verdict, what a person has to look at, and what would resolve it.

In a pipeline, the release's claims and everything the pipeline produced decide
together:

```bash
release-gate assure release.jsonl --evidence evidence/ \
  --methodology general-agent-action@1.0.0 --admission
```

Exit 0 PROMOTE, 10 HOLD, 1 BLOCK. [CI templates](ci-templates/admission/) cover
GitHub Actions, GitLab, Jenkins, CircleCI and Azure Pipelines.

Nothing to install first: **[drop a run into the browser demo](https://release-gate.com/assurance.html)**
— it runs this same engine, and its three sample runs are the files in
[`examples/assurance/`](examples/assurance/), byte for byte.

Or run the worked examples. In [six tools, one release, one decision](examples/demo-admission/README.md),
five tools report good news and the decision still holds, for the reason it
prints. Five agent runs cover an OpenTelemetry trace, a promptfoo eval, a
destructive migration, a research swarm, and one that **promotes**:

```bash
python examples/demo-admission/run_demo.py
cd examples/agents && ./run-all.sh
```

[What each one demonstrates →](examples/agents/README.md)

---

## Three things a scanner or a score cannot do

### 1. It reduces machine work to a list a person can actually read

Two million records is not reviewable. A score over two million records is not
reviewable either — it is one number standing in for a judgement nobody made.

Release-gate returns a **bounded set of things that need a human**, derived from
which claims the decision actually rests on:

| | distinct producers | records seen | evidence | claims | reaches a person |
|---|---|---|---|---|---|
| one agent, one action | 4 | 7 | 6 | 0 | **1 item** |
| 10,248 workers | 10,254 | 2,287,133 | 10,258 | 2,420 | **13 items**, 7 undroppable |

Every figure in that table is measured by the test suite, not written here by
hand — a claim that drifts from the implementation fails a test.

Criticality comes from reachability in the claim graph, never from volume — a
claim one agent emitted once is exactly as load-bearing as one four hundred agents
discussed.

**And a shorter list is not a better case.** That is a property in code that
cannot return anything else, because the one dangerous way to read this table is
that a smaller number is a win. It can equally mean detection got worse.

### 2. Every verdict says what it did *not* check

This is the part most tools skip. A pass that doesn't state its own coverage is
indistinguishable from a pass that never looked.

```
WHAT WAS ASSESSED
  [    assessed]  input_integrity: the input file was hashed by release-gate
  [    assessed]  record_mapping: 6 of 6 record(s) mapped; 0 skipped
  [NOT_ASSESSED]  execution_reconstruction: no execution graph was reconstructed
  [NOT_ASSESSED]  replication: no verification attempt names a target
  [NOT_ASSESSED]  adversarial_review: no verifier set out to disprove this
```

`NOT_ASSESSED` is a first-class answer, kept apart from "we looked and found
nothing" everywhere in the engine. So is `UNKNOWN`, and so is a refuted check as
against an unresolved one. Collapsing those is how a gap comes to read as a clean
bill of health.

### 3. When it holds, it returns the work order

A gate that only says no is a nag. Each item comes with what would close it:

```
[BLOCK]    RG-ACT-001    'execution_reconstruction' is stated as NOT_ASSESSED
             → supply the run's trace or tool-call log

[ADVISORY] RG-PROV-002   all evidence traces to a single producer
             → add evidence from an independently-operated producer
```

That list is machine-readable (`--json`), so the next agent run can go and get the
evidence rather than a human re-reading the case to work out what was missing.

---

## What it will not tell you

Not that a release is **safe**. Not that a result is **guaranteed correct**. Not
that the gate is **unhackable** — twenty attacks run against the engine itself and
one is recorded `NOT_DEFENDED` with what bounds it instead. Not that a case is
**uncontested**, that hallucinations are **solved**, or that an expert has been
**replaced**: the output is a list of what needs a person.

Each refusal is a property in code that cannot return anything else.
[`docs/POSITIONING.md`](docs/POSITIONING.md) names every one with the line that
enforces it.

---

## From Python

```python
import release_gate as rg

case = rg.create_case(objective="Deploy generated migration", subject=migration)
case.add_execution(trace)                       # the steps, or a native trace
case.add_verification(test_result, method="TEST_SUITE", outcome="PASSED",
                      verifier="ci://pytest", against_subject=True)

decision = case.finalize()     # PROMOTE / HOLD / BLOCK, with its coverage attached
print(decision.required_evidence)
```

The same four calls carry one agent's migration and a ten-thousand-worker research
run. Not two products with a shared name — **one code path**: 346 engine functions
are common to both, 87% of everything the single-agent path touches.

---

## Configuration

Nothing is required to run. A **methodology** is what turns structure into a
verdict — without one, release-gate reports everything structural it can see and
**holds**, because "is this enough?" is a domain question and inventing an answer
would be claiming a standard it does not have.

```bash
release-gate assure --list-methodologies
release-gate assure run.jsonl --methodology research-mathematics@1.1.0
```

One input, four yardsticks, four answers — each naming what it is missing:

| methodology | verdict | unmet |
|---|---|---|
| *(none)* | HOLD | `METHODOLOGY_REQUIRED` |
| `general-autonomous-action@1.0.0` | BLOCK | no execution record |
| `software-change@1.0.0` | HOLD | structural findings only |
| `research-mathematics@1.1.0` | BLOCK | machine check, assumptions, independence |

Organisation config (`--config`) layers your own standards on top and can only
ever **tighten**. The methodology, the resolution policy (`--resolution-policy`:
what it takes to establish a claim, what a counterexample does) and the
organisation config together are the **declared release policy** a PROMOTE is
measured against. Each is digested into the case.

📖 **[Full walkthrough: inputs, outputs, and what to configure →](docs/DEMO.md)**

---

## What feeds the decision

The admission decision above is the product. These produce or carry its
evidence, and each is documented in its own place:

| | |
|---|---|
| **[External evidence](examples/evidence/README.md)** | Evaluations, red teams, SAST, formal verification, reviews and behavioural evaluations, each through one documented contract. Read and attributed, never re-run |
| **[Trace & eval ingestion](docs/INTEGRATION_GUIDE.md)** | OpenTelemetry · Langfuse · Arize-Phoenix · promptfoo read in place: no bespoke file, no new instrumentation |
| **[Agent code scanning](docs/RULES.md)** | Release-gate's own evidence producer for code-level agent risk: AST and taint analysis of model output reaching `eval`/`pickle`, retrieved text reaching prompts, uncapped LLM loops. Measured on its own [93-case corpus](benchmark/RESULTS.md) |
| **[`release-gate pr`](docs/REFERENCE.md#commands)** | One verdict on what a pull request *introduced*: net-new agent risk only, inherited debt shown and never gated |
| **[Semantic verification](docs/REFERENCE.md)** | Optional. A model, or a panel of independent models, reads evidence the rules cannot. Its readings are recorded and never decide; disagreement goes to a person |
| **[Evidence packs](docs/REFERENCE.md)** | A sealed, verifiable record of what was decided and on what |
| **[GitHub Action](action.yml)** · **[MCP server](docs/REFERENCE.md)** | `command: assure` in the Action; `pip install 'release-gate[mcp]'` |
| **[Benchmarks](benchmark/README.md)** | The scanner, the assurance layer and semantic providers, measured separately. The [assurance corpus](benchmark/ASSURANCE.md) publishes no headline precision figure, because on most of its cases precision is not a meaningful thing to measure |

---

## Docs

| | |
|---|---|
| [Demo & integration walkthrough](docs/DEMO.md) | inputs, outputs, configuration |
| [Positioning](docs/POSITIONING.md) | every claim, and the line that enforces it |
| [Architecture](docs/ARCHITECTURE.md) | how the engine is put together |
| [Reference](docs/REFERENCE.md) | full command and feature reference |
| [Changelog](docs/CHANGELOG.md) | release history |
| [Contributing](docs/CONTRIBUTING.md) · [Security](SECURITY.md) | |

## Development

```bash
git clone https://github.com/VamsiSudhakaran1/release-gate
cd release-gate && pip install -e '.[dev]'
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
