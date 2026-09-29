# release-gate

**A machine produced something consequential. A human has to decide whether the
evidence is enough to act on it. Release-gate builds the case they decide from.**

It does not generate results and it does not verify them — agents generate, tools
verify, and release-gate assembles the argument those two leave behind, then says
whether that argument is sound enough to put to a person.

[![PyPI version](https://badge.fury.io/py/release-gate.svg)](https://badge.fury.io/py/release-gate)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Benchmark](https://img.shields.io/badge/benchmark-93--case_corpus_%C2%B7_100%25_precision-blue.svg)](benchmark/RESULTS.md)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

```bash
pip install release-gate
release-gate assure your-run.jsonl        # no config file, no YAML, no account
```

That works on an OpenTelemetry trace, a Langfuse export, a promptfoo result, or
release-gate's own record format — the shape is detected, not declared. You get a
verdict, what a person has to look at, and what would resolve it.

Nothing to install first: **[drop a run into the browser demo](https://release-gate.com/assurance.html)**
— it runs this same engine, and its three sample runs are the files in
[`examples/assurance/`](examples/assurance/), byte for byte.

Or run the five worked examples — an OpenTelemetry agent trace, a promptfoo eval,
a destructive migration, a research swarm, and one that **promotes**:

```bash
cd examples/agents && ./run-all.sh
```

[What each one demonstrates →](examples/agents/README.md)

---

## Three things it does that a scanner or a score cannot

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
ever **tighten**.

📖 **[Full walkthrough: inputs, outputs, and what to configure →](docs/DEMO.md)**

---

## We also do this

The assurance engine above is the product. These are separate lanes that feed it
or stand on their own — each documented in its own place:

| | |
|---|---|
| **[`release-gate pr`](docs/EXTENDED_README.md#pr-gating)** | One verdict on what a pull request *introduced* — net-new agent risk only, inherited debt shown and never gated |
| **[Agent code scanning](docs/RULES.md)** | AST + taint analysis for the agent layer: model output reaching `eval`/`pickle`, prompt injection from RAG, uncapped LLM loops. [93-case corpus](benchmark/RESULTS.md), 100% precision / 100% recall |
| **[Trace & eval ingestion](docs/INTEGRATION_GUIDE.md)** | OpenTelemetry · Langfuse · Arize-Phoenix · promptfoo convert in place — no bespoke file, no new instrumentation |
| **[Evidence packs](docs/REFERENCE.md)** | A sealed, verifiable record of what was decided and on what |
| **[GitHub Action](action.yml)** · **[MCP server](docs/REFERENCE.md)** | `pip install 'release-gate[mcp]'` |
| **[Assurance corpus](benchmark/ASSURANCE.md)** | 16 constructed cases for the engine itself — publishes no headline precision figure, because on most of them precision is not a meaningful thing to measure |

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
