# Running and showing Release-Gate

What to feed it, what comes back, and what — if anything — you have to configure.

Every command and output in this file was run against the repository at the
commit that added it. Where a figure appears it was measured, not estimated.

Every figure here was measured on the repository at the commit that added it.

---

## The short version

| | |
|---|---|
| **Configuration required to run** | none |
| **Configuration required to PROMOTE** | a methodology |
| **Input** | one file; the format is detected, not declared |
| **Output** | a verdict, what a person must look at, and what would resolve it |
| **Exit codes** | `0` PROMOTE · `10` HOLD · `1` BLOCK |

```bash
release-gate assure examples/assurance/single-action.jsonl
```

That works with no config file, no YAML, no account. It will HOLD, and it will
tell you why: nothing has said what *enough* means for this decision.

**Five worked examples,** in the shapes real systems emit — an OpenTelemetry
agent trace, a promptfoo eval whose failures become refuted claims, a destructive
production migration, a research swarm, and one that reaches PROMOTE:
`cd examples/agents && ./run-all.sh` ([what each shows](../examples/agents/README.md)).

**Without installing anything:** <https://release-gate.com/assurance.html> takes
a pasted or dropped run and returns the same case. Its three samples are the
files in `examples/assurance/` — the page and the CLI submit identical bytes, and
a test fails if they ever diverge.

---

## 1. Inputs

### What it accepts

Nine formats, auto-detected from the content. You never pass a `--format` flag.

| Kind | Typical source |
|---|---|
| `OTLP_TRACE` | OpenTelemetry GenAI spans |
| `NATIVE_TRACE` | release-gate's own trace shape |
| `LANGFUSE_EXPORT` | Langfuse |
| `ARIZE_EXPORT` | Arize / Phoenix |
| `PROMPTFOO_EVAL` | `promptfoo eval -o results.json` |
| `ASSURANCE_ENVELOPE` | the native record format (below) |
| `AUDIT_REPORT` | release-gate's own audit output |
| `VERIFIER_REPORT` | a prover, checker or lab report |
| `ORCHESTRATOR_EXPORT` | LangGraph, OpenAI Agents, CrewAI, AutoGen, Temporal |

Detection reports its own confidence, and `UNRECOGNISED` is a real answer rather
than a guess.

### The assurance envelope

JSONL, one record per line. Every record carries a `record_type`:

```
evidence · claim · artifact · execution · expectation
counterexample · failed_branch · adversarial · completeness · edge
```

`consequence` is accepted too — it describes what the action would do.

A minimal, useful submission:

```jsonl
{"record_type":"consequence","REVERSIBILITY":"REVERSIBLE","SCOPE":"SINGLE_SUBJECT","DATA_IMPACT":"MODIFIED"}
{"record_type":"evidence","evidence_id":"e1","kind":"TEST_RESULT","producer":{"producer_id":"agent://assistant/1","kind":"agent"},"coverage_note":"the project's test suite, 412 of 412 passing; does not cover migration under load"}
{"record_type":"artifact","logical_id":"migration.sql","artifact_kind":"MIGRATION","digest_method":"SHA256_CONTENT"}
{"record_type":"claim","claim_id":"C-1","proposition":"the migration applies cleanly and is reversible","supporting_evidence":["e1"],"verification_attempts":[{"method":"TEST_SUITE","outcome":"PASSED","verifier":"ci://build/991"}]}
```

Two fields do more work than they look like they do:

- **`coverage_note`** is what the evidence does *and does not* cover. It is not
  decoration — it is how a pass stays bounded by what was checked.
- **`verification_attempts[].method`** must be a real method name. "Verified" on
  its own is not an answer, so an untyped check does not count as verification.

### Execution: give it steps, not one record per node

Several methodologies require a reconstruction of what the agent actually did,
and there are two ways to supply one.

**A trace file** — OTLP or any of the other trace formats above. The example
below is detected as `OTLP_TRACE` at 95% and reconstructs a five-node graph.

```bash
release-gate assure examples/assurance/agent-trace.json
```

**A native trace inside the envelope** — one record carrying `steps`:

```json
{"record_type": "execution", "trace_id": "run-01", "steps": [
  {"type": "tool_call", "tool": "postgres_query"},
  {"type": "llm_call", "model": "planner", "tokens": 900},
  {"type": "tool_call", "tool": "shell"}
]}
```

What does **not** work is one `execution` record per node. That shape is counted
and not folded, and the ingest says so rather than dropping it:

```
skipped: {'execution records are not folded by the zero-config path': 1}
```

From Python, pass the steps to `add_execution` — either spelling works:

```python
case.add_execution([{"type": "tool_call", "tool": "shell"}])          # the steps
case.add_execution({"trace_id": "run-01", "steps": [...]})            # or the trace
```

---

## 2. Output

### Default: the assurance report

```bash
release-gate assure examples/assurance/single-action.jsonl \
  --methodology general-autonomous-action@1.0.0
```

The report opens with the verdict, the subject and the case digest, then a
coverage block that states what was and was not assessed:

```
  BLOCK   Assurance of single-action.jsonl

  Subject    subj_f6260c1cd2bd64e5  (GENERAL_RESULT)
  Input      ASSURANCE_ENVELOPE at 83% — 83% of sampled lines carry a known record_type
  Case       case_ee6ecc87c91dca70 v1  digest sha256:bb29512dcb69d816…

  WHAT WAS ASSESSED
    [    assessed]  input_integrity: the input file was hashed by release-gate
    [NOT_ASSESSED]  execution_reconstruction: no execution graph was reconstructed
    ...
```

`NOT_ASSESSED` is not a failure. It is the difference between *we looked and
found nothing* and *we did not look*, and it is printed for every dimension.

### `--review`: the one-screen version

```bash
release-gate assure <file> --review
```

Execution counts, the critical path, coverage, what a person must look at, and
the verdict — on one screen. Every figure on it is a field, and the renderer
computes none of them.

### `--json`: for a pipeline

The whole outcome, including the case, the findings, the coverage ledger and the
required-evidence protocol. `--case-output FILE` writes the sealed case on its own.

### What a reviewer actually acts on

Two lists. What needs a person:

```
[BLOCK]    RG-ACT-001        'execution_reconstruction' is stated as NOT_ASSESSED
[ADVISORY] RG-REPL-006       1 path records no lineage and cites no evidence
```

…and what would close each one:

```
supply the run's trace or tool-call log
add evidence from an independently-operated producer
declare reversibility and scope for this action
```

That second list is the product. A gate that only says no is a nag; this one
returns the work order.

---

## 3. Configuration

### Nothing is required

There is no config file to write, no YAML schema to learn, and nothing is
discovered from the filesystem — a gate whose verdict depends on which directory
it ran from is a gate whose verdict cannot be reproduced.

### A methodology is what turns structure into a verdict

Without one, release-gate reports everything structural it can see and **holds**,
reporting `METHODOLOGY_REQUIRED`. It will not invent a standard.

```bash
release-gate assure --list-methodologies     # the built-ins
release-gate assure <file> --methodology research-mathematics@1.1.0
release-gate assure <file> --methodology ./our-methodology.json
```

Always pass `id@version`. A bare id is refused on purpose: resolving "the latest"
implicitly is how an existing case silently acquires a different bar.

The same input under four yardsticks, measured:

| Methodology | Verdict | Unmet |
|---|---|---|
| *(none)* | HOLD | — `METHODOLOGY_REQUIRED` |
| `general-autonomous-action@1.0.0` | BLOCK | `RG-ACT-001` — no execution record |
| `software-change@1.0.0` | HOLD | structural findings only |
| `research-mathematics@1.1.0` | BLOCK | machine check, assumptions, independence, lemma coverage |

One input, four answers, each naming what it is missing. That is the demo.

### Organisation config, if you want it

`--config FILE` layers an organisation's own standards on top. It can only ever
**tighten**: raise the required assurance level, add requirements, name verifiers
that must have run, declare what kind of check a tool performs. There is
deliberately no way to lower a bar through it.

---

## 4. The three scales, same engine

```bash
python -m release_gate.demos.single_agent              # one agent, one action
python -m release_gate.demos.frontier_research 100     # ~100 agents
python -m release_gate.demos.frontier_research         # 10,248 workers
```

| | Producers | Records | Review items | Verdict |
|---|---|---|---|---|
| Single agent | 1 | 7 | 1 | PROMOTE |
| ~100 agents | 108 | 24,782 | 13 | BLOCK |
| 10,248 workers | 10,254 | 2,287,133 | 13 | BLOCK |

Two million records to thirteen things a person reads — and the two big cases
BLOCK for substantive reasons (an open contradiction, a live counterexample), not
because they are large.

These are one code path, not three: 346 engine functions are common to all three
across 27 modules, which is 87% of everything the single-agent path touches.

---

## 5. Showing it to someone

The arc that lands:

1. **Submit evidence with no config.** It HOLDs and says a methodology is
   required. Nobody is asked to trust a number.
2. **Add a methodology.** It BLOCKs and names one missing thing —
   *supply the run's trace*. The gate is answerable.
3. **Show the frontier demo.** Two million records, thirteen review items, and a
   verdict that refuses to promote a case carrying an open contradiction.
4. **Show what it will not say.** The report states what was not assessed, and
   nothing in it claims the result is true.

The last one is the point. The verdict authorises an action against an exact
state; it does not certify that a machine was right.

---

## Two defects this file found

Writing it turned up two, both since fixed. Recorded because the shape is worth
recognising: **a call that looks like it worked and did nothing.**

- **`Case.add_execution([...])` built no graph.** Given the steps as a list, they
  were flattened to a scalar and no execution graph was reconstructed — so the
  case then reported `execution_reconstruction: NOT_ASSESSED` and asked for the
  trace it had just been handed. A bare sequence is now wrapped into the shape the
  ingest folds, and a payload that cannot become a trace is refused rather than
  stored.
- **`create_case(methodology="research-mathematics-v1")` discarded the `-v1`.**
  The id was split at `-v` and the newest version of any major came back. With one
  version published nobody could tell; with two, a caller who named a version got
  a different one. `id@X.Y.Z` now pins exactly, `id-vN` pins to the newest version
  in the N line, and a bare id still takes the newest — which is what the CLI does,
  and the case records the ref either way.
