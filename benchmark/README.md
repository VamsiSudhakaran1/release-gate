# release-gate benchmarks

**Accuracy demonstrated, not asserted.** Three reproducible harnesses over
three labeled corpora, kept apart because they measure three different things.

| | Unit | Corpus | Results |
|---|---|---|---|
| **Scanner** (`run.py`) | a code snippet | `cases.yaml`, 93 cases | [`RESULTS.md`](RESULTS.md) |
| **Assurance** (`assurance.py`) | an assurance case | `release_gate/assurance/corpus.py`, 16 cases | [`ASSURANCE.md`](ASSURANCE.md) |
| **Semantic providers** (`semantic.py`) | a model's reading of an evidence packet | `semantic_cases.jsonl`, 15 cases | [`SEMANTIC.md`](SEMANTIC.md) |

```bash
python benchmark/run.py          # the scanner: human report
python benchmark/run.py --md     # regenerate RESULTS.md

python benchmark/assurance.py    # the assurance layer: human report
python benchmark/assurance.py --md   # regenerate ASSURANCE.md

python benchmark/semantic.py     # semantic providers: the reference providers
python benchmark/semantic.py --provider env --repeats 3   # + your configured model
python benchmark/semantic.py --md    # regenerate SEMANTIC.md
```

**They are deliberately not merged.** The scanner benchmark asks *does this
snippet contain this vulnerability*; the assurance benchmark asks *does
release-gate correctly report the structure of the evidence it was given*; the
semantic benchmark asks *how well does a model read evidence, and how often is
it confidently wrong*. None of these figures carries over to another layer, and
putting them in one table is how a reader comes to believe it does.

The semantic benchmark scores false certainty hardest and never ranks by raw
accuracy. Its labels were written with the cases, each with its rationale, and
have not been independently adjudicated: add your reviewers' cases with
`--cases FILE`. See [`SEMANTIC.md`](SEMANTIC.md) and the REFERENCE section
*Benchmarking semantic providers*.

The rest of this file is about the scanner benchmark.

## How it works

`cases.yaml` is labeled ground truth. Each case is either:

- **`vulnerable`** — the engine must emit every rule id in `expect` (a miss is a
  false negative).
- **`clean`** — the engine must stay silent. Most clean cases are real
  look-alikes drawn from frameworks where a naive scanner false-positives
  (mem0, smolagents, crewAI, gpt-researcher, livekit…). Each doubles as a
  permanent regression guard: reintroduce the false positive and the benchmark
  fails.

A vulnerable case scores a true positive only on the **exact expected rule id**;
any unexpected emission anywhere is a false positive.

## What this is and isn't

- **It is** the reproducible, growing evidence a reviewer can run themselves, and
  a regression floor in CI (`tests/test_benchmark.py`).
- **It is not** a third-party security audit, and it is not a claim of
  perfection. The corpus is deliberately honest about limits — e.g.
  `exec-cross-function-taint-KNOWN-MISS` documents that taint is intra-procedural
  and does not follow a value across function boundaries. release-gate is
  **precision-first**: it would rather stay silent than cry wolf, so recall is
  intentionally below 100% while precision is held at 100%. When it flags, trust
  it; it will not catch everything.

## Contributing cases

Found a false positive or a missed vulnerability? Add it to `cases.yaml` with a
`source`, run `python benchmark/run.py --md`, and open a PR. Adversarial cases
are especially welcome — the benchmark only earns authority by surviving them.
