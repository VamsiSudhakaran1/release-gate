# release-gate accuracy benchmark

**Accuracy demonstrated, not asserted.** This is a reproducible precision/recall
harness over a labeled corpus — so a reviewer can check the tool's error rate
today instead of taking the README's word for it.

```bash
python benchmark/run.py          # human report
python benchmark/run.py --json   # machine output
python benchmark/run.py --md     # regenerate RESULTS.md
```

See [`RESULTS.md`](RESULTS.md) for the current numbers.

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
