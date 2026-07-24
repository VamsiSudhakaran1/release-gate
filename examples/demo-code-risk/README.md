# Demo — the PR review gate catching a net-new code risk

A real, reproducible example behind [release-gate.com/demo](https://release-gate.com/demo.html).

`analysis-agent` answers questions about a CSV. On `main` it lets the model pick
one **named aggregation** from an allowlist — validated, never executed. A pull
request then adds "natural-language queries" by asking the model for a pandas
expression and running it through `eval()`. Every line looks reasonable in review;
a prompt-injected cell in the CSV now reaches `eval()`.

- [`fixed/agent.py`](fixed/agent.py) — the safe baseline (state of `main`).
- [`vulnerable/agent.py`](vulnerable/agent.py) — what the PR introduces.
- [`build_demo.sh`](build_demo.sh) — builds a throwaway git repo (safe version as
  `main`, the eval as a branch) and runs `release-gate pr` against it.

## Run it

```bash
pip install release-gate
./build_demo.sh
```

Expected verdict on the PR (net-new, scoped to the diff):

```
### 🔴 release-gate — AI-change review: BLOCK
Agent Code Safety: 100 → 76 (▼ -24)

Introduced by this change (not pre-existing):
- HIGH  (high · confirmed): Dangerous execution sink   agent.py:25
    ↳ eval() executes `expr` — the model's own output.
- LOW   (medium · inferred): LLM call with no token ceiling   agent.py:17
```

The `HIGH` is graded **confirmed** because the source is visible in scope: the
value came from `client.chat.completions.create(...)` and reaches `eval()` in the
same function. The gate blocks only what the diff introduced — never inherited debt.
