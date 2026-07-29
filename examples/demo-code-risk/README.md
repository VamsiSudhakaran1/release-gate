# Demo — the PR review gate catching a net-new code risk

A real, reproducible example behind [release-gate.com/demo](https://release-gate.com/demo.html).
Everything below is captured output. CI re-runs it on every push
(`./build_demo.sh --check`), so if the engine ever stops producing these exact
results the build fails — instead of the published demo quietly becoming a mockup.

`analysis-agent` answers questions about a CSV. On `main` it lets the model pick
one **named aggregation** from an allowlist — validated, never executed. A pull
request then adds "natural-language queries" by asking the model for a pandas
expression and running it through `eval()`. Every line looks reasonable in review;
a prompt-injected cell in the CSV now reaches `eval()`.

- [`fixed/agent.py`](fixed/agent.py) — the safe baseline (state of `main`).
- [`vulnerable/agent.py`](vulnerable/agent.py) — what the PR introduces.
- [`lookalike/agent.py`](lookalike/agent.py) — the *other* half: an identically
  dangerous shape that we deliberately do **not** call a HIGH.
- [`build_demo.sh`](build_demo.sh) — builds a throwaway git repo (safe version as
  `main`, the eval as a branch) and runs the real gate.

## Run it

```bash
pip install release-gate
./build_demo.sh            # print the demo
./build_demo.sh --check    # print it and assert every claim below (what CI runs)
```

## 1. The PR verdict — net-new risk only

```
### 🔴 release-gate — AI-change review: BLOCK
_this change made things net-worse — see reasons_

Agent Code Safety: 100 → 76 (▼ -24)

Introduced by this change (not pre-existing):
- ⚠ HIGH (high · confirmed): Dangerous execution sink   agent.py:25
  ↳ eval() executes `expr`, which we traced to the model's own output at line 17.
- ⚠ LOW  (medium · inferred): LLM call with no token ceiling   agent.py:17
  ↳ This LLM call sets no max_tokens — a single response can run to the model's max output.
```

The gate blocks only what the diff introduced — inherited debt is shown, never gated.

## 2. Why that HIGH is trustworthy — and what we refuse to flag

The HIGH is graded **confirmed** because we can point at where the value came
from: it was assigned from `client.chat.completions.create(...)` on line 17 and
reaches `eval()` on line 25. Open those two lines and check us.

Scan the same service and both tiers appear in one report:

```
  Code findings  (3)

  • HIGH  high confidence · confirmed  Dangerous execution sink
     agent.py:25
     Evidence: client.chat.completions.create() (L17) -> `expr` -> eval() (L25)
     Impact:   Remote code execution: whoever controls the model's own output
               controls the code this process runs (L25).

  • MEDIUM  medium confidence · inferred  Deserialization of unverified data
     cache.py:26
     Evidence: `payload` -> pickle.loads() (L26) — origin unknown (name suggests external input)
     Impact:   RCE only if an untrusted source can reach this sink. Origin not
               proven here — this is a lead to check, not a confirmed vulnerability.

  ▸ Low severity · advisory  (1)
     · LLM call with no token ceiling  agent.py:17
```

`cache.py` contains `pickle.loads(payload)` — a genuinely dangerous sink. A
name-matching scanner reports it as confirmed remote code execution, because the
variable is *called* `payload`. We report it as a **MEDIUM that asks you to
confirm the source**, because nothing here proves it is attacker-controlled: it
is a function parameter, and its value comes from a caller this file cannot see.

That distinction is not academic. In AutoGPT the identically-named variable held
the cache's own HMAC-signed bytes — calling that a confirmed vulnerability is how
a report gets dismissed by a maintainer who knows their own code. **A variable's
name is never evidence.** A HIGH requires a traced origin we can cite by line.

See the tier contract in the [main README](../../README.md#what-it-detects--the-agent-safety-rule-catalog)
and the machine-checked `HIGH-tier integrity` invariant in
[`benchmark/RESULTS.md`](../../benchmark/RESULTS.md).
