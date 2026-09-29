# Example agent runs

Five inputs in the shapes real systems emit, and what release-gate decides about
each. Nothing here is a fixture with a pinned answer — run `./run-all.sh` and the
verdicts are whatever the engine reaches.

```bash
pip install release-gate
cd examples/agents && ./run-all.sh
```

```
INPUT                              METHODOLOGY                        VERDICT   EXIT
────────────────────────────────────────────────────────────────────────────────────
01-coding-agent-otel.json          (none)                             HOLD      10
01-coding-agent-otel.json          general-autonomous-action@1.0.0    HOLD      10
02-release-promoted.jsonl          general-autonomous-action@1.0.0    PROMOTE   0
03-support-eval-promptfoo.json     (none)                             BLOCK     1
04-production-db-change.jsonl      production-database-change@1.0.0   HOLD      10
05-research-swarm.jsonl            research-mathematics@1.0.0         BLOCK     1
05-research-swarm.jsonl            research-mathematics@1.1.0         BLOCK     1
```

Exit codes: `0` PROMOTE · `10` HOLD · `1` BLOCK.

---

## 01 — A coding agent, as OpenTelemetry emits it

`01-coding-agent-otel.json` · OTLP GenAI spans · **HOLD**

An agent fixes a rounding bug: plans, reads two files, edits, runs the tests, the
tests fail, it reads the failure, edits again, tests pass, commits. Eleven spans
with `gen_ai.*` attributes — the file an OpenTelemetry-instrumented agent already
produces. No release-gate-specific instrumentation.

What it shows:

- **Detection, not declaration.** `OTLP_TRACE at 95%`. You never pass a format flag.
- **Execution reconstruction** from the span tree.
- **Capability discovery, honestly bounded.** It reports `CODE_MODIFICATION`,
  `FILESYSTEM` and two tools it could not identify — and states that an
  unidentified tool *can reach capabilities without appearing as them*, so the
  list is not an inventory.
- **A coverage ledger** in which most dimensions read `NOT_ASSESSED`, because a
  trace on its own says nothing about stakes, replication or adversarial review.

It holds rather than blocks: nothing is wrong, and nothing established that the
evidence is enough.

## 02 — The same engine saying yes

`02-release-promoted.jsonl` · assurance envelope · **PROMOTE**

The case a well-evidenced change actually looks like: consequence declared across
all ten dimensions, an execution record, three pieces of evidence from three
independently-operated producers (CI, a type checker, a human reviewer), each
naming what it does *and does not* cover, and a root claim with three typed
verification attempts bound to the artifact's digest.

This is the example to read first if you suspect the gate only ever says no.

It still returns one **advisory** — no verification attempt records its lineage,
so reproduction has to be assumed rather than derived. PROMOTE does not mean
there is nothing to say.

## 03 — An eval suite, where failures become refuted claims

`03-support-eval-promptfoo.json` · promptfoo output · **BLOCK**

Eight cases from a support agent's regression suite, six passing. The two
failures are the interesting kind: the agent invents a price-match policy that
was withdrawn, and claims a water-*resistant* product is waterproof to 50m.

A 75% pass rate is a number. What release-gate returns instead is
`2 claim(s) are refuted by the evidence in this case` — and it blocks, because a
refuted claim is not a low score, it is a claim the evidence contradicts.

## 04 — A destructive production migration

`04-production-db-change.jsonl` · assurance envelope · **HOLD**

An agent proposes dropping four columns from a 41M-row billing table. The
consequence record says what that means: `IRREVERSIBLE`, `DESTROYED`,
`PRODUCTION`, `UNBOUNDED`, `REGULATED`. The only evidence is a 2,000-row
development fixture.

The important part is *why* it holds. The engine does not decide that a
production drop is dangerous — it holds because the operator's own runbook,
recorded as an `expectation`, requires three rehearsal environments and one
arrived. The bar comes from the organisation, not from the tool's opinion.

A `failed_branch` record carries the attempt that would have answered the
question — querying the read-replica for 30 days of column reads — and why it was
abandoned. A failed branch is evidence, not noise.

## 05 — A research swarm, and why a version bump matters

`05-research-swarm.jsonl` · assurance envelope · **BLOCK**

Thirteen contributors support one claim. Nine of them restate the same upstream
preprint; three are genuinely independent; one contradicts the claim outright,
and an adversarial reviewer disputes the axiom the machine check rests on.

```
WHERE THE SUPPORT COMES FROM
  Supporting contributors: 13
  Independent evidence roots: 4
  Largest shared lineage: 10 contributors (76.9%)
  Result: HIGH lineage concentration
  Reported, not penalised: relying on one authoritative source is
  often exactly right. Only a methodology can make this a verdict.
```

Run it under both versions of the same methodology and exactly one row differs:

```bash
release-gate assure 05-research-swarm.jsonl --methodology research-mathematics@1.0.0
release-gate assure 05-research-swarm.jsonl --methodology research-mathematics@1.1.0
```

`@1.1.0` adds `independence.evidence.ancestry`, which is what turns that 76.9%
into something the verdict accounts for. Both block — thirteen supporters do not
close an open counterexample — but only one of them can see the concentration.

**Scale is not confidence.** That is the whole point of this file.

---

## Two things worth knowing before you write your own

Both came out of writing these examples.

**A consequence value outside its dimension's vocabulary is refused, and the
report says so.** It is not coerced into something close — release-gate does not
guess at stakes. What you get instead, right under the `UNKNOWN:` list it
explains:

```
UNKNOWN: EXTERNALITY, SCOPE, USER_IMPACT, DATA_IMPACT, ...
REFUSED in consequence record 1 of the envelope: 'ALL_USERS' is not admissible
  SCOPE, so that dimension stays UNKNOWN; known: SINGLE_SUBJECT, BOUNDED_SET,
  BROAD, UNKNOWN
```

Writing these examples is how that line came to exist. Until 0.11.1 the refusal
was silent: the dimension went to `UNKNOWN` with no note, no `skipped` tally and
no trace in `--json`, so an operator who declared the stakes and misspelled one
value was told the stakes were never stated. Worth knowing the vocabulary anyway
— a refusal you have to read is still a round trip:

```jsonl
{"record_type":"consequence","SCOPE":"ALL_USERS"}     # not a SCOPE value -> silently UNKNOWN
{"record_type":"consequence","SCOPE":"BROAD"}         # correct
```

The vocabularies:

| dimension | values |
|---|---|
| `REVERSIBILITY` | `REVERSIBLE` · `REVERSIBLE_WITH_EFFORT` · `IRREVERSIBLE` |
| `EXTERNALITY` | `CONTAINED` · `CROSSES_SYSTEM_BOUNDARY` · `CROSSES_ORGANISATION_BOUNDARY` |
| `SCOPE` | `SINGLE_SUBJECT` · `BOUNDED_SET` · `BROAD` |
| `USER_IMPACT` | `NONE` · `INDIRECT` · `DIRECT` |
| `FINANCIAL_IMPACT` | `NONE` · `BOUNDED` · `UNBOUNDED` |
| `DATA_IMPACT` | `NONE` · `READ` · `MODIFIED` · `DESTROYED` |
| `SECURITY_IMPACT` | `NONE` · `AFFECTS_CONTROLS` · `GRANTS_ACCESS` |
| `PRODUCTION_IMPACT` | `NONE` · `NON_PRODUCTION` · `PRODUCTION` |
| `RESEARCH_IMPACT` | `NONE` · `INTERNAL_RESULT` · `PUBLISHED_RESULT` |
| `LEGAL_IMPACT` | `NONE` · `POSSIBLE` · `REGULATED` |
| `UNKNOWN_IMPACT` | `NOT_FLAGGED` · `FLAGGED` |

**A rejected record tells you exactly what was wrong — in `--json`, not in the
report.** The text output says only `1 record(s) in the input could not be
mapped`. The reason is in `ingest.notes`:

```bash
release-gate assure your-run.jsonl --json | python -c \
  "import json,sys; print(*json.load(sys.stdin)['ingest']['notes'], sep='\n')"
```
```
a adversarial record was rejected: 'DISPUTED' is not a valid AdversarialOutcome
```

That is the first place to look when a record does not map. Two enum sets bit
these examples: `expectation.source.kind` (`METHODOLOGY`,
`ORCHESTRATION_MANIFEST`, `PRODUCER_MANIFEST`, `AGENT_ROSTER`,
`VERIFIER_INVENTORY`, `EXPERIMENT_MATRIX`, `CI_PLAN`, `SEQUENCE_DECLARATION`,
`OTHER`) and `adversarial.outcome` (`CANDIDATE_REFUTED`, `ARGUMENT_DEFECT`,
`WEAKNESS_FOUND`, `NO_FINDING`, `INCONCLUSIVE`, `NOT_RUN`).

Consequence declarations report through the same channel, and additionally
print in the stakes block as `REFUSED` (above), because that is the section
whose `UNKNOWN:` list they explain.

---

## Other ways to read the same case

```bash
release-gate assure 05-research-swarm.jsonl --methodology research-mathematics@1.1.0 --review
release-gate assure 02-release-promoted.jsonl --methodology general-autonomous-action@1.0.0 --json
release-gate assure --list-methodologies
```

`--review` is the one-screen version. `--json` is the whole outcome — case,
findings, coverage ledger and the required-evidence protocol — for a pipeline.
