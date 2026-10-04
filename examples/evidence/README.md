# External evidence examples

One file per generic evidence contract, and one envelope that composes them.
Release-gate ran none of these tools. It reads what each one says, keeps it in
that tool's words, and decides from it under a declared policy. Every report
says so, under EVIDENCE ORIGIN.

| File | Contract | What it shows |
|---|---|---|
| `eval.json` | `release-gate.eval/1` | three eval cases about one claim. One failure contradicts the claim, and the two passes do not average it away. The harness's own `summary` stays "2 of 3 declared" |
| `red-team.json` | `release-gate.red-team/1` | five attacks on one claim. `atk-017` succeeded and is a counterexample. Three were blocked; those support the claim and never establish it. One timed out and bears on nothing |
| `sast.json` | `release-gate.sast/1` | two findings at the tool's own severity, one of them suppressed, with the declared scan scope |
| `review.json` | `release-gate.review/1` | an approval of the overdraft claim and a changes-requested review of the transfer claim, both bound to a commit, plus an approval of a previous release that names no claim and is recorded as nothing more than that |
| `formal.json` | `release-gate.formal/1` | a model checker's result for the overdraft claim: the spec it checked, its assumptions, the commit and the proof artifact |
| `release.jsonl` | an envelope with `producer_export` rows | the release: a candidate, three claims and all five exports. It blocks on `atk-017`, and the proof establishes the overdraft claim |

```
release-gate assure examples/evidence/release.jsonl
release-gate assure examples/evidence/red-team.json --json
```

Each file is also read on its own. An export inside an envelope means exactly
what the same file means on disk. To add who did the work, append `authorship`
rows (`release-gate authorship --role implementation --from-ci …`).
Release-gate then reports whether anyone but the author checked each claim.
That is about independence, not about who or what wrote the code.
