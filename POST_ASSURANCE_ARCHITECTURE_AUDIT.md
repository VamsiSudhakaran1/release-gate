# Post-assurance architecture audit

A hostile review of release-gate's admission controller, after the assurance
architecture was built. It looks for ways the evidence a release is admitted on
could be laundered, outvoted, mis-attributed, replayed or made to disappear.
Twenty-five attack areas were set out in advance. Each area was attacked against
the running code. Every defect found was reproduced first as a failing test,
then fixed, then re-run with the full suite.

This audit is not a certificate. It found eleven defects in an architecture that
had already been through several rounds of hostile testing. That alone is reason
to expect that others remain. Nothing below says the architecture is secure in
general. It says which attacks were tried, what each came to, and what is still
open.

The regression suite for everything here is
[`tests/test_post_assurance_audit.py`](tests/test_post_assurance_audit.py).

---

## 1. Architecture reviewed

The admission path, end to end, as `release-gate assure` runs it:

```text
 inputs ──▶ strict load ──▶ detect ──▶ producer contract ──▶ normalisation
 (release.jsonl,            (envelope,   (one adapter per     (evidence, claims, attempts,
  --evidence files)          export,      format; words read   counterexamples, adversarial
                             verifier)    through a table)     findings, expectations, failed
                                                               branches, unread values)
        ──▶ case (subject digest, candidate state, policy) ──▶ analysis
            (state binding, correlation, contradictions, counterexample standing,
             claim coverage, claim resolution, semantic readings)
        ──▶ methodology assessment ──▶ admission evaluation (conditions by dimension;
            the worst condition decides) ──▶ verdict ──▶ Admission Report
        ──▶ approvals (two-step BoundApproval) · overrides (bound to the case digest)
```

The surfaces that reach a decision were reviewed too:

- the CLI (`assure`, and the scanner-side `audit`, `pr`, `score` and `run`);
- the GitHub Action and the five CI templates in `ci-templates/admission/`;
- the hosted API (`POST /api/assure`);
- the MCP server, which is scanner-only and read-only.

Modules read for the review:

- `ingest.py`, `producer_contract.py`, `reference_adapters.py`, `producer_adapters.py`;
- `candidate.py`, `approval.py`, `analysis.py`, `admission.py`, `admission_report.py`;
- `resolution.py`, `correlation.py`, `semantic_verifier.py`, `semantic_panel.py`;
- `hostile.py`, `adapters/common.py`, `release_gate_api/_app.py`, `action.yml`.

---

## 2. Attack scenarios and what each came to

Each area was attacked through the public entry points (`assure`, the
envelope, the evidence contracts, the API, the Action). The results:

- **Defended**: the attack did not change the decision in its favour, and a test now pins that.
- **Dn**: a defect, now fixed (section 3).
- **Limitation**: not defended by release-gate. It is stated in sections 5–7.

| # | Area | Attack | Result |
|---|---|---|---|
| 1 | Evidence laundering | An envelope declares its own evidence `VERIFIED`. | Defended: it stays DECLARED. |
| | | A failed check or counterexample is written so the ingest drops it. | **D1, D6** |
| | | An agent declares a PASSED formal proof of its own work. | Limitation: imported evidence is its producer's word (section 6). |
| 2 | Stale evidence accepted as current | Evidence names an older commit or policy. | Defended: support is withheld (RG-DRIFT-006). |
| | | Evidence names only the repository. | **D2** |
| 3 | Duplicates treated as independent | Five identical attempts. | Defended: deduplicated to one. |
| | | Duplicate evidence. | Defended: one correlation group. |
| | | Fifty restamped replays. | Defended: one record. |
| 4 | Semantic verifier overriding deterministic evidence | Model readings of "supported" against a CONTRADICTED claim. | Defended: BLOCK is unchanged. A reading closes no gap. |
| 5 | UNKNOWN becoming PASS | Outcome words outside the vocabulary (`error`, `success`, `true`), and a promptfoo row with no verdict. | **D1, D4, D11** |
| 6 | Unsupported claims from absent evidence | Claims with no evidence at all. | Defended: NOT_ASSESSED, HOLD. |
| 7 | Score averaging hiding a critical failure | One critical failure among 999 passing eval cases. | Defended: BLOCK. Readings are never averaged (P22). |
| 8 | Counterexamples washed out by passes | One counterexample among 500 passes. | Defended: BLOCK, CR-01. |
| | | A counterexample whose method or answer is malformed. | **D1** |
| 9 | Approval applying to the wrong artifact | An approval of another commit, another model, or no state. | Defended: it does not count. |
| | | An approval naming only the repository. | **D2** |
| 10 | Policy changed after approval | The methodology, resolution policy or ruleset is swapped after a person approved. | **D3**. Overrides were already bound to the exact case digest. |
| 11 | Evaluator result mapped to the wrong claim | A target claim id with a typo. | Defended: an orphan counterexample still blocks (RG-CEX-002). |
| | | The right id with another claim's wording. | **D10** |
| 12 | Model prompt injection | Instructions inside evidence; smuggled verdicts; tool calls. | Defended by the P21 hardening (`tests/test_semantic_injection.py`). Detection is pattern-based (section 5). |
| 13 | Malformed adapter data | Unlisted words; results that are not a list; non-boolean `success`; NaN; top-level scalars; nesting 64+ deep. | **D1, D4, D5, D11**. Otherwise defended: no crash, no PROMOTE. |
| 14 | Spoofed producer identity | A record claims release-gate's own producer, kind and `in-process` basis. | Defended: kind refused, basis `unauthenticated`. |
| | | Two producer ids run by one actor. | Limitation (section 6). |
| 15 | Manipulated timestamps | Every time moved ±100 years, or set to 1970 or 9999. | Defended: same decision, rules and claim statuses. Currency is read from stated state, never from a clock. |
| 16 | Hash and canonicalisation | Duplicate JSON keys, NaN and Infinity in input. | **D5**. |
| | | NaN in canonical form. | Already refused. |
| | | Commit case and abbreviations. | Defended: compared case-insensitively. A prefix under 7 characters reads STALE, which fails closed. |
| 17 | Race between evidence and deployment | The artifact changes between decision and deploy. | Limitation. The subject re-check detects mutation inside a case (RG-DRIFT-001). After the decision, it is the pipeline's job (section 5). |
| 18 | Human approval replay | A BoundApproval presented to another case, a revised case, or a later commit. | Defended: FOREIGN, INVALIDATED, does not bind. The repository-only form was **D2**. |
| 19 | Contradictory evidence silently collapsed | Five supports and one contradiction. | Defended: CONTRADICTED. Reading disagreement goes to a person (RG-SEM-007). |
| | | The collapse of rows by repeated id. | **D6** |
| 20 | Failed branches disappearing from reports | A declared failed branch. | **D8** |
| 21 | Model or provider outage promoting | Every semantic question unanswered (provider down). | Defended: decision and claim statuses unchanged. |
| | | A corrupt evidence file. | Defended: refused, exit 1, Action ERROR. |
| 22 | Old CLI paths bypassing admission | A deploy gated on the Action's `decision` with `command: audit`. | **D9** |
| 23 | CI templates reading HOLD wrongly | HOLD under normal and strict; a report disagreeing with the exit code; a report left from an earlier run. | Defended (`tests/test_ci_admission.py`): HOLD is never BLOCK or PROMOTE. |
| 24 | Hosted API disagreeing with local CLI | The same bytes through the API and the CLI. | Decisions agreed across all 117 corpus runs. The case digest did not: **D7**. |
| 25 | Nondeterministic ordering | Shuffled rows, shuffled evidence files, `PYTHONHASHSEED` 0, 1, 12345 and random. | Defended: the same decision, rules and claim statuses. Across hash seeds the digest is identical too. |

---

## 3. Defects found

Severity is what the defect could do to a decision.

| Rating | What the defect could do |
|---|---|
| **Critical** | It could PROMOTE a release that should block or hold. |
| **High** | It could count evidence or an approval that should not count. |
| **Medium** | The record misstated or omitted something. The decision was not affected. |

| | Severity | Defect | Reproduction |
|---|---|---|---|
| D1 | High | A word outside the vocabulary removed a whole record. This covered an attempt outcome (`error`, `PASS`, `true`), a counterexample method (`fuzzing`) and an adversarial role (`red team`). An answer its own checks refused did the same: RESOLVED with no evidence, ACCEPTED_RISK with nobody accepting. | C-2 has a FAILED check plus an `error` check. The claim vanished, and BLOCK became an unmapped-record HOLD that a reviewer could approve without seeing a failure. |
| D2 | High | A state naming only identity components (repository, environment) bound PARTIAL: "everything it names matches". | An approval stating only `{"repository": …}` satisfied "approved this exact release" for every future commit. Repository-only support escaped RG-DRIFT-008. |
| D3 | High | A BoundApproval recorded no policy. | Re-decided under another methodology, resolution policy or ruleset, it stayed VALID: "the change is in release-gate's own output". |
| D4 | **Critical** | Reference contracts kept unlisted outcome words as unknown, and nothing read the unknown. | Five attacks blocked and one `"outcome": "success"`: PROMOTE. A results field that was not a list read as an empty run. |
| D5 | **Critical** | Duplicate JSON keys resolved to the last value. NaN was accepted at input. | `{"outcome": "FAILED", "outcome": "PASSED"}`: PROMOTE. A failing attempt with a NaN score was refused at canonicalisation, and BLOCK became HOLD. |
| D6 | **Critical** | A row reusing an id was absorbed whole, whatever it said. | A COUNTEREXAMPLE record reusing a passing test's `evidence_id`: PROMOTE instead of BLOCK. A second claim row with a FAILED check: PROMOTE. |
| D7 | Medium | The API read submissions from a random temporary path. The path is part of the case. | Two identical API calls returned two digests. Neither matched any CLI run of the same bytes. |
| D8 | Medium | The Admission Report omitted the failed-branch ledger. | A declared failed branch appeared in neither the JSON nor the text report. |
| D9 | Medium | The Action exposes every command's verdict as `decision`. | A deploy gated on `decision == 'PROMOTE'` with `command: audit` admitted a release on a code scan alone, and nothing said so. |
| D10 | High | A result joins a claim by id. Its own wording of the claim was not compared. | A review of "Refund answers follow the published refund policy" filed under `cl_x` counted as `cl_x`'s support: PROMOTE. |
| D11 | High | The admission path reused the scanner-side promptfoo reader. That reader decides a row with no boolean verdict by `score > 0`. | `{"success": "false", "score": 0.9}` read as a pass: an evaluator's score thresholded into a verdict. |

---

## 4. Fixes

Each fix has its failing test in `tests/test_post_assurance_audit.py`. Each was
verified by a tamper probe that removes the guard and confirms the suite catches
it (section 8).

- **D1**: a value outside the vocabulary is kept at its most conservative reading, beside the producer's own word.
  - Readings: an attempt UNKNOWN; a counterexample result UNKNOWN; a method OTHER; an adversarial outcome INCONCLUSIVE.
  - A refused answer to a found counterexample or a refuting attack leaves it OPEN and unanswered.
  - Each such value is a line in `Normalisation.unread_values`, and holds the case through RG-COV-002, as a rejected record already did.
  - `ingest._read_enum`, `_counterexample_from`, `_adversarial_from`; `analysis._analyse_coverage`.
- **D2**: a binding whose only matches are identity components reads UNKNOWN when the candidate states a revision.
  - Another repository still reads INCOMPATIBLE.
  - A candidate with no revision binds its subject as before.
  - `candidate._names_only_the_subject`.
- **D3**: approvals record `bound_policy`: the methodology digest, the resolution-policy digest and the ruleset version.
  - A change to any of them requires review (APPROVAL_REVIEW_REQUIRED, `moved_policy`).
  - The offer and acknowledgement carry it too. A submission read under another policy conflicts, and sends the person back.
  - An approval recorded before this, against a moved case digest, cannot show the policy did not move. It reads REVIEW_REQUIRED, not VALID.
  - `approval.policy_of`.
- **D4**: the producer contract records every claim-bearing result whose word its contract does not define (`NativeResult.outcome_unread`), or that the shared table cannot read.
  - Such a result is never a pass, and it holds the case.
  - The red-team, behaviour and review contracts flag words outside their tables.
  - A results field present and not a list is counted as unmapped.
- **D5**: the admission path loads JSON strictly.
  - A key named twice in one object is refused, and so are NaN and Infinity (exit 1; the Action reports ERROR).
  - The scanner-side readers keep their lenient parse. `adapters.common._loads(strict=)`.
- **D6**: rows under one id that differ only in their times are still a replay, and collapse (`ingest._said`).
  - Rows that say something else are kept.
  - A second evidence record is kept beside the first. References to the id still resolve to the first, and the clash holds.
  - A repeated claim row's checks and evidence are joined to the first. A different proposition under the same id holds.
- **D7**: the API reads each submission as `release-gate assure submission.jsonl` reads it, from beside the file, and returns that name as `case.source`.
  - The same bytes now give the same case on every call, and the CLI reproduces it.
  - The temporary directory is entered only inside a synchronous block (no `await`, no threads), so no other request observes it.
- **D8**: the Admission Report carries `failed_branches`: outcome, claims, producer, where it failed, detail. In text it is a FAILED BRANCHES section, stated as "none" when empty.
- **D9**: the Action gains a `decided-by` output: `admission` for `assure`, or the command's name.
  - The scanner's printed verdict now says it is a code-level scan, not an admission decision.
  - Exit codes and `decision` are unchanged.
- **D10**: a result that words its claim as some other claim is still joined to it, so a failure is not lost. The mismatch holds the case.
  - The comparison ignores case, spacing and a closing stop.
  - A result naming the claim by id alone is joined as before.
- **D11**: the admission promptfoo adapter reads only what promptfoo stated: `success`, then the grading's `pass`, then an error.
  - A row with none of those is unread: never a pass, and it holds.
  - A word the contract does not define never reads as a pass, even where the shared table would (`"true"`).
  - `release-gate score` keeps its reading.

**Migrations.** Every behaviour change makes a decision stricter. None makes one more lenient.

- The 117-run corpus (13 inputs × every built-in methodology, and none) is byte-identical in decision, fired rules and reasons before and after.
- One existing test changed: `test_assurance_chaos.py::test_the_first_copy_wins_not_the_last`. A second, different record under one id is now kept (D6). The first still wins references.
- New fields are serialised only when they say something: `unread_values`, `moved_policy`, and `bound_policy` on approvals. So every existing case and approval digest is unchanged.

---

## 5. Remaining limitations

- **The decision is as good as the integrity of its inputs.** release-gate reads what it is handed. Anyone who can write the release file or the evidence directory can write evidence. The defences are:
  - restrict who writes the evidence;
  - bind the candidate (`--candidate`);
  - keep the signed evidence pack;
  - prefer evidence the pipeline produced over evidence a submitter attached.
- **Between the decision and the deploy.**
  - release-gate decides; it does not deploy.
  - The Admission Report names the candidate and its state hash. Nothing in release-gate checks that the deployed artifact is that candidate.
  - The GitHub Actions template's candidate binding is optional and commented out, because without it evidence that names no state still counts.
  - Pipelines should deploy the exact admitted SHA and compare it to the report's candidate.
- **Prompt-injection detection is pattern-based.**
  - A reading cannot decide, close a gap or override a check, so an injection that evades the patterns still cannot promote.
  - It can still produce a misleading reading, which RG-SEM-001 and RG-SEM-007 route to a person.
- **Claim mapping trusts ids.**
  - D10 compares a result's wording only when the producer states one.
  - A producer that files a result under the wrong id and states no wording is joined as filed.
  - Lookalike ids (Unicode confusables) are not normalised. Such an id creates a separate claim. The critical claim lacks that support (which fails closed), and a counterexample against a lookalike still blocks (RG-CEX-002).
- **The case digest is bound to the input's path.**
  - The CLI reproduces a case for the same bytes under the same path.
  - The API returns the name to use (D7).
- **Legacy scanner paths keep their verdicts.**
  - `audit`, `pr` and `score` still PROMOTE/HOLD/BLOCK over what they examine.
  - The scanner-side promptfoo reader still reads `score > 0` as a pass for `release-gate score`.
  - They are labelled (D9) but not removed, for backward compatibility.
- **The hosted API is a demonstration.**
  - It is rate-limited, takes no `--evidence`, `--candidate` or resolution policy, and its working-directory switch depends on the app staying single-threaded.
  - The code comment says so.

## 6. Known trust assumptions

- **Producer identity is asserted, not authenticated.** Every submitted record reads `identity_basis: unauthenticated`. The hostile harness records `fake_verifier_identity` and `verifier_name_squatting` as DECLARED: the case reports them; it does not prevent them.
  - Independence is computed from declared provenance: producer, model family, lineage, session, reviewer and the rest.
  - Two producer ids operated by one actor read as two producers unless their provenance says otherwise.
- **Imported evidence is its producer's word.**
  - An agent that declares a PASSED proof of its own work produces declared evidence.
  - Whether the author of the work may also attest to it is the methodology's call, through authorship independence and admission levels. Under `general-agent-action@1.0.0` such a case can promote.
- **Stated times are the producer's.** Review expiry is checked against the evaluation time the document states, because the decision must reproduce without a clock. A producer can backdate.
- **Cross-tenant evidence mixing is NOT_DEFENDED** (hostile harness). A deployment serving several tenants must keep their evidence apart before it reaches the engine.
- **The semantic verifier's provider** is whoever the operator configures. Its readings are recorded as that provider's, and never decide.

## 7. NOT_ASSESSED areas

What this audit did not examine, and so says nothing about:

- the scanner's own rule accuracy beyond its benchmark (below), and agent behaviour at runtime;
- network-facing deployment of the hosted API beyond its handler:
  - authentication, rate-limit bypass, the database layer;
  - the frontend;
  - the serverless platform;
- supply-chain integrity of release-gate's own dependencies and release artifacts;
- the VS Code extension and the MCP server beyond their read-only scanner role;
- side channels, timing, and resource exhaustion beyond the bounds the hostile harness exercises (DoS, oversized payloads, nesting depth);
- semantic providers' real-world accuracy: the benchmark's rows are reference providers, not models;
- the cryptographic evidence pack's signing keys and their custody;
- correctness of any producer's own results (eval harnesses, red teams, SAST tools, provers). release-gate reads them and never re-runs them.

## 8. Benchmark results

| Measurement | Result |
|---|---|
| Scanner accuracy: 93 labelled cases (43 vulnerable, 50 clean look-alikes), `benchmark/RESULTS.md` | precision 100.0%, recall 100.0%; 44 TP, 0 FP, 0 FN; 0 HIGH-tier integrity violations. This measures the static scanner only. |
| Assurance corpus: 16 constructed cases, `benchmark/ASSURANCE.md` | 16 of 16 pass. Case-level precision 100.0% (6 stopped with a defect built in, 0 clean cases stopped). Constructed cases, not a measure of release safety. |
| Semantic provider benchmark: 15 labelled questions, 14 categories, `benchmark/SEMANTIC.md` | Reference providers only. The oracle scores 1.00 and always-abstain 0.33 (both eligible). The confident confirmer is ineligible: 100% false confirms, mean −5.57. |
| Hostile harness: 20 threats, `release_gate/assurance/hostile.py` | All 20 at their recorded outcomes after these fixes: 7 REFUSED, 1 IDENTICAL, 11 DECLARED, 1 NOT_DEFENDED (`cross_tenant_evidence_mixing`). |
| Admission corpus: 13 inputs × every built-in methodology and none (117 runs) | Byte-identical before and after this audit in decision, fired rules and reasons. The case verdict, admission engine, Admission Report and exit code agree in every run. |
| Audit regression suite: `tests/test_post_assurance_audit.py` | 107 tests. Each defect's tests failed before its fix. |
| Tamper probes: each P24 guard removed in turn | 24 probes, each caught by the regression suite. |
| Full suite, with this audit's tests and the acceptance test | 6137 passed, 1 skipped, in fixed order and in random order. |

## 9. Remaining risks

The risks below are the ones this audit would rank highest, in order:

1. **Input integrity outside release-gate.** The strongest attacks found here were authored inputs: a duplicate key, a reused id, a word outside a table. They are closed for the shapes tried. The general shape — someone who can write the evidence chooses what it says — is not. It is closed by who may write the evidence, not by the engine.
2. **Unknown-word coverage in contracts not yet reviewed.** D1, D4 and D11 were found by trying words outside each table. An organisation's own adapters, registered through `ProducerRegistry`, inherit the contract's unread check only when their words pass through the shared result table, or when they set `outcome_unread`.
3. **Deploy-time binding.** Until a pipeline checks that what it deploys is the admitted candidate, an admitted decision can be applied to something else (section 5).
4. **Self-attestation under permissive methodologies.** The built-in general methodology admits supported claims whose only checks came from the agent that did the work. Organisations with a stricter bar must declare it.
5. **This audit's own blind spots.** It was written by the same author as the engine, against areas chosen in advance. A review by someone else, choosing their own areas, is the next step this document cannot stand in for.
