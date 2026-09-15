# Spec — Universal Autonomous Assurance Architecture

> **Status: ARCHITECTURE ONLY. No production code changes.** This document is the
> design that must be agreed before a single line of `release_gate/assurance/` is
> written. It is a companion to `ROADMAP.md` (why/when) and `docs/ARCHITECTURE.md`
> (what exists today). Where the two disagree about the *shape* of the system,
> this document is the target and `docs/ARCHITECTURE.md` is the present tense.
>
> Scope of the change it describes: release-gate stops being *a pre-deploy gate
> that happens to ingest evidence* and becomes *an assurance engine that happens
> to have a pre-deploy mode*. Every capability listed in the master contract is
> preserved; none of them remains the architectural centre.

---

## 0. Convergence output

The master contract requires this block before any implementation. It is
reproduced here so the design can be reviewed against it later.

### 0.1 Interpretation of requirement

Today release-gate answers exactly one question — *may this **version of a
codebase** be admitted to deployment?* — and its data model is shaped like that
question: a `report` dict keyed on a repo path, with findings, safeguards, two
scores and a decision. Everything else (traces, evals, lockfile, behavioural
probes) is an *attachment* to that report.

The requirement is to invert the relationship. The unit of the system becomes a
**proposition a named human is about to authorise**, and the repo audit becomes
*one evidence producer among many* feeding it. Two modes of that unit are
first-class:

* **ADMISSION** — the subject is a *version of an autonomous system*. "May this
  agent version ship?" This is what exists today, re-expressed.
* **DECISION** — the subject is *a result or action an autonomous system already
  produced*. "Is there enough evidence for a human to authorise this exact
  output?" This does not exist today in any form.

Both modes must render the same verdict vocabulary (PROMOTE / HOLD / BLOCK), on
the same evidence substrate, with the same honesty rules about what was not
assessed. DECISION additionally emits a **HumanAttentionSet** and, on HOLD,
**RequiredEvidence** — the smallest set of things that would resolve the hold.

Three scales must work on one architecture: one agent/one migration; 20–100
cooperating agents; 10,000 workers and millions of model calls. The architecture
does not get three implementations — it gets one, with *progressive assurance*
(Invariant 14): structures that a small case never populates.

Explicit interpretation of a constraint that shapes everything below: release-gate
is **not** given domain truth. It cannot know whether a mathematical result is
correct or a treatment recommendation is sound. What it can know, deterministically,
is the *shape and integrity of the evidence offered in support of it*: where each
piece came from, whether it was independently produced, whether it still applies
to the current artifact, what it contradicts, and what is simply missing. That —
and only that — is what the engine rules on (Invariant 10).

### 0.2 Architecture impact

| Area | Impact |
|---|---|
| Core data model | New root `AssuranceCase` + `AssuranceSubject`. Today's `report` dict becomes a *projection* of an ADMISSION case, not the root. |
| Evidence | New `EvidenceRecord` atom with epistemic status and typed verification. Every existing producer emits these through an adapter; none of them is rewritten. |
| Decision path | New deterministic `assurance/policy.py`. For ADMISSION it *delegates to today's* `apply_decision_mode()` so verdicts are bit-identical; for DECISION it is new. |
| Graphs | New `EvidenceGraph` (mandatory), with optional `ExecutionGraph` / `ClaimGraph` / `ArtifactGraph` / `VerificationGraph` overlays. |
| Methodology | New `AssuranceMethodology` — sufficiency criteria per case type. `governance.yaml` becomes *one input to*, and one evidence source under, a methodology. It stops being the policy engine. |
| Human output | New `HumanAttentionSet` + `ApprovalPacket` + `BoundApproval`. Today's evidence pack becomes one rendering of a packet. |
| Persistence | New content-addressed evidence store (local dir; optional Postgres in the hosted API). Today's `runs` table keeps working unchanged. |
| CLI / Action / API / MCP | Purely additive commands and outputs. Zero changes to existing flags, JSON keys, SARIF, exit codes. |
| Dependencies | None added to the base install. The core assurance engine is stdlib + the existing three libraries. |

The one genuinely invasive change is conceptual, not mechanical: **static
analysis and governance config are demoted to evidence producers.** No module is
deleted to achieve that; `audit.py` keeps its public surface and gains a wrapper.

### 0.3 Existing release-gate components reused

Every one of these is *reused as-is behind an adapter*, not reimplemented:

| Existing component | Role in the new architecture |
|---|---|
| `agent_analysis.py`, `verify.py` (AST + taint) | Evidence producer → `EvidenceRecord(kind=CODE_FINDING, status=DERIVED, method=STATIC_ANALYSIS)`. The `confirmed`/`inferred` basis maps directly onto evidence strength. |
| `rules.py` (stable RG-* ids) | Reused verbatim, and *extended* with new namespaces for assurance findings. The `Rule` NamedTuple gains optional fields; no id changes, no reuse of retired ids. |
| `audit.py::build_report` | The ADMISSION case builder's single biggest input. Output shape frozen for compatibility. |
| `audit.py::compare_to_baseline`, `unify_verdict`, `changed_tests_ratio` | The PR/change gate becomes an ADMISSION case whose subject is a commit; these stay the decision logic for that case type. |
| `audit.py::compute_coverage` | The direct ancestor of the `CoverageMatrix`. Its vocabulary (`assessed` / `partial` / `not_assessed` / `not_supplied` / `n/a`) is generalised, not replaced. |
| `lockfile.py` (AIBOM, `compare_lock`) | Artifact identity + drift evidence. `collect_components()` already produces a path→sha256 list; that *is* an `ArtifactGraph` slice. |
| `trace_validator.py` | Execution evidence producer (with a status fix at the boundary — see §18). |
| `adapters/` (OTel, Langfuse, Arize/Phoenix, promptfoo) | The ingest front door for DECISION. Same parsers, second projection: `to_evidence()` alongside today's `convert()`. |
| `adapters/common.py::Coverage` | Already the right idea (`records_seen` / `mapped` / `skipped_by_reason`). Becomes a `CoverageMatrix` row per source. |
| `evals/runner.py` | Eval evidence producer (`TEST_SUITE`). |
| `agent_score.py`, `loop_verifier.py`, `loop_sim.py` | Behavioural evidence producers (`EXPERIMENT` / `SIMULATION`). Tier + canary structure is already evidence-shaped. |
| `evidence_pack.py` | Becomes one renderer of an `ApprovalPacket`. |
| `crypto/` (RSA-PSS + SHA256) | The signing primitive for `BoundApproval` and for signed evidence envelopes. |
| `frameworks.py` | Already speaks `PASS/FAIL/PARTIAL/NOT_ASSESSED`; becomes the compliance projection of a case. |
| `mcp_server.py` | Gains read-only case tools; keeps its allow-root sandboxing model. |
| `action.yml`, `release_gate_api/`, `cli.py` | Surfaces. Additive only. |

### 0.4 New abstractions needed

`AssuranceCase` · `AssuranceSubject` · `AssuranceMethodology` · `EvidenceRecord` ·
`EvidenceGraph` · `ExecutionGraph` · `ClaimGraph` · `ArtifactGraph` ·
`VerificationGraph` · `EpistemicStatus` · `VerificationMethod` ·
`ProvenanceChain` · `IndependenceGroup` · `Assumption` · `Contradiction` ·
`Counterexample` · `CoverageMatrix` · `CompletenessDeclaration` ·
`HumanAttentionSet` / `AttentionItem` · `RequiredEvidence` · `ApprovalPacket` ·
`BoundApproval` · `CaseDigest` (canonicalisation).

That is a lot of nouns. Three of them carry the design; the rest are supporting
records: **EvidenceRecord** (the atom, with epistemic status), **EvidenceGraph**
(what supports and what refutes what), **AssuranceMethodology** (what evidence
*should* have existed).

### 0.5 Components explicitly NOT being built

* **Not an agent orchestrator / scheduler / swarm runtime.** We never launch or
  coordinate the workers whose evidence we read.
* **Not an observability platform.** No long-term span storage product, no
  sampling agent, no SDK to instrument code. We ingest exports (as today).
* **Not a quality evaluator.** Answer goodness / faithfulness / relevance stays
  out of scope — the ROADMAP anti-goal is unchanged. We ingest eval verdicts and
  rule *on* them; we never re-grade them.
* **Not a theorem prover, simulator, experiment runner, or replication harness.**
  We consume their outputs as typed verification evidence.
* **Not a runtime guardrail / policy enforcement point.** We never sit in the
  request path.
* **Not an LLM judge.** No model output may satisfy a critical verification
  requirement unless the active methodology explicitly admits that type, and
  never silently (Invariant 4).
* **Not a truth oracle.** No component asserts a domain proposition is true.
* **Not a bigger `governance.yaml`.** The policy YAML is not extended to express
  claims, methodologies or evidence. New concepts get new, versioned files.
* **No new base dependencies.** Graph work is stdlib; no networkx, no database
  driver in the core.

### 0.6 Invariants affected

All fifteen. The mapping from each invariant to the *single component that
enforces it* is Appendix A; that table is the main review artefact of this
document. Four invariants required specific mechanisms that would not otherwise
exist:

* **Invariant 2/3** → the *status calculus* (§4.2): statuses are computed, never
  written by a producer, and a parent claim can never outrank its load-bearing
  dependencies.
* **Invariant 6** → *structural independence grouping* (§6.4): agreement is
  reported as `agreeing_records` **and** `independent_groups`, never as one number.
* **Invariant 9/13** → *expected-vs-observed coverage* (§8.2): percentages exist
  only where an expectation (a manifest, a sequence, a declaration) makes a
  denominator real; otherwise coverage is `UNKNOWN`.
* **Invariant 5** → *case binding* (§9): one canonical digest over everything the
  human saw, checked on every subsequent run.

### 0.7 Tests required

Summarised here; specified in §20.

1. Status-calculus property tests — no upgrade without an independent record; the
   minimum rule over `DEPENDS_ON`; refutation always wins.
2. Determinism — same inputs produce a byte-identical `case_digest`; shuffled and
   parallel ingest produce identical graphs (order-independent fold).
3. No-LLM-in-path — the whole authoritative path runs with network and model
   access disabled and produces identical verdicts.
4. Unknown-never-becomes-safe fuzzing — drop any field from any input; assert the
   verdict never improves.
5. Independence — 10,000 clones of one run collapse to `independent_groups == 1`.
6. Failed-branch retention — a refuted branch survives ingest and surfaces in
   attention when load-bearing.
7. Coverage honesty — no verdict without a coverage matrix; no percentage without
   a real denominator.
8. Binding staleness — flip one byte of the subject, approval reports stale.
9. Backward compatibility — golden tests pinning today's `audit`/`pr`/`score`
   JSON, SARIF, markdown and exit codes.
10. Scale — a synthetic 10^6-step execution stream ingests in bounded memory with
    honest materialisation counts.

### 0.8 Migration / backward compatibility

Full statement in §15. The contract in one line: **every command, flag, JSON key,
SARIF field, Action output and exit code that exists today behaves identically
after the change**, and the assurance layer is reached only through new
subcommands and new optional flags. The ADMISSION plane's verdict is not
recomputed by new logic — it *delegates* to `apply_decision_mode()`, and a golden
test asserts equality on a corpus of reports.

### 0.9 Failure modes

Detailed in §19. The four that actually threaten the design:

* **Claim extraction.** Without producer cooperation there is no reliable,
  deterministic way to know what an agent is *asserting*. Resolution: claims are
  **declared** through an emission protocol; LLM-suggested claims are a separate,
  non-authoritative lane marked `DECLARED` + `model-derived`.
* **Invisible correlation.** Structural independence cannot see shared
  pre-training or a shared upstream corpus. Resolution: the term "independent" is
  never emitted bare — it is always `independence_basis: structural` with an
  explicit not-assessed note.
* **Evidence omission.** A producer that hides its failures looks clean.
  Resolution: Invariant 13 machinery (§8.3) — sequence gaps, expected-source
  manifests, heartbeats — and, where completeness cannot be established, saying so
  instead of scoring it.
* **Adoption.** DECISION needs evidence that most teams do not emit yet.
  Resolution: degrade honestly from what they *do* emit (OTel spans, git, CI) and
  report the gap, rather than requiring instrumentation before the first useful
  answer.

### 0.10 Acceptance criteria

The architecture is accepted as coherent when all of the following hold. Each is
checkable against this document, not against taste.

1. Every capability in the master contract's preserve-list maps to a named
   component in §14, and none of them is reimplemented.
2. Every invariant maps to exactly one enforcing component in Appendix A, and that
   component can fail a test if the invariant is violated.
3. The smallest case (one engineer, one migration) runs with one command, no new
   config, no new services, and produces a packet a human can read in under a
   minute (§B.1).
4. The frontier case (10^4 workers, 10^6 calls) uses the same objects and
   degrades only through *relevance-directed materialisation with declared
   counts* — never through silent truncation (§12).
5. No LLM appears anywhere in the authoritative verdict path (§6, §13).
6. Existing CLI/API/Action/MCP contracts are unchanged (§15).
7. Every conflict between the master invariants and today's behaviour is named,
   not silently inherited (§18).
8. A verdict is structurally incapable of being emitted without a coverage matrix.
9. Static analysis and `governance.yaml` each appear in the architecture only as
   evidence producers, and neither is on the critical path of a DECISION case.

---

## 1. What changes, and what deliberately does not

**Does not change.** The precision-over-recall philosophy, the deterministic core,
the local-first CLI, stable rule ids, evidence-bearing findings, the
PROMOTE/HOLD/BLOCK vocabulary, exit codes `0/10/1`, "we verify, we do not vouch",
and the register: *"meets the declared policy, with these gaps not assessed."*

**Changes.** The *root object*. Today the root is a report about a repo. After
this change the root is a case about a proposition, and the repo report is one
input to it. Everything else in this document follows mechanically from that one
move.

A useful way to hold it: today release-gate answers *"is this code safe enough to
ship?"*. The new engine answers *"is the evidence behind this proposition strong
enough, complete enough and current enough for a named human to put their name on
it?"* — and "this code is safe enough to ship" is one proposition of that form.

---

## 2. The two planes

Both planes are the same object with a different `AssuranceSubject` type and a
different default methodology.

### Plane 1 — ADMISSION (exists today, re-expressed)

* **Question.** Should this version of an autonomous system be admitted to
  deployment?
* **Subject.** `agent_version` / `code_change` — a commit, a package digest, a
  model+prompt+tool configuration.
* **Typical evidence.** Static findings, safeguard verification, AIBOM lock, PR
  baseline delta, eval outputs, behavioural probe results, CI results.
* **Verdict logic.** Delegates to the existing two-axis scoring and
  `apply_decision_mode()`. **Bit-identical output is a hard requirement**, not an
  aspiration — see §15.3.
* **Default methodology.** `software-change-v1`.

### Plane 2 — DECISION (new)

* **Question.** Is there sufficient evidence for this exact machine-generated
  result or action to proceed to human authorisation?
* **Subject.** `artifact` / `action_batch` / `result` — a migration script, 8,214
  refunds, a proof, a research conclusion, an infrastructure plan, a message set.
* **Typical evidence.** Execution traces, declared claims, artifacts and their
  lineage, tool results, experiments, simulations, formal verification, replication
  runs, adversarial review, contradictions, counterexamples, failed branches,
  assumptions, human interventions, prior approvals.
* **Verdict logic.** New, deterministic, methodology-driven (§8).
* **Extra outputs.** `HumanAttentionSet` always; `RequiredEvidence` on HOLD.
* **Default methodology.** `general-agent-action-v1` (deliberately conservative:
  it can reach PROMOTE only for reversible, low-consequence subjects).

### What the planes share

One `AssuranceCase` class, one evidence model, one status calculus, one coverage
model, one attention engine, one binding mechanism, one verdict vocabulary. The
planes differ **only** in subject type, admissible producers, and the default
methodology. A future third plane (for example, continuous post-deployment
assurance) must be addable by defining a subject type and a methodology, with no
change to the engine. That is the test of whether the split is in the right place.

---

## 3. The root: AssuranceCase, AssuranceSubject, AssuranceMethodology

### 3.1 Why `AssuranceCase` is the right name

It is a term of art. In safety engineering an *assurance case* (or safety case) is
"a structured argument, supported by evidence, that a claim holds in a given
environment" — the Claims-Argument-Evidence and GSN traditions, and the register
ISO 26262 / DO-178C / UL 4600 reviewers already read. Adopting it buys four things
that an invented name would not:

1. It already means *argument plus evidence plus context*, not *score*.
2. It carries the notion of **defeaters** — the reasons a case fails — which is
   precisely what contradictions, counterexamples and unresolved assumptions are.
3. It is honest about its own limits: an assurance case is always argued
   *relative to a stated methodology and environment*, which is Invariant 10.
4. It survives contact with regulated industries, where this vocabulary is the
   native one.

Alternatives considered and rejected: `DecisionRecord` (records the decision, not
the argument), `ApprovalRequest` (workflow noun, implies a queue we are not
building), `Attestation` (implies we are vouching — the exact thing we refuse to
do), `Verdict` (the output, not the object).

### 3.2 `AssuranceCase`

> **Implemented** — `release_gate/assurance/case.py`, `records.py`. Field-level
> rules: [`assurance-data-model.md` §3.0](assurance-data-model.md).

```text
AssuranceCase
  case_id                 derived from the QUESTION (case type, objective,
                          requested decision, subject identity) — stable while
                          evidence accumulates and across versions
  case_version            revision counter; supersedes links to the previous one
  case_type               DEPLOYMENT | AUTONOMOUS_ACTION | RESEARCH_RESULT |
                          CODE_CHANGE | DATA_CHANGE | FINANCIAL_ACTION |
                          INFRASTRUCTURE_CHANGE | GENERAL_DECISION | CUSTOM
  objective               what the work was trying to achieve
  requested_decision      what the human is being asked to decide
  subject                 AssuranceSubject                       (mandatory)
  methodology             MethodologyRef | NONE (legal, and reported)
  state                   DRAFT | SEALED | APPROVED | SUPERSEDED | INVALIDATED
  created_at / updated_at excluded from every digest

  collections             twelve, each ABSENT until supplied (Invariant 14):
                            evidence · claims · artifacts · executions ·
                            verification · contradictions · assumptions ·
                            counterexamples · coverage · attention_items ·
                            required_evidence · approvals

  verdict                 CaseVerdict | None — renderable only on a SEALED case
                          that carries coverage (Invariant 9)

  subject_digest          the subject's state digest
  evidence_digest         fold over the eight evidentiary collections
  case_digest             everything an approval binds to, minus approvals
```

Three structural rules:

* **The case is mandatory; every collection is optional.** A migration case
  populates two of the twelve. `ABSENT` (nobody supplied it) and `PRESENT` but
  empty (we looked and found none) are different states with different digests —
  collapsing them is how "we did not look" becomes "there was nothing there".
* **Counted is not dropped.** Each collection folds *every* record it sees into a
  commitment, whether or not the record is materialised, and reports held against
  total. That is what lets one object serve a single migration and a case built
  from millions of calls without the digest quietly becoming a statement about a
  subset.
* **The case is immutable.** Every transition returns a new instance; new
  evidence means a revision, which opens as a DRAFT with no verdict and no
  inherited approvals.

**`case_type` selects no behaviour anywhere in the core.** What a class of
decision requires is a methodology question, and methodologies are data supplied
from outside. A case type that changed the engine's behaviour would be a domain
assumption compiled into the one object that has to stay neutral.

### 3.3 `AssuranceSubject`

> **Implemented** — `release_gate/assurance/subject.py`. Field-level rules and
> rationale: [`assurance-data-model.md` §3.1](assurance-data-model.md).

```text
AssuranceSubject
  subject_id              derived from identity; stable across annotation
  state_digest            identity + metadata — what a BoundApproval binds to
  subject_type            DEPLOYMENT | CODE_CHANGE | AUTONOMOUS_ACTION | RESEARCH_RESULT |
                          DATA_CHANGE | FINANCIAL_ACTION | INFRASTRUCTURE_CHANGE | DOCUMENT |
                          MODEL_CHANGE | CONFIG_CHANGE | GENERAL_RESULT | CUSTOM
  custom_type             required label when subject_type is CUSTOM
  version / version_basis explicit where possible; never invented
  digest                  sha256:<hex> or git:<hex>; None where content is unhashable
  digest_method           how it was produced (content, manifest, Merkle, git, attested, none)
  digest_status           OBSERVED (we computed it) | DECLARED (someone asserts it) | UNKNOWN
  digest_attested_by      required whenever the digest is DECLARED
  content_reference       kind + locator (file, directory, inline, item set, git, store, url)
  requested_action        what approval permits — the verb, not the noun
  created_at              excluded from both digests: identity is content, not clock
  supersedes              subject_id of the revision this replaces (part of identity)
  metadata
```

`digest` is the hinge of Invariant 5. For a file it is a sha256. For a batch it is
a Merkle root over the canonicalised item list, so "8,214 refunds" is one digest
and changing one recipient changes it. For a code change it reuses the existing
lockfile digest approach (`lockfile.py::_digest`), which already covers
model + prompts + governance + tool config.

**`requested_action` is mandatory and is prose.** Approval authorises an action,
not a blob. A subject without a stated action is rejected at construction — you
cannot bind a human's name to "this artifact" with no verb.

**Where content cannot be hashed**, the subject is still valid: `digest: None`,
`digest_status: UNKNOWN`, `mutation_detectable: false`. That is an honest subject
with a stated limitation, and it belongs on the packet next to the verdict — an
approval over content nobody can re-verify is a weaker thing than one over
content anybody can. What is never permitted is inventing a digest so the field
looks populated (Invariant 3).

### 3.4 `AssuranceMethodology`

> **Implemented** — `release_gate/assurance/methodology.py` (types, predicates,
> registry, assessment) and `methodologies.py` (the shipped ones, as data).
> Field-level rules: [`assurance-data-model.md` §3.2](assurance-data-model.md).

The concept that stops the engine from either fabricating domain standards or
being useless without configuration.

```text
AssuranceMethodology
  methodology_id / version        versioned; MAJOR.MINOR.PATCH so "latest" is orderable
  digest                          content digest — proves the definition has not moved
  domain
  case_types                      explicit; there is no implicit "applies to everything"
  requirements                    typed predicates that evaluate themselves
  criticality_rules               how consequence weight is assigned to records
  accepted_verification_types     what this decision class credits (Invariant 8)
  minimum_evidence_expectations   floors, compiled into ordinary requirements
  independence_requirements       where corroboration must be independent (Invariant 6)
  coverage_expectations           which dimensions must be stated, and their denominators
  override_rules                  what may be waived, by whom, on what terms
  non_overridable_conditions      what no waiver can satisfy
  provenance / derived_from       builtin | plugin | api | organization, and its parent
  metadata
```

**It is code-first, not a file format.** Requirements are a closed algebra of
typed predicates — `CollectionSupplied`, `MinimumRecords`, `SubjectIdentified`,
`VerificationPresent`, `IndependenceThreshold`, `NoUnresolved`,
`RecordFieldRequired`, `CoverageDimensionDeclared` — each of which evaluates
itself against a case and reports what it actually saw. Closed on purpose: a
requirement holding an arbitrary callable could not be serialised, sent to an API
client, or shown to the person whose release it held. `from_dict` exists for JSON
transport; nothing in the module imports a YAML parser and no file is required
anywhere.

**Honest under partial data.** A predicate that cannot see enough of the case
returns `NOT_ASSESSED`, and `NOT_ASSESSED` is explicitly not met. Where a
collection is partly materialised the reasoning is monotone: an at-least check
that passes on held records stands, because unheld records cannot un-satisfy it;
one that fails is `NOT_ASSESSED`, because a requirement must not fail on evidence
nobody looked at. A none-of-these check inverts — a violation found is
definitive, finding none means something only when everything was inspected.

**It cannot change underneath a case.** `id@version` identifies a methodology and
a sha256 over its content proves it. The registry refuses to register different
content under an existing version; a case records the digest inside
`case_digest`; and resolving a case's reference re-checks it. Resolving a bare id
is refused outright, because implicit "latest" resolution is how an existing case
silently acquires a different bar.

**Extension means at least as strict.** `extend()` inherits every requirement and
non-overridable condition, may add more, and may narrow `accepted_verification_types`
but never widen them. Without that rule, "extends the regulated methodology"
would be a claim anyone could make while removing the parts they disliked. An
organisation wanting a looser bar writes its own methodology and owns that fact.

**Absence is reportable, not fatal.** With no methodology, `assess()` returns
`METHODOLOGY_REQUIRED`: the structural analyses still have plenty to say, and
sufficiency is a question only a stated yardstick can answer. A methodology
built for another case type returns `CASE_TYPE_NOT_COVERED` rather than ruling
anyway.

Four ship as data — `general-agent-action-v1`, `software-change-v1`,
`production-database-change-v1`, and `research-mathematics-v1` as a worked domain
example. Nothing in the engine branches on a methodology id; deleting them all
would leave a working system where every case reports `METHODOLOGY_REQUIRED`.

## 4. The evidence model

### 4.1 `EvidenceRecord` — the atom

> **Implemented** — `release_gate/assurance/evidence.py`. Field-level rules:
> [`assurance-data-model.md` §3.3](assurance-data-model.md). The shipped record
> splits the single `epistemic_status` sketched below into four orthogonal axes
> (epistemic, provenance, trust, coverage) and the single `polarity` field into
> `supports_claims` / `contradicts_claims`, so one record can support one claim
> while refuting another.

Every producer in the system — the AST scanner, a safeguard check, an OTel span,
a promptfoo case, a theorem prover, a human reviewer, a replication run — emits
the same record type.

```text
EvidenceRecord
  evidence_id           content-derived id
  kind                  CODE_FINDING | SAFEGUARD | EVAL_RESULT | TRACE_EVENT | PROBE |
                        ATTESTATION | PROOF | EXPERIMENT | SIMULATION | REVIEW |
                        EXTERNAL_REFERENCE | DRIFT | COMPLETENESS | COUNTEREXAMPLE | OTHER
  epistemic_status      OBSERVED | DECLARED | DERIVED | VERIFIED | DISPUTED |
                        REFUTED | UNKNOWN | NOT_ASSESSED
  verification_method   VerificationMethod — required iff status is VERIFIED/REFUTED (Invariant 8)
  producer              Producer {producer_id, kind: agent|tool|human|release_gate|external,
                                  identity_basis, model?, version?, attested_by?}
  produced_at
  subject_ref           what this is evidence ABOUT (claim_id | artifact digest | execution node | subject)
  polarity              SUPPORTS | REFUTES | QUALIFIES | CONTEXT
  content               producer-specific payload (today's finding dict slots in unchanged)
  provenance            ProvenanceChain {input_digests[], transform, producer, signature?}
  integrity             SIGNED{alg,key_id} | DIGEST_ONLY | UNSIGNED
  applies_to_digest     the exact artifact digest this evidence was produced against
  coverage_note         what this record does NOT establish
  metadata
```

Two fields carry disproportionate weight:

* **`applies_to_digest`.** A proof about artifact v3 is not evidence about
  artifact v4. This single field makes "FORMALLY_VERIFIED ≠ APPLICABLE TO CURRENT
  ARTIFACT" (Invariant 2) mechanical rather than aspirational: the drift analyser
  compares it against the subject's current digest and invalidates on mismatch.
* **`polarity`.** Refuting evidence is a first-class citizen with the same
  structure as supporting evidence. This is what keeps failed branches in the
  graph (Invariant 7) instead of losing them to a filter.

### 4.2 Epistemic status and the status calculus

The definitions, stated so implementers cannot drift:

| Status | Means | Example |
|---|---|---|
| `OBSERVED` | release-gate directly recorded it from an instrument it reads itself. A statement about the *record*, not about the world. | This span exists in the ingested export; this file has digest X. |
| `DECLARED` | An actor asserted it. Zero independent support. | An agent says "I tested this"; `governance.yaml` declares a kill switch. |
| `DERIVED` | release-gate computed it deterministically from other records. | Total tokens; a taint path; a baseline delta. |
| `VERIFIED` | An admissible method, executed by a producer independent of the claim's author, returned a positive result **against the current subject digest**. | A theorem prover accepted proof P; an independent replication reproduced result R. |
| `DISPUTED` | Supporting and refuting evidence of comparable weight, unresolved. | Two verifiers disagree. |
| `REFUTED` | Refuting evidence stands unanswered. | A counterexample was found and never addressed. |
| `UNKNOWN` | In scope, we looked, nothing answers it. | A claim with no evidence attached. |
| `NOT_ASSESSED` | Out of scope for this run / no capability to look. | Physical reproducibility of a wet-lab step. |

`UNKNOWN` and `NOT_ASSESSED` are deliberately distinct: `UNKNOWN` is a hole *inside*
the argument, `NOT_ASSESSED` is a declared boundary *of* the argument. Collapsing
them is the most likely implementation error and gets its own test.

**The calculus.** Status is *computed*, never written by a producer.

1. A producer supplies `kind`, `content`, `provenance`, `polarity` and its own
   claims. The **ingest boundary** (§4.4) assigns `epistemic_status` by rule.
2. A claim's status is recomputed from its evidence on every engine run. No
   component may set it directly.
3. Precedence when a claim has mixed evidence:
   `REFUTED > DISPUTED > VERIFIED > DERIVED > OBSERVED > DECLARED > UNKNOWN`.
   Refutation is never outvoted by volume of support (Invariant 7).
4. **Two attributes per claim, not one.**
   `direct_status` from evidence about the claim itself;
   `inherited_ceiling` = the minimum status over all `DEPENDS_ON` children;
   `effective_status = min(direct_status, inherited_ceiling)`.
   A conclusion can never be stronger than the assumptions it rests on. A proof
   depending on an unproven lemma is not verified, no matter how good the proof.
   (Where evidence genuinely does not depend on a child — an end-to-end
   replication that does not use the lemma — the edge is `SUPPORTS`, not
   `DEPENDS_ON`. Edge type carries that semantics and is chosen by the producer,
   then audited by the independence analyser.)
5. **Upgrade requires a new record.** No transformation, aggregation, summary or
   rendering may raise a status. The only path from `DECLARED` to `VERIFIED` is an
   independent verification record arriving (Invariants 1, 2).
6. **Digest change invalidates.** Any `VERIFIED` whose `applies_to_digest` no
   longer matches the current subject falls to `DERIVED` at best, and raises a
   drift finding.

### 4.3 Verification typing

`VerificationMethod` is the closed enum from Invariant 8: `FORMAL_PROOF`,
`INDEPENDENT_REPLICATION`, `TEST_SUITE`, `SIMULATION`, `EXPERIMENT`,
`STATIC_ANALYSIS`, `RUNTIME_ASSERTION`, `HUMAN_REVIEW`, `CROSS_MODEL_REVIEW`,
`THEOREM_PROVER`, `EXTERNAL_REFERENCE`, `DOMAIN_CHECKER`, `PROPERTY_TEST`,
`COMPILER`, `TYPE_CHECKER`, `OTHER`.

A `VERIFIED` record without a method is invalid and is rejected at ingest, not
downgraded quietly. The methodology decides which methods count *for this decision
class*: `CROSS_MODEL_REVIEW` may satisfy a low-consequence content claim and is
inadmissible for a load-bearing lemma under `research-mathematics-v1`.

### 4.4 The ingest boundary — where status is assigned

One chokepoint, one place to audit, one place to test. Rules:

* Producer self-reports (`"verified": true`, `"passed": true`, `"status": "ok"`)
  are recorded as **content**, never as status. An agent's assertion becomes
  `DECLARED` evidence *that the agent asserted it* (Invariant 1, second clause).
* `release_gate`-produced analysis is `DERIVED` (it is our computation) or
  `OBSERVED` (we read the bytes ourselves).
* `VERIFIED` requires all of: an admissible method, a producer distinct from the
  claim's author, an `applies_to_digest` matching the subject, and a result
  artifact that can be re-examined.
* A check that ran against **no policy** yields `NOT_ASSESSED`, never `PASS`
  (see §18.3 — this is a real defect in today's behaviour).
* Anything an adapter cannot map is **counted and reported**, never dropped —
  today's `Coverage` object already does this and generalises directly.

---

## 5. The graphs

### 5.1 `EvidenceGraph` (mandatory)

> **Implemented** — `release_gate/assurance/evidence_graph.py`.

Nodes are evidence records, the sources that produced them, the action under
authorisation, and **opaque references** to claims. Edges are `SUPPORTS`,
`CONTRADICTS`, `DERIVED_FROM`, `VERIFIES`, `INVALIDATES`, `REPLICATES`,
`ATTESTS`, `SUPERSEDES`, `DEPENDS_ON`, plus the structural `PRODUCED_BY` that
forms the last hop of every trace.

**The boundary with the ClaimGraph is the point.** A claim appears here as an id
and a label and nothing else: the graph records that evidence supports `cl_887`
and says nothing about what `cl_887` means or what it logically rests on. Keeping
that sharp is what lets a reviewer ask "what is the evidentiary basis for this?"
without the answer turning into "what does this follow from?".

**The trace** is `explain_verdict()`: verdict → unresolved condition → claim or
action → evidence → source, arriving at a named producer with its identity basis
and trust status. The lower three levels come from the graph; the top two are
supplied by the caller's verdict and methodology assessment, because a graph of
evidence should not store what a policy engine decided. A condition that names no
claim descends to the action, which is the honest shape for a case with no
declared claims.

**Nothing is removed.** Superseded and invalidated evidence stays, marked
(Invariant 7), and a reference the case cannot resolve becomes an explicit
`MISSING` node with a dangling-reference anomaly rather than vanishing. Cycles in
the derivation relations are reported as anomalies rather than raised, because
evidence arrives from the wild and a graph that refuses to build tells a reviewer
nothing. Traversals are iterative, so a deep lineage chain cannot exhaust the
stack.

A minimal case is a star: the action in the middle, a handful of evidence records
around it. That is a legitimate, complete `EvidenceGraph`.

### 5.2 `ExecutionGraph` (optional)

> **Implemented** — `release_gate/assurance/execution_graph.py`.

Who did what, caused by what. Nodes: `AGENT`, `TASK`, `TOOL`, `ACTION`,
`MODEL_CALL`, `ARTIFACT`, `EXTERNAL_SYSTEM`, `HUMAN`, `VERIFIER`, plus
`UNOBSERVED` for anything referenced that never arrived. Edges: `SPAWNED`,
`DELEGATED`, `CALLED`, `PRODUCED`, `CONSUMED`, `MODIFIED`, `VERIFIED`,
`REJECTED`, `AUTHORIZED`, `DERIVED_FROM`.

**Nothing registers.** Agents, tools, verifiers and artifacts are inferred from
span and resource attributes through a documented classification table, and every
node records which rule fired so a reviewer can disagree with a call rather than
wonder about it. Anything unrecognised becomes a `TASK` — a wrong `AGENT` node
would distort every delegation and independence question asked afterwards.

The same OTLP export the trace adapter reads becomes a richer object here:
`adapters/otel.py` skips `invoke_agent` spans as structural because a trace policy
gates on behaviour, and this graph wants exactly that structure. Same input,
different projection, one parser — `adapters/common.py` is reused, not
reimplemented. The native `{trace_id, steps[]}` format is the linear degenerate
case and keeps working unchanged.

**The skeleton is kept, the leaves collapse.** Agents, tasks, tools, artifacts,
humans and verifiers are always materialised; model calls fold into per-agent
aggregates past a budget. Measured: 410,000 spans from 10,000 agents build in
~4s, keeping all 10,001 agents and 10,000 spawn edges while representing 400,000
model calls as counts.

**Completeness is never claimed.** The status vocabulary has no `COMPLETE` value.
A graph with nothing visibly missing reports `UNKNOWN`, because absence of
observed gaps is not evidence of completeness (Invariant 13). A source manifest or
a sequence range turns that into something checkable, and what arrived is compared
against it; even then the answer is `MATCHES_DECLARATION`, since the manifest is a
claim by the producing system.

**Arrival order cannot change the graph.** Parent references are resolved once at
build time, so an exporter that emits children before parents produces the same
digest. An unresolved reference becomes an `UNOBSERVED` node rather than a
silently reparented orphan, which would make the run look shallower than it was.

The graph is optional: a case with no execution telemetry gets `None`, not an
empty graph, because a case with no telemetry has not been shown to have done
nothing (Invariant 14).

### 5.3 `ClaimGraph` (optional)

> **Implemented** — `release_gate/assurance/claims.py`.

Nodes are `Claim`s; edges are `DEPENDS_ON`, `SUPPORTS`, `CONTRADICTS`,
`DERIVED_FROM`, `SUPERSEDES` and declared `EQUIVALENT_TO`. Statuses are
`UNKNOWN`, `UNVERIFIED`, `PARTIALLY_VERIFIED`, `VERIFIED`, `DISPUTED`, `REFUTED`
and `SUPERSEDED`.

**Status is computed on every build, never carried in the document.** A
producer-supplied status is ignored; the calculus reads the evidence actually
present. Each claim gets a `direct_status` from its own evidence and an
`inherited_ceiling` that is the weakest status among everything it `DEPENDS_ON`,
and the effective status is the lower of the two. A machine-checked proof resting
on an unproven lemma is `UNKNOWN`, capped by the lemma — expressed as a minimum
rather than a warning, so it cannot be lost. `SUPPORTS` corroborates without
capping; the producer chooses the edge and the choice is visible.

**Contradictions and failed attempts move status.** An unresolved contradiction
with no support refutes; alongside support it disputes, because only resolving a
contradiction resolves it. A verification attempt that ran and rejected is a
refutation; one that could not tell leaves the claim `PARTIALLY_VERIFIED`
alongside passes. Every attempt stays on the claim whatever its outcome
(Invariant 7).

**No model is in the authoritative path** (Invariant 4). Claims match by explicit
id — no fuzzy matching, no semantic clustering. Model-assisted extraction is
supported, must name its model, carries `DERIVED` provenance and is listed
separately; equivalence a model-derived claim asserts is recorded but **not
applied** unless explicitly asked for. A model may propose that two statements
mean the same thing; it may not make them the same thing in a computation that
gates a release.

**Load-bearing is computed, not declared.** `load_bearing()` is the dependency
closure of the root; `binding_constraints()` narrows that to the claims whose
status is what actually caps it — the difference between "these 3,114 lemmas
matter" and "these 118 are why the result is not verified". `counterfactual()`
says what settling one claim would change, which is the raw material of attention
ranking (Invariant 12). Measured: 3,115 claims resolve in ~0.1s.

The graph is optional: a transactional case gets `None`, because an empty claim
graph would read as "nothing is asserted" rather than "claims were not part of
this case" (Invariant 14).

### 5.4 `ArtifactGraph`

> **Implemented** — `release_gate/assurance/artifacts.py`.

Six questions, and the API is those six: what created this, what inputs
contributed, what modified it, what verified it, what decision depends on it, and
**has it changed since verification**.

**Two identities, and the difference between them is the design.** An artifact's
*content identity* is its digest, and that is what a verification attaches to.
Its *logical identity* is the handle successive versions share. Without the
split, a revised file is simply a different artifact and the sixth question has
no answer; with it, "verified at v1, now at v3" is a comparison rather than a
judgement. This is what makes FORMALLY_VERIFIED ≠ APPLICABLE TO THE CURRENT
ARTIFACT mechanical (Invariant 2) and how an approval decays instead of carrying
over (Invariant 5).

`verification_currency()` returns `VERIFIED_CURRENT`, `VERIFIED_STALE`,
`NEVER_VERIFIED` or `UNVERIFIABLE`, and only the first is truthy — code asking
"is this still fine?" must not read "I cannot tell" as yes. A forked history
(more than one version nothing revises) is reported as ambiguous rather than
resolved by picking a head, and counts as current only when every branch is
verified.

**Digests where possible, honesty where not.** Hashed here is `OBSERVED`; attested
by a store is `DECLARED` and must name the attestor; unhashable carries no digest
and reports `UNVERIFIABLE`. A missing digest is never an unchanged one
(Invariant 3).

It reads artifacts the `ExecutionGraph` already extracted rather than parsing
telemetry a second time, and rolls up to decisions through the `ClaimGraph`:
artifact → the evidence verifying it → the claims that evidence supports. Every
hop is a link someone recorded; nothing is inferred about meaning. The subject is
always in the graph, which is where provenance meets the decision.

### 5.5 `VerificationGraph` (optional)

> **Implemented.** `release_gate/assurance/verification.py`.

Answers "what was checked, by whom, with what method, against which digest, and
does it still apply?" — and answers it as a graph, because a boolean is how
assurance systems mislead people.

```text
Claim C-12
 ├── verified_by   FormalProof    V-1
 ├── tested_by     Simulation     V-8
 ├── challenged_by Counterexample CE-2
 └── reviewed_by   Agent 818
```

The relationship is computed from method and status together rather than supplied
alongside them, so the two can never disagree: a **failed** proof is
`CHALLENGED_BY`, not `VERIFIED_BY`, whatever produced it.

**An attempt binds to an exact target state.** `target_digest` is the content the
check actually ran against. When the target moves, the attempt does not move with
it — it becomes `SUPERSEDED` and stops counting. Applicability is therefore a
computation, not an assumption, and `UNDETERMINED` (no digest on one side) is
emphatically not `APPLIES`: "cannot tell whether this still holds" must never be
read as "it holds".

Six statuses, and two pairs of them are deliberately distinct:

* `INVALIDATED` ≠ `FAILED`. One means the check was withdrawn or found
  unreliable; the other that the claim did not hold. An invalidated pass is not a
  pass and is not counted as one.
* `INVALIDATED` ≠ superseded. Invalidation is a property of the *attempt*;
  supersession is a property of its *relationship to a target that moved*. An
  attempt can be perfectly sound and still not apply.
* `NOT_RUN` is a status, so a check somebody expected and never ran is a fact
  about the case rather than an absence of one.

**A challenge outranks a pass.** One applicable failure and one applicable pass
gives `FAILED`: a check that found a problem is not cancelled by a check that did
not look for it (Invariant 7).

**Corroboration is counted by lineage, not by attempt.** `independence_lineage`
records what a verification's independence rests on, and attempts sharing any
element are one group — two provers run by one organisation share that
organisation's assumptions. An attempt with no recorded lineage is counted apart
rather than credited, because provenance nobody stated is not independence.

`claims.VerificationAttempt` was a narrower version of this record, not a peer,
and has been generalised onto it; `AttemptOutcome` remains as an alias for
`VerificationStatus`, whose three old values could not express `NOT_RUN` or
`INVALIDATED`.

---

### 5.6 Formal verification adapters

> **Implemented.** `release_gate/assurance/verifiers.py`, plus the
> `VERIFIER_REPORT` input kind in `release_gate/assurance/ingest.py`.

`VerificationGraph` says how a machine check is *recorded*. This says how one
gets *in* — from Lean, Coq, Isabelle, an SMT solver, a model checker, a property
checker, a compiler or type checker, a test framework, or a domain validator.

**Release-Gate does not replace any of these tools and does not re-verify their
work.** It records what was verified, against which artifact version, with what
result, by which tool identity and version, with a verifier digest where one is
available, with the evidence, and with the coverage limits of the method. The
proof obligation stays with the prover; the epistemic bookkeeping is ours.

**No prover is hardcoded.** An adapter is a class with `detect(doc) -> int`
(0–100 confidence) and `convert(doc) -> VerifierReport`. `VerifierRegistry`
picks the highest scorer and records the runner-up, so an ambiguous document is
visibly ambiguous rather than silently assigned. Two adapters ship: a
tool-neutral envelope any tool can emit, and an SMT-LIB adapter that exists to
demonstrate the pattern — not to privilege solvers.

**`ToolFamily` selects a default `VerificationMethod` and nothing else.** It
never affects status, confidence, or weight. A proof assistant's `PASSED` and a
test framework's `PASSED` are the same status; what differs is the coverage
recorded beside it.

**One result-word table, shared by every adapter** (`VerifierAdapter.RESULT_WORDS`).
Adapters do not each re-decide what `unknown` means — that is exactly how one of
them eventually maps it to a pass. `unknown`, `timeout`, `gaveup`,
`resource_limit` and kin are `INCONCLUSIVE`: a tool that gave up has verified
nothing. `skipped`/`pending` are `NOT_RUN`, `retracted` is `INVALIDATED`, and
**any word the table does not contain is `UNKNOWN`, never `PASSED`** — an
unrecognised result is a gap in our vocabulary, not a success.

**SMT results are read through declared polarity, or not at all.** `unsat`
means "no model exists for the query as posed", which is a proof of the property
only when the query is the property's *negation*. `QueryPolarity` makes the
encoding say so:

| polarity | `unsat` | `sat` | `unknown` |
|---|---|---|---|
| `NEGATION_OF_PROPERTY` | `PASSED` | `FAILED` (model is a counterexample) | `INCONCLUSIVE` |
| `DIRECT` | `FAILED` — contradictory assertion: a broken or vacuous encoding, not a proof | `INCONCLUSIVE` — a model exists; the property is not thereby proved | `INCONCLUSIVE` |
| `UNDECLARED` | `UNKNOWN` | `UNKNOWN` | `INCONCLUSIVE` |

An undeclared polarity establishes nothing, because the same solver output
supports opposite conclusions depending on how the query was written. Guessing
the likely one is how a vacuous encoding becomes a green check.

**Coverage is a property of the method, stated once** (`_FAMILY_COVERAGE`), as a
pair: what the family's result covers, and what it explicitly does not. A proof
assistant does not establish "whether the formalisation says what its author
meant"; a model checker does not cover "states outside the explored bound"; a
test framework does not cover "behaviour the tests do not exercise". Adapters
inherit these rather than each inventing their own wording, and
`VerifierCoverage.complete` is true only when a report says so — the default is
incomplete, and `ToolFamily.OTHER` records "nothing is recorded about what this
result covers" rather than an empty list that could read as "nothing is
excluded".

**Pinning a tool establishes identity, not correctness.**
`ToolIdentity.trust_status` is `PROVISIONAL` when a digest is pinned and
`NOT_ESTABLISHED` when it is not. It is never `ESTABLISHED`: knowing exactly
which binary ran is not evidence that the binary is sound (Invariant 11 —
provenance is not trust). A verifier that verifies itself is the oldest failure
in this space.

**The report arrives as `DECLARED` evidence, not `VERIFIED`.** Ingest emits a
`FORMAL_PROOF` evidence record whose producer is the tool, whose epistemic status
is `DECLARED` — Release-Gate observed the tool's *claim*, not the proof — and
whose `coverage_note` carries the method's limits. The individual attempts land
in the `verification` collection, where the graph's existing rules apply
unchanged: an attempt binds to `target_digest`, moves to `SUPERSEDED` when the
target moves, and an applicable failure still outranks an applicable pass.

---

## 6. The assurance engine

Six analysers. Each is a **pure function** `(AssuranceCase) -> AnalysisResult`.
No I/O, no model calls, no clock reads, no randomness. Each emits findings with
stable rule ids in new namespaces so today's `RG-EXEC-*` etc. are untouched, and
each finding carries the evidence that produced it.

| Analyser | Namespace | Answers |
|---|---|---|
| Provenance & integrity | `RG-PROV-*` | Where did this come from, is the chain intact, is it self-attested, do the timestamps make sense? |
| Verification coverage | `RG-COV-*` | Which claims/artifacts have admissible verification, and which have none? |
| Contradiction | `RG-CONTRA-*` | What refutes what, and which of those is unresolved? |
| Independence | `RG-INDEP-*` | How many *genuinely distinct* sources support this, and what shared ancestry remains unassessed? |
| Change / drift | `RG-DRIFT-*` | What changed after it was verified or approved? |
| Completeness | `RG-COMPLETE-*` | What evidence should exist and does not appear? |

Verdict rules live in a seventh namespace, `RG-DECIDE-*`, and are policy rather
than analysis (§8).

### 6.1 Provenance & integrity (`RG-PROV-*`)

Broken or absent provenance chains; artifacts with no producer; evidence whose
`produced_at` precedes the artifact it claims to verify (timestamp inversion);
self-attestation (the producer of the claim is the producer of its only support);
unsigned evidence where the methodology requires signing; unverifiable
`external_reference`s. Per Invariant 11, this analyser reports *origin* only —
how much authority to give that origin is a methodology question and is reported
separately, never merged into one "trust score".

### 6.2 Verification coverage (`RG-COV-*`)

For each claim and artifact, weighted by consequence: is there at least one
admissible verification, of an admissible type, from an admissible producer,
against the current digest? Produces the per-claim rows of the coverage matrix and
the `NOT_ASSESSED` list. Refuses to compute a percentage where the denominator is
unknown (§8.2).

### 6.3 Contradiction (`RG-CONTRA-*`)

Unresolved `REFUTES` edges; claims both supported and refuted; a trace that
contradicts a declared safeguard; two artifacts claiming to be the same output
with different digests; counterexamples never addressed; abandoned branches whose
refutation was never answered (Invariant 7). Resolution is explicit: a
contradiction is closed only by a record that answers it (a later verification, a
human ruling), never by a newer successful branch existing.

### 6.3 Failed branches (`RG-BRANCH-*`)

> **Implemented.** `release_gate/assurance/failed_branches.py`, plus the
> `failed_branches` collection.

A case that records only its successes looks exactly like its best branch. Five
hundred approaches that failed and one that worked reads, in the final report,
identically to one approach that worked first time — and those are very different
situations for whoever is signing (Invariant 7).

So failures are retained, but **not every token**. A frontier run produces
millions of dead ends, and hoarding transcripts would make the case unreadable and
unstorable while adding nothing anyone can act on. What is kept is the *structure*
of each failure — outcome, locus, depth — plus a reference to wherever the full
record lives.

```text
8,054 branch(es) failed; 7 retained as examples (CAPPED)
  7,993 at lemma 48, deepest 51
  60 at simulation / X, deepest 59
  7,989 branch(es) counted but not retained; their failure points are above
```

**The aggregate is never sampled.** Retention drops *branches*; it never drops
*failure points*. If 7,992 proof attempts died at lemma 48, the ledger says so
whether it kept three of them or none — losing a branch costs a reviewer an
example, losing the count would cost them the finding.

**The policy is stated and bounded.** `MaterialisationBasis` is reused rather than
invented, so the collection says how it came to hold what it holds, and `observed`
versus `retained` is always reported. Retention is a bounded priority queue per
failure point: claim-bearing branches outrank others, deeper attempts outrank
shallower. An earlier design kept a branch whenever it beat the deepest so far,
which meant a run whose depth merely increased retained everything — the cap never
bound, and at frontier scale that is the transcript-hoarding this section exists
to prevent.

**The inline-detail cap is enforced, not advised.** A branch whose detail exceeds
it is refused with a message pointing at the reference; the ingest truncates
instead, so a producer that pasted a transcript still gets its failure recorded.

Failed verification attempts are lifted automatically — a check that ran and did
not pass *is* an attempt that did not work out, and it is already in the case, so
the exploration record is honest by default rather than by discipline. Nothing in
`RG-BRANCH-*` blocks or holds: penalising a run for recording its failures would
teach producers to stop recording them, which is the outcome this whole area is
designed against.

---

### 6.3a Assumptions (`RG-ASSUME-*`)

> **Implemented.** `release_gate/assurance/assumptions.py`, plus the
> `AssumptionsExamined` methodology predicate.

Every argument rests on things nobody checked. The danger is not that assumptions
exist — it is that they are invisible, so a reviewer approving a conclusion
cannot ask the only question that matters about them:

> If this assumption fails, what conclusions collapse?

Answered by computation. An assumption's **criticality is its collapse set**:
`LOAD_BEARING` means a root conclusion falls with it, `SUPPORTING` means other
claims do, `ISOLATED` means nothing does. Derived from the graph, not a severity
scale someone invented — which is the only way it means the same thing twice.

```text
as_clock  [UNKNOWN]  LOAD_BEARING
    "the replica clock is within 50ms of primary"
    nothing bears on whether this holds
    If it fails, 3 claim(s) collapse:
      directly:     cl_ordering
      and then:     cl_noloss, cl_root
      THE CONCLUSION FALLS: cl_root
```

**Not a new record type.** `ClaimType.ASSUMPTION` already existed and
`Claim.depends_on` already folds `assumptions` in beside `parents`, so status
already propagated through them — a conclusion cannot outrank the assumption it
rests on. What was missing was the *view*: which claims rest on each, and what
happens to them if it gives way. `AssumptionGraph` is a projection over the claim
graph, not a parallel store.

**The case it cares most about is the one the claim graph could not see.** A claim
that says "this rests on X" where X is nowhere described yields an `Assumption`
with `stated=False`, because an assumption nobody wrote down is the hardest to
evaluate and the easiest to miss.

**Collapse is not second-guessed.** A claim that names an assumption declared that
it depends on it, so it collapses, and so does anything depending on it. Whether a
claim might survive its assumption failing is a domain judgement; where a
collapsing claim carries its own verification it is *flagged for that judgement*
rather than quietly excused.

Coverage never implies the list is complete: these are the assumptions somebody
wrote down, and the dangerous ones are usually the ones nobody thought to mention.

---

### 6.2a Criticality (`RG-CRIT-*`)

> **Implemented.** `release_gate/assurance/criticality.py`, plus the
> `CriticalClaimsIdentified` methodology predicate.

A claim is critical when the decision being asked for depends on it. That is the
whole definition, and everything difficult follows from what it excludes.

**Volume is never an input.** Not the number of agents that mentioned a claim,
not how many messages discussed it, not how much evidence piled up behind it, not
how central it looks in a drawing of the graph. A claim four hundred agents argued
about that the decision does not rest on is not critical. A claim one agent
emitted once, five links down a chain, is critical if the conclusion falls
without it (Invariant 12). The record states this at the point of measurement and
the predicate restates it at the point of judgement:
`volume_affects_criticality: false`.

**Depth is not a discount.** In `Decision -> A -> B -> C`, claim C is
load-bearing exactly as much as A. Nothing decays with distance and no threshold
stops the propagation. Distance is reported because a reader wants it, and is
never a weight.

**A label is not a dependency.** The `criticality` a producer sets on a claim is
read, kept, and compared against the graph — but a producer calling their own
claim critical does not make the decision rest on it (Invariant 1). Where the two
disagree, `RG-CRIT-003` holds and says so without resolving it: either the label
is wrong or a dependency edge is missing, and a graph cannot settle which.

**An empty critical set is not "nothing is critical".** This is the sharpest
refusal here, because the failure is silent. Every critical-claim guard in the
system — `RG-CEX-001`, `RG-ADV-001`, `RG-REPL-001`, and the contradiction
`render_verdict` may not omit — asks whether a claim is critical. A case whose
criticality could not be derived answers *no* to all of them and comes out clean
for the worst possible reason. So `determinable` is carried explicitly,
`is_critical()` returns `None` rather than a bare `False`, the coverage row reads
NOT_ASSESSED with "every critical-claim guard was inactive", and `RG-CRIT-001`
holds.

`analysis.py` no longer computes criticality inline. One derived set is built
once and read by every guard, because three approximations of the same question
would eventually disagree about the same case.

**Propagation** is a single multi-source breadth-first walk from the decision's
claims over `depends_on`, which already unifies declared parents with declared
assumptions — an assumption the conclusion rests on is load-bearing in exactly
this sense. Each claim records one predecessor rather than its full chain, and
paths are reconstructed on demand: storing every claim's chain costs the square
of the chain length, and a ten-thousand-link chain is a legitimate input. The
walk is iterative, cycle-safe, and linear.

The decision's own claims come from `is_root` where a producer declared it, and
from the graph's sinks where nobody did. Where neither exists — every claim
depends on another, which means a cycle — the answer is `NONE` and criticality is
undetermined rather than guessed. Sinks the decision cannot reach are reported by
`RG-CRIT-004`: a second conclusion nobody linked up puts everything beneath it
outside every guard.

`LoadBearing` has four values — `LOAD_BEARING`, `SUPPORTING`, `ISOLATED`,
`UNKNOWN` — and **`AssumptionCriticality` is now an alias of it**. An assumption
the decision rests on and a claim the decision rests on are the same fact about
the same graph; two vocabularies for it would eventually disagree.

`RG-CRIT-005` reports load-bearing claims resting on a single producer. It is
advisory, and it exists so a reviewer sees how thinly the decision is supported —
not so the system can dock it. That is the prompt's example stated as a rule: a
claim one agent generated may be load-bearing, and its thinness is a fact to show
a human rather than a reason to weigh it less.

---

### 6.3c Counterexamples (`RG-CEX-*`)

> **Implemented.** `release_gate/assurance/counterexample.py`.

A counterexample search is a verification attempt with its semantics inverted,
and the inversion is where systems go wrong. Finding one is decisive: the claim,
as stated, is false. Finding none is almost nothing — it bounds the search, not
the claim. Folding both into one pass/fail field destroys exactly the content
that matters.

**An empty search never proves absence.** `proves_absence` returns `False`
unconditionally — a refusal, not a computation. Not for a formal method, not for
"the entire input space", not for a thousand searches; and per §6.4, a thousand
searches sharing a generator are one search anyway. No field is offered that
could be read as "proven safe", and the ledger summary states `absence_proven:
false` flatly so a reader of the summary alone cannot infer otherwise.

**`result` and `status` are separate fields, and the separation is load-bearing.**
`result` is what the search came back with; `status` is where a finding now
stands. A search that found nothing is `NOT_APPLICABLE` — nothing to resolve —
which is a different fact from `RESOLVED`, and the constructor refuses to let one
be recorded as the other. Conflating them would let "we looked and found nothing"
read as "we found something and dealt with it".

**A live refutation becomes a contradiction.** Rather than a second enforcement
path, an unresolved counterexample is converted into a `Contradiction`, which
§6.3b's `render_verdict()` guard already refuses to omit when the claim is
critical. One guard kept correct beats two that drift apart — and the conversion
skips claims that already produced a claim/evidence conflict, so the same
disagreement is never filed twice under two ids.

Two intake paths, because each sees what the other cannot. Evidence typed
`COUNTEREXAMPLE` is lifted automatically, so producers that never called their
finding a counterexample still get tracked; and an envelope `counterexample`
record is the only way to say a search came back *empty*, since there is no
evidence record for "I looked here and there was nothing".

---

### 6.3d Adversarial verification (`RG-ADV-*`)

> **Implemented.** `release_gate/assurance/adversarial.py`, plus the
> `AdversarialReviewRequired` methodology predicate.

A counterexample agent, a red team, a proof critic, a security adversary, a
falsification agent, an independent tester: all of them do the same structural
thing, which is to try to break the candidate rather than confirm it. That stance
is the content, because evidence from a party trying to fail you is worth
something evidence from a party trying to agree with you is not.

**Release-Gate never requires them.** Most decisions have no adversary and are
not worse for it. A case with none reports `NOT_ASSESSED` on the
`adversarial_review` coverage row, stores no review record, and produces no
finding. Only `AdversarialReviewRequired` can turn absence into a verdict.

**Breaking the argument is not breaking the claim.** A proof critic who finds
that step 7 does not follow has not shown the theorem false — they have shown the
proof does not establish it. `CANDIDATE_REFUTED` and `ARGUMENT_DEFECT` are
separate outcomes: collapsing them one way would call true claims false,
collapsing them the other would let broken support read as clean. Only a
refutation converts to a `CounterexampleAttempt`, which reaches `Contradiction`
and `render_verdict` by the path §6.3c already built — so refutations are
deliberately *not* re-reported under `RG-ADV-*`, and there is one guard to keep
correct rather than two that drift.

**An adversary sharing origin with the candidate is not an adversary.** A red
team running the same model, from the same prompt lineage, staffed by the people
who built the thing, will systematically miss what the builders missed.
`AdversarialStance` is derived — from who produced the candidate's supporting
evidence and from declared lineage — never accepted as a claim, and an adversary
that records nothing about where it came from is `UNDETERMINED` rather than
independent. `UNDETERMINED` is also deliberately not counted as *related*: not
knowing is not knowing.

**A finding closed by the party it was against is not closed.** The oldest
failure in assurance is the team that wrote the code resolving the red-team
ticket with "not exploitable". `self_cleared` is computed from the candidate's
own producers, not from anything the resolver said, and a self-cleared finding on
a critical claim blocks (`RG-ADV-004`) whatever its recorded status says.

**Accepting a risk is not resolving it.** `ACCEPTED_RISK` is a distinct status
and counts as open. It requires both a stated basis and a named accepting party,
because proceeding with a known weakness is an act of authority somebody has to
be answerable for. It converts to an *open* counterexample, never a resolved one.
And it always reaches Human Attention: the person authorizing the release is
exactly who should be told what is being accepted on their behalf — approval is
authorization, not truth certification (Invariant 15).

**An attack that found nothing bounds the search, not the claim.**
`proves_absence` is `False` at both the finding and the review level, and
`search_bound` states what the role structurally cannot cover — a red team does
not cover "attacks this team did not think of"; a property checker does not cover
"inputs the generator did not produce" — so an adversary's own account of its
thoroughness earns nothing (Invariant 1).

Seven rules. `RG-ADV-001` blocks on an open argument defect against a critical
claim; `RG-ADV-002` holds everything else still standing; `RG-ADV-003` surfaces
accepted risks; `RG-ADV-004` surfaces self-clearing; `RG-ADV-005`, `RG-ADV-006`
and `RG-ADV-007` report non-independent adversaries, empty searches, and critical
claims nobody attacked — all advisory, because adversarial review is optional and
a gate that docked its absence would be charging for a thing it says is not
required.

**Human Attention.** `ADVERSARIAL_FINDING`, `ACCEPTED_RISK` and `SELF_CLEARED`
are separate reasons, and the attention builder now takes a group's reason from
the most specific rule present rather than the alphabetically first — an accepted
risk grouped with a generic open finding would otherwise reach a reviewer labelled
as neither. All four substantive rules are non-monotone: an adversarial finding
that was answered can be reopened by an attack nobody has made yet, so a clean
adversarial result is never settled by arrival.

---

### 6.3b Contradiction preservation

> **Implemented.** `release_gate/assurance/contradiction.py`, plus the refusal in
> `AssuranceCase.render_verdict()`.

The failure this guards against is quiet. A system gathers evidence pointing both
ways, synthesises a confident summary, and the disagreement never reaches the
person signing. Nothing was falsified. Something was just not mentioned.

So a contradiction is a first-class object — both sides, who is on each, how many
independent lineages back each — and it can never be closed without a statement
of what closed it. `resolve()` demands `resolution_evidence`; `invalidate()` and
`supersede()` demand a reason. Dismissing a recorded disagreement is a claim
somebody has to be answerable for.

**The verdict may not omit one.** `render_verdict()` refuses a verdict that does
not name every unresolved contradiction affecting a critical claim — the same
shape of enforcement as the coverage check, for the same reason: the harm is
silence, not falsehood. A case may reach *any* decision over an open
disagreement; it may not reach one without mentioning it. Criticality is
structural — a root claim, or one others depend on — never release-gate judging
importance.

**The counting is inert.** Seven independent roots on one side and one on the
other is reported and never adjudicated. More sources is not more true, and a
module that resolved disagreements by weight would be doing exactly the silent
erasure it was built to stop.

Two things were found while building it and are worth recording. `RG-CONTRA-001`
scanned for a record that both supports and contradicts one claim, and **could
never fire** — `EvidenceRecord` refuses that construction — so it has been
removed; a rule that cannot fire is worse than no rule, because it implies a
check is happening. And the ingest *rejected* such a record outright, which
dropped the disagreement entirely: the erasure this section exists to prevent,
sitting in the ingest. It now splits the record into its two halves, so one
producer declaring both sides becomes a recorded `RECORD_SELF_CONFLICT` rather
than a skipped line.

---

### 6.4 Independence (`RG-INDEP-*`)

> **Implemented.** `release_gate/assurance/independence.py`, plus the
> `AncestryIndependence` methodology predicate.

The mechanism behind Invariant 6. Ten thousand verifier agents deriving from one
upstream artifact are not ten thousand independent validations — they are one
validation observed ten thousand times, and a system that counts them as ten
thousand has turned a single point of failure into apparent overwhelming
consensus.

Independence is **derived, not asked**. Evidence records carry `parent_evidence`;
following those chains to their roots says where support actually comes from,
whatever a producer claims about itself. That is a different question from the one
`IndependenceThreshold` asks — which reads a *declared* `independence_group` — and
both are kept, for the same reason DECLARED and OBSERVED capability are kept
apart.

```text
Supporting contributors: 8,437
Independent evidence roots: 7
Largest shared lineage: 7,993 contributors (94.7%)
Result: HIGH lineage concentration
```

Three rules constrain it.

**No probability of truth.** The module emits structure — roots, cluster sizes,
the share of contributors in the largest lineage — and no confidence, likelihood
or trust score. Seven independent roots do not make a claim 7/8ths true, and
concentration is not an error rate. A structural measure dressed as a probability
would be the most persuasive wrong number this system could produce, so a test
asserts the serialised profile contains no such field.

**Concentration is reported, never penalised.** Many parties legitimately relying
on one authoritative source is a normal and often correct workflow. Every
`RG-INDEP-*` finding is ADVISORY, and their remedies say *none required*. Only a
methodology that actually needs independent evidence can turn concentration into
a verdict, through `AncestryIndependence(minimum_roots=…, maximum_concentration=…)`.

**The band refuses itself when the ranking is undetermined.** Contributors whose
every record is isolated — no parents, no dependents — have unrecorded ancestry,
and when that group is at least as large as the biggest known cluster it could
*be* the biggest cluster, so no band is honest and the answer is `UNKNOWN`. That
threshold is structural rather than tuned. A record others derive from is a
*demonstrated* origin and is not counted as unknown: otherwise every case with
several real lineages would report as undeterminable purely for having roots.

Latent correlation — shared pre-training, a shared upstream corpus — remains
outside what ancestry can see, and the coverage row says so rather than implying
more (Invariant 10).

### 6.4a Replication (`RG-REPL-*`)

> **Implemented.** `release_gate/assurance/replication.py`, plus the
> `ReplicationEstablished` methodology predicate.

Independence asks where evidence came from. Replication asks the question one
level up: **could this second answer have been wrong differently from the
first?** A copy could not, so it adds nothing however many times it appears.

Replication is a *relation between verification attempts*, not a new record.
`VerificationAttempt` already carries what the question needs — method,
implementation, input state, lineage, cited evidence, result — so this is a
projection over the `verification` collection, the way `VerificationGraph` is,
and no producer gets a new field to certify themselves with.

**Copies collapse, and the collapse says why.** Attempts merge into one path
when they share a signature, a declared lineage element, or an evidence root,
recorded as `IDENTICAL_SIGNATURE`, `SHARED_LINEAGE`, `SHARED_EVIDENCE_ROOT`. The
merging is three hash-indexed union passes, not a pairwise sweep, so ten thousand
attempts on one target cost ten thousand unions rather than fifty million
comparisons — and `SINGLE_PATH` is the default reading of mass agreement.

**A label is not a path.** `VerificationMethod.INDEPENDENT_REPLICATION` is what a
producer called their own work. It earns nothing: an attempt declaring itself an
independent replication, resting on the lineage it claims to replicate, collapses
into that lineage like anything else (Invariant 1).

**Timestamps are deliberately not in the signature.** A cron job re-running one
script hourly is not twenty-four replications a day. A second run with nothing
recorded to distinguish it — no seed, no sample, no separate lineage — is not an
established second path, and the remedy says to record what differed rather than
crediting the repetition.

Five axes, never summed and never scored:

| axis | what it asks | source |
|---|---|---|
| `METHOD` | a different strategy — another proof, another test shape | `method` |
| `IMPLEMENTATION` | a different tool or codebase did the work | `verifier` |
| `INPUT` | a different input state was used | `input_state` |
| `LINEAGE` | disjoint declared independence lineage | `independence_lineage` |
| `PRODUCER` | different parties produced the cited evidence | derived from the records |

**An unrecorded axis is `UNDETERMINED`, never a difference.** Two attempts that
both recorded no input state have not been shown to use different inputs. This is
the rule a naive implementation gets wrong, and it is the one that matters: the
cheapest way to look independent is to record nothing, and a system that read
silence as difference would hand its highest rating to whoever documented least.
`INDEPENDENT` additionally requires `LINEAGE` to be determinable and disjoint —
not because lineage outranks the rest, but because it is the axis that catches
the echo.

Axes are compared as *sets over each path's members*, never via a representative
attempt: a path of four hundred attempts has no canonical member, and picking one
would make the reported comparison depend on a sort order rather than on the
evidence.

**Disagreement is never outvoted.** Nine confirming paths and one divergent one
is not ninety percent replicated. It is `DIVERGENT`, it becomes an open
`Contradiction` under `VERIFICATION_CONFLICT` so final synthesis cannot present
it as clean, and `RG-REPL-001` blocks where the claim is one the decision rests
on. There is no majority rule anywhere in this module.

**Same verdict is not the same result.** Two independent implementations agreeing
that something passes have not been shown to have computed the same thing.
`ResultEquivalence` records the basis: `IDENTICAL` (matching content), `DECLARED`
or `TOLERANCE` (a producer stated one, and said so), `VERDICT_ONLY`, or
`UNDETERMINED`. Release-Gate cannot decide whether two numbers are the same
number — tolerance is domain knowledge, and inferring it would be a universal
truth claim about somebody else's field (Invariant 10).

`replications` is a count of established paths beyond the first. It is not a
probability and nothing scales with agreement: five paths do not make a claim
five times more likely to be true (Invariants 6 and 10). Every finding except
divergence is ADVISORY, because a workflow that rests on one path is normal and
often correct; only `ReplicationEstablished` turns a shortfall into a verdict,
and its `required_axes` is what distinguishes "a different proof strategy"
(`METHOD`) from "an independent implementation" (`IMPLEMENTATION`) from "an
independent run" (`INPUT`, `LINEAGE`).

**Schema change.** `VerificationAttempt.identity()` gained
`independence_lineage` at `VERIFICATION_SCHEMA_VERSION = 2`. Two checks that
differ only in what they rest on are two attempts — that is the whole difference
between corroboration and an echo — and while lineage was absent from the
identity, two labs reporting the same outcome collided into one record and a case
could not hold both. Version-1 `verification_id` values do not survive the
change; the version sits inside the digest, so the break is explicit rather than
silent.

### 6.5 Change / drift (`RG-DRIFT-*`)

Verified-then-modified artifacts; subject digest changes since the last case
version; `compare_lock()` drift; baseline deltas from `compare_to_baseline()`;
approvals whose binding no longer matches; evidence produced against a superseded
digest. This analyser is what makes an approval *decay* correctly instead of
silently carrying over.

### 6.6 Completeness (`RG-COMPLETE-*`)

Invariant 13's home. Sequence-number gaps in an event stream; sources named in an
expected-source manifest that never reported; verifiers listed in a verifier
manifest with no result; heartbeat gaps; a `CompletenessDeclaration` that does not
match what arrived; missing spans between a parent and its children. Where none of
those signals exist, the analyser emits exactly one thing: completeness is
`UNKNOWN`, and "not observed" must not be read as "did not happen".

### 6.7 Capability discovery (`RG-CAP-*`)

> **Implemented.** `release_gate/assurance/capabilities.py`.

*What did the system reach for?* — answered at four strengths, because the
evidence for it arrives at four strengths. The vocabulary is
`OBSERVED_CAPABILITY` / `DECLARED_CAPABILITY` / `INFERRED_CAPABILITY` /
`UNKNOWN_CAPABILITY` over a closed set of thirteen capabilities.

**Status is the weaker of two independent axes.** *Did we see it happen?* is
answered by whether a span exists. *Do we know what it was?* is answered by
whether the telemetry named it or we matched a string. A span carrying
`db.system=postgresql` with `db.operation=INSERT` is an observed database write;
a tool called `db_write` with no other attribute is an observed *something* we
are guessing about. Reporting the second as OBSERVED would launder a naming
convention into a fact, so it is INFERRED.

Three consequences the implementation makes explicit rather than hiding:

* **The capabilities that matter most are the ones no telemetry standard names.**
  Payment, deployment and identity management have no semantic convention, so
  they are almost always INFERRED. Reaching `api.stripe.com` is an *observed*
  external API call and an *inferred* payment — a balance read looks identical
  from here.
* **Some categories cannot determine their own properties.** `mutating` and
  `external_effect` are `Optional[bool]`: "filesystem" covers reads and writes
  alike, so the category alone cannot say a read changed anything. `None` is
  never defaulted to `False`.
* **The list is not an inventory.** A shell can curl; an MCP server exposes
  whatever its author wrote; an unidentified tool could do anything. Where one of
  these was exercised, `CapabilitySurface.bounded` is `False` and the coverage row
  says the surface was sampled, not assessed. A tidy list that implied
  completeness would be the most dangerous output this analyser could produce.

The sharp finding is the cross-product: **exercised but never declared** — the
system did something nobody said it could. That is `RG-CAP-001`, and it fires
only when a manifest exists; with nothing declared there is no bound to have
exceeded, which is `RG-CAP-003` and is a coverage gap rather than a violation.

**Nothing here BLOCKs.** "The agent sent an email" is not structurally wrong, and
whether it was permitted is a domain question a methodology answers. Capability
discovery is evidence, and is deliberately not the centre of the product.

---

### 6.8 Consequence (`RG-CONS-*`)

> **Implemented.** `release_gate/assurance/consequence.py`, plus the
> `ConsequenceDeclared` methodology predicate.

The human authorization boundary depends partly on consequence: an irreversible
production change and a scratch notebook deserve different amounts of a person's
attention. So the engine needs somewhere to put that — and a hard rule against
filling it in.

Eleven generic dimensions (reversibility, externality, scope, user, financial,
data, security, production, research, legal, and a catch-all for impacts the
taxonomy has no dimension for). **Every one defaults to `UNKNOWN`, and `UNKNOWN`
is a real answer.** A profile of eleven unknowns is valid and honest — it records
that nobody stated the stakes, which is different from stating there are none.

Four rules keep it from becoming a guess:

* **Nothing is invented.** A value appears only when someone `DECLARED` it or it
  follows structurally from evidence already in the case (`DERIVED`). Value and
  basis are checked against each other in both directions: a known value must
  name who established it, and an `UNKNOWN` cannot have been established by
  anyone.
* **Derivation reads only OBSERVED capabilities.** A capability inferred from a
  tool's name is a guess, and a consequence derived from a guess is a guess
  wearing a better coat. Only two dimensions are reachable structurally —
  externality and data impact — and only from §6.7's observed set. Where the
  capability surface is not an upper bound, even `CONTAINED` is unprovable and
  the dimension stays `UNKNOWN`.
* **`REVERSIBILITY` is never derived.** It is the dimension people most want and
  the one no telemetry supports. A structural rule for it would be pure
  invention.
* **`UNKNOWN` never sorts as a middle value.** Its rank is `None`, not the
  midpoint — the exact defect recorded against the legacy readiness scorer in
  §18.1, not repeated here. There is also no total: no score, no level, no
  aggregate, because collapsing eleven dimensions into one number would invent a
  trade-off between money and legality that nobody stated.

Precedence is declarations, then domain plugins, then structural derivation, and
a lower tier never overwrites a higher one. Disagreement is recorded rather than
resolved: a declaration contradicted by derived evidence is `RG-CONS-003` and
HOLDs, because somebody stated the stakes and the trace says otherwise — but the
declaration still stands, since a person is answerable for it and may know the
call went to a sandbox. The engine's job is to put the disagreement in front of a
human, not to adjudicate it.

**Consequence never blocks, and never reorders attention.** Reordering would
require a weight nobody supplied. It reaches the authorization boundary through
the methodology instead: `ConsequenceDeclared(dimensions=…)` lets a methodology
say which dimensions a decision of this kind cannot be taken without. That is how
"irreversible changes need a second approver" becomes expressible without
release-gate ever deciding it.

---

### 6.9 Determinism requirements

* Pure functions; all inputs in the case; no wall-clock, no network, no model.
* **Order-independent fold.** Ingesting the same records in any order, serially or
  in parallel, must produce an identical graph and identical digests.
* Stable ids and sorted iteration everywhere, so output is byte-reproducible.
* Engine and ruleset versions are recorded in the binding; a verdict is
  reproducible only against the versions that produced it, and the packet says so.

---

## 7. The Human Attention Engine

> **Implemented.** `release_gate/assurance/attention.py`. Measured on 188,001
> input records — 98,000 claims, 90,000 evidence records from 10,000 producers,
> 8,000 verification attempts — producing **8 attention items, 7 shown**.

The component the frontier case exists for: given a case with potentially millions
of records, produce **the smallest set of things a human must inspect before
accepting responsibility**.

Ranking is deterministic and follows Invariant 12 — dependency and consequence,
not volume and not a generic severity number.

```text
AttentionItem
  item_id
  kind             INTEGRITY_BREAK | CONTRADICTION | LOAD_BEARING_ASSUMPTION |
                   UNVERIFIED_CRITICAL_CLAIM | INDEPENDENCE_DEFICIT | DRIFT |
                   COMPLETENESS_GAP | POLICY_CONDITION
  what             the thing to look at (claim, artifact, evidence, execution node)
  why              why it is on the list, in one sentence
  question         the question the human is actually answering
  leverage         what changes if they rule each way (computed over the claim graph)
  evidence_refs    what to read, smallest sufficient set
  consequence      what this gates
```

`leverage` is the differentiator and it is computable: for each candidate, flip its
status to best-case and worst-case and recompute the root claim's
`effective_status`. Items that change the root's status rank above items that do
not, regardless of how many events they involve. A single load-bearing lemma
outranks 50,000 informational events by construction, not by heuristic.

**Every item answers nine questions**, on the item rather than scattered across
the case: what it is, why it matters, what depends on it, what supports it, what
contradicts it, where it stands, what epistemic status that standing has, what
the human can do, and what evidence would resolve it. The last of those is joined
onto the item from `RequiredEvidence` rather than left in a second list, so a
reviewer is never sent elsewhere to find out what to ask for. An answer nobody
recorded renders as `(none recorded)` — never as an assertion that nothing
depends on it.

**Ranking is three factors, kept separate.** `AttentionRanking` carries
dependency criticality (from §6.2a), unresolved requirement pressure (from the
methodology assessment), and consequence (from §6.8), compared as an ordered
tuple. They are deliberately **not multiplied into a score**: `composite_score`
is `None` in the record, because a reviewer told an item scored 0.82 cannot argue
with it, while one told "the decision rests on this claim, a blocking requirement
is waiting on it, and the action is irreversible" can. Effect and leverage break
remaining ties and come last — a count of findings must never outrank a
dependency.

Two orderings invert what a naive implementation would do. `UNDETERMINED`
criticality ranks **above** `OFF_PATH`, and `UNKNOWN` consequence **above**
`BOUNDED`: not knowing whether something matters is a reason to look, and sorting
unknowns to the bottom with the unimportant is how a case whose criticality could
not be derived comes to look calm (Invariant 3).

**Compression collapses findings onto inspections; it never drops an
inspection.** Forty findings across three claims are three items. But `top(n)`
returns *at least* everything undroppable — every blocking item and every item on
what the decision rests on — so `top(7)` over eleven blockers returns eleven, and
`withheld_note` says why the list is longer than asked for. What is left out is
named by reason and counted; nothing vanishes silently. This also reaches the
advisories: an advisory finding normally rides along rather than filling the
list, **except** where it bears on a load-bearing claim, because "never hide
critical issues for compression" outranks keeping the list short.

An item's criticality does not depend on the shape of its refs. A counterexample
finding refs counterexample ids, not claim ids, so the analysers that partition by
criticality state the claims in `observed["critical_claims"]` — without it, a
finding whose own summary read "against a critical claim" ranked `OFF_PATH`, and
an off-path item is droppable.

### 7.1 The required-evidence protocol

> **Implemented.** `release_gate/assurance/required_evidence.py`, plus the
> protocol form on `RequiredEvidenceSet.protocol()`.

**`RequiredEvidence`** is the HOLD counterpart: for each condition blocking
PROMOTE, what specific evidence would resolve it — "an independent replication of
claim C by a producer not descended from agent A, against digest D". This is what
makes HOLD actionable instead of a shrug.

Prose is actionable by a person and not by a machine, so three things are typed:

```json
{"status": "HOLD",
 "required_evidence": [
   {"target": "claim:C-184",
    "requirement": "independent_verification",
    "reason": "critical single-lineage dependency",
    "constraints": {"independent_of": ["agent-A"]}}]}
```

**What to act on** is addressable. Requirements are grouped by *(target, kind)*,
not by the text of a remedy: two claims both needing independent verification are
two requirements, because a verifier can act on one and not the other, and
collapsing them into "verify the claims" is a sentence nobody can dispatch. The
target kind is derived from `attention._FOCUS_KIND` rather than a second table —
one source of truth, already tested for completeness, so a requirement and the
inspection it corresponds to always name the same object. A finding about the
whole case targets `case:`, exactly as attention refuses to point a reviewer at
an arbitrary record.

**What kind of evidence is wanted** is a closed vocabulary a consumer can switch
on, and it covers methodology HOLDs too: a `RequirementResult` now carries its
`predicate_kind`, so "this decision requires independent ancestry" reads off as
`independent_verification` with `{"minimum_roots": 2, "independent_roots": 1}`
rather than as a sentence to parse. A methodology HOLD is the most common HOLD
there is, so it should be the most dispatchable.

**What would count** travels as `constraints` and `acceptance`, read only from
what the case establishes. A constraint invented to look precise — a lineage
nobody recorded, a digest nobody computed — would send a verifier to produce
evidence against a condition that was never true.

Where nothing in the vocabulary names what would close a gap, the answer is
`unspecified` with the prose intact, and `dispatchable` is false. An
organisation's own predicate arriving through the API degrades the same way:
guessing what satisfies somebody else's yardstick is exactly the invention this
system refuses (Invariant 3).

**Release-Gate does not orchestrate.** There is no assignee, priority, deadline,
schedule, callback or agent selection anywhere in the protocol, and a test
asserts the serialised payload contains none of those keys, so the boundary
survives its author. Release-Gate says what would resolve what, addressed to
nobody; who does the work, in what order, and whether at all, is somebody else's
authority.

**Satisfying every requirement does not yield PROMOTE.** `satisfies_decision` is
`False` unconditionally in the payload. A protocol whose completion implied
authorisation would let an external system grind out evidence until the gate
opened, which is the exact inversion of an assurance boundary (Invariant 15).

**The return leg is recorded, not laundered.** Evidence submitted with
`in_response_to` was produced by a party told exactly what would close the gate.
That does not make it false and does not make it dependent — but it is a motive,
and motive is provenance, so `RG-PROV-003` reports it as advisory. It is the loop
working, and it is not a reason to weigh the evidence less (Invariants 1 and 11).

---

## 8. Verdict and coverage

### 8.1 The decision function

`decide(case, methodology, profile) -> Verdict` is pure, ordered, and every fired
rule is named in the output.

* **BLOCK** — integrity break in the evidence chain; unresolved contradiction on a
  load-bearing claim; a `non_overridable_condition` unmet; the subject digest no
  longer matches the evidence and the action is irreversible; a required
  verification type absent for an irreversible high-consequence action.
* **HOLD** — coverage below the methodology's bar; independence deficit where the
  methodology requires corroboration; drift after verification; unresolved
  load-bearing assumptions; completeness `UNKNOWN` where the methodology expects a
  manifest; methodology absent for a case type that needs one
  (`METHODOLOGY_REQUIRED`).
* **PROMOTE** — every methodology requirement met, no unresolved contradictions on
  load-bearing claims, binding computed, coverage declared. Never reachable while
  a load-bearing claim is `UNKNOWN` (Invariant 3).

For ADMISSION the function delegates to `apply_decision_mode()` and adds nothing;
its `mode` values (`audit` / `ci` / `strict` / `public-advisory`) become
methodology profiles, preserving behaviour exactly.

### 8.2 Coverage is part of the verdict, not a footnote

> **Implemented.** `release_gate/assurance/expectation.py`, plus the
> `ExpectationDeclared` methodology predicate and the `RG-EXPECT-*` analyser.
> Every coverage row in the system now carries the five-state answer.

A `Verdict` object cannot be constructed without a `CoverageMatrix` — enforced in
the constructor, tested directly. Each row:

```text
dimension | expected | observed | status | basis | note
```

`status` ∈ `EXPECTED` / `OBSERVED` / `KNOWN_MISSING` / `UNKNOWN` / `NOT_ASSESSED`.

The percentage rule, stated as code would state it: a ratio is emitted **only**
when `expected` is a real number established by a manifest, a declaration, a
sequence, or direct enumeration. Otherwise `coverage: UNKNOWN`. Valid:
`observed 97 of expected 100 → 97%`. Also valid: `observed 97, expected UNKNOWN →
coverage UNKNOWN`. Never: `observed 97 → 100%`.

`coverage` is `None` where no ratio exists and serialises as `null` — never `0`,
never `1`. `UNKNOWN` and `NOT_ASSESSED` are kept apart everywhere including the
rendering, because "examined, and no denominator exists" and "never examined" are
the two absences that most want to collapse into one line.

**A denominator needs a source, and the source must name who wrote it.**
`EvidenceExpectation` refuses to hold an `expected` with no `ExpectationSource`,
and an `ExpectationSource` refuses to exist without a `declared_by`. The eight
kinds — methodology, orchestration manifest, producer manifest, agent roster,
verifier inventory, experiment matrix, CI plan, sequence declaration — select no
behaviour at all. What separates them is the next rule.

**The counted party cannot be the counting party.** An expectation declared by
whoever produced the observations cannot detect an omission: a producer that
dropped a record dropped it from its own count too, and the coverage reads high
*precisely because* something is missing (Invariant 13). `ExpectationStanding`
derives `SELF_REPORTED` from `ESTABLISHED` by comparing `declared_by` against
`observed_from`. The ratio is still reported, because a producer's count of
itself is a real if weaker fact; what is refused is `matches_expectation`.
Signing does not move the needle — a signature establishes *which* party wrote
the number, not that they were disinterested (Invariant 11).

**An over-count is not 110%, and not 100% either.** Eleven arriving where ten
were expected means the denominator is no longer known, so the state degrades to
`UNKNOWN` with a basis saying why. Clamping would render an anomaly as
perfection.

**An enumeration beats a count** and is worth asking for: `expected_ids` names
*which* record is missing rather than how many, and separates "everything planned
arrived" from "something unplanned also arrived" — a distinction a cardinality
cannot make at all, which is why an unplanned arrival degrades a count to
`UNKNOWN` but leaves an enumeration computable.

**No overall percentage is ever offered.** `CoverageLedger.overall_coverage`
returns `None` as a refusal, not an omission: averaging the dimensions that
happen to have denominators would let a case with one measurable dimension out of
fifteen report a confident number. A reader gets the rows.

**And `OBSERVED` is deliberately not called COMPLETE.** An expectation is itself a
declaration: "the manifest said ten and ten arrived" does not establish there were
not twelve. `bounds_completeness` returns `False` unconditionally, on the row and
on the ledger, and the methodology predicate restates it in its own observed
fields — the same refusal `CompletenessStatus` makes by having no `COMPLETE`
member, one level up.

### 8.3 Completeness declarations

A producer may emit a `CompletenessDeclaration` ("agents 1..100 reported; stream
sequence 1..48,201 complete"). That declaration is itself `DECLARED` evidence — it
raises the *expected* denominator and is never taken as proof of completeness.
Where it can be checked (sequence gaps, signed streams, heartbeats), the
completeness analyser checks it and reports the delta.

---

## 8a. The approval packet

> **Implemented.** `release_gate/assurance/packet.py`, reachable as
> `AssuranceOutcome.packet()`.

Everything upstream exists so that one person, about to accept responsibility for
something a machine did, can answer eleven questions and know where each answer
came from. The packet puts those answers side by side. It computes no new
judgement: it is a projection of a sealed case, and it can never be more
confident than the case it renders.

| # | Question | Source |
|---|---|---|
| 1 | What exactly am I being asked to authorize? | `AssuranceSubject` + its digest basis |
| 2 | What happens if I authorize it? | `ConsequenceProfile` (§6.8), UNKNOWNs listed |
| 3 | What evidence supports it? | evidence, ordered load-bearing first (§6.2a) |
| 4 | What verification was performed? | `VerificationGraph` (§5.5) |
| 5 | What remains unresolved? | contradictions, counterexamples, assumptions, adversarial findings, known-missing evidence |
| 6 | How independent is supporting evidence? | `IndependenceProfile` (§6.4) |
| 7 | What failed? | `FailedBranchLedger` (§6.3), relevance-directed |
| 8 | What changed since the previous verified state? | `AssuranceDelta` |
| 9 | What has not been assessed? | the case's own coverage collection (§8.2) |
| 10 | What does Release-Gate recommend? | `CaseVerdict` |
| 11 | What exact digests will approval bind to? | `binding_state()` / `rg-bind-1` (§9) |

The order is the product. A reviewer asks what they are authorising before they
ask what supports it, and asks what is unresolved before they are told what is
recommended. A packet that led with the recommendation would be asking for assent
rather than judgement.

**No section is ever omitted.** The constructor refuses a packet missing any of
the eleven. A section with nothing to say says so — "no typed verification is
recorded", "no previous verified state was supplied" — because an absent section
reads as an answered one.

**Section 9 is numbered, not appended.** It carries the same weight as section 3,
and it separates *never examined* from *examined without a denominator*: two
different facts that PROMPT 24 established must not merge. It reads the sealed
case rather than the analysis, because the analysis carries a coverage ledger
built while it was still running — reading that reported criticality,
contradiction and adversarial review as "never examined" while section 5 was
simultaneously listing findings from them.

**Section 8 never says "nothing changed" when there was nothing to compare.** A
first run and an unchanged run are different facts and only one of them is
reassuring. `AssuranceDelta.shrank` is restricted to the evidentiary collections:
release-gate's own derived outputs shrink whenever it finds less to say, and
reporting that as "evidence present before and absent now" would cry wolf on the
one signal here that most needs to be believed (Invariant 13).
`approval_carryover_permitted` is unconditionally `False`, as it is in
`describe_supersession`.

**Filtering is never hiding.** Section 7 shows relevant failures, and "relevant"
is a filter, so it obeys the attention engine's rule: a failure bearing on what
the decision rests on is never dropped to shorten the list, and what is left out
is counted with `RELEVANCE_DIRECTED` as its declared basis. Every section carries
a `MaterialisationBasis` and a truncation count, and none claims completeness —
`bounds_completeness` is `False` throughout.

**The packet binds; it does not approve.** `authorises` is unconditionally
`False`, the header says so before any content, and section 11 states the exact
digests a human act would attach to. `packet.matches(case)` reports whether the
packet still describes that case — a packet is a view of one exact state, and
when the case moves the packet describes something that is no longer what would
be authorised (Invariant 15).

---

## 9. Approval binding

> **Implemented.** `release_gate/assurance/approval.py`. `AssuranceCase.with_approval()`
> already kept approvals outside `case_digest`; this supplies the record and the check.

An approval is the moment a person accepts responsibility for what a machine did.
Everything else exists to make that moment informed; this makes it *specific* —
bound to one state of one case, attributed to one party, and incapable of quietly
outliving either.

Four behaviours carry the weight, and the differences between them are the point:

| condition | standing | why |
|---|---|---|
| the subject moved | `APPROVAL_INVALIDATED` | the human authorised a different thing; no re-check repairs it |
| the case was revised | `APPROVAL_INVALIDATED` | `revise()` re-opens the argument and states the approval applies to the previous version only |
| evidentiary collections moved | `APPROVAL_REVIEW_REQUIRED` | what was authorised is unchanged; what is *known about it* moved |
| a verification target moved | attempts reported `SUPERSEDED` | already computed by `applicability()`; the check names them |
| issued for another case | `APPROVAL_FOREIGN` | not out of date — used for something it was never given for |

**Review-required is deliberately not fatal.** The thing authorised has not
changed, so a person looking again may reasonably let the approval stand.
Blocking outright would train people to re-approve reflexively, which is worse
than asking.

**"Relevant" is derived, not asserted.** Only the collections constituting the
evidentiary state trigger review. Release-gate's own derived outputs — attention
items, required evidence, coverage rows — move whenever it finds different things
to say, and treating that as an evidence change would raise review on noise until
nobody read the signal (Invariant 13). The same split that stopped §8a crying
wolf.

**A revision is not a replay.** `case_id` folds in the subject id, which folds in
the subject's content digest — so revising the subject *always* produces a
different case id, and reporting that as `APPROVAL_FOREIGN` would send a reviewer
hunting an attacker when a colleague edited a file. Supersession tells them
apart, and both links must name *this* approval's case or subject: a case that
supersedes some other case is not a revision of what was approved here, and
treating it as one would silence a genuine replay.

**Release-gate cannot approve.** `AuthSource.RELEASE_GATE` is refused in the
constructor — present in the enum so it can be refused by name rather than by
omission. `ASSERTED` means the approval is attributable to a *claim* of identity,
not an established one, and `identity_established` says so: signing establishes
which party made a statement, never that the statement is right (Invariant 11).
An API key proves possession of a key, which is weaker than a person
authenticating, and is deliberately not counted as established.

**An approval never rewrites a verdict.** It records `case_decision` beside
`decision`, so approving over a HOLD or BLOCK is visible as
`overrides_recommendation` — a person taking responsibility despite the
recommendation, which is legitimate and sometimes necessary, and never a case
that became clean because somebody signed it (Invariant 15).

**Checking repairs nothing.** `check_approval` is pure: it never refreshes an
approval, extends an expiry, or mutates a case. A re-check that could repair an
approval would make the binding a formality. It reports *every* applicable
condition, not only the one naming the standing — an approval both expired and
bound to a moved subject has two problems, and a reader told about one would fix
it and be surprised.

```text
CaseBinding
  binding_algo      rg-bind-1
  case_digest       canonical digest over: proposition, subject digest, methodology ref,
                    evidence set digests, claim graph canonical form, coverage matrix,
                    verdict + fired rules, engine/ruleset versions
  computed_at

BoundApproval
  approval_id
  case_id + case_version + case_digest
  subject_digest
  approver_identity     who, and how they were authenticated
  scope                 exactly what was authorised (the requested_action)
  statement             "accepted responsibility under this evidence state"
  signature             reuses release_gate/crypto (RSA-PSS + SHA256)
  approved_at
  status                VALID | STALE | INVALIDATED | SUPERSEDED
```

Canonicalisation is explicit and versioned: sorted keys, stable ids, a published
exclusion list for volatile fields (wall-clock report timestamps, absolute paths,
run ids). Any later run recomputes `case_digest`; a mismatch marks the approval
`STALE` and names exactly which component changed. That is Invariant 5, mechanised.

Invariant 15 is enforced in the `statement` field and in every rendering: an
approval records that an identified human **accepted responsibility for an exact
bound subject under a visible evidence state**. It never says safe, correct,
validated, or compliant. The packet's own wording is part of the spec, not a
copywriting decision.

---

## 10. Zero-config behaviour

> **Implemented.** `release_gate/assurance/ingest.py`, `analysis.py`,
> `attention.py`, `zero_config.py`, and the `release-gate assure` command.
> The verb is `assure`, not `decide`: `decide` named the output, and what the
> command actually does is assemble and examine a case, which is a different and
> smaller claim.

Non-negotiable: `release-gate` must stay a three-dependency CLI that does
something useful in one command with no setup.

* `release-gate audit .` — unchanged, byte for byte.
* `release-gate assure <file>` — detects the format (OTLP, Langfuse, Arize,
  promptfoo, a release-gate audit report, or an assurance envelope), hashes the
  input, reconstructs execution, claims and artifacts, and runs every structural
  analyser. With no methodology it reports `METHODOLOGY_REQUIRED` for sufficiency
  and holds. The engineer gets provenance, drift, contradiction, verification
  status and integrity results plus an explicit statement of what was not
  assessed. That is useful and honest on day zero.
* **A file it cannot identify is not an error.** It is hashed, recorded as the
  subject, and reported as `RG-COV-001` with a named remedy. Refusing to run
  would give a user with an unusual export nothing at all; pretending to
  understand it would be worse.
* **The asymmetry that makes this safe:** with no methodology the command can
  return BLOCK and can return HOLD, and **cannot return PROMOTE** — asserted in
  `decide()`, not merely intended. A refutation is a fact about the evidence;
  sufficiency is a claim about a domain nobody has described. Refusal needs less
  authority than permission.
* Progressive assurance (Invariant 14): each structure a team adds — declared
  claims, a verifier manifest, signed evidence — populates more of the case and
  moves rows of the coverage matrix from `NOT_ASSESSED` toward `OBSERVED`. Nothing
  is required up front; nothing is faked when missing.

---

## 10a. The research assurance profile (`RG-CLAIM-*`)

> **Implemented.** `release_gate/assurance/methodologies.py` —
> `RESEARCH_ASSURANCE_V1`, plus three new predicates in `methodology.py`.

The first advanced domain profile: mathematics, computer science, formal proofs,
scientific hypotheses, engineering optimisation, algorithm discovery.

**A profile is a methodology, not a new analyser.** The ten rules are
*sufficiency* judgements over structure the analysers already derive domain-free,
which is this system's standing layering: analysis enforces shape, methodology
enforces sufficiency. So each rule is a `Requirement` whose `requirement_id` is
its `RG-CLAIM-*` id, and the whole existing machinery — assessment, required
evidence, attention, packet — works unchanged. Nothing in the engine branches on
a methodology id.

**It does not say a result is true.** It says the argument has the shape a
research result should have: what it rests on is identified, what it rests on is
checked, what checked it was independent of what it checked, something tried to
break it, and nothing it rests on has moved. A profile claiming more would be a
truth oracle (Invariant 10).

| rule | fires when | does *not* fire when | NOT_ASSESSED when |
|---|---|---|---|
| **001** CRITICAL_CLAIM_UNVERIFIED | a load-bearing claim has no PASSED verification by an accepted method carrying a target digest | verified by any accepted method; not load-bearing | criticality undeterminable, or the load-bearing set truncated |
| **002** LOAD_BEARING_ASSUMPTION_UNVERIFIED | an assumption a conclusion rests on has nothing bearing on it | it has evidence or a verification | no assumption graph |
| **003** FALSE_INDEPENDENCE | more lineages asserted across attempts than the ancestry traces to | assertion ≤ derived | nothing asserts a lineage |
| **004** OPEN_COUNTEREXAMPLE | a counterexample was FOUND and nothing answers it | a search came back empty | collection never supplied |
| **005** FORMAL_VERIFICATION_MISMATCH | an attempt's target digest ≠ the target's current digest | they match; no digest named (that is `RG-VERIF-005`) | no attempts recorded |
| **006** CRITICAL_CLAIM_SINGLE_LINEAGE | a load-bearing claim's support traces to one producer | two or more producers; **zero** producers (that is `RG-COV-003`) | criticality undeterminable |
| **007** SUPERSEDED_EVIDENCE_USED | evidence names `applies_to_digest` and no current artifact carries it | it matches; no digest named | no artifact carries a digest |
| **008** VERIFICATION_COVERAGE_GAP | no denominator, one written by the prover, or coverage below the floor | an independent source states a total and it is met | no coverage row names the dimension |
| **009** OPEN_CRITICAL_CONTRADICTION | a contradiction is OPEN or UNKNOWN | all resolved, superseded or invalid with a reason | collection never supplied |
| **010** VERIFIED_ARTIFACT_MUTATED | an artifact's verified digest ≠ its current digest | they match; none recorded | no artifact carries a digest |

Three more carry the emphases that are requirements rather than failure modes:
`RG-CLAIM-011` independent replication differing in implementation,
`RG-CLAIM-012` adversarial review from a disjoint lineage with nothing
self-cleared, and `RG-CLAIM-013` criticality being derivable at all — the last
because every other rule asks about load-bearing claims, and where criticality is
undeterminable they all answer no and the case passes because nothing was
checked.

**Six rules reuse existing predicates; three are new.**
`CriticalClaimsVerified` because `VerificationPresent` counts records across a
case ("was anything checked") while this is per-claim ("was everything
load-bearing checked"), and the two come apart exactly where it matters.
`DeclaredIndependenceHolds` because an *asserted* lineage is a falsifiable claim
about the world. `AppliesToCurrentState(scope=…)` because 005, 007 and 010 are one
question — *did what this rested on move?* — seen from three sides, and writing it
once means a case cannot pass one side while failing the identical test on
another. `CriticalClaimsIdentified` gained `maximum_thin` rather than becoming a
fourth new predicate.

> **What 003 deliberately does not read.** `independence_group` on an evidence
> record is release-gate's own fingerprint over source and producer. Comparing it
> against release-gate's own ancestry tracing would fire on any case with two
> producers and one upstream — the normal and often correct shape §6.4 reports
> and never penalises — making concentration blocking by the back door. 003 reads
> `independence_lineage` on verification attempts, which is a producer asserting
> something falsifiable.

**Cross-model review is not an accepted verification here.** Models agreeing
about a derivation is agreement, not verification (Invariant 8). Seven rules
cannot be waived; the rest can, by a named party with a stated reason — a profile
nobody can override in a real emergency is one people route around entirely.

---

## 10b. The software / agent assurance profile (`RG-SW-*`)

> **Implemented.** `release_gate/assurance/methodologies.py` —
> `SOFTWARE_AGENT_ASSURANCE_V1`; the audit bridge in `ingest.py`
> (`_audit_records`); one new predicate and one generalised predicate in
> `methodology.py`.

**There is one product, not two.** Release-gate's ADMISSION plane already
computes static analysis and taint, agent tool boundaries, PII and
prompt-injection paths, execution sinks, evals, traces, tests, AIBOM and lock
drift, PR diff and runtime evidence. Before this, those findings arrived as
evidence attached to *no claim*, so criticality, contradiction detection,
attention ranking, the packet and the approval binding all had nothing to work
with, and a software case was a second-class case. The bridge folds an audit
report into the same `AssuranceCase` a research case uses.

**The bridge derives claims; it never invents them.** An audit dimension
produces a claim only where the audit actually assessed it:

* `code_findings` become evidence *contradicting* `sw:code-safety`.
* A clean scan (`code_findings: []` with `code_safety.applicable`) produces the
  same claim with evidence *supporting* it — the scanner ran and found nothing.
* A scan that could not run (`applicable: false` — no agent detected, or a
  language the analyser cannot parse) produces **no claim at all**, because
  asserting code safety there would assert something nobody established.
* Each declared safeguard becomes `sw:safeguard:<name>`, supported by an
  `ATTESTATION` (DECLARED — a governance file saying a kill switch exists is the
  team's account of their own system, not a runtime guarantee, Invariant 1) or
  contradicted by release-gate's own observation that it looked and did not find
  it (DERIVED).
* The audit's own `coverage` rows become `EvidenceExpectation`s, so a dimension
  the checks could not reach reads as `NOT_ASSESSED` on the case rather than
  being absent and therefore invisible (Invariant 3). `partial` is recorded as
  NOT_ASSESSED, never rounded up to assessed.
* `sw:admissible` is the root, resting on every dimension claim — which is what
  makes a refuted safeguard reach the thing the human is being asked about.

| rule | fires when | does *not* fire when | NOT_ASSESSED when |
|---|---|---|---|
| **001** UNRESOLVED_CODE_FINDING | a finding leaves a load-bearing claim REFUTED or DISPUTED with nothing answering it | the finding was answered; it bears on no load-bearing claim | no claims supplied, or criticality undeterminable |
| **002** SAFEGUARD_ABSENT | a load-bearing safeguard claim is broken or the chain cannot be walked | every safeguard the audit checks is present | criticality undeterminable |
| **003** RUNTIME_EVIDENCE_ABSENT | no test, eval, simulation or runtime assertion carries a typed verification | any accepted runtime method is present | the verification collection was never supplied |
| **004** CAPABILITY_UNDECLARED | `capability_discovery` is NOT_ASSESSED — no execution evidence, or a surface that is not an upper bound | the surface was observed **and** bounds what ran | never: a missing row is UNSATISFIED |
| **005** ARTIFACT_MUTATED_AFTER_VERIFICATION | an artifact's verified digest ≠ its current digest | they match; none recorded | no artifact carries a digest |
| **006** STALE_VERIFICATION | a check names a target digest the target has left | digests match; no digest named | no verification attempts recorded |
| **007** EVIDENCE_AGAINST_A_SUPERSEDED_BUILD | evidence names an `applies_to_digest` no current artifact has | it matches; none named | no artifact carries a digest |
| **008** COVERAGE_UNSTATED | the `overall` dimension is absent | coverage is stated, whatever it says | the coverage collection was never supplied |
| **009** SUBMISSION_DENOMINATOR_SELF_REPORTED | the denominator for what was submitted is the submitting system's own count | an independent source (CI plan, orchestration manifest, verifier inventory) declares it | no coverage row names the dimension |
| **010** CONSEQUENCE_UNSTATED | no consequence dimension is stated | reversibility is declared | no consequence profile was built |

`RG-SW-001`, `005`, `006` and `subject.identified` cannot be waived.

> **Why 001 does not read the contradictions collection.** A `Contradiction`
> record is written only where evidence points **both ways** at one claim. A
> taint path to an execution sink with nothing answering it is *unanimous* — so
> the collection stays empty, and `NoUnresolved(collection="contradictions")`
> reports "all 0 contradictions resolved" on a live finding. That false clean is
> what the new `NoClaimInStatus` predicate closes: it reads the status the claim
> graph *computes* (REFUTED, DISPUTED) rather than a record somebody wrote. The
> two predicates catch genuinely different failures and neither subsumes the
> other. A test pins the gap so 001 is never "simplified" back onto the wrong one.

> **Why 004 needs `require_assessed`.** `CoverageDimensionDeclared` asks whether
> somebody answered the question; zero-config emits a `capability_discovery` row
> for every input, including one saying plainly that it discovered nothing. A
> bare presence check is therefore satisfied on exactly the case the rule exists
> to catch. The predicate was **generalised** with `require_assessed` (default
> `False`, so every existing rule is unchanged) rather than forked into a second
> near-identical predicate. Stating a dimension as NOT_ASSESSED still satisfies
> the default, and should: a case that declares its gaps has met the coverage
> obligation, and refusing it would pressure cases into silence.

> **Why 009 is advisory and fires on nearly every ingest.** A document that
> states its own total *is its own denominator*, so it can say how many records
> failed to map and nothing at all about a record the producer never wrote — the
> omission it cannot detect is the one that matters (Invariant 13). That is true
> of almost every software case, which is why it informs rather than blocks, and
> it clears the moment an independent plan declares the total instead.

**Nothing here re-implements a check.** Every rule is a sufficiency judgement
over findings the existing engine already produces — the same layering as §10a,
and the reason the audit path did not need a parallel architecture.

---

## 10c. The general autonomous action profile (`RG-ACT-*`)

> **Implemented.** `release_gate/assurance/methodologies.py` —
> `GENERAL_AUTONOMOUS_ACTION_V1`; `AcceptedFinding` in `methodology.py`;
> the acceptance branch in `zero_config.decide()`.

The ordinary case, and the one most teams actually have: **one agent, one
action, the execution record it produced, and verification only where it happens
to exist.** Send an email. Modify a record. Execute a transaction. Deploy an
app. Change cloud infrastructure.

### 10c.1 The problem this exposed

`decide()` computed `elif unmet_hold or holding:` — *any* structural finding with
HOLD effect forced HOLD, and no methodology could speak to it. Two findings fire
on every single-agent action:

* `RG-PROV-002` "all evidence traces to a single producer" — **tautological**
  when there is one agent.
* `RG-VERIF-001` "nothing in this case was verified".

So **PROMOTE was unreachable for the entire one-agent scale**, whatever the
operator supplied; a case with all eleven consequence dimensions declared still
held on both. The only case in the repository that reached PROMOTE carried a
claim graph, two producers and two typed verifications — exactly the research
machinery this scale does not have. A gate that can only refuse the ordinary
case is not a gate; it is an outage.

### 10c.2 `AcceptedFinding`

A methodology may declare, up front, that a named structural HOLD is not
disqualifying for the class of decision it covers. It is the sibling of
`accepted_verification_types` — both are a methodology stating its standards
before any case exists — and deliberately **not** `OverrideRule`, which is a
person waiving a requirement at decision time and carries an actor, a role and a
recorded act. Merging them would invent an actor where there is none and lose one
where there is.

Four properties stop it becoming a suppression channel:

* **HOLD only.** `decide()` never consults acceptance for a blocking finding.
  A structural BLOCK is a fact about the evidence that no yardstick waves
  through, and a methodology naming every BLOCK on a case as accepted still
  gets BLOCK.
* **A rationale is mandatory.** A methodology that cannot say why is not making
  a judgement, and the constructor refuses it.
* **The ceiling denies UNKNOWN.** An acceptance conditioned on consequence
  applies only where that consequence is *stated* at or below the named value.
  A guarded dimension that is missing or UNKNOWN fails the ceiling, and UNKNOWN
  may not even appear in one: an unstated consequence is an unassessed one,
  never a small one (Invariant 3).
* **Nothing is hidden.** The finding still reaches Human Attention and the
  packet; the verdict records the acceptance and its rationale and fires
  `RG-ZC-005`. This narrows what **blocks**, never what is **shown**.

### 10c.3 The profile

| rule | fires when | does *not* fire when | NOT_ASSESSED when |
|---|---|---|---|
| `subject.identified` | no digest binds the subject | a digest binds it | never |
| `contradictions.resolved` | any contradiction is open | all resolved | collection never supplied |
| **RG-ACT-001** EXECUTION_RECORD_ABSENT | `execution_reconstruction` is NOT_ASSESSED | an execution graph was rebuilt | never — a missing row is UNSATISFIED |
| **RG-ACT-002** CONSEQUENCE_UNSTATED | reversibility or scope is not stated | both carry a value | never |
| **RG-ACT-003** COVERAGE_UNSTATED | the `overall` dimension is absent | coverage is stated, whatever it says | collection never supplied |

`subject.identified` and `RG-ACT-001` cannot be waived — without an execution
record there is nothing to promote on.

**`RG-ACT-002` is the load-bearing requirement.** Both acceptances are
conditioned on stated consequence, so a case that declines to say what the action
would do gets neither and holds. Release-gate cannot derive from a trace whether
sending an email is a reminder or a termination notice; the operator states the
stakes, and the profile then holds them to it.

The two acceptances apply only inside `_BOUNDED_ACTION`: reversible or reversible
with effort, single-subject or bounded scope, no or bounded financial impact, no
security impact, no legal impact. Outside those bounds the action is not
"risky" — it is simply beyond what one unverified actor's own account can settle,
and it holds.

| stated consequence | verdict |
|---|---|
| none declared | HOLD — required evidence names `RG-ACT-002` |
| bounded (send a reminder email) | **PROMOTE**, with no claims and one producer |
| irreversible | HOLD |
| grants access, unbounded financial, broad scope | HOLD |

### 10c.4 The tension, stated

Acceptance keys on *declared* consequence, so an operator's assertion is what
unlocks PROMOTE — friction with Invariant 1 (evidence over assertion). It is
resolved rather than hidden: consequence is inherently a domain statement nobody
can derive from a trace, the architecture already treats it that way
(`ConsequenceDeclared`, `RG-SW-010`), and the acceptance is recorded in the
verdict and packet with its rationale. A false declaration is attributable to
whoever made it through the approval binding. The profile does not certify that
the action was correct; it records the basis on which it was authorised —
which is what Invariant 15 says an approval is.

**No claim graph, no replication, no adversarial review, no second producer.**
Invariant 14 in practice: not every graph is mandatory.

---

## 10d. Progressive assurance (`AssuranceLevel`)

> **Implemented.** `release_gate/assurance/level.py` — `AssuranceLevel`,
> `LevelAssessment`, `assess_level()`; consumed by `zero_config.assure()` and
> packet §9. Stdlib-only, and it imports nothing from the package.

Progressive assurance was Invariant 14 and a paragraph in §0.1 — a principle the
analysers honoured and **nothing in the code ever named**. The degrade-gracefully
half was already true: analysers no-op on an absent collection rather than
inventing one. What was missing is that no case ever stated its own depth, so
every case was *reported* in the vocabulary of the deepest one.

Measured, before this section existed. A PROMOTE'd one-agent "send an invoice
reminder": **21 coverage dimensions, nine of them about replication, adversarial
review, criticality, counterexamples and failed branches**, each NOT_ASSESSED.
The same case on HOLD: **two of its three required-evidence items asked for an
independently-operated producer and a typed verification**, while the one thing
that would actually resolve it — say what the action does — sat third.
That is forcing Level 4 onto Level 0.

### 10d.1 The five levels

| level | the question | what it turns on |
|---|---|---|
| **L0** MINIMAL | one agent, low consequence | what happened, and what it was asked to do |
| **L1** ATTRIBUTED | one agent, consequential | action provenance, subject integrity, authorization |
| **L2** ORCHESTRATED | a multi-agent workflow | execution lineage, artifact provenance |
| **L3** CORROBORATED | a high-impact workflow | independent verification, contradictions, assumptions |
| **L4** FRONTIER | research, critical infrastructure | claim graph, formal verification, adversarial review, replication |

The names are scales, not scores. **Level 0 is not a worse case than Level 4; it
is a smaller question.**

### 10d.2 Two numbers, never one

`supported` is the depth the evidence present can sustain. `required` is the
depth this decision demands, from the three inputs the contract names — case
type, methodology, available evidence — with consequence folded into `required`
because it is what separates "send a reminder" from "send a termination notice"
when the two produce identical traces. Collapsing them into a single "level"
would lose the only interesting fact: which is larger. `required > supported` is
the gap worth leading with; `supported > required` is a team being thorough and
is never a penalty.

Where the builtin profiles land: `general-autonomous-action` and
`general-agent-action` require **L1**; `software-change`,
`production-database-change` and `software-agent-assurance` require **L3**;
`research-assurance` requires **L4**.

### 10d.3 The level is not a gate

**It is computed after `decide()`, from the sealed case, and consumed only by
reporting and ordering.** No analyser reads it, no finding's effect is softened
by it, and no verdict consults it. A level that could stop release-gate from
looking would be a way to launder a finding out of a case, which is the exact
opposite of the point.

Asserted directly rather than assumed: a Level 3 contradiction planted in a
Level 1 case is still detected, still ranked into Human Attention, and **still
BLOCKs**, with the `contradiction` dimension sitting out of scope the whole time.

Scope is a statement about **depth**, never about results. An early version
partitioned on coverage state instead, and got it backwards: `assessed` does not
mean the same thing across dimensions — for the ledger dimensions it means
*settled*, so an OPEN contradiction reads NOT_ASSESSED — and the case carrying a
live contradiction was the one reporting that dimension as unexamined.

Out-of-scope dimensions keep their coverage rows and their states. They are
grouped and counted, never dropped: NOT_ASSESSED is first-class (Invariant 3),
and a matrix that silently omitted rows would claim a completeness nobody
established.

### 10d.4 What it changes

* **Packet §9** separates "dimensions this decision was expected to cover and did
  not" from "dimensions that apply above this depth", and lists the first group
  first. The L1 email send reads *3 in-depth gaps and 7 above depth* instead of
  ten undifferentiated failures.
* **Required evidence** is re-ranked so proportionate asks come first — the L1
  case now leads with "declare reversibility and scope". Above-level asks are
  **kept and ranked last, never dropped**; the gap they describe is real.

### 10d.5 Two derivation traps, both hit

* **Presence is not population.** Release-gate marks a collection PRESENT to mean
  *this was looked for*, so every case has empty frontier ledgers. Reading
  presence rated a one-agent email send as FRONTIER-**supported** on the strength
  of five empty ledgers. `supported` reads record counts.
* **One node is not a relation.** Level 2 is execution lineage and artifact
  provenance, both claims about how things relate, and every zero-config run
  creates an artifact for the input file itself — so a threshold of one rated
  that same email send as carrying multi-agent workflow structure. L2 collections
  need two records; L3 and L4 collections are about a kind of evidence existing
  at all, so one is enough.

Level 1 is the one level no collection represents — "action provenance and
subject integrity" is a property of records the case already holds — so it is
asserted from named signals (`subject_digest`, `execution_reconstructed`,
`producers_identified`) rather than inferred from a count.

An unclassified dimension is treated as **L0**, so a newly added dimension shows
up in every case and gets noticed rather than silently vanishing from the small
ones.

---

## 10e. The no-YAML default experience

> **Implemented.** `release_gate/assurance/session.py` — `AssuranceSession`,
> `records_digest`; `release_gate/assurance/organisation.py` —
> `OrganisationConfig`; `VerifierRequired` in `methodology.py`;
> `assure_normalisation()` in `zero_config.py`; `release-gate assure --config`
> and `--diagnostics`.

Two entry points must work with nothing configured, and both now do.

```bash
release-gate assure run.json          # one file, no config, exit 0/10/1
```
```text
open session → add records → finalize → decision     # no files at all
```

### 10e.1 The CLI was broken, and not by configuration

`release-gate assure run.json` **did not work** on any install where an optional
native dependency failed to initialise. `cli.py` guards its optional imports with
`except ImportError`, and a `cryptography` wheel whose Rust extension cannot load
raises `pyo3_runtime.PanicException` — which derives from **BaseException**, so
it is missed even by `except Exception`. One unusable optional backend took down
the entire CLI, including the zero-config assurance path *that uses no
cryptography at all*.

The eight optional-feature guards now catch `BaseException`, re-raising
`KeyboardInterrupt` and `SystemExit`, and record why each feature is unavailable.
`release-gate assure --diagnostics` prints that list and says plainly that
`assure` needs none of them.

This was also the cause of 22 of the 25 test failures previously written off as
environmental. The real environmental residue is 3 — the `release-gate` console
script is not on `PATH` when running from a source tree.

### 10e.2 The session is the same code as the file

`AssuranceSession` accumulates records and calls `assure_normalisation()` — the
function `assure()` calls after reading a file. One implementation, not two that
agree until somebody edits one. `provisional()` runs the full analysis without
sealing, which is `GET /required-evidence` on an open case: the steering signal a
running agent reads to find out what is still missing.

Finalize is a boundary. Records added afterwards are refused, because a decision
names the exact state it was taken on and a case that kept accepting evidence
after being decided would make its own approval unfalsifiable (Invariant 5).

A session has no file, so two things had to be generalised rather than forked:
`_file_artifact` takes optional bytes, and `_subject_for` reads the digest the
ingest already computed instead of re-hashing the path. The second is a
single-sourcing fix in its own right — there were two independent computations of
one digest that had to agree forever.

### 10e.3 Local parity, corrected

Protocol spec §15 claimed a case built locally and a case built through the API
from the same records produce **the same `case_digest`**. They do not, and making
them would mean lying about provenance: release-gate records the input container
as evidence in its own right, and a file on disk is a FILE reference with a path
while records posted over a wire are an INLINE reference with none. Those are
genuinely different inputs. Fabricating a file reference for a submission that
never touched a disk is exactly the assertion-over-evidence this system refuses
(Invariants 1 and 11).

What is true, and what the claim was reaching for, is `records_digest()`: **the
records the client submitted fold identically and the decision is the same.**
That is the property a local reproduction needs to check a hosted decision.
Parity holds for the same records under the same `source`, which is not a
loophole — `source` is provenance, it flows into every derived evidence id, and
two submissions from different places are different evidence.

### 10e.4 Configuration improves assurance; it does not constitute it

`OrganisationConfig` is JSON, optional, and covers the seven things an
organisation may state: risk appetite, domain requirements, required verifiers,
approval roles, custom capabilities, methodology selection, override rules.

It is applied through `AssuranceMethodology.extend()`, which already enforces
that an extension inherits every requirement and non-overridable condition and
may only narrow what it credits — so configuration is structurally incapable of
demanding less. Four properties, each enforced rather than documented:

* **An empty config returns the very same methodology object**, so a case decided
  with an empty config is byte-identical to one decided with none. Asserted by a
  test, because the moment configuration changes an unconfigured run,
  configuration has started constituting the product.
* **It cannot lower a structural finding.** `decide()` reads analysis findings
  directly and configuration never touches them. A config waiving every
  requirement on a refuted case still gets BLOCK.
* **It cannot waive a non-overridable condition** — `extend()` drops a permissive
  override rule naming one.
* **It cannot invent a methodology from nothing.** `apply_to(None)` returns
  `None`. Config that assembled a yardstick from its own extras would let an
  organisation's additions become the whole standard while looking like an
  addition to one.

Risk appetite is a **floor** on `LevelAssessment.required` (§10d) and there is
deliberately no way to lower one: an organisation declaring that irreversible
actions are a Level 0 question would be configuring away the analysis rather
than configuring it.

### 10e.5 No YAML, and no discovery

Configuration is JSON. A `.yaml`/`.yml` path is refused with the reason, and
`governance.yaml` remains supported as an **evidence producer** — its contents
become DECLARED evidence, the right epistemic status for a file in which a team
wrote down what it intends — but never as policy input here.

Nothing walks the filesystem looking for configuration. `--config` names a file
explicitly, because a gate that behaves differently depending on which directory
it ran from is a gate whose verdict cannot be reproduced. The two specs that
still referenced `.release-gate/methodology.yaml` have been corrected; that
resolution order was never implemented and contradicted protocol spec §16.

A misspelled key is **refused, not ignored**: a typo in a file whose whole job is
to tighten a gate would otherwise silently not tighten it.

---

## 10f. The event protocol (`AssuranceEvent`)

> **Implemented.** `release_gate/assurance/events.py` — `EventType` (20
> classes), `AssuranceEvent`, `events_to_records()`, `events_from_otlp()`;
> execution folding for envelopes in `ingest._execution_from`.

A vendor-neutral vocabulary for *things that happened*, which adapters target and
which converts into the records a case is already built from.

**A framework does not need to know release-gate exists.** That is the constraint
this was written under. OTLP spans carrying the GenAI semantic conventions
convert with nothing installed on the emitting side, and a team that has never
heard of this vocabulary still gets a case. Native emission is available —
a span may carry `assurance.event_type` directly — and is never required.

> **Naming.** Not to be confused with the protocol spec's
> `POST /cases/{id}/events`, which is the universal door for the *record*
> envelope. That endpoint carries records; this section describes things that
> happened, which convert into records before reaching it. Both names are in the
> wild and neither is worth renaming.

### 10f.1 An event is a claim about what happened, made by its emitter

That sentence is the whole design, and the twenty classes split cleanly on it.

| standing | classes | why |
|---|---|---|
| **OBSERVED** | `CASE_CREATED`, `RUN_STARTED`, `AGENT_STARTED`, `TASK_STARTED`, `TOOL_CALLED`, `ARTIFACT_CREATED`, `ARTIFACT_MODIFIED`, `VERIFICATION_STARTED`, `HUMAN_INTERVENTION`, `ACTION_PROPOSED`, `RUN_COMPLETED`, `CASE_FINALIZED` | the emitter is the authority on its own execution — a framework saying it called a tool is the best evidence anyone will have that it called that tool |
| **DECLARED** | `CLAIM_CREATED`, `CLAIM_SUPPORTED`, `CLAIM_CHALLENGED`, `ASSUMPTION_DECLARED`, `VERIFICATION_COMPLETED`, `COUNTEREXAMPLE_FOUND`, `CONTRADICTION_OPENED`, `CONTRADICTION_RESOLVED` | the emitter is asserting a conclusion about the world, and an assertion is not a finding however confidently it is serialised |

DECLARED is the **default** for anything not in the self-report set, so a class
added later is conservative until somebody argues otherwise.

### 10f.2 Two refusals, structural rather than checked

**No event can produce `VERIFIED`.** `VERIFICATION_COMPLETED` records that a
verifier reported a result; it does not make the thing verified. The typed
verification door — the only place VERIFIED is assigned, and only with a named
method (Invariant 8) — would otherwise be a formality anyone could route around,
and self-certification would cost one line of JSON. Tested against behaviour: an
agent emitting `VERIFICATION_COMPLETED` with `outcome: PASSED` on its own claim
gets a claim that reads `UNVERIFIED`.

**`CONTRADICTION_RESOLVED` does not close a contradiction.** It records that
somebody said it was closed. A contradiction is closed by evidence that answers
it, never by an announcement and never by a different branch succeeding
(Invariant 7). The conversion emits no `resolved` flag on anything, and a case
whose evidence genuinely points both ways still carries the contradiction after
the announcement.

Both are absent by construction rather than by a check that could be edited out:
`events_to_records()` only ever emits OBSERVED or DECLARED, and never writes a
resolution.

### 10f.3 OpenTelemetry where OTel has the concept

`trace_id`, `span_id`, `parent_span_id`, `timestamp_ns` (Unix nanoseconds), an
`attributes` bag, `resource` attributes and the three span status values — OTel's
names with OTel's meanings, rather than synonyms. The emitter is read from
`service.name`, which is where OTel already records who is speaking, and status
depends on knowing that.

A span with neither GenAI attributes nor an explicit `assurance.event_type` is
**skipped and counted**. An HTTP or database span from the same trace is real
work, but this vocabulary has no class for it and inventing one would put words
in the emitter's mouth. Likewise an unknown event class is **refused, not
dropped**: an emitter using a name we do not know has told us something we cannot
represent, and discarding it silently would understate what the run did.

### 10f.4 Converting telemetry must not be worse than reading it

The first working version of this was. The OTLP→trace adapter builds an execution
graph; OTLP→events→evidence-records built none, so `execution_reconstruction`
read NOT_ASSESSED on a run whose every tool call had been reported — the
vendor-neutral door was a strict downgrade from the one it generalises.

Fixed in two places: execution-describing events also emit an `execution` record
carrying the native trace shape, and `ingest._execution_from` folds `execution`
records out of an assurance envelope (it previously reconstructed only for
trace-shaped inputs). Both paths now agree on the execution graph, the capability
surface and the decision, which is asserted by a parity test rather than assumed.

---

## 10g. Completeness and evidence omission (`StreamCompleteness`)

> **Implemented.** `release_gate/assurance/completeness.py` —
> `StreamCompleteness`, `SourceStream`, `EndOfStream`, `StreamLedger`,
> `ledger_from_events()`; `stream_id`/`sequence`/`event_counter` on
> `AssuranceEvent`; phrasing fix in `NoUnresolved`.

Every other analysis here reasons about evidence that arrived. This one reasons
about evidence that did not, which is the harder question: **a producer that
wants a clean verdict does not forge a passing test, it declines to mention the
failing one.** Nothing downstream can see that.

### 10g.1 The asymmetry that shapes everything

**Derived detection is worth a great deal.** A span naming a parent that never
arrived, a sequence with a hole in it, a counter that went backwards: these are
observations release-gate makes about the stream's *own structure*, and a
producer suppressing a record has to suppress the structure too. Omission becomes
visible rather than silent.

**Declaration is worth much less, and signing does not change that.** A producer
stating "that was all of it" is telling you what it chose to say about what it
chose to send. Signing establishes *who said it* — attribution, not completeness
(Invariant 11). A party that omitted a record omits it from its own manifest too,
and its signature over that manifest is perfectly valid. `EndOfStream.to_dict()`
reports `signature_verified: false` and the epistemics would not change if it
were true.

| mechanism | kind | status |
|---|---|---|
| missing-span detection | derived | **already worked** — an unobserved parent yields `GAPS_DETECTED` |
| sequence numbers | derived | was a field nothing ever populated; now detected |
| monotonic event counters | derived | new — a regression means replay or reordering |
| source stream IDs | derived | new — omission hides in aggregation |
| expected source manifest | declared | existed (`ORCHESTRATION_MANIFEST`, `PRODUCER_MANIFEST`) |
| expected verifier manifest | declared | existed (`VERIFIER_INVENTORY`, `VerifierRequired`) |
| end-of-stream attestation | declared | new |
| signed completion declaration | declared | new — recorded, never treated as proof |
| producer identity | declared | existed |

### 10g.2 On having a `COMPLETE` value at all

`ExecutionCompleteness` deliberately has none: "nothing a graph can observe about
telemetry it received establishes that nothing was withheld, and a status value
saying otherwise would be the single most load-bearing lie in the system." That
reasoning is right for what it covers — raw spans, with no independent statement
of what should have been there — and **that enum is unchanged**.

This module has a value it does not, because it can require something that graph
cannot. `COMPLETE` needs **three** conditions, not one:

1. an **enumerated expectation from a party other than the producer**;
2. every enumerated stream present;
3. no derived gap anywhere — no sequence hole, counter regression, truncated
   tail or count shortfall.

Under those it says something real and bounded: *complete against that
enumeration*. It never means "nothing is missing" absolutely, because the
independent party could itself have been told a shorter story, and the note a
human reads says exactly that.

The guard that makes it safe is one branch: **a self-certified enumeration can
never reach COMPLETE**, whatever else is true. A producer counting its own output
— signed, matching, nothing visibly missing — is precisely what a successful
omission looks like from the inside, and it is the common case. It reports
`PARTIALLY_COMPLETE` with the reason.

`COMPLETENESS_UNKNOWN` is the default and is **not a failing grade**: it is the
correct answer whenever nobody supplied anything to check against, which is most
of the time. A stream with no numbering reports it rather than passing, because
"no shape for a hole to show up in" is a finding.

### 10g.3 Observed, not absent

The closing rule made concrete. `NoUnresolved` reported *"all 0 contradictions
record(s) are marked resolved"* on a case where detection merely found none —
phrased as though the set were closed. It now reads:

> none of the 0 contradictions record(s) held is unresolved; no contradictions
> was observed among what was submitted, **which is not the same as none
> existing**

and the predicate describes itself as "no unresolved contradictions **among those
observed**". Detection is structural and runs over the records a case *holds*; a
disagreement nobody submitted leaves no trace for it to find.

---

## 10h. Attestation chain (`AttestationChain`)

> **Implemented.** `release_gate/assurance/attestation.py` — `LinkStatus`,
> `ChainStatus`, `CustodyLink`, `SignatureMetadata`, `AttestationRef`,
> `chain_from_case()`; unresolved-parent retention in `ingest`.

The chain a decision rests on:

```text
agent event --digest--> tool output --digest--> verifier result
            --target digest--> evidence pack --digest--> human approval
```

**Every one of those links already existed as a field** — `parent_evidence`,
`applies_to_digest`, `target_digest`, `evidence_pack_digest`, and
`ProvenanceStatus` already had `CHAIN_VERIFIED` and `BROKEN`. What did not exist
is anything that *walks* them. This section is a traversal and a report over
links other modules already record; no producer has to adopt a new format.

### 10h.1 No blockchain, and the reason is not fashion

A blockchain answers "how do mutually distrusting strangers agree on an ordering
without a referee". That is not the question here. The question here is "can the
person holding this evidence recompute the digests and see that nothing was
swapped" — content addressing plus a traversal, with no consensus, ledger,
network or token. Every link is verifiable offline by anyone with the bytes,
which is strictly stronger than a chain of blocks nobody in the approval path can
audit.

### 10h.2 Two refusals, as properties rather than prose

**A chain establishes integrity, not truth.** An unbroken, fully signed chain
proves nothing was altered between the recorded steps and who put their name to
each. It does not establish that the agent was honest, the tool correct or the
verifier competent. `AttestationChain.establishes_truth` is an unconditional
`False` property and appears in `to_dict()`, so nothing downstream can read a
green chain as a green verdict (Invariant 11).

**Signatures are recorded here and verified elsewhere.** This package is
stdlib-only — the deterministic authoritative path imports no cryptography stack
— so `SignatureMetadata` carries signer, algorithm and key id and reports
`NOT_ASSESSED`. A `VALID` or `INVALID` state is accepted only when it names who
checked it, because this module verifies nothing and an unattributed result has
no standing. `establishes_correctness` is likewise unconditionally `False`: a
signature says *who*, never *whether*. (The container this was built in has a
`cryptography` wheel that cannot initialise at all, which made that an honest
test rather than a hypothetical one.)

### 10h.3 A missing link is UNLINKED, not BROKEN

Evidence that never claimed a parent has not been tampered with — it is silent
about its origin. Reporting that as a break would flood a case with alarms for
the ordinary shape of unchained evidence, and the real breaks would be lost in
them. So `LINKED` (a digest is named and resolves), `BROKEN` (named and does not
resolve, or resolves to something else), `UNLINKED` (nothing named).

### 10h.4 The signal that was being erased

`parent_evidence` resolution read
`tuple(id_map[p] for p in declared_parents if p in id_map)` — **a declared parent
this case does not hold was silently filtered out, with no note.** A record
claiming derivation from evidence that was never supplied is precisely "what was
used is not what is here", and the walker reported `CONTINUOUS` over it.

Unresolved parents are now retained on the record and noted at ingest, and the
chain reports them as `BROKEN`.

This also makes an id link a content link: `evidence_id` is
`short_id("ev", digest_object(identity()))`, so a parent whose content changed
hashes to a different id and the reference dangles. A dangling reference is
therefore a real integrity finding rather than a bookkeeping slip.

### 10h.5 What a bare case reports

Release-gate hashes its own input and records it as evidence applying to its own
digest, so the shortest possible chain is one hop that holds. `CONTINUOUS` on a
bare case means *the bytes we read are the bytes we hashed* — and nothing more,
which is why §10h.2 matters more than the status value does.

`ToolIdentity` (name, version, family, binary digest) is carried on a link when a
verifier says which build produced a result; a verifier that does not is recorded
as a named verifier, which is weaker and reported as what it is.

---

## 10i. Massive scale — measured, then fixed

> **Implemented.** `RetentionPolicy` / `RetainAll` / `RetainFirst` /
> `RetainRelevant` in `records.py`; the quadratic removed from
> `RecordCollectionBuilder.add`; single-pass identity in `evidence.py`;
> `tests/test_assurance_scale.py`.

**Measure before deciding, and do not introduce a graph database until the
measurements justify one.** They do not. Every target below is met by indexed
dicts and a streaming fold, on one core, in this container.

### 10i.1 What the measurements said

| target | result |
|---|---|
| **10,000,000 events** | 97s, **25.8 MB flat** — RSS identical at 1M, 5M and 10M |
| **100,000 agents / 1,000,000 records** | 10.3s, **26.7 MB** |
| **1,000,000 claims** | 30s, 1.35 GB (linear, retained in full) |
| **100,000 claims** | 3.8s, 164 MB |
| 500,000 evidence + contradiction detection | 0.80s — the PROMPT 25 fix holds |

Memory is genuinely bounded on the fold path: 10M events cost the same 25.8 MB
as 1M. The claim graph is the one structure that is O(n) in memory by design,
because a claim graph that dropped claims would be a different argument.

### 10i.2 Two real defects, both found by measuring

**A naive O(N²) in the hot path.** `RecordCollectionBuilder.add` checked for
duplicates with `any(r.record_id == record.record_id for r in self._materialised)`
— a linear scan over every held record, on every add. Measured at 41µs per
record over 2,000 records and **152µs over 8,000**: four times the work for twice
the input. A million records would have taken about five hours. Replaced with a
set of held ids, which is bounded by what is already retained and so costs no
asymptotic memory: now **flat at ~10.3µs from 2,000 to 128,000 records**.

This is why the bounded-memory design was not actually delivering bounded
memory — the fold was sound and the duplicate check in the same method defeated
it.

**Every evidence record was hashed twice.** `__post_init__` called
`canonical_json(self.identity())` purely to prove the identity canonicalises,
threw the result away, then called `digest_object(self.identity())` — which
rebuilds the identity and canonicalises it again. Two constructions and two JSON
encodings per record, on the hottest path in the system. Since
`digest_object(x)` is exactly `digest_bytes(canonical_bytes(x))`, building once
is **digest-preserving**: verified over 2,000 varied records that every
`evidence_id` is unchanged, which matters because every content-addressed
reference in the system derives from one. Record construction went from ~124µs to
~40µs, about 3x.

### 10i.3 Storage abstractions

`CaseRecord` (Protocol) already kept the container ignorant of what it contains.
What was missing was *which* records a bounded fold keeps — previously a
`materialise` boolean computed at each call site, which is how two call sites end
up disagreeing about what relevant means.

`RetentionPolicy` makes it a stated, reviewable decision, and the basis it
produces is derived from the policy rather than asserted:

| policy | holds | basis | meaning |
|---|---|---|---|
| `RetainAll` (default) | everything | `COMPLETE` | almost every real case |
| `RetainFirst(n)` | the first n | `CAPPED` | **not** SAMPLED — the first n is not a representative n |
| `RetainRelevant(pred, n)` | what the predicate picks | `RELEVANCE_DIRECTED` | the frontier shape: count four million calls, keep the dozen that bear on the conclusion |

Retention decides what is **held**, never what is **counted**: a dropped record
is still in the total and still in the commitment, and a fold that dropped
records reports `CAPPED` or `SUMMARY_ONLY` rather than `COMPLETE`. Two folds over
the same records produce the same `fold_digest` whether or not either kept
anything — tested.

### 10i.4 Batch, parallel and resumable

The multiset commitment is order-independent and associative, so six shards
merged in scrambled order produce a **byte-identical** `fold_digest` to a single
pass. That one property is what makes parallel ingest, batch submission and a
resumed run sound; it is asserted by test rather than assumed. A fold that cannot
vouch for its ids degrades the merged collection to `MATERIALISED_ONLY` rather
than letting the stronger half speak for the weaker.

### 10i.5 Memoized ancestry — measured, and deliberately not added

`depends_closure` is **not** memoized, and looping it over every claim is O(N²):
582µs per claim at 2,000 claims, 3,041µs at 8,000. But **no caller does that**.
`load_bearing` and `binding_constraints` traverse once per root, roots are few,
and the measured cost is flat at ~9µs per root.

Memoizing would trade that for O(N²) *memory* — each cached closure can be O(N)
and there are N of them — which is the worse failure at this scale. So the method
carries a docstring saying not to loop it and why, because a per-claim loop added
later would be a scaling bug that looks like ordinary code. The right answer, if
one is ever needed, is a single shared reverse traversal rather than a cache.

---

## 10j. Evidence compaction (`compact_case`)

> **Implemented.** `release_gate/assurance/compaction.py` — `RetentionReason`,
> `CompactionBudget`, `CompactionReport`, `classify()`, `compact_case()`,
> `verify_drill_down()`.

A frontier run produces four million model calls. The engine must not hold four
million model calls, and must not pretend they did not happen. Compaction keeps
the argument and drops the bulk while the count and the commitment stay exactly
what they were.

### 10j.1 Three properties, in the order they matter

**1. Critical-path drill-down survives, unconditionally.** A record on the path
from the decision to the reason is retained whatever the budget says. The budget
bounds the *residue* — what is left after everything the retain list names has
been kept — and never the argument. If the argument alone exceeds the budget, the
budget is **exceeded and reported**, never honoured by evicting a critical node.
Verified on a case of 2,000 bulk records with a residue budget of **zero**: the
whole argument survives, including the evidence arguing *against* the claim.

**2. Deterministic.** The retained set is a function of the records, not of the
order they arrived in. `RetainFirst` (§10i) was not: the same evidence sharded
six ways kept six different sets while committing to one digest, so two runs
agreed on what existed and disagreed on what could be inspected. Selection orders
by **content digest**, which is stable across shards, reruns and resumptions —
asserted by permuting a collection and getting a byte-identical retained set.
Compaction is also idempotent.

**3. The commitment is untouched.** A compacted record is still in `total_count`
and still folded into `fold_digest`. Measured: 4,006 evidence records → **22
held, 4,006 counted, identical fold digest**. Compaction can never be used to
quietly change what a case says it saw, and a compacted collection stops calling
itself `COMPLETE`.

### 10j.2 The retain list, as named reasons

Every surviving record carries *why*, so a reviewer asking "why is this here and
that not" gets an answer from the case rather than from whoever wrote the policy.

| reason | what it covers |
|---|---|
| `CRITICAL_NODE` | on a path to the decision |
| `DEPENDENCY_EDGE` | a parent of a critical claim, or an artifact something points at — without it drill-down stops one hop short of the reason |
| `FINAL_DEPENDENCY` | what the decision ultimately rests on |
| `VERIFICATION` · `FAILURE` · `CONTRADICTION` · `ASSUMPTION` · `COUNTEREXAMPLE` · `COVERAGE` | whole collections, retained entire — these *are* the retain list, and a case that compacted them would have compacted away its own findings |
| `EXTERNAL_REFERENCE` | holds a pointer to raw evidence |
| `DIGEST_ONLY` | compacted: counted, committed, not held |

**Evidence that contradicts a claim is never bulk.** A compaction that kept the
supporting half and dropped the objecting half would be the most dangerous edit
this engine could make to itself, so it is a retention reason in its own right
rather than something that happens to survive.

### 10j.3 Raw evidence lives outside

A compacted record keeps its `ContentReference`, so the bytes stay fetchable from
wherever they actually are. Release-gate holds the digest and the reference; the
object store holds the object. Nothing here deletes anything from anybody's
system — this is only about what the *engine* carries. A record with an external
reference is retained for that reason alone: it is cheap, and it is the handle
that makes compaction safe.

### 10j.4 Measured

20,000 bulk records plus a four-record argument, residue budget 50: **fewer than
200 records held**, over 20,000 counted, drill-down intact. The basis reports
`CAPPED` rather than `SAMPLED`, because the residue slice makes no claim to be
representative even though the retained argument was chosen on purpose.

---

## 10k. Streaming assurance (`AssurancePhase`)

> **Implemented.** `release_gate/assurance/streaming.py` — `AssurancePhase`,
> `PhaseObservation`, `PhaseTransition`, `observe_phase()`, `observe_session()`.

A case can stay open for hours. Agents keep working, evidence keeps arriving, and
a reviewer wants to know where things stand *now* — not after everything stops.

### 10k.1 The constraint that shapes it

**Release-gate must not become the orchestrator.** Every phase here is an
observation about evidence, never an instruction. There is no
`begin_verification()`, no `request_review()`, nothing imperative — asserted by a
test that scans the module for imperative names. `observe_phase()` is a pure
function of a case: the same case always yields the same phase, reading it
changes nothing, and reading a live session does not finalize it.

Release-gate reports `VERIFYING` because verification attempts are arriving, not
to announce that verification should begin. `PhaseObservation.directs_work` is an
unconditional `False`. When a case sits in `EVIDENCE_ACCUMULATING` with an
unresolved contradiction, release-gate says so and stops: it does not pause the
agents, schedule a verifier or retry anything. An orchestrator watching may do
all three — that is its job, and the separation is what lets one assurance engine
sit behind many orchestrators without owning any.

**Transitions are reported, never enforced.** Release-gate cannot refuse a
transition because it does not control the world: if evidence arrived after a
human started reviewing, that happened. A backward move is a *finding* — the
reviewer holds a view about a case that has since changed — not an error to
reject. There is deliberately no `permitted()` and no `enforce_transition()`.

### 10k.2 Two axes, deliberately not merged

`CaseState` (DRAFT / SEALED / APPROVED / SUPERSEDED / INVALIDATED) is the
*record's* integrity lifecycle: SEALED means the digest is fixed and a verdict
may be attached. `AssurancePhase` is the *work's* progress. Folding them would
mean a case could not be both "evidence still arriving" and "this snapshot is
sealed and digested" — which is what a long-running case is every time somebody
reads it, and is asserted directly.

### 10k.3 The eight phases, and what each is read from

| phase | read from |
|---|---|
| `OPEN` | nothing **submitted** has arrived |
| `EVIDENCE_ACCUMULATING` | records arriving, nothing identifiable asserted |
| `CANDIDATE_READY` | a claim or a submitted artifact exists, nothing has checked it |
| `VERIFYING` | verification attempts recorded, settled or not, case still open |
| `HUMAN_REVIEW` | a verdict rendered on a sealed case, unanswered |
| `APPROVED` · `REJECTED` | a person's decision, read rather than inferred |
| `INVALIDATED` | the case record or the approval says what was judged has moved |

### 10k.4 Three derivation defects, found by driving a case through

**Every session reported `CANDIDATE_READY` before anyone sent anything.**
Release-gate records its own work as evidence — the input container it hashed,
plus the consequence, independence and criticality profiles it derived — so an
empty case already held three evidence records. Submitted work now means work
whose producer is somebody other than release-gate; a record with no producer at
all was not submitted by anybody. `OPEN` was unreachable before this.

**The subject digest could not mark a candidate.** Release-gate always sets one,
because it hashes whatever it was handed, so every case looked like it had a
candidate from the first record and `EVIDENCE_ACCUMULATING` was unreachable too.
What makes a candidate is somebody *asserting* something — a claim, or an
artifact submitted with a digest. Raw trace evidence piling up is work happening,
which is a different thing.

**A passed test suite read as "nothing has checked it".** Attempts submitted
through the envelope arrive embedded on their claims, so the `verification`
collection stays empty and counting it was wrong. Read through
`VerificationGraph` instead, which folds both places attempts live.

### 10k.5 Weaknesses while the work continues

`observe_session()` runs the provisional analysis, so a caller gets what
release-gate can already see while the external system is still operating — a
contradiction detected at minute three is worth far more than the same
contradiction at hour six. Reading does not finalize the session, and more
evidence can arrive afterwards.

---

## 10l. The assurance query API (`run_query`)

> **Implemented.** `release_gate/assurance/query.py` — `QueryResult`,
> `QueryOutcome`, eleven queries, `QUERIES`, `run_query()`, `run_all()`.

Eleven questions, answered **from the case rather than recomputed**. Every query
reads an analysis the engine already performed; none re-derives criticality,
re-detects contradictions or re-walks the artifact graph. A query that computed
its own answer would eventually disagree with the verdict that was rendered, and
a reviewer would have two numbers and no way to tell which one the gate used.
`blockers` in particular reads the rendered verdict's own fired rules.

### 10l.1 Empty must never be able to mean "nobody looked"

An empty answer means one of two things and the API refuses to blur them:

| outcome | meaning |
|---|---|
| `FOUND` | these matched |
| `NONE_FOUND` | the analysis ran and nothing matched — a real, load-bearing answer |
| `NOT_ASSESSED` | the analysis this question needs was never performed |

"Which critical claims are unverified" answering *none* on a case where
criticality could not be derived would be the most comfortable lie this system
could tell. `answered` distinguishes the two, and `NOT_ASSESSED` notes say
"this is unknown, not none".

The distinction is finer than it first looks. Assumption analysis always runs, so
an empty assumptions answer is `NONE_FOUND` — and its basis still refuses the
overclaim: *"an argument that declares none is not an argument without any."*
Approvals are the opposite: a case does not go looking for an approval it was
never given, so that query answers `NOT_ASSESSED` rather than "none are stale".

### 10l.2 The eleven

| query | reads |
|---|---|
| `unverified_critical_claims` | criticality + verification |
| `blockers` | the rendered verdict |
| `missing_evidence` | required evidence (§10 PROMPT 26) |
| `artifacts_changed_after_verification` | `ArtifactGraph.stale_verifications()` |
| `single_root_claims` | `CriticalitySet.thin()` |
| `open_contradictions` | `ContradictionLedger.open()` |
| `assumptions_affecting_result` | `AssumptionGraph.load_bearing()` |
| `unresolved_verifier_failures` | verification attempts that FAILED or were INVALIDATED |
| `stale_approvals` | `check_approval()` against supplied approvals |
| `unknown_completeness_sources` | a supplied `StreamLedger` (§10g) |
| `hold_resolution` | required evidence with HOLD effect |

`run_all()` never omits a query it could not answer: a caller reading the sweep
must see that a question was asked and came back unknown, not find it missing and
assume it did not apply.

### 10l.3 Three bugs, and the pattern that hid two of them

Writing these against real cases surfaced three defects, two of which were
masked by defensive coding:

* **`open_contradictions` reported none on a case holding one.** The code read
  `getattr(ledger, "unresolved", lambda: ())()` — the ledger's method is
  `open()`, so the default returned an empty tuple and a wrong method name became
  a clean bill of health. Now called directly: a missing method must fail loudly,
  not answer reassuringly.
* **`artifacts_changed_after_verification` raised**, because
  `verification_currency()` takes one logical id; the graph's own answer to this
  question is `stale_verifications()`. The sweep's exception guard turned the
  raise into `NOT_ASSESSED` — a broken query reporting "not assessed" is exactly
  what this module must not ship.
* **`single_root_claims` raised** calling `len()` on `supporting_producers`,
  which is a count rather than a collection.

The lesson worth keeping: `getattr(x, "name", default)` on a *method* converts a
typo into a plausible answer. That is tolerable for optional attributes and
dangerous for the API of an analysis whose silence means "all clear".

---

## 11. Methodology behaviour

* **Resolution order.** Explicit `--methodology` → an organisation
  configuration the caller named (`--config`, JSON) → built-in default for the
  subject type → `NONE`. **Never YAML, and never discovered by walking the
  filesystem**: a gate that behaves differently depending on which directory it
  ran from is a gate whose verdict cannot be reproduced (§10e).
* **`NONE` is legal and loud.** Structural analyses run; the sufficiency question
  answers `METHODOLOGY_REQUIRED`; the verdict cannot be PROMOTE for an
  irreversible high-consequence subject.
* **Overrides are evidence.** A human waiving a requirement produces a `REVIEW`
  evidence record with identity, scope and rationale, and it enters the binding.
  `non_overridable_conditions` cannot be waived at all; attempting it is a BLOCK
  with a named rule.
* **Versioned and bound.** The methodology id and version sit in the case digest,
  so tightening a methodology invalidates prior approvals rather than silently
  re-grading them.
* **`METHODOLOGY_MODEL_VERSION` is 3.** Bumped when `CoverageDimensionDeclared`
  gained `require_assessed` (§10b), and again when methodologies gained
  `accepted_findings` (§10c). A methodology serialised under v1 still
  loads — the field defaults to `False`, which is the old behaviour exactly — but
  its **digest changes**, because the predicate now serialises one more key.
  Anything that pinned a v1 methodology digest must re-pin. Stated rather than
  hidden: a digest that silently changes meaning is the failure content
  addressing exists to prevent.

---

## 12. Expected scaling characteristics

The frontier case is the design constraint: ~10^4 workers, ~10^6 model calls,
thousands of hypotheses, most of it irrelevant to the proposition.

* **Streaming ingest, bounded memory.** Adapters emit records; the engine folds
  them into graph summaries. The fold is commutative and associative so parallel
  ingest is deterministic. Raw records land in a content-addressed append-only
  store; the engine holds the reduced graph.
* **Relevance-directed materialisation.** Start from the proposition, walk
  backwards. Only execution on a path to a cited claim is materialised. Everything
  else is counted, digested and summarised — and the count is *reported*:
  `execution materialised: 12,431 of 4,120,884 nodes (relevance-directed)`. Silent
  truncation is the failure this bullet exists to prevent.
* **Sampling is typed evidence.** If anything is sampled, the sample is an evidence
  record with a stated method, and the remainder is `NOT_ASSESSED` — never "clean".
* **Attention is O(relevant), not O(total).** Ranking runs over the claim graph
  (thousands of nodes), not the execution log (millions).
* **Complexity targets.** Ingest linear in records, constant memory per record.
  Analyses linear in the *reduced* graph. Attention linear in claims × average
  dependents. Nothing quadratic in agent count.

---

## 13. Security and trust boundaries

* **All ingested evidence is untrusted input.** Traces, claims and artifacts come
  from agents and third-party platforms. Parsing is defensive, stdlib-only, with
  no vendor SDK and no code execution — exactly today's adapter posture.
* **Provenance ≠ trust (Invariant 11).** The engine reports origin and attestation
  state; how much authority an origin carries is a methodology decision, reported
  separately. No merged "trust score" exists anywhere in the data model.
* **Self-attestation is detected and named.** A producer supporting its own claim
  is flagged, never counted as corroboration.
* **Signing.** Evidence may be signed; approvals are signed. Key handling reuses
  `release_gate/crypto`. Unsigned evidence is usable and labelled `UNSIGNED`,
  because a tool that only works with a PKI in place serves nobody at day zero.
* **The engine never executes ingested content.** No `eval`, no dynamic import, no
  shell — the same rule release-gate flags others for breaking.
* **MCP surface stays read-only** and root-constrained, as it is today.
* **Hosted API.** Evidence may contain sensitive payloads; the store is
  content-addressed with per-tenant isolation, and payload storage is opt-in with
  digests-only as the default.

---

## 14. Proposed module boundaries

New package, additive. Nothing below imports from `release_gate_api`; nothing in
the core gains a dependency.

```text
release_gate/assurance/
  __init__.py            public API: build_case, decide, render_packet
  case.py                AssuranceCase, AssuranceSubject, Consequence, Proposition
  evidence.py            EvidenceRecord, EpistemicStatus, VerificationMethod, status calculus
  canonical.py           canonical JSON, digests, CaseBinding  (rg-bind-1)
  methodology.py         AssuranceMethodology, Requirement, resolution order
  methodologies/         builtin: software-change-v1, production-database-change-v1,
                         general-agent-action-v1, research-mathematics-v1
  graphs/
    evidence_graph.py    mandatory
    execution.py         optional overlay
    claim.py             optional overlay (+ load-bearing computation)
    artifact.py          optional overlay
    verification.py      optional projection
  ingest/
    registry.py          producer registry + the status-assignment boundary
    from_audit.py        audit.build_report        -> evidence   (ADMISSION)
    from_traces.py       adapters/*                -> ExecutionGraph + evidence
    from_evals.py        evals/runner, promptfoo   -> evidence
    from_behavioral.py   agent_score, loop_sim     -> evidence
    from_lockfile.py     lockfile                  -> ArtifactGraph + drift evidence
    from_governance.py   governance.yaml           -> DECLARED evidence
    from_envelope.py     the emission protocol (declared claims/evidence/artifacts)
    verifiers.py         external verifier adapters (proof assistants, SMT, model
                         checkers, type checkers, compilers, test frameworks) -> attempts
  analyzers/
    provenance.py  coverage.py  contradiction.py  independence.py  drift.py  completeness.py
    replication.py       paths to a result, copies collapsed
    adversarial.py       verifiers that set out to disprove the candidate
    criticality.py       what the decision rests on, by dependency
    expectation.py       denominators: what was expected, what arrived
    required_evidence.py the outbound protocol: typed, targeted, dispatchable
  policy.py              deterministic verdict; ADMISSION delegates to audit.apply_decision_mode
  attention.py           HumanAttentionSet, leverage computation, RequiredEvidence
  packet.py              ApprovalPacket: the eleven questions (§8a)
  approval.py            BoundApproval + check_approval (§9); signing via release_gate/crypto
  store.py               content-addressed local evidence store
```

Boundary rules, stated so review can enforce them:

1. `analyzers/` may not import `ingest/` — analysis never re-reads raw input.
2. `ingest/` is the only place `epistemic_status` is assigned.
3. `policy.py` is the only place a verdict is produced.
4. Nothing under `assurance/` may import an LLM client. Enforced by a test that
   greps the package, in the spirit of the existing no-network guarantees.
5. `case.py` has no dependency on `audit.py`; the coupling runs the other way
   through `ingest/from_audit.py`, so the assurance core never knows what a repo is.

---

## 15. Migration and backward compatibility

### 15.1 The contract

Everything that exists today keeps working identically: `audit`, `pr`, `score`,
`compare`, `ingest`, `evidence-pack`, `impact`, `run`, `verify`, `loop-sim`,
`agent-score`, `lock`, `validate-and-lock`, `pricing-lock`, `init`, `demo`; all
flags; all JSON keys; SARIF; markdown and PR comments; badge URLs; Action inputs
and outputs; MCP tools; API endpoints; exit codes `0 / 10 / 1`.

### 15.2 New surface (all additive)

```text
release-gate case build <target>        # construct an AssuranceCase, emit JSON
release-gate case show <case.json>      # human rendering + attention set
release-gate decide <subject>           # DECISION plane verdict + packet
  --action "..."        what approval would authorise     (required)
  --claims <file>       declared claims (envelope)
  --evidence <file...>  evidence envelopes / platform exports
  --traces <file>       existing trace inputs
  --methodology <id|file>
release-gate approve <case.json>        # produce a BoundApproval (signed)
release-gate verify-approval <approval> # VALID | STALE | INVALIDATED | SUPERSEDED
```

Plus optional flags on existing commands — `audit --case out.json`,
`pr --case out.json` — that *additionally* write the case without altering
existing output. New Action outputs (`case-digest`, `attention-count`) are added
below the existing ones. New MCP tools are read-only.

### 15.3 How the ADMISSION plane stays identical

`ingest/from_audit.py` calls the existing `build_report()` and converts its output
into evidence records. The ADMISSION verdict is **not recomputed** by new logic —
`policy.py` delegates to `apply_decision_mode()` and returns its result verbatim.
A golden corpus of existing reports is asserted equal before and after, at the
JSON level. If that test cannot be made to pass, the design is wrong and gets
fixed, rather than the expectations being lowered.

### 15.4 Phasing

| Phase | Delivers | Gate to pass before the next phase |
|---|---|---|
| 0 (this document) | Architecture | Reviewed against §0.10 |
| 1 | `case.py`, `evidence.py`, `canonical.py`, `store.py`, `from_audit.py`; `release-gate case build` for ADMISSION | ADMISSION verdicts byte-identical on the golden corpus; determinism tests green |
| 2 | `ExecutionGraph` + `ClaimGraph`, envelope protocol, coverage/contradiction/drift/completeness analysers, `release-gate decide` | The one-engineer migration case (§B.1) works end to end with no new config |
| 3 | Independence, attention engine, packet, binding, approvals | The 20–100 agent case (§B.2); staleness tests green |
| 4 | Streaming fold, relevance-directed materialisation, frontier adapters (provers, replication harnesses), optional non-authoritative LLM explanation lane | 10^6-step synthetic ingests in bounded memory with honest counts |

---

## 16. Persistence implications

* **Local CLI stays file-based.** `.release-gate/evidence/` holds a
  content-addressed store (`sha256/xx/xxxx…json`) plus `cases/<case_id>/<version>.json`.
  No database, no service, no daemon. Git-ignorable; nothing is required to be
  committed.
* **Content addressing is the storage model.** Deduplication is free, and evidence
  is immutable by construction — an edit is a new record, which is what drift
  detection needs.
* **Append-only.** Records are never mutated or deleted by the engine. Retention
  is the operator's decision, and a pruned store reports reduced coverage rather
  than silently losing evidence.
* **Hosted API.** `runs` keeps its current shape. New tables (`assurance_cases`,
  `evidence_index`, `approvals`) are additive, per-tenant. Default is
  digests-and-metadata; payload storage is opt-in per tenant.
* **Scale.** The frontier store is the one place large data lands, and it is
  designed for external object storage behind the same interface. The engine's
  working set is the reduced graph, not the store.

---

## 17. Protocol plan

### 17.1 Evidence emission envelope

A JSONL file (or stream) of records typed `claim`, `evidence`, `artifact`,
`execution`, `completeness`. Producers append; order does not matter. Schema and
worked examples: `docs/specs/assurance-data-model.md`. Design rules: stdlib-parseable,
no SDK required, every record self-describing with its producer, and unknown
fields preserved rather than dropped.

### 17.2 Adapters for teams that emit nothing yet

OTel / Langfuse / Phoenix / promptfoo exports already carry execution and eval
evidence; the existing adapters gain a `to_evidence()` projection. Git supplies
artifact lineage. CI supplies test evidence. What cannot be derived is reported as
`NOT_ASSESSED` with a named remedy — the same honesty contract the current
`Coverage` object already implements.

### 17.3 Surfaces

* **CLI** — §15.2.
* **GitHub Action** — new optional inputs (`methodology`, `case-output`) and
  outputs (`case-digest`, `attention-count`); existing ones untouched.
* **Hosted API** — **superseded by `docs/specs/assurance-protocol.md`.** The
  four-endpoint sketch that stood here was written before the case model existed
  and does not survive contact with streaming, out-of-order and concurrent intake.
  The protocol spec is the design; in summary, the surface is
  `/api/v1/assurance/cases…`, intake is an append-only content-addressed ledger
  with an order-independent fold, and no decision is available before an explicit
  `finalize`. Existing endpoints unchanged.
* **MCP** — read-only `build_assurance_case`, `explain_attention_item`. An agent
  may inspect its own case; it can never approve one. That asymmetry is the whole
  point of the product and is enforced at the tool boundary, not by convention —
  concretely, by scope: the MCP server never requests `assurance:decide` or
  `assurance:approve` (protocol spec §13).

---

## 18. Conflicts between the master invariants and today's behaviour

The contract says: if an implementation conflicts with an invariant, stop and
explain rather than silently reinterpret. Four conflicts exist in the current code.
None is a bug in today's product, and each would become an invariant violation if
inherited by the assurance plane. **The resolution in every case is the same
shape: today's legacy output is preserved unchanged, and the assurance path
refuses to launder the value.**

### 18.1 `ReadinessScorer` scores unknown as 50

`release_gate/readiness_scorer.py` sets `eq = 50` when there are no eval results,
and `obs = 50` by default. Missing evidence becomes a number, which then flows
into a weighted average and a PROMOTE/HOLD/BLOCK. That is Invariant 3.

*Resolution.* `score` keeps its current numbers. Evidence ingested from it is
`DECLARED`/`DERIVED` with an explicit `coverage_note`; absent evals become a
`NOT_ASSESSED` coverage row, and no 50 enters any assurance computation.

### 18.2 `_confidence()` is a proxy, not evidence

The same module returns `high`/`medium`/`low` from how many *kinds* of input were
supplied. Presence of inputs is not confidence in a result; it reads as an
epistemic claim and is not one.

*Resolution.* The assurance plane has no scalar confidence field. It reports
coverage and independence, which is what the proxy was reaching for. The legacy
field stays in the legacy output.

### 18.3 `TraceValidator` returns PASS when no policy is declared

`trace_validator.py::validate()` computes
`status = FAIL if violations else (WARN if warnings else PASS)`. With an empty
`trace_policies` there can be no violations, so an unpoliced trace returns **PASS**.
Missing policy becomes a pass — Invariant 3, in the module most central to the
DECISION plane.

*Resolution.* Fix at the ingest boundary, not in the validator (whose current
behaviour other consumers depend on): `from_traces.py` maps *PASS with an empty
policy set* to `NOT_ASSESSED`, and the coverage matrix says "trace policy: none
declared". Changing the validator's own default is a separate, breaking decision
for a future major version, and is recorded here rather than made silently.

### 18.4 `build_report` falls back to score 100 / PROMOTE

In `audit.py`, the `not_deployed_agent` branch sets `score, decision = 100, "PROMOTE"`
when the code-safety axis is not applicable. Nothing assessed becomes a perfect
score. In context it is defensible — the report also says "not a deployed agent" —
but as evidence it is an Invariant 3 violation.

*Resolution.* `from_audit.py` never converts that 100 into evidence of anything. It
emits a `NOT_ASSESSED` coverage row with the reason. Today's report output is
unchanged.

---

## 19. Failure modes and honest limits

### 19.1 Claim extraction is the hard problem

There is no deterministic way to read an agent's prose and know what it is
asserting. Extracting claims with an LLM and then ruling on them would put a model
in the authoritative path (Invariant 4) and would make the verdict depend on an
extraction we cannot reproduce.

*Design answer.* Claims are **declared** by the producing system through the
envelope. An LLM-assisted extraction lane may exist, but its output is `DECLARED`
evidence marked `model-derived`, is never `VERIFIED`, and cannot satisfy a
requirement on its own. **Consequence, stated plainly: without producer
cooperation the DECISION plane is limited to what traces and artifacts show, and
the claim-coverage row reads `NOT_ASSESSED: no declared claims`.** That is a real
product limitation and belongs in the docs, not in a caveat nobody reads.

### 19.2 Independence has a floor we cannot see

Structural independence cannot detect shared pre-training, a shared upstream
corpus, or a common unstated assumption. Every independence output therefore
carries `independence_basis: structural` and an explicit not-assessed note. We
never emit the word "independent" unqualified.

### 19.3 Evidence omission

A producer that hides failures looks clean. The completeness analyser catches what
is catchable (sequence gaps, manifests, heartbeats); where it cannot, the answer is
`UNKNOWN`, and the packet states that "not observed" is not "did not happen".

### 19.4 Graph explosion and relevance error

Relevance-directed materialisation can miss something relevant. Mitigation:
materialisation is *declared* (counts reported), the relevance rule is documented
and deterministic, and refuting evidence is never deprioritised by it — refutations
are materialised regardless of distance from the proposition.

### 19.5 Methodology capture

An organisation can write a methodology that admits weak evidence. Mitigation:
methodology id and version are in the binding and printed on the packet, built-ins
are signed, and `non_overridable_conditions` exist so a methodology cannot waive
integrity or contradiction blocks.

### 19.6 Adoption cost

DECISION asks for evidence most teams do not emit. Mitigation: degrade honestly
from what they already emit, make every gap a named row with a remedy, and make
the zero-config path produce something useful on the first run.

### 19.7 Over-trust in the packet

A clean packet may read as "this is fine". Mitigation: Invariant 15 wording is
part of the rendering spec; coverage sits next to the verdict, never below the
fold; and the phrase "safe to deploy" remains banned in every surface.

---

## 20. Acceptance tests

Written against the architecture, to be implemented per phase. Style follows the
repo: deterministic, fast, no network.

**Invariant tests.**
1. `DECLARED` never becomes `VERIFIED` without an independent verification record — property test over generated evidence sets.
2. Parent claim status never exceeds the minimum over its `DEPENDS_ON` children.
3. Refutation beats any volume of support on the same claim.
4. Dropping any field from any input never improves a verdict (fuzz).
5. A `Verdict` cannot be constructed without a `CoverageMatrix`.
6. No ratio is emitted where `expected` is `UNKNOWN`.
7. 10,000 clones of one run yield `independent_groups == 1`.
8. A refuted branch survives ingest and appears in attention when load-bearing.
9. Flipping one byte of the subject marks every prior approval `STALE`.
10. No module under `release_gate/assurance/` imports an LLM client, and the full decision path runs with network disabled producing identical verdicts.
11. A trace validated against an empty policy set yields `NOT_ASSESSED`, never `PASS` (§18.3).
12. `UNKNOWN` and `NOT_ASSESSED` never collapse into each other across a full round trip.

**Determinism tests.**
13. Same inputs → byte-identical `case_digest`, across runs and platforms.
14. Shuffled and parallel ingest → identical graphs and digests.
15. Canonicalisation excludes exactly the documented volatile fields, no more.

**Compatibility tests.**
16. Golden corpus: `audit` / `pr` / `score` JSON, SARIF, markdown, badge, exit codes identical before and after.
17. ADMISSION verdict equals `apply_decision_mode()` on every corpus repo.
18. Existing Action outputs and MCP tool payloads unchanged.

**Scale tests.**
19. 10^6-step synthetic execution stream: bounded memory, reported materialisation counts, attention set computed in the claim-graph budget.

**End-to-end tests.**
20. The three worked examples in Appendix B produce the stated verdicts, attention sets, and coverage rows.

---

## Appendix A — invariant → enforcement point

| # | Invariant | Enforced by | Fails loudly when |
|---|---|---|---|
| 1 | Evidence over assertion | `ingest/registry.py` status boundary (§4.4) | A producer's `"verified": true` becomes anything but `DECLARED` |
| 2 | Preserve epistemic status | `evidence.py` status calculus (§4.2) | Any component writes a status directly, or a transform upgrades one |
| 3 | Unknown is first-class | Status calculus + `CoverageMatrix` constructor | Missing input maps to a number, a pass, or a silent default |
| 4 | Deterministic authoritative path | `policy.py` purity + no-LLM import test (§14 rule 4) | Any model output reaches the verdict, or a verdict is irreproducible |
| 5 | Approval binds exact state | `canonical.py` + `approval.py` (§9) | A changed digest leaves an approval `VALID` |
| 6 | Scale ≠ confidence | `analyzers/independence.py` (§6.4) | Agreement is reported without `independent_groups` |
| 7 | Failed branches are evidence | `polarity` field + `analyzers/contradiction.py` | A refutation is dropped or closed by an unrelated success |
| 8 | Verification is typed | `VerificationMethod` required for `VERIFIED` | A `VERIFIED` record has no method |
| 9 | Coverage accompanies every verdict | `Verdict` constructor + §8.2 rule | A verdict lacks coverage, or a ratio has no real denominator |
| 10 | No universal truth claims | Packet rendering spec + banned-language test | A surface asserts safe/correct/true |
| 11 | Provenance ≠ trust | `analyzers/provenance.py` reports origin only | Origin and authority are merged into one score |
| 12 | Dependency criticality beats volume | `criticality.py` reachability from the decision (§6.2a), then `attention.py` leverage (§7) | Criticality or ranking keys on counts, producers, depth or generic severity |
| 13 | Evidence omission is a threat | `expectation.py` denominators and self-certification (§8.2), `analyzers/completeness.py` (§6.6) | "Not observed" is rendered as "did not happen"; a producer's count of itself is read as coverage |
| 14 | Not every graph is mandatory | Optional overlays in `case.py` (§3.2) | A small case is forced to populate a claim graph |
| 15 | Approval is authorisation, not truth | `BoundApproval.statement` + rendering spec | A packet implies certification |

---

## Appendix B — the three scales, worked

### B.1 Smallest — one engineer, one migration

**Subject.** `migration_2026_09_12_add_index.sql`, digest `sha256:9f2c…`.
**Requested action.** Apply to `prod-eu`.
**Methodology.** `production-database-change-v1` (built-in).
**Evidence.** The artifact (OBSERVED); the agent's execution trace (OBSERVED); the
agent's statement that it is backward-compatible (DECLARED); a dry-run against a
staging snapshot (VERIFIED, `SIMULATION`, against digest `9f2c…`); no rollback
script found (UNKNOWN).

**Verdict.** HOLD.
**Attention set (2 items).** (1) No rollback path for an irreversible change —
load-bearing, gates the whole action. (2) Backward compatibility is `DECLARED`
only; the dry-run covered schema, not application queries.
**Required evidence.** A rollback script, or an explicit human acceptance of
irreversibility recorded as a `REVIEW` record.
**Coverage.** Staging dry-run `OBSERVED`; production data distribution
`NOT_ASSESSED`; application-level compatibility `UNKNOWN`.

No claim graph. No independence analysis. One artifact node. Progressive assurance
doing its job.

### B.2 Medium — 40 agents, one recommendation

**Subject.** A vendor-migration recommendation document, digest `sha256:71ab…`.
**Requested action.** Adopt as the engineering plan for Q4.
**Evidence.** 40 agent execution traces (OBSERVED); 18 declared claims; 6 claims
with test-suite verification; 3 contradictions between agents on cost estimates;
one abandoned branch that found a licensing blocker, never addressed.

**Verdict.** HOLD.
**Attention set (4 items).** (1) The licensing blocker from the abandoned branch —
`REFUTES` an unresolved load-bearing claim. (2) Cost contradiction between three
agents, all descended from one research agent — `independent_groups: 1` against
`agreeing_records: 3`. (3) A load-bearing assumption that the current contract
allows transfer, `DECLARED` only. (4) Two claims verified against a superseded
document digest — drift.

This is the case the master contract describes: the failed branch is the most
important thing on the page, and volume of agreement is worth less than the one
refutation.

### B.3 Frontier — 10,000 workers, one proof

**Subject.** A proof of Theorem T, digest `sha256:c41d…`.
**Requested action.** Publish as a verified result.
**Methodology.** `research-mathematics-v1` — `FORMAL_PROOF` and
`THEOREM_PROVER` admissible for load-bearing lemmas; `CROSS_MODEL_REVIEW` is not.
**Evidence.** 4.1M model calls (counted, 12,431 materialised); 3,114 candidate
lemmas; 2,996 machine-checked; 118 unproven, of which 3 are load-bearing; 41
counterexamples, 40 resolved, 1 open against a lemma in the main line; verifier
agents V1–V17, of which 14 share one prompt template.

**Verdict.** BLOCK.
**Fired rule.** Unresolved counterexample against a load-bearing lemma.
**Attention set (3 items).** (1) The open counterexample. (2) Lemma L-887 —
`DECLARED` only, load-bearing, no admissible verification. (3) Verifier
independence: 17 verifiers, 4 independent groups, and the methodology requires 3
independent verifications for a load-bearing lemma — L-2210 has 11 verifications
in a single group.
**Coverage.** Execution materialised 12,431 of 4,120,884 (relevance-directed);
lemma verification 2,996 of 3,114 (`expected` from the lemma manifest — a real
denominator); latent verifier correlation `NOT_ASSESSED`.

A human reads three items instead of four million calls, and the engine never once
says the theorem is true.
