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

The projection that answers "what was checked, by whom, with what method, against
which digest, and did it still apply?" It is derived from evidence records with a
`verification_method`, and it is the structure the approval packet renders.

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

### 6.4 Independence (`RG-INDEP-*`)

The mechanism behind Invariant 6. Each evidence record gets a **provenance
fingerprint**: model family, prompt template digest, tool identity, input artifact
closure, producer lineage, execution environment, seed source. Records sharing a
designated dimension land in the same `IndependenceGroup`.

Output is always a pair, never a single number:

```text
agreeing_records: 8,214
independent_groups: 2
independence_basis: structural
not_assessed: latent correlation (shared pre-training, shared upstream corpus)
```

Ten thousand descendants of one root collapse to one group. The final clause is
mandatory and non-removable: structural independence is what we can see, and we
say so rather than implying more (Invariant 10).

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

### 6.7 Determinism requirements

* Pure functions; all inputs in the case; no wall-clock, no network, no model.
* **Order-independent fold.** Ingesting the same records in any order, serially or
  in parallel, must produce an identical graph and identical digests.
* Stable ids and sorted iteration everywhere, so output is byte-reproducible.
* Engine and ruleset versions are recorded in the binding; a verdict is
  reproducible only against the versions that produced it, and the packet says so.

---

## 7. The Human Attention Engine

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

Ordering: integrity breaks and unresolved contradictions on load-bearing claims are
pinned first, then by `(consequence_weight × leverage)`, ties broken by stable id so
output is reproducible. The set is capped (default 7) with an **explicit remainder
count and a reference to the full set** — never a silent truncation, which would be
an Invariant 3 violation dressed as UX.

**`RequiredEvidence`** is the HOLD counterpart: for each condition blocking
PROMOTE, what specific evidence would resolve it — "an independent replication of
claim C by a producer not descended from agent A, against digest D". This is what
makes HOLD actionable instead of a shrug, and it is derived directly from the
unmet methodology requirements.

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

### 8.3 Completeness declarations

A producer may emit a `CompletenessDeclaration` ("agents 1..100 reported; stream
sequence 1..48,201 complete"). That declaration is itself `DECLARED` evidence — it
raises the *expected* denominator and is never taken as proof of completeness.
Where it can be checked (sequence gaps, signed streams, heartbeats), the
completeness analyser checks it and reports the delta.

---

## 9. Approval binding

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

Non-negotiable: `release-gate` must stay a three-dependency CLI that does
something useful in one command with no setup.

* `release-gate audit .` — unchanged, byte for byte.
* `release-gate decide <artifact> --action "apply this migration to prod-eu"` —
  builds a DECISION case from what is present: the artifact and its digest, git
  history, any trace file passed, CI outputs if pointed at them. With no
  methodology it runs every structural analysis and reports
  `METHODOLOGY_REQUIRED` for sufficiency. The engineer gets provenance, drift,
  contradiction and integrity results plus an explicit statement of what was not
  assessed. That is useful and honest on day zero.
* Progressive assurance (Invariant 14): each structure a team adds — declared
  claims, a verifier manifest, signed evidence — populates more of the case and
  moves rows of the coverage matrix from `NOT_ASSESSED` toward `OBSERVED`. Nothing
  is required up front; nothing is faked when missing.

---

## 11. Methodology behaviour

* **Resolution order.** Explicit `--methodology` → repository
  `.release-gate/methodology.yaml` → organisation methodology (hosted API) →
  built-in default for the subject type → `NONE`.
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
  analyzers/
    provenance.py  coverage.py  contradiction.py  independence.py  drift.py  completeness.py
  policy.py              deterministic verdict; ADMISSION delegates to audit.apply_decision_mode
  attention.py           HumanAttentionSet, leverage computation, RequiredEvidence
  packet.py              ApprovalPacket rendering (json / markdown / html)
  approval.py            BoundApproval, sign/verify (uses release_gate/crypto)
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
| 12 | Dependency criticality beats volume | `attention.py` leverage computation (§7) | Ranking keys on counts or generic severity |
| 13 | Evidence omission is a threat | `analyzers/completeness.py` (§6.6) | "Not observed" is rendered as "did not happen" |
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
