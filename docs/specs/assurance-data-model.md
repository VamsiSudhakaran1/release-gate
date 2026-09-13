# Spec — Assurance data model, wire protocol and binding algorithm

> **Status: SPECIFICATION. No production code changes.** The companion to
> `docs/specs/universal-assurance-architecture.md`, which argues the design; this
> document pins the shapes an implementer needs and nothing else. Where the two
> disagree, the architecture document wins on intent and this one wins on field
> names.
>
> Everything here is JSON, stdlib-parseable, and free of vendor SDKs — the same
> constraint that keeps `pip install release-gate` a three-library install.

---

## 1. Conventions

* All ids are strings. Content-derived ids use the form `<prefix>_<first16hex>` of
  a sha256 over the record's canonical form: `ev_9f2c4a1b8e3d5c70`,
  `cl_71ab…`, `case_c41d…`.
* All digests are `sha256:<hex>`, lowercase.
* All timestamps are RFC 3339 UTC with a `Z` suffix.
* Unknown fields are **preserved**, never dropped — a newer producer must not lose
  data through an older reader.
* Enum values are UPPER_SNAKE. An unrecognised enum value is an ingest error, not a
  silent coercion to a default: coercion is how `UNKNOWN` becomes `safe`.
* Absent ≠ null ≠ `UNKNOWN`. Absent means the producer said nothing; explicit
  `"UNKNOWN"` means the producer looked and could not tell. Both are legal; they
  are not interchangeable.

---

## 2. Enumerations

```text
Plane                ADMISSION | DECISION

SubjectType          DEPLOYMENT | CODE_CHANGE | AUTONOMOUS_ACTION | RESEARCH_RESULT |
                     DATA_CHANGE | FINANCIAL_ACTION | INFRASTRUCTURE_CHANGE | DOCUMENT |
                     MODEL_CHANGE | CONFIG_CHANGE | GENERAL_RESULT | CUSTOM
                     (CUSTOM requires a custom_type label — an unlabelled custom
                      subject cannot be matched to a methodology or explained)

ReferenceKind        FILE | DIRECTORY | INLINE | ITEM_SET | GIT_COMMIT | GIT_RANGE |
                     OBJECT_STORE | URL | EXTERNAL

DigestMethod         SHA256_CONTENT | SHA256_MANIFEST | MERKLE_UNORDERED |
                     MERKLE_ORDERED | GIT_OBJECT | EXTERNAL_ATTESTED | NONE

DigestStatus         OBSERVED | DECLARED | UNKNOWN
VersionBasis         DECLARED | GIT_COMMIT | EXTERNAL | DERIVED | UNKNOWN
MutationStatus       UNCHANGED | MUTATED | UNVERIFIABLE

EpistemicStatus      OBSERVED | DECLARED | DERIVED | VERIFIED |
                     DISPUTED | REFUTED | UNKNOWN | NOT_ASSESSED

VerificationMethod   FORMAL_PROOF | INDEPENDENT_REPLICATION | TEST_SUITE |
                     SIMULATION | EXPERIMENT | STATIC_ANALYSIS |
                     RUNTIME_ASSERTION | HUMAN_REVIEW | CROSS_MODEL_REVIEW |
                     THEOREM_PROVER | EXTERNAL_REFERENCE | DOMAIN_CHECKER |
                     PROPERTY_TEST | COMPILER | TYPE_CHECKER | OTHER

EvidenceKind         CODE_FINDING | SAFEGUARD | EVAL_RESULT | TRACE_EVENT | PROBE |
                     ATTESTATION | PROOF | EXPERIMENT | SIMULATION | REVIEW |
                     EXTERNAL_REFERENCE | DRIFT | COMPLETENESS | COUNTEREXAMPLE | OTHER

Polarity             SUPPORTS | REFUTES | QUALIFIES | CONTEXT

ProducerKind         agent | tool | human | release_gate | external

Integrity            SIGNED | DIGEST_ONLY | UNSIGNED

EdgeType             SUPPORTS | REFUTES | QUALIFIES | DEPENDS_ON |
                     DERIVED_FROM | DUPLICATES | SUPERSEDES | INPUT_TO | SPAWNED_BY

CoverageStatus       EXPECTED | OBSERVED | KNOWN_MISSING | UNKNOWN | NOT_ASSESSED

ConsequenceWeight    CRITICAL | HIGH | MEDIUM | LOW
Reversibility        REVERSIBLE | COSTLY_TO_REVERSE | IRREVERSIBLE | UNKNOWN

Verdict              PROMOTE | HOLD | BLOCK
ApprovalStatus       VALID | STALE | INVALIDATED | SUPERSEDED

CaseType             DEPLOYMENT | AUTONOMOUS_ACTION | RESEARCH_RESULT | CODE_CHANGE |
                     DATA_CHANGE | FINANCIAL_ACTION | INFRASTRUCTURE_CHANGE |
                     GENERAL_DECISION | CUSTOM
                     (a different axis from SubjectType, and never validated
                      against it: a DOCUMENT subject may be argued as a
                      RESEARCH_RESULT case or a GENERAL_DECISION one)

CaseState            DRAFT | SEALED | APPROVED | SUPERSEDED | INVALIDATED
Presence             ABSENT | PRESENT
MaterialisationBasis COMPLETE | RELEVANCE_DIRECTED | SAMPLED | CAPPED | SUMMARY_ONLY
DedupeBasis          ALL_RECORDS | MATERIALISED_ONLY | NONE
```

Two enum notes that carry design weight:

* `EpistemicStatus` has both `UNKNOWN` and `NOT_ASSESSED` and they never collapse
  (architecture §4.2). `UNKNOWN` is a hole inside the argument; `NOT_ASSESSED` is a
  declared boundary of it.
* `Reversibility.UNKNOWN` exists so a producer cannot be forced to guess. An
  irreversibility question that nobody answered must not default to `REVERSIBLE`.

---

## 3. Core records

### 3.0 `AssuranceCase` and its collections

Implemented in `release_gate/assurance/case.py` and `records.py`.

```json
{
  "record_type": "assurance_case",
  "case_id": "case_3af429f2a411d15f",
  "case_version": 1,
  "case_type": "DATA_CHANGE",
  "state": "SEALED",
  "objective": "add an index to orders without taking write downtime",
  "requested_decision": "authorise applying this migration to prod-eu",
  "subject": { "…AssuranceSubject…": "" },
  "methodology": {"methodology_id": "production-database-change", "version": "1.0.0"},
  "collections": {
    "executions": {
      "kind": "executions",
      "presence": "PRESENT",
      "total_count": 4120884,
      "materialised_count": 12431,
      "not_materialised": 4108453,
      "basis": "RELEVANCE_DIRECTED",
      "dedupe_basis": "MATERIALISED_ONLY",
      "fold_algo": "rg-mset-1",
      "fold_digest": "sha256:…",
      "notes": [],
      "records": []
    }
  },
  "verdict": {"decision": "HOLD", "fired_rules": ["RG-DECIDE-014"], "reasons": ["…"]},
  "subject_digest": "sha256:…",
  "evidence_digest": "sha256:…",
  "case_digest": "sha256:…"
}
```

**Three digests, each answering a different question.**

| Digest | Covers | Question it answers |
|---|---|---|
| `subject_digest` | the subject's state | Is this still the thing? |
| `evidence_digest` | the eight evidentiary collections' folds | Has the body of evidence changed? |
| `case_digest` | identity, subject state, methodology, all collections except approvals, verdict, metadata | Is this the exact page the human saw? |

`case_id`, by contrast, derives from the *question* — case type, custom type,
objective, requested decision and subject id — so it survives new evidence and
new versions. Re-running a case yields the same `case_id`, a higher
`case_version`, and a different `case_digest`.

Approvals are excluded from `case_digest` by construction: an approval binds to
that digest, so folding it back in would make the digest depend on the thing that
depends on it. Timestamps are excluded too — `created_at`, `updated_at` and a
verdict's `decided_at`. A verdict's `reasons` *are* included, because the stated
reasons are what a person relied on.

**Presence and materialisation.** Every collection carries:

```text
presence        ABSENT (never supplied) | PRESENT (supplied, possibly empty)
total_count     records SEEN
materialised    records HELD  (len() reports this; total_count reports the other)
basis           COMPLETE | RELEVANCE_DIRECTED | SAMPLED | CAPPED | SUMMARY_ONLY
dedupe_basis    ALL_RECORDS | MATERIALISED_ONLY | NONE
fold_digest     multiset commitment over every record seen
```

A collection whose records were dropped cannot describe itself as `COMPLETE`; the
builder downgrades the basis rather than let the label outrun the contents. A
collection is always truthy regardless of how many records it holds — presence is
a field, not truthiness.

**The fold** is `rg-mset-1`, an additive multiset commitment: sum record digests
modulo 2^256, then commit to the sum with the cardinality. Commutative,
associative and constant-memory, so parallel shards can fold independently and
merge to the same value. Two limits, stated because a commitment whose limits are
unstated gets mistaken for a Merkle tree: it commits to a multiset (order is not
recoverable, and a record added twice is a different multiset, so at-least-once
delivery must be deduplicated by the caller), and it supports no inclusion proofs
(`merkle_root` is what proves membership).

Measured: 500,000 execution records fold in ~6s at ~20 MB peak RSS, with 25
materialised.

**Lifecycle.** `DRAFT → SEALED → APPROVED`, with `SUPERSEDED` and `INVALIDATED`
reachable and terminal. Every other edge is refused, including every backward
one: a reviewer's "I looked at the sealed case" must keep meaning what it said. A
verdict may be rendered only on a SEALED case that carries coverage — that is the
enforcement point for Invariant 9. (The architecture spec placed that check in
the verdict constructor; it lives on the case instead, because that is where the
coverage data is. Same guarantee, right seam.)

### 3.1 `AssuranceSubject`

Implemented in `release_gate/assurance/subject.py`.

```json
{
  "record_type": "subject",
  "model_version": 1,
  "subject_id": "subj_9f2c4a1b8e3d5c70",
  "state_digest": "sha256:08aa296b…d520",
  "subject_type": "DATA_CHANGE",
  "custom_type": null,
  "version": "3",
  "version_basis": "DECLARED",
  "digest": "sha256:9f2c4a1b…ef01",
  "digest_method": "SHA256_CONTENT",
  "digest_status": "OBSERVED",
  "digest_basis": "sha256 over the bytes of 2026_09_12_add_index.sql",
  "digest_attested_by": null,
  "content_reference": {
    "kind": "FILE",
    "locator": "migrations/2026_09_12_add_index.sql",
    "detail": {}
  },
  "requested_action": "Apply this migration to prod-eu",
  "supersedes": "subj_71ab33c9d0e1f2a3",
  "created_at": "2026-09-12T09:14:00Z",
  "mutation_detectable": true,
  "metadata": {}
}
```

**Two digests, not one.** `subject_id` is derived from *identity* — subject type,
custom type, version and its basis, digest and its method/status/attestor,
content reference, requested action, and `supersedes`. `state_digest` covers
identity **plus** `digest_basis` and `metadata`: everything a human would have
seen on the page. A `BoundApproval` binds to `state_digest`.

The split exists because re-tagging a subject does not change what it is, but it
does change what was on the page, and only the second of those may invalidate an
approval.

**`created_at` is in neither digest.** Identity is content, not clock: the same
bytes submitted twice are one subject. Without this, every re-run would
manufacture a new thing to approve and deduplication would be impossible. This
refines the record-timestamp rule in §6.2 — an evidence record's timestamp *is*
part of what was approved (when a verification ran matters); a subject's creation
time is not.

**`supersedes` is part of identity on purpose.** "v2 of X" and "a standalone
artifact with identical bytes" are different things to authorise. Conflating them
is precisely how an approval would carry over silently.

Rules enforced at construction:

| Rule | Why |
|---|---|
| `requested_action` is mandatory, non-empty prose | Approval authorises an action, not a blob. A subject with no verb cannot be bound to a human's name. |
| `digest` is cryptographic wherever content is hashable | File, directory, inline and item-set subjects are hashed by release-gate, never declared. |
| A digest we did not compute is `DECLARED`, never `OBSERVED` | Invariant 1. An object store's digest is that store's claim. |
| A `DECLARED` digest must name `digest_attested_by` | Invariant 11 — provenance is part of the claim. |
| No digest → `digest_method: NONE`, `digest_status: UNKNOWN` | Invariant 3. A large or remote subject may be unhashable; the field is never populated with a fabricated value. |
| A version is never invented | `version: null` with `version_basis: UNKNOWN` is the honest answer; a supplied version must say where it came from. |
| Abbreviated git ids are refused | A 7-character prefix is ambiguous by design, and an ambiguous subject is the one thing an approval cannot bind to. |
| `subject_id` / `state_digest` are recomputed on load | A stored id that disagrees with its content means the record was edited; that is a hard error, not a repair. |

**Content identifiers carry their algorithm.** `sha256:<64 hex>` for digests
release-gate or a peer computed; `git:<40 or 64 hex>` for a git object id. A
sha-1 git id padded into a `sha256:` field would misstate which algorithm
identified the content, so the two namespaces stay distinct.

**Item sets** (the 8,214 refunds case) digest through a Merkle root that is
order-independent by default — the same refunds in a different order are the same
batch — and order-sensitive when sequence is part of the meaning. Leaves and
interior nodes are domain-separated, odd nodes are promoted rather than
duplicated, and the leaf count is folded into the root.

**Mutation detection** is `recheck()` returning `UNCHANGED` / `MUTATED` /
`UNVERIFIABLE`. File, directory and inline subjects are re-checkable offline;
everything else needs a resolver or an attestation, and says so through
`mutation_detectable: false`. A subject whose content has vanished is
`UNVERIFIABLE`, never `UNCHANGED`: "I could not tell" must not read as "fine".

**Supersession** produces a new `subject_id` by construction, so no code path can
match an approval of the old subject to the new one.
`describe_supersession(previous, current)` names what changed and returns
`approval_carryover_permitted: false` unconditionally. That field is not a policy
knob — a knob that could be true would eventually be set true by something
automated at 3am.

### 3.2 `Consequence`

```json
{
  "weight": "HIGH",
  "reversibility": "IRREVERSIBLE",
  "blast_radius": "production database, EU region, all tenants",
  "affected_parties": ["customers-eu"],
  "estimated_cost": null,
  "notes": "Index build locks the table on the current engine version."
}
```

`weight` and `reversibility` drive both the verdict rules and attention ranking.
`estimated_cost: null` is legal and means absent; it is never read as zero.

### 3.3 `EvidenceRecord`

```json
{
  "record_type": "evidence",
  "evidence_id": "ev_4d1e77a2b3c4d5e6",
  "kind": "SIMULATION",
  "epistemic_status": "VERIFIED",
  "verification_method": "SIMULATION",
  "producer": {
    "producer_id": "ci://github/acme/api/run/8821",
    "kind": "tool",
    "identity_basis": "github-oidc",
    "version": "staging-dryrun@2.1.0",
    "attested_by": null
  },
  "produced_at": "2026-09-12T09:31:04Z",
  "subject_ref": {"kind": "claim", "id": "cl_3311aabbccddeeff"},
  "polarity": "SUPPORTS",
  "applies_to_digest": "sha256:9f2c4a1b…ef01",
  "content": {
    "summary": "Dry-run applied cleanly to a 14-day-old staging snapshot",
    "duration_s": 412,
    "rows_affected": 0
  },
  "provenance": {
    "input_digests": ["sha256:9f2c4a1b…ef01", "sha256:5522ee…snapshot"],
    "transform": "postgres dry-run in a disposable container",
    "chain": ["ci://github/acme/api/run/8821"]
  },
  "integrity": {"mode": "DIGEST_ONLY"},
  "coverage_note": "Covers schema application only; application query compatibility not exercised.",
  "metadata": {}
}
```

Field rules an implementer must enforce at ingest:

| Field | Rule |
|---|---|
| `epistemic_status` | **Assigned by the ingest boundary, never by the producer.** A producer-supplied value is moved into `content.producer_claimed_status` and ignored for computation. |
| `verification_method` | Required iff status is `VERIFIED` or `REFUTED`. Missing → the record is rejected, not downgraded silently. |
| `applies_to_digest` | Required for `VERIFIED`/`REFUTED`. Mismatch with the current subject digest invalidates the verification and raises a drift finding. |
| `polarity` | Required. `REFUTES` records are retained forever and are never filtered by relevance. |
| `provenance.input_digests` | Empty is legal for a direct observation; empty on a `DERIVED` record is a provenance finding. |
| `coverage_note` | Required on every `VERIFIED` record. If a producer cannot say what its verification does *not* cover, the verification is not well-formed. |

### 3.4 `Claim`

```json
{
  "record_type": "claim",
  "claim_id": "cl_3311aabbccddeeff",
  "proposition": "The migration is backward compatible with API v4.2 queries.",
  "is_root": false,
  "assumption": false,
  "consequence_weight": "HIGH",
  "declared_by": {"producer_id": "agent://migration-planner/7", "kind": "agent"},
  "declared_at": "2026-09-12T09:12:44Z",
  "applies_to_digest": "sha256:9f2c4a1b…ef01",
  "metadata": {}
}
```

Computed at analysis time and **never** accepted from a producer:
`direct_status`, `inherited_ceiling`, `effective_status`, `load_bearing`,
`independent_groups`, `attention_rank`. A producer supplying any of these is an
ingest error — that is the concrete mechanism behind "no component may claim
something happened merely because an agent says it happened".

### 3.5 `ArtifactNode`

```json
{
  "record_type": "artifact",
  "artifact_id": "art_88ce0011",
  "digest": "sha256:9f2c4a1b…ef01",
  "kind": "sql_migration",
  "content_reference": {"kind": "file", "path": "migrations/2026_09_12_add_index.sql"},
  "produced_by": {"producer_id": "agent://migration-planner/7", "kind": "agent"},
  "derived_from": ["sha256:aa17…schema-snapshot"],
  "signed_by": null,
  "created_at": "2026-09-12T09:12:40Z"
}
```

### 3.6 `ExecutionNode`

```json
{
  "record_type": "execution",
  "node_id": "ex_00a1b2c3",
  "node_kind": "tool_call",
  "parent_id": "ex_00a1b2c0",
  "producer": {"producer_id": "agent://migration-planner/7", "kind": "agent"},
  "started_at": "2026-09-12T09:12:31Z",
  "attributes": {"tool": "read_schema", "args": {"table": "orders"}},
  "sequence": 412,
  "stream_id": "run-8821"
}
```

`node_kind` ∈ `agent_turn | model_call | tool_call | verifier_run |
human_intervention | retry | fallback | branch_start | branch_abandoned`.

`sequence` + `stream_id` are what make gap detection possible (Invariant 13). A
producer that omits them gets `completeness: UNKNOWN` for that stream, stated
plainly rather than assumed complete.

Today's trace step `{"type": "tool_call", "tool": "x", "args": {...}}` maps onto
this with `parent_id` absent and `sequence` taken from list position — the linear
degenerate case of the graph.

### 3.7 `CompletenessDeclaration`

```json
{
  "record_type": "completeness",
  "declaration_id": "cd_5f10",
  "declared_by": {"producer_id": "orchestrator://run-8821", "kind": "tool"},
  "scope": {"stream_id": "run-8821"},
  "expected_sources": ["agent://worker/1", "agent://worker/2"],
  "expected_sequence": {"from": 1, "to": 48201},
  "declared_at": "2026-09-12T10:02:00Z"
}
```

This record raises the *expected* denominator and is itself `DECLARED` evidence.
It is never treated as proof of completeness; where it can be checked against
arrived sequences it is, and the delta is reported.

---

## 4. Graph edges

```json
{
  "record_type": "edge",
  "edge_type": "DEPENDS_ON",
  "from": {"kind": "claim", "id": "cl_root"},
  "to": {"kind": "claim", "id": "cl_lemma887"},
  "declared_by": {"producer_id": "agent://prover/3", "kind": "agent"}
}
```

The distinction that carries the status calculus: `DEPENDS_ON` means *the
conclusion rests on this*, and caps the parent's `effective_status` at the child's.
`SUPPORTS` means *this is corroborating evidence that does not carry the
conclusion*, and does not cap. Producers choose; the independence and provenance
analysers audit the choice and flag a `SUPPORTS` edge whose source is the only
thing establishing the parent.

---

## 5. Container objects

### 5.1 `CoverageMatrix` row

```json
{
  "dimension": "Lemma verification",
  "expected": 3114,
  "observed": 2996,
  "status": "OBSERVED",
  "basis": "lemma manifest declared by orchestrator://run-8821",
  "ratio": 0.9621,
  "note": "118 lemmas unproven; 3 of them load-bearing."
}
```

The one hard rule: `ratio` may be present **only** when `expected` is a real number
established by a manifest, declaration, sequence or direct enumeration, and `basis`
must name that source. Otherwise `expected: "UNKNOWN"`, `ratio` absent. This is the
whole of Invariant 9 in one field pair.

Legacy continuity: today's `audit.compute_coverage()` rows
(`assessed` / `partial` / `not_assessed` / `not_supplied` / `n/a`) map onto this
shape with `expected`/`observed` absent — they are qualitative rows, and that is
legal.

### 5.2 `Verdict`

```json
{
  "verdict": "HOLD",
  "fired_rules": ["RG-DECIDE-014", "RG-COV-003"],
  "reasons": [
    "No rollback path for an IRREVERSIBLE action (RG-DECIDE-014).",
    "Backward-compatibility claim has no admissible verification (RG-COV-003)."
  ],
  "methodology": "production-database-change-v1@1.0.0",
  "coverage": [ "…CoverageMatrix rows…" ],
  "engine": {"version": "0.11.0", "ruleset_version": "2026.09"}
}
```

A `Verdict` without a non-empty `coverage` array is invalid and cannot be
constructed. This is a constructor precondition, with a test, not a convention.

### 5.3 `AttentionItem`

```json
{
  "item_id": "att_1",
  "kind": "LOAD_BEARING_ASSUMPTION",
  "what": {"kind": "claim", "id": "cl_3311aabbccddeeff"},
  "why": "The whole change rests on this, and only the agent asserts it.",
  "question": "Do API v4.2 queries still work against the new index definition?",
  "leverage": {
    "if_accepted": "root claim reaches DERIVED; verdict becomes PROMOTE",
    "if_rejected": "root claim becomes REFUTED; verdict becomes BLOCK"
  },
  "evidence_refs": ["ev_4d1e77a2b3c4d5e6"],
  "consequence": {"weight": "HIGH", "reversibility": "IRREVERSIBLE"}
}
```

`leverage` is computed by flipping the item's status to best and worst case and
recomputing the root claim — deterministic, and the reason attention ranking
survives Invariant 12 (dependency over volume).

### 5.4 `RequiredEvidence`

```json
{
  "condition": "RG-COV-003",
  "needed": "An admissible verification of cl_3311… against digest sha256:9f2c…",
  "admissible_methods": ["TEST_SUITE", "INDEPENDENT_REPLICATION"],
  "producer_constraint": "structurally independent of agent://migration-planner/7",
  "would_change": "HOLD → PROMOTE, if no other condition regresses"
}
```

---

## 6. Canonicalisation and digests (`rg-bind-1`)

### 6.1 Canonical JSON

1. UTF-8, no BOM.
2. Object keys sorted lexicographically by code point.
3. No insignificant whitespace: separators `,` and `:`.
4. Numbers in shortest round-trip form; integers without a decimal point.
5. `null` is preserved (it means "explicitly absent", which is data).
6. Arrays keep producer order **except** where this document names a sort key.

### 6.2 Volatile-field exclusion list

Excluded from every digest, because they change without the content changing:

```text
produced_at / created_at / computed_at on container objects (not on records)
absolute filesystem paths          (relative paths are kept)
run ids, job ids, hostnames
engine wall-clock timings
rendering fields (colours, emoji, terminal widths)
```

Record-level timestamps *are* included: when a verification ran is part of what
was approved. The one exception is `AssuranceSubject.created_at`, excluded from
both subject digests so that identical content is one subject rather than a new
one per run — see §3.1.

### 6.3 Set digests

For an `action_batch` (the 8,214 refunds case): canonicalise each item, sha256 it,
sort the hex digests lexicographically, build a binary Merkle tree, and take the
root. Sorting makes the root order-independent; the tree makes "which item
changed" answerable without re-sending the batch.

### 6.4 `case_digest`

```text
case_digest = sha256(canonical_json({
  "binding_algo":     "rg-bind-1",
  "proposition":      case.proposition,
  "subject":          {id, type, version, digest, requested_action},
  "consequence":      {weight, reversibility},
  "methodology":      "id@version"  |  "NONE",
  "evidence_set":     [sorted evidence_ids with their record digests],
  "claim_graph":      canonical claim+edge form with computed statuses,
  "coverage":         coverage matrix rows,
  "verdict":          {verdict, fired_rules},
  "engine":           {version, ruleset_version}
}))
```

Including the computed statuses and the fired rules is deliberate: the human
approved *this verdict under this reading of this evidence*. A re-run that reaches
the same verdict by a different route is a different state and should say so.

### 6.5 Staleness

On any later run, recompute. Mismatch → every `BoundApproval` for that case moves
to `STALE`, and the drift analyser names which component of the digest changed
(subject, evidence, claims, coverage, verdict, methodology, engine). `INVALIDATED`
is reserved for integrity failures — a signature that no longer verifies, evidence
that vanished from the store.

---

## 7. The emission envelope (wire protocol)

### 7.1 Format

JSONL. One record per line. Any order. Producers append; nobody coordinates.
Mixed record types in one file are expected.

```jsonl
{"record_type":"claim","claim_id":"cl_root","proposition":"…","is_root":true,"consequence_weight":"HIGH","declared_by":{"producer_id":"agent://planner/7","kind":"agent"}}
{"record_type":"artifact","artifact_id":"art_1","digest":"sha256:9f2c…","kind":"sql_migration"}
{"record_type":"evidence","evidence_id":"ev_1","kind":"SIMULATION","verification_method":"SIMULATION","polarity":"SUPPORTS","subject_ref":{"kind":"claim","id":"cl_root"},"applies_to_digest":"sha256:9f2c…","producer":{"producer_id":"ci://…/8821","kind":"tool"},"coverage_note":"schema only"}
{"record_type":"edge","edge_type":"DEPENDS_ON","from":{"kind":"claim","id":"cl_root"},"to":{"kind":"claim","id":"cl_lemma1"}}
{"record_type":"completeness","declaration_id":"cd_1","scope":{"stream_id":"run-8821"},"expected_sequence":{"from":1,"to":412}}
```

### 7.2 Producer obligations

A producer must supply: `record_type`, a stable id, a `producer`, and for evidence
a `polarity` and a `subject_ref`. A producer must **not** supply: any
`epistemic_status`, any computed claim field, any verdict. Supplying them is an
ingest error with a named reason, because silently ignoring them would let a
producer believe it had influenced the verdict.

### 7.3 Signed envelopes

An envelope may be wrapped:

```json
{
  "envelope_version": 1,
  "records_digest": "sha256:…",
  "signature": {"alg": "RSA-PSS-SHA256", "key_id": "…", "value": "base64…"},
  "records": ["…"]
}
```

Verified with the existing `release_gate/crypto` primitives. Unsigned envelopes are
accepted and marked `UNSIGNED`; requiring a PKI before the first useful answer
would put the tool out of reach on day zero, which is a product failure, not a
security win.

---

## 8. Mapping today's producers onto the model

The migration is mechanical. Every row reuses existing code behind an adapter in
`release_gate/assurance/ingest/`.

| Existing output | Record | Status assigned at ingest | Method |
|---|---|---|---|
| `verify.scan_code_findings()` finding (`basis: confirmed`) | `evidence(CODE_FINDING)` | `DERIVED` | `STATIC_ANALYSIS` |
| same, `basis: inferred` / `heuristic` | `evidence(CODE_FINDING)` | `DERIVED` + `coverage_note` recording the weaker basis | `STATIC_ANALYSIS` |
| `verify_safeguards_for()` present=true | `evidence(SAFEGUARD)` | `DECLARED` — a declaration is not a runtime guarantee | — |
| `governance.yaml` contents | `evidence(SAFEGUARD)` | `DECLARED` | — |
| `lockfile.collect_components()` | `artifact` nodes | `OBSERVED` (we hashed the bytes) | — |
| `lockfile.compare_lock()` | `evidence(DRIFT)` | `DERIVED` | — |
| `audit.compare_to_baseline()` | `evidence(DRIFT)` | `DERIVED` | — |
| `trace_validator` FAIL/WARN | `evidence(TRACE_EVENT)` | `OBSERVED` violation + `DERIVED` judgement | `RUNTIME_ASSERTION` |
| `trace_validator` PASS **with a policy** | `evidence(TRACE_EVENT)` | `DERIVED` | `RUNTIME_ASSERTION` |
| `trace_validator` PASS **with no policy** | coverage row only | `NOT_ASSESSED` | — |
| adapter spans (OTel/Langfuse/Phoenix) | `execution` nodes | `OBSERVED` | — |
| adapter `Coverage` object | coverage rows | `KNOWN_MISSING` per skip reason | — |
| `evals/runner` case result | `evidence(EVAL_RESULT)` | `DERIVED` (ours) / `DECLARED` (ingested verdict) | `TEST_SUITE` |
| promptfoo ingested results | `evidence(EVAL_RESULT)` | `DECLARED` — we rule on their verdict, never re-grade it | `TEST_SUITE` |
| `agent_score` probe leak | `evidence(PROBE)` | `OBSERVED` (the response) + `DERIVED` (the leak judgement) | `EXPERIMENT` |
| `loop_sim` run | `evidence(SIMULATION)` | `DERIVED` | `SIMULATION` |
| `readiness_scorer` output | coverage rows + `DERIVED` context | never a status source (architecture §18.1) | — |
| agent prose ("I tested this") | `evidence(OTHER)` | `DECLARED` — evidence that it was asserted, not that it is true | — |
| human sign-off | `evidence(REVIEW)` | `VERIFIED` iff identity is established | `HUMAN_REVIEW` |

The three rows that encode the master contract most directly are the
`governance.yaml` row (a declaration stays `DECLARED`), the no-policy trace row
(absence of a rule is not a pass), and the agent-prose row (an assertion is
evidence of the assertion).

---

## 9. Persistence layout

```text
.release-gate/
  evidence/
    sha256/9f/2c4a1b….json          content-addressed, immutable, append-only
  cases/
    case_c41d…/1.json               each case version, full
    case_c41d…/2.json
  approvals/
    appr_77bc….json                 signed; references case_id + case_digest
  methodology.yaml                  optional, organisation or repo methodology
```

Properties: no database, no service, nothing required in git; dedup is free
because content addressing gives it; immutability is what makes drift detection
possible at all. A pruned store reports reduced coverage rather than silently
losing evidence — deletion changes what can be claimed, and the coverage matrix is
where that shows up.

Hosted API adds `assurance_cases`, `evidence_index`, `approvals`, per-tenant,
additive to the existing `runs` table. Default storage is digests and metadata;
payloads are opt-in per tenant, because evidence bodies can carry customer data.

---

## 10. Validation rules (implementer's checklist)

Reject at ingest, with a named reason:

1. `VERIFIED`/`REFUTED` without `verification_method`.
2. `VERIFIED`/`REFUTED` without `applies_to_digest`.
3. `VERIFIED` without `coverage_note`.
4. Any producer-supplied `epistemic_status` or computed claim field.
5. An `AssuranceSubject` without `digest` or without `requested_action`.
6. An unrecognised enum value.
7. A `Verdict` constructed without coverage rows.
8. A ratio in a coverage row whose `expected` is `UNKNOWN`.
9. An evidence record whose `subject_ref` points at nothing in the case.
10. A cyclic `DEPENDS_ON` chain in the claim graph.

Warn, and record as a finding rather than rejecting:

11. `DERIVED` with empty `provenance.input_digests`.
12. A claim whose only support is its own author (self-attestation).
13. An edge typed `SUPPORTS` that is in fact the sole basis for its parent.
14. An execution stream with no `sequence`, which forces `completeness: UNKNOWN`.
