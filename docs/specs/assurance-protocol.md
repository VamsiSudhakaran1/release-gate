# Spec — The Assurance Protocol (hosted endpoint)

> **Status: DESIGN ONLY. No production code changes.** This document specifies the
> HTTP surface through which release-gate is used as an assurance endpoint rather
> than a CLI. It is a companion to `docs/specs/universal-assurance-architecture.md`
> (the engine) and `docs/specs/assurance-data-model.md` (the records on the wire).
> Where this document and §17.3 of the architecture spec disagree about endpoint
> names, this document supersedes it — §17.3 was a four-line sketch written before
> the case model existed.
>
> Scope: how a case is opened, fed, read, closed, decided, approved, and how it
> behaves when evidence arrives late, out of order, twice, in parallel from ten
> thousand workers, or not at all.

---

## 0. Convergence output

The master contract requires this block before any implementation.

### 0.1 Interpretation of requirement

The CLI has a property the endpoint does not: **the whole case exists before
anything is computed.** `release-gate audit` reads a repo that is sitting still,
builds a report, prints a decision, exits. Every ordering question is answered by
the filesystem.

An endpoint has no such luxury. Evidence arrives over minutes or hours, from
producers that do not know about each other, in an order nobody controls, some of
it twice, some of it never. A verification finishes after the decision was made.
Two workers post concurrently. A stream is cut off halfway and nobody says so.

So the requirement is not *"expose the CLI over HTTP"*. It is: **define an intake
discipline under which a case assembled from an unordered, unreliable, concurrent
stream yields exactly the verdict it would have yielded had every record been
present on disk from the start** — and where that is impossible, says so in
coverage instead of guessing.

That reduces to one architectural commitment, from which the rest of this
document is derived:

> The endpoint is an **append-only intake with a deterministic fold**. It is not
> CRUD over a mutable case. `AssuranceCase` is frozen by construction; the API
> does not mutate one, it accumulates records and folds them into one.

The named requirements then stop being ten separate features and become
consequences:

| Requirement | Consequence of |
|---|---|
| out-of-order events | the fold is order-independent (§5) |
| duplicate events | records are content-addressed (§4.1) |
| idempotency | ids are derived, not assigned (§4) |
| streaming evidence | append-only intake, constant-memory fold (§3.3) |
| partial completion | a case is readable while open (§8) |
| large executions | the fold never needs the whole stream (§3.3, §14) |
| late verification | versions, not mutation (§9) |
| case versioning | already in the model — `case_version` (§10) |
| immutable historical references | `case_digest` addresses a state (§2) |
| optimistic concurrency | required only where operations don't commute (§7) |

### 0.2 Architecture impact

Additive. A new router, `release_gate_api/assurance_routes.py`, mounted under the
existing app. No existing endpoint changes shape, status code, or auth behaviour.
`release_gate/assurance/` gains no HTTP awareness — the router imports the core,
never the reverse, and the core continues to import nothing outside the stdlib.

One genuinely new component: the **intake ledger** (§3.5), which is the durable
append-only record of what arrived. It is the only stateful thing this design adds
and it is what makes every property above true rather than aspirational.

### 0.3 Existing release-gate components reused

* `AssuranceCase`, `AssuranceCaseBuilder`, `CaseState`, `revise()` — the whole
  lifecycle already exists and is already immutable. The API drives it; it does
  not reimplement it.
* `canonical.multiset_add / multiset_merge / multiset_digest` (`rg-mset-1`) — built
  for additive, order-independent, constant-memory commitment. It is the intake
  ETag (§7.1). This is the single most load-bearing reuse in the design.
* `EvidenceRecord.from_producer` — the ingest boundary. The HTTP layer performs no
  status assignment of its own; it calls this and nothing else.
* `ExecutionGraph.from_otlp` / `from_native_trace` — order-independent by
  construction (parent resolution is deferred to `build()`). Spans may arrive in
  any order across any number of requests.
* `MethodologyRegistry`, `assess()` — methodology by reference or inline JSON.
* `release_gate/crypto` — envelope signature verification, approval signing.
* `evidence_pack.generate_evidence_pack` — the pack endpoint renders, not rebuilds.
* `release_gate_api`: `_require_user`, `_check_rate_limit`, `PLAN_LIMITS`,
  `get_db`, `_ph`. Auth and tenancy are not reinvented.

### 0.4 New abstractions needed

1. **Intake ledger** — append-only `(tenant, case_id, version, record_digest)` with
   a uniqueness constraint. Dedupe, idempotency and the intake commitment all fall
   out of it.
2. **Pending reference** — a reference to a record that has not arrived. A first
   class row, not an error and not a retry queue (§5).
3. **Intake commitment** — `rg-mset-1` accumulator + count per open case version.
4. **Idempotency record** — `(tenant, key) → (request_digest, response, status)`,
   for the transitions that are not content-addressable (§4.2).
5. **Approval standing** — whether an approval's *subject* still holds, kept
   strictly separate from whether the approval *signature* is valid (§9.3).
6. **Token scope** — the agent/human asymmetry made enforceable (§13).

### 0.5 Components explicitly NOT being built

* **No webhook/notification service.** `GET /standing` is polled or read at the
  moment of use. Delivery guarantees are a different product.
* **No job queue, no async workers.** Finalize is synchronous. A case too large to
  fold inside a request is a case whose intake should have been folded
  incrementally, which it is (§3.5).
* **No WebSocket/SSE.** Streaming here means *the client streams in*, not the
  server streams out. Long-poll is not offered either; `GET /attention` is cheap.
* **No GraphQL, no batch mutation envelope.** One fold, four doors (§3.2).
* **No server-side record ordering or reordering.** Ordering is not needed (§5).
* **No partial-update verbs.** No PATCH on a case, ever. A case is not editable;
  that is the point of it.
* **No YAML parsing anywhere on this surface** (§16).

### 0.6 Invariants affected

* **1 (evidence over assertion)** — a producer POSTing `"verified": true` yields
  DECLARED evidence that it said so. Enforced by calling `from_producer`, §3.6.
* **3 (unknown is first-class)** — dangling references and truncated streams become
  coverage rows, not 4xx. §5, §6.
* **4 (deterministic authoritative path)** — the fold is order-independent, so two
  arrival orders of the same multiset produce the same `case_digest`. §5.1, §18.
* **5 (approval binds to exact state)** — the immutable historical reference *is*
  the digest the approval binds to. §2, §9.
* **9 (coverage accompanies every verdict)** — already structural in
  `render_verdict()`; the protocol adds intake coverage (what never arrived). §6.
* **11 (provenance ≠ trust)** — an authenticated tenant token establishes
  `identity_basis`, never trust. §13.
* **13 (evidence omission is a threat)** — the protocol refuses to let a dropped
  record look like an absent one. §6 is entirely about this.
* **15 (approval is authorization, not truth certification)** — §9.3 keeps
  `approval.valid` and `approval.standing` apart.

### 0.7 Tests required

Listed as acceptance tests in §18. The three that matter most: shuffled-arrival
digest equality, duplicate-flood idempotency, and decision-before-finalize refusal.

### 0.8 Migration / backward compatibility

Nothing to migrate. Every existing endpoint is untouched; the new surface is a new
prefix with new tables. `POST /api/verify` (the loop verifier) keeps its shape and
its YAML input — it is a different product surface with existing users, and §16's
"no YAML" applies to the assurance protocol, not retroactively to it.

### 0.9 Failure modes

§17. The one worth naming here: an intake that silently drops records would make
every coverage statement a lie, which is worse than an outage. Intake therefore
fails loudly and per-record, never silently and never wholesale.

### 0.10 Acceptance criteria

§18. Summarised: the same records in any order, any grouping, any duplication, over
any number of requests, from any number of concurrent writers, produce one identical
`case_digest`; and no ordering of requests can produce a decision that overstates
its own coverage.

---

## 1. What this endpoint is

An agent, a CI job, a worker in a fleet, or a human tool opens a **case** —
a question someone will have to authorise — then feeds it whatever evidence it has,
whenever it has it, and eventually asks for a decision.

The endpoint's promise is narrow and total:

> Everything you sent is in the case or was reported back to you as rejected.
> Nothing was silently dropped. What never arrived is described in the verdict's
> coverage rather than assumed to be absent.

It is **not** a database of reports, a workflow engine, or a place where agents
negotiate. It has no opinion about whether evidence is sufficient — that is the
methodology's job (§8.3). It has exactly one opinion of its own: what arrived.

---

## 2. Three identifiers, three jobs

The single most common API design error available here is using one identifier for
all three of these. They are distinct and the distinction is load-bearing.

| Identifier | Shape | Stable across | Addresses |
|---|---|---|---|
| `case_id` | `case_9f2c4a1b8e3d5c70` | evidence, versions, decisions | **the question** |
| `case_id@vN` | `case_9f2c…@v2` | evidence within that version | **an argument** |
| `case_digest` | `sha256:<64hex>` | nothing at all | **one exact state** |

`case_id` is derived from the case's `identity()` — case type, objective, requested
decision, subject id. It is a pure function of the question being asked. Two
consequences:

**Creation is intrinsically idempotent.** `POST /cases` twice with the same body
returns the same `case_id`; the second is a 200, not a duplicate. Forty agents that
independently decide a case is needed for the same subject converge on one case
without coordinating. No idempotency key is required for creation, because the
identifier is a function of the content rather than of the request.

> **The corollary is an operational obligation.** Convergence is over the *exact*
> identity, so `"deploy migration 0043"` and `"Deploy migration 0043"` are two
> questions and therefore two cases. A fleet that wants one case must derive the
> objective and requested decision deterministically from the work, not phrase them
> per worker. The API cannot fix this for them — normalising free text would mean
> guessing that two differently-worded questions are the same question, which is
> exactly the semantic equivalence the engine refuses to assert (Invariant 10).

**A changed subject is a different question, not an edit.** Revising the subject
produces a different `case_id` by construction. There is no way to point a case at
a different subject while keeping its identity, which is Invariant 5 expressed as
a namespace property.

`case_digest` is what an approval binds to and therefore what any historical
reference must use. "The evidence as it stood when this was approved" is
`?at=sha256:…`, and that response is byte-identical forever.

> **Tenancy.** `case_id` is globally deterministic, so two tenants asking an
> identical question derive an identical id. Every storage key and every lookup is
> `(tenant_id, case_id)`. A case id is not a capability and leaking one grants
> nothing.

> **Collision.** `short_id` truncates to 64 bits of the digest. Ids are scoped per
> tenant and per-tenant case counts are nowhere near the birthday bound, but the
> full digest is stored and the create path compares full `identity()` digests
> before returning an existing case. A truncated match with a different identity is
> a 409, not a silent merge.

---

## 3. Intake: one fold, four doors

### 3.1 The universal door

```http
POST /api/v1/assurance/cases/{case_id}/events
Content-Type: application/x-ndjson
```

The body is the emission envelope from `assurance-data-model.md` §7 — JSONL, one
record per line, any `record_type` (`claim`, `evidence`, `artifact`, `execution`,
`edge`, `completeness`), any order, mixed freely.

This is the whole protocol. Everything else is a convenience.

### 3.2 The typed doors

```http
POST /api/v1/assurance/cases/{case_id}/evidence
POST /api/v1/assurance/cases/{case_id}/claims
POST /api/v1/assurance/cases/{case_id}/artifacts
POST /api/v1/assurance/cases/{case_id}/execution
POST /api/v1/assurance/cases/{case_id}/verification
POST /api/v1/assurance/cases/{case_id}/completeness
```

Each accepts one record or an array of records of that type, as `application/json`,
for clients that would rather not construct NDJSON. Each is **literally** a wrapper
that stamps `record_type` and calls the same intake function as `/events`.

This is a deliberate constraint, not an implementation detail: **two intake paths
eventually disagree.** One of them gains a validation rule the other lacks, and
then the same evidence is accepted through one door and rejected through the other.
The typed doors must therefore never be able to express anything `/events` cannot,
and a test asserts the two produce identical ledger rows for the same record (§18).

Two of the typed doors carry semantics beyond convenience:

* `/verification` is the only door through which `VERIFIED` status can be assigned,
  and only with a named `verification_method` (Invariant 8). It also carries the
  late-verification behaviour of §9.
* `/completeness` is how a producer declares the extent of what it intends to send,
  which is the only thing that makes a truncated stream detectable (§6).

`/execution` accepts OTLP or native trace payloads and hands them to
`ExecutionGraph.from_otlp` / `from_native_trace`. It is the high-volume door and
the only one expected to see millions of records.

### 3.3 Streaming

NDJSON with `Transfer-Encoding: chunked`. The server folds line by line and holds:

* the intake accumulator (one integer) and count,
* per-collection counters,
* the retained record subset under the case's materialisation basis,
* pending references.

It never holds the stream. A JSON array body would require buffering the whole
thing before the first record could be parsed, which is why the universal door is
NDJSON and the JSON doors are for small batches (`RG-MAX-BATCH`, default 1,000).

A client may stream for as long as it likes across as many requests as it likes.
There is no session, no open transaction, and no ordering relationship between
requests. Two requests that overlap in time are fine (§7.2).

### 3.4 The response: per-record, never wholesale

```json
{
  "case_id": "case_9f2c4a1b8e3d5c70",
  "case_version": 1,
  "received": 4120,
  "accepted": 4098,
  "duplicate": 20,
  "rejected": 2,
  "intake_digest": "sha256:7ab3…",
  "intake_count": 41982,
  "pending_references": 17,
  "warnings": [
    {"code": "PRECONDITION_IGNORED",
     "message": "If-Match was supplied and ignored; appends commute and cannot conflict",
     "remedy": "send If-Match on /finalize, /approve and /revise only"}
  ],
  "results": [
    {"index": 3311, "status": "rejected", "code": "RECORD_MALFORMED",
     "message": "evidence record has no subject_ref",
     "remedy": "supply subject_ref.kind and subject_ref.id, or post to /claims first"},
    {"index": 3390, "status": "accepted", "record_digest": "sha256:1c4f…",
     "warnings": [{"code": "PRODUCER_CLAIMED_STATUS",
                   "message": "epistemic_status was supplied and has been recorded as content.producer_claimed_epistemic_status; it does not affect the verdict"}]}
  ]
}
```

Rules:

1. **One bad record never discards a good batch.** A 100,000-record stream with two
   malformed lines yields HTTP 200, 99,998 accepted, 2 rejected. Rejecting the
   batch would make a producer's cheapest recovery "retry everything", which at
   this scale is how records get lost.
2. **`index` is the line offset within this request**, so a client can retry
   precisely the failed slice.
3. **Duplicates are `duplicate`, not `rejected`.** They are a success — the record
   is in the case. Reporting them separately lets a client detect a retry storm
   without treating it as failure.
4. `accepted` entries are elided from `results` unless they carry warnings, so the
   response stays small for large batches. `rejected` entries are never elided.
5. HTTP status is 200 whenever the envelope itself parsed. 4xx is reserved for
   problems with the *request* (auth, unknown case, sealed case, malformed NDJSON
   framing, body over limit), never with individual records.

### 3.5 The intake ledger

```sql
CREATE TABLE assurance_intake (
    tenant_id     TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    case_version  INTEGER NOT NULL,
    record_digest TEXT NOT NULL,          -- sha256: of the canonical record
    record_type   TEXT NOT NULL,
    record_id     TEXT,                   -- producer-supplied, non-unique
    producer_id   TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    body          TEXT,                   -- NULL when retained by reference only
    PRIMARY KEY (tenant_id, case_id, case_version, record_digest)
);
```

The primary key does all the work. `INSERT … ON CONFLICT DO NOTHING` is an
idempotent append: a record submitted a thousand times occupies one row, and the
number of rows actually inserted is the number of records that were genuinely new —
which is exactly what must be folded into the accumulator.

The accumulator is not recomputed. It is advanced by the delta of each request:

```
acc_new = multiset_merge(acc_old, fold(multiset_add, digests_actually_inserted))
```

Because `multiset_merge` is commutative and associative, and because only
genuinely-inserted digests contribute, this is correct under any interleaving of
concurrent requests and any amount of retrying.

Two write strategies, both sound, chosen by scale:

* **Simple** — `SELECT … FOR UPDATE` the case's accumulator row, merge, write.
  One short row lock per request. Fine to thousands of requests per minute.
* **Sharded** — append the per-request delta to `assurance_intake_deltas` and fold
  on read. No lock at all. Associativity is what makes this safe, and it is the
  path for the 10,000-worker case.

The design does not need to choose now; the accumulator's algebra makes both valid.

### 3.6 Where status is assigned

The HTTP layer assigns no epistemic status. It parses, authenticates, and calls
`EvidenceRecord.from_producer(payload, evidence_type=…, source=…, producer=…)`.

`from_producer` moves `epistemic_status`, `trust_status`, `provenance_status`,
`coverage_status`, `evidence_id` and `verified` into
`content.producer_claimed_*` and they take no part in anything. The record is
DECLARED unless an adapter chose otherwise.

> **Divergence found and resolved.** `assurance-data-model.md` §7.2 used to say
> supplying a forbidden field is "an ingest error with a named reason". The
> implementation relocates and warns instead, and the implementation is right:
> rejecting a record because it carried an extra field destroys evidence, and
> evidence omission is a threat (Invariant 13). The producer still learns it had no
> influence — via the `PRODUCER_CLAIMED_STATUS` warning in §3.4 — which is the
> property §7.2 was actually protecting. §7.2 has been amended to say *relocated
> and reported*.

The one hard refusal remains: a non-release-gate producer cannot be ingested as
`OBSERVED` or `DERIVED`. Those describe release-gate's own work. Attempting it is a
per-record rejection with code `STATUS_NOT_SELF_ASSIGNABLE`.

### 3.7 Signed envelopes

```http
POST /api/v1/assurance/cases/{case_id}/events
Content-Type: application/json
```
with the signed envelope of data-model §7.3. The signature is verified against the
tenant's registered keys; a valid signature sets each record's producer
`identity_basis` to `signed:<key_id>` and `attested_by`. An invalid signature is a
400 for the whole envelope — unlike a malformed record, a bad signature says
something about every record inside it.

Unsigned envelopes are accepted and marked `unauthenticated`. Requiring PKI before
the first useful answer puts the tool out of reach on day zero.

**A signature is provenance, not trust** (Invariant 11). It changes
`identity_basis`. It does not change `epistemic_status`, and it never makes a
DECLARED record VERIFIED.

---

## 4. Idempotency: two mechanisms, two jobs

Conflating these is the second common design error available here. They protect
different things and neither substitutes for the other.

### 4.1 Intrinsic — content addressing (all intake)

A record's identity is the digest of its canonical form. Submitting it twice is
submitting the same thing twice, and the ledger's primary key collapses it.

This requires **nothing from the client**. No key, no sequence number, no
coordination between the forty agents that all observed the same tool call. It
works across requests, across processes, across retries after a timeout where the
client never learned whether the first attempt landed.

It covers: `/events`, `/evidence`, `/claims`, `/artifacts`, `/execution`,
`/completeness`, and `POST /cases`.

> **What content addressing does not collapse.** Two records that differ only in a
> producer-supplied timestamp are different records and both are kept. This is
> correct — two observations of the same fact by the same producer at different
> times is information, and deduplicating it would fabricate independence. Clients
> that want dedupe across retries should send byte-identical retries, which is what
> a retry is.

### 4.2 Extrinsic — `Idempotency-Key` (transitions only)

Finalize and approve are not content-addressable: they are *transitions*, and
replaying one must return the original outcome rather than perform it again.

```http
POST /api/v1/assurance/cases/{case_id}/finalize
Idempotency-Key: 5f3a91c2-…
If-Match: W/"mset:sha256:7ab3…"
```

Stored as `(tenant_id, key) → (request_digest, response_body, status_code)`,
retained 24h (`RG-IDEMPOTENCY-TTL`).

* Same key, same request digest → the stored response, byte-identical, with
  `Idempotency-Replayed: true`.
* Same key, **different** request digest → `409 IDEMPOTENCY_KEY_REUSED`. The key
  identified a different intent; silently serving the old response would be worse
  than failing.
* No key on `/finalize` or `/approve` → `400 IDEMPOTENCY_KEY_REQUIRED`. These are
  the operations where an ambiguous retry has a consequence, so the key is not
  optional.

### 4.3 Why not one mechanism

An idempotency key on intake would be strictly worse: it makes correctness depend
on client discipline, it cannot deduplicate the same observation arriving from two
different workers, and it fails exactly where it matters — a worker that crashed
before recording which key it used. Content addressing has no such failure.

Conversely, content addressing cannot make finalize idempotent, because the request
body is not the outcome. The outcome depends on the case state at the moment of the
call, which is precisely what must not be recomputed on a replay.

---

## 5. Out-of-order events

### 5.1 The fold is order-independent

Three properties already hold in the implementation and this protocol depends on
all three:

1. `RecordCollection` aggregation is commutative — counts, multiset commitments and
   Merkle roots over sorted leaves do not depend on insertion order.
2. `ExecutionGraph` defers *all* parent resolution to `build()`. A child span
   arriving before its parent produces the same graph as the reverse. This was
   built in PROMPT 7 and verified against shuffled input; it is what makes span
   intake across thousands of concurrent workers safe.
3. `ClaimGraph` evidence linkage runs as a whole-graph pass (`link_evidence`), not
   incrementally at insert.

Therefore: **arrival order cannot affect `case_digest`.** §18 asserts it directly by
shuffling.

### 5.2 A reference to something that has not arrived

Evidence naming `claim cl_7` when `cl_7` has not been sent is the normal case, not
an error. A 20-agent fleet has no way to guarantee the claiming agent posts before
the verifying one.

The record is **accepted**, and a pending reference is recorded:

```json
{"from": "sha256:1c4f…", "to": {"kind": "claim", "id": "cl_7"}, "since": "2026-09-13T09:14:02Z"}
```

When `cl_7` arrives, the reference resolves. Nothing is retried, nothing is
buffered, no worker waits.

If it never arrives, then at finalize the unresolved references become:

* a `MISSING` node in the `EvidenceGraph` — the node kind that already exists for
  exactly this,
* an `UNOBSERVED` node in the `ExecutionGraph` where the reference was to a span,
* a coverage row stating what was referred to and never supplied.

They are never an error, and they are never invisible. `GET /cases/{id}` reports
`pending_references` at all times, and the finalize response reports how many never
resolved, because a verdict resting on four hundred dangling references is a verdict
whose coverage a human needs to see.

### 5.3 Why not buffer and reorder

Buffering requires a completion signal to know when to stop waiting, and §6 is
about the fact that no such signal exists. A server that buffers is a server that
eventually evicts, and an eviction is a silently dropped record — the one failure
this protocol may not have.

---

## 6. Completeness: the server never infers that a stream ended

**A closed connection is not a finished stream.** Neither is a timeout, an idle
period, nor a client calling finalize. Each of those is equally consistent with a
worker that crashed mid-batch.

There is no `COMPLETE` status anywhere in this system, and the protocol does not
introduce one. What it offers is the ability for a producer to *declare* its intent
so that a shortfall becomes visible:

```json
{"record_type": "completeness", "declaration_id": "cd_1",
 "scope": {"stream_id": "run-8821", "producer_id": "worker://fleet/331"},
 "expected_sequence": {"from": 1, "to": 412}}
```

At finalize the declaration is compared against what arrived, yielding the existing
`CompletenessStatus`:

| | |
|---|---|
| `MATCHES_DECLARATION` | every declared item arrived |
| `GAPS_DETECTED` | a declaration exists and items are missing — the gaps are enumerated |
| `UNKNOWN` | no declaration was made; nothing can be said |

`UNKNOWN` is the default and is not a failure. It is the truthful answer to "did
everything arrive?" when nobody said what everything was.

This is the protocol's answer to Invariant 13. Without declarations, a producer
whose evidence was dropped in transit and a producer that had no evidence are
indistinguishable — and the case would quietly treat a transport failure as an
absence of findings. With them, the difference is mechanical.

---

## 7. Concurrency: appends commute, transitions do not

### 7.1 ETag

| Case state | ETag | Meaning |
|---|---|---|
| DRAFT | `W/"mset:sha256:7ab3…"` | `multiset_digest(accumulator, count)` over intake |
| SEALED / DECIDED / APPROVED | `"sha256:9f2c…"` | `case_digest` |

The weak/strong distinction is meaningful rather than decorative. The open-case tag
is a commitment to *what arrived*, computed additively in constant memory and
independent of order. The sealed tag is `case_digest`, a commitment to a fixed
argument.

> **Honest limit.** `rg-mset-1` is an additive multiset commitment. It detects that
> two intakes differ; it supports **no inclusion proofs**. "Is record X in this
> case?" is answered after sealing, by the ordered Merkle structure behind
> `evidence_digest`. The ETag is for concurrency control, not for audit.

### 7.2 Appends need no precondition

`If-Match` is **ignored** on every intake door. Not rejected — ignored, and a
client that sends one gets a `PRECONDITION_IGNORED` warning explaining why.

Appends commute. Ten thousand workers posting evidence concurrently cannot
conflict: the ledger's primary key handles duplicates, `multiset_merge` is
associative, and the fold is order-independent. Requiring `If-Match` here would
manufacture a conflict that does not exist and serialise a workload that is
naturally parallel. It is the difference between an endpoint that supports a fleet
and one that supports a client.

### 7.3 Transitions require a precondition

`If-Match` is **required** on `/finalize`, `/approve`, and `/revise`. These do not
commute; "seal and decide" means something different depending on what had arrived.

```http
POST /api/v1/assurance/cases/{case_id}/finalize
If-Match: W/"mset:sha256:7ab3…"
```

If evidence arrived since the client read that tag, the case is not the case it
decided to finalize: `412 PRECONDITION_FAILED`, with the current tag and the
intake delta so the client can decide whether the new evidence matters.

Missing `If-Match` on a transition is `428 PRECONDITION_REQUIRED`. This is the one
place the protocol is strict, and it is strict because sealing a case while
evidence is still landing is how a verdict comes to overstate its coverage.

### 7.4 The two-writer case

Worker A and worker B both finalize. Both hold tag `T`. A wins; the case is SEALED
at `case_digest D`. B gets 412. B re-reads, sees SEALED, and reads the decision
instead of making one. No lost update, no double decision, no lock held across a
network round trip.

---

## 8. What is readable, and when

> **Vocabulary.** The state machine is the model's, not a new one. `DRAFT` is
> the intake-open state; this document says "open" in prose and always
> `DRAFT` on the wire. There is no `OPEN`, no `CLOSED`, and no API-only state —
> a second vocabulary for the same lifecycle is how the two drift apart.

This asymmetry is the protocol's most consequential rule.

| Endpoint | DRAFT case | SEALED / APPROVED |
|---|---|---|
| `GET /cases/{id}` | 200 — provisional view, `"state": "DRAFT"` | 200 |
| `GET /cases/{id}/records` | 200 | 200 |
| `GET /cases/{id}/attention` | **200** | 200 |
| `GET /cases/{id}/required-evidence` | **200** | 200 |
| `GET /cases/{id}/decision` | **409 `CASE_NOT_FINALIZED`** | 200 |
| `GET /cases/{id}/evidence-pack` | **409** | 200 |

**You may always ask what is missing. You may only ask what was decided once the
stream is closed.**

### 8.1 Why attention is readable while open

`GET /required-evidence` on an open case is the steering signal a running agent
needs: *what would I have to produce for this to be decidable?* An agent that can
only learn this after finalizing has to finalize to find out, which defeats the
purpose.

What makes this safe to expose is not monotonicity. **The required set is not
monotone and the response must not imply it is.** A newly arrived claim can carry
new obligations, so the set can grow; and the methodology's *none-of-these* checks
(no unresolved contradiction, no independence violation) can flip from satisfied to
unsatisfied as evidence lands. Only the *at-least* checks — `MinimumRecords`,
`CollectionSupplied` — are monotone under arrival.

What makes it safe is that a gap statement carries no authority. It says "this is
missing right now"; nobody can act on it as a decision, and nobody can cite it as a
coverage claim. A verdict cannot say that, which is why the decision waits. The
response therefore carries `"basis": "PROVISIONAL"`, the intake tag it was computed
at, and per-item `"monotone": true|false` so a caller knows which items can come
back.

### 8.2 Why the decision is not

A verdict is inseparable from its coverage statement (Invariant 9). A verdict
computed over a stream that is still arriving would carry a coverage statement that
was true at computation time and false by the time anyone read it — it would say
"assessed these 4,098 records" while a 4,099th was in flight, and no field in the
response could make that honest.

So there is no provisional decision, no `?preview=true`, and no
`"decision_so_far"`. The only way to obtain a decision is to close the intake,
which is an explicit act with a precondition (§7.3). A client that wants a fast
answer should finalize a small case, not peek at a large one.

### 8.3 Sufficiency is the methodology's job, not the protocol's

Finalize does **not** refuse a case with gaps, dangling references, or a truncated
stream. It renders the verdict the evidence supports and states the coverage
honestly.

A methodology may absolutely require that no gaps exist — `CollectionSupplied`,
`MinimumRecords`, `CoverageDimensionDeclared` are exactly that — and then `assess()`
returns UNSATISFIED and the verdict is HOLD or BLOCK, with `RequiredEvidence`
naming the shortfall.

The layering is deliberate: **the protocol enforces shape, the methodology enforces
sufficiency.** A protocol with opinions about sufficiency would be a policy engine
with a URL, and it would be the wrong place to change those opinions.

---

## 9. Late verification

A formal verification, a slow eval suite, or a human review that completes after the
decision was rendered.

### 9.1 Before finalize

Ordinary intake through `/verification`. Nothing special.

### 9.2 After finalize

```http
POST /api/v1/assurance/cases/{case_id}/verification
```

The sealed version is **not modified**. Its bytes, its `case_digest`, its verdict
and its approval remain exactly as they were, forever. That is what "immutable
historical state reference" has to mean to be worth anything.

Instead, the verification lands in the next version:

```json
{
  "recorded": "sha256:4d1a…",
  "applied_to": {"case_id": "case_9f2c…", "case_version": 2, "state": "DRAFT"},
  "created_version": true,
  "sealed_version_unchanged": {"case_version": 1, "case_digest": "sha256:D1…"},
  "standing_change": "CONTRADICTED"
}
```

Version 2 is opened via the existing `revise()`, which returns a DRAFT with the
verdict cleared and — critically — **approvals dropped**. `describe_supersession()`
returns `approval_carryover_permitted: false` unconditionally. A later version is a
re-argued case and inherits no authorisation. The protocol has no override for
this; there is no query parameter and no header that carries an approval forward.

### 9.3 Standing: valid is not the same as still supported

```http
GET /api/v1/assurance/cases/{case_id}/standing
```

```json
{
  "case_version": 1,
  "case_digest": "sha256:D1…",
  "approval": {
    "valid": true,
    "binds_to": "sha256:D1…",
    "approver": "person://…",
    "verified_at": "2026-09-13T12:04:11Z"
  },
  "standing": "CONTRADICTED",
  "contradicted_by": ["sha256:4d1a…"],
  "since": "2026-09-13T15:41:55Z",
  "remedy": "case_version 2 is open and carries the refuting verification"
}
```

`valid` is about the signature: does this approval cryptographically bind to this
state, and did the named person make it? It stays `true`. Nothing that happens
later can retroactively unmake an approval that was made.

`standing` is about the world: is the argument that approval rested on still
supported? `SUPPORTED` / `CONTRADICTED` / `SUBJECT_MUTATED` / `SUPERSEDED`.

These are never merged into one field, for the same reason the evidence model keeps
four status axes apart. An approval whose subject was refuted is not an invalid
approval — it is a valid approval of something that turned out to be wrong, and
those call for different human responses. Collapsing them would either make people
distrust their own audit trail or let them act on a contradicted authorisation.

`SUBJECT_MUTATED` comes from `check_subject()` and is evaluated on every read of
this endpoint, so "has the thing I approved changed underneath me" is answerable at
the moment of use rather than only at decision time.

---

## 9a. The approval endpoint: read the bound state, acknowledge it, submit

> **Implemented.** `release_gate/assurance/approval.py` —
> `offer_approval()` / `submit_approval()`. The transport below is the binding;
> the mechanism is transport-agnostic and lives in the library.

```http
GET  /api/v1/assurance/cases/{case_id}/approval-offer     # the read half
POST /api/v1/assurance/cases/{case_id}/approve            # the write half
```

§7.3 already requires `If-Match` on `/approve`. That is optimistic concurrency on
an *opaque* token, and it is not enough on its own. An ETag says "the case you
read". It does not say **what the client took that case to be**, and a client that
echoes a token it never looked inside has acknowledged nothing.

So the write half requires three named values, and all three:

```json
{"acknowledged": {"case_version": 1,
                  "subject_digest": "sha256:S1…",
                  "evidence_pack_digest": "sha256:E1…"},
 "decision": "APPROVED", "approver": "person://…", "scope": "deploy:staging"}
```

**A partial acknowledgement is a refusal, not a weaker acknowledgement.**
Acknowledging the version but not the subject digest is precisely the gap this
two-step exists to close, so it returns `400 INCOMPLETE_ACKNOWLEDGEMENT` naming
the fields that were absent — never a lenient accept.

### 9a.1 The read half returns exactly what would be approved

`GET /approval-offer` returns the three acknowledgement values, the per-collection
digests, the recommendation, and **the approval packet (§8a) in the same
response**. One call rather than two, because a client that fetches the values
and the document separately can straddle a change and present a human with a
packet describing one state while acknowledging another.

> **An offer is not a lock, and the payload says so** (`"is_a_lock": false`).
> Optimistic concurrency reserves nothing: two clients may hold offers against
> the same state, the first to submit wins, and the second is told the state
> moved. An offer that *looked* like a lock would be worse than no offer, because
> a client would stop checking.

### 9a.2 There is no "approve latest"

Not discouraged — unexpressible. `submit_approval` takes the acknowledgement as a
required positional argument, and an empty one returns
`INCOMPLETE_ACKNOWLEDGEMENT` rather than defaulting to current state. A read and
a write that are not bound to the same version are a race with a human signature
on the losing side.

Note that "approve latest, atomically" reduces to this anyway: the only way to
make the read and the write atomic is for the client to name the version it read
and the server to check it at write time, which is what this is.

### 9a.3 The acknowledgement is verified against the live case

Never against the offer object the caller holds. An offer is a convenience for
the human; treating it as the authority would let a fabricated one authorise
anything. A forged offer whose digests do not match the case conflicts like any
other stale read.

### 9a.4 A conflict says whether the human must look again

`409` / `CONFLICT` returns the current state and one further bit:

| what moved | `evidentiary_change` | what the client should do |
|---|---|---|
| subject, evidence pack, or version | `true` | re-present the packet; the basis of the decision moved |
| case digest only | `false` | re-acknowledge; release-gate found different things to say about the same evidence |

The second case still conflicts — it is never silently accepted — but a coverage
row changing should not force a person to re-read a packet describing evidence
that did not move. Same evidentiary-versus-derived split as §9 and §8a.

---

## 10. Case versioning and historical references

```http
GET /api/v1/assurance/cases/{case_id}                   # current version
GET /api/v1/assurance/cases/{case_id}?version=2         # that version
GET /api/v1/assurance/cases/{case_id}?at=sha256:9f2c…   # that exact state
GET /api/v1/assurance/cases/{case_id}/versions          # the chain
```

`?at=` is the immutable reference. Responses to it are byte-identical across time
and carry `Cache-Control: public, max-age=31536000, immutable` — the one place in
this API where hard caching is correct, because the resource cannot change by
construction.

Three outcomes, all distinct:

* **200** — that state existed and is retained.
* **404** — no such state ever existed for this case.
* **410 `STATE_PRUNED`** — it existed and the tenant's retention policy removed it.

410 rather than 404 matters. An auditor asking for an approved state and getting
"not found" learns nothing; getting "this was deleted under a retention policy on
this date" learns exactly what happened. An audit trail that cannot distinguish
"never was" from "no longer kept" is not an audit trail.

Versions only ever move forward. There is no unseal, no reopen, and no way to move
a sealed version back to DRAFT — `_TRANSITIONS` does not permit it and the API
exposes no verb for it.

---

## 11. Endpoint reference

All under `/api/v1/assurance/`. **Prefix note:** the proposal in the task used a
bare `/v1/…`. That cannot work against the current app — `_serve_spa`
(`@app.get("/{full_path:path}")`) returns the SPA's HTML for every path that does
not start with `api/`, so `/v1/assurance/cases` would return a web page with a 200.
Mounting under `/api/v1/` preserves the existing guard untouched and keeps the new
surface consistent with `/api/audit`, `/api/verify`, `/api/dashboard`.

### Writes

| Method | Path | Idem. | If-Match | Scope | Success |
|---|---|---|---|---|---|
| POST | `/cases` | intrinsic | — | `assurance:write` | 201 new / 200 existing |
| POST | `/cases/{id}/events` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/evidence` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/claims` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/artifacts` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/execution` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/verification` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/completeness` | intrinsic | ignored | `assurance:write` | 200 |
| POST | `/cases/{id}/finalize` | **key** | **required** | `assurance:decide` | 200 |
| GET | `/cases/{id}/approval-offer` | — | — | `assurance:read` | 200 |
| POST | `/cases/{id}/approve` | **key** | **required** | `assurance:approve` | 201 |

> `/approve` additionally requires the three-field acknowledgement (§9a); `If-Match` alone is not sufficient, because an opaque token does not record what the client took the case to be.
| POST | `/cases/{id}/revise` | **key** | **required** | `assurance:write` | 201 |

### Reads

| Method | Path | DRAFT case | Scope |
|---|---|---|---|
| GET | `/cases` | 200 (paged, filterable) | `assurance:read` |
| GET | `/cases/{id}` | 200 provisional | `assurance:read` |
| GET | `/cases/{id}/versions` | 200 | `assurance:read` |
| GET | `/cases/{id}/records` | 200 (paged) | `assurance:read` |
| GET | `/cases/{id}/graph/{kind}` | 200 (paged, projected) | `assurance:read` |
| GET | `/cases/{id}/attention` | 200 provisional | `assurance:read` |
| GET | `/cases/{id}/required-evidence` | 200 provisional | `assurance:read` |
| GET | `/cases/{id}/decision` | **409** | `assurance:read` |
| GET | `/cases/{id}/standing` | 200 | `assurance:read` |
| GET | `/cases/{id}/evidence-pack` | **409** | `assurance:read` |
| GET | `/methodologies` | 200 | `assurance:read` |
| GET | `/methodologies/{ref}` | 200 | `assurance:read` |

### Departures from the proposed surface

Names were offered as proposals; these are the changes and why.

1. **`/api/v1/` prefix** rather than `/v1/` — the SPA catch-all, above.
2. **`POST /cases/{id}/approve` added.** The proposed list ends at `finalize`, which
   produces a verdict. But a verdict is release-gate's output and an approval is a
   *human's* act of taking responsibility, bound to an exact `case_digest`. The
   product's entire thesis is the gap between those two, and a surface with no
   approval endpoint can express a decision but not an authorisation.
3. **`POST /cases/{id}/revise` added** — the explicit form of what late verification
   does implicitly (§9.2). Without it, a client that wants to re-argue a sealed case
   has to mutate one, and there must be no verb that does that.
4. **`GET /cases/{id}/records` added.** Without read-back a large case is
   write-only: a client cannot verify what the server actually holds, which makes
   every coverage statement unauditable.
5. **`GET /cases/{id}/standing` added** — §9.3.
6. **`POST /cases/{id}/completeness` and `/execution` added** as typed doors — the
   first because §6 has no other mechanism, the second because it is the volume path
   and deserves its own limits and its own adapter dispatch.
7. **`/events` kept, and promoted.** In the proposal it reads as one door among
   several; here it is *the* door and the rest are wrappers over it (§3.2).
8. **`finalize` kept as a composite.** It is `seal()` then `render_verdict()`. Two
   endpoints would let a client seal and never decide, leaving cases in a state
   that is neither open nor answered. One verb, two internal steps, reported
   separately in the response.

---

## 12. Errors

Existing endpoints raise `HTTPException(status_code, detail="a sentence")`. That
convention is preserved everywhere it exists today.

The assurance surface uses a structured `detail`, and this is a deliberate, scoped
divergence:

```json
{"detail": {
  "code": "CASE_NOT_FINALIZED",
  "message": "this case is still open; a decision is available after finalize",
  "remedy": "POST /api/v1/assurance/cases/case_9f2c…/finalize with If-Match: W/\"mset:sha256:7ab3…\"",
  "case_state": "DRAFT"
}}
```

The justification is that these responses are read by agents, not by people. An
agent needs a stable symbol to branch on and an actionable next step; a prose
sentence gives it neither. `remedy` is the same discipline the engine already
applies to `NOT_ASSESSED` — never report a gap without naming what would close it.

| Code | HTTP | |
|---|---|---|
| `CASE_NOT_FOUND` | 404 | unknown to this tenant |
| `CASE_SEALED` | 409 | intake on a sealed version |
| `CASE_NOT_FINALIZED` | 409 | decision requested while open |
| `CASE_IDENTITY_CONFLICT` | 409 | truncated id match, different identity |
| `PRECONDITION_REQUIRED` | 428 | transition without `If-Match` |
| `PRECONDITION_FAILED` | 412 | intake moved since the tag was read |
| `IDEMPOTENCY_KEY_REQUIRED` | 400 | transition without a key |
| `IDEMPOTENCY_KEY_REUSED` | 409 | key reused with a different body |
| `ENVELOPE_MALFORMED` | 400 | NDJSON framing or signed envelope |
| `ENVELOPE_SIGNATURE_INVALID` | 400 | signature failed |
| `BODY_TOO_LARGE` | 413 | over `RG-MAX-BODY` |
| `SCOPE_REQUIRED` | 403 | token lacks the scope |
| `STATE_PRUNED` | 410 | retained no longer |
| `RATE_LIMITED` | 429 | with `Retry-After` |

Per-record codes (`RECORD_MALFORMED`, `STATUS_NOT_SELF_ASSIGNABLE`,
`RECORD_TYPE_UNKNOWN`, `SUBJECT_REF_MISSING`) appear only inside a 200 body (§3.4)
and never as an HTTP status.

---

## 13. Auth, scopes, and the asymmetry that is the product

Authentication is unchanged: `Authorization: Bearer <jwt>` or an `rg_*` token, via
the existing `_current_user`.

Scopes are new and additive — existing tokens are grandfathered to
`assurance:read assurance:write`, which means **no existing token can finalize or
approve**. Fail-closed is the right default for a capability that did not exist
when the token was issued.

| Scope | Grants |
|---|---|
| `assurance:read` | every GET |
| `assurance:write` | intake, create, revise |
| `assurance:decide` | finalize |
| `assurance:approve` | approve |

The rule the product exists to enforce:

> **A token that can write evidence must not be able to approve.**

`assurance:write` and `assurance:approve` are refused on the same token at issuance.
An agent that could both produce the evidence and accept it has removed the
independent party from the loop, which is the one thing this system is for.

The MCP server never requests `assurance:decide` or `assurance:approve`. An agent
may inspect its own case, see its own attention items, and learn what evidence
would resolve a hold. It cannot decide and cannot approve — enforced at the token
boundary, not by convention, so an agent that talks its way into a different prompt
still cannot do it.

Approval additionally requires an *interactive* identity — a JWT from a login, not
a machine token — because Invariant 15 makes approval an act of a named person
taking responsibility, and a shared service token names nobody.

---

## 14. Scale and limits

| Knob | Default | |
|---|---|---|
| `RG-MAX-BODY` | 32 MiB | per request |
| `RG-MAX-BATCH` | 1,000 | records per JSON (not NDJSON) door |
| `RG-MAX-RECORD` | 256 KiB | per record; larger must be referenced |
| `RG-MAX-CASE-RECORDS` | 10,000,000 | per version, then `CAPPED` basis applies |
| `RG-MAX-PENDING-REFS` | 100,000 | then aggregated rather than enumerated |

**Large content is referenced, not uploaded.** `external_content()` exists for
this: a 4 GB model checkpoint contributes its digest and a locator. The endpoint
is not a blob store and does not become one.

**Retention and materialisation.** A tenant chooses whether `body` is stored or
only digests and metadata. Digests-only is the default. A case whose bodies were
never stored still verifies its own commitments and still reports honest coverage —
it simply cannot show a reviewer the record text, and says so.

**The 10,000-worker shape.** Workers hold `assurance:write` only. They post spans
and evidence to one case id, concurrently, with no coordination, no session, and no
ordering. The case's materialisation basis is `RELEVANCE_DIRECTED`, so the retained
set is bounded by what is on a path to the proposition while counts and commitments
cover everything. One orchestrator — or one human — holds `assurance:decide`.

**What is O(n) and what is not.** Intake is O(records) with constant memory per
request; the accumulator fold is O(1) per record. Finalize evaluates the
methodology over O(retained), not O(received) — which is the whole reason
relevance-directed materialisation exists, and why a case with ten million records
can be decided inside one HTTP request. Two parts of finalize *are* O(received) and
are stated rather than hidden: the completeness comparison (§6) and the intake
recomputation (§17.6). Both are database aggregates over an indexed ledger, not
in-process scans, so neither loads the stream.

---

## 15. Local parity

Every endpoint has a CLI equivalent, and the wire format is the file format — the
NDJSON a client POSTs is the NDJSON the CLI reads. A case built locally and a case
built through the API from the same records, under the same `source`, produce the
same **`records_digest`** and the same decision. Anything else would make the
hosted service a different product wearing the same name, and would mean a local
reproduction could not check a hosted decision.

**Not the same `case_digest`, and deliberately so.** This section previously
claimed that, and it was wrong. Release-gate records the input container as
evidence in its own right: a file on disk is a FILE content reference carrying a
path, and records posted over a wire are an INLINE reference carrying none. Those
are different inputs, and forcing the digests equal would mean fabricating a file
reference for a submission that never touched a disk — the assertion-over-evidence
this protocol exists to refuse. `records_digest()` covers the records a client
submitted and excludes release-gate's own note about how they arrived, which is
the comparison a reproduction actually needs.

---

## 16. No YAML

Nowhere on this surface does YAML appear: not for methodology, not for policy, not
for configuration.

* Methodology by reference: `{"methodology": "software-change-v1"}`.
* Methodology inline: a JSON object matching `AssuranceMethodology`.
* Methodology omitted: `default_case_type(subject.subject_type)` selects a built-in, and
  the response states which one and why (§10 of the architecture spec).

`governance.yaml` remains supported *as an evidence producer* — its contents become
DECLARED evidence through `ingest/from_governance.py`, which is the correct
epistemic status for a file in which a team wrote down what it intends. It is never
policy input on this surface.

`POST /api/verify` keeps its `governance_yaml` field. It is a different, shipped
surface with existing users; this rule is about the assurance protocol.

---

## 17. Failure modes

**17.1 Silent intake loss.** The failure this protocol may not have. A dropped
record makes every coverage statement downstream a lie. Mitigation: per-record
accounting (§3.4), the ledger as the single source of truth, completeness
declarations (§6), and read-back (`GET /records`). A client that wants certainty can
compare its own multiset digest to the server's.

**17.2 Pending-reference flood.** A producer that references thousands of records it
never sends inflates pending references and makes coverage unreadable. Mitigation:
`RG-MAX-PENDING-REFS`, then aggregation by producer — and the aggregate itself is a
coverage signal worth surfacing, because a producer that dangles 100,000 references
is broken and the case should say so.

**17.3 Finalize contention.** A busy case where every finalize attempt 412s against
continuing intake. This is the protocol working — the case genuinely is not done —
but a client can livelock. Mitigation: the 412 body carries the intake delta so a
client can see whether the new evidence is relevant, and a case may declare an
intake deadline after which writes are refused with `CASE_SEALED`.

**17.4 Idempotency key collision across producers.** Two workers generating the same
key. Mitigation: keys are scoped per tenant and required to be ≥ 16 bytes of
entropy; a reused key with a different body is a 409, never a silent replay.

**17.5 Approval standing is polled, not pushed.** Someone who approved at T and
deployed at T+1 will not learn about a contradiction at T+2 unless they look.
Honest limit — §0.5 explicitly declines to build notification delivery. Mitigation
is documentation and a `standing` field in the evidence pack, so the pack a
reviewer opens shows it even if nobody polled.

**17.6 Accumulator drift.** A bug in delta computation would desynchronise the
intake commitment from the ledger, and the ETag would be wrong without anything
failing. Mitigation: the accumulator is recomputable from the ledger by definition,
finalize recomputes and compares, and a mismatch is a hard error rather than a
correction — a commitment that silently repairs itself is not a commitment.

**17.7 Tenant retention destroying an approved state.** Mitigation: 410 with the
policy date (§10), and approved states are excluded from automatic pruning by
default. An operator can still delete them deliberately; the protocol's obligation
is to make the deletion legible, not to prevent it.

---

## 18. Acceptance tests

1. **Shuffled arrival.** N records, ten random orders, ten arbitrary groupings into
   requests. All ten produce the same `case_digest`, the same verdict, and the same
   coverage. This is the central test; if it fails the protocol is unsound.
2. **Duplicate flood.** Every record sent five times across overlapping concurrent
   requests. `accepted` totals N, `duplicate` totals 4N, `case_digest` equals the
   single-submission case.
3. **Concurrent writers.** Twenty simultaneous streams into one case. No 409, no
   lost record, ledger count equals the union of what was sent.
4. **Decision before finalize.** `GET /decision` on an open case returns 409 in every
   state and cannot be coaxed into a provisional verdict by any parameter.
5. **Attention before finalize.** `GET /required-evidence` returns 200 and is marked
   PROVISIONAL. Items from at-least checks only clear as evidence arrives; items
   from none-of-these checks are permitted to reappear, and the test asserts they
   are flagged `"monotone": false` rather than asserting they never do.
6. **Dangling reference.** Evidence referencing an absent claim is accepted; the
   claim's later arrival resolves it; a claim that never arrives becomes a MISSING
   node and a coverage row, never an error.
7. **Truncated stream.** A declared 412-record stream that delivers 380 yields
   `GAPS_DETECTED` with the gaps enumerated; the same 380 with no declaration yields
   `UNKNOWN`. Both still render a verdict.
8. **Late verification.** A refutation after approval leaves v1's bytes,
   `case_digest`, verdict and approval identical; opens v2 without the approval;
   and flips standing to CONTRADICTED while `approval.valid` stays true.
9. **Precondition.** Finalize with a stale `If-Match` is 412; without `If-Match` is
   428; intake with `If-Match` succeeds and warns.
10. **Idempotent finalize.** The same key and body replays byte-identically; the same
    key with a different body is 409.
11. **Idempotent creation.** `POST /cases` twice returns one `case_id`, 201 then 200.
12. **Scope asymmetry.** A token with `assurance:write` gets 403 on finalize and on
    approve. No token can hold both `write` and `approve`.
13. **Producer status laundering.** A POST claiming `"epistemic_status": "VERIFIED"`
    yields a DECLARED record with `content.producer_claimed_epistemic_status`, a
    warning in the response, and no change to the verdict.
14. **Immutable reference.** `?at=<digest>` returns byte-identical responses before
    and after v2 exists; a pruned state is 410, an unknown one 404.
15. **Door equivalence.** The same record through `/events` and through its typed
    door produces identical ledger rows and an identical `case_digest`.
16. **Local parity.** The same NDJSON through the API and through the CLI produces
    the same `case_digest`.
17. **Scale.** 1,000,000 records across 200 concurrent requests: constant memory per
    request, finalize inside one request, `case_digest` reproducible from the ledger.

---

## 19. Open questions

Named rather than silently decided.

1. **Intake deadlines.** §17.3 proposes an optional deadline after which a case
   refuses writes. It solves livelock but introduces a clock into a system that has
   so far avoided one. Deferred until a real workload demonstrates the livelock.
2. **Cross-case evidence reuse.** The same evidence record legitimately belongs to
   several cases. Content addressing makes sharing the storage trivial, but sharing
   raises an independence question — two cases citing one record are not
   independently corroborated. Until `RG-INDEP-*` has an answer, evidence is stored
   per case and the duplication is accepted.
3. **Partial evidence packs.** Whether a pack may be rendered for a case version
   whose bodies were pruned. Leaning yes, with the pack stating what it cannot show,
   consistent with how coverage is handled everywhere else.
4. **Approval delegation.** Whether an organisation may authorise a role rather than
   a person. Invariant 15 says approval is a named person's act; role-based approval
   may be a legitimate refinement or may be the first step to laundering
   responsibility. Not decided here.
