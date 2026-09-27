"""Evidence that lives in somebody else's system, and what pointing at it settles.

A large company does not keep its evidence in one place. The trace is in
Langfuse, the test run is in GitHub Actions, the model weights are an S3 key, the
cohort is a Snowflake table, the proof is a Lean file, the experiment is in MLflow
and the assay was run by a lab in another country. Release-gate is not going to
hold any of that, and should not: §10aa already says a store is not an authority
and §10ab already says proprietary content must never have to leave the
environment that produced it.

So the question is not how to copy it all in. It is what a *reference* is worth.

## "Verify identity/digest without copying" is three questions

Run together they produce a case that reads as clean while resting on nothing, so
they are three fields here and never one:

* **Identity** — does this reference name the object the case says it does?
* **Integrity** — do the bytes at that reference hash to the claimed digest?
* **Availability** — is it there *now*?

A content-addressed reference settles identity for free and says nothing about
whether the object exists. An existence probe settles availability and nothing
about content. Only re-reading the bytes settles integrity on release-gate's own
authority, and that transfers everything, which is the thing the brief asks to
avoid. Every method sits somewhere on that grid, and `ESTABLISHMENT_TABLE` is the
grid rather than a series of branches that could disagree with each other.

Availability is separated out because federation is the one thing in this
architecture that genuinely weakens Invariant 5. An approval binds to an exact
state; a remote object can be deleted or rewritten the day after the approval, and
a model that folded "is it there" into "is it right" would have no way to say so.

## Establishment and authority are orthogonal, and both travel

`Establishment` says whether a question got an answer. `DigestStatus` says on
whose authority. They are not the same axis and merging them would lose the
common, legitimate case: an S3 object whose checksum the store reports is
`ESTABLISHED` *and* `DECLARED` — the question is answered, and the answer is the
store's word, not release-gate's observation. That is worth having and it is not
the same as `ESTABLISHED` + `OBSERVED`.

`DigestStatus` is `subject`'s, unchanged. "Someone else says this is the digest"
was already `DECLARED` with a `DigestMethod.EXTERNAL_ATTESTED` to go with it, and
inventing a federation-specific status would have been a second vocabulary for one
distinction.

## The adapter reports; this module adjudicates

A `Resolver` returns a `Probe`: what it did, what it saw, how many bytes it moved.
`resolve()` turns that into a `Resolution` by the table. The split is deliberate
and it is the same one §10aa draws for a work queue — a worker is a producer, not a
verifier. An adapter cannot grant itself `OBSERVED`, because an adapter that could
mark its own read authoritative is the self-attestation problem with a storage
client in front of it.

Nothing here imports a driver, a client, or a credential, and nothing here can:
this module is stdlib-only like the rest of the package. An S3 resolver, a
GitHub-Actions resolver and a Lean resolver are adapters that live outside and get
passed in.

## What the addressing decides, not what the vendor is

The finding worth leading with: **how a system addresses its objects decides what
can be verified without copying, and the vendor is almost irrelevant.** An OCI
registry and IPFS are content-addressed, so identity costs nothing. S3 and GCS
publish checksums, so integrity costs one metadata call and arrives `DECLARED`. A
trace id is opaque — it has no integrity relationship to anything, so existence is
the ceiling. And a database *query* is not an object at all: `SELECT` results are
not stable, which is why `Addressing.QUERY` exists and why a holding that uses it
cannot establish identity however cooperative the database is.

## A reference is not retained evidence

`Holding.is_held_by_release_gate` and `Resolution.retains_the_evidence` are both
unconditionally `False`, and an unresolved holding emits an `EvidenceExpectation`
with `assessed=False` — the same mechanism §10ab uses for a withheld content
class, landing in the coverage ledger rather than in a federation report nobody
reads next to the verdict (Invariants 3 and 9). Federation and privacy are the
same operation seen from two sides: in both, release-gate does not hold the bytes,
and in both the case must read as *narrower* rather than as clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Protocol,
                    Sequence, Tuple)

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.expectation import EvidenceExpectation
from release_gate.assurance.subject import ContentReference, DigestStatus, ReferenceKind

FEDERATION_SCHEMA_VERSION = 1


class FederationError(ValueError):
    """A holding or resolution described in a way that would read as more than it is."""


# ── the seven classes of system evidence actually lives in ───────────────────

class SystemClass(str, Enum):
    """What kind of system holds the evidence.

    Selects no behaviour on its own — `Addressing` decides what is verifiable, and
    a class is how a reviewer knows what they are looking at. Kept as the brief's
    seven rather than collapsed into "external": a proof and a lab report are both
    things release-gate does not hold, and treating them as one kind of reference
    would erase the difference between a claim that can be re-checked in seconds
    and one that would take a quarter and a second laboratory.
    """

    OBSERVABILITY = "OBSERVABILITY"      # traces, spans, logs
    CI = "CI"                            # build and test runs, job logs
    OBJECT_STORE = "OBJECT_STORE"        # bytes at a key
    DATABASE = "DATABASE"                # rows, tables, snapshots, query results
    THEOREM_PROVER = "THEOREM_PROVER"    # machine-checkable proofs
    RESEARCH_SYSTEM = "RESEARCH_SYSTEM"  # experiment trackers, datasets, archives
    EXTERNAL_LAB = "EXTERNAL_LAB"        # another organisation's measurements

    def describe(self) -> str:
        return _CLASS_NOTE[self][0]

    @property
    def independently_recheckable(self) -> bool:
        """Whether the holding's *claim* can be re-established by another party cheaply.

        The axis that separates a proof from an assay, and it is not about
        federation mechanics at all — it is about what a lost reference costs. A
        Lean proof is a file anybody can re-check; a trace of a run that has
        finished, and a lab's measurement of a physical sample, cannot be
        reproduced from the reference by anyone. For those, losing the holding
        loses the evidence, which is why availability is reported separately.
        """
        return _CLASS_NOTE[self][1]


_CLASS_NOTE: Mapping[SystemClass, Tuple[str, bool]] = {
    SystemClass.OBSERVABILITY: (
        "traces and spans of runs that have already finished; ids are usually "
        "opaque and the retention window is the platform's, not the case's", False),
    SystemClass.CI: (
        "build and test runs; the verdict is usually retained far longer than the "
        "logs and artifacts behind it, so a green run can outlive its evidence", False),
    SystemClass.OBJECT_STORE: (
        "bytes at a key, often with a checksum the store will report, sometimes "
        "addressed by the digest itself", False),
    SystemClass.DATABASE: (
        "rows, tables and snapshots; the hard case, because a query result is not "
        "an object and a live table has no fixed content to digest", False),
    SystemClass.THEOREM_PROVER: (
        "machine-checkable proofs; the one class where re-establishing the claim "
        "is cheap relative to trusting a reference to it", True),
    SystemClass.RESEARCH_SYSTEM: (
        "experiment runs, datasets and archives; a DOI-addressed deposit is a "
        "durable reference, a scratch run directory is not", False),
    SystemClass.EXTERNAL_LAB: (
        "measurements made by another organisation on material release-gate will "
        "never see; the reference is to a report, and the report is a claim", False),
}


class Addressing(str, Enum):
    """How a holding is named, which is what decides verifiability without transfer.

    The load-bearing enum in this module. Vendor identity barely matters: two
    object stores with different addressing are further apart, for this question,
    than an object store and a CI system that both hand out opaque ids.
    """

    #: The locator *is* the digest — a git object id, an OCI manifest digest, a
    #: CID. Identity is checkable from the reference alone, at zero payload cost.
    CONTENT_ADDRESSED = "CONTENT_ADDRESSED"
    #: The store holds a checksum it will report on request. One metadata call
    #: answers integrity, on the store's authority.
    CHECKSUMMED = "CHECKSUMMED"
    #: An identifier with no integrity relationship to the content: a trace id, a
    #: run number, a row id. Existence is the ceiling without transferring.
    OPAQUE_ID = "OPAQUE_ID"
    #: The holding is the *result of a query*. Not a stable object at all.
    QUERY = "QUERY"

    @property
    def identity_is_free(self) -> bool:
        return self is Addressing.CONTENT_ADDRESSED

    @property
    def can_report_a_digest(self) -> bool:
        """Whether the system can answer 'what is this object's digest' at all."""
        return self in (Addressing.CONTENT_ADDRESSED, Addressing.CHECKSUMMED)

    def describe(self) -> str:
        return _ADDRESSING_NOTE[self]


_ADDRESSING_NOTE: Mapping[Addressing, str] = {
    Addressing.CONTENT_ADDRESSED: (
        "the locator is the digest, so a reference that names the wrong object is "
        "detectable without contacting the system at all"),
    Addressing.CHECKSUMMED: (
        "the system will report a digest it computed, which answers integrity on "
        "the system's authority and never on release-gate's"),
    Addressing.OPAQUE_ID: (
        "the identifier says nothing about content, so nothing short of reading "
        "the bytes establishes what is behind it"),
    Addressing.QUERY: (
        "the holding is a query result rather than an object; there is no fixed "
        "content for a digest to be a digest of, and repeating the query later "
        "may answer differently for reasons nobody recorded"),
}


class Custody(str, Enum):
    """Whose system this is. Provenance, never trust (Invariant 11).

    Present because the brief names external labs, and a lab is a different
    organisation. It records the boundary; it does not enforce one. Cross-tenant
    evidence separation remains `NOT_DEFENDED` (§10am.4) — naming the boundary here
    is what lets a reviewer see that two holdings sit on opposite sides of it, and
    inventing an isolation mechanism inside a federation module would be the same
    wrong place §10am.4 declined to build it in.
    """

    OWN = "OWN"                                  # this organisation runs it
    VENDOR = "VENDOR"                            # a supplier runs it for them
    OTHER_ORGANISATION = "OTHER_ORGANISATION"    # a different party entirely
    UNKNOWN = "UNKNOWN"                          # nobody recorded which

    @property
    def crosses_an_organisational_boundary(self) -> bool:
        """UNKNOWN counts. An unrecorded custodian is not a domestic one."""
        return self in (Custody.OTHER_ORGANISATION, Custody.UNKNOWN)


# ── the systems, as rows ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class FederatedSystem:
    """One system evidence may live in. Data, not a code path.

    The same shape as §10ac's dialects, §10ad's orchestrator profiles and §10af's
    source systems, for the same reason: a code path per vendor is how a consumer
    becomes a dependent. A system this build has never heard of is a row a
    deployment writes.
    """

    name: str
    label: str
    system_class: SystemClass
    addressing: Addressing
    custody: Custody = Custody.UNKNOWN
    #: What the operator of this system says about how long it keeps things.
    #: DECLARED, always — release-gate cannot measure another system's retention.
    retention_note: str = ""
    reference_kind: ReferenceKind = ReferenceKind.EXTERNAL
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "system_class", SystemClass(self.system_class))
        object.__setattr__(self, "addressing", Addressing(self.addressing))
        object.__setattr__(self, "custody", Custody(self.custody))
        object.__setattr__(self, "reference_kind", ReferenceKind(self.reference_kind))
        if not str(self.name or "").strip():
            raise FederationError("a federated system must be named so a holding can cite it")

    @property
    def retention_is_declared(self) -> bool:
        """True when somebody stated a window. Never means the window is honoured."""
        return bool(self.retention_note)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "federated_system", "record_id": self.name,
                "name": self.name, "label": self.label,
                "system_class": self.system_class.value,
                "addressing": self.addressing.value,
                "custody": self.custody.value,
                "reference_kind": self.reference_kind.value,
                "retention_note": self.retention_note,
                "retention_is_declared": self.retention_is_declared,
                "notes": self.notes,
                "schema_version": FEDERATION_SCHEMA_VERSION}


#: Every system this build can classify, in one list so the registry below cannot
#: disagree with itself about which exist. Chosen to cover all seven classes and,
#: within the object stores, all three addressing modes — because the addressing
#: is the part that changes the answer.
_SYSTEM_LIST: Tuple[FederatedSystem, ...] = (
    # ── observability ──
    FederatedSystem(
        name="langfuse", label="Langfuse", system_class=SystemClass.OBSERVABILITY,
        addressing=Addressing.OPAQUE_ID, custody=Custody.VENDOR,
        reference_kind=ReferenceKind.URL,
        notes="A trace id resolves to a console page (§10af) and to nothing a "
              "digest can be taken of. The link is for a person; it is not a check."),
    FederatedSystem(
        name="datadog", label="Datadog APM", system_class=SystemClass.OBSERVABILITY,
        addressing=Addressing.OPAQUE_ID, custody=Custody.VENDOR,
        reference_kind=ReferenceKind.URL,
        retention_note="APM trace retention is commonly 15 days by plan"),
    FederatedSystem(
        name="otlp_collector", label="OpenTelemetry collector",
        system_class=SystemClass.OBSERVABILITY, addressing=Addressing.OPAQUE_ID,
        custody=Custody.OWN, reference_kind=ReferenceKind.URL),
    # ── CI ──
    FederatedSystem(
        name="github_actions", label="GitHub Actions", system_class=SystemClass.CI,
        addressing=Addressing.OPAQUE_ID, custody=Custody.VENDOR,
        reference_kind=ReferenceKind.URL,
        retention_note="logs and artifacts expire on a repository setting, "
                       "commonly 90 days, while the run conclusion persists",
        notes="The gap this row exists to make visible: a green conclusion "
              "outlives the logs and artifacts that justified it, so a reference "
              "to the run can resolve long after the evidence behind it is gone."),
    FederatedSystem(
        name="gitlab_ci", label="GitLab CI", system_class=SystemClass.CI,
        addressing=Addressing.OPAQUE_ID, custody=Custody.VENDOR,
        reference_kind=ReferenceKind.URL),
    FederatedSystem(
        name="jenkins", label="Jenkins", system_class=SystemClass.CI,
        addressing=Addressing.OPAQUE_ID, custody=Custody.OWN,
        reference_kind=ReferenceKind.URL,
        retention_note="build discarders are configured per job, so the window is "
                       "the job's and not the platform's"),
    # ── object stores, one per addressing mode ──
    FederatedSystem(
        name="s3", label="Amazon S3", system_class=SystemClass.OBJECT_STORE,
        addressing=Addressing.CHECKSUMMED, custody=Custody.VENDOR,
        reference_kind=ReferenceKind.OBJECT_STORE,
        notes="A HeadObject returns a checksum the store computed. That answers "
              "integrity as DECLARED for one call and no payload; an ETag on a "
              "multipart upload is not a sha256 of the object and must not be "
              "read as one."),
    FederatedSystem(
        name="gcs", label="Google Cloud Storage", system_class=SystemClass.OBJECT_STORE,
        addressing=Addressing.CHECKSUMMED, custody=Custody.VENDOR,
        reference_kind=ReferenceKind.OBJECT_STORE),
    FederatedSystem(
        name="azure_blob", label="Azure Blob Storage",
        system_class=SystemClass.OBJECT_STORE, addressing=Addressing.CHECKSUMMED,
        custody=Custody.VENDOR, reference_kind=ReferenceKind.OBJECT_STORE),
    FederatedSystem(
        name="oci_registry", label="OCI registry", system_class=SystemClass.OBJECT_STORE,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.UNKNOWN,
        reference_kind=ReferenceKind.OBJECT_STORE,
        notes="A manifest is addressed by its own digest, so a reference naming "
              "the wrong image is detectable without contacting the registry. A "
              "*tag* is not: it is a mutable name, and a holding that carries one "
              "is OPAQUE_ID wearing a content-addressed coat."),
    FederatedSystem(
        name="ipfs", label="IPFS", system_class=SystemClass.OBJECT_STORE,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.UNKNOWN,
        reference_kind=ReferenceKind.EXTERNAL,
        notes="Content addressing makes identity free and says nothing about "
              "availability: a CID for an object no node is pinning is a perfectly "
              "valid name for something nobody can fetch."),
    FederatedSystem(
        name="git_remote", label="Git remote", system_class=SystemClass.OBJECT_STORE,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.OWN,
        reference_kind=ReferenceKind.GIT_COMMIT,
        notes="The object id is the digest, which is why §10c could already treat "
              "GIT_OBJECT as a DigestMethod rather than an attestation."),
    # ── databases ──
    FederatedSystem(
        name="postgres", label="PostgreSQL", system_class=SystemClass.DATABASE,
        addressing=Addressing.QUERY, custody=Custody.OWN,
        notes="A live table has no fixed content. A holding here is honest only "
              "if it names something immutable — a snapshot, an export, a "
              "point-in-time id — and QUERY is what it reads as otherwise."),
    FederatedSystem(
        name="snowflake", label="Snowflake", system_class=SystemClass.DATABASE,
        addressing=Addressing.QUERY, custody=Custody.VENDOR,
        notes="Time-travel gives a query a stable AT clause, which turns a QUERY "
              "holding into something closer to an object. Whether a given "
              "holding used one is a fact about the holding, not the platform."),
    FederatedSystem(
        name="bigquery", label="BigQuery", system_class=SystemClass.DATABASE,
        addressing=Addressing.QUERY, custody=Custody.VENDOR),
    # ── theorem provers ──
    FederatedSystem(
        name="lean", label="Lean", system_class=SystemClass.THEOREM_PROVER,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.OWN,
        reference_kind=ReferenceKind.GIT_COMMIT,
        notes="A proof is a file in a repository, so it is content-addressed for "
              "free — and unlike every other class, a party that distrusts the "
              "reference can re-check the proof instead of arguing about it."),
    FederatedSystem(
        name="coq", label="Coq / Rocq", system_class=SystemClass.THEOREM_PROVER,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.OWN,
        reference_kind=ReferenceKind.GIT_COMMIT),
    FederatedSystem(
        name="isabelle", label="Isabelle", system_class=SystemClass.THEOREM_PROVER,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.OWN,
        reference_kind=ReferenceKind.GIT_COMMIT),
    FederatedSystem(
        name="smt_solver", label="SMT solver output",
        system_class=SystemClass.THEOREM_PROVER, addressing=Addressing.CHECKSUMMED,
        custody=Custody.OWN, reference_kind=ReferenceKind.FILE,
        notes="An UNSAT result with no proof certificate is a claim about a run, "
              "not a proof; the certificate is the thing worth referencing."),
    # ── research systems ──
    FederatedSystem(
        name="mlflow", label="MLflow", system_class=SystemClass.RESEARCH_SYSTEM,
        addressing=Addressing.OPAQUE_ID, custody=Custody.OWN,
        reference_kind=ReferenceKind.URL),
    FederatedSystem(
        name="wandb", label="Weights & Biases",
        system_class=SystemClass.RESEARCH_SYSTEM, addressing=Addressing.OPAQUE_ID,
        custody=Custody.VENDOR, reference_kind=ReferenceKind.URL),
    FederatedSystem(
        name="zenodo", label="Zenodo (DOI deposit)",
        system_class=SystemClass.RESEARCH_SYSTEM, addressing=Addressing.CHECKSUMMED,
        custody=Custody.OTHER_ORGANISATION, reference_kind=ReferenceKind.URL,
        retention_note="a DOI deposit is intended to be permanent and its "
                       "checksums are published",
        notes="The strongest research reference available: a published checksum "
              "and a custodian whose whole purpose is not losing the object."),
    FederatedSystem(
        name="dvc", label="DVC", system_class=SystemClass.RESEARCH_SYSTEM,
        addressing=Addressing.CONTENT_ADDRESSED, custody=Custody.OWN,
        reference_kind=ReferenceKind.OBJECT_STORE),
    # ── external labs ──
    FederatedSystem(
        name="external_lab", label="External laboratory",
        system_class=SystemClass.EXTERNAL_LAB, addressing=Addressing.OPAQUE_ID,
        custody=Custody.OTHER_ORGANISATION, reference_kind=ReferenceKind.EXTERNAL,
        notes="Generic on purpose: a laboratory is an organisation rather than a "
              "product, and there is no API to classify. The reference is to a "
              "report, the report is a claim, and the claim was made by whoever "
              "was paid to make it — which is an independence question (§10g) "
              "before it is a federation one."),
    FederatedSystem(
        name="lab_lims", label="Laboratory information system (LIMS)",
        system_class=SystemClass.EXTERNAL_LAB, addressing=Addressing.OPAQUE_ID,
        custody=Custody.OTHER_ORGANISATION, reference_kind=ReferenceKind.URL,
        notes="A sample id is an opaque id in somebody else's database, which is "
              "the weakest reference in this registry and the one most often "
              "quoted as though it were the strongest."),
)

#: name → system. Built from the one list above.
FEDERATED_SYSTEMS: Mapping[str, FederatedSystem] = {s.name: s for s in _SYSTEM_LIST}


def system_for(name: str) -> Optional[FederatedSystem]:
    """The row for a system, or None if this build has never heard of it.

    None rather than a raise, and rather than a permissive default: a holding in an
    unregistered system is still a holding worth carrying, and `Holding` reads an
    unknown system as `Addressing.OPAQUE_ID` with `Custody.UNKNOWN` — the weakest
    reading available, not the most convenient one.
    """
    return FEDERATED_SYSTEMS.get(name)


# ── one piece of evidence, somewhere else ────────────────────────────────────

@dataclass(frozen=True)
class Holding:
    """Evidence in another system: which system, where in it, and what is claimed.

    Deliberately not a subclass or a wrapper of `EvidenceRecord`. A record already
    carries a `content_reference` and a `digest`; this is the *federation view* of
    the same fact — who holds it, under whose custody, and what a reference to it
    can establish. Making it a record would have put a second evidence model
    beside the first.
    """

    holding_id: str
    system: str
    locator: str
    claimed_digest: Optional[str] = None
    #: Who asserts this holding exists and has that digest. A holding whose
    #: declarer is also the producer of the claim it supports is self-certified,
    #: which is §10g's question and is why the field is required rather than nice.
    declared_by: str = ""
    #: Who stated the *expected* digest, when that is somebody other than the party
    #: that wrote the reference. Empty means the same party, which is the case a
    #: content-addressed check cannot learn anything from — see
    #: `digest_is_independently_declared`.
    digest_declared_by: str = ""
    supports_evidence: Tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if not str(self.holding_id or "").strip():
            raise FederationError("a holding needs an id so a resolution can cite it")
        if not str(self.system or "").strip():
            raise FederationError(
                f"{self.holding_id}: a holding must name the system that holds it. "
                "Without one there is nothing to classify and nothing to resolve "
                "against, and 'somewhere external' is not a reference")
        if not str(self.locator or "").strip():
            raise FederationError(
                f"{self.holding_id}: a holding must carry a locator; a reference "
                "with no locator points nowhere and cannot even be pasted")
        object.__setattr__(self, "supports_evidence", tuple(self.supports_evidence))

    # ── classification, read off the registry ───────────────────────────────

    @property
    def known_system(self) -> bool:
        """Whether this build can classify the system. Not whether it is reachable."""
        return self.system in FEDERATED_SYSTEMS

    @property
    def system_class(self) -> Optional[SystemClass]:
        found = system_for(self.system)
        return found.system_class if found else None

    @property
    def addressing(self) -> Addressing:
        """The weakest reading for an unregistered system, never the handiest."""
        found = system_for(self.system)
        return found.addressing if found else Addressing.OPAQUE_ID

    @property
    def custody(self) -> Custody:
        found = system_for(self.system)
        return found.custody if found else Custody.UNKNOWN

    @property
    def is_held_by_release_gate(self) -> bool:
        """Unconditionally False. That is what makes it a holding and not a record."""
        return False

    @property
    def digest_is_independently_declared(self) -> bool:
        """Whether the expected digest came from somewhere other than the reference.

        The question a content-addressed check lives or dies on. Comparing a
        locator to a digest **the same party supplied** is comparing a submission
        to itself: it is trivially consistent and establishes nothing about the
        world, which is how a document could otherwise grant itself
        `verified_without_copying` with no external interaction at all (§10aq.8).

        Not inferred from anything the holding says about itself: either a second
        party is named or one is not.
        """
        declarer = (self.digest_declared_by or "").strip()
        return bool(declarer) and declarer != (self.declared_by or "").strip()

    @property
    def identity_checkable_without_transfer(self) -> bool:
        """A content-addressed locator that actually looks like a digest.

        Both halves are required. A system row saying CONTENT_ADDRESSED describes
        how the system addresses objects; whether *this* holding used that
        addressing is a fact about the locator. An OCI tag in a content-addressed
        registry is the case this catches, and it is the case most likely to be
        quoted as verified.
        """
        return self.addressing.identity_is_free and _looks_like_digest(self.locator)

    def reference(self) -> ContentReference:
        """The holding as a `ContentReference`, so it travels in the record model."""
        found = system_for(self.system)
        kind = found.reference_kind if found else ReferenceKind.EXTERNAL
        detail: Dict[str, Any] = {"system": self.system,
                                  "custody": self.custody.value,
                                  "addressing": self.addressing.value}
        if self.declared_by:
            detail["declared_by"] = self.declared_by
        if self.system_class is not None:
            detail["system_class"] = self.system_class.value
        return ContentReference(kind=kind, locator=self.locator, detail=detail)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "federated_holding", "record_id": self.holding_id,
                "holding_id": self.holding_id, "system": self.system,
                "known_system": self.known_system,
                "system_class": self.system_class.value if self.system_class else None,
                "addressing": self.addressing.value,
                "custody": self.custody.value,
                "crosses_an_organisational_boundary":
                    self.custody.crosses_an_organisational_boundary,
                "locator": self.locator, "claimed_digest": self.claimed_digest,
                "declared_by": self.declared_by,
                "digest_declared_by": self.digest_declared_by,
                "digest_is_independently_declared": self.digest_is_independently_declared,
                "supports_evidence": list(self.supports_evidence),
                "identity_checkable_without_transfer":
                    self.identity_checkable_without_transfer,
                "is_held_by_release_gate": False,
                "note": self.note,
                "schema_version": FEDERATION_SCHEMA_VERSION}


def _looks_like_digest(locator: str) -> bool:
    """Whether a locator is shaped like a content address.

    Shape only, and named so. `sha256:` plus 64 hex, a bare 40-hex git oid, or a
    `bafy…`/`Qm…` CID. This is a syntactic check and it is used only to decide
    whether a *claim* of content addressing is even coherent — it establishes
    nothing about content, which is the distinction the rest of this module is
    built on and which a helper called `is_valid_digest` would have blurred.
    """
    text = (locator or "").strip()
    if text.startswith("sha256:"):
        text = text[len("sha256:"):]
    if len(text) in (40, 64) and all(c in "0123456789abcdefABCDEF" for c in text):
        return True
    return text.startswith(("bafy", "bafk", "Qm")) and len(text) > 20


# ── what a resolution can settle ─────────────────────────────────────────────

class Establishment(str, Enum):
    """Whether a question got an answer. Says nothing about whose authority.

    Paired with `DigestStatus`, never merged into it: the common case for federated
    evidence is ESTABLISHED on somebody else's authority, and one enum covering
    both would have to choose which half to lose.
    """

    ESTABLISHED = "ESTABLISHED"          # answered, yes
    REFUTED = "REFUTED"                  # answered, no — the reference is wrong
    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # asked and could not settle it
    NOT_ASSESSED = "NOT_ASSESSED"        # nobody asked

    @property
    def settled(self) -> bool:
        return self in (Establishment.ESTABLISHED, Establishment.REFUTED)


class MatchOutcome(str, Enum):
    """Whether an observed digest matched the claimed one."""

    MATCHED = "MATCHED"
    MISMATCHED = "MISMATCHED"
    #: No digest to compare against, or none obtained. Not a pass.
    NOT_COMPARED = "NOT_COMPARED"


class ResolutionMethod(str, Enum):
    """How a holding's identity was approached. One row of `ESTABLISHMENT_TABLE` each."""

    #: The locator is the digest and it matches what the case claims. No contact
    #: with the system at all, so nothing about availability.
    ADDRESS_IS_DIGEST = "ADDRESS_IS_DIGEST"
    #: The system reported a digest it computed. One metadata call, no payload.
    METADATA_DIGEST = "METADATA_DIGEST"
    #: A signed statement of the digest, whose signature was checked.
    SIGNED_ATTESTATION = "SIGNED_ATTESTATION"
    #: Release-gate read the bytes and hashed them itself. The only OBSERVED path,
    #: and the one that moves everything.
    RECOMPUTED = "RECOMPUTED"
    #: The object is there. Nothing about what is in it.
    EXISTENCE_PROBE = "EXISTENCE_PROBE"
    #: Tried and failed — store down, credential revoked, object gone.
    UNREACHABLE = "UNREACHABLE"
    #: Nobody tried.
    NOT_ATTEMPTED = "NOT_ATTEMPTED"

    @property
    def transfers_payload(self) -> bool:
        """Whether the whole object had to move. The brief's actual question."""
        return self is ResolutionMethod.RECOMPUTED


@dataclass(frozen=True)
class Establishes:
    """What one method settles, before the digest comparison is taken into account."""

    identity: Establishment
    integrity: Establishment
    availability: Establishment
    digest_status: DigestStatus
    why: str


#: The grid, exhaustive over `ResolutionMethod`. A table rather than a chain of
#: branches, so "does an existence probe establish integrity" has one answer in one
#: place instead of one answer per call site.
#:
#: The two rows worth arguing about:
#:
#: * `ADDRESS_IS_DIGEST` leaves integrity NOT_ASSESSED. Nothing was compared
#:   against any bytes, because no bytes were involved — the check is that the
#:   reference names what the case says it names. Reading it as integrity would
#:   make a CID nobody is pinning look like verified content.
#: * `METADATA_DIGEST` and `SIGNED_ATTESTATION` establish integrity while leaving
#:   the digest DECLARED. The question is answered; the answer is somebody else's
#:   computation. That pairing is the normal state of federated evidence and
#:   flattening it either way would lose something true.
ESTABLISHMENT_TABLE: Mapping[ResolutionMethod, Establishes] = {
    ResolutionMethod.ADDRESS_IS_DIGEST: Establishes(
        identity=Establishment.ESTABLISHED,
        integrity=Establishment.NOT_ASSESSED,
        availability=Establishment.NOT_ASSESSED,
        digest_status=DigestStatus.DECLARED,
        why="the locator is the digest, so the reference names the object the case "
            "claims; no bytes were seen and the system was never contacted"),
    ResolutionMethod.METADATA_DIGEST: Establishes(
        identity=Establishment.ESTABLISHED,
        integrity=Establishment.ESTABLISHED,
        availability=Establishment.ESTABLISHED,
        digest_status=DigestStatus.DECLARED,
        why="the system reported a digest it computed and the object was there to "
            "report on; the digest is the system's word, not release-gate's"),
    ResolutionMethod.SIGNED_ATTESTATION: Establishes(
        identity=Establishment.ESTABLISHED,
        integrity=Establishment.ESTABLISHED,
        availability=Establishment.NOT_ASSESSED,
        digest_status=DigestStatus.DECLARED,
        why="a signature over a statement of the digest was checked; the signer "
            "computed the digest, and a statement about an object is not the object"),
    ResolutionMethod.RECOMPUTED: Establishes(
        identity=Establishment.ESTABLISHED,
        integrity=Establishment.ESTABLISHED,
        availability=Establishment.ESTABLISHED,
        digest_status=DigestStatus.OBSERVED,
        why="release-gate read the bytes and hashed them, which is the only path "
            "to OBSERVED and the only one that moves the whole object"),
    ResolutionMethod.EXISTENCE_PROBE: Establishes(
        identity=Establishment.NOT_ASSESSED,
        integrity=Establishment.NOT_ASSESSED,
        availability=Establishment.ESTABLISHED,
        digest_status=DigestStatus.UNKNOWN,
        why="something is there. Existence is not integrity, and an object at the "
            "right key with the wrong contents passes this and only this"),
    ResolutionMethod.UNREACHABLE: Establishes(
        identity=Establishment.NOT_ESTABLISHED,
        integrity=Establishment.NOT_ESTABLISHED,
        availability=Establishment.NOT_ESTABLISHED,
        digest_status=DigestStatus.UNKNOWN,
        why="the system could not be reached or the object was not found, which is "
            "a gap rather than a failed case — and distinct from nobody trying"),
    ResolutionMethod.NOT_ATTEMPTED: Establishes(
        identity=Establishment.NOT_ASSESSED,
        integrity=Establishment.NOT_ASSESSED,
        availability=Establishment.NOT_ASSESSED,
        digest_status=DigestStatus.UNKNOWN,
        why="no resolver was supplied for this holding, so nothing was asked. "
            "NOT_ASSESSED, which is not the same as absent (Invariant 3)"),
}


# ── the seam a deployment binds ──────────────────────────────────────────────

@dataclass(frozen=True)
class Probe:
    """What an adapter did and saw. Raw, not adjudicated.

    An adapter reports its method and its observation; `resolve` decides what that
    establishes. The split is the same one §10aa draws between a worker and a
    verifier: an adapter that could mark its own read OBSERVED would be
    self-attestation with a storage client in front of it.
    """

    method: ResolutionMethod
    observed_digest: Optional[str] = None
    present: Optional[bool] = None
    bytes_transferred: Optional[int] = None
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", ResolutionMethod(self.method))
        if self.bytes_transferred is not None and self.bytes_transferred < 0:
            raise FederationError("bytes_transferred cannot be negative")
        if (self.method is ResolutionMethod.RECOMPUTED
                and not self.observed_digest):
            raise FederationError(
                "a RECOMPUTED probe must carry the digest it computed; the method "
                "is the claim that release-gate hashed the bytes itself, and a "
                "claim to have hashed them with no digest to show is the one thing "
                "that would launder DECLARED into OBSERVED")


class Resolver(Protocol):
    """A deployment's adapter for one or more systems.

    Stdlib-only in here means the S3 client, the GitHub token and the Lean
    checkout all live outside and arrive through this protocol.
    """

    def probe(self, holding: Holding) -> Probe:  # pragma: no cover - structural
        """Look at a holding and report what was done. May raise; `resolve` copes."""
        ...


@dataclass(frozen=True)
class Resolution:
    """What was settled about one holding, and on whose authority.

    Not a record and never folded into a case digest: a resolution is a fact about
    an attempt at a moment, and an approval that bound to it would bind to network
    weather. What belongs in the case is the holding and the coverage consequence.
    """

    holding_id: str
    method: ResolutionMethod
    identity: Establishment
    integrity: Establishment
    availability: Establishment
    digest_status: DigestStatus
    match: MatchOutcome = MatchOutcome.NOT_COMPARED
    observed_digest: Optional[str] = None
    bytes_transferred: Optional[int] = None
    #: True when the only thing compared was a producer's reference against that
    #: same producer's digest. The comparison holds and it is not evidence.
    self_referential: bool = False
    why: str = ""

    def __post_init__(self) -> None:
        for name, enum in (("method", ResolutionMethod), ("identity", Establishment),
                           ("integrity", Establishment), ("availability", Establishment),
                           ("digest_status", DigestStatus), ("match", MatchOutcome)):
            object.__setattr__(self, name, enum(getattr(self, name)))
        if not self.why:
            raise FederationError(
                f"{self.holding_id}: a resolution must say what it rests on. A "
                "reviewer asked to accept remote evidence is owed the mechanism, "
                "not the conclusion")
        if (self.digest_status is DigestStatus.OBSERVED
                and self.method is not ResolutionMethod.RECOMPUTED):
            raise FederationError(
                f"{self.holding_id}: only {ResolutionMethod.RECOMPUTED.value} yields "
                f"OBSERVED. {self.method.value} means somebody else computed the "
                "digest, which is DECLARED however trustworthy they are "
                "(Invariants 1, 2, 11)")

    # ── reading it ──────────────────────────────────────────────────────────

    @property
    def verified_without_copying(self) -> bool:
        """Identity settled, and the object did not move. The brief's ask, exactly.

        False for `RECOMPUTED` even though that is the strongest result: it settled
        identity *by* copying, so counting it here would make the metric report its
        own opposite. False for a self-referential check, because a property a
        submitted document can grant itself is not a property (§10aq.8).
        """
        return (self.identity is Establishment.ESTABLISHED
                and not self.method.transfers_payload
                and not self.self_referential
                and self.match is not MatchOutcome.MISMATCHED)

    @property
    def retains_the_evidence(self) -> bool:
        """Unconditionally False. Resolving a reference is not holding the bytes."""
        return False

    @property
    def is_a_gap(self) -> bool:
        """Whether this holding leaves something a reviewer should be told about."""
        return (self.match is MatchOutcome.MISMATCHED
                or not self.identity.settled
                or self.self_referential
                or self.availability is Establishment.NOT_ESTABLISHED)

    def render(self) -> str:
        parts = [f"{self.holding_id}: {self.method.value}",
                 f"identity={self.identity.value}",
                 f"integrity={self.integrity.value}",
                 f"availability={self.availability.value}",
                 f"digest={self.digest_status.value}"]
        if self.match is not MatchOutcome.NOT_COMPARED:
            parts.append(self.match.value)
        if self.self_referential:
            parts.append("SELF_REFERENTIAL")
        if self.bytes_transferred is not None:
            parts.append(f"{self.bytes_transferred:,} bytes moved")
        return "  ".join(parts) + f"\n      {self.why}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "federated_resolution", "record_id": self.holding_id,
                "holding_id": self.holding_id, "method": self.method.value,
                "identity": self.identity.value, "integrity": self.integrity.value,
                "availability": self.availability.value,
                "digest_status": self.digest_status.value,
                "match": self.match.value, "observed_digest": self.observed_digest,
                "bytes_transferred": self.bytes_transferred,
                "self_referential": self.self_referential,
                "verified_without_copying": self.verified_without_copying,
                "retains_the_evidence": False, "is_a_gap": self.is_a_gap,
                "why": self.why, "schema_version": FEDERATION_SCHEMA_VERSION}


def resolve(holding: Holding, resolver: Optional[Resolver] = None) -> Resolution:
    """Establish what can be established about one holding, and no more.

    Never raises for a resolver that fails. An adapter throwing is the loudest form
    of "cannot confirm", and letting it propagate would turn "is this evidence
    still there" into a crash in the approval path — the same fix `subject.recheck`
    needed for the same reason. A failure becomes `UNREACHABLE`, which is a gap and
    is distinct from `NOT_ATTEMPTED`.

    With no resolver the answer is `NOT_ATTEMPTED`: this module does not fall back
    to inspecting a locator on disk, because a holding's locator arrives in a
    submitted document and reading wherever it points is the digest oracle §10am.3
    closed.
    """
    if resolver is None:
        return _adjudicate(holding, Probe(method=ResolutionMethod.NOT_ATTEMPTED))
    try:
        probe = resolver.probe(holding)
    except Exception as exc:
        return _adjudicate(
            holding,
            Probe(method=ResolutionMethod.UNREACHABLE,
                  note=f"{type(exc).__name__}: {exc}"))
    if not isinstance(probe, Probe):
        raise FederationError(
            f"{holding.holding_id}: a resolver must return a Probe describing what "
            f"it did, got {type(probe).__name__}. An adapter that returned a bare "
            "digest would be asserting its own authority over the result")
    return _adjudicate(holding, probe)


def _adjudicate(holding: Holding, probe: Probe) -> Resolution:
    """Turn what an adapter did into what it established, by the table."""
    method = probe.method
    # A holding that claims content addressing without a content-addressed locator
    # cannot use the free-identity path. An OCI tag is the case in mind.
    if (method is ResolutionMethod.ADDRESS_IS_DIGEST
            and not holding.identity_checkable_without_transfer):
        grid = ESTABLISHMENT_TABLE[ResolutionMethod.UNREACHABLE]
        return Resolution(
            holding_id=holding.holding_id, method=ResolutionMethod.UNREACHABLE,
            identity=grid.identity, integrity=grid.integrity,
            availability=grid.availability, digest_status=grid.digest_status,
            bytes_transferred=probe.bytes_transferred,
            why=(f"{holding.locator!r} was resolved as content-addressed, and it is "
                 f"not: the system addresses objects as "
                 f"{holding.addressing.value} and this locator is not shaped like a "
                 "digest. A mutable name in a content-addressed store establishes "
                 "nothing about what it currently points at"))

    grid = ESTABLISHMENT_TABLE[method]
    observed = probe.observed_digest
    if method is ResolutionMethod.ADDRESS_IS_DIGEST and observed is None:
        # The address is the observation, which is what makes this path free.
        observed = holding.locator

    match = MatchOutcome.NOT_COMPARED
    if observed and holding.claimed_digest:
        match = (MatchOutcome.MATCHED
                 if _same_digest(observed, holding.claimed_digest)
                 else MatchOutcome.MISMATCHED)

    identity, integrity = grid.identity, grid.integrity
    why = grid.why
    if match is MatchOutcome.MISMATCHED:
        # Not a gap — a refutation. The remote object is not the one the case
        # describes, and reporting that as "could not establish" would make the
        # strongest negative result read as an absence of information.
        identity = Establishment.REFUTED
        if integrity is not Establishment.NOT_ASSESSED:
            integrity = Establishment.REFUTED
        why = (f"the digest obtained ({(observed or '')[:23]}…) is not the one the "
               f"case claims ({(holding.claimed_digest or '')[:23]}…). The object at "
               "this reference is not the object this case is about")
    elif probe.present is False and method is not ResolutionMethod.UNREACHABLE:
        why = f"{why}; the system reported the object as absent"

    availability = grid.availability
    if probe.present is False:
        availability = Establishment.REFUTED
    elif probe.present is True and availability is Establishment.NOT_ASSESSED:
        availability = Establishment.ESTABLISHED

    # A content-addressed check compares the locator against the claimed digest.
    # When both came from the same party that is a submission agreeing with itself:
    # the comparison holds, and it is not evidence. Narrow to this method on
    # purpose — under METADATA_DIGEST the store computed the digest independently
    # of whatever the producer claimed, which is a real cross-check.
    self_referential = (method is ResolutionMethod.ADDRESS_IS_DIGEST
                        and match is MatchOutcome.MATCHED
                        and not holding.digest_is_independently_declared)
    if self_referential:
        who = holding.declared_by or "an unnamed party"
        why = (f"{why}. The expected digest was supplied by {who}, the same party "
               "that wrote the reference, so this compares a submission against "
               "itself: internally consistent, and no evidence about the object")

    note = f" ({probe.note})" if probe.note else ""
    return Resolution(
        holding_id=holding.holding_id, method=method, identity=identity,
        integrity=integrity, availability=availability,
        digest_status=grid.digest_status, match=match, observed_digest=observed,
        bytes_transferred=probe.bytes_transferred,
        self_referential=self_referential, why=why + note)


def _same_digest(left: str, right: str) -> bool:
    """Compare digests by value, ignoring a `sha256:` prefix on either side."""
    def bare(text: str) -> str:
        text = (text or "").strip()
        return text[len("sha256:"):].lower() if text.startswith("sha256:") else text.lower()
    return bool(bare(left)) and bare(left) == bare(right)


# ── the case's federated evidence, and what it costs coverage ────────────────

@dataclass(frozen=True)
class FederationLedger:
    """Every holding a case depends on, and what was established about each.

    Not a score. "Nine of eleven holdings resolved" describes a moment on a network
    and says nothing about whether the case is sound: a case resting on two
    unresolvable holdings and one that matters may be in better shape than one
    where everything resolved and none of it was independent.
    """

    holdings: Tuple[Holding, ...] = ()
    resolutions: Tuple[Resolution, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "holdings", tuple(self.holdings))
        object.__setattr__(self, "resolutions", tuple(self.resolutions))
        known = {h.holding_id for h in self.holdings}
        orphans = sorted(r.holding_id for r in self.resolutions if r.holding_id not in known)
        if orphans:
            raise FederationError(
                f"resolution(s) for holding(s) this ledger does not hold: "
                f"{', '.join(orphans)}. A resolution with no holding is a claim "
                "about evidence the case never declared")

    def __len__(self) -> int:
        return len(self.holdings)

    def of(self, holding_id: str) -> Optional[Resolution]:
        for resolution in self.resolutions:
            if resolution.holding_id == holding_id:
                return resolution
        return None

    @property
    def unresolved(self) -> Tuple[Holding, ...]:
        """Holdings whose identity nobody settled — including ones nobody tried.

        A self-referential check counts as unsettled. Its comparison held, and it
        held against a number the same party chose, so a reviewer who read this as
        resolved would be reading a submission's own agreement with itself.
        """
        return tuple(h for h in self.holdings
                     if (r := self.of(h.holding_id)) is None
                     or not r.identity.settled or r.self_referential)

    @property
    def refuted(self) -> Tuple[Resolution, ...]:
        """The serious ones: a reference that names something other than it claims."""
        return tuple(r for r in self.resolutions
                     if r.match is MatchOutcome.MISMATCHED
                     or r.identity is Establishment.REFUTED)

    @property
    def unavailable(self) -> Tuple[Resolution, ...]:
        return tuple(r for r in self.resolutions
                     if r.availability in (Establishment.REFUTED,
                                           Establishment.NOT_ESTABLISHED))

    @property
    def cross_organisation(self) -> Tuple[Holding, ...]:
        return tuple(h for h in self.holdings
                     if h.custody.crosses_an_organisational_boundary)

    @property
    def bytes_transferred(self) -> Optional[int]:
        """Payload moved to reach these conclusions, or None if nobody measured.

        The brief's claim made checkable. A ledger of content-addressed and
        checksummed holdings reports a number near zero; one that recomputed
        everything reports the size of the evidence, and calling that "without
        copying" would be false.
        """
        measured = [r.bytes_transferred for r in self.resolutions
                    if r.bytes_transferred is not None]
        return sum(measured) if measured else None

    @property
    def verified_without_copying(self) -> Tuple[Resolution, ...]:
        return tuple(r for r in self.resolutions if r.verified_without_copying)

    @property
    def by_class(self) -> Mapping[str, int]:
        counts: Dict[str, int] = {}
        for holding in self.holdings:
            key = holding.system_class.value if holding.system_class else "UNCLASSIFIED"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def is_a_completeness_claim(self) -> bool:
        """Unconditionally False.

        A ledger lists the holdings somebody declared. Whether evidence exists in a
        system nobody mentioned is exactly the omission §10p treats as an attack,
        and a federation ledger is in the worst possible position to detect it.
        """
        return False

    # ── the coverage consequence ────────────────────────────────────────────

    def expectations(self) -> Tuple[EvidenceExpectation, ...]:
        """Unresolved and refuted holdings, as coverage rows.

        The same mechanism §10ab uses for withheld content: a dimension the case
        could not assess becomes an `EvidenceExpectation` with `assessed=False`, so
        it lands in the coverage ledger beside every other gap rather than in a
        federation report a reviewer would have to think to open (Invariants 3, 9).

        A refuted holding gets a row too, and it is not the same row. "We could not
        check this" and "we checked and the reference is wrong" are different
        findings, and giving them one shape would bury the worse one.
        """
        rows: List[EvidenceExpectation] = []
        # One row per system, not per holding. `CoverageLedger.of()` returns the
        # first row matching a dimension, so two unresolved holdings in one system
        # would have put the second behind the first — losing a gap at exactly the
        # boundary this method exists to carry gaps across. The holding ids travel
        # in the note, so nothing is dropped to get the dimension unique.
        by_system: Dict[str, List[Holding]] = {}
        for holding in self.unresolved:
            by_system.setdefault(holding.system, []).append(holding)
        for system, group in sorted(by_system.items()):
            methods = sorted({(self.of(h.holding_id).method.value
                               if self.of(h.holding_id) else "NOT_ATTEMPTED")
                              for h in group})
            declarers = sorted({h.declared_by or "an unnamed party" for h in group})
            rows.append(EvidenceExpectation(
                dimension=f"federated.{system}",
                assessed=False,
                observed_from=f"holding(s) {', '.join(h.holding_id for h in group)} "
                              f"declared by {', '.join(declarers)}",
                note=(f"{len(group)} holding(s) of evidence for this case live in "
                      f"{system} and their identity was not established "
                      f"({', '.join(methods)}). What they contain was not assessed "
                      "here")))
        for resolution in self.refuted:
            rows.append(EvidenceExpectation(
                dimension=f"federated.mismatch.{resolution.holding_id}",
                assessed=False,
                observed_from=f"resolution of holding {resolution.holding_id}",
                note=(f"the remote object does not match the digest this case "
                      f"claims for it: {resolution.why}")))
        return tuple(rows)

    def render(self) -> str:
        lines = ["FEDERATED EVIDENCE"]
        if not self.holdings:
            lines.append("  no holdings declared: every record in this case is local")
            return "\n".join(lines)
        lines.append(f"  {len(self.holdings)} holding(s) across "
                     f"{len(self.by_class)} class(es)")
        for name, count in self.by_class.items():
            lines.append(f"    {count:>4}  {name}")
        lines.append("")
        for holding in self.holdings:
            resolution = self.of(holding.holding_id)
            lines.append(f"    {holding.holding_id}  {holding.system} "
                         f"[{holding.addressing.value}, custody "
                         f"{holding.custody.value}]")
            lines.append("      " + (resolution.render().split("\n", 1)[0]
                                     if resolution else
                                     "no resolution attempted"))
        lines.append("")
        moved = self.bytes_transferred
        free = len(self.verified_without_copying)
        lines.append(f"  {free} of {len(self.holdings)} holding(s) had their identity "
                     f"established without the object moving")
        lines.append("  payload moved: " + (f"{moved:,} bytes" if moved is not None
                                            else "not measured"))
        if self.refuted:
            lines.append(f"  REFUTED: {len(self.refuted)} reference(s) name something "
                         "other than what this case claims")
        if self.unresolved:
            lines.append(f"  unresolved: {len(self.unresolved)} holding(s), each a "
                         "coverage gap rather than a clean read")
        if self.cross_organisation:
            lines.append(f"  {len(self.cross_organisation)} holding(s) sit in another "
                         "organisation's custody, or one nobody recorded")
        lines.append("")
        lines.append("  Release-gate holds none of this evidence. A resolved reference")
        lines.append("  says the object was there when asked, not that it will be, and")
        lines.append("  this list covers only the holdings somebody declared.")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "federation_ledger",
                "record_id": short_id("fed", digest_object(
                    [h.to_dict() for h in self.holdings])),
                "holdings": [h.to_dict() for h in self.holdings],
                "resolutions": [r.to_dict() for r in self.resolutions],
                "by_class": dict(self.by_class),
                "unresolved": [h.holding_id for h in self.unresolved],
                "refuted": [r.holding_id for r in self.refuted],
                "unavailable": [r.holding_id for r in self.unavailable],
                "cross_organisation": [h.holding_id for h in self.cross_organisation],
                "bytes_transferred": self.bytes_transferred,
                "verified_without_copying":
                    [r.holding_id for r in self.verified_without_copying],
                "is_a_completeness_claim": False,
                "schema_version": FEDERATION_SCHEMA_VERSION}


def holdings_in(records: Iterable[Any]) -> Tuple[Holding, ...]:
    """Holdings carried by evidence records, read back out of their references.

    The other half of `Holding.reference()`, and the reason neither needed a new
    ingest path. A producer names a federated holding by putting it in the
    `content_reference` an `EvidenceRecord` already has; this reads them back so
    they can be resolved. The record model did not have to grow a field, and a
    second evidence model was never built (§10aq).

    Records with no federated reference are skipped in silence — most evidence is
    local, and a case of ten thousand local records should not produce ten thousand
    notes saying so.

    `digest_declared_by` is deliberately left empty. The locator and the digest both
    come off one record, so there is no second party to name, and a content-addressed
    resolution of a holding read this way is `self_referential` — which is the
    correct reading and the reason that flag exists. A caller who knows the expected
    digest came from somewhere else (a methodology, a second producer, a release
    manifest) says so by constructing the `Holding` with that party named.
    """
    found: List[Holding] = []
    seen: set = set()
    for record in records:
        reference = getattr(record, "content_reference", None)
        detail = dict(getattr(reference, "detail", None) or {}) if reference else {}
        system = str(detail.get("system") or "")
        if not system:
            continue
        record_id = str(getattr(record, "record_id", "")
                        or getattr(record, "evidence_id", "") or "")
        holding_id = f"holding:{record_id}" if record_id else f"holding:{len(found)}"
        if holding_id in seen:
            continue
        seen.add(holding_id)
        found.append(Holding(
            holding_id=holding_id, system=system, locator=reference.locator,
            claimed_digest=getattr(record, "digest", None),
            declared_by=str(detail.get("declared_by") or ""),
            supports_evidence=(record_id,) if record_id else ()))
    return tuple(found)


def resolve_all(holdings: Sequence[Holding],
                resolver: Optional[Resolver] = None) -> FederationLedger:
    """Resolve every holding and gather the result. One resolver, or none at all."""
    return FederationLedger(
        holdings=tuple(holdings),
        resolutions=tuple(resolve(h, resolver) for h in holdings))


__all__ = [
    "ESTABLISHMENT_TABLE",
    "FEDERATED_SYSTEMS",
    "FEDERATION_SCHEMA_VERSION",
    "Addressing",
    "Custody",
    "Establishes",
    "Establishment",
    "FederatedSystem",
    "FederationError",
    "FederationLedger",
    "Holding",
    "MatchOutcome",
    "Probe",
    "Resolution",
    "ResolutionMethod",
    "Resolver",
    "SystemClass",
    "holdings_in",
    "resolve",
    "resolve_all",
    "system_for",
]
