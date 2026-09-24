"""The universal evidence record — one shape for every producer.

A static analyser, an OpenTelemetry span, a promptfoo case, a theorem prover, a
replication run and a human reviewer all produce the same record type. That is
what makes it possible to ask one question across all of them: what supports this
proposition, how was it established, and how much of it is independent?

**Four status axes, deliberately not merged.** The temptation is a single
confidence number. Four separate fields exist because they answer four different
questions and collapsing them destroys the answer to each:

    epistemic_status    How was this established?      OBSERVED … NOT_ASSESSED
    provenance_status   Where did it come from?        SIGNED … UNATTRIBUTED
    trust_status        How much authority does that
                        source carry?                  ACCEPTED … NOT_ESTABLISHED
    coverage_status     How much does it cover?        COMPLETE | PARTIAL | UNKNOWN

Provenance and trust in particular are never interchangeable (Invariant 11). A
signed record from a verifier nobody has vetted has strong provenance and no
established trust. A trusted vendor's unsigned assertion is the reverse. One
number would lose both facts.

**Status is assigned at the boundary, never by the producer.** `from_producer()`
is where untrusted payloads become records: any `epistemic_status`, `trust_status`
or `provenance_status` the producer put in its payload is moved into
`content.producer_claimed_*` and plays no part in anything. An agent saying
"verified: true" produces DECLARED evidence *that the agent said so* — which is a
real and useful fact, and is not evidence the thing is true (Invariant 1).

**Trust is never self-asserted.** `trust_status` starts at `NOT_ESTABLISHED` and
can only be moved by `with_trust()`, which demands a basis naming who decided and
on what grounds. There is no path by which a record can vouch for itself.

**Large content is referenced, not copied.** The record carries a digest and a
content reference; payloads above a small threshold stay where they are. A
million-line trace does not get copied into an evidence pack to prove it existed.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from release_gate.assurance.canonical import (
    CanonicalisationError,
    canonical_bytes,
    canonical_json,
    digest_bytes,
    digest_file,
    digest_object,
    freeze_value,
    is_content_id,
    require_content_id,
    short_id,
    thaw_value,
)
from release_gate.assurance.subject import ContentReference, ReferenceKind

#: Bumped when the record shape changes in a way readers must know about. A
#: record from a NEWER schema is refused rather than partially understood: a
#: reader that silently ignores fields it does not recognise is a reader that
#: drops evidence.
EVIDENCE_SCHEMA_VERSION = 1

#: Content above this size is referenced rather than embedded.
MAX_INLINE_BYTES = 64 * 1024


class EvidenceType(str, Enum):
    """What kind of thing this evidence is. Orthogonal to how it was established."""

    TRACE = "TRACE"
    TOOL_RESULT = "TOOL_RESULT"
    TEST_RESULT = "TEST_RESULT"
    FORMAL_PROOF = "FORMAL_PROOF"
    SIMULATION_RESULT = "SIMULATION_RESULT"
    EXPERIMENT_RESULT = "EXPERIMENT_RESULT"
    STATIC_FINDING = "STATIC_FINDING"
    EVAL_RESULT = "EVAL_RESULT"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"
    CODE_ARTIFACT = "CODE_ARTIFACT"
    DATA_ARTIFACT = "DATA_ARTIFACT"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    APPROVAL = "APPROVAL"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    CLAIM_DERIVATION = "CLAIM_DERIVATION"
    REPLICATION = "REPLICATION"
    ATTESTATION = "ATTESTATION"
    OTHER = "OTHER"


class VerificationMethod(str, Enum):
    """HOW something was verified. "Verified" alone is not an answer (Invariant 8)."""

    FORMAL_PROOF = "FORMAL_PROOF"
    INDEPENDENT_REPLICATION = "INDEPENDENT_REPLICATION"
    TEST_SUITE = "TEST_SUITE"
    SIMULATION = "SIMULATION"
    EXPERIMENT = "EXPERIMENT"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    RUNTIME_ASSERTION = "RUNTIME_ASSERTION"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    CROSS_MODEL_REVIEW = "CROSS_MODEL_REVIEW"
    THEOREM_PROVER = "THEOREM_PROVER"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"
    DOMAIN_CHECKER = "DOMAIN_CHECKER"
    PROPERTY_TEST = "PROPERTY_TEST"
    COMPILER = "COMPILER"
    TYPE_CHECKER = "TYPE_CHECKER"
    OTHER = "OTHER"


class EpistemicStatus(str, Enum):
    """How this was established. Computed at the boundary; never producer-supplied."""

    OBSERVED = "OBSERVED"          # release-gate read it directly from an instrument
    DECLARED = "DECLARED"          # an actor asserted it; zero independent support
    DERIVED = "DERIVED"            # release-gate computed it from other records
    VERIFIED = "VERIFIED"          # an admissible method returned a positive result
    DISPUTED = "DISPUTED"          # comparable support and refutation, unresolved
    REFUTED = "REFUTED"            # refutation stands unanswered
    UNKNOWN = "UNKNOWN"            # in scope, looked, nothing answers it
    NOT_ASSESSED = "NOT_ASSESSED"  # out of scope for this run; we did not look


class ProvenanceStatus(str, Enum):
    """Where it came from, and whether that chain holds. Says nothing about authority."""

    SIGNED = "SIGNED"                # cryptographically signed by its producer
    CHAIN_VERIFIED = "CHAIN_VERIFIED"  # inputs digested and the chain checks out
    ATTRIBUTED = "ATTRIBUTED"        # a named producer, unsigned
    SELF_ATTESTED = "SELF_ATTESTED"  # the producer is also what it vouches for
    UNATTRIBUTED = "UNATTRIBUTED"    # no identifiable producer
    BROKEN = "BROKEN"                # chain claimed and does not hold


class TrustStatus(str, Enum):
    """How much authority a source carries. Never inferred, never self-asserted."""

    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # nobody has ruled on this source (default)
    ACCEPTED = "ACCEPTED"                # accepted for this purpose, by a named decider
    PROVISIONAL = "PROVISIONAL"          # accepted with stated reservations
    REVOKED = "REVOKED"                  # previously accepted, since withdrawn
    REJECTED = "REJECTED"                # explicitly not to be relied on


class CoverageStatus(str, Enum):
    """How much of its subject this evidence actually covers."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ProducerKind(str, Enum):
    AGENT = "agent"
    TOOL = "tool"
    HUMAN = "human"
    RELEASE_GATE = "release_gate"
    EXTERNAL = "external"


#: Statuses whose claim rests on a verification having happened.
_VERIFICATION_STATUSES = (EpistemicStatus.VERIFIED, EpistemicStatus.REFUTED)

#: Statuses release-gate may assign to its own work. Anything else arriving from
#: outside is at best DECLARED until an independent record says otherwise.
_SELF_ASSIGNABLE = (EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED)

#: Payload keys a producer may not set. They are moved into the content, kept as
#: a record of what was claimed, and ignored for every purpose.
_PRODUCER_FORBIDDEN = ("epistemic_status", "trust_status", "provenance_status",
                       "coverage_status", "evidence_id", "verified")


class EvidenceError(ValueError):
    """An evidence record was constructed in a state that cannot be relied on."""


class EvidenceIntegrityError(ValueError):
    """A serialised evidence record's stored id disagrees with its content."""


class EvidenceSchemaError(ValueError):
    """A record was written by a schema version this reader cannot honour."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Producer:
    """Who or what produced a piece of evidence.

    `identity_basis` is how that identity was established — `github-oidc`,
    `api-key`, `unauthenticated`. An authenticated producer is not a correct one
    (Invariant 2), so this field describes the authentication and nothing more.
    """

    producer_id: str
    kind: ProducerKind = ProducerKind.EXTERNAL
    identity_basis: str = "unauthenticated"
    model: Optional[str] = None
    version: Optional[str] = None
    attested_by: Optional[str] = None

    def __post_init__(self) -> None:
        if not (self.producer_id or "").strip():
            raise EvidenceError(
                "producer_id is required: evidence with no identifiable producer cannot "
                "be weighed, corroborated, or held to account")
        object.__setattr__(self, "producer_id", self.producer_id.strip())
        object.__setattr__(self, "kind", ProducerKind(self.kind))

    def to_dict(self) -> Dict[str, Any]:
        return {"producer_id": self.producer_id, "kind": self.kind.value,
                "identity_basis": self.identity_basis, "model": self.model,
                "version": self.version, "attested_by": self.attested_by}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Producer":
        return cls(producer_id=data["producer_id"],
                   kind=ProducerKind(data.get("kind", ProducerKind.EXTERNAL.value)),
                   identity_basis=data.get("identity_basis", "unauthenticated"),
                   model=data.get("model"), version=data.get("version"),
                   attested_by=data.get("attested_by"))

    @classmethod
    def release_gate(cls, component: str) -> "Producer":
        """release-gate's own analysis, identified by component."""
        return cls(producer_id=f"release-gate/{component}", kind=ProducerKind.RELEASE_GATE,
                   identity_basis="in-process")


@dataclass(frozen=True)
class TrustDecision:
    """An explicit ruling on a source's authority, and who made it."""

    status: TrustStatus
    basis: str
    decided_by: str
    decided_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", TrustStatus(self.status))
        if not (self.basis or "").strip() or not (self.decided_by or "").strip():
            raise EvidenceError(
                "a trust decision requires a basis and a decider: trust that cannot be "
                "traced to someone's judgement is indistinguishable from an assumption")

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status.value, "basis": self.basis,
                "decided_by": self.decided_by, "decided_at": self.decided_at}

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> Optional["TrustDecision"]:
        if not data:
            return None
        return cls(status=TrustStatus(data["status"]), basis=data["basis"],
                   decided_by=data["decided_by"], decided_at=data.get("decided_at") or _utc_now())


# ── content attachment ──────────────────────────────────────────────────────
#
# "Large underlying content should be referenced rather than unnecessarily
# copied." These are the three ways a record points at its content, and the
# choice between them is where that requirement is actually honoured.

def file_content(path: str | Path) -> Tuple[ContentReference, str]:
    """Reference a file on disk and digest it by streaming — never read whole."""
    p = Path(path)
    if not p.is_file():
        raise EvidenceError(f"not a file: {p}")
    return (ContentReference(ReferenceKind.FILE, str(p), {"byte_length": p.stat().st_size}),
            digest_file(p))


def inline_content(data: bytes | str, label: str = "inline") -> Tuple[ContentReference, str]:
    """Embed small content so it stays readable offline; reference it when large.

    The threshold is the point of the function: a one-line tool result travels
    with the record, and a 40 MB trace does not get copied into every evidence
    pack to prove it existed.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    detail: Dict[str, Any] = {"byte_length": len(raw)}
    if len(raw) <= MAX_INLINE_BYTES:
        try:
            detail["inline"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            detail["encoding"] = "binary (not embedded)"
    else:
        detail["encoding"] = f"not embedded (> {MAX_INLINE_BYTES} bytes)"
    return ContentReference(ReferenceKind.INLINE, label, detail), digest_bytes(raw)


def external_content(locator: str, *, digest: Optional[str] = None,
                     kind: ReferenceKind = ReferenceKind.EXTERNAL,
                     detail: Optional[Mapping[str, Any]] = None
                     ) -> Tuple[ContentReference, Optional[str]]:
    """Reference content held elsewhere — an object store, a URL, a trace backend.

    A digest is optional here and its absence is honest: some content genuinely
    cannot be hashed from where release-gate runs, and the record says so rather
    than inventing one.
    """
    if digest is not None:
        require_content_id(digest)
    return ContentReference(kind, locator, detail or {}), digest


@dataclass(frozen=True)
class EvidenceRecord:
    """One normalised piece of evidence, from any producer, at any scale."""

    evidence_type: EvidenceType
    source: str
    producer: Producer
    epistemic_status: EpistemicStatus = EpistemicStatus.DECLARED
    content_reference: Optional[ContentReference] = None
    digest: Optional[str] = None
    source_identity: str = "unauthenticated"
    timestamp: str = ""
    parent_evidence: Tuple[str, ...] = ()
    supports_claims: Tuple[str, ...] = ()
    contradicts_claims: Tuple[str, ...] = ()
    verification_method: Optional[VerificationMethod] = None
    applies_to_digest: Optional[str] = None
    provenance_status: ProvenanceStatus = ProvenanceStatus.ATTRIBUTED
    trust: Optional[TrustDecision] = None
    coverage_status: CoverageStatus = CoverageStatus.UNKNOWN
    coverage_note: str = ""
    content: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = EVIDENCE_SCHEMA_VERSION

    evidence_id: str = field(default="", init=False)
    #: True when release-gate stamped the timestamp on arrival because nobody
    #: supplied one. Such a stamp is a fact about this process, not about the
    #: evidence, and it is kept out of `identity()` for that reason.
    stamped_on_arrival: bool = field(default=False, init=False)

    # ── construction ────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        if not (self.timestamp or "").strip():
            object.__setattr__(self, "timestamp", _utc_now())
            object.__setattr__(self, "stamped_on_arrival", True)
        object.__setattr__(self, "evidence_type", EvidenceType(self.evidence_type))
        object.__setattr__(self, "epistemic_status", EpistemicStatus(self.epistemic_status))
        object.__setattr__(self, "provenance_status", ProvenanceStatus(self.provenance_status))
        object.__setattr__(self, "coverage_status", CoverageStatus(self.coverage_status))
        if self.verification_method is not None:
            object.__setattr__(self, "verification_method",
                               VerificationMethod(self.verification_method))
        for name in ("parent_evidence", "supports_claims", "contradicts_claims"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

        if not (self.source or "").strip():
            raise EvidenceError("source is required: evidence from nowhere cannot be weighed")
        object.__setattr__(self, "source", self.source.strip())
        if not isinstance(self.producer, Producer):
            raise EvidenceError("producer must be a Producer")

        if int(self.schema_version) > EVIDENCE_SCHEMA_VERSION:
            raise EvidenceSchemaError(
                f"evidence schema version {self.schema_version} is newer than this reader "
                f"understands ({EVIDENCE_SCHEMA_VERSION}); upgrade release-gate rather than "
                "reading a record whose fields it would silently drop")

        self._validate_verification()
        self._validate_claims()
        self._validate_digest()

        try:
            object.__setattr__(self, "content", freeze_value(self.content or {}, "content"))
            object.__setattr__(self, "metadata", freeze_value(self.metadata or {}, "metadata"))
            # Built and canonicalised ONCE. This used to call
            # `canonical_json(self.identity())` purely to prove the identity
            # canonicalises, throw the result away, and then call
            # `digest_object(self.identity())` — which rebuilds the identity and
            # canonicalises it a second time. Two identity constructions and two
            # JSON encodings per record, and record construction is the hottest
            # path in the system at scale. `digest_object(x)` is exactly
            # `digest_bytes(canonical_bytes(x))`, so this is digest-preserving:
            # every evidence id is unchanged.
            payload = canonical_bytes(self.identity())
        except CanonicalisationError as exc:
            raise EvidenceError(str(exc)) from exc

        object.__setattr__(self, "evidence_id", short_id("ev", digest_bytes(payload)))

    def _validate_verification(self) -> None:
        if self.epistemic_status in _VERIFICATION_STATUSES:
            if self.verification_method is None:
                raise EvidenceError(
                    f"{self.epistemic_status.value} requires a verification_method: "
                    "'verified' alone does not say how, and a claim nobody can re-check "
                    "is not a verification (Invariant 8)")
            if self.applies_to_digest is None:
                raise EvidenceError(
                    f"{self.epistemic_status.value} requires applies_to_digest: a proof "
                    "about one artifact is not evidence about a different one, and without "
                    "the digest nobody can tell which it was")
            if not self.coverage_note.strip():
                raise EvidenceError(
                    f"{self.epistemic_status.value} requires a coverage_note: a producer "
                    "that cannot say what its verification does NOT cover has not "
                    "described a verification (Invariant 9)")
        elif self.verification_method is not None:
            raise EvidenceError(
                f"verification_method is set but the status is "
                f"{self.epistemic_status.value}; a method without a verified or refuted "
                "finding implies a verification that did not happen")

    def _validate_claims(self) -> None:
        both = set(self.supports_claims) & set(self.contradicts_claims)
        if both:
            raise EvidenceError(
                f"evidence both supports and contradicts {sorted(both)}; a record that "
                "cuts both ways on one claim needs splitting into the parts that do each")

    def _validate_digest(self) -> None:
        for name in ("digest", "applies_to_digest"):
            value = getattr(self, name)
            if value is not None and not is_content_id(value):
                raise EvidenceError(
                    f"{name} must be a 'sha256:<64 hex>' or 'git:<hex>' content id, "
                    f"got {value!r}")

    # ── identity ────────────────────────────────────────────────────────────

    def identity(self) -> Dict[str, Any]:
        """Everything that makes this a distinct piece of evidence.

        A **supplied** `timestamp` is included, unlike a subject's creation time:
        when a verification ran is part of what it establishes, and the same test
        suite passing today and passing last March are two pieces of evidence.

        A timestamp release-gate stamped on arrival is not. It records when this
        process read the input, which is a fact about the run and not about the
        evidence — and putting it in a content address made the address vary with
        the clock. The same input ingested twice a second apart produced two sets
        of evidence ids, two fold digests and two case digests, so a case could
        not be re-derived from its own input, identical submissions did not
        deduplicate, and an approval or override bound to a case digest went
        stale the moment CI ran the gate again. The producer's own claimed time
        is unaffected: ingest keeps it in `metadata["declared_timestamp"]`, which
        is part of this identity, so evidence stamped last March is still
        distinct from evidence stamped today.
        """
        return {
            "schema_version": self.schema_version,
            "evidence_type": self.evidence_type.value,
            "source": self.source,
            "source_identity": self.source_identity,
            "producer": self.producer.to_dict(),
            "timestamp": (None if self.stamped_on_arrival else self.timestamp),
            "epistemic_status": self.epistemic_status.value,
            "verification_method": (self.verification_method.value
                                    if self.verification_method else None),
            "applies_to_digest": self.applies_to_digest,
            "digest": self.digest,
            "content_reference": (self.content_reference.to_dict()
                                  if self.content_reference else None),
            "parent_evidence": list(self.parent_evidence),
            "supports_claims": list(self.supports_claims),
            "contradicts_claims": list(self.contradicts_claims),
            "provenance_status": self.provenance_status.value,
            "coverage_status": self.coverage_status.value,
            "coverage_note": self.coverage_note,
            "content": thaw_value(self.content),
            "metadata": thaw_value(self.metadata),
        }

    # ── the case record protocol ────────────────────────────────────────────

    @property
    def record_id(self) -> str:
        return self.evidence_id

    @property
    def record_type(self) -> str:
        return "evidence"

    # ── properties ──────────────────────────────────────────────────────────

    @property
    def is_verification(self) -> bool:
        return self.epistemic_status in _VERIFICATION_STATUSES

    @property
    def is_attached(self) -> bool:
        """Does this bear on any declared claim?

        Unattached evidence is legal and common — in a case with no declared
        claims, everything is unattached, which is exactly what the claim-coverage
        row should report rather than something to hide.
        """
        return bool(self.supports_claims or self.contradicts_claims)

    @property
    def content_is_embedded(self) -> bool:
        return bool(self.content_reference
                    and "inline" in (self.content_reference.detail or {}))

    @property
    def trust_status(self) -> TrustStatus:
        """Never inferred. Absent a decision, nobody has ruled on this source."""
        return self.trust.status if self.trust else TrustStatus.NOT_ESTABLISHED

    def applies_to(self, digest: str) -> bool:
        """Is this evidence about that exact artifact?

        The mechanism behind FORMALLY_VERIFIED ≠ APPLICABLE TO CURRENT ARTIFACT.
        A verification whose subject has moved on answers a question nobody is
        asking any more.
        """
        return self.applies_to_digest is not None and self.applies_to_digest == digest

    def independence_fingerprint(self) -> str:
        """A digest of the attributes that make this record a distinct source.

        Always present, because `source` and `producer_id` are both mandatory:
        rather than tolerate unattributable evidence and report it as ungrouped,
        the record makes it impossible to construct.

        Grouping here is local to the record. Deeper lineage closure — two
        differently-named agents that are both descendants of one derivation — is
        the independence analyser's job, and it needs `parent_evidence` to do it.
        """
        return digest_object({
            "source": self.source,
            "producer_id": self.producer.producer_id,
            "model": self.producer.model,
            "prompt_digest": (self.metadata or {}).get("prompt_digest"),
            "environment": (self.metadata or {}).get("environment"),
        })

    @property
    def independence_basis(self) -> str:
        """How much weight the grouping deserves: `authenticated` or `asserted`.

        A producer id nobody authenticated is a claim about identity, so two
        records naming different producers may still be one actor. That does not
        make the grouping useless — an honest CI job is normally unauthenticated —
        but it does make it weaker, and which of the two a decision requires is a
        methodology question rather than something to hardcode here.
        """
        basis = (self.producer.identity_basis or "").strip().lower()
        return "asserted" if basis in ("", "none", "unauthenticated", "unknown") \
            else "authenticated"

    # ── transitions ─────────────────────────────────────────────────────────

    def with_trust(self, status: TrustStatus, *, basis: str,
                   decided_by: str) -> "EvidenceRecord":
        """Record an explicit ruling on this source's authority.

        The only way `trust_status` ever moves. It takes a decider and a basis
        because trust that cannot be traced to someone's judgement is an
        assumption wearing a field name.
        """
        return dataclasses.replace(
            self, trust=TrustDecision(status=status, basis=basis, decided_by=decided_by))

    def supporting(self, *claim_ids: str) -> "EvidenceRecord":
        return dataclasses.replace(
            self, supports_claims=tuple(dict.fromkeys(self.supports_claims + claim_ids)))

    def contradicting(self, *claim_ids: str) -> "EvidenceRecord":
        return dataclasses.replace(
            self, contradicts_claims=tuple(dict.fromkeys(self.contradicts_claims + claim_ids)))

    # ── serialisation ───────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "evidence",
            "evidence_id": self.evidence_id,
            "record_id": self.evidence_id,
            "trust_status": self.trust_status.value,
            "trust": self.trust.to_dict() if self.trust else None,
            "independence_group": self.independence_fingerprint(),
            "independence_basis": self.independence_basis,
            **self.identity(),
            # After the spread on purpose. `identity()` holds an arrival stamp
            # out of the content address; the record still has to carry it, or a
            # reader loses when release-gate saw this. The flag says which kind
            # of time this is, and `from_dict` uses it to recompute the same id.
            "timestamp": self.timestamp,
            "stamped_on_arrival": self.stamped_on_arrival,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRecord":
        version = int(data.get("schema_version", EVIDENCE_SCHEMA_VERSION))
        if version > EVIDENCE_SCHEMA_VERSION:
            raise EvidenceSchemaError(
                f"evidence record declares schema version {version}; this reader "
                f"understands {EVIDENCE_SCHEMA_VERSION}. Upgrade rather than read a record "
                "whose fields would be silently dropped.")
        reference = data.get("content_reference")
        record = cls(
            evidence_type=EvidenceType(data["evidence_type"]),
            source=data["source"],
            producer=Producer.from_dict(data["producer"]),
            epistemic_status=EpistemicStatus(data["epistemic_status"]),
            content_reference=ContentReference.from_dict(reference) if reference else None,
            digest=data.get("digest"),
            source_identity=data.get("source_identity", "unauthenticated"),
            # A payload that says its timestamp was stamped on arrival is read
            # back as unsupplied, so the id recomputes to the same value. A
            # payload without the flag predates it and is read the old way: its
            # timestamp counts, and records written before this change keep the
            # ids they were stored under.
            timestamp=("" if data.get("stamped_on_arrival")
                       else (data.get("timestamp") or "")),
            parent_evidence=tuple(data.get("parent_evidence", ())),
            supports_claims=tuple(data.get("supports_claims", ())),
            contradicts_claims=tuple(data.get("contradicts_claims", ())),
            verification_method=(VerificationMethod(data["verification_method"])
                                 if data.get("verification_method") else None),
            applies_to_digest=data.get("applies_to_digest"),
            provenance_status=ProvenanceStatus(data.get("provenance_status",
                                                        ProvenanceStatus.ATTRIBUTED.value)),
            trust=TrustDecision.from_dict(data.get("trust")),
            coverage_status=CoverageStatus(data.get("coverage_status",
                                                    CoverageStatus.UNKNOWN.value)),
            coverage_note=data.get("coverage_note", ""),
            content=data.get("content") or {},
            metadata=data.get("metadata") or {},
            schema_version=version)
        stored = data.get("evidence_id")
        if stored and stored != record.evidence_id:
            raise EvidenceIntegrityError(
                f"evidence_id in the record ({stored}) does not match the value recomputed "
                f"from its content ({record.evidence_id}) — it was modified after it was "
                "written")
        return record

    # ── constructors ────────────────────────────────────────────────────────

    @classmethod
    def observed(cls, evidence_type: EvidenceType, *, source: str, producer: Producer,
                 **kwargs: Any) -> "EvidenceRecord":
        """Something release-gate read directly from an instrument.

        A statement about the record, not about the world: that this span exists
        in the ingested export, not that what it describes is true.
        """
        return cls(evidence_type=evidence_type, source=source, producer=producer,
                   epistemic_status=EpistemicStatus.OBSERVED, **kwargs)

    @classmethod
    def declared(cls, evidence_type: EvidenceType, *, source: str, producer: Producer,
                 **kwargs: Any) -> "EvidenceRecord":
        """An actor asserted this. Zero independent support, and that is the point."""
        return cls(evidence_type=evidence_type, source=source, producer=producer,
                   epistemic_status=EpistemicStatus.DECLARED, **kwargs)

    @classmethod
    def derived(cls, evidence_type: EvidenceType, *, source: str, producer: Producer,
                parent_evidence: Iterable[str] = (), **kwargs: Any) -> "EvidenceRecord":
        """release-gate computed this from other records."""
        parents = tuple(parent_evidence)
        kwargs.setdefault(
            "provenance_status",
            ProvenanceStatus.CHAIN_VERIFIED if parents else ProvenanceStatus.UNATTRIBUTED)
        return cls(evidence_type=evidence_type, source=source, producer=producer,
                   epistemic_status=EpistemicStatus.DERIVED, parent_evidence=parents, **kwargs)

    @classmethod
    def verification(cls, evidence_type: EvidenceType, *, source: str, producer: Producer,
                     method: VerificationMethod, applies_to_digest: str, coverage_note: str,
                     refuted: bool = False, **kwargs: Any) -> "EvidenceRecord":
        """A verification result — positive, or a refutation.

        A refutation is the same record type with the same rigour, because a
        failed proof attempt is evidence and losing it is how a case comes to
        look cleaner than it is (Invariant 7).
        """
        return cls(evidence_type=evidence_type, source=source, producer=producer,
                   epistemic_status=(EpistemicStatus.REFUTED if refuted
                                     else EpistemicStatus.VERIFIED),
                   verification_method=method, applies_to_digest=applies_to_digest,
                   coverage_note=coverage_note, **kwargs)

    @classmethod
    def from_producer(cls, payload: Mapping[str, Any], *, evidence_type: EvidenceType,
                      source: str, producer: Producer,
                      status: EpistemicStatus = EpistemicStatus.DECLARED,
                      **kwargs: Any) -> "EvidenceRecord":
        """The ingest boundary: where an untrusted payload becomes a record.

        Whatever a producer put in its payload about its own status is moved to
        `content.producer_claimed_*` and plays no part in anything. The `status`
        argument is chosen by the adapter — release-gate's own code — not by the
        thing being ingested. An agent asserting "verified: true" yields DECLARED
        evidence that the agent asserted it, which is a real fact worth keeping
        and is not evidence the assertion is true (Invariant 1).

        `OBSERVED` and `DERIVED` are refused here: those describe release-gate's
        own work, and an adapter that wants them should say so through
        `observed()` or `derived()` rather than through the boundary for foreign
        payloads.
        """
        status = EpistemicStatus(status)
        if status in _SELF_ASSIGNABLE and producer.kind is not ProducerKind.RELEASE_GATE:
            raise EvidenceError(
                f"{status.value} describes release-gate's own observation or computation; "
                f"a payload from {producer.producer_id} cannot be ingested as {status.value}. "
                "Use DECLARED, or a verification with a named method.")

        claimed = {f"producer_claimed_{k}": payload[k] for k in _PRODUCER_FORBIDDEN
                   if k in payload}
        content = {k: v for k, v in payload.items() if k not in _PRODUCER_FORBIDDEN}
        content.update(claimed)
        merged = dict(kwargs.pop("content", {}) or {})
        merged.update(content)
        return cls(evidence_type=evidence_type, source=source, producer=producer,
                   epistemic_status=status, content=merged, **kwargs)
