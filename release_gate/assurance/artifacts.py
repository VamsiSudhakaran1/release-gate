"""ArtifactGraph — where a thing came from, and whether it is still that thing.

Source code, a Lean file, a dataset, a SQL result, a paper, a simulation output,
a model checkpoint, a generated report, a payment batch, a deployment plan, a
config. Different in every respect except the questions people ask about them:

    What created this?                  created_by()
    What inputs contributed?            inputs(), lineage()
    What modified it?                   modified_by(), revision_chain()
    What verified it?                   verifications()
    What decision depends on it?        decisions_depending_on()
    Has it changed since verification?  verification_currency()

**Two identities, and the difference between them is the whole point.** An
artifact's *content identity* is its digest, and that is what a verification
attaches to. Its *logical identity* is the handle successive versions share —
`migrations/2026_09_12.sql`, `model/checkpoint`, `batch/refunds-q4`. Without the
split, a revised file is simply a different artifact and the sixth question has
no answer; with it, "verified at v1, now at v3" is a comparison rather than a
judgement.

That is what makes FORMALLY_VERIFIED ≠ APPLICABLE TO THE CURRENT ARTIFACT
mechanical (Invariant 2), and it is the mechanism by which an approval decays
instead of silently carrying over (Invariant 5).

**Digests where possible, and honesty where not.** An artifact release-gate
hashed itself is `OBSERVED`; one a store attests to is `DECLARED`; one that
cannot be hashed from here carries no digest at all and reports
`UNVERIFIABLE` currency. A missing digest is never treated as an unchanged one
(Invariant 3).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Tuple)

from release_gate.assurance.canonical import (
    CanonicalisationError,
    digest_object,
    freeze_value,
    is_content_id,
    require_content_id,
    thaw_value,
)
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.evidence import EpistemicStatus, EvidenceRecord
from release_gate.assurance.records import Presence
from release_gate.assurance.subject import (
    AssuranceSubject,
    ContentReference,
    DigestMethod,
    DigestStatus,
    ReferenceKind,
)

ARTIFACT_SCHEMA_VERSION = 1


class ArtifactKind(str, Enum):
    """What sort of thing it is. Selects no behaviour; it is for the reader."""

    SOURCE_CODE = "SOURCE_CODE"
    PROOF = "PROOF"
    DATASET = "DATASET"
    QUERY_OUTPUT = "QUERY_OUTPUT"
    DOCUMENT = "DOCUMENT"
    SIMULATION_OUTPUT = "SIMULATION_OUTPUT"
    MODEL_CHECKPOINT = "MODEL_CHECKPOINT"
    REPORT = "REPORT"
    PAYMENT_BATCH = "PAYMENT_BATCH"
    DEPLOYMENT_PLAN = "DEPLOYMENT_PLAN"
    CONFIGURATION = "CONFIGURATION"
    MIGRATION = "MIGRATION"
    OTHER = "OTHER"


class ArtifactEdgeType(str, Enum):
    DERIVED_FROM = "DERIVED_FROM"      # artifact → the inputs that contributed
    CREATED_BY = "CREATED_BY"          # artifact → the actor that produced it
    MODIFIED_BY = "MODIFIED_BY"        # artifact → an actor that changed it
    VERIFIED_BY = "VERIFIED_BY"        # artifact → evidence about THIS digest
    REVISES = "REVISES"                # this content → the content it replaced
    DEPENDED_ON_BY = "DEPENDED_ON_BY"  # artifact → a claim or decision resting on it
    SIGNED_BY = "SIGNED_BY"


class ArtifactNodeKind(str, Enum):
    ARTIFACT = "ARTIFACT"
    ACTOR = "ACTOR"
    EVIDENCE = "EVIDENCE"
    DECISION = "DECISION"


class CurrencyStatus(str, Enum):
    """Whether what was verified is what is in front of you now."""

    VERIFIED_CURRENT = "VERIFIED_CURRENT"    # this exact content was verified
    VERIFIED_STALE = "VERIFIED_STALE"        # an earlier revision was; this one is not
    NEVER_VERIFIED = "NEVER_VERIFIED"        # no revision was ever verified
    UNVERIFIABLE = "UNVERIFIABLE"            # no digest, so the question has no answer


class ArtifactError(ValueError):
    """An artifact was described in a way that cannot be traced."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Artifact:
    """One version of one thing, identified by its content where possible."""

    logical_id: str
    artifact_kind: ArtifactKind = ArtifactKind.OTHER
    digest: Optional[str] = None
    digest_method: DigestMethod = DigestMethod.NONE
    digest_status: DigestStatus = DigestStatus.UNKNOWN
    digest_attested_by: Optional[str] = None
    created_by: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    inputs: Tuple[str, ...] = ()
    revises: Optional[str] = None
    modified_by: Tuple[str, ...] = ()
    signed_by: Optional[str] = None
    content_reference: Optional[ContentReference] = None
    byte_length: Optional[int] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = ARTIFACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_kind", ArtifactKind(self.artifact_kind))
        object.__setattr__(self, "digest_method", DigestMethod(self.digest_method))
        object.__setattr__(self, "digest_status", DigestStatus(self.digest_status))
        for name in ("inputs", "modified_by"):
            object.__setattr__(self, name, tuple(dict.fromkeys(getattr(self, name))))

        if not (self.logical_id or "").strip():
            raise ArtifactError(
                "logical_id is required: without a stable handle, successive versions of "
                "one thing cannot be recognised as versions of one thing, and 'has it "
                "changed since verification?' has no answer")
        object.__setattr__(self, "logical_id", self.logical_id.strip())

        if self.digest is not None:
            require_content_id(self.digest)
            if self.digest_status is DigestStatus.UNKNOWN:
                raise ArtifactError(
                    f"{self.logical_id}: a digest was supplied but digest_status is UNKNOWN; "
                    "say whether release-gate computed it (OBSERVED) or someone asserts it "
                    "(DECLARED)")
            if self.digest_status is DigestStatus.DECLARED and not self.digest_attested_by:
                raise ArtifactError(
                    f"{self.logical_id}: a DECLARED digest must name its attestor")
        elif self.digest_status is not DigestStatus.UNKNOWN:
            raise ArtifactError(
                f"{self.logical_id}: no digest, so digest_status must be UNKNOWN — a "
                "missing digest is never an unchanged one (Invariant 3)")

        if self.revises is not None and self.revises == self.digest:
            raise ArtifactError(f"{self.logical_id}: an artifact cannot revise itself")

        try:
            object.__setattr__(self, "metadata", freeze_value(self.metadata or {}, "metadata"))
        except CanonicalisationError as exc:
            raise ArtifactError(f"{self.logical_id} metadata: {exc}") from exc

    # ── identity ────────────────────────────────────────────────────────────

    @property
    def artifact_id(self) -> str:
        """Content identity where there is one, logical identity otherwise.

        An unhashed artifact still gets a node — it is part of the lineage — but
        its node stands for "whatever is at this handle", not for exact content,
        and `content_identified` says which.
        """
        return self.digest or f"unhashed:{self.logical_id}"

    @property
    def content_identified(self) -> bool:
        return self.digest is not None

    @property
    def record_id(self) -> str:
        return self.artifact_id

    @property
    def record_type(self) -> str:
        return "artifact"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "artifact",
            "record_id": self.artifact_id,
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            "logical_id": self.logical_id,
            "artifact_kind": self.artifact_kind.value,
            "digest": self.digest,
            "digest_method": self.digest_method.value,
            "digest_status": self.digest_status.value,
            "digest_attested_by": self.digest_attested_by,
            "content_identified": self.content_identified,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "inputs": list(self.inputs),
            "revises": self.revises,
            "modified_by": list(self.modified_by),
            "signed_by": self.signed_by,
            "content_reference": (self.content_reference.to_dict()
                                  if self.content_reference else None),
            "byte_length": self.byte_length,
            "metadata": thaw_value(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Artifact":
        if int(data.get("schema_version", ARTIFACT_SCHEMA_VERSION)) > ARTIFACT_SCHEMA_VERSION:
            raise ArtifactError(
                f"artifact schema version {data['schema_version']} is newer than this "
                f"reader understands ({ARTIFACT_SCHEMA_VERSION})")
        reference = data.get("content_reference")
        return cls(
            logical_id=data["logical_id"],
            artifact_kind=ArtifactKind(data.get("artifact_kind", ArtifactKind.OTHER.value)),
            digest=data.get("digest"),
            digest_method=DigestMethod(data.get("digest_method", DigestMethod.NONE.value)),
            digest_status=DigestStatus(data.get("digest_status", DigestStatus.UNKNOWN.value)),
            digest_attested_by=data.get("digest_attested_by"),
            created_by=data.get("created_by"), created_at=data.get("created_at") or _utc_now(),
            inputs=tuple(data.get("inputs", ())), revises=data.get("revises"),
            modified_by=tuple(data.get("modified_by", ())), signed_by=data.get("signed_by"),
            content_reference=ContentReference.from_dict(reference) if reference else None,
            byte_length=data.get("byte_length"), metadata=data.get("metadata") or {})

    @classmethod
    def from_subject(cls, subject: AssuranceSubject, **kwargs: Any) -> "Artifact":
        """The thing under authorisation, as an artifact.

        The subject is where the artifact graph meets the decision: everything
        that flows into it is what the approval ultimately rests on.
        """
        reference = subject.content_reference
        locator = reference.locator
        if reference.kind is ReferenceKind.INLINE:
            # "inline" is a label, not a path; qualify it so it cannot be mistaken
            # for a file of that name, or for another inline artifact.
            locator = f"subject:{subject.subject_type.value}:{locator}"
        kwargs.setdefault("logical_id", locator)
        kwargs.setdefault("artifact_kind", ArtifactKind.OTHER)
        return cls(digest=subject.digest, digest_method=subject.digest_method,
                   digest_status=subject.digest_status,
                   digest_attested_by=subject.digest_attested_by,
                   content_reference=subject.content_reference,
                   metadata={"subject_id": subject.subject_id,
                             "requested_action": subject.requested_action},
                   **kwargs)


@dataclass(frozen=True)
class ArtifactEdge:
    edge_type: ArtifactEdgeType
    from_id: str
    to_id: str
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_type", ArtifactEdgeType(self.edge_type))

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.edge_type.value, self.from_id, self.to_id)

    def to_dict(self) -> Dict[str, Any]:
        return {"edge_type": self.edge_type.value, "from": self.from_id,
                "to": self.to_id, "basis": self.basis}


@dataclass(frozen=True)
class VerificationCurrency:
    """The answer to "has it changed since verification?"."""

    logical_id: str
    current_digest: Optional[str]
    status: CurrencyStatus
    verified_digests: Tuple[str, ...] = ()
    verifications_of_current: Tuple[str, ...] = ()
    revisions_since_verification: int = 0
    ambiguous_heads: Tuple[str, ...] = ()
    detail: str = ""

    @property
    def current(self) -> bool:
        """True only for a positive answer.

        `UNVERIFIABLE` and `VERIFIED_STALE` are both falsy here: code asking "is
        this still fine?" must not read "I cannot tell" as yes.
        """
        return self.status is CurrencyStatus.VERIFIED_CURRENT

    def to_dict(self) -> Dict[str, Any]:
        return {"logical_id": self.logical_id, "current_digest": self.current_digest,
                "status": self.status.value, "verified_digests": list(self.verified_digests),
                "verifications_of_current": list(self.verifications_of_current),
                "revisions_since_verification": self.revisions_since_verification,
                "ambiguous_heads": list(self.ambiguous_heads), "detail": self.detail}


class ArtifactGraph:
    """Provenance, revisions, verification currency, and what rests on it all."""

    def __init__(self, artifacts: Iterable[Artifact], edges: Iterable[ArtifactEdge],
                 *, notes: Iterable[str] = ()) -> None:
        self._artifacts: Dict[str, Artifact] = {a.artifact_id: a for a in artifacts}
        self._edges: Tuple[ArtifactEdge, ...] = tuple(sorted(
            {e.key: e for e in edges}.values(), key=lambda e: e.key))
        self.notes: Tuple[str, ...] = tuple(notes)

        self._out: Dict[str, List[ArtifactEdge]] = defaultdict(list)
        self._in: Dict[str, List[ArtifactEdge]] = defaultdict(list)
        for edge in self._edges:
            self._out[edge.from_id].append(edge)
            self._in[edge.to_id].append(edge)

        self._by_logical: Dict[str, List[Artifact]] = defaultdict(list)
        for artifact in self.artifacts:
            self._by_logical[artifact.logical_id].append(artifact)

    # ── access ──────────────────────────────────────────────────────────────

    @property
    def artifacts(self) -> Tuple[Artifact, ...]:
        return tuple(self._artifacts[k] for k in sorted(self._artifacts))

    @property
    def edges(self) -> Tuple[ArtifactEdge, ...]:
        return self._edges

    def artifact(self, artifact_id: str) -> Optional[Artifact]:
        return self._artifacts.get(artifact_id)

    def versions(self, logical_id: str) -> Tuple[Artifact, ...]:
        """Every recorded version of one logical thing, oldest first where known."""
        return tuple(sorted(self._by_logical.get(logical_id, ()),
                            key=lambda a: (a.created_at, a.artifact_id)))

    def logical_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._by_logical))

    def __len__(self) -> int:
        return len(self._artifacts)

    def __contains__(self, artifact_id: object) -> bool:
        return artifact_id in self._artifacts

    def out_edges(self, node_id: str, *types: ArtifactEdgeType) -> Tuple[ArtifactEdge, ...]:
        return tuple(e for e in self._out.get(node_id, ())
                     if not types or e.edge_type in types)

    def in_edges(self, node_id: str, *types: ArtifactEdgeType) -> Tuple[ArtifactEdge, ...]:
        return tuple(e for e in self._in.get(node_id, ())
                     if not types or e.edge_type in types)

    # ── question 1: what created this? ──────────────────────────────────────

    def created_by(self, artifact_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.to_id for e in self.out_edges(artifact_id,
                                                            ArtifactEdgeType.CREATED_BY)))

    # ── question 2: what inputs contributed? ────────────────────────────────

    def inputs(self, artifact_id: str) -> Tuple[str, ...]:
        """Direct inputs only."""
        return tuple(sorted(e.to_id for e in self.out_edges(artifact_id,
                                                            ArtifactEdgeType.DERIVED_FROM)))

    def lineage(self, artifact_id: str) -> Tuple[str, ...]:
        """Every input, transitively. Iterative and cycle-safe."""
        seen: Set[str] = set()
        frontier = [artifact_id]
        while frontier:
            for edge in self.out_edges(frontier.pop(), ArtifactEdgeType.DERIVED_FROM):
                if edge.to_id not in seen:
                    seen.add(edge.to_id)
                    frontier.append(edge.to_id)
        return tuple(sorted(seen))

    def dependents(self, artifact_id: str) -> Tuple[str, ...]:
        """Everything downstream — what would have to be re-examined if this moved."""
        seen: Set[str] = set()
        frontier = [artifact_id]
        while frontier:
            for edge in self.in_edges(frontier.pop(), ArtifactEdgeType.DERIVED_FROM):
                if edge.from_id not in seen:
                    seen.add(edge.from_id)
                    frontier.append(edge.from_id)
        return tuple(sorted(seen))

    # ── question 3: what modified it? ───────────────────────────────────────

    def modified_by(self, artifact_id: str) -> Tuple[str, ...]:
        return tuple(sorted(e.to_id for e in self.out_edges(artifact_id,
                                                            ArtifactEdgeType.MODIFIED_BY)))

    def revision_chain(self, logical_id: str) -> Tuple[str, ...]:
        """Content digests of one logical artifact, oldest to newest.

        Ordered by the REVISES links where they exist, so the chain reflects what
        actually replaced what rather than when records happened to be written.
        """
        versions = {a.artifact_id: a for a in self.versions(logical_id)}
        if not versions:
            return ()
        revised = {a.revises for a in versions.values() if a.revises}
        heads = [aid for aid in versions if aid not in revised]
        chain: List[str] = []
        for head in sorted(heads):
            walk: List[str] = []
            current: Optional[str] = head
            seen: Set[str] = set()
            while current and current in versions and current not in seen:
                seen.add(current)
                walk.append(current)
                current = versions[current].revises
            chain = list(reversed(walk)) + [c for c in chain if c not in walk]
        for aid in sorted(versions):
            if aid not in chain:
                chain.append(aid)
        return tuple(chain)

    def heads(self, logical_id: str) -> Tuple[str, ...]:
        """Versions nothing revises. More than one means the history forked."""
        versions = {a.artifact_id: a for a in self.versions(logical_id)}
        revised = {a.revises for a in versions.values() if a.revises}
        return tuple(sorted(aid for aid in versions if aid not in revised))

    def current_version(self, logical_id: str) -> Optional[Artifact]:
        """The head of the revision chain — what is in front of you now.

        With a forked history there is no single answer, and this returns the
        latest head rather than pretending otherwise; `heads()` and
        `verification_currency().ambiguous_heads` expose the fork.
        """
        heads = self.heads(logical_id)
        if not heads:
            chain = self.revision_chain(logical_id)
            return self._artifacts.get(chain[-1]) if chain else None
        return max((self._artifacts[h] for h in heads),
                   key=lambda a: (a.created_at, a.artifact_id))

    # ── question 4: what verified it? ───────────────────────────────────────

    def verifications(self, artifact_id: str) -> Tuple[str, ...]:
        """Evidence about THIS exact content — never about a sibling revision."""
        return tuple(sorted(e.to_id for e in self.out_edges(artifact_id,
                                                            ArtifactEdgeType.VERIFIED_BY)))

    # ── question 5: what decision depends on it? ────────────────────────────

    def decisions_depending_on(self, artifact_id: str) -> Tuple[str, ...]:
        """Claims and decisions resting on this artifact or anything derived from it."""
        reachable = {artifact_id} | set(self.dependents(artifact_id))
        return tuple(sorted({e.to_id for aid in reachable
                             for e in self.out_edges(aid, ArtifactEdgeType.DEPENDED_ON_BY)}))

    # ── question 6: has it changed since verification? ──────────────────────

    def verification_currency(self, logical_id: str) -> VerificationCurrency:
        """Compare what was verified against what is there now.

        The whole reason content identity and logical identity are separate. A
        verification attaches to a digest; an artifact moves on; and the gap
        between those two facts is what makes an approval go stale rather than
        quietly carry over (Invariants 2 and 5).
        """
        chain = self.revision_chain(logical_id)
        if not chain:
            return VerificationCurrency(logical_id, None, CurrencyStatus.NEVER_VERIFIED,
                                        detail="no versions of this artifact are on record")

        heads = self.heads(logical_id)
        forked = heads if len(heads) > 1 else ()
        current = self.current_version(logical_id)
        current_id = current.artifact_id if current else chain[-1]
        verified = tuple(aid for aid in chain if self.verifications(aid))
        fork_note = (f" The history forked into {len(heads)} versions nothing revises, so "
                     "'the current one' is not a single thing." if forked else "")

        if not current or not current.content_identified:
            return VerificationCurrency(
                logical_id, None, CurrencyStatus.UNVERIFIABLE, verified_digests=verified,
                ambiguous_heads=forked,
                detail=("the current version carries no digest, so whether it is what was "
                        "verified cannot be established from here" + fork_note))

        # With a fork, "verified" means every head is verified: a verification of
        # one branch says nothing about the other.
        relevant = list(heads) if forked else [current_id]
        if all(self.verifications(aid) for aid in relevant):
            return VerificationCurrency(
                logical_id, current.digest, CurrencyStatus.VERIFIED_CURRENT,
                verified_digests=verified, ambiguous_heads=forked,
                verifications_of_current=self.verifications(current_id),
                detail="this exact content was verified" + fork_note)
        if verified:
            last_verified = chain.index(verified[-1])
            return VerificationCurrency(
                logical_id, current.digest, CurrencyStatus.VERIFIED_STALE,
                verified_digests=verified, ambiguous_heads=forked,
                revisions_since_verification=len(chain) - 1 - last_verified,
                detail=(f"an earlier revision was verified and the artifact has changed "
                        f"{len(chain) - 1 - last_verified} time(s) since; the verification "
                        "describes content that is no longer in front of you" + fork_note))
        return VerificationCurrency(
            logical_id, current.digest, CurrencyStatus.NEVER_VERIFIED,
            ambiguous_heads=forked,
            detail="no revision of this artifact has been verified" + fork_note)

    def stale_verifications(self) -> Tuple[VerificationCurrency, ...]:
        """Every logical artifact whose verification no longer describes it."""
        return tuple(c for c in (self.verification_currency(l) for l in self.logical_ids())
                     if c.status is CurrencyStatus.VERIFIED_STALE)

    # ── the whole story for one artifact ────────────────────────────────────

    def provenance(self, artifact_id: str) -> Dict[str, Any]:
        """All six answers for one artifact, in one object."""
        artifact = self._artifacts.get(artifact_id)
        if artifact is None:
            return {"artifact_id": artifact_id, "present": False,
                    "detail": "this artifact is not in the case"}
        return {
            "artifact_id": artifact_id,
            "present": True,
            "logical_id": artifact.logical_id,
            "kind": artifact.artifact_kind.value,
            "content_identified": artifact.content_identified,
            "digest_status": artifact.digest_status.value,
            "created_by": self.created_by(artifact_id),
            "inputs": self.inputs(artifact_id),
            "lineage": self.lineage(artifact_id),
            "modified_by": self.modified_by(artifact_id),
            "verified_by": self.verifications(artifact_id),
            "decisions_depending_on": self.decisions_depending_on(artifact_id),
            "revision_chain": self.revision_chain(artifact.logical_id),
            "currency": self.verification_currency(artifact.logical_id).to_dict(),
        }

    def summary(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = defaultdict(int)
        for artifact in self.artifacts:
            by_kind[artifact.artifact_kind.value] += 1
        unhashed = [a.logical_id for a in self.artifacts if not a.content_identified]
        stale = self.stale_verifications()
        return {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "artifacts": len(self._artifacts),
            "logical_artifacts": len(self._by_logical),
            "edges": len(self._edges),
            "by_kind": dict(sorted(by_kind.items())),
            "without_digest": sorted(set(unhashed)),
            "stale_verifications": [c.to_dict() for c in stale],
            "notes": list(self.notes),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "artifact_graph",
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "edges": [e.to_dict() for e in self.edges],
            "notes": list(self.notes),
            "digest": self.digest(),
        }

    def digest(self) -> str:
        return digest_object({"schema_version": ARTIFACT_SCHEMA_VERSION,
                              "artifacts": [a.to_dict() for a in self.artifacts],
                              "edges": [e.to_dict() for e in self.edges]})

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_case(cls, case: AssuranceCase, *, execution_graph: Any = None,
                  claim_graph: Any = None) -> "ArtifactGraph":
        """Build from the subject, the artifacts collection, and the evidence.

        Always returns a graph rather than `None`: every case has at least one
        artifact, because the subject is one. That is also where the graph meets
        the decision — everything flowing into the subject is what the approval
        ultimately rests on.
        """
        builder = ArtifactGraphBuilder()
        notes: List[str] = []

        collection = case.collection("artifacts")
        if collection.presence is Presence.PRESENT:
            typed = [a for a in collection.materialised if isinstance(a, Artifact)]
            for artifact in typed:
                builder.add(artifact)
            skipped = collection.held_count - len(typed)
            if skipped:
                notes.append(f"{skipped} record(s) in the artifacts collection are not "
                             "Artifacts and were not modelled")
            if collection.not_materialised:
                notes.append(f"{collection.not_materialised} artifact(s) were counted but "
                             "not materialised; they are absent from this graph")

        subject_artifact = Artifact.from_subject(case.subject)
        builder.add(subject_artifact)
        decision_id = f"decision:{case.case_id}"
        builder.link(ArtifactEdgeType.DEPENDED_ON_BY, subject_artifact.artifact_id,
                     decision_id, basis="the subject of this case")

        for kind in ("evidence", "verification", "contradictions", "counterexamples"):
            for record in case.collection(kind).materialised:
                if isinstance(record, EvidenceRecord):
                    builder.add_evidence(record)

        if execution_graph is not None:
            builder.add_execution_graph(execution_graph)
        if claim_graph is not None:
            builder.add_claim_graph(claim_graph, case)

        return builder.build(notes=notes)


class ArtifactGraphBuilder:
    """Accumulates artifacts and the relations that explain them."""

    def __init__(self) -> None:
        self._artifacts: Dict[str, Artifact] = {}
        self._edges: Dict[Tuple[str, str, str], ArtifactEdge] = {}
        self._claims_by_evidence: Dict[str, Set[str]] = defaultdict(set)

    def add(self, artifact: Artifact) -> str:
        """Add an artifact and every relation its own fields express."""
        self._artifacts.setdefault(artifact.artifact_id, artifact)
        node_id = artifact.artifact_id
        if artifact.created_by:
            self.link(ArtifactEdgeType.CREATED_BY, node_id, artifact.created_by,
                      basis="created_by on the artifact")
        for actor in artifact.modified_by:
            self.link(ArtifactEdgeType.MODIFIED_BY, node_id, actor, basis="modified_by")
        for source in artifact.inputs:
            self.link(ArtifactEdgeType.DERIVED_FROM, node_id, source, basis="inputs")
        if artifact.revises:
            self.link(ArtifactEdgeType.REVISES, node_id, artifact.revises, basis="revises")
        if artifact.signed_by:
            self.link(ArtifactEdgeType.SIGNED_BY, node_id, artifact.signed_by,
                      basis="signed_by")
        return node_id

    def link(self, edge_type: ArtifactEdgeType, from_id: str, to_id: str,
             basis: str = "") -> None:
        edge = ArtifactEdge(edge_type, from_id, to_id, basis=basis or "declared")
        self._edges.setdefault(edge.key, edge)

    def add_evidence(self, record: EvidenceRecord) -> None:
        """Attach a verification to the exact content it was produced against.

        Only to that content. A verification of `sha256:abc…` says nothing about
        `sha256:def…`, and the absence of that edge is how the graph knows
        (Invariant 2).
        """
        if record.is_verification and record.applies_to_digest:
            self.link(ArtifactEdgeType.VERIFIED_BY, record.applies_to_digest,
                      record.evidence_id,
                      basis=f"{record.epistemic_status.value} via "
                            f"{record.verification_method.value}")
        for claim_id in record.supports_claims:
            self._claims_by_evidence[record.evidence_id].add(claim_id)

    def add_execution_graph(self, execution_graph: Any) -> None:
        """Read artifacts the execution graph already extracted from telemetry.

        Deliberately a read rather than a second parse: the execution graph has
        seen the spans, and re-deriving artifacts from raw telemetry here would be
        a second implementation that could disagree with the first.
        """
        from release_gate.assurance.execution_graph import (ExecutionEdgeType,
                                                            ExecutionNodeKind)

        for node in execution_graph.nodes_of(ExecutionNodeKind.ARTIFACT):
            handle = node.label or node.node_id
            digest = handle if is_content_id(handle) else None
            artifact = Artifact(
                logical_id=handle,
                digest=digest,
                digest_method=DigestMethod.EXTERNAL_ATTESTED if digest else DigestMethod.NONE,
                digest_status=DigestStatus.DECLARED if digest else DigestStatus.UNKNOWN,
                digest_attested_by="execution telemetry" if digest else None,
                metadata={"from": "execution telemetry"})
            self._artifacts.setdefault(artifact.artifact_id, artifact)

            for edge in execution_graph.in_edges(node.node_id):
                if edge.edge_type is ExecutionEdgeType.PRODUCED:
                    self.link(ArtifactEdgeType.CREATED_BY, artifact.artifact_id,
                              edge.from_id, basis="PRODUCED in execution telemetry")
                elif edge.edge_type is ExecutionEdgeType.MODIFIED:
                    self.link(ArtifactEdgeType.MODIFIED_BY, artifact.artifact_id,
                              edge.from_id, basis="MODIFIED in execution telemetry")
            for edge in execution_graph.out_edges(node.node_id,
                                                  ExecutionEdgeType.DERIVED_FROM):
                target = execution_graph.node(edge.to_id)
                handle = (target.label if target else edge.to_id)
                self.link(ArtifactEdgeType.DERIVED_FROM, artifact.artifact_id,
                          handle if is_content_id(handle) else f"unhashed:{handle}",
                          basis="DERIVED_FROM in execution telemetry")

    def add_claim_graph(self, claim_graph: Any, case: AssuranceCase) -> None:
        """Roll artifacts up to the claims that rest on them.

        The path is artifact → the evidence verifying it → the claims that
        evidence supports. Nothing is inferred about meaning; every hop is a link
        someone recorded.
        """
        verified_by: Dict[str, List[str]] = defaultdict(list)
        for edge in self._edges.values():
            if edge.edge_type is ArtifactEdgeType.VERIFIED_BY:
                verified_by[edge.to_id].append(edge.from_id)

        for evidence_id, claim_ids in self._claims_by_evidence.items():
            for artifact_id in verified_by.get(evidence_id, ()):
                for claim_id in sorted(claim_ids):
                    if claim_id in claim_graph:
                        self.link(ArtifactEdgeType.DEPENDED_ON_BY, artifact_id, claim_id,
                                  basis=f"verified by {evidence_id}, which supports "
                                        "this claim")

    def build(self, *, notes: Iterable[str] = ()) -> ArtifactGraph:
        return ArtifactGraph(self._artifacts.values(), self._edges.values(), notes=notes)
