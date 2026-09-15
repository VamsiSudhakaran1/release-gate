"""Chain of custody: what connects one piece of evidence to the next.

The chain a decision actually rests on:

    agent event  --digest-->  tool output  --digest-->  verifier result
                 --target digest-->  evidence pack  --digest-->  human approval

Every one of those links already existed as a field — `parent_evidence`,
`applies_to_digest`, `target_digest`, `evidence_pack_digest`. What did not exist
is anything that *walks* them and says where the chain holds and where it breaks.
That is all this module is: a traversal and a report over links other modules
already record.

**No blockchain, and the reason is not fashion.** A blockchain answers "how do
mutually distrusting strangers agree on an ordering without a referee", which is
not the question here. The question here is "can the person holding this evidence
recompute the digests and see that nothing was swapped", and the answer to that
is content addressing plus a traversal — no consensus, no ledger, no network, no
tokens. Every link below is verifiable offline by anyone with the bytes, which is
strictly stronger than a chain of blocks nobody in the approval path can audit.

## Two refusals

**A chain establishes integrity, not truth.** An unbroken, fully signed chain
proves that nothing was altered between the steps recorded and who put their name
to each one. It does not establish that the agent was honest, that the tool was
correct, or that the verifier was competent — and `establishes_truth` is an
unconditional `False` property rather than a sentence in a docstring, so nothing
downstream can read it any other way (Invariant 11: provenance is not trust).

**Signatures are recorded here and verified elsewhere.** This package is
stdlib-only by design — the deterministic authoritative path does not import a
cryptography stack — so `SignatureMetadata` carries algorithm, key id and signer
and reports `verified` as NOT_ASSESSED. A verification result may be supplied by
whoever ran the check; this module will not invent one. That is the same
treatment `EndOfStream` gets in §10g, for the same reason: a signature
establishes authorship, and authorship is not completeness or correctness.

**A missing link is UNLINKED, not BROKEN.** Evidence that never claimed a parent
has not been tampered with — it simply asserts nothing about where it came from.
Reporting that as a break would flood a case with alarms for the ordinary shape
of evidence nobody bothered to chain, and the real breaks would be lost in them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, is_digest, short_id

ATTESTATION_SCHEMA_VERSION = 1


class AttestationError(ValueError):
    """A custody record that cannot be represented."""


class SignatureState(str, Enum):
    """What is known about a signature. Never set to VALID by this module."""

    NOT_ASSESSED = "NOT_ASSESSED"   # recorded, nobody has checked it here
    VALID = "VALID"                 # an external verifier reported it valid
    INVALID = "INVALID"             # an external verifier reported it invalid
    UNVERIFIABLE = "UNVERIFIABLE"   # no key, or an algorithm nobody here knows


class LinkStatus(str, Enum):
    """Whether one hop of the chain holds."""

    LINKED = "LINKED"        # a digest connects the two and it resolves
    BROKEN = "BROKEN"        # a digest is asserted and does not resolve
    UNLINKED = "UNLINKED"    # nothing asserts a connection; not a break


class ChainStatus(str, Enum):
    """What can be said about the chain as a whole."""

    CONTINUOUS = "CONTINUOUS"      # every asserted hop resolves, end to end
    PARTIAL = "PARTIAL"            # what is asserted resolves, but stops short
    BROKEN = "BROKEN"              # at least one asserted hop does not resolve
    NOT_ASSESSED = "NOT_ASSESSED"  # nothing asserts any link


@dataclass(frozen=True)
class SignatureMetadata:
    """Who signed something, with what, and whether anyone has checked.

    Deliberately inert. Carrying a signature is useful — it says which party is
    accountable for a record — and checking it is somebody else's job, because
    this package holds no keys and imports no cryptography.
    """

    signer: str
    algorithm: str = ""
    key_id: str = ""
    signature_id: str = ""
    #: Only ever set by a caller relaying an external verification result.
    state: SignatureState = SignatureState.NOT_ASSESSED
    verified_by: str = ""

    def __post_init__(self) -> None:
        if not str(self.signer or "").strip():
            raise AttestationError(
                "a signature must name its signer: an anonymous signature "
                "establishes nothing at all, which is worse than no signature")
        object.__setattr__(self, "signer", str(self.signer).strip())
        object.__setattr__(self, "state", SignatureState(self.state))
        if (self.state in (SignatureState.VALID, SignatureState.INVALID)
                and not str(self.verified_by or "").strip()):
            raise AttestationError(
                f"a signature reported {self.state.value} must name who checked "
                "it; this package verifies nothing itself, so an unattributed "
                "result has no standing")

    @property
    def establishes_correctness(self) -> bool:
        """Unconditionally False. A signature says who, never whether."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"signer": self.signer, "algorithm": self.algorithm,
                "key_id": self.key_id, "signature_id": self.signature_id,
                "state": self.state.value, "verified_by": self.verified_by,
                "establishes_correctness": False}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SignatureMetadata":
        return cls(signer=data.get("signer", ""),
                   algorithm=data.get("algorithm", ""),
                   key_id=data.get("key_id", ""),
                   signature_id=data.get("signature_id", ""),
                   state=data.get("state", SignatureState.NOT_ASSESSED),
                   verified_by=data.get("verified_by", ""))


@dataclass(frozen=True)
class AttestationRef:
    """A pointer to an attestation held somewhere else.

    In-toto layouts, SLSA provenance, Sigstore bundles and a vendor's own signed
    manifest are all this shape: a kind, a locator, and the digest of what it
    attests to. Release-gate records the reference and the digest it names so the
    link can be checked; fetching and validating the document is the job of
    whoever operates that system.
    """

    kind: str
    locator: str = ""
    subject_digest: str = ""
    signature: Optional[SignatureMetadata] = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not str(self.kind or "").strip():
            raise AttestationError("an attestation reference must state its kind")
        object.__setattr__(self, "kind", str(self.kind).strip())
        if self.subject_digest and not is_digest(self.subject_digest):
            raise AttestationError(
                f"subject_digest {self.subject_digest!r} is not a sha256 content "
                "digest; an attestation that cannot name what it covers cannot be "
                "checked against anything")

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "locator": self.locator,
                "subject_digest": self.subject_digest, "detail": self.detail,
                "signature": self.signature.to_dict() if self.signature else None}


@dataclass(frozen=True)
class CustodyLink:
    """One hop: what produced what, and the digest that ties them together."""

    from_ref: str
    to_ref: str
    #: The digest the successor names for its predecessor.
    asserted_digest: str = ""
    #: The digest the predecessor actually has.
    actual_digest: str = ""
    relation: str = "derived_from"
    producer_id: str = ""
    tool_identity: Mapping[str, Any] = field(default_factory=dict)
    signature: Optional[SignatureMetadata] = None
    attestations: Tuple[AttestationRef, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_identity", dict(self.tool_identity or {}))
        object.__setattr__(self, "attestations", tuple(self.attestations))

    @property
    def status(self) -> LinkStatus:
        if not self.asserted_digest:
            # Nothing was claimed, so nothing is broken. Evidence that never
            # named a parent has not been tampered with; it is simply silent
            # about where it came from.
            return LinkStatus.UNLINKED
        if not self.actual_digest:
            # A digest was named and the thing it names is not held, so the link
            # cannot be followed. That is a real break in what this case can
            # show, whatever exists elsewhere.
            return LinkStatus.BROKEN
        return (LinkStatus.LINKED if self.asserted_digest == self.actual_digest
                else LinkStatus.BROKEN)

    @property
    def basis(self) -> str:
        status = self.status
        if status is LinkStatus.LINKED:
            return (f"{self.to_ref} names {self.asserted_digest[:23]}… and that is "
                    f"what {self.from_ref} hashes to")
        if status is LinkStatus.UNLINKED:
            return (f"{self.to_ref} asserts no predecessor digest, so the step from "
                    f"{self.from_ref} is unrecorded rather than broken")
        if not self.actual_digest:
            return (f"{self.to_ref} names {self.asserted_digest[:23]}… and nothing "
                    "held by this case carries that digest")
        return (f"{self.to_ref} names {self.asserted_digest[:23]}… but "
                f"{self.from_ref} hashes to {self.actual_digest[:23]}… — the thing "
                "that was used is not the thing that is here")

    def to_dict(self) -> Dict[str, Any]:
        return {"from": self.from_ref, "to": self.to_ref, "relation": self.relation,
                "status": self.status.value, "basis": self.basis,
                "asserted_digest": self.asserted_digest,
                "actual_digest": self.actual_digest,
                "producer_id": self.producer_id,
                "tool_identity": dict(self.tool_identity),
                "signature": self.signature.to_dict() if self.signature else None,
                "attestations": [a.to_dict() for a in self.attestations]}


@dataclass(frozen=True)
class AttestationChain:
    """The custody links a case holds, and what they do and do not establish."""

    links: Tuple[CustodyLink, ...] = ()
    #: The ref the chain should reach if it is complete — normally the approval.
    terminal_ref: str = ""
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "links", tuple(self.links))

    @property
    def broken(self) -> Tuple[CustodyLink, ...]:
        return tuple(l for l in self.links if l.status is LinkStatus.BROKEN)

    @property
    def linked(self) -> Tuple[CustodyLink, ...]:
        return tuple(l for l in self.links if l.status is LinkStatus.LINKED)

    @property
    def unlinked(self) -> Tuple[CustodyLink, ...]:
        return tuple(l for l in self.links if l.status is LinkStatus.UNLINKED)

    @property
    def signed_links(self) -> Tuple[CustodyLink, ...]:
        return tuple(l for l in self.links if l.signature is not None)

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False, however continuous and however well signed.

        A chain shows that what is here is what was used and who handled it. That
        an agent was honest, a tool correct or a verifier competent are different
        questions this cannot reach, and a caller that could read `True` here
        would eventually treat a green chain as a green verdict.
        """
        return False

    @property
    def status(self) -> ChainStatus:
        if self.broken:
            return ChainStatus.BROKEN
        if not self.linked:
            return ChainStatus.NOT_ASSESSED
        if self.terminal_ref and not self.reaches(self.terminal_ref):
            return ChainStatus.PARTIAL
        if self.unlinked:
            return ChainStatus.PARTIAL
        return ChainStatus.CONTINUOUS

    def reaches(self, ref: str) -> bool:
        """Is `ref` the successor of some link that holds?"""
        return any(l.to_ref == ref and l.status is LinkStatus.LINKED
                   for l in self.links)

    def note(self) -> str:
        status = self.status
        if status is ChainStatus.CONTINUOUS:
            return (f"All {len(self.linked)} recorded step(s) resolve: each thing "
                    "named is the thing held. This establishes that nothing was "
                    "swapped between the steps recorded and who handled each one. "
                    "It does not establish that any of them was right.")
        if status is ChainStatus.BROKEN:
            return (f"{len(self.broken)} step(s) name something this case does not "
                    "hold, or something whose digest differs. What was used is not "
                    "what is here, and the evidence downstream of the break is "
                    "about a different object than it appears to be.")
        if status is ChainStatus.PARTIAL:
            return (f"{len(self.linked)} step(s) resolve and {len(self.unlinked)} "
                    "assert no predecessor. Nothing is broken; the custody record "
                    "simply stops rather than reaching end to end.")
        return ("No step asserts a predecessor digest, so there is no custody "
                "record to check. Nothing here is broken and nothing is "
                "established.")

    @property
    def chain_id(self) -> str:
        return short_id("chain", digest_object([l.to_dict() for l in self.links]))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "attestation_chain", "record_id": self.chain_id,
                "status": self.status.value, "note": self.note(),
                "links": [l.to_dict() for l in self.links],
                "linked": len(self.linked), "broken": len(self.broken),
                "unlinked": len(self.unlinked),
                "signed_links": len(self.signed_links),
                "terminal_ref": self.terminal_ref,
                "establishes_truth": False,
                "notes": list(self.notes),
                "schema_version": ATTESTATION_SCHEMA_VERSION}


def chain_from_case(case: Any, *, approval: Any = None) -> AttestationChain:
    """Walk the custody links a case already holds.

    Reads the fields other modules record rather than asking anyone to restate
    them: `parent_evidence` for agent-to-tool derivation, `applies_to_digest` for
    what a record was produced against, `target_digest` on a verification attempt
    for what was actually checked, and the approval's own digests for the last
    hop. Nothing here requires a producer to adopt a new format.
    """
    links: List[CustodyLink] = []
    notes: List[str] = []

    evidence = list(case.collection("evidence").materialised)
    by_id = {getattr(r, "evidence_id", ""): r for r in evidence}
    digests = {getattr(r, "digest", "") for r in evidence if getattr(r, "digest", "")}
    artifacts = list(case.collection("artifacts").materialised)
    digests |= {getattr(a, "digest", "") for a in artifacts if getattr(a, "digest", "")}

    # agent event -> tool output: a record naming the record it came from.
    #
    # The asserted digest here is the parent's evidence id, which is not a
    # convenience: `evidence_id` is `short_id("ev", digest_object(identity()))`,
    # so it is derived from the record's own content. A parent whose content
    # changed would hash to a different id and this reference would dangle —
    # which makes an id link a content link, and makes a dangling one a real
    # break rather than a bookkeeping slip.
    for record in evidence:
        for parent_id in getattr(record, "parent_evidence", ()) or ():
            parent = by_id.get(parent_id)
            links.append(CustodyLink(
                from_ref=parent_id, to_ref=getattr(record, "evidence_id", ""),
                relation="derived_from",
                asserted_digest=parent_id,
                actual_digest=getattr(parent, "evidence_id", "") if parent else "",
                producer_id=getattr(getattr(record, "producer", None),
                                    "producer_id", "") or "",
                signature=_signature_of(record)))
        # Parents the producer named and this case does not hold. Kept by the
        # ingest precisely so they can be reported here.
        for missing in (getattr(record, "metadata", None) or {}).get(
                "unresolved_parent_evidence", ()) or ():
            links.append(CustodyLink(
                from_ref=str(missing), to_ref=getattr(record, "evidence_id", ""),
                relation="derived_from", asserted_digest=str(missing),
                actual_digest="",
                producer_id=getattr(getattr(record, "producer", None),
                                    "producer_id", "") or ""))
        applies = getattr(record, "applies_to_digest", "")
        if applies:
            links.append(CustodyLink(
                from_ref=applies[:23] + "…", to_ref=getattr(record, "evidence_id", ""),
                relation="applies_to", asserted_digest=applies,
                actual_digest=applies if applies in digests else "",
                producer_id=getattr(getattr(record, "producer", None),
                                    "producer_id", "") or "",
                signature=_signature_of(record)))

    # verifier result -> target: what the check actually ran against.
    try:
        from release_gate.assurance.verification import VerificationGraph
        attempts = tuple(VerificationGraph.from_case(case).attempts)
    except Exception:
        attempts = ()
    for attempt in attempts:
        target = getattr(attempt, "target", None)
        target_id = getattr(target, "target_id", "") if target else ""
        asserted = getattr(attempt, "target_digest", "") or ""
        links.append(CustodyLink(
            from_ref=target_id or "target",
            to_ref=getattr(attempt, "verification_id", "") or "verification",
            relation="verified_target", asserted_digest=asserted,
            actual_digest=asserted if asserted in digests else "",
            producer_id=str(getattr(attempt, "verifier", "") or ""),
            tool_identity=_tool_identity_of(attempt)))
    if attempts and not any(getattr(a, "target_digest", "") for a in attempts):
        notes.append(
            "no verification attempt names a target digest, so what each check "
            "ran against is UNDETERMINED rather than linked (Invariant 5)")

    # evidence pack -> approval: the last hop, and the one a human signs.
    if approval is not None:
        case_digest = getattr(case, "case_digest", "")
        asserted = getattr(approval, "case_digest", "") or ""
        links.append(CustodyLink(
            from_ref="case", to_ref=getattr(approval, "approval_id", "") or "approval",
            relation="approves", asserted_digest=asserted,
            actual_digest=case_digest if asserted == case_digest else "",
            producer_id=str(getattr(approval, "approver", "") or ""),
            signature=_approval_signature(approval)))

    terminal = (getattr(approval, "approval_id", "") or "") if approval is not None else ""
    return AttestationChain(links=tuple(links), terminal_ref=terminal,
                            notes=tuple(notes))


def _signature_of(record: Any) -> Optional[SignatureMetadata]:
    """Signature metadata a record carries, if it carries any.

    Read from the record's own provenance rather than invented: a record marked
    SIGNED names a signer, and one that does not gets no signature object rather
    than an empty one that would read as an unsigned signature.
    """
    provenance = getattr(getattr(record, "provenance_status", None), "value", "")
    if provenance not in ("SIGNED", "CHAIN_VERIFIED"):
        return None
    producer = getattr(record, "producer", None)
    signer = (getattr(producer, "attested_by", "")
              or getattr(producer, "producer_id", "") or "")
    if not signer:
        return None
    metadata = getattr(record, "metadata", None) or {}
    return SignatureMetadata(
        signer=str(signer), algorithm=str(metadata.get("signature_algorithm") or ""),
        key_id=str(metadata.get("key_id") or ""),
        signature_id=str(metadata.get("signature_id") or ""))


def _approval_signature(approval: Any) -> Optional[SignatureMetadata]:
    approver = str(getattr(approval, "approver", "") or "")
    if not approver:
        return None
    source = getattr(getattr(approval, "auth_source", None), "value", "")
    return SignatureMetadata(signer=approver, algorithm="", key_id="",
                             signature_id=str(getattr(approval, "approval_id", "")
                                              or ""), verified_by="")


def _tool_identity_of(attempt: Any) -> Dict[str, Any]:
    """The verifier binary, when the attempt carries one.

    `ToolIdentity` already models name, version, family and a binary digest, so
    a verifier that says which build produced a result gets that recorded in the
    chain. One that does not is simply a named verifier, which is weaker and is
    reported as what it is.
    """
    tool = getattr(attempt, "tool", None)
    if tool is None:
        verifier = str(getattr(attempt, "verifier", "") or "")
        return {"name": verifier} if verifier else {}
    return {"name": str(getattr(tool, "name", "") or ""),
            "version": str(getattr(tool, "version", "") or ""),
            "family": str(getattr(getattr(tool, "family", None), "value",
                                  getattr(tool, "family", "")) or ""),
            "digest": str(getattr(tool, "digest", "") or "")}
