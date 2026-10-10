"""Signed evidence: a document in a DSSE envelope, and what a verification found.

A producer identity a document carries is the document's claim. RG-PROV-001 says
so on every case, and until this module nothing a submission could do changed
it. A document can now arrive signed: inside a DSSE envelope, the format in-toto
attestations and Sigstore use, either as the evidence document itself or as an
in-toto Statement whose predicate is the document.

    {"payloadType": "application/vnd.release-gate.evidence+json",
     "payload": "<base64 of the document's bytes>",
     "signatures": [{"keyid": "acme-evals-ci", "sig": "<base64>"}]}

**This module verifies nothing.** The assurance layer imports no cryptography
(`attestation.py`, `identity.py`): it records what an authenticator established,
and a recorder that re-derived its inputs would be asserting what it was meant
to cite. Verification happens at the host boundary — `release_gate/crypto/
envelope.py`, run by the CLI against the keys an organisation names in
`--trusted-keys` — and arrives here as a `SignatureVerdict` keyed by the
envelope's digest. The ingest applies it:

* **VALID**, from a key trusted for the record's producer: the record is
  authenticated (`EvidenceRecord.authentication`). A key is trusted for named
  producers only, so a key an organisation gave its eval harness cannot vouch
  for a person's approval or for release-gate's own output.
* **INVALID**: the envelope is not read. Its contents are not evidence of
  anything but that someone presented them signed and they do not verify, and
  reading them would weigh a tampered payload as what it says. The refusal is a
  skipped record, so the case holds (RG-COV).
* **UNVERIFIABLE**, or no verdict at all: the document is read exactly as the
  same document unsigned would be — unauthenticated — and said so.

A verdict is never read from a submitted file. It is a parameter of the run, and
`EvidenceRecord.from_dict` drops an `authentication` a row carries, because a
document that could say it had been verified would have verified itself.

**A signature establishes who, never whether.** `SignatureMetadata.
establishes_correctness` stays `False`: an authenticated eval harness reporting
a pass has reported a pass, and authentication is about the report, not the
property.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from release_gate.assurance.attestation import SignatureMetadata, SignatureState
from release_gate.assurance.canonical import digest_object

__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "IN_TOTO_PAYLOAD_TYPE",
    "IN_TOTO_STATEMENT_TYPES",
    "SIGNED_EVIDENCE_SCHEMA_VERSION",
    "SignatureVerdict",
    "SignedEnvelopeError",
    "collect_signed_envelopes",
    "envelope_digest",
    "envelope_keyids",
    "inner_document",
    "is_signed_envelope",
    "pae",
    "payload_bytes",
    "producer_pattern_matches",
]

SIGNED_EVIDENCE_SCHEMA_VERSION = 1

#: The payload type release-gate signs with: the evidence document itself.
DSSE_PAYLOAD_TYPE = "application/vnd.release-gate.evidence+json"
#: An in-toto Statement, whose `predicate` is the evidence document.
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPES = frozenset({"https://in-toto.io/Statement/v1",
                                     "https://in-toto.io/Statement/v0.1"})

#: Bounds on what an envelope may carry before anything is decoded.
MAX_PAYLOAD_CHARS = 32 * 1024 * 1024
MAX_SIGNATURES = 16


class SignedEnvelopeError(ValueError):
    """An envelope whose payload cannot be read."""


def is_signed_envelope(doc: Any) -> bool:
    """A DSSE envelope by shape: a type, a payload, and at least one signature."""
    if not isinstance(doc, Mapping):
        return False
    signatures = doc.get("signatures")
    return (isinstance(doc.get("payloadType"), str) and bool(doc["payloadType"].strip())
            and isinstance(doc.get("payload"), str)
            and isinstance(signatures, list) and 0 < len(signatures) <= MAX_SIGNATURES
            and all(isinstance(s, Mapping) and isinstance(s.get("sig"), str)
                    and isinstance(s.get("keyid", ""), str) for s in signatures))


def envelope_digest(doc: Mapping[str, Any]) -> str:
    """The digest a verdict is keyed by: over the three DSSE fields and nothing else.

    A field added beside them (a comment, a transport annotation) does not change
    what was signed, so it does not change which verdict applies.
    """
    return digest_object({
        "payloadType": str(doc.get("payloadType") or ""),
        "payload": str(doc.get("payload") or ""),
        "signatures": [{"keyid": str(s.get("keyid") or ""), "sig": str(s.get("sig") or "")}
                       for s in (doc.get("signatures") or ()) if isinstance(s, Mapping)]})


def envelope_keyids(doc: Mapping[str, Any]) -> Tuple[str, ...]:
    return tuple(str(s.get("keyid") or "") for s in (doc.get("signatures") or ())
                 if isinstance(s, Mapping))


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE's pre-authentication encoding: what each signature is over."""
    kind = payload_type.encode("utf-8")
    return b" ".join([b"DSSEv1", str(len(kind)).encode(), kind,
                      str(len(payload)).encode(), payload])


def payload_bytes(doc: Mapping[str, Any]) -> bytes:
    """The payload, decoded strictly. Base64 that does not decode is refused."""
    text = str(doc.get("payload") or "")
    if len(text) > MAX_PAYLOAD_CHARS:
        raise SignedEnvelopeError("the payload is larger than release-gate reads")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignedEnvelopeError(f"the payload is not base64: {exc}") from exc


def _parse(raw: bytes) -> Any:
    """JSON, or JSONL for an envelope's rows, read as strictly as a file is."""
    from release_gate.adapters.common import _loads
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SignedEnvelopeError("the payload is not UTF-8 text") from exc
    try:
        return _loads(text, strict=True)
    except ValueError:
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) < 2:
            raise SignedEnvelopeError("the payload is neither JSON nor JSON lines")
        try:
            return [_loads(line, strict=True) for line in lines]
        except ValueError as exc:
            raise SignedEnvelopeError(f"the payload is neither JSON nor JSON lines: "
                                      f"{exc}") from exc


def inner_document(doc: Mapping[str, Any]) -> Tuple[Any, str]:
    """The evidence document an envelope carries, and a sentence saying what it was.

    An in-toto Statement is read through its `predicate`: the statement says what
    the predicate is about, and the predicate is the document release-gate reads.
    """
    if not is_signed_envelope(doc):
        raise SignedEnvelopeError("not a signed envelope")
    document = _parse(payload_bytes(doc))
    kind = str(doc.get("payloadType"))
    if kind == IN_TOTO_PAYLOAD_TYPE:
        if not isinstance(document, Mapping) or str(document.get("_type")) \
                not in IN_TOTO_STATEMENT_TYPES:
            raise SignedEnvelopeError("an in-toto payload that is not an in-toto Statement")
        if not isinstance(document.get("predicate"), (Mapping, list)):
            raise SignedEnvelopeError("an in-toto Statement with no predicate to read")
        subjects = document.get("subject") if isinstance(document.get("subject"),
                                                         list) else []
        return document["predicate"], (
            f"an in-toto Statement ({document.get('predicateType') or 'no predicateType'}) "
            f"about {len(subjects)} subject(s); its predicate was read")
    return document, f"a {kind} payload"


def producer_pattern_matches(pattern: str, producer_id: str) -> bool:
    """`acme-evals` names one producer; `release-gate/*` names a family. Nothing else."""
    pattern, producer_id = str(pattern or "").strip(), str(producer_id or "").strip()
    if not pattern or not producer_id:
        return False
    if pattern.endswith("*"):
        return producer_id.startswith(pattern[:-1])
    return producer_id == pattern


@dataclass(frozen=True)
class SignatureVerdict:
    """What the host boundary found when it checked one envelope's signatures.

    `producers` is what the organisation trusts the key to speak for, and
    `decided_by` is who decided that: a trust that nobody can be asked about is an
    assumption (`TrustDecision`).
    """

    envelope_digest: str
    state: SignatureState
    key_id: str = ""
    algorithm: str = ""
    producers: Tuple[str, ...] = ()
    decided_by: str = ""
    verified_by: str = ""
    detail: str = ""
    keyids: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", SignatureState(self.state))
        object.__setattr__(self, "producers", tuple(str(p) for p in self.producers))
        object.__setattr__(self, "keyids", tuple(str(k) for k in self.keyids))
        if self.state is SignatureState.VALID:
            missing = [name for name in ("key_id", "decided_by", "verified_by")
                       if not str(getattr(self, name) or "").strip()]
            if missing or not self.producers:
                raise SignedEnvelopeError(
                    "a VALID verdict names its key, the producers the key is trusted "
                    "for, who trusts it and who checked it; missing: "
                    + ", ".join(missing + ([] if self.producers else ["producers"])))

    def speaks_for(self, producer_id: str) -> bool:
        return self.state is SignatureState.VALID and any(
            producer_pattern_matches(p, producer_id) for p in self.producers)

    def signature(self) -> SignatureMetadata:
        """The record of it each authenticated evidence record carries."""
        return SignatureMetadata(
            signer=f"key {self.key_id}, trusted by {self.decided_by} for "
                   f"{', '.join(self.producers)}",
            algorithm=self.algorithm, key_id=self.key_id,
            signature_id=self.envelope_digest, state=self.state,
            verified_by=self.verified_by)

    def to_dict(self) -> Dict[str, Any]:
        return {"envelope_digest": self.envelope_digest, "state": self.state.value,
                "key_id": self.key_id, "algorithm": self.algorithm,
                "producers": list(self.producers), "decided_by": self.decided_by,
                "verified_by": self.verified_by, "detail": self.detail,
                "keyids": list(self.keyids)}


def collect_signed_envelopes(primary: str | Path, evidence: Sequence[str | Path] = ()
                             ) -> List[Mapping[str, Any]]:
    """Every envelope a run will read: whole files, and `signed_export` rows in envelopes.

    What the host boundary verifies, so that each one the ingest meets has a
    verdict. Read with the same reader and the same file expansion the ingest uses.
    """
    from release_gate.assurance.ingest import _evidence_files, load_input
    primary = Path(primary)
    found: List[Mapping[str, Any]] = []
    for path in [primary] + _evidence_files(evidence, primary):
        doc = load_input(path)
        if is_signed_envelope(doc):
            found.append(doc)
        elif isinstance(doc, list):
            found.extend(row["envelope"] for row in doc
                         if isinstance(row, Mapping)
                         and row.get("record_type") == "signed_export"
                         and is_signed_envelope(row.get("envelope")))
    return found
