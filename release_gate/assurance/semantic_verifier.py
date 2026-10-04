"""The semantic verifier — a model reads what structure cannot, and decides nothing.

Some questions an admission decision turns on are reading problems. A claim says
*transfers above the threshold require human authorization*; three records say
they support it; whether what those records actually contain bears on that
sentence is not something a digest comparison can settle. The deterministic
engine knows it cannot settle it: the claim resolves short of ESTABLISHED on
support that is declared rather than checked (resolution.py). This module asks a
model that one question, about that one claim, over only the records that bear
on it, and turns the answer into a bounded assertion the deterministic policy
then reads.

    deterministic analysis
          ↓  unresolved_questions()       — claims the rules could not settle
    SemanticQuestion
          ↓  build_evidence_packet()      — only the records that bear on it,
    EvidencePacket                           minimised, bounded, hashed
          ↓  SemanticVerifier.verify()    — any provider, behind one interface
    SemanticAssertion                     — supported | contradicted |
          ↓  assertions_to_records()        insufficient_evidence, or UNKNOWN
    AssuranceCase
          ↓  resolution.py / analysis.py  — the same deterministic policy
    PROMOTE / HOLD / BLOCK

**It never returns a verdict.** A `SemanticAssertion` has three possible answers
and none of them is PROMOTE, HOLD or BLOCK. A model that replies with an
admission word, or with anything outside the three, has replied malformed, and a
malformed reply is UNKNOWN. `makes_admission_decision` is unconditionally False.
What an assertion does to a case is decided by the declared resolution policy
(`ResolutionPolicy.semantic_support`, `semantic_contradiction`), deterministically,
from what was persisted.

**Every failure is UNKNOWN, and UNKNOWN moves nothing.** No provider, provider
unavailable, timeout, a reply that is not one JSON object, a verdict outside the
three, a confidence outside 0..1, a citation of a record the packet did not
contain, an answer to a different question — each is an UNKNOWN assertion naming
the reason. The resolver sets UNKNOWN aside without counting it, so a failed
call leaves a claim exactly where the deterministic rules left it. Nothing here
converts a failure into support.

**Confidence can only withhold.** `semantic.py` records a model's confidence and
reads nothing from it, because a mechanism that *acts* above 0.9 has made a
model's self-assessment authoritative. This module reads it in one direction
only: an answer below the policy's `min_confidence` becomes UNKNOWN
(`LOW_CONFIDENCE`), or asks for more verification when the policy says so. A
high confidence promotes nothing; the answer's standing comes from the policy,
never from the model's opinion of itself.

**Data minimisation is the packet.** A packet holds the claim, the question and
the records the deterministic analysis named as bearing on that claim — never a
repository, never the rest of the case. Each record is reduced to a fixed set of
fields, secrets and identifiers are replaced by digests (`privacy.py`), every
excerpt is bounded, and a packet over the policy's size is refused rather than
sent. What was sent is exactly what was hashed: `packet_hash` and `prompt_hash`
commit to it.

**Provider-neutral by construction.** `SemanticProvider` is a two-method
protocol — say who you are, complete one request — and a `ProviderRegistry` holds
named factories. This package never opens a socket (the hostile suite asserts
it), so the network transports live in `release_gate/semantic_providers.py`,
which speaks any wire format `model_neutral.py` describes, hosted or local. A
provider this build does not ship — a future Jev, Laya, or release-gate
specialist model — is a class implementing the protocol, registered by name.
Nothing in the verifier, the packet or the policy names a vendor, and the
provider-free guard in the test suite reads this file to keep it that way.

**Persisted for reproducibility, not for trust.** Every assertion records the
provider, model, the model version the provider reported, the prompt hash, the
packet hash, the candidate state hash, the raw response (bounded) and its digest,
the time, and the verifier policy. The model's answer may differ run to run; the
case built from a persisted assertion does not, because the policy that reads it
is deterministic and reads only what was stored.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol,
                    Sequence, Tuple, runtime_checkable)

from release_gate.assurance.canonical import canonical_json, digest_bytes, digest_object, short_id
from release_gate.assurance.privacy import (DataClass, Disposition, RedactionPolicy,
                                            minimise)

__all__ = [
    "SEMANTIC_PROMPT_VERSION",
    "SEMANTIC_VERIFIER_SCHEMA_VERSION",
    "AssertionStatus",
    "DEFAULT_SEMANTIC_VERIFIER_POLICY",
    "EvidencePacket",
    "LowConfidenceAction",
    "PacketItem",
    "ProviderIdentity",
    "ProviderRegistry",
    "ProviderReply",
    "ProviderRequest",
    "ProviderTimeout",
    "ProviderUnavailable",
    "QuestionKind",
    "SemanticAssertion",
    "SemanticProvider",
    "SemanticQuestion",
    "SemanticVerdict",
    "SemanticVerifier",
    "SemanticVerifierError",
    "SemanticVerifierPolicy",
    "UnknownReason",
    "assertions_from_records",
    "assertions_to_records",
    "build_evidence_packet",
    "state_hash_for",
    "unresolved_questions",
]

SEMANTIC_VERIFIER_SCHEMA_VERSION = 1

#: Versions the instruction text. Part of every prompt hash, so a changed
#: instruction is a different prompt even when the packet is the same.
SEMANTIC_PROMPT_VERSION = "rg-semantic-prompt-1"


class SemanticVerifierError(ValueError):
    """Something was described in a way the verifier could not use."""


class ProviderUnavailable(RuntimeError):
    """The provider could not be reached or refused the request."""


class ProviderTimeout(ProviderUnavailable):
    """The provider did not answer within the policy's timeout."""


# ── vocabulary ───────────────────────────────────────────────────────────────

class SemanticVerdict(str, Enum):
    """The three things a model may say about a claim and its packet. No fourth."""

    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class AssertionStatus(str, Enum):
    ANSWERED = "ANSWERED"   # a well-formed answer within the policy's bounds
    UNKNOWN = "UNKNOWN"     # anything else, with the reason named


class UnknownReason(str, Enum):
    NO_PROVIDER = "NO_PROVIDER"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    MISMATCHED_QUESTION = "MISMATCHED_QUESTION"
    OUT_OF_PACKET_REFERENCE = "OUT_OF_PACKET_REFERENCE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    EMPTY_PACKET = "EMPTY_PACKET"
    PACKET_TOO_LARGE = "PACKET_TOO_LARGE"


class LowConfidenceAction(str, Enum):
    """What a below-threshold answer becomes. Both are UNKNOWN; one also asks for more."""

    UNKNOWN = "UNKNOWN"
    REQUIRE_VERIFICATION = "REQUIRE_VERIFICATION"


class QuestionKind(str, Enum):
    #: Does what these records contain bear on, and support, this claim?
    EVIDENCE_SUPPORTS_CLAIM = "EVIDENCE_SUPPORTS_CLAIM"


# ── policy ───────────────────────────────────────────────────────────────────

_WITHHELD_BY_DEFAULT = (DataClass.SECRET, DataClass.IDENTIFIER)


@dataclass(frozen=True)
class SemanticVerifierPolicy:
    """How a question becomes a packet and an answer becomes an assertion.

    What an assertion then *does* to a case is not here: that is the resolution
    policy's, read deterministically. This policy only bounds what is sent and
    what is accepted back.
    """

    policy_id: str = "rg-semantic"
    version: str = "1"
    #: An answer below this becomes UNKNOWN. It never raises anything above it.
    min_confidence: float = 0.75
    low_confidence: LowConfidenceAction = LowConfidenceAction.UNKNOWN
    max_items: int = 12
    max_excerpt_chars: int = 1200
    max_packet_chars: int = 16000
    #: Data classes replaced by a digest before a packet is built.
    withhold: Tuple[DataClass, ...] = _WITHHELD_BY_DEFAULT
    max_tokens: int = 400
    timeout_seconds: float = 60.0
    max_reason_chars: int = 400
    max_response_chars: int = 4000

    def __post_init__(self) -> None:
        object.__setattr__(self, "low_confidence", LowConfidenceAction(self.low_confidence))
        object.__setattr__(self, "withhold", tuple(sorted(
            {DataClass(c) for c in self.withhold}, key=lambda c: c.value)))
        try:
            confidence = float(self.min_confidence)
        except (TypeError, ValueError) as exc:
            raise SemanticVerifierError("min_confidence must be a number") from exc
        if isinstance(self.min_confidence, bool) or not 0.0 <= confidence <= 1.0:
            raise SemanticVerifierError("min_confidence must be within 0..1")
        object.__setattr__(self, "min_confidence", confidence)
        for name in ("max_items", "max_excerpt_chars", "max_packet_chars", "max_tokens",
                     "max_reason_chars", "max_response_chars"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SemanticVerifierError(f"{name} must be a positive integer")
        if not float(self.timeout_seconds) > 0:
            raise SemanticVerifierError("timeout_seconds must be positive")
        if DataClass.SECRET not in self.withhold:
            raise SemanticVerifierError(
                "a packet always withholds SECRET: no question about a claim needs a "
                "credential, and a policy that sent one would be sending it to a "
                "third party for nothing")

    @property
    def ref(self) -> str:
        return f"{self.policy_id}@{self.version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id, "version": self.version,
                "min_confidence": self.min_confidence,
                "low_confidence": self.low_confidence.value,
                "max_items": self.max_items, "max_excerpt_chars": self.max_excerpt_chars,
                "max_packet_chars": self.max_packet_chars,
                "withhold": [c.value for c in self.withhold],
                "max_tokens": self.max_tokens, "timeout_seconds": self.timeout_seconds,
                "max_reason_chars": self.max_reason_chars,
                "max_response_chars": self.max_response_chars,
                "prompt_version": SEMANTIC_PROMPT_VERSION,
                "schema_version": SEMANTIC_VERIFIER_SCHEMA_VERSION}

    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SemanticVerifierPolicy":
        if not isinstance(data, Mapping):
            raise SemanticVerifierError("a semantic verifier policy is a JSON object")
        default = DEFAULT_SEMANTIC_VERIFIER_POLICY
        try:
            return cls(**{f: data.get(f, getattr(default, f)) for f in (
                "policy_id", "version", "min_confidence", "low_confidence", "max_items",
                "max_excerpt_chars", "max_packet_chars", "withhold", "max_tokens",
                "timeout_seconds", "max_reason_chars", "max_response_chars")})
        except (TypeError, ValueError) as exc:
            if isinstance(exc, SemanticVerifierError):
                raise
            raise SemanticVerifierError(f"unusable semantic verifier policy: {exc}") from exc


DEFAULT_SEMANTIC_VERIFIER_POLICY = SemanticVerifierPolicy()


# ── the question ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SemanticQuestion:
    """One reading question about one claim, and why structure could not answer it."""

    claim_id: str
    statement: str
    evidence_refs: Tuple[str, ...]
    unresolved_because: str = ""
    kind: QuestionKind = QuestionKind.EVIDENCE_SUPPORTS_CLAIM
    question_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", QuestionKind(self.kind))
        object.__setattr__(self, "evidence_refs",
                           tuple(dict.fromkeys(str(r) for r in self.evidence_refs if r)))
        if not str(self.claim_id or "").strip():
            raise SemanticVerifierError("a question must name the claim it is about")
        object.__setattr__(self, "question_id", short_id("sq", digest_object(
            {"kind": self.kind.value, "claim_id": self.claim_id,
             "statement": self.statement, "evidence_refs": list(self.evidence_refs)})))

    @property
    def text(self) -> str:
        return ("Do the records in this packet, read as they are, support the claim, "
                "contradict it, or leave it unsettled?")

    def to_dict(self) -> Dict[str, Any]:
        return {"question_id": self.question_id, "kind": self.kind.value,
                "claim_id": self.claim_id, "statement": self.statement,
                "question": self.text, "evidence_refs": list(self.evidence_refs),
                "unresolved_because": self.unresolved_because}


#: Statuses the deterministic rules leave open to a reading. ESTABLISHED and
#: CONTRADICTED are settled; NOT_ASSESSED has nothing to read; UNSUPPORTED has
#: nothing that counts, and re-reading what was set aside (another state of the
#: release, an inadmissible method) would be asking a model to overrule a rule.
_OPEN_TO_READING = frozenset({"SUPPORTED", "PARTIALLY_SUPPORTED", "UNKNOWN"})
_READABLE_ROLES = frozenset({"SUPPORTS", "INCONCLUSIVE"})


def unresolved_questions(report: Any, *, establishing: Iterable[str] = ("PROOF",
                         "MECHANICAL", "EMPIRICAL")) -> List[SemanticQuestion]:
    """The claims the deterministic resolution left to a reading, one question each.

    A claim qualifies when it is open (`_OPEN_TO_READING`) and something that
    bears on it is readable but unchecked: support that is a declaration, an
    observation or a judgement rather than a mechanical, empirical or proof
    check, or a check that reached no conclusion. A claim already carried by
    checks of the `establishing` kinds is left alone — there is nothing for a
    reading to add.
    """
    if report is None:
        return []
    checked = {str(s).upper() for s in establishing}
    questions: List[SemanticQuestion] = []
    for resolution in report.resolutions:
        if resolution.status.value not in _OPEN_TO_READING:
            continue
        items = [i for i in resolution.items if i.role.value in _READABLE_ROLES]
        unchecked = [i for i in items if i.role.value == "INCONCLUSIVE"
                     or (i.strength is not None and i.strength.value not in checked)]
        if not unchecked:
            continue
        questions.append(SemanticQuestion(
            claim_id=resolution.claim_id, statement=resolution.statement,
            evidence_refs=tuple(i.item_id for i in items),
            unresolved_because=f"{resolution.status.value} ({resolution.rule}): "
                               f"{resolution.basis}"))
    return questions


def state_hash_for(analysis: Any) -> str:
    """The candidate an assertion binds to: the stated one, or none.

    A candidate implied by the case's own artifacts includes the input file, and
    a persisted assertion replayed inside that file changes it — so binding to an
    implied candidate would make every replay read as stale. That is the rule
    `candidate.py` already keeps: unbound is not a finding when nobody stated
    what it should be bound to.
    """
    binding = getattr(analysis, "state_binding", None)
    if binding is None or not binding.candidate.explicit:
        return ""
    return binding.candidate.digest()


# ── the packet ───────────────────────────────────────────────────────────────

#: The fields of a record a reader needs, and nothing else. A record's whole
#: serialisation carries ids, digests and bookkeeping a model cannot use and a
#: privacy review would have to clear.
_EVIDENCE_FIELDS = ("evidence_type", "coverage_note", "coverage_status",
                    "epistemic_status")
_ATTEMPT_FIELDS = ("method", "method_label", "status", "detail", "verifier")


@dataclass(frozen=True)
class PacketItem:
    ref: str
    kind: str                      # "evidence" | "verification"
    fields: Mapping[str, Any]
    excerpt: str = ""
    truncated: bool = False
    content_digest: str = ""       # of the excerpt before truncation

    def to_dict(self) -> Dict[str, Any]:
        return {"ref": self.ref, "kind": self.kind, "fields": dict(self.fields),
                "excerpt": self.excerpt, "truncated": self.truncated,
                "content_digest": self.content_digest}


@dataclass(frozen=True)
class EvidencePacket:
    """Exactly what one question sends. Hashed, so what was sent is checkable."""

    question: SemanticQuestion
    items: Tuple[PacketItem, ...] = ()
    state_hash: str = ""
    policy_ref: str = ""
    #: Refs the question named that were not sent, and why.
    omitted: Tuple[Tuple[str, str], ...] = ()
    #: What minimisation replaced, by class: {"class", "occurrences", "digest"}.
    redactions: Tuple[Mapping[str, Any], ...] = ()
    over_budget: bool = False
    packet_hash: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "packet_hash", digest_object(self.payload()))

    @property
    def refs(self) -> Tuple[str, ...]:
        return tuple(i.ref for i in self.items)

    def payload(self) -> Dict[str, Any]:
        """The part a model reads. The packet hash is over this, and only this."""
        return {"question": self.question.to_dict(),
                "items": [i.to_dict() for i in self.items],
                "state_hash": self.state_hash}

    def size(self) -> int:
        return len(canonical_json(self.payload()))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "evidence_packet", "packet_hash": self.packet_hash,
                **self.payload(), "policy": self.policy_ref,
                "omitted": [{"ref": r, "why": w} for r, w in self.omitted],
                "redactions": [dict(r) for r in self.redactions],
                "over_budget": self.over_budget, "size": self.size()}


def _minimisation_policy(policy: SemanticVerifierPolicy) -> RedactionPolicy:
    return RedactionPolicy(
        policy_id=f"{policy.policy_id}-packet", declared_by="release-gate",
        basis="a semantic question needs what a record says, never a credential "
              "or a person's identifier",
        dispositions={c: Disposition.DIGESTED for c in policy.withhold})


def _bounded(text: str, limit: int) -> Tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f" [truncated {len(text) - limit} chars]", True


def build_evidence_packet(question: SemanticQuestion, *, records: Mapping[str, Any],
                 attempts: Optional[Mapping[str, Any]] = None, state_hash: str = "",
                 policy: SemanticVerifierPolicy = DEFAULT_SEMANTIC_VERIFIER_POLICY
                 ) -> EvidencePacket:
    """The question and the records it names, minimised and bounded. Nothing else.

    `records` and `attempts` are lookups by id; only the ids the question names
    are read from them, so passing a whole case's records sends none of the rest.
    """
    attempts = attempts or {}
    redaction = _minimisation_policy(policy)
    items: List[PacketItem] = []
    omitted: List[Tuple[str, str]] = []
    found: Dict[str, Dict[str, Any]] = {}
    for ref in question.evidence_refs:
        if len(items) >= policy.max_items:
            omitted.append((ref, f"over the policy's {policy.max_items} items"))
            continue
        record = records.get(ref)
        attempt = attempts.get(ref)
        if record is not None:
            kind = "evidence"
            payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
            fields = {k: payload.get(k) for k in _EVIDENCE_FIELDS
                      if payload.get(k) not in (None, "")}
            fields["producer"] = (payload.get("producer") or {}).get("producer_id")
            body = payload.get("content") or {}
        elif attempt is not None:
            kind = "verification"
            payload = attempt.to_dict() if hasattr(attempt, "to_dict") else dict(attempt)
            fields = {k: payload.get(k) for k in _ATTEMPT_FIELDS
                      if payload.get(k) not in (None, "")}
            body = payload.get("result") or {}
        else:
            omitted.append((ref, "not held by this case"))
            continue
        sent, record_of = minimise({"fields": fields, "content": body}, redaction)
        for redacted in record_of.redactions:
            slot = found.setdefault(redacted.data_class.value,
                                    {"class": redacted.data_class.value,
                                     "occurrences": 0, "digests": []})
            slot["occurrences"] += redacted.occurrences
            slot["digests"].append(redacted.content_digest)
        text = canonical_json(sent["content"]) if sent["content"] else ""
        excerpt, truncated = _bounded(text, policy.max_excerpt_chars)
        items.append(PacketItem(
            ref=ref, kind=kind, fields=sent["fields"], excerpt=excerpt,
            truncated=truncated,
            content_digest=digest_bytes(text.encode("utf-8")) if text else ""))
    redactions = tuple({"class": s["class"], "occurrences": s["occurrences"],
                        "digest": digest_object(sorted(s["digests"]))}
                       for _, s in sorted(found.items()))
    packet = EvidencePacket(question=question, items=tuple(items), state_hash=state_hash,
                            policy_ref=policy.ref, omitted=tuple(omitted),
                            redactions=redactions)
    if packet.size() > policy.max_packet_chars:
        import dataclasses
        packet = dataclasses.replace(packet, over_budget=True)
    return packet


# ── providers ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProviderIdentity:
    """Who answered. As the provider states it; release-gate did not watch it run."""

    provider: str
    model: str
    model_family: str = ""
    endpoint: str = ""             # never carries a credential
    local: bool = False
    dialect: str = ""
    dialect_recognised: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "model": self.model,
                "model_family": self.model_family, "endpoint": self.endpoint,
                "local": self.local, "dialect": self.dialect,
                "dialect_recognised": self.dialect_recognised}


@dataclass(frozen=True)
class ProviderRequest:
    system: str
    user: str
    max_tokens: int
    timeout_seconds: float
    temperature: float = 0.0


@dataclass(frozen=True)
class ProviderReply:
    text: str
    #: The model the provider says served the request (most chat-completion APIs
    #: return it as `model`); empty when the provider does not say.
    model_version: str = ""


@runtime_checkable
class SemanticProvider(Protocol):
    """Anything that can answer one request. Two methods; no vendor in sight."""

    def identity(self) -> ProviderIdentity: ...

    def complete(self, request: ProviderRequest) -> ProviderReply: ...


class ProviderRegistry:
    """Named provider factories. Registration extends and never overrides."""

    def __init__(self) -> None:
        self._factories: Dict[str, Callable[..., SemanticProvider]] = {}

    def register(self, name: str, factory: Callable[..., SemanticProvider]) -> None:
        key = str(name or "").strip().lower()
        if not key:
            raise SemanticVerifierError("a provider must be registered under a name")
        if key in self._factories:
            raise SemanticVerifierError(
                f"a provider named {key!r} is already registered; a second one would "
                "decide by registration order which model answers")
        self._factories[key] = factory

    def names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._factories))

    def create(self, name: str, **config: Any) -> SemanticProvider:
        key = str(name or "").strip().lower()
        if key not in self._factories:
            raise SemanticVerifierError(
                f"no provider named {key!r}; registered: {', '.join(self.names()) or 'none'}")
        provider = self._factories[key](**config)
        if not isinstance(provider, SemanticProvider):
            raise SemanticVerifierError(
                f"{key!r} built something without identity() and complete()")
        return provider


# ── the assertion ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SemanticAssertion:
    """A bounded answer about one claim, and everything needed to check it later."""

    question_id: str
    claim_id: str
    status: AssertionStatus
    verdict: Optional[SemanticVerdict] = None
    unknown_reason: Optional[UnknownReason] = None
    requires_verification: bool = False
    confidence: Optional[float] = None
    evidence_refs: Tuple[str, ...] = ()
    reason: str = ""
    #: The verdict word the model returned, verbatim and bounded, even when it
    #: was refused — so a reviewer can see what was rejected.
    returned_verdict: str = ""
    provider: str = ""
    model: str = ""
    model_version: str = ""
    model_family: str = ""
    prompt_hash: str = ""
    packet_hash: str = ""
    state_hash: str = ""
    policy_ref: str = ""
    response: str = ""
    response_digest: str = ""
    timestamp: str = ""
    detail: str = ""
    schema_version: int = SEMANTIC_VERIFIER_SCHEMA_VERSION
    assertion_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", AssertionStatus(self.status))
        if self.verdict is not None:
            object.__setattr__(self, "verdict", SemanticVerdict(self.verdict))
        if self.unknown_reason is not None:
            object.__setattr__(self, "unknown_reason", UnknownReason(self.unknown_reason))
        object.__setattr__(self, "evidence_refs", tuple(str(r) for r in self.evidence_refs))
        if self.status is AssertionStatus.ANSWERED and (
                self.verdict is None or self.unknown_reason is not None):
            raise SemanticVerifierError("an ANSWERED assertion carries a verdict and no "
                                        "unknown reason")
        if self.status is AssertionStatus.UNKNOWN and self.unknown_reason is None:
            raise SemanticVerifierError("an UNKNOWN assertion must say why")
        if self.status is AssertionStatus.UNKNOWN and self.verdict is not None:
            raise SemanticVerifierError(
                "an UNKNOWN assertion has no verdict; what the model said stays in "
                "returned_verdict, where nothing reads it as an answer")
        if self.confidence is not None:
            value = float(self.confidence)
            if not 0.0 <= value <= 1.0:
                raise SemanticVerifierError("confidence must be within 0..1")
            object.__setattr__(self, "confidence", value)
        if not str(self.claim_id or "").strip():
            raise SemanticVerifierError("an assertion must name its claim")
        object.__setattr__(self, "assertion_id",
                           short_id("sa", digest_object(self.identity())))

    # ── refusals, as properties ──────────────────────────────────────────────
    @property
    def makes_admission_decision(self) -> bool:
        """Unconditionally False. PROMOTE, HOLD and BLOCK are the policy's."""
        return False

    @property
    def establishes(self) -> bool:
        """Unconditionally False. A reading is never proof of what it read."""
        return False

    @property
    def answered(self) -> bool:
        return self.status is AssertionStatus.ANSWERED

    def identity(self) -> Dict[str, Any]:
        """Everything but the time it was made, which is a fact about the run."""
        return {k: v for k, v in self._fields().items() if k != "timestamp"}

    def _fields(self) -> Dict[str, Any]:
        return {"schema_version": self.schema_version, "question_id": self.question_id,
                "claim_id": self.claim_id, "status": self.status.value,
                "verdict": self.verdict.value if self.verdict else None,
                "unknown_reason": (self.unknown_reason.value
                                   if self.unknown_reason else None),
                "requires_verification": self.requires_verification,
                "confidence": self.confidence, "evidence_refs": list(self.evidence_refs),
                "reason": self.reason, "returned_verdict": self.returned_verdict,
                "provider": self.provider, "model": self.model,
                "model_version": self.model_version, "model_family": self.model_family,
                "prompt_hash": self.prompt_hash, "packet_hash": self.packet_hash,
                "state_hash": self.state_hash, "policy": self.policy_ref,
                "response": self.response, "response_digest": self.response_digest,
                "timestamp": self.timestamp, "detail": self.detail}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "semantic_assertion", "assertion_id": self.assertion_id,
                **self._fields(), "makes_admission_decision": False,
                "establishes": False}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SemanticAssertion":
        """Read a persisted assertion. Strict: a malformed one is refused, not repaired."""
        if not isinstance(data, Mapping):
            raise SemanticVerifierError("a semantic assertion is a JSON object")
        try:
            return cls(
                question_id=str(data.get("question_id") or ""),
                claim_id=str(data.get("claim_id") or ""),
                status=AssertionStatus(str(data.get("status") or "")),
                verdict=(SemanticVerdict(str(data["verdict"]))
                         if data.get("verdict") else None),
                unknown_reason=(UnknownReason(str(data["unknown_reason"]))
                                if data.get("unknown_reason") else None),
                requires_verification=bool(data.get("requires_verification")),
                confidence=(None if data.get("confidence") is None
                            else _number(data["confidence"])),
                evidence_refs=tuple(str(r) for r in (data.get("evidence_refs") or ())),
                reason=str(data.get("reason") or ""),
                returned_verdict=str(data.get("returned_verdict") or ""),
                provider=str(data.get("provider") or ""),
                model=str(data.get("model") or ""),
                model_version=str(data.get("model_version") or ""),
                model_family=str(data.get("model_family") or ""),
                prompt_hash=str(data.get("prompt_hash") or ""),
                packet_hash=str(data.get("packet_hash") or ""),
                state_hash=str(data.get("state_hash") or ""),
                policy_ref=str(data.get("policy") or data.get("policy_ref") or ""),
                response=str(data.get("response") or ""),
                response_digest=str(data.get("response_digest") or ""),
                timestamp=str(data.get("timestamp") or ""),
                detail=str(data.get("detail") or ""))
        except (TypeError, ValueError) as exc:
            if isinstance(exc, SemanticVerifierError):
                raise
            raise SemanticVerifierError(f"unreadable semantic assertion: {exc}") from exc


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SemanticVerifierError(f"{value!r} is not a number")
    return float(value)


# ── the verifier ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You check whether evidence records support a single claim. You are given one "
    "claim and a packet of records, as JSON. Read only the packet. Do not use "
    "outside knowledge, and do not assume anything a record does not say.\n\n"
    "Answer with one verdict:\n"
    "- supported: the records, as written, show the claim holds for what they "
    "cover.\n"
    "- contradicted: a record shows the claim does not hold.\n"
    "- insufficient_evidence: the records do not settle it either way.\n\n"
    "You do not decide whether anything is released, approved or blocked. Do not "
    "answer with any word but those three.\n\n"
    "Cite the refs of the records your verdict rests on; cite only refs that "
    "appear in the packet. Give a confidence between 0 and 1.\n\n"
    "Reply with one JSON object and nothing else:\n"
    '{"question_id": "<as given>", "claim_id": "<as given>", '
    '"verdict": "supported" | "contradicted" | "insufficient_evidence", '
    '"confidence": <0..1>, "evidence_refs": ["<ref>", ...], '
    '"reason": "<one or two sentences>"}'
)

_FENCED = re.compile(r"\A```(?:json)?\s*(?P<body>\{.*\})\s*```\Z", re.DOTALL)


def _parse_reply(text: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """One JSON object, or a single fenced one. Anything else is malformed."""
    stripped = (text or "").strip()
    fenced = _FENCED.match(stripped)
    body = fenced.group("body") if fenced else stripped
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError) as exc:
        return None, f"the reply is not one JSON object ({type(exc).__name__})"
    if not isinstance(parsed, dict):
        return None, f"the reply is JSON {type(parsed).__name__}, not an object"
    return parsed, ""


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SemanticVerifier:
    """Ask one provider one question per packet. Every failure is UNKNOWN."""

    def __init__(self, provider: Optional[SemanticProvider], *,
                 policy: SemanticVerifierPolicy = DEFAULT_SEMANTIC_VERIFIER_POLICY,
                 clock: Callable[[], str] = _utc_now) -> None:
        self.provider = provider
        self.policy = policy
        self.clock = clock

    def request_for(self, packet: EvidencePacket) -> ProviderRequest:
        return ProviderRequest(
            system=f"[{SEMANTIC_PROMPT_VERSION}]\n{_SYSTEM_PROMPT}",
            user=canonical_json(packet.payload()),
            max_tokens=self.policy.max_tokens,
            timeout_seconds=float(self.policy.timeout_seconds))

    def prompt_hash(self, request: ProviderRequest, model: str) -> str:
        return digest_object({"system": request.system, "user": request.user,
                              "model": model, "temperature": request.temperature,
                              "max_tokens": request.max_tokens})

    def verify(self, packet: EvidencePacket) -> SemanticAssertion:
        question = packet.question
        base: Dict[str, Any] = {
            "question_id": question.question_id, "claim_id": question.claim_id,
            "packet_hash": packet.packet_hash, "state_hash": packet.state_hash,
            "policy_ref": self.policy.ref, "timestamp": self.clock()}

        def unknown(why: UnknownReason, explained: str, **extra: Any) -> SemanticAssertion:
            return SemanticAssertion(status=AssertionStatus.UNKNOWN, unknown_reason=why,
                                     detail=explained[:400], **{**base, **extra})

        if self.provider is None:
            return unknown(UnknownReason.NO_PROVIDER,
                           "no provider is configured, so the question was not asked")
        if not packet.items:
            return unknown(UnknownReason.EMPTY_PACKET,
                           "nothing the question names is held by this case, so "
                           "there was nothing to read")
        if packet.over_budget:
            return unknown(UnknownReason.PACKET_TOO_LARGE,
                           f"the packet is {packet.size()} characters and the policy "
                           f"allows {self.policy.max_packet_chars}; it was not sent")
        try:
            identity = self.provider.identity()
        except Exception as exc:  # a provider that cannot say who it is is unavailable
            return unknown(UnknownReason.PROVIDER_UNAVAILABLE,
                           f"the provider could not identify itself: {type(exc).__name__}")
        request = self.request_for(packet)
        who = {"provider": identity.provider, "model": identity.model,
               "model_family": identity.model_family,
               "prompt_hash": self.prompt_hash(request, identity.model)}
        try:
            reply = self.provider.complete(request)
        except ProviderTimeout as exc:
            return unknown(UnknownReason.TIMEOUT,
                           f"no answer within {self.policy.timeout_seconds}s: {exc}", **who)
        except Exception as exc:  # unreachable, refused, crashed — all the same here
            return unknown(UnknownReason.PROVIDER_UNAVAILABLE,
                           f"{type(exc).__name__}: {exc}", **who)

        text = reply.text if isinstance(reply, ProviderReply) else ""
        stored, _ = _bounded_text(text, self.policy.max_response_chars)
        who.update(model_version=getattr(reply, "model_version", "") or "",
                   response=stored,
                   response_digest=digest_bytes((text or "").encode("utf-8")))
        parsed, problem = _parse_reply(text)
        if parsed is None:
            return unknown(UnknownReason.MALFORMED_RESPONSE, problem, **who)

        returned = str(parsed.get("verdict", ""))[:60]
        who["returned_verdict"] = returned
        if (str(parsed.get("question_id", "")) != question.question_id
                or str(parsed.get("claim_id", "")) != question.claim_id):
            return unknown(UnknownReason.MISMATCHED_QUESTION,
                           "the reply names a different question or claim than the "
                           "one asked", **who)
        try:
            verdict = SemanticVerdict(returned.strip().lower())
        except ValueError:
            return unknown(UnknownReason.MALFORMED_RESPONSE,
                           f"verdict {returned!r} is not supported, contradicted or "
                           "insufficient_evidence", **who)
        try:
            confidence = _number(parsed.get("confidence"))
        except SemanticVerifierError:
            return unknown(UnknownReason.MALFORMED_RESPONSE,
                           "confidence is missing or not a number", **who)
        if not 0.0 <= confidence <= 1.0:
            return unknown(UnknownReason.MALFORMED_RESPONSE,
                           f"confidence {confidence} is outside 0..1", **who)
        refs = parsed.get("evidence_refs")
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            return unknown(UnknownReason.MALFORMED_RESPONSE,
                           "evidence_refs is not a list of refs", **who)
        outside = [r for r in refs if r not in packet.refs]
        if outside:
            return unknown(UnknownReason.OUT_OF_PACKET_REFERENCE,
                           f"the reply cites {', '.join(outside[:3])}, which the packet "
                           "did not contain", **who, confidence=confidence)
        if verdict is not SemanticVerdict.INSUFFICIENT_EVIDENCE and not refs:
            return unknown(UnknownReason.MALFORMED_RESPONSE,
                           f"a {verdict.value} verdict cites no record, so nothing "
                           "under it can be checked", **who, confidence=confidence)
        reason, _ = _bounded_text(str(parsed.get("reason") or ""),
                                  self.policy.max_reason_chars)
        if confidence < self.policy.min_confidence:
            return unknown(
                UnknownReason.LOW_CONFIDENCE,
                f"the model reported {confidence} and the policy needs "
                f"{self.policy.min_confidence}; its {verdict.value} is recorded and "
                "not read", **who, confidence=confidence,
                evidence_refs=tuple(refs), reason=reason,
                requires_verification=(self.policy.low_confidence
                                       is LowConfidenceAction.REQUIRE_VERIFICATION))
        return SemanticAssertion(status=AssertionStatus.ANSWERED, verdict=verdict,
                                 confidence=confidence, evidence_refs=tuple(refs),
                                 reason=reason, **base, **who)

    def verify_all(self, packets: Sequence[EvidencePacket]) -> List[SemanticAssertion]:
        return [self.verify(p) for p in packets]


def _bounded_text(text: str, limit: int) -> Tuple[str, bool]:
    return _bounded(text or "", limit)


# ── entering the case ────────────────────────────────────────────────────────

def assertions_to_records(assertions: Iterable[SemanticAssertion], *,
                          submitted: bool = False) -> List[Any]:
    """Each assertion as an evidence record, through the one model seam.

    In process, `quality.model_assisted_evidence` makes it DERIVED and refuses
    anything that would raise that. Read back from a file (`submitted=True`) it is
    DECLARED: release-gate has only the file's word that a model said it.

    The record links to no claim. An assertion reaches a claim only through the
    resolver, which reads it under the declared resolution policy; linking it as
    support or contradiction here would let it act through rules written for
    other kinds of evidence.
    """
    from release_gate.assurance.evidence import (EpistemicStatus, EvidenceRecord,
                                                 EvidenceType, Producer, ProducerKind)
    from release_gate.assurance.quality import model_assisted_evidence

    out: List[Any] = []
    for assertion in assertions:
        model = assertion.model or "unnamed-model"
        provenance = {"provider": assertion.provider, "model_version": assertion.model_version,
                      **({"model_family": assertion.model_family}
                         if assertion.model_family else {})}
        content = {"semantic_assertion": assertion.to_dict(), "provenance": provenance}
        note = (f"a model's reading of {len(assertion.evidence_refs)} record(s) about "
                f"{assertion.claim_id}; {assertion.status.value.lower()}"
                + (f" ({assertion.unknown_reason.value})" if assertion.unknown_reason
                   else f", {assertion.verdict.value}" if assertion.verdict else "")
                + ". It establishes nothing; the resolution policy decides what it does")
        refs = tuple(r for r in assertion.evidence_refs if r.startswith("ev_"))
        if submitted:
            out.append(EvidenceRecord.from_producer(
                content, evidence_type=EvidenceType.CLAIM_DERIVATION,
                source=f"semantic:{assertion.question_id}",
                producer=Producer(producer_id=f"model://{model}", kind=ProducerKind.AGENT,
                                  model=model),
                status=EpistemicStatus.DECLARED, coverage_note=note,
                parent_evidence=refs))
        else:
            out.append(model_assisted_evidence(
                model=model, classification=(
                    assertion.verdict.value if assertion.verdict
                    else f"unknown: {assertion.unknown_reason.value}"),
                source=f"semantic:{assertion.question_id}", parent_evidence=refs,
                content=content, coverage_note=note))
    return out


def assertions_from_records(records: Iterable[Any]) -> List[Tuple[str, SemanticAssertion]]:
    """(evidence_id, assertion) for every record carrying one. Unreadable ones skip."""
    found: List[Tuple[str, SemanticAssertion]] = []
    for record in records:
        content = getattr(record, "content", None) or {}
        payload = content.get("semantic_assertion") if isinstance(content, Mapping) else None
        if not isinstance(payload, Mapping):
            continue
        try:
            found.append((str(getattr(record, "evidence_id", "")),
                          SemanticAssertion.from_dict(payload)))
        except SemanticVerifierError:
            continue
    return found
