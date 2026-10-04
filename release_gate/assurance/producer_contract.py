"""The evidence producer contract — how any system's results become evidence.

Release-gate reads evidence from systems it does not control and will never
enumerate: an eval harness, a static analyser, a prover, a review bot, a test
runner, a vendor's console, a tool somebody writes next year. The decision engine
must not know any of them by name. So the boundary is a **contract**, and every
producer meets the engine only through it:

    ProducerDeclaration   what a producer is, stated once, as data
    EvidenceAdapter       reads one source-native document, says what it found
    normalise_output()    the one place those findings become evidence records
    ProducerRegistry      where adapters are registered; the ingest asks it

**A declaration states what the evidence means before any of it arrives.** The
modality is the existing `EvidenceLane` (seven lanes, `producers.py`), not a
second taxonomy. Beside it a producer states whether it is deterministic, what
its confidence numbers are (an ordinal label, a score on its own scale, a
probability it claims is calibrated — never ours to reinterpret), what its
coverage figures count, how independent it is of the thing it assesses, and —
required, non-empty — what it cannot establish. A producer that lists no limits
is the one a reviewer would weight hardest, so the declaration refuses it, as
the lane registry does.

**An adapter reports; the normaliser decides the record.** The adapter's whole
output is `NativeResult`s: the producer's own identifier, its own outcome word,
its own severity, its own confidence, its own counts, and the source fields
themselves. An adapter cannot construct an `EvidenceRecord`, cannot choose an
epistemic status, and cannot write the sentence a reviewer reads. The normaliser
does all three, the same way for every producer:

* **Every record is DECLARED.** A file on disk is somebody's account of what
  happened. An adapter that wanted OBSERVED would be self-attestation with a
  parser in front of it (Invariant 1). Status keys a source carries are moved
  aside by `EvidenceRecord.from_producer`, as at every other boundary.
* **The producer's words stay the producer's.** `47 of 50` arrives as a
  `Measurement` — two integers, a unit and an outcome word — and is rendered
  *"promptfoo reported 47 of 50 declared test cases passed"*. No ratio is
  computed, no percentage, no score. A count is not a safety level, and a
  denominator the producer chose is the producer's.
* **Severity is never translated.** A SonarQube `CRITICAL` is kept as
  `native_severity: "CRITICAL"` from SonarQube. Mapping it onto release-gate's
  `high` would assert an equivalence between two rule sets nobody established.
* **A decision is an artifact, not a verdict.** A result of kind `DECISION` — a
  review bot's "review", a policy engine's "deny" — is recorded as an external
  decision in its producer's own vocabulary. It is refused any claim attachment,
  and nothing maps its word onto PROMOTE / HOLD / BLOCK. A methodology may
  require one; the engine never adopts one.
* **Unknown fields are kept.** Each result's source fields travel in
  `content.native`, bounded: an oversized string is truncated with a marker, and
  a field that does not fit is named in `native_omitted` rather than dropped
  without a word (Invariant 13).

**Registration extends and never overrides.** A second adapter for a producer
type already registered is refused, and detection ranks by confidence then by
name, so the order adapters were registered in cannot change which one reads a
document (Invariant 4). An adapter is an object passed in, never a module named
in configuration — the stance `plugin.py` takes, for the same reason: "what is
release-gate running" must stay answerable.

`check_adapter_contract` is the contract as a test: any adapter, built-in or
not, can be run through it, and the shipped suite runs every built-in through it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, is_digest, thaw_value
from release_gate.assurance.claims import Claim, ClaimProvenance, ClaimType
from release_gate.assurance.evidence import (
    CoverageStatus,
    EpistemicStatus,
    EvidenceRecord,
    EvidenceType,
    Producer,
    ProducerKind,
    VerificationMethod,
)
from release_gate.assurance.producers import EvidenceLane, lane_for
from release_gate.assurance.verification import VerificationAttempt, VerificationStatus
from release_gate.assurance.verifiers import VerifierAdapter

__all__ = [
    "PRODUCER_CONTRACT_SCHEMA_VERSION",
    "AdapterOutput",
    "ConfidenceSemantics",
    "ContractReport",
    "CoverageSemantics",
    "Determinism",
    "EvidenceAdapter",
    "Independence",
    "Measurement",
    "NativeResult",
    "ProducerContractError",
    "ProducerDeclaration",
    "ProducerIdentity",
    "ProducerNormalisation",
    "ProducerRegistry",
    "ResultKind",
    "check_adapter_contract",
    "default_producer_registry",
    "normalise_output",
]

PRODUCER_CONTRACT_SCHEMA_VERSION = 1

#: Below this, detection does not commit — the floor every other detector uses.
DETECT_FLOOR = 50

#: Bounds on what a result carries of its source. Values, not scattered literals.
MAX_NATIVE_STRING = 4_096
MAX_NATIVE_FIELDS = 64
MAX_NATIVE_DEPTH = 6

_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class ProducerContractError(ValueError):
    """A producer or its output was described in a way that would change what it means."""


# ── the declaration ──────────────────────────────────────────────────────────

class Determinism(str, Enum):
    """Whether the same inputs give the same result."""

    DETERMINISTIC = "DETERMINISTIC"
    NON_DETERMINISTIC = "NON_DETERMINISTIC"  # sampling, a model judge, a flaky harness
    UNKNOWN = "UNKNOWN"


class ConfidenceSemantics(str, Enum):
    """What a confidence value from this producer is. Never what release-gate thinks it is."""

    NONE = "NONE"                                  # the producer reports none
    ORDINAL_LABEL = "ORDINAL_LABEL"                # high/medium/low, CRITICAL…: an order, not a probability
    PRODUCER_SCORE = "PRODUCER_SCORE"              # a number on the producer's own scale
    DECLARED_PROBABILITY = "DECLARED_PROBABILITY"  # the producer says it is calibrated; unchecked here


class CoverageSemantics(str, Enum):
    """What a coverage figure from this producer counts."""

    ENUMERATED = "ENUMERATED"                      # every result is listed; coverage is the list
    DECLARED_DENOMINATOR = "DECLARED_DENOMINATOR"  # "N of M", where the producer counted M
    SCOPED_TO_TARGETS = "SCOPED_TO_TARGETS"        # the files or targets it names, nothing else
    UNSTATED = "UNSTATED"


@dataclass(frozen=True)
class Independence:
    """How far this producer stands from the subject it assesses.

    `independent_of_subject` is three-valued: `None` means nobody stated it,
    which is not the same as either answer.
    """

    independent_of_subject: Optional[bool] = None
    operated_by: str = "unstated"
    shares_lineage_with: Tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "shares_lineage_with", tuple(self.shares_lineage_with))

    def to_dict(self) -> Dict[str, Any]:
        return {"independent_of_subject": self.independent_of_subject,
                "operated_by": self.operated_by,
                "shares_lineage_with": list(self.shares_lineage_with), "note": self.note}

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "Independence":
        data = data if isinstance(data, Mapping) else {}
        flag = data.get("independent_of_subject")
        return cls(independent_of_subject=flag if isinstance(flag, bool) else None,
                   operated_by=str(data.get("operated_by") or "unstated"),
                   shares_lineage_with=tuple(
                       str(x) for x in (data.get("shares_lineage_with") or ())),
                   note=str(data.get("note") or ""))


@dataclass(frozen=True)
class ProducerDeclaration:
    """What one kind of producer is. Stated once, before any of its evidence arrives."""

    producer_type: str
    label: str
    origin: str                               # vendor, project, or "any producer of format X"
    modality: EvidenceLane
    determinism: Determinism
    evidence_types: Tuple[EvidenceType, ...]
    supported_claims: Tuple[str, ...]          # what its results can bear on, in words
    confidence: ConfidenceSemantics
    coverage: CoverageSemantics
    limitations: Tuple[str, ...]
    independence: Independence = field(default_factory=Independence)
    default_producer_id: str = ""
    confidence_note: str = ""
    coverage_note: str = ""
    schema_version: int = PRODUCER_CONTRACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not _TYPE_RE.match(str(self.producer_type or "")):
            raise ProducerContractError(
                f"producer_type {self.producer_type!r} must be a short lowercase "
                "identifier ([a-z][a-z0-9_.-]); it is a key, not a label")
        if not str(self.label or "").strip() or not str(self.origin or "").strip():
            raise ProducerContractError(
                f"{self.producer_type}: a producer must say what it is and where it "
                "comes from (label, origin)")
        object.__setattr__(self, "modality", EvidenceLane(self.modality))
        object.__setattr__(self, "determinism", Determinism(self.determinism))
        object.__setattr__(self, "confidence", ConfidenceSemantics(self.confidence))
        object.__setattr__(self, "coverage", CoverageSemantics(self.coverage))
        object.__setattr__(self, "evidence_types",
                           tuple(EvidenceType(t) for t in self.evidence_types))
        object.__setattr__(self, "supported_claims", tuple(self.supported_claims))
        object.__setattr__(self, "limitations",
                           tuple(str(x) for x in self.limitations if str(x).strip()))
        if not isinstance(self.independence, Independence):
            object.__setattr__(self, "independence",
                               Independence.from_dict(self.independence))
        if not self.evidence_types:
            raise ProducerContractError(
                f"{self.producer_type}: declare which evidence types it emits; an "
                "adapter that may emit anything has told the engine nothing")
        if not self.limitations:
            raise ProducerContractError(
                f"{self.producer_type}: state what this producer cannot establish. "
                "Every producer has limits, and the one that lists none is the one "
                "a reviewer will weight hardest")
        if not self.default_producer_id:
            object.__setattr__(self, "default_producer_id", self.producer_type)

    @property
    def lane(self):
        """The lane description this producer sits in (`producers.lane_for`)."""
        return lane_for(self.modality)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "producer", "producer_type": self.producer_type,
                "label": self.label, "origin": self.origin,
                "modality": self.modality.value, "determinism": self.determinism.value,
                "evidence_types": [t.value for t in self.evidence_types],
                "supported_claims": list(self.supported_claims),
                "confidence": self.confidence.value,
                "confidence_note": self.confidence_note,
                "coverage": self.coverage.value, "coverage_note": self.coverage_note,
                "limitations": list(self.limitations),
                "independence": self.independence.to_dict(),
                "default_producer_id": self.default_producer_id,
                "schema_version": self.schema_version}

    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProducerDeclaration":
        """Read a declaration a document supplies. Unknown enum values are refused."""
        try:
            return cls(
                producer_type=str(data.get("producer_type") or ""),
                label=str(data.get("label") or data.get("producer_type") or ""),
                origin=str(data.get("origin") or ""),
                modality=EvidenceLane(str(data.get("modality") or "").upper()),
                determinism=Determinism(
                    str(data.get("determinism") or "UNKNOWN").upper()),
                evidence_types=tuple(EvidenceType(str(t).upper())
                                     for t in (data.get("evidence_types") or ())),
                supported_claims=tuple(str(x) for x in (data.get("supported_claims") or ())),
                confidence=ConfidenceSemantics(str(data.get("confidence") or "NONE").upper()),
                coverage=CoverageSemantics(str(data.get("coverage") or "UNSTATED").upper()),
                limitations=tuple(str(x) for x in (data.get("limitations") or ())),
                independence=Independence.from_dict(data.get("independence")),
                default_producer_id=str(data.get("default_producer_id")
                                        or data.get("producer_id") or ""),
                confidence_note=str(data.get("confidence_note") or ""),
                coverage_note=str(data.get("coverage_note") or ""))
        except ValueError as exc:
            if isinstance(exc, ProducerContractError):
                raise
            raise ProducerContractError(f"unusable producer declaration: {exc}") from exc

    def summary(self) -> Dict[str, Any]:
        """The compact form each record carries in its metadata."""
        return {"producer_type": self.producer_type, "modality": self.modality.value,
                "determinism": self.determinism.value,
                "confidence_semantics": self.confidence.value,
                "coverage_semantics": self.coverage.value,
                "declaration_digest": self.digest()}


@dataclass(frozen=True)
class ProducerIdentity:
    """Which producer, which version, in which state — as the document states it.

    Nothing here is authenticated. A file names its producer; that names a
    producer, and establishes nothing about who actually wrote the file.
    """

    producer_id: str
    version: Optional[str] = None
    origin: str = ""
    source_identity: str = ""
    source_state: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        pid = str(self.producer_id or "").strip()
        if not pid:
            raise ProducerContractError("a producer identity must name the producer")
        object.__setattr__(self, "producer_id", pid)
        version = str(self.version).strip() if self.version not in (None, "") else None
        object.__setattr__(self, "version", version or None)
        object.__setattr__(self, "source_state",
                           {str(k): str(v) for k, v in dict(self.source_state or {}).items()
                            if v not in (None, "")})

    def producer(self) -> Producer:
        return Producer(producer_id=self.producer_id, kind=ProducerKind.EXTERNAL,
                        identity_basis="unauthenticated", version=self.version)

    def to_dict(self) -> Dict[str, Any]:
        return {"producer_id": self.producer_id, "version": self.version,
                "origin": self.origin, "source_identity": self.source_identity,
                "source_state": dict(self.source_state)}


# ── what an adapter may say ──────────────────────────────────────────────────

class ResultKind(str, Enum):
    FINDING = "FINDING"          # something the producer found (an analyser result)
    CHECK = "CHECK"              # one test, eval or check case, with the producer's outcome
    MEASUREMENT = "MEASUREMENT"  # a count the producer reports: N of M
    DECISION = "DECISION"        # the producer's own decision or evaluation
    OBSERVATION = "OBSERVATION"  # something the producer reports seeing
    ATTESTATION = "ATTESTATION"  # a statement the producer makes about a subject


@dataclass(frozen=True)
class Measurement:
    """A count, in the producer's terms. Two integers; never a ratio."""

    count: int
    of: Optional[int]
    unit: str
    outcome: str
    denominator_basis: str = "counted by the producer"

    def __post_init__(self) -> None:
        for name in ("count", "of"):
            value = getattr(self, name)
            if value is None and name == "of":
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ProducerContractError(
                    f"a measurement's {name} must be a non-negative integer, got {value!r}")
        if self.of is not None and self.count > self.of:
            raise ProducerContractError(
                f"{self.count} of {self.of}: a count cannot exceed its own total")
        if not str(self.unit).strip() or not str(self.outcome).strip():
            raise ProducerContractError(
                "a measurement must say what was counted and with what outcome")

    def statement(self, producer_id: str) -> str:
        total = (f"{self.of} declared" if self.of is not None
                 else "an undeclared number of")
        return f"{producer_id} reported {self.count} of {total} {self.unit} {self.outcome}"

    def to_dict(self) -> Dict[str, Any]:
        return {"count": self.count, "of": self.of, "unit": self.unit,
                "outcome": self.outcome, "denominator_basis": self.denominator_basis}


@dataclass(frozen=True)
class NativeResult:
    """One result, as the producer gave it. The adapter's entire vocabulary."""

    kind: ResultKind
    native_id: str
    native_outcome: str = ""
    subject: str = ""
    native_severity: str = ""
    native_confidence: Any = None
    measurement: Optional[Measurement] = None
    location: Mapping[str, Any] = field(default_factory=dict)
    evidence_type: Optional[EvidenceType] = None
    #: A proposition the producer's own result is about — "eval case X passes".
    #: Becomes a DECLARED claim with this result as its check. Never allowed on a
    #: DECISION: an external decision is recorded, not counted.
    claim_statement: str = ""
    #: A stable id for that claim, where an earlier record shape fixed one.
    #: Derived from the result when empty.
    claim_id: str = ""
    state: Mapping[str, str] = field(default_factory=dict)
    native: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""
    produced_at: str = ""
    identity: Optional[ProducerIdentity] = None
    #: Fields an adapter mapped for compatibility with an earlier record shape.
    #: Carried as given, beside — never instead of — the native fields.
    compatibility: Mapping[str, Any] = field(default_factory=dict)
    #: The outcome for the claim, where the producer's own word is about
    #: something else: an attack that "succeeded" is a claim that "failed". Read
    #: through the same result-word table as `native_outcome`, which stays as
    #: the producer wrote it. Empty means the native word is the claim's.
    claim_outcome: str = ""
    #: What the result says it bears on, by dimension (`claim_coverage.py`):
    #: `{"tool": "refund", "environment": "staging"}`. Nothing is inferred.
    covers: Mapping[str, Any] = field(default_factory=dict)
    #: What the document states produced this result: the keys `correlation.py`
    #: reads (`provider`, `model_family`, `session`, `agent`, `reviewer`,
    #: `toolchain`, `dataset`, …). Read, never guessed; absent stays absent.
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ResultKind(self.kind))
        if self.evidence_type is not None:
            object.__setattr__(self, "evidence_type", EvidenceType(self.evidence_type))
        if not str(self.native_id or "").strip():
            raise ProducerContractError("a result must carry the producer's identifier for it")
        if self.kind is ResultKind.MEASUREMENT and self.measurement is None:
            raise ProducerContractError("a MEASUREMENT result must carry its Measurement")
        if self.kind is ResultKind.DECISION and self.claim_statement:
            raise ProducerContractError(
                "a DECISION is an external artifact and cannot propose a claim: "
                "recording another system's decision is not adopting it")
        if str(self.claim_outcome or "").strip() and not self.claim_statement:
            raise ProducerContractError(
                "a claim outcome is the outcome for a claim; a result that proposes "
                "no claim has none to state")


@dataclass(frozen=True)
class AdapterOutput:
    """Everything an adapter read from one document."""

    identity: ProducerIdentity
    results: Tuple[NativeResult, ...] = ()
    records_seen: int = 0
    skipped: Mapping[str, int] = field(default_factory=dict)
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", tuple(self.results))
        object.__setattr__(self, "notes", tuple(self.notes))
        object.__setattr__(self, "skipped", dict(self.skipped or {}))


class EvidenceAdapter:
    """Read one source-native format. Subclass, set `declaration`, implement two methods.

    * `detect(doc)` returns 0-100 and must never raise.
    * `read(doc)` returns an `AdapterOutput` and must never invent a result. A row
      it cannot read is counted in `skipped` with a reason.
    * Neither may re-run the producer, re-grade its results, or translate its
      vocabulary into release-gate's.

    `input_kind` names an existing ingest kind this adapter serves (promptfoo is
    `PROMPTFOO_EVAL`), or None for a producer the ingest knows only through the
    registry, which reaches it as `PRODUCER_EXPORT`.
    """

    declaration: ProducerDeclaration
    input_kind: Optional[str] = None

    @property
    def name(self) -> str:
        return self.declaration.producer_type

    def detect(self, doc: Any) -> int:  # pragma: no cover - abstract
        raise NotImplementedError

    def read(self, doc: Any) -> AdapterOutput:  # pragma: no cover - abstract
        raise NotImplementedError


# ── the normaliser ───────────────────────────────────────────────────────────

_LANE_CHECK_TYPE: Mapping[EvidenceLane, EvidenceType] = {
    EvidenceLane.TESTS: EvidenceType.TEST_RESULT,
    EvidenceLane.EVALS: EvidenceType.EVAL_RESULT,
    EvidenceLane.FORMAL_VERIFIER: EvidenceType.FORMAL_PROOF,
    EvidenceLane.CODE_SCANNER: EvidenceType.STATIC_FINDING,
    EvidenceLane.RUNTIME_TRACE: EvidenceType.TRACE,
    EvidenceLane.HUMAN_REVIEW: EvidenceType.HUMAN_REVIEW,
    EvidenceLane.EXTERNAL_EVIDENCE: EvidenceType.EXTERNAL_REFERENCE,
}

#: The method a check from each lane is. A lane with no entry produces no
#: verification attempt: its results are evidence, not checks.
_LANE_METHOD: Mapping[EvidenceLane, VerificationMethod] = {
    EvidenceLane.TESTS: VerificationMethod.TEST_SUITE,
    EvidenceLane.EVALS: VerificationMethod.TEST_SUITE,
    EvidenceLane.FORMAL_VERIFIER: VerificationMethod.FORMAL_PROOF,
    EvidenceLane.HUMAN_REVIEW: VerificationMethod.HUMAN_REVIEW,
}


def _default_type(result: NativeResult, lane: EvidenceLane) -> EvidenceType:
    if result.kind in (ResultKind.DECISION, ResultKind.ATTESTATION):
        return (EvidenceType.HUMAN_REVIEW if lane is EvidenceLane.HUMAN_REVIEW
                else EvidenceType.ATTESTATION)
    if result.kind is ResultKind.FINDING:
        return (EvidenceType.STATIC_FINDING if lane is EvidenceLane.CODE_SCANNER
                else _LANE_CHECK_TYPE.get(lane, EvidenceType.OTHER))
    return _LANE_CHECK_TYPE.get(lane, EvidenceType.OTHER)


def _bounded(value: Any, depth: int = 0) -> Any:
    """A JSON-safe, size-bounded copy of a source value. Truncation is marked."""
    if depth > MAX_NATIVE_DEPTH:
        return "[nested deeper than release-gate retains]"
    if isinstance(value, str):
        if len(value) > MAX_NATIVE_STRING:
            return (value[:MAX_NATIVE_STRING]
                    + f"…[truncated {len(value) - MAX_NATIVE_STRING} chars]")
        return value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) \
            else str(value)
    if isinstance(value, Mapping):
        return {str(k): _bounded(v, depth + 1)
                for k, v in list(value.items())[:MAX_NATIVE_FIELDS]}
    if isinstance(value, (list, tuple)):
        return [_bounded(v, depth + 1) for v in list(value)[:MAX_NATIVE_FIELDS]]
    return str(value)


def _native(fields: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """The source's own fields, kept; the ones that do not fit, named."""
    items = sorted(dict(fields or {}).items(), key=lambda kv: str(kv[0]))
    kept = {str(k): _bounded(v) for k, v in items[:MAX_NATIVE_FIELDS]}
    omitted = [str(k) for k, _ in items[MAX_NATIVE_FIELDS:]]
    return kept, omitted


@dataclass(frozen=True)
class ProducerNormalisation:
    """What one adapter output became."""

    evidence: Tuple[EvidenceRecord, ...] = ()
    claims: Tuple[Claim, ...] = ()
    declaration: Optional[ProducerDeclaration] = None
    identity: Optional[ProducerIdentity] = None
    records_seen: int = 0
    records_mapped: int = 0
    skipped: Mapping[str, int] = field(default_factory=dict)
    notes: Tuple[str, ...] = ()


def _observation(result: NativeResult, producer_id: str) -> str:
    """The one sentence a reviewer reads, written here and never by an adapter."""
    about = f" for {result.subject}" if result.subject else ""
    if result.kind is ResultKind.MEASUREMENT and result.measurement is not None:
        return result.measurement.statement(producer_id)
    if result.kind is ResultKind.DECISION:
        return (f"{producer_id} recorded the decision {result.native_outcome!r}{about}; "
                f"that is {producer_id}'s decision in its own vocabulary, not a "
                "release-gate verdict")
    if result.kind is ResultKind.FINDING:
        sev = (f" at its own severity {result.native_severity!r}"
               if result.native_severity else "")
        # Only where the outcome is not the claim's: an attack that succeeded is
        # said as such, so the sentence cannot read as the claim having passed.
        said = (f", outcome {result.native_outcome!r}"
                if result.claim_outcome and result.native_outcome else "")
        return f"{producer_id} reported {result.native_id}{sev}{said}{about}"
    if result.kind is ResultKind.CHECK or (result.kind is ResultKind.OBSERVATION
                                           and result.claim_outcome):
        outcome = result.native_outcome or "an unstated outcome"
        return f"{producer_id} reported {result.native_id!r} as {outcome}"
    if result.kind is ResultKind.ATTESTATION and result.native_outcome:
        return (f"{producer_id} recorded {result.native_outcome!r} in "
                f"{result.native_id}{about}")
    return f"{producer_id} reported {result.native_id}{about}"


#: Result kinds that are checks of the claim they name, and so become a
#: verification attempt in a lane that has a method. A finding bears on a claim
#: through its evidence; an observation is not a check — a hundred attacks that
#: did not get through show those hundred failed, never that none can succeed.
_CHECK_KINDS = frozenset({ResultKind.CHECK, ResultKind.ATTESTATION})


def _merge_claim(held: Claim, more: Claim, notes: List[str]) -> Claim:
    """One producer's several results about one claim are one claim."""
    if more.statement != held.statement:
        notes.append(
            f"claim {held.claim_id!r} was stated twice in different words; the first "
            f"statement stands ({held.statement!r}) and the second is kept on its "
            "evidence")
    return replace(
        held,
        supporting_evidence=held.supporting_evidence + more.supporting_evidence,
        contradicting_evidence=held.contradicting_evidence + more.contradicting_evidence,
        verification_attempts=held.verification_attempts + tuple(
            a for a in more.verification_attempts
            if a.verification_id not in {h.verification_id
                                         for h in held.verification_attempts}))


def normalise_output(output: AdapterOutput, declaration: ProducerDeclaration, *,
                     source: str, applies_to: Optional[str] = None
                     ) -> ProducerNormalisation:
    """Turn an adapter's results into evidence. The only place that does.

    `applies_to` is a content digest the records bind to when a result names no
    state of its own. It is left None for a producer's results about a system —
    an eval is about the model and prompt it ran against, not the JSON file that
    reports it, and binding it to the file would assert the wrong subject.
    """
    evidence: List[EvidenceRecord] = []
    claims: List[Claim] = []
    skipped: Dict[str, int] = dict(output.skipped)
    notes: List[str] = list(output.notes)
    lane = declaration.modality
    summary = declaration.summary()
    method = _LANE_METHOD.get(lane)

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    claim_at: Dict[str, int] = {}
    for index, result in enumerate(output.results):
        identity = result.identity or output.identity
        producer = identity.producer()
        etype = result.evidence_type or _default_type(result, lane)
        if etype not in declaration.evidence_types:
            skip(f"{declaration.producer_type} emitted {etype.value}, which its "
                 "declaration does not list")
            notes.append(
                f"a {declaration.producer_type} result was refused: it emitted "
                f"{etype.value} evidence, which the producer's declaration does not "
                "include. A declaration is what the record means; a record outside "
                "it has no stated meaning")
            continue

        native, omitted = _native(result.native)
        observation = _observation(result, identity.producer_id)
        content: Dict[str, Any] = {
            **{k: _bounded(v) for k, v in dict(result.compatibility).items()},
            "producer_type": declaration.producer_type,
            "result_kind": result.kind.value,
            "native_id": result.native_id,
            "native_outcome": result.native_outcome or None,
            "native_severity": result.native_severity or None,
            "observation": observation,
            "does_not_establish": list(declaration.limitations),
            "native": native,
        }
        if omitted:
            content["native_omitted"] = omitted
        if result.subject:
            content["subject"] = result.subject
        if result.message:
            content["message"] = _bounded(result.message)
        if result.location:
            content["location"] = _bounded(dict(result.location))
        if result.native_confidence is not None:
            content["confidence"] = {"value": _bounded(result.native_confidence),
                                     "semantics": declaration.confidence.value}
        if result.measurement is not None:
            content["measurement"] = result.measurement.to_dict()
        if result.state:
            content["state"] = {str(k): str(v) for k, v in dict(result.state).items()}
        if result.claim_outcome:
            content["claim_outcome"] = str(result.claim_outcome)
        if result.covers:
            content["covers"] = _bounded(dict(result.covers))
        if result.provenance:
            content["provenance"] = _bounded(dict(result.provenance))
        if result.kind is ResultKind.DECISION:
            content["external_decision"] = {
                "decision": result.native_outcome or None,
                "decided_by": identity.producer_id,
                "is_release_gate_verdict": False}

        metadata: Dict[str, Any] = {**summary, "source_identity": identity.source_identity,
                                    "source_state": dict(identity.source_state),
                                    "origin": identity.origin or declaration.origin}
        if result.produced_at:
            # The producer's clock is the producer's claim (see the envelope ingest).
            metadata["declared_timestamp"] = str(result.produced_at)

        claim_id = ""
        status: Optional[VerificationStatus] = None
        if result.claim_statement and result.kind is not ResultKind.DECISION:
            # The one shared result-word table: `unknown`, `timeout` and their kin
            # are INCONCLUSIVE everywhere, never a pass.
            status = VerifierAdapter.status_for(result.claim_outcome
                                                or result.native_outcome)
            claim_id = result.claim_id or (
                f"cl_{declaration.producer_type}_"
                f"{digest_object([identity.producer_id, result.native_id, index])[7:19]}")

        supports = (claim_id,) if claim_id and status is VerificationStatus.PASSED else ()
        contradicts = (claim_id,) if claim_id and status is VerificationStatus.FAILED else ()
        digest = str(result.state.get("applies_to") or "") if result.state else ""
        try:
            record = EvidenceRecord.from_producer(
                {}, evidence_type=etype, source=source, producer=producer,
                status=EpistemicStatus.DECLARED,
                applies_to_digest=digest if is_digest(digest) else applies_to,
                supports_claims=supports, contradicts_claims=contradicts,
                coverage_status=CoverageStatus.PARTIAL,
                coverage_note=(f"{observation}. As reported by {identity.producer_id}; "
                               "release-gate did not re-run or re-grade it"),
                content=content, metadata=metadata)
        except Exception as exc:
            skip(f"result rejected: {type(exc).__name__}")
            notes.append(f"a {declaration.producer_type} result was rejected: {exc}")
            continue
        evidence.append(record)

        if claim_id:
            attempts = ()
            if method is not None and status is not None and result.kind in _CHECK_KINDS:
                # The check ran against what its result names, so the attempt
                # binds to the candidate exactly as its evidence does. Without
                # this a stale check still counted through its PASSED attempt.
                # `applies_to` is the digest the attempt carries as its target;
                # left in the state it would be an unrecognised key that made
                # the binding read nothing at all.
                bound = {k: v for k, v in dict(content.get("state") or {}).items()
                         if k != "applies_to"}
                checked: Dict[str, Any] = {}
                if bound:
                    checked["state"] = bound
                for key in ("covers", "provenance"):
                    if content.get(key):
                        checked[key] = content[key]
                # A check that did not run cites nothing and was performed by
                # nobody, as an envelope's own NOT_RUN attempt is read.
                ran = status is not VerificationStatus.NOT_RUN
                attempts = (VerificationAttempt(
                    method=method, verifier=identity.producer_id if ran else "",
                    status=status, evidence=(record.evidence_id,) if ran else (),
                    target_digest=record.applies_to_digest,
                    result=checked,
                    detail=f"reported by {identity.producer_id}"),)
            built = Claim(
                claim_id=claim_id, statement=result.claim_statement,
                claim_type=ClaimType.ASSERTION, producer=producer,
                provenance=ClaimProvenance.DECLARED,
                supporting_evidence=(record.evidence_id,) if supports else (),
                contradicting_evidence=(record.evidence_id,) if contradicts else (),
                verification_attempts=attempts,
                metadata={"producer_type": declaration.producer_type})
            if claim_id in claim_at:
                claims[claim_at[claim_id]] = _merge_claim(
                    claims[claim_at[claim_id]], built, notes)
            else:
                claim_at[claim_id] = len(claims)
                claims.append(built)

    mapped = len(evidence)
    return ProducerNormalisation(
        evidence=tuple(evidence), claims=tuple(claims), declaration=declaration,
        identity=output.identity, records_seen=output.records_seen,
        records_mapped=mapped, skipped=skipped, notes=tuple(notes))


# ── the registry ─────────────────────────────────────────────────────────────

class ProducerRegistry:
    """The producers this process knows, and the adapters that read them.

    A declaration may be registered without an adapter, for a producer whose
    records are built elsewhere (release-gate's own static scanner): what it
    means is still stated in one place.
    """

    def __init__(self, *, include_builtin: bool = True) -> None:
        self._adapters: Dict[str, EvidenceAdapter] = {}
        self._declarations: Dict[str, ProducerDeclaration] = {}
        if include_builtin:
            from release_gate.assurance.producer_adapters import builtin_adapters
            from release_gate.assurance.static_producer import STATIC_DECLARATION
            self.declare(STATIC_DECLARATION)
            for adapter in builtin_adapters():
                self.register(adapter)

    def declare(self, declaration: ProducerDeclaration) -> "ProducerRegistry":
        if not isinstance(declaration, ProducerDeclaration):
            raise ProducerContractError("a declaration must be a ProducerDeclaration")
        held = self._declarations.get(declaration.producer_type)
        if held is not None and held != declaration:
            raise ProducerContractError(
                f"a different declaration for {declaration.producer_type!r} is already "
                "registered; replacing one would change what its evidence means")
        self._declarations[declaration.producer_type] = declaration
        return self

    def register(self, adapter: EvidenceAdapter) -> "ProducerRegistry":
        if not isinstance(adapter, EvidenceAdapter):
            raise ProducerContractError("an evidence adapter must subclass EvidenceAdapter")
        declaration = getattr(adapter, "declaration", None)
        if not isinstance(declaration, ProducerDeclaration):
            raise ProducerContractError(
                f"{type(adapter).__name__} declares no ProducerDeclaration")
        if declaration.producer_type in self._adapters:
            raise ProducerContractError(
                f"an adapter for {declaration.producer_type!r} is already registered; a "
                "second would make which one reads a document depend on registration "
                "order")
        self.declare(declaration)
        self._adapters[declaration.producer_type] = adapter
        return self

    @property
    def adapters(self) -> Tuple[EvidenceAdapter, ...]:
        return tuple(self._adapters[k] for k in sorted(self._adapters))

    @property
    def declarations(self) -> Tuple[ProducerDeclaration, ...]:
        return tuple(self._declarations[k] for k in sorted(self._declarations))

    def declaration(self, producer_type: str) -> Optional[ProducerDeclaration]:
        return self._declarations.get(producer_type)

    def adapter(self, producer_type: str) -> Optional[EvidenceAdapter]:
        return self._adapters.get(producer_type)

    def detect(self, doc: Any, *, include_routed: bool = True
               ) -> Tuple[Tuple[str, int], ...]:
        """Every adapter's confidence, best first; ties broken by name, not order.

        `include_routed=False` leaves out adapters that serve an existing ingest
        kind, for a caller that already detects those kinds its own way.
        """
        scored: List[Tuple[str, int]] = []
        for name in sorted(self._adapters):
            adapter = self._adapters[name]
            if not include_routed and adapter.input_kind:
                continue
            try:
                confidence = max(0, min(100, int(adapter.detect(doc))))
            except Exception:
                confidence = 0
            if confidence > 0:
                scored.append((name, confidence))
        scored.sort(key=lambda row: (-row[1], row[0]))
        return tuple(scored)

    def read(self, doc: Any, *, producer_type: Optional[str] = None
             ) -> Tuple[EvidenceAdapter, AdapterOutput]:
        if producer_type:
            adapter = self._adapters.get(producer_type)
            if adapter is None:
                raise ProducerContractError(
                    f"no adapter for {producer_type!r}; registered: "
                    + ", ".join(sorted(self._adapters)))
        else:
            scored = self.detect(doc)
            if not scored or scored[0][1] < DETECT_FLOOR:
                best = (f" Closest was {scored[0][0]} at {scored[0][1]}%."
                        if scored else "")
                raise ProducerContractError(
                    f"no registered producer recognised this document above "
                    f"{DETECT_FLOOR}% confidence.{best}")
            adapter = self._adapters[scored[0][0]]
        return adapter, adapter.read(doc)

    def normalise(self, doc: Any, *, source: str, applies_to: Optional[str] = None,
                  producer_type: Optional[str] = None) -> ProducerNormalisation:
        adapter, output = self.read(doc, producer_type=producer_type)
        return normalise_output(output, adapter.declaration, source=source,
                                applies_to=applies_to)


def default_producer_registry() -> ProducerRegistry:
    """A fresh registry per call, so one caller's adapter is not another's surprise."""
    return ProducerRegistry()


# ── the contract, as a check ─────────────────────────────────────────────────

@dataclass(frozen=True)
class ContractReport:
    adapter: str
    violations: Tuple[str, ...] = ()

    @property
    def holds(self) -> bool:
        return not self.violations


#: Inputs every adapter must survive without raising from `detect`.
HOSTILE_INPUTS: Tuple[Any, ...] = (
    None, "", "text", 0, 1.5, True, [], {}, [None], [1, 2, 3], {"results": None},
    {"results": [None, 3, "x"]}, {"runs": "nope"}, {"a": {"b": {"c": {"d": []}}}},
)


def check_adapter_contract(adapter: EvidenceAdapter, sample: Any, *,
                           source: str = "contract-check.json") -> ContractReport:
    """Run one adapter against the contract on one real sample.

    Returns the violations rather than raising, so a caller can report all of
    them at once. An adapter that holds this contract on its samples can be
    registered without the engine knowing anything else about it.
    """
    name = getattr(getattr(adapter, "declaration", None), "producer_type", type(adapter).__name__)
    problems: List[str] = []
    declaration = getattr(adapter, "declaration", None)
    if not isinstance(declaration, ProducerDeclaration):
        return ContractReport(name, ("declares no ProducerDeclaration",))

    for hostile in HOSTILE_INPUTS:
        try:
            score = adapter.detect(hostile)
        except Exception as exc:
            problems.append(f"detect raised {type(exc).__name__} on {hostile!r}")
            continue
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            problems.append(f"detect returned {score!r} for {hostile!r}; it must be 0-100")

    try:
        confidence = adapter.detect(sample)
    except Exception as exc:
        return ContractReport(name, tuple(problems + [f"detect raised on its sample: {exc}"]))
    if confidence < DETECT_FLOOR:
        problems.append(f"detects its own sample at {confidence}%, below the floor")

    try:
        output = adapter.read(sample)
    except Exception as exc:
        return ContractReport(name, tuple(problems + [f"read raised on its sample: {exc}"]))
    if not isinstance(output, AdapterOutput):
        return ContractReport(name, tuple(problems + ["read did not return an AdapterOutput"]))
    if not all(isinstance(r, NativeResult) for r in output.results):
        problems.append("read returned something other than NativeResults")
    accounted = len(output.results) + sum(output.skipped.values())
    if output.records_seen < len(output.results):
        problems.append(f"reports {output.records_seen} records seen but returned "
                        f"{len(output.results)} results")
    if output.records_seen and accounted < output.records_seen and not any(
            r.kind is ResultKind.MEASUREMENT for r in output.results):
        problems.append(f"{output.records_seen - accounted} record(s) seen were "
                        "neither mapped nor counted as skipped")
    if any(not r.native for r in output.results if r.kind is not ResultKind.MEASUREMENT):
        problems.append("a result carries none of its source fields")

    first = normalise_output(output, declaration, source=source)
    second = normalise_output(adapter.read(sample), declaration, source=source)
    if [e.evidence_id for e in first.evidence] != [e.evidence_id for e in second.evidence]:
        problems.append("reading the same sample twice produced different evidence")
    for record in first.evidence:
        if record.epistemic_status is not EpistemicStatus.DECLARED:
            problems.append(f"{record.evidence_id} is {record.epistemic_status.value}; "
                            "a document's evidence is DECLARED")
        if record.evidence_type not in declaration.evidence_types:
            problems.append(f"{record.evidence_id} has undeclared type "
                            f"{record.evidence_type.value}")
        content = thaw_value(record.content)
        if content.get("result_kind") == ResultKind.DECISION.value and (
                record.supports_claims or record.contradicts_claims):
            problems.append(f"{record.evidence_id}: an external decision bears on a claim")
        for key in ("verdict", "decision", "release_gate_decision"):
            if key in content:
                problems.append(f"{record.evidence_id} carries a top-level {key!r}; an "
                                "external outcome belongs under external_decision")
        measurement = content.get("measurement")
        if isinstance(measurement, Mapping) and set(measurement) - {
                "count", "of", "unit", "outcome", "denominator_basis"}:
            problems.append(f"{record.evidence_id}: a measurement gained a derived field")
    refused = {reason: count for reason, count in first.skipped.items()
               if count > int(output.skipped.get(reason, 0))}
    for reason, count in sorted(refused.items()):
        problems.append(f"the normaliser refused {count} of its own sample's "
                        f"result(s): {reason}")
    return ContractReport(name, tuple(problems))
