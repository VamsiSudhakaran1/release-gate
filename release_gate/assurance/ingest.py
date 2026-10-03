"""Zero-config ingestion — turn a file into assurance records without being told what it is.

The premise of `release-gate assure trace.json` is that a person with one file
and no configuration should still get real structural assurance. That is only
honest if three rules hold, and this module is where all three live.

**Detection is evidence, not a guess.** Every `Detection` carries the basis on
which it was made and the alternatives it beat. A file we cannot identify is not
an error — it is a case with an unrecognised subject, a computed digest, and a
coverage gap naming what would resolve it.

**The boundary is here.** Epistemic status is assigned in this module and
nowhere downstream. A digest release-gate computed over bytes it read is
`OBSERVED`. Everything the document *says* — that a span ran, that a tool
succeeded, that an eval passed — is `DECLARED`, because we did not watch it
happen and a file is not a witness. Conflating those two would let any producer
promote its own assertions to observations by writing them down.

**Nothing is invented.** A record we cannot map is counted and reported, never
approximated into the case. Zero configuration reduces what a user must supply;
it does not reduce what release-gate must be able to show.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.artifacts import Artifact, ArtifactKind
from release_gate.assurance.canonical import digest_object, is_digest
from release_gate.assurance.capabilities import CapabilitySurface, declared_from_document
from release_gate.assurance.consequence import (
    ConsequenceDescriptor, descriptors_from_mapping,
)
from release_gate.assurance.expectation import (
    EvidenceExpectation, ExpectationSource, ExpectationSourceKind)
from release_gate.assurance.adversarial import (
    AdversarialFinding, AdversarialOutcome, AdversarialRole, AdversarialStatus)
from release_gate.assurance.counterexample import (
    CounterexampleAttempt, CounterexampleError, CounterexampleResult,
    CounterexampleStatus,
)
from release_gate.assurance.failed_branches import (
    MAX_INLINE_DETAIL, BranchOutcome, FailedBranch, FailureLocus,
)
from release_gate.assurance.verifiers import (
    VerifierError, VerifierReport, default_verifier_registry,
)
from release_gate.assurance.claims import Claim, ClaimProvenance, ClaimType
from release_gate.assurance.producer_contract import (
    ProducerContractError,
    ProducerDeclaration,
    ProducerNormalisation,
    default_producer_registry,
    normalise_output,
)
from release_gate.assurance.verification import (
    VerificationAttempt, VerificationError, VerificationStatus,
)
from release_gate.assurance.evidence import (
    EpistemicStatus, EvidenceRecord, EvidenceType, Producer, ProducerKind,
    VerificationMethod, file_content, inline_content,
)
from release_gate.assurance.execution_graph import (
    ExecutionGraph, ExecutionGraphBuilder,
)
from release_gate.assurance.subject import (
    ContentReference, DigestMethod, DigestStatus, ReferenceKind, SubjectType,
)

__all__ = [
    "Detection",
    "IngestError",
    "InputKind",
    "Normalisation",
    "detect_document",
    "ingest_path",
    "load_input",
    "normalise",
    "subject_type_for",
]

# Below this, detection does not commit. The adapters use the same floor for the
# same reason: a gate resting on a guessed format is a gate resting on a guess.
DETECT_FLOOR = 50

ENVELOPE_RECORD_TYPES = frozenset(
    {"claim", "evidence", "artifact", "execution", "edge", "completeness",
     "counterexample", "failed_branch", "adversarial", "expectation",
     # A `ProducerDeclaration` (producer_contract.py): what one producer's
     # evidence means, stated by the submission before that evidence is read.
     "producer",
     # A `CandidateState` (candidate.py): the release the submission says it is
     # evidence about. Labelled as the submission's own description.
     "candidate"})


class IngestError(ValueError):
    """An input could not be read at all. Not knowing what a file *is* is not this."""


class InputKind(str, Enum):
    """What a document turned out to be."""

    OTLP_TRACE = "OTLP_TRACE"
    NATIVE_TRACE = "NATIVE_TRACE"
    LANGFUSE_EXPORT = "LANGFUSE_EXPORT"
    ARIZE_EXPORT = "ARIZE_EXPORT"
    PROMPTFOO_EVAL = "PROMPTFOO_EVAL"
    ASSURANCE_ENVELOPE = "ASSURANCE_ENVELOPE"
    AUDIT_REPORT = "AUDIT_REPORT"
    VERIFIER_REPORT = "VERIFIER_REPORT"
    #: An agent framework's own export — LangGraph, OpenAI Agents, CrewAI,
    #: AutoGen, Temporal, or any framework described by an `OrchestratorProfile`.
    #: One kind for all of them, because the orchestrator is a fact about the
    #: input rather than a mode the engine runs in.
    ORCHESTRATOR_EXPORT = "ORCHESTRATOR_EXPORT"
    #: A document a registered evidence adapter reads — SARIF, an external
    #: decision, or any producer an organisation registers. One kind for all of
    #: them, for the same reason as ORCHESTRATOR_EXPORT: which producer it was is
    #: a fact about the input, carried in `Detection.adapter`, not a mode of the
    #: engine. A new producer needs a registration, never a new kind.
    PRODUCER_EXPORT = "PRODUCER_EXPORT"
    UNRECOGNISED = "UNRECOGNISED"


_ADAPTER_KIND = {
    "otel": InputKind.OTLP_TRACE,
    "langfuse": InputKind.LANGFUSE_EXPORT,
    "arize": InputKind.ARIZE_EXPORT,
    "promptfoo": InputKind.PROMPTFOO_EVAL,
}

# What kind of thing a human is being asked about, per input kind. A trace is a
# record of an autonomous action; an eval run is a result; an audit report is a
# deployment question. None of these is a domain judgement — it is the shape of
# the subject, which is all the file can tell us.
_SUBJECT_TYPE = {
    InputKind.OTLP_TRACE: SubjectType.AUTONOMOUS_ACTION,
    InputKind.NATIVE_TRACE: SubjectType.AUTONOMOUS_ACTION,
    InputKind.LANGFUSE_EXPORT: SubjectType.AUTONOMOUS_ACTION,
    InputKind.ARIZE_EXPORT: SubjectType.AUTONOMOUS_ACTION,
    InputKind.PROMPTFOO_EVAL: SubjectType.GENERAL_RESULT,
    InputKind.ASSURANCE_ENVELOPE: SubjectType.GENERAL_RESULT,
    InputKind.AUDIT_REPORT: SubjectType.DEPLOYMENT,
    InputKind.VERIFIER_REPORT: SubjectType.GENERAL_RESULT,
    InputKind.PRODUCER_EXPORT: SubjectType.GENERAL_RESULT,
    InputKind.UNRECOGNISED: SubjectType.GENERAL_RESULT,
}


def subject_type_for(kind: InputKind) -> SubjectType:
    return _SUBJECT_TYPE.get(kind, SubjectType.GENERAL_RESULT)


@dataclass(frozen=True)
class Detection:
    """What we decided a document is, and what that decision rests on."""

    kind: InputKind
    confidence: int
    basis: str
    alternatives: Tuple[Tuple[str, int], ...] = ()
    adapter: Optional[str] = None

    @property
    def recognised(self) -> bool:
        return self.kind is not InputKind.UNRECOGNISED

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "confidence": self.confidence,
                "basis": self.basis, "adapter": self.adapter,
                "alternatives": [{"name": n, "confidence": c} for n, c in self.alternatives]}


@dataclass(frozen=True)
class Normalisation:
    """Everything one file yielded, plus an account of what it did not."""

    detection: Detection
    source: str
    evidence: Tuple[EvidenceRecord, ...] = ()
    claims: Tuple[Claim, ...] = ()
    artifacts: Tuple[Artifact, ...] = ()
    execution: Optional[ExecutionGraph] = None
    capabilities: Optional[CapabilitySurface] = None
    declared_consequence: Tuple[ConsequenceDescriptor, ...] = ()
    counterexamples: Tuple[CounterexampleAttempt, ...] = ()
    adversarial: Tuple[AdversarialFinding, ...] = ()
    expectations: Tuple[EvidenceExpectation, ...] = ()
    failed_branches: Tuple[FailedBranch, ...] = ()
    verifier_report: Optional[VerifierReport] = None
    records_seen: int = 0
    records_mapped: int = 0
    #: How many records of each `record_type` passed through, counted at the ingest
    #: boundary by release-gate. Added because `records_seen` alone could not answer
    #: "how many events were there" — a reviewer's first question at frontier scale,
    #: and the reason §10ao had to report the compression funnel's event stage as
    #: NOT_ASSESSED. Empty when nobody counted, which is distinct from all-zero.
    records_seen_by_kind: Mapping[str, int] = field(default_factory=dict)
    skipped: Mapping[str, int] = field(default_factory=dict)
    notes: Tuple[str, ...] = ()
    #: Consequence declarations the vocabulary refused, one readable line each.
    #: Kept as its own field rather than left among `notes` so the report can
    #: print them beside the UNKNOWN list they explain without matching on
    #: prose — a dimension is UNKNOWN because nobody stated it OR because
    #: somebody stated it and the value was refused, and only the second is
    #: something the operator can go and fix.
    refused_consequence: Tuple[str, ...] = ()
    #: The candidate the document states or implies: an envelope's `candidate`
    #: record (the submitter describing its own release), or an audit report's
    #: provenance. None when the document says nothing about one.
    candidate: Optional[Any] = None

    @property
    def skipped_total(self) -> int:
        return sum(self.skipped.values())

    @property
    def records_unaccounted(self) -> int:
        """Records in the total that no kind accounts for.

        Positive when rows arrived that could not be classified: not an object,
        over a parsing bound, or naming no `record_type`. Each is counted in
        `skipped` with a reason, so the information exists — this is the
        arithmetic that says how many, so a reader summing the breakdown against
        the total gets a number here instead of an unexplained shortfall.

        Zero when the breakdown accounts for everything. Negative only when the
        two counters disagree, which is a defect in whatever built this
        `Normalisation` and is reported rather than clamped: the engine's own
        paths keep them reconciled by construction and a test pins that.
        """
        return self.records_seen - sum(self.records_seen_by_kind.values())

    def to_dict(self) -> Dict[str, Any]:
        return {"detection": self.detection.to_dict(), "source": self.source,
                "evidence": len(self.evidence), "claims": len(self.claims),
                "artifacts": len(self.artifacts),
                "execution_nodes": len(self.execution.nodes) if self.execution else 0,
                "capabilities": (self.capabilities.summary() if self.capabilities
                                 else None),
                "declared_consequence": [d.to_dict() for d in self.declared_consequence],
                "counterexamples": len(self.counterexamples),
                "adversarial": len(self.adversarial),
                "expectations": len(self.expectations),
                "failed_branches": len(self.failed_branches),
                "verifier_report": (self.verifier_report.summary()
                                    if self.verifier_report else None),
                "records_seen": self.records_seen, "records_mapped": self.records_mapped,
                "records_seen_by_kind": dict(self.records_seen_by_kind),
                "records_unaccounted": self.records_unaccounted,
                "records_skipped": self.skipped_total,
                "skipped_by_reason": dict(self.skipped), "notes": list(self.notes),
                "refused_consequence": list(self.refused_consequence)}


# ── loading ──────────────────────────────────────────────────────────────────

def load_input(path: str | Path) -> Any:
    """Read a JSON or JSONL file. The only thing that is allowed to be fatal."""
    from release_gate.adapters.common import load_document
    try:
        return load_document(str(path))
    except FileNotFoundError as exc:
        raise IngestError(str(exc)) from exc
    except (ValueError, json.JSONDecodeError) as exc:
        raise IngestError(
            f"{path}: not readable as JSON or JSONL ({exc}). Zero-config assurance "
            "reads structured evidence; convert the file or point at an export.") from exc


# ── detection ────────────────────────────────────────────────────────────────

def _looks_like_envelope(doc: Any) -> int:
    if not isinstance(doc, list) or not doc:
        return 0
    typed = sum(1 for r in doc[:200]
                if isinstance(r, Mapping)
                and isinstance(r.get("record_type"), str)
                and r.get("record_type") in ENVELOPE_RECORD_TYPES)
    sample = min(len(doc), 200)
    return int(100 * typed / sample) if sample else 0


def _looks_like_audit_report(doc: Any) -> int:
    if not isinstance(doc, Mapping):
        return 0
    markers = sum(1 for k in ("code_findings", "safeguards", "score", "decision",
                              "frameworks", "readiness") if k in doc)
    return min(100, markers * 22) if markers >= 2 else 0


def _looks_like_native_trace(doc: Any) -> int:
    traces = doc.get("traces") if isinstance(doc, Mapping) else (
        doc if isinstance(doc, list) else None)
    if not isinstance(traces, list) or not traces:
        return 0
    shaped = sum(1 for t in traces[:100]
                 if isinstance(t, Mapping) and isinstance(t.get("steps"), list))
    sample = min(len(traces), 100)
    return int(95 * shaped / sample) if sample else 0


def _looks_like_otlp(doc: Any) -> int:
    """Structural OTLP, whatever the spans happen to be about.

    The platform adapters score on *content* — gen_ai attributes, OpenInference
    keys — so a perfectly valid OTLP export of database and HTTP spans scores zero
    with all of them and would be reported as unrecognised. The envelope shape is
    recognisable on its own, and recognising it is what lets execution and
    capability reconstruction run. Scored below the content adapters so a GenAI
    trace still routes to the adapter that understands it.
    """
    from release_gate.adapters.common import iter_otlp_spans
    spans = 0
    identified = 0
    for span, _ in iter_otlp_spans(doc):
        spans += 1
        if span.get("spanId") or span.get("span_id"):
            identified += 1
        if spans >= 50:
            break
    if not spans:
        return 0
    return 65 if identified else 55


def _otlp_basis(doc: Any) -> str:
    """Say which OpenTelemetry shape matched, not which one usually does.

    The wire format and the SDK's console export are both OpenTelemetry and
    neither is the other. Reporting "resource/scope/span structure" for a file
    that has no `resourceSpans` in it is a small lie in the one line whose job
    is to tell the reader what release-gate thought it was reading.
    """
    if isinstance(doc, Mapping) and (doc.get("resourceSpans") or doc.get("resource_spans")):
        return "OTLP resource/scope/span structure"
    if isinstance(doc, list) and any(
            isinstance(row, Mapping) and (row.get("resourceSpans") or row.get("resource_spans"))
            for row in doc[:5]):
        return "OTLP resource/scope/span structure"
    return "OpenTelemetry SDK span export (ids under `context`, flat attributes)"


def _looks_like_verifier_report(doc: Any) -> int:
    """A machine verifier's output, via whatever adapters are registered."""
    try:
        scored = default_verifier_registry().detect(doc)
    except Exception:
        return 0
    return scored[0][1] if scored else 0


def detect_document(doc: Any, *, filename: str = "",
                    producers: Optional[Any] = None) -> Detection:
    """Identify a document, or say plainly that we could not.

    Native release-gate shapes are checked before the platform adapters, because
    they are exact structural matches rather than heuristics. Below `DETECT_FLOOR`
    nothing is committed to: an unrecognised file still yields a case, and a
    wrongly-recognised one would yield a confident lie.
    """
    native: List[Tuple[InputKind, int, str]] = []
    score = _looks_like_envelope(doc)
    if score:
        native.append((InputKind.ASSURANCE_ENVELOPE, score,
                       f"{score}% of sampled lines carry a known assurance record_type"))
    score = _looks_like_audit_report(doc)
    if score:
        native.append((InputKind.AUDIT_REPORT, score,
                       "top-level keys match a release-gate audit report"))
    score = _looks_like_native_trace(doc)
    if score:
        native.append((InputKind.NATIVE_TRACE, score,
                       "objects carrying trace steps in release-gate's native shape"))
    score = _looks_like_otlp(doc)
    if score:
        native.append((InputKind.OTLP_TRACE, score, _otlp_basis(doc)))
    score = _looks_like_verifier_report(doc)
    if score:
        native.append((InputKind.VERIFIER_REPORT, score,
                       "a registered verifier adapter recognised this output"))
    try:
        from release_gate.assurance.orchestration import identify
        found = identify(doc)
        if found.profile is not None:
            native.append((InputKind.ORCHESTRATOR_EXPORT, found.confidence,
                           found.basis))
    except Exception:
        # An orchestrator profile that cannot read a document must not stop the
        # document being read some other way.
        pass

    try:
        from release_gate.adapters import detect as adapter_detect
        adapter_scores = [(n, c) for n, c in adapter_detect(doc)]
    except Exception:
        adapter_scores = []

    # Registered evidence producers that have no kind of their own. Adapters
    # serving an existing kind (promptfoo) are left out here: that kind is
    # already detected above, and counting it twice would let one document
    # compete with itself.
    producer_scores: List[Tuple[str, int]] = []
    try:
        registry = producers if producers is not None else default_producer_registry()
        producer_scores = list(registry.detect(doc, include_routed=False))
    except Exception:
        producer_scores = []

    ranked: List[Tuple[str, int, str, Optional[str], InputKind]] = [
        (k.value, c, basis, None, k) for k, c, basis in native
    ] + [
        (n, c, f"matched the {n} adapter at {c}% confidence", n,
         _ADAPTER_KIND.get(n, InputKind.UNRECOGNISED))
        for n, c in adapter_scores
    ] + [
        (f"{InputKind.PRODUCER_EXPORT.value}:{n}", c,
         f"the registered {n} evidence producer recognised this document at {c}%",
         n, InputKind.PRODUCER_EXPORT)
        for n, c in producer_scores
    ]
    ranked.sort(key=lambda row: (-row[1], row[0]))

    alternatives = tuple((row[0], row[1]) for row in ranked[1:4])
    if not ranked or ranked[0][1] < DETECT_FLOOR:
        best = f" Closest was {ranked[0][0]} at {ranked[0][1]}%." if ranked else ""
        name = f"{filename}: " if filename else ""
        return Detection(
            kind=InputKind.UNRECOGNISED, confidence=ranked[0][1] if ranked else 0,
            basis=(f"{name}no known format matched above {DETECT_FLOOR}% confidence.{best}"),
            alternatives=alternatives)

    top = ranked[0]
    return Detection(kind=top[4], confidence=top[1], basis=top[2],
                     alternatives=alternatives, adapter=top[3])


# ── producers ────────────────────────────────────────────────────────────────

def _record_producer(row: Mapping[str, Any], fallback: Producer) -> Producer:
    """The producer a single envelope record names, falling back to the document's.

    Per-record producers are what make independence analysis mean anything: a file
    is a container, not an author, and forty records from four systems are not four
    records from one. `identity_basis` stays `unauthenticated` regardless — the
    record asserting its own producer is not the same as that producer being
    established (Invariant 11).
    """
    raw = row.get("producer")
    if isinstance(raw, Mapping):
        producer_id = str(raw.get("producer_id") or "").strip()
        if producer_id:
            kind = _enum_or(ProducerKind, raw.get("kind"), ProducerKind.EXTERNAL)
            # A payload cannot declare itself release-gate's own work.
            if kind is ProducerKind.RELEASE_GATE:
                kind = ProducerKind.EXTERNAL
            return Producer(producer_id=producer_id, kind=kind,
                            identity_basis="unauthenticated",
                            model=str(raw["model"]) if raw.get("model") else None,
                            version=str(raw["version"]) if raw.get("version") else None)
    if isinstance(raw, str) and raw.strip():
        return Producer(producer_id=raw.strip(), kind=ProducerKind.EXTERNAL,
                        identity_basis="unauthenticated")
    return fallback


def _document_producer(doc: Any, detection: Detection, source: str) -> Producer:
    """Who the document says made it.

    A file on disk carries no authenticated identity, so `identity_basis` is
    `unauthenticated` whatever the document claims about itself. That is not a
    formality: it is what makes RG-PROV-002 fire, and what stops an unsigned
    export from being weighed as though someone had vouched for it.
    """
    named = None
    if isinstance(doc, Mapping):
        for key in ("service_name", "serviceName", "producer", "generated_by", "tool"):
            value = doc.get(key)
            if isinstance(value, str) and value.strip():
                named = value.strip()
                break
    if named is None and detection.adapter:
        named = f"{detection.adapter}-export"
    return Producer(
        producer_id=named or f"file://{Path(source).name}",
        kind=ProducerKind.EXTERNAL, identity_basis="unauthenticated")


def _release_gate_producer() -> Producer:
    return Producer.release_gate("assurance/ingest")


# ── normalisation ────────────────────────────────────────────────────────────

def _file_artifact(path: str | Path, content: Optional[bytes] = None
                   ) -> Tuple[Artifact, EvidenceRecord, ContentReference, str]:
    """The input itself: hashed by us, so the digest is OBSERVED.

    `content` supplies the bytes directly for an input that never touched a
    disk — the incremental session, where the records arrive over a wire and
    there is no file to stat. The subject still has to carry a digest, because
    `subject.identified` is non-overridable and an approval that cannot name what
    it bound to is unfalsifiable; for a session that digest is over the records
    themselves, which is the same content addressing applied to the same bytes.

    Hashed by release-gate either way, so the status stays OBSERVED rather than
    becoming something a caller asserted.
    """
    name = Path(path).name
    if content is None:
        reference, digest = file_content(path)
        byte_length = Path(path).stat().st_size
        note = "the input file's bytes, hashed by release-gate"
    else:
        reference, digest = inline_content(content, label=name)
        byte_length = len(content)
        note = "the submitted records' bytes, hashed by release-gate"
    artifact = Artifact(
        logical_id=f"file:{name}", artifact_kind=ArtifactKind.OTHER, digest=digest,
        digest_method=DigestMethod.SHA256_CONTENT, digest_status=DigestStatus.OBSERVED,
        content_reference=reference, byte_length=byte_length,
        metadata={"role": "assurance-input"})
    record = EvidenceRecord.observed(
        EvidenceType.EXTERNAL_REFERENCE, source=str(path),
        producer=_release_gate_producer(), content_reference=reference, digest=digest,
        applies_to_digest=digest, coverage_note=note,
        content={"role": "assurance-input", "filename": name})
    return artifact, record, reference, digest


def _execution_from(doc: Any, detection: Detection) -> Tuple[Optional[ExecutionGraph], List[str]]:
    notes: List[str] = []
    try:
        if detection.kind is InputKind.OTLP_TRACE:
            return ExecutionGraph.from_otlp(doc), notes
        if detection.kind is InputKind.NATIVE_TRACE:
            traces = doc.get("traces") if isinstance(doc, Mapping) else doc
            graphs = [ExecutionGraph.from_native_trace(t)
                      for t in traces if isinstance(t, Mapping)]
            if not graphs:
                return None, notes
            if len(graphs) == 1:
                return graphs[0], notes
            notes.append(f"{len(graphs)} traces in one file; the first was reconstructed "
                         "and the rest counted as execution evidence")
            return graphs[0], notes
        if detection.kind is InputKind.ASSURANCE_ENVELOPE and isinstance(doc, list):
            # An envelope may carry `execution` records in the native trace
            # shape. Folding them here is what lets the event protocol preserve
            # execution reconstruction: without it, telemetry converted to
            # events would lose the graph that the same telemetry keeps when
            # read as a trace.
            traces = [row for row in doc
                      if isinstance(row, Mapping)
                      and row.get("record_type") == "execution"
                      and isinstance(row.get("steps"), list)]
            if traces:
                if len(traces) > 1:
                    notes.append(
                        f"{len(traces)} execution record(s) in one envelope; the "
                        "first was reconstructed and the rest counted as execution "
                        "evidence")
                return ExecutionGraph.from_native_trace(traces[0]), notes
        if detection.kind is InputKind.ORCHESTRATOR_EXPORT:
            from release_gate.assurance.orchestration import read_execution
            reading = read_execution(doc)
            if reading.records:
                builder = ExecutionGraphBuilder()
                for record in reading.records:
                    builder.add_span_record(record)
                builder.note(
                    f"read from a {reading.profile_name} export: "
                    f"{reading.mapped} of {reading.seen} step(s) mapped")
                if reading.unmapped:
                    # Counted, never dropped: a reading that discarded what it
                    # did not understand would report a smaller run than the one
                    # that happened.
                    builder.note(
                        f"{len(reading.unmapped)} step(s) carried a kind this "
                        "profile does not map and were counted rather than "
                        "guessed into the graph")
                for gap in reading.gaps:
                    builder.note(f"{reading.profile_name}: {gap}")
                return builder.build(), notes
        if detection.kind in (InputKind.LANGFUSE_EXPORT, InputKind.ARIZE_EXPORT):
            from release_gate.adapters import convert
            converted = convert(doc, source=detection.adapter)
            # A trace adapter's payload is the list of traces itself. This read
            # it as a mapping, so every Langfuse and Phoenix export failed here
            # and the case reported that no execution telemetry was present.
            payload = converted.get("payload")
            traces = payload.get("traces") if isinstance(payload, Mapping) else payload
            traces = [t for t in (traces or []) if isinstance(t, Mapping)]
            if traces:
                if len(traces) > 1:
                    notes.append(
                        f"{len(traces)} traces in one {converted.get('label') or 'trace'} "
                        "export; the first was reconstructed and the other "
                        f"{len(traces) - 1} were not — export one trace per case to "
                        "assess a different run")
                return ExecutionGraph.from_native_trace(traces[0]), notes
    except Exception as exc:  # a malformed export must not crash the run
        notes.append(f"execution reconstruction did not complete: {exc}")
    return None, notes


def _capabilities_from(doc: Any, detection: Detection,
                       execution: Optional[ExecutionGraph]
                       ) -> Tuple[Optional[CapabilitySurface], List[str]]:
    """What the system reached for, read from the strongest source available.

    Raw OTLP spans still carry the attributes that settle a capability outright,
    so they are preferred. A graph alone keeps labels only, and the surface built
    from one says so — every classification there is a name match, and none of
    them can be OBSERVED.
    """
    notes: List[str] = []
    declared = declared_from_document(doc)
    try:
        # Raw spans wherever the document *has* them, not only where the GenAI
        # adapter claimed it. A trace of pure database and HTTP spans carries no
        # gen_ai attributes and so is not an "OTLP_TRACE" to the adapter — but its
        # attributes are exactly the ones that settle a capability outright, and
        # dropping to labels here would turn observations into inferences.
        from release_gate.adapters.common import iter_otlp_spans
        if next(iter_otlp_spans(doc), None) is not None:
            return CapabilitySurface.from_spans(doc, declared=declared), notes
        if execution is not None:
            return CapabilitySurface.from_execution_graph(
                execution, declared=declared), notes
        if declared:
            # No execution evidence at all, but somebody said what the system may
            # do. That is worth keeping: it is the denominator a later run needs.
            return CapabilitySurface.from_execution_graph(
                None, declared=declared), notes
    except Exception as exc:
        notes.append(f"capability discovery did not complete: {exc}")
    return None, notes


#: Where a document tends to state what is at stake.
_CONSEQUENCE_KEYS = ("consequence", "consequences", "impact", "stakes")


def _consequence_from(doc: Any,
                      source: str) -> Tuple[List[ConsequenceDescriptor], List[str]]:
    """Consequence someone stated in the document, if any, and what was refused.

    Nothing is inferred here. A document that says nothing about stakes yields no
    descriptors, and every dimension stays UNKNOWN — which is the correct answer,
    not a gap to be filled in.

    Unrecognised dimensions and values are skipped rather than guessed at: a
    best-effort sweep of a document must not fail a run over a stray key, and it
    must not silently coerce `"impact": "very bad"` into a vocabulary value.
    What it must also not do is skip without saying so, which is why this
    returns notes alongside the descriptors the way `_execution_from` and
    `_capabilities_from` already do. A stated dimension that reads UNKNOWN
    because of a typo is indistinguishable from one nobody stated, and the
    operator who typed it has no way to tell the difference from the report.
    """
    found: List[ConsequenceDescriptor] = []
    refused: List[str] = []
    name = Path(source).name

    def harvest(value: Any, origin: str, where: str) -> None:
        if not isinstance(value, Mapping):
            return
        rejected: List[str] = []
        found.extend(descriptors_from_mapping(value, source=origin,
                                              rejected=rejected))
        refused.extend(f"{where}: {line}" for line in rejected)

    if isinstance(doc, Mapping):
        for key in _CONSEQUENCE_KEYS:
            harvest(doc.get(key), f"document:{name}#{key}",
                    f"in the document's {key!r}")
    elif isinstance(doc, list):
        for index, row in enumerate(doc):
            if isinstance(row, Mapping) and row.get("record_type") == "consequence":
                payload = {k: v for k, v in row.items()
                           if k not in ("record_type", "record_id", "source")}
                producer = str(row.get("source") or f"envelope:{name}#{index}")
                # "record N", not "line N": the envelope is normally JSONL, where
                # the two coincide, but a JSON array is also accepted and there
                # they do not. An error message that sends someone to the wrong
                # line of a pretty-printed file is worse than one that does not try.
                harvest(payload, producer,
                        f"in consequence record {index + 1} of the envelope")

    # One dimension, two different declared values, in one document: keep the
    # first and let the registry record the disagreement rather than dropping it.
    return found, refused


def _envelope_records(doc: Sequence[Any], source: str, fallback: Producer, *,
                      execution: Any = None,
                      declared_consequence: Sequence[Any] = ()
                      ) -> Tuple[List[EvidenceRecord], List[Claim], List[Artifact],
                                 List[CounterexampleAttempt], List[FailedBranch],
                                 List[AdversarialFinding],
                                 List[EvidenceExpectation],
                                 int, Dict[str, int], List[str]]:
    evidence: List[EvidenceRecord] = []
    claims: List[Claim] = []
    artifacts: List[Artifact] = []
    counterexamples: List[CounterexampleAttempt] = []
    adversarial: List[AdversarialFinding] = []
    expectations: List[EvidenceExpectation] = []
    branches: List[FailedBranch] = []
    skipped: Dict[str, int] = {}
    notes: List[str] = []
    mapped = 0
    seen_by_kind: Dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    # Evidence first, so claims can be linked to the records they cite. An
    # evidence_id is derived from content at the boundary, never accepted from a
    # producer, so the envelope's own id would otherwise dangle — and a claim whose
    # support cannot be found counts as unsupported, which would be a false gap
    # manufactured by the ingest rather than found in the evidence.
    id_map: Dict[str, str] = {}
    claim_rows: List[Tuple[Mapping[str, Any], Producer]] = []
    evidence_rows: List[Tuple[Mapping[str, Any], Producer]] = []
    seen_artifacts: Set[str] = set()
    absorbed_artifacts = 0
    # Producer id -> what that producer declared its evidence means. Read in the
    # same pass as everything else and applied when evidence is built, which
    # happens after the pass, so a declaration's position in the file does not
    # matter.
    declarations: Dict[str, ProducerDeclaration] = {}

    for row in doc:
        if not isinstance(row, Mapping):
            skip("record is not an object")
            continue
        # Bounds before parsing. A submitted document is attacker-controlled in
        # the deployments this engine is built for, and three shapes used to get
        # past this point and take the process with them rather than being
        # refused: a record nested thousands deep (RecursionError inside the
        # canonicaliser), a `record_type` that is not hashable (TypeError on the
        # membership test below), and a single field holding tens of megabytes,
        # which was accepted and then *retained* in the case.
        #
        # Each is a `skip`, never an exception and never a silent drop: a bound
        # that quietly discards a record is itself evidence omission, which is
        # the threat Invariant 13 names. The skip is counted, noted, and shows
        # up in the record_mapping coverage row like any other record that did
        # not make it.
        breach = _exceeds_bounds(row)
        if breach:
            skip(f"record refused: {breach}")
            notes.append(f"a record was refused before parsing: {breach}")
            continue
        record_type = row.get("record_type")
        if isinstance(record_type, str) and record_type:
            # Counted before any decision about the row, so the tally is what
            # arrived rather than what survived: a rejected record still happened.
            seen_by_kind[record_type] = seen_by_kind.get(record_type, 0) + 1
        if not isinstance(record_type, str):
            skip("record_type is not a string")
            notes.append(
                f"a record declares record_type {type(record_type).__name__}, "
                "which cannot name a kind; it was refused rather than parsed")
            continue
        try:
            # Inside the guard: a malformed producer identity is a reason to
            # refuse one record, never to take the whole run down. It sat outside
            # and a control character in a producer id propagated out of
            # `normalise` as an exception.
            producer = _record_producer(row, fallback)
        except Exception as exc:
            skip(f"record rejected: {type(exc).__name__}")
            notes.append(f"a record names an unusable producer: {exc}")
            continue
        try:
            if record_type == "evidence":
                evidence_rows.append((row, producer))
            elif record_type == "claim":
                claim_rows.append((row, producer))
            elif record_type == "candidate":
                # Parsed by `_envelope_candidate` before this loop; counted here so
                # a submission stating its candidate is not told it was unmapped.
                mapped += 1
            elif record_type == "producer":
                declaration = ProducerDeclaration.from_dict(row)
                named = str(row.get("producer_id") or declaration.default_producer_id)
                held = declarations.get(named)
                if held is not None and held != declaration:
                    # Two meanings for one producer's evidence. Neither is chosen:
                    # the second is refused and said so (Invariant 4).
                    skip("producer declared twice with different meanings")
                    notes.append(
                        f"producer {named!r} is declared twice with different "
                        "semantics; the first declaration stands and the second "
                        "was refused rather than chosen between")
                else:
                    declarations[named] = declaration
                    mapped += 1
            elif record_type == "artifact":
                built_artifact = _artifact_from(row, producer)
                if built_artifact.record_id in seen_artifacts:
                    # Same discipline as evidence and claims. An artifact id is
                    # content-addressed, so a repeat here is byte-identical by
                    # construction — nothing is chosen between.
                    absorbed_artifacts += 1
                else:
                    seen_artifacts.add(built_artifact.record_id)
                    artifacts.append(built_artifact)
                mapped += 1
            elif record_type == "counterexample":
                counterexamples.append(_counterexample_from(row, producer))
                mapped += 1
            elif record_type == "failed_branch":
                branches.append(_failed_branch_from(row, producer))
                mapped += 1
            elif record_type == "adversarial":
                adversarial.append(_adversarial_from(row, producer))
                mapped += 1
            elif record_type == "expectation":
                expectations.append(_expectation_from(row, producer))
                mapped += 1
            elif record_type == "execution" and execution is not None:
                # Folded by `_execution_from` before this loop ran. Counting it
                # skipped reported a record as unmapped that had built the
                # execution graph the whole case rests on, and the resulting
                # "records could not be mapped" finding held cases whose
                # submissions were complete.
                mapped += 1
            elif record_type == "consequence" and declared_consequence:
                # Same: read by `_consequence_from` before this loop. A
                # submission stating what its action would do was told its
                # statement could not be mapped.
                mapped += 1
            elif record_type in ENVELOPE_RECORD_TYPES:
                skip(f"{record_type} records are not folded by the zero-config path")
            else:
                skip(f"unknown record_type {record_type!r}")
        except Exception as exc:
            skip(f"record rejected: {type(exc).__name__}")
            notes.append(f"a {record_type} record was rejected: {exc}")

    if absorbed_artifacts:
        notes.append(
            f"{absorbed_artifacts} artifact row(s) repeated a content digest "
            "already held and were absorbed; they are counted as mapped")

    ordered_rows, absorbed_evidence = _ordered_evidence(evidence_rows, notes)
    mapped += absorbed_evidence
    for row, producer, declared_parents in ordered_rows:
        # Resolved here, not at sort time: the ordering guarantees every parent has
        # already been built and entered in the map by the time its child is.
        resolved_parents = tuple(id_map[p] for p in declared_parents if p in id_map)
        payload = dict(row)
        payload.pop("record_type", None)
        payload.pop("parent_evidence", None)
        # A declared parent that was never supplied is KEPT, not dropped. It used
        # to be filtered out silently, which erased the one signal that matters
        # for chain of custody: a record claiming derivation from evidence this
        # case does not hold. The chain walker reported CONTINUOUS over exactly
        # that. Recorded on the record so it survives to §10h, and noted so it is
        # visible without one.
        unresolved = tuple(p for p in declared_parents if p not in id_map)
        if unresolved:
            payload["unresolved_parent_evidence"] = list(unresolved)
            notes.append(
                f"an evidence record names {len(unresolved)} parent(s) this case "
                f"does not hold ({', '.join(unresolved[:3])}); the custody link is "
                "recorded as broken rather than dropped")
        declared_id = str(payload.get("evidence_id") or "").strip()
        supports = tuple(_as_ids(payload.get("supports_claims")))
        contradicts = tuple(_as_ids(payload.get("contradicts_claims")))
        try:
            built = _build_evidence(payload, source=source, producer=producer,
                                    parents=resolved_parents, supports=supports,
                                    contradicts=contradicts, notes=notes,
                                    declaration=declarations.get(producer.producer_id))
        except Exception as exc:
            skip(f"record rejected: {type(exc).__name__}")
            notes.append(f"an evidence record was rejected: {exc}")
            continue
        evidence.extend(built)
        if declared_id:
            if declared_id in id_map:
                notes.append(
                    f"evidence id {declared_id!r} was declared more than once; "
                    "references to it resolve to the first record")
            else:
                id_map[declared_id] = built[0].evidence_id
        mapped += 1

    # Claims collapse on their declared id exactly as evidence does, and for the
    # same two reasons: a producer that states one claim twice has stated one
    # claim, and a redelivered batch must not reach the collection builder as a
    # duplicate. The builder refuses duplicate ids on purpose — evidence must
    # not be counted twice — but that refusal is fatal to the whole run, so a
    # retried delivery used to take the gate down rather than be absorbed.
    seen_claims: Set[str] = set()
    for row, producer in claim_rows:
        declared = str(row.get("claim_id") or row.get("id") or "").strip()
        if declared and declared in seen_claims:
            mapped += 1
            continue
        try:
            claims.append(_claim_from(row, producer, id_map, notes))
            if declared:
                seen_claims.add(declared)
            mapped += 1
        except Exception as exc:
            skip("record rejected: " + type(exc).__name__)
            notes.append(f"a claim record was rejected: {exc}")
    repeated_claims = len(claim_rows) - len(claims)
    if repeated_claims > 0 and seen_claims:
        notes.append(
            f"{repeated_claims} claim row(s) repeated a claim_id already seen and "
            "were absorbed into the first record under that id")

    return (evidence, claims, artifacts, counterexamples, branches, adversarial,
            expectations, mapped, skipped, notes, seen_by_kind)


def _build_evidence(payload: Mapping[str, Any], *, source: str, producer: Producer,
                    parents: Tuple[str, ...], supports: Tuple[str, ...],
                    contradicts: Tuple[str, ...], notes: List[str],
                    declaration: Optional[ProducerDeclaration] = None
                    ) -> List[EvidenceRecord]:
    """Build a record, splitting one that cuts both ways rather than dropping it.

    `EvidenceRecord` refuses to hold a claim in both `supports` and `contradicts`,
    which is correct — one record cannot be read both ways without saying which
    reading applies. But *rejecting* the record loses the disagreement entirely,
    and a producer that says a claim is both supported and contradicted has told us
    something real: it disagrees with itself.

    So the record is split into the two halves it was trying to be. Both keep the
    producer, so the contradiction that falls out of them shows one participant on
    each side — which is the honest picture of what arrived.
    """
    # Evidence produced in answer to a required-evidence requirement was produced
    # by a party told exactly what would close the gate. That does not make it
    # false and does not make it dependent — but it is a motive, and motive is
    # provenance, so it is recorded rather than laundered out (Invariants 1, 11).
    solicited = str(payload.get("in_response_to") or "").strip()
    metadata = {"solicited_by": solicited} if solicited else {}
    # Set by the ingest, not by the producer — its own `parent_evidence` key was
    # consumed above. A named parent this case does not hold is the custody break
    # §10h reports, and it has to survive onto the record to get there.
    unresolved = payload.pop("unresolved_parent_evidence", None)
    if unresolved:
        metadata["unresolved_parent_evidence"] = list(unresolved)
    # What the producer declared its evidence means, beside the evidence and
    # never folded into it: the payload stays exactly what was submitted.
    if declaration is not None:
        metadata.update(declaration.summary())
        metadata["declared_limitations"] = list(declaration.limitations)

    # What the producer says this evidence was produced against. Dropped
    # silently until now, which blinded every check that asks "is this evidence
    # about the current state": RG-CLAIM-007, RG-SW-007 and the `applies_to` hop
    # of the custody chain all read this field, and for envelope-submitted
    # evidence it was always None. A producer declaring what its result applies
    # to had that declaration discarded without a note.
    applies_to = str(payload.get("applies_to_digest") or "").strip()
    state: Dict[str, Any] = {}
    if applies_to:
        if is_digest(applies_to):
            state["applies_to_digest"] = applies_to
        else:
            notes.append(
                f"a record from {producer.producer_id} declares applies_to_digest "
                f"{applies_to[:32]!r}, which is not a sha256 content digest; it "
                "cannot be compared to anything and was not recorded")

    # Where the bytes live, when they do not live here. A producer declaring
    # `content_reference` — an object store key, a URL, a trace backend — had that
    # declaration dropped until now, along with any digest beside it, which left
    # no way at all to submit externally-held evidence through the envelope. That
    # is the same silent drop `applies_to_digest` suffered, and it defeats the
    # rule that large raw evidence is referenced rather than carried: the handle
    # is the whole point of the reference.
    #
    # The digest is DECLARED, never OBSERVED: release-gate did not fetch those
    # bytes and hash them, the producer says that is what they hash to. That is
    # usable, it is recorded, and it is not evidence we verified anything
    # (Invariant 1) — the same reading `_artifact_from` gives a declared digest.
    reference_row = payload.get("content_reference")
    if isinstance(reference_row, Mapping):
        locator = str(reference_row.get("locator") or "").strip()
        raw_kind = str(reference_row.get("kind") or "EXTERNAL").strip().upper()
        if locator:
            try:
                kind = ReferenceKind(raw_kind)
            except ValueError:
                kind = ReferenceKind.EXTERNAL
                notes.append(
                    f"a record from {producer.producer_id} declares content "
                    f"reference kind {raw_kind!r}, which is not one release-gate "
                    "models; it was recorded as EXTERNAL and the locator kept")
            declared_digest = str(payload.get("digest") or "").strip()
            if declared_digest and not is_digest(declared_digest):
                notes.append(
                    f"a record from {producer.producer_id} declares digest "
                    f"{declared_digest[:32]!r}, which is not a sha256 content "
                    "digest; the reference was kept and the digest was not")
                declared_digest = ""
            state["content_reference"] = ContentReference(
                kind=kind, locator=locator,
                detail=dict(reference_row.get("detail") or {}))
            if declared_digest:
                state["digest"] = declared_digest

    # How the producer says it checked this — kept beside the record, never ON
    # it. `EvidenceRecord` refuses `verification_method` on a DECLARED record
    # because "a method without a verified or refuted finding implies a
    # verification that did not happen", and everything arriving through the
    # envelope is DECLARED. That constraint is right and this must not route
    # around it: an agent naming a method would otherwise be self-certifying,
    # which is the thing §10r exists to prevent.
    #
    # So it goes in metadata, the way a producer's declared timestamp does. A
    # reviewer can see that the agent says it ran a test suite; nothing reads it
    # as a check having happened, and it was silently discarded before this.
    declared_method = str(payload.get("verification_method") or "").strip().upper()
    if declared_method:
        try:
            VerificationMethod(declared_method)
        except ValueError:
            notes.append(
                f"a record from {producer.producer_id} declares verification method "
                f"{declared_method!r}, which release-gate does not model")
        else:
            metadata["declared_verification_method"] = declared_method

    # A producer's clock is a producer's claim. `EvidenceRecord.timestamp` stays
    # what release-gate knows — when the record arrived here — because a field
    # release-gate populates must mean something release-gate observed, and a
    # forged production time written into it would read as ours. But the
    # producer's claim is not discarded either: it is kept beside the observed
    # one, as a declaration, so a reviewer can see a result stamped next year or
    # last decade for what it is. Nothing derives from it (Invariants 1, 2, 13).
    declared_at = str(payload.get("timestamp") or "").strip()
    if declared_at:
        metadata["declared_timestamp"] = declared_at

    overlap = tuple(sorted(set(supports) & set(contradicts)))
    if not overlap:
        return [EvidenceRecord.from_producer(
            payload, evidence_type=_evidence_type_of(payload), source=source,
            producer=producer, status=EpistemicStatus.DECLARED,
            parent_evidence=parents, supports_claims=supports,
            contradicts_claims=contradicts, metadata=metadata, **state,
            coverage_note=str(payload.get("coverage_note") or ""))]

    notes.append(
        f"a record from {producer.producer_id} both supports and contradicts "
        f"{', '.join(overlap)}; it has been split into its two halves so the "
        "disagreement is preserved rather than the record being dropped")
    note = str(payload.get("coverage_note") or "")
    marker = {"split_from_self_conflict": True, "self_conflict_claims": list(overlap)}
    halves: List[EvidenceRecord] = []
    for label, keeps, drops in (("supports", supports, contradicts),
                                ("contradicts", contradicts, supports)):
        # This half keeps the whole of its own side; the other side keeps only
        # what was never contested, so each claim in the overlap lands on exactly
        # one half and the conflict becomes two records disagreeing.
        mine = tuple(sorted(set(keeps)))
        theirs = tuple(sorted(set(drops) - set(overlap)))
        halves.append(EvidenceRecord.from_producer(
            {**payload, "_split_side": label},
            evidence_type=_evidence_type_of(payload), source=source,
            producer=producer, status=EpistemicStatus.DECLARED,
            parent_evidence=parents,
            supports_claims=mine if label == "supports" else theirs,
            contradicts_claims=mine if label == "contradicts" else theirs,
            content={**marker, "split_side": label}, metadata=metadata,
            coverage_note=(f"{note} (split half: {label})" if note
                           else f"split half: {label}")))
    return halves


#: Bounds on one submitted record. Values, not magic numbers scattered about,
#: so a deployment that genuinely needs more can see what it is changing.
MAX_RECORD_DEPTH = 64
MAX_FIELD_CHARS = 1_048_576          # 1 MiB of text in any single field
MAX_RECORD_KEYS = 4_096


def _exceeds_bounds(row: Mapping[str, Any]) -> str:
    """The first bound this record breaks, named, or an empty string.

    Iterative rather than recursive on purpose: a depth check that recursed
    would hit the very stack limit it exists to prevent, which is the kind of
    guard that only works on inputs that did not need it.
    """
    stack: List[Tuple[Any, int]] = [(row, 0)]
    keys = 0
    while stack:
        value, depth = stack.pop()
        if depth > MAX_RECORD_DEPTH:
            return (f"nested deeper than {MAX_RECORD_DEPTH}; a record this deep "
                    "exhausts the stack in canonicalisation rather than parsing")
        if isinstance(value, Mapping):
            keys += len(value)
            if keys > MAX_RECORD_KEYS:
                return f"more than {MAX_RECORD_KEYS} keys in one record"
            for key, item in value.items():
                if isinstance(key, str) and len(key) > MAX_FIELD_CHARS:
                    return f"a key longer than {MAX_FIELD_CHARS} characters"
                stack.append((item, depth + 1))
        elif isinstance(value, (list, tuple)):
            for item in value:
                stack.append((item, depth + 1))
        elif isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
            return (f"a field of {len(value):,} characters, over the "
                    f"{MAX_FIELD_CHARS:,} bound; it would be retained in the case")
    return ""


def _ordered_evidence(rows: Sequence[Tuple[Mapping[str, Any], Producer]],
                      notes: List[str]
                      ) -> Tuple[List[Tuple[Mapping[str, Any], Producer,
                                            Tuple[str, ...]]], int]:
    """Evidence rows in ancestry order, plus how many repeats were absorbed.

    The count is returned rather than left implicit because the caller adds it
    to `records_mapped`: a row folded into an existing record *mapped*, and
    counting it as unmapped is what made a redelivery look like a loss.

    An `evidence_id` is derived from content at the boundary, and content includes
    `parent_evidence`, so a record's id depends on its parents' ids. Parents must
    therefore be built first. Emitting rows in file order would leave every
    `parent_evidence` pointing at an envelope id that resolves to nothing, and the
    whole population would read as unrelated roots — ten thousand agents deriving
    from one artifact would look like ten thousand independent validations, which
    is precisely the error independence analysis exists to catch.

    Kahn's algorithm over the declared references. A reference to a row that is not
    present is left as-is and simply will not match any held record, which is the
    honest outcome: we can see the record derives from something we do not hold.
    Rows left over after the sort are in a declaration cycle and are emitted in
    file order with a note, rather than being dropped.
    """
    # Rows sharing a declared `evidence_id` collapse to ONE, and the first wins.
    # That is not an accident of using a dict: it is the guarantee that a replay
    # buys no extra record. Fifty copies of one test result, each restamped with
    # a fresh clock, are fifty rows the producer has given one name — and a
    # producer cannot multiply its own corroboration by saying the same thing
    # again (`test_restamping_a_replay_does_not_multiply_it`).
    #
    # First wins rather than last. The dict previously kept whichever arrived
    # latest, which let a later copy quietly replace an earlier one; the rest of
    # this function already says references "resolve to the first record", so
    # this now matches what it claims.
    #
    # The collapse is *counted*. Absorbed rows used to be neither mapped nor
    # skipped, so `records_mapped` came out below `records_seen` and the
    # record_mapping coverage row reported a shortfall for records that had not
    # gone missing — which made a redelivered batch degrade the verdict.
    indexed = {}
    absorbed = 0
    for position, (row, producer) in enumerate(rows):
        declared = str(row.get("evidence_id") or "").strip()
        key = declared or f"__row_{position}"
        if key in indexed:
            absorbed += 1
            continue
        indexed[key] = (position, row, producer)
    if absorbed:
        notes.append(
            f"{absorbed} evidence row(s) repeated an evidence_id already seen and "
            "were absorbed into the first record under that id; they are counted "
            "as mapped, not as evidence that failed to arrive")

    pending = {key: [p for p in _as_ids(row.get("parent_evidence")) if p in indexed]
               for key, (_pos, row, _prod) in indexed.items()}
    dependents: Dict[str, List[str]] = {key: [] for key in indexed}
    for key, parents in pending.items():
        for parent in parents:
            dependents[parent].append(key)

    import heapq
    ready = [indexed[k][0] for k, parents in pending.items() if not parents]
    heapq.heapify(ready)
    by_position = {position: key for key, (position, _r, _p) in indexed.items()}
    remaining = {k: len(v) for k, v in pending.items()}

    ordered: List[Tuple[Mapping[str, Any], Producer, Tuple[str, ...]]] = []
    emitted: Set[str] = set()
    while ready:
        key = by_position[heapq.heappop(ready)]
        _position, row, producer = indexed[key]
        emitted.add(key)
        ordered.append((row, producer, tuple(_as_ids(row.get("parent_evidence")))))
        for dependent in dependents[key]:
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                heapq.heappush(ready, indexed[dependent][0])

    leftover = [k for k in indexed if k not in emitted]
    if leftover:
        notes.append(
            f"{len(leftover)} evidence record(s) declare a parent cycle; their ancestry "
            "could not be ordered and their parent references may not resolve")
        for key in sorted(leftover, key=lambda k: indexed[k][0]):
            _position, row, producer = indexed[key]
            ordered.append((row, producer, tuple(_as_ids(row.get("parent_evidence")))))
    return ordered, absorbed


def _as_ids(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _evidence_type_of(payload: Mapping[str, Any]) -> EvidenceType:
    raw = str(payload.get("kind") or payload.get("evidence_type") or "").upper()
    try:
        return EvidenceType(raw)
    except ValueError:
        return EvidenceType.OTHER


def _method_of(raw: Mapping[str, Any],
               notes: Optional[List[str]] = None) -> Tuple[VerificationMethod, str]:
    """The method and, for one release-gate does not model, its producer's name.

    An unmodelled method used to raise out of `VerificationMethod(...)` and be
    caught by a bare `except: continue`, so the whole attempt vanished with no
    skip count and no note. That is release-gate omitting evidence, which is the
    threat Invariant 13 names and the reason this returns `OTHER` plus the name
    rather than nothing: a formal method invented after this release can still be
    recorded, and §10aw decides what kind of check it was — or says nobody has.
    """
    declared = str(raw.get("method") or "OTHER").strip()
    try:
        return VerificationMethod(declared.upper()), ""
    except ValueError:
        if notes is not None:
            notes.append(
                f"a verification attempt declares method {declared!r}, which "
                "release-gate does not model; it is kept as OTHER under that "
                "name, and what kind of check it is reads as not established "
                "rather than as no formal verification")
        return VerificationMethod.OTHER, declared


def _claim_from(row: Mapping[str, Any], producer: Producer,
                id_map: Optional[Mapping[str, str]] = None,
                notes: Optional[List[str]] = None) -> Claim:
    resolve = (lambda i: (id_map or {}).get(i, i))
    attempts: List[VerificationAttempt] = []
    for raw in row.get("verification_attempts") or ():
        if not isinstance(raw, Mapping):
            continue
        evidence_ids = tuple(resolve(i) for i in _as_ids(
            raw.get("evidence") or raw.get("evidence_id")))
        status = VerificationStatus(str(raw.get("outcome") or raw.get("status")
                                        or "INCONCLUSIVE").upper())
        # A check nobody is answerable for cannot be weighed, so an attempt with
        # no named verifier inherits the record's producer rather than being
        # dropped — the evidence is real even when the attribution is coarse.
        verifier = str(raw.get("verifier") or raw.get("performed_by")
                       or producer.producer_id).strip()
        method, method_label = _method_of(raw, notes)
        try:
            attempts.append(VerificationAttempt(
                method=method, method_label=method_label,
                verifier="" if status is VerificationStatus.NOT_RUN else verifier,
                # `target_digest` is passed through when the envelope records it
                # and left absent when it does not. Absent means UNDETERMINED
                # against any state — the truthful reading of a check that never
                # said what it ran against, and never to be filled in from the
                # target's current digest, which would assert currency the check
                # never established.
                target_digest=(str(raw["target_digest"])
                               if raw.get("target_digest") else None),
                input_state=(str(raw["input_state"])
                             if raw.get("input_state") else None),
                # What the check's producer says about what produced it — model,
                # session, reviewer, toolchain (correlation.py) — kept with the
                # result so the attempt can be placed in a correlation group.
                result={**(dict(raw["result"]) if isinstance(raw.get("result"), Mapping)
                           else {}),
                        **({"provenance": dict(raw["provenance"])}
                           if isinstance(raw.get("provenance"), Mapping) else {})},
                evidence=() if status is VerificationStatus.NOT_RUN else evidence_ids,
                independence_lineage=tuple(_as_ids(raw.get("independence_lineage"))),
                status=status, detail=str(raw.get("detail") or "")))
        except (ValueError, VerificationError) as exc:
            # Noted, never silent. A refused attempt is a record that arrived and
            # did not make it, which a reviewer is entitled to know about.
            if notes is not None:
                notes.append(
                    f"a verification attempt on {row.get('claim_id') or 'a claim'} "
                    f"was refused: {exc}")
            continue
    extracted_by = row.get("extracted_by_model")
    return Claim(
        claim_id=str(row.get("claim_id") or row.get("id") or ""),
        statement=str(row.get("proposition") or row.get("statement") or ""),
        claim_type=_enum_or(ClaimType, row.get("claim_type"), ClaimType.ASSERTION),
        producer=producer,
        # A model-extracted claim is DERIVED however the envelope labels it; the
        # engine does not let a producer upgrade its own provenance.
        provenance=(ClaimProvenance.DERIVED if extracted_by
                    else _enum_or(ClaimProvenance, row.get("provenance"),
                                  ClaimProvenance.DECLARED)),
        parents=tuple(_as_ids(row.get("depends_on") or row.get("parents"))),
        # `assumptions` is a dependency edge like `parents`, and dropping it would
        # make every assumption look isolated — the assumption graph would report
        # that nothing rests on things the argument explicitly rests on.
        assumptions=tuple(_as_ids(row.get("assumptions"))),
        supports=tuple(_as_ids(row.get("supports"))),
        supporting_evidence=tuple(resolve(i) for i in _as_ids(row.get("supporting_evidence"))),
        contradicting_evidence=tuple(
            resolve(i) for i in _as_ids(row.get("contradicting_evidence"))),
        verification_attempts=tuple(attempts),
        criticality=(str(row.get("consequence_weight")) if row.get("consequence_weight")
                     else None),
        is_root=bool(row.get("is_root")),
        extracted_by_model=str(extracted_by) if extracted_by else None,
        # What the claim says it needs, and what may bear on it at all. Read by
        # the claim resolver (resolution.py); absent unless the submission says.
        metadata={k: [str(x) for x in (row[k] if isinstance(row[k], (list, tuple))
                                       else [row[k]])]
                  for k in ("requires", "admissible_evidence") if row.get(k)})


def _counterexample_from(row: Mapping[str, Any],
                         producer: Producer) -> CounterexampleAttempt:
    """An explicitly declared attempt to break a claim.

    The envelope is the only way to record a search that came back *empty*:
    evidence can carry a counterexample that was found, but there is no evidence
    record for "I looked here and there was nothing", and that fact is worth
    keeping — bounded though it is.
    """
    result = CounterexampleResult(str(row.get("result") or "UNKNOWN").upper())
    declared_status = row.get("status")
    if declared_status:
        status = CounterexampleStatus(str(declared_status).upper())
    elif result is CounterexampleResult.FOUND:
        # A found counterexample is open until something answers it. Silence in the
        # envelope is not an answer.
        status = CounterexampleStatus.OPEN
    else:
        status = CounterexampleStatus.NOT_APPLICABLE
    return CounterexampleAttempt(
        target_claim=str(row.get("target_claim") or row.get("claim_id") or ""),
        producer=str(row.get("producer_id") or producer.producer_id),
        method=VerificationMethod(str(row.get("method") or "PROPERTY_TEST").upper()),
        result=result, evidence=tuple(_as_ids(row.get("evidence"))),
        resolution=str(row.get("resolution") or ""),
        resolution_evidence=tuple(_as_ids(row.get("resolution_evidence"))),
        status=status, searched=str(row.get("searched") or ""),
        detail=str(row.get("detail") or ""))


def _expectation_from(row: Mapping[str, Any],
                      producer: Producer) -> EvidenceExpectation:
    """A declared denominator: how many of something should have arrived.

    The source is required and is not defaulted to the document's producer: a
    denominator whose author is unknown cannot be told apart from one the
    evidence's own producer wrote, and that difference is the whole value of the
    record. Where the envelope names nobody, the document producer is used and
    the expectation reads SELF_REPORTED, which is the truthful reading rather
    than a generous one.
    """
    raw = row.get("source") if isinstance(row.get("source"), Mapping) else {}
    declared_by = str(raw.get("declared_by") or row.get("declared_by")
                      or producer.producer_id)
    expected = row.get("expected")
    expected_ids = tuple(_as_ids(row.get("expected_ids")))
    source = None
    if expected is not None or expected_ids:
        source = ExpectationSource(
            kind=ExpectationSourceKind(
                str(raw.get("kind") or row.get("source_kind") or "OTHER").upper()),
            declared_by=declared_by,
            authenticated=bool(raw.get("authenticated")),
            detail=str(raw.get("detail") or ""))
    return EvidenceExpectation(
        dimension=str(row.get("dimension") or ""),
        expected=(int(expected) if expected is not None else None),
        expected_ids=expected_ids,
        observed=int(row.get("observed") or 0),
        observed_ids=tuple(_as_ids(row.get("observed_ids"))),
        source=source,
        observed_from=str(row.get("observed_from") or producer.producer_id),
        # Read rather than defaulted, so a producer can declare a dimension nobody
        # assessed. Until this was read, an expectation arriving in a document could
        # only ever report `assessed=True` — `privacy`, `federation` and `vetting`
        # could express a coverage gap programmatically and the envelope format could
        # not. Safe to honour because it is the conservative direction: `False` reads
        # as a gap and holds a case, so nothing is gained by claiming it.
        assessed=(bool(row["assessed"]) if "assessed" in row else True),
        note=str(row.get("note") or ""))


def _adversarial_from(row: Mapping[str, Any],
                      producer: Producer) -> AdversarialFinding:
    """A verifier whose job was to make the candidate fail.

    The status default is the asymmetry in miniature. A finding that turned
    something up is OPEN until something answers it — silence in the envelope is
    not an answer — and an attack that found nothing has nothing to answer, which
    is NOT_APPLICABLE rather than resolved.
    """
    outcome = AdversarialOutcome(str(row.get("outcome") or "NOT_RUN").upper())
    declared = row.get("status")
    if declared:
        status = AdversarialStatus(str(declared).upper())
    elif outcome in (AdversarialOutcome.CANDIDATE_REFUTED,
                     AdversarialOutcome.ARGUMENT_DEFECT,
                     AdversarialOutcome.WEAKNESS_FOUND):
        status = AdversarialStatus.OPEN
    else:
        status = AdversarialStatus.NOT_APPLICABLE
    return AdversarialFinding(
        target_claim=str(row.get("target_claim") or row.get("claim_id") or ""),
        role=AdversarialRole(str(row.get("role") or "OTHER").upper()),
        adversary=str(row.get("adversary") or row.get("producer_id")
                      or producer.producer_id),
        method=(VerificationMethod(str(row["method"]).upper())
                if row.get("method") else None),
        outcome=outcome, status=status,
        evidence=tuple(_as_ids(row.get("evidence"))),
        independence_lineage=tuple(_as_ids(row.get("independence_lineage"))),
        attacked=str(row.get("attacked") or row.get("searched") or ""),
        resolution=str(row.get("resolution") or ""),
        resolution_evidence=tuple(_as_ids(row.get("resolution_evidence"))),
        resolved_by=str(row.get("resolved_by") or ""),
        accepted_by=str(row.get("accepted_by") or ""),
        detail=str(row.get("detail") or ""))


def _failed_branch_from(row: Mapping[str, Any], producer: Producer) -> FailedBranch:
    """A declared attempt that did not work out.

    `detail` is truncated rather than rejected: a producer that pasted a
    transcript into a field meant for a sentence should still have its failure
    recorded, and the note it carries points at where the full record belongs.
    """
    detail = str(row.get("detail") or "")
    if len(detail) > MAX_INLINE_DETAIL:
        detail = (detail[:MAX_INLINE_DETAIL - 80].rstrip()
                  + " …[truncated; put the full record behind `reference`]")
    reference = None
    locator = row.get("reference") or row.get("locator")
    if isinstance(locator, Mapping):
        reference = ContentReference.from_dict(locator)
    elif isinstance(locator, str) and locator.strip():
        reference = ContentReference(kind=ReferenceKind.EXTERNAL, locator=locator.strip())
    locus = row.get("locus") if isinstance(row.get("locus"), Mapping) else {}
    ordinal = locus.get("ordinal", row.get("ordinal"))
    return FailedBranch(
        outcome=_enum_or(BranchOutcome, row.get("outcome"), BranchOutcome.OTHER),
        locus=FailureLocus(
            step=str(locus.get("step") or row.get("step") or ""),
            ordinal=int(ordinal) if isinstance(ordinal, int) else None,
            invariant=str(locus.get("invariant") or row.get("invariant") or "")),
        produced_by=str(row.get("produced_by") or producer.producer_id),
        bears_on_claims=tuple(_as_ids(row.get("bears_on_claims"))),
        evidence=tuple(_as_ids(row.get("evidence"))),
        reference=reference,
        digest=str(row["digest"]) if row.get("digest") else None,
        depth=int(row["depth"]) if isinstance(row.get("depth"), int) else None,
        detail=detail)


def _artifact_from(row: Mapping[str, Any], producer: Producer) -> Artifact:
    digest = row.get("digest")
    return Artifact(
        logical_id=str(row.get("artifact_id") or row.get("logical_id") or "artifact"),
        artifact_kind=_enum_or(ArtifactKind, row.get("kind"), ArtifactKind.OTHER),
        digest=str(digest) if digest else None,
        # We did not hash this — the envelope asserted it — so the digest is
        # DECLARED and must name who asserted it. Without an attestor a declared
        # digest is a number with nobody behind it.
        digest_method=DigestMethod.SHA256_CONTENT if digest else DigestMethod.NONE,
        digest_status=DigestStatus.DECLARED if digest else DigestStatus.UNKNOWN,
        digest_attested_by=producer.producer_id if digest else None,
        created_by=str(row["created_by"]) if row.get("created_by") else None,
        inputs=tuple(_as_ids(row.get("inputs"))),
        revises=str(row["revises"]) if row.get("revises") else None)


def _enum_or(enum_cls, value: Any, default):
    if value is None:
        return default
    try:
        return enum_cls(str(value).upper())
    except ValueError:
        return default


def normalise(doc: Any, detection: Detection, *, source: str,
              content: Optional[bytes] = None,
              producers: Optional[Any] = None) -> Normalisation:
    """Fold one document into records. Never raises on unmappable content.

    `producers` is the `ProducerRegistry` to read registered formats with; the
    built-in one when omitted. Passing one is how an organisation's own adapter
    reaches a case without this function changing.
    """
    producer = _document_producer(doc, detection, source)
    evidence: List[EvidenceRecord] = []
    claims: List[Claim] = []
    artifacts: List[Artifact] = []
    counterexamples: List[CounterexampleAttempt] = []
    adversarial: List[AdversarialFinding] = []
    expectations: List[EvidenceExpectation] = []
    failed_branches: List[FailedBranch] = []
    skipped: Dict[str, int] = {}
    notes: List[str] = []
    seen = 0
    mapped = 0
    # Empty rather than zeroed: only the envelope path walks typed rows, so for any
    # other input nobody counted by kind, and an all-zero tally would read as
    # "there were none of those" (Invariant 3).
    seen_by_kind: Dict[str, int] = {}

    artifact, file_record, _reference, file_digest = _file_artifact(source, content)
    artifacts.append(artifact)
    evidence.append(file_record)

    execution, exec_notes = _execution_from(doc, detection)
    notes.extend(exec_notes)

    capabilities, cap_notes = _capabilities_from(doc, detection, execution)
    notes.extend(cap_notes)

    declared_consequence, refused_consequence = _consequence_from(doc, source)
    # Reported in both places on purpose: `notes` is where every other ingest
    # rejection lands, and the dedicated field is what the report reads.
    notes.extend(refused_consequence)

    verifier_report: Optional[VerifierReport] = None
    if detection.kind is InputKind.VERIFIER_REPORT:
        try:
            verifier_report = default_verifier_registry().convert(doc)
        except VerifierError as exc:
            notes.append(f"verifier output was recognised but not convertible: {exc}")

    if detection.kind is InputKind.ASSURANCE_ENVELOPE and isinstance(doc, list):
        seen = len(doc)
        ev, cl, art, cex, fbr, adv, exp, mapped, skipped, env_notes, seen_by_kind = \
            _envelope_records(doc, source, producer, execution=execution,
                              declared_consequence=declared_consequence)
        expectations.extend(exp)
        failed_branches.extend(fbr)
        evidence.extend(ev)
        claims.extend(cl)
        artifacts.extend(art)
        counterexamples.extend(cex)
        adversarial.extend(adv)
        notes.extend(env_notes)

    elif detection.kind in (InputKind.PROMPTFOO_EVAL, InputKind.PRODUCER_EXPORT):
        # Both through the producer contract: promptfoo is a registered adapter
        # that happens to have its own input kind, and every other registered
        # producer arrives as PRODUCER_EXPORT. Neither has a code path here.
        registry = producers if producers is not None else default_producer_registry()
        producer_type = ("promptfoo" if detection.kind is InputKind.PROMPTFOO_EVAL
                         else detection.adapter)
        try:
            produced = registry.normalise(doc, source=source,
                                          producer_type=producer_type)
        except ProducerContractError as exc:
            produced = ProducerNormalisation()
            notes.append(f"the {producer_type} producer recognised this document but "
                         f"could not read it: {exc}")
        evidence.extend(produced.evidence)
        claims.extend(produced.claims)
        seen, mapped = produced.records_seen, produced.records_mapped
        skipped.update(produced.skipped)
        notes.extend(produced.notes)

    elif execution is not None:
        seen = len(execution.nodes)
        mapped = seen
        # Every record counted here is an execution node release-gate rebuilt.
        # Left untallied, a trace's spans all read as "records no kind accounts
        # for — could not be classified" beside a mapping of N of N.
        seen_by_kind = {"execution": seen}
        # The spans are the producer's account of what happened. release-gate read
        # the file; it did not witness the run, so this is DECLARED (Invariant 1).
        evidence.append(EvidenceRecord.from_producer(
            {"nodes": len(execution.nodes), "edges": len(execution.edges),
             "completeness": execution.completeness.status.value},
            evidence_type=EvidenceType.TRACE, source=source, producer=producer,
            status=EpistemicStatus.DECLARED, applies_to_digest=file_digest,
            coverage_note=("execution as reported by the emitting system; release-gate "
                           "reconstructed the graph but did not observe the run")))

    elif verifier_report is not None:
        seen = verifier_report.records_seen
        mapped = verifier_report.records_mapped
        skipped.update(verifier_report.skipped)
        notes.extend(verifier_report.notes)
        # The tool's own account, recorded as DECLARED: release-gate read the file,
        # it did not watch the prover run, and it does not re-check the result.
        evidence.append(EvidenceRecord.from_producer(
            {"verifier": verifier_report.tool.to_dict(),
             "coverage": verifier_report.coverage.to_dict()},
            evidence_type=EvidenceType.FORMAL_PROOF, source=source,
            producer=Producer(producer_id=verifier_report.tool.reference,
                              kind=ProducerKind.TOOL,
                              identity_basis=("pinned-digest"
                                              if verifier_report.tool.pinned
                                              else "unauthenticated"),
                              version=verifier_report.tool.version or None),
            status=EpistemicStatus.DECLARED, applies_to_digest=file_digest,
            coverage_note="; ".join(verifier_report.coverage.does_not_cover)[:400]
                          or "the verifier stated no coverage limits"))

    elif detection.kind is InputKind.AUDIT_REPORT and isinstance(doc, Mapping):
        seen, mapped, extra = _audit_records(doc, source, evidence, file_digest,
                                             claims, expectations, artifacts)
        skipped.update(extra)

    else:
        notes.append(
            "the file was hashed and recorded, but nothing in it could be mapped to "
            "evidence, claims or execution")

    candidate = None
    if detection.kind is InputKind.ASSURANCE_ENVELOPE and isinstance(doc, list):
        candidate = _envelope_candidate(doc, notes)
    elif detection.kind is InputKind.AUDIT_REPORT and isinstance(doc, Mapping):
        from release_gate.assurance.static_producer import ScanProvenance
        candidate = ScanProvenance.from_report(doc).candidate_state(doc)

    return Normalisation(
        candidate=candidate,
        detection=detection, source=source, evidence=tuple(evidence),
        claims=tuple(claims), artifacts=tuple(artifacts), execution=execution,
        capabilities=capabilities, declared_consequence=tuple(declared_consequence),
        counterexamples=tuple(counterexamples), adversarial=tuple(adversarial),
        expectations=tuple(expectations),
        failed_branches=tuple(failed_branches), verifier_report=verifier_report,
        records_seen=seen, records_mapped=mapped,
        records_seen_by_kind=dict(seen_by_kind), skipped=dict(skipped),
        notes=tuple(notes), refused_consequence=tuple(refused_consequence))


def _envelope_candidate(doc: Sequence[Any], notes: List[str]) -> Optional[Any]:
    """The candidate an envelope states about itself, if it states exactly one."""
    from release_gate.assurance.candidate import (
        CandidateError, CandidateSource, CandidateState)
    stated: List[Any] = []
    for row in doc:
        if not (isinstance(row, Mapping) and row.get("record_type") == "candidate"):
            continue
        declared_by = ""
        producer = row.get("producer")
        if isinstance(producer, Mapping):
            declared_by = str(producer.get("producer_id") or "")
        elif isinstance(producer, str):
            declared_by = producer
        try:
            stated.append(CandidateState.from_dict(
                row, source=CandidateSource.DECLARED_BY_SUBMISSION,
                declared_by=declared_by or "the submission"))
        except (CandidateError, ValueError) as exc:
            notes.append(f"a candidate record could not be read and was not used: {exc}")
    distinct = {c.digest(): c for c in stated}
    if len(distinct) > 1:
        # Two descriptions of one release. Neither is chosen (Invariant 4); the
        # case falls back to its artifacts and says why.
        notes.append(f"the submission states {len(distinct)} different candidates; "
                     "none was used, and the case's own artifacts stand in")
        return None
    return next(iter(distinct.values()), None)


def _audit_records(doc: Mapping[str, Any], source: str,
                   evidence: List[EvidenceRecord], applies_to: str,
                   claims: Optional[List[Claim]] = None,
                   expectations: Optional[List[EvidenceExpectation]] = None,
                   artifacts: Optional[List[Artifact]] = None
                   ) -> Tuple[int, int, Dict[str, int]]:
    """release-gate's own audit output, folded in as a real assurance argument.

    The point of this function is that there is one product. Everything the
    ADMISSION plane already computes — static analysis, taint, agent tool
    boundaries, declared safeguards, its own coverage — becomes claims with
    evidence for and against them, so a software case gets criticality,
    contradiction detection, attention ranking, a packet and an approval binding
    exactly like a research case does.

    The conversion itself lives in `static_producer`, which is the one place an
    audit report becomes Universal Evidence; `release-gate audit --evidence-out`
    goes through the same producer. What this function adds is only where the
    results land. The report arrived as a document, so the producer is told it
    did not run the scan: attributing it to an in-process run would credit a
    file with having been produced here (§10ag.4).

    `applies_to` is the report's own digest. It is used only when the report
    carries no provenance block; otherwise evidence binds to the manifest of the
    exact files the scan read, and that code is registered as an artifact so the
    binding can be checked rather than merely stated.
    """
    from release_gate.assurance.static_producer import emit_from_report

    emission = emit_from_report(doc, source=source, report_digest=applies_to,
                                in_process=False)
    evidence.extend(emission.evidence)
    if claims is not None:
        claims.extend(emission.claims)
    if expectations is not None:
        expectations.extend(emission.expectations)
    mapped = emission.mapped - (0 if expectations is not None
                                else len(emission.expectations))
    if artifacts is not None:
        artifacts.extend(emission.artifacts)
    return mapped, mapped, {}


# ── the one-call path ────────────────────────────────────────────────────────

def ingest_path(path: str | Path, *, producers: Optional[Any] = None) -> Normalisation:
    """Read, identify and fold one file. The whole zero-config front door."""
    doc = load_input(path)
    detection = detect_document(doc, filename=Path(path).name, producers=producers)
    return normalise(doc, detection, source=str(path), producers=producers)
