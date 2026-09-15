"""A vendor-neutral event protocol, and the conversion that makes it records.

An agent framework does not need to know release-gate exists. That is the
constraint this module is written under: the twenty event classes below are a
*canonical form adapters target*, not a format anyone is required to emit. OTLP
spans carrying the GenAI semantic conventions convert without touching the
framework that produced them, and a team that has never heard of this vocabulary
still gets a case.

**Events become records; they are not a second lane.** Conversion produces the
same `EvidenceRecord`, `Claim`, `Artifact` and `VerificationAttempt` objects the
file and session paths produce, through the same constructors. Two intake paths
eventually disagree — one gains a validation rule the other lacks, and the same
evidence is accepted through one door and refused at the other — so there is one
set of record types and events are a source for them.

(Not to be confused with the protocol spec's `POST /cases/{id}/events`, which is
the universal door for the *record* envelope. That endpoint carries records; this
module carries things that happened. Both names are in the wild and neither is
worth renaming, so: records go through that door, and events described here
convert into records before reaching it.)

## What an event is, epistemically

**An event is a claim about what happened, made by whoever emitted it.** That is
the whole design. Status is assigned at the ingest boundary from what the emitter
has standing to say, and the twenty classes split cleanly in two:

* **Self-report** — `RUN_STARTED`, `TOOL_CALLED`, `ARTIFACT_CREATED`,
  `HUMAN_INTERVENTION` and the rest of the execution vocabulary. The emitter is
  the authority on its own execution: a framework saying it called a tool is the
  best evidence anyone will ever have that it called that tool. **OBSERVED.**

* **Judgement** — `CLAIM_SUPPORTED`, `VERIFICATION_COMPLETED`,
  `COUNTEREXAMPLE_FOUND`, `CONTRADICTION_RESOLVED` and the rest of the epistemic
  vocabulary. Here the emitter is asserting a conclusion about the world, and an
  assertion is not a finding however confidently it is serialised. **DECLARED.**

Two refusals follow from that split, and both are enforced rather than described:

1. **No event can produce `VERIFIED`.** A `VERIFICATION_COMPLETED` event records
   that a verifier reported a result; it does not make the thing verified.
   Otherwise self-certification costs one line of JSON, and the typed
   verification door — the only place VERIFIED is assigned, and only with a named
   method (Invariant 8) — would be a formality anyone could route around.

2. **`CONTRADICTION_RESOLVED` does not close a contradiction.** It records that
   somebody said it was closed. A contradiction is closed by evidence that
   answers it, never by an announcement and never by a different branch
   succeeding (Invariant 7).

## OpenTelemetry compatibility

The correlation fields are OTel's, by name and by meaning: `trace_id`,
`span_id`, `parent_span_id`, `timestamp_ns` (Unix nanoseconds), an `attributes`
bag, and `resource` attributes describing the emitting process. An OTLP span
becomes an event by reading its name and attributes; nothing needs a release-gate
SDK. Where OTel has a concept, this uses it rather than inventing a synonym.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.evidence import (
    EpistemicStatus, EvidenceRecord, EvidenceType, Producer, ProducerKind,
)

EVENT_SCHEMA_VERSION = 1


class EventError(ValueError):
    """An event that cannot be represented, or that asserts what it may not."""


class EventType(str, Enum):
    """The canonical vocabulary. Vendor-neutral by construction.

    Ordered by where they sit in a run rather than alphabetically, because the
    list is also documentation of the shape of a run.
    """

    CASE_CREATED = "CASE_CREATED"
    RUN_STARTED = "RUN_STARTED"
    AGENT_STARTED = "AGENT_STARTED"
    TASK_STARTED = "TASK_STARTED"
    TOOL_CALLED = "TOOL_CALLED"
    ARTIFACT_CREATED = "ARTIFACT_CREATED"
    ARTIFACT_MODIFIED = "ARTIFACT_MODIFIED"
    CLAIM_CREATED = "CLAIM_CREATED"
    CLAIM_SUPPORTED = "CLAIM_SUPPORTED"
    CLAIM_CHALLENGED = "CLAIM_CHALLENGED"
    ASSUMPTION_DECLARED = "ASSUMPTION_DECLARED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    COUNTEREXAMPLE_FOUND = "COUNTEREXAMPLE_FOUND"
    CONTRADICTION_OPENED = "CONTRADICTION_OPENED"
    CONTRADICTION_RESOLVED = "CONTRADICTION_RESOLVED"
    HUMAN_INTERVENTION = "HUMAN_INTERVENTION"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    RUN_COMPLETED = "RUN_COMPLETED"
    CASE_FINALIZED = "CASE_FINALIZED"

    @property
    def standing(self) -> EpistemicStatus:
        """What the emitter has standing to establish by saying this."""
        return (EpistemicStatus.OBSERVED if self in _SELF_REPORT
                else EpistemicStatus.DECLARED)

    @property
    def is_self_report(self) -> bool:
        """True when the emitter is the authority on what it is reporting."""
        return self in _SELF_REPORT


#: Events where the emitter reports its own execution. A framework saying it
#: called a tool is the best evidence anyone will have that it called that tool,
#: so these are OBSERVED. Everything not listed here is a judgement about the
#: world and is DECLARED — the default is the conservative one deliberately, so
#: a new event class added later is DECLARED until somebody argues otherwise.
_SELF_REPORT = frozenset({
    EventType.CASE_CREATED,
    EventType.RUN_STARTED,
    EventType.AGENT_STARTED,
    EventType.TASK_STARTED,
    EventType.TOOL_CALLED,
    EventType.ARTIFACT_CREATED,
    EventType.ARTIFACT_MODIFIED,
    EventType.VERIFICATION_STARTED,
    EventType.HUMAN_INTERVENTION,
    EventType.ACTION_PROPOSED,
    EventType.RUN_COMPLETED,
    EventType.CASE_FINALIZED,
})

#: Event -> the evidence type its record carries. Chosen so a converted event is
#: indistinguishable from the same fact submitted directly as a record.
_EVIDENCE_TYPE: Mapping[EventType, EvidenceType] = {
    EventType.CASE_CREATED: EvidenceType.OTHER,
    EventType.RUN_STARTED: EvidenceType.TRACE,
    EventType.AGENT_STARTED: EvidenceType.TRACE,
    EventType.TASK_STARTED: EvidenceType.TRACE,
    EventType.TOOL_CALLED: EvidenceType.TOOL_RESULT,
    EventType.ARTIFACT_CREATED: EvidenceType.CODE_ARTIFACT,
    EventType.ARTIFACT_MODIFIED: EvidenceType.CODE_ARTIFACT,
    EventType.CLAIM_CREATED: EvidenceType.CLAIM_DERIVATION,
    EventType.CLAIM_SUPPORTED: EvidenceType.ATTESTATION,
    EventType.CLAIM_CHALLENGED: EvidenceType.ATTESTATION,
    EventType.ASSUMPTION_DECLARED: EvidenceType.ATTESTATION,
    EventType.VERIFICATION_STARTED: EvidenceType.TRACE,
    EventType.VERIFICATION_COMPLETED: EvidenceType.ATTESTATION,
    EventType.COUNTEREXAMPLE_FOUND: EvidenceType.COUNTEREXAMPLE,
    EventType.CONTRADICTION_OPENED: EvidenceType.ATTESTATION,
    EventType.CONTRADICTION_RESOLVED: EvidenceType.ATTESTATION,
    EventType.HUMAN_INTERVENTION: EvidenceType.HUMAN_REVIEW,
    EventType.ACTION_PROPOSED: EvidenceType.OTHER,
    EventType.RUN_COMPLETED: EvidenceType.TRACE,
    EventType.CASE_FINALIZED: EvidenceType.OTHER,
}

_HEX = re.compile(r"^[0-9a-f]+$")


def _clean_id(value: Any, field_name: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        if required:
            raise EventError(f"an event must carry a {field_name}")
        return ""
    if len(text) > 200:
        raise EventError(f"{field_name} is longer than 200 characters")
    return text


@dataclass(frozen=True)
class AssuranceEvent:
    """One thing that happened, said by whoever emitted it.

    The correlation fields are OpenTelemetry's, by name and meaning, so an OTLP
    span converts without a translation table: `trace_id` groups a run,
    `span_id`/`parent_span_id` carry causality, `timestamp_ns` is Unix
    nanoseconds, `attributes` is the span's attribute bag and `resource`
    describes the emitting process.
    """

    event_type: EventType
    emitter: Producer
    timestamp_ns: int = 0
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    #: What the event is about — a claim id, an artifact id, a tool name. The
    #: conversion needs it for every event that names something.
    subject_ref: str = ""
    #: Completeness carriers (§10g). Optional, and a stream that supplies none is
    #: simply one with no shape for a hole to show up in — which is itself worth
    #: reporting rather than reading as "nothing was missing".
    stream_id: str = ""
    sequence: Optional[int] = None
    event_counter: Optional[int] = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    resource: Mapping[str, Any] = field(default_factory=dict)
    #: OTel span status. ERROR is preserved rather than discarded: a failed tool
    #: call is evidence, and a run that reports its own failure is telling the
    #: truth about itself.
    status: str = "UNSET"
    detail: str = ""

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "event_type", EventType(self.event_type))
        except ValueError as exc:
            # Refused rather than dropped. An emitter using a name this protocol
            # does not know has told us something we cannot represent, and
            # silently discarding it would understate what the run did.
            raise EventError(
                f"{self.event_type!r} is not an event class this protocol defines. "
                f"Known: {', '.join(e.value for e in EventType)}") from exc
        if not isinstance(self.emitter, Producer):
            raise EventError(
                "an event must name its emitter: status is assigned from who is "
                "speaking, so an anonymous event cannot be given one")
        status = str(self.status or "UNSET").strip().upper()
        if status not in ("UNSET", "OK", "ERROR"):
            raise EventError(
                f"status {self.status!r} is not an OTel span status "
                "(UNSET, OK, ERROR)")
        object.__setattr__(self, "status", status)
        for name in ("trace_id", "span_id", "parent_span_id", "subject_ref",
                     "stream_id"):
            object.__setattr__(self, name, _clean_id(getattr(self, name), name))
        for name in ("sequence", "event_counter"):
            value = getattr(self, name)
            if value is not None:
                try:
                    object.__setattr__(self, name, int(value))
                except (TypeError, ValueError) as exc:
                    raise EventError(
                        f"{name} must be a whole number, not {value!r}") from exc
        try:
            object.__setattr__(self, "timestamp_ns", max(0, int(self.timestamp_ns or 0)))
        except (TypeError, ValueError) as exc:
            raise EventError(
                f"timestamp_ns must be Unix nanoseconds, not {self.timestamp_ns!r}"
            ) from exc
        object.__setattr__(self, "attributes", dict(self.attributes or {}))
        object.__setattr__(self, "resource", dict(self.resource or {}))

    @property
    def standing(self) -> EpistemicStatus:
        """The status this event's record carries. Never VERIFIED.

        Read from the event class, not from the emitter's opinion of itself: an
        event that asserted its own status would be the self-certification this
        protocol exists to prevent.
        """
        return self.event_type.standing

    @property
    def event_id(self) -> str:
        """Content-addressed, so the same event submitted twice is one event."""
        return short_id("evt", digest_object(self._identity()))

    def _identity(self) -> Dict[str, Any]:
        return {"event_type": self.event_type.value,
                "emitter": self.emitter.producer_id,
                "timestamp_ns": self.timestamp_ns, "trace_id": self.trace_id,
                "span_id": self.span_id, "parent_span_id": self.parent_span_id,
                "subject_ref": self.subject_ref, "attributes": dict(self.attributes),
                "stream_id": self.stream_id, "sequence": self.sequence,
                "event_counter": self.event_counter,
                "status": self.status, "detail": self.detail}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_event", "event_id": self.event_id,
                "event_type": self.event_type.value,
                "standing": self.standing.value,
                "emitter": self.emitter.to_dict(),
                "timestamp_ns": self.timestamp_ns, "trace_id": self.trace_id,
                "span_id": self.span_id, "parent_span_id": self.parent_span_id,
                "subject_ref": self.subject_ref, "attributes": dict(self.attributes),
                "stream_id": self.stream_id, "sequence": self.sequence,
                "event_counter": self.event_counter,
                "resource": dict(self.resource), "status": self.status,
                "detail": self.detail, "schema_version": EVENT_SCHEMA_VERSION}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AssuranceEvent":
        if not isinstance(data, Mapping):
            raise EventError("an event must be a JSON object")
        emitter = data.get("emitter")
        if isinstance(emitter, Mapping):
            emitter = Producer.from_dict(emitter)
        elif isinstance(emitter, str):
            emitter = Producer(producer_id=emitter, kind=ProducerKind.EXTERNAL)
        return cls(
            event_type=data.get("event_type", ""), emitter=emitter,
            timestamp_ns=data.get("timestamp_ns", 0),
            trace_id=data.get("trace_id", ""), span_id=data.get("span_id", ""),
            parent_span_id=data.get("parent_span_id", ""),
            subject_ref=data.get("subject_ref", ""),
            attributes=data.get("attributes") or {},
            stream_id=data.get("stream_id", ""), sequence=data.get("sequence"),
            event_counter=data.get("event_counter"),
            resource=data.get("resource") or {},
            status=data.get("status", "UNSET"), detail=data.get("detail", ""))


def _ordered(events: Iterable[AssuranceEvent]) -> List[AssuranceEvent]:
    """Events in run order, stably.

    Sorted on timestamp with the original position as tiebreak, so events sharing
    a timestamp — common when a framework stamps a whole batch at once — keep the
    order they arrived in rather than being permuted by the sort.
    """
    return [e for _, _, e in sorted(
        ((e.timestamp_ns, i, e) for i, e in enumerate(events)),
        key=lambda t: (t[0], t[1]))]


@dataclass(frozen=True)
class EventConversion:
    """What a stream of events became, and what it could not express."""

    records: Tuple[Mapping[str, Any], ...] = ()
    events_seen: int = 0
    events_mapped: int = 0
    notes: Tuple[str, ...] = ()

    @property
    def skipped(self) -> int:
        return self.events_seen - self.events_mapped

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "event_conversion", "records": len(self.records),
                "events_seen": self.events_seen, "events_mapped": self.events_mapped,
                "skipped": self.skipped, "notes": list(self.notes)}


def events_to_records(events: Iterable[AssuranceEvent]) -> EventConversion:
    """Convert events into the records a case is built from.

    The output is the ordinary record envelope — the same NDJSON a client would
    POST or a file would carry — so a case built from events and a case built
    from records go through one set of constructors and one set of rules.

    Nothing here assigns VERIFIED, and nothing here closes a contradiction. Those
    are the two things an event stream is structurally not allowed to do, and
    they are absent by construction rather than by a check that could be edited
    out: this function only ever emits DECLARED or OBSERVED status, and it emits
    no `resolved` flag on anything.
    """
    ordered = _ordered(events)
    records: List[Mapping[str, Any]] = []
    notes: List[str] = []
    mapped = 0
    claims_seen: Dict[str, Dict[str, Any]] = {}

    for event in ordered:
        kind = event.event_type
        base = {
            "producer": event.emitter.to_dict(),
            "epistemic_status": event.standing.value,
            "coverage_note": _coverage_note(event),
            "content": {"event_type": kind.value, "event_id": event.event_id,
                        "trace_id": event.trace_id, "span_id": event.span_id,
                        "parent_span_id": event.parent_span_id,
                        "timestamp_ns": event.timestamp_ns,
                        "otel_status": event.status,
                        **dict(event.attributes)},
        }

        if kind in (EventType.CLAIM_CREATED, EventType.ASSUMPTION_DECLARED):
            if not event.subject_ref:
                notes.append(f"{kind.value} names no claim, so nothing was created")
                continue
            claim = claims_seen.setdefault(event.subject_ref, {
                "record_type": "claim", "claim_id": event.subject_ref,
                "proposition": str(event.attributes.get("proposition")
                                   or event.detail or event.subject_ref),
                "producer": event.emitter.to_dict(),
                "supporting_evidence": [], "contradicting_evidence": []})
            if kind is EventType.ASSUMPTION_DECLARED:
                claim["claim_type"] = "ASSUMPTION"
            records.append(claim)
            mapped += 1
            continue

        if kind in (EventType.CLAIM_SUPPORTED, EventType.CLAIM_CHALLENGED,
                    EventType.COUNTEREXAMPLE_FOUND):
            if not event.subject_ref:
                notes.append(f"{kind.value} names no claim, so it bears on nothing")
                continue
            side = ("supports_claims" if kind is EventType.CLAIM_SUPPORTED
                    else "contradicts_claims")
            records.append({"record_type": "evidence",
                            "evidence_id": event.event_id,
                            "kind": _EVIDENCE_TYPE[kind].value,
                            side: [event.subject_ref], **base})
            mapped += 1
            continue

        if kind in (EventType.ARTIFACT_CREATED, EventType.ARTIFACT_MODIFIED):
            digest = str(event.attributes.get("digest") or "")
            if not digest:
                # An artifact with no digest cannot be checked for drift later,
                # which is most of what an artifact record is for. Recorded as
                # evidence so the event is not lost, and noted so the gap is
                # visible rather than looking like an artifact that never moved.
                notes.append(
                    f"{kind.value} for {event.subject_ref or 'an artifact'} carries "
                    "no digest, so it was recorded as evidence and cannot be "
                    "checked for mutation")
            else:
                records.append({"record_type": "artifact",
                                "logical_id": event.subject_ref or event.event_id,
                                "digest": digest,
                                "digest_status": "DECLARED",
                                "artifact_kind": str(event.attributes.get(
                                    "artifact_kind") or "OTHER")})
            records.append({"record_type": "evidence", "evidence_id": event.event_id,
                            "kind": _EVIDENCE_TYPE[kind].value, **base})
            mapped += 1
            continue

        if kind is EventType.VERIFICATION_COMPLETED:
            # DECLARED, always. A verifier reporting a result is a verifier
            # reporting a result; VERIFIED is assigned only through the typed
            # verification door with a named method (Invariant 8), and if an
            # event could mint it then self-certification would cost one line of
            # JSON. The outcome the emitter reported is preserved in the content
            # so a reader can see what was claimed.
            records.append({"record_type": "evidence", "evidence_id": event.event_id,
                            "kind": _EVIDENCE_TYPE[kind].value,
                            **({"supports_claims": [event.subject_ref]}
                               if event.subject_ref and event.status != "ERROR" else {}),
                            **({"contradicts_claims": [event.subject_ref]}
                               if event.subject_ref and event.status == "ERROR" else {}),
                            **base})
            mapped += 1
            continue

        if kind in (EventType.CONTRADICTION_OPENED, EventType.CONTRADICTION_RESOLVED):
            # Deliberately NOT a contradiction record with a `resolved` flag.
            # Release-gate detects contradictions structurally, from evidence
            # pointing both ways at one claim, and closes them on evidence that
            # answers them. An emitter announcing either is making a statement
            # about the case, which is what this records — a statement.
            if kind is EventType.CONTRADICTION_RESOLVED:
                notes.append(
                    f"{kind.value} from {event.emitter.producer_id} is recorded as a "
                    "declaration and does not close anything: a contradiction is "
                    "closed by evidence that answers it (Invariant 7)")
            records.append({"record_type": "evidence", "evidence_id": event.event_id,
                            "kind": _EVIDENCE_TYPE[kind].value, **base})
            mapped += 1
            continue

        # Everything else is execution the emitter is entitled to report.
        records.append({"record_type": "evidence", "evidence_id": event.event_id,
                        "kind": _EVIDENCE_TYPE[kind].value, **base})
        mapped += 1

    # Execution events also become an `execution` record carrying the native
    # trace shape. Without this, routing telemetry through the event protocol
    # would build no execution graph while the older OTLP->trace adapter does —
    # so the vendor-neutral door would be strictly worse than the one it
    # generalises, and `execution_reconstruction` would read NOT_ASSESSED on a
    # run whose every tool call was reported.
    for trace in _traces_from(ordered):
        records.append(trace)

    return EventConversion(records=tuple(records), events_seen=len(ordered),
                           events_mapped=mapped, notes=tuple(dict.fromkeys(notes)))


#: Events that describe execution, and the native step each becomes. Ordered by
#: the run, so the reconstructed spine matches what happened.
_EXECUTION_STEP: Mapping[EventType, str] = {
    EventType.AGENT_STARTED: "agent",
    EventType.TASK_STARTED: "llm_call",
    EventType.TOOL_CALLED: "tool_call",
}


def _traces_from(ordered: Sequence[AssuranceEvent]) -> List[Mapping[str, Any]]:
    """Execution events as native traces, one per `trace_id`.

    Grouped by trace id because that is what OTel already uses to mean "one run",
    so a stream covering several runs reconstructs several spines rather than one
    spliced fiction.
    """
    by_trace: Dict[str, List[Dict[str, Any]]] = {}
    for event in ordered:
        step_kind = _EXECUTION_STEP.get(event.event_type)
        if step_kind is None:
            continue
        step: Dict[str, Any] = {"type": step_kind}
        if step_kind == "tool_call":
            step["tool"] = event.subject_ref or str(
                event.attributes.get("gen_ai.tool.name") or "unnamed-tool")
            args = event.attributes.get("arguments")
            if isinstance(args, Mapping):
                step["args"] = dict(args)
        elif step_kind == "llm_call":
            model = event.attributes.get("gen_ai.request.model")
            if model:
                step["model"] = str(model)
        else:
            step["name"] = event.subject_ref or "agent"
        by_trace.setdefault(event.trace_id or "events", []).append(step)
    return [{"record_type": "execution", "trace_id": trace_id, "steps": steps}
            for trace_id, steps in by_trace.items() if steps]


def _coverage_note(event: AssuranceEvent) -> str:
    who = event.emitter.producer_id or "an unnamed emitter"
    if event.event_type.is_self_report:
        return (f"{event.event_type.value} reported by {who} about its own "
                "execution; OBSERVED because the emitter is the authority on "
                "what it did")
    return (f"{event.event_type.value} asserted by {who}; DECLARED because this "
            "is the emitter's judgement about the world, not a finding")


# ── adapters: existing telemetry, unchanged frameworks ──────────────────────
#
# The constraint from the product contract is that a framework must not have to
# emit release-gate events when an adapter can convert what it already produces.
# So this is the direction that matters: OTLP in, canonical events out, nothing
# installed on the emitting side.

#: OTel GenAI operation names -> event class. The GenAI semantic conventions are
#: the vendor-neutral ground truth here: any backend that exports OTLP/JSON with
#: `gen_ai.*` attributes converts, which is most of the instrumented ecosystem.
_GENAI_OPERATION: Mapping[str, EventType] = {
    "chat": EventType.TASK_STARTED,
    "text_completion": EventType.TASK_STARTED,
    "generate_content": EventType.TASK_STARTED,
    "completion": EventType.TASK_STARTED,
    "embeddings": EventType.TASK_STARTED,
    "execute_tool": EventType.TOOL_CALLED,
    "tool": EventType.TOOL_CALLED,
    "invoke_agent": EventType.AGENT_STARTED,
    "create_agent": EventType.AGENT_STARTED,
    "agent": EventType.AGENT_STARTED,
}

#: An emitter that already speaks this vocabulary can say so directly, on a span
#: attribute. Checked before the GenAI mapping so a framework that has adopted
#: the protocol is taken at its word about which class its span is.
_EVENT_TYPE_ATTRIBUTE = "assurance.event_type"


def events_from_otlp(doc: Any, *,
                     default_emitter: Optional[Producer] = None
                     ) -> Tuple[List[AssuranceEvent], List[str]]:
    """Convert OTLP/JSON spans into canonical events. No framework changes.

    Returns the events and the notes about what could not be mapped. A span with
    no GenAI attributes and no explicit event type is **skipped and counted**
    rather than guessed at: an HTTP or database span from the same trace is real
    work, but it is not something this vocabulary has a class for, and inventing
    one would put words in the emitter's mouth.

    The emitter is read from OTel resource attributes (`service.name`), because
    that is where OTel already records who is speaking and status depends on
    knowing that.
    """
    from release_gate.adapters.common import (
        iter_otlp_spans, otlp_attributes, span_start_ns)

    events: List[AssuranceEvent] = []
    notes: List[str] = []
    unmapped = 0

    for span, resource_attrs in iter_otlp_spans(doc):
        # `iter_otlp_spans` yields resource attributes ALREADY FLATTENED, not the
        # raw resource object. Re-flattening them produced an empty mapping and
        # silently lost `service.name`, so every span was attributed to an
        # unidentified emitter — and since status is assigned from who is
        # speaking, that is not a cosmetic loss.
        attrs = otlp_attributes(span.get("attributes", []))
        resource_attrs = dict(resource_attrs or {})

        declared = str(attrs.get(_EVENT_TYPE_ATTRIBUTE) or "").strip()
        if declared:
            try:
                event_type = EventType(declared.upper())
            except ValueError:
                notes.append(
                    f"span declares {_EVENT_TYPE_ATTRIBUTE}={declared!r}, which is "
                    "not an event class this protocol defines; span skipped")
                unmapped += 1
                continue
        else:
            operation = str(attrs.get("gen_ai.operation.name") or "").strip().lower()
            event_type = _GENAI_OPERATION.get(operation)
            if event_type is None:
                unmapped += 1
                continue

        emitter = default_emitter or _emitter_from(resource_attrs, attrs)
        subject = str(attrs.get("gen_ai.tool.name")
                      or attrs.get("assurance.subject_ref")
                      or attrs.get("gen_ai.agent.name") or "").strip()
        # Completeness carriers off span attributes, so a producer that already
        # numbers its output gets gap detection without a release-gate SDK.
        stream_id = str(attrs.get("assurance.stream_id") or "").strip()
        sequence = _as_int(attrs.get("assurance.sequence"))
        counter = _as_int(attrs.get("assurance.event_counter"))

        events.append(AssuranceEvent(
            event_type=event_type, emitter=emitter,
            timestamp_ns=span_start_ns(span),
            trace_id=str(span.get("traceId") or span.get("trace_id") or ""),
            span_id=str(span.get("spanId") or span.get("span_id") or ""),
            parent_span_id=str(span.get("parentSpanId")
                               or span.get("parent_span_id") or ""),
            subject_ref=subject, stream_id=stream_id, sequence=sequence,
            event_counter=counter,
            attributes={k: v for k, v in attrs.items()
                        if k.startswith("gen_ai.") or k.startswith("assurance.")},
            resource=resource_attrs,
            status=_otel_status(span),
            detail=str(span.get("name") or "")))

    if unmapped:
        notes.append(
            f"{unmapped} span(s) carried neither GenAI attributes nor an explicit "
            f"{_EVENT_TYPE_ATTRIBUTE}, so this protocol has no class for them and "
            "they were skipped rather than guessed at")
    return events, notes


def _as_int(value: Any) -> Optional[int]:
    """A span attribute as a whole number, or None when it is not one.

    OTLP carries everything as a string often enough that refusing a numeric
    string here would silently disable gap detection for most real producers.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _emitter_from(resource_attrs: Mapping[str, Any],
                  attrs: Mapping[str, Any]) -> Producer:
    """Who is speaking, from OTel resource attributes.

    `service.name` is where OTel already records this, so nothing new has to be
    instrumented. An unnamed service becomes an EXTERNAL producer called what it
    is — unidentified — rather than being attributed to anybody.
    """
    name = str(resource_attrs.get("service.name")
               or attrs.get("gen_ai.agent.name")
               or attrs.get("gen_ai.system") or "").strip()
    if not name:
        return Producer(producer_id="otel://unidentified", kind=ProducerKind.EXTERNAL)
    kind = (ProducerKind.AGENT if attrs.get("gen_ai.agent.name")
            else ProducerKind.EXTERNAL)
    return Producer(producer_id=f"otel://{name}", kind=kind)


def _otel_status(span: Mapping[str, Any]) -> str:
    """OTel span status -> the three values this protocol carries."""
    raw = (span.get("status") or {})
    code = str(raw.get("code") or raw.get("statusCode") or "").strip().upper()
    if code in ("STATUS_CODE_ERROR", "ERROR", "2"):
        return "ERROR"
    if code in ("STATUS_CODE_OK", "OK", "1"):
        return "OK"
    return "UNSET"
