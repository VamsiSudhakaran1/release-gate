"""Selective omission as a first-class threat (Invariant 13).

Every other analysis in this system reasons about evidence that *arrived*. This
one reasons about evidence that did not, which is the harder and more important
question: a producer that wants a clean verdict does not forge a passing test, it
declines to mention the failing one. Nothing downstream can see that. The only
defences are structural — a shape in the stream that a hole shows up in — and
declarative, and the two are worth very different amounts.

**Derived detection is worth a great deal.** A span naming a parent that never
arrived, a sequence with a hole in it, a counter that went backwards: these are
observations release-gate makes about the stream's own structure, and a producer
suppressing a record has to suppress the structure too. Omission becomes visible
rather than silent.

**Declaration is worth much less, and signing does not change that.** A producer
stating "that was all of it" is telling you what it chose to say about what it
chose to send. Signing the statement establishes *who said it* — which matters
for attribution and not at all for completeness (Invariant 11: provenance is not
trust). A party that omitted a record omits it from its own manifest too, and its
signature over that manifest is perfectly valid.

That asymmetry is the whole design, and it is why `COMPLETE` is so tightly
guarded below.

## On having a COMPLETE value at all

`ExecutionCompleteness` in `execution_graph.py` deliberately has none, on the
grounds that nothing observable about received telemetry establishes that nothing
was withheld. That reasoning is correct for what it covers: raw spans, with no
independent statement of what should have been there.

This module has a value it does not, because it can require something that graph
cannot: an **enumerated expectation from a party other than the producer**, every
one of those ids present, and no derived gap anywhere in the stream. Under those
three conditions `COMPLETE` says something real and bounded — *complete against
that enumeration*. It never means "nothing is missing" in an absolute sense,
because the independent party could itself have been told a shorter story, and
`to_dict` says so in the row a human reads.

The guard that makes this safe is one line in `status`: a self-certified
expectation can never reach COMPLETE, whatever else is true. A producer counting
its own output is the case Invariant 13 exists for, and it is the common case.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id

COMPLETENESS_SCHEMA_VERSION = 1


class CompletenessError(ValueError):
    """A completeness declaration that cannot be represented."""


class StreamCompleteness(str, Enum):
    """What can be said about whether a stream is whole.

    Ordered worst-known to best-known for reading, not for comparison: these are
    different kinds of answer rather than points on a scale, and
    `COMPLETENESS_UNKNOWN` in particular is not "bad" — it is the honest default
    when nobody supplied anything to check against.
    """

    #: Gaps were positively detected: a hole in a sequence, a span whose parent
    #: never arrived, a counter that went backwards, a declared source silent.
    KNOWN_GAPS = "KNOWN_GAPS"
    #: An enumeration exists and some of it arrived. What is missing is named.
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    #: Complete *against an independent enumeration*, with no gap detected.
    #: Never reachable from a producer's account of its own output.
    COMPLETE = "COMPLETE"
    #: Nothing states what should have been here, so nothing can be checked.
    #: The default, and the correct answer far more often than the others.
    COMPLETENESS_UNKNOWN = "COMPLETENESS_UNKNOWN"


@dataclass(frozen=True)
class EndOfStream:
    """A producer's statement that a stream is finished.

    `declared_by` is who said it, and is the field that decides everything: when
    it differs from the stream's producer the declaration is independent, and
    when it does not the declaration is the producer's account of its own output
    and cannot establish completeness however it is signed.

    `signature_id` records that a signature was presented and whose it is. This
    module does not verify it, and verification would not change the epistemics:
    a valid signature over an incomplete manifest is a valid signature.
    """

    declared_by: str
    final_sequence: Optional[int] = None
    record_count: Optional[int] = None
    signature_id: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if not str(self.declared_by or "").strip():
            raise CompletenessError(
                "an end-of-stream attestation must name who declared it: an "
                "anonymous completion claim cannot be weighed against the "
                "producer, which is the only thing that makes it worth anything")
        object.__setattr__(self, "declared_by", str(self.declared_by).strip())
        for name in ("final_sequence", "record_count"):
            value = getattr(self, name)
            if value is not None:
                try:
                    object.__setattr__(self, name, int(value))
                except (TypeError, ValueError) as exc:
                    raise CompletenessError(
                        f"{name} must be a whole number, not {value!r}") from exc

    def to_dict(self) -> Dict[str, Any]:
        return {"declared_by": self.declared_by, "final_sequence": self.final_sequence,
                "record_count": self.record_count, "signature_id": self.signature_id,
                "signature_verified": False, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EndOfStream":
        return cls(declared_by=data.get("declared_by", ""),
                   final_sequence=data.get("final_sequence"),
                   record_count=data.get("record_count"),
                   signature_id=data.get("signature_id", ""),
                   detail=data.get("detail", ""))


@dataclass(frozen=True)
class SourceStream:
    """One identified stream of records from one producer, and its gaps.

    A stream id matters because omission hides in aggregation: ten producers
    folded into one undifferentiated pile has no shape for a hole to show up in,
    while ten separately identified streams each have a sequence a gap interrupts.
    """

    stream_id: str
    producer_id: str = ""
    #: Sequence numbers actually seen. Held as a set because streams arrive out
    #: of order routinely and that is not itself a gap.
    observed_sequences: Tuple[int, ...] = ()
    #: What the sequence should span, when something states it.
    expected_first: Optional[int] = None
    expected_last: Optional[int] = None
    #: Monotonic counter readings in arrival order. A counter going backwards is
    #: evidence of replay or reordering, which is a different fault from a hole.
    counter_readings: Tuple[int, ...] = ()
    end_of_stream: Optional[EndOfStream] = None
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not str(self.stream_id or "").strip():
            raise CompletenessError("a source stream must carry a stream_id")
        object.__setattr__(self, "stream_id", str(self.stream_id).strip())
        object.__setattr__(self, "observed_sequences",
                           tuple(sorted({int(s) for s in self.observed_sequences})))
        object.__setattr__(self, "counter_readings",
                           tuple(int(c) for c in self.counter_readings))

    # ── the derived detectors ───────────────────────────────────────────────

    @property
    def sequence_gaps(self) -> Tuple[int, ...]:
        """Sequence numbers missing from the range that arrived.

        Derived from the stream's own shape, so it needs nobody's declaration:
        if 1, 2 and 4 arrive then 3 was not sent, whatever any manifest says.
        Bounded by what arrived unless an expected range widens it — absent a
        declaration this cannot see a record dropped from either end, which is
        stated rather than papered over.
        """
        if not self.observed_sequences:
            return ()
        first = (self.expected_first if self.expected_first is not None
                 else self.observed_sequences[0])
        last = (self.expected_last if self.expected_last is not None
                else self.observed_sequences[-1])
        present = set(self.observed_sequences)
        return tuple(n for n in range(first, last + 1) if n not in present)

    @property
    def counter_regressions(self) -> Tuple[Tuple[int, int], ...]:
        """Places a monotonic counter went backwards, as (previous, next)."""
        out: List[Tuple[int, int]] = []
        for previous, nxt in zip(self.counter_readings, self.counter_readings[1:]):
            if nxt < previous:
                out.append((previous, nxt))
        return tuple(out)

    @property
    def truncated_tail(self) -> bool:
        """The attestation names a final sequence that never arrived."""
        eos = self.end_of_stream
        if eos is None or eos.final_sequence is None or not self.observed_sequences:
            return False
        return self.observed_sequences[-1] < eos.final_sequence

    @property
    def count_shortfall(self) -> Optional[int]:
        """How many records an attested count says are missing, if it says one."""
        eos = self.end_of_stream
        if eos is None or eos.record_count is None:
            return None
        return max(0, eos.record_count - len(self.observed_sequences))

    @property
    def self_certified(self) -> bool:
        """The party that produced the stream also declared it finished.

        The case Invariant 13 exists for, and the common one. Such a declaration
        can be perfectly honest and still cannot detect an omission, because
        whatever was left out of the stream was left out of the declaration with
        it.
        """
        eos = self.end_of_stream
        if eos is None:
            return False
        return bool(self.producer_id) and eos.declared_by == self.producer_id

    @property
    def gaps(self) -> Tuple[str, ...]:
        """Every gap detected in this stream, as readable statements."""
        out: List[str] = []
        if self.sequence_gaps:
            shown = ", ".join(str(n) for n in self.sequence_gaps[:8])
            out.append(f"{len(self.sequence_gaps)} sequence number(s) never arrived "
                       f"in {self.stream_id}: {shown}")
        for previous, nxt in self.counter_regressions:
            out.append(f"the monotonic counter on {self.stream_id} went backwards "
                       f"({previous} then {nxt}), so records were replayed or "
                       "reordered and the stream is not a faithful record of order")
        if self.truncated_tail:
            eos = self.end_of_stream
            out.append(f"{self.stream_id} was attested complete to sequence "
                       f"{eos.final_sequence} but stops at "
                       f"{self.observed_sequences[-1]}")
        shortfall = self.count_shortfall
        if shortfall:
            out.append(f"{self.stream_id} was attested to carry "
                       f"{self.end_of_stream.record_count} record(s) and "
                       f"{len(self.observed_sequences)} arrived")
        return tuple(out)

    def to_dict(self) -> Dict[str, Any]:
        return {"stream_id": self.stream_id, "producer_id": self.producer_id,
                "observed": len(self.observed_sequences),
                "sequence_gaps": list(self.sequence_gaps),
                "counter_regressions": [list(p) for p in self.counter_regressions],
                "truncated_tail": self.truncated_tail,
                "count_shortfall": self.count_shortfall,
                "self_certified": self.self_certified,
                "end_of_stream": (self.end_of_stream.to_dict()
                                  if self.end_of_stream else None),
                "gaps": list(self.gaps), "notes": list(self.notes)}


@dataclass(frozen=True)
class StreamLedger:
    """Every identified stream in a case, and what can be said about the whole.

    The ledger is the object a methodology asks and a packet reports. Its status
    is the conservative fold of its streams: one stream with a hole makes the
    whole record one with a hole in it, because a decision rests on the union.
    """

    streams: Tuple[SourceStream, ...] = ()
    #: Streams a manifest promised that never reported at all — the strongest
    #: omission signal there is, since a stream that is entirely absent leaves no
    #: internal shape for any other detector to catch.
    expected_streams: Tuple[str, ...] = ()
    #: True when the enumeration of expected streams came from someone other than
    #: the producers being counted. The single field COMPLETE depends on.
    enumeration_independent: bool = False
    enumeration_source: str = ""
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "streams", tuple(self.streams))
        object.__setattr__(self, "expected_streams",
                           tuple(sorted({str(s).strip() for s in self.expected_streams
                                         if str(s).strip()})))

    @property
    def observed_streams(self) -> Tuple[str, ...]:
        return tuple(sorted({s.stream_id for s in self.streams}))

    @property
    def silent_streams(self) -> Tuple[str, ...]:
        """Expected streams that produced nothing at all."""
        return tuple(sorted(set(self.expected_streams) - set(self.observed_streams)))

    @property
    def gaps(self) -> Tuple[str, ...]:
        out: List[str] = []
        for stream_id in self.silent_streams:
            out.append(f"{stream_id} was expected and never reported at all; a "
                       "stream that is entirely absent leaves no internal "
                       "structure for any other check to catch")
        for stream in self.streams:
            out.extend(stream.gaps)
        return tuple(out)

    @property
    def any_self_certified(self) -> bool:
        return any(s.self_certified for s in self.streams)

    @property
    def uncheckable_streams(self) -> Tuple[str, ...]:
        """Streams with no shape in which a gap could show.

        A stream that arrived without sequence numbers cannot be checked for
        holes: whatever was dropped from it left no trace, so "no gap detected"
        is a statement about the detector rather than the stream.
        `unknown_completeness_sources` has always reported these; the fold used
        to disagree with it and call the whole ledger COMPLETE.
        """
        return tuple(sorted(s.stream_id for s in self.streams
                            if not s.observed_sequences and not s.counter_readings))

    @property
    def status(self) -> StreamCompleteness:
        """The fold. `COMPLETE` is guarded by four conditions, not one."""
        if self.gaps:
            return StreamCompleteness.KNOWN_GAPS
        if not self.expected_streams:
            # Nothing enumerates what should have been here. No gap was seen, and
            # that is not the same as there being none.
            return StreamCompleteness.COMPLETENESS_UNKNOWN
        if set(self.observed_streams) < set(self.expected_streams):
            return StreamCompleteness.PARTIALLY_COMPLETE
        if not self.enumeration_independent:
            # The guard this module exists for. Everything checks out against a
            # list the counted party wrote, which is exactly what an omission
            # looks like from the inside.
            return StreamCompleteness.PARTIALLY_COMPLETE
        if self.uncheckable_streams:
            # The conservative fold this class documents: one stream nothing
            # could be detected in makes the whole record one whose completeness
            # was not established, because the decision rests on the union.
            return StreamCompleteness.COMPLETENESS_UNKNOWN
        return StreamCompleteness.COMPLETE

    def note(self) -> str:
        """What the status means, and — more importantly — what it does not."""
        status = self.status
        if status is StreamCompleteness.COMPLETE:
            return (f"Every stream {self.enumeration_source or 'the enumeration'} "
                    "names arrived, and no sequence gap, counter regression or "
                    "truncated tail was detected in any of them. This is complete "
                    "AGAINST THAT ENUMERATION. It does not establish that nothing "
                    "exists which the enumeration itself failed to mention.")
        if status is StreamCompleteness.PARTIALLY_COMPLETE:
            if self.silent_streams:
                return (f"{len(self.silent_streams)} expected stream(s) never "
                        "reported. What is held is a subset of what was expected.")
            return ("What arrived matches the enumeration, but the enumeration "
                    "came from the party being counted, so it cannot detect an "
                    "omission: whatever was left out of the evidence was left out "
                    "of the count with it (Invariant 13).")
        if status is StreamCompleteness.KNOWN_GAPS:
            return (f"{len(self.gaps)} gap(s) were positively detected. What is "
                    "held describes part of what happened, and the missing part is "
                    "named rather than assumed absent.")
        if not self.expected_streams:
            # The more fundamental reason, and so the one reported first: without
            # an enumeration you do not know a missing stream was ever expected.
            return ("Nothing states what should have been here, so arrival cannot "
                    "be checked against anything. No gap was observed; that is not "
                    "the same as there being none.")
        if self.uncheckable_streams:
            return (f"{len(self.uncheckable_streams)} stream(s) arrived with no "
                    "sequence numbering — "
                    + ", ".join(self.uncheckable_streams[:4])
                    + " — so a hole in them would leave no trace. Every stream the "
                      "enumeration names did arrive. No gap was observed in these; "
                      "that is a fact about the detector, not about the stream.")
        return ("Nothing states what should have been here, so arrival cannot be "
                "checked against anything. No gap was observed; that is not the "
                "same as there being none.")

    @property
    def ledger_id(self) -> str:
        return short_id("cmpl", digest_object(
            {"streams": [s.to_dict() for s in self.streams],
             "expected": list(self.expected_streams),
             "independent": self.enumeration_independent}))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "stream_completeness", "record_id": self.ledger_id,
                "status": self.status.value, "note": self.note(),
                "streams": [s.to_dict() for s in self.streams],
                "expected_streams": list(self.expected_streams),
                "observed_streams": list(self.observed_streams),
                "silent_streams": list(self.silent_streams),
                "enumeration_independent": self.enumeration_independent,
                "enumeration_source": self.enumeration_source,
                "any_self_certified": self.any_self_certified,
                "uncheckable_streams": list(self.uncheckable_streams),
                "gaps": list(self.gaps), "notes": list(self.notes),
                "schema_version": COMPLETENESS_SCHEMA_VERSION}


def ledger_from_events(events: Iterable[Any], *,
                       expected_streams: Sequence[str] = (),
                       enumeration_source: str = "",
                       enumeration_independent: bool = False,
                       end_of_stream: Mapping[str, Any] = None) -> StreamLedger:
    """Fold a stream of `AssuranceEvent`s into a completeness ledger.

    Events are the natural carrier: they already have a producer, a trace id and
    an ordering, and §10f gave them `stream_id` and `sequence` for exactly this.
    A stream with neither is still counted — it simply has no shape for a gap to
    show up in, which is itself the finding.
    """
    by_stream: Dict[str, Dict[str, Any]] = {}
    for event in events:
        stream_id = (getattr(event, "stream_id", "") or getattr(event, "trace_id", "")
                     or "unidentified")
        bucket = by_stream.setdefault(stream_id, {"sequences": [], "counters": [],
                                                  "producer": ""})
        sequence = getattr(event, "sequence", None)
        if sequence is not None:
            bucket["sequences"].append(int(sequence))
        counter = getattr(event, "event_counter", None)
        if counter is not None:
            bucket["counters"].append(int(counter))
        if not bucket["producer"]:
            bucket["producer"] = getattr(getattr(event, "emitter", None),
                                         "producer_id", "") or ""

    attestations = dict(end_of_stream or {})
    streams = []
    for stream_id, bucket in sorted(by_stream.items()):
        eos = attestations.get(stream_id)
        streams.append(SourceStream(
            stream_id=stream_id, producer_id=bucket["producer"],
            observed_sequences=tuple(bucket["sequences"]),
            counter_readings=tuple(bucket["counters"]),
            end_of_stream=(EndOfStream.from_dict(eos) if isinstance(eos, Mapping)
                           else eos)))
    return StreamLedger(
        streams=tuple(streams), expected_streams=tuple(expected_streams),
        enumeration_independent=bool(enumeration_independent),
        enumeration_source=enumeration_source)
