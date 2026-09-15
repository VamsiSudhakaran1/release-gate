"""Selective omission as a first-class threat (Invariant 13).

The test that matters most is the one asserting `COMPLETE` is unreachable from a
producer's account of its own output — signed, matching, and with nothing
visibly missing. That is exactly what a successful omission looks like from the
inside, and it is the common case rather than the exotic one.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.completeness import (
    COMPLETENESS_SCHEMA_VERSION, CompletenessError, EndOfStream, SourceStream,
    StreamCompleteness, StreamLedger, ledger_from_events,
)
from release_gate.assurance.events import AssuranceEvent, EventType, events_from_otlp
from release_gate.assurance.evidence import Producer, ProducerKind

AGENT = Producer(producer_id="agent://1", kind=ProducerKind.AGENT)


def stream(**kwargs):
    kwargs.setdefault("stream_id", "s1")
    kwargs.setdefault("producer_id", "agent://1")
    return SourceStream(**kwargs)


def ledger(streams, expected=("s1",), independent=True, source="orchestration manifest"):
    return StreamLedger(streams=tuple(streams), expected_streams=tuple(expected),
                        enumeration_independent=independent, enumeration_source=source)


# ── the guard ───────────────────────────────────────────────────────────────

class TestCompleteIsGuarded:
    """`COMPLETE` needs three conditions, and self-certification defeats it."""

    def test_a_producer_counting_its_own_output_never_reaches_complete(self):
        """Signed, matching, nothing visibly missing — and still not COMPLETE.

        Whatever was left out of the stream was left out of the count with it,
        and the signature over that count is perfectly valid.
        """
        result = StreamLedger(
            streams=(stream(observed_sequences=(1, 2, 3),
                            end_of_stream=EndOfStream(declared_by="agent://1",
                                                      final_sequence=3,
                                                      record_count=3,
                                                      signature_id="sig-abc")),),
            expected_streams=("s1",), enumeration_independent=False)
        assert result.status is StreamCompleteness.PARTIALLY_COMPLETE
        assert "cannot detect an omission" in result.note()

    def test_an_independent_enumeration_with_no_gaps_is_complete(self):
        result = ledger([stream(observed_sequences=(1, 2, 3))])
        assert result.status is StreamCompleteness.COMPLETE

    def test_complete_says_what_it_does_not_mean(self):
        note = ledger([stream(observed_sequences=(1, 2))]).note()
        assert "AGAINST THAT ENUMERATION" in note
        assert "failed to mention" in note

    def test_signing_does_not_upgrade_a_self_certified_stream(self):
        """A valid signature over an incomplete manifest is a valid signature."""
        signed = stream(observed_sequences=(1,),
                        end_of_stream=EndOfStream(declared_by="agent://1",
                                                  signature_id="sig"))
        assert signed.self_certified
        assert StreamLedger(streams=(signed,), expected_streams=("s1",),
                            enumeration_independent=False).status \
            is not StreamCompleteness.COMPLETE

    def test_the_signature_is_recorded_as_unverified(self):
        payload = EndOfStream(declared_by="orc", signature_id="sig").to_dict()
        assert payload["signature_verified"] is False

    def test_nothing_stated_is_unknown_not_complete(self):
        """The honest default, and the correct answer most of the time."""
        assert StreamLedger().status is StreamCompleteness.COMPLETENESS_UNKNOWN

    def test_the_unknown_note_refuses_the_overclaim(self):
        note = StreamLedger().note()
        assert "not the same as there being none" in note


# ── derived detectors ───────────────────────────────────────────────────────

class TestSequenceGaps:

    def test_a_hole_is_detected(self):
        assert stream(observed_sequences=(1, 2, 4, 5)).sequence_gaps == (3,)

    def test_contiguous_sequences_have_no_gap(self):
        assert stream(observed_sequences=(1, 2, 3)).sequence_gaps == ()

    def test_out_of_order_arrival_is_not_a_gap(self):
        """Streams arrive out of order routinely; that is not an omission."""
        assert stream(observed_sequences=(3, 1, 2)).sequence_gaps == ()

    def test_a_declared_range_widens_what_can_be_seen(self):
        """Without a declaration a drop from either end is invisible, which is
        stated rather than papered over."""
        assert stream(observed_sequences=(2, 3)).sequence_gaps == ()
        assert stream(observed_sequences=(2, 3), expected_first=1,
                      expected_last=5).sequence_gaps == (1, 4, 5)

    def test_a_gap_makes_the_ledger_known_gaps(self):
        assert ledger([stream(observed_sequences=(1, 3))]).status \
            is StreamCompleteness.KNOWN_GAPS


class TestMonotonicCounters:

    def test_a_regression_is_detected(self):
        assert stream(counter_readings=(1, 5, 4)).counter_regressions == ((5, 4),)

    def test_a_rising_counter_is_clean(self):
        assert stream(counter_readings=(1, 2, 9)).counter_regressions == ()

    def test_a_regression_is_reported_as_replay_or_reordering(self):
        gaps = ledger([stream(observed_sequences=(1,), counter_readings=(9, 2))]).gaps
        assert any("replayed or reordered" in g for g in gaps)


class TestEndOfStreamAttestations:

    def test_a_truncated_tail_is_detected(self):
        assert stream(observed_sequences=(1, 2),
                      end_of_stream=EndOfStream(declared_by="orc",
                                                final_sequence=9)).truncated_tail

    def test_a_matching_tail_is_not_truncated(self):
        assert not stream(observed_sequences=(1, 2),
                          end_of_stream=EndOfStream(declared_by="orc",
                                                    final_sequence=2)).truncated_tail

    def test_a_count_shortfall_is_detected(self):
        assert stream(observed_sequences=(1, 2),
                      end_of_stream=EndOfStream(declared_by="orc",
                                                record_count=5)).count_shortfall == 3

    def test_an_anonymous_attestation_is_refused(self):
        """Who declared it is the field that decides everything."""
        with pytest.raises(CompletenessError, match="who declared it"):
            EndOfStream(declared_by="  ")

    def test_a_nonsense_count_is_refused(self):
        with pytest.raises(CompletenessError):
            EndOfStream(declared_by="orc", record_count="lots")

    def test_it_round_trips(self):
        eos = EndOfStream(declared_by="orc", final_sequence=3, record_count=3,
                          signature_id="sig")
        assert EndOfStream.from_dict(eos.to_dict()).declared_by == "orc"


class TestSilentStreams:

    def test_a_stream_that_never_reported_is_the_strongest_signal(self):
        result = ledger([stream(stream_id="a", observed_sequences=(1,))],
                        expected=("a", "b"))
        assert result.status is StreamCompleteness.KNOWN_GAPS
        assert any("never reported at all" in g for g in result.gaps)

    def test_it_explains_why_nothing_else_would_catch_it(self):
        result = ledger([stream(stream_id="a", observed_sequences=(1,))],
                        expected=("a", "b"))
        assert any("no internal structure" in g for g in result.gaps)


class TestStreamIdentity:

    def test_a_stream_must_be_identified(self):
        with pytest.raises(CompletenessError, match="stream_id"):
            SourceStream(stream_id="")

    def test_separate_streams_each_keep_their_own_shape(self):
        """Omission hides in aggregation: one pile has no shape for a hole."""
        result = ledger([stream(stream_id="a", observed_sequences=(1, 2)),
                         stream(stream_id="b", observed_sequences=(1, 3))],
                        expected=("a", "b"))
        assert result.status is StreamCompleteness.KNOWN_GAPS
        assert any("in b" in g for g in result.gaps)

    def test_one_bad_stream_makes_the_whole_record_gapped(self):
        """A decision rests on the union."""
        result = ledger([stream(stream_id="a", observed_sequences=(1, 2, 3)),
                         stream(stream_id="b", observed_sequences=(1, 9))],
                        expected=("a", "b"))
        assert result.status is StreamCompleteness.KNOWN_GAPS


# ── the event carrier ───────────────────────────────────────────────────────

class TestEventsCarryCompleteness:

    def _events(self, sequences, **kw):
        return [AssuranceEvent(event_type=EventType.TOOL_CALLED, emitter=AGENT,
                               stream_id="s1", sequence=n, timestamp_ns=n, **kw)
                for n in sequences]

    def test_events_fold_into_a_ledger(self):
        result = ledger_from_events(self._events([1, 2, 3]),
                                    expected_streams=["s1"],
                                    enumeration_independent=True)
        assert result.status is StreamCompleteness.COMPLETE

    def test_a_missing_event_is_caught(self):
        result = ledger_from_events(self._events([1, 2, 4]),
                                    expected_streams=["s1"],
                                    enumeration_independent=True)
        assert result.status is StreamCompleteness.KNOWN_GAPS

    def test_events_without_a_stream_fall_back_to_the_trace(self):
        events = [AssuranceEvent(event_type=EventType.TOOL_CALLED, emitter=AGENT,
                                 trace_id="t1", sequence=1)]
        assert ledger_from_events(events).observed_streams == ("t1",)

    def test_a_stream_with_no_numbering_reports_unknown(self):
        """No shape for a hole to show up in — which is the finding, not a pass."""
        events = [AssuranceEvent(event_type=EventType.TOOL_CALLED, emitter=AGENT,
                                 stream_id="s1")]
        assert ledger_from_events(events).status \
            is StreamCompleteness.COMPLETENESS_UNKNOWN

    def test_a_bad_sequence_value_is_refused(self):
        with pytest.raises(Exception):
            AssuranceEvent(event_type=EventType.TOOL_CALLED, emitter=AGENT,
                           sequence="third")

    def test_otlp_carries_the_fields_without_an_sdk(self):
        doc = {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{
            "spans": [{"traceId": "t1", "spanId": "s1", "name": "execute_tool",
                       "startTimeUnixNano": "1",
                       "attributes": [
                           {"key": "gen_ai.operation.name",
                            "value": {"stringValue": "execute_tool"}},
                           {"key": "assurance.stream_id",
                            "value": {"stringValue": "billing"}},
                           {"key": "assurance.sequence",
                            "value": {"stringValue": "7"}}]}]}]}]}
        events, _ = events_from_otlp(doc)
        assert events[0].stream_id == "billing"
        assert events[0].sequence == 7

    def test_events_still_round_trip_with_the_new_fields(self):
        event = AssuranceEvent(event_type=EventType.TOOL_CALLED, emitter=AGENT,
                               stream_id="s1", sequence=3, event_counter=30)
        assert AssuranceEvent.from_dict(event.to_dict()) == event


# ── missing-span detection, which already worked ────────────────────────────

class TestMissingSpanDetection:

    def test_a_span_whose_parent_never_arrived_is_a_gap(self):
        from release_gate.assurance.execution_graph import ExecutionGraph
        doc = {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{
            "spans": [{"traceId": "t1", "spanId": "s3",
                       "parentSpanId": "never-arrived", "name": "execute_tool",
                       "startTimeUnixNano": "3",
                       "attributes": [{"key": "gen_ai.operation.name",
                                       "value": {"stringValue": "execute_tool"}}]}]}]}]}
        completeness = ExecutionGraph.from_otlp(doc).completeness
        assert completeness.unobserved_parents == ("never-arrived",)
        assert completeness.status.value == "GAPS_DETECTED"


# ── the closing rule ────────────────────────────────────────────────────────

class TestObservedNotAbsent:
    """Do not claim 'no contradiction exists' when only 'none was observed'."""

    def test_a_clean_case_says_observed_rather_than_none_exist(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        from release_gate.assurance.methodologies import (
            GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE)
        path = tmp_path / "clean.json"
        path.write_text(json.dumps([
            {"record_type": "evidence", "evidence_id": "e1", "kind": "OBSERVATION",
             "producer": {"producer_id": "a://1", "kind": "agent"},
             "coverage_note": "did a thing"}]))
        outcome = assure(str(path), methodology=PROFILE)
        detail = next(r for r in outcome.assessment.results
                      if r.requirement_id == "contradictions.resolved").detail
        assert "was observed" in detail
        assert "not the same as none existing" in detail

    def test_the_predicate_describes_itself_as_observational(self):
        from release_gate.assurance.methodology import NoUnresolved
        assert NoUnresolved(collection="contradictions").describe() \
            == "no unresolved contradictions among those observed"

    def test_the_execution_graph_still_refuses_a_complete_value(self):
        """Raw spans have no independent enumeration, so that enum correctly
        has no COMPLETE. This module's COMPLETE rests on something it lacks."""
        from release_gate.assurance.execution_graph import CompletenessStatus
        assert not any(s.name == "COMPLETE" for s in CompletenessStatus)


class TestSerialisation:

    def test_the_ledger_serialises(self):
        payload = ledger([stream(observed_sequences=(1, 2))]).to_dict()
        assert payload["record_type"] == "stream_completeness"
        assert payload["status"] == "COMPLETE"
        assert payload["schema_version"] == COMPLETENESS_SCHEMA_VERSION

    def test_the_ledger_id_is_content_addressed(self):
        a = ledger([stream(observed_sequences=(1, 2))])
        b = ledger([stream(observed_sequences=(1, 2))])
        c = ledger([stream(observed_sequences=(1, 2, 3))])
        assert a.ledger_id == b.ledger_id and a.ledger_id != c.ledger_id
