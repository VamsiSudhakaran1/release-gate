"""The vendor-neutral event protocol.

Two properties carry this module, and both are tested against behaviour rather
than asserted in a docstring:

* **An event stream can never mint VERIFIED.** An agent emitting
  VERIFICATION_COMPLETED with outcome PASSED must not end up with a verified
  claim, or self-certification costs one line of JSON.
* **Converting existing telemetry must not be worse than reading it directly.**
  OTLP through the event door has to reconstruct the same execution the OTLP
  trace adapter reconstructs, or the vendor-neutral path is a downgrade.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.claims import ClaimGraph
from release_gate.assurance.events import (
    EVENT_SCHEMA_VERSION, AssuranceEvent, EventConversion, EventError, EventType,
    events_from_otlp, events_to_records,
)
from release_gate.assurance.evidence import EpistemicStatus, Producer, ProducerKind
from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.session import AssuranceSession

AGENT = Producer(producer_id="agent://solver/1", kind=ProducerKind.AGENT)


def event(event_type, **kwargs):
    kwargs.setdefault("emitter", AGENT)
    return AssuranceEvent(event_type=event_type, **kwargs)


def otlp(spans, service="billing-agent"):
    return {"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": service}}]},
        "scopeSpans": [{"spans": spans}]}]}


def span(name, operation=None, start="1000", **attrs):
    attributes = []
    if operation:
        attributes.append({"key": "gen_ai.operation.name",
                           "value": {"stringValue": operation}})
    for key, value in attrs.items():
        attributes.append({"key": key.replace("__", "."),
                           "value": {"stringValue": str(value)}})
    return {"traceId": "t1", "spanId": name, "name": name,
            "startTimeUnixNano": start, "attributes": attributes}


# ── the vocabulary ──────────────────────────────────────────────────────────

class TestVocabulary:

    def test_all_twenty_classes_are_defined(self):
        assert len(list(EventType)) == 20

    def test_every_class_has_a_standing(self):
        for kind in EventType:
            assert kind.standing in (EpistemicStatus.OBSERVED, EpistemicStatus.DECLARED)

    def test_self_reports_are_observed(self):
        """The emitter is the authority on its own execution."""
        for kind in (EventType.RUN_STARTED, EventType.AGENT_STARTED,
                     EventType.TASK_STARTED, EventType.TOOL_CALLED,
                     EventType.ARTIFACT_CREATED, EventType.HUMAN_INTERVENTION,
                     EventType.RUN_COMPLETED):
            assert kind.standing is EpistemicStatus.OBSERVED, kind

    def test_judgements_are_declared(self):
        """An assertion is not a finding however confidently it is serialised."""
        for kind in (EventType.CLAIM_CREATED, EventType.CLAIM_SUPPORTED,
                     EventType.CLAIM_CHALLENGED, EventType.ASSUMPTION_DECLARED,
                     EventType.VERIFICATION_COMPLETED,
                     EventType.COUNTEREXAMPLE_FOUND,
                     EventType.CONTRADICTION_OPENED,
                     EventType.CONTRADICTION_RESOLVED):
            assert kind.standing is EpistemicStatus.DECLARED, kind

    def test_no_class_is_ever_verified(self):
        assert not any(k.standing is EpistemicStatus.VERIFIED for k in EventType)


class TestEventShape:

    def test_it_uses_otel_correlation_fields(self):
        e = event(EventType.TOOL_CALLED, trace_id="t", span_id="s",
                  parent_span_id="p", timestamp_ns=42)
        assert (e.trace_id, e.span_id, e.parent_span_id, e.timestamp_ns) == \
            ("t", "s", "p", 42)

    def test_an_unknown_class_is_refused_not_dropped(self):
        """An emitter using a name we do not know has told us something we
        cannot represent; discarding it silently would understate the run."""
        with pytest.raises(EventError, match="not an event class"):
            event("AGENT_VIBED")

    def test_an_anonymous_event_is_refused(self):
        """Status is assigned from who is speaking."""
        with pytest.raises(EventError, match="emitter"):
            AssuranceEvent(event_type=EventType.TOOL_CALLED, emitter=None)

    def test_a_non_otel_status_is_refused(self):
        with pytest.raises(EventError, match="OTel span status"):
            event(EventType.TOOL_CALLED, status="SORT_OF_FINE")

    def test_the_id_is_content_addressed(self):
        a = event(EventType.TOOL_CALLED, timestamp_ns=1, subject_ref="x")
        b = event(EventType.TOOL_CALLED, timestamp_ns=1, subject_ref="x")
        c = event(EventType.TOOL_CALLED, timestamp_ns=2, subject_ref="x")
        assert a.event_id == b.event_id and a.event_id != c.event_id

    def test_it_round_trips_through_its_dict(self):
        e = event(EventType.CLAIM_SUPPORTED, subject_ref="c1", timestamp_ns=7,
                  attributes={"confidence": "high"})
        assert AssuranceEvent.from_dict(e.to_dict()) == e

    def test_the_dict_states_the_standing(self):
        assert event(EventType.VERIFICATION_COMPLETED).to_dict()["standing"] \
            == "DECLARED"
        assert event(EventType.TOOL_CALLED).to_dict()["schema_version"] \
            == EVENT_SCHEMA_VERSION


# ── the two refusals ────────────────────────────────────────────────────────

class TestAnEventCannotMintVerified:
    """The property the whole protocol rests on."""

    STREAM = [
        (EventType.RUN_STARTED, {"timestamp_ns": 1}),
        (EventType.CLAIM_CREATED, {"timestamp_ns": 2, "subject_ref": "c1",
                                   "attributes": {"proposition": "it is safe"}}),
        (EventType.VERIFICATION_COMPLETED,
         {"timestamp_ns": 3, "subject_ref": "c1", "status": "OK",
          "attributes": {"method": "FORMAL_PROOF", "outcome": "PASSED"}}),
        (EventType.RUN_COMPLETED, {"timestamp_ns": 4}),
    ]

    def _records(self):
        return events_to_records([event(k, **kw) for k, kw in self.STREAM]).records

    def test_no_record_carries_verified_status(self):
        blob = json.dumps(list(self._records()))
        assert '"VERIFIED"' not in blob

    def test_only_observed_and_declared_are_emitted(self):
        statuses = {r.get("epistemic_status") for r in self._records()}
        assert statuses <= {"OBSERVED", "DECLARED", None}

    def test_a_self_certified_claim_does_not_come_out_verified(self):
        """An agent asserting its own proof passed proves nothing."""
        outcome = AssuranceSession.open(methodology=PROFILE).extend(
            self._records()).finalize()
        graph = ClaimGraph.from_case(outcome.case)
        assert graph is not None
        assert graph.status("c1").value != "VERIFIED"

    def test_a_reported_failure_argues_against_the_claim(self):
        """ERROR status is preserved: a run reporting its own failure is telling
        the truth about itself."""
        records = events_to_records([
            event(EventType.CLAIM_CREATED, timestamp_ns=1, subject_ref="c1"),
            event(EventType.VERIFICATION_COMPLETED, timestamp_ns=2,
                  subject_ref="c1", status="ERROR"),
        ]).records
        against = [r for r in records if r.get("contradicts_claims") == ["c1"]]
        assert against


class TestAnEventCannotCloseAContradiction:

    def test_resolved_emits_no_resolved_flag(self):
        records = events_to_records([
            event(EventType.CONTRADICTION_OPENED, timestamp_ns=1, subject_ref="c1"),
            event(EventType.CONTRADICTION_RESOLVED, timestamp_ns=2, subject_ref="c1"),
        ]).records
        assert '"resolved": true' not in json.dumps(list(records)).lower()

    def test_it_is_recorded_as_a_declaration_with_a_note(self):
        conversion = events_to_records([
            event(EventType.CONTRADICTION_RESOLVED, timestamp_ns=1, subject_ref="c1")])
        assert any("does not close anything" in n for n in conversion.notes)
        assert all(r.get("epistemic_status") == "DECLARED"
                   for r in conversion.records if "epistemic_status" in r)

    def test_a_real_contradiction_survives_the_announcement(self):
        """Evidence both ways still contradicts, whatever anyone announces."""
        records = list(events_to_records([
            event(EventType.CLAIM_CREATED, timestamp_ns=1, subject_ref="c1"),
            event(EventType.CLAIM_SUPPORTED, timestamp_ns=2, subject_ref="c1"),
            event(EventType.CLAIM_CHALLENGED, timestamp_ns=3, subject_ref="c1"),
            event(EventType.CONTRADICTION_RESOLVED, timestamp_ns=4, subject_ref="c1"),
        ]).records)
        outcome = AssuranceSession.open(methodology=PROFILE).extend(records).finalize()
        assert list(outcome.case.collection("contradictions").materialised)


# ── conversion ──────────────────────────────────────────────────────────────

class TestConversion:

    def test_events_become_ordinary_records(self):
        conversion = events_to_records([event(EventType.TOOL_CALLED, timestamp_ns=1,
                                              subject_ref="email.send")])
        assert conversion.events_mapped == 1
        assert any(r.get("record_type") == "evidence" for r in conversion.records)

    def test_ordering_is_by_timestamp_and_stable(self):
        events = [event(EventType.TOOL_CALLED, timestamp_ns=5, subject_ref="c"),
                  event(EventType.TOOL_CALLED, timestamp_ns=1, subject_ref="a"),
                  event(EventType.TOOL_CALLED, timestamp_ns=1, subject_ref="b")]
        steps = [r for r in events_to_records(events).records
                 if r.get("record_type") == "execution"][0]["steps"]
        assert [s["tool"] for s in steps] == ["a", "b", "c"]

    def test_a_claim_event_creates_a_claim(self):
        records = events_to_records([
            event(EventType.CLAIM_CREATED, timestamp_ns=1, subject_ref="c1",
                  attributes={"proposition": "the sum is 42"})]).records
        claims = [r for r in records if r.get("record_type") == "claim"]
        assert claims and claims[0]["proposition"] == "the sum is 42"

    def test_an_assumption_is_typed_as_one(self):
        records = events_to_records([
            event(EventType.ASSUMPTION_DECLARED, timestamp_ns=1, subject_ref="a1")]).records
        claims = [r for r in records if r.get("record_type") == "claim"]
        assert claims[0]["claim_type"] == "ASSUMPTION"

    def test_a_claim_event_naming_nothing_is_noted_not_guessed(self):
        conversion = events_to_records([event(EventType.CLAIM_CREATED, timestamp_ns=1)])
        assert conversion.skipped == 1
        assert any("names no claim" in n for n in conversion.notes)

    def test_an_artifact_without_a_digest_is_noted(self):
        """Nothing to check for drift later, which is most of the point."""
        conversion = events_to_records([
            event(EventType.ARTIFACT_CREATED, timestamp_ns=1, subject_ref="build.tar")])
        assert any("no digest" in n for n in conversion.notes)
        assert not [r for r in conversion.records if r.get("record_type") == "artifact"]

    def test_an_artifact_with_a_digest_becomes_one(self):
        records = events_to_records([
            event(EventType.ARTIFACT_CREATED, timestamp_ns=1, subject_ref="build.tar",
                  attributes={"digest": "sha256:" + "a" * 64})]).records
        assert [r for r in records if r.get("record_type") == "artifact"]

    def test_the_conversion_reports_what_it_did(self):
        conversion = events_to_records([event(EventType.RUN_STARTED, timestamp_ns=1)])
        assert conversion.to_dict()["events_seen"] == 1

    def test_an_empty_stream_converts_to_nothing(self):
        assert events_to_records([]).records == ()


# ── adapters: no framework changes ──────────────────────────────────────────

class TestOtelAdapter:

    def test_genai_spans_become_events(self):
        events, _ = events_from_otlp(otlp([
            span("s1", "invoke_agent"),
            span("s2", "execute_tool", gen_ai__tool__name="email.send")]))
        assert [e.event_type for e in events] == \
            [EventType.AGENT_STARTED, EventType.TOOL_CALLED]

    def test_the_emitter_comes_from_otel_resource_attributes(self):
        """`service.name` is where OTel already records who is speaking, and
        re-flattening the already-flattened resource lost it."""
        events, _ = events_from_otlp(otlp([span("s1", "execute_tool")]))
        assert events[0].emitter.producer_id == "otel://billing-agent"

    def test_a_non_genai_span_is_skipped_and_counted(self):
        """An HTTP span is real work, but this vocabulary has no class for it
        and inventing one would put words in the emitter's mouth."""
        events, notes = events_from_otlp(otlp([span("s1", None, http__method="GET")]))
        assert events == []
        assert any("skipped rather than guessed at" in n for n in notes)

    def test_an_emitter_may_declare_the_class_directly(self):
        events, _ = events_from_otlp(otlp([
            span("s1", None, assurance__event_type="COUNTEREXAMPLE_FOUND")]))
        assert events[0].event_type is EventType.COUNTEREXAMPLE_FOUND

    def test_a_declared_class_we_do_not_know_is_refused_with_a_note(self):
        events, notes = events_from_otlp(otlp([
            span("s1", None, assurance__event_type="VIBES_CHECKED")]))
        assert events == []
        assert any("not an event class" in n for n in notes)

    def test_otel_error_status_is_preserved(self):
        doc = otlp([span("s1", "execute_tool")])
        doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"] = \
            {"code": "STATUS_CODE_ERROR"}
        events, _ = events_from_otlp(doc)
        assert events[0].status == "ERROR"

    def test_an_unnamed_service_is_not_attributed_to_anybody(self):
        events, _ = events_from_otlp(otlp([span("s1", "execute_tool")], service=""))
        assert events[0].emitter.producer_id == "otel://unidentified"


class TestTelemetryParity:
    """Converting existing telemetry must not be worse than reading it."""

    DOC = None

    def _both(self, tmp_path):
        doc = otlp([span("s1", "invoke_agent", start="1000"),
                    span("s2", "execute_tool", start="2000",
                         gen_ai__tool__name="email.send")])
        path = tmp_path / "otlp.json"
        path.write_text(json.dumps(doc))
        from release_gate.assurance.zero_config import assure
        direct = assure(str(path), methodology=PROFILE)
        events, _ = events_from_otlp(doc)
        via = AssuranceSession.open(methodology=PROFILE).extend(
            events_to_records(events).records).finalize()
        return direct, via

    def test_the_event_door_still_reconstructs_execution(self, tmp_path):
        """Without this the vendor-neutral path would be a downgrade: the trace
        adapter builds an execution graph and the event path built none."""
        direct, via = self._both(tmp_path)
        assert direct.normalisation.execution is not None
        assert via.normalisation.execution is not None

    def test_both_paths_discover_the_same_capability_surface(self, tmp_path):
        direct, via = self._both(tmp_path)
        assert (len(direct.capabilities.records)
                == len(via.capabilities.records))
        assert direct.capabilities.bounded == via.capabilities.bounded

    def test_both_paths_reach_the_same_decision(self, tmp_path):
        direct, via = self._both(tmp_path)
        assert direct.decision is via.decision

    def test_execution_coverage_is_assessed_through_the_event_door(self, tmp_path):
        _, via = self._both(tmp_path)
        rows = {str(r.to_dict().get("dimension")): r.to_dict().get("state")
                for r in via.case.collection("coverage").materialised}
        assert rows["execution_reconstruction"] != "NOT_ASSESSED"


class TestEndToEnd:

    def test_a_pure_event_stream_produces_a_decision(self):
        events = [event(EventType.RUN_STARTED, timestamp_ns=1, trace_id="t"),
                  event(EventType.TOOL_CALLED, timestamp_ns=2, trace_id="t",
                        subject_ref="email.send"),
                  event(EventType.RUN_COMPLETED, timestamp_ns=3, trace_id="t")]
        outcome = AssuranceSession.open(methodology=PROFILE).extend(
            events_to_records(events).records).finalize()
        assert outcome.decision is not None

    def test_a_stream_with_no_judgement_events_still_decides(self):
        events = [event(EventType.RUN_STARTED, timestamp_ns=1),
                  event(EventType.RUN_COMPLETED, timestamp_ns=2)]
        outcome = AssuranceSession.open(methodology=PROFILE).extend(
            events_to_records(events).records).finalize()
        assert outcome.decision is not None

    def test_events_carry_their_provenance_into_the_case(self):
        outcome = AssuranceSession.open(methodology=PROFILE).extend(
            events_to_records([event(EventType.TOOL_CALLED, timestamp_ns=1,
                                     subject_ref="email.send")]).records).finalize()
        blob = json.dumps(outcome.case.to_dict(), default=str)
        assert "agent://solver/1" in blob
