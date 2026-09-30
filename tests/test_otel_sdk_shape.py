"""Two defects a single OpenTelemetry span found, and the behaviour that replaced them.

Someone pasted one span from the OpenTelemetry sample traces into the demo — a
Consul health check against Vault, exported by the Python SDK's console
exporter. It has nothing to do with agents, which makes it a good input: the
honest answers are "this is a trace" and "there is no agent work in it", and
release-gate gave neither.

  1. It was identified as **Temporal workflow history at 75%**, and then mapped
     0 of 0 records out of it. The Temporal profile scores 40 for a top-level
     `events` key and 35 for that key holding a non-empty list. Both are true of
     this span. Its `eventType` check — the thing that actually identifies
     Temporal — contributed nothing and did not need to, because 75 already
     cleared the floor of 50.

     That is precisely the failure `orchestration.py` warns about in its own
     docstring: reading one framework's export with another's key names,
     producing a run that is plausible and wrong. It arrived by a route the
     scoring allowed.

  2. With that fixed it fell to UNRECOGNISED, which is honest and useless. The
     file *is* an OpenTelemetry span. The wire format is not the only shape
     OpenTelemetry comes in, and `ConsoleSpanExporter` piped to a file is the
     commonest way a person gets one to hand to something else.

The distinction these tests defend: a format claim is a claim, and a wrong one
gets a verdict attached to it.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

# The span exactly as the OpenTelemetry sample publishes it.
VAULT_SPAN = {
    "name": "/v1/sys/health",
    "context": {"trace_id": "7bba9f33312b3dbb8b2c2c62bb7abe2d",
                "span_id": "086e83747d0e381e"},
    "parent_id": "",
    "start_time": "2021-10-22 16:04:01.209458162 +0000 UTC",
    "end_time": "2021-10-22 16:04:01.209514132 +0000 UTC",
    "status_code": "STATUS_CODE_OK",
    "status_message": "",
    "attributes": {
        "net.transport": "IP.TCP", "net.peer.ip": "172.17.0.1",
        "net.peer.port": "51820", "net.host.ip": "10.177.2.152",
        "net.host.port": "26040", "http.method": "GET",
        "http.target": "/v1/sys/health", "http.server_name": "mortar-gateway",
        "http.route": "/v1/sys/health", "http.user_agent": "Consul Health Check",
        "http.scheme": "http", "http.host": "10.177.2.152:26040",
        "http.flavor": "1.1",
    },
    "events": [{"name": "", "message": "OK",
                "timestamp": "2021-10-22 16:04:01.209512872 +0000 UTC"}],
}


def _assure(document):
    from release_gate.assurance.zero_config import assure

    path = tempfile.mktemp(suffix=".json")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        return assure(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


class TestAProfileNeedsItsOwnEvidence:
    """A declared distinguishing value is necessary, not a bonus."""

    def test_the_health_check_span_is_not_a_temporal_workflow(self):
        from release_gate.assurance.orchestration import identify

        resolved = identify(VAULT_SPAN)
        assert resolved.profile is None, (
            f"a Consul health check resolved to the {resolved.profile.name!r} "
            f"profile at {resolved.confidence}%")

    def test_it_still_appears_as_a_weak_structural_resemblance(self):
        """Capped, not erased — the shape really does look a little like one."""
        from release_gate.assurance.orchestration import identify

        assert dict(identify(VAULT_SPAN).alternatives).get("temporal"), (
            "the near-match vanished entirely; it should be reported and not acted on")

    def test_the_cap_holds_for_every_profile_that_names_its_values(self):
        """Not a special case for Temporal: the rule is the rule."""
        from release_gate.assurance.orchestration import DETECT_FLOOR, _PROFILE_LIST

        for profile in _PROFILE_LIST:
            if not profile.detect_values:
                continue
            # A document with the profile's key names and nothing else.
            document = {key: [{"unrelated": "value"}] for key in profile.detect_keys}
            score = profile.matches(document)
            assert score < DETECT_FLOOR, (
                f"{profile.name} resolves at {score}% on key names alone, with "
                "none of the values it says identify it")

    def test_a_real_temporal_history_still_resolves(self):
        """The fix must not cost the detection it exists to protect."""
        from release_gate.assurance.orchestration import identify

        history = {"events": [
            {"eventId": "1", "eventType": "WorkflowExecutionStarted"},
            {"eventId": "2", "eventType": "ActivityTaskScheduled"},
            {"eventId": "3", "eventType": "ActivityTaskCompleted"}]}
        resolved = identify(history)
        assert resolved.profile is not None and resolved.profile.name == "temporal"


class TestTheSdkExportShapeIsRead:

    def test_the_span_is_found(self):
        from release_gate.adapters.common import iter_otlp_spans

        spans = list(iter_otlp_spans(VAULT_SPAN))
        assert len(spans) == 1

    def test_the_ids_are_mapped_onto_the_wire_names(self):
        from release_gate.adapters.common import iter_otlp_spans

        span, _ = next(iter(iter_otlp_spans(VAULT_SPAN)))
        assert span["spanId"] == "086e83747d0e381e"
        assert span["traceId"] == "7bba9f33312b3dbb8b2c2c62bb7abe2d"

    def test_an_empty_parent_is_a_root_not_a_dangling_reference(self):
        """`parent_id: ""` is how this exporter spells root."""
        from release_gate.adapters.common import iter_otlp_spans

        span, _ = next(iter(iter_otlp_spans(VAULT_SPAN)))
        assert "parentSpanId" not in span, (
            "an empty parent id was carried through; every root span would "
            "become the child of a span that is not there")

    def test_a_real_parent_is_kept(self):
        from release_gate.adapters.common import iter_otlp_spans

        child = dict(VAULT_SPAN, parent_id="0000000000000001")
        span, _ = next(iter(iter_otlp_spans(child)))
        assert span["parentSpanId"] == "0000000000000001"

    def test_something_without_ids_is_not_claimed_as_a_span(self):
        """The shape is recognised by its ids, not by having a `context` key."""
        from release_gate.adapters.common import iter_otlp_spans

        assert list(iter_otlp_spans({"name": "x", "context": {"note": "no ids here"}})) == []

    def test_a_list_of_them_is_read(self):
        from release_gate.adapters.common import iter_otlp_spans

        assert len(list(iter_otlp_spans([VAULT_SPAN, VAULT_SPAN]))) == 2

    def test_a_spans_batch_is_read_with_its_parent_links(self):
        """The changelog says a `{"spans": [...]}` batch is read. This is that."""
        from release_gate.adapters.common import iter_otlp_spans

        child = dict(VAULT_SPAN, name="child", parent_id="086e83747d0e381e",
                     context={"trace_id": VAULT_SPAN["context"]["trace_id"],
                              "span_id": "1111111111111111"})
        spans = [s for s, _ in iter_otlp_spans({"spans": [VAULT_SPAN, child]})]
        assert [s["name"] for s in spans] == ["/v1/sys/health", "child"]
        assert "parentSpanId" not in spans[0]
        assert spans[1]["parentSpanId"] == "086e83747d0e381e"

    def test_the_wire_format_is_untouched(self):
        """The branch must not shadow the format it sits in front of."""
        import pathlib

        from release_gate.adapters.common import iter_otlp_spans

        root = pathlib.Path(__file__).resolve().parent.parent
        wire = json.loads(
            (root / "examples" / "agents" / "01-coding-agent-otel.json").read_text(
                encoding="utf-8"))
        assert len(list(iter_otlp_spans(wire))) == 11


class TestWhatTheCaseSaysAboutIt:

    @pytest.fixture(scope="class")
    @classmethod
    def outcome(cls):
        return _assure(VAULT_SPAN)

    def test_it_is_identified_as_a_trace(self, outcome):
        from release_gate.assurance.ingest import InputKind

        assert outcome.normalisation.detection.kind is InputKind.OTLP_TRACE

    def test_the_basis_names_the_shape_it_actually_matched(self, outcome):
        """It used to say "resource/scope/span structure" for a file with none."""
        basis = outcome.normalisation.detection.basis
        assert "SDK" in basis, basis
        assert "resource/scope/span" not in basis

    def test_the_span_is_mapped_rather_than_counted_and_dropped(self, outcome):
        n = outcome.normalisation
        assert (n.records_seen, n.records_mapped) == (1, 1)
        assert not n.skipped

    def test_the_http_attributes_are_read_as_an_observed_capability(self, outcome):
        """Observed from protocol attributes, not guessed from a tool name."""
        surface = outcome.capabilities
        assert surface is not None
        names = {str(r.capability.value) for r in surface.records}
        assert "NETWORK" in names, names

    def test_it_holds_rather_than_promoting_a_health_check(self, outcome):
        assert outcome.case.verdict.decision.value == "HOLD"
        assert outcome.exit_code == 10

    def test_nothing_about_agent_work_is_claimed(self, outcome):
        """There is no agent in this file, and the case must not imply one."""
        assert outcome.case.collection("claims").total_count == 0
        dimensions = {row.to_dict()["dimension"]: row.to_dict()["status"]
                      for row in outcome.case.records("coverage")}
        assert dimensions.get("domain_sufficiency") != "ASSESSED"
