"""Seven readouts, and links to the systems that hold everything else.

The constraint under test is as much what is absent as what is present: no
metrics, no time axis, no span storage, nothing fetched. The trace fixtures
carry real ids and real durations, because the point is that the ids survive and
the durations do not.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.status import (
    READOUTS, SOURCE_SYSTEMS, STATUS_SCHEMA_VERSION, AssuranceStatus,
    LinkResolution, Readout, SourceLink, SourceSystem, StatusError, link_for,
    status_of,
)
from release_gate.assurance.zero_config import assure
from release_gate.demos import single_agent

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"

OTLP = {"resourceSpans": [{"resource": {"attributes": [
    {"key": "service.name", "value": {"stringValue": "agent"}}]},
    "scopeSpans": [{"spans": [
        {"name": "llm", "spanId": "01", "traceId": TRACE_ID,
         "startTimeUnixNano": "1700000000000000000",
         "endTimeUnixNano": "1700000002500000000", "attributes": [
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
            {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "1200"}}]},
        {"name": "tool.write", "spanId": "02", "traceId": TRACE_ID,
         "startTimeUnixNano": "1700000002500000000",
         "endTimeUnixNano": "1700000003000000000", "attributes": [
            {"key": "tool.name", "value": {"stringValue": "write_file"}}]}]}]}]}


@pytest.fixture
def traced(tmp_path):
    path = tmp_path / "otlp.json"
    path.write_text(json.dumps(OTLP))
    return assure(str(path))


@pytest.fixture
def promoted():
    return single_agent.run().outcome


# ── all seven, on one surface ────────────────────────────────────────────────

class TestSevenReadouts:

    def test_there_are_seven(self):
        assert len(READOUTS) == 7

    @pytest.mark.parametrize("name", READOUTS)
    def test_each_is_present(self, name, promoted):
        assert status_of(promoted).readout(name) is not None

    def test_one_left_out_is_refused(self, promoted):
        """One missing reads as one with nothing to say, which is the difference
        between a clean case and an unexamined one."""
        full = status_of(promoted)
        with pytest.raises(StatusError) as exc:
            AssuranceStatus(case_id="c",
                            readouts=tuple(r for r in full.readouts
                                           if r.name != "coverage"))
        assert "an unexamined one" in str(exc.value)

    def test_an_eighth_readout_is_refused(self):
        """An eighth added here would be a metric, and metrics are what the
        platforms already do better."""
        with pytest.raises(StatusError) as exc:
            Readout(name="p99_latency", headline="12ms")
        assert "metrics are what the platforms already do better" in str(exc.value)

    def test_a_duplicate_readout_is_refused(self, promoted):
        full = status_of(promoted)
        with pytest.raises(StatusError):
            AssuranceStatus(case_id="c",
                            readouts=full.readouts + (full.readout("case"),))

    def test_an_undecided_case_has_no_status(self):
        class Bare:
            case = None
            normalisation = None
        with pytest.raises(StatusError) as exc:
            status_of(Bare())
        assert "a state nobody reached" in str(exc.value)

    def test_the_case_readout_carries_the_verdict_and_its_binding(self, promoted):
        detail = status_of(promoted).readout("case").detail
        assert detail["decision"] in ("PROMOTE", "HOLD", "BLOCK")
        assert detail["exit_code"] in (0, 10, 1)
        assert detail["case_digest"].startswith("sha256:")

    def test_ingestion_reports_what_it_could_not_map(self, traced):
        detail = status_of(traced).readout("ingestion").detail
        assert detail["seen"] >= detail["mapped"]
        assert "skipped_total" in detail

    def test_attention_is_ranked_and_bounded(self, promoted):
        detail = status_of(promoted).readout("human_attention").detail
        assert len(detail["top"]) <= 5

    def test_required_evidence_is_a_work_order(self, promoted):
        readout = status_of(promoted).readout("required_evidence")
        assert "dispatchable" in readout.detail


# ── absent is not clean ──────────────────────────────────────────────────────

class TestNotAssessed:

    def test_completeness_without_a_ledger_is_not_assessed(self, promoted):
        readout = status_of(promoted).readout("completeness")
        assert readout.not_assessed
        assert "not a clean answer" in readout.note

    def test_completeness_with_one_reports_it(self, promoted):
        from release_gate.assurance.completeness import StreamLedger
        readout = status_of(promoted, completeness=StreamLedger()).readout(
            "completeness")
        assert not readout.not_assessed

    def test_one_run_is_not_a_trend(self, promoted):
        """Reporting it as unchanged would invent a history."""
        readout = status_of(promoted).readout("verdict_evolution")
        assert readout.not_assessed
        assert "invent a history" in readout.note

    def test_two_runs_give_an_evolution(self, promoted):
        readout = status_of(promoted, previous=promoted).readout(
            "verdict_evolution")
        assert not readout.not_assessed
        assert "→" in readout.headline

    def test_not_assessed_is_marked_in_the_render(self, promoted):
        assert "[NOT ASSESSED]" in status_of(promoted).render()


# ── links point, they do not copy ────────────────────────────────────────────

class TestSourceLinks:

    def test_a_trace_id_survives_ingestion(self, traced):
        """It did not. `add_span` read spanId and parentSpanId and never traceId,
        so the case kept a span id and no trace to find it in — exactly the wrong
        half of the pointer."""
        assert traced.normalisation.execution.trace_ids == (TRACE_ID,)

    def test_it_becomes_an_openable_link(self, traced):
        status = status_of(traced, system="langfuse",
                           host="https://cloud.langfuse.com", project="prod")
        link = status.links[0]
        assert link.openable
        assert link.url == (f"https://cloud.langfuse.com/project/prod/traces/"
                            f"{TRACE_ID}")

    @pytest.mark.parametrize("system", sorted(SOURCE_SYSTEMS))
    def test_every_platform_builds_a_url(self, system, traced):
        status = status_of(traced, system=system, host="https://example",
                           project="proj")
        assert status.links[0].openable
        assert TRACE_ID in status.links[0].url

    def test_a_link_never_resolves_the_data(self, traced):
        status = status_of(traced, system="jaeger", host="https://j")
        assert status.links[0].resolves_the_data is False
        assert status.links[0].to_dict()["resolves_the_data"] is False

    def test_an_unconfigured_host_keeps_the_id(self, traced):
        """Losing both would report a run with no telemetry rather than
        telemetry nobody linked."""
        link = status_of(traced, system="langfuse").links[0]
        assert not link.openable
        assert link.resolution is LinkResolution.NO_HOST
        assert link.identifier == TRACE_ID

    def test_a_missing_project_is_named_as_such(self, traced):
        link = status_of(traced, system="phoenix",
                         host="http://localhost:6006").links[0]
        assert link.resolution is LinkResolution.NO_PROJECT
        assert "the id is exact and the path to it is not" in link.note

    def test_an_unknown_system_keeps_the_id_too(self, traced):
        link = status_of(traced, system="some_future_platform",
                         host="https://x").links[0]
        assert link.resolution is LinkResolution.NO_SOURCE
        assert link.identifier == TRACE_ID

    def test_no_system_at_all_is_still_reported(self, traced):
        link = status_of(traced).links[0]
        assert link.resolution is LinkResolution.NO_SOURCE
        assert "whichever console holds it" in link.note

    def test_unresolved_links_are_counted_once(self, traced):
        """Several readouts carry the same trace; aggregated naively that
        reported three unresolved links where one trace was unreachable."""
        assert len(status_of(traced, system="langfuse").unresolved_links) == 1

    def test_a_link_must_carry_its_id(self):
        with pytest.raises(StatusError) as exc:
            SourceLink(kind="trace", identifier="  ")
        assert "cannot be pasted either" in str(exc.value)

    def test_a_custom_platform_needs_no_code_change(self, traced):
        house = SourceSystem(name="house_apm", label="our APM",
                             trace_template="{host}/t/{trace_id}")
        assert house.url(host="https://apm.internal/", trace_id=TRACE_ID) == \
            f"https://apm.internal/t/{TRACE_ID}"

    def test_a_system_must_say_how_to_reach_a_trace(self):
        with pytest.raises(StatusError) as exc:
            SourceSystem(name="x", label="x")
        assert "indistinguishable from one nobody configured" in str(exc.value)

    def test_the_registry_cannot_disagree_with_itself(self):
        for name, system in SOURCE_SYSTEMS.items():
            assert system.name == name


# ── and it is not an observability platform ──────────────────────────────────

class TestNotObservability:

    def test_it_says_so(self, promoted):
        status = status_of(promoted)
        assert status.replaces_your_observability is False
        assert status.answers_what_happened_at is False
        assert status.stores_telemetry is False

    def test_the_payload_carries_the_refusals(self, promoted):
        payload = status_of(promoted).to_dict()
        for key in ("replaces_your_observability", "answers_what_happened_at",
                    "stores_telemetry"):
            assert payload[key] is False

    def test_span_durations_are_not_retained(self, traced):
        """Durations are Datadog's business. The 2.5s span in the fixture must
        leave no trace in the case."""
        blob = json.dumps(traced.to_dict())
        assert "2500000000" not in blob
        assert "1700000002500000000" not in blob

    def test_raw_timestamps_are_not_retained(self, traced):
        assert "1700000000000000000" not in json.dumps(traced.to_dict())

    def test_the_status_surface_has_no_time_axis(self, promoted):
        """A question about a moment is a question for the system that indexes
        by time."""
        payload = json.dumps(status_of(promoted).to_dict()).lower()
        for metric in ("p50", "p95", "p99", "latency_ms", "throughput",
                       "requests_per_second", "histogram"):
            assert metric not in payload

    def test_nothing_fetches(self):
        """A link is a URL a person opens, never something release-gate
        follows."""
        import ast
        from pathlib import Path
        source = (Path(__file__).resolve().parent.parent / "release_gate"
                  / "assurance" / "status.py")
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                assert name not in ("urllib", "http", "requests", "httpx",
                                    "socket"), name

    def test_the_render_says_where_the_spans_live(self, promoted):
        assert "stay in the systems above" in status_of(promoted).render()


# ── the trace-id collection is bounded ───────────────────────────────────────

class TestBounded:

    def test_a_trace_id_is_kept_once_per_run_not_once_per_node(self, traced):
        """Copying it onto every node is exactly the bloat `_carry` prevents."""
        graph = traced.normalisation.execution
        assert len(graph.trace_ids) == 1
        assert len(graph.nodes) >= 2
        for node in graph.nodes:
            assert "trace_id" not in node.attributes

    def test_many_traces_are_capped(self, tmp_path):
        from release_gate.assurance.execution_graph import ExecutionGraphBuilder
        builder = ExecutionGraphBuilder()
        for index in range(200):
            builder.add_span({"name": "s", "spanId": f"s{index}",
                              "traceId": f"t{index}", "attributes": []})
        assert len(builder.build().trace_ids) == ExecutionGraphBuilder.MAX_TRACE_IDS

    def test_a_graph_with_no_traces_reports_none(self, promoted):
        assert status_of(promoted).links == ()
