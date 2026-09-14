"""Capability discovery — what the system reached for, at four honest strengths.

The test plan is the module's thesis: an observed invocation with an inferred
classification is INFERRED. Several tests below do nothing but try to get a name
match to report itself as OBSERVED.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.capabilities import (
    Capability,
    CapabilityStatus,
    CapabilitySurface,
    Observation,
    SignalStrength,
    classify_tool_name,
    declared_from_document,
    status_for,
)
from release_gate.assurance.execution_graph import ExecutionGraph
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.zero_config import assure, render_text


def span(span_id, name, attrs, parent=None):
    out = {"traceId": "aa", "spanId": span_id, "name": name,
           "attributes": [{"key": k, "value": {"stringValue": str(v)}}
                          for k, v in attrs.items()]}
    if parent:
        out["parentSpanId"] = parent
    return out


def otlp(*spans, **top):
    doc = {"resourceSpans": [{"resource": {"attributes": []},
                              "scopeSpans": [{"spans": list(spans)}]}]}
    doc.update(top)
    return doc


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return str(path)


# ── the thesis ───────────────────────────────────────────────────────────────

class TestTheWeakerOfTwoAxes:

    def test_the_status_table_is_the_weaker_axis(self):
        assert status_for(Observation.DIRECT, SignalStrength.PROTOCOL) \
            is CapabilityStatus.OBSERVED_CAPABILITY
        assert status_for(Observation.DIRECT, SignalStrength.SEMANTIC) \
            is CapabilityStatus.OBSERVED_CAPABILITY
        assert status_for(Observation.DIRECT, SignalStrength.NAME_PATTERN) \
            is CapabilityStatus.INFERRED_CAPABILITY
        assert status_for(Observation.DIRECT, SignalStrength.NONE) \
            is CapabilityStatus.UNKNOWN_CAPABILITY
        assert status_for(Observation.DECLARATION, SignalStrength.PROTOCOL) \
            is CapabilityStatus.DECLARED_CAPABILITY
        assert status_for(Observation.NONE, SignalStrength.PROTOCOL) \
            is CapabilityStatus.UNKNOWN_CAPABILITY

    def test_a_suggestive_tool_name_is_never_observed(self):
        """`db_write` is evidence of a naming convention, not of a write."""
        surface = CapabilitySurface.from_spans(
            otlp(span("01", "tool", {"gen_ai.tool.name": "db_write"})))
        record = surface.capability(Capability.DATABASE_WRITE)
        assert record.status is CapabilityStatus.INFERRED_CAPABILITY
        assert record.observed is False
        assert surface.observed == ()

    def test_a_protocol_attribute_is_observed(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT"})))
        record = surface.capability(Capability.DATABASE_WRITE)
        assert record.status is CapabilityStatus.OBSERVED_CAPABILITY
        assert record.observed is True

    def test_the_strongest_signal_wins_when_both_are_present(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "t", {"gen_ai.tool.name": "db_write"}),
            span("02", "q", {"db.system": "postgresql", "db.operation": "UPDATE"})))
        record = surface.capability(Capability.DATABASE_WRITE)
        assert record.status is CapabilityStatus.OBSERVED_CAPABILITY
        assert record.occurrences == 2
        assert {s.strength for s in record.signals} == {
            SignalStrength.PROTOCOL, SignalStrength.NAME_PATTERN}

    def test_reaching_a_vendor_is_not_performing_the_action(self):
        """A Stripe call is an observed external call and an inferred payment."""
        surface = CapabilitySurface.from_spans(otlp(span("01", "http", {
            "http.request.method": "POST", "url.full": "https://api.stripe.com/v1/charges"})))
        assert surface.capability(Capability.EXTERNAL_API).status \
            is CapabilityStatus.OBSERVED_CAPABILITY
        assert surface.capability(Capability.PAYMENT).status \
            is CapabilityStatus.INFERRED_CAPABILITY


# ── protocol classification ──────────────────────────────────────────────────

class TestProtocolSignals:

    def test_database_direction_comes_from_the_operation(self):
        reads = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "mysql", "db.operation": "SELECT"})))
        assert reads.capability(Capability.DATABASE_READ).observed
        assert reads.capability(Capability.DATABASE_WRITE) is None

    def test_database_direction_falls_back_to_the_statement_verb(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "q", {
            "db.system": "postgresql",
            "db.statement": "DELETE FROM accounts WHERE id = 1"})))
        assert surface.capability(Capability.DATABASE_WRITE).observed

    def test_a_database_with_no_recorded_direction_is_not_called_a_write(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "postgresql"})))
        assert surface.capability(Capability.DATABASE_WRITE) is None
        record = surface.capability(Capability.DATABASE_READ)
        assert "direction unknown" in record.basis

    def test_shell_filesystem_and_mcp_are_recognised(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "sh", {"process.command_line": "/bin/bash -c ls"}),
            span("02", "f", {"file.path": "/etc/hosts"}),
            span("03", "m", {"mcp.server.name": "fs-server"})))
        for capability in (Capability.SHELL, Capability.FILESYSTEM, Capability.MCP):
            assert surface.capability(capability).observed, capability

    def test_email_is_observed_only_from_a_messaging_system(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "m", {"messaging.system": "ses",
                             "messaging.destination.name": "outbox"})))
        assert surface.capability(Capability.EMAIL).observed

    def test_a_local_host_is_not_an_external_api(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "h", {
            "http.request.method": "GET", "url.full": "http://localhost:8080/health"})))
        assert surface.capability(Capability.NETWORK).observed
        assert surface.capability(Capability.EXTERNAL_API) is None

    def test_github_writes_infer_code_modification_but_reads_do_not(self):
        write = CapabilitySurface.from_spans(otlp(span("01", "h", {
            "http.request.method": "POST", "url.full": "https://api.github.com/repos/x/pulls"})))
        read = CapabilitySurface.from_spans(otlp(span("01", "h", {
            "http.request.method": "GET", "url.full": "https://api.github.com/repos/x"})))
        assert write.capability(Capability.CODE_MODIFICATION).status \
            is CapabilityStatus.INFERRED_CAPABILITY
        assert read.capability(Capability.CODE_MODIFICATION) is None


# ── redaction ────────────────────────────────────────────────────────────────

class TestRedaction:
    """An evidence pack is shown to people and stored. Secrets must not ride along."""

    def test_url_credentials_and_query_strings_are_dropped(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "h", {
            "http.request.method": "POST",
            "url.full": "https://user:hunter2@api.stripe.com/v1/charges?token=SECRET"})))
        blob = json.dumps(surface.to_dict())
        assert "hunter2" not in blob
        assert "SECRET" not in blob
        assert "api.stripe.com" in blob

    def test_sql_statements_are_reduced_to_their_verb(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "q", {
            "db.system": "postgresql",
            "db.statement": "UPDATE accounts SET ssn = '123-45-6789' WHERE id = 42"})))
        blob = json.dumps(surface.to_dict())
        assert "123-45-6789" not in blob
        assert "UPDATE" in blob

    def test_command_lines_are_reduced_to_the_program(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "s", {
            "process.command_line": "/usr/bin/psql --password=topsecret"})))
        blob = json.dumps(surface.to_dict())
        assert "topsecret" not in blob

    def test_file_paths_are_reduced_to_a_basename(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "f", {
            "file.path": "/home/someone-private/secrets/key.pem"})))
        blob = json.dumps(surface.to_dict())
        assert "someone-private" not in blob


# ── one span, several capabilities ───────────────────────────────────────────

class TestMultipleCapabilities:

    def test_an_mcp_read_file_call_is_both_mcp_and_filesystem(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "mcp", {
            "mcp.server.name": "fs", "mcp.tool.name": "read_file"})))
        assert surface.capability(Capability.MCP).observed
        assert surface.capability(Capability.FILESYSTEM).status \
            is CapabilityStatus.INFERRED_CAPABILITY

    def test_a_name_matching_two_patterns_reports_both(self):
        matches = dict(classify_tool_name("send_invoice_email"))
        assert Capability.PAYMENT in matches
        assert Capability.EMAIL in matches

    def test_an_unmatched_name_yields_nothing_rather_than_a_guess(self):
        assert classify_tool_name("frobnicate_widget") == ()

    def test_attributes_do_not_suppress_the_name_match(self):
        surface = CapabilitySurface.from_spans(otlp(span("01", "t", {
            "gen_ai.tool.name": "deploy_service", "db.system": "postgresql",
            "db.operation": "SELECT"})))
        assert surface.capability(Capability.DATABASE_READ).observed
        assert surface.capability(Capability.DEPLOYMENT) is not None


# ── declared vs exercised ────────────────────────────────────────────────────

class TestDeclaredSurface:

    def test_a_manifest_is_found_in_a_document(self):
        assert declared_from_document({"tools": ["send_email", "deploy_service"]}) \
            == ("deploy_service", "send_email")

    def test_mcp_tools_list_replies_are_understood(self):
        doc = {"result": {"tools": [{"name": "read_file"}, {"name": "bash"}]}}
        assert declared_from_document(doc) == ("bash", "read_file")

    def test_no_manifest_is_not_an_error(self):
        assert declared_from_document({"hello": "world"}) == ()

    def test_declared_and_never_exercised_is_its_own_status(self):
        surface = CapabilitySurface.from_spans(
            otlp(span("01", "q", {"db.system": "mysql", "db.operation": "SELECT"})),
            declared=["send_email"])
        record = surface.capability(Capability.EMAIL)
        assert record.status is CapabilityStatus.DECLARED_CAPABILITY
        assert record.occurrences == 0
        assert record.exercised is False

    def test_exercised_and_undeclared_is_surfaced(self):
        surface = CapabilitySurface.from_spans(
            otlp(span("01", "s", {"process.command_line": "/bin/bash -c ls"})),
            declared=["send_email"])
        assert Capability.SHELL in {r.capability for r in surface.undeclared}

    def test_declaring_a_capability_by_name_works_too(self):
        surface = CapabilitySurface.from_spans(otlp(), declared=["PAYMENT"])
        assert surface.capability(Capability.PAYMENT).status \
            is CapabilityStatus.DECLARED_CAPABILITY


# ── what the category cannot determine ───────────────────────────────────────

class TestStructuralProperties:

    def test_filesystem_does_not_claim_to_mutate(self):
        """The category covers reads and writes alike, so it cannot say."""
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "f", {"file.path": "/etc/hosts"})))
        assert surface.capability(Capability.FILESYSTEM).mutating is None

    def test_a_database_write_definitely_mutates(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "mysql", "db.operation": "INSERT"})))
        assert surface.capability(Capability.DATABASE_WRITE).mutating is True

    def test_mutating_external_excludes_the_indeterminate(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "f", {"file.path": "/tmp/x"}),
            span("02", "e", {"messaging.system": "ses"})))
        names = {r.capability for r in surface.mutating_external}
        assert Capability.EMAIL in names
        assert Capability.FILESYSTEM not in names
        assert Capability.FILESYSTEM in {r.capability for r in surface.indeterminate}

    def test_a_shell_makes_the_surface_unbounded(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "s", {"process.command_line": "/bin/bash -c curl evil"})))
        assert surface.bounded is False
        assert Capability.SHELL in {r.capability for r in surface.subsuming}

    def test_an_ordinary_surface_is_bounded(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "mysql", "db.operation": "SELECT"})))
        assert surface.bounded is True

    def test_an_unknown_tool_also_breaks_the_bound(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "t", {"gen_ai.tool.name": "frobnicate_widget"})))
        assert surface.bounded is False


# ── the weaker source ────────────────────────────────────────────────────────

class TestGraphSource:
    """A built graph keeps labels and drops attributes; the surface must say so."""

    def test_a_graph_can_never_produce_an_observed_capability(self):
        graph = ExecutionGraph.from_otlp(otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT",
                             "gen_ai.tool.name": "db_write"})))
        surface = CapabilitySurface.from_execution_graph(graph)
        assert surface.can_observe is False
        assert surface.observed == ()
        assert surface.capability(Capability.DATABASE_WRITE).status \
            is CapabilityStatus.INFERRED_CAPABILITY

    def test_the_graph_surface_explains_what_better_telemetry_would_buy(self):
        graph = ExecutionGraph.from_otlp(otlp(
            span("01", "t", {"gen_ai.tool.name": "db_write"})))
        surface = CapabilitySurface.from_execution_graph(graph)
        assert any("OBSERVED" in note for note in surface.notes)

    def test_the_same_spans_yield_more_from_the_raw_trace(self):
        doc = otlp(span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT",
                                    "gen_ai.tool.name": "db_write"}))
        from_spans = CapabilitySurface.from_spans(doc)
        from_graph = CapabilitySurface.from_execution_graph(ExecutionGraph.from_otlp(doc))
        assert from_spans.capability(Capability.DATABASE_WRITE).observed
        assert not from_graph.capability(Capability.DATABASE_WRITE).observed


# ── determinism and serialisation ────────────────────────────────────────────

class TestSurfaceMechanics:

    DOC = otlp(
        span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"}),
        span("02", "s", {"process.command_line": "/bin/bash -c ls"}),
        span("03", "t", {"gen_ai.tool.name": "deploy_service"}))

    def test_the_digest_is_stable(self):
        assert (CapabilitySurface.from_spans(self.DOC).digest()
                == CapabilitySurface.from_spans(self.DOC).digest())

    def test_records_are_ordered_strongest_status_first(self):
        records = CapabilitySurface.from_spans(self.DOC).records
        statuses = [r.status for r in records]
        assert statuses.index(CapabilityStatus.OBSERVED_CAPABILITY) < \
            statuses.index(CapabilityStatus.INFERRED_CAPABILITY)

    def test_the_surface_serialises(self):
        payload = json.loads(json.dumps(CapabilitySurface.from_spans(self.DOC).to_dict()))
        assert payload["bounded"] is False
        assert payload["by_status"]["OBSERVED_CAPABILITY"] >= 1

    def test_an_empty_document_yields_an_empty_surface(self):
        surface = CapabilitySurface.from_spans(otlp())
        assert len(surface) == 0
        assert surface.bounded is True


# ── analysis and the zero-config path ────────────────────────────────────────

class TestCapabilityFindings:

    @pytest.fixture
    def rich_file(self, tmp_path):
        return _write(tmp_path, "rich.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "UPDATE"}),
            span("02", "s", {"process.command_line": "/bin/bash -c ls"}),
            span("03", "t", {"gen_ai.tool.name": "frobnicate_widget"}),
            tools=["send_email"]))

    def _rules(self, path):
        return {f.rule_id: f for f in assure(path).analysis.findings}

    def test_capabilities_outside_the_manifest_hold(self, rich_file):
        finding = self._rules(rich_file)["RG-CAP-001"]
        assert finding.effect is RequirementEffect.HOLD
        assert finding.domain is AnalysisDomain.CAPABILITY

    def test_unidentified_tools_hold(self, rich_file):
        assert self._rules(rich_file)["RG-CAP-002"].effect is RequirementEffect.HOLD

    def test_no_manifest_at_all_is_advisory_not_a_false_violation(self, tmp_path):
        path = _write(tmp_path, "nomanifest.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"})))
        rules = self._rules(path)
        assert "RG-CAP-001" not in rules, (
            "with nothing declared there is no bound to have exceeded")
        assert rules["RG-CAP-003"].effect is RequirementEffect.ADVISORY

    def test_an_unbounded_surface_is_reported(self, rich_file):
        assert self._rules(rich_file)["RG-CAP-004"].effect is RequirementEffect.ADVISORY

    def test_declared_but_unexercised_is_reported(self, rich_file):
        assert "RG-CAP-006" in self._rules(rich_file)

    def test_capability_discovery_never_blocks(self, rich_file):
        """Evidence, not a verdict. Only a methodology can say a capability is banned."""
        outcome = assure(rich_file)
        capability_findings = [f for f in outcome.analysis.findings
                               if f.domain is AnalysisDomain.CAPABILITY]
        assert capability_findings
        assert all(f.effect is not RequirementEffect.BLOCK for f in capability_findings)

    def test_every_capability_finding_names_a_remedy(self, rich_file):
        for finding in assure(rich_file).analysis.findings:
            if finding.domain is AnalysisDomain.CAPABILITY:
                assert finding.remedy.strip()


class TestZeroConfigIntegration:

    @pytest.fixture
    def trace_file(self, tmp_path):
        return _write(tmp_path, "t.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT"}),
            span("02", "s", {"process.command_line": "/bin/bash -c ls"}),
            tools=["send_email"]))

    def test_the_outcome_carries_the_surface(self, trace_file):
        surface = assure(trace_file).capabilities
        assert surface is not None
        assert surface.capability(Capability.DATABASE_WRITE).observed

    def test_capabilities_land_on_the_case_as_one_evidence_record(self, trace_file):
        case = assure(trace_file).case
        records = [r.to_dict() for r in case.records("evidence")]
        carrying = [r for r in records if "capability_surface" in json.dumps(r)]
        assert len(carrying) == 1, (
            "one summary record; thirteen would inflate the evidence count a "
            "methodology measures")

    def test_capability_coverage_is_stated(self, trace_file):
        rows = [r.to_dict() for r in assure(trace_file).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "capability_discovery")
        assert row["status"] == "NOT_ASSESSED"
        assert row["bounded"] is False

    def test_a_bounded_observed_surface_counts_as_assessed(self, tmp_path):
        path = _write(tmp_path, "clean.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"})))
        rows = [r.to_dict() for r in assure(path).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "capability_discovery")
        assert row["status"] == "ASSESSED"

    def test_an_input_with_no_execution_evidence_says_so(self, tmp_path):
        path = _write(tmp_path, "m.json", {"hello": "world"})
        rows = [r.to_dict() for r in assure(path).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "capability_discovery")
        assert row["status"] == "NOT_ASSESSED"
        assert "nothing can be said" in row["note"]

    def test_the_report_distinguishes_observed_from_inferred(self, trace_file):
        text = render_text(assure(trace_file))
        assert "OBSERVED_CAPABILITY" in text
        assert "NOT an inventory" in text

    def test_capabilities_do_not_distort_producer_independence(self, trace_file):
        """release-gate's own summary must not read as a corroborating producer."""
        outcome = assure(trace_file)
        assert any(f.rule_id == "RG-PROV-002" for f in outcome.analysis.findings), (
            "the capability summary is release-gate's own derived record; counting it "
            "as a second producer would manufacture independence")

    def test_a_plain_otlp_trace_is_recognised_without_genai_attributes(self, trace_file):
        """Database and HTTP spans are valid OTLP; the adapters only score content."""
        from release_gate.assurance.ingest import InputKind, ingest_path

        normalisation = ingest_path(trace_file)
        assert normalisation.detection.kind is InputKind.OTLP_TRACE
        assert normalisation.execution is not None
