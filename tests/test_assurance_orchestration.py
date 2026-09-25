"""Evidence from any orchestrator, dependence on none.

Every export here is the real shape the framework writes: an OpenAI Agents trace
with nested `span_data`, a LangGraph checkpoint whose steps are a *mapping* of
node name to writes, a CrewAI task list, an AutoGen conversation and a Temporal
event history. Reading them from invented shapes would have hidden both defects
this file's fixtures caught.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.execution_graph import ExecutionNodeKind
from release_gate.assurance.ingest import InputKind
from release_gate.assurance.orchestration import (
    DETECT_FLOOR, ORCHESTRATION_SCHEMA_VERSION, PROFILES, OrchestrationError,
    OrchestratorProfile, ProfileResolution, StepReading, identify, profile_for,
    read_execution,
)
from release_gate.assurance.zero_config import assure

LANGGRAPH = {
    "config": {"configurable": {"thread_id": "t1"}},
    "values": {"plan": "migrate"}, "next": ["apply"], "checkpoint_id": "1ef-abc",
    "metadata": {"step": 3, "source": "loop",
                 "writes": {"plan_node": {"plan": "migrate"},
                            "apply_node": {"applied": True}}}}

OPENAI_AGENTS = {"traces": [{"workflow_name": "migration", "trace_id": "tr_1",
    "spans": [
        {"span_id": "sp_1", "parent_id": None,
         "span_data": {"type": "agent", "name": "Planner"}},
        {"span_id": "sp_2", "parent_id": "sp_1",
         "span_data": {"type": "function", "name": "read_file"}},
        {"span_id": "sp_3", "parent_id": "sp_1",
         "span_data": {"type": "generation", "name": "plan"}},
        {"span_id": "sp_4", "parent_id": "sp_1",
         "span_data": {"type": "guardrail", "name": "safety"}}]}]}

CREWAI = {"tasks_output": [
    {"name": "plan", "description": "plan the migration", "agent": "Planner",
     "raw": "done"},
    {"name": "apply", "description": "apply it", "agent": "Applier",
     "raw": "applied"}],
    "token_usage": {"total_tokens": 900}}

AUTOGEN = {"chat_history": [
    {"role": "user", "name": "admin", "content": "migrate the db"},
    {"role": "assistant", "name": "planner", "content": "here is a plan",
     "tool_calls": [{"function": {"name": "read_schema"}}]},
    {"role": "tool", "name": "read_schema", "content": "schema ok"}],
    "summary": "migration planned"}

TEMPORAL = {"events": [
    {"eventId": 1, "eventType": "WorkflowExecutionStarted"},
    {"eventId": 2, "eventType": "ActivityTaskScheduled"},
    {"eventId": 3, "eventType": "ActivityTaskCompleted"},
    {"eventId": 4, "eventType": "WorkflowExecutionCompleted"}]}

ALL = {"langgraph": LANGGRAPH, "openai_agents": OPENAI_AGENTS,
       "crewai": CREWAI, "autogen": AUTOGEN, "temporal": TEMPORAL}


# ── release-gate depends on no orchestrator ──────────────────────────────────

class TestNoDependence:

    def test_no_orchestrator_sdk_is_imported(self):
        import ast
        from pathlib import Path
        frameworks = {"langgraph", "langchain", "crewai", "autogen",
                      "temporalio", "agents", "llama_index", "haystack",
                      "semantic_kernel", "dspy"}
        root = Path(__file__).resolve().parent.parent / "release_gate"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            guarded = {id(n) for block in ast.walk(tree)
                       if isinstance(block, ast.Try)
                       for stmt in block.body
                       for n in ast.walk(stmt)
                       if isinstance(n, (ast.Import, ast.ImportFrom))}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                if id(node) in guarded:
                    continue
                offenders += [f"{path.name}:{node.lineno} {n}"
                              for n in names if n in frameworks]
        assert offenders == [], offenders

    def test_a_profile_never_establishes_correctness(self):
        """An export is the orchestrator's account of itself, and frameworks are
        built to report success."""
        for profile in PROFILES.values():
            assert profile.establishes_correctness is False
            assert profile.to_dict()["establishes_correctness"] is False

    def test_the_registry_cannot_disagree_with_itself(self):
        for name, profile in PROFILES.items():
            assert profile.name == name

    def test_the_neutral_vocabulary_was_already_sufficient(self):
        """Every kind any profile maps to already exists; no framework forced a
        new node kind into the graph."""
        neutral = {k.value for k in ExecutionNodeKind}
        for profile in PROFILES.values():
            assert set(profile.kind_map.values()) <= neutral
            if profile.default_kind:
                assert profile.default_kind in neutral


# ── every named framework is read ────────────────────────────────────────────

class TestEveryFramework:

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_it_is_identified(self, name):
        found = identify(ALL[name])
        assert found.profile is not None
        assert found.profile.name == name
        assert found.recognised
        assert found.confidence >= DETECT_FLOOR

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_no_framework_is_mistaken_for_another(self, name):
        """§10ac's lesson: a resolver that confidently misidentifies one thing as
        another is worse than one that admits it does not know."""
        for other, document in ALL.items():
            found = identify(document)
            assert found.profile.name == other, (
                f"{other} identified as {found.profile.name}")

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_its_steps_are_read(self, name):
        reading = read_execution(ALL[name])
        assert reading.mapped > 0
        assert reading.profile_name == name

    @pytest.mark.parametrize("name", sorted(ALL))
    def test_assure_produces_a_real_execution_graph(self, name, tmp_path):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(ALL[name]))
        outcome = assure(str(path))
        assert outcome.detection.kind is InputKind.ORCHESTRATOR_EXPORT
        graph = outcome.normalisation.execution
        assert graph is not None, "no execution graph was reconstructed"
        assert len(graph.nodes) > 0

    def test_openai_agents_keeps_its_delegation_structure(self):
        """The kind lives in a nested `span_data` beside the label; reading the
        label where the kind belonged mapped none of the run."""
        reading = read_execution(OPENAI_AGENTS)
        kinds = {r["label"]: r["node_kind"] for r in reading.records}
        assert kinds == {"Planner": "AGENT", "read_file": "TOOL",
                         "plan": "MODEL_CALL", "safety": "VERIFIER"}
        children = [r for r in reading.records if r["parent_id"]]
        assert len(children) == 3

    def test_langgraph_writes_are_a_mapping_not_a_list(self):
        """Read as a single row, two nodes collapsed into one and the node name
        — the only label a checkpoint carries — was lost."""
        reading = read_execution(LANGGRAPH)
        assert reading.seen == 2
        assert {r["label"] for r in reading.records} == {"plan_node", "apply_node"}

    def test_crewai_reconstructs_delegation_from_the_agent_field(self):
        reading = read_execution(CREWAI)
        assert {r["parent_id"] for r in reading.records} == {
            "crewai:Planner", "crewai:Applier"}

    def test_crewai_agents_are_referenced_but_not_observed(self, tmp_path):
        """An agent named as a parent that never arrives as a step is exactly
        what UNOBSERVED is for."""
        path = tmp_path / "crew.json"
        path.write_text(json.dumps(CREWAI))
        graph = assure(str(path)).normalisation.execution
        assert ExecutionNodeKind.UNOBSERVED in {n.kind for n in graph.nodes}

    def test_autogen_separates_the_human_from_the_agents(self):
        reading = read_execution(AUTOGEN)
        kinds = [r["node_kind"] for r in reading.records]
        assert kinds == ["HUMAN", "AGENT", "TOOL"]

    def test_temporal_maps_its_event_vocabulary(self):
        reading = read_execution(TEMPORAL)
        assert [r["node_kind"] for r in reading.records] == [
            "AGENT", "TASK", "ACTION", "ACTION"]

    def test_steps_carry_which_framework_they_came_from(self):
        for name, document in ALL.items():
            for record in read_execution(document).records:
                assert record["attributes"]["orchestrator"] == name


# ── a step that cannot be mapped is counted, not dropped ─────────────────────

class TestNothingIsDroppedSilently:

    def test_an_unmapped_kind_is_counted(self):
        """The adapters' rule from the start: never invent a step, report the
        gap."""
        document = {"events": [
            {"eventId": 1, "eventType": "WorkflowExecutionStarted"},
            {"eventId": 2, "eventType": "SomeFutureEventType"}]}
        reading = read_execution(document, PROFILES["temporal"])
        assert reading.seen == 2
        assert reading.mapped == 1
        assert len(reading.unmapped) == 1
        assert reading.unmapped[0]["kind"] == "SomeFutureEventType"
        assert not reading.complete

    def test_a_step_with_no_kind_and_no_default_is_counted(self):
        profile = OrchestratorProfile(
            name="strict", label="strict", step_path=("steps", "[]"),
            kind_keys=("kind",), kind_map={}, default_kind="")
        reading = read_execution({"steps": [{"id": "1"}]}, profile)
        assert reading.mapped == 0 and len(reading.unmapped) == 1
        assert "unknown" in reading.unmapped[0]["reason"]

    def test_a_complete_reading_says_so(self):
        assert read_execution(TEMPORAL).complete

    def test_the_unmapped_count_reaches_the_graph_notes(self, tmp_path):
        path = tmp_path / "t.json"
        path.write_text(json.dumps({"events": [
            {"eventId": 1, "eventType": "WorkflowExecutionStarted"},
            {"eventId": 2, "eventType": "SomeFutureEventType"}]}))
        graph = assure(str(path)).normalisation.execution
        # On `completeness.notes`, where the graph keeps what it could not fully
        # observe — not on the graph itself.
        assert any("counted rather than guessed" in note
                   for note in graph.completeness.notes)

    def test_inherent_gaps_travel_with_every_reading(self):
        """A gap that depends on being remembered is one that goes
        unmentioned."""
        assert any("replay" in gap for gap in read_execution(TEMPORAL).gaps)
        assert any("not whether the receiving agent was entitled" in gap
                   for gap in read_execution(OPENAI_AGENTS).gaps)

    def test_the_gaps_reach_the_graph_too(self, tmp_path):
        path = tmp_path / "t.json"
        path.write_text(json.dumps(TEMPORAL))
        graph = assure(str(path)).normalisation.execution
        assert any("temporal:" in note for note in graph.completeness.notes)


# ── an unknown framework is a refusal, not a guess ───────────────────────────

class TestUnknownFrameworks:

    def test_an_unrecognised_export_resolves_to_nothing(self):
        found = identify({"some": "shape", "nobody": "wrote down"})
        assert found.profile is None
        assert not found.recognised
        assert "reported as unread rather than as an empty run" in found.basis

    def test_reading_one_without_a_profile_is_refused(self):
        with pytest.raises(OrchestrationError) as exc:
            read_execution({"unknown": "shape"})
        assert "plausible and wrong" in str(exc.value)

    def test_it_still_produces_a_case(self, tmp_path):
        """Unrecognised is not unusable: the file is hashed and recorded."""
        path = tmp_path / "x.json"
        path.write_text(json.dumps({"mystery": [1, 2, 3]}))
        outcome = assure(str(path))
        assert outcome.detection.kind is InputKind.UNRECOGNISED
        assert outcome.case.verdict is not None

    def test_an_unknown_profile_name_is_refused_by_name(self):
        with pytest.raises(OrchestrationError) as exc:
            profile_for("some_future_framework")
        assert "is not one it refuses" in str(exc.value)

    def test_a_profile_must_say_where_the_steps_are(self):
        with pytest.raises(OrchestrationError) as exc:
            OrchestratorProfile(name="p", label="l")
        assert "unreadable one" in str(exc.value)

    def test_a_profile_must_be_named(self):
        with pytest.raises(OrchestrationError) as exc:
            OrchestratorProfile(name=" ", label="l", step_path=("a",))
        assert "cite which framework" in str(exc.value)


# ── a custom or future framework needs no code change ────────────────────────

class TestCustomFrameworks:

    def test_a_private_framework_is_a_profile(self):
        house = OrchestratorProfile(
            name="house_runner", label="our own agent runner",
            step_path=("run", "activities", "[]"),
            id_keys=("uid",), parent_keys=("caller",), label_keys=("title",),
            kind_keys=("activity_kind",),
            kind_map={"think": "MODEL_CALL", "do": "TOOL", "check": "VERIFIER"},
            carry_keys=("duration_ms",),
            inherent_gaps=("our runner does not record retries",))
        document = {"run": {"activities": [
            {"uid": "a1", "title": "decide", "activity_kind": "think"},
            {"uid": "a2", "caller": "a1", "title": "write", "activity_kind": "do",
             "duration_ms": 12}]}}
        reading = read_execution(document, house)
        assert reading.mapped == 2
        assert reading.records[0]["node_kind"] == "MODEL_CALL"
        assert reading.records[1]["parent_id"] == "house_runner:a1"
        assert reading.records[1]["attributes"]["duration_ms"] == 12
        assert reading.gaps == ("our runner does not record retries",)

    def test_a_future_framework_needs_no_new_module(self):
        """Adding one is a row. The adapters are modules; profiles are data, and
        a code path per orchestrator is how a consumer becomes a dependent."""
        before = set(PROFILES)
        future = OrchestratorProfile(name="framework_2031", label="future",
                                     step_path=("ops", "[]"),
                                     default_kind="ACTION")
        assert read_execution({"ops": [{"id": 1}, {"id": 2}]}, future).mapped == 2
        assert set(PROFILES) == before  # the registry is untouched

    def test_a_mapping_shaped_step_list_is_supported(self):
        """LangGraph is not the only framework that keys steps by name."""
        profile = OrchestratorProfile(name="keyed", label="keyed",
                                      step_path=("stages", "{}"),
                                      id_keys=("_key",), label_keys=("_key",),
                                      default_kind="TASK")
        reading = read_execution({"stages": {"one": {"ok": True},
                                             "two": {"ok": False}}}, profile)
        assert {r["label"] for r in reading.records} == {"one", "two"}


# ── the reading is the framework's own account ───────────────────────────────

class TestEpistemicStatus:

    def test_a_framework_reporting_success_does_not_verify_anything(self, tmp_path):
        """Treating a framework's self-report as observation would put the thing
        being assessed in charge of the assessment."""
        path = tmp_path / "crew.json"
        path.write_text(json.dumps(CREWAI))
        outcome = assure(str(path))
        from release_gate.assurance.evidence import EpistemicStatus
        # The evidence collection also holds release-gate's own derived profiles,
        # which carry no epistemic status; only the evidence records do.
        statuses = {r.epistemic_status for r
                    in outcome.case.collection("evidence").materialised
                    if hasattr(r, "epistemic_status")}
        assert statuses, "no evidence records to check"
        assert EpistemicStatus.VERIFIED not in statuses

    def test_the_reading_says_so_in_its_payload(self):
        assert read_execution(TEMPORAL).to_dict()[
            "establishes_correctness"] is False

    def test_a_completed_workflow_does_not_promote(self, tmp_path):
        """Temporal reports every activity completed. That is the framework
        saying its own run went fine."""
        path = tmp_path / "t.json"
        path.write_text(json.dumps(TEMPORAL))
        assert assure(str(path)).case.verdict.decision.value != "PROMOTE"
