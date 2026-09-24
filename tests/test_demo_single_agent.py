"""One agent, one migration — and the question that decides whether the product
is usable at all: can the engine say yes?

Every demo before this one produced HOLD or BLOCK. A single-agent case that
could not reach PROMOTE would mean the ordinary case is unservable, which is the
failure `GENERAL_AUTONOMOUS_ACTION_V1` was written to prevent.

The risk with a demo that promotes is that it was tuned until it did. So the
sensitivity tests carry as much weight here as the happy path: mutate the
artifact after its checks ran, raise the consequence past the bounded ceiling,
or invoke a tool nothing can identify, and the promote has to stop. A verdict
that only ever says yes is worth exactly what one that only ever says no is.
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from release_gate.assurance.case import Decision
from release_gate.assurance.evidence import EpistemicStatus
from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1
from release_gate.assurance.methodology import AppliesToCurrentState
from release_gate.demos.single_agent import (
    AGENT, DEFAULT_SCENARIO, MIGRATION_DIGEST, MIGRATION_SQL, MigrationScenario,
    SingleAgentRun, build_document, render, run)


@pytest.fixture(scope="module")
def promoted() -> SingleAgentRun:
    return run()


# ── it can say yes ──────────────────────────────────────────────────────────

def test_the_engine_promotes(promoted):
    assert promoted.case.verdict.decision is Decision.PROMOTE
    assert promoted.case.verdict.fired_rules


def test_the_report_offers_authorization_rather_than_granting_it(promoted):
    text = render(promoted)
    assert "PROMOTE" in text
    assert "Ready for human authorization." in text
    assert "The authorization is a person's" in text
    assert "authorized" not in text.lower().replace("authorization", "")


def test_no_claim_graph_is_required(promoted):
    """One agent doing one task has no claims to graph, and the profile says so."""
    assert promoted.analysis.claim_graph is None
    assert promoted.case.verdict.decision is Decision.PROMOTE


def test_every_submitted_record_is_mapped(promoted):
    """A submission the engine cannot fully read is one it should not promote."""
    assert promoted.outcome.normalisation.records_mapped == (
        promoted.outcome.normalisation.records_seen)
    assert not promoted.outcome.normalisation.skipped


def test_there_are_no_blocking_findings(promoted):
    assert promoted.outcome.attention.blocking == ()


# ── what the engine observed ────────────────────────────────────────────────

def test_the_three_artifacts_are_held_with_their_digests(promoted):
    held = {r.to_dict().get("logical_id"): r.to_dict().get("digest")
            for r in promoted.case.records("artifacts")}
    assert held.get("migration.sql") == MIGRATION_DIGEST
    assert "rollback.sql" in held and "dry-run-report.txt" in held


def test_the_production_database_action_is_observed(promoted):
    """The one capability that changes something outside the agent, and the whole
    reason a person is being asked."""
    exercised = {r.capability.value for r in promoted.analysis.capabilities.records}
    assert "DATABASE_WRITE" in exercised


def test_the_twelve_tool_calls_reach_the_execution_graph(promoted):
    """A graph, not a log: twelve calls to five tools are five nodes. The demo
    reports what the graph says rather than inventing a call count."""
    document = build_document()
    steps = next(r for r in document if r["record_type"] == "execution")["steps"]
    assert len([s for s in steps if s["type"] == "tool_call"]) == 12
    tools = [n for n in promoted.analysis.execution_graph.nodes
             if n.kind.value == "TOOL"]
    assert tools


def test_the_agent_reports_its_checks_without_self_certifying(promoted):
    """`EvidenceRecord` refuses a verification method on a DECLARED record,
    because a method without a finding implies a check that did not happen. The
    declaration is kept beside the record instead of on it."""
    declared = [(r.to_dict().get("metadata") or {}).get(
        "declared_verification_method") for r in promoted.case.records("evidence")]
    assert "TEST_SUITE" in declared and "SIMULATION" in declared

    # Only the records the agent submitted. Release-gate's own record of the
    # input it hashed is legitimately OBSERVED — it did observe it.
    for record in promoted.case.records("evidence"):
        payload = record.to_dict()
        if (payload.get("metadata") or {}).get("declared_verification_method"):
            assert payload.get("verification_method") is None
            assert payload.get("epistemic_status") == EpistemicStatus.DECLARED.value

    # And nothing the agent said put anything in the verification collection.
    assert not promoted.case.records("verification")


def test_the_checks_name_the_content_they_ran_against(promoted):
    held = {r.to_dict().get("digest") for r in promoted.case.records("artifacts")}
    for record in promoted.case.records("evidence"):
        payload = record.to_dict()
        if (payload.get("metadata") or {}).get("declared_verification_method"):
            assert payload.get("applies_to_digest") in held


# ── the acceptance is shown, not hidden ─────────────────────────────────────

def test_the_tautological_hold_is_accepted_and_still_reported(promoted):
    """The absence of an independent check is real and stays visible. What the
    methodology says is that an operator may authorise a bounded action on the
    execution record alone — and the report says that in those words."""
    reasons = " ".join(promoted.case.verdict.reasons)
    assert "RG-VERIF-001" in reasons
    assert "accepted by general-autonomous-action" in reasons
    assert "The finding stands and is shown" in reasons
    assert "What this rests on:" in render(promoted)


# ── sensitivity: the verdict must be able to say no ─────────────────────────

def test_an_artifact_edited_after_its_checks_ran_stops_promoting():
    """The gap this demo found.

    `GENERAL_AUTONOMOUS_ACTION_V1` had no AppliesToCurrentState requirement while
    the research and software profiles had three between them — so the profile
    governing the most ordinary case promoted a migration whose file had moved
    since its tests ran, with the drift reported as an advisory nobody had to act
    on.
    """
    mutated = dataclasses.replace(
        DEFAULT_SCENARIO, migration_sql=MIGRATION_SQL + "-- a later edit\n",
        verified_digest=MIGRATION_DIGEST)
    outcome = run(mutated).outcome
    assert outcome.decision is not Decision.PROMOTE
    assert "RG-ACT-004" in outcome.case.verdict.fired_rules


def test_the_general_profile_now_asks_whether_evidence_still_applies():
    present = [r.requirement_id for r in GENERAL_AUTONOMOUS_ACTION_V1.requirements
               if isinstance(r.predicate, AppliesToCurrentState)]
    assert present == ["RG-ACT-004"]


def test_asking_whether_evidence_still_applies_is_a_level_one_question():
    """L1 is defined as "who produced this, WHAT IT BINDS TO, and on whose
    authority". A single agent editing its own file has broken the binding with
    no second agent anywhere, so the question does not imply a workflow."""
    from release_gate.assurance.level import AssuranceLevel, assess_level
    assessment = assess_level(methodology=GENERAL_AUTONOMOUS_ACTION_V1)
    assert assessment.required <= AssuranceLevel.ATTRIBUTED


@pytest.mark.parametrize("field,value", [
    ("reversibility", "IRREVERSIBLE"),
    ("scope", "ORGANISATION"),
])
def test_raising_the_consequence_past_the_ceiling_withdraws_the_acceptance(
        field, value):
    """The acceptances are conditional. An action declared outside the bounded
    ceiling gets neither, and the tautological holds bite again."""
    raised = dataclasses.replace(DEFAULT_SCENARIO, **{field: value})
    assert run(raised).outcome.decision is not Decision.PROMOTE


def test_a_tool_nothing_can_identify_stops_promoting():
    """An unidentified tool is an unassessed part of the execution, not an
    absent one."""
    unknown = dataclasses.replace(DEFAULT_SCENARIO, test_tool="frobnicate_widget")
    outcome = run(unknown).outcome
    assert outcome.decision is not Decision.PROMOTE
    assert outcome.analysis.capabilities.unclassified_tools


def test_an_unstated_consequence_is_an_unassessed_one():
    document = [r for r in build_document() if r["record_type"] != "consequence"]
    from release_gate.assurance.ingest import detect_document, normalise
    from release_gate.assurance.zero_config import assure_normalisation
    import json

    content = ("\n".join(json.dumps(r, sort_keys=True) for r in document) + "\n").encode()
    detection = detect_document(document, filename="migration-run.jsonl")
    normalisation = normalise(document, detection, source="migration-run.jsonl",
                              content=content)
    outcome = assure_normalisation(
        normalisation, source_name="migration-run.jsonl",
        methodology=GENERAL_AUTONOMOUS_ACTION_V1)
    assert outcome.decision is not Decision.PROMOTE


# ── every rendered line comes from the engine ───────────────────────────────

def test_the_renderer_contains_no_literal_count():
    import inspect

    from release_gate.demos import single_agent

    source = inspect.getsource(single_agent.render)
    assert not re.search(r"(?<![\w:.>{])\d{2,}(?![\w}])", source)


def _value_after(text: str, label: str) -> str:
    lines = text.splitlines()
    return lines[lines.index(label) + 1].strip()


def test_the_rendered_figures_match_the_engine(promoted):
    text = render(promoted)
    assert _value_after(text, "Artifacts:") == str(len(
        [r for r in promoted.case.records("artifacts")
         if (r.to_dict().get("metadata") or {}).get("role") != "assurance-input"]))
    assert _value_after(text, "Unresolved findings:") == str(
        len(promoted.outcome.attention.blocking))
    assert _value_after(text, "Distinct tools called:") == str(len(
        [n for n in promoted.analysis.execution_graph.nodes
         if n.kind.value == "TOOL"]))


def test_the_submission_digest_is_the_one_an_approval_binds_to(promoted):
    text = render(promoted)
    assert promoted.case.subject.digest in text


def test_the_run_is_deterministic():
    assert run().case.case_digest == run().case.case_digest
