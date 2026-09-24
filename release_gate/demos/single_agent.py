"""One agent, one migration, and the same architecture that handles ten thousand.

The frontier demo answers "does this hold up at scale". This one answers the
question that decides whether the product is usable at all: **can it say yes?**

A single coding agent writes a migration, runs its tests, runs a dry-run against
a copy, and asks to apply it. There is no claim graph, no replication, no
adversarial review and no independent producer, because one agent doing one task
has none of those by construction. A system that demanded them would mean the
ordinary case can never be promoted however careful it was — penalising a case
for being small, which is the volume judgement Invariants 6 and 12 refuse.

So this runs on `GENERAL_AUTONOMOUS_ACTION_V1`, which asks for four things: an
identified subject, an execution record that was actually reconstructed, a
statement of what the action would do, and coverage. It accepts the two
structural holds that are tautological at this scale — `RG-PROV-002` (one
producer) and `RG-VERIF-001` (no independent check) — **and only while the
declared consequence stays inside stated bounds**. An unstated consequence is an
unassessed one rather than a small one, and a migration declared irreversible
gets neither acceptance.

**The acceptance shows the finding, it does not erase it.** The case still
records that everything traces to one producer and that nothing independently
verified the work. What the methodology says is that an operator may authorise a
bounded, reversible action on the strength of its own execution record — which
the packet states in those words, so the person signing knows what they are
signing on.

**PROMOTE is a recommendation.** The report ends "Ready for human
authorization", never "authorized": the engine has finished its work and the act
is still a person's (Invariant 15).

Nothing here is tuned until it promotes. `tests/test_demo_single_agent.py`
proves the verdict is sensitive in both directions — mutate the artifact after
verification and it stops promoting; raise the consequence past the bounded
ceiling and the acceptances are withdrawn — because a verdict that only ever
says yes is worth exactly as much as one that only ever says no.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1
from release_gate.assurance.zero_config import assure_normalisation
from release_gate.assurance.ingest import detect_document, normalise

__all__ = [
    "DEFAULT_SCENARIO",
    "MigrationScenario",
    "SingleAgentRun",
    "build_document",
    "render",
    "run",
]

#: The migration the agent wrote. Real bytes, so the digest is a real digest.
MIGRATION_SQL = """\
-- 2026_04_02_add_orders_customer_idx
BEGIN;
CREATE INDEX CONCURRENTLY IF NOT EXISTS orders_customer_idx
    ON orders (customer_id);
COMMIT;
"""

ROLLBACK_SQL = """\
-- rollback for 2026_04_02_add_orders_customer_idx
BEGIN;
DROP INDEX CONCURRENTLY IF EXISTS orders_customer_idx;
COMMIT;
"""

DRY_RUN_REPORT = """\
plan: CREATE INDEX CONCURRENTLY on orders(customer_id)
estimated duration: 41s
locks taken: none (CONCURRENTLY)
rows rewritten: 0
"""

RUN_AT = "2026-04-02T14:07:00Z"


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


MIGRATION_DIGEST = _sha256(MIGRATION_SQL)
ROLLBACK_DIGEST = _sha256(ROLLBACK_SQL)
DRY_RUN_DIGEST = _sha256(DRY_RUN_REPORT)

AGENT = "agent://migrations/coder-1"


@dataclass(frozen=True)
class MigrationScenario:
    """What the agent did. Every count here is generated and then observed."""

    tool_calls: int = 12
    #: The content the agent shipped. Overridden by the mutation test, which is
    #: how the demo proves the digest match is load-bearing rather than decorative.
    migration_sql: str = MIGRATION_SQL
    #: What the operator declared about the action. Overridden by the ceiling
    #: test, which is how the demo proves the acceptances are conditional.
    reversibility: str = "REVERSIBLE"
    scope: str = "SINGLE_SUBJECT"
    data_impact: str = "MODIFIED"
    tests_pass: bool = True
    dry_run_passes: bool = True
    #: Overridden by the sensitivity test to a name nothing can classify.
    test_tool: str = "bash"
    #: What the checks were run against. Normally the migration's own digest —
    #: the mutation test pins it to the pre-edit content, which is what "the
    #: artifact moved after it was verified" actually looks like: the file
    #: changes, the checks do not, and they still name what they ran on.
    verified_digest: Optional[str] = None

    @property
    def migration_digest(self) -> str:
        return _sha256(self.migration_sql)

    @property
    def checked_digest(self) -> str:
        """The digest the tests and dry-run were run against."""
        return self.verified_digest or self.migration_digest


DEFAULT_SCENARIO = MigrationScenario()


def build_document(scenario: MigrationScenario = DEFAULT_SCENARIO) -> List[Dict[str, Any]]:
    """The run, in the shape a coding agent's telemetry actually arrives in.

    A native trace with the tool calls, plus the records the agent submitted
    alongside it. Nothing here is a release-gate-specific format the agent had to
    learn: the trace is the trace, and the artifacts and checks are declared next
    to it.
    """
    digest = scenario.migration_digest

    # Twelve tool calls: reading the schema, writing the migration and its
    # rollback, running the suite, running the dry-run, and the production apply
    # the agent is asking permission for.
    # Tool names as real tooling spells them, which is also what lets the
    # capability classifier identify them. A tool it cannot identify is an
    # unassessed part of the execution rather than an absent one, and holds the
    # case — `test_an_unidentifiable_tool_holds_the_case` shows that happening.
    steps: List[Dict[str, Any]] = [
        {"type": "tool_call", "tool": "read_file"},
        {"type": "tool_call", "tool": "read_file"},
        {"type": "tool_call", "tool": "sql_query"},
        {"type": "llm_call", "model": "coder", "tokens": 2_140},
        {"type": "tool_call", "tool": "write_file"},
        {"type": "tool_call", "tool": "write_file"},
        {"type": "tool_call", "tool": scenario.test_tool},
        {"type": "tool_call", "tool": "read_file"},
        {"type": "tool_call", "tool": "sql_query"},
        {"type": "tool_call", "tool": "read_file"},
        {"type": "tool_call", "tool": "read_file"},
        # The one production action, and the whole reason a person is being asked.
        {"type": "tool_call", "tool": "db_migrate"},
    ]
    # The count is the scenario's; the record is what the engine will observe.
    while len([s for s in steps if s["type"] == "tool_call"]) < scenario.tool_calls:
        steps.append({"type": "tool_call", "tool": "read_file"})

    records: List[Dict[str, Any]] = [
        # The three artifacts, each with the digest of its real bytes.
        {"record_type": "artifact", "artifact_id": "migration.sql", "kind": "CODE",
         "digest": digest, "created_by": AGENT,
         "producer": {"producer_id": AGENT, "kind": "agent"}},
        {"record_type": "artifact", "artifact_id": "rollback.sql", "kind": "CODE",
         "digest": ROLLBACK_DIGEST, "created_by": AGENT,
         "producer": {"producer_id": AGENT, "kind": "agent"}},
        {"record_type": "artifact", "artifact_id": "dry-run-report.txt",
         "kind": "DOCUMENT", "digest": DRY_RUN_DIGEST, "created_by": AGENT,
         "producer": {"producer_id": AGENT, "kind": "agent"}},

        # What the operator says this action would do. Load-bearing: both
        # structural acceptances are conditioned on it, and an unstated
        # consequence gets neither.
        {"record_type": "consequence",
         "REVERSIBILITY": scenario.reversibility, "SCOPE": scenario.scope,
         "FINANCIAL_IMPACT": "NONE", "DATA_IMPACT": scenario.data_impact,
         "SECURITY_IMPACT": "NONE", "LEGAL_IMPACT": "NONE"},
    ]

    # The checks, each bound to the digest it ran against. That binding is what
    # makes "subject hash matches verified artifact" a checkable statement rather
    # than a claim: mutate the file and these stop applying to it.
    checked = scenario.checked_digest
    if scenario.tests_pass:
        records.append({
            "record_type": "evidence", "evidence_id": "tests", "kind": "TEST_RESULT",
            "producer": {"producer_id": "ci://pytest", "kind": "tool"},
            "verification_method": "TEST_SUITE", "applies_to_digest": checked,
            "timestamp": RUN_AT,
            "coverage_note": ("the migration suite, including the rollback path; "
                              "does not cover production data volume")})
    if scenario.dry_run_passes:
        records.append({
            "record_type": "evidence", "evidence_id": "dry-run",
            "kind": "SIMULATION_RESULT",
            "producer": {"producer_id": "tool://pg-dry-run", "kind": "tool"},
            "verification_method": "SIMULATION", "applies_to_digest": checked,
            "timestamp": RUN_AT,
            "content_reference": {"kind": "FILE", "locator": "dry-run-report.txt"},
            "coverage_note": ("applied to a restored copy of production; does not "
                              "cover concurrent write load")})

    # One envelope. The trace rides as an `execution` record in the native trace
    # shape, which the ingest folds into the execution graph — so the agent
    # submits one document rather than learning two formats.
    return [{"record_type": "execution", "trace_id": "migration-run-8812",
             "steps": steps}] + records


@dataclass(frozen=True)
class SingleAgentRun:
    """What the engine returned. Nothing here is computed by the demo."""

    outcome: Any
    scenario: MigrationScenario

    @property
    def case(self) -> Any:
        return self.outcome.case

    @property
    def analysis(self) -> Any:
        return self.outcome.analysis


def run(scenario: MigrationScenario = DEFAULT_SCENARIO) -> SingleAgentRun:
    """Put the run through the engine unmodified."""
    document = build_document(scenario)
    # The bytes the agent submitted, so the subject's digest is OBSERVED because
    # release-gate hashed them — the same path the incremental session takes for
    # records that arrive over a wire and never touch a disk.
    content = ("\n".join(json.dumps(row, sort_keys=True)
                         for row in document) + "\n").encode()
    detection = detect_document(document, filename="migration-run.jsonl")
    normalisation = normalise(document, detection, source="migration-run.jsonl",
                              content=content)
    outcome = assure_normalisation(
        normalisation,
        source_name="migration-run.jsonl",
        methodology=GENERAL_AUTONOMOUS_ACTION_V1,
        objective="Apply migration.sql to the production orders database",
        requested_decision="Apply this migration to production",
        requested_action="apply migration.sql to prod-eu")
    return SingleAgentRun(outcome=outcome, scenario=scenario)


#: Width of the report's rules. Named so the only numbers in `render` are the
#: engine's, the same discipline the frontier demo's renderer keeps.
RULE_WIDTH = 24


def render(run_result: SingleAgentRun) -> str:
    """The report. Every figure is read from `run_result`; none is written here."""
    outcome, case, analysis = run_result.outcome, run_result.case, run_result.analysis
    execution = getattr(analysis, "execution_graph", None)
    surface = getattr(analysis, "capabilities", None)
    consequence = getattr(outcome, "consequence", None)
    verdict = case.verdict

    tool_calls = tuple(n for n in (getattr(execution, "nodes", ()) or ())
                       if getattr(getattr(n, "kind", None), "value", "") == "TOOL")
    called = tuple(e for e in (getattr(execution, "edges", ()) or ())
                   if getattr(getattr(e, "edge_type", None), "value", "") == "CALLED")
    artifacts = tuple(r for r in case.records("artifacts")
                      if (r.to_dict().get("metadata") or {}).get("role")
                      != "assurance-input")
    checks = tuple(r for r in case.records("evidence")
                   if (r.to_dict().get("metadata") or {}).get(
                       "declared_verification_method"))
    held_digests = {str(r.to_dict().get("digest") or "")
                    for r in case.records("artifacts")}
    stale = tuple(c for c in checks
                  if str(c.to_dict().get("applies_to_digest") or "") not in held_digests)
    accepted = tuple(r for r in verdict.reasons if "accepted by" in r)

    lines = [
        "RELEASE-GATE",
        "",
        # The subject is the SUBMISSION, hashed by release-gate — that is what
        # the zero-config path binds an approval to, and calling it migration.sql
        # would name a thing the approval does not cover. The migration and its
        # digest are shown below, where they belong.
        "Submission (what an approval would bind to):",
        f"{case.subject.content_reference.locator}",
        f"{case.subject.digest}",
        "",
        "Action requested:",
        f"{case.subject.requested_action}",
        "",
        "Agent:",
        AGENT,
        "",
        # The execution graph is a graph, not a log: twelve calls to five tools
        # are five nodes. Reporting the edge count as "tool calls" would be the
        # demo inventing a figure the engine did not give it.
        "Distinct tools called:",
        f"{len(tool_calls)}",
        "",
        "Call edges in the execution graph:",
        f"{len(called)}",
        "",
        "Artifacts:",
        f"{len(artifacts)}",
        "",]
    for record in sorted(artifacts, key=lambda r: str(r.to_dict().get("logical_id"))):
        payload = record.to_dict()
        lines.append(f"  {payload.get('logical_id')}  {payload.get('digest')}")
    lines += [
        "",
        "Capabilities exercised:",
        (", ".join(sorted(r.capability.value for r in surface.records))
         if surface is not None else "(not derived)"),
        "",
        "Capabilities that mutate something outside the agent:",
        (", ".join(sorted(r.capability.value for r in surface.mutating_external))
         or "none" if surface is not None else "(not derived)"),
        "",
        "Checks the agent reports running:",
        (", ".join(f"{c.to_dict()['metadata']['declared_verification_method']}"
                   for c in checks) or "none"),
        "",
        "…each bound to content this case holds:",
        f"{len(checks) - len(stale)} of {len(checks)}",
        "",
        "Declared consequence:",
        (f"{consequence.value('REVERSIBILITY')} · {consequence.value('SCOPE')} · "
         f"data {consequence.value('DATA_IMPACT')}" if consequence else "(unstated)"),
        "",
        "Unresolved findings:",
        f"{len(outcome.attention.blocking)}",
        "",
        "─" * RULE_WIDTH,
        "",
        verdict.decision.value,
        "",
    ]

    if verdict.decision.value == "PROMOTE":
        lines.append("Ready for human authorization.")
    else:
        lines.append("Not ready. " + "; ".join(verdict.fired_rules))
    lines.append("")

    if accepted:
        lines += ["What this rests on:", ""]
        for reason in accepted:
            lines.append(f"  {reason}")
        lines.append("")

    lines += [
        "─" * RULE_WIDTH,
        "",
        "Release-gate recommends. The authorization is a person's, and this "
        "report is what they are being asked to sign.",
    ]
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m release_gate.demos.single_agent`."""
    print(render(run()))
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
