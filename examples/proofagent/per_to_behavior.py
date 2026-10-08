#!/usr/bin/env python3
"""ProofAgent's PER export → `release-gate.behavior/1`. An example mapping, not native support.

    python examples/proofagent/per_to_behavior.py run.per.json -o behaviour.json

ProofAgent Harness (0.13.0 and later) can write each evaluation as a **PER**,
the Portable Evaluation Record of the EIO-Agents standard
(`proof run … --per run.per.json`, or `proof per report.json -o run.per.json`).
The PER is versioned, and its JSON Schemas are published:
https://www.proofagent.ai/eio-agents/schema/per/2.1.2/per.schema.json.

This shim reads the few PER fields it needs and writes them in release-gate's
own generic behavioural-evaluation contract, which `release-gate assure`
reads natively. Every field path below is taken from the published PER 2.1.2
schema (2.1.0 and 2.1.1 carry the same paths). It reads nothing else, and
writes nothing it did not read:

    PER                                        behavior/1
    header.per_version                    →    (checked: 2.1.0–2.1.2; anything else refused)
    provenance.producer.{name,version}    →    producer.{id,version}
    provenance.run.run_id                 →    run_id, provenance.session
    provenance.run.completed_at           →    ran_at
    provenance.evaluator_models[]         →    provenance.evaluator_models
    subject.agent.model                   →    state.model
    subject.agent.version                 →    state["custom:agent-version"]
    subject.ai_bom.content_hash           →    state["artifact:ai-bom"]
    claims[].id                           →    checks[].id
    claims[].predicate                    →    checks[].claim_id ("pa:<predicate>")
    claims[].state                        →    checks[].outcome   (verbatim: APPLICABLE_PASS …)
    claims[].decided_by                   →    checks[].decided_by (verbatim)
    claims[].turn_indices                 →    checks[].turns
    claims[].provenance.model             →    checks[].evaluator_model (semantic claims)
    findings[] (kind BEHAVIOURAL)         →    violations[] (id, check_ids, proof, severity,
                                                             observed = display_label)
    release_recommendation.state          →    recommendation.decision (PASS / REVIEW / BLOCK)
    scores                                →    scores (verbatim; release-gate reads none of it)
    limitations[]                         →    limitations ("<limitation_id> at <field_path>")

CONTEXT_GAP findings are about the agent's context engineering, not its
behaviour, so they are not carried; the shim says how many it left out.

**Not re-graded, not reinterpreted.** A PER claim's state is passed through as
ProofAgent wrote it, and release-gate's one result table reads it: only
APPLICABLE_PASS passes, only APPLICABLE_FAIL fails, every evaluator-fault state
is inconclusive. ProofAgent's scores and readiness index are carried verbatim
beside its recommendation and are never read as confidence. A PER claim
carries no confidence of its own (the schema forbids one), and none is added.

**Status: an example.** Release-gate has not been tested against a PER that
ProofAgent produced; the bundled sample is synthetic, written to the
published schema. If a later PER version moves a field, this file is where it
moves — about seventy lines, and `release-gate.behavior/1` does not change.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

#: PER versions whose field paths this mapping was written against.
SUPPORTED_PER_VERSIONS = ("2.1.0", "2.1.1", "2.1.2")

#: The prefix that turns a PER predicate into a release-gate claim id. A
#: release's own claims name these in `depends_on` to rest on them.
CLAIM_PREFIX = "pa:"


class MappingError(ValueError):
    """A document this example does not map, with the reason."""


def _get(doc: Mapping[str, Any], *path: str) -> Any:
    value: Any = doc
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def per_to_behavior(per: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """(the behavior/1 document, notes on what was not carried)."""
    if not isinstance(per, Mapping):
        raise MappingError("a PER is a JSON object")
    version = _get(per, "header", "per_version")
    if version not in SUPPORTED_PER_VERSIONS:
        raise MappingError(f"PER version {version!r} is not one this mapping was written "
                           f"against ({', '.join(SUPPORTED_PER_VERSIONS)}); check the "
                           "field paths against its schema before extending the list")
    notes: List[str] = []
    run_id = _get(per, "provenance", "run", "run_id")
    producer = _get(per, "provenance", "producer") or {}
    state = {k: v for k, v in (
        ("model", _get(per, "subject", "agent", "model")),
        ("custom:agent-version", _get(per, "subject", "agent", "version")),
        ("artifact:ai-bom", _get(per, "subject", "ai_bom", "content_hash"))) if v}

    checks = []
    for claim in per.get("claims") or ():
        if not isinstance(claim, Mapping) or not claim.get("id"):
            notes.append("a PER claim without an id was not carried")
            continue
        predicate = str(claim.get("predicate") or "")
        check = {"id": claim["id"],
                 "claim_id": f"{CLAIM_PREFIX}{predicate}" if predicate else "",
                 "claim": (f"the agent passes ProofAgent's EIO check {predicate}"
                           if predicate else ""),
                 "behaviour": predicate,
                 "outcome": claim.get("state"),
                 "decided_by": claim.get("decided_by"),
                 "turns": list(claim.get("turn_indices") or ())}
        judge = _get(claim, "provenance", "model")
        if judge:
            check["evaluator_model"] = judge
        checks.append({k: v for k, v in check.items() if v not in ("", None)})

    violations = []
    context_gaps = 0
    for finding in per.get("findings") or ():
        if not isinstance(finding, Mapping):
            continue
        if finding.get("kind") != "BEHAVIOURAL":
            context_gaps += 1
            continue
        violations.append({k: v for k, v in {
            "id": finding.get("finding_id"),
            "check_ids": list(finding.get("claim_ids") or ()),
            "proof": finding.get("proof_status"),
            "witnessed": finding.get("witnessed"),
            "severity": finding.get("severity"),
            "observed": finding.get("display_label")}.items() if v is not None})
    if context_gaps:
        notes.append(f"{context_gaps} CONTEXT_GAP finding(s) are about context "
                     "engineering, not behaviour, and were not carried")

    document: Dict[str, Any] = {
        "schema": "release-gate.behavior/1",
        "producer": {"id": producer.get("name") or "proofagent-harness",
                     "version": producer.get("version"),
                     "origin": f"ProofAgent Harness, read from its PER {version} export "
                               "by the example mapping in examples/proofagent"},
        "run_id": run_id,
        "ran_at": _get(per, "provenance", "run", "completed_at"),
        "state": state,
        "provenance": {"session": run_id,
                       "toolchain": [f"{producer.get('name')}@{producer.get('version')}"],
                       "evaluator_models": [m.get("model") for m in
                                            _get(per, "provenance", "evaluator_models") or ()
                                            if isinstance(m, Mapping) and m.get("model")]},
        "checks": checks,
        "violations": violations,
        "limitations": [f"{item.get('limitation_id')} at {item.get('field_path')}"
                        for item in per.get("limitations") or ()
                        if isinstance(item, Mapping) and item.get("limitation_id")],
    }
    decision = _get(per, "release_recommendation", "state")
    if decision:
        document["recommendation"] = {
            "decision": decision,
            "basis": "ProofAgent's release recommendation under release semantics "
                     f"{_get(per, 'header', 'release_semantics') or 'unstated'}"}
    if "scores" in per:
        document["scores"] = per["scores"]
    return {k: v for k, v in document.items() if v is not None}, notes


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="ProofAgent PER → release-gate.behavior/1 "
                                                 "(an example mapping)")
    parser.add_argument("per", help="a PER JSON file (proof run … --per FILE)")
    parser.add_argument("-o", "--output", help="write here instead of stdout")
    args = parser.parse_args(argv)
    try:
        document, notes = per_to_behavior(
            json.loads(Path(args.per).read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(document, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
