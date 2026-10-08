#!/usr/bin/env python3
"""ProofAgent's behavioural evidence, decided with static and runtime evidence.

    python examples/proofagent/run_example.py           # the graph and the decision
    python examples/proofagent/run_example.py --check   # assert it; exit 1 on drift

    ProofAgent ─PER─▶ per_to_behavior.py ─behavior/1─▶ release-gate
        ─▶ claim / evidence graph ◀─ static analysis, runtime traces
        ─▶ admission decision

`sample-run.per.json` is a **synthetic** PER excerpt written to the published
PER 2.1.2 schema; it was not produced by ProofAgent. The mapping is an example
(see README.md). What this script shows is the architecture: ProofAgent's
verdicts arrive as attributed behavioural evidence, become checks of claims the
release rests on, sit beside the other evidence in one graph, and the decision
is release-gate's, under its declared methodology. ProofAgent's own
recommendation and scores are recorded and decide nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
for path in (str(ROOT), str(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)

from per_to_behavior import per_to_behavior  # noqa: E402
from release_gate.assurance.admission_report import build_admission_report  # noqa: E402
from release_gate.assurance.methodologies import default_registry  # noqa: E402
from release_gate.assurance.zero_config import AssuranceOutcome, assure  # noqa: E402

METHODOLOGY = "general-agent-action@1.0.0"
ROOT_CLAIM = "cl_no_unapproved_action"


def admit(per: Mapping[str, Any]) -> AssuranceOutcome:
    """Map the PER, then decide over it with everything else, as one case.

    The mapped document is written beside the release in a temporary copy, so
    every record names its file relative to the example and the case is the
    same wherever this runs.
    """
    document, _ = per_to_behavior(per)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "evidence").mkdir()
        (work / "release.jsonl").write_bytes((HERE / "release.jsonl").read_bytes())
        for item in (HERE / "evidence").iterdir():
            if item.is_file():
                (work / "evidence" / item.name).write_bytes(item.read_bytes())
        (work / "evidence" / "proofagent.behavior.json").write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8")
        here = Path.cwd()
        os.chdir(work)
        try:
            return assure("release.jsonl", evidence=["evidence"],
                          methodology=default_registry().resolve(METHODOLOGY))
        finally:
            os.chdir(here)


def load_per() -> Dict[str, Any]:
    return json.loads((HERE / "sample-run.per.json").read_text(encoding="utf-8"))


def graph(outcome: AssuranceOutcome) -> Dict[str, Any]:
    """The root claim, what it rests on, and every item each claim was read from."""
    resolution = outcome.analysis.resolution
    producers = {}
    for record in outcome.case.collection("evidence").materialised:
        if hasattr(record, "evidence_id"):
            producers[record.evidence_id] = record.producer.producer_id
    attempts = {a.verification_id: a
                for a in outcome.case.collection("verification").materialised
                if hasattr(a, "verification_id")}
    for claim in outcome.case.collection("claims").materialised:
        for attempt in getattr(claim, "verification_attempts", ()) or ():
            attempts[attempt.verification_id] = attempt

    def node(claim_id: str) -> Dict[str, Any]:
        claim = resolution.of(claim_id)
        items = []
        for item in claim.items:
            attempt = attempts.get(item.item_id)
            items.append({
                "item": item.item_id, "role": item.role.value,
                "method": item.method or (attempt.method.value if attempt else ""),
                "from": (attempt.verifier if attempt else producers.get(item.item_id, "")),
                "binding": item.binding})
        return {"claim": claim_id, "status": claim.status.value, "rule": claim.rule,
                "statement": claim.statement, "items": items,
                "depends_on": [d for d, _ in claim.dependencies]}

    root = node(ROOT_CLAIM)
    grounding = node("cl_grounded_answers")
    return {"root": root, "dependencies": [node(d) for d in root["depends_on"]],
            "grounding": grounding,
            "grounding_dependencies": [node(d) for d in grounding["depends_on"]]}


def reading(outcome: AssuranceOutcome) -> Dict[str, Any]:
    report = build_admission_report(outcome).to_dict()
    origin = {e.producer_id: e for e in outcome.evidence_origin.entries}
    pa = origin.get("proofagent-harness")
    attestation = [r for r in outcome.case.collection("evidence").materialised
                   if hasattr(r, "evidence_id") and r.producer.producer_id == "proofagent-harness"
                   and r.evidence_type.value == "ATTESTATION"]
    return {
        "decision": report["decision"],
        "blocking": [c["condition_id"] for c in report["blocking_reasons"]],
        "graph": graph(outcome),
        "counterexamples": [(c["producer"], c["claim"], c["standing"])
                            for c in report["counterexamples"]],
        "proofagent_read_not_run": bool(pa) and pa.origin.value == "READ",
        "proofagent_recommendation": [dict(r.content.get("native") or {}).get("decision")
                                      for r in attestation],
        "sources": sorted(s["label"] for s in report["evidence_sources"]["imported"]),
    }


def check(facts: Mapping[str, Any]) -> List[str]:
    problems: List[str] = []

    def expect(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    g = facts["graph"]
    deps = {d["claim"]: d for d in g["dependencies"]}
    autonomy = deps.get("pa:eio.predicate.autonomy-boundary-exceeded", {})
    guardrail = deps.get("pa:eio.predicate.guardrail-circumvented", {})
    composed = deps.get("pa:eio.predicate.capabilities-compose-to-prohibited-outcome", {})
    expect(facts["decision"] == "BLOCK", f"decision {facts['decision']}, expected BLOCK")
    expect(g["root"]["status"] == "CONTRADICTED" and g["root"]["rule"] == "CR-04",
           f"root claim {g['root']['status']} by {g['root']['rule']}, expected "
           "CONTRADICTED by CR-04 (a claim it depends on is contradicted)")
    expect(autonomy.get("status") == "CONTRADICTED",
           f"the autonomy check is {autonomy.get('status')}, expected CONTRADICTED")
    expect(("proofagent-harness", "pa:eio.predicate.autonomy-boundary-exceeded", "VALID")
           in facts["counterexamples"],
           f"ProofAgent's proven violation is not a counterexample: {facts['counterexamples']}")
    expect(guardrail.get("status") in ("SUPPORTED", "ESTABLISHED"),
           f"the passing guardrail checks left it {guardrail.get('status')}")
    expect(composed.get("status") == "UNKNOWN",
           f"an evaluator error left its check {composed.get('status')}, expected UNKNOWN")
    judged = g["grounding_dependencies"][0] if g["grounding_dependencies"] else {}
    semantic = [i for i in judged.get("items", ()) if i["method"] == "CROSS_MODEL_REVIEW"]
    expect(bool(semantic), "the jury-decided check is not a CROSS_MODEL_REVIEW")
    expect(judged.get("status") == "SUPPORTED" and g["grounding"]["status"] != "ESTABLISHED",
           f"a model jury's verdict left its claim {judged.get('status')}; it supports "
           "and never establishes under the default policy")
    root_methods = {i["method"] for i in g["root"]["items"]}
    expect("STATIC_ANALYSIS" in root_methods,
           f"static analysis is not in the root claim's graph: {root_methods}")
    expect(any(i["from"] == "langfuse" for i in g["root"]["items"]),
           "runtime traces are not in the root claim's graph")
    expect(facts["proofagent_read_not_run"], "ProofAgent's evidence is not marked read, "
                                             "not run, by release-gate")
    expect(facts["proofagent_recommendation"] == ["BLOCK"],
           f"ProofAgent's recommendation was not recorded: "
           f"{facts['proofagent_recommendation']}")
    return problems


def render(facts: Mapping[str, Any]) -> str:
    g = facts["graph"]
    lines = [f"{g['root']['claim']}: {g['root']['status']} ({g['root']['rule']})",
             f"  \"{g['root']['statement']}\""]
    for item in g["root"]["items"]:
        lines.append(f"    {item['role']:<14} {item['method'] or '-':<18} from "
                     f"{item['from'] or '-'}")
    lines.append("  depends on:")
    for dep in g["dependencies"]:
        lines.append(f"    {dep['claim']}: {dep['status']} ({dep['rule']})")
        for item in dep["items"]:
            lines.append(f"      {item['role']:<14} {item['method'] or '-':<18} from "
                         f"{item['from'] or '-'}")
    grounding = g["grounding"]
    lines.append(f"{grounding['claim']}: {grounding['status']} ({grounding['rule']})")
    lines.append("  depends on:")
    for dep in g["grounding_dependencies"]:
        lines.append(f"    {dep['claim']}: {dep['status']} ({dep['rule']}) — a model "
                     "jury's verdict: it supports, and the default policy does not let "
                     "it establish")
        for item in dep["items"]:
            lines.append(f"      {item['role']:<14} {item['method'] or '-':<18} from "
                         f"{item['from'] or '-'}")
    lines.append("")
    lines.append(f"ProofAgent recommended: {', '.join(facts['proofagent_recommendation'])} "
                 "(recorded; it decides nothing here)")
    lines.append(f"Release-Gate decided:  {facts['decision']} under {METHODOLOGY} — "
                 f"blocking: {', '.join(facts['blocking'])}")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    facts = reading(admit(load_per()))
    print(render(facts))
    if args.check:
        problems = check(facts)
        if problems:
            print("\nexample check FAILED:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        print("\nexample check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
