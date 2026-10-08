#!/usr/bin/env python3
"""Six tools look at one release of a money-moving agent. Release-Gate decides.

    python examples/demo-admission/run_demo.py            # the reasoning, under both policies
    python examples/demo-admission/run_demo.py --check    # assert it; exit 1 on any drift
    python examples/demo-admission/run_demo.py --out DIR  # also write each Admission Report

The claim at stake: "No transfer executes without a signed human approval for
that exact transfer". Every evidence file in `evidence/` is what an outside tool
emits about the candidate; `release.jsonl` states the candidate, the claim, what
the eval suite declares, and the production traces. The methodology and the two
resolution policies are the declared policy. Nothing here is a screenshot: the
decision is computed from these files every time this runs, and `--check` fails
the build if any part of the reasoning below stops being what the engine does.

The left column is read from each tool's own file. The right column is read
from the outcome Release-Gate computed. Neither is typed in by hand.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from release_gate.assurance.admission_report import (  # noqa: E402
    build_admission_report, render_admission_report)
from release_gate.assurance.methodology import AssuranceMethodology  # noqa: E402
from release_gate.assurance.resolution import ResolutionPolicy  # noqa: E402
from release_gate.assurance.zero_config import AssuranceOutcome, assure  # noqa: E402

CLAIM = "cl_transfer_requires_approval"

#: policy file -> (decision, exit code) the declared policy must produce.
POLICIES: Mapping[str, Tuple[str, int]] = {
    "policy/block-on-counterexample.json": ("BLOCK", 1),
    "policy/hold-on-counterexample.json": ("HOLD", 10),
}

#: What every policy must agree on, whatever it does with a counterexample.
#: Each entry: evidence file -> what Release-Gate must have concluded from it.
EXPECTED_READING = {
    "evidence/static-analysis.json": "counted, incomplete",
    "evidence/promptfoo.json": "49 positive observations, 1 declared case missing",
    "evidence/behaviour-tests.json": "valid counterexample",
    "release.jsonl#trace": "stale: another commit",
    "evidence/formal-proof.json": "stale: another approval policy",
    "evidence/approval.json": "stale: another commit",
}


def _load(name: str) -> Any:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def admit(policy_file: str) -> AssuranceOutcome:
    """One admission decision over the release and every tool's output.

    Paths are given relative to this directory, so the case (whose records name
    their source files) is the same wherever the repository is checked out.
    """
    here = Path.cwd()
    os.chdir(HERE)
    try:
        return assure("release.jsonl", evidence=["evidence"],
                      methodology=AssuranceMethodology.from_dict(_load("methodology.json")),
                      resolution_policy=ResolutionPolicy.from_dict(_load(policy_file)))
    finally:
        os.chdir(here)


# ── what each tool said, read from its own file ──────────────────────────────

def tool_reports() -> Dict[str, str]:
    static = _load("evidence/static-analysis.json")["results"][0]
    promptfoo = _load("evidence/promptfoo.json")["results"]
    behaviour = _load("evidence/behaviour-tests.json")["attacks"]
    formal_doc = _load("evidence/formal-proof.json")
    formal = formal_doc["results"][0]
    review = _load("evidence/approval.json")["reviews"][0]
    rows = [json.loads(line) for line in
            (HERE / "release.jsonl").read_text(encoding="utf-8").splitlines() if line]
    trace = next(r for r in rows if r.get("kind") == "TRACE")
    expectation = next(r for r in rows if r.get("record_type") == "expectation")
    passed = sum(1 for r in promptfoo["results"] if r.get("success"))
    blocked = sum(1 for a in behaviour if a["outcome"] == "blocked")
    succeeded = [a for a in behaviour if a["outcome"] == "succeeded"]
    return {
        "evidence/static-analysis.json":
            f"static analysis: {static['result']} — {static['detail']}",
        "evidence/promptfoo.json":
            f"promptfoo: {passed}/{expectation['expected']} tests pass "
            f"({len(promptfoo['results'])} ran)",
        "evidence/behaviour-tests.json":
            f"behaviour tests: {blocked} attempted violations blocked, "
            f"{len(succeeded)} succeeded — {succeeded[0]['observed']}",
        "release.jsonl#trace":
            f"runtime traces ({trace['producer']['producer_id']}): {trace['coverage_note']}",
        "evidence/formal-proof.json":
            f"formal proof ({formal_doc['verifier']['name']} "
            f"{formal_doc['verifier']['version']}): {formal['result']} — "
            f"{formal['covers'][0]}",
        "evidence/approval.json":
            f"human approval: {review['reviewer']['role']} {review['decision']}d "
            f"commit {review['state']['commit']}",
    }


# ── what Release-Gate concluded from it, read from the outcome ───────────────

def _file_of(source: str) -> str:
    """`release.jsonl#evidence/x.json` -> `evidence/x.json`."""
    return source.split("#", 1)[1] if "#" in source else source


def _record_files(outcome: AssuranceOutcome) -> Dict[str, str]:
    """Every evidence record and verification attempt -> the file it came from."""
    files: Dict[str, str] = {}
    by_producer: Dict[str, str] = {}
    for record in outcome.case.collection("evidence").materialised:
        if not hasattr(record, "evidence_id"):
            continue
        name = _file_of(str(record.source or ""))
        if name == "release.jsonl" and record.evidence_type.value == "TRACE":
            name = "release.jsonl#trace"
        files[record.evidence_id] = name
        by_producer.setdefault(record.producer.producer_id, name)
    attempts = list(outcome.case.collection("verification").materialised)
    for claim in outcome.case.collection("claims").materialised:
        attempts.extend(getattr(claim, "verification_attempts", ()) or ())
    for attempt in attempts:
        cited = [files[e] for e in attempt.evidence if e in files]
        files[attempt.verification_id] = (cited[0] if cited
                                          else by_producer.get(attempt.verifier, "?"))
    return files


def reading(outcome: AssuranceOutcome) -> Dict[str, Any]:
    """The facts the demo asserts, each taken from the computed outcome."""
    report = build_admission_report(outcome).to_dict()
    files = _record_files(outcome)
    bindings = outcome.analysis.state_binding.bindings
    stale: Dict[str, List[str]] = {}
    counted: Dict[str, List[str]] = {}
    for binding in bindings:
        if CLAIM not in binding.bears_on:
            continue
        target = stale if binding.withholds_support else counted
        target.setdefault(files.get(binding.record_id, "?"), []).append(
            binding.reason)
    status = next(s for s, claims in report["critical_claims"]["by_status"].items()
                  if any(c["claim_id"] == CLAIM for c in claims))
    attempts = outcome.analysis.verification_graph.attempts
    promptfoo = [a for a in attempts if a.verifier == "promptfoo"]
    static = next(r for r in outcome.case.collection("evidence").materialised
                  if getattr(r, "producer", None) is not None
                  and r.producer.producer_id.startswith("approval-path-check"))
    return {
        "decision": report["decision"],
        "exit_code": report["exit_code"],
        "claim_status": status,
        "blocking": [c["condition_id"] for c in report["blocking_reasons"]],
        "holding": [c.condition_id for c in outcome.admission.holding],
        "counterexamples": [(c["producer"], c["claim"], c["standing"])
                            for c in report["counterexamples"]],
        "stale": stale,
        "counted": counted,
        "promptfoo_passed": sum(1 for a in promptfoo if a.status.value == "PASSED"),
        "promptfoo_on_claim": sum(1 for a in promptfoo
                                  if a.target is not None and a.target.target_id == CLAIM),
        "static_does_not_cover": static.coverage_note,
        "generated": [s["label"] for s in report["evidence_sources"]
                      ["generated_by_release_gate"]],
        "imported": sorted(s["label"] for s in report["evidence_sources"]["imported"]),
        "report": report,
    }


def conclusions(facts: Mapping[str, Any], counterexample_effect: str) -> Dict[str, str]:
    """The right-hand column: what the facts mean for the critical claim."""
    stale = facts["stale"]

    def why(name: str) -> str:
        return stale[name][0].split(": ", 1)[-1] if name in stale else "?"

    return {
        "evidence/static-analysis.json":
            "supportive but incomplete: counted for this candidate, and its own "
            f"report says it does not cover: {facts['static_does_not_cover']}",
        "evidence/promptfoo.json":
            f"{facts['promptfoo_passed']} positive observations, each about its own "
            f"case; {facts['promptfoo_on_claim']} bear on the authorization claim. "
            "The 50th declared case never ran, and unknown is not a pass "
            "(RG-EXPECT-001, HOLD)",
        "evidence/behaviour-tests.json":
            "a valid counterexample: it contradicts the critical claim on this exact "
            f"candidate, and support cannot outvote it (RG-CEX-001, "
            f"{counterexample_effect} under this policy)",
        "release.jsonl#trace":
            f"observations of another state, not this candidate: {why('release.jsonl#trace')}",
        "evidence/formal-proof.json":
            f"state mismatch, cannot support this candidate: {why('evidence/formal-proof.json')}",
        "evidence/approval.json":
            f"stale, wrong candidate: {why('evidence/approval.json')}; the "
            "release-owner approval this methodology requires is missing "
            "(approvals.release-owner, HOLD)",
    }


# ── the check ────────────────────────────────────────────────────────────────

def check(policy_file: str, facts: Mapping[str, Any]) -> List[str]:
    """Every way the outcome could drift from what the README says. Empty is OK."""
    decision, exit_code = POLICIES[policy_file]
    problems: List[str] = []

    def expect(ok: bool, what: str) -> None:
        if not ok:
            problems.append(f"{policy_file}: {what}")

    expect(facts["decision"] == decision and facts["exit_code"] == exit_code,
           f"decision {facts['decision']} (exit {facts['exit_code']}), "
           f"expected {decision} (exit {exit_code})")
    expect(facts["claim_status"] == "CONTRADICTED",
           f"critical claim is {facts['claim_status']}, expected CONTRADICTED")
    expect(facts["counterexamples"] == [("acme-behaviour-suite", CLAIM, "VALID")],
           f"counterexamples {facts['counterexamples']}")
    if decision == "BLOCK":
        expect(facts["blocking"] == ["RG-CEX-001"],
               f"blocking {facts['blocking']}, expected only RG-CEX-001")
    else:
        expect(facts["blocking"] == [], f"blocking {facts['blocking']}, expected none")
        expect("RG-CEX-001" in facts["holding"], "the counterexample does not hold")
    for condition in ("RG-EXPECT-001", "approvals.release-owner"):
        expect(condition in facts["holding"] or condition in facts["blocking"],
               f"{condition} raised nothing")
    expect(sorted(facts["stale"]) == sorted(["release.jsonl#trace",
                                             "evidence/formal-proof.json",
                                             "evidence/approval.json"]),
           f"support withheld from {sorted(facts['stale'])}")
    expect(any("governance_policy" in r
               for r in facts["stale"].get("evidence/formal-proof.json", [])),
           "the proof is not withheld for its approval-policy version")
    for name in ("release.jsonl#trace", "evidence/approval.json"):
        expect(any("commit" in r for r in facts["stale"].get(name, [])),
               f"{name} is not withheld for its commit")
    expect("evidence/static-analysis.json" in facts["counted"],
           "the static analysis is not counted for this candidate")
    expect("scheduled transfers" in facts["static_does_not_cover"],
           "the static analysis no longer says what it does not cover")
    expect(facts["promptfoo_passed"] == 49 and facts["promptfoo_on_claim"] == 0,
           f"promptfoo: {facts['promptfoo_passed']} passed, "
           f"{facts['promptfoo_on_claim']} on the claim")
    expect("Release-Gate Static" not in facts["generated"]
           and set(facts["imported"]) >= {"Promptfoo", "Red team", "Formal verification",
                                           "Human review", "Runtime trace"},
           f"evidence sources: generated {facts['generated']}, imported {facts['imported']}")
    return problems


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="assert the expected reasoning and decisions; exit 1 on drift")
    parser.add_argument("--out", help="write each policy's Admission Report here")
    args = parser.parse_args(argv)

    reports = tool_reports()
    problems: List[str] = []
    for policy_file, (expected, _) in POLICIES.items():
        outcome = admit(policy_file)
        facts = reading(outcome)
        policy = _load(policy_file)
        effect = policy["counterexample_effect"]
        if args.check:
            problems.extend(check(policy_file, facts))
        print("=" * 78)
        print(f"  Policy: {policy['policy_id']} — {policy['note']}")
        print("=" * 78)
        for name, concluded in conclusions(facts, effect).items():
            print(f"\n  {reports[name]}")
            print(f"    Release-Gate: {concluded}")
        print(f"\n  Critical claim {CLAIM}: {facts['claim_status']}")
        print(f"  Decision: {facts['decision']} (exit {facts['exit_code']})")
        if facts["blocking"]:
            print(f"  Blocking: {', '.join(facts['blocking'])}")
        print(f"  Holding:  {', '.join(facts['holding'])}\n")
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            stem = Path(policy_file).stem
            report = build_admission_report(outcome)
            (out / f"{stem}.json").write_text(
                json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            (out / f"{stem}.txt").write_text(render_admission_report(report) + "\n",
                                             encoding="utf-8")

    if args.check:
        if problems:
            print("demo check FAILED:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        print("demo check OK: both policies reach the documented decision for the "
              "documented reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
