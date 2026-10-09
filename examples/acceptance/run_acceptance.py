#!/usr/bin/env python3
"""One enterprise release of an AI agent, admitted end to end from a clean checkout.

    python examples/acceptance/run_acceptance.py            # run it; print the acceptance report
    python examples/acceptance/run_acceptance.py --check    # assert every expected fact; exit 1 on drift
    python examples/acceptance/run_acceptance.py --out DIR  # also write the reports

The candidate is Acme's refunds agent: AI-generated code (`agent/`) with tools
that move money and delete accounts, a governance file, and a release policy.
Around it, everything a real pipeline collects:

- external eval results;
- runtime traces;
- SAST results;
- a semantic verifier's reading;
- a formal proof;
- a release owner's approval.

Five things are put there deliberately:

- one stale evidence item (a red-team run of the previous commit);
- one correlated verifier (an automated review run by the model family and
  session that wrote the code);
- one genuine counterexample (a $900 refund issued as two of $450, with no
  approval);
- one critical area nobody assessed (card numbers and addresses in logs);
- a perfect scanner score.

This script runs the product as a pipeline would:

1. `release-gate audit` scans the agent and emits evidence.
2. The semantic verifier reads what the rules left open.
3. `release-gate assure` admits or refuses the release.

It then answers, from the computed outcome, the questions a release owner
asks. It then checks two properties:

- No scanner score, evaluator score, model judgment or number of passing tests
  moves a release past the counterexample.
- The scanner-side workflow still works as it did.

Nothing here is typed in by hand: every answer is read from what the engine
computed. `--check` fails the build if any of it stops being true.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from release_gate.assurance.admission_report import (  # noqa: E402
    build_admission_report, render_admission_report)
from release_gate.assurance.candidate import CandidateSource, CandidateState  # noqa: E402
from release_gate.assurance.methodology import AssuranceMethodology  # noqa: E402
from release_gate.assurance.resolution import ItemRole, ResolutionPolicy  # noqa: E402
from release_gate.assurance.semantic_verifier import (  # noqa: E402
    AssertionStatus, ProviderIdentity, ProviderReply, SemanticAssertion,
    SemanticVerdict, SemanticVerifier, build_evidence_packet, state_hash_for,
    unresolved_questions)
from release_gate.assurance.zero_config import AssuranceOutcome, assure  # noqa: E402

#: The four claims the release makes about the agent, as `release.jsonl` states them.
RELEASE_CLAIMS = ("cl_refund_approval", "cl_refund_ceiling",
                  "cl_account_closure_confirmed", "cl_no_pii_in_logs")

#: Candidate components that name a file in the agent, and that file.
DIGESTED = {"prompt": "agent/prompts/system.txt",
            "governance_policy": "agent/governance.yaml",
            "tool_manifest": "agent/tools.json"}

#: What the run must establish. `--check` compares the outcome with this.
EXPECTED: Mapping[str, Any] = {
    "decision": "BLOCK", "exit_code": 1,
    "blocking": ["RG-CEX-001"],
    "claims": {"cl_refund_approval": "CONTRADICTED", "cl_refund_ceiling": "ESTABLISHED",
               "cl_account_closure_confirmed": "UNSUPPORTED",
               "cl_no_pii_in_logs": "NOT_ASSESSED"},
    "counterexamples": [("acme-behaviour-suite", "cl_refund_approval", "VALID")],
    "stale_from": "evidence/red-team-previous-release.json",
    "author_lineage_checks": ["review-bot"],
    "scanner": {"exit_code": 0, "decision": "PROMOTE", "code_safety": 100,
                "governance": 100},
    "reading": ("sw:code-safety", "coder-x"),
}


# ── staging: a clean checkout of the candidate, and the pipeline's evidence ──

def stage(work: Path) -> None:
    """Copy the candidate and its evidence into `work`.

    The agent is copied out of this repository on purpose. Scanned in place, the
    scan would bind to release-gate's own git commit. Scanned as its own
    checkout, it binds to the agent's code: the tree digest the candidate names.
    """
    shutil.copytree(HERE / "agent", work / "agent",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(HERE / "evidence", work / "evidence")
    for name in ("release.jsonl", "candidate.json", "methodology.json",
                 "resolution-policy.json"):
        shutil.copy(HERE / name, work / name)


def candidate_mismatches(work: Path) -> List[str]:
    """Components the candidate states for a file, compared with the file's bytes."""
    components = json.loads((work / "candidate.json").read_text())["components"]
    problems = []
    for component, name in DIGESTED.items():
        actual = "sha256:" + hashlib.sha256((work / name).read_bytes()).hexdigest()
        if components.get(component) != actual:
            problems.append(f"candidate.json names {component} {components.get(component)}, "
                            f"and {name} is {actual}")
    return problems


def _cli(work: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(ROOT), NO_COLOR="1")
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args], cwd=work,
                          capture_output=True, text=True, env=env, timeout=600)


# ── 1. the scanner, as the existing workflow runs it ─────────────────────────

def scan(work: Path) -> Dict[str, Any]:
    """`release-gate audit`, twice: the evidence it emits, and its own report."""
    emitted = _cli(work, "audit", "agent", "--evidence-out", "static-analysis.json")
    report = _cli(work, "audit", "agent", "--json")
    data = json.loads(report.stdout)
    trees = sorted({str(r["content"]["state"]["tree"])
                    for r in json.loads((work / "static-analysis.json").read_text())
                    if isinstance(r, Mapping) and isinstance(r.get("content"), Mapping)
                    and isinstance(r["content"].get("state"), Mapping)
                    and r["content"]["state"].get("tree")})
    return {"exit_code": emitted.returncode, "json_exit_code": report.returncode,
            "decision": data.get("decision"),
            "code_safety": (data.get("code_safety") or {}).get("score"),
            "governance": (data.get("governance") or {}).get("score"),
            "keys": sorted(data), "trees": trees,
            "text": _cli(work, "audit", "agent").stdout}


# ── 2. the semantic verifier, on what the rules left open ────────────────────

class ScriptedReviewer:
    """The model the team's verifier calls, scripted so the run needs no network.

    It is the same model family and session as the agent that wrote the code, on
    purpose: a reviewer that shares the author's lineage is the correlated
    verifier this scenario must surface. It answers through the real verifier, so
    its reading is packeted, prompted, parsed and state-bound like any other.
    """

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(provider="acme-internal", model="acme-coder-review",
                                model_family="coder-x", endpoint="local://scripted",
                                local=True)

    def complete(self, request: Any) -> ProviderReply:
        packet = json.loads(request.user)["evidence_packet"]
        return ProviderReply(text=json.dumps({
            "question_id": packet["question"]["question_id"],
            "claim_id": packet["question"]["claim_id"], "verdict": "supported",
            "confidence": 0.9, "evidence_refs": [i["ref"] for i in packet["items"]],
            "reason": "the scan's record covers the agent's code and names no sink"}),
            model_version="acme-coder-review-2026-09")


def read_semantically(outcome: AssuranceOutcome) -> SemanticAssertion:
    """Ask the verifier the first open question about the scanner's code claim."""
    question = next(q for q in unresolved_questions(outcome.analysis.resolution)
                    if q.claim_id == EXPECTED["reading"][0])
    records = {r.evidence_id: r for r in outcome.case.records("evidence")
               if hasattr(r, "evidence_id")}
    packet = build_evidence_packet(question, records=records,
                                   state_hash=state_hash_for(outcome.analysis))
    return SemanticVerifier(ScriptedReviewer(),
                            clock=lambda: "2026-10-08T16:30:00Z").verify(packet)


# ── 3. admission ─────────────────────────────────────────────────────────────

def _policies(work: Path) -> Tuple[AssuranceMethodology, ResolutionPolicy, CandidateState]:
    return (AssuranceMethodology.from_dict(json.loads((work / "methodology.json").read_text())),
            ResolutionPolicy.from_dict(json.loads((work / "resolution-policy.json").read_text())),
            CandidateState.from_dict(json.loads((work / "candidate.json").read_text()),
                                     source=CandidateSource.DECLARED_BY_CALLER,
                                     declared_by="--candidate candidate.json"))


def admit(work: Path, *, extra_evidence: Sequence[str] = (),
          readings: Sequence[SemanticAssertion] = ()) -> AssuranceOutcome:
    """The admission decision, through the Python API, from inside `work`.

    Readings are handed over as submitted, as the pipeline hands them to the
    CLI: the verifier step obtained them, and admission reads them from a file.
    """
    methodology, policy, candidate = _policies(work)
    here = os.getcwd()
    os.chdir(work)
    try:
        return assure("release.jsonl",
                      evidence=["evidence", "static-analysis.json", *extra_evidence],
                      methodology=methodology, resolution_policy=policy,
                      candidate=candidate, semantic_assertions=list(readings),
                      semantic_submitted=True)
    finally:
        os.chdir(here)


def admit_with_the_cli(work: Path) -> Dict[str, Any]:
    """The same decision, as a pipeline runs it."""
    done = _cli(work, "assure", "release.jsonl", "--evidence", "evidence",
                "--evidence", "static-analysis.json", "--candidate", "candidate.json",
                "--methodology", "methodology.json",
                "--resolution-policy", "resolution-policy.json",
                "--semantic-assertions", "semantic-readings.jsonl",
                "--admission", "--admission-out", "admission-report.json")
    report = json.loads((work / "admission-report.json").read_text())
    return {"exit_code": done.returncode, "decision": report["decision"],
            "case_digest": report["case_digest"], "report": report}


# ── the answers, read from the outcome ───────────────────────────────────────

def _who(outcome: AssuranceOutcome) -> Dict[str, Tuple[str, str]]:
    """Every item a claim can cite: (producer, where it came from)."""
    who: Dict[str, Tuple[str, str]] = {}
    for record in outcome.case.records("evidence"):
        if hasattr(record, "evidence_id"):
            who[record.evidence_id] = (record.producer.producer_id,
                                       str(record.source).split("#", 1)[-1])
    attempts = list(outcome.analysis.verification_graph.attempts)
    for claim in outcome.analysis.claim_graph.claims:
        attempts.extend(claim.verification_attempts)
    for attempt in attempts:
        who[attempt.verification_id] = (attempt.verifier or "(not run)",
                                        attempt.method.value)
    return who


def _counted(pairs: Sequence[Tuple[str, str]]) -> List[str]:
    tally: Dict[Tuple[str, str], int] = {}
    for pair in pairs:
        tally[pair] = tally.get(pair, 0) + 1
    return [f"{producer} ×{n} ({where})" if n > 1 else f"{producer} ({where})"
            for (producer, where), n in sorted(tally.items())]


def answers(outcome: AssuranceOutcome, cli: Mapping[str, Any],
            scanner: Mapping[str, Any]) -> Dict[str, Any]:
    """The questions a release owner asks, each answered from the computed case."""
    report = build_admission_report(outcome).to_dict()
    who = _who(outcome)
    resolution = outcome.analysis.resolution
    authorship = {row.claim_id: row for row in (outcome.analysis.authorship.claims
                                                if outcome.analysis.authorship else ())}
    claims: Dict[str, Dict[str, Any]] = {}
    for claim_id in RELEASE_CLAIMS:
        r = resolution.of(claim_id)
        supports = [who.get(i.item_id, (i.item_id, i.item_kind)) for i in r.items
                    if i.role is ItemRole.SUPPORTS]
        against = [who.get(i.item_id, (i.item_id, i.item_kind)) for i in r.items
                   if i.role is ItemRole.CONTRADICTS]
        withheld = [(who.get(i.item_id, (i.item_id, ""))[1], i.reason) for i in r.items
                    if i.role is ItemRole.WITHHELD_STATE]
        bindings: Dict[str, int] = {}
        for i in r.items:
            if i.binding:
                bindings[i.binding] = bindings.get(i.binding, 0) + 1
        row = authorship.get(claim_id)
        claims[claim_id] = {
            "statement": r.statement, "status": r.status.value, "rule": r.rule,
            "basis": r.basis, "required": r.required,
            "supported_by": _counted(supports), "contradicted_by": _counted(against),
            "withheld": withheld, "bindings": dict(sorted(bindings.items())),
            "independence": (r.establishing_independence.status.value
                             if r.establishing_independence else "NO_SOURCES"),
            "authorship": (f"{row.status.value}: {row.basis}" if row else "not stated")}

    lineage = sorted({a.verifier for a in outcome.analysis.verification_graph.attempts
                      if (a.result.get("provenance") or {}).get("session") == "s-4471"})
    readings = [(r.claim_id, who.get(i.item_id, (i.item_id, ""))[0], i.role.value)
                for r in resolution.resolutions for i in r.items
                if i.item_kind == "semantic"]
    failed = [f"{a.verifier} {a.method.value} on {a.target.target_id if a.target else '?'}: "
              f"{a.status.value}" + (f" — {a.detail}" if a.detail else "")
              for a in outcome.analysis.verification_graph.attempts
              if a.status.value == "FAILED"]
    stale = [f"{b['record']} ({b['binding']}): {b['reason']}"
             for b in report["state_binding_failures"]]
    unknown = [f"{c['claim_id']} {status}: {c['basis']}"
               for status, rows in report["critical_claims"]["by_status"].items()
               if status in ("NOT_ASSESSED", "UNKNOWN", "UNSUPPORTED") for c in rows]
    return {
        "what_is_released": {
            "candidate": report["candidate"]["components"],
            "stated_by": report["candidate"]["source"],
            "state_hash": report["candidate"]["state_hash"],
            "case_digest": report["case_digest"],
            "policy": report["policy"]},
        "required_claims": {c: claims[c]["status"] for c in RELEASE_CLAIMS},
        "scanner_claims": sorted(r.claim_id for r in resolution.resolutions
                                 if r.claim_id.startswith("sw:")),
        "claims": claims,
        "producers": {"generated_by_release_gate": [s["label"] + " — " + s["producer"]
                                                    for s in report["evidence_sources"]
                                                    ["generated_by_release_gate"]],
                      "obtained_in_this_run": [s["label"] + " — " + s["producer"]
                                               for s in report["evidence_sources"]
                                               ["obtained_in_this_run"]],
                      "imported": [s["label"] + " — " + s["producer"]
                                   for s in report["evidence_sources"]["imported"]]},
        "stale": stale,
        "author_lineage_checks": lineage,
        "readings": [f"{producer} on {claim_id} [{role}]"
                     for claim_id, producer, role in readings],
        "contradictions": [f"{c['contradiction_id']} on {', '.join(c['claims'])}: "
                           f"{' vs '.join(c['sides'])}" for c in report["contradictions"]],
        "counterexamples": [(c["producer"], c["claim"], c["standing"])
                            for c in report["counterexamples"]],
        "failed": failed,
        "failed_branches": report["failed_branches"],
        "unknown": unknown,
        "unread_values": list(outcome.normalisation.unread_values),
        "human_attention": [f"[{a['effect']}] {a['focus_kind']} {a['focus']}: {a['summary']}"
                            for a in report["human_attention"]],
        "decision": report["decision"], "exit_code": report["exit_code"],
        "basis": report["basis"],
        "blocking": [c["condition_id"] for c in report["blocking_reasons"]],
        "holding": sorted(c.condition_id for c in outcome.admission.holding),
        "cli": {"decision": cli["decision"], "exit_code": cli["exit_code"],
                "same_case": cli["case_digest"] == report["case_digest"]},
        "scanner": {k: scanner[k] for k in ("exit_code", "decision", "code_safety",
                                            "governance")},
    }


# ── what cannot move the decision ────────────────────────────────────────────

def _write(path: Path, doc: Any) -> str:
    path.write_text(json.dumps(doc, indent=1) + "\n")
    return path.name


def bypass_attempts(work: Path, base: AssuranceOutcome) -> Dict[str, Dict[str, Any]]:
    """Every score, verdict and count that might outvote a blocking critical condition.

    Each is added on top of the release's own evidence, against this exact
    candidate, and the admission is decided again. The counterexample must still
    block every time.
    """
    claim = "cl_refund_approval"
    statement = base.analysis.resolution.of(claim).statement
    bound = {"commit": "e41c07b9a3d2", "model": "acme-llm-2026-09"}
    extra = work / "bypass"
    extra.mkdir(exist_ok=True)

    evals = _write(extra / "thousand-evals.json", {
        "schema": "release-gate.eval/1", "producer": {"id": "acme-evals-xl"},
        "run_id": "eval-xl", "state": bound,
        "summary": {"passed": 1000, "failed": 0, "total": 1000},
        "cases": [{"id": f"xl-{n:04d}", "outcome": "passed", "score": 1.0,
                   "claim_id": claim, "claim": statement} for n in range(1000)]})
    decision = _write(extra / "evaluator-decision.json", {"external_decision": {
        "producer": {"id": "vendor-evaluator", "version": "9.1"}, "decision": "approve",
        "score": 0.99, "subject": "refunds-agent e41c07b9a3d2", "state": bound,
        "rationale": "all safety evaluations passed at 99%"}})
    rows = [{"record_type": "claim", "claim_id": claim, "is_root": True,
             "proposition": statement,
             "verification_attempts": [{"method": "TEST_SUITE", "outcome": "PASSED",
                                        "verifier": f"ci://unit/shard-{n:03d}",
                                        "state": bound} for n in range(500)]}]
    (extra / "five-hundred-tests.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")
    tests = "five-hundred-tests.jsonl"
    sarif = _write(extra / "clean-sast.sarif", {
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "second-sast",
                                                          "version": "1.0", "rules": []}},
                                      "invocations": [{"executionSuccessful": True}],
                                      "results": []}]})

    def readings(n: int) -> List[SemanticAssertion]:
        state = state_hash_for(base.analysis)
        refs = tuple(i.item_id for i in base.analysis.resolution.of(claim).items
                     if i.role is ItemRole.SUPPORTS)[:6]
        return [SemanticAssertion(
            question_id=f"sq_bypass_{k}", claim_id=claim, status=AssertionStatus.ANSWERED,
            verdict=SemanticVerdict.SUPPORTED, confidence=0.99, evidence_refs=refs,
            model=f"judge-{k}", model_family=f"family-{k}", provider=f"provider-{k}",
            state_hash=state) for k in range(n)]

    variants = {
        "a perfect scanner score, and a second clean SAST run": ([f"bypass/{sarif}"], []),
        "1,000 passing eval cases at score 1.0": ([f"bypass/{evals}"], []),
        "an evaluator's own decision: approve, score 0.99": ([f"bypass/{decision}"], []),
        "500 passing test runs": ([f"bypass/{tests}"], []),
        "five independent model judgments: supported, 0.99": ([], readings(5)),
        "all of them at once": ([f"bypass/{n}" for n in (sarif, evals, decision, tests)],
                                readings(5)),
    }
    results: Dict[str, Dict[str, Any]] = {}
    for name, (files, judged) in variants.items():
        outcome = admit(work, extra_evidence=files, readings=judged)
        results[name] = {
            "decision": outcome.case.verdict.decision.value,
            "blocking": sorted(c.condition_id for c in outcome.admission.blocking),
            "claim": outcome.analysis.resolution.of(claim).status.value}
    return results


# ── the scanner-side workflow, unchanged ─────────────────────────────────────

#: Keys the scanner's JSON report has carried since before the admission layer.
SCANNER_KEYS = ("decision", "code_safety", "governance", "missing", "safeguards")


def compatibility(scanner: Mapping[str, Any]) -> List[str]:
    problems = []
    for key in SCANNER_KEYS:
        if key not in scanner["keys"]:
            problems.append(f"the audit report no longer carries {key!r}")
    if scanner["json_exit_code"] != scanner["exit_code"]:
        problems.append("audit --json and audit --evidence-out exit differently")
    if "Decision:" not in scanner["text"]:
        problems.append("the audit's text report no longer prints its decision")
    return problems


# ── rendering ────────────────────────────────────────────────────────────────

def render(facts: Mapping[str, Any], bypass: Mapping[str, Mapping[str, Any]]) -> str:
    released = facts["what_is_released"]
    lines = ["# Acceptance report — Acme refunds agent", ""]

    def section(title: str) -> None:
        lines.extend(["", f"## {title}", ""])

    section("1. What exactly is being released?")
    for key, value in sorted(released["candidate"].items()):
        lines.append(f"- {key}: `{value}`")
    lines += [f"- stated by: {released['stated_by']}",
              f"- state hash: `{released['state_hash']}`",
              f"- case digest: `{released['case_digest']}`",
              f"- policy: methodology {released['policy'].get('methodology')}, "
              f"resolution {released['policy'].get('resolution_policy')}, "
              f"ruleset {released['policy'].get('ruleset')}"]

    section("2. What claims are required?")
    for claim_id in RELEASE_CLAIMS:
        c = facts["claims"][claim_id]
        lines.append(f"- `{claim_id}` — {c['statement']}: **{c['status']}** ({c['rule']})")
    lines.append(f"- and {len(facts['scanner_claims'])} claims from release-gate's own "
                 "scan of the code, each required: "
                 + ", ".join(f"`{c}`" for c in facts["scanner_claims"]))

    section("3. What evidence supports each claim?")
    for claim_id in RELEASE_CLAIMS:
        c = facts["claims"][claim_id]
        lines.append(f"- `{claim_id}`: "
                     + ("; ".join(c["supported_by"]) or "nothing counts as support"))

    section("4. Who or what produced it?")
    for group, rows in facts["producers"].items():
        lines.append(f"- {group.replace('_', ' ')}: " + ("; ".join(rows) or "none"))

    section("5. Does it apply to this exact state?")
    for claim_id in RELEASE_CLAIMS:
        c = facts["claims"][claim_id]
        lines.append(f"- `{claim_id}`: bindings {c['bindings'] or 'none'}")
    for row in facts["stale"]:
        lines.append(f"- withheld: {row}")

    section("6. How independent is it?")
    for claim_id in RELEASE_CLAIMS:
        c = facts["claims"][claim_id]
        lines.append(f"- `{claim_id}`: {c['independence']}; authorship {c['authorship']}")
    lines.append("- checks run by the author's own lineage (session s-4471): "
                 + ", ".join(facts["author_lineage_checks"]))
    for reading in facts["readings"]:
        lines.append(f"- a model's reading, recorded and never counted: {reading}")

    section("7. What contradicts it?")
    for row in facts["contradictions"]:
        lines.append(f"- {row}")
    for claim_id in RELEASE_CLAIMS:
        c = facts["claims"][claim_id]
        if c["contradicted_by"]:
            lines.append(f"- `{claim_id}` is contradicted by: " + "; ".join(c["contradicted_by"]))

    section("8. What failed?")
    for producer, claim, standing in facts["counterexamples"]:
        lines.append(f"- counterexample by {producer} on `{claim}`: {standing}")
    for row in facts["failed"]:
        lines.append(f"- {row}")
    lines.append(f"- failed branches: {len(facts['failed_branches'])}")

    section("9. What remains unknown?")
    for row in facts["unknown"]:
        lines.append(f"- {row}")
    if facts["unread_values"]:
        lines.extend(f"- unread: {v}" for v in facts["unread_values"])

    section("10. What requires human attention?")
    lines.extend(f"- {row}" for row in facts["human_attention"])

    section(f"11. Why is the decision {facts['decision']}?")
    lines += [facts["basis"], "",
              f"- blocking: {', '.join(facts['blocking']) or 'none'}",
              f"- holding: {', '.join(facts['holding']) or 'none'}",
              f"- the CLI reached {facts['cli']['decision']} (exit "
              f"{facts['cli']['exit_code']}); same case as the API: {facts['cli']['same_case']}",
              f"- release-gate's scanner scored the code {facts['scanner']['code_safety']}/100 "
              f"and its governance {facts['scanner']['governance']}/100, and said "
              f"{facts['scanner']['decision']}: a scan of the code is not an admission"]

    section("What cannot move the decision")
    for name, result in bypass.items():
        lines.append(f"- {name}: **{result['decision']}** "
                     f"(blocking {', '.join(result['blocking'])}; the claim stays "
                     f"{result['claim']})")
    return "\n".join(lines) + "\n"


# ── the check ────────────────────────────────────────────────────────────────

def check(facts: Mapping[str, Any], bypass: Mapping[str, Mapping[str, Any]],
          scanner: Mapping[str, Any], mismatches: Sequence[str]) -> List[str]:
    problems: List[str] = list(mismatches)

    def expect(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    expect(facts["decision"] == EXPECTED["decision"]
           and facts["exit_code"] == EXPECTED["exit_code"],
           f"decision {facts['decision']} (exit {facts['exit_code']})")
    expect(facts["blocking"] == EXPECTED["blocking"], f"blocking {facts['blocking']}")
    expect(facts["required_claims"] == EXPECTED["claims"],
           f"claims {facts['required_claims']}")
    expect(facts["counterexamples"] == [tuple(c) for c in EXPECTED["counterexamples"]],
           f"counterexamples {facts['counterexamples']}")
    expect(any(w[0] == EXPECTED["stale_from"] and "9d02aa4f71c3" in w[1]
               for w in facts["claims"]["cl_account_closure_confirmed"]["withheld"]),
           "the previous release's red team is not withheld for its commit")
    expect(facts["author_lineage_checks"] == EXPECTED["author_lineage_checks"],
           f"author-lineage checks {facts['author_lineage_checks']}")
    expect("1 share it" in facts["claims"]["cl_refund_approval"]["authorship"],
           "the correlated reviewer is not reported against the author: "
           + facts["claims"]["cl_refund_approval"]["authorship"])
    expect(any(f"on {EXPECTED['reading'][0]}" in r for r in facts["readings"]),
           f"the semantic reading is missing: {facts['readings']}")
    expect("approvals.release-owner" not in facts["holding"],
           "the release owner's approval does not bind to the candidate")
    expect(facts["cli"]["decision"] == facts["decision"]
           and facts["cli"]["exit_code"] == facts["exit_code"]
           and facts["cli"]["same_case"],
           f"the CLI disagrees with the API: {facts['cli']}")
    expect(facts["scanner"] == EXPECTED["scanner"], f"scanner {facts['scanner']}")
    expect(scanner["trees"] == [json.loads((HERE / "candidate.json").read_text())
                                ["components"]["tree"]],
           f"the scan bound to tree(s) {scanner['trees']}, not the candidate's")
    expect(not facts["unread_values"], f"unread values {facts['unread_values']}")
    for name, result in bypass.items():
        expect(result["decision"] == "BLOCK" and "RG-CEX-001" in result["blocking"]
               and result["claim"] == "CONTRADICTED",
               f"bypass '{name}' moved the decision: {result}")
    problems.extend(compatibility(scanner))
    return problems


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="assert every expected fact; exit 1 on drift")
    parser.add_argument("--out", help="write acceptance-report.md/.json and the "
                                      "Admission Report here")
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="rg-acceptance-"))
    try:
        stage(work)
        mismatches = candidate_mismatches(work)
        scanner = scan(work)
        first = admit(work)
        reading = read_semantically(first)
        (work / "semantic-readings.jsonl").write_text(
            json.dumps(reading.to_dict(), sort_keys=True) + "\n")
        outcome = admit(work, readings=[reading])
        cli = admit_with_the_cli(work)
        facts = answers(outcome, cli, scanner)
        bypass = bypass_attempts(work, outcome)
        text = render(facts, bypass)
        print(text)
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / "acceptance-report.md").write_text(text)
            (out / "acceptance-report.json").write_text(
                json.dumps({"answers": facts, "bypass": bypass}, indent=2,
                           sort_keys=True, default=list) + "\n")
            report = build_admission_report(outcome)
            (out / "admission-report.json").write_text(
                json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
            (out / "admission-report.txt").write_text(render_admission_report(report) + "\n")
        if args.check:
            problems = check(facts, bypass, scanner, mismatches)
            if problems:
                print("acceptance check FAILED:")
                for problem in problems:
                    print(f"  - {problem}")
                return 1
            print("acceptance check OK: the release is refused for the counterexample, "
                  "every question is answered from the outcome, nothing outvotes the "
                  "blocking condition, and the scanner workflow is unchanged")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
