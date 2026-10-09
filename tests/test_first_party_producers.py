"""Release-gate's own commands as evidence producers.

The CLI listed `pr`, `verify`, `loop-sim` and `agent-score` as evidence
release-gate produces itself, "each one source among the case's evidence", and
`assure` read every one of their outputs as UNRECOGNISED: the file was hashed
and nothing in it reached the case. These tests started from that: each command's
`--json` output handed to `assure --evidence`, failing because it was not read.

They pin what reading it means. A command's own verdict is recorded and adopted
by nothing; its score is read by nothing; a deterministic check is scoped to the
artifact it checked; a behavioural pass supports and never establishes; a word
outside a contract's table is never a pass.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.first_party import (
    AGENT_SCORE_SCHEMA,
    EVAL_BEHAVIOURS,
    FIRST_PARTY_SCHEMAS,
    LOOP_SIM_SCHEMA,
    LOOP_VERIFY_SCHEMA,
    PR_SCHEMA,
    first_party_adapters,
    first_party_document,
)
from release_gate.assurance.ingest import InputKind, detect_document
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.producer_contract import (
    HOSTILE_INPUTS,
    check_adapter_contract,
    default_producer_registry,
)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "examples" / "agents" / "02-release-promoted.jsonl"
GENERAL = default_registry().resolve("general-agent-action@1.0.0")
GOV = "sha256:" + "a" * 64
OTHER_GOV = "sha256:" + "b" * 64


# ── the documents each command writes ────────────────────────────────────────

def _verify(**changes):
    doc = {"decision": "SHIP", "reasons": ["Every check that ran passed"],
           "violations": [], "warnings": [],
           "checks": {"loop_policy": {"status": "PASS", "violations": [], "warnings": [],
                                      "iteration": 1, "cost_so_far": 0.0},
                      "trace": {"status": "PASS", "trace_id": "t-1", "total_steps": 3,
                                "tool_calls": 2, "violations": [], "warnings": [],
                                "unauthorized_tool_calls": []}},
           "iteration": 1, "cost_so_far": 0.0, "cost_remaining": None}
    doc.update(changes)
    return first_party_document(LOOP_VERIFY_SCHEMA, doc,
                                producer_id="release-gate/loop-verifier",
                                version="0.11.2", state={"governance_policy": GOV})


def _trace(status, **extra):
    doc = _verify()
    doc["checks"]["trace"].update(status=status, **extra)
    return doc


def _loop_sim(**changes):
    doc = {"decision": "PROMOTE", "reasons": ["all scenarios as expected"],
           "scenarios_run": 2, "scenarios_passed": 2, "scenarios_failed": 0,
           "convergence_rate": 1.0, "adversarial_pass_rate": 1.0,
           "scenario_results": [
               {"id": "summarise", "expect": "SHIP", "decision": "SHIP", "passed": True,
                "iterations": 2, "violations": [], "adversarial": False},
               {"id": "exfiltrate", "expect": "ROLLBACK", "decision": "ROLLBACK",
                "passed": True, "iterations": 1, "violations": [], "adversarial": True}]}
    doc.update(changes)
    return first_party_document(LOOP_SIM_SCHEMA, doc, producer_id="release-gate/loop-sim",
                                version="0.11.2")


def _agent_score(**changes):
    doc = {"score": 100, "decision": "PROMOTE", "agent": "py:acme.agent:handle",
           "reasons": [], "runtime": {},
           "dimensions": {
               "safety": {"score": 100, "passed": 14, "total": 14, "critical_failed": 0,
                          "l1": {"total": 3, "passed": 3, "leaked": 0, "errored": 0},
                          "l2": {"total": 4, "passed": 4, "leaked": 0, "errored": 0},
                          "l3": {"total": 4, "passed": 4, "leaked": 0, "errored": 0},
                          "l4": {"total": 3, "passed": 3, "leaked": 0, "errored": 0},
                          "critical_leaked": 0, "leaked_beyond_l1": 0, "errored": 0},
               "correctness": {"score": 100, "passed": 3, "total": 3}},
           "issues": []}
    doc.update(changes)
    return first_party_document(AGENT_SCORE_SCHEMA, doc,
                                producer_id="release-gate/agent-score", version="0.11.2")


def _pr(**changes):
    doc = {"decision": "PROMOTE", "base": "origin/main", "merge_base": "9d02aa4f71c3",
           "changed_files": 1, "reasons": ["No net-new highs"],
           "new_code_findings": [], "new_safeguard_failures": [],
           "resolved_code_findings": [], "code_safety_delta": 0, "coverage": None,
           "lock_drift": None}
    doc.update(changes)
    return first_party_document(PR_SCHEMA, doc, producer_id="release-gate/pr",
                                version="0.11.2",
                                state={"commit": "e41c07b9a3d2", "tree": GOV})


_LEAK = {"dimension": "safety", "severity": "high", "probe": "encoded-exfil-base64",
         "detail": "Response leaked blocked keywords"}
_NEW_FINDING = {"rule_id": "RG-EXEC-001", "severity": "high", "file": "agent.py",
                "line": 87, "title": "Dangerous execution sink"}


def _run(tmp_path, doc, *, name="first-party.json", methodology=GENERAL, **kwargs):
    evidence = tmp_path / name
    evidence.write_text(json.dumps(doc))
    return assure(str(RELEASE), methodology=methodology, evidence=[str(evidence)],
                  **kwargs)


def _records(outcome, producer):
    return [r for r in outcome.case.collection("evidence").materialised
            if getattr(getattr(r, "producer", None), "producer_id", None) == producer]


def _status(outcome, claim_id):
    resolved = outcome.analysis.resolution.of(claim_id)
    assert resolved is not None, f"{claim_id} is not in the case"
    return resolved.status.value


def _decision(outcome):
    return outcome.case.verdict.decision.value


def _fired(outcome):
    return sorted({f.rule_id for f in outcome.analysis.findings
                   if f.effect.value != "ADVISORY"})


SAMPLES = {"release_gate_pr": _pr, "release_gate_loop_verify": _verify,
           "release_gate_loop_sim": _loop_sim, "release_gate_agent_score": _agent_score}
PRODUCER = {"release_gate_pr": "release-gate/pr",
            "release_gate_loop_verify": "release-gate/loop-verifier",
            "release_gate_loop_sim": "release-gate/loop-sim",
            "release_gate_agent_score": "release-gate/agent-score"}


# ── read at all ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("producer_type", sorted(SAMPLES))
def test_a_command_output_is_read_as_release_gate_evidence(tmp_path, producer_type):
    doc = SAMPLES[producer_type]()
    detection = detect_document(doc, filename="out.json")
    assert detection.kind is InputKind.PRODUCER_EXPORT
    assert detection.adapter == producer_type
    outcome = _run(tmp_path, doc)
    held = _records(outcome, PRODUCER[producer_type])
    assert held, "nothing the command wrote reached the case"
    entry = next(e for e in outcome.evidence_origin.entries
                 if e.producer_id == PRODUCER[producer_type])
    assert entry.origin.value == "READ"
    assert "attributed to release-gate" in entry.statement


@pytest.mark.parametrize("producer_type", sorted(SAMPLES))
def test_each_contract_is_detected_by_its_schema_alone(producer_type):
    doc = SAMPLES[producer_type]()
    unnamed = {k: v for k, v in doc.items() if k != "schema"}
    for adapter in first_party_adapters():
        assert adapter.detect(unnamed) == 0
        assert adapter.detect(doc) == (95 if adapter.name == producer_type else 0)


@pytest.mark.parametrize("producer_type", sorted(SAMPLES))
def test_each_adapter_holds_the_producer_contract(producer_type):
    adapter = next(a for a in first_party_adapters() if a.name == producer_type)
    report = check_adapter_contract(adapter, SAMPLES[producer_type]())
    assert report.holds, report.violations
    for hostile in HOSTILE_INPUTS:
        assert adapter.detect(hostile) == 0


def test_the_four_contracts_are_registered_and_named_once():
    registry = default_producer_registry()
    names = {a.name for a in registry.adapters}
    assert set(SAMPLES) <= names
    assert len(FIRST_PARTY_SCHEMAS) == len(set(FIRST_PARTY_SCHEMAS)) == 4


def test_the_document_names_its_producer_whatever_it_claims(tmp_path):
    doc = _verify()
    doc["producer"] = {"id": "someone-else", "version": "9.9"}
    outcome = _run(tmp_path, doc)
    assert _records(outcome, "release-gate/loop-verifier")
    assert not _records(outcome, "someone-else")


def test_the_command_keys_are_kept_and_the_contract_keys_lead():
    payload = {"decision": "SHIP", "checks": {}, "iteration": 1}
    doc = first_party_document(LOOP_VERIFY_SCHEMA, payload, producer_id="release-gate/x",
                               version="1", state={"governance_policy": GOV, "commit": ""})
    assert list(doc)[:3] == ["schema", "producer", "state"]
    assert {k: doc[k] for k in payload} == payload
    assert doc["state"] == {"governance_policy": GOV}


# ── a command's verdict and score decide nothing ─────────────────────────────

@pytest.mark.parametrize("producer_type", sorted(SAMPLES))
def test_the_command_verdict_is_recorded_and_adopted_by_nothing(tmp_path, producer_type):
    outcome = _run(tmp_path, SAMPLES[producer_type]())
    decided = [r for r in _records(outcome, PRODUCER[producer_type])
               if (r.content or {}).get("external_decision")]
    assert len(decided) == 1
    record = decided[0]
    assert record.content["external_decision"]["is_release_gate_verdict"] is False
    assert not record.supports_claims and not record.contradicts_claims


@pytest.mark.parametrize("verdict", ["BLOCK", "ROLLBACK", "HOLD", "PROMOTE", "SHIP"])
def test_no_command_verdict_moves_the_decision(tmp_path, verdict):
    """The promoting release stays PROMOTE whatever a command said about itself."""
    baseline = assure(str(RELEASE), methodology=GENERAL)
    for build in (_pr, _verify, _loop_sim, _agent_score):
        outcome = _run(tmp_path, build(decision=verdict))
        assert _decision(outcome) == _decision(baseline) == "PROMOTE"


@pytest.mark.parametrize("build,field", [
    (_agent_score, "score"), (_loop_sim, "convergence_rate"),
    (_loop_sim, "adversarial_pass_rate"), (_pr, "code_safety_delta")])
def test_a_score_is_read_by_nothing(tmp_path, build, field):
    low, high = build(**{field: 0}), build(**{field: 100})
    a, b = _run(tmp_path, low, name="low.json"), _run(tmp_path, high, name="high.json")
    assert _decision(a) == _decision(b)
    assert _fired(a) == _fired(b)
    statuses = lambda o: sorted((r.claim_id, r.status.value)  # noqa: E731
                                for r in o.analysis.resolution.resolutions)
    assert statuses(a) == statuses(b)


def test_a_perfect_score_cannot_establish_anything(tmp_path):
    outcome = _run(tmp_path, _agent_score())
    for claim in ("rg-agent-score:no-secret-revealed", "rg-agent-score:correctness"):
        assert _status(outcome, claim) == "SUPPORTED"


# ── trace validation: a check, scoped to the trace it read ───────────────────

def test_a_trace_that_broke_its_policy_is_a_failed_check(tmp_path):
    doc = _trace("FAIL", violations=["Forbidden tool called: close_account"])
    outcome = _run(tmp_path, doc)
    assert _status(outcome, "rg-trace:t-1") == "CONTRADICTED"
    # The loop verifier's own word stayed SHIP; the case blocks on the check.
    assert doc["decision"] == "SHIP" and _decision(outcome) == "BLOCK"
    [record] = [r for r in _records(outcome, "release-gate/loop-verifier")
                if r.contradicts_claims]
    assert record.contradicts_claims == ("rg-trace:t-1",)
    assert record.content["native_outcome"] == "FAIL"


def test_a_clean_trace_supports_only_the_claim_about_that_trace(tmp_path):
    outcome = _run(tmp_path, _trace("PASS"))
    # One passing check supports; it does not establish (the default policy asks
    # for more than one source to establish anything).
    assert _status(outcome, "rg-trace:t-1") == "SUPPORTED"
    claim = next(c for c in outcome.normalisation.claims if c.claim_id == "rg-trace:t-1")
    assert "trace t-1" in claim.statement
    [attempt] = claim.verification_attempts
    assert attempt.status.value == "PASSED"
    assert attempt.method.value == "RUNTIME_ASSERTION"


@pytest.mark.parametrize("status,expected,resolved", [
    ("WARN", "INCONCLUSIVE", "UNKNOWN"), ("ERROR", "FAILED", "CONTRADICTED")])
def test_a_trace_warning_or_error_is_never_a_pass(tmp_path, status, expected, resolved):
    outcome = _run(tmp_path, _trace(status, warnings=["Possible tool loop detected"]))
    claim = next(c for c in outcome.normalisation.claims if c.claim_id == "rg-trace:t-1")
    assert [a.status.value for a in claim.verification_attempts] == [expected]
    assert _status(outcome, "rg-trace:t-1") == resolved


@pytest.mark.parametrize("status", ["OK", "green", "", "pass-ish", True])
def test_a_check_word_outside_the_table_holds(tmp_path, status):
    outcome = _run(tmp_path, _trace(status))
    claim = next(c for c in outcome.normalisation.claims if c.claim_id == "rg-trace:t-1")
    assert all(a.status.value != "PASSED" for a in claim.verification_attempts)
    assert outcome.normalisation.unread_values
    assert "RG-COV-002" in _fired(outcome)
    assert _decision(outcome) == "HOLD"


def test_trace_validation_against_another_governance_version_is_stale(tmp_path):
    from release_gate.assurance.candidate import CandidateSource, CandidateState
    candidate = CandidateState(components={"governance_policy": OTHER_GOV},
                               source=CandidateSource.DECLARED_BY_CALLER,
                               declared_by="test")
    passed = _run(tmp_path, _trace("PASS"), candidate=candidate, name="pass.json")
    assert _status(passed, "rg-trace:t-1") == "UNSUPPORTED"
    assert "RG-DRIFT-006" in _fired(passed)
    # A failure against the previous policy still stands: moving on answers nothing.
    failed = _run(tmp_path, _trace("FAIL", violations=["Forbidden tool called: x"]),
                  candidate=candidate, name="fail.json")
    assert _status(failed, "rg-trace:t-1") == "CONTRADICTED"
    current = CandidateState(components={"governance_policy": GOV},
                             source=CandidateSource.DECLARED_BY_CALLER, declared_by="test")
    bound = _run(tmp_path, _trace("PASS"), candidate=current, name="bound.json")
    assert _status(bound, "rg-trace:t-1") == "SUPPORTED"


# ── evals the loop verifier ran ──────────────────────────────────────────────

def _evals(mode, *rows):
    doc = _verify()
    doc["checks"]["evals"] = {"mode": mode, "total": len(rows), "results": list(rows)}
    return doc


def _case(name, passed=True, expected="contains_keywords"):
    return {"name": name, "severity": "high", "passed": passed, "expected": expected,
            "failure_reason": None if passed else "missing keyword", "response": "text"}


def test_an_eval_with_no_output_checked_nothing(tmp_path):
    outcome = _run(tmp_path, _evals("static", _case("refund-cap")))
    claim = next(c for c in outcome.normalisation.claims
                 if c.claim_id == "rg-loop-eval:refund-cap:iteration-1")
    assert [a.status.value for a in claim.verification_attempts] == ["NOT_RUN"]


def test_an_eval_behaviour_the_runner_does_not_know_checked_nothing(tmp_path):
    outcome = _run(tmp_path, _evals("live", _case("tone", expected="polite")))
    claim = next(c for c in outcome.normalisation.claims
                 if c.claim_id == "rg-loop-eval:tone:iteration-1")
    assert [a.status.value for a in claim.verification_attempts] == ["NOT_RUN"]


def test_a_live_eval_is_a_check_of_the_output_it_read(tmp_path):
    outcome = _run(tmp_path, _evals("live", _case("refund-cap"),
                                    _case("pii", passed=False)))
    claims = {c.claim_id: c for c in outcome.normalisation.claims}
    assert [a.status.value for a in claims["rg-loop-eval:refund-cap:iteration-1"]
            .verification_attempts] == ["PASSED"]
    assert [a.status.value for a in claims["rg-loop-eval:pii:iteration-1"]
            .verification_attempts] == ["FAILED"]
    assert "loop iteration 1" in claims["rg-loop-eval:pii:iteration-1"].statement


def test_the_known_behaviours_are_the_eval_runners():
    from release_gate.evals.runner import EvalRunner
    runner = EvalRunner()
    for behaviour in EVAL_BEHAVIOURS:
        case = {"name": "x", "expected_behavior": behaviour, "keywords_blocked": ["k"],
                "keywords_required": ["k"], "schema": {"type": "object"}}
        _, reason = runner._assert_behavior(case, "{}", behaviour)
        assert "Unknown expected_behavior" not in (reason or "")
    _, reason = runner._assert_behavior({}, "{}", "polite")
    assert "Unknown expected_behavior" in reason


# ── behavioural samples: a pass supports, a breach is a counterexample ───────

def test_an_adversarial_scenario_that_got_through_is_a_counterexample(tmp_path):
    doc = _loop_sim()
    doc["scenario_results"][1].update(decision="SHIP", passed=False)
    outcome = _run(tmp_path, doc)
    found = [r for r in _records(outcome, "release-gate/loop-sim")
             if r.evidence_type.value == "COUNTEREXAMPLE"]
    assert [r.contradicts_claims for r in found] == [("rg-loop-sim:exfiltrate",)]
    assert _status(outcome, "rg-loop-sim:exfiltrate") == "CONTRADICTED"
    assert "RG-CEX-002" in _fired(outcome) and _decision(outcome) == "BLOCK"


def test_a_scenario_that_went_well_supports_and_never_establishes(tmp_path):
    outcome = _run(tmp_path, _loop_sim())
    for claim_id in ("rg-loop-sim:summarise", "rg-loop-sim:exfiltrate"):
        claim = next(c for c in outcome.normalisation.claims if c.claim_id == claim_id)
        assert claim.supporting_evidence and not claim.verification_attempts
        assert _status(outcome, claim_id) == "SUPPORTED"


def test_a_leaked_probe_is_a_counterexample_however_high_the_score(tmp_path):
    outcome = _run(tmp_path, _agent_score(score=99, decision="PROMOTE", issues=[_LEAK]))
    found = [r for r in _records(outcome, "release-gate/agent-score")
             if r.evidence_type.value == "COUNTEREXAMPLE"]
    assert [r.contradicts_claims for r in found] == [("rg-agent-score:no-secret-revealed",)]
    assert _status(outcome, "rg-agent-score:no-secret-revealed") == "CONTRADICTED"
    assert "RG-CEX-002" in _fired(outcome) and _decision(outcome) == "BLOCK"
    claim = next(c for c in outcome.normalisation.claims
                 if c.claim_id == "rg-agent-score:no-secret-revealed")
    assert not claim.supporting_evidence


def test_an_errored_safety_battery_supports_nothing(tmp_path):
    doc = _agent_score()
    doc["dimensions"]["safety"]["errored"] = 5
    outcome = _run(tmp_path, doc)
    assert not any(c.claim_id == "rg-agent-score:no-secret-revealed"
                   for c in outcome.normalisation.claims)


def test_probe_counts_are_measurements_not_ratios(tmp_path):
    outcome = _run(tmp_path, _agent_score())
    counts = [r.content["measurement"] for r in _records(outcome, "release-gate/agent-score")
              if r.content.get("measurement")]
    assert {(m["unit"], m["count"], m["of"]) for m in counts} >= {
        ("L1 injection probes", 3, 3), ("correctness probes", 3, 3)}


# ── PR diff analysis ─────────────────────────────────────────────────────────

def test_a_net_new_finding_argues_against_the_change(tmp_path):
    outcome = _run(tmp_path, _pr(new_code_findings=[_NEW_FINDING], decision="BLOCK"))
    against = [r for r in _records(outcome, "release-gate/pr") if r.contradicts_claims]
    assert [r.contradicts_claims for r in against] == [("rg-pr:no-net-new-finding",)]
    assert against[0].content["native_severity"] == "high"
    assert against[0].content["state"]["commit"] == "e41c07b9a3d2"
    assert _status(outcome, "rg-pr:no-net-new-finding") == "CONTRADICTED"


def test_no_net_new_finding_supports_by_what_was_read_and_never_checks(tmp_path):
    outcome = _run(tmp_path, _pr())
    claim = next(c for c in outcome.normalisation.claims
                 if c.claim_id == "rg-pr:no-net-new-finding")
    assert claim.supporting_evidence and not claim.verification_attempts
    # Worded the same for every change; the merge-base is on the record.
    assert claim.statement == ("this change introduces no static finding that its "
                               "merge-base did not have")
    [record] = [r for r in _records(outcome, "release-gate/pr")
                if r.evidence_id in claim.supporting_evidence]
    assert "9d02aa4f71c3" in record.content["subject"]
    assert record.content["result_kind"] == "OBSERVATION"


def test_lock_drift_argues_against_the_pinned_context(tmp_path):
    drift = {"drift": True, "expired": False, "model_changed": True,
             "changed": ["prompts/system.txt"], "added": [], "removed": [],
             "saved_model": "m-1", "current_model": "m-2", "gate_ok": False,
             "_lock_updated_in_pr": False}
    outcome = _run(tmp_path, _pr(lock_drift=drift))
    against = sorted(r.content["native_id"] for r in _records(outcome, "release-gate/pr")
                     if "rg-pr:context-matches-lock" in r.contradicts_claims)
    assert against == ["lock:model", "lock:prompts/system.txt"]
    updated = dict(drift, _lock_updated_in_pr=True)
    outcome = _run(tmp_path, _pr(lock_drift=updated), name="updated.json")
    assert not any("rg-pr:context-matches-lock" in r.contradicts_claims
                   for r in _records(outcome, "release-gate/pr"))


def test_lock_drift_that_names_nothing_is_never_a_match(tmp_path):
    outcome = _run(tmp_path, _pr(lock_drift={"drift": True, "gate_ok": False}))
    assert any("rg-pr:context-matches-lock" in r.contradicts_claims
               for r in _records(outcome, "release-gate/pr"))


# ── several outputs of one command ───────────────────────────────────────────

def _run_many(tmp_path, docs, **kwargs):
    paths = []
    for index, doc in enumerate(docs):
        path = tmp_path / f"many-{index}.json"
        path.write_text(json.dumps(doc))
        paths.append(str(path))
    return assure(str(RELEASE), methodology=GENERAL, evidence=paths, **kwargs)


def test_two_runs_of_one_battery_are_one_claim_and_a_leak_in_either_stands(tmp_path):
    clean = _agent_score(agent="py:acme.agent:handle")
    leaked = _agent_score(agent="http://agent.internal/handle", issues=[_LEAK])
    outcome = _run_many(tmp_path, [clean, leaked])
    assert not outcome.normalisation.unread_values
    claims = [c for c in outcome.normalisation.claims
              if c.claim_id == "rg-agent-score:no-secret-revealed"]
    assert len(claims) == 1 and claims[0].supporting_evidence
    assert _status(outcome, "rg-agent-score:no-secret-revealed") == "CONTRADICTED"


def test_two_changes_against_different_bases_share_their_claims(tmp_path):
    outcome = _run_many(tmp_path, [_pr(merge_base="9d02aa4f71c3"),
                                   _pr(merge_base="77c1e0d2b9aa")])
    assert not outcome.normalisation.unread_values
    assert _status(outcome, "rg-pr:no-net-new-finding") == "SUPPORTED"


def test_an_eval_claim_is_about_one_iterations_output(tmp_path):
    first = _evals("live", _case("refund-cap", passed=False))
    third = _evals("live", _case("refund-cap"))
    third["iteration"] = 3
    outcome = _run_many(tmp_path, [first, third])
    assert not outcome.normalisation.unread_values
    assert _status(outcome, "rg-loop-eval:refund-cap:iteration-3") == "SUPPORTED"
    assert _status(outcome, "rg-loop-eval:refund-cap:iteration-1") == "CONTRADICTED"


def test_a_loop_policy_breach_at_any_iteration_stands(tmp_path):
    ok = _verify()
    breached = _verify(iteration=9)
    breached["checks"]["loop_policy"].update(
        status="FAIL", iteration=9, violations=["Max iterations exceeded: 9 > 8"])
    outcome = _run_many(tmp_path, [ok, breached])
    assert not outcome.normalisation.unread_values
    assert _status(outcome, "rg-loop:policy") == "CONTRADICTED"


# ── reports ──────────────────────────────────────────────────────────────────

def test_the_admission_report_lists_them_as_release_gates_own(tmp_path):
    from release_gate.assurance.admission_report import build_admission_report
    evidence = []
    for index, build in enumerate((_pr, _verify, _loop_sim, _agent_score)):
        path = tmp_path / f"fp-{index}.json"
        path.write_text(json.dumps(build()))
        evidence.append(str(path))
    outcome = assure(str(RELEASE), methodology=GENERAL, evidence=evidence)
    report = build_admission_report(outcome)
    labels = {s.label for s in report.generated}
    assert {"Release-Gate PR diff", "Release-Gate trace and loop verifier",
            "Release-Gate loop simulation", "Release-Gate agent score"} <= labels
    assert not {s.producer for s in report.imported} & set(PRODUCER.values())


# ── from the commands themselves ─────────────────────────────────────────────

def _cli(*args, cwd=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args], cwd=cwd,
                          capture_output=True, text=True, env=env, timeout=300)


def _governance(tmp_path):
    gov = tmp_path / "governance.yaml"
    gov.write_text("loop:\n  max_iterations: 4\n  checker_model: checker-1\n"
                   "  maker_model: maker-1\n"
                   "trace_policies:\n  forbidden_tools: [close_account]\n")
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps({"trace_id": "t-9", "steps": [
        {"type": "llm_call", "model": "m", "tokens": 10},
        {"type": "tool_call", "tool": "close_account", "args": {"id": "c-1"}}]}))
    return gov, trace


def test_verify_json_is_read_with_the_governance_it_checked(tmp_path):
    import hashlib
    gov, trace = _governance(tmp_path)
    run = _cli("verify", str(gov), "--trace", str(trace), "--json")
    assert run.returncode == 1, run.stderr
    doc = json.loads(run.stdout)
    assert doc["schema"] == LOOP_VERIFY_SCHEMA
    assert doc["decision"] == "ROLLBACK"
    assert doc["state"]["governance_policy"] == \
        "sha256:" + hashlib.sha256(gov.read_bytes()).hexdigest()
    assert doc["inputs"]["trace"]["sha256"].startswith("sha256:")
    outcome = _run(tmp_path, doc)
    assert _status(outcome, "rg-trace:t-9") == "CONTRADICTED"


def test_loop_sim_json_is_read(tmp_path):
    run = _cli("loop-sim", str(ROOT / "examples" / "loop_scenarios.yaml"), "--json")
    doc = json.loads(run.stdout)
    assert doc["schema"] == LOOP_SIM_SCHEMA
    assert doc["inputs"]["scenarios"]["sha256"].startswith("sha256:")
    outcome = _run(tmp_path, doc)
    assert _records(outcome, "release-gate/loop-sim")


def test_agent_score_json_is_read(tmp_path):
    run = _cli("agent-score", "py:examples.loop_agents:mid", "--json", cwd=ROOT)
    doc = json.loads(run.stdout)
    assert doc["schema"] == AGENT_SCORE_SCHEMA
    outcome = _run(tmp_path, doc)
    assert any(r.evidence_type.value == "COUNTEREXAMPLE"
               for r in _records(outcome, "release-gate/agent-score"))


def test_pr_json_is_read_and_binds_to_the_change(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True,  # noqa: E731
                                    capture_output=True)
    git("init", "-q", "-b", "main")
    (repo / "agent.py").write_text("from openai import OpenAI\nclient = OpenAI()\n")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
    git("checkout", "-qb", "change")
    (repo / "agent.py").write_text(
        "from openai import OpenAI\nclient = OpenAI()\n\n\ndef run(blob):\n"
        "    reply = client.chat.completions.create(model='m', messages=[])\n"
        "    return eval(reply.choices[0].message.content)\n")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "change")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                          text=True).stdout.strip()
    run = _cli("pr", "--base", "main", "--json", cwd=repo)
    doc = json.loads(run.stdout)
    assert doc["schema"] == PR_SCHEMA
    assert doc["state"]["commit"] == head
    outcome = _run(tmp_path, doc)
    assert any("rg-pr:no-net-new-finding" in r.contradicts_claims
               for r in _records(outcome, "release-gate/pr"))


def test_the_loop_verifier_says_what_it_checked_not_that_output_is_ready(tmp_path):
    from release_gate.loop_verifier import LoopVerifier
    result = LoopVerifier().verify(iteration=1, loop_policy={"max_iterations": 3})
    assert result.decision == "SHIP"
    said = " ".join(result.reasons)
    assert "ready to ship" not in said
    assert "loop_policy" in said and "not an admission decision" in said


def test_the_legacy_outputs_keep_every_key(tmp_path):
    """The contract keys are added; nothing a consumer already reads is moved."""
    gov, trace = _governance(tmp_path)
    run = _cli("verify", str(gov), "--trace", str(trace), "--json")
    doc = json.loads(run.stdout)
    assert {"decision", "reasons", "violations", "warnings", "checks", "iteration",
            "cost_so_far", "cost_remaining"} <= set(doc)
