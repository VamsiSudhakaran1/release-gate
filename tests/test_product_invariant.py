"""The product, in one picture, and the invariant it keeps — pinned to the code.

`docs/ARCHITECTURE.md` draws the product as five parts: first-party evidence
producers, external evidence, semantic verification, the AssuranceCase, and a
deterministic admission policy. This file holds that picture to the code in two
ways.

**The picture.** Every node in the drawing resolves to the module, class or
value that implements it, and the drawing in the document is the drawing here.
A node nothing implements, or a drawing edited away from the code, fails.

**The invariant.** "Release-Gate may generate evidence, ingest evidence,
normalize evidence, compare evidence, semantically interpret bounded evidence,
and determine whether evidence satisfies policy. It must never pretend that one
model, one scanner, one evaluator, one score, or one successful test establishes
universal truth." Each clause is executed: one source of each kind is added,
alone, to a release that holds on an unassessed required claim and to one that
blocks on a counterexample, and what it can and cannot do is asserted. The
contrast is executed too, because an invariant a policy can never satisfy would
be a gate that never opens: two independent groups of passing checks do
establish, and a release whose declared policy asks only for support admits on
the support it asked for.
"""
from __future__ import annotations

import dataclasses
import importlib
import json
import re
from pathlib import Path

import pytest

from release_gate.assurance.first_party import (
    AGENT_SCORE_SCHEMA,
    LOOP_SIM_SCHEMA,
    LOOP_VERIFY_SCHEMA,
    PR_SCHEMA,
    first_party_document,
)
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.resolution import DEFAULT_RESOLUTION_POLICY, ResolutionStatus
from release_gate.assurance.semantic_verifier import (
    AssertionStatus,
    SemanticAssertion,
    SemanticVerdict,
    UnknownReason,
    state_hash_for,
)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
GENERAL = default_registry().resolve("general-agent-action@1.0.0")
BASE = [json.loads(line) for line in
        (ROOT / "examples" / "agents" / "02-release-promoted.jsonl").read_text().splitlines()
        if line.strip()]
DIGEST = "sha256:9c2f1e4a7b83d05fe6c1a9b4d72e8f3016a5c9d84b2e7f1a3c6d0985b7e4f2a1"

INVARIANT = ("Release-Gate may generate evidence, ingest evidence, normalize evidence, "
             "compare evidence, semantically interpret bounded evidence, and determine "
             "whether evidence satisfies policy. It must never pretend that one model, one "
             "scanner, one evaluator, one score, or one successful test establishes "
             "universal truth.")

PICTURE = """\
Release-Gate
│
├── First-party evidence producers
│      ├── AST / taint
│      ├── PR diff analysis
│      ├── governance verification
│      ├── trace validation
│      └── behavioral safety where already present
│
├── External evidence
│      ├── evaluators
│      ├── red-team tools
│      ├── observability
│      ├── SAST
│      ├── formal verification
│      └── humans
│
├── Semantic verification
│      ├── bounded questions only
│      ├── Laya/Jev-style providers
│      ├── reasoning LLM providers
│      └── UNKNOWN on uncertainty/failure
│
├── AssuranceCase
│      ├── claims
│      ├── evidence
│      ├── assumptions
│      ├── contradictions
│      ├── counterexamples
│      ├── failed branches
│      ├── coverage
│      └── independence
│
└── Deterministic admission policy
       ├── PROMOTE
       ├── HOLD
       └── BLOCK
"""

#: Every node, and what implements it: `module` or `module:attribute.path`.
IMPLEMENTED_BY = {
    "First-party evidence producers": {
        "AST / taint": ["release_gate.agent_analysis",
                        "release_gate.assurance.static_producer:STATIC_DECLARATION"],
        "PR diff analysis": ["release_gate.audit:compare_to_baseline",
                             "release_gate.assurance.first_party:PrDiffAdapter"],
        "governance verification": [
            "release_gate.verify",
            "release_gate.assurance.static_producer:safeguard_profile"],
        "trace validation": ["release_gate.trace_validator:TraceValidator",
                             "release_gate.assurance.first_party:LoopVerifyAdapter"],
        "behavioral safety where already present": [
            "release_gate.loop_verifier:LoopVerifier",
            "release_gate.loop_sim:LoopSimulator",
            "release_gate.agent_score:AgentScorer",
            "release_gate.assurance.first_party:LoopSimAdapter",
            "release_gate.assurance.first_party:AgentScoreAdapter"],
    },
    "External evidence": {
        "evaluators": ["release_gate.assurance.reference_adapters:GenericEvalAdapter",
                       "release_gate.assurance.reference_adapters:BehaviorEvalAdapter",
                       "release_gate.assurance.producer_adapters:PromptfooAdapter"],
        "red-team tools": ["release_gate.assurance.reference_adapters:RedTeamAdapter"],
        "observability": ["release_gate.adapters.otel", "release_gate.adapters.langfuse",
                          "release_gate.adapters.arize"],
        "SAST": ["release_gate.assurance.producer_adapters:SarifAdapter",
                 "release_gate.assurance.reference_adapters:GenericSastAdapter"],
        "formal verification": ["release_gate.assurance.verifiers:GenericVerifierAdapter"],
        "humans": ["release_gate.assurance.reference_adapters:HumanReviewAdapter",
                   "release_gate.assurance.approval:BoundApproval"],
    },
    "Semantic verification": {
        "bounded questions only": [
            "release_gate.assurance.escalation:plan_escalation",
            "release_gate.assurance.semantic_verifier:SemanticVerifier"],
        "Laya/Jev-style providers": ["release_gate.decision_providers.laya",
                                     "release_gate.decision_providers.jev"],
        "reasoning LLM providers": ["release_gate.semantic_providers:provider_from_env",
                                    "release_gate.assurance.semantic_panel"],
        "UNKNOWN on uncertainty/failure": [
            "release_gate.assurance.semantic_verifier:AssertionStatus.UNKNOWN",
            "release_gate.assurance.semantic_verifier:UnknownReason"],
    },
    "AssuranceCase": {
        "claims": ["release_gate.assurance.claims:Claim",
                   "release_gate.assurance.resolution:ClaimResolutionReport"],
        "evidence": ["release_gate.assurance.evidence:EvidenceRecord"],
        "assumptions": ["release_gate.assurance.assumptions:AssumptionGraph"],
        "contradictions": ["release_gate.assurance.contradiction"],
        "counterexamples": ["release_gate.assurance.counterexample:CounterexampleLedger"],
        "failed branches": ["release_gate.assurance.failed_branches:FailedBranchLedger"],
        "coverage": ["release_gate.assurance.claim_coverage"],
        "independence": ["release_gate.assurance.correlation",
                         "release_gate.assurance.authorship"],
    },
    "Deterministic admission policy": {
        "PROMOTE": ["release_gate.assurance.case:Decision.PROMOTE"],
        "HOLD": ["release_gate.assurance.case:Decision.HOLD"],
        "BLOCK": ["release_gate.assurance.case:Decision.BLOCK"],
    },
}


def _resolve(target: str):
    module, _, path = target.partition(":")
    found = importlib.import_module(module)
    for name in filter(None, path.split(".")):
        found = getattr(found, name)
    return found


def _between(text: str, marker: str) -> str:
    match = re.search(rf"<!-- {marker}:start -->\n(.*?)<!-- {marker}:end -->", text,
                      re.DOTALL)
    assert match, f"docs/ARCHITECTURE.md has no {marker} block"
    return match.group(1)


def _drawn(picture: str):
    """(part, node) for every node in the drawing, in order."""
    part = None
    for line in picture.splitlines():
        top = re.match(r"^[├└]── (.+)$", line)
        leaf = re.match(r"^[│ ]\s+[├└]── (.+)$", line)
        if top:
            part = top.group(1).strip()
        elif leaf:
            yield part, leaf.group(1).strip()


# ── the picture ──────────────────────────────────────────────────────────────

def test_the_architecture_document_draws_this_picture():
    text = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    block = _between(text, "product-model")
    assert block.strip().strip("`").replace("text\n", "", 1).strip() == PICTURE.strip()


def test_every_node_in_the_picture_is_implemented():
    drawn = list(_drawn(PICTURE))
    assert len(drawn) == 26
    assert {(p, n) for p, nodes in IMPLEMENTED_BY.items() for n in nodes} == set(drawn)
    for part, node in drawn:
        for target in IMPLEMENTED_BY[part][node]:
            assert _resolve(target) is not None, f"{part} / {node}: {target}"


def test_the_admission_policy_has_exactly_three_outcomes():
    from release_gate.assurance.case import Decision
    assert [d.value for d in Decision] == ["PROMOTE", "HOLD", "BLOCK"]


def test_every_first_party_producer_reaches_a_case_through_the_contract():
    """Each first-party node is a producer `assure` can read — none is a side channel."""
    from release_gate.assurance.producer_contract import default_producer_registry
    from release_gate.assurance.static_producer import STATIC_DECLARATION
    registry = default_producer_registry()
    names = {a.name for a in registry.adapters}
    assert {"release_gate_pr", "release_gate_loop_verify", "release_gate_loop_sim",
            "release_gate_agent_score"} <= names
    assert STATIC_DECLARATION.producer_type in {d.producer_type
                                                for d in registry.declarations}
    for adapter in registry.adapters:
        assert adapter.declaration.limitations, adapter.name


def test_every_failure_of_a_semantic_provider_is_unknown_and_moves_nothing(tmp_path):
    before = _run(tmp_path, _hold(), name="before")
    state = state_hash_for(before.analysis)
    for reason in UnknownReason:
        reading = SemanticAssertion(question_id="sq_C-9", claim_id="C-9",
                                    status=AssertionStatus.UNKNOWN, unknown_reason=reason,
                                    model="m", provider="p", state_hash=state)
        after = _run(tmp_path, _hold(), name=f"u-{reason.value}",
                     semantic_assertions=[reading])
        assert _decision(after) == _decision(before) == "HOLD"
        assert _status(after, "C-9") == _status(before, "C-9")


def test_the_invariant_is_stated_where_the_product_is_described():
    for name in ("README.md", "docs/ARCHITECTURE.md", "docs/POSITIONING.md"):
        lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
        text = " ".join(" ".join(re.sub(r"^\s*>\s?", "", line) for line in lines).split())
        assert INVARIANT in text, name


# ── the invariant, executed ──────────────────────────────────────────────────

_C9 = {"record_type": "claim", "claim_id": "C-9", "is_root": True,
       "proposition": "no customer record leaves the EU region"}


def _hold():
    """The promoting release, plus a required claim nothing has assessed."""
    return [*BASE, dict(_C9)]


def _block():
    """The promoting release, plus a found counterexample to its claim."""
    return [*BASE, {"record_type": "counterexample", "target_claim": "C-1",
                    "result": "FOUND", "method": "PROPERTY_TEST",
                    "producer_id": "fuzz://lab",
                    "detail": "0.005 JPY rounds to 0.01 under the fix"}]


def _run(tmp_path, rows, *, name, evidence=(), **kwargs):
    path = tmp_path / f"{name}.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    paths = []
    for index, doc in enumerate(evidence):
        extra = tmp_path / f"{name}-{index}.json"
        extra.write_text(json.dumps(doc))
        paths.append(str(extra))
    return assure(str(path), methodology=kwargs.pop("methodology", GENERAL),
                  evidence=paths, **kwargs)


def _decision(outcome):
    return outcome.case.verdict.decision.value


def _status(outcome, claim_id):
    resolved = outcome.analysis.resolution.of(claim_id)
    return resolved.status.value if resolved else None


def _eval(claim_id="C-9", case="c-1", outcome="passed", session="s-1", provider="acme",
          **extra):
    return {"schema": "release-gate.eval/1",
            "producer": {"id": f"{provider}-evals", "version": "1"},
            "provenance": {"provider": provider, "session": session},
            "cases": [{"id": case, "outcome": outcome, "claim_id": claim_id,
                       "state": {"applies_to": DIGEST}, **extra}]}


def _evaluator(decision="approve", score=0.99):
    return {"external_decision": {
        "producer": {"id": "acme-evaluator", "version": "1"}, "decision": decision,
        "subject": "C-9", "vocabulary": ["approve", "reject"], "score": score,
        "state": {"applies_to": DIGEST}}}


def _clean_sarif():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {
        "name": "acme-sast", "version": "4.2"}}, "results": []}]}


def _first_party_promote():
    """Release-gate's own commands, each saying PROMOTE or SHIP at full marks."""
    return [
        first_party_document(PR_SCHEMA, {
            "decision": "PROMOTE", "merge_base": "9d02aa4", "reasons": [],
            "new_code_findings": [], "new_safeguard_failures": [],
            "resolved_code_findings": []}, producer_id="release-gate/pr", version="1"),
        first_party_document(LOOP_VERIFY_SCHEMA, {
            "decision": "SHIP", "reasons": [], "checks": {
                "trace": {"status": "PASS", "trace_id": "t-1", "violations": []}}},
            producer_id="release-gate/loop-verifier", version="1"),
        first_party_document(LOOP_SIM_SCHEMA, {
            "decision": "PROMOTE", "reasons": [], "scenarios_run": 1,
            "scenarios_passed": 1, "convergence_rate": 1.0, "scenario_results": [
                {"id": "s-1", "expect": "SHIP", "decision": "SHIP", "passed": True}]},
            producer_id="release-gate/loop-sim", version="1"),
        first_party_document(AGENT_SCORE_SCHEMA, {
            "score": 100, "decision": "PROMOTE", "agent": "py:acme:agent",
            "dimensions": {"safety": {"total": 3, "passed": 3, "errored": 0}},
            "issues": []}, producer_id="release-gate/agent-score", version="1"),
    ]


def _model(outcome, claim_id, *, family, verdict=SemanticVerdict.SUPPORTED):
    return SemanticAssertion(question_id=f"sq_{claim_id}_{family}", claim_id=claim_id,
                             status=AssertionStatus.ANSWERED, verdict=verdict,
                             confidence=0.99, model=f"{family}-large", provider=family,
                             model_family=family, state_hash=state_hash_for(outcome.analysis))


#: One source of each kind the invariant names, bearing on the held claim C-9.
ONE_OF_EACH = {
    "one evaluator": lambda: [_evaluator()],
    "one scanner": lambda: [_clean_sarif()],
    "one score": lambda: [_eval(outcome="", score=1.0)],
    "release-gate's own commands": _first_party_promote,
}


def test_the_starting_points(tmp_path):
    held = _run(tmp_path, _hold(), name="hold")
    assert _decision(held) == "HOLD" and _status(held, "C-9") == "NOT_ASSESSED"
    blocked = _run(tmp_path, _block(), name="block")
    assert _decision(blocked) == "BLOCK"


@pytest.mark.parametrize("kind", sorted(ONE_OF_EACH))
def test_one_evaluator_scanner_score_or_own_command_cannot_admit(tmp_path, kind):
    outcome = _run(tmp_path, _hold(), name=kind.replace(" ", "-"),
                   evidence=ONE_OF_EACH[kind]())
    assert _decision(outcome) == "HOLD"
    assert _status(outcome, "C-9") in ("NOT_ASSESSED", "UNKNOWN")


def test_one_model_cannot_admit_or_establish(tmp_path):
    before = _run(tmp_path, _hold(), name="model-before")
    readings = [_model(before, "C-9", family=f) for f in ("a", "b", "c", "d", "e")]
    after = _run(tmp_path, _hold(), name="model-after", semantic_assertions=readings)
    assert _decision(after) == "HOLD"
    assert _status(after, "C-9") == "NOT_ASSESSED"


def test_a_counted_model_reading_supports_and_never_establishes(tmp_path):
    from release_gate.assurance.resolution import SemanticSupport
    counts = dataclasses.replace(DEFAULT_RESOLUTION_POLICY,
                                 semantic_support=SemanticSupport.COUNTS,
                                 admission_level=ResolutionStatus.ESTABLISHED)
    before = _run(tmp_path, _hold(), name="counted-before", resolution_policy=counts)
    readings = [_model(before, "C-9", family=f) for f in ("a", "b", "c")]
    after = _run(tmp_path, _hold(), name="counted-after", resolution_policy=counts,
                 semantic_assertions=readings)
    assert _status(after, "C-9") != "ESTABLISHED"
    assert _decision(after) == "HOLD"


def test_one_successful_test_supports_and_never_establishes(tmp_path):
    outcome = _run(tmp_path, _hold(), name="one-test", evidence=[_eval()])
    assert _status(outcome, "C-9") == "SUPPORTED"


def _short(outcome):
    """The required claims the policy holds on: below its admission level."""
    return {r.claim_id for r in outcome.analysis.resolution.below_admission()}


STRICT = dataclasses.replace(DEFAULT_RESOLUTION_POLICY,
                             admission_level=ResolutionStatus.ESTABLISHED)


def test_copies_of_one_successful_test_are_still_one(tmp_path):
    copies = [_eval(case=f"c-{i}") for i in range(5)]
    outcome = _run(tmp_path, _hold(), name="copies", evidence=copies,
                   resolution_policy=STRICT)
    assert _status(outcome, "C-9") == "SUPPORTED"
    assert "C-9" in _short(outcome) and _decision(outcome) == "HOLD"


def test_the_policy_decides_what_one_test_is_worth(tmp_path):
    """The declared policy, not the test, says whether support is enough."""
    asks_support = _run(tmp_path, _hold(), name="asks-support", evidence=[_eval()])
    assert _decision(asks_support) == "PROMOTE" and "C-9" not in _short(asks_support)
    asks_more = _run(tmp_path, _hold(), name="asks-more", evidence=[_eval()],
                     resolution_policy=STRICT)
    assert "C-9" in _short(asks_more) and _decision(asks_more) == "HOLD"


def test_independent_evidence_can_satisfy_a_policy_that_asks_for_it(tmp_path):
    """The contrast: the invariant is about one source, not about never admitting."""
    two = [_eval(provider="acme", session="s-1"),
           _eval(provider="globex", session="s-9", case="g-1")]
    outcome = _run(tmp_path, _hold(), name="two-groups", evidence=two,
                   resolution_policy=STRICT)
    resolved = outcome.analysis.resolution.of("C-9")
    assert (resolved.status.value, resolved.rule) == ("ESTABLISHED", "CR-09")
    assert "C-9" not in _short(outcome)


@pytest.mark.parametrize("kind", sorted([*ONE_OF_EACH, "one successful test",
                                         "five models"]))
def test_nothing_of_one_kind_outvotes_a_counterexample(tmp_path, kind):
    before = _run(tmp_path, _block(), name=f"cx-{kind.replace(' ', '-')}")
    evidence, readings = [], []
    if kind == "one successful test":
        evidence = [_eval(claim_id="C-1", case=f"c-{i}") for i in range(50)]
    elif kind == "five models":
        readings = [_model(before, "C-1", family=f) for f in ("a", "b", "c", "d", "e")]
    else:
        evidence = ONE_OF_EACH[kind]()
    after = _run(tmp_path, _block(), name=f"cx2-{kind.replace(' ', '-')}",
                 evidence=evidence, semantic_assertions=readings)
    assert _decision(after) == "BLOCK"
    assert _status(after, "C-1") == "CONTRADICTED"


def test_an_admission_says_what_it_is_measured_against_and_never_safe(tmp_path):
    from release_gate.assurance.admission_report import (build_admission_report,
                                                          render_admission_report)
    outcome = _run(tmp_path, BASE, name="promoted")
    report = build_admission_report(outcome)
    text = render_admission_report(report)
    assert report.decision == "PROMOTE"
    assert report.to_dict()["decided_by_score"] is False
    # A PROMOTE names the policy it was measured against, and nothing beyond it.
    assert "PROMOTE under general-agent-action@1.0.0 and rg-resolution@1" in text
    assert not re.search(r"\b(is|are) safe\b|\bsafe to (deploy|ship)\b|\bguarantee",
                         text, re.IGNORECASE)


def test_every_record_says_what_its_producer_cannot_establish(tmp_path):
    evidence = [_eval(), _evaluator(), *_first_party_promote()]
    outcome = _run(tmp_path, _hold(), name="limits", evidence=evidence)
    produced = [r for r in outcome.case.collection("evidence").materialised
                if (getattr(r, "content", None) or {}).get("producer_type")]
    assert len({r.content["producer_type"] for r in produced}) >= 6
    for record in produced:
        assert record.content.get("does_not_establish"), record.content["producer_type"]
