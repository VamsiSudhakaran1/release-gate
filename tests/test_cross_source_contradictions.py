"""Cross-source contradictions — a disagreement is a contradiction only when it is one.

Pinned here, against release_gate/assurance/contradiction.py and the analysis that
reads it:

* the four examples: a static finding against a runtime trace, an eval suite
  against an adversarial result, a proof of tool_v2 for a tool_v3 candidate, an
  approval of build abc123 for def456;
* every disagreement is classified — GENUINE, STALE, SCOPE_MISMATCH,
  POPULATION_MISMATCH, ENVIRONMENT_MISMATCH, AMBIGUOUS — from what its sides
  declare, and only GENUINE is called a contradiction;
* classification never makes a disagreement disappear: every unresolved one on a
  critical claim still holds and is still named in the verdict, and the claim
  resolution still reads the failing side;
* the declared policy can make a genuine contradiction block, and cannot make any
  disagreement weaker than a hold;
* contradictions and state mismatches are first-class: stored on the case, with
  stable ids, and as edges of one conflict graph.
"""

from __future__ import annotations

import dataclasses
import json
from types import SimpleNamespace

import pytest

from release_gate.assurance.contradiction import (ConflictClass, Contradiction,
                                                  ContradictionKind, ContradictionSide,
                                                  classify_sides, conflict_graph)
from release_gate.assurance.resolution import (AdmissionEffect, ResolutionError,
                                               ResolutionPolicy, ResolutionStatus)
from release_gate.assurance.zero_config import assure, render_text

C = ConflictClass


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def claim(cid="c-x", text="the property holds", **kw):
    return {"record_type": "claim", "claim_id": cid, "is_root": True, "proposition": text,
            "producer": P("platform", "human"), **kw}


def ev(eid, kind, producer, *, supports=(), contradicts=(), **kw):
    return {"record_type": "evidence", "evidence_id": eid, "kind": kind,
            "producer": P(producer), "supports_claims": list(supports),
            "contradicts_claims": list(contradicts), "summary": eid,
            "coverage_note": eid, **kw}


def run(tmp_path, rows, name="case.json", **kw):
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return assure(str(path), **kw)


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def finding(outcome, rule_id):
    return next(f for f in outcome.analysis.findings if f.rule_id == rule_id)


def only(outcome):
    [contradiction] = list(outcome.contradictions)
    return contradiction


def pair(left: dict, right: dict, cid="c-x", lk="TEST_RESULT", rk="TEST_RESULT"):
    """One claim, one record for it, one against it."""
    return [claim(cid), ev("e-for", lk, "producer-a", supports=[cid], **left),
            ev("e-against", rk, "producer-b", contradicts=[cid], **right)]


# ── the four examples ────────────────────────────────────────────────────────

class TestTheFourExamples:

    def test_a_static_gate_against_a_trace_without_approval(self, tmp_path):
        """A: static analysis says the approval gate exists; the agent ran the
        action without approval. Same tool, same release: a contradiction."""
        outcome = run(tmp_path, [
            claim("c-gate", "Refunds require human approval before execution"),
            ev("e-static", "STATIC_FINDING", "release-gate-static", supports=["c-gate"],
               covers={"tool": "refund"}, summary="approval gate found on refund_tool"),
            ev("e-trace", "TRACE", "otel", contradicts=["c-gate"],
               covers={"tool": "refund"},
               summary="refund_tool executed with no approval event")])
        c = only(outcome)
        assert c.classification is C.GENUINE and c.is_contradiction
        assert c.cross_source
        assert {k for s in c.sides for k in s.kinds} == {"STATIC_FINDING", "TRACE"}
        assert "both state tool refund" in c.classification_basis
        assert "RG-CONTRA-005" in rules(outcome)
        assert outcome.case.verdict.decision.value == "HOLD"

    def test_b_an_eval_suite_against_a_privilege_escalation(self, tmp_path):
        """B: "all authorization tests pass" claims what a successful escalation
        refutes — the suite does not qualify which privileges it covered."""
        outcome = run(tmp_path, [
            claim("c-authz", "Authorization is enforced on every privileged action"),
            ev("e-pf", "EVAL_RESULT", "promptfoo", supports=["c-authz"],
               covers={"dataset": "authz-suite-v3"},
               summary="all 48 authorization tests pass"),
            ev("e-proofagent", "EXTERNAL_REFERENCE", "proofagent",
               contradicts=["c-authz"], covers={"adversarial_class": "privilege-escalation"},
               summary="privilege-escalation scenario succeeded")])
        c = only(outcome)
        assert c.classification is C.GENUINE and c.cross_source
        assert "RG-CONTRA-005" in rules(outcome)

    def test_c_a_proof_of_another_version_is_not_a_proof_of_this_one(self, tmp_path):
        """C: proven for tool_v2, the candidate ships tool_v3. Not a valid proof —
        a state mismatch with the release, not a contradiction with anything."""
        outcome = run(tmp_path, [
            {"record_type": "candidate", "components": {"tool_manifest": "tool_v3"}},
            claim("c-limit", "transfer_tool enforces the 10,000 limit"),
            ev("e-proof", "FORMAL_PROOF", "prover", supports=["c-limit"],
               state={"tool_manifest": "tool_v2"})])
        assert len(outcome.contradictions) == 0
        resolution = outcome.analysis.resolution.of("c-limit")
        assert resolution.status not in (ResolutionStatus.ESTABLISHED,
                                         ResolutionStatus.SUPPORTED)
        assert [i.role.value for i in resolution.items] == ["WITHHELD_STATE"]
        [edge] = conflict_graph(outcome.contradictions,
                                outcome.analysis.state_binding).of("STATE_MISMATCH")
        assert edge.classification is C.STALE and edge.target == ("candidate",)
        assert "tool_v2" in edge.detail and "tool_v3" in edge.detail
        assert "withheld" in edge.detail

    def test_c_and_a_current_failure_is_stale_not_contradictory(self, tmp_path):
        outcome = run(tmp_path, [
            {"record_type": "candidate", "components": {"tool_manifest": "tool_v3"}},
            claim("c-limit", "transfer_tool enforces the 10,000 limit"),
            ev("e-proof", "FORMAL_PROOF", "prover", supports=["c-limit"],
               state={"tool_manifest": "tool_v2"}),
            ev("e-fail", "TEST_RESULT", "ci", contradicts=["c-limit"],
               state={"tool_manifest": "tool_v3"})])
        c = only(outcome)
        assert c.classification is C.STALE and not c.is_contradiction
        assert "other than the candidate" in c.classification_basis
        assert "RG-CONTRA-005" not in rules(outcome)
        assert "RG-CONTRA-006" in rules(outcome)
        # Refuted on the release being admitted: the proof is about another one.
        assert outcome.case.verdict.decision.value == "BLOCK"

    def test_d_an_approval_of_another_build_cannot_satisfy_this_one(self, tmp_path):
        """D: approved build abc123, the candidate is def456."""
        outcome = run(tmp_path, [
            {"record_type": "candidate", "components": {"commit": "def4567890"}},
            claim("c-approved", "the payments owner approved this release"),
            ev("e-approval", "HUMAN_REVIEW", "payments-owner", supports=["c-approved"],
               state={"commit": "abc1234567"})])
        resolution = outcome.analysis.resolution.of("c-approved")
        assert [i.role.value for i in resolution.items] == ["WITHHELD_STATE"]
        assert resolution.status is not ResolutionStatus.SUPPORTED
        [edge] = conflict_graph(outcome.contradictions,
                                outcome.analysis.state_binding).of("STATE_MISMATCH")
        assert edge.classification is C.STALE
        assert "abc1234567" in edge.detail and "def4567890" in edge.detail
        assert outcome.case.verdict.decision.value != "PROMOTE"


# ── six classes, from what the sides declare ─────────────────────────────────

class TestSixClasses:

    @pytest.mark.parametrize("left, right, expected, rule", [
        ({"covers": {"tool": "email"}}, {"covers": {"tool": "email"}},
         C.GENUINE, "RG-CONTRA-005"),
        ({"state": {"commit": "aaaa1111"}}, {"state": {"commit": "bbbb2222"}},
         C.STALE, "RG-CONTRA-006"),
        ({"covers": {"tool": "refund"}}, {"covers": {"tool": "email"}},
         C.SCOPE_MISMATCH, "RG-CONTRA-006"),
        ({"covers": {"dataset": "eval-a"}}, {"covers": {"dataset": "redteam-b"}},
         C.POPULATION_MISMATCH, "RG-CONTRA-006"),
        ({"state": {"environment": "production"}}, {"state": {"environment": "staging"}},
         C.ENVIRONMENT_MISMATCH, "RG-CONTRA-006"),
        ({"covers": {"environment": "production"}}, {"covers": {"environment": "staging"}},
         C.ENVIRONMENT_MISMATCH, "RG-CONTRA-006"),
        ({"covers": {"static_path": "app/refund.py"}}, {"covers": {"tool": "refund"}},
         C.AMBIGUOUS, "RG-CONTRA-007"),
    ])
    def test_each_class(self, tmp_path, left, right, expected, rule):
        outcome = run(tmp_path, pair(left, right))
        c = only(outcome)
        assert c.classification is expected
        assert c.is_contradiction is (expected is C.GENUINE)
        assert rule in rules(outcome)
        others = {"RG-CONTRA-005", "RG-CONTRA-006", "RG-CONTRA-007"} - {rule}
        assert not others & rules(outcome)
        assert finding(outcome, rule).effect.value == "HOLD"
        assert outcome.case.verdict.decision.value != "PROMOTE"

    @pytest.mark.parametrize("left, right", [
        ({"covers": {"tool": "refund"}}, {"covers": {"tool": "email"}}),
        ({"covers": {"dataset": "a"}}, {"covers": {"dataset": "b"}}),
        ({"state": {"environment": "production"}}, {"state": {"environment": "staging"}}),
        ({"state": {"commit": "aaaa1111"}}, {"state": {"commit": "bbbb2222"}}),
    ])
    def test_an_incomparable_disagreement_is_not_called_a_contradiction(
            self, tmp_path, left, right):
        outcome = run(tmp_path, pair(left, right))
        c = only(outcome)
        assert c.described.startswith("not a contradiction")
        text = render_text(outcome, full=True)
        assert "not a contradiction" in text
        assert "RG-CONTRA-005" not in rules(outcome)
        summary = finding(outcome, "RG-CONTRA-006").summary
        assert "not contradictions" in summary

    def test_the_claim_still_reads_the_failing_side(self, tmp_path):
        """Calling it a mismatch changes what a reviewer is told, not what the
        failure does: the claim is still contradicted, and the case still holds."""
        outcome = run(tmp_path, pair({"covers": {"tool": "refund"}},
                                     {"covers": {"tool": "email"}}))
        resolution = outcome.analysis.resolution.of("c-x")
        assert resolution.status is ResolutionStatus.CONTRADICTED
        assert resolution.rule == "CR-03"


# ── what an unstated condition means ─────────────────────────────────────────

class TestWhatUnstatedMeans:

    def test_two_unqualified_sides_speak_to_the_claim_as_stated(self, tmp_path):
        c = only(run(tmp_path, pair({}, {})))
        assert c.classification is C.GENUINE
        assert "speak to the claim as stated" in c.classification_basis

    def test_an_unqualified_side_speaks_to_all_of_it(self, tmp_path):
        """"All tests pass" names no tool; "email failed" names one. The first
        claims what the second refutes."""
        c = only(run(tmp_path, pair({}, {"covers": {"tool": "email"}})))
        assert c.classification is C.GENUINE
        assert "stated by one side only" in c.classification_basis

    def test_unstated_state_is_the_candidate_as_in_the_binding(self, tmp_path):
        c = only(run(tmp_path, pair({"state": {"commit": "aaaa1111"}}, {})))
        assert c.classification is C.GENUINE

    @pytest.mark.parametrize("matched", ["aaa-tool", "zzz-tool"])
    def test_any_comparable_pairing_makes_it_genuine(self, tmp_path, matched):
        """Whichever pairing is compared first: one side passing on a tool the
        other failed on is a contradiction, however many other tools it names."""
        other = "zzz-tool" if matched == "aaa-tool" else "aaa-tool"
        outcome = run(tmp_path, [
            claim(), ev("e-other", "TEST_RESULT", "ci", supports=["c-x"],
                        covers={"tool": other}),
            ev("e-match-pass", "TEST_RESULT", "ci2", supports=["c-x"],
               covers={"tool": matched}),
            ev("e-match-fail", "TRACE", "otel", contradicts=["c-x"],
               covers={"tool": matched})])
        c = only(outcome)
        assert c.classification is C.GENUINE
        assert matched in c.classification_basis

    def test_overlapping_scope_is_comparable(self, tmp_path):
        c = only(run(tmp_path, pair({"covers": {"tool": ["refund", "email"]}},
                                    {"covers": {"tool": ["email", "transfer"]}})))
        assert c.classification is C.GENUINE
        assert "email" in c.classification_basis

    def test_state_is_compared_before_scope(self, tmp_path):
        c = only(run(tmp_path, pair(
            {"state": {"commit": "aaaa1111"}, "covers": {"tool": "refund"}},
            {"state": {"commit": "bbbb2222"}, "covers": {"tool": "email"}})))
        assert c.classification is C.STALE
        families = {r.family for r in c.comparability if r.comparison.value == "DIFFERENT"}
        assert families == {"STATE", "SCOPE"}

    def test_values_are_compared_without_case_but_paths_with_it(self):
        def holder(eid, **content):
            return SimpleNamespace(evidence_id=eid, content=content)
        same, _, _ = classify_sides([holder("a", covers={"environment": "Production"})],
                                    [holder("b", covers={"environment": "production"})])
        assert same is C.GENUINE
        paths, _, _ = classify_sides([holder("a", covers={"static_path": "App/x.py"})],
                                     [holder("b", covers={"static_path": "app/x.py"})])
        assert paths is C.SCOPE_MISMATCH


# ── checks that disagree ─────────────────────────────────────────────────────

class TestChecksThatDisagree:

    def test_attempts_are_classified_from_what_they_cover(self, tmp_path):
        outcome = run(tmp_path, [claim(verification_attempts=[
            {"method": "TEST_SUITE", "outcome": "PASSED", "verifier": "ci",
             "covers": {"tool": "refund"}},
            {"method": "RUNTIME_ASSERTION", "outcome": "FAILED", "verifier": "monitor",
             "covers": {"tool": "email"}}])])
        [c] = [c for c in outcome.contradictions
               if c.kind is ContradictionKind.VERIFICATION_CONFLICT]
        assert c.classification is C.SCOPE_MISMATCH
        assert c.cross_source
        assert {k for s in c.sides for k in s.kinds} == {"TEST_SUITE", "RUNTIME_ASSERTION"}


# ── what the policy can do with it ───────────────────────────────────────────

class TestAdmission:

    def test_a_genuine_contradiction_can_be_made_to_block(self, tmp_path):
        rows = pair({"covers": {"tool": "email"}}, {"covers": {"tool": "email"}})
        held = run(tmp_path, rows)
        strict = run(tmp_path, rows, resolution_policy=ResolutionPolicy(
            policy_id="strict", critical_contradiction="BLOCK"))
        assert finding(held, "RG-CONTRA-005").effect.value == "HOLD"
        assert held.case.verdict.decision.value == "HOLD"
        assert finding(strict, "RG-CONTRA-005").effect.value == "BLOCK"
        assert strict.case.verdict.decision.value == "BLOCK"

    @pytest.mark.parametrize("left, right", [
        ({"covers": {"tool": "refund"}}, {"covers": {"tool": "email"}}),
        ({"covers": {"static_path": "a.py"}}, {"covers": {"tool": "refund"}}),
    ])
    def test_the_blocking_policy_is_about_contradictions_only(self, tmp_path, left, right):
        """A mismatch or an ambiguity holds under any policy: it is open, and a
        person sees it as what it is rather than as a contradiction."""
        outcome = run(tmp_path, pair(left, right), resolution_policy=ResolutionPolicy(
            policy_id="strict", critical_contradiction="BLOCK"))
        assert outcome.case.verdict.decision.value == "HOLD"

    @pytest.mark.parametrize("left, right", [
        ({}, {}), ({"covers": {"tool": "refund"}}, {"covers": {"tool": "email"}}),
        ({"covers": {"dataset": "a"}}, {"covers": {"dataset": "b"}}),
        ({"covers": {"static_path": "a.py"}}, {"covers": {"tool": "refund"}}),
        ({"state": {"environment": "prod"}}, {"state": {"environment": "dev"}}),
    ])
    def test_every_unresolved_critical_disagreement_is_named_in_the_verdict(
            self, tmp_path, left, right):
        outcome = run(tmp_path, pair(left, right))
        c = only(outcome)
        assert c.affects_critical and c.is_open
        assert c.contradiction_id in outcome.case.verdict.fired_rules
        assert any(c.described in r for r in outcome.case.verdict.reasons)

    def test_no_policy_can_make_a_disagreement_advisory(self):
        for value in ("ADVISORY", "NONE", "PROMOTE"):
            with pytest.raises(ResolutionError):
                ResolutionPolicy.from_dict({"critical_contradiction": value})
        policy = ResolutionPolicy.from_dict({"critical_contradiction": "BLOCK"})
        assert policy.critical_contradiction is AdmissionEffect.BLOCK
        assert ResolutionPolicy.from_dict(policy.to_dict()) == policy


# ── first-class, persisted, and a graph ──────────────────────────────────────

class TestFirstClass:

    def test_stored_on_the_case_with_its_class(self, tmp_path):
        outcome = run(tmp_path, pair({"covers": {"tool": "refund"}},
                                     {"covers": {"tool": "email"}}))
        [stored] = [r.to_dict() for r in outcome.case.records("contradictions")]
        assert stored["classification"] == "SCOPE_MISMATCH"
        assert stored["is_contradiction"] is False
        assert stored["comparability"][0]["dimension"] == "tool"
        again = Contradiction.from_dict(stored)
        assert again.classification is C.SCOPE_MISMATCH
        assert again.contradiction_id == stored["contradiction_id"]
        assert again.comparability == only(outcome).comparability

    def test_the_class_is_derived_and_outside_the_identity(self):
        base = Contradiction(target_claims=("c",), sides=(
            ContradictionSide(label="supports", evidence=("e1",)),
            ContradictionSide(label="contradicts", evidence=("e2",))))
        moved = dataclasses.replace(base, classification=C.STALE)
        assert moved.contradiction_id == base.contradiction_id

    def test_the_ledger_counts_by_class(self, tmp_path):
        outcome = run(tmp_path, pair({"covers": {"dataset": "a"}},
                                     {"covers": {"dataset": "b"}}))
        summary = outcome.contradictions.summary()
        assert summary["by_classification"]["POPULATION_MISMATCH"] == 1
        assert summary["by_classification"]["GENUINE"] == 0

    def test_one_graph_holds_disagreements_and_state_mismatches(self, tmp_path):
        outcome = run(tmp_path, [
            {"record_type": "candidate", "components": {"commit": "def4567890"}},
            claim("c-ok"),
            ev("e-approval", "HUMAN_REVIEW", "owner", supports=["c-ok"],
               state={"commit": "abc1234567"}),
            ev("e-objection", "HUMAN_REVIEW", "auditor", contradicts=["c-ok"],
               state={"commit": "def4567890"})])
        graph = outcome.to_dict()["conflict_graph"]
        relations = sorted(e["relation"] for e in graph["edges"])
        assert relations == ["DISAGREES", "STATE_MISMATCH"]
        assert all(e["classification"] == "STALE" for e in graph["edges"])
        assert "c-ok" in graph["nodes"] and "candidate" in graph["nodes"]
        again = run(tmp_path, json.loads((tmp_path / "case.json").read_text()))
        assert again.to_dict()["conflict_graph"]["digest"] == graph["digest"]
