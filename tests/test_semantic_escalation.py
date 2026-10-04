"""Semantic escalation — which questions go to a model, decided before any is asked.

Pinned here, against release_gate/assurance/escalation.py and the case it reads:

* every rule declares an adjudication mode, and a policy can withdraw a rule from
  reading but never open a DETERMINISTIC one to it;
* a deterministic HIGH finding cannot be erased by semantic disagreement — not by
  a model that says the claim it contradicts is supported, not by five of them
  under a policy that counts readings, not by a replayed file, not by
  `--verify` refuting the finding, and not by a HYBRID reading that says a
  supplied mechanism controls the path;
* a model existing is never a reason: the subjects asked with a model are exactly
  those that would be asked without one;
* EXTERNAL_ONLY results are not re-graded; DETERMINISTIC findings are not asked;
* completeness, criticality, policy, prior readings, availability and budget are
  each weighed, deterministically, and the plan says which settled each subject;
* the same inputs give the same plan.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys

import pytest

from release_gate.assurance.escalation import (
    DEFAULT_ESCALATION_POLICY, ESCALATION_SCHEMA_VERSION, QUESTION_MODES,
    SCANNER_RULE_MODES, AdjudicationMode, EscalationError, EscalationPolicy,
    EscalationReason, EscalationScope, adjudication_mode, is_external_result,
    plan_escalation)
from release_gate.assurance.resolution import (ResolutionPolicy, ResolutionStatus,
                                               SemanticChallenge, SemanticSupport)
from release_gate.assurance.rules_registry import family_of
from release_gate.assurance.semantic_verifier import (
    AssertionStatus, ProviderCapabilities, ProviderIdentity,
    ProviderInterface, ProviderReply, QuestionKind, SemanticAssertion, SemanticVerdict,
    SemanticVerifier, SemanticVerifierPolicy, UnknownReason, OutputKind,
    default_capabilities, state_hash_for)
from release_gate.assurance.static_producer import RULE_PROFILES, emit_from_report
from release_gate.assurance.zero_config import assure

S = ResolutionStatus
R = EscalationReason
CHAT = default_capabilities(ProviderInterface.CHAT, local=True)


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def finding(rule, line, severity="high", file="app/agent.py"):
    return {"rule_id": rule, "severity": severity, "basis": "confirmed",
            "title": f"{rule} finding", "file": file, "line": line}


def report(*findings, safeguards=None):
    return {"score": 40, "decision": "BLOCK", "code_findings": list(findings),
            "safeguards": safeguards or {}, "code_safety": {"applicable": True, "score": 40}}


EXEC_REPORT = report(finding("RG-EXEC-001", 42))
GATE_REPORT = report(finding("RG-GATE-001", 77, file="app/tools.py"))


def static_rows(doc):
    return emit_from_report(doc, source="release-gate-static:test").records()


def mechanism(addresses=("RG-GATE-001",), claim="c-approval", eid="e-orch"):
    return [
        {"record_type": "claim", "claim_id": claim, "is_root": True,
         "proposition": "Every refund the agent issues is approved by a human in the "
                        "orchestrator before it executes",
         "producer": P("platform", "human")},
        {"record_type": "evidence", "evidence_id": eid, "kind": "OTHER",
         "producer": P("platform", "human"), "supports_claims": [claim],
         "addresses": list(addresses),
         "summary": "orchestrator policy refund.requires_approval=true; the call is "
                    "queued until a reviewer approves it",
         "coverage_note": "orchestrator configuration"},
    ]


def open_claims():
    """Two declared claims the rules leave open; one required, one not."""
    return [
        {"record_type": "claim", "claim_id": "c-transfer", "is_root": True,
         "proposition": "All transfers above 10,000 require human approval",
         "producer": P("platform", "human")},
        {"record_type": "evidence", "evidence_id": "e-trace", "kind": "TRACE",
         "producer": P("otel"), "supports_claims": ["c-transfer"],
         "summary": "412 transfers above 10,000; each preceded by approve_transfer",
         "coverage_note": "30 days"},
        {"record_type": "claim", "claim_id": "c-other", "proposition": "a side note",
         "producer": P("platform", "human")},
        {"record_type": "evidence", "evidence_id": "e-side", "kind": "OTHER",
         "producer": P("hr"), "supports_claims": ["c-other"], "summary": "x",
         "coverage_note": "x"},
    ]


def write(tmp_path, data, name="case.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def evidence_of(outcome):
    return [r for r in outcome.case.records("evidence") if hasattr(r, "evidence_id")]


def plan_of(outcome, **kw):
    kw.setdefault("capabilities", CHAT)
    return plan_escalation(outcome.analysis.resolution, evidence_of(outcome),
                           state_hash=state_hash_for(outcome.analysis), **kw)


def by_subject(plan):
    return {d.subject: d for d in plan.decisions}


def static_findings(outcome):
    return {r.evidence_id: r for r in evidence_of(outcome)
            if r.evidence_type.value == "STATIC_FINDING" and r.contradicts_claims}


def claim(outcome, cid):
    return outcome.analysis.resolution.of(cid)


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def reading(cid, verdict=SemanticVerdict.SUPPORTED, refs=(), i=0, **kw):
    return SemanticAssertion(
        question_id=f"sq_forged_{i}", claim_id=cid, status=AssertionStatus.ANSWERED,
        verdict=verdict, confidence=0.99, evidence_refs=tuple(refs),
        model=f"model-{i}", model_family=f"family-{i}", provider=f"provider-{i}", **kw)


#: An external evaluator's run: three cases, two passing.
PROMPTFOO = {"evalId": "eval-2026-10-01", "results": {
    "version": 3, "timestamp": "2026-10-01T10:00:00Z",
    "stats": {"successes": 2, "failures": 1, "errors": 0},
    "results": [{"success": i < 2, "score": 1 if i < 2 else 0,
                 "testCase": {"description": f"case {i}"},
                 "provider": {"id": "local:model"},
                 "prompt": {"raw": "You are a support agent.", "label": "support"},
                 "latencyMs": 800 + i, "cost": 0.0004} for i in range(3)]}}

#: Another scanner's finding, as SARIF.
SARIF = {"version": "2.1.0", "runs": [{
    "tool": {"driver": {"name": "SonarQube", "version": "10.6"}},
    "results": [{"ruleId": "python:S5332", "level": "error", "kind": "fail",
                 "message": {"text": "Using http protocol is insecure."},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/client.py"},
                     "region": {"startLine": 12}}}]}]}]}


COUNTS = ResolutionPolicy(policy_id="counts-readings",
                          semantic_support=SemanticSupport.COUNTS,
                          semantic_contradiction=SemanticChallenge.BLOCK)


# ── modes ────────────────────────────────────────────────────────────────────

class TestEveryRuleHasAMode:

    def test_every_scanner_rule_states_one(self):
        """A rule added to the catalogue without a mode fails here."""
        assert set(SCANNER_RULE_MODES) == set(RULE_PROFILES)

    def test_one_hybrid_rule_and_it_is_the_approval_gate(self):
        hybrid = {r for r, m in SCANNER_RULE_MODES.items() if m is AdjudicationMode.HYBRID}
        assert hybrid == {"RG-GATE-001"}
        assert adjudication_mode("RG-EXEC-001") is AdjudicationMode.DETERMINISTIC

    @pytest.mark.parametrize("rule", ["RG-CLAIM-001", "RG-CONTRA-002", "RG-SEM-001",
                                      "RG-ZC-001", "RG-EXEC-099", "RG-NOPE-001", ""])
    def test_structural_and_unknown_rules_are_deterministic(self, rule):
        assert adjudication_mode(rule) is AdjudicationMode.DETERMINISTIC

    def test_every_question_kind_has_a_mode(self):
        assert set(QUESTION_MODES) == set(QuestionKind)
        assert QUESTION_MODES[QuestionKind.MECHANISM_CONTROLS_PATH] is AdjudicationMode.HYBRID

    def test_the_semantic_rules_have_a_family(self):
        for rule in ("RG-SEM-001", "RG-SEM-002", "RG-SEM-003", "RG-SEM-004"):
            assert family_of(rule).prefix == "RG-SEM"


class TestThePolicy:

    def test_a_rule_can_be_withdrawn_from_reading(self, tmp_path):
        outcome = assure(write(tmp_path, static_rows(GATE_REPORT) + mechanism()))
        withdrawn = EscalationPolicy(modes={"RG-GATE-001": "DETERMINISTIC"})
        plan = plan_of(outcome, policy=withdrawn)
        assert [d.reason for d in plan.decisions if d.rule_id == "RG-GATE-001"] == [
            R.DETERMINISTIC_RULE]

    @pytest.mark.parametrize("rule, mode", [("RG-EXEC-001", "HYBRID"),
                                            ("RG-EXEC-001", "SEMANTIC"),
                                            ("RG-GATE-001", "SEMANTIC"),
                                            ("RG-CLAIM-001", "HYBRID")])
    def test_a_deterministic_rule_cannot_be_opened_to_a_model(self, rule, mode):
        with pytest.raises(EscalationError, match="cannot make it"):
            EscalationPolicy(modes={rule: mode})

    @pytest.mark.parametrize("bad", [
        {"surprise": 1}, {"scope": "SOME"}, {"max_questions": -1},
        {"max_questions": True}, {"max_cost": -0.5}, {"max_cost": float("nan")},
        {"always": ["a"], "never": ["a"]}, {"always": "a"}, {"modes": ["RG-GATE-001"]},
        {"hybrid": "no"}, "not an object"])
    def test_an_unusable_policy_is_refused(self, bad):
        with pytest.raises(EscalationError):
            EscalationPolicy.from_dict(bad)

    def test_round_trip_and_a_stable_digest(self):
        policy = EscalationPolicy(policy_id="p", scope="ALL", always=("b", "a"),
                                  max_questions=3, max_cost=1.5,
                                  modes={"RG-GATE-001": "DETERMINISTIC"})
        again = EscalationPolicy.from_dict(json.loads(json.dumps(policy.to_dict())))
        assert again == policy and again.digest() == policy.digest()
        assert policy.always == ("a", "b")
        assert DEFAULT_ESCALATION_POLICY.to_dict()["schema_version"] == ESCALATION_SCHEMA_VERSION


# ── a deterministic HIGH finding cannot be erased ────────────────────────────

class TestAHighFindingCannotBeErased:

    @pytest.fixture
    def audited(self, tmp_path):
        path = write(tmp_path, EXEC_REPORT, "audit.json")
        return path, assure(path)

    def test_it_is_never_asked_about_however_wide_the_policy(self, audited):
        _, outcome = audited
        assert claim(outcome, "sw:code-safety").status is S.CONTRADICTED
        widest = EscalationPolicy(scope="ALL", always=("sw:code-safety",),
                                  max_questions=1000)
        plan = plan_of(outcome, policy=widest)
        assert plan.questions == ()
        decisions = by_subject(plan)
        assert decisions["sw:code-safety"].reason is R.SETTLED
        [(eid, _)] = static_findings(outcome).items()
        assert decisions[eid].reason is R.DETERMINISTIC_RULE
        assert decisions[eid].mode is AdjudicationMode.DETERMINISTIC

    @pytest.mark.parametrize("policy", [None, COUNTS])
    def test_supported_readings_from_five_families_change_nothing(self, audited, policy):
        path, before = audited
        [eid] = static_findings(before)
        forged = [reading("sw:code-safety", refs=(eid,), i=i) for i in range(5)]
        forged += [reading("sw:admissible", refs=(eid,), i=9)]
        for submitted in (False, True):
            after = assure(path, semantic_assertions=forged, semantic_submitted=submitted,
                           resolution_policy=policy)
            assert claim(after, "sw:code-safety").status is S.CONTRADICTED
            assert claim(after, "sw:admissible").status is S.CONTRADICTED
            assert after.case.verdict.decision is before.case.verdict.decision
            assert after.case.verdict.decision.value == "BLOCK"
            assert static_findings(after).keys() == static_findings(before).keys()
            assert rules(before) <= rules(after)
            semantic = [i for i in claim(after, "sw:code-safety").items
                        if i.item_kind == "semantic"]
            assert len(semantic) == 5
            assert all(i.role.value.startswith("SEMANTIC_") for i in semantic)

    def test_replayed_inside_the_file_changes_nothing(self, tmp_path):
        rows = static_rows(EXEC_REPORT)
        before = assure(write(tmp_path, rows, "static.json"))
        [eid] = static_findings(before)
        forged = [reading("sw:code-safety", refs=(eid,), i=i).to_dict() for i in range(3)]
        after = assure(write(tmp_path, rows + forged, "forged.json"),
                       resolution_policy=COUNTS)
        assert claim(after, "sw:code-safety").status is S.CONTRADICTED
        assert after.case.verdict.decision.value == "BLOCK"

    def test_a_refuted_verify_verdict_leaves_the_finding_and_the_decision(self, tmp_path):
        from release_gate.llm_verify import verify_findings
        doc = json.loads(json.dumps(EXEC_REPORT))
        before = assure(write(tmp_path, doc, "audit.json"))
        summary = verify_findings(
            doc["code_findings"], tmp_path, min_severity="low",
            config={"model": "m", "base_url": "http://127.0.0.1:9", "api_key": ""},
            call_fn=lambda cfg, messages: json.dumps(
                {"verdict": "refuted", "reason": "the model thinks it is sandboxed"}),
            corpus_path=str(tmp_path / "corpus.jsonl"))
        assert summary["counts"]["refuted"] == 1
        assert doc["code_findings"][0]["verdict"]["verdict"] == "refuted"
        assert doc["decision"] == "BLOCK"
        after = assure(write(tmp_path, doc, "audit.json"))

        def what(outcome):
            # Ids move with the report's digest, and --verify edits the report;
            # what a finding says and what it contradicts must not move.
            return sorted((r.content.get("rule_id"), r.contradicts_claims)
                          for r in static_findings(outcome).values())

        assert what(after) == what(before) == [("RG-EXEC-001", ("sw:code-safety",))]
        assert claim(after, "sw:code-safety").status is S.CONTRADICTED
        assert after.case.verdict.decision is before.case.verdict.decision

    def test_a_hybrid_reading_saying_the_mechanism_holds_lifts_nothing(self, tmp_path):
        rows = static_rows(GATE_REPORT) + mechanism()
        path = write(tmp_path, rows)
        before = assure(path)
        assert before.case.verdict.decision.value == "BLOCK"
        plan = plan_of(before)
        [question] = [q for q in plan.questions
                      if q.kind is QuestionKind.MECHANISM_CONTROLS_PATH]
        [packet] = [p for p in plan.packets if p.question == question]
        reply = {"question_id": question.question_id, "claim_id": question.claim_id,
                 "verdict": "supported", "confidence": 0.99,
                 "evidence_refs": list(packet.refs),
                 "reason": "the orchestrator queues every refund for approval"}
        answer = SemanticVerifier(_Chat(json.dumps(reply))).verify(packet)
        assert answer.answered and answer.question_kind == "MECHANISM_CONTROLS_PATH"
        assert answer.claim_id == "c-approval"
        for policy in (None, COUNTS):
            after = assure(path, semantic_assertions=[answer], resolution_policy=policy)
            assert claim(after, "sw:code-safety").status is S.CONTRADICTED
            assert after.case.verdict.decision.value == "BLOCK"
            assert static_findings(after).keys() == static_findings(before).keys()
            assert claim(after, "c-approval").status is not S.ESTABLISHED

    def test_a_mechanism_addressing_a_deterministic_rule_is_not_asked(self, tmp_path):
        outcome = assure(write(tmp_path, static_rows(EXEC_REPORT)
                               + mechanism(addresses=("RG-EXEC-001",))))
        plan = plan_of(outcome)
        assert not [q for q in plan.questions
                    if q.kind is QuestionKind.MECHANISM_CONTROLS_PATH]
        [eid] = static_findings(outcome)
        assert by_subject(plan)[eid].reason is R.DETERMINISTIC_RULE


class TestAReadingIsNotMoreEvidence:
    """A reading is about records already in the case. Counted as evidence, five
    readings were five more producers, and RG-PROV-002 — all evidence traces to a
    single producer, a HOLD — vanished because a model was asked about it."""

    EXAMPLES = ("examples/agents/01-coding-agent-otel.json",
                "examples/agents/02-release-promoted.jsonl",
                "examples/agents/03-support-eval-promptfoo.json",
                "examples/agents/04-production-db-change.jsonl",
                "examples/agents/05-research-swarm.jsonl",
                "examples/assurance/agent-trace.json",
                "examples/assurance/research-claim.jsonl",
                "examples/assurance/single-action.jsonl")

    @staticmethod
    def _readings(outcome):
        found = []
        for res in outcome.analysis.resolution.resolutions:
            refs = tuple(i.item_id for i in res.items)[:3]
            found += [reading(res.claim_id, refs=refs, i=i) for i in range(4)]
        return found

    @pytest.mark.parametrize("example", EXAMPLES)
    def test_readings_never_remove_a_finding_or_soften_a_decision(self, example):
        order = {"PROMOTE": 0, "HOLD": 1, "BLOCK": 2}
        before = assure(example)
        readings = self._readings(before)
        for policy in (None, COUNTS):
            for submitted in (False, True):
                after = assure(example, semantic_assertions=readings,
                               semantic_submitted=submitted, resolution_policy=policy)
                assert rules(before) <= rules(after), (policy, submitted)
                assert (order[after.case.verdict.decision.value]
                        >= order[before.case.verdict.decision.value])

    def test_a_single_producer_stays_a_single_producer(self, tmp_path):
        path = write(tmp_path, EXEC_REPORT, "audit.json")
        before = assure(path)
        assert "RG-PROV-002" in rules(before)
        after = assure(path, semantic_assertions=self._readings(before))
        assert "RG-PROV-002" in rules(after)
        assert {f.observed.get("producers") for f in after.analysis.findings
                if f.rule_id == "RG-PROV-002"} == {1}


class TestWhatAReaderIsSent:

    def test_no_reading_anchors_the_next(self, tmp_path):
        """Why the rules left a claim open is the reviewer's. Once a reading is
        on record that reason names it, and sending it would tell the next model
        what the last one answered."""
        outcome = assure(write(tmp_path, open_claims()))
        [packet] = plan_of(outcome).packets
        prior = SemanticAssertion(
            question_id=packet.question.question_id, claim_id="c-transfer",
            packet_hash=packet.packet_hash, status=AssertionStatus.ANSWERED,
            verdict=SemanticVerdict.CONTRADICTED, confidence=0.9,
            evidence_refs=packet.refs, model="m")
        again = assure(write(tmp_path, open_claims() + [prior.to_dict()]))
        plan = plan_of(again, policy=EscalationPolicy(scope="ALL"))
        decision = by_subject(plan)["c-transfer"]
        assert "semantic verifier" in decision.question.unresolved_because
        rebuilt = SemanticVerifier(None).request_for(
            dataclasses.replace(packet, question=decision.question))
        assert "unresolved_because" not in rebuilt.user
        assert "semantic verifier" not in rebuilt.user
        assert "contradict" not in json.loads(rebuilt.user)["question"]["statement"]
        assert packet.to_dict()["unresolved_because"]       # kept for the reviewer

    def test_a_record_is_sent_as_what_it_says(self, tmp_path):
        outcome = assure(write(tmp_path, static_rows(GATE_REPORT) + mechanism()))
        [packet] = [p for p in plan_of(outcome).packets
                    if p.question.kind is QuestionKind.MECHANISM_CONTROLS_PATH]
        finding_excerpt = packet.items[0].excerpt
        assert finding_excerpt.startswith('{"rule_id":"RG-GATE-001","title":')
        for machinery in ("sha256:", "producer_claimed_", "stamped_on_arrival",
                          "independence_group", "schema_version"):
            assert machinery not in finding_excerpt
        # What identifies the finding leads, so a bound cuts detail, not identity.
        for lead in ('"severity":"high"', "did not identify a code-level approval gate",
                     '"file":"app/tools.py","line":77'):
            assert lead in finding_excerpt


class _Chat:
    """A chat provider with one scripted reply."""

    def __init__(self, text):
        self.text, self.requests = text, []

    def identity(self):
        return ProviderIdentity(provider="scripted", model="m", model_family="f",
                                local=True)

    def complete(self, request):
        self.requests.append(request)
        return ProviderReply(text=self.text, model_version="m-1")


# ── a model existing is never a reason ───────────────────────────────────────

class TestAModelIsNeverTheReason:

    @pytest.mark.parametrize("build", [
        lambda: EXEC_REPORT, lambda: static_rows(GATE_REPORT) + mechanism(),
        lambda: open_claims(), lambda: static_rows(EXEC_REPORT) + open_claims()])
    def test_the_same_subjects_with_or_without_a_model(self, tmp_path, build):
        outcome = assure(write(tmp_path, build()))
        policy = EscalationPolicy(scope="ALL", max_questions=1000)
        with_model = plan_of(outcome, policy=policy)
        without = plan_of(outcome, policy=policy, capabilities=None)
        asked = {d.subject for d in with_model.decisions if d.escalated}
        would = {d.subject for d in without.decisions if d.reason is R.NO_MODEL}
        assert asked == would
        assert not any(d.escalated for d in without.decisions)
        assert without.packets == ()

    def test_settled_checked_and_empty_claims_ask_nothing(self, tmp_path):
        rows = [
            {"record_type": "claim", "claim_id": "c-empty", "is_root": True,
             "proposition": "nobody looked", "producer": P("a")},
            {"record_type": "claim", "claim_id": "c-refuted", "proposition": "refuted",
             "producer": P("a")},
            {"record_type": "evidence", "evidence_id": "e-no", "kind": "TEST_RESULT",
             "producer": P("ci"), "contradicts_claims": ["c-refuted"], "summary": "fail"},
        ]
        outcome = assure(write(tmp_path, rows))
        plan = plan_of(outcome, policy=EscalationPolicy(scope="ALL"))
        assert plan.questions == ()
        reasons = {d.subject: d.reason for d in plan.decisions}
        assert reasons["c-empty"] is R.NOTHING_TO_READ
        assert reasons["c-refuted"] is R.SETTLED


# ── external results are not re-graded ───────────────────────────────────────

class TestExternalOnly:

    def test_a_claim_carried_by_an_external_eval_is_not_sent(self, tmp_path):
        outcome = assure(write(tmp_path, PROMPTFOO, "promptfoo.json"))
        assert any(is_external_result(r) for r in evidence_of(outcome))
        plan = plan_of(outcome, policy=EscalationPolicy(scope="ALL"))
        assert plan.questions == ()
        reasons = {d.reason for d in plan.decisions}
        assert R.EXTERNAL_ONLY in reasons
        assert reasons <= {R.EXTERNAL_ONLY, R.SETTLED}

        sarif = assure(write(tmp_path, SARIF, "sarif.json"))
        [decision] = plan_of(sarif).decisions
        assert decision.subject_kind == "finding" and decision.rule_id == "python:S5332"
        assert decision.mode is AdjudicationMode.EXTERNAL_ONLY
        assert decision.reason is R.EXTERNAL_ONLY


# ── HYBRID ───────────────────────────────────────────────────────────────────

class TestHybrid:

    def test_a_supplied_mechanism_is_one_question_bound_to_its_own_claim(self, tmp_path):
        outcome = assure(write(tmp_path, static_rows(GATE_REPORT) + mechanism()))
        plan = plan_of(outcome)
        [gate] = [d for d in plan.decisions if d.rule_id == "RG-GATE-001"]
        assert gate.reason is R.MECHANISM_SUPPLIED and gate.escalated
        assert gate.mode is AdjudicationMode.HYBRID
        assert gate.claim_id == "c-approval"
        assert gate.question.kind is QuestionKind.MECHANISM_CONTROLS_PATH
        [finding_id] = static_findings(outcome)
        assert gate.question.evidence_refs[0] == finding_id
        [packet] = [p for p in plan.packets if p.question == gate.question]
        assert len(packet.items) == 2
        assert packet.items[0].fields["evidence_type"] == "STATIC_FINDING"
        assert '"rule_id":"RG-GATE-001"' in packet.items[0].excerpt
        assert "requires_approval" in packet.items[1].excerpt
        assert "app/tools.py:77" in gate.detail
        # HYBRID first: it is asked before the plain reading of the same claim.
        assert plan.escalated[0] is gate

    def test_a_decision_model_is_asked_about_the_path(self, tmp_path):
        outcome = assure(write(tmp_path, static_rows(GATE_REPORT) + mechanism()))
        plan = plan_of(outcome)
        [packet] = [p for p in plan.packets
                    if p.question.kind is QuestionKind.MECHANISM_CONTROLS_PATH]
        request = SemanticVerifier(None).decision_request_for(packet)
        assert request.question.startswith("Does the supplied mechanism control the path")
        assert request.state.index("RG-GATE-001") < request.state.index("requires_approval")

    @pytest.mark.parametrize("rows, reason", [
        (lambda: static_rows(GATE_REPORT), R.NO_MECHANISM),
        (lambda: static_rows(GATE_REPORT) + [
            {"record_type": "evidence", "evidence_id": "e-loose", "kind": "OTHER",
             "producer": P("platform"), "addresses": ["RG-GATE-001"], "summary": "x"}],
         R.MECHANISM_UNBOUND),
    ])
    def test_without_something_to_weigh_nothing_is_asked(self, tmp_path, rows, reason):
        outcome = assure(write(tmp_path, rows()))
        [gate] = [d for d in plan_of(outcome).decisions if d.rule_id == "RG-GATE-001"]
        assert gate.reason is reason and not gate.escalated

    def test_a_policy_can_turn_hybrid_questions_off(self, tmp_path):
        outcome = assure(write(tmp_path, static_rows(GATE_REPORT) + mechanism()))
        plan = plan_of(outcome, policy=EscalationPolicy(hybrid=False))
        [gate] = [d for d in plan.decisions if d.rule_id == "RG-GATE-001"]
        assert gate.reason is R.HYBRID_DISABLED


# ── completeness, criticality, policy, prior readings ────────────────────────

class TestWhatIsWeighed:

    def test_criticality_decides_scope(self, tmp_path):
        outcome = assure(write(tmp_path, open_claims()))
        plan = plan_of(outcome)
        decisions = by_subject(plan)
        assert decisions["c-transfer"].reason is R.OPEN_CLAIM
        assert decisions["c-other"].reason is R.OUT_OF_SCOPE
        wide = by_subject(plan_of(outcome, policy=EscalationPolicy(scope="ALL")))
        assert wide["c-other"].reason is R.OPEN_CLAIM
        named = by_subject(plan_of(outcome, policy=EscalationPolicy(always=("c-other",))))
        assert named["c-other"].reason is R.OPEN_CLAIM
        excluded = by_subject(plan_of(outcome, policy=EscalationPolicy(never=("c-transfer",))))
        assert excluded["c-transfer"].reason is R.EXCLUDED_BY_POLICY

    def test_undetermined_criticality_is_never_read_as_unimportant(self, tmp_path):
        outcome = assure(write(tmp_path, open_claims()))
        report = outcome.analysis.resolution
        unknown = dataclasses.replace(report, resolutions=tuple(
            dataclasses.replace(r, required=None) for r in report.resolutions))
        default = plan_escalation(unknown, evidence_of(outcome), capabilities=CHAT)
        assert {d.subject for d in default.decisions if d.escalated} == {
            "c-transfer", "c-other"}
        strict = plan_escalation(unknown, evidence_of(outcome), capabilities=CHAT,
                                 policy=EscalationPolicy(scope=EscalationScope.REQUIRED))
        assert not any(d.escalated for d in strict.decisions)

    def test_policy_named_claims_go_first(self, tmp_path):
        outcome = assure(write(tmp_path, open_claims()))
        plan = plan_of(outcome, policy=EscalationPolicy(scope="ALL", always=("c-other",)))
        assert [d.subject for d in plan.escalated] == ["c-other", "c-transfer"]

    def _with_prior(self, tmp_path, unknown_reason=None):
        outcome = assure(write(tmp_path, open_claims()))
        plan = plan_of(outcome)
        [packet] = plan.packets
        q = packet.question
        fields = dict(question_id=q.question_id, claim_id=q.claim_id,
                      packet_hash=packet.packet_hash, model="m")
        prior = (SemanticAssertion(status=AssertionStatus.UNKNOWN,
                                   unknown_reason=unknown_reason, **fields)
                 if unknown_reason else
                 SemanticAssertion(status=AssertionStatus.ANSWERED,
                                   verdict=SemanticVerdict.CONTRADICTED, confidence=0.9,
                                   evidence_refs=packet.refs, **fields))
        # The same file: evidence ids include where a record was read from.
        again = assure(write(tmp_path, open_claims() + [prior.to_dict()]))
        return by_subject(plan_of(again))["c-transfer"]

    def test_an_answer_already_on_record_is_not_shopped_for(self, tmp_path):
        assert self._with_prior(tmp_path).reason is R.ALREADY_READ

    @pytest.mark.parametrize("why, reason", [
        (UnknownReason.LOW_CONFIDENCE, R.ALREADY_READ),
        (UnknownReason.NO_DECISION, R.ALREADY_READ),
        (UnknownReason.MALFORMED_RESPONSE, R.ALREADY_READ),
        (UnknownReason.TIMEOUT, R.OPEN_CLAIM),
        (UnknownReason.PROVIDER_UNAVAILABLE, R.OPEN_CLAIM),
    ])
    def test_a_transport_failure_may_be_asked_again(self, tmp_path, why, reason):
        assert self._with_prior(tmp_path, why).reason is reason

    def test_a_reading_of_other_records_does_not_count_as_prior(self, tmp_path):
        outcome = assure(write(tmp_path, open_claims()))
        [packet] = plan_of(outcome).packets
        stale = SemanticAssertion(
            question_id=packet.question.question_id, claim_id="c-transfer",
            packet_hash="sha256:" + "0" * 64, status=AssertionStatus.ANSWERED,
            verdict=SemanticVerdict.SUPPORTED, confidence=0.9, model="m")
        again = assure(write(tmp_path, open_claims() + [stale.to_dict()]))
        assert by_subject(plan_of(again))["c-transfer"].reason is R.OPEN_CLAIM


# ── availability and budget ──────────────────────────────────────────────────

def _caps(**kw):
    return ProviderCapabilities(interface=kw.pop("interface", ProviderInterface.CHAT),
                                outputs=(OutputKind.CHOICE,), **kw)


class TestAvailabilityAndBudget:

    @pytest.fixture
    def outcome(self, tmp_path):
        rows = open_claims() + [
            {"record_type": "claim", "claim_id": f"c-{i}", "is_root": True,
             "proposition": f"claim {i}", "producer": P("platform", "human")}
            for i in range(3)] + [
            {"record_type": "evidence", "evidence_id": f"e-{i}", "kind": "OTHER",
             "producer": P("agent"), "supports_claims": [f"c-{i}"], "summary": f"s{i}",
             "coverage_note": "x"} for i in range(3)]
        return assure(write(tmp_path, rows))

    def test_no_model_asks_nothing_and_says_what_it_would_have(self, outcome):
        plan = plan_of(outcome, capabilities=None)
        assert plan.packets == () and plan.questions == ()
        assert {d.reason for d in plan.decisions} >= {R.NO_MODEL}

    def test_a_question_budget_cuts_the_same_questions_every_time(self, outcome):
        policy = EscalationPolicy(scope="ALL", max_questions=2)
        one, two = plan_of(outcome, policy=policy), plan_of(outcome, policy=policy)
        assert [d.subject for d in one.escalated] == [d.subject for d in two.escalated]
        assert len(one.escalated) == 2
        assert sum(d.reason is R.QUESTION_BUDGET for d in one.decisions) >= 1
        assert [d.rank for d in one.escalated] == [1, 2]

    def test_a_cost_budget_needs_a_declared_cost(self, outcome):
        policy = EscalationPolicy(scope="ALL", max_cost=1.0)
        unknown = plan_of(outcome, policy=policy, capabilities=_caps())
        assert not unknown.escalated
        assert {d.reason for d in unknown.decisions} >= {R.UNKNOWN_COST}
        priced = plan_of(outcome, policy=policy, capabilities=_caps(cost_per_call=0.4))
        assert len(priced.escalated) == 2
        assert priced.estimated_cost == 0.8
        assert {d.reason for d in priced.decisions} >= {R.COST_BUDGET}

    def test_a_context_the_provider_cannot_take_is_not_sent(self, outcome):
        plan = plan_of(outcome, capabilities=_caps(max_input_chars=200))
        assert not plan.escalated
        assert {d.reason for d in plan.decisions} >= {R.EXCEEDS_CONTEXT}
        decision = plan_of(outcome, capabilities=_caps(interface=ProviderInterface.DECISION,
                                                         max_choices=2))
        assert {d.reason for d in decision.decisions} >= {R.UNSUPPORTED_BY_PROVIDER}

    def test_a_packet_over_the_verifier_policy_is_not_sent(self, outcome):
        small = SemanticVerifierPolicy(max_packet_chars=100)
        plan = plan_of(outcome, verifier_policy=small)
        assert not plan.escalated
        assert {d.reason for d in plan.decisions} >= {R.PACKET_TOO_LARGE}


# ── the plan itself ──────────────────────────────────────────────────────────

class TestThePlan:

    def test_the_same_inputs_give_the_same_plan(self, tmp_path):
        rows = static_rows(GATE_REPORT) + mechanism() + open_claims()
        one = plan_of(assure(write(tmp_path, rows, "a.json"))).to_dict()
        two = plan_of(assure(write(tmp_path, rows, "a.json"))).to_dict()
        assert one == two and one["plan_digest"] == two["plan_digest"]
        assert one["record_type"] == "escalation_plan"
        json.dumps(one, allow_nan=False)

    def test_record_order_does_not_move_the_plan(self, tmp_path):
        rows = static_rows(GATE_REPORT) + mechanism() + open_claims()
        outcome = assure(write(tmp_path, rows))
        forward = plan_escalation(outcome.analysis.resolution, evidence_of(outcome),
                                  capabilities=CHAT)
        backward = plan_escalation(outcome.analysis.resolution,
                                   list(reversed(evidence_of(outcome))), capabilities=CHAT)
        assert forward.to_dict() == backward.to_dict()

    def test_every_claim_and_finding_is_accounted_for(self, tmp_path):
        rows = static_rows(GATE_REPORT) + mechanism() + open_claims()
        outcome = assure(write(tmp_path, rows))
        plan = plan_of(outcome)
        claims = {r.claim_id for r in outcome.analysis.resolution.resolutions}
        assert claims <= {d.claim_id or d.subject for d in plan.decisions}
        findings = set(static_findings(outcome))
        assert findings <= {d.subject.split("->")[0] for d in plan.decisions
                            if d.subject_kind == "finding"}
        assert all(d.detail for d in plan.decisions)


# ── the command line ─────────────────────────────────────────────────────────

class TestTheCommandLine:

    def _cli(self, *args, env=None):
        import os
        environment = {k: v for k, v in os.environ.items()
                       if not k.startswith("RG_SEMANTIC_")}
        environment.update(env or {})
        return subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", *args],
                              capture_output=True, text=True, timeout=300, env=environment)

    def test_a_zero_budget_asks_nothing_and_says_why(self, tmp_path):
        case = write(tmp_path, open_claims())
        policy = tmp_path / "escalation.json"
        policy.write_text(json.dumps({"policy_id": "frugal", "max_questions": 0}))
        out = tmp_path / "semantic.jsonl"
        # Nothing listens on port 9: a question asked would come back UNKNOWN.
        result = self._cli(case, "--semantic", "--escalation-policy", str(policy),
                           "--semantic-out", str(out),
                           env={"RG_SEMANTIC_BASE_URL": "http://127.0.0.1:9/v1",
                                "RG_SEMANTIC_MODEL": "m"})
        assert "0 of" in result.stderr and "question budget" in result.stderr, result.stderr
        [plan] = [json.loads(line) for line in out.read_text().splitlines()]
        assert plan["record_type"] == "escalation_plan" and plan["asked"] == 0
        assert plan["policy"] == "frugal@1"
        assert result.returncode == assure(case).exit_code

    @pytest.mark.parametrize("args, says", [
        (["--escalation-policy", "x.json"], "without --semantic"),
        (["--semantic", "--escalation-policy", "missing.json"], "not a readable"),
    ])
    def test_misuse_is_an_error(self, tmp_path, args, says):
        case = write(tmp_path, open_claims())
        result = self._cli(case, *args, env={"RG_SEMANTIC_BASE_URL": "http://127.0.0.1:9/v1",
                                             "RG_SEMANTIC_MODEL": "m"})
        assert result.returncode == 1 and says in result.stdout
