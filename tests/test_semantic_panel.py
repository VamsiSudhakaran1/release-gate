"""Several semantic verifiers on one claim: independent readings, never a vote.

Pinned here, against release_gate/assurance/semantic_panel.py, the corroboration
policy in release_gate/assurance/resolution.py, the panel transport in
release_gate/semantic_providers.py and `assure --semantic-panel`:

* each verifier's answer is its own evidence, with the probability or
  confidence it stated, and nothing combines them: 0.91 "established" beside
  0.87 "violated" is a disagreement for a person, never 0.52 of anything;
* a disagreement is CONTRADICTION (independent verifiers, the same evidence,
  opposite answers) or REQUIRES_REVIEW (every other), and holds;
* independence is read from what is stated about each model (provider, family,
  model, declared lineage, reported session), never assumed, and a reply
  cannot vouch for its own;
* a declared corroboration policy decides when a "supported" on a critical
  claim counts: beside a check or an observation, beside agreeing readings
  from independent verifiers, or beside a person's approval. A corroborated
  reading still never establishes, and no reading moves a decision toward
  admission;
* a panel is configured in a file that names each verifier's key variable,
  never its key, and each member is planned and asked under the same rules.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from release_gate.assurance.case import Decision
from release_gate.assurance.correlation import READER_INDEPENDENCE_POLICY
from release_gate.assurance.escalation import EscalationPolicy, EscalationScope
from release_gate.assurance.resolution import (
    DEFAULT_RESOLUTION_POLICY, CorroborationRoute, ItemRole, ResolutionError,
    ResolutionPolicy, ResolutionStatus, SemanticCorroboration, SemanticSupport)
from release_gate.assurance.semantic_panel import (PanelMember, ReadingDisagreement,
                                                   SemanticPanel, plan_panel,
                                                   reading_provenance, tag_reading)
from release_gate.assurance.semantic_verifier import (
    AssertionStatus, DecisionReply, OutputKind, ProviderCapabilities, ProviderIdentity,
    ProviderInterface, SemanticAssertion, SemanticVerdict, SemanticVerifier,
    SemanticVerifierError, build_evidence_packet, state_hash_for, unresolved_questions)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
S = ResolutionStatus
V = SemanticVerdict


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def rows(*extra, attempts=None, required=True) -> list:
    claim = {"record_type": "claim", "claim_id": "c-gate", "is_root": required,
             "proposition": "Every refund above 500 is approved by a person before it is issued",
             "producer": P("platform", "human")}
    if attempts:
        claim["verification_attempts"] = attempts
    found = [claim,
             {"record_type": "evidence", "evidence_id": "e-code", "kind": "CODE_ARTIFACT",
              "producer": P("repository", "tool"), "supports_claims": ["c-gate"],
              "coverage_note": "refunds/service.py",
              "summary": "issue_refund calls require_human_approval above 500"}]
    if not required:
        found.append({"record_type": "claim", "claim_id": "c-root", "is_root": True,
                      "proposition": "the release is admissible", "producer": P("platform", "human")})
    return found + list(extra)


def write(tmp_path, data, name="case.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def bearing(outcome, cid="c-gate"):
    return tuple(i.item_id for i in outcome.analysis.resolution.of(cid).items
                 if i.role in (ItemRole.SUPPORTS, ItemRole.INCONCLUSIVE))


def reading(outcome, verdict, *, provider="pa", model="m-a", family="fam-a",
            confidence=0.9, cid="c-gate", packet="sha256:" + "a" * 64, i=0, **kw):
    return SemanticAssertion(
        question_id=f"sq_{cid}", claim_id=cid, status=AssertionStatus.ANSWERED,
        verdict=verdict, confidence=confidence, evidence_refs=bearing(outcome, cid),
        provider=provider, model=model, model_family=family, packet_hash=packet,
        state_hash=state_hash_for(outcome.analysis), timestamp=f"t{i}", **kw)


def rules(outcome):
    return {f.rule_id: f for f in outcome.analysis.findings}


COUNTS = ResolutionPolicy(policy_id="counts", semantic_support=SemanticSupport.COUNTS)


def corroborating(**kw):
    return ResolutionPolicy(policy_id="corroborate", semantic_support=SemanticSupport.COUNTS,
                            semantic_corroboration=SemanticCorroboration(**kw))


@pytest.fixture
def case_file(tmp_path):
    return write(tmp_path, rows())


@pytest.fixture
def first(case_file):
    return assure(case_file)


# ── the example: 0.91 established, 0.87 violated ─────────────────────────────

class Decider:
    """A decision model that answers with the distribution it is given."""

    def __init__(self, name, family, probabilities, provider):
        self.name, self.family, self.probabilities = name, family, probabilities
        self.provider = provider

    def identity(self):
        return ProviderIdentity(provider=self.provider, model=self.name,
                                model_family=self.family, local=True,
                                dialect="release-gate-decision/1")

    def capabilities(self):
        return ProviderCapabilities(interface=ProviderInterface.DECISION,
                                    outputs=(OutputKind.PROBABILITY, OutputKind.CHOICE))

    def decide(self, request):
        chosen = max(self.probabilities, key=self.probabilities.get)
        return DecisionReply(probabilities=dict(self.probabilities), choice=chosen,
                             metadata={"panel": {"lineage": ["forged-by-reply"]}})


A = {"established": 0.91, "violated": 0.06, "insufficient_evidence": 0.03}
B = {"established": 0.08, "violated": 0.87, "insufficient_evidence": 0.05}
#: What averaging would produce, and must never appear: the mean of the two
#: "established" figures, of the two "violated" figures, and the prompt's
#: (0.91 + 0.13) / 2.
AVERAGES = ("0.495", "0.465", "0.52")


def panel_of(*names, scope="REQUIRED"):
    return SemanticPanel(panel_id="critical", scope=scope, members=tuple(
        PanelMember(name=n, config={"model": n}, lineage=()) for n in names))


def ask_both(outcome):
    [question] = [q for q in unresolved_questions(outcome.analysis.resolution)
                  if q.claim_id == "c-gate"]
    records = {r.evidence_id: r for r in outcome.case.records("evidence")
               if hasattr(r, "evidence_id")}
    packet = build_evidence_packet(question, records=records,
                                   state_hash=state_hash_for(outcome.analysis))
    panel = panel_of("verifier-a", "verifier-b")
    out = []
    for member, decider in zip(panel.members,
                               (Decider("sys1-a", "fam-a", A, "vendor-a"),
                                Decider("sys1-b", "fam-b", B, "vendor-b"))):
        out.append(tag_reading(SemanticVerifier(decider).verify(packet), panel, member))
    return out


class TestTheExample:

    def test_two_independent_verifiers_disagreeing_is_a_contradiction_for_a_person(
            self, case_file, first):
        readings = ask_both(first)
        assert [r.verdict for r in readings] == [V.SUPPORTED, V.CONTRADICTED]
        after = assure(case_file, semantic_assertions=readings)
        found = rules(after)["RG-SEM-007"]
        assert found.effect.value == "HOLD"
        [disagreement] = found.observed["disagreements"]
        assert ReadingDisagreement(disagreement["classification"]) is (
            ReadingDisagreement.CONTRADICTION)
        stated = {(r["verdict"], r["confidence"]) for r in disagreement["readings"]}
        assert stated == {("supported", 0.91), ("contradicted", 0.87)}
        assert after.case.verdict.decision is not Decision.PROMOTE
        # On the claim's attention item, beside every other reason to look at it,
        # with each reading's figure as it was stated.
        [item] = [i for i in after.attention if i.focus == "c-gate"]
        assert "RG-SEM-007" in item.rule_ids and item.effect.value == "HOLD"
        assert item.observed["RG-SEM-007"]["contradictions"] == 1

    def test_nothing_averages_the_two(self, case_file, first):
        after = assure(case_file, semantic_assertions=ask_both(first))
        text = json.dumps(rules(after)["RG-SEM-007"].observed) + \
            json.dumps(after.case.to_dict(), default=str)
        for averaged in AVERAGES:
            assert averaged not in text
        numbers = set()

        def walk(node):
            if isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
            elif isinstance(node, float):
                numbers.add(node)

        walk(rules(after)["RG-SEM-007"].observed)
        assert numbers <= set(A.values()) | set(B.values())
        resolution = after.analysis.resolution.of("c-gate").to_dict()
        assert "confidence" not in json.dumps(resolution)

    def test_each_verifier_is_its_own_evidence(self, case_file, first):
        readings = ask_both(first)
        after = assure(case_file, semantic_assertions=readings)
        semantic = [i for i in after.analysis.resolution.of("c-gate").items
                    if i.item_kind == "semantic"]
        assert len(semantic) == 2 and len({i.item_id for i in semantic}) == 2
        assert {r.provider_metadata["panel"]["member"] for r in readings} == {
            "verifier-a", "verifier-b"}

    def test_a_reply_cannot_declare_its_own_lineage(self, first):
        """The deciders put a lineage under `panel` in their reply metadata. It is
        kept in the verbatim response, for audit, and read nowhere: only the
        operator's tag is in the metadata, and the provenance does not carry it."""
        for r in ask_both(first):
            assert r.provider_metadata["panel"]["lineage"] == []
            assert "forged-by-reply" in r.response
            assert "forged-by-reply" not in json.dumps(r.provider_metadata)
            assert not any("forged" in key for key in
                           reading_provenance("e", r).keys(READER_INDEPENDENCE_POLICY))


    def test_an_untagged_reply_cannot_place_itself(self, first):
        """Without a panel nothing overwrites `panel`, so the verifier strips it:
        a model that states no family cannot become independent by saying it has
        a lineage."""
        [question] = [q for q in unresolved_questions(first.analysis.resolution)
                      if q.claim_id == "c-gate"]
        records = {r.evidence_id: r for r in first.case.records("evidence")
                   if hasattr(r, "evidence_id")}
        packet = build_evidence_packet(question, records=records,
                                       state_hash=state_hash_for(first.analysis))
        reading = SemanticVerifier(Decider("sys1-x", "", A, "vendor-x")).verify(packet)
        assert "panel" not in reading.provider_metadata
        assert not reading_provenance("e", reading).determinable(READER_INDEPENDENCE_POLICY)


# ── what a disagreement is ───────────────────────────────────────────────────

class TestClassification:

    def disagreement(self, case_file, first, a, b):
        after = assure(case_file, semantic_assertions=[a, b])
        found = rules(after).get("RG-SEM-007")
        assert found is not None
        [d] = found.observed["disagreements"]
        return d, found

    def test_independent_and_the_same_evidence_is_a_contradiction(self, case_file, first):
        d, found = self.disagreement(case_file, first, reading(first, V.SUPPORTED),
                                     reading(first, V.CONTRADICTED, provider="pb",
                                             model="m-b", family="fam-b", i=1))
        assert d["classification"] == "CONTRADICTION" and found.effect.value == "HOLD"

    @pytest.mark.parametrize("second, says", [
        ({"provider": "pa", "model": "m-a", "family": "fam-a"}, "share provenance"),
        ({"provider": "pa", "model": "m-b", "family": "fam-b"}, "share provenance"),
        ({"provider": "pb", "model": "m-b", "family": "fam-a"}, "share provenance"),
        ({"provider": "pb", "model": "M-A", "family": "fam-b"}, "share provenance"),
        ({"provider": "pb", "model": "m-b", "family": ""}, "cannot be told"),
        ({"provider": "pb", "model": "m-b", "family": "fam-b",
          "packet": "sha256:" + "b" * 64}, "different evidence"),
    ], ids=["same-model", "same-provider", "same-family-two-hosts", "same-model-id",
            "family-unstated", "different-packets"])
    def test_every_other_opposite_answer_requires_review(self, case_file, first, second,
                                                         says):
        d, found = self.disagreement(case_file, first, reading(first, V.SUPPORTED),
                                     reading(first, V.CONTRADICTED, i=1, **second))
        assert d["classification"] == "REQUIRES_REVIEW" and says in d["basis"]
        assert found.effect.value == "HOLD"

    def test_a_shared_declared_lineage_or_reported_session_correlates(self, case_file,
                                                                      first):
        panel = panel_of("x", "y")
        shared = [tag_reading(r, panel, PanelMember(name=n, lineage=("base-model-7",)))
                  for r, n in ((reading(first, V.SUPPORTED), "x"),
                               (reading(first, V.CONTRADICTED, provider="pb", model="m-b",
                                        family="fam-b", i=1), "y"))]
        d, _ = self.disagreement(case_file, first, *shared)
        assert d["classification"] == "REQUIRES_REVIEW"
        session = [reading(first, V.SUPPORTED, provider_metadata={"session": "s-1"}),
                   reading(first, V.CONTRADICTED, provider="pb", model="m-b",
                           family="fam-b", i=1, provider_metadata={"session": "s-1"})]
        d, _ = self.disagreement(case_file, first, *session)
        assert d["classification"] == "REQUIRES_REVIEW"

    def test_decisive_beside_insufficient_requires_review(self, case_file, first):
        d, _ = self.disagreement(case_file, first, reading(first, V.SUPPORTED),
                                 reading(first, V.INSUFFICIENT_EVIDENCE, provider="pb",
                                         model="m-b", family="fam-b", i=1))
        assert d["classification"] == "REQUIRES_REVIEW" and "insufficient" in d["basis"]

    def test_agreement_and_non_answers_are_not_disagreements(self, case_file, first):
        agreeing = [reading(first, V.SUPPORTED),
                    reading(first, V.SUPPORTED, provider="pb", model="m-b", family="fam-b",
                            i=1)]
        unknown = SemanticAssertion(question_id="sq_c-gate", claim_id="c-gate",
                                    status=AssertionStatus.UNKNOWN,
                                    unknown_reason="TIMEOUT", provider="pc", model="m-c")
        stale = dataclass_replace(reading(first, V.CONTRADICTED, provider="pd", model="m-d",
                                          family="fam-d", i=2),
                                  state_hash="sha256:" + "f" * 64)
        after = assure(case_file, semantic_assertions=agreeing + [unknown])
        assert "RG-SEM-007" not in rules(after)
        # Bound to a candidate the case states, a reading about another one is set
        # aside and disagrees with nothing.
        stated = write(Path(case_file).parent, [{"record_type": "candidate", "components": {
            "commit": "abc"}}] + rows(), "stated.json")
        bound = assure(stated)
        both = [reading(bound, V.SUPPORTED), dataclass_replace(stale, evidence_refs=bearing(bound))]
        assert "RG-SEM-007" not in rules(assure(stated, semantic_assertions=both))

    def test_a_claim_the_decision_does_not_need_is_advisory(self, tmp_path):
        path = write(tmp_path, rows(required=False))
        first = assure(path)
        assert first.analysis.resolution.of("c-gate").required is False
        after = assure(path, semantic_assertions=[
            reading(first, V.SUPPORTED),
            reading(first, V.CONTRADICTED, provider="pb", model="m-b", family="fam-b", i=1)])
        assert rules(after)["RG-SEM-007"].effect.value == "ADVISORY"


def dataclass_replace(obj, **changes):
    import dataclasses
    return dataclasses.replace(obj, **changes)


# ── when a "supported" counts ────────────────────────────────────────────────

def counted_readings(outcome, cid="c-gate"):
    return [i for i in outcome.analysis.resolution.of(cid).items
            if i.item_kind == "semantic" and i.role is ItemRole.SUPPORTS]


class TestCorroboration:

    def test_without_a_policy_a_reading_counts_as_it_did(self, case_file, first):
        after = assure(case_file, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=COUNTS)
        assert len(counted_readings(after)) == 1
        assert after.analysis.resolution.of("c-gate").corroboration is None
        assert "RG-SEM-006" not in rules(after)

    def test_one_reading_alone_does_not_count_on_a_critical_claim(self, case_file, first):
        after = assure(case_file, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=corroborating())
        assert counted_readings(after) == []
        [item] = [i for i in after.analysis.resolution.of("c-gate").items
                  if i.item_kind == "semantic"]
        assert item.role is ItemRole.SEMANTIC_SUPPORT and "uncorroborated" in item.reason
        state = after.analysis.resolution.of("c-gate").corroboration
        assert state["met"] is False and set(state["routes_missing"]) == {
            r.value for r in CorroborationRoute}
        assert rules(after)["RG-SEM-006"].effect.value == "ADVISORY"

    def test_unmet_takes_the_declared_effect(self, case_file, first):
        after = assure(case_file, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=corroborating(unmet="HOLD"))
        assert rules(after)["RG-SEM-006"].effect.value == "HOLD"

    def test_a_check_corroborates(self, tmp_path):
        path = write(tmp_path, rows(attempts=[{"method": "TEST_SUITE", "outcome": "PASSED",
                                               "verifier": "ci"}]))
        first = assure(path)
        after = assure(path, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=corroborating())
        assert len(counted_readings(after)) == 1
        assert after.analysis.resolution.of("c-gate").corroboration["routes_met"] == [
            "DETERMINISTIC_SUPPORT"]

    def test_a_persons_approval_corroborates(self, tmp_path):
        approval = {"record_type": "evidence", "evidence_id": "e-review",
                    "kind": "HUMAN_REVIEW", "producer": P("dana", "human"),
                    "supports_claims": ["c-gate"], "coverage_note": "read the refund path",
                    "summary": "approved: the gate is on every refund path"}
        path = write(tmp_path, rows(approval))
        first = assure(path)
        after = assure(path, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=corroborating())
        assert after.analysis.resolution.of("c-gate").corroboration["routes_met"] == [
            "HUMAN_APPROVAL"]
        assert len(counted_readings(after)) == 1

    def test_two_independent_verifiers_corroborate(self, case_file, first):
        two = [reading(first, V.SUPPORTED),
               reading(first, V.SUPPORTED, provider="pb", model="m-b", family="fam-b", i=1)]
        after = assure(case_file, semantic_assertions=two, resolution_policy=corroborating())
        state = after.analysis.resolution.of("c-gate").corroboration
        assert state["routes_met"] == ["INDEPENDENT_READINGS"]
        assert state["independent_reader_groups"] == 2
        assert len(counted_readings(after)) == 2
        assert "RG-SEM-006" not in rules(after)

    @pytest.mark.parametrize("second", [
        {"provider": "pa", "model": "m-b", "family": "fam-b"},
        {"provider": "pb", "model": "m-b", "family": "fam-a"},
        {"provider": "pb", "model": "m-b", "family": ""},
    ], ids=["same-provider", "same-family", "family-unstated"])
    def test_correlated_or_unplaceable_verifiers_do_not(self, case_file, first, second):
        two = [reading(first, V.SUPPORTED), reading(first, V.SUPPORTED, i=1, **second)]
        after = assure(case_file, semantic_assertions=two, resolution_policy=corroborating())
        assert after.analysis.resolution.of("c-gate").corroboration["met"] is False
        assert counted_readings(after) == []

    def test_agreement_with_a_dissent_does_not(self, case_file, first):
        three = [reading(first, V.SUPPORTED),
                 reading(first, V.SUPPORTED, provider="pb", model="m-b", family="fam-b", i=1),
                 reading(first, V.CONTRADICTED, provider="pc", model="m-c", family="fam-c",
                         i=2)]
        after = assure(case_file, semantic_assertions=three,
                       resolution_policy=corroborating())
        state = after.analysis.resolution.of("c-gate").corroboration
        assert state["met"] is False and state["readings_disagreeing"] == ["contradicted"]
        assert "RG-SEM-007" in rules(after)

    def test_only_the_declared_routes_count(self, tmp_path):
        path = write(tmp_path, rows(attempts=[{"method": "TEST_SUITE", "outcome": "PASSED",
                                               "verifier": "ci"}]))
        first = assure(path)
        after = assure(path, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=corroborating(routes=["HUMAN_APPROVAL"]))
        assert after.analysis.resolution.of("c-gate").corroboration["met"] is False

    def test_a_claim_outside_the_scope_is_read_as_before(self, tmp_path):
        path = write(tmp_path, rows(required=False))
        first = assure(path)
        after = assure(path, semantic_assertions=[reading(first, V.SUPPORTED)],
                       resolution_policy=corroborating())
        assert after.analysis.resolution.of("c-gate").corroboration is None
        assert len(counted_readings(after)) == 1
        everywhere = assure(path, semantic_assertions=[reading(first, V.SUPPORTED)],
                            resolution_policy=corroborating(applies_to="ALL"))
        assert counted_readings(everywhere) == []

    def test_a_corroborated_reading_still_establishes_nothing(self, case_file, first):
        many = [reading(first, V.SUPPORTED, provider=f"p{k}", model=f"m{k}",
                        family=f"fam-{k}", i=k) for k in range(5)]
        policy = corroborating()
        before = assure(case_file, resolution_policy=policy)
        after = assure(case_file, semantic_assertions=many, resolution_policy=policy)
        resolved = after.analysis.resolution.of("c-gate")
        assert resolved.corroboration["met"] is True
        assert resolved.status is not S.ESTABLISHED
        assert resolved.status is before.analysis.resolution.of("c-gate").status
        assert after.case.verdict.decision is before.case.verdict.decision

    @pytest.mark.parametrize("example, methodology", [
        ("examples/agents/02-release-promoted.jsonl", "general-agent-action@1.0.0"),
        ("examples/agents/04-production-db-change.jsonl", "general-agent-action@1.0.0"),
        ("examples/proofagent/release.jsonl", "general-agent-action@1.0.0")])
    def test_no_panel_moves_a_decision_toward_admission(self, example, methodology):
        """Every claim read by five independent verifiers agreeing, under a
        policy that counts corroborated readings: the decision is never more
        permissive, and nothing below the admission level reaches it."""
        from release_gate.assurance.methodologies import default_registry
        path = str(ROOT / example)
        kw = {"methodology": default_registry().resolve(methodology),
              "resolution_policy": corroborating(applies_to="ALL")}
        before = assure(path, **kw)
        rank = {Decision.PROMOTE: 0, Decision.HOLD: 1, Decision.BLOCK: 2}
        level = {S.ESTABLISHED: 3, S.SUPPORTED: 2}
        state = state_hash_for(before.analysis)
        for verdict in V:
            panel = [SemanticAssertion(
                question_id=f"sq_{r.claim_id}", claim_id=r.claim_id,
                status=AssertionStatus.ANSWERED, verdict=verdict, confidence=0.99,
                evidence_refs=tuple(i.item_id for i in r.items
                                    if i.role in (ItemRole.SUPPORTS, ItemRole.INCONCLUSIVE))
                or ("nothing",), provider=f"p{k}", model=f"m{k}", model_family=f"fam-{k}",
                state_hash=state, packet_hash="sha256:" + "c" * 64)
                for r in before.analysis.resolution.resolutions for k in range(5)]
            after = assure(path, semantic_assertions=panel, **kw)
            assert rank[after.case.verdict.decision] >= rank[before.case.verdict.decision]
            for r in before.analysis.resolution.resolutions:
                if level.get(r.status, 0) < 2:
                    assert level.get(after.analysis.resolution.of(r.claim_id).status, 0) < 2


class TestThePolicy:

    @pytest.mark.parametrize("change", [
        {"routes": []}, {"min_independent_readings": 1}, {"applies_to": "SOME"},
        {"unmet": "ADVISORY"}])
    def test_an_unusable_corroboration_policy_is_refused(self, change):
        with pytest.raises((ResolutionError, ValueError)):
            SemanticCorroboration(**change)

    def test_it_round_trips_and_is_recorded_only_when_declared(self):
        declared = corroborating(unmet="HOLD", routes=["INDEPENDENT_READINGS"],
                                 min_independent_readings=3)
        again = ResolutionPolicy.from_dict(json.loads(json.dumps(declared.to_dict())))
        assert again == declared and again.digest() == declared.digest()
        assert "semantic_corroboration" not in DEFAULT_RESOLUTION_POLICY.to_dict()
        assert "semantic_corroboration" not in COUNTS.to_dict()
        with pytest.raises(ResolutionError, match="unknown"):
            ResolutionPolicy.from_dict({"semantic_corroboration": {"majority": True}})

    def test_readers_are_correlated_by_provider_by_default(self):
        assert "provider" in {d.value for d in READER_INDEPENDENCE_POLICY.correlate_on}
        a = reading_provenance("e1", SemanticAssertion(question_id="q", claim_id="c",
                                                       status=AssertionStatus.ANSWERED,
                                                       verdict=V.SUPPORTED, confidence=0.9,
                                                       provider="Vendor", model="M",
                                                       model_family="Fam"))
        keys = a.keys(READER_INDEPENDENCE_POLICY)
        assert {"provider:vendor", "verifier:m", "lineage:model_family:fam"} <= keys
        assert a.determinable(READER_INDEPENDENCE_POLICY)
        unplaced = reading_provenance("e2", SemanticAssertion(
            question_id="q", claim_id="c", status=AssertionStatus.ANSWERED,
            verdict=V.SUPPORTED, confidence=0.9, provider="v", model="m",
            provider_metadata={"session": "s"}))
        assert not unplaced.determinable(READER_INDEPENDENCE_POLICY)


# ── the panel ────────────────────────────────────────────────────────────────

PANEL = {"schema": "release-gate.semantic-panel/1", "panel_id": "critical",
         "verifiers": [
             {"name": "a", "provider": "openai_compatible", "base_url": "http://localhost:1/v1",
              "model": "model-a", "model_family": "fam-a"},
             {"name": "b", "provider": "openai_compatible", "base_url": "https://b.example/v1",
              "model": "model-b", "model_family": "fam-b", "api_key_env": "PANEL_B_KEY",
              "lineage": ["base-x"]}]}


class TestThePanel:

    def test_a_panel_reads_and_round_trips(self):
        panel = SemanticPanel.from_dict(PANEL)
        assert [m.name for m in panel.members] == ["a", "b"]
        assert panel.scope is EscalationScope.REQUIRED
        assert panel.members[1].lineage == ("base-x",)
        assert SemanticPanel.from_dict(panel.to_dict()) == panel

    @pytest.mark.parametrize("change, says", [
        ({"verifiers": PANEL["verifiers"][:1]}, "at least two"),
        ({"verifiers": [PANEL["verifiers"][0], dict(PANEL["verifiers"][0])]}, "own name"),
        ({"verifiers": [PANEL["verifiers"][0], {**PANEL["verifiers"][1],
                                                "api_key": "sk-live"}]}, "never the key"),
        ({"verifiers": [PANEL["verifiers"][0], {**PANEL["verifiers"][1],
                                                "temperature": 2}]}, "unknown keys"),
        ({"verifiers": [PANEL["verifiers"][0], {"name": "c"}]}, "no model"),
        ({"weights": [0.5, 0.5]}, "unknown panel keys"),
        ({"panel_id": ""}, "named"),
    ])
    def test_an_unusable_panel_is_refused(self, change, says):
        with pytest.raises(SemanticVerifierError, match=says):
            SemanticPanel.from_dict({**PANEL, **change})

    def test_each_member_is_built_as_rg_semantic_builds_one(self):
        from release_gate.semantic_providers import (SemanticProviderConfigError,
                                                     panel_providers)
        panel = SemanticPanel.from_dict(PANEL)
        with pytest.raises(SemanticProviderConfigError, match="PANEL_B_KEY"):
            panel_providers(panel, environ={})
        built = panel_providers(panel, environ={"PANEL_B_KEY": "secret"})
        assert {n: p.identity().model_family for n, p in built.items()} == {
            "a": "fam-a", "b": "fam-b"}
        twice = SemanticPanel.from_dict({**PANEL, "verifiers": [
            PANEL["verifiers"][0], {**PANEL["verifiers"][0], "name": "again"}]})
        with pytest.raises(SemanticProviderConfigError, match="asked twice"):
            panel_providers(twice, environ={})

    def test_a_tag_is_part_of_the_readings_identity(self, first):
        r = reading(first, V.SUPPORTED)
        tagged = tag_reading(r, panel_of("a", "b"), PanelMember(name="a", lineage=("x",)))
        assert tagged.assertion_id != r.assertion_id
        assert tagged.provider_metadata["panel"] == {"panel_id": "critical", "member": "a",
                                                     "lineage": ["x"]}


class TestPlanning:

    def caps(self):
        return ProviderCapabilities(interface=ProviderInterface.CHAT,
                                    outputs=(OutputKind.CHOICE,))

    def members(self):
        return {"a": (ProviderIdentity(provider="pa", model="m-a"), self.caps()),
                "b": (ProviderIdentity(provider="pb", model="m-b"), self.caps())}

    def plan(self, outcome, panel, policy=None):
        records = [r for r in outcome.case.records("evidence") if hasattr(r, "evidence_id")]
        return dict(plan_panel(outcome.analysis.resolution, records, panel, self.members(),
                               policy=policy or EscalationPolicy(scope="ALL"),
                               state_hash=state_hash_for(outcome.analysis)))

    def test_the_others_are_asked_only_about_critical_claims(self, tmp_path):
        outcome = assure(write(tmp_path, rows(required=False)))
        plans = self.plan(outcome, panel_of("a", "b"))
        asked = {name: {p.question.claim_id for p in plan.packets}
                 for name, plan in plans.items()}
        assert "c-gate" in asked["a"]
        assert "c-gate" not in asked["b"]
        everywhere = self.plan(outcome, panel_of("a", "b", scope="ALL"))
        assert "c-gate" in {p.question.claim_id for p in everywhere["b"].packets}

    def test_each_member_counts_only_its_own_earlier_reading(self, case_file, first):
        plans = self.plan(first, panel_of("a", "b"))
        [packet] = [p for p in plans["a"].packets if p.question.claim_id == "c-gate"]
        earlier = SemanticAssertion(
            question_id=packet.question.question_id, claim_id="c-gate",
            status=AssertionStatus.ANSWERED, verdict=V.SUPPORTED, confidence=0.9,
            evidence_refs=packet.refs, provider="pa", model="m-a",
            packet_hash=packet.packet_hash, state_hash=packet.state_hash)
        again = assure(case_file, semantic_assertions=[earlier])
        replanned = self.plan(again, panel_of("a", "b"))
        assert not any(p.question.claim_id == "c-gate" for p in replanned["a"].packets)
        assert any(p.question.claim_id == "c-gate" for p in replanned["b"].packets)


# ── the command line ─────────────────────────────────────────────────────────

class _TwoModels:
    """A local OpenAI-compatible endpoint answering per model: one says supported,
    the other contradicted."""

    def __init__(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                packet = json.loads(body["messages"][-1]["content"])["evidence_packet"]
                verdict = "supported" if body["model"] == "agrees" else "contradicted"
                text = json.dumps({
                    "question_id": packet["question"]["question_id"],
                    "claim_id": packet["question"]["claim_id"], "verdict": verdict,
                    "confidence": 0.9, "evidence_refs": [i["ref"] for i in packet["items"]],
                    "reason": "read the code"})
                payload = json.dumps({"model": body["model"], "choices": [
                    {"message": {"role": "assistant", "content": text}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"


class TestTheCommandLine:

    def _cli(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("RG_SEMANTIC_")}
        return subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", *args],
                              capture_output=True, text=True, timeout=300, env=env)

    def test_a_panel_asks_each_verifier_and_keeps_every_answer(self, case_file, tmp_path):
        server = _TwoModels()
        panel = tmp_path / "panel.json"
        panel.write_text(json.dumps({"panel_id": "critical", "verifiers": [
            {"name": "first", "base_url": server.url, "model": "agrees",
             "model_family": "fam-a"},
            {"name": "second", "base_url": server.url, "model": "dissents",
             "model_family": "fam-b"}]}))
        out = tmp_path / "semantic.jsonl"
        try:
            result = self._cli(case_file, "--semantic", "--semantic-panel", str(panel),
                               "--semantic-out", str(out), "--full")
        finally:
            server.httpd.shutdown()
        assert "RG-SEM-007" in result.stdout, result.stderr
        assert result.returncode == 10
        assert "semantic panel critical: first" in result.stderr
        assert "semantic panel critical: second" in result.stderr
        kept = [json.loads(line) for line in out.read_text().splitlines()]
        plans = [r for r in kept if r["record_type"] == "escalation_plan"]
        assert [p["panel_member"] for p in plans] == ["first", "second"]
        readings = [r for r in kept if r["record_type"] == "semantic_assertion"]
        assert {r["provider_metadata"]["panel"]["member"] for r in readings} == {
            "first", "second"}
        # One local server is one provider: the readings share it, so the
        # disagreement is for review, not a contradiction between independents.
        assert "REQUIRES_REVIEW" in result.stdout

    def test_a_panel_without_asking_is_an_error(self, case_file, tmp_path):
        panel = tmp_path / "panel.json"
        panel.write_text(json.dumps(PANEL))
        result = self._cli(case_file, "--semantic-panel", str(panel))
        assert result.returncode == 1 and "without --semantic" in result.stdout

    def test_an_unusable_panel_file_is_an_error(self, case_file, tmp_path):
        panel = tmp_path / "panel.json"
        panel.write_text(json.dumps({**PANEL, "verifiers": PANEL["verifiers"][:1]}))
        result = self._cli(case_file, "--semantic", "--semantic-panel", str(panel))
        assert result.returncode == 1 and "not a usable semantic panel" in result.stdout
