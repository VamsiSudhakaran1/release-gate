"""Evidence independence — how many sources a body of agreement rests on.

Five outputs from one model session are one opinion, however they are labelled.
These tests hold correlation.py to that, and to its other half: independence
that cannot be read from what a source states is reported as unknown, never
assumed. The five scenarios are the ones the design is answerable to:

1. five independent sources;
2. five outputs from one model and session;
3. different models working from the same generated test dataset;
4. a human reviewer relying entirely on an AI-generated summary;
5. a formal verifier checking the same artifact independently.

Each is run at the level of the grouping, and end to end through `assure`, where
what matters is the claim's status, the verification graph's confirmation count
and the words a person reads.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.correlation import (
    DEFAULT_INDEPENDENCE_POLICY,
    IndependenceError,
    IndependencePolicy,
    IndependenceStatus,
    ProvenanceDimension,
    SourceProvenance,
    assess_independence,
)
from release_gate.assurance.resolution import ResolutionPolicy, ResolutionStatus
from release_gate.assurance.zero_config import assure, render_text

I = IndependenceStatus


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def check(method: str, verifier: str, provenance: dict, **kw) -> dict:
    return {"method": method, "outcome": "PASSED", "verifier": verifier,
            "provenance": provenance, **kw}


def case(checks, *extra) -> list:
    return [{"record_type": "claim", "claim_id": "c-transfer", "is_root": True,
             "proposition": "transfers above the threshold require human approval",
             "producer": P("platform-team", "human"),
             "verification_attempts": list(checks)}, *extra]


def run(tmp_path, rows, name="case", **kw):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(rows))
    return assure(str(path), **kw)


def resolution(outcome):
    return outcome.analysis.resolution.of("c-transfer")


TOOL = "sha256:" + "7" * 64


def confirmations(outcome):
    """The verification graph's independent-confirmation count for these checks.

    The graph counts only checks that provably apply to the current state, and a
    claim has no content digest to apply to, so the case's own attempts are moved
    onto an artifact whose current digest is known. Same attempts, same
    provenance, same case index: only the target changes.
    """
    import dataclasses

    from release_gate.assurance.verification import (
        TargetKind, VerificationGraph, VerificationTarget)
    graph = outcome.analysis.verification_graph
    target = VerificationTarget(kind=TargetKind.ARTIFACT, target_id="transfer_tool")
    moved = [dataclasses.replace(a, target=target, target_digest=TOOL)
             for a in graph.attempts]
    regraphed = VerificationGraph(moved, digests={target.key: TOOL},
                                  provenance=graph.provenance)
    return regraphed.assess(target).independent_confirmations


def source(sid: str, **kw) -> SourceProvenance:
    return SourceProvenance(source_id=sid, source_kind="verification", **kw)


CODEX = {"provider": "openai", "model_family": "codex", "model_version": "codex-1",
         "session": "codex-run-4471", "agent": "builder"}


# ── 1. five independent sources ──────────────────────────────────────────────

FIVE_INDEPENDENT = [
    check("TEST_SUITE", "ci", {"toolchain": ["pytest"], "session": "ci-981"}),
    check("STATIC_ANALYSIS", "semgrep", {"toolchain": ["semgrep"]}),
    check("HUMAN_REVIEW", "j.doe", {"reviewer": "j.doe"}),
    check("SIMULATION", "proofagent", {"provider": "proofagent", "model_family": "pa-sim",
                                       "session": "pa-12"}),
    check("FORMAL_PROOF", "tlc", {"toolchain": ["tla+", "tlc"]}),
]


class TestFiveIndependentSources:

    def test_they_form_five_groups(self):
        sources = [source(f"s{i}", toolchain=(f"tool-{i}",)) for i in range(5)]
        found = assess_independence(sources)
        assert found.status is I.INDEPENDENT
        assert found.independent_groups == 5 and not found.undetermined

    def test_end_to_end_they_establish_the_claim(self, tmp_path):
        out = run(tmp_path, case(FIVE_INDEPENDENT))
        r = resolution(out)
        assert r.status is ResolutionStatus.ESTABLISHED
        assert r.establishing_independence.status is I.INDEPENDENT
        assert r.establishing_independence.independent_groups == 5
        assert confirmations(out) == 5


# ── 2. five outputs from one model and session ───────────────────────────────

def five_codex(**varied):
    """Five checks one Codex session produced, each under its own verifier name
    and lineage tag — the labels an agent would give five artifacts."""
    return [check(method, f"codex-{i}", CODEX, independence_lineage=[f"codex-{i}"],
                  **varied)
            for i, method in enumerate(("TEST_SUITE", "STATIC_ANALYSIS", "PROPERTY_TEST",
                                        "SIMULATION", "DOMAIN_CHECKER"))]


class TestFiveOutputsOfOneSession:

    def test_they_are_one_group(self):
        sources = [source(f"s{i}", provider="openai", model_family="codex",
                          session="run-1", verifier=f"codex-{i}") for i in range(5)]
        found = assess_independence(sources)
        assert found.status is I.CORRELATED
        assert found.independent_groups == 1
        [group] = found.groups
        assert "model_family:openai/codex" in group.shared
        assert "session:run-1" in group.shared

    def test_end_to_end_the_claim_is_supported_and_not_established(self, tmp_path):
        out = run(tmp_path, case(five_codex()))
        r = resolution(out)
        assert r.status is ResolutionStatus.SUPPORTED
        assert r.establishing_independence.status is I.CORRELATED
        assert r.establishing_independence.sources == 5
        assert r.establishing_independence.independent_groups == 1

    def test_the_verification_graph_does_not_count_five_confirmations(self, tmp_path):
        assert confirmations(run(tmp_path, case(five_codex()))) == 1

    def test_no_report_says_five_independent_confirmations(self, tmp_path):
        out = run(tmp_path, case(five_codex()))
        text = render_text(out, full=True)
        assert "5 independent confirmation" not in text
        assert "1 independent group(s) and the policy asks for 2" in text
        assert "RG-INDEP-005" in {f.rule_id for f in out.analysis.findings}
        [finding] = [f for f in out.analysis.findings if f.rule_id == "RG-INDEP-005"]
        assert "5 check(s), 1 group" in finding.detail

    def test_different_model_versions_of_one_family_are_still_one_source(self, tmp_path):
        checks = [check("TEST_SUITE", f"codex-{i}",
                        {**CODEX, "model_version": f"codex-1.{i}", "session": f"s-{i}"})
                  for i in range(3)]
        out = run(tmp_path, case(checks))
        assert resolution(out).establishing_independence.independent_groups == 1


# ── 3. different models, one generated dataset ───────────────────────────────

DATASET = "sha256:" + "d" * 64


class TestDifferentModelsOneDataset:

    CHECKS = [
        check("TEST_SUITE", "gpt-runner", {"provider": "openai", "model_family": "gpt-4o",
                                           "session": "g-1", "dataset": [DATASET]}),
        check("TEST_SUITE", "claude-runner", {"provider": "anthropic",
                                              "model_family": "claude", "session": "c-1",
                                              "dataset": [DATASET]}),
        check("TEST_SUITE", "gemini-runner", {"provider": "google", "model_family": "gemini",
                                              "session": "m-1", "dataset": [DATASET]}),
    ]

    def test_the_shared_dataset_makes_them_one_group(self):
        sources = [source("a", model_family="gpt-4o", datasets=(DATASET,)),
                   source("b", model_family="claude", datasets=(DATASET,))]
        found = assess_independence(sources)
        assert found.status is I.CORRELATED
        assert found.groups[0].shared == (f"dataset:{DATASET}",)

    def test_end_to_end_three_model_families_are_one_source(self, tmp_path):
        out = run(tmp_path, case(self.CHECKS))
        r = resolution(out)
        assert r.status is ResolutionStatus.SUPPORTED
        assert r.establishing_independence.independent_groups == 1
        assert confirmations(out) == 1

    def test_without_the_shared_dataset_they_are_independent(self, tmp_path):
        apart = [{**c, "provenance": {k: v for k, v in c["provenance"].items()
                                      if k != "dataset"}} for c in self.CHECKS]
        out = run(tmp_path, case(apart), name="apart")
        assert resolution(out).establishing_independence.independent_groups == 3

    def test_a_shared_generated_artifact_correlates_the_same_way(self):
        spec = "sha256:" + "e" * 64
        found = assess_independence([
            source("a", model_family="gpt-4o", generated_from=(spec,)),
            source("b", reviewer="j.doe", generated_from=(spec,))])
        assert found.status is I.CORRELATED


# ── 4. a reviewer relying on an AI-written summary ───────────────────────────

SUMMARY = {"record_type": "evidence", "evidence_id": "e-summary", "kind": "OTHER",
           "producer": P("codex"), "coverage_note": "an AI summary of the approval path",
           "provenance": CODEX}


class TestAReviewerReadingTheModelsSummary:

    def test_relied_on_puts_the_review_in_the_summarys_group(self, tmp_path):
        out = run(tmp_path, case([
            check("TEST_SUITE", "codex-tests", CODEX),
            check("HUMAN_REVIEW", "j.doe", {"reviewer": "j.doe", "relied_on": ["e-summary"]}),
        ], SUMMARY))
        r = resolution(out)
        grouping = r.establishing_independence
        assert grouping.status is I.CORRELATED and grouping.independent_groups == 1
        assert r.status is ResolutionStatus.SUPPORTED
        assert confirmations(out) == 1

    def test_citing_the_summary_as_evidence_does_the_same(self, tmp_path):
        out = run(tmp_path, case([
            check("TEST_SUITE", "codex-tests", CODEX),
            check("HUMAN_REVIEW", "j.doe", {"reviewer": "j.doe"}, evidence=["e-summary"]),
        ], SUMMARY))
        assert resolution(out).establishing_independence.independent_groups == 1
        assert confirmations(out) == 1

    def test_a_reviewer_who_read_the_code_is_a_second_source(self, tmp_path):
        out = run(tmp_path, case([
            check("TEST_SUITE", "codex-tests", CODEX),
            check("HUMAN_REVIEW", "j.doe", {"reviewer": "j.doe"}),
        ], SUMMARY), name="read-code")
        r = resolution(out)
        assert r.establishing_independence.independent_groups == 2
        assert r.status is ResolutionStatus.ESTABLISHED

    def test_reliance_reaches_through_a_chain(self):
        from release_gate.assurance.correlation import ProvenanceIndex
        from release_gate.assurance.evidence import (
            EvidenceRecord, EvidenceType, Producer, ProducerKind)

        def record(eid, provenance, parents=()):
            return EvidenceRecord.declared(
                EvidenceType.OTHER, source="agent-log",
                producer=Producer("p", ProducerKind.AGENT),
                content={"provenance": provenance, "producer_claimed_evidence_id": eid},
                parent_evidence=tuple(parents))

        summary = record("s", {"model_family": "codex", "session": "run-1"})
        digest = record("d", {"agent": "digester"}, parents=[summary.evidence_id])
        index = ProvenanceIndex([summary, digest], DEFAULT_INDEPENDENCE_POLICY)
        review = source("review", reviewer="j.doe",
                        inherited=tuple(sorted(index.of(digest.evidence_id).keys(
                            DEFAULT_INDEPENDENCE_POLICY))))
        found = assess_independence([index.of(summary.evidence_id), review])
        assert found.status is I.CORRELATED


# ── 5. a formal verifier checking the same artifact ──────────────────────────

class TestAFormalVerifierOnTheSameArtifact:

    ARTIFACT = "sha256:" + "a" * 64

    def test_checking_the_same_thing_is_not_a_correlation(self, tmp_path):
        candidate = {"record_type": "candidate",
                     "components": {"artifact:transfer_tool": self.ARTIFACT}}
        state = {"state": {"artifact:transfer_tool": self.ARTIFACT}}
        out = run(tmp_path, case([
            check("TEST_SUITE", "codex-tests", CODEX, result=state),
            check("FORMAL_PROOF", "tlc", {"toolchain": ["tla+", "tlc"]}, result=state),
        ], candidate))
        r = resolution(out)
        assert r.establishing_independence.status is I.INDEPENDENT
        assert r.establishing_independence.independent_groups == 2
        assert r.status is ResolutionStatus.ESTABLISHED
        assert confirmations(out) == 2

    def test_a_verifier_run_by_the_same_session_is_not_independent(self, tmp_path):
        out = run(tmp_path, case([
            check("TEST_SUITE", "codex-tests", CODEX),
            check("FORMAL_PROOF", "tlc", {**CODEX, "toolchain": ["tla+", "tlc"]}),
        ]), name="same-session")
        assert resolution(out).establishing_independence.independent_groups == 1


# ── unknown is an answer ─────────────────────────────────────────────────────

class TestIndependenceUnknown:

    def test_sources_that_state_nothing_are_never_counted_independent(self):
        found = assess_independence([source("a", verifier="x"), source("b", verifier="y")])
        assert found.status is I.INDEPENDENCE_UNKNOWN
        assert found.independent_groups == 0
        assert set(found.undetermined) == {"a", "b"}

    def test_one_placed_source_and_one_unplaced_is_not_two(self):
        found = assess_independence([source("a", reviewer="j.doe"), source("b", verifier="y")])
        assert found.status is I.INDEPENDENCE_UNKNOWN
        assert found.independent_groups == 1

    def test_unplaced_checks_do_not_fill_the_quota_end_to_end(self, tmp_path):
        out = run(tmp_path, case([
            {"method": "TEST_SUITE", "outcome": "PASSED", "verifier": "ci-a"},
            {"method": "TEST_SUITE", "outcome": "PASSED", "verifier": "ci-b"},
        ]))
        r = resolution(out)
        assert r.status is ResolutionStatus.SUPPORTED
        assert r.establishing_independence.status is I.INDEPENDENCE_UNKNOWN
        assert "RG-INDEP-006" in {f.rule_id for f in out.analysis.findings}

    def test_a_shared_provider_alone_does_not_correlate_by_default(self):
        found = assess_independence([source("a", provider="openai", model_family="gpt-4o"),
                                     source("b", provider="openai", model_family="o3")])
        assert found.status is I.INDEPENDENT

    def test_a_policy_can_make_a_shared_provider_correlate(self):
        policy = IndependencePolicy(policy_id="strict", correlate_on=tuple(
            DEFAULT_INDEPENDENCE_POLICY.correlate_on) + (ProvenanceDimension.PROVIDER,))
        found = assess_independence([source("a", provider="openai", model_family="gpt-4o"),
                                     source("b", provider="openai", model_family="o3")],
                                    policy)
        assert found.status is I.CORRELATED

    @pytest.mark.parametrize("dropped", [d for d in ProvenanceDimension
                                         if d is not ProvenanceDimension.PROVIDER])
    def test_no_policy_can_drop_a_dimension(self, dropped):
        with pytest.raises(IndependenceError):
            IndependencePolicy(policy_id="loose", correlate_on=tuple(
                d for d in DEFAULT_INDEPENDENCE_POLICY.correlate_on if d is not dropped))

    def test_a_model_id_is_not_parsed_into_a_family(self):
        found = assess_independence([source("a", model_version="gpt-4o-2024-08-06"),
                                     source("b", model_version="gpt-4o-2024-11-20")])
        assert found.status is I.INDEPENDENCE_UNKNOWN

    def test_independence_is_groups_and_never_a_score(self):
        payload = assess_independence(
            [source(f"s{i}", toolchain=(f"t{i}",)) for i in range(3)]).to_dict()
        assert set(payload) == {"status", "sources", "independent_groups", "groups",
                                "undetermined", "policy", "basis"}
        assert not any(isinstance(v, float) for v in payload.values())


class TestThePolicyDecidesWhatIsEnough:

    def test_one_group_is_enough_only_when_the_policy_says_so(self, tmp_path):
        rows = case(five_codex())
        assert resolution(run(tmp_path, rows, name="default")).status \
            is ResolutionStatus.SUPPORTED
        lenient = ResolutionPolicy(policy_id="single-source-ok", independence=(
            IndependencePolicy(policy_id="single", min_independent_groups=1)))
        out = run(tmp_path, rows, name="lenient", resolution_policy=lenient)
        assert resolution(out).status is ResolutionStatus.ESTABLISHED
        assert out.analysis.resolution.policy.ref == "single-source-ok@1"

    def test_grouping_is_deterministic(self, tmp_path):
        first = resolution(run(tmp_path, case(FIVE_INDEPENDENT))).to_dict()
        second = resolution(run(tmp_path, case(FIVE_INDEPENDENT))).to_dict()
        assert first == second
