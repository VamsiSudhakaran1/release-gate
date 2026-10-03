"""Claim resolution — every claim gets a status, a rule and its evidence, and no average.

The resolver (release_gate/assurance/resolution.py) is an order of rules, and
these tests pin it rule by rule, then hold it to the properties the order exists
for: a counterexample outranks any amount of support, a proof about the wrong
artifact does not count, a missing assessment is not success, and the same case
resolves the same way every time.

Most cases are built as envelopes and run through `assure`, so what is tested is
the path a submission takes, not the resolver in isolation.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from release_gate.assurance.correlation import IndependenceError, IndependencePolicy
from release_gate.assurance.resolution import (
    DEFAULT_RESOLUTION_POLICY,
    POLICY_METADATA_KEY,
    ItemRole,
    ResolutionError,
    ResolutionPolicy,
    ResolutionStatus,
    Strength,
    policy_for_case,
)
from release_gate.assurance.zero_config import assure, render_text

S = ResolutionStatus


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def claim(cid: str, **kw) -> dict:
    return {"record_type": "claim", "claim_id": cid, "proposition": f"{cid} holds",
            "producer": P("codex"), "is_root": kw.pop("is_root", True), **kw}


def attempt(method: str, outcome: str = "PASSED", **kw) -> dict:
    return {"method": method, "outcome": outcome, **kw}


def evidence(eid: str, cid: str, producer: str = "qa", **kw) -> dict:
    return {"record_type": "evidence", "evidence_id": eid, "kind": "TEST_RESULT",
            "producer": P(producer), "supports_claims": [cid],
            "coverage_note": "what this run covered", **kw}


def counterexample(cid: str, **kw) -> dict:
    return {"record_type": "counterexample", "target_claim": cid, "result": "FOUND",
            "method": "PROPERTY_TEST", "producer": P("proofagent"),
            "detail": "a transfer of 10001 executed without approval", **kw}


#: Provenance that places a check in a group of its own.
def placed(name: str) -> dict:
    return {"toolchain": [name], "session": f"{name}-run"}


def run(tmp_path, rows, name="case", **kw):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(rows))
    return assure(str(path), **kw)


def resolved(outcome, cid):
    found = outcome.analysis.resolution.of(cid)
    assert found is not None, f"{cid} was not resolved"
    return found


def blocking(outcome):
    return {f.rule_id for f in outcome.analysis.findings if f.effect.value == "BLOCK"}


def holding(outcome):
    return {f.rule_id for f in outcome.analysis.findings if f.effect.value == "HOLD"}


# ── the rules, one by one ────────────────────────────────────────────────────

class TestTheRules:

    def test_cr01_an_open_counterexample_contradicts(self, tmp_path):
        out = run(tmp_path, [claim("c1"), evidence("e1", "c1"), counterexample("c1")])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.CONTRADICTED, "CR-01")
        assert r.of(ItemRole.COUNTEREXAMPLE)

    def test_a_resolved_counterexample_is_listed_and_does_not_contradict(self, tmp_path):
        out = run(tmp_path, [
            claim("c1", verification_attempts=[attempt("TEST_SUITE", verifier="ci")]),
            {**evidence("e-fix", "c1"), "kind": "TEST_RESULT"},
            counterexample("c1", status="RESOLVED", resolution="threshold check fixed",
                           resolution_evidence=["e-fix"])])
        r = resolved(out, "c1")
        assert r.status is not S.CONTRADICTED
        assert [i.reason for i in r.of(ItemRole.RESOLVED)] == ["threshold check fixed"]

    def test_cr02_a_failed_check_contradicts(self, tmp_path):
        out = run(tmp_path, [claim("c1", verification_attempts=[
            attempt("TEST_SUITE", verifier="ci", provenance=placed("pytest")),
            attempt("FORMAL_PROOF", "FAILED", verifier="tlc", detail="bypass at 10001")])])
        assert (resolved(out, "c1").status, resolved(out, "c1").rule) == (
            S.CONTRADICTED, "CR-02")

    def test_cr03_unresolved_evidence_against_contradicts(self, tmp_path):
        out = run(tmp_path, [
            claim("c1", verification_attempts=[attempt("TEST_SUITE", verifier="ci")]),
            {**evidence("e-against", "c1"), "supports_claims": [],
             "contradicts_claims": ["c1"]}])
        assert resolved(out, "c1").rule == "CR-03"

    def test_cr04_a_contradicted_dependency_contradicts(self, tmp_path):
        out = run(tmp_path, [
            claim("c1", depends_on=["c2"],
                  verification_attempts=[attempt("TEST_SUITE", verifier="ci")]),
            claim("c2", is_root=False, verification_attempts=[
                attempt("TEST_SUITE", "FAILED", verifier="ci")])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.CONTRADICTED, "CR-04")
        assert ("c2", "CONTRADICTED") in r.dependencies

    def test_cr05_nothing_bears_on_it_is_not_assessed(self, tmp_path):
        out = run(tmp_path, [claim("c1")])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.NOT_ASSESSED, "CR-05")
        assert "Not assessed is not passed" in r.basis

    def test_cr05_an_expected_check_that_never_ran_is_still_not_assessed(self, tmp_path):
        out = run(tmp_path, [claim("c1", verification_attempts=[
            attempt("FORMAL_PROOF", "NOT_RUN")])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.NOT_ASSESSED, "CR-05")
        assert "1 expected check(s) never ran" in r.basis

    def test_cr06_support_that_is_all_set_aside_is_unsupported(self, tmp_path):
        out = run(tmp_path, [
            {"record_type": "candidate", "components": {"commit": "bbbb2222"}},
            claim("c1", verification_attempts=[attempt(
                "TEST_SUITE", verifier="ci", result={"state": {"commit": "aaaa1111"}})])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.UNSUPPORTED, "CR-06")
        assert r.of(ItemRole.WITHHELD_STATE)

    def test_cr06_a_search_that_found_nothing_is_not_support(self, tmp_path):
        out = run(tmp_path, [claim("c1"), counterexample(
            "c1", result="NOT_FOUND", searched="10k random transfers")])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.UNSUPPORTED, "CR-06")
        assert r.of(ItemRole.SEARCHED_NOT_FOUND)

    def test_cr07_only_inconclusive_checks_are_unknown(self, tmp_path):
        out = run(tmp_path, [claim("c1", verification_attempts=[
            attempt("SIMULATION", "INCONCLUSIVE", verifier="sim")])])
        assert (resolved(out, "c1").status, resolved(out, "c1").rule) == (S.UNKNOWN, "CR-07")

    def test_cr08_a_named_gap_makes_it_partial(self, tmp_path):
        out = run(tmp_path, [
            claim("c-notrun", verification_attempts=[
                attempt("TEST_SUITE", verifier="ci"), attempt("FORMAL_PROOF", "NOT_RUN")]),
            claim("c-requires", requires=["FORMAL_PROOF"], verification_attempts=[
                attempt("TEST_SUITE", verifier="ci2")]),
            claim("c-inconclusive", verification_attempts=[
                attempt("TEST_SUITE", verifier="ci3"),
                attempt("SIMULATION", "INCONCLUSIVE", verifier="sim")])])
        for cid, words in (("c-notrun", "never ran"), ("c-requires", "requires FORMAL_PROOF"),
                           ("c-inconclusive", "no conclusion")):
            r = resolved(out, cid)
            assert (r.status, r.rule) == (S.PARTIALLY_SUPPORTED, "CR-08"), cid
            assert words in r.basis, cid

    def test_cr08_support_naming_no_part_of_a_stated_candidate_is_partial(self, tmp_path):
        out = run(tmp_path, [
            {"record_type": "candidate", "components": {"commit": "bbbb2222"}},
            claim("c1", verification_attempts=[attempt("TEST_SUITE", verifier="ci")])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.PARTIALLY_SUPPORTED, "CR-08")
        assert "names the candidate" in r.basis

    def test_cr09_a_bound_proof_establishes(self, tmp_path):
        out = run(tmp_path, [
            {"record_type": "candidate", "components": {"commit": "bbbb2222"}},
            claim("c1", verification_attempts=[attempt(
                "FORMAL_PROOF", verifier="tlc", result={"state": {"commit": "bbbb2222"}})])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.ESTABLISHED, "CR-09")
        assert "proof-carrying" in r.basis

    def test_cr09_independent_groups_of_checks_establish(self, tmp_path):
        out = run(tmp_path, [claim("c1", verification_attempts=[
            attempt("TEST_SUITE", verifier="ci", provenance=placed("pytest")),
            attempt("HUMAN_REVIEW", verifier="j.doe", provenance={"reviewer": "j.doe"})])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.ESTABLISHED, "CR-09")
        assert r.establishing_independence.independent_groups == 2

    def test_cr10_correlated_checks_support_and_do_not_establish(self, tmp_path):
        session = {"provider": "openai", "model_family": "codex", "session": "s-1"}
        out = run(tmp_path, [claim("c1", verification_attempts=[
            attempt("TEST_SUITE", verifier="codex-a", provenance=session),
            attempt("STATIC_ANALYSIS", verifier="codex-b", provenance=session)])])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.SUPPORTED, "CR-10")
        assert "1 independent group(s) and the policy asks for 2" in r.basis

    def test_cr10_a_declaration_supports_and_never_establishes(self, tmp_path):
        out = run(tmp_path, [claim("c1"), evidence("e1", "c1", "a"),
                             evidence("e2", "c1", "b"), evidence("e3", "c1", "c")])
        r = resolved(out, "c1")
        assert (r.status, r.rule) == (S.SUPPORTED, "CR-10")
        assert {i.strength for i in r.counted} == {Strength.DECLARATION}

    def test_cr11_a_conclusion_follows_its_dependencies_and_no_further(self, tmp_path):
        out = run(tmp_path, [
            claim("c-top", depends_on=["c-a", "c-b"]),
            claim("c-a", is_root=False, verification_attempts=[
                attempt("FORMAL_PROOF", verifier="tlc", provenance=placed("tlc")),
                attempt("TEST_SUITE", verifier="ci", provenance=placed("pytest"))]),
            claim("c-b", is_root=False, verification_attempts=[
                attempt("TEST_SUITE", verifier="ci2", provenance=placed("jest"))])])
        r = resolved(out, "c-top")
        assert (r.status, r.rule) == (S.SUPPORTED, "CR-11")
        assert resolved(out, "c-a").status is S.ESTABLISHED

    def test_cr11_a_partially_supported_dependency_caps_the_conclusion(self, tmp_path):
        out = run(tmp_path, [
            claim("c-top", depends_on=["c-a"]),
            claim("c-a", is_root=False, verification_attempts=[
                attempt("TEST_SUITE", verifier="ci"), attempt("FORMAL_PROOF", "NOT_RUN")])])
        assert (resolved(out, "c-top").status, resolved(out, "c-top").rule) == (
            S.PARTIALLY_SUPPORTED, "CR-11")


# ── the properties the order exists for ──────────────────────────────────────

class TestNoAveraging:

    def test_one_counterexample_outranks_five_supports(self, tmp_path):
        rows = [claim("c1")] + [evidence(f"e{i}", "c1", f"agent-{i}") for i in range(5)]
        rows.append(counterexample("c1"))
        out = run(tmp_path, rows)
        r = resolved(out, "c1")
        assert r.status is S.CONTRADICTED
        assert len(r.counted) == 5
        assert out.case.verdict.decision.value == "BLOCK"

    @pytest.mark.parametrize("extra", [1, 5, 20])
    def test_adding_support_never_moves_a_contradicted_claim(self, tmp_path, extra):
        bound = {"commit": "bbbb2222"}
        checks = [attempt("TEST_SUITE", verifier=f"ci-{i}", provenance=placed(f"tool-{i}"),
                          result={"state": bound}) for i in range(extra)]
        checks.append(attempt("FORMAL_PROOF", verifier="tlc", result={"state": bound}))
        out = run(tmp_path, [{"record_type": "candidate", "components": bound},
                             claim("c1", verification_attempts=checks),
                             counterexample("c1")])
        assert resolved(out, "c1").status is S.CONTRADICTED

    def test_a_proof_about_the_wrong_artifact_does_not_count(self, tmp_path):
        out = run(tmp_path, [
            {"record_type": "candidate",
             "components": {"artifact:transfer_tool": "sha256:" + "3" * 64}},
            claim("c1", verification_attempts=[attempt(
                "FORMAL_PROOF", verifier="tlc",
                result={"state": {"artifact:transfer_tool": "sha256:" + "2" * 64}})])])
        r = resolved(out, "c1")
        assert r.status is S.UNSUPPORTED
        [withheld] = r.of(ItemRole.WITHHELD_STATE)
        assert withheld.strength is Strength.PROOF and withheld.binding == "STALE"
        assert "RG-DRIFT-006" in holding(out)

    def test_a_missing_assessment_is_not_success(self, tmp_path):
        out = run(tmp_path, [claim("c1")])
        assert resolved(out, "c1").status is S.NOT_ASSESSED
        assert "RG-CRIT-006" in holding(out)
        assert out.case.verdict.decision.value != "PROMOTE"

    def test_a_cross_model_review_supports_and_does_not_establish(self, tmp_path):
        out = run(tmp_path, [claim("c1", verification_attempts=[
            attempt("CROSS_MODEL_REVIEW", verifier="gpt", provenance={"model_family": "gpt"}),
            attempt("CROSS_MODEL_REVIEW", verifier="claude",
                    provenance={"model_family": "claude"})])])
        assert resolved(out, "c1").status is S.SUPPORTED

    def test_evidence_outside_what_the_claim_admits_is_set_aside(self, tmp_path):
        out = run(tmp_path, [claim("c1", admissible_evidence=["FORMAL_PROOF"],
                                   verification_attempts=[attempt("TEST_SUITE", verifier="ci")])])
        r = resolved(out, "c1")
        assert r.status is S.UNSUPPORTED
        assert r.of(ItemRole.NOT_ADMISSIBLE)


class TestEveryContradictedRequiredClaimBlocks:
    """The resolver does not raise a blocking finding of its own for a contradicted
    claim: the refutation already blocks through the rule that reads it. This is
    the property that makes that safe, over every way a claim gets contradicted."""

    SHAPES = {
        "counterexample": [claim("c1"), counterexample("c1")],
        "failed check": [claim("c1", verification_attempts=[
            attempt("TEST_SUITE", "FAILED", verifier="ci")])],
        "evidence against": [
            claim("c1", verification_attempts=[attempt("TEST_SUITE", verifier="ci")]),
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
             "producer": P("qa"), "contradicts_claims": ["c1"], "coverage_note": "x"}],
        "contradicted dependency": [
            claim("c1", depends_on=["c2"]),
            claim("c2", is_root=False, verification_attempts=[
                attempt("TEST_SUITE", "FAILED", verifier="ci")])],
        "dependency counterexample": [
            claim("c1", depends_on=["c2"]),
            claim("c2", is_root=False, verification_attempts=[
                attempt("TEST_SUITE", verifier="ci")]),
            counterexample("c2")],
        "stale failed check": [
            {"record_type": "candidate", "components": {"commit": "bbbb2222"}},
            claim("c1", verification_attempts=[attempt(
                "TEST_SUITE", "FAILED", verifier="ci",
                result={"state": {"commit": "aaaa1111"}})])],
    }

    @pytest.mark.parametrize("shape", sorted(SHAPES))
    def test_it_blocks(self, tmp_path, shape):
        out = run(tmp_path, self.SHAPES[shape], name=shape.replace(" ", "_"))
        contradicted = [r for r in out.analysis.resolution.required()
                        if r.status is S.CONTRADICTED]
        assert contradicted, shape
        assert out.case.verdict.decision.value == "BLOCK", shape
        assert blocking(out), shape


# ── the example the resolver is built around ─────────────────────────────────

V3 = "sha256:" + "3" * 64
V2 = "sha256:" + "2" * 64
CANDIDATE = {"commit": "9f2c1a7e4b", "artifact:transfer_tool": V3}
TRANSFER = ("All transfers above the configured threshold require affirmative "
            "human authorization before execution")


def transfer_case(*, proof_state=None, cex=False, one_session=False):
    """Six kinds of evidence about one claim, each from where it would come from."""
    bound = {"state": dict(CANDIDATE)}
    codex = {"provider": "openai", "model_family": "codex", "session": "codex-77"}

    def prov(own):
        return codex if one_session else own

    checks = [
        # the static code path: release-gate's scanner found the approval gate
        attempt("STATIC_ANALYSIS", verifier="release_gate_static", result=bound,
                provenance=prov({"toolchain": ["release-gate-static"]})),
        # a behavioural test of a 10001 transfer
        attempt("TEST_SUITE", verifier="ci", result=bound,
                provenance=prov({"toolchain": ["pytest"], "session": "ci-981"})),
        # a ProofAgent adversarial scenario
        attempt("SIMULATION", verifier="proofagent", result=bound,
                provenance=prov({"provider": "proofagent", "model_family": "pa-sim",
                                 "session": "pa-12"})),
        # a person read the approval path
        attempt("HUMAN_REVIEW", verifier="j.doe", result=bound,
                provenance=prov({"reviewer": "j.doe"})),
    ]
    if not one_session:
        checks.append(attempt(
            "FORMAL_PROOF", verifier="tlc",
            result={"state": proof_state or dict(CANDIDATE)},
            provenance={"toolchain": ["tla+", "tlc"]}))
    rows = [
        {"record_type": "candidate", "components": CANDIDATE},
        {"record_type": "claim", "claim_id": "c-transfer", "proposition": TRANSFER,
         "producer": P("platform-team", "human"), "is_root": True,
         "verification_attempts": checks},
        # a production trace: an observation of approvals, not a check
        {"record_type": "evidence", "evidence_id": "e-trace", "kind": "TRACE",
         "producer": P("otel-collector"), "supports_claims": ["c-transfer"],
         "coverage_note": "30 days of production transfers", "state": dict(CANDIDATE)},
    ]
    if cex:
        rows.append({"record_type": "counterexample", "target_claim": "c-transfer",
                     "result": "FOUND", "method": "SIMULATION", "producer": P("proofagent"),
                     "detail": "a transfer split into two of 5001 executed without approval"})
    return rows


class TestTheTransferThresholdClaim:

    def test_every_kind_of_evidence_bound_to_the_candidate_establishes_it(self, tmp_path):
        out = run(tmp_path, transfer_case())
        r = resolved(out, "c-transfer")
        assert (r.status, r.rule) == (S.ESTABLISHED, "CR-09")
        assert r.statement == TRANSFER
        kinds = {i.strength for i in r.counted}
        assert kinds == {Strength.PROOF, Strength.EMPIRICAL, Strength.JUDGEMENT,
                         Strength.DECLARATION}
        assert r.required is True

    def test_a_proof_of_the_previous_tool_does_not_count_and_holds(self, tmp_path):
        out = run(tmp_path, transfer_case(
            proof_state={**CANDIDATE, "artifact:transfer_tool": V2}))
        r = resolved(out, "c-transfer")
        [proof] = r.of(ItemRole.WITHHELD_STATE)
        assert proof.strength is Strength.PROOF and proof.binding == "STALE"
        # Still established, by the four independent checks, and not by the proof.
        assert r.status is S.ESTABLISHED
        assert "independent group" in r.basis and "proof" not in r.basis
        assert "RG-DRIFT-006" in holding(out)

    def test_the_proofagent_counterexample_outranks_everything_else(self, tmp_path):
        out = run(tmp_path, transfer_case(cex=True))
        r = resolved(out, "c-transfer")
        assert (r.status, r.rule) == (S.CONTRADICTED, "CR-01")
        assert len(r.counted) == 6
        assert out.case.verdict.decision.value == "BLOCK"

    def test_the_same_checks_from_one_model_session_only_support_it(self, tmp_path):
        out = run(tmp_path, transfer_case(one_session=True))
        r = resolved(out, "c-transfer")
        assert (r.status, r.rule) == (S.SUPPORTED, "CR-10")
        assert r.establishing_independence.status.value == "CORRELATED"
        assert r.establishing_independence.independent_groups == 1
        assert "RG-INDEP-005" in {f.rule_id for f in out.analysis.findings}

    def test_the_text_report_shows_the_claim_and_its_rule(self, tmp_path):
        text = render_text(run(tmp_path, transfer_case(cex=True)))
        assert "CLAIMS (1), resolved under rg-resolution@1" in text
        assert "c-transfer  CR-01  (required)" in text


# ── the policy ───────────────────────────────────────────────────────────────

class TestThePolicy:

    def test_admission_at_established_holds_a_supported_required_claim(self, tmp_path):
        rows = [claim("c1"), evidence("e1", "c1")]
        default = run(tmp_path, rows, name="default")
        assert resolved(default, "c1").status is S.SUPPORTED
        assert "RG-CRIT-006" not in holding(default)
        strict = run(tmp_path, rows, name="strict", resolution_policy=ResolutionPolicy(
            policy_id="strict", admission_level=S.ESTABLISHED))
        assert "RG-CRIT-006" in holding(strict)

    def test_more_groups_required_means_two_is_not_enough(self, tmp_path):
        rows = [claim("c1", verification_attempts=[
            attempt("TEST_SUITE", verifier="ci", provenance=placed("pytest")),
            attempt("HUMAN_REVIEW", verifier="j.doe", provenance={"reviewer": "j.doe"})])]
        assert resolved(run(tmp_path, rows, name="two"), "c1").status is S.ESTABLISHED
        three = ResolutionPolicy(policy_id="three", independence=IndependencePolicy(
            policy_id="three", min_independent_groups=3))
        assert resolved(run(tmp_path, rows, name="three", resolution_policy=three),
                        "c1").status is S.SUPPORTED

    def test_a_proof_need_not_establish_alone(self, tmp_path):
        rows = [{"record_type": "candidate", "components": {"commit": "bbbb2222"}},
                claim("c1", verification_attempts=[attempt(
                    "FORMAL_PROOF", verifier="tlc", provenance=placed("tlc"),
                    result={"state": {"commit": "bbbb2222"}})])]
        policy = ResolutionPolicy(policy_id="corroborate", proof_establishes_alone=False)
        assert resolved(run(tmp_path, rows, resolution_policy=policy),
                        "c1").status is S.SUPPORTED

    @pytest.mark.parametrize("bad", [
        {"admission_level": "PARTIALLY_SUPPORTED"},
        {"admission_level": "NOT_ASSESSED"},
        {"establishing": ["DECLARATION"]},
        {"establishing": ["UNCLASSIFIED", "PROOF"]},
        {"establishing": ["NOT_A_KIND"]},
        {"independence": "strict"},
    ])
    def test_a_policy_that_would_admit_too_little_is_refused(self, bad):
        with pytest.raises(ResolutionError):
            ResolutionPolicy.from_dict({"policy_id": "loose", **bad})

    @pytest.mark.parametrize("bad", [
        {"min_independent_groups": 0},
        {"correlate_on": ["model_family"]},
    ])
    def test_an_independence_policy_that_would_invent_independence_is_refused(self, bad):
        with pytest.raises((IndependenceError, ResolutionError)):
            ResolutionPolicy.from_dict({"policy_id": "loose", "independence": bad})

    def test_the_policy_is_recorded_on_the_case_and_read_back(self, tmp_path):
        policy = ResolutionPolicy(policy_id="acme", version="4",
                                  admission_level=S.ESTABLISHED)
        out = run(tmp_path, [claim("c1")], resolution_policy=policy)
        assert ResolutionPolicy.from_dict(out.case.metadata[POLICY_METADATA_KEY]) == policy
        assert policy_for_case(out.case) == policy
        assert out.analysis.resolution.policy == policy

    def test_without_a_policy_the_default_is_recorded_not_left_implicit(self, tmp_path):
        rows = [claim("c1")]
        one = policy_for_case(run(tmp_path, rows, name="one").case)
        other = policy_for_case(run(tmp_path, rows, name="other", resolution_policy=(
            ResolutionPolicy(policy_id="other"))).case)
        assert one == DEFAULT_RESOLUTION_POLICY and other.policy_id == "other"
        assert one.digest() != other.digest()

    def test_a_policy_round_trips(self):
        policy = ResolutionPolicy(
            policy_id="acme", version="2", proof_establishes_alone=False,
            establishing=(Strength.PROOF, Strength.MECHANICAL),
            admission_level=S.ESTABLISHED,
            independence=IndependencePolicy(
                policy_id="acme-ind", min_independent_groups=3,
                correlate_on=tuple(DEFAULT_RESOLUTION_POLICY.independence.correlate_on)
                + ("provider",)))
        assert ResolutionPolicy.from_dict(policy.to_dict()) == policy
        assert ResolutionPolicy.from_dict(policy.to_dict()).digest() == policy.digest()


# ── reproducible ─────────────────────────────────────────────────────────────

class TestDeterminism:

    def test_the_same_case_resolves_the_same_way(self, tmp_path):
        # The same file: an evidence id is content-addressed over its source too.
        rows = transfer_case(cex=True)
        first = run(tmp_path, rows).analysis.resolution.to_dict()
        second = run(tmp_path, rows).analysis.resolution.to_dict()
        assert first == second

    @staticmethod
    def _shape(report):
        return [(r.claim_id, r.status, r.rule, r.basis,
                 sorted((i.item_kind, i.role.value, i.strength.value if i.strength else "",
                         i.binding) for i in r.items),
                 r.establishing_independence.to_dict()["independent_groups"])
                for r in report.resolutions]

    def test_the_order_of_the_rows_does_not_matter(self, tmp_path):
        rows = transfer_case(proof_state={**CANDIDATE, "artifact:transfer_tool": V2})
        forward = run(tmp_path, rows, name="forward").analysis.resolution
        backward = run(tmp_path, list(reversed(rows)), name="backward").analysis.resolution
        assert self._shape(forward) == self._shape(backward)

    def test_it_is_in_the_outcome_and_reads_back_from_the_dict(self, tmp_path):
        out = run(tmp_path, transfer_case())
        block = out.to_dict()["analysis"]["claim_resolution"]
        assert block["by_status"]["ESTABLISHED"] == 1
        assert block["policy"] == "rg-resolution@1"
        [row] = block["resolutions"]
        assert row["claim_id"] == "c-transfer" and row["rule"] == "CR-09"
        assert row["establishing_independence"]["status"] == "INDEPENDENT"


# ── where a person reads it ──────────────────────────────────────────────────

class TestWhereItIsShown:

    def test_the_review_lists_required_and_contradicted_claims(self, tmp_path):
        from release_gate.assurance.review import build_review, render_review
        out = run(tmp_path, [claim("c-ok", verification_attempts=[
                                 attempt("TEST_SUITE", verifier="ci")]),
                             claim("c-bad", is_root=False), counterexample("c-bad")])
        review = build_review(out)
        assert review.claim_policy == "rg-resolution@1"
        assert [line.claim_id for line in review.claim_lines] == ["c-bad", "c-ok"]
        assert review.claim_lines[0].status == "CONTRADICTED"
        text = render_review(review)
        assert "CLAIMS" in text and "[CONTRADICTED] c-bad  CR-01" in text

    def test_the_api_view_carries_each_claim_and_its_grouping(self, tmp_path):
        from release_gate_api._app import _claims_view
        view = _claims_view(run(tmp_path, transfer_case(one_session=True)))
        assert view["claims_total"] == 1 and view["admission_level"] == "SUPPORTED"
        [row] = view["claims"]
        assert row["status"] == "SUPPORTED" and row["rule"] == "CR-10"
        assert row["independence"]["status"] == "CORRELATED"
        assert {i["role"] for i in row["items"]} == {"SUPPORTS"}

    def test_the_demo_page_renders_the_claims_view(self):
        page = open("public/assurance.html", encoding="utf-8").read()
        assert "const cl = d.claims" in page and "${claims}" in page

    @staticmethod
    def _coverage(outcome):
        return {r.to_dict().get("dimension"): r.to_dict()
                for r in outcome.case.collection("coverage").materialised}

    def test_no_claims_means_the_coverage_row_says_not_assessed(self, tmp_path):
        row = self._coverage(run(tmp_path, [evidence("e1", "nothing")]))["claim_resolution"]
        assert row["status"] == "NOT_ASSESSED"

    def test_claims_mean_the_coverage_row_counts_them(self, tmp_path):
        row = self._coverage(run(tmp_path, transfer_case()))["claim_resolution"]
        assert row["status"] == "ASSESSED"
        assert row["ESTABLISHED"] == 1 and row["policy"] == "rg-resolution@1"


class TestTheCommandLine:

    @staticmethod
    def _cli(*args):
        return subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", *args],
                              capture_output=True, text=True, timeout=300)

    def test_resolution_policy_is_read_and_applied(self, tmp_path):
        case = tmp_path / "case.json"
        case.write_text(json.dumps([claim("c1"), evidence("e1", "c1")]))
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps({"policy_id": "strict", "version": "3",
                                      "admission_level": "ESTABLISHED"}))
        result = self._cli(str(case), "--resolution-policy", str(policy), "--full")
        assert "resolved under strict@3" in result.stdout
        assert "RG-CRIT-006" in result.stdout
        assert result.returncode != 0

    @pytest.mark.parametrize("body", [{"establishing": ["DECLARATION"]}, ["not", "an", "object"]])
    def test_an_unusable_policy_is_refused_not_ignored(self, tmp_path, body):
        case = tmp_path / "case.json"
        case.write_text(json.dumps([claim("c1")]))
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps(body))
        result = self._cli(str(case), "--resolution-policy", str(policy))
        assert result.returncode == 1
        assert "not a readable resolution policy" in result.stdout
