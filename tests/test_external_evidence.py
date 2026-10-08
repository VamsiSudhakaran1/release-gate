"""External evidence through generic contracts — read, never re-run, never re-competed with.

Pinned here, against release_gate/assurance/reference_adapters.py, the formal
schema in verifiers.py, the `producer_export` envelope record and origin.py:

* each class of evidence has one documented contract (eval, red team, SAST,
  human review, formal verification), detected only by name and never by
  resemblance;
* a successful attack is a counterexample to the claim it targeted, and blocks a
  critical claim however many attacks were blocked beside it; a blocked attack
  supports and never establishes;
* a review names its reviewer, role, state and expiry, and an expiry nobody can
  check against a stated time is not a pass;
* a proof binds to the state and artifact it names, and its assumptions are
  carried as limits;
* one envelope composes many producers' exports about one set of claims, read
  exactly as their files are;
* every report says whose evidence it is, and that release-gate ran none of the
  tools it names.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from release_gate.assurance.evidence import (EpistemicStatus, EvidenceRecord, EvidenceType,
                                             Producer)
from release_gate.assurance.quality import model_assisted_evidence
from release_gate.assurance.origin import OriginKind, evidence_origin
from release_gate.assurance.producer_contract import (AdapterOutput, NativeResult,
                                                      ProducerContractError,
                                                      ProducerIdentity, ResultKind,
                                                      check_adapter_contract,
                                                      normalise_output)
from release_gate.assurance.reference_adapters import (EVAL_DECLARATION,
                                                       RED_TEAM_DECLARATION,
                                                       REFERENCE_SCHEMAS,
                                                       reference_adapters)
from release_gate.assurance.resolution import ResolutionStatus
from release_gate.assurance.verification import VerificationStatus
from release_gate.assurance.zero_config import assure, render_text

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "evidence"
COMMIT = "9f2c1a7e"


def example(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def run(tmp_path, doc, name="input.json", **kw):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return assure(str(path), **kw)


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def resolved(outcome, claim_id):
    return outcome.analysis.resolution.of(claim_id)


def claim(outcome, claim_id):
    return next(c for c in outcome.normalisation.claims if c.claim_id == claim_id)


def by_native(outcome, native_id):
    return next(e for e in outcome.normalisation.evidence
                if (e.content or {}).get("native_id") == native_id)


def envelope(*exports, claims=(), candidate=None):
    rows = []
    if candidate is not None:
        rows.append({"record_type": "candidate", "components": candidate})
    rows += list(claims)
    rows += [{"record_type": "producer_export", "source": name, "document": doc}
             for name, doc in exports]
    return rows


def critical(claim_id, statement="the claim"):
    return {"record_type": "claim", "claim_id": claim_id, "is_root": True,
            "proposition": statement,
            "producer": {"producer_id": "owners", "kind": "human"}}


# ── the contracts ────────────────────────────────────────────────────────────

class TestEveryContractIsAContract:

    @pytest.mark.parametrize("adapter", reference_adapters(), ids=lambda a: a.name)
    def test_each_holds_the_producer_contract_on_its_shipped_example(self, adapter):
        sample = {"eval": "eval.json", "red_team": "red-team.json",
                  "sast": "sast.json", "human_review": "review.json",
                  "behavior": "behavior.json"}[adapter.name]
        report = check_adapter_contract(adapter, example(sample))
        assert report.holds, report.violations

    @pytest.mark.parametrize("adapter", reference_adapters(), ids=lambda a: a.name)
    def test_nothing_is_read_by_resemblance(self, adapter):
        sample = {"eval": "eval.json", "red_team": "red-team.json",
                  "sast": "sast.json", "human_review": "review.json",
                  "behavior": "behavior.json"}[adapter.name]
        doc = example(sample)
        doc.pop("schema")
        assert adapter.detect(doc) == 0
        doc["schema"] = doc.get("schema", "") + "release-gate.eval/2"
        assert adapter.detect(doc) == 0

    def test_the_six_schemas_are_named_in_one_place(self):
        assert REFERENCE_SCHEMAS == ("release-gate.eval/1", "release-gate.red-team/1",
                                     "release-gate.sast/1", "release-gate.review/1",
                                     "release-gate.formal/1", "release-gate.behavior/1")

    def test_every_shipped_example_is_recognised_as_its_own_contract(self, tmp_path):
        expected = {"eval.json": "PRODUCER_EXPORT:eval",
                    "red-team.json": "PRODUCER_EXPORT:red_team",
                    "sast.json": "PRODUCER_EXPORT:sast",
                    "review.json": "PRODUCER_EXPORT:human_review",
                    "behavior.json": "PRODUCER_EXPORT:behavior",
                    "formal.json": "VERIFIER_REPORT"}
        from release_gate.assurance.ingest import detect_document
        for name, kind in expected.items():
            detection = detect_document(example(name), filename=name)
            label = (f"{detection.kind.value}:{detection.adapter}"
                     if detection.kind.value == "PRODUCER_EXPORT" else detection.kind.value)
            assert label == kind, name

    def test_the_ingest_names_none_of_them(self):
        source = (ROOT / "release_gate/assurance/ingest.py").read_text(encoding="utf-8")
        for producer_type in ("red_team", "human_review", "sast", "release-gate.eval"):
            assert f'"{producer_type}"' not in source, producer_type


# ── eval ─────────────────────────────────────────────────────────────────────

class TestEval:

    def test_each_case_is_a_declared_check_of_the_claim_it_names(self, tmp_path):
        outcome = run(tmp_path, example("eval.json"))
        held = claim(outcome, "cl_refund_policy")
        statuses = sorted(a.status.value for a in held.verification_attempts)
        assert statuses == ["FAILED", "PASSED", "PASSED"]
        for record in outcome.normalisation.evidence:
            if record.content.get("producer_type") == "eval":
                assert record.epistemic_status is EpistemicStatus.DECLARED

    def test_three_cases_about_one_claim_are_one_claim(self, tmp_path):
        outcome = run(tmp_path, example("eval.json"))
        assert [c.claim_id for c in outcome.normalisation.claims] == ["cl_refund_policy"]

    def test_a_failed_case_is_not_averaged_with_the_passes(self, tmp_path):
        outcome = run(tmp_path, example("eval.json"))
        assert resolved(outcome, "cl_refund_policy").status is ResolutionStatus.CONTRADICTED
        text = render_text(outcome, full=True) + json.dumps(outcome.to_dict(), default=str)
        assert "66%" not in text and "67%" not in text and "0.66" not in text

    def test_the_harness_totals_stay_its_count(self, tmp_path):
        outcome = run(tmp_path, example("eval.json"))
        summary = by_native(outcome, "summary")
        assert summary.content["measurement"] == {
            "count": 2, "of": 3, "unit": "eval cases", "outcome": "passed",
            "denominator_basis": "acme-evals's own summary"}

    @pytest.mark.parametrize("word,status", [("error", "FAILED"), ("skipped", "NOT_RUN"),
                                             ("timeout", "INCONCLUSIVE"),
                                             ("looks fine", "UNKNOWN")])
    def test_no_outcome_word_but_a_pass_passes(self, tmp_path, word, status):
        doc = example("eval.json")
        doc["cases"] = [dict(doc["cases"][0], outcome=word)]
        doc.pop("summary")
        attempt = claim(run(tmp_path, doc), "cl_refund_policy").verification_attempts[0]
        assert attempt.status.value == status

    def test_a_case_without_a_claim_is_its_own(self, tmp_path):
        doc = {"schema": "release-gate.eval/1", "producer": {"id": "h"},
               "cases": [{"id": "c-1", "outcome": "passed"}]}
        outcome = run(tmp_path, doc)
        assert outcome.normalisation.claims[0].statement == "eval case 'c-1' passes"


# ── red team ─────────────────────────────────────────────────────────────────

def red_team(*attacks, target="cl_authz"):
    return {"schema": "release-gate.red-team/1",
            "producer": {"id": "red-team", "version": "1"},
            "state": {"commit": COMMIT},
            "provenance": {"session": "rt-1", "model_family": "attacker"},
            "target_claim_id": target,
            "attacks": list(attacks)}


def attack(i, outcome, **more):
    return {"id": f"atk-{i}", "class": "indirect_injection", "outcome": outcome, **more}


class TestRedTeam:

    def test_a_success_is_a_counterexample_to_its_target(self, tmp_path):
        outcome = run(tmp_path, example("red-team.json"))
        record = by_native(outcome, "atk-017")
        assert record.evidence_type is EvidenceType.COUNTEREXAMPLE
        assert record.contradicts_claims == ("cl_no_unauthorised_transfer",)
        assert record.content["native_outcome"] == "succeeded"
        assert record.content["claim_outcome"] == "failed"
        [found] = outcome.counterexamples.attempts
        assert found.target_claim == "cl_no_unauthorised_transfer"
        assert found.result.value == "FOUND" and found.state == {
            "commit": COMMIT, "environment": "staging"}

    def test_a_blocked_attack_supports_and_is_never_a_check(self, tmp_path):
        outcome = run(tmp_path, example("red-team.json"))
        record = by_native(outcome, "atk-002")
        assert record.supports_claims == ("cl_no_unauthorised_transfer",)
        assert record.evidence_type is EvidenceType.EVAL_RESULT
        held = claim(outcome, "cl_no_unauthorised_transfer")
        assert held.verification_attempts == ()

    def test_unsettled_attacks_bear_on_nothing(self, tmp_path):
        outcome = run(tmp_path, red_team(attack(1, "timeout"), attack(2, "partial"),
                                         attack(3, "pwned"), attack(4, "skipped")))
        for i in range(1, 5):
            record = by_native(outcome, f"atk-{i}")
            assert record.supports_claims == () and record.contradicts_claims == ()
        assert not outcome.counterexamples.attempts

    def test_one_success_outweighs_a_thousand_blocked_attacks(self, tmp_path):
        doc = red_team(*[attack(i, "blocked") for i in range(1000)],
                       attack(1000, "succeeded", reproduction={"steps": ["x"]}))
        outcome = run(tmp_path, envelope(("rt.json", doc),
                                         claims=[critical("cl_authz")]))
        r = resolved(outcome, "cl_authz")
        assert r.status is ResolutionStatus.CONTRADICTED and r.rule == "CR-01"
        assert "RG-CEX-001" in rules(outcome)
        assert outcome.decision.value == "BLOCK"

    def test_a_thousand_blocked_attacks_never_establish(self, tmp_path):
        doc = red_team(*[attack(i, "blocked") for i in range(1000)])
        outcome = run(tmp_path, envelope(("rt.json", doc),
                                         claims=[critical("cl_authz")]))
        assert resolved(outcome, "cl_authz").status is not ResolutionStatus.ESTABLISHED
        assert outcome.decision.value != "PROMOTE"

    def test_a_success_with_no_target_is_its_own_claim_and_still_breaks_it(self, tmp_path):
        doc = red_team(attack(9, "succeeded"), target=None)
        doc.pop("target_claim_id")
        outcome = run(tmp_path, doc)
        [built] = outcome.normalisation.claims
        assert built.statement == ("attack 'atk-9' does not succeed against the system "
                                   "under test")
        assert outcome.counterexamples.attempts[0].target_claim == built.claim_id

    def test_a_success_without_a_reproduction_still_stands_and_is_said(self, tmp_path):
        outcome = run(tmp_path, red_team(attack(5, "succeeded")))
        assert outcome.counterexamples.attempts
        assert any("records no reproduction" in n for n in outcome.normalisation.notes)

    def test_the_attack_class_is_what_it_covers(self, tmp_path):
        outcome = run(tmp_path, red_team(attack(1, "blocked")))
        assert by_native(outcome, "atk-1").content["covers"] == {
            "adversarial_class": "indirect_injection"}

    def test_the_attackers_provenance_travels(self, tmp_path):
        outcome = run(tmp_path, red_team(attack(1, "blocked")))
        assert by_native(outcome, "atk-1").content["provenance"] == {
            "session": "rt-1", "model_family": "attacker"}


# ── SAST ─────────────────────────────────────────────────────────────────────

class TestSast:

    def test_a_finding_stays_the_tools_rule_at_the_tools_severity(self, tmp_path):
        outcome = run(tmp_path, example("sast.json"))
        record = by_native(outcome, "PY-SQLI-001")
        assert record.content["native_severity"] == "HIGH"
        assert record.content["location"] == {"file": "src/ledger/query.py",
                                              "start_line": 42}
        assert record.producer.producer_id == "acme-sast"
        assert record.supports_claims == () and record.contradicts_claims == ()

    def test_a_suppressed_finding_is_kept_as_suppressed(self, tmp_path):
        outcome = run(tmp_path, example("sast.json"))
        assert by_native(outcome, "PY-LOG-007").content["native_outcome"] == "suppressed"

    def test_the_scan_scope_is_said_and_its_absence_too(self, tmp_path):
        outcome = run(tmp_path, example("sast.json"))
        assert any("states it scanned src/" in n for n in outcome.normalisation.notes)
        doc = example("sast.json")
        doc.pop("scanned")
        outcome = run(tmp_path, doc)
        assert any("does not state what it scanned" in n
                   for n in outcome.normalisation.notes)


# ── human review ─────────────────────────────────────────────────────────────

def review(decision="approve", **more):
    row = {"id": "rev-1", "reviewer": {"id": "dana@example.com", "role": "owner"},
           "decision": decision, "claim_id": "cl_x", "claim": "x holds",
           "state": {"commit": COMMIT}, **more}
    return {"schema": "release-gate.review/1", "reviews": [row]}


class TestHumanReview:

    @pytest.mark.parametrize("word,status", [("approve", "PASSED"),
                                             ("changes_requested", "FAILED"),
                                             ("reject", "FAILED"),
                                             ("comment", "INCONCLUSIVE"),
                                             ("thumbs-up", "INCONCLUSIVE")])
    def test_a_decision_is_a_human_review_of_the_claim(self, tmp_path, word, status):
        attempt = claim(run(tmp_path, review(word)), "cl_x").verification_attempts[0]
        assert attempt.method.value == "HUMAN_REVIEW"
        # An unlisted word is never read as an approval.
        assert attempt.status.value == status

    def test_the_reviewer_is_the_producer_and_the_provenance(self, tmp_path):
        record = run(tmp_path, review()).normalisation.evidence[1]
        assert record.producer.producer_id == "dana@example.com"
        assert record.content["provenance"]["reviewer"] == "dana@example.com"
        assert record.metadata["origin"] == "human reviewer (owner)"

    def test_a_review_of_no_claim_is_recorded_and_adopted_as_nothing(self, tmp_path):
        doc = review()
        doc["reviews"][0].pop("claim_id")
        doc["reviews"][0].pop("claim")
        outcome = run(tmp_path, doc)
        assert outcome.normalisation.claims == ()
        record = outcome.normalisation.evidence[1]
        assert record.content["external_decision"]["is_release_gate_verdict"] is False

    def test_an_expired_approval_is_not_a_pass(self, tmp_path):
        doc = review(expires_at="2026-10-01T00:00:00Z")
        doc["evaluated_at"] = "2026-10-03T00:00:00Z"
        attempt = claim(run(tmp_path, doc), "cl_x").verification_attempts[0]
        assert attempt.status is VerificationStatus.INCONCLUSIVE

    def test_an_expiry_nobody_can_check_is_not_a_pass(self, tmp_path):
        outcome = run(tmp_path, review(expires_at="2026-12-01T00:00:00Z"))
        attempt = claim(outcome, "cl_x").verification_attempts[0]
        assert attempt.status is VerificationStatus.INCONCLUSIVE
        assert any("does not read a clock" in n for n in outcome.normalisation.notes)

    def test_an_approval_inside_its_window_passes(self, tmp_path):
        doc = review(expires_at="2026-12-01T00:00:00Z")
        doc["evaluated_at"] = "2026-10-03T00:00:00Z"
        attempt = claim(run(tmp_path, doc), "cl_x").verification_attempts[0]
        assert attempt.status is VerificationStatus.PASSED

    def test_an_approval_of_another_commit_does_not_count(self, tmp_path):
        doc = review(state={"commit": "0000aaaa"})
        outcome = run(tmp_path, envelope(("review.json", doc),
                                         claims=[critical("cl_x", "x holds")],
                                         candidate={"commit": COMMIT}))
        binding = outcome.analysis.state_binding
        assert binding.withheld_attempts
        assert resolved(outcome, "cl_x").status is not ResolutionStatus.ESTABLISHED

    def test_a_state_hash_binds_the_review(self, tmp_path):
        digest = "sha256:" + "ab" * 32
        doc = review(state_hash=digest)
        doc["reviews"][0].pop("state")
        record = run(tmp_path, doc).normalisation.evidence[1]
        assert record.applies_to_digest == digest
        attempt = claim(run(tmp_path, doc), "cl_x").verification_attempts[0]
        assert attempt.target_digest == digest
        assert "state" not in attempt.result


# ── formal verification ──────────────────────────────────────────────────────

class TestFormal:

    def test_a_row_stating_its_claim_makes_a_declared_claim_it_checks(self, tmp_path):
        outcome = run(tmp_path, example("formal.json"))
        held = claim(outcome, "cl_no_overdraft")
        [attempt] = held.verification_attempts
        assert attempt.method.value == "FORMAL_PROOF" and attempt.status.value == "PASSED"
        assert attempt.result["proof_artifact"]["locator"].startswith("s3://")
        assert attempt.result["assumptions"] == [
            "the bank adapter debits at most once per request",
            "account balances fit in 64 bits"]

    def test_assumptions_are_limits_on_what_it_covers(self, tmp_path):
        report = run(tmp_path, example("formal.json")).normalisation.verifier_report
        assert ("anything that depends on the assumption: account balances fit in 64 bits"
                in report.coverage.does_not_cover)

    def test_the_artifact_binds_as_a_candidate_component(self, tmp_path):
        attempt = claim(run(tmp_path, example("formal.json")),
                        "cl_no_overdraft").verification_attempts[0]
        assert attempt.result["state"]["artifact:spec/Ledger.tla"].startswith("sha256:")
        assert attempt.target_digest is None

    def test_a_proof_of_another_version_of_the_spec_does_not_establish(self, tmp_path):
        doc = example("formal.json")
        outcome = run(tmp_path, envelope(
            ("formal.json", doc), claims=[critical("cl_no_overdraft")],
            candidate={"commit": COMMIT,
                       "artifact:spec/Ledger.tla": "sha256:" + "cd" * 32}))
        assert resolved(outcome, "cl_no_overdraft").status is not \
            ResolutionStatus.ESTABLISHED
        assert outcome.analysis.state_binding.withheld_attempts

    def test_a_proof_of_this_state_establishes(self, tmp_path):
        outcome = run(tmp_path, envelope(
            ("formal.json", example("formal.json")),
            claims=[critical("cl_no_overdraft")], candidate={"commit": COMMIT}))
        assert resolved(outcome, "cl_no_overdraft").status is ResolutionStatus.ESTABLISHED

    def test_an_unclassified_method_establishes_nothing(self, tmp_path):
        doc = example("formal.json")
        doc["results"][0]["method"] = "VIBES"
        outcome = run(tmp_path, envelope(("formal.json", doc),
                                         claims=[critical("cl_no_overdraft")],
                                         candidate={"commit": COMMIT}))
        attempt = claim(outcome, "cl_no_overdraft").verification_attempts[0]
        assert attempt.method.value == "OTHER"
        assert resolved(outcome, "cl_no_overdraft").status is not \
            ResolutionStatus.ESTABLISHED

    def test_a_solver_that_gave_up_is_not_a_pass(self, tmp_path):
        doc = example("formal.json")
        doc["results"][0]["result"] = "unknown"
        attempt = claim(run(tmp_path, doc), "cl_no_overdraft").verification_attempts[0]
        assert attempt.status is VerificationStatus.INCONCLUSIVE


# ── composition ──────────────────────────────────────────────────────────────

class TestOneEnvelopeManyProducers:

    def test_the_shipped_release_blocks_on_the_red_teams_counterexample(self):
        outcome = assure(str(EXAMPLES / "release.jsonl"))
        assert outcome.decision.value == "BLOCK"
        assert "RG-CEX-001" in rules(outcome)
        assert resolved(outcome, "cl_no_unauthorised_transfer").rule == "CR-01"
        assert resolved(outcome, "cl_no_overdraft").status is ResolutionStatus.ESTABLISHED
        assert sorted(c.claim_id for c in outcome.normalisation.claims) == [
            "cl_no_overdraft", "cl_no_unauthorised_transfer", "cl_refund_policy"]
        assert outcome.normalisation.records_mapped == outcome.normalisation.records_seen

    def test_an_exports_claim_is_the_claim_the_envelope_declares(self, tmp_path):
        outcome = run(tmp_path, envelope(
            ("rt.json", red_team(attack(1, "blocked"))),
            claims=[critical("cl_authz", "nobody moves money unasked")]))
        [held] = outcome.normalisation.claims
        assert held.statement == "nobody moves money unasked" and held.is_root
        assert len(held.supporting_evidence) == 1

    def test_an_export_means_what_its_file_means(self, tmp_path):
        alone = run(tmp_path, example("red-team.json"))
        inside = run(tmp_path, envelope(("red-team.json", example("red-team.json"))),
                     name="env.json")

        def readings(outcome):
            return sorted((e.content.get("native_id"), e.evidence_type.value,
                           e.supports_claims, e.contradicts_claims)
                          for e in outcome.normalisation.evidence
                          if e.content.get("producer_type") == "red_team")
        assert readings(alone) == readings(inside)

    def test_the_same_export_twice_is_absorbed_not_counted_twice(self, tmp_path):
        doc = red_team(attack(1, "blocked"))
        outcome = run(tmp_path, envelope(("a.json", doc), ("a.json", copy.deepcopy(doc)),
                                         claims=[critical("cl_authz")]))
        ids = [e.evidence_id for e in outcome.normalisation.evidence]
        assert len(ids) == len(set(ids))
        assert any("absorbed" in n for n in outcome.normalisation.notes)

    def test_an_envelope_inside_an_envelope_is_not_read(self, tmp_path):
        outcome = run(tmp_path, envelope(("inner", [critical("cl_y")]),
                                         claims=[critical("cl_authz")]))
        assert outcome.normalisation.skipped == {
            "producer_export is not a producer's document": 1}
        assert [c.claim_id for c in outcome.normalisation.claims] == ["cl_authz"]

    def test_a_named_producer_that_is_not_registered_is_refused(self, tmp_path):
        rows = envelope(claims=[critical("cl_authz")]) + [{
            "record_type": "producer_export", "producer_type": "acme_unknown",
            "document": red_team(attack(1, "blocked"))}]
        outcome = run(tmp_path, rows)
        assert "producer_export could not be read" in outcome.normalisation.skipped
        assert any("no adapter for 'acme_unknown'" in n for n in outcome.normalisation.notes)

    def test_an_export_with_no_document_is_refused(self, tmp_path):
        rows = envelope(claims=[critical("cl_authz")]) + [
            {"record_type": "producer_export", "document": "sarif.json"}]
        outcome = run(tmp_path, rows)
        assert outcome.normalisation.skipped == {"producer_export carries no document": 1}

    def test_a_verifier_check_joins_the_claim_it_targets(self, tmp_path):
        doc = {"verifier": {"name": "lean", "version": "4", "family": "PROOF_ASSISTANT"},
               "results": [{"target": "cl_authz", "result": "proved",
                            "state": {"commit": COMMIT}}]}
        outcome = run(tmp_path, envelope(("lean.json", doc),
                                         claims=[critical("cl_authz")],
                                         candidate={"commit": COMMIT}))
        held = claim(outcome, "cl_authz")
        assert [a.method.value for a in held.verification_attempts] == ["THEOREM_PROVER"]
        assert resolved(outcome, "cl_authz").status is ResolutionStatus.ESTABLISHED


# ── the producer contract's additions ────────────────────────────────────────

class TestContractAdditions:

    def test_a_claim_outcome_needs_a_claim(self):
        with pytest.raises(ProducerContractError, match="proposes no claim"):
            NativeResult(kind=ResultKind.OBSERVATION, native_id="x", claim_outcome="failed")

    def test_an_observation_is_never_a_verification_attempt(self):
        output = AdapterOutput(identity=ProducerIdentity("h"), results=(
            NativeResult(kind=ResultKind.OBSERVATION, native_id="o", native_outcome="ok",
                         evidence_type=EvidenceType.EVAL_RESULT,
                         claim_statement="it holds", claim_id="c", claim_outcome="passed",
                         native={"a": 1}),))
        result = normalise_output(output, EVAL_DECLARATION, source="s")
        [built] = result.claims
        assert built.verification_attempts == () and built.supporting_evidence

    def test_a_finding_bears_on_its_claim_through_evidence_alone(self):
        output = AdapterOutput(identity=ProducerIdentity("rt"), results=(
            NativeResult(kind=ResultKind.FINDING, native_id="f", native_outcome="succeeded",
                         evidence_type=EvidenceType.COUNTEREXAMPLE,
                         claim_statement="it holds", claim_id="c", claim_outcome="failed",
                         native={"a": 1}),))
        [built] = normalise_output(output, RED_TEAM_DECLARATION, source="s").claims
        assert built.verification_attempts == () and built.contradicting_evidence

    def test_two_wordings_of_one_claim_keep_the_first_and_say_so(self):
        output = AdapterOutput(identity=ProducerIdentity("h"), results=tuple(
            NativeResult(kind=ResultKind.CHECK, native_id=f"c{i}", native_outcome="passed",
                         claim_statement=text, claim_id="c", native={"i": i})
            for i, text in enumerate(("it holds", "it really holds"))))
        result = normalise_output(output, EVAL_DECLARATION, source="s")
        [built] = result.claims
        assert built.statement == "it holds" and len(built.verification_attempts) == 2
        assert any("stated twice in different words" in n for n in result.notes)


# ── origin ───────────────────────────────────────────────────────────────────

class TestEvidenceOrigin:

    def test_every_report_says_release_gate_ran_none_of_the_tools(self):
        outcome = assure(str(EXAMPLES / "release.jsonl"))
        origin = outcome.to_dict()["evidence_origin"]
        assert origin["read_not_run"] == ["acme-evals", "acme-red-team", "acme-sast",
                                          "dana@example.com", "sam@example.com",
                                          "tlc@2.19"]
        for entry in origin["entries"]:
            if entry["producer_id"] in origin["read_not_run"]:
                assert entry["release_gate_ran_it"] is False
        text = render_text(outcome)
        assert "EVIDENCE ORIGIN — release-gate read 6 producer(s)' evidence and ran " \
               "none of them" in text
        assert ("release-gate did not run acme-red-team, re-run its checks or re-grade "
                "its results") in text
        assert "dana@example.com's review as recorded" in text

    def test_the_review_screen_says_it_too(self):
        from release_gate.assurance.review import build_review, render_review
        screen = render_review(build_review(assure(str(EXAMPLES / "release.jsonl"))))
        assert "EVIDENCE ORIGIN" in screen and "acme-red-team@0.9.4 (read; not run here)" \
            in screen

    def test_a_document_attributed_to_release_gate_is_read_not_computed(self):
        record = EvidenceRecord.from_producer(
            {"finding": "x"}, evidence_type=EvidenceType.STATIC_FINDING, source="audit.json",
            producer=Producer.release_gate("audit", in_process=False),
            status=EpistemicStatus.DECLARED)
        [entry] = evidence_origin([record]).entries
        assert entry.origin is OriginKind.READ
        assert "this run did not produce it" in entry.statement

    def test_a_model_asked_in_this_run_is_obtained_not_computed(self):
        record = model_assisted_evidence(model="acme-reader", classification="supported",
                                         source="semantic:q1", content={"q": 1},
                                         coverage_note="a reading")
        [entry] = evidence_origin([record]).entries
        assert entry.origin is OriginKind.OBTAINED_HERE
        assert "acme-reader" in entry.statement and "not release-gate's" in entry.statement

    def test_release_gates_own_work_is_the_only_thing_it_ran(self, tmp_path):
        outcome = run(tmp_path, example("sast.json"))
        computed = [e for e in outcome.evidence_origin.entries
                    if e.origin is OriginKind.COMPUTED_HERE]
        assert computed and all(e.producer_id.startswith("release-gate/") for e in computed)

    def test_origin_is_the_same_on_every_run(self, tmp_path):
        first = run(tmp_path, example("review.json")).to_dict()["evidence_origin"]
        second = run(tmp_path, example("review.json")).to_dict()["evidence_origin"]
        assert first == second
