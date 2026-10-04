"""Counterexample-first admission — one reproducible failure outweighs any count of passes.

Pinned here, against release_gate/assurance/counterexample.py, the claim resolution
and the admission rules that read them:

* one counterexample against 1,000 positive observations: the claim is
  contradicted and the case blocks — nothing averages to a score;
* a hundred clean traces are observations, never a proof that something cannot
  happen, and no policy can make them one;
* a counterexample blocks until the candidate moves past the state it was found
  against, it is invalidated with a reason, or a declared policy permits a
  documented exception made for this state;
* a counterexample found against another state, or a different subject, holds
  until re-run — it is never dropped;
* failed checks and failed branches stay on the record after a later pass;
* the same input gives the same counterexample ids and the same case.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.counterexample import (CounterexampleAttempt,
                                                   CounterexampleError,
                                                   CounterexampleResult,
                                                   CounterexampleStanding,
                                                   CounterexampleStatus, assess_standing)
from release_gate.assurance.resolution import (ResolutionError, ResolutionPolicy,
                                               ResolutionStatus, Strength)
from release_gate.assurance.zero_config import assure, render_text

S = CounterexampleStanding
EXCEPTIONS = ResolutionPolicy(policy_id="documented-exceptions",
                              counterexample_exceptions=True)


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


CLAIM = {"record_type": "claim", "claim_id": "c-authz", "is_root": True,
         "proposition": "No transfer executes without authorization",
         "producer": P("platform", "human")}


def observations(n, kind="TRACE"):
    return [{"record_type": "evidence", "evidence_id": f"obs-{i}", "kind": kind,
             "producer": P("otel"), "supports_claims": ["c-authz"],
             "summary": f"transfer {i} carried an authorization", "coverage_note": "x"}
            for i in range(n)]


def counterexample(**kw):
    return {"record_type": "counterexample", "target_claim": "c-authz",
            "result": "FOUND", "producer_id": "red-team", "method": "SIMULATION",
            "evidence": ["e-repro"],
            "detail": "an unauthorized transfer of 50,000 succeeded; reproducible", **kw}


REPRO = {"record_type": "evidence", "evidence_id": "e-repro", "kind": "TRACE",
         "producer": P("red-team"), "summary": "replay script and the transfer it made",
         "coverage_note": "x"}


def candidate(commit="bbbb2222", **more):
    return {"record_type": "candidate", "components": {"commit": commit, **more}}


def run(tmp_path, rows, name="case.json", **kw):
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return assure(str(path), **kw)


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def finding(outcome, rule_id):
    return next(f for f in outcome.analysis.findings if f.rule_id == rule_id)


def resolution(outcome):
    return outcome.analysis.resolution.of("c-authz")


def standings(outcome):
    return [s.standing for s in outcome.analysis.counterexample_standings]


# ── one against a thousand ──────────────────────────────────────────────────

class TestOneAgainstAThousand:

    def test_one_counterexample_outweighs_a_thousand_observations(self, tmp_path):
        outcome = run(tmp_path, [CLAIM, REPRO] + observations(1000) + [counterexample()])
        r = resolution(outcome)
        assert r.status is ResolutionStatus.CONTRADICTED and r.rule == "CR-01"
        assert "outranks any amount of support (1000 item(s) here)" in r.basis
        assert finding(outcome, "RG-CEX-001").effect.value == "BLOCK"
        assert outcome.case.verdict.decision.value == "BLOCK"

    def test_and_ninety_nine_passing_tests(self, tmp_path):
        outcome = run(tmp_path, [CLAIM, REPRO] + observations(99, "TEST_RESULT")
                      + [counterexample()])
        assert outcome.case.verdict.decision.value == "BLOCK"
        assert resolution(outcome).status is ResolutionStatus.CONTRADICTED

    def test_nothing_averages_to_a_score(self, tmp_path):
        outcome = run(tmp_path, [CLAIM, REPRO] + observations(99, "TEST_RESULT")
                      + [counterexample()])
        text = render_text(outcome, full=True) + json.dumps(outcome.to_dict(), default=str)
        assert "99%" not in text and "0.99" not in text


class TestObservationsAreNotProof:

    def test_a_hundred_clean_traces_never_establish(self, tmp_path):
        outcome = run(tmp_path, [CLAIM] + observations(100))
        r = resolution(outcome)
        assert r.status is ResolutionStatus.SUPPORTED
        assert r.status is not ResolutionStatus.ESTABLISHED
        # Submitted in a file they are declarations; observed directly they would
        # be observations. Neither establishes.
        assert "does not accept as establishing" in r.basis

    def test_no_policy_can_make_observations_a_proof(self):
        with pytest.raises(ResolutionError, match="show what happened"):
            ResolutionPolicy(policy_id="p", establishing=(Strength.OBSERVATION,
                                                          Strength.PROOF))
        with pytest.raises(ResolutionError):
            ResolutionPolicy.from_dict({"establishing": ["OBSERVATION"]})


# ── until the candidate moves ────────────────────────────────────────────────

class TestUntilTheCandidateMoves:

    def test_found_on_this_state_it_blocks(self, tmp_path):
        outcome = run(tmp_path, [candidate("aaaa1111"), CLAIM, REPRO] + observations(10)
                      + [counterexample(state={"commit": "aaaa1111"})])
        assert standings(outcome) == [S.VALID]
        assert outcome.case.verdict.decision.value == "BLOCK"

    def test_found_on_another_state_it_holds_and_is_kept(self, tmp_path):
        outcome = run(tmp_path, [candidate("bbbb2222"), CLAIM, REPRO] + observations(10)
                      + [counterexample(state={"commit": "aaaa1111"})])
        assert standings(outcome) == [S.STALE]
        assert "RG-CEX-001" not in rules(outcome)
        held = finding(outcome, "RG-CEX-004")
        assert held.effect.value == "HOLD"
        assert "aaaa1111" in held.detail and "bbbb2222" in held.detail
        assert outcome.case.verdict.decision.value == "HOLD"
        # Not dropped: still a counterexample on the case, still against the claim.
        assert [c.to_dict()["state"] for c in outcome.case.records("counterexamples")] == [
            {"commit": "aaaa1111"}]
        assert resolution(outcome).status is ResolutionStatus.CONTRADICTED

    def test_a_counterexample_for_a_different_subject_is_not_this_candidates(
            self, tmp_path):
        outcome = run(tmp_path, [candidate(environment="production"), CLAIM, REPRO]
                      + observations(10)
                      + [counterexample(state={"environment": "staging"})])
        [standing] = outcome.analysis.counterexample_standings
        assert standing.standing is S.STALE
        assert "a different subject" in standing.reason
        assert outcome.case.verdict.decision.value != "BLOCK"

    def test_counterexample_evidence_from_another_state_does_not_block_either(
            self, tmp_path):
        """Typed evidence lifts into the same standing, and the claim graph's
        refutation does not block it a second way."""
        outcome = run(tmp_path, [candidate("bbbb2222"), CLAIM] + observations(10) + [
            {"record_type": "evidence", "evidence_id": "e-cex", "kind": "COUNTEREXAMPLE",
             "producer": P("red-team"), "contradicts_claims": ["c-authz"],
             "summary": "unauthorized transfer", "state": {"commit": "aaaa1111"}}])
        assert standings(outcome) == [S.STALE]
        assert not {"RG-CEX-001", "RG-CONTRA-002", "RG-CONTRA-003"} & rules(outcome)
        assert "RG-CEX-004" in rules(outcome)
        assert outcome.case.verdict.decision.value == "HOLD"

    def test_alone_it_holds_once_and_is_not_a_refutation_that_blocks(self, tmp_path):
        outcome = run(tmp_path, [candidate("bbbb2222"), CLAIM,
            {"record_type": "evidence", "evidence_id": "e-cex", "kind": "COUNTEREXAMPLE",
             "producer": P("red-team"), "contradicts_claims": ["c-authz"],
             "summary": "unauthorized transfer", "state": {"commit": "aaaa1111"}}])
        assert standings(outcome) == [S.STALE]
        assert "RG-CONTRA-002" not in rules(outcome)
        assert outcome.case.verdict.decision.value == "HOLD"

    def test_the_same_evidence_on_this_state_still_blocks(self, tmp_path):
        outcome = run(tmp_path, [candidate("aaaa1111"), CLAIM] + observations(10) + [
            {"record_type": "evidence", "evidence_id": "e-cex", "kind": "COUNTEREXAMPLE",
             "producer": P("red-team"), "contradicts_claims": ["c-authz"],
             "summary": "unauthorized transfer", "state": {"commit": "aaaa1111"}}])
        assert outcome.case.verdict.decision.value == "BLOCK"


# ── until it is invalidated ──────────────────────────────────────────────────

class TestUntilInvalidated:

    def test_an_invalidated_counterexample_moves_nothing(self, tmp_path):
        outcome = run(tmp_path, [CLAIM, REPRO] + observations(10) + [counterexample(
            status="INVALID", resolution="the harness used a debug token production "
                                         "does not accept")])
        [standing] = outcome.analysis.counterexample_standings
        assert standing.standing is S.INVALIDATED
        assert "debug token" in standing.reason
        assert not {"RG-CEX-001", "RG-CEX-004"} & rules(outcome)
        assert resolution(outcome).status is ResolutionStatus.SUPPORTED

    def test_invalidating_one_needs_a_reason(self):
        with pytest.raises(CounterexampleError, match="must say why"):
            CounterexampleAttempt(target_claim="c", producer="p",
                                  result=CounterexampleResult.FOUND,
                                  status=CounterexampleStatus.INVALID)


# ── until a permitted, documented exception ──────────────────────────────────

class TestDocumentedException:

    def accepted(self, **kw):
        fields = dict(status="ACCEPTED_RISK",
                      resolution="the bank enforces the limit downstream",
                      accepted_by="cfo@example.com", reference="RISK-2026-114",
                      accepted_for={"commit": "bbbb2222"})
        fields.update(kw)
        return counterexample(**fields)

    def test_without_a_permitting_policy_it_still_blocks(self, tmp_path):
        outcome = run(tmp_path, [candidate(), CLAIM, REPRO] + observations(10)
                      + [self.accepted()])
        [standing] = outcome.analysis.counterexample_standings
        assert standing.standing is S.VALID
        assert "does not permit documented exceptions" in standing.reason
        assert outcome.case.verdict.decision.value == "BLOCK"

    def test_permitted_it_stops_blocking_and_stays_on_the_record(self, tmp_path):
        outcome = run(tmp_path, [candidate(), CLAIM, REPRO] + observations(10)
                      + [self.accepted()], resolution_policy=EXCEPTIONS)
        assert standings(outcome) == [S.ACCEPTED]
        assert "RG-CEX-001" not in rules(outcome)
        reported = finding(outcome, "RG-CEX-005")
        assert reported.effect.value == "ADVISORY"
        assert reported.observed["accepted_by"] == ["cfo@example.com"]
        assert outcome.case.verdict.decision.value != "BLOCK"
        [named] = [r for r in outcome.case.verdict.reasons if "documented risk" in r]
        assert "cfo@example.com" in named and "RISK-2026-114" in named
        # Accepting a risk is not an answer: the claim is still false as stated.
        r = resolution(outcome)
        assert r.status is ResolutionStatus.CONTRADICTED and r.rule == "CR-01"
        assert any("documented risk" in i.reason for i in r.items)

    def test_an_exception_made_for_another_state_lapses(self, tmp_path):
        outcome = run(tmp_path, [candidate("cccc3333"), CLAIM, REPRO] + observations(10)
                      + [self.accepted()], resolution_policy=EXCEPTIONS)
        [standing] = outcome.analysis.counterexample_standings
        assert standing.standing is S.VALID and "lapsed" in standing.reason
        assert outcome.case.verdict.decision.value == "BLOCK"

    def test_an_exception_for_no_state_is_not_honoured_against_a_stated_candidate(
            self, tmp_path):
        outcome = run(tmp_path, [candidate(), CLAIM, REPRO] + observations(10)
                      + [self.accepted(accepted_for={})], resolution_policy=EXCEPTIONS)
        assert standings(outcome) == [S.VALID]

    @pytest.mark.parametrize("missing", ["accepted_by", "reference", "resolution"])
    def test_an_exception_names_who_why_and_where(self, missing):
        fields = dict(target_claim="c", producer="p", result=CounterexampleResult.FOUND,
                      status=CounterexampleStatus.ACCEPTED_RISK, resolution="why",
                      accepted_by="who", reference="where")
        fields[missing] = ""
        with pytest.raises(CounterexampleError, match="documented exception"):
            CounterexampleAttempt(**fields)

    def test_exception_fields_cannot_ride_on_anything_else(self):
        with pytest.raises(CounterexampleError, match="belong to an ACCEPTED_RISK"):
            CounterexampleAttempt(target_claim="c", producer="p",
                                  result=CounterexampleResult.FOUND,
                                  status=CounterexampleStatus.OPEN, accepted_by="who")


# ── the policy ───────────────────────────────────────────────────────────────

class TestPolicy:

    def test_the_effect_on_a_critical_claim_is_declared(self, tmp_path):
        rows = [CLAIM, REPRO] + observations(5) + [counterexample()]
        held = run(tmp_path, rows, resolution_policy=ResolutionPolicy(
            policy_id="hold", counterexample_effect="HOLD"))
        assert finding(held, "RG-CEX-001").effect.value == "HOLD"
        assert held.case.verdict.decision.value == "HOLD"

    def test_it_round_trips_and_refuses_what_it_cannot_mean(self):
        policy = ResolutionPolicy(policy_id="p", counterexample_effect="HOLD",
                                  counterexample_exceptions=True)
        assert ResolutionPolicy.from_dict(policy.to_dict()) == policy
        for bad in ({"counterexample_effect": "ADVISORY"},
                    {"counterexample_exceptions": "yes"}):
            with pytest.raises(ResolutionError):
                ResolutionPolicy.from_dict(bad)


# ── failures are kept ────────────────────────────────────────────────────────

class TestFailuresAreKept:

    def claim_with(self, *attempts):
        return [{**CLAIM, "verification_attempts": list(attempts)}]

    def test_a_later_pass_does_not_hide_an_earlier_failure(self, tmp_path):
        outcome = run(tmp_path, self.claim_with(
            {"method": "TEST_SUITE", "outcome": "FAILED", "verifier": "ci",
             "detail": "authz bypass on retry path"},
            {"method": "TEST_SUITE", "outcome": "PASSED", "verifier": "ci",
             "detail": "rerun"}))
        r = resolution(outcome)
        assert r.status is ResolutionStatus.CONTRADICTED and r.rule == "CR-02"
        assert any(i.role.value == "FAILED_CHECK" for i in r.items)
        assert any(c.kind.value == "VERIFICATION_CONFLICT" for c in outcome.contradictions)
        branches = outcome.to_dict()["failed_branches"]
        assert branches["observed"] >= 1
        assert "authz bypass" in json.dumps(branches)

    def test_a_failure_on_an_earlier_state_is_still_on_the_record(self, tmp_path):
        outcome = run(tmp_path, [candidate("bbbb2222")] + self.claim_with(
            {"method": "TEST_SUITE", "outcome": "FAILED", "verifier": "ci",
             "detail": "authz bypass", "state": {"commit": "aaaa1111"}},
            {"method": "TEST_SUITE", "outcome": "PASSED", "verifier": "ci",
             "state": {"commit": "bbbb2222"}}))
        r = resolution(outcome)
        failed = [i for i in r.items if i.role.value == "FAILED_CHECK"]
        assert len(failed) == 1
        assert outcome.to_dict()["failed_branches"]["observed"] >= 1


# ── the same input, the same case ────────────────────────────────────────────

class TestDeterminism:

    def test_the_clock_is_not_part_of_a_counterexamples_identity(self):
        one = CounterexampleAttempt(target_claim="c", producer="p",
                                    result=CounterexampleResult.FOUND,
                                    status=CounterexampleStatus.OPEN,
                                    attempted_at="2026-01-01T00:00:00Z")
        two = CounterexampleAttempt(target_claim="c", producer="p",
                                    result=CounterexampleResult.FOUND,
                                    status=CounterexampleStatus.OPEN,
                                    attempted_at="2026-10-04T12:00:00Z")
        assert one.counterexample_id == two.counterexample_id
        moved = CounterexampleAttempt(target_claim="c", producer="p",
                                      result=CounterexampleResult.FOUND,
                                      status=CounterexampleStatus.OPEN,
                                      state={"commit": "aaaa1111"})
        assert moved.counterexample_id != one.counterexample_id

    def test_assuring_twice_gives_the_same_case(self, tmp_path, monkeypatch):
        import release_gate.assurance.counterexample as module
        rows = [CLAIM, REPRO] + observations(3) + [counterexample()]
        monkeypatch.setattr(module, "_utc_now", lambda: "2026-01-01T00:00:00Z")
        first = run(tmp_path, rows)
        monkeypatch.setattr(module, "_utc_now", lambda: "2026-10-04T12:00:00Z")
        second = run(tmp_path, rows)
        assert [c.counterexample_id for c in first.counterexamples] == [
            c.counterexample_id for c in second.counterexamples]
        assert first.case.case_digest == second.case.case_digest

    def test_standing_is_a_pure_function_of_its_inputs(self):
        attempt = CounterexampleAttempt(target_claim="c", producer="p",
                                        result=CounterexampleResult.FOUND,
                                        status=CounterexampleStatus.OPEN)
        assert assess_standing(attempt) == assess_standing(attempt)
        assert assess_standing(attempt).standing is S.VALID
