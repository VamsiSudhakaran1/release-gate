"""Authorship and verification correlation — was the work checked by anyone but its author?

Pinned here, against release_gate/assurance/authorship.py:

* one agent session writing the implementation, the tests, the security review
  and the fix is reported as *verification independence low* — and so is one
  person doing the same; the finding is about correlation, never about who or
  what wrote the code;
* an agent's implementation checked by a person, static analysers, another
  provider's model and the owner is independent, and nothing fires;
* authorship is read from statements — CI metadata, declared — and never
  inferred from style, a message's wording or a producer's name; an author
  nobody stated stays UNKNOWN;
* only support the resolution counted is compared, so a stale check is not
  verification of this release;
* a resolution policy can require independence from the author for required
  claims; unknown never satisfies it.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.authorship import (AuthorIndependence, AuthorRelation,
                                               AuthorshipError, AuthorshipStatement,
                                               assess_authorship, authorship_from_ci)
from release_gate.assurance.correlation import IndependencePolicy
from release_gate.assurance.resolution import (AdmissionEffect, ResolutionError,
                                               ResolutionPolicy)
from release_gate.assurance.zero_config import assure, render_text

CODEX_A = {"agent": "codex", "session": "codex-session-A", "provider": "openai",
           "model_family": "codex"}


def P(pid, kind="agent"):
    return {"producer_id": pid, "kind": kind}


def claim(cid="c-pay", *attempts, root=True, evidence=()):
    return {"record_type": "claim", "claim_id": cid, "is_root": root,
            "proposition": f"{cid} holds", "producer": P("payments-team", "human"),
            "verification_attempts": list(attempts),
            "supporting_evidence": list(evidence)}


def check(method="TEST_SUITE", provenance=None, **more):
    row = {"method": method, "outcome": "PASSED", "verifier": "ci://checks"}
    if provenance is not None:
        row["provenance"] = provenance
    row.update(more)
    return row


def authored(role, provenance, **more):
    return {"record_type": "authorship", "role": role, "provenance": provenance,
            "producer": P("ci://github-actions", "tool"), **more}


def run(tmp_path, rows, name="case.json", **kw):
    path = tmp_path / name
    path.write_text(json.dumps(rows), encoding="utf-8")
    return assure(str(path), **kw)


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def finding(outcome, rule_id):
    return next(f for f in outcome.analysis.findings if f.rule_id == rule_id)


def row(outcome, cid="c-pay"):
    return outcome.analysis.authorship.claim(cid)


# ── one source doing and checking the work ──────────────────────────────────

class TestOneSessionDidEverything:

    ROWS = [claim("c-pay", check("TEST_SUITE", CODEX_A),
                  check("HUMAN_REVIEW", CODEX_A, verifier="security-review")),
            authored("implementation", CODEX_A, subject="src/payments/"),
            authored("tests", CODEX_A), authored("security_review", CODEX_A),
            authored("fix", CODEX_A, subject="src/payments/transfer.py")]

    def test_it_is_verification_independence_low(self, tmp_path):
        outcome = run(tmp_path, self.ROWS)
        assert row(outcome).status is AuthorIndependence.LOW
        found = finding(outcome, "RG-INDEP-007")
        assert found.summary.startswith("verification independence low")
        assert found.effect.value == "ADVISORY"
        assert "agent:codex" in found.observed["shared"]
        assert "session:codex-session-A" in found.observed["shared"]

    def test_it_never_says_the_code_is_unsafe(self, tmp_path):
        outcome = run(tmp_path, self.ROWS)
        text = (render_text(outcome, full=True)
                + json.dumps(outcome.to_dict(), default=str)).lower()
        assert "unsafe" not in text
        assert "not about who or what wrote it" in text
        assert outcome.to_dict()["analysis"]["authorship"][
            "is_a_judgement_of_ai_written_code"] is False

    def test_reporting_it_does_not_move_the_verdict(self, tmp_path):
        without = run(tmp_path, self.ROWS[:1], name="plain.json")
        assert run(tmp_path, self.ROWS).decision is without.decision

    def test_one_person_doing_everything_reads_exactly_the_same(self, tmp_path):
        alice = {"person": "alice@example.com"}
        outcome = run(tmp_path, [
            claim("c-pay", check("TEST_SUITE", {"reviewer": "alice@example.com"}),
                  check("HUMAN_REVIEW", {"reviewer": "alice@example.com"})),
            authored("implementation", alice), authored("approval", alice)])
        assert row(outcome).status is AuthorIndependence.LOW
        assert "RG-INDEP-007" in rules(outcome)


# ── diverse checks of an agent's work ───────────────────────────────────────

class TestTheDiverseAlternative:

    ROWS = [
        claim("c-pay",
              check("TEST_SUITE", {"reviewer": "bob@example.com"}),
              check("TEST_SUITE", {"toolchain": ["pytest-regression"]},
                    verifier="regression-suite"),
              check("STATIC_ANALYSIS", {"toolchain": ["codeql"]}, verifier="codeql"),
              check("STATIC_ANALYSIS", {"toolchain": ["release-gate"]},
                    verifier="release-gate"),
              check("SIMULATION", {"provider": "anthropic", "model_family": "proofagent",
                                   "session": "pa-7"}, verifier="proofagent"),
              check("HUMAN_REVIEW", {"reviewer": "carol@example.com"},
                    verifier="owner-approval")),
        authored("implementation", CODEX_A)]

    def test_every_check_is_independent_of_the_author(self, tmp_path):
        outcome = run(tmp_path, self.ROWS)
        held = row(outcome)
        assert held.status is AuthorIndependence.INDEPENDENT
        assert len(held.of(AuthorRelation.INDEPENDENT_OF_AUTHOR)) == 6
        assert held.independent_groups >= 5
        assert not {"RG-INDEP-007", "RG-INDEP-008"} & rules(outcome)

    def test_an_agent_author_is_not_itself_a_finding(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE",
                                                      {"reviewer": "bob@example.com"})),
                                 authored("implementation", CODEX_A)])
        assert row(outcome).status is AuthorIndependence.INDEPENDENT
        assert not {"RG-INDEP-007", "RG-INDEP-008"} & rules(outcome)

    def test_one_shared_check_among_independent_ones_is_said_not_flagged(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", CODEX_A),
                                       check("HUMAN_REVIEW", {"reviewer": "carol"})),
                                 authored("implementation", CODEX_A)])
        held = row(outcome)
        assert held.status is AuthorIndependence.INDEPENDENT
        assert "1 share it" in held.basis


# ── unknown stays unknown; nothing is inferred ──────────────────────────────

class TestNothingIsInferred:

    def test_no_statement_means_author_unknown_and_no_finding(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", CODEX_A))])
        assert row(outcome).status is AuthorIndependence.AUTHOR_UNKNOWN
        assert not {"RG-INDEP-007", "RG-INDEP-008"} & rules(outcome)
        reported = outcome.to_dict()["analysis"]["authorship"]
        assert reported["present"] is False
        assert reported["by_status"]["AUTHOR_UNKNOWN"] == 1
        assert "WHO CHECKED THE WORK" not in render_text(outcome)

    def test_a_role_with_no_author_names_nobody(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", CODEX_A)),
                                 authored("implementation", {})])
        held = row(outcome)
        assert held.status is AuthorIndependence.AUTHOR_UNKNOWN
        assert "name a role and no author" in held.basis

    def test_style_names_and_messages_are_not_authorship(self, tmp_path):
        outcome = run(tmp_path, [
            claim("c-pay", check("TEST_SUITE", CODEX_A), evidence=["e-1"]),
            {"record_type": "evidence", "evidence_id": "e-1", "kind": "CODE_ARTIFACT",
             "producer": P("codex-bot"), "supports_claims": ["c-pay"],
             "summary": "Generated with Codex; Co-authored-by: Codex", "coverage_note": "x",
             "commit_message": "feat: written by an AI agent"}])
        assert row(outcome).status is AuthorIndependence.AUTHOR_UNKNOWN

    def test_a_check_that_states_nothing_is_unknown_never_independent(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE")),
                                 authored("implementation", CODEX_A)])
        held = row(outcome)
        assert held.status is AuthorIndependence.UNDETERMINED
        assert held.verifiers[0].relation is AuthorRelation.UNKNOWN
        assert finding(outcome, "RG-INDEP-008").effect.value == "ADVISORY"

    def test_whoever_reported_the_authorship_is_not_the_author(self, tmp_path):
        statement = authored("implementation", CODEX_A)
        statement["producer"] = P("carol", "human")
        outcome = run(tmp_path, [claim("c-pay", check("HUMAN_REVIEW",
                                                      {"reviewer": "carol"})),
                                 statement])
        assert row(outcome).status is AuthorIndependence.INDEPENDENT


    def test_a_person_who_reported_an_authorship_did_not_do_the_work(self):
        """Built in-process, where a producer can be a person: the reporter's own
        identity must not become the author's."""
        from types import SimpleNamespace

        from release_gate.assurance.claims import Claim
        from release_gate.assurance.evidence import (EpistemicStatus, EvidenceRecord,
                                                     EvidenceType, Producer, ProducerKind)
        from release_gate.assurance.resolution import ItemRole, ResolvedItem

        carol = Producer("carol", kind=ProducerKind.HUMAN)
        statement = AuthorshipStatement(role="implementation", provenance=CODEX_A) \
            .to_record(producer=carol, source="ci")
        review = EvidenceRecord.from_producer(
            {"review": "walked every path"}, evidence_type=EvidenceType.HUMAN_REVIEW,
            source="review", producer=carol, status=EpistemicStatus.DECLARED,
            supports_claims=("c",))

        class Graph:
            claims = (Claim(claim_id="c", statement="c holds"),)

            def __len__(self):
                return 1

        class Resolution:
            def of(self, claim_id):
                return SimpleNamespace(required=True, items=(
                    ResolvedItem(review.evidence_id, "evidence", ItemRole.SUPPORTS),))

        held = assess_authorship(Graph(), Resolution(), [statement, review]).claim("c")
        assert held.status is AuthorIndependence.INDEPENDENT


# ── what is compared ────────────────────────────────────────────────────────

class TestWhatIsCompared:

    def test_a_tests_statement_lends_its_author_to_the_results_it_names(self, tmp_path):
        outcome = run(tmp_path, [
            claim("c-pay", evidence=["e-tests"]),
            {"record_type": "evidence", "evidence_id": "e-tests", "kind": "TEST_RESULT",
             "producer": P("ci://pytest", "tool"), "supports_claims": ["c-pay"],
             "summary": "412 passed", "coverage_note": "x"},
            authored("implementation", CODEX_A),
            authored("tests", CODEX_A, evidence=["e-tests"])])
        [verifier] = row(outcome).verifiers
        assert verifier.role.value == "tests"
        assert verifier.relation is AuthorRelation.SHARES_AUTHOR

    def test_a_verification_statement_with_no_evidence_is_a_source_itself(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay"),
                                 authored("implementation", CODEX_A),
                                 authored("security_review", CODEX_A)])
        held = row(outcome)
        assert [(v.source_kind, v.role.value) for v in held.verifiers] == [
            ("authorship", "security_review")]
        assert held.status is AuthorIndependence.LOW

    def test_a_statement_scoped_to_one_claim_says_nothing_of_another(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", CODEX_A)),
                                 claim("c-refund", check("TEST_SUITE", CODEX_A), root=False),
                                 authored("implementation", CODEX_A, claims=["c-pay"])])
        assert row(outcome, "c-pay").status is AuthorIndependence.LOW
        assert row(outcome, "c-refund").status is AuthorIndependence.AUTHOR_UNKNOWN

    def test_a_check_of_another_state_is_not_verification_of_this_one(self, tmp_path):
        outcome = run(tmp_path, [
            {"record_type": "candidate", "components": {"commit": "bbbb2222"}},
            claim("c-pay", check("HUMAN_REVIEW", {"reviewer": "carol"},
                                 state={"commit": "aaaa1111"})),
            authored("implementation", CODEX_A)])
        assert row(outcome).status is AuthorIndependence.NO_VERIFICATION

    def test_one_provider_is_not_one_author_unless_the_policy_says(self, tmp_path):
        rows = [claim("c-pay", check("SIMULATION", {"provider": "openai",
                                                    "model_family": "o-series",
                                                    "session": "s-9"})),
                authored("implementation", CODEX_A)]
        assert row(run(tmp_path, rows)).status is AuthorIndependence.INDEPENDENT
        strict = ResolutionPolicy(policy_id="provider-correlates", independence=
                                  IndependencePolicy(correlate_on=tuple(
                                      IndependencePolicy().correlate_on) + ("provider",)))
        assert row(run(tmp_path, rows, resolution_policy=strict)).status is \
            AuthorIndependence.LOW


# ── policy ──────────────────────────────────────────────────────────────────

REQUIRE = ResolutionPolicy(policy_id="independent-of-author",
                           author_independence=AdmissionEffect.BLOCK)


class TestPolicy:

    def test_a_required_claim_checked_only_by_its_author_takes_the_declared_effect(
            self, tmp_path):
        outcome = run(tmp_path, TestOneSessionDidEverything.ROWS,
                      resolution_policy=REQUIRE)
        assert finding(outcome, "RG-INDEP-007").effect.value == "BLOCK"
        assert outcome.decision.value == "BLOCK"

    def test_a_claim_nobody_requires_stays_advisory(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", {"reviewer": "x"})),
                                 claim("c-side", check("TEST_SUITE", CODEX_A), root=False),
                                 authored("implementation", CODEX_A)],
                      resolution_policy=REQUIRE)
        assert finding(outcome, "RG-INDEP-007").effect.value == "ADVISORY"

    def test_unknown_independence_holds_a_required_claim(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE")),
                                 authored("implementation", CODEX_A)],
                      resolution_policy=REQUIRE)
        assert finding(outcome, "RG-INDEP-008").effect.value == "HOLD"

    def test_an_author_nobody_stated_does_not_satisfy_a_requirement(self, tmp_path):
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", {"reviewer": "x"}))],
                      resolution_policy=REQUIRE)
        found = finding(outcome, "RG-INDEP-008")
        assert found.effect.value == "HOLD" and found.observed["author_unknown"] == 1
        assert outcome.decision.value != "PROMOTE"

    def test_it_round_trips_and_refuses_what_it_cannot_mean(self):
        assert ResolutionPolicy.from_dict(REQUIRE.to_dict()) == REQUIRE
        assert ResolutionPolicy().to_dict()["author_independence"] is None
        with pytest.raises(ValueError):
            ResolutionPolicy(author_independence="ADVISE")
        with pytest.raises(ResolutionError):
            ResolutionPolicy.from_dict({"author_independence": "SOMETIMES"})


# ── statements and CI metadata ──────────────────────────────────────────────

class TestStatements:

    def test_an_unknown_role_is_refused_not_guessed(self):
        with pytest.raises(AuthorshipError, match="not one release-gate reads"):
            AuthorshipStatement(role="vibes")

    def test_an_unreadable_statement_is_refused_and_said(self, tmp_path):
        outcome = run(tmp_path, [claim(), authored("vibes", CODEX_A)])
        assert outcome.normalisation.skipped == {"record rejected: AuthorshipError": 1}

    def test_only_correlation_vocabulary_is_kept(self):
        statement = AuthorshipStatement(role="implementation", provenance={
            "agent": "codex", "style": "terse", "author": "dana"})
        assert dict(statement.provenance) == {"agent": "codex", "person": "dana"}

    def test_its_id_is_its_content(self):
        one = AuthorshipStatement(role="tests", provenance={"person": "bob"})
        assert one.statement_id == AuthorshipStatement.from_dict(one.to_dict()).statement_id

    def test_github_actions_states_a_bot_account_as_an_agent(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "copilot-swe-agent[bot]",
               "GITHUB_REPOSITORY": "acme/pay", "GITHUB_RUN_ID": "42",
               "GITHUB_SHA": "9f2c1a7e"}
        statement = authorship_from_ci(env)
        assert statement.provenance == {"agent": "copilot-swe-agent[bot]"}
        assert statement.basis.value == "ci_metadata"
        assert statement.reference == "https://github.com/acme/pay/actions/runs/42"
        assert statement.subject == "9f2c1a7e"

    def test_any_other_account_is_kept_and_not_placed(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "dana", "GITHUB_SHA": "abc"}
        statement = authorship_from_ci(env)
        assert statement.provenance == {} and statement.ci["actor"] == "dana"
        assert not statement.states_an_author
        stated = authorship_from_ci(env, provenance={"person": "dana"})
        assert stated.provenance == {"person": "dana"}

    def test_gitlab_is_read_too(self):
        env = {"GITLAB_CI": "true", "GITLAB_USER_LOGIN": "dana",
               "CI_PROJECT_PATH": "acme/pay", "CI_COMMIT_SHA": "abc",
               "CI_PIPELINE_URL": "https://gitlab.example/acme/pay/-/pipelines/7"}
        statement = authorship_from_ci(env, role="tests", provenance={"session": "s"})
        assert statement.ci["system"] == "gitlab_ci"
        assert statement.reference.endswith("/pipelines/7")

    def test_outside_ci_it_refuses_rather_than_guessing(self):
        with pytest.raises(AuthorshipError, match="no CI system"):
            authorship_from_ci({})

    def test_the_cli_emits_a_record_the_envelope_reads(self, tmp_path, monkeypatch, capsys):
        from release_gate import cli
        monkeypatch.setattr("sys.argv", ["release-gate", "authorship", "--role",
                                         "implementation", "--agent", "codex",
                                         "--session", "codex-session-A"])
        cli._run_authorship_command()
        emitted = json.loads(capsys.readouterr().out)
        assert emitted["record_type"] == "authorship"
        outcome = run(tmp_path, [claim("c-pay", check("TEST_SUITE", CODEX_A)), emitted])
        assert row(outcome).status is AuthorIndependence.LOW

    def test_the_same_case_gives_the_same_assessment(self, tmp_path):
        first = run(tmp_path, TestOneSessionDidEverything.ROWS)
        second = run(tmp_path, TestOneSessionDidEverything.ROWS)
        assert first.to_dict()["analysis"]["authorship"] == \
            second.to_dict()["analysis"]["authorship"]

    def test_no_claims_no_assessment(self):
        assert assess_authorship(None, None, []) is None
