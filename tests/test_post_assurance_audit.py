"""The post-assurance red-team audit, kept as regressions.

`POST_ASSURANCE_ARCHITECTURE_AUDIT.md` records a hostile review of the
admission controller across twenty-five attack areas. Every defect it found was
reproduced here first, as a failing test, and then fixed; every area it found
defended is pinned here too, so the defence cannot be removed without a test
saying which attack it reopens.

Each test starts from one shipped release that promotes
(`examples/agents/02-release-promoted.jsonl`) and changes one thing.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "examples" / "agents" / "02-release-promoted.jsonl"
BASE = [json.loads(line) for line in RELEASE.read_text().splitlines() if line.strip()]
GENERAL = default_registry().resolve("general-agent-action@1.0.0")
DIGEST = "sha256:9c2f1e4a7b83d05fe6c1a9b4d72e8f3016a5c9d84b2e7f1a3c6d0985b7e4f2a1"


def _run(tmp_path, rows, name="release.jsonl", **kwargs):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return assure(str(path), methodology=GENERAL, **kwargs)


def _rows():
    return copy.deepcopy(BASE)


def _decision(outcome) -> str:
    return outcome.case.verdict.decision.value


def _fired(outcome):
    return {f.rule_id for f in outcome.analysis.findings
            if f.effect.value != "ADVISORY"}


def test_the_starting_release_promotes(tmp_path):
    outcome = _run(tmp_path, _rows())
    assert _decision(outcome) == "PROMOTE"
    assert outcome.analysis.resolution.of("C-1").status.value == "SUPPORTED"


# ── D1: a word the vocabulary does not know never removes a record ──────────
#
# Before the fix, an attempt outcome, a counterexample method or an adversarial
# role outside the enum raised inside the ingest, and the whole record went:
# a claim with a failed check disappeared, a found counterexample disappeared,
# and the BLOCK it carried became an "input could not be mapped" HOLD that a
# reviewer could approve without ever seeing what was found.

def _failing_claim(*extra_attempts):
    return {"record_type": "claim", "claim_id": "C-2", "is_root": True,
            "proposition": "no other currency changes",
            "verification_attempts": [
                {"method": "TEST_SUITE", "outcome": "FAILED",
                 "verifier": "ci://nightly", "applies_to": DIGEST},
                *extra_attempts]}


@pytest.mark.parametrize("word", ["error", "skipped", "timeout", "flaky", "PASS",
                                  "ok", "success", "green", True, 1, "partial"])
def test_an_unknown_attempt_outcome_keeps_the_claim_and_its_failure(tmp_path, word):
    rows = _rows()
    rows.append(_failing_claim({"method": "TEST_SUITE", "outcome": word,
                                "verifier": "ci://other", "applies_to": DIGEST}))
    outcome = _run(tmp_path, rows)
    resolved = outcome.analysis.resolution.of("C-2")
    assert resolved is not None, "the claim was dropped"
    assert resolved.status.value == "CONTRADICTED"
    assert _decision(outcome) == "BLOCK"
    claim = next(c for c in outcome.analysis.claim_graph.claims if c.claim_id == "C-2")
    unread = [a for a in claim.verification_attempts if a.verifier == "ci://other"]
    assert len(unread) == 1
    assert unread[0].status.value == "UNKNOWN"
    assert unread[0].result["native_outcome"] == str(word)


@pytest.mark.parametrize("word", ["PASS", "ok", "success", True])
def test_an_unknown_word_never_reads_as_a_pass(tmp_path, word):
    """A claim whose only check reports a word nobody defined is not verified,
    and the case says a value could not be read rather than promoting."""
    rows = _rows()
    rows.append({"record_type": "claim", "claim_id": "C-2", "is_root": True,
                 "proposition": "no other currency changes",
                 "verification_attempts": [{"method": "TEST_SUITE", "outcome": word,
                                            "verifier": "ci://nightly",
                                            "applies_to": DIGEST}]})
    outcome = _run(tmp_path, rows)
    assert outcome.analysis.resolution.of("C-2").status.value != "SUPPORTED"
    assert _decision(outcome) == "HOLD"
    finding = next(f for f in outcome.analysis.findings if f.rule_id == "RG-COV-002")
    assert repr(str(word)) in finding.detail


def _counterexample(**changes):
    row = {"record_type": "counterexample", "target_claim": "C-1", "result": "FOUND",
           "method": "PROPERTY_TEST", "producer_id": "fuzz://lab",
           "detail": "a EUR transfer crossed the limit"}
    row.update(changes)
    return row


def test_a_found_counterexample_blocks(tmp_path):
    outcome = _run(tmp_path, _rows() + [_counterexample()])
    assert _decision(outcome) == "BLOCK"
    assert "RG-CEX-001" in _fired(outcome)


@pytest.mark.parametrize("changes", [
    {"method": "fuzzing"},
    {"method": "manual exploration"},
    {"status": "opened"},
    {"status": "RESOLVED", "resolution": "fixed upstream"},     # no evidence for it
    {"status": "ACCEPTED_RISK"},                                # nobody accepted it
    {"status": "INVALID"},                                      # nobody said why
    {"status": "SUPERSEDED"},
    {"status": "NOT_APPLICABLE"},
], ids=lambda c: ",".join(f"{k}={v}" for k, v in c.items()))
def test_a_found_counterexample_survives_an_unreadable_or_unchecked_answer(
        tmp_path, changes):
    """An answer that cannot be read or checked is no answer: the
    counterexample stays found and open, and the case still blocks."""
    outcome = _run(tmp_path, _rows() + [_counterexample(**changes)])
    assert _decision(outcome) == "BLOCK"
    assert "RG-CEX-001" in _fired(outcome)
    kept = outcome.normalisation.counterexamples
    assert kept and all(c.result.value == "FOUND" and c.status.value == "OPEN"
                        for c in kept)
    assert "RG-COV-002" in _fired(outcome)


@pytest.mark.parametrize("word", ["yes", True, "found!", "maybe"])
def test_an_unreadable_counterexample_result_is_unknown_and_holds(tmp_path, word):
    """Whether something was found cannot be read: neither a refutation nor a
    clean search, and never silently gone."""
    outcome = _run(tmp_path, _rows() + [_counterexample(result=word)])
    kept = outcome.normalisation.counterexamples
    assert len(kept) == 1 and kept[0].result.value == "UNKNOWN"
    assert repr(str(word)) in kept[0].detail
    assert _decision(outcome) == "HOLD"
    assert "RG-COV-002" in _fired(outcome)


def _attack(**changes):
    row = {"record_type": "adversarial", "target_claim": "C-1",
           "outcome": "CANDIDATE_REFUTED", "role": "RED_TEAM",
           "adversary": "redteam://lab", "attacked": "limit bypass"}
    row.update(changes)
    return row


@pytest.mark.parametrize("changes", [
    {"role": "red team"},
    {"method": "manual"},
    {"status": "open!"},
    {"status": "ADDRESSED", "resolution": "patched"},           # no evidence for it
    {"status": "ACCEPTED_RISK", "resolution": "acceptable"},    # nobody accepted it
    {"status": "INVALID"},
    {"status": "NOT_APPLICABLE"},
], ids=lambda c: ",".join(f"{k}={v}" for k, v in c.items()))
def test_a_refuting_attack_survives_an_unreadable_or_unchecked_answer(
        tmp_path, changes):
    outcome = _run(tmp_path, _rows() + [_attack(**changes)])
    assert _decision(outcome) == "BLOCK"
    kept = outcome.normalisation.adversarial
    assert kept and all(a.outcome.value == "CANDIDATE_REFUTED"
                        and a.status.value == "OPEN" for a in kept)
    assert "RG-COV-002" in _fired(outcome)


def test_an_unreadable_attack_outcome_is_inconclusive_and_holds(tmp_path):
    outcome = _run(tmp_path, _rows() + [_attack(outcome="refuted")])
    kept = outcome.normalisation.adversarial
    assert len(kept) == 1 and kept[0].outcome.value == "INCONCLUSIVE"
    assert "'refuted'" in kept[0].detail
    assert _decision(outcome) == "HOLD"


def test_a_well_formed_release_reads_nothing_as_unread(tmp_path):
    """The fix adds a line only where a value was refused, so every existing
    case — and its digest — is unchanged."""
    outcome = _run(tmp_path, _rows() + [_counterexample()])
    assert "unread_values" not in outcome.normalisation.to_dict()
    assert not outcome.normalisation.unread_values


# ── D2: naming the subject is not naming the release ─────────────────────────
#
# A record whose state named only identity components (the repository, the
# environment) bound PARTIAL: "everything it names matches". Nothing it named
# was a revision, so it could be about any commit of that repository — yet its
# support counted as bound, it escaped the "names no state" hold (RG-DRIFT-008),
# and an approval stating only `{"repository": ...}` satisfied "the release
# owner approved this exact release" for every future commit.

REPO = "github.com/acme/billing"
COMMIT = "4b1e0f9a2c7d"


def test_identity_only_state_names_no_state_of_the_release():
    from release_gate.assurance.candidate import CandidateSource, CandidateState, bind
    candidate = CandidateState.from_dict(
        {"components": {"repository": REPO, "commit": COMMIT}},
        source=CandidateSource.DECLARED_BY_CALLER)
    only_repo = bind(candidate, state={"repository": REPO}, record_id="r",
                     record_kind="evidence", supports=True)
    assert only_repo.match.value == "UNKNOWN"
    assert "no revision" in only_repo.reason
    # What did bind before still binds: a revision that matches, a revision that
    # does not, a repository that does not.
    assert bind(candidate, state={"repository": REPO, "commit": COMMIT}, record_id="r",
                record_kind="evidence").match.value == "EXACT"
    assert bind(candidate, state={"commit": COMMIT}, record_id="r",
                record_kind="evidence").match.value == "PARTIAL"
    assert bind(candidate, state={"repository": REPO, "commit": "0123456789ab"},
                record_id="r", record_kind="evidence").match.value == "STALE"
    assert bind(candidate, state={"repository": "github.com/other/repo"}, record_id="r",
                record_kind="evidence").match.value == "INCOMPATIBLE"


def test_a_candidate_that_states_no_revision_still_binds_its_subject():
    """Only where the candidate names a revision could the record have named one."""
    from release_gate.assurance.candidate import CandidateSource, CandidateState, bind
    candidate = CandidateState.from_dict({"components": {"repository": REPO}},
                                         source=CandidateSource.DECLARED_BY_CALLER)
    assert bind(candidate, state={"repository": REPO}, record_id="r",
                record_kind="evidence").match.value == "EXACT"


def _with_states(state):
    rows = _rows()
    rows.insert(0, {"record_type": "candidate",
                    "components": {"repository": REPO, "commit": COMMIT}})
    for row in rows:
        if row["record_type"] == "evidence":
            row["state"] = dict(state)
        if row["record_type"] == "claim":
            for attempt in row.get("verification_attempts") or ():
                attempt["state"] = {"repository": REPO, "commit": COMMIT}
    return rows


def test_support_naming_only_the_repository_is_unbound_support(tmp_path):
    bound = _run(tmp_path, _with_states({"repository": REPO, "commit": COMMIT}),
                 name="bound.jsonl")
    assert "RG-DRIFT-008" not in _fired(bound)
    only_repo = _run(tmp_path, _with_states({"repository": REPO}), name="repo.jsonl")
    assert "RG-DRIFT-008" in _fired(only_repo)
    assert _decision(only_repo) != "PROMOTE"


def _demo(tmp_path, approval_state):
    import importlib.util
    import shutil
    demo = ROOT / "examples" / "demo-admission"
    target = tmp_path / "demo"
    shutil.copytree(demo, target, ignore=shutil.ignore_patterns("__pycache__"))
    path = target / "evidence" / "approval.json"
    doc = json.loads(path.read_text())
    doc["reviews"][0]["state"] = approval_state
    path.write_text(json.dumps(doc))
    spec = importlib.util.spec_from_file_location(f"demo_{abs(hash(target))}",
                                                  demo / "run_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE = target
    return module.reading(module.admit("policy/hold-on-counterexample.json"))


DEMO_COMMIT = "c4f8d31a9e27"
DEMO_POLICY = "sha256:9e65a381cc59ac16d9d7e801912a1c6bc117281554744c70e8bb76f4ef38c166"


@pytest.mark.parametrize("state, counts", [
    ({"commit": DEMO_COMMIT}, True),
    ({"commit": DEMO_COMMIT, "governance_policy": DEMO_POLICY}, True),
    ({"repository": "github.com/acme/treasury-agent"}, False),   # D2
    ({"commit": "7a1c9e2b40d6"}, False),                          # another commit
    ({"commit": DEMO_COMMIT, "governance_policy": "sha256:" + "1" * 64}, False),
    ({"commit": DEMO_COMMIT, "model": "openai:gpt-4o-mini"}, False),
], ids=["commit", "commit+policy", "repository-only", "other-commit",
        "policy-changed-after-approval", "other-model"])
def test_an_approval_counts_only_for_the_state_it_names(tmp_path, state, counts):
    facts = _demo(tmp_path, state)
    assert ("approvals.release-owner" not in facts["holding"]) is counts


# ── D3: an approval is given under a policy, and binds to it ────────────────
#
# A BoundApproval recorded the case digest and the evidentiary collections, and
# nothing that named the release policy. Re-decided under another methodology
# or resolution policy, the case digest moved, no evidentiary collection did,
# and the approval read VALID with "the change is in release-gate's own
# output" — so a policy loosened after a person signed carried their signature
# over to decisions they never saw.

def _fixed_run(tmp_path, **kwargs):
    import os
    path = tmp_path / "release.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in _rows()) + "\n")
    here = os.getcwd()
    os.chdir(tmp_path)
    try:
        return assure("release.jsonl", **{"methodology": GENERAL, **kwargs})
    finally:
        os.chdir(here)


def _approve(outcome):
    from release_gate.assurance.approval import offer_approval, submit_approval
    offer = offer_approval(outcome.case, outcome)
    submission = submit_approval(outcome.case, offer.acknowledgement(),
                                 approver="release-owner@acme.example",
                                 scope="the release as offered")
    assert submission.accepted
    return submission.approval


def _hold_policy():
    from release_gate.assurance.resolution import ResolutionPolicy
    return ResolutionPolicy.from_dict(json.loads(
        (ROOT / "examples/demo-admission/policy/hold-on-counterexample.json").read_text()))


def test_an_approval_stays_valid_when_nothing_moved(tmp_path):
    from release_gate.assurance.approval import check_approval
    approval = _approve(_fixed_run(tmp_path))
    assert check_approval(approval, _fixed_run(tmp_path).case).standing.value == "VALID"


@pytest.mark.parametrize("change, moved", [
    ({"methodology": "production-database-change"}, "methodology"),
    ({"methodology": None}, "methodology"),
    ({"resolution_policy": "hold"}, "resolution_policy"),
])
def test_a_policy_change_after_approval_requires_review(tmp_path, change, moved):
    from release_gate.assurance.approval import check_approval
    approval = _approve(_fixed_run(tmp_path))
    assert moved in approval.bound_policy
    kwargs = {}
    if "methodology" in change:
        kwargs["methodology"] = (default_registry().latest(change["methodology"])
                                 if change["methodology"] else None)
    if "resolution_policy" in change:
        kwargs["resolution_policy"] = _hold_policy()
    found = check_approval(approval, _fixed_run(tmp_path, **kwargs).case)
    assert found.standing.value == "APPROVAL_REVIEW_REQUIRED"
    assert moved in found.moved_policy
    assert "own output" not in " ".join(found.reasons)


def test_a_submission_read_under_another_policy_sends_the_person_back(tmp_path):
    from release_gate.assurance.approval import offer_approval, submit_approval
    offer = offer_approval(_fixed_run(tmp_path).case)
    live = _fixed_run(tmp_path, resolution_policy=_hold_policy()).case
    found = submit_approval(live, offer.acknowledgement(), approver="alice")
    assert found.outcome.value == "CONFLICT"
    assert "bound_policy" in found.mismatched
    assert found.human_must_re_read


def test_an_approval_recorded_before_policies_were_bound_is_not_read_as_valid(tmp_path):
    """Unknown is not a pass: an approval with no policy on record, against a case
    whose digest moved, cannot show the policy did not move."""
    import dataclasses
    from release_gate.assurance.approval import check_approval
    approval = dataclasses.replace(_approve(_fixed_run(tmp_path)), bound_policy={})
    assert "bound_policy" not in approval.identity()
    unchanged = check_approval(approval, _fixed_run(tmp_path).case)
    assert unchanged.standing.value == "VALID"
    moved = check_approval(approval,
                           _fixed_run(tmp_path, resolution_policy=_hold_policy()).case)
    assert moved.standing.value == "APPROVAL_REVIEW_REQUIRED"
    assert "cannot be established" in " ".join(moved.reasons)


def test_a_bound_policy_survives_the_round_trip(tmp_path):
    from release_gate.assurance.approval import BoundApproval
    approval = _approve(_fixed_run(tmp_path))
    again = BoundApproval.from_dict(json.loads(json.dumps(approval.to_dict())))
    assert again.bound_policy == approval.bound_policy
    assert again.approval_id == approval.approval_id


# ── D4: a producer's word the contract does not define is read, not ignored ──
#
# The reference contracts keep an outcome word outside their vocabulary and
# read it as unknown — never a pass. But nothing then read the unknown: an
# attack whose outcome was "success" or `true` (meaning, quite possibly, that it
# got through) left a critical claim SUPPORTED by the attacks that were blocked,
# and the release promoted. A result list that was not a list read as an empty
# run, with no finding at all.

TARGET = "No transfer executes without authorization"
CANDIDATE_ROW = {"record_type": "candidate",
                 "components": {"repository": "github.com/acme/payments-agent",
                                "commit": "9f2c1a7e", "environment": "staging"}}
BOUND = {"commit": "9f2c1a7e", "environment": "staging"}


def _payments(*documents):
    claim = {"record_type": "claim", "claim_id": "cl_x", "is_root": True,
             "proposition": TARGET,
             "producer": {"producer_id": "payments-team", "kind": "human"},
             "verification_attempts": [{
                 "method": "TEST_SUITE", "outcome": "PASSED", "verifier": "ci://unit",
                 "state": {**BOUND, "repository": "github.com/acme/payments-agent"}}]}
    evals = {"schema": "release-gate.eval/1", "producer": {"id": "acme-evals"},
             "run_id": "e1", "ran_at": "2026-10-02T09:00:00Z", "state": BOUND,
             "cases": [{"id": "c1", "outcome": "passed", "claim_id": "cl_x",
                        "claim": TARGET}]}
    rows = [CANDIDATE_ROW, claim,
            {"record_type": "producer_export", "source": "eval.json", "document": evals}]
    rows += [{"record_type": "producer_export", "source": f"doc-{i}.json", "document": d}
             for i, d in enumerate(documents)]
    return rows


def _red_team(*outcomes, attacks=None):
    listed = [{"id": f"atk-{i}", "class": "tool_misuse", "technique": "t",
               "outcome": outcome, "severity": "critical"}
              for i, outcome in enumerate(outcomes)]
    return {"schema": "release-gate.red-team/1", "producer": {"id": "acme-red-team"},
            "run_id": "rt-1", "ran_at": "2026-10-02T11:00:00Z", "state": BOUND,
            "target_claim_id": "cl_x", "target_claim": TARGET,
            "attacks": listed if attacks is None else attacks}


BLOCKED = ("blocked",) * 5


def test_the_payments_release_promotes_with_every_attack_blocked(tmp_path):
    assert _decision(_run(tmp_path, _payments(_red_team(*BLOCKED)))) == "PROMOTE"


@pytest.mark.parametrize("word", ["succeeded", "Succeeded", "bypassed", "breached"])
def test_an_attack_that_got_through_blocks(tmp_path, word):
    outcome = _run(tmp_path, _payments(_red_team(*BLOCKED, word)))
    assert _decision(outcome) == "BLOCK"


@pytest.mark.parametrize("word", ["success", True, "got through", "pwned", ""])
def test_an_attack_outcome_nobody_defined_holds_the_release(tmp_path, word):
    outcome = _run(tmp_path, _payments(_red_team(*BLOCKED, word)))
    assert _decision(outcome) == "HOLD"
    finding = next(f for f in outcome.analysis.findings if f.rule_id == "RG-COV-002")
    assert repr(str(word)) in finding.detail


def test_a_listed_unsettled_attack_word_is_read_as_it_always_was(tmp_path):
    """`timeout` is in the contract: inconclusive, a read word, nothing unread."""
    outcome = _run(tmp_path, _payments(_red_team(*BLOCKED, "timeout")))
    assert not outcome.normalisation.unread_values


def test_a_result_list_that_is_not_a_list_is_not_an_empty_run(tmp_path):
    attacks = {"atk-9": {"outcome": "succeeded"}}
    outcome = _run(tmp_path, _payments(_red_team(attacks=attacks)))
    assert _decision(outcome) == "HOLD"
    finding = next(f for f in outcome.analysis.findings if f.rule_id == "RG-COV-002")
    assert "attacks" in finding.detail


def test_a_behaviour_check_word_nobody_defined_holds(tmp_path):
    behaviour = {"schema": "release-gate.behavior/1",
                 "producer": {"id": "acme-behaviour"}, "run_id": "b1",
                 "state": BOUND,
                 "checks": [{"id": "chk-1", "outcome": "APPLICABLE_PASS",
                             "claim_id": "cl_x", "claim": TARGET},
                            {"id": "chk-2", "outcome": "violation_proven",
                             "claim_id": "cl_x", "claim": TARGET}]}
    outcome = _run(tmp_path, _payments(behaviour))
    assert _decision(outcome) == "HOLD"
    assert any("'violation_proven'" in line
               for line in outcome.normalisation.unread_values)


def test_a_review_decision_nobody_defined_holds(tmp_path):
    review = {"schema": "release-gate.review/1",
              "evaluated_at": "2026-10-03T12:00:00Z",
              "reviews": [{"id": "rev-1",
                           "reviewer": {"id": "dana@example.com", "role": "owner"},
                           "decision": "lgtm", "claim_id": "cl_x", "claim": TARGET,
                           "state": BOUND, "reviewed_at": "2026-10-03T11:00:00Z"}]}
    outcome = _run(tmp_path, _payments(review))
    assert _decision(outcome) == "HOLD"
    assert any("'lgtm'" in line for line in outcome.normalisation.unread_values)


# ── D5: an object two parsers would read differently is refused ─────────────
#
# Python's JSON reader keeps the last of two equal keys; other readers keep the
# first or refuse. `{"outcome": "FAILED", "outcome": "PASSED"}` promoted here
# while a reviewer's first-wins viewer showed a failure. NaN and Infinity are
# not JSON at all; a failing attempt carrying one was refused at
# canonicalisation, and its failure went with it.

def _lines(*extra):
    return "\n".join([json.dumps(r) for r in _rows()] + list(extra)) + "\n"


DUPLICATE_OUTCOME = (
    '{"record_type": "claim", "claim_id": "C-2", "is_root": true, '
    '"proposition": "no other currency changes", "verification_attempts": '
    '[{"method": "TEST_SUITE", "outcome": "FAILED", "outcome": "PASSED", '
    '"verifier": "ci://nightly"}]}')


@pytest.mark.parametrize("line, says", [
    (DUPLICATE_OUTCOME, "'outcome'"),
    ('{"record_type": "claim", "claim_id": "C-2", "claim_id": "C-1", '
     '"proposition": "p"}', "'claim_id'"),
    ('{"record_type": "claim", "claim_id": "C-2", "proposition": "p", '
     '"verification_attempts": [{"method": "TEST_SUITE", "outcome": "FAILED", '
     '"verifier": "ci://n", "result": {"score": NaN}}]}', "NaN"),
    ('{"record_type": "evidence", "kind": "TEST_RESULT", "score": Infinity, '
     '"producer": {"producer_id": "ci"}}', "Infinity"),
], ids=["duplicate-outcome", "duplicate-claim-id", "nan", "infinity"])
def test_ambiguous_or_non_json_input_is_refused(tmp_path, line, says):
    from release_gate.assurance.ingest import IngestError
    path = tmp_path / "release.jsonl"
    path.write_text(_lines(line))
    with pytest.raises(IngestError) as refused:
        assure(str(path), methodology=GENERAL)
    assert says in str(refused.value)


def test_an_ambiguous_evidence_file_is_refused_too(tmp_path):
    from release_gate.assurance.ingest import IngestError
    release = tmp_path / "release.jsonl"
    release.write_text(_lines())
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "eval.json").write_text(
        '{"schema": "release-gate.eval/1", "producer": {"id": "e"}, "cases": '
        '[{"id": "c1", "outcome": "failed", "outcome": "passed", "claim_id": "C-1"}]}')
    with pytest.raises(IngestError):
        assure(str(release), methodology=GENERAL, evidence=[str(evidence)])


def test_the_cli_refuses_ambiguous_input_with_the_block_exit_code(tmp_path):
    import subprocess
    import sys
    path = tmp_path / "release.jsonl"
    path.write_text(_lines(DUPLICATE_OUTCOME))
    done = subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", str(path),
                           "--methodology", "general-agent-action@1.0.0"],
                          capture_output=True, text=True, cwd=str(ROOT))
    assert done.returncode == 1
    assert "duplicate key" in done.stdout


def test_the_scanner_side_reader_is_unchanged(tmp_path):
    """Backward compatibility: only the admission path is strict."""
    from release_gate.adapters.common import load_document
    path = tmp_path / "export.json"
    path.write_text('{"a": 1, "a": 2, "b": NaN}')
    doc = load_document(str(path))
    assert doc["a"] == 2


# ── D6: a repeated claim id joins the claim, it does not vanish ─────────────
#
# Claim rows collapsed on their declared id, so a redelivered batch would not
# count a claim twice — but "collapsed" meant the later row was dropped whole.
# A second row for C-1 carrying a FAILED check was absorbed, and the release
# promoted on the first row's support.

def _claim_row(**changes):
    row = next(copy.deepcopy(r) for r in BASE if r["record_type"] == "claim")
    row.update(changes)
    return row


def test_a_repeated_claim_row_keeps_its_failed_check(tmp_path):
    again = _claim_row(verification_attempts=[{
        "method": "TEST_SUITE", "outcome": "FAILED", "verifier": "ci://nightly",
        "applies_to": DIGEST}])
    outcome = _run(tmp_path, _rows() + [again])
    assert outcome.analysis.resolution.of("C-1").status.value == "CONTRADICTED"
    assert _decision(outcome) == "BLOCK"


def test_a_redelivered_claim_row_is_still_absorbed(tmp_path):
    original = _run(tmp_path, _rows(), name="once.jsonl")
    outcome = _run(tmp_path, _rows() + [_claim_row()], name="twice.jsonl")
    assert _decision(outcome) == "PROMOTE"
    claim = next(c for c in outcome.analysis.claim_graph.claims if c.claim_id == "C-1")
    first = next(c for c in original.analysis.claim_graph.claims if c.claim_id == "C-1")
    # Evidence ids name their source file, so the two runs are compared by count:
    # nothing the repeat carried was counted a second time.
    assert len(claim.supporting_evidence) == len(first.supporting_evidence)
    assert len(set(claim.supporting_evidence)) == len(claim.supporting_evidence)
    assert len(claim.verification_attempts) == len(first.verification_attempts)


def test_one_claim_id_stating_two_propositions_holds(tmp_path):
    outcome = _run(tmp_path, _rows() + [_claim_row(proposition="something else")])
    assert _decision(outcome) == "HOLD"
    assert any("C-1" in line and "two" in line
               for line in outcome.normalisation.unread_values)


def test_a_counterexample_reusing_an_evidence_id_is_not_absorbed(tmp_path):
    """The worst form of D6: a found counterexample named like a passing test
    result was absorbed into it, and the release promoted."""
    reused = {"record_type": "evidence", "evidence_id": "e1", "kind": "COUNTEREXAMPLE",
              "producer": {"producer_id": "fuzz://lab", "kind": "tool"},
              "applies_to": DIGEST, "contradicts_claims": ["C-1"],
              "coverage_note": "a EUR transfer crossed the limit"}
    outcome = _run(tmp_path, _rows() + [reused])
    assert _decision(outcome) == "BLOCK"
    assert any("'e1'" in line for line in outcome.normalisation.unread_values)


def test_a_restamped_evidence_replay_is_still_one_record(tmp_path):
    first = next(r for r in BASE if r.get("evidence_id") == "e1")
    replays = [dict(copy.deepcopy(first), timestamp=f"2026-09-17T10:{i:02d}:00Z")
               for i in range(5)]
    outcome = _run(tmp_path, _rows() + replays)
    assert _decision(outcome) == "PROMOTE"
    assert not outcome.normalisation.unread_values


# ── D7: the hosted API's case is the CLI's case ─────────────────────────────
#
# The decision always agreed (117 corpus runs: the case verdict, the admission
# engine, the report and the exit code never differ). The case did not: the
# API read each submission from a randomly named temporary file, the path is
# part of the case, and so the digest it returned changed on every call and
# matched no CLI run of the same bytes — a digest nobody could reproduce,
# including the API itself.

def test_the_hosted_api_and_the_cli_reach_the_same_case(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from release_gate_api._app import app
    content = RELEASE.read_text()
    client = TestClient(app)
    body = {"content": content, "methodology": "general-agent-action@1.0.0"}
    first = client.post("/api/assure", json=body).json()
    second = client.post("/api/assure", json=body).json()
    assert first["case"]["digest"] == second["case"]["digest"]

    name = first["case"]["source"]
    (tmp_path / name).write_text(content)
    monkeypatch.chdir(tmp_path)
    local = assure(name, methodology=GENERAL)
    assert local.case.verdict.decision.value == first["decision"]
    assert local.case.case_digest == first["case"]["digest"]


# ── D8: what was tried and failed reaches the admission record ───────────────
#
# A declared failed branch — a proof that died at a step, a property run that
# broke — reached the case's ledger and the review, and appeared nowhere in the
# Admission Report, which is the record a pipeline keeps of what was admitted
# and why. A reader of the artifact could not tell that anything had failed
# beside the checks that passed.

def test_a_failed_branch_is_in_the_admission_report(tmp_path):
    from release_gate.assurance.admission_report import (build_admission_report,
                                                         render_admission_report)
    branch = {"record_type": "failed_branch", "outcome": "INVARIANT_VIOLATED",
              "bears_on_claims": ["C-1"], "invariant": "balance >= 0",
              "produced_by": "sim://ledger", "detail": "a refund ran twice"}
    outcome = _run(tmp_path, _rows() + [branch])
    report = build_admission_report(outcome)
    listed = report.to_dict()["failed_branches"]
    assert [(b["outcome"], b["claims"], b["produced_by"]) for b in listed] == [
        ("INVARIANT_VIOLATED", ["C-1"], "sim://ledger")]
    assert "a refund ran twice" in listed[0]["detail"]
    text = render_admission_report(report)
    assert "FAILED BRANCHES (1)" in text and "a refund ran twice" in text


def test_a_report_with_no_failed_branch_says_so(tmp_path):
    from release_gate.assurance.admission_report import (build_admission_report,
                                                         render_admission_report)
    report = build_admission_report(_run(tmp_path, _rows()))
    assert report.to_dict()["failed_branches"] == []
    assert "FAILED BRANCHES — none" in render_admission_report(report)


# ── Defended areas, pinned ───────────────────────────────────────────────────
#
# Areas the audit attacked and found defended. Each test is the attack, so the
# defence cannot be removed without a test naming what it reopens.

@pytest.mark.parametrize("release, methodology", [
    ("examples/agents/02-release-promoted.jsonl", GENERAL),
    ("examples/agents/02-release-promoted.jsonl", None),
    ("examples/agents/04-production-db-change.jsonl", GENERAL),
    ("examples/evidence/release.jsonl", GENERAL),
])
def test_a_provider_outage_never_moves_a_decision(release, methodology):
    """Area 21. Every question unanswered because the provider was down."""
    from release_gate.assurance.semantic_verifier import (AssertionStatus,
                                                          SemanticAssertion,
                                                          UnknownReason,
                                                          state_hash_for)
    before = assure(str(ROOT / release), methodology=methodology)
    state = state_hash_for(before.analysis)
    down = [SemanticAssertion(
        question_id=f"sq_{r.claim_id}", claim_id=r.claim_id,
        status=AssertionStatus.UNKNOWN,
        unknown_reason=UnknownReason.PROVIDER_UNAVAILABLE,
        model="m", provider="p", state_hash=state)
        for r in before.analysis.resolution.resolutions]
    after = assure(str(ROOT / release), methodology=methodology,
                   semantic_assertions=down)
    assert after.case.verdict.decision is before.case.verdict.decision
    for r in before.analysis.resolution.resolutions:
        assert after.analysis.resolution.of(r.claim_id).status is r.status


def test_an_approval_replayed_onto_another_case_is_foreign(tmp_path):
    """Area 18. The same approval, presented to a case it was not given for."""
    from release_gate.assurance.approval import check_approval
    approval = _approve(_fixed_run(tmp_path))
    other = tmp_path / "other"
    other.mkdir()
    rows = _rows()
    rows.append({"record_type": "claim", "claim_id": "C-9", "proposition": "another"})
    (other / "release.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    found = check_approval(approval, assure(str(other / "release.jsonl"),
                                            methodology=GENERAL).case)
    assert found.standing.value == "APPROVAL_FOREIGN"
    assert found.needs_new_approval


def test_an_envelope_cannot_claim_to_be_release_gate():
    """Area 14. A record naming release-gate's own producer, kind and basis."""
    from release_gate.assurance.ingest import _record_producer
    from release_gate.assurance.evidence import Producer, ProducerKind
    fallback = Producer(producer_id="file", kind=ProducerKind.EXTERNAL)
    for kind in ("release_gate", "RELEASE_GATE"):
        claimed = _record_producer(
            {"producer": {"producer_id": "release-gate/assurance/ingest", "kind": kind,
                          "identity_basis": "in-process"}}, fallback)
        assert claimed.kind is not ProducerKind.RELEASE_GATE
        assert claimed.identity_basis == "unauthenticated"


@pytest.mark.parametrize("shift", [100, -30])
def test_moving_every_timestamp_moves_no_decision(tmp_path, shift):
    """Area 15. The decision reads stated state, never a clock."""
    import re
    stamp = re.compile(r'"(\d{4})-(\d\d-\d\dT[0-9:.]+Z?)"')
    text = RELEASE.read_text()
    moved = stamp.sub(lambda m: f'"{int(m.group(1)) + shift}-{m.group(2)}"', text)
    rows = [json.loads(line) for line in moved.splitlines() if line.strip()]
    before = _run(tmp_path, _rows(), name="before.jsonl")
    after = _run(tmp_path, rows, name="after.jsonl")
    assert _decision(after) == _decision(before)
    assert _fired(after) == _fired(before)


def test_row_order_moves_no_decision(tmp_path):
    """Area 25. Same records, any order: same decision, rules and claims."""
    import random
    rows = [json.loads(line) for line in
            (ROOT / "examples/evidence/release.jsonl").read_text().splitlines()
            if line.strip()]

    def read(order, name):
        o = _run(tmp_path, order, name=name)
        v = o.case.verdict
        return (v.decision.value,
                sorted(r for r in v.fired_rules if not r.startswith("contra_")),
                sorted((r.claim_id, r.status.value) for r in
                       o.analysis.resolution.resolutions))

    first = read(rows, "in-order.jsonl")
    for seed in range(3):
        shuffled = rows[:]
        random.Random(seed).shuffle(shuffled)
        assert read(shuffled, f"shuffled-{seed}.jsonl") == first


# ── D9: a scanner's verdict cannot pass for an admission ────────────────────
#
# `audit`, `pr` and `score` decide PROMOTE / HOLD / BLOCK over what they
# examine, and the Action exposes every command's verdict through one
# `decision` output. A deploy job gated on `decision == 'PROMOTE'` admitted a
# release on a code scan alone if the step ran `command: audit` — no evals, no
# approvals, no policy — and nothing in the output said which kind of decision
# it was. Exit codes and `decision` are unchanged; what reached the decision is
# now said.

def test_the_action_says_what_reached_the_decision():
    import yaml
    spec = yaml.safe_load((ROOT / "action.yml").read_text())
    decided_by = spec["outputs"]["decided-by"]
    assert "inputs.command == 'assure' && 'admission'" in decided_by["value"]
    assert "admission" in decided_by["description"]


def test_the_scanners_verdict_names_its_scope():
    import subprocess
    import sys
    done = subprocess.run(
        [sys.executable, "-m", "release_gate.cli", "audit",
         str(ROOT / "examples" / "demo-code-risk" / "vulnerable")],
        capture_output=True, text=True, cwd=str(ROOT))
    assert "Decision:" in done.stdout
    assert "not an admission decision" in done.stdout
    assert "release-gate assure" in done.stdout


# ── D10: a result whose wording names another claim is not quietly counted ──
#
# Results join a claim by id. A review that named `cl_x` while stating the
# refund-policy claim's wording — a mapping error in the producer, or an id
# reused across releases — was joined to `cl_x` and counted as its support,
# and the release promoted. The wording is the producer's own account of what
# it evaluated; where it is not the claim's, which claim the result bears on
# cannot be read. Results that name the claim by id alone, or state it as the
# case does (whitespace and case aside), join exactly as before.

def _review(text):
    return {"schema": "release-gate.review/1", "evaluated_at": "2026-10-03T12:00:00Z",
            "reviews": [{"id": "rev-1", "reviewer": {"id": "dana@example.com",
                                                     "role": "owner"},
                         "decision": "approve", "claim_id": "cl_x", "claim": text,
                         "state": BOUND, "reviewed_at": "2026-10-03T11:00:00Z"}]}


@pytest.mark.parametrize("text", [TARGET, "  no transfer executes WITHOUT authorization. "])
def test_a_result_stating_the_claim_joins_it(tmp_path, text):
    outcome = _run(tmp_path, _payments(_review(text)))
    assert _decision(outcome) == "PROMOTE"
    assert not outcome.normalisation.unread_values


def test_a_result_stating_another_claim_holds(tmp_path):
    outcome = _run(tmp_path, _payments(
        _review("Refund answers follow the published refund policy")))
    assert _decision(outcome) == "HOLD"
    assert any("cl_x" in line and "refund policy" in line
               for line in outcome.normalisation.unread_values)


# ── D11: a promptfoo score is not a promptfoo verdict ───────────────────────
#
# The admission path reused the scanner-side promptfoo reader, which, when a
# row carried no boolean `success` and no grading `pass`, decided the row by
# `score > 0`. `{"success": "false", "score": 0.9}` read as a pass: an
# evaluator's score thresholded into a verdict, which the admission path
# promises never to do. The scanner-side reader (`release-gate score`) keeps its
# reading; the admission adapter now reads only what promptfoo stated.

def _promptfoo(*rows):
    return {"evalId": "eval-1",
            "results": {"version": 3, "results": list(rows),
                        "stats": {"successes": 1, "failures": 0}}}


def _promptfoo_attempts(outcome):
    return [a for a in outcome.analysis.verification_graph.attempts
            if a.verifier == "promptfoo"]


@pytest.mark.parametrize("row", [
    {"success": "false", "score": 0.9},
    {"success": "yes", "score": 1},
    {"score": 0.01},
], ids=["string-false", "string-yes", "score-only"])
def test_a_promptfoo_row_with_no_stated_verdict_is_never_a_pass(tmp_path, row):
    row = {**row, "testCase": {"description": "refund case"}}
    outcome = _run(tmp_path, _payments(_promptfoo(row)))
    assert all(a.status.value != "PASSED" for a in _promptfoo_attempts(outcome))
    assert _decision(outcome) != "PROMOTE"
    assert any("promptfoo" in line for line in outcome.normalisation.unread_values)


@pytest.mark.parametrize("row, status", [
    ({"success": True, "score": 0.0}, "PASSED"),
    ({"success": False, "score": 1.0}, "FAILED"),
    ({"gradingResult": {"pass": False, "score": 0.9}}, "FAILED"),
    ({"error": "timeout", "score": 1.0}, "FAILED"),
])
def test_what_promptfoo_states_is_read_as_before(tmp_path, row, status):
    row = {**row, "testCase": {"description": "refund case"}}
    outcome = _run(tmp_path, _payments(_promptfoo(row)))
    assert [a.status.value for a in _promptfoo_attempts(outcome)] == [status]
    assert not outcome.normalisation.unread_values


def test_the_scanner_side_promptfoo_reading_is_unchanged():
    from release_gate.adapters.promptfoo import _passed
    assert _passed({"score": 0.5}, {}) is True


def test_an_unread_word_is_never_a_pass_even_where_the_shared_table_reads_one(tmp_path):
    row = {"success": "true", "score": 1, "testCase": {"description": "refund case"}}
    outcome = _run(tmp_path, _payments(_promptfoo(row)))
    assert [a.status.value for a in _promptfoo_attempts(outcome)] == ["UNKNOWN"]


def test_an_engine_ruleset_change_after_approval_requires_review(tmp_path, monkeypatch):
    """D3, the third part of the rules a person approved under."""
    from release_gate.assurance import zero_config
    from release_gate.assurance.approval import check_approval
    approval = _approve(_fixed_run(tmp_path))
    assert "ruleset" in approval.bound_policy
    monkeypatch.setattr(zero_config, "ZERO_CONFIG_RULESET_VERSION", "zero-config-next")
    found = check_approval(approval, _fixed_run(tmp_path).case)
    assert found.standing.value == "APPROVAL_REVIEW_REQUIRED"
    assert found.moved_policy == ("ruleset",)
