"""Evidence identity and exact-state binding.

An approval binds to an exact state; so must the evidence behind it. A formal
proof of `transfer_tool_v2`, presented beside a candidate that ships v3, used to
read its claim VERIFIED under every methodology release-gate ships. These tests
hold the replacement: a candidate is a set of canonical components, every
claim-bearing record is bound against it, and support from a different state is
withheld — with the reason printed — while a refutation from one still stands.

The scenarios asked for are each a test class below: same state, prompt only,
model, tool schema, code, governance, a stale eval result, a stale formal proof,
and an incomplete identity.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.candidate import (
    CANDIDATE_METADATA_KEY, CandidateError, CandidateSource, CandidateState,
    StateMatch, bind)
from release_gate.assurance.claims import ClaimGraph, ClaimStatus

ROOT = Path(__file__).resolve().parent.parent

D = {name: "sha256:" + ch * 64 for name, ch in
     (("p0", "a"), ("p1", "b"), ("t0", "c"), ("t1", "d"), ("g0", "e"), ("g1", "f"),
      ("e0", "1"), ("e1", "2"), ("v2", "3"), ("v3", "4"), ("tree0", "5"), ("tree1", "6"))}

BASE = {
    "repository": "https://github.com/acme/agent",
    "commit": "9f2c1a7e4b0d3c2a1f9e8d7c6b5a4f3e2d1c0b9a",
    "tree": D["tree0"],
    "model": "gpt-4o-2024-08-06",
    "prompt": D["p0"],
    "tool_manifest": D["t0"],
    "governance_policy": D["g0"],
    "eval_definition": D["e0"],
}

P = {"producer_id": "ci://acme/pipeline", "kind": "tool"}


def candidate(**over) -> CandidateState:
    components = dict(BASE)
    components.update(over)
    return CandidateState(components={k: v for k, v in components.items() if v},
                          source=CandidateSource.DECLARED_BY_CALLER, declared_by="test")


def envelope(state=None, *, passed=True, attempt_state=None, refutes=False,
             digest=None, extra=()):
    """A claim with one supporting (or refuting) record bound to `state`."""
    claim = {"record_type": "claim", "claim_id": "c-release",
             "proposition": "the agent release is safe to admit", "producer": P,
             "is_root": True}
    if attempt_state is not None or digest is not None:
        attempt = {"method": "TEST_SUITE", "outcome": "PASSED" if passed else "FAILED",
                   "verifier": "ci://acme/pytest", "detail": "suite"}
        if attempt_state is not None:
            attempt["result"] = {"state": attempt_state}
        if digest is not None:
            attempt["target_digest"] = digest
        claim["verification_attempts"] = [attempt]
    rows = [claim]
    if state is not None:
        rows.append({"record_type": "evidence", "evidence_id": "e-run", "kind": "TEST_RESULT",
                     "producer": P, "state": state,
                     ("contradicts_claims" if refutes else "supports_claims"): ["c-release"],
                     "coverage_note": "the integration suite"})
    rows.extend(extra)
    return rows


def run(tmp_path, rows, cand=None, name="case.json", methodology=None):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(rows), encoding="utf-8")
    return assure(str(path), candidate=cand, methodology=methodology)


def status(outcome, claim_id="c-release") -> ClaimStatus:
    return ClaimGraph.from_case(outcome.case).status(claim_id)


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def bindings(outcome):
    return {b.record_id: b for b in outcome.analysis.state_binding.bindings}


def the_binding(outcome, kind="evidence"):
    found = [b for b in outcome.analysis.state_binding.bindings if b.record_kind == kind]
    assert len(found) == 1, found
    return found[0]


# ── the candidate itself ─────────────────────────────────────────────────────

class TestTheCandidate:

    def test_its_digest_is_deterministic_and_order_free(self):
        a = CandidateState(components=dict(BASE))
        b = CandidateState(components=dict(reversed(list(BASE.items()))))
        assert a.digest() == b.digest()

    def test_its_digest_is_about_the_state_not_who_declared_it(self):
        a = CandidateState(components=dict(BASE), declared_by="ci")
        b = CandidateState(components=dict(BASE), declared_by="someone else",
                           source=CandidateSource.DECLARED_BY_SUBMISSION)
        assert a.digest() == b.digest()

    def test_one_change_moves_the_digest(self):
        assert candidate().digest() != candidate(prompt=D["p1"]).digest()

    @pytest.mark.parametrize("left,right", [
        ("https://github.com/Acme/agent", "git@github.com:Acme/agent.git"),
        ("https://GitHub.com/Acme/agent/", "https://token@github.com/Acme/agent.git"),
    ])
    def test_one_repository_has_one_spelling(self, left, right):
        assert (CandidateState(components={"repository": left}).components
                == CandidateState(components={"repository": right}).components)

    def test_digests_and_commits_are_compared_without_case(self):
        a = CandidateState(components={"prompt": D["p0"].upper().replace("SHA256", "sha256"),
                                       "commit": "9F2C1A7"})
        assert a.components["prompt"] == D["p0"]
        assert a.components["commit"] == "9f2c1a7"

    def test_a_misspelt_component_is_refused(self):
        with pytest.raises(CandidateError, match="not a candidate component"):
            CandidateState(components={"modle": "gpt-4o"})

    def test_a_control_character_is_refused(self):
        with pytest.raises(CandidateError, match="control character"):
            CandidateState(components={"environment": "prod\nFORGED: approved"})

    def test_artifacts_and_custom_dimensions_are_named_not_guessed(self):
        c = CandidateState(components={"artifact:transfer_tool": D["v3"],
                                       "custom:feature_flags": "flags-v12"})
        assert set(c.components) == {"artifact:transfer_tool", "custom:feature_flags"}

    def test_what_it_does_not_state_is_listed(self):
        c = CandidateState(components={"repository": BASE["repository"]})
        assert "model" in c.missing() and "repository" not in c.missing()

    def test_a_newer_schema_is_refused_rather_than_read_loosely(self):
        with pytest.raises(CandidateError, match="newer"):
            CandidateState.from_dict({"schema_version": 99, "components": dict(BASE)})

    def test_an_abbreviated_commit_matches_its_full_form(self):
        b = bind(candidate(), state={"commit": BASE["commit"][:7]}, record_id="e",
                 record_kind="evidence", supports=True)
        assert b.match is StateMatch.PARTIAL


# ── the scenarios ────────────────────────────────────────────────────────────

class TestSameState:

    def test_evidence_naming_every_component_is_exact_and_counts(self, tmp_path):
        out = run(tmp_path, envelope(attempt_state=dict(BASE)), candidate())
        assert the_binding(out, "verification").match is StateMatch.EXACT
        assert status(out) is ClaimStatus.VERIFIED
        assert not rules(out) & {"RG-DRIFT-006", "RG-DRIFT-007", "RG-DRIFT-008"}

    def test_the_same_inputs_bind_the_same_way_twice(self, tmp_path):
        first = run(tmp_path, envelope(dict(BASE)), candidate(), "a.json")
        second = run(tmp_path, envelope(dict(BASE)), candidate(), "a.json")
        assert first.case.case_digest == second.case.case_digest
        assert [b.to_dict() for b in first.analysis.state_binding.bindings] == [
            b.to_dict() for b in second.analysis.state_binding.bindings]


@pytest.mark.parametrize("component,changed", [
    ("prompt", D["p1"]),                       # modified prompt only
    ("model", "gpt-4o-2024-11-20"),            # changed model
    ("tool_manifest", D["t1"]),                # changed tool schema
    ("commit", "0" * 40),                      # changed code
    ("tree", D["tree1"]),                      # changed code, by tree
    ("governance_policy", D["g1"]),            # changed governance
])
class TestOneComponentChanged:

    def test_the_evidence_is_stale(self, tmp_path, component, changed):
        out = run(tmp_path, envelope(attempt_state=dict(BASE)),
                  candidate(**{component: changed}))
        b = the_binding(out, "verification")
        assert b.match is StateMatch.STALE
        assert [c.component for c in b.mismatches()] == [component]

    def test_its_support_no_longer_satisfies_the_claim(self, tmp_path, component, changed):
        out = run(tmp_path, envelope(attempt_state=dict(BASE)),
                  candidate(**{component: changed}))
        assert status(out) is ClaimStatus.UNKNOWN
        basis = ClaimGraph.from_case(out.case).assessment("c-release").basis
        assert "withheld" in basis

    def test_it_holds_and_says_which_component_moved(self, tmp_path, component, changed):
        out = run(tmp_path, envelope(attempt_state=dict(BASE)),
                  candidate(**{component: changed}))
        assert "RG-DRIFT-006" in rules(out)
        assert out.case.verdict.decision.value != "PROMOTE"
        reason = the_binding(out, "verification").reason
        assert component in reason and "withheld" in reason

    def test_a_refutation_from_that_state_still_stands(self, tmp_path, component, changed):
        """The asymmetry: stale support is withheld, a stale defect is not."""
        out = run(tmp_path, envelope(dict(BASE), refutes=True),
                  candidate(**{component: changed}))
        assert the_binding(out).match is StateMatch.STALE
        assert status(out) is ClaimStatus.REFUTED


class TestStaleEvalResult:
    """A real promptfoo run, read through its adapter, against a moved candidate."""

    def _promptfoo(self):
        rows = [{"success": True, "score": 1, "testCase": {"description": f"case {i}"},
                 "provider": {"id": "openai:gpt-4o"},
                 "prompt": {"raw": "You are a support agent.", "label": "support"}}
                for i in range(3)]
        return {"evalId": "eval-1", "results": {"version": 3, "results": rows,
                                                 "stats": {"successes": 3, "failures": 0}}}

    def _prompt_digest(self):
        from release_gate.assurance.canonical import digest_bytes
        return digest_bytes(b"You are a support agent.")

    def test_the_eval_binds_to_the_model_and_prompt_it_ran_against(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "evals.json"
        path.write_text(json.dumps(self._promptfoo()), encoding="utf-8")
        out = assure(str(path), candidate=CandidateState(components={
            "model": "openai:gpt-4o", "prompt": self._prompt_digest()}))
        assert {b.match for b in out.analysis.state_binding.bindings} == {StateMatch.EXACT}
        assert status(out, "cl_eval_0") is not ClaimStatus.UNKNOWN

    def test_after_the_prompt_changes_the_eval_is_stale(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        path = tmp_path / "evals.json"
        path.write_text(json.dumps(self._promptfoo()), encoding="utf-8")
        out = assure(str(path), candidate=CandidateState(components={
            "model": "openai:gpt-4o", "prompt": D["p1"]}))
        stale = [b for b in out.analysis.state_binding.bindings
                 if b.match is StateMatch.STALE]
        assert stale and all(b.withholds_support for b in stale if b.supports)
        assert status(out, "cl_eval_0") is ClaimStatus.UNKNOWN
        assert "RG-DRIFT-006" in rules(out)

    def test_an_eval_definition_that_moved_makes_it_stale(self, tmp_path):
        out = run(tmp_path, envelope({"eval_definition": D["e0"], "model": BASE["model"]}),
                  candidate(eval_definition=D["e1"]))
        assert the_binding(out).match is StateMatch.STALE


class TestStaleFormalProof:
    """`transfer_tool_v2` proved; `transfer_tool_v3` is the candidate."""

    def _rows(self, *, named: bool):
        attempt = {"method": "FORMAL_PROOF", "outcome": "PASSED", "verifier": "lean@4.8",
                   "detail": "proof of transfer_tool_v2"}
        if named:
            attempt["result"] = {"state": {"artifact:transfer_tool": D["v2"]}}
        else:
            attempt["target_digest"] = D["v2"]
        return [
            {"record_type": "artifact", "artifact_id": "transfer_tool",
             "kind": "SOURCE_CODE", "digest": D["v3"], "producer": P},
            {"record_type": "claim", "claim_id": "c-transfer", "is_root": True,
             "proposition": "transfer_tool cannot move funds without approval",
             "producer": P, "verification_attempts": [attempt]}]

    def test_with_no_candidate_stated_the_case_artifacts_still_catch_it(self, tmp_path):
        out = run(tmp_path, self._rows(named=False))
        assert out.analysis.state_binding.candidate.source is \
            CandidateSource.IMPLIED_BY_ARTIFACTS
        assert the_binding(out, "verification").match is StateMatch.STALE
        assert status(out, "c-transfer") is ClaimStatus.UNKNOWN
        assert "RG-DRIFT-006" in rules(out)

    def test_named_against_a_stated_candidate_it_names_the_artifact(self, tmp_path):
        out = run(tmp_path, self._rows(named=True), CandidateState(components={
            "artifact:transfer_tool": D["v3"]}))
        b = the_binding(out, "verification")
        assert b.match is StateMatch.STALE
        assert b.mismatches()[0].component == "artifact:transfer_tool"
        assert "artifact:transfer_tool is sha256:333" in b.reason

    def test_under_every_shipped_methodology_the_claim_is_not_verified(self, tmp_path):
        """Before this, every one of these read the claim VERIFIED."""
        from release_gate.assurance.methodologies import default_registry
        registry = default_registry()
        for ref in [f"{i}@{v}" for i in registry.ids() for v in registry.versions(i)]:
            out = run(tmp_path, self._rows(named=False), name="p.json",
                      methodology=registry.resolve(ref))
            assert status(out, "c-transfer") is not ClaimStatus.VERIFIED, ref

    def test_the_proof_of_v3_is_accepted(self, tmp_path):
        rows = self._rows(named=False)
        rows[1]["verification_attempts"][0]["target_digest"] = D["v3"]
        out = run(tmp_path, rows)
        # PARTIAL, not EXACT: the attempt names the tool, not the input file the
        # implied candidate also holds. What it names matches, so it counts.
        assert the_binding(out, "verification").match is StateMatch.PARTIAL
        assert status(out, "c-transfer") is ClaimStatus.VERIFIED


class TestIncompleteIdentity:

    def test_a_candidate_that_states_too_little_cannot_be_checked_against(self, tmp_path):
        thin = CandidateState(components={"repository": BASE["repository"]})
        out = run(tmp_path, envelope({"commit": BASE["commit"], "model": BASE["model"]}),
                  thin)
        b = the_binding(out)
        assert b.match is StateMatch.UNKNOWN
        found = rules(out)
        assert "RG-DRIFT-008" in found and "RG-DRIFT-009" in found
        unchecked = next(f for f in out.analysis.findings if f.rule_id == "RG-DRIFT-009")
        assert set(unchecked.observed["unchecked_components"]) == {"commit", "model"}

    def test_unbound_support_against_a_stated_candidate_holds(self, tmp_path):
        out = run(tmp_path, envelope({}), candidate())
        assert the_binding(out).match is StateMatch.UNKNOWN
        assert "RG-DRIFT-008" in rules(out)
        assert out.case.verdict.decision.value != "PROMOTE"

    def test_without_a_stated_candidate_unbound_support_is_not_a_finding(self, tmp_path):
        """Nothing said what it should have been bound to."""
        out = run(tmp_path, envelope({"model": BASE["model"]}))
        assert "RG-DRIFT-008" not in rules(out)


class TestADifferentSubject:

    def test_another_repository_is_incompatible_not_stale(self, tmp_path):
        out = run(tmp_path, envelope({**BASE, "repository": "https://github.com/other/svc"}),
                  candidate())
        assert the_binding(out).match is StateMatch.INCOMPATIBLE
        assert "RG-DRIFT-007" in rules(out)
        assert status(out) is ClaimStatus.UNKNOWN

    def test_another_environment_is_incompatible(self, tmp_path):
        out = run(tmp_path, envelope({**BASE, "environment": "staging"}),
                  candidate(environment="prod-eu"))
        assert the_binding(out).match is StateMatch.INCOMPATIBLE


# ── where the candidate comes from ──────────────────────────────────────────

class TestWhereTheCandidateComesFrom:

    def _with_candidate_row(self, components):
        return envelope(dict(BASE), extra=[
            {"record_type": "candidate", "components": components, "producer": P}])

    def test_a_submission_can_state_its_own_and_it_is_labelled_so(self, tmp_path):
        out = run(tmp_path, self._with_candidate_row(dict(BASE)))
        c = out.analysis.state_binding.candidate
        assert c.source is CandidateSource.DECLARED_BY_SUBMISSION
        assert c.declared_by == "ci://acme/pipeline"
        n = out.normalisation
        assert n.records_mapped == n.records_seen

    def test_the_callers_candidate_wins_and_the_override_is_said(self, tmp_path):
        out = run(tmp_path, self._with_candidate_row(dict(BASE)),
                  candidate(prompt=D["p1"]))
        assert out.analysis.state_binding.candidate.source is \
            CandidateSource.DECLARED_BY_CALLER
        assert any("the caller's candidate" in note for note in out.normalisation.notes)
        assert the_binding(out).match is StateMatch.STALE

    def test_two_candidates_in_one_submission_are_neither_chosen(self, tmp_path):
        rows = self._with_candidate_row(dict(BASE)) + [
            {"record_type": "candidate", "components": {**BASE, "model": "other"}}]
        out = run(tmp_path, rows)
        assert any("different candidates" in note for note in out.normalisation.notes)
        assert CANDIDATE_METADATA_KEY not in out.case.metadata

    def test_the_candidate_is_bound_into_the_case_digest(self, tmp_path):
        a = run(tmp_path, envelope(dict(BASE)), candidate(), "x.json")
        b = run(tmp_path, envelope(dict(BASE)), candidate(prompt=D["p1"]), "x.json")
        assert a.case.metadata[CANDIDATE_METADATA_KEY]["digest"] == candidate().digest()
        assert a.case.case_digest != b.case.case_digest

    def test_a_case_with_no_candidate_carries_no_key(self, tmp_path):
        out = run(tmp_path, envelope(dict(BASE)))
        assert CANDIDATE_METADATA_KEY not in out.case.metadata


class TestAnAuditImpliesItsCandidate:

    @pytest.fixture
    def report(self, tmp_path):
        import shutil
        if not shutil.which("git"):
            pytest.skip("git is not available")
        from release_gate.audit import build_report
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "agent.py").write_text(
            (ROOT / "examples/demo-code-risk/vulnerable/agent.py").read_text(),
            encoding="utf-8")
        (repo / "prompts").mkdir()
        (repo / "prompts" / "system.txt").write_text("You are careful.\n", encoding="utf-8")
        for args in (["init", "-q"], ["add", "."],
                     ["-c", "user.email=t@example.com", "-c", "user.name=t",
                      "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"]):
            subprocess.run(["git", "-C", str(repo), *args], check=True,
                           capture_output=True)
        return build_report(repo)

    def test_the_audit_records_the_behaviour_components(self, report):
        behaviour = report["evidence_provenance"]["behaviour"]
        assert behaviour["prompt"]["files"] == 1
        assert behaviour["prompt"]["digest"].startswith("sha256:")

    def test_its_candidate_is_what_it_scanned(self, tmp_path, report):
        out = run(tmp_path, report, name="audit.json")
        c = out.analysis.state_binding.candidate
        assert c.source is CandidateSource.DERIVED_FROM_AUDIT
        block = report["evidence_provenance"]
        assert c.components["commit"] == block["candidate"]["commit"]
        assert c.components["tree"] == block["candidate"]["scanned_set"]["digest"]
        assert c.components["prompt"] == block["behaviour"]["prompt"]["digest"]
        assert c.components["model"] == report["detected_model"]

    def test_its_own_evidence_binds_and_nothing_is_withheld(self, tmp_path, report):
        out = run(tmp_path, report, name="audit.json")
        matches = {b.match for b in out.analysis.state_binding.bindings}
        assert matches <= {StateMatch.EXACT, StateMatch.PARTIAL}
        assert not out.analysis.state_binding.withheld_evidence
        assert not rules(out) & {"RG-DRIFT-006", "RG-DRIFT-007", "RG-DRIFT-008"}

    def test_against_a_moved_commit_its_support_is_withheld(self, tmp_path, report):
        from release_gate.assurance.static_producer import ScanProvenance
        derived = ScanProvenance.from_report(report).candidate_state(report)
        moved = CandidateState(components={**derived.components, "commit": "0" * 40})
        out = run(tmp_path, report, moved, name="audit.json")
        assert any(b.match is StateMatch.STALE
                   for b in out.analysis.state_binding.bindings)


# ── the explanation, on every surface ───────────────────────────────────────

class TestWhyEvidenceWasRejectedIsShown:

    def _stale(self, tmp_path):
        return run(tmp_path, envelope(attempt_state=dict(BASE)), candidate(model="gpt-5"))

    def test_the_terminal_report_names_the_record_and_the_component(self, tmp_path):
        from release_gate.assurance.zero_config import render_text
        text = render_text(self._stale(tmp_path))
        assert "STATE BINDING" in text
        assert "model is gpt-4o-2024-08-06 in the record and gpt-5 in the candidate" in text
        assert "its support was withheld" in text

    def test_the_review_carries_it(self, tmp_path):
        from release_gate.assurance.review import build_review, render_review
        review = build_review(self._stale(tmp_path))
        assert review.state_lines and review.state_lines[0].withheld
        rendered = render_review(review)
        assert "STATE BINDING" in rendered and "[STALE]" in rendered
        withheld = next(f for f in review.state_figures if f.label == "Support withheld")
        assert withheld.value == 1

    def test_the_json_outcome_carries_every_binding(self, tmp_path):
        out = self._stale(tmp_path)
        report = out.analysis.state_binding.to_dict()
        assert report["support_withheld"] == 1
        assert report["bindings"][0]["reason"].startswith("bound to a different state")

    def test_the_web_demo_response_carries_it(self, tmp_path):
        pytest.importorskip("fastapi")
        from release_gate_api._app import _state_binding_view
        view = _state_binding_view(self._stale(tmp_path))
        assert view["support_withheld"] == 1
        assert view["records"][0]["match"] == "STALE"
        assert "gpt-5" in view["records"][0]["reason"]

    def test_the_demo_page_renders_it_escaped(self):
        page = (ROOT / "public" / "assurance.html").read_text(encoding="utf-8")
        assert "Evidence against the candidate" in page
        block = page[page.index("const sb = d.state_binding"):]
        block = block[:block.index("    : '';")]
        assert "esc(r.reason)" in block and "esc(r.record_id)" in block


class TestTheCli:

    def _files(self, tmp_path, cand):
        case = tmp_path / "case.json"
        case.write_text(json.dumps(envelope(attempt_state=dict(BASE))), encoding="utf-8")
        cfile = tmp_path / "candidate.json"
        cfile.write_text(json.dumps(cand), encoding="utf-8")
        return case, cfile

    def _cli(self, *args):
        return subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", *args],
                              capture_output=True, text=True, timeout=300)

    def test_a_candidate_file_is_applied(self, tmp_path):
        case, cfile = self._files(tmp_path, {**BASE, "prompt": D["p1"]})
        result = self._cli(str(case), "--candidate", str(cfile))
        assert "STATE BINDING" in result.stdout
        assert "DECLARED_BY_CALLER" in result.stdout
        assert result.returncode != 0

    def test_a_misspelt_component_is_an_error_not_a_silent_miss(self, tmp_path):
        case, cfile = self._files(tmp_path, {"modle": "gpt-4o"})
        result = self._cli(str(case), "--candidate", str(cfile))
        assert result.returncode == 1
        assert "not a candidate component" in result.stdout
