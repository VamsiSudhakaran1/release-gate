"""Claim coverage — what portion of the required claim surface was actually assessed.

Pinned here, against release_gate/assurance/claim_coverage.py and the analysis that
reads it:

* the example: refund and delete pass, transfer was never assessed, email failed —
  3 of 4 assessed, 1 not assessed, 1 assessed failure, and transfer named as
  missing; never a percentage of safety;
* six statuses kept apart: assessed and supported, assessed and failed, not
  assessed, inaccessible, not applicable, unknown;
* evidence covers only what it names: "eight checks passed" covers nothing;
* evidence the resolution set aside — another state, inadmissible — covers nothing;
* the policy decides what a shortfall does: by default every dimension of a
  required claim's surface must be fully assessed, and a shortfall holds;
* not assessed never becomes passed, under any policy.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_gate.assurance.analysis import _analyse_claim_coverage
from release_gate.assurance.claim_coverage import (ClaimSurface, ClaimSurfaceError,
                                                   SurfaceStatus, assess_claim_coverage,
                                                   canonical_dimension, conditions_of)
from release_gate.assurance.resolution import (DEFAULT_RESOLUTION_POLICY, ResolutionError,
                                               ResolutionPolicy)
from release_gate.assurance.zero_config import assure, render_text

S = SurfaceStatus
TOOLS = ["refund", "delete", "transfer", "email"]


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def claim(surface, cid="c-approval", root=True, **kw):
    return {"record_type": "claim", "claim_id": cid, "is_root": root,
            "proposition": "All irreversible tools require approval",
            "producer": P("platform", "human"), "surface": surface, **kw}


def ev(eid, *, supports=(), contradicts=(), kind="TEST_RESULT", producer="ci", **kw):
    return {"record_type": "evidence", "evidence_id": eid, "kind": kind,
            "producer": P(producer), "supports_claims": list(supports),
            "contradicts_claims": list(contradicts), "summary": eid,
            "coverage_note": eid, **kw}


def example():
    """The prompt's example, as an envelope."""
    return [claim({"tool": TOOLS}),
            ev("e-refund", supports=["c-approval"], covers={"tool": "refund"}),
            ev("e-delete", supports=["c-approval"], covers={"tool": "delete"},
               producer="ci-2"),
            ev("e-email", contradicts=["c-approval"], covers={"tool": "email"},
               kind="TRACE", producer="otel")]


def run(tmp_path, rows, name="case.json", **kw):
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return assure(str(path), **kw)


def coverage(outcome, cid="c-approval"):
    return outcome.analysis.claim_coverage.of(cid)


def statuses(outcome, dimension="tool", cid="c-approval"):
    [dim] = [d for d in coverage(outcome, cid).dimensions if d.dimension == dimension]
    return {e.element: e.status for e in dim.elements}


def rules(outcome):
    return {f.rule_id for f in outcome.analysis.findings}


def finding(outcome, rule_id):
    return next(f for f in outcome.analysis.findings if f.rule_id == rule_id)


# ── the example ──────────────────────────────────────────────────────────────

class TestTheExample:

    def test_each_tool_is_what_the_evidence_shows(self, tmp_path):
        outcome = run(tmp_path, example())
        assert statuses(outcome) == {
            "refund": S.ASSESSED_SUPPORTED, "delete": S.ASSESSED_SUPPORTED,
            "transfer": S.NOT_ASSESSED, "email": S.ASSESSED_FAILED}

    def test_three_of_four_assessed_one_missing_one_failed(self, tmp_path):
        c = coverage(run(tmp_path, example()))
        [tool] = c.dimensions
        assert (tool.required, tool.assessed) == (4, 3)
        assert tool.count(S.NOT_ASSESSED) == 1 and tool.count(S.ASSESSED_FAILED) == 1
        assert tool.summary() == "3 of 4 assessed · 1 not assessed · 1 assessed failure"
        assert [(e.dimension, e.element) for e in c.missing] == [("tool", "transfer")]
        assert [(e.dimension, e.element) for e in c.failed] == [("tool", "email")]
        assert not c.complete

    def test_the_conclusion_is_not_a_percentage_of_safety(self, tmp_path):
        outcome = run(tmp_path, example())
        rendered = coverage(outcome).render()
        assert "%" not in rendered and "safe" not in rendered.lower()
        assert "missing: tool transfer" in rendered
        text = render_text(outcome, full=True)
        assert "CLAIM COVERAGE" in text and "transfer" in text
        assert "never counted as passed" in text

    def test_the_missing_surface_holds_and_is_named(self, tmp_path):
        outcome = run(tmp_path, example())
        held = finding(outcome, "RG-COV-006")
        assert held.effect.value == "HOLD"
        assert "tool transfer NOT_ASSESSED" in held.detail
        assert "failed tool email" in held.detail
        assert held.observed["missing"] == {"c-approval": ["tool:transfer"]}
        assert outcome.case.verdict.decision.value != "PROMOTE"

    def test_the_failure_is_the_resolutions_to_act_on(self, tmp_path):
        outcome = run(tmp_path, example())
        assert outcome.analysis.resolution.of("c-approval").status.value == "CONTRADICTED"


# ── six statuses ─────────────────────────────────────────────────────────────

class TestSixStatuses:

    def test_inaccessible_is_said_by_someone_who_tried(self, tmp_path):
        rows = example() + [ev("e-probe", supports=[], contradicts=[])]
        rows[0]["verification_attempts"] = [
            {"method": "TEST_SUITE", "outcome": "INCONCLUSIVE", "verifier": "harness",
             "inaccessible": {"tool": ["transfer"]}}]
        outcome = run(tmp_path, rows)
        assert statuses(outcome)["transfer"] is S.INACCESSIBLE
        assert ("tool", "transfer") in [(e.dimension, e.element)
                                        for e in coverage(outcome).missing]

    def test_an_inconclusive_check_is_unknown_and_still_missing(self, tmp_path):
        rows = example()
        rows[0]["verification_attempts"] = [
            {"method": "TEST_SUITE", "outcome": "INCONCLUSIVE", "verifier": "harness",
             "covers": {"tool": "transfer"}}]
        outcome = run(tmp_path, rows)
        assert statuses(outcome)["transfer"] is S.UNKNOWN
        assert "RG-COV-006" in rules(outcome)

    def test_not_applicable_is_declared_with_a_reason_and_leaves_scope(self, tmp_path):
        rows = example()
        rows[0]["surface"] = {"tool": {"required": ["refund", "delete", "email"],
                                       "not_applicable": {"transfer": "read-only export"}}}
        outcome = run(tmp_path, rows)
        assert statuses(outcome)["transfer"] is S.NOT_APPLICABLE
        [tool] = coverage(outcome).dimensions
        assert (tool.required, tool.assessed) == (3, 3)
        assert "RG-COV-006" not in rules(outcome)

    def test_a_failure_on_a_not_applicable_element_still_reads_failed(self, tmp_path):
        rows = example()
        rows[0]["surface"] = {"tool": {"required": ["refund", "delete", "transfer"],
                                       "not_applicable": {"email": "outside the pilot"}}}
        outcome = run(tmp_path, rows)
        [email] = [e for e in coverage(outcome).dimensions[0].elements
                   if e.element == "email"]
        assert email.status is S.ASSESSED_FAILED
        assert "declared not applicable" in email.note

    def test_a_pass_does_not_cancel_a_failure_on_the_same_element(self, tmp_path):
        rows = example() + [ev("e-email-pass", supports=["c-approval"],
                               covers={"tool": "email"}, producer="ci-3")]
        assert statuses(run(tmp_path, rows))["email"] is S.ASSESSED_FAILED

    def test_dropping_part_of_a_claim_needs_a_reason(self):
        with pytest.raises(ClaimSurfaceError, match="must say why"):
            ClaimSurface.from_dict({"tool": {"required": ["a"],
                                             "not_applicable": {"b": ""}}})


# ── evidence covers only what it names ───────────────────────────────────────

class TestEvidenceCoversWhatItNames:

    def test_eight_passing_checks_that_name_nothing_cover_nothing(self, tmp_path):
        rows = [claim({"tool": TOOLS})] + [
            ev(f"e-{i}", supports=["c-approval"], producer=f"tool-{i}") for i in range(8)]
        outcome = run(tmp_path, rows)
        assert set(statuses(outcome).values()) == {S.NOT_ASSESSED}
        assert len(coverage(outcome).unattributed["SUPPORTS"]) == 8
        assert "RG-COV-006" in rules(outcome)
        advisory = finding(outcome, "RG-COV-008")
        assert advisory.effect.value == "ADVISORY"
        assert "do not say which part" in advisory.summary

    def test_support_about_another_state_covers_nothing(self, tmp_path):
        rows = [{"record_type": "candidate", "components": {"commit": "def4567890"}},
                claim({"tool": ["refund"]}),
                ev("e-old", supports=["c-approval"], covers={"tool": "refund"},
                   state={"commit": "abc1234567"})]
        outcome = run(tmp_path, rows)
        [refund] = coverage(outcome).dimensions[0].elements
        assert refund.status is S.NOT_ASSESSED
        assert "another state" in refund.note

    def test_environment_and_dataset_are_read_from_the_declared_state(self, tmp_path):
        rows = [claim({"environment": ["production", "staging"]}),
                ev("e-prod", supports=["c-approval"], state={"environment": "production"})]
        outcome = run(tmp_path, rows)
        assert statuses(outcome, "environment") == {
            "production": S.ASSESSED_SUPPORTED, "staging": S.NOT_ASSESSED}

    def test_an_element_outside_the_surface_is_reported_not_counted(self, tmp_path):
        rows = [claim({"tool": ["refund"]}),
                ev("e-x", supports=["c-approval"], covers={"tool": ["refund", "export"]})]
        [tool] = coverage(run(tmp_path, rows)).dimensions
        assert tool.outside_surface == ("export",)
        assert tool.assessed == 1

    def test_per_dimension_not_per_combination(self, tmp_path):
        rows = [claim({"tool": ["refund", "transfer"],
                       "environment": ["staging", "production"]}),
                ev("e-1", supports=["c-approval"],
                   covers={"tool": "refund", "environment": "staging"}),
                ev("e-2", supports=["c-approval"], producer="ci-2",
                   covers={"tool": "transfer", "environment": "production"})]
        c = coverage(run(tmp_path, rows))
        assert c.complete and all(d.assessed == 2 for d in c.dimensions)

    @pytest.mark.parametrize("name, canonical", [
        ("tools", "tool"), ("Actions", "tool"), ("environments", "environment"),
        ("population", "dataset"), ("model", "model_version"),
        ("authorization levels", "authorization_level"),
        ("failure-modes", "failure_mode"), ("attack_class", "adversarial_class"),
        ("controls", "obligation"), ("region", "region"), ("9bad", None), ("", None)])
    def test_dimension_names(self, name, canonical):
        assert canonical_dimension(name) == canonical

    def test_conditions_are_read_wherever_the_producer_put_them(self):
        from types import SimpleNamespace
        direct = SimpleNamespace(content={"covers": {"tools": ["Refund"]}})
        nested = SimpleNamespace(content={"content": {"covers": {"tool": "refund"}}})
        attempt = SimpleNamespace(content=None, result={"covers": {"tool": "refund"}})
        for holder in (direct, nested, attempt):
            assert conditions_of(holder) == {"tool": frozenset({"refund"})}


# ── what the policy does ─────────────────────────────────────────────────────

class TestPolicy:

    def test_a_lower_share_is_held_per_dimension_never_averaged(self, tmp_path):
        rows = example()
        three_quarters = ResolutionPolicy(policy_id="p", surface_coverage=0.75)
        assert "RG-COV-006" not in rules(run(tmp_path, rows,
                                             resolution_policy=three_quarters))
        rows[0]["surface"] = {"tool": TOOLS, "environment": ["production", "staging"]}
        rows[1]["state"] = {"environment": "production"}
        rows.append(ev("e-transfer", supports=["c-approval"], covers={"tool": "transfer"},
                       producer="ci-4"))
        # tool: 4 of 4; environment: 1 of 2. Averaged, 5 of 6 clears 0.75; held
        # dimension by dimension, environment does not — and nothing averages.
        outcome = run(tmp_path, rows, resolution_policy=three_quarters)
        assert "RG-COV-006" in rules(outcome)
        assert "environment staging" in finding(outcome, "RG-COV-006").detail

    def test_a_shortfall_can_be_made_to_block(self, tmp_path):
        outcome = run(tmp_path, example(), resolution_policy=ResolutionPolicy(
            policy_id="p", surface_shortfall="BLOCK"))
        assert finding(outcome, "RG-COV-006").effect.value == "BLOCK"
        assert outcome.case.verdict.decision.value == "BLOCK"

    def test_a_policy_can_require_every_required_claim_to_declare_a_surface(
            self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "c-bare", "is_root": True,
                 "proposition": "it is safe", "producer": P("platform", "human")},
                ev("e", supports=["c-bare"])]
        assert "RG-COV-007" not in rules(run(tmp_path, rows))
        outcome = run(tmp_path, rows, resolution_policy=ResolutionPolicy(
            policy_id="p", require_surface=True))
        assert "c-bare" in finding(outcome, "RG-COV-007").refs

    def test_a_claim_that_is_not_required_is_reported_not_held(self, tmp_path):
        rows = [claim({"tool": ["refund"]}, cid="c-root"),
                claim({"tool": TOOLS}, root=False),
                ev("e", supports=["c-root"], covers={"tool": "refund"})]
        outcome = run(tmp_path, rows)
        assert outcome.analysis.resolution.of("c-approval").required is False
        assert coverage(outcome).missing
        assert "RG-COV-006" not in rules(outcome)

    def test_undetermined_criticality_is_never_read_as_unimportant(self, tmp_path):
        outcome = run(tmp_path, example())
        report = outcome.analysis.resolution
        unknown = dataclasses.replace(report, resolutions=tuple(
            dataclasses.replace(r, required=None) for r in report.resolutions))
        coverage_report = assess_claim_coverage(
            outcome.analysis.claim_graph, unknown,
            [r for r in outcome.case.records("evidence") if hasattr(r, "evidence_id")])
        held = _analyse_claim_coverage(coverage_report, DEFAULT_RESOLUTION_POLICY)
        assert [f.rule_id for f in held] == ["RG-COV-006"]

    def test_an_unreadable_surface_is_never_met(self, tmp_path):
        rows = example()
        rows[0]["surface"] = {"tool": {"required": TOOLS, "surprise": True}}
        outcome = run(tmp_path, rows)
        c = coverage(outcome)
        assert c.surface.problem and not c.declared
        assert "unreadable" in finding(outcome, "RG-COV-006").detail

    @pytest.mark.parametrize("bad", [
        {"surface_coverage": 0}, {"surface_coverage": 1.5}, {"surface_coverage": "all"},
        {"surface_coverage": True}, {"surface_shortfall": "ADVISORY"},
        {"require_surface": "yes"}])
    def test_no_policy_reads_unassessed_as_passed(self, bad):
        with pytest.raises(ResolutionError):
            ResolutionPolicy.from_dict(bad)

    def test_the_policy_round_trips(self):
        policy = ResolutionPolicy(policy_id="p", surface_coverage=0.5,
                                  surface_shortfall="BLOCK", require_surface=True)
        assert ResolutionPolicy.from_dict(policy.to_dict()) == policy


# ── on the case ──────────────────────────────────────────────────────────────

class TestOnTheCase:

    def coverage_row(self, outcome):
        [row] = [r.to_dict() for r in outcome.case.records("coverage")
                 if r.to_dict().get("dimension") == "claim_coverage"]
        return row

    def test_no_surface_is_not_assessed_rather_than_absent(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "c", "is_root": True,
                 "proposition": "p", "producer": P("x")}, ev("e", supports=["c"])]
        row = self.coverage_row(run(tmp_path, rows))
        assert row["status"] != "ASSESSED"
        assert "no claim declares a surface" in row["note"]

    def test_a_shortfall_is_not_assessed_and_a_full_surface_is(self, tmp_path):
        short = self.coverage_row(run(tmp_path, example()))
        assert short["status"] != "ASSESSED"
        assert "1 element(s) not assessed, 1 assessed and failed" in short["note"]
        full = [claim({"tool": ["refund"]}),
                ev("e", supports=["c-approval"], covers={"tool": "refund"})]
        assert self.coverage_row(run(tmp_path, full, "full.json"))["status"] == "ASSESSED"

    def test_the_outcome_carries_it_and_it_is_deterministic(self, tmp_path):
        one = run(tmp_path, example()).to_dict()["claim_coverage"]
        two = run(tmp_path, example()).to_dict()["claim_coverage"]
        assert one == two
        [detail] = [c for c in one["detail"] if c["claim_id"] == "c-approval"]
        assert detail["missing"] == [{"dimension": "tool", "element": "transfer",
                                      "status": "NOT_ASSESSED"}]
