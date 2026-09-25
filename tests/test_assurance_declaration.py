"""`governance.yaml` as evidence about intent, not as the yardstick.

The fixtures are the real file's shape, read from the repository's own
`governance.yaml` where possible. The central property — that a default case does
not depend on a governance file — is measured by digest rather than asserted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from release_gate.assurance.declaration import (
    DECLARATION_SCHEMA_VERSION, Declaration, DeclarationError, DeclaredBudget,
    DeclaredSafeguard, declaration_evidence, read_declaration,
)
from release_gate.assurance.zero_config import assure
from release_gate.demos import single_agent

ROOT = Path(__file__).resolve().parent.parent

#: The shape a governance.yaml actually has — plain booleans and nested blocks.
GOVERNANCE = {
    "project": {"name": "demo-agent"},
    "agent": {"model": "gpt-4-turbo", "daily_requests": 500},
    "policy": {"fail_on": ["ACTION_BUDGET"], "warn_on": ["INPUT_CONTRACT"]},
    "checks": {
        "action_budget": {"enabled": True, "max_daily_cost": 100},
        "fallback_declared": {"enabled": True, "team_owner": "platform-team",
                              "fallback_mode": "escalate-to-human"},
        "identity_boundary": {"enabled": False},
    },
    "safeguards": {"kill_switch": True, "human_approval": False,
                   "rate_limit": {"type": "token-bucket"}},
}


# ── the default case does not depend on it ───────────────────────────────────

class TestDefaultIndependence:

    def test_the_same_input_yields_the_same_case_either_way(self, tmp_path):
        """Measured by digest, not asserted. A governance file in the working
        directory must change nothing about a case built from one input."""
        case = tmp_path / "case.json"
        case.write_text(json.dumps(single_agent.build_document()))
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            without = assure(str(case))
            (tmp_path / "governance.yaml").write_text(
                "project:\n  name: demo\nsafeguards:\n  kill_switch: true\n")
            with_file = assure(str(case))
        finally:
            os.chdir(cwd)
        assert without.case.case_digest == with_file.case.case_digest
        assert without.case.verdict.decision is with_file.case.verdict.decision

    def test_the_assurance_layer_opens_no_governance_file(self):
        """Prose about governance is fine, and so is a default label; a read is
        not.

        Checked through the AST. A substring search flagged
        `source: str = "governance.yaml"` — a default parameter naming where a
        mapping came from, not a path anything opens.
        """
        import ast
        readers = {"open", "read_text", "read_bytes", "load", "safe_load"}
        for path in (ROOT / "release_gate" / "assurance").glob("*.py"):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "attr", None) or getattr(
                    node.func, "id", None)
                if name not in readers:
                    continue
                for argument in ast.walk(node):
                    if isinstance(argument, ast.Constant) and isinstance(
                            argument.value, str):
                        assert "governance" not in argument.value.lower(), (
                            f"{path.name}:{node.lineno}")

    def test_a_declaration_is_never_required(self):
        assert Declaration().is_required is False
        assert Declaration().to_dict()["is_required"] is False

    def test_an_empty_declaration_is_legitimate(self):
        """Most cases have no governance file, and one without is not a case
        with a gap."""
        empty = read_declaration({})
        assert empty.safeguards == ()
        assert declaration_evidence(empty) == ()


# ── it is evidence, not policy ───────────────────────────────────────────────

class TestNotPolicy:

    def test_it_is_not_policy_input(self):
        """A declaration that could set its own sufficiency bar would be the
        system under assessment grading its own paper."""
        found = read_declaration(GOVERNANCE)
        assert found.is_policy_input is False
        assert found.to_dict()["is_policy_input"] is False

    def test_it_constrains_no_verdict(self):
        assert read_declaration(GOVERNANCE).constrains_the_verdict is False

    def test_a_safeguard_establishes_nothing(self):
        """`kill_switch: true` establishes that somebody wrote
        `kill_switch: true`."""
        found = read_declaration(GOVERNANCE)
        for safeguard in found.safeguards:
            assert safeguard.establishes_the_safeguard is False
            assert safeguard.to_dict()["establishes_the_safeguard"] is False

    def test_a_budget_is_a_number_a_team_chose(self):
        payload = DeclaredBudget(name="max_daily_cost", value=100).to_dict()
        assert payload["enforced_by_release_gate"] is False

    def test_it_is_not_a_methodology(self):
        """Not a rename. A declaration has no requirements, no case types, and
        nothing that evaluates itself against a case."""
        found = read_declaration(GOVERNANCE)
        for attribute in ("requirements", "case_types", "digest", "applies_to",
                          "evaluate", "assess"):
            assert not hasattr(found, attribute), attribute

    def test_declared_preferences_are_recorded_not_applied(self):
        found = read_declaration(GOVERNANCE)
        assert found.fail_on == ("ACTION_BUDGET",)
        assert found.constrains_the_verdict is False

    def test_the_render_says_what_it_is(self):
        rendered = read_declaration(GOVERNANCE).render()
        assert "establishes nothing and requires nothing" in rendered


# ── reading the real shape ───────────────────────────────────────────────────

class TestReading:

    def test_the_repositorys_own_governance_file_reads(self):
        yaml = pytest.importorskip("yaml")
        path = ROOT / "governance.yaml"
        if not path.exists():
            pytest.skip("no governance.yaml in the repository")
        found = read_declaration(yaml.safe_load(path.read_text()))
        assert found.project
        assert found.safeguards

    def test_a_plain_boolean_is_read(self):
        """governance.yaml writes `kill_switch: true`."""
        found = read_declaration(GOVERNANCE)
        names = {s.name: s.declared_present for s in found.safeguards}
        assert names["kill_switch"] is True
        assert names["human_approval"] is False

    def test_an_enabled_flag_is_read(self):
        found = read_declaration(GOVERNANCE)
        names = {s.name: s.declared_present for s in found.safeguards}
        assert names["action_budget"] is True
        assert names["identity_boundary"] is False

    def test_configuration_without_a_presence_flag_states_nothing(self):
        """Settings for a rate limit are not a claim that one is in place.
        Reading that as absent would report a team as having said something they
        did not."""
        found = read_declaration(GOVERNANCE)
        assert "rate_limit" in found.configured_without_stating
        assert "rate_limit" not in found.declared_present
        assert "rate_limit" not in found.declared_absent

    def test_and_produces_no_attestation(self):
        """Manufacturing the claim for them would put words in the record."""
        records = declaration_evidence(read_declaration(GOVERNANCE))
        subjects = {r.to_dict()["content"]["safeguard"] for r in records}
        assert "rate_limit" not in subjects
        assert "kill_switch" in subjects

    def test_present_and_absent_are_both_recorded(self):
        found = read_declaration(GOVERNANCE)
        assert "kill_switch" in found.declared_present
        assert "human_approval" in found.declared_absent

    def test_the_owner_is_found_wherever_it_is_written(self):
        assert read_declaration(GOVERNANCE).owner == "platform-team"

    def test_budgets_are_read_with_their_units(self):
        budgets = {b.name: b.unit for b in read_declaration(GOVERNANCE).budgets}
        assert budgets["max_daily_cost"] == "USD/day"
        assert budgets["daily_requests"] == "requests/day"

    def test_unknown_keys_are_recorded_not_refused(self):
        """A governance file is a team's own document and may carry anything."""
        found = read_declaration(dict(GOVERNANCE, house_specific={"a": 1}))
        assert "house_specific" in found.raw_keys

    def test_a_string_is_refused(self):
        """Nothing here parses a file."""
        with pytest.raises(DeclarationError) as exc:
            read_declaration("project: demo")
        assert "nothing here parses a file" in str(exc.value)

    def test_no_yaml_parser_is_imported(self):
        import ast
        source = (ROOT / "release_gate" / "assurance" / "declaration.py")
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            assert "yaml" not in names


# ── it becomes DECLARED evidence ─────────────────────────────────────────────

class TestEvidence:

    def test_every_stated_safeguard_becomes_an_attestation(self):
        found = read_declaration(GOVERNANCE)
        records = declaration_evidence(found)
        assert len(records) == len(found.declared_present) + \
            len(found.declared_absent)

    def test_the_status_is_declared(self):
        from release_gate.assurance.evidence import EpistemicStatus
        for record in declaration_evidence(read_declaration(GOVERNANCE)):
            assert record.epistemic_status is EpistemicStatus.DECLARED

    def test_the_producer_is_the_document_not_release_gate(self):
        from release_gate.assurance.evidence import ProducerKind
        for record in declaration_evidence(read_declaration(GOVERNANCE)):
            assert record.producer.kind is ProducerKind.EXTERNAL
            assert "declared-document" in record.producer.identity_basis

    def test_the_coverage_note_says_it_is_not_a_guarantee(self):
        for record in declaration_evidence(read_declaration(GOVERNANCE)):
            assert "not a runtime guarantee" in record.coverage_note

    def test_it_binds_to_a_subject_when_one_is_given(self):
        digest = "sha256:" + "a" * 64
        for record in declaration_evidence(read_declaration(GOVERNANCE),
                                           applies_to_digest=digest):
            assert record.applies_to_digest == digest


# ── the ingest no longer drops a shape ───────────────────────────────────────

class TestSafeguardShapes:
    """A governance.yaml writes plain booleans. Requiring a Mapping dropped every
    bool-shaped safeguard silently, so declaring `kill_switch: false` was
    indistinguishable from declaring nothing."""

    BASE = {"score": 80, "decision": "PROMOTE", "code_findings": [],
            "code_safety": {"applicable": True, "score": 80}}

    def _assure(self, tmp_path, safeguards, name):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(dict(self.BASE, safeguards=safeguards)))
        return assure(str(path))

    def _kinds(self, outcome):
        kinds = {}
        for record in outcome.case.collection("evidence").materialised:
            found = record.to_dict().get("evidence_type")
            if found in ("ATTESTATION", "STATIC_FINDING"):
                kinds[found] = kinds.get(found, 0) + 1
        return kinds

    def test_a_bool_true_produces_an_attestation(self, tmp_path):
        outcome = self._assure(tmp_path, {"kill_switch": True}, "t")
        assert self._kinds(outcome).get("ATTESTATION") == 1

    def test_a_bool_false_produces_a_contradicting_finding(self, tmp_path):
        outcome = self._assure(tmp_path, {"kill_switch": False}, "f")
        assert self._kinds(outcome).get("ATTESTATION") is None
        assert self._kinds(outcome).get("STATIC_FINDING", 0) >= 2

    def test_the_two_shapes_agree(self, tmp_path):
        """Whatever a report writes, the same declaration means the same thing."""
        as_bool = self._assure(tmp_path, {"kill_switch": True}, "b")
        as_dict = self._assure(tmp_path, {"kill_switch": {"present": True}}, "d")
        assert self._kinds(as_bool) == self._kinds(as_dict)
        assert as_bool.case.verdict.decision is as_dict.case.verdict.decision

    def test_declaring_absent_is_not_the_same_as_declaring_nothing(self, tmp_path):
        absent = self._assure(tmp_path, {"kill_switch": False}, "a")
        path = tmp_path / "none.json"
        path.write_text(json.dumps(self.BASE))
        silent = assure(str(path))
        assert absent.case.verdict.decision is not silent.case.verdict.decision
