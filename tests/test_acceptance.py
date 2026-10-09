"""The product acceptance test: one enterprise release, end to end.

`examples/acceptance/run_acceptance.py --check` is what CI runs. These tests run
it from a clean environment, then change one input at a time in a copy to show
that each conclusion comes from that input:

- answer the counterexample, and nothing blocks;
- re-run the account-closure red team against this commit, and that claim is
  supported;
- change the governance file without restating the candidate, and the check
  refuses the run.

A scenario whose decision survived those edits would be a mockup.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ACCEPTANCE = ROOT / "examples" / "acceptance"


def _module(base: Path):
    """run_acceptance.py, loaded to read a copy of the scenario at `base`."""
    spec = importlib.util.spec_from_file_location(
        f"run_acceptance_{abs(hash(base))}", ACCEPTANCE / "run_acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE = base
    return module


@pytest.fixture
def copy(tmp_path):
    target = tmp_path / "acceptance"
    shutil.copytree(ACCEPTANCE, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def _run(base: Path, tmp_path: Path):
    """Everything `main` does, returning the facts instead of printing them."""
    module = _module(base)
    work = tmp_path / "work"
    module.stage(work)
    mismatches = module.candidate_mismatches(work)
    scanner = module.scan(work)
    reading = module.read_semantically(module.admit(work))
    (work / "semantic-readings.jsonl").write_text(
        json.dumps(reading.to_dict(), sort_keys=True) + "\n")
    outcome = module.admit(work, readings=[reading])
    facts = module.answers(outcome, module.admit_with_the_cli(work), scanner)
    return module, facts, scanner, mismatches


def _edit(path: Path, change) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


class TestTheScenarioAsShipped:

    def test_the_check_passes_from_a_clean_environment(self, tmp_path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("RG_")}
        env["PYTHONPATH"] = str(ROOT)
        done = subprocess.run(
            [sys.executable, str(ACCEPTANCE / "run_acceptance.py"), "--check",
             "--out", str(tmp_path)],
            capture_output=True, text=True, cwd=str(tmp_path), env=env, timeout=900)
        assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
        assert "acceptance check OK" in done.stdout
        written = {p.name for p in tmp_path.iterdir()}
        assert {"acceptance-report.md", "acceptance-report.json",
                "admission-report.json", "admission-report.txt"} <= written

    def test_every_question_is_answered(self, tmp_path):
        done = subprocess.run([sys.executable, str(ACCEPTANCE / "run_acceptance.py")],
                              capture_output=True, text=True, timeout=900,
                              env={**os.environ, "PYTHONPATH": str(ROOT)})
        for heading in ("What exactly is being released?", "What claims are required?",
                        "What evidence supports each claim?", "Who or what produced it?",
                        "Does it apply to this exact state?", "How independent is it?",
                        "What contradicts it?", "What failed?",
                        "What remains unknown?", "What requires human attention?",
                        "Why is the decision BLOCK?", "What cannot move the decision"):
            assert heading in done.stdout, heading

    def test_the_facts(self, tmp_path):
        module, facts, scanner, mismatches = _run(ACCEPTANCE, tmp_path)
        assert not mismatches
        assert facts["decision"] == "BLOCK" and facts["blocking"] == ["RG-CEX-001"]
        assert facts["required_claims"] == module.EXPECTED["claims"]
        assert facts["author_lineage_checks"] == ["review-bot"]
        assert facts["scanner"]["decision"] == "PROMOTE"
        assert facts["cli"]["same_case"]


class TestEachConclusionComesFromItsInput:

    def test_answering_the_counterexample_unblocks(self, copy, tmp_path):
        def blocked(doc):
            for attack in doc["attacks"]:
                attack["outcome"] = "blocked"
        _edit(copy / "evidence" / "behaviour-tests.json", blocked)
        _module, facts, _scanner, _m = _run(copy, tmp_path)
        assert facts["blocking"] == []
        assert facts["decision"] == "HOLD"
        assert facts["required_claims"]["cl_refund_approval"] != "CONTRADICTED"

    def test_a_current_red_team_supports_account_closure(self, copy, tmp_path):
        _edit(copy / "evidence" / "red-team-previous-release.json",
              lambda doc: doc.update(state={"commit": "e41c07b9a3d2"}))
        _module, facts, _scanner, _m = _run(copy, tmp_path)
        assert facts["required_claims"]["cl_account_closure_confirmed"] in (
            "SUPPORTED", "PARTIALLY_SUPPORTED")
        assert not facts["stale"]

    def test_a_governance_change_the_candidate_does_not_name_is_refused(
            self, copy, tmp_path):
        governance = copy / "agent" / "governance.yaml"
        governance.write_text(governance.read_text() + "\n# a late edit\n")
        _module, _facts, _scanner, mismatches = _run(copy, tmp_path)
        assert any("governance_policy" in m for m in mismatches)

    def test_removing_the_approval_holds_for_it(self, copy, tmp_path):
        (copy / "evidence" / "approval.json").unlink()
        _module, facts, _scanner, _m = _run(copy, tmp_path)
        assert "approvals.release-owner" in facts["holding"]
        assert facts["decision"] == "BLOCK"
