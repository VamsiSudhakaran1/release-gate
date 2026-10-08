"""The admission demo: executable, checked, and driven by its evidence.

`examples/demo-admission/run_demo.py --check` is what CI runs. These tests run
it, run the CLI the README quotes, and then change one input at a time in a
copy of the demo to show that each conclusion comes from that input: re-bind
the approval to the candidate and its hold goes; re-prove the invariant for the
candidate's policy and the proof stops being withheld; remove the successful
violation and nothing blocks. A demo whose decision survived those edits would
be a mockup.
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
DEMO = ROOT / "examples" / "demo-admission"


def _module(base: Path):
    """run_demo.py, loaded to read a copy of the demo at `base`."""
    spec = importlib.util.spec_from_file_location(f"run_demo_{abs(hash(base))}",
                                                  DEMO / "run_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE = base
    return module


@pytest.fixture
def copy(tmp_path):
    target = tmp_path / "demo"
    shutil.copytree(DEMO, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def _edit(path: Path, change) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def _facts(base: Path, policy: str):
    module = _module(base)
    return module.reading(module.admit(policy))


BLOCK = "policy/block-on-counterexample.json"
HOLD = "policy/hold-on-counterexample.json"


class TestTheDemoAsShipped:

    def test_the_check_ci_runs_passes(self):
        result = subprocess.run([sys.executable, str(DEMO / "run_demo.py"), "--check"],
                                capture_output=True, text=True, cwd=ROOT)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "demo check OK" in result.stdout
        assert "Decision: BLOCK (exit 1)" in result.stdout
        assert "Decision: HOLD (exit 10)" in result.stdout

    @pytest.mark.parametrize("policy,code", [(BLOCK, 1), (HOLD, 10)])
    def test_the_cli_the_readme_quotes(self, policy, code):
        result = subprocess.run(
            [sys.executable, "-m", "release_gate.cli", "assure", "release.jsonl",
             "--evidence", "evidence", "--methodology", "methodology.json",
             "--resolution-policy", policy, "--admission"],
            capture_output=True, text=True, cwd=DEMO,
            env={**os.environ, "PYTHONPATH": str(ROOT)})
        assert result.returncode == code, result.stdout + result.stderr
        assert "ADMISSION REPORT" in result.stdout

    def test_the_reports_it_writes(self, tmp_path):
        result = subprocess.run([sys.executable, str(DEMO / "run_demo.py"),
                                 "--out", str(tmp_path)],
                                capture_output=True, text=True, cwd=ROOT)
        assert result.returncode == 0, result.stderr
        for stem, decision in (("block-on-counterexample", "BLOCK"),
                               ("hold-on-counterexample", "HOLD")):
            report = json.loads((tmp_path / f"{stem}.json").read_text())
            assert report["decision"] == decision
            assert f"Decision     {decision}" in (tmp_path / f"{stem}.txt").read_text()

    def test_the_same_inputs_give_the_same_case_wherever_it_runs(self, copy):
        """Records name their files relative to the demo, not to the checkout.

        And every time in the case comes from the evidence, not the clock: the
        second run is made in a later second, and the case is still the same.
        """
        import time
        here = _facts(DEMO, BLOCK)["report"]
        time.sleep(1.1)
        there = _facts(copy, BLOCK)["report"]
        assert here["case_digest"] == there["case_digest"]
        assert here == there

    def test_the_case_does_not_depend_on_the_second_it_was_read_in(self, monkeypatch):
        """Attempts with no stated time are stamped when they are read. Read
        across a second boundary, the stamps differ, and they once ordered the
        attempts, so the same evidence gave a different case digest about one run
        in fifteen. Every stamp a different second here, against a stopped clock."""
        import itertools

        from release_gate.assurance import evidence, verification

        def stopped():
            return "2026-01-01T00:00:00Z"

        ticks = itertools.count()

        def running():
            n = next(ticks)
            return f"2026-01-01T00:{n // 60 % 60:02d}:{n % 60:02d}Z"

        for module in (evidence, verification):
            monkeypatch.setattr(module, "_utc_now", stopped)
        steady = _facts(DEMO, BLOCK)["report"]["case_digest"]
        for module in (evidence, verification):
            monkeypatch.setattr(module, "_utc_now", running)
        assert _facts(DEMO, BLOCK)["report"]["case_digest"] == steady

    def test_the_tool_column_is_read_from_the_tools_files(self, copy):
        _edit(copy / "evidence" / "promptfoo.json",
              lambda d: d["results"]["results"].pop())
        reports = _module(copy).tool_reports()
        assert reports["evidence/promptfoo.json"].startswith(
            "promptfoo: 48/50 tests pass (48 ran)")

    def test_the_check_reports_drift_instead_of_passing(self, copy):
        module = _module(copy)
        facts = module.reading(module.admit(BLOCK))
        facts["decision"] = "PROMOTE"
        assert module.check(BLOCK, facts)


class TestEachConclusionComesFromItsEvidence:

    def test_an_approval_of_this_candidate_satisfies_the_approval_requirement(self, copy):
        _edit(copy / "evidence" / "approval.json",
              lambda d: d["reviews"][0]["state"].update(commit="c4f8d31a9e27"))
        facts = _facts(copy, HOLD)
        assert "approvals.release-owner" not in facts["holding"]
        assert "evidence/approval.json" not in facts["stale"]

    def test_a_proof_of_the_candidates_policy_is_not_withheld(self, copy):
        candidate = json.loads((copy / "release.jsonl").read_text().splitlines()[0])
        policy = candidate["components"]["governance_policy"]
        _edit(copy / "evidence" / "formal-proof.json",
              lambda d: d["results"][0]["state"].update(governance_policy=policy))
        facts = _facts(copy, HOLD)
        assert "evidence/formal-proof.json" not in facts["stale"]

    def test_without_the_successful_violation_nothing_blocks(self, copy):
        _edit(copy / "evidence" / "behaviour-tests.json",
              lambda d: d.update(attacks=[a for a in d["attacks"]
                                          if a["outcome"] != "succeeded"]))
        facts = _facts(copy, BLOCK)
        assert facts["blocking"] == []
        assert facts["counterexamples"] == []
        assert facts["claim_status"] != "CONTRADICTED"
        assert facts["decision"] == "HOLD"     # stale proof, stale approval, missing case

    def test_traces_of_the_candidate_count_and_traces_of_another_do_not(self, copy):
        path = copy / "release.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        for row in rows:
            if row.get("kind") == "TRACE":
                row["state"]["commit"] = "c4f8d31a9e27"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        facts = _facts(copy, HOLD)
        assert "release.jsonl#trace" not in facts["stale"]

    def test_the_missing_eval_case_is_what_raises_the_expectation(self, copy):
        path = copy / "release.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        rows = [r for r in rows if r.get("record_type") != "expectation"]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        facts = _facts(copy, HOLD)
        assert "RG-EXPECT-001" not in facts["holding"]

    def test_the_policy_not_the_evidence_moves_block_to_hold(self):
        block, hold = _facts(DEMO, BLOCK), _facts(DEMO, HOLD)
        assert (block["decision"], hold["decision"]) == ("BLOCK", "HOLD")
        assert block["counterexamples"] == hold["counterexamples"]
        assert block["stale"].keys() == hold["stale"].keys()
        assert block["claim_status"] == hold["claim_status"] == "CONTRADICTED"


class TestCiRunsIt:
    """The demo is only evidence of anything while CI keeps running it."""

    @pytest.fixture
    def workflow(self):
        import yaml
        return yaml.safe_load((ROOT / ".github" / "workflows" / "tests.yml").read_text())

    def test_the_test_job_runs_the_check(self, workflow):
        runs = [s.get("run", "") for s in workflow["jobs"]["test"]["steps"]]
        assert "python examples/demo-admission/run_demo.py --check" in runs

    def test_the_action_is_run_on_the_demo_under_each_hold_policy(self, workflow):
        steps = workflow["jobs"]["admission-action"]["steps"]
        gates = {s["id"]: s for s in steps if s.get("uses") == "./"}
        assert set(gates) == {"block", "hold-normal", "hold-strict"}
        for gate in gates.values():
            assert gate["continue-on-error"] is True
            assert gate["with"]["command"] == "assure"
            assert gate["with"]["input"] == "examples/demo-admission/release.jsonl"
        assert gates["hold-normal"]["with"]["hold-policy"] == "normal"
        assert gates["hold-strict"]["with"]["hold-policy"] == "strict"
        verify = steps[-1]["run"]
        for expected in ('"$BLOCK_OUTCOME" failure', '"$HOLD_NORMAL_OUTCOME" success',
                         '"$HOLD_NORMAL_DECISION" HOLD', '"$HOLD_STRICT_OUTCOME" failure'):
            assert expected in verify
