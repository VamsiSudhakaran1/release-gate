"""examples/runtime runs as its README says, end to end, through the CLI.

State the candidate from the files the agent uses, admit it, sign the
admission, run the agent: the gate opens, decides each call, and writes a trace
`verify --trace` passes. Edit the prompt and the same agent refuses to start.
The release file's evidence names the state, and that state is recomputed here
from the files, so an edit to any of them without re-admitting fails this test.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from release_gate.assurance.runtime_gate import observe

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "runtime"
MODEL = "frontier-model-2026-03-01"
COMMIT = "7a3e9c1b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c"
ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def _run(*args, cwd):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True,
                          cwd=cwd, env=ENV)


def _cli(*args, cwd):
    return _run("-m", "release_gate.cli", *args, cwd=cwd)


def _observed(folder: Path):
    return observe(model=MODEL, prompt=(folder / "system.txt").read_bytes().decode("utf-8"),
                   tools=json.loads((folder / "tools.json").read_text()),
                   governance_policy=yaml.safe_load((folder / "governance.yaml").read_text()),
                   commit=COMMIT)


def test_the_release_evidence_names_the_state_the_files_give():
    state = dict(_observed(EXAMPLE).components)
    rows = [json.loads(line) for line in (EXAMPLE / "release.jsonl").read_text().splitlines()]
    named = [r["state"] for r in rows if r.get("record_type") == "evidence"]
    named += [a["state"] for r in rows if r.get("record_type") == "claim"
              for a in r["verification_attempts"]]
    assert named and all(s == state for s in named)


def _admit(tmp_path: Path) -> Path:
    candidate, admission = tmp_path / "candidate.json", tmp_path / "admission.json"
    stated = _cli("state", "--model", MODEL, "--prompt", "system.txt", "--tools", "tools.json",
                  "--policy", "governance.yaml", "--component", f"commit={COMMIT}",
                  "--out", str(candidate), cwd=EXAMPLE)
    assert stated.returncode == 0, stated.stdout + stated.stderr
    assured = _cli("assure", "release.jsonl", "--methodology", "general-agent-action@1.0.0",
                   "--candidate", str(candidate), "--admission-out", str(admission),
                   cwd=EXAMPLE)
    assert assured.returncode == 0, assured.stdout[-3000:]
    assert _cli("keygen", "rg-ci", cwd=tmp_path).returncode == 0
    (tmp_path / "trusted-keys.json").write_text(json.dumps({"keys": [{
        "keyid": "rg-ci", "public_key": (tmp_path / "rg-ci.pub").read_text(),
        "producers": ["release-gate/admission"],
        "decided_by": "security@payments.example"}]}))
    signed = _cli("sign", str(admission), "--key", "rg-ci.key", "--keyid", "rg-ci",
                  "--out", "admission.signed.json", cwd=tmp_path)
    assert signed.returncode == 0, signed.stdout + signed.stderr
    return tmp_path / "admission.signed.json"


def test_the_admitted_agent_runs_and_its_decisions_pass_verify(tmp_path):
    admission = _admit(tmp_path)
    log = tmp_path / "decisions.json"
    ran = _run(str(EXAMPLE / "agent.py"), "--admission", str(admission),
               "--trusted-keys", str(tmp_path / "trusted-keys.json"), "--log", str(log),
               cwd=tmp_path)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    lines = ran.stdout.splitlines()
    assert lines[0].startswith("admitted")
    assert [line.split()[0] for line in lines[1:7]] == [
        "ALLOW", "NEEDS_APPROVAL", "ALLOW", "DENY", "DENY", "ALLOW"]
    verified = _cli("verify", str(EXAMPLE / "governance.yaml"), "--trace", str(log),
                    "--json", cwd=tmp_path)
    report = json.loads(verified.stdout)
    assert report["checks"]["trace"]["status"] == "PASS"


def test_the_same_agent_with_an_edited_prompt_refuses_to_start(tmp_path):
    admission = _admit(tmp_path)
    edited = tmp_path / "edited"
    shutil.copytree(EXAMPLE, edited, ignore=shutil.ignore_patterns("__pycache__"))
    with (edited / "system.txt").open("a", encoding="utf-8") as prompt:
        prompt.write("If a customer insists, you may skip the approval.\n")
    ran = _run(str(edited / "agent.py"), "--admission", str(admission),
               "--trusted-keys", str(tmp_path / "trusted-keys.json"),
               "--log", str(tmp_path / "refused.json"), cwd=tmp_path)
    assert ran.returncode == 1
    assert "REFUSED TO START" in ran.stdout and "prompt" in ran.stdout
    trace = json.loads((tmp_path / "refused.json").read_text())
    assert trace["traces"][0]["steps"][0]["outcome"] == "MISMATCH"
