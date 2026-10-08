"""CI/CD admission: `assure --evidence`, the Action's `assure` step, and the templates.

The contract every CI integration keeps: exit 0 PROMOTE, 10 HOLD, 1 BLOCK, and
HOLD is never BLOCK. Under the normal hold policy a HOLD routes the release to
a person; under strict it stops pending approval; BLOCK and anything that is
not a decision the Admission Report confirms always stop.

The gate scripts are not read for keywords: each template's script is pulled
out of the file a user would copy and executed, under the shell that platform
runs, against a stub `release-gate` that returns every exit code and report
combination, and once against the real CLI on the admission demo. The routing
conditions (GitHub `if:`, Azure `condition:`) are evaluated over their whole
truth table, so "HOLD never deploys unreviewed" is checked rather than claimed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

from release_gate.assurance.ingest import IngestError, compose_inputs
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "ci-templates"
ADMISSION = TEMPLATES / "admission"
EVIDENCE_EXAMPLE = ROOT / "examples" / "evidence"
DEMO = ROOT / "examples" / "demo-admission"

SHELLS = [s for s in ("sh", "bash") if shutil.which(s)]


def _bash_available():
    return shutil.which("bash") is not None


# ── `assure --evidence`: one case from many files ────────────────────────────

def _split_release(tmp_path: Path) -> Path:
    """examples/evidence/release.jsonl without its embedded exports."""
    rows = [line for line in (EVIDENCE_EXAMPLE / "release.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]
    kept = [r for r in rows if json.loads(r).get("record_type") != "producer_export"]
    claims = tmp_path / "claims.jsonl"
    claims.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return claims


def _tool_files(tmp_path: Path) -> Path:
    folder = tmp_path / "tools"
    folder.mkdir()
    for name in ("eval.json", "formal.json", "red-team.json", "review.json", "sast.json"):
        shutil.copy(EVIDENCE_EXAMPLE / name, folder / name)
    return folder


def _conditions(outcome) -> List[tuple]:
    return sorted((c.dimension.value, c.effect.value, c.summary)
                  for c in outcome.admission.conditions)


class TestComposition:

    def test_files_beside_the_claims_decide_as_the_same_files_embedded(self, tmp_path):
        """Composition is the envelope a pipeline would otherwise have to build."""
        embedded = assure(EVIDENCE_EXAMPLE / "release.jsonl")
        composed = assure(_split_release(tmp_path), evidence=[_tool_files(tmp_path)])
        assert composed.decision is embedded.decision
        assert _conditions(composed) == _conditions(embedded)
        assert (sorted(e.producer_id for e in composed.evidence_origin.entries)
                == sorted(e.producer_id for e in embedded.evidence_origin.entries))

    def test_a_directory_contributes_its_evidence_files_in_name_order(self, tmp_path):
        folder = _tool_files(tmp_path)
        (folder / "notes.md").write_text("# not evidence\n", encoding="utf-8")
        (folder / "build.log").write_text("not evidence\n", encoding="utf-8")
        _, _, read = compose_inputs(_split_release(tmp_path), [folder])
        names = [Path(r).name for r in read]
        assert names == ["claims.jsonl", "eval.json", "formal.json", "red-team.json",
                         "review.json", "sast.json"]

    def test_a_file_named_twice_or_the_primary_repeated_is_read_once(self, tmp_path):
        claims = _split_release(tmp_path)
        folder = _tool_files(tmp_path)
        one = folder / "eval.json"
        _, _, read = compose_inputs(claims, [one, one, claims, folder])
        assert [Path(r).name for r in read].count("eval.json") == 1
        assert [Path(r).name for r in read].count("claims.jsonl") == 1

    def test_one_document_under_two_names_counts_its_evidence_once(self, tmp_path):
        """A file passed to --evidence that an envelope beside it already embeds."""
        claims = _split_release(tmp_path)
        folder = _tool_files(tmp_path)
        once = assure(claims, evidence=[folder])
        twice = assure(claims, evidence=[folder, EVIDENCE_EXAMPLE / "release.jsonl"])
        assert len(twice.normalisation.evidence) == len(once.normalisation.evidence)
        assert (sum(e.records for e in twice.evidence_origin.entries)
                == sum(e.records for e in once.evidence_origin.entries))
        assert twice.decision is once.decision

    def test_the_repeat_is_named_rather_than_silently_dropped(self, tmp_path):
        from release_gate.assurance.ingest import detect_document, normalise
        rows, content, _ = compose_inputs(
            _split_release(tmp_path),
            [_tool_files(tmp_path), EVIDENCE_EXAMPLE / "release.jsonl"])
        result = normalise(rows, detect_document(rows, filename="claims.jsonl"),
                           source="claims.jsonl", content=content)
        assert any("carries the same document as" in n and "it was read once" in n
                   for n in result.notes)

    def test_an_envelope_carrying_one_verifier_document_twice_does_not_crash(self, tmp_path):
        """Two copies of one proof are one proof: the second is absorbed, not fatal."""
        formal = json.loads((EVIDENCE_EXAMPLE / "formal.json").read_text(encoding="utf-8"))
        rows = [{"record_type": "claim", "claim_id": "cl_no_overdraft",
                 "proposition": "A transfer never overdraws the source account"},
                {"record_type": "producer_export", "source": "a.json", "document": formal},
                {"record_type": "producer_export", "source": "b.json", "document": formal}]
        path = tmp_path / "twice.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        outcome = assure(path)
        proofs = [e for e in outcome.evidence_origin.entries if e.producer_id == "tlc@2.19"]
        assert proofs and proofs[0].records == 1

    def test_two_reports_sharing_one_check_count_it_once(self, tmp_path):
        """Different documents, one identical row: the shared check is one check."""
        formal = json.loads((EVIDENCE_EXAMPLE / "formal.json").read_text(encoding="utf-8"))
        wider = json.loads(json.dumps(formal))
        extra = dict(wider["results"][0], claim_id="cl_second", claim="a second claim")
        wider["results"].append(extra)
        rows = [{"record_type": "claim", "claim_id": "cl_no_overdraft",
                 "proposition": "A transfer never overdraws the source account"},
                {"record_type": "producer_export", "source": "a.json", "document": formal},
                {"record_type": "producer_export", "source": "b.json", "document": wider}]
        path = tmp_path / "shared.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        outcome = assure(path)
        attempts = [a.verification_id for a in outcome.analysis.verification_graph.attempts]
        assert len(attempts) == len(set(attempts)) == 2
        assert any("repeated attempts already held" in n
                   for n in outcome.normalisation.notes)

    def test_a_missing_evidence_path_is_an_error_not_an_empty_case(self, tmp_path):
        with pytest.raises(IngestError, match="no such evidence"):
            compose_inputs(_split_release(tmp_path), [tmp_path / "missing"])

    def test_the_composed_bytes_are_what_the_case_names(self, tmp_path):
        """Change one evidence file and the subject digest changes with it."""
        claims = _split_release(tmp_path)
        folder = _tool_files(tmp_path)
        before = assure(claims, evidence=[folder]).case.subject_digest
        doc = json.loads((folder / "eval.json").read_text(encoding="utf-8"))
        doc["cases"][0]["score"] = 0.95
        (folder / "eval.json").write_text(json.dumps(doc), encoding="utf-8")
        after = assure(claims, evidence=[folder]).case.subject_digest
        assert before != after

    def test_a_document_that_is_not_one_producers_output_is_refused_and_named(self, tmp_path):
        """A raw trace export cannot ride in an envelope; it is not quietly read."""
        trace = ROOT / "integrations" / "langfuse" / "example-trace.json"
        from release_gate.assurance.ingest import detect_document, normalise
        rows, content, _ = compose_inputs(_split_release(tmp_path), [trace])
        result = normalise(rows, detect_document(rows, filename="claims.jsonl"),
                           source="claims.jsonl", content=content)
        assert any("was not read" in n and "example-trace.json" in n for n in result.notes)
        assert result.skipped_total >= 1

    def test_a_single_file_is_read_exactly_as_before(self):
        """No --evidence: the old path, untouched.

        Compared on what does not carry the clock. This example states no times,
        so its records are stamped when they are read, and two runs a second
        apart differ in case digest for that reason alone.
        """
        plain = assure(EVIDENCE_EXAMPLE / "release.jsonl")
        empty = assure(EVIDENCE_EXAMPLE / "release.jsonl", evidence=())
        assert plain.case.case_id == empty.case.case_id
        assert plain.case.subject_digest == empty.case.subject_digest
        assert plain.detection.kind is empty.detection.kind
        assert plain.decision is empty.decision
        assert _conditions(plain) == _conditions(empty)
        for outcome in (plain, empty):
            assert not any(n.startswith("composed from") for n in outcome.normalisation.notes)
        assert ([e.evidence_id for e in plain.normalisation.evidence]
                == [e.evidence_id for e in empty.normalisation.evidence])
        assert ([c.claim_id for c in plain.normalisation.claims]
                == [c.claim_id for c in empty.normalisation.claims])

    def test_the_old_path_and_the_composed_path_differ_only_by_the_note(self, tmp_path):
        """A composed case states which files it was composed from; a plain one does not."""
        claims = _split_release(tmp_path)
        composed = assure(claims, evidence=[_tool_files(tmp_path)])
        assert composed.normalisation.notes[0].startswith("composed from 6 file(s): ")


class TestTheCliFlag:

    def _run(self, *args, cwd=None):
        return subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", *args],
                              capture_output=True, text=True, cwd=cwd or ROOT,
                              env={**os.environ, "PYTHONPATH": str(ROOT)})

    def test_flags_reads_every_value_of_a_repeatable_flag(self):
        from release_gate.cli import _flags
        argv = ["release-gate", "assure", "x", "--evidence", "a", "--json",
                "--evidence", "b", "--evidence"]
        assert _flags(argv, "--evidence") == ["a", "b"]
        assert _flags(argv, "--absent") == []

    def test_repeated_evidence_flags_reach_one_decision(self, tmp_path):
        claims = _split_release(tmp_path)
        folder = _tool_files(tmp_path)
        args = [str(claims)]
        for name in sorted(os.listdir(folder)):
            args += ["--evidence", str(folder / name)]
        out = tmp_path / "admission.json"
        result = self._run(*args, "--admission-out", str(out))
        expected = assure(claims, evidence=[folder / n for n in sorted(os.listdir(folder))])
        assert result.returncode == expected.exit_code
        assert json.loads(out.read_text(encoding="utf-8"))["decision"] == \
            expected.decision.value

    def test_a_missing_evidence_path_fails_closed(self, tmp_path):
        result = self._run(str(_split_release(tmp_path)), "--evidence",
                           str(tmp_path / "nope"))
        assert result.returncode == 1 and "no such evidence" in result.stdout


# ── verifier records are typed by what their checks are ──────────────────────

class TestVerifierRecordType:

    def _record(self, tmp_path, rows, family="OTHER"):
        doc = {"verifier": {"name": "probe", "version": "1", "family": family},
               "results": rows}
        envelope = [{"record_type": "claim", "claim_id": "c1", "proposition": "p"},
                    {"record_type": "producer_export", "source": "v.json", "document": doc}]
        path = tmp_path / "e.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in envelope), encoding="utf-8")
        outcome = assure(path)
        return [e for e in outcome.evidence_origin.entries if e.producer_id == "probe@1"][0]

    def test_a_static_analysers_report_is_its_result_not_a_proof(self, tmp_path):
        entry = self._record(tmp_path, [{"claim_id": "c1", "method": "STATIC_ANALYSIS",
                                         "result": "passed"}])
        assert dict(entry.evidence_types) == {"TOOL_RESULT": 1}

    def test_a_proof_stays_a_proof(self, tmp_path):
        entry = self._record(tmp_path, [{"claim_id": "c1", "method": "FORMAL_PROOF",
                                         "result": "verified"}])
        assert dict(entry.evidence_types) == {"FORMAL_PROOF": 1}

    def test_one_non_proof_check_makes_the_report_a_tool_result(self, tmp_path):
        entry = self._record(tmp_path, [
            {"claim_id": "c1", "method": "FORMAL_PROOF", "result": "verified"},
            {"claim_id": "c1", "method": "TEST_SUITE", "result": "passed"}])
        assert dict(entry.evidence_types) == {"TOOL_RESULT": 1}

    def test_every_family_default_is_a_tuple_of_sentences(self):
        """DOMAIN_VALIDATOR's limit was a bare string, split into characters."""
        from release_gate.assurance.verifiers import _FAMILY_COVERAGE
        for family, (covers, does_not) in _FAMILY_COVERAGE.items():
            for column in (covers, does_not):
                assert isinstance(column, tuple), family
                assert all(isinstance(x, str) and len(x) > 3 for x in column), family

    def test_an_unclassified_tools_stated_coverage_replaces_the_no_coverage_default(self):
        from release_gate.assurance.verifiers import GenericVerifierAdapter
        stated = GenericVerifierAdapter().convert({
            "verifier": {"name": "probe"},
            "results": [{"claim_id": "c1", "result": "passed", "covers": ["the API"],
                         "does_not_cover": ["the scheduler"]}]})
        silent = GenericVerifierAdapter().convert({
            "verifier": {"name": "probe"},
            "results": [{"claim_id": "c1", "result": "passed"}]})
        assert stated.coverage.does_not_cover == ("the scheduler",)
        assert silent.coverage.does_not_cover == (
            "nothing is recorded about what this result covers",)


# ── the gate scripts, executed ───────────────────────────────────────────────

STUB = textwrap.dedent('''\
    #!{python}
    """A stand-in `release-gate`: records its argv, writes the report it is told to."""
    import json, os, sys
    argv = sys.argv[1:]
    with open(os.environ["STUB_ARGV"], "w") as f:
        json.dump(argv, f)
    report = os.environ.get("STUB_REPORT", "NONE")
    if "--admission-out" in argv and report != "NONE":
        with open(argv[argv.index("--admission-out") + 1], "w") as f:
            json.dump({{"decision": report}}, f)
    print("stub admission report:", report)
    sys.exit(int(os.environ["STUB_CODE"]))
''')

#: (exit code, report decision) -> the decision a gate must reach. Anything the
#: report does not confirm is ERROR, never the exit code's reading of it.
SCENARIOS = [
    (0, "PROMOTE", "PROMOTE"),
    (10, "HOLD", "HOLD"),
    (1, "BLOCK", "BLOCK"),
    (1, "NONE", "ERROR"),       # an error before any report: exit 1 is not BLOCK
    (10, "PROMOTE", "ERROR"),   # code and report disagree
    (0, "HOLD", "ERROR"),
    (2, "NONE", "ERROR"),
    (137, "NONE", "ERROR"),
]


@pytest.fixture
def stub(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "release-gate"
    script.write_text(STUB.format(python=sys.executable), encoding="utf-8")
    shim = bin_dir / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for f in (script, shim):
        f.chmod(f.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def _run_script(script: str, *, shell: str, cwd: Path, env: Dict[str, str],
                bin_dir: Path) -> subprocess.CompletedProcess:
    path = cwd / "gate.sh"
    path.write_text(script, encoding="utf-8")
    flags = ["-e"] if shell == "sh" else ["--noprofile", "--norc", "-eo", "pipefail"]
    full_env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(cwd)}
    full_env.update(env)
    return subprocess.run([shell, *flags, str(path)], cwd=cwd, env=full_env,
                          capture_output=True, text=True, timeout=60)


def _gitlab_script() -> str:
    return yaml.safe_load((ADMISSION / "gitlab-ci.yml").read_text())["admission"]["script"][0]


def _azure_script() -> str:
    spec = yaml.safe_load((ADMISSION / "azure-pipelines.yml").read_text())
    release = next(s for s in spec["stages"] if s["stage"] == "Release")
    admission = next(j for j in release["jobs"] if j["job"] == "Admission")
    return next(s["bash"] for s in admission["steps"] if s.get("name") == "gate")


def _circleci_script() -> str:
    spec = yaml.safe_load((ADMISSION / "circleci" / "config.yml").read_text())
    for step in spec["jobs"]["admission"]["steps"]:
        run = step.get("run") if isinstance(step, dict) else None
        if isinstance(run, dict) and run.get("name") == "release-gate admission":
            return run["command"]
    raise AssertionError("no admission step")


def _jenkins_groovy() -> str:
    return (ADMISSION / "Jenkinsfile").read_text()


def _jenkins_script() -> str:
    text = _jenkins_groovy()
    stage = text[text.index("stage('Admission')"):]
    body = re.search(r"sh '''\n(.*?)'''", stage, re.S).group(1)
    assert "\\" not in body, "Groovy ''' strings process backslashes; keep them out"
    return textwrap.dedent(body)


def _action_step() -> Dict[str, Any]:
    spec = yaml.safe_load((ROOT / "action.yml").read_text())
    return next(s for s in spec["runs"]["steps"] if s.get("id") == "assure")


#: platform -> (script reader, shells, exit for each (decision, policy)).
def _exit_gitlab(decision, policy):
    return {"PROMOTE": 0, "HOLD": 10 if policy == "normal" else 1}.get(decision, 1)


def _exit_azure(decision, policy):
    return {"PROMOTE": 0, "HOLD": 0 if policy == "normal" else 1}.get(decision, 1)


def _exit_circleci(decision, policy):
    return _exit_azure(decision, policy)


def _exit_jenkins_sh(decision, policy):
    return 0     # the Groovy that follows decides; tested in TestJenkinsRouting


PLATFORMS = {
    "gitlab": (_gitlab_script, _exit_gitlab),
    "azure": (_azure_script, _exit_azure),
    "circleci": (_circleci_script, _exit_circleci),
    "jenkins": (_jenkins_script, _exit_jenkins_sh),
}


def _gate_env(tmp_path: Path, code: int, report: str, policy: str, **more) -> Dict[str, str]:
    (tmp_path / "release-gate-out" / "evidence").mkdir(parents=True, exist_ok=True)
    env = {"STUB_CODE": str(code), "STUB_REPORT": report,
           "STUB_ARGV": str(tmp_path / "argv.json"),
           "RELEASE_GATE_INPUT": "release-gate/claims.jsonl",
           "RELEASE_GATE_METHODOLOGY": "general-agent-action@1.0.0",
           "RELEASE_GATE_OUT": "release-gate-out",
           "RELEASE_GATE_HOLD_POLICY": policy,
           "PIPELINE_WORKSPACE": str(tmp_path / "release-gate-out")}
    env.update(more)
    return env


def _decision_file(tmp_path: Path) -> Optional[str]:
    path = tmp_path / "release-gate-out" / "decision.env"
    if not path.exists():
        return None
    return path.read_text().strip().replace("RELEASE_GATE_DECISION=", "")


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("policy", ["normal", "strict"])
@pytest.mark.parametrize("code,report,decision", SCENARIOS)
def test_each_templates_gate_reaches_the_decision_and_the_exit_its_policy_says(
        platform, shell, policy, code, report, decision, tmp_path, stub):
    read, expected_exit = PLATFORMS[platform]
    result = _run_script(read(), shell=shell, cwd=tmp_path, bin_dir=stub,
                         env=_gate_env(tmp_path, code, report, policy))
    assert _decision_file(tmp_path) == decision, result.stdout + result.stderr
    assert result.returncode == expected_exit(decision, policy), result.stdout + result.stderr
    if platform == "azure":
        marked = "result=SucceededWithIssues" in result.stdout
        assert marked == (decision == "HOLD" and policy == "normal")
        assert f"variable=decision;isOutput=true]{decision}" in result.stdout
    if platform == "circleci":
        continuation = tmp_path / "release-gate-out" / "continuation.json"
        continues = decision == "PROMOTE" or (decision == "HOLD" and policy == "normal")
        assert continuation.exists() == continues
        if continues:
            assert json.loads(continuation.read_text()) == {
                "release-gate-decision": decision}


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
def test_hold_is_never_block_and_never_promote(platform):
    """The three-state contract in one place, from the tables the scripts are run against."""
    _, expected_exit = PLATFORMS[platform]
    if platform == "jenkins":
        return
    assert expected_exit("HOLD", "normal") != expected_exit("BLOCK", "normal")
    assert expected_exit("HOLD", "strict") != expected_exit("PROMOTE", "strict")
    for policy in ("normal", "strict"):
        assert expected_exit("BLOCK", policy) == 1
        assert expected_exit("ERROR", policy) == 1


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
@pytest.mark.parametrize("policy", ["", "Normal", "lenient", "none"])
def test_a_policy_that_is_not_normal_or_strict_stops_before_running(
        platform, policy, tmp_path, stub):
    read, _ = PLATFORMS[platform]
    result = _run_script(read(), shell="sh", cwd=tmp_path, bin_dir=stub,
                         env=_gate_env(tmp_path, 0, "PROMOTE", policy or "normal",
                                       **({"RELEASE_GATE_HOLD_POLICY": policy}
                                          if policy else {})))
    if policy == "":
        # Unset defaults to normal: the documented default, not a typo.
        assert result.returncode == 0
        return
    assert result.returncode == 1
    assert not (tmp_path / "argv.json").exists(), "release-gate ran under a bad policy"


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
def test_the_gate_passes_what_it_was_given_and_nothing_else(platform, tmp_path, stub):
    read, _ = PLATFORMS[platform]
    _run_script(read(), shell="sh", cwd=tmp_path, bin_dir=stub,
                env=_gate_env(tmp_path, 0, "PROMOTE", "normal"))
    argv = json.loads((tmp_path / "argv.json").read_text())
    assert argv[0] == "assure" and argv[1] == "release-gate/claims.jsonl"
    assert "--evidence" in argv and "--admission" in argv
    assert argv[argv.index("--admission-out") + 1] == \
        "release-gate-out/admission-report.json"
    assert argv[argv.index("--case-output") + 1] == "release-gate-out/case.json"
    assert argv[argv.index("--methodology") + 1] == "general-agent-action@1.0.0"
    for absent in ("--candidate", "--resolution-policy", "--config"):
        assert absent not in argv

    _run_script(read(), shell="sh", cwd=tmp_path, bin_dir=stub,
                env=_gate_env(tmp_path, 0, "PROMOTE", "normal",
                              RELEASE_GATE_CANDIDATE="c.json",
                              RELEASE_GATE_RESOLUTION_POLICY="r.json",
                              RELEASE_GATE_CONFIG="o.json"))
    argv = json.loads((tmp_path / "argv.json").read_text())
    for flag, value in (("--candidate", "c.json"), ("--resolution-policy", "r.json"),
                        ("--config", "o.json")):
        assert argv[argv.index(flag) + 1] == value


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
def test_a_report_left_by_an_earlier_run_cannot_pass_this_one(platform, tmp_path, stub):
    read, _ = PLATFORMS[platform]
    out = tmp_path / "release-gate-out"
    out.mkdir()
    (out / "admission-report.json").write_text('{"decision": "PROMOTE"}')
    _run_script(read(), shell="sh", cwd=tmp_path, bin_dir=stub,
                env=_gate_env(tmp_path, 0, "NONE", "normal"))
    assert _decision_file(tmp_path) == "ERROR"


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
def test_no_claims_file_stops_before_running(platform, tmp_path, stub):
    read, _ = PLATFORMS[platform]
    env = _gate_env(tmp_path, 0, "PROMOTE", "normal")
    env["RELEASE_GATE_INPUT"] = ""
    result = _run_script(read(), shell="sh", cwd=tmp_path, bin_dir=stub, env=env)
    assert result.returncode == 1 and not (tmp_path / "argv.json").exists()


# ── the Action's assure step, executed ───────────────────────────────────────

def _run_action(tmp_path, stub, *, code, report, policy="normal", fail_on_warn="false",
                evidence="release-gate-evidence", **inputs):
    step = _action_step()
    hold_policy = "strict" if fail_on_warn == "true" else policy
    env = {"STUB_CODE": str(code), "STUB_REPORT": report,
           "STUB_ARGV": str(tmp_path / "argv.json"),
           "GITHUB_OUTPUT": str(tmp_path / "github-output"),
           "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
           "RELEASE_GATE_INPUT": inputs.get("input", "release-gate/claims.jsonl"),
           "RELEASE_GATE_EVIDENCE": evidence,
           "RELEASE_GATE_METHODOLOGY": inputs.get("methodology", ""),
           "RELEASE_GATE_CANDIDATE": inputs.get("candidate", ""),
           "RELEASE_GATE_RESOLUTION_POLICY": inputs.get("resolution_policy", ""),
           "RELEASE_GATE_CONFIG": inputs.get("org_config", ""),
           "RELEASE_GATE_HOLD_POLICY": hold_policy,
           "RELEASE_GATE_OUT": "release-gate-out"}
    for name in ("github-output", "summary.md"):
        (tmp_path / name).write_text("")
    return _run_script(step["run"], shell="bash", cwd=tmp_path, env=env, bin_dir=stub)


def _outputs(tmp_path) -> Dict[str, str]:
    lines = (tmp_path / "github-output").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


@pytest.mark.skipif(not _bash_available(), reason="the Action runs bash")
class TestTheActionAssureStep:

    @pytest.mark.parametrize("policy", ["normal", "strict"])
    @pytest.mark.parametrize("code,report,decision", SCENARIOS)
    def test_decision_output_and_exit(self, policy, code, report, decision, tmp_path, stub):
        result = _run_action(tmp_path, stub, code=code, report=report, policy=policy)
        outputs = _outputs(tmp_path)
        assert outputs["decision"] == decision
        assert outputs["admission-report"] == "release-gate-out/admission-report.json"
        expected = {"PROMOTE": 0, "HOLD": 0 if policy == "normal" else 1}.get(decision, 1)
        assert result.returncode == expected, result.stdout
        if decision == "HOLD" and policy == "normal":
            assert "::warning title=release-gate HOLD::" in result.stdout
        summary = (tmp_path / "summary.md").read_text()
        assert f"## Admission decision: {decision}" in summary

    def test_fail_on_warn_means_strict(self, tmp_path, stub):
        step = _action_step()
        assert "inputs.fail-on-warn == 'true' && 'strict'" in step["env"][
            "RELEASE_GATE_HOLD_POLICY"]
        result = _run_action(tmp_path, stub, code=10, report="HOLD", fail_on_warn="true")
        assert result.returncode == 1 and _outputs(tmp_path)["decision"] == "HOLD"

    def test_evidence_lines_and_commas_each_become_a_flag(self, tmp_path, stub):
        _run_action(tmp_path, stub, code=0, report="PROMOTE",
                    evidence="evals/promptfoo.json\n  scans/ , review.json\n\n")
        argv = json.loads((tmp_path / "argv.json").read_text())
        values = [argv[i + 1] for i, a in enumerate(argv) if a == "--evidence"]
        assert values == ["evals/promptfoo.json", "scans/", "review.json"]

    def test_optional_inputs_pass_through_only_when_set(self, tmp_path, stub):
        _run_action(tmp_path, stub, code=0, report="PROMOTE", methodology="m@1",
                    candidate="c.json", resolution_policy="r.json", org_config="o.json")
        argv = json.loads((tmp_path / "argv.json").read_text())
        for flag, value in (("--methodology", "m@1"), ("--candidate", "c.json"),
                            ("--resolution-policy", "r.json"), ("--config", "o.json")):
            assert argv[argv.index(flag) + 1] == value
        _run_action(tmp_path, stub, code=0, report="PROMOTE")
        argv = json.loads((tmp_path / "argv.json").read_text())
        assert not {"--methodology", "--candidate", "--resolution-policy",
                    "--config"} & set(argv)

    @pytest.mark.parametrize("policy", ["lenient", "Strict"])
    def test_a_bad_hold_policy_is_an_error(self, policy, tmp_path, stub):
        result = _run_action(tmp_path, stub, code=0, report="PROMOTE", policy=policy)
        assert result.returncode == 1 and _outputs(tmp_path)["decision"] == "ERROR"
        assert not (tmp_path / "argv.json").exists()

    def test_no_input_is_an_error(self, tmp_path, stub):
        result = _run_action(tmp_path, stub, code=0, report="PROMOTE", input="")
        assert result.returncode == 1 and _outputs(tmp_path)["decision"] == "ERROR"


class TestTheActionSpec:

    @pytest.fixture
    def spec(self):
        return yaml.safe_load((ROOT / "action.yml").read_text())

    def test_the_decision_output_is_wired_to_every_gating_step(self, spec):
        """It used to have no `value:`, so it was never set for anybody."""
        value = spec["outputs"]["decision"]["value"]
        for step in ("assure", "audit", "pr", "loop-sim", "gate"):
            assert f"steps.{step}.outputs.decision" in value
        steps = {s.get("id"): s for s in spec["runs"]["steps"] if s.get("id")}
        for step in ("audit", "pr", "loop-sim", "gate", "assure"):
            assert "decision=" in steps[step]["run"] and "$GITHUB_OUTPUT" in steps[step]["run"]

    def test_assure_does_not_also_run_the_generic_step(self, spec):
        generic = next(s for s in spec["runs"]["steps"] if s.get("id") == "gate")
        assert "inputs.command != 'assure'" in generic["if"]

    def test_inputs_reach_the_assure_script_through_the_environment(self, spec):
        """Never spliced into the script, where a crafted path would be code."""
        step = next(s for s in spec["runs"]["steps"] if s.get("id") == "assure")
        assert "${{" not in step["run"]

    def test_the_admission_report_is_kept_as_an_artifact(self, spec):
        upload = next(s for s in spec["runs"]["steps"]
                      if s.get("name") == "Upload the Admission Report")
        assert "always()" in upload["if"] and "inputs.command == 'assure'" in upload["if"]
        assert upload["with"]["path"] == "${{ inputs.output-dir }}"


# ── routing: who deploys, under which decision ───────────────────────────────

def _github_eval(expression: str, *, decision: str, admission: str, review: str) -> bool:
    """Evaluate a GitHub `if:` over the few contexts the template uses."""
    if not any(fn in expression for fn in ("always()", "success()", "failure()")):
        expression = f"success() && ({expression})"
    python = (expression.replace("&&", " and ").replace("||", " or ")
              .replace("always()", "True")
              .replace("success()", f"({admission!r} == 'success')")
              .replace("needs.admission.outputs.decision", repr(decision))
              .replace("needs.admission.result", repr(admission))
              .replace("needs.human-review.result", repr(review)))
    return bool(eval(python, {"__builtins__": {}}, {}))  # noqa: S307 - our template text


class TestGitHubRouting:

    @pytest.fixture
    def jobs(self):
        return yaml.safe_load((ADMISSION / "github-actions.yml").read_text())["jobs"]

    @pytest.mark.parametrize("decision", ["PROMOTE", "HOLD", "BLOCK", "ERROR", ""])
    @pytest.mark.parametrize("admission", ["success", "failure"])
    @pytest.mark.parametrize("review", ["success", "failure", "skipped"])
    def test_deploy_runs_only_on_promote_or_a_reviewed_hold(self, jobs, decision,
                                                             admission, review):
        deploys = _github_eval(jobs["deploy"]["if"], decision=decision,
                               admission=admission, review=review)
        assert deploys == (admission == "success" and (
            decision == "PROMOTE" or (decision == "HOLD" and review == "success")))

    @pytest.mark.parametrize("decision", ["PROMOTE", "HOLD", "BLOCK", "ERROR"])
    @pytest.mark.parametrize("admission", ["success", "failure"])
    def test_review_is_asked_for_only_on_an_admitted_hold(self, jobs, decision, admission):
        asks = _github_eval(jobs["human-review"]["if"], decision=decision,
                            admission=admission, review="skipped")
        assert asks == (decision == "HOLD" and admission == "success")

    def test_the_review_job_waits_on_a_protected_environment(self, jobs):
        assert jobs["human-review"]["environment"] == "release-review"
        assert jobs["deploy"]["needs"] == ["admission", "human-review"]

    def test_the_admission_job_uses_the_action_with_the_policy(self, jobs):
        step = next(s for s in jobs["admission"]["steps"] if s.get("id") == "admit")
        assert step["uses"].startswith("VamsiSudhakaran1/release-gate@v")
        assert step["with"]["command"] == "assure"
        assert step["with"]["hold-policy"] == "${{ env.RELEASE_GATE_HOLD_POLICY }}"
        assert jobs["admission"]["outputs"]["decision"] == \
            "${{ steps.admit.outputs.decision }}"


def _azure_eval(expression: str, *, decision: str, admission: str, review: str) -> bool:
    def _and(*xs):
        return all(xs)

    def _or(*xs):
        return any(xs)

    def _eq(a, b):
        return str(a).lower() == str(b).lower()

    def _in(a, *xs):
        return any(_eq(a, x) for x in xs)

    python = (expression
              .replace("dependencies.Admission.outputs['gate.decision']", repr(decision))
              .replace("dependencies.Admission.result", repr(admission))
              .replace("dependencies.HumanReview.result", repr(review))
              .replace("succeeded()", repr(admission in ("Succeeded", "SucceededWithIssues")))
              .replace("and(", "_and(").replace("or(", "_or(")
              .replace("eq(", "_eq(").replace("in(", "_in("))
    return bool(eval(python, {"__builtins__": {}},  # noqa: S307 - our template text
                     {"_and": _and, "_or": _or, "_eq": _eq, "_in": _in}))


class TestAzureRouting:

    @pytest.fixture
    def jobs(self):
        spec = yaml.safe_load((ADMISSION / "azure-pipelines.yml").read_text())
        release = next(s for s in spec["stages"] if s["stage"] == "Release")
        return {j["job"]: j for j in release["jobs"]}

    @pytest.mark.parametrize("decision", ["PROMOTE", "HOLD", "BLOCK", "ERROR", ""])
    @pytest.mark.parametrize("admission", ["Succeeded", "SucceededWithIssues", "Failed"])
    @pytest.mark.parametrize("review", ["Succeeded", "Failed", "Skipped"])
    def test_deploy_runs_only_on_promote_or_a_validated_hold(self, jobs, decision,
                                                              admission, review):
        deploys = _azure_eval(jobs["Deploy"]["condition"], decision=decision,
                              admission=admission, review=review)
        admitted = admission in ("Succeeded", "SucceededWithIssues")
        assert deploys == (admitted and (
            decision == "PROMOTE" or (decision == "HOLD" and review == "Succeeded")))

    @pytest.mark.parametrize("decision", ["PROMOTE", "HOLD", "BLOCK", "ERROR"])
    @pytest.mark.parametrize("admission", ["Succeeded", "SucceededWithIssues", "Failed"])
    def test_validation_is_asked_for_only_on_an_admitted_hold(self, jobs, decision,
                                                               admission):
        asks = _azure_eval(jobs["HumanReview"]["condition"], decision=decision,
                           admission=admission, review="Skipped")
        assert asks == (decision == "HOLD" and admission != "Failed")

    def test_review_is_a_manual_validation_that_rejects_on_timeout(self, jobs):
        review = jobs["HumanReview"]
        assert review["pool"] == "server"
        task = review["steps"][0]
        assert task["task"] == "ManualValidation@0"
        assert task["inputs"]["onTimeout"] == "reject"


@pytest.mark.parametrize("shell", SHELLS)
class TestGitLabRouting:

    @pytest.fixture
    def jobs(self):
        return yaml.safe_load((ADMISSION / "gitlab-ci.yml").read_text())

    def _deploy(self, jobs, job, decision, tmp_path, shell):
        out = tmp_path / "release-gate-out"
        out.mkdir(exist_ok=True)
        if decision is not None:
            (out / "decision.env").write_text(f"RELEASE_GATE_DECISION={decision}\n")
        deploy = tmp_path / "deploy.sh"
        deploy.write_text("#!/bin/sh\ntouch deployed\n")
        deploy.chmod(0o755)
        script = jobs[job]["script"][0]
        result = subprocess.run(
            [shell, "-e", "-c", script], cwd=tmp_path, capture_output=True, text=True,
            env={"PATH": os.environ["PATH"], "GITLAB_USER_LOGIN": "reviewer"})
        return result.returncode, (tmp_path / "deployed").exists()

    @pytest.mark.parametrize("decision,code,deployed", [
        ("PROMOTE", 0, True), ("HOLD", 10, False), ("BLOCK", 1, False),
        ("ERROR", 1, False)])
    def test_the_automatic_deploy(self, jobs, decision, code, deployed, tmp_path, shell):
        assert self._deploy(jobs, "deploy", decision, tmp_path, shell) == (code, deployed)

    @pytest.mark.parametrize("decision,code,deployed", [
        ("HOLD", 0, True), ("PROMOTE", 0, False), ("BLOCK", 1, False),
        ("ERROR", 1, False)])
    def test_the_manual_deploy_after_review(self, jobs, decision, code, deployed,
                                            tmp_path, shell):
        assert self._deploy(jobs, "deploy:reviewed", decision, tmp_path, shell) == \
            (code, deployed)
        if decision == "HOLD":
            assert "reviewer" in (tmp_path / "release-gate-out" / "hold-review.txt").read_text()

    def test_no_decision_file_deploys_nothing(self, jobs, tmp_path, shell):
        for job in ("deploy", "deploy:reviewed"):
            code, deployed = self._deploy(jobs, job, None, tmp_path, shell)
            assert code != 0 and not deployed

    def test_hold_is_a_warning_and_review_is_manual(self, jobs, tmp_path, shell):
        assert jobs["admission"]["allow_failure"] == {"exit_codes": [10]}
        assert jobs["deploy"]["allow_failure"] == {"exit_codes": [10]}
        assert jobs["deploy:reviewed"]["when"] == "manual"
        assert jobs["admission"]["artifacts"]["when"] == "always"
        for job in ("deploy", "deploy:reviewed"):
            assert jobs[job]["needs"] == [{"job": "admission", "artifacts": True}]


class TestCircleCIRouting:

    @pytest.fixture
    def release(self):
        return yaml.safe_load((ADMISSION / "circleci" / "release.yml").read_text())

    def test_only_promote_and_hold_can_continue(self, release):
        parameter = release["parameters"]["release-gate-decision"]
        assert parameter["type"] == "enum"
        assert set(parameter["enum"]) == {"NONE", "PROMOTE", "HOLD"}
        assert parameter["default"] == "NONE"

    def test_promote_deploys_and_hold_needs_an_approval_first(self, release):
        workflows = release["workflows"]
        promote = workflows["deploy"]
        assert promote["when"]["equal"][0] == "PROMOTE"
        assert promote["jobs"] == ["deploy"]
        hold = workflows["review-then-deploy"]
        assert hold["when"]["equal"][0] == "HOLD"
        jobs = {next(iter(j)): next(iter(j.values())) for j in hold["jobs"]}
        assert jobs["human-review"] == {"type": "approval"}
        assert jobs["deploy"]["requires"] == ["human-review"]

    def test_the_setup_hands_on_the_file_the_gate_writes(self):
        spec = yaml.safe_load((ADMISSION / "circleci" / "config.yml").read_text())
        assert spec["setup"] is True
        cont = next(s["continuation/continue"] for s in spec["jobs"]["admission"]["steps"]
                    if isinstance(s, dict) and "continuation/continue" in s)
        assert cont["configuration_path"] == ".circleci/release.yml"
        assert cont["parameters"] == "release-gate-out/continuation.json"
        assert '"$out/continuation.json"' in _circleci_script()
        environment = spec["jobs"]["admission"]["environment"]
        assert environment["RELEASE_GATE_OUT"] == "release-gate-out"


class TestTheAdmissionReportIsKeptOnEveryRun:
    """A BLOCK is exactly when someone needs the report; a failed gate must still keep it."""

    def test_github(self):
        spec = yaml.safe_load((ROOT / "action.yml").read_text())
        upload = next(s for s in spec["runs"]["steps"]
                      if s.get("name") == "Upload the Admission Report")
        assert "always()" in upload["if"]

    def test_gitlab(self):
        job = yaml.safe_load((ADMISSION / "gitlab-ci.yml").read_text())["admission"]
        assert job["artifacts"]["when"] == "always"
        assert job["artifacts"]["paths"] == ["release-gate-out/"]

    def test_azure(self):
        spec = yaml.safe_load((ADMISSION / "azure-pipelines.yml").read_text())
        release = next(s for s in spec["stages"] if s["stage"] == "Release")
        admission = next(j for j in release["jobs"] if j["job"] == "Admission")
        publish = next(s for s in admission["steps"]
                       if s.get("artifact") == "release-gate-admission")
        assert publish["condition"] == "always()"

    def test_jenkins(self):
        text = _jenkins_groovy()
        stage = text[text.index("stage('Admission')"):text.index("stage('Human review')")]
        post = stage[stage.index("post {"):]
        assert "always {" in post and "archiveArtifacts artifacts: 'release-gate-out/**'" in post

    def test_circleci(self):
        spec = yaml.safe_load((ADMISSION / "circleci" / "config.yml").read_text())
        store = next(s["store_artifacts"] for s in spec["jobs"]["admission"]["steps"]
                     if isinstance(s, dict) and "store_artifacts" in s)
        assert store["path"] == "release-gate-out" and store["when"] == "always"

    def test_circleci_audit(self):
        spec = yaml.safe_load((TEMPLATES / "circleci.yml").read_text())
        stores = [s["store_artifacts"] for s in spec["jobs"]["release-gate"]["steps"]
                  if isinstance(s, dict) and "store_artifacts" in s]
        assert stores and all(s["when"] == "always" for s in stores)


class TestJenkinsRouting:
    """No Jenkins here, so the Groovy that follows the executed `sh` is read for its shape."""

    def test_each_decision_takes_its_branch(self):
        text = _jenkins_groovy()
        script = text[text.index("script {"):text.index("post {")]
        branches = re.findall(r"if \((.*?)\) \{\s*(\w+)[\s(]", script)
        assert branches == [
            ("decision == 'PROMOTE'", "echo"),
            ("decision == 'HOLD' && env.RELEASE_GATE_HOLD_POLICY == 'normal'", "unstable"),
            ("decision == 'HOLD'", "error"),
        ]
        assert re.search(r"\} else \{\s*error\(", script), "anything else must error"

    def test_review_is_an_input_on_hold_and_deploy_follows_it(self):
        text = _jenkins_groovy()
        review = text[text.index("stage('Human review')"):text.index("stage('Deploy')")]
        assert "environment name: 'RELEASE_GATE_DECISION', value: 'HOLD'" in review
        assert "input message:" in review and "submitter:" in review
        deploy = text[text.index("stage('Deploy')"):]
        assert ("env.RELEASE_GATE_DECISION == 'PROMOTE' || "
                "env.RELEASE_GATE_DECISION == 'HOLD'") in deploy
        assert "archiveArtifacts artifacts: 'release-gate-out/**'" in text


# ── the audit templates ──────────────────────────────────────────────────────

AUDIT_STUB = '#!/bin/sh\necho "$@" >> audit-calls\nexit "${AUDIT_CODE}"\n'


@pytest.fixture
def audit_stub(tmp_path):
    bin_dir = tmp_path / "abin"
    bin_dir.mkdir()
    script = bin_dir / "release-gate"
    script.write_text(AUDIT_STUB, encoding="utf-8")
    script.chmod(0o755)
    return bin_dir


def _circle_audit_script():
    spec = yaml.safe_load((TEMPLATES / "circleci.yml").read_text())
    return next(s["run"]["command"] for s in spec["jobs"]["release-gate"]["steps"]
                if isinstance(s, dict) and isinstance(s.get("run"), dict)
                and s["run"].get("name") == "AI safeguard audit")


def _azure_audit_script():
    spec = yaml.safe_load((TEMPLATES / "azure-pipelines.yml").read_text())
    return next(s["bash"] for s in spec["steps"] if "bash" in s)


@pytest.mark.parametrize("read", [_circle_audit_script, _azure_audit_script])
@pytest.mark.parametrize("code,policy,expected", [
    (0, "normal", 0), (0, "strict", 0), (10, "normal", 0), (10, "strict", 1),
    (1, "normal", 1), (1, "strict", 1), (2, "normal", 1)])
def test_audit_templates_keep_hold_apart_from_block(read, code, policy, expected,
                                                     tmp_path, audit_stub):
    result = _run_script(read(), shell="bash", cwd=tmp_path, bin_dir=audit_stub,
                         env={"AUDIT_CODE": str(code),
                              "RELEASE_GATE_HOLD_POLICY": policy})
    assert result.returncode == expected, result.stdout + result.stderr
    if code == 10 and policy == "normal" and read is _azure_audit_script:
        assert "result=SucceededWithIssues" in result.stdout


def test_gitlab_audit_holds_with_a_warning_rather_than_failing():
    job = yaml.safe_load((TEMPLATES / "gitlab-ci.yml").read_text())["release-gate"]
    assert job["allow_failure"] == {"exit_codes": [10]}
    assert job["artifacts"]["when"] == "always"


def test_jenkins_audit_maps_hold_to_unstable():
    text = (TEMPLATES / "jenkins" / "Jenkinsfile").read_text()
    assert "returnStatus: true" in text
    assert re.search(r"code == 10 && env.RELEASE_GATE_HOLD_POLICY == 'normal'\) \{\s*"
                     r"unstable\(", text)


@pytest.mark.parametrize("path", sorted(p for p in TEMPLATES.rglob("*")
                                        if p.is_file() and p.suffix != ".md"),
                         ids=lambda p: str(p.relative_to(TEMPLATES)))
def test_no_template_passes_a_value_to_audits_json_flag(path):
    """`--json release-gate.json` wrote no file: --json takes no value."""
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"audit[^\n]*--json\s+(?![>|&;\\]|$)[^\s-]", text, re.M)


# ── end to end: the real CLI, through a template's gate, on the demo ─────────

@pytest.fixture
def real_cli(tmp_path):
    bin_dir = tmp_path / "rbin"
    bin_dir.mkdir()
    script = bin_dir / "release-gate"
    script.write_text(f'#!/bin/sh\nPYTHONPATH="{ROOT}" exec "{sys.executable}" '
                      f'-m release_gate.cli "$@"\n', encoding="utf-8")
    shim = bin_dir / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for f in (script, shim):
        f.chmod(0o755)
    return bin_dir


@pytest.mark.parametrize("policy_file,hold_policy,decision,code", [
    ("block-on-counterexample.json", "normal", "BLOCK", 1),
    ("hold-on-counterexample.json", "normal", "HOLD", 10),
    ("hold-on-counterexample.json", "strict", "HOLD", 1),
])
def test_the_gitlab_gate_admits_the_demo_by_its_declared_policy(
        policy_file, hold_policy, decision, code, tmp_path, real_cli):
    env = {"RELEASE_GATE_INPUT": str(DEMO / "release.jsonl"),
           "RELEASE_GATE_EVIDENCE": str(DEMO / "evidence"),
           "RELEASE_GATE_METHODOLOGY": str(DEMO / "methodology.json"),
           "RELEASE_GATE_RESOLUTION_POLICY": str(DEMO / "policy" / policy_file),
           "RELEASE_GATE_OUT": "release-gate-out",
           "RELEASE_GATE_HOLD_POLICY": hold_policy}
    result = _run_script(_gitlab_script(), shell="sh", cwd=tmp_path, env=env,
                         bin_dir=real_cli)
    assert result.returncode == code, result.stdout + result.stderr
    assert _decision_file(tmp_path) == decision
    out = tmp_path / "release-gate-out"
    report = json.loads((out / "admission-report.json").read_text())
    assert report["decision"] == decision and report["record_type"] == "admission_report"
    assert "ADMISSION REPORT" in (out / "admission-report.txt").read_text()
    assert json.loads((out / "case.json").read_text())
