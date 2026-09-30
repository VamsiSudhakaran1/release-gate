"""The static scanner as a first-class evidence producer.

Six properties, each asked for by name and each tested against a real scan of a
real (temporary, git-backed) repository rather than a hand-shaped dict wherever
the scan can produce the input:

  1. the RG-* findings, and every renderer that prints them, are unchanged;
  2. every finding becomes a Universal Evidence record;
  3. that record keeps the source-to-sink path and the lines it covers;
  4. a finding about something *missing* is scoped to where the analyser
     looked, and never reads as absence everywhere;
  5. every record is bound to the exact repository, commit and bytes scanned;
  6. `release-gate audit`, its JSON and its exit code behave as they did.

Property 4 is the one with history. RG-GATE-001 told a maintainer their project
had no approval gate when the gate lived in a layer the analyser does not read.
What the rule established was narrower — static analysis did not identify a
code-level approval gate on that path — and these tests hold the evidence to
that sentence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.evidence import EvidenceRecord, EvidenceType, ProducerKind
from release_gate.assurance.static_producer import (
    PRODUCER_TYPE, RULE_PROFILES, SCAN_PROVENANCE_KEY, Binding, ObservationKind,
    PathStatus, RuleEvidenceProfile, ScanProvenance, StaticEvidenceProducer,
    StaticProducerError, emit_from_report, finding_span, evidence_profile_for, region_key,
    safeguard_profile)

ROOT = Path(__file__).resolve().parent.parent

# The demo's vulnerable agent, plus one tool that deletes without a gate: a
# CONFIRMED taint path (RG-EXEC-001) and a scoped absence (RG-GATE-001) from the
# real analyser, in one file.
AGENT = '''import os

import pandas as pd
from openai import OpenAI
from langchain.tools import tool

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def answer(df: pd.DataFrame, question: str):
    resp = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=64,
        messages=[
            {"role": "system", "content": "Reply with a single pandas expression over `df`."},
            {"role": "user", "content": question},
        ],
    )
    expr = resp.choices[0].message.content
    return eval(expr, {"df": df})


@tool
def purge(path):
    os.remove(path)
'''

GATE_SENTENCE = "static analysis did not identify a code-level approval gate on this path"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=test@example.com",
         "-c", "user.name=test", "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git is not available")
    root = tmp_path / "agent-repo"
    root.mkdir()
    (root / "agent.py").write_text(AGENT, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "init")
    return root


@pytest.fixture
def report(repo):
    from release_gate.audit import build_report
    return build_report(repo)


def _finding(report, rule_id):
    hits = [f for f in report["code_findings"] if f.get("rule_id") == rule_id]
    assert hits, f"the fixture no longer raises {rule_id}: {[f.get('rule_id') for f in report['code_findings']]}"
    return hits[0]


def _record_for(emission, rule_id):
    hits = [e for e in emission.evidence
            if e.content.get("rule_id") == rule_id]
    assert len(hits) == 1, rule_id
    return hits[0]


def _without_provenance(report):
    return {k: v for k, v in report.items() if k != SCAN_PROVENANCE_KEY}


def _assure_doc(tmp_path, doc, name="audit.json", methodology=None):
    from release_gate.assurance.zero_config import assure
    path = tmp_path / name
    path.write_text(json.dumps(doc, default=str), encoding="utf-8")
    return assure(str(path), methodology=methodology)


# ── 1. the findings and their renderings are unchanged ──────────────────────

#: Every key a code finding has carried. This work adds none: the provenance
#: lives beside the findings, in its own block.
FINDING_KEYS = {"basis", "confidence", "evidence", "file", "impact", "line",
                "recommendation", "rule_id", "severity", "snippet", "title",
                "compliance_tags", "provenance"}


class TestOldFindingsRenderIdentically:

    def test_the_fixture_raises_both_kinds_of_finding(self, report):
        assert _finding(report, "RG-EXEC-001")["basis"] == "confirmed"
        assert _finding(report, "RG-GATE-001")

    def test_no_finding_gains_a_key(self, report):
        for finding in report["code_findings"]:
            assert set(finding) <= FINDING_KEYS, set(finding) - FINDING_KEYS

    def test_the_rule_ids_are_the_catalogue_ids(self, report):
        from release_gate.rules import get_rule
        for finding in report["code_findings"]:
            assert get_rule(finding["rule_id"]) is not None, finding["rule_id"]

    @pytest.mark.parametrize("name", ["render_markdown", "badge_markdown",
                                      "render_pr_comment"])
    def test_each_renderer_prints_the_same_with_or_without_the_block(self, report, name):
        import release_gate.audit as audit
        render = getattr(audit, name)
        args = (None,) if name == "render_pr_comment" else ()
        assert render(report, *args) == render(_without_provenance(report), *args)

    def test_the_terminal_report_is_the_same(self, report, capsys):
        from release_gate.audit import render_terminal
        render_terminal(report, full=True)
        with_block = capsys.readouterr().out
        render_terminal(_without_provenance(report), full=True)
        assert capsys.readouterr().out == with_block

    def test_sarif_is_the_same(self, report, tmp_path):
        from release_gate.audit import emit_sarif
        emit_sarif(report, str(tmp_path / "a.sarif"))
        emit_sarif(_without_provenance(report), str(tmp_path / "b.sarif"))
        assert (json.loads((tmp_path / "a.sarif").read_text())
                == json.loads((tmp_path / "b.sarif").read_text()))

    def test_emitting_evidence_does_not_touch_the_report(self, report):
        before = copy.deepcopy(report)
        emit_from_report(report, source="audit.json")
        assert report == before

    def test_the_keys_the_bridge_always_carried_keep_their_values(self, report):
        finding = _finding(report, "RG-EXEC-001")
        record = _record_for(emit_from_report(report, source="a.json"), "RG-EXEC-001")
        for key in ("rule_id", "title", "file", "line", "severity", "basis",
                    "confidence", "evidence", "compliance_tags"):
            assert record.content[key] == (tuple(finding[key]) if isinstance(
                finding[key], list) else finding[key]), key
        assert record.content["method"] == "STATIC_ANALYSIS"


# ── 2. every finding is Universal Evidence ───────────────────────────────────

class TestStaticFindingsAreUniversalEvidence:

    def test_one_record_per_finding_against_the_code_safety_claim(self, report):
        emission = emit_from_report(report, source="a.json")
        findings = [e for e in emission.evidence if e.content.get("rule_id")]
        assert len(findings) == len(report["code_findings"])
        for record in findings:
            assert record.evidence_type is EvidenceType.STATIC_FINDING
            assert record.contradicts_claims == ("sw:code-safety",)
            assert record.epistemic_status.value == "DERIVED"
            assert record.coverage_status.value == "PARTIAL"

    def test_the_producer_is_identified_typed_and_versioned(self, report):
        emission = emit_from_report(report, source="a.json")
        version = report[SCAN_PROVENANCE_KEY]["scanner"]["version"]
        for record in emission.evidence:
            assert record.producer.producer_id == "release-gate/static"
            assert record.producer.version == version
            assert record.metadata["producer_type"] == PRODUCER_TYPE
        assert PRODUCER_TYPE == "release_gate_static"

    def test_each_record_names_its_rule_version_and_mappings(self, report):
        from release_gate.rules import get_rule, rule_digest
        record = _record_for(emit_from_report(report, source="a.json"), "RG-EXEC-001")
        rule = get_rule("RG-EXEC-001")
        assert record.content["rule"]["digest"] == rule_digest(rule)
        assert record.content["finding_type"] == f"{rule.category}/{rule.type_key}"
        assert set(record.content["framework_mappings"]) == set(
            _finding(report, "RG-EXEC-001")["compliance_tags"])
        assert record.metadata["ruleset_digest"].startswith("sha256:")
        assert record.metadata["analyser_digest"].startswith("sha256:")

    def test_every_catalogue_rule_has_a_profile_and_no_profile_is_invented(self):
        from release_gate.rules import RULES
        assert {r.id for r in RULES} == set(RULE_PROFILES)

    def test_an_unknown_rule_is_unclassified_not_borrowed(self):
        profile = evidence_profile_for("RG-TAINT-001")
        assert profile.kind is ObservationKind.UNCLASSIFIED
        assert profile.not_identified == ""
        assert "never stated" in profile.does_not_establish[0]

    def test_the_producer_is_the_code_scanner_lane(self):
        from release_gate.assurance.producers import EvidenceLane, lane_for
        descriptor = StaticEvidenceProducer().descriptor
        assert descriptor is lane_for(EvidenceLane.CODE_SCANNER)
        assert descriptor.establishes_runtime_behaviour is False

    def test_a_profile_without_limits_is_refused(self):
        with pytest.raises(StaticProducerError):
            RuleEvidenceProfile(rule_id="RG-X", kind=ObservationKind.PRESENCE,
                                observed="x", scope="y", does_not_establish=())

    def test_an_absence_phrased_as_a_fact_about_the_world_is_refused(self):
        with pytest.raises(StaticProducerError):
            RuleEvidenceProfile(rule_id="RG-X", kind=ObservationKind.SCOPED_ABSENCE,
                                observed="a tool deletes", scope="the tool",
                                does_not_establish=("z",),
                                not_identified="there is no approval gate")

    def test_a_presence_cannot_smuggle_in_an_absence(self):
        with pytest.raises(StaticProducerError):
            RuleEvidenceProfile(rule_id="RG-X", kind=ObservationKind.PRESENCE,
                                observed="x", scope="y", does_not_establish=("z",),
                                not_identified=GATE_SENTENCE)


# ── 3. the source-to-sink path survives ──────────────────────────────────────

def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class TestSourceToSinkProvenance:

    def test_the_traced_path_carries_both_coordinates(self, report):
        finding = _finding(report, "RG-EXEC-001")
        record = _record_for(emit_from_report(report, source="a.json"), "RG-EXEC-001")
        path = record.content["path"]
        assert path["status"] == PathStatus.TRACED.value
        assert path["source"]["line"] == finding["provenance"]["origin_line"]
        assert path["source"]["expression"] == finding["provenance"]["origin_expr"]
        assert path["sink"]["line"] == finding["provenance"]["sink_line"]
        assert path["chain"] == finding["evidence"]
        location = record.content["location"]
        assert (location["start_line"], location["end_line"]) == (
            finding["provenance"]["origin_line"], finding["provenance"]["sink_line"])

    def test_the_line_digest_is_of_exactly_those_lines(self, repo, report):
        record = _record_for(emit_from_report(report, source="a.json"), "RG-EXEC-001")
        region = record.content["code"]["region"]
        raw = (repo / "agent.py").read_bytes()
        lines = raw.split(b"\n")[region["start"] - 1:region["end"]]
        assert region["sha256"] == _sha(b"\n".join(lines))
        assert b"eval(" in lines[-1] and b"create(" in lines[0]
        assert record.content["code"]["file_sha256"] == _sha(raw)

    def test_a_finding_without_coordinates_says_so(self):
        emission = emit_from_report({"code_findings": [
            {"rule_id": "RG-EXEC-003", "title": "Dynamic execution sink",
             "file": "a.py", "line": 4, "basis": "heuristic", "evidence": ""}]},
            source="a.json")
        record = emission.evidence[0]
        assert record.content["path"]["status"] == PathStatus.NOT_RECORDED.value
        assert any("no source-to-sink coordinates" in item
                   for item in record.content["limitations"])

    def test_a_cross_module_origin_names_its_own_file(self):
        """The origin line of a cross-module taint belongs to another file."""
        finding = {"rule_id": "RG-EXEC-001", "file": "app/run.py", "line": 40,
                   "provenance": {"origin_line": 7, "sink_line": 40, "value": "cmd",
                                  "origin_expr": "ask_model() [app/llm.py]"}}
        assert finding_span(finding) == (40, 40)
        record = emit_from_report({"code_findings": [finding]},
                                  source="a.json").evidence[0]
        assert record.content["path"]["source"]["file"] == "app/llm.py"
        assert record.content["path"]["sink"]["file"] == "app/run.py"

    def test_the_audit_and_the_producer_key_regions_identically(self, report):
        finding = _finding(report, "RG-EXEC-001")
        key = region_key(finding["file"], *finding_span(finding))
        assert key in report[SCAN_PROVENANCE_KEY]["regions"]


# ── 4. an absence is scoped to where the analyser looked ────────────────────

class TestStaticAbsenceIsNotGlobalAbsence:

    def test_gate_001_says_exactly_what_it_established(self, report):
        record = _record_for(emit_from_report(report, source="a.json"), "RG-GATE-001")
        assert record.content["observation_kind"] == ObservationKind.SCOPED_ABSENCE.value
        assert record.content["not_identified"] == GATE_SENTENCE
        assert GATE_SENTENCE in record.content["observation"]
        assert GATE_SENTENCE in record.coverage_note
        assert "that no human approval exists anywhere" in record.content[
            "does_not_establish"]

    def test_every_scoped_absence_is_phrased_as_what_analysis_did_not_identify(self):
        absences = [p for p in RULE_PROFILES.values()
                    if p.kind is ObservationKind.SCOPED_ABSENCE]
        assert absences
        for profile in absences:
            assert profile.not_identified.startswith("static analysis did not identify")

    def test_the_absence_rules_are_the_ones_that_report_something_missing(self):
        """Pinned, so a rule cannot drift from SCOPED_ABSENCE to PRESENCE unseen."""
        assert {p.rule_id for p in RULE_PROFILES.values()
                if p.kind is ObservationKind.SCOPED_ABSENCE} == {
            "RG-EXEC-002", "RG-PARSE-001", "RG-TOOL-001", "RG-GATE-001",
            "RG-PII-001", "RG-COST-001", "RG-COST-002", "RG-LOOP-001"}

    def test_a_missing_safeguard_is_evidence_about_the_repository(self, report):
        emission = emit_from_report(report, source="a.json")
        claim = next(c for c in emission.claims if c.claim_id == "sw:safeguard:kill_switch")
        assert claim.statement == "this repository carries a valid kill switch declaration"
        assert "deployed system" in claim.metadata["does_not_ask"]
        against = [e for e in emission.evidence
                   if "sw:safeguard:kill_switch" in e.contradicts_claims]
        assert len(against) == 1
        assert against[0].contradicts_claims == ("sw:safeguard:kill_switch",)
        assert against[0].content["not_identified"] == (
            "static analysis did not identify a valid kill switch declaration in "
            "this repository")
        assert "that the deployed system has no kill switch" in against[0].content[
            "does_not_establish"]

    def test_no_claim_asserts_the_deployed_system_state(self, report):
        """The claims a static scan argues about are about code and repository."""
        emission = emit_from_report(report, source="a.json")
        statements = {c.claim_id: c.statement for c in emission.claims}
        for claim_id, statement in statements.items():
            if claim_id.startswith("sw:safeguard:"):
                assert statement.startswith("this repository carries a valid ")
        assert statements["sw:code-safety"] == (
            "static analysis found no unsafe pattern in this code")

    def test_scoping_the_claim_does_not_weaken_the_gate(self, tmp_path, report):
        """Narrower wording, same refutation, same verdict. A missing safeguard
        declaration still refutes the claim that asks for one, still caps the
        root, and the case still blocks."""
        from release_gate.assurance.methodologies import SOFTWARE_AGENT_ASSURANCE_V1
        for methodology in (None, SOFTWARE_AGENT_ASSURANCE_V1):
            outcome = _assure_doc(tmp_path, report, methodology=methodology)
            assert outcome.case.verdict.decision.value == "BLOCK"

    def test_the_verdict_and_claim_statuses_match_a_report_without_provenance(
            self, tmp_path, report):
        """Provenance is attribution. It must not move a decision."""
        from release_gate.assurance.claims import ClaimGraph
        from release_gate.assurance.methodologies import SOFTWARE_AGENT_ASSURANCE_V1

        def statuses(outcome):
            evidence = {e.evidence_id: e
                        for e in outcome.case.collection("evidence").materialised
                        if isinstance(e, EvidenceRecord)}
            claims = list(outcome.case.collection("claims").materialised)
            graph = ClaimGraph(claims, evidence)
            return {c.claim_id: graph.status(c.claim_id) for c in claims}

        for methodology in (None, SOFTWARE_AGENT_ASSURANCE_V1):
            new = _assure_doc(tmp_path, report, "new.json", methodology)
            old = _assure_doc(tmp_path, _without_provenance(report), "old.json",
                              methodology)
            assert new.case.verdict.decision is old.case.verdict.decision
            assert new.exit_code == old.exit_code
            assert statuses(new) == statuses(old)


# ── 5. bound to the exact state ──────────────────────────────────────────────

class TestBoundToTheExactState:

    def test_the_commit_is_the_one_scanned(self, repo, report):
        block = report[SCAN_PROVENANCE_KEY]
        assert block["candidate"]["commit"] == _git(repo, "rev-parse", "HEAD")
        assert block["candidate"]["tree_state"] == "clean"
        assert block["repository"]["vcs"] == "git"

    def test_the_scanned_set_digest_can_be_recomputed_from_the_files(self, repo, report):
        from release_gate.assurance.canonical import digest_object
        pairs = sorted([p.relative_to(repo).as_posix(), _sha(p.read_bytes())]
                       for p in repo.rglob("*.py"))
        scanned = report[SCAN_PROVENANCE_KEY]["candidate"]["scanned_set"]
        assert scanned["files"] == len(pairs)
        assert scanned["digest"] == digest_object(pairs)

    def test_evidence_applies_to_the_scanned_code(self, tmp_path, report):
        digest = report[SCAN_PROVENANCE_KEY]["candidate"]["scanned_set"]["digest"]
        emission = emit_from_report(report, source="a.json", report_digest=None)
        assert emission.binding is Binding.SCANNED_FILES
        assert {e.applies_to_digest for e in emission.evidence} == {digest}
        artifact = emission.artifacts[0]
        assert artifact.digest == digest
        assert artifact.artifact_kind.value == "SOURCE_CODE"
        assert artifact.digest_method.value == "SHA256_MANIFEST"
        assert artifact.digest_status.value == "DECLARED"
        # And the case holds the candidate, so the binding is checkable there.
        outcome = _assure_doc(tmp_path, report)
        held = {a.digest for a in outcome.case.collection("artifacts").materialised}
        assert digest in held

    def test_changing_the_code_moves_the_binding(self, repo, report):
        from release_gate.audit import build_report
        with (repo / "agent.py").open("a", encoding="utf-8") as handle:
            handle.write("# edited\n")
        again = build_report(repo)
        before = report[SCAN_PROVENANCE_KEY]["candidate"]
        after = again[SCAN_PROVENANCE_KEY]["candidate"]
        assert after["scanned_set"]["digest"] != before["scanned_set"]["digest"]
        assert after["tree_state"] == "dirty"
        assert any("working tree differs" in item
                   for item in again[SCAN_PROVENANCE_KEY]["limitations"])
        ids_before = {e.evidence_id for e in emit_from_report(report, source="a").evidence}
        ids_after = {e.evidence_id for e in emit_from_report(again, source="a").evidence}
        assert ids_before.isdisjoint(ids_after)

    def test_a_subdirectory_scan_records_where_in_the_repository(self, repo):
        from release_gate.audit import build_report
        sub = repo / "svc"
        sub.mkdir()
        (sub / "agent.py").write_text(AGENT, encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "svc")
        block = build_report(sub)[SCAN_PROVENANCE_KEY]
        assert block["repository"]["root_relative"] == "svc"
        assert block["candidate"]["commit"] == _git(repo, "rev-parse", "HEAD")

    def test_an_untracked_directory_is_not_credited_with_the_enclosing_commit(
            self, repo):
        """A tarball extracted under a CI checkout sits inside a work tree that
        tracks none of it. That repository's commit describes none of its bytes."""
        from release_gate.audit import build_report
        stray = repo / "extracted"
        stray.mkdir()
        (stray / "agent.py").write_text(AGENT, encoding="utf-8")
        block = build_report(stray)[SCAN_PROVENANCE_KEY]
        assert block["candidate"]["commit"] is None
        assert block["repository"]["vcs"] != "git"
        assert any("tracks none of its files" in item for item in block["limitations"])
        assert not any("no git repository was found" in item
                       for item in block["limitations"])

    def test_tree_state_is_about_the_scanned_directory(self, repo):
        """An uncommitted edit elsewhere in the repository is not a change to
        what was scanned here."""
        from release_gate.audit import build_report
        sub = repo / "svc"
        sub.mkdir()
        (sub / "agent.py").write_text(AGENT, encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "svc")
        (repo / "NOTES.md").write_text("elsewhere\n", encoding="utf-8")
        assert build_report(sub)[SCAN_PROVENANCE_KEY]["candidate"]["tree_state"] == "clean"
        assert build_report(repo)[SCAN_PROVENANCE_KEY]["candidate"]["tree_state"] == "dirty"

    def test_without_git_nothing_is_invented(self, tmp_path):
        from release_gate.audit import build_report
        plain = tmp_path / "no-git"
        plain.mkdir()
        (plain / "agent.py").write_text(AGENT, encoding="utf-8")
        block = build_report(plain)[SCAN_PROVENANCE_KEY]
        assert block["candidate"]["commit"] is None
        assert block["repository"]["vcs"] != "git"
        assert block["candidate"]["scanned_set"]["digest"].startswith("sha256:")
        assert any("no git repository" in item for item in block["limitations"])

    def test_remote_credentials_never_reach_the_report(self, repo):
        from release_gate.audit import build_report
        _git(repo, "remote", "add", "origin",
             "https://x-access-token:ghs_NOTAREALTOKEN@example.com/o/r.git")
        built = build_report(repo)
        assert "ghs_NOTAREALTOKEN" not in json.dumps(built, default=str)
        assert built[SCAN_PROVENANCE_KEY]["repository"]["identity"] == (
            "https://example.com/o/r.git")

    def test_a_report_from_before_the_block_binds_to_itself_and_says_so(self, tmp_path):
        doc = {"score": 60, "decision": "HOLD",
               "code_findings": [{"rule_id": "RG-GATE-001", "file": "a.py", "line": 3,
                                  "title": "Irreversible tool action without a gate"}],
               "code_safety": {"applicable": True}}
        outcome = _assure_doc(tmp_path, doc)
        record = next(e for e in outcome.case.collection("evidence").materialised
                      if isinstance(e, EvidenceRecord)
                      and e.content.get("rule_id") == "RG-GATE-001")
        subject_file = next(e for e in outcome.normalisation.evidence
                            if e.evidence_type is EvidenceType.EXTERNAL_REFERENCE)
        assert record.applies_to_digest == subject_file.digest
        assert record.metadata["binding"] == Binding.REPORT.value
        assert record.metadata["provenance_recorded"] is False
        assert record.metadata["commit"] is None
        assert record.producer.version is None
        assert any("no provenance block" in item for item in record.content["limitations"])
        # The scoping does not depend on the provenance block.
        assert record.content["not_identified"] == GATE_SENTENCE

    def test_malformed_provenance_is_dropped_rather_than_trusted(self):
        provenance = ScanProvenance.from_report({SCAN_PROVENANCE_KEY: {
            "candidate": {"commit": "not-a-sha; rm -rf", "tree_state": "pristine",
                          "scanned_set": {"digest": "abc", "files": -3}},
            "files": {"a.py": "nope"}, "ruleset": {"digest": 7}}})
        assert provenance.recorded
        assert provenance.commit is None
        assert provenance.tree_state == "unknown"
        assert provenance.scanned_set_digest is None
        assert provenance.files_scanned is None
        assert dict(provenance.file_digests) == {}
        assert provenance.ruleset_digest is None
        assert provenance.binding is Binding.REPORT

    def test_a_documents_clock_is_declared_and_an_in_process_one_is_observed(self, report):
        scanned_at = report[SCAN_PROVENANCE_KEY]["scanned_at"]
        ingested = emit_from_report(report, source="a").evidence[0]
        assert ingested.stamped_on_arrival
        assert ingested.metadata["declared_timestamp"] == scanned_at
        assert ingested.producer.kind is ProducerKind.EXTERNAL
        own = emit_from_report(report, source="a", in_process=True).evidence[0]
        assert own.timestamp == scanned_at and not own.stamped_on_arrival
        assert "declared_timestamp" not in own.metadata
        assert own.producer.kind is ProducerKind.RELEASE_GATE

    def test_the_same_report_yields_the_same_evidence(self, report):
        """Reproducible from persisted state: ids are content, not the clock."""
        first = [e.evidence_id for e in emit_from_report(report, source="a").evidence]
        second = [e.evidence_id for e in emit_from_report(report, source="a").evidence]
        assert first == second


# ── 6. the CLI behaves as it did ─────────────────────────────────────────────

def _cli(*args: str, cwd: Path):
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args],
                          capture_output=True, text=True, cwd=str(cwd), timeout=300)


class TestCliCompatibility:

    def test_the_terminal_output_and_exit_code_are_unchanged_by_the_flag(
            self, repo, tmp_path):
        plain = _cli("audit", str(repo), cwd=tmp_path)
        with_flag = _cli("audit", str(repo), "--evidence-out",
                         str(tmp_path / "ev.json"), cwd=tmp_path)
        assert with_flag.returncode == plain.returncode
        assert with_flag.stdout == plain.stdout
        assert "Evidence written to" in with_flag.stderr
        assert "Evidence written to" not in with_flag.stdout

    def test_json_output_keeps_every_key_and_stays_parseable(self, repo, tmp_path):
        result = _cli("audit", str(repo), "--json", "--evidence-out",
                      str(tmp_path / "ev.json"), cwd=tmp_path)
        doc = json.loads(result.stdout)
        for key in ("agent_detected", "code_findings", "code_safety", "coverage",
                    "decision", "detected_model", "example_findings",
                    "expired_suppressions", "frameworks", "governance",
                    "governance_applicable", "governance_file", "has_ci_integration",
                    "missing", "mode", "passing", "path", "real_checks", "safeguards",
                    "scan_coverage", "score", "suppressed"):
            assert key in doc, key
        assert doc[SCAN_PROVENANCE_KEY]["candidate"]["commit"]

    def test_the_evidence_file_is_verifiable_and_assure_reads_all_of_it(
            self, repo, tmp_path):
        from release_gate.assurance.zero_config import assure
        out = tmp_path / "ev.json"
        _cli("audit", str(repo), "--evidence-out", str(out), cwd=tmp_path)
        rows = json.loads(out.read_text(encoding="utf-8"))
        evidence = [r for r in rows if r["record_type"] == "evidence"]
        assert evidence
        for row in evidence:
            record = EvidenceRecord.from_dict(row)   # recomputes and checks the id
            assert record.producer.kind is ProducerKind.RELEASE_GATE
            assert record.metadata["producer_type"] == PRODUCER_TYPE
        gate = [r for r in evidence if r["content"].get("rule_id") == "RG-GATE-001"]
        assert gate and gate[0]["content"]["not_identified"] == GATE_SENTENCE
        outcome = assure(str(out))
        n = outcome.normalisation
        assert n.detection.kind.value == "ASSURANCE_ENVELOPE"
        assert n.records_mapped == n.records_seen and not n.skipped
        # A file on disk cannot claim to be release-gate's own run.
        assert all(r.producer.kind is ProducerKind.EXTERNAL for r in n.evidence
                   if r.producer.producer_id == "release-gate/static")

    def test_a_failing_evidence_write_does_not_change_the_exit_code(self, repo, tmp_path):
        plain = _cli("audit", str(repo), cwd=tmp_path)
        unwritable = tmp_path / "no-such-dir" / "ev.json"
        failed = _cli("audit", str(repo), "--evidence-out", str(unwritable), cwd=tmp_path)
        assert failed.returncode == plain.returncode
        assert failed.stdout == plain.stdout
        assert "could not write evidence" in failed.stderr

    def test_a_tampered_evidence_row_is_refused(self, repo, tmp_path):
        from release_gate.assurance.evidence import EvidenceIntegrityError
        out = tmp_path / "ev.json"
        _cli("audit", str(repo), "--evidence-out", str(out), cwd=tmp_path)
        row = next(r for r in json.loads(out.read_text(encoding="utf-8"))
                   if r["record_type"] == "evidence"
                   and r["content"].get("rule_id") == "RG-GATE-001")
        row["content"]["not_identified"] = "there is no approval gate anywhere"
        with pytest.raises(EvidenceIntegrityError):
            EvidenceRecord.from_dict(row)

    def test_assure_still_reads_an_audit_report(self, repo, tmp_path):
        from release_gate.assurance.zero_config import assure
        result = _cli("audit", str(repo), "--json", cwd=tmp_path)
        path = tmp_path / "audit.json"
        path.write_text(result.stdout, encoding="utf-8")
        outcome = assure(str(path))
        assert outcome.normalisation.detection.kind.value == "AUDIT_REPORT"
        assert outcome.case.verdict.decision.value == "BLOCK"


def test_the_free_tier_redaction_covers_the_provenance_block(report):
    """Anonymous users see no findings. The provenance block names the files and
    line ranges findings sit in, so those parts are locked with them."""
    pytest.importorskip("fastapi")
    from release_gate_api._app import _redact_for_free
    assert report[SCAN_PROVENANCE_KEY]["files"] and report[SCAN_PROVENANCE_KEY]["regions"]
    redacted = _redact_for_free(report)
    assert redacted["code_findings"] == []
    block = redacted[SCAN_PROVENANCE_KEY]
    assert block["files"] == {} and block["regions"] == {} and block["_redacted"]
    blob = json.dumps(redacted, default=str)
    for finding in report["code_findings"]:
        assert f"{finding['file']}#L" not in blob
    # What was scanned stays visible; only where the findings are is locked.
    assert block["candidate"] == report[SCAN_PROVENANCE_KEY]["candidate"]
    # And the caller's report is not mutated by the redaction.
    assert report[SCAN_PROVENANCE_KEY]["files"]


def test_safeguard_profiles_scope_both_directions():
    present = safeguard_profile("kill_switch", present=True)
    absent = safeguard_profile("kill_switch", present=False)
    assert present.kind is ObservationKind.PRESENCE
    assert "that the safeguard fires at runtime" in present.does_not_establish
    assert absent.kind is ObservationKind.SCOPED_ABSENCE
    assert absent.not_identified.startswith("static analysis did not identify")
