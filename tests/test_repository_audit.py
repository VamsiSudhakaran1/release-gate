"""What the final repository audit found, pinned so it cannot come back.

Five defects, none of them in the assurance engine and all of them the same
shape: **a statement the repository makes about itself that was not true.** A
version banner, a docstring's timing figure, a claim about how much work a demo
does, and — the one with teeth — a core schema that said it would refuse a record
from the future and did not.

None was a regression. Each had been true for as long as the file existed, which
is the argument for pinning them: nothing was watching.
"""

from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args],
                          capture_output=True, text=True, cwd=str(ROOT), timeout=300)


# ── one version, not two ────────────────────────────────────────────────────

class TestTheVersionIsStatedOnce:

    def test_the_cli_reports_the_package_version(self):
        """The banner said v0.8.4 while the package was 0.10.1. A user reading it
        was told the wrong thing about what they had installed."""
        from release_gate import __version__

        result = _cli("--version")
        assert result.returncode == 0
        assert __version__ in result.stdout

    def test_no_version_is_hardcoded_in_the_cli(self):
        """Derived from one source, so the two cannot disagree again."""
        source = (ROOT / "release_gate" / "cli.py").read_text()
        hardcoded = re.findall(r"release-gate[^\"\n]*v\d+\.\d+\.\d+", source)
        assert hardcoded == [], f"hardcoded version banners: {hardcoded}"

    def test_the_banner_lines_interpolate_it(self):
        source = (ROOT / "release_gate" / "cli.py").read_text()
        assert source.count("_VERSION") >= 4


# ── the flags every CLI is expected to answer ───────────────────────────────

class TestTheConventionalFlags:

    @pytest.mark.parametrize("flag", ["--help", "-h", "help"])
    def test_help_succeeds(self, flag):
        """`--help` printed "Unknown command: --help" and exited 1, which fails a
        CI smoke step and tells a first-time user their install is broken."""
        result = _cli(flag)
        assert result.returncode == 0
        assert "Unknown command" not in result.stdout

    @pytest.mark.parametrize("flag", ["--version", "-V", "version"])
    def test_version_succeeds(self, flag):
        result = _cli(flag)
        assert result.returncode == 0
        assert "Unknown command" not in result.stdout

    def test_an_unknown_command_still_fails(self):
        """The half that was already right: a typo in a workflow must not pass."""
        result = _cli("scoer")
        assert result.returncode == 1
        assert "Unknown command" in result.stdout


# ── a wrong argument gets a sentence, not a stack trace ─────────────────────

class TestNoRawTracebacks:

    def test_score_on_a_directory_explains_itself(self):
        """`release-gate score .` raised IsADirectoryError at the user.

        `audit` takes a directory and `score` takes a governance file, so the
        confusion is the product's — and a traceback is the worst available way
        to explain it.
        """
        result = _cli("score", ".")
        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        assert "is a directory" in result.stdout
        assert "release-gate audit ." in result.stdout


# ── the core schema that said it would refuse the future ───────────────────

class TestForwardCompatibility:

    BASE = {"method": "THEOREM_PROVER", "verifier": "x", "status": "PASSED",
            "target": {"kind": "CLAIM", "target_id": "C-1"}}

    def test_a_future_verification_record_is_refused(self):
        """It was read instead, dropping whatever the newer version added.

        `verification` is core, and the only core schema that has actually moved
        — three times, to v4. A v5 attempt read by a v4 reader loses v5's fields
        silently, into a case an approval then binds to (Invariant 5).
        """
        from release_gate.assurance.verification import (
            VerificationAttempt, VerificationError)

        with pytest.raises(VerificationError) as exc:
            VerificationAttempt.from_dict({**self.BASE, "schema_version": 99})
        assert "newer than this reader" in str(exc.value)

    def test_an_unparseable_version_is_refused_too(self):
        from release_gate.assurance.verification import (
            VerificationAttempt, VerificationError)

        with pytest.raises(VerificationError):
            VerificationAttempt.from_dict({**self.BASE, "schema_version": "v5"})

    @pytest.mark.parametrize("version", [None, 1, 2, 3, 4])
    def test_this_version_and_every_older_one_still_read(self, version):
        """The guard must not cost backward compatibility, which is the whole
        reason a reader tolerates old records in the first place."""
        from release_gate.assurance.verification import VerificationAttempt

        payload = dict(self.BASE)
        if version is not None:
            payload["schema_version"] = version
        assert VerificationAttempt.from_dict(payload).method.value == "THEOREM_PROVER"

    def test_the_guard_reads_the_same_wherever_it_fires(self):
        """Same sentence, so a reader meeting it anywhere recognises it.

        Compared by raising it, not by grepping the source: the phrase is split
        across two source lines in `verification.py`, so a text search for it
        finds nothing while the message a user sees is identical. Substring
        checks read text, not meaning.
        """
        from release_gate.assurance.claims import Claim
        from release_gate.assurance.evidence import (
            EvidenceRecord, EvidenceType, Producer, ProducerKind)
        from release_gate.assurance.verification import VerificationAttempt

        messages = []
        for build in (
            lambda: Claim.from_dict({
                "claim_id": "C-1", "statement": "s", "claim_type": "ASSERTION",
                "provenance": "DECLARED", "schema_version": 99,
                "producer": {"producer_id": "a://b", "kind": "agent"}}),
            lambda: EvidenceRecord(
                evidence_type=EvidenceType.TRACE, source="s",
                producer=Producer(producer_id="a://b", kind=ProducerKind.AGENT),
                coverage_note="n", schema_version=99),
            lambda: VerificationAttempt.from_dict({
                **self.BASE, "schema_version": 99}),
        ):
            with pytest.raises(Exception) as exc:
                build()
            messages.append(str(exc.value))

        for message in messages:
            assert "newer than this reader understands" in message
            assert "upgrade release-gate" in message

    def test_which_core_schemas_are_still_unguarded(self):
        """Documented rather than asserted away, and probed rather than grepped.

        Three of eight core schemas refuse a record from the future. The other
        five sit at v1 and have never moved, so nothing can yet have been
        misread — but the guard is cheap and the exposure begins the first time
        one of them moves. This fails if the set changes in either direction, so
        the decision gets taken deliberately rather than drifting.
        """
        from release_gate.assurance.protocol import PROTOCOL

        guarded = {"evidence", "claim", "verification"}
        unguarded = {"event", "subject", "case", "approval_packet",
                     "required_evidence"}
        assert guarded | unguarded == {
            r.name for r in PROTOCOL.schemas if r.core}
        assert all(PROTOCOL.schema(n).version == 1 for n in unguarded), (
            "a core schema moved past v1 without a future-version guard; add one "
            "before its reader can silently drop a newer record's fields")


# ── counts the README states about the engine ─────────────────────────────

class TestTheReadmeCountsAreCurrent:

    def test_the_attack_count_matches_the_threat_model(self):
        """It said nineteen after the twentieth was added.

        A number in a README is a claim like any other, and this one is checkable
        against the thing it describes — so nothing excuses it drifting.
        """
        from release_gate.assurance.hostile import THREATS

        readme = (ROOT / "README.md").read_text()
        words = {19: "nineteen", 20: "twenty", 21: "twenty-one", 22: "twenty-two"}
        stated = words.get(len(THREATS))
        assert stated, f"add a word for {len(THREATS)} threats"
        assert f"{stated} attacks run against the engine" in readme, (
            f"the threat model holds {len(THREATS)} attacks; the README says "
            "something else")

    def test_the_readme_does_not_make_the_forbidden_claims(self):
        """Each forbidden phrase appears only as something release-gate refuses.

        A plain substring scan flags all of them, because the README's job here is
        to name what it does not claim. So this checks the phrase is negated, not
        that it is absent — a tripwire that could not tell a claim from its
        refusal would force the document to stop being explicit.
        """
        readme = (ROOT / "README.md").read_text().lower()
        for phrase in ("guaranteed correct", "unhackable", "uncontested"):
            assert phrase in readme, f"{phrase!r} is no longer named"
            before = readme[max(0, readme.index(phrase) - 120):readme.index(phrase)]
            assert "not that" in before, (
                f"{phrase!r} reads as a claim rather than one being refused")


# ── the GitHub Action cannot call a command that does not exist ────────────

class TestTheActionMatchesTheCLI:

    def test_every_command_the_action_runs_is_dispatched(self):
        """A workflow calling a command the CLI dropped fails in users' CI, not ours.

        Parsed from the `run:` blocks only. A first pass at this grepped the
        whole file and "found" a `release-gate rules` command — which was the
        English phrase "release-gate rules on their verdict" inside an input's
        description. Substring checks read text, not meaning.
        """
        import re

        import yaml

        spec = yaml.safe_load((ROOT / "action.yml").read_text())
        invoked = set()
        for step in spec["runs"]["steps"]:
            for match in re.finditer(r"release-gate\s+([a-z][a-z-]*)",
                                     step.get("run") or ""):
                invoked.add(match.group(1))

        source = (ROOT / "release_gate" / "cli.py").read_text()
        dispatched = set(re.findall(r"command == '([a-z-]+)'", source))
        dispatched |= {"help", "version"}

        assert invoked, "no invocations parsed — the parse is wrong, not the action"
        assert invoked <= dispatched, (
            f"action.yml runs {sorted(invoked - dispatched)}, which the CLI does "
            "not dispatch")


# ── the flagship demo's claims about itself ────────────────────────────────

class TestTheDemoDoesNotOverstateItself:

    @staticmethod
    @pytest.fixture(scope="class")
    def docstring():
        source = (ROOT / "release_gate" / "demos" / "frontier_research.py").read_text()
        return ast.get_docstring(ast.parse(source)) or ""

    def test_it_no_longer_claims_half_a_minute(self, docstring):
        """It never took half a minute: 3.8s at the commit that wrote the
        sentence, ~3.4s today.

        The docstring still contains the phrase, because it now quotes the claim
        while correcting it — so this asserts the correction is there rather than
        that the words are absent. A tripwire that could not tell a claim from a
        retraction of it would force the file to stop explaining itself.
        """
        assert "overstated it twice" in docstring
        assert docstring.count("half a minute") == 1
        quoted = docstring.index("half a minute")
        assert docstring.index("overstated it twice") < quoted, (
            "the phrase appears before its correction, so it reads as a claim")

    def test_nor_that_every_event_is_digested(self, docstring):
        """2.18M events are counted; ~13K records are built and digested.

        Claiming the first would be claiming 170x the work the demo does — and
        in a file whose stated purpose is to let a claim be checked rather than
        asserted.
        """
        assert "Every event and claim is constructed" not in docstring

    def test_and_the_counts_it_does_state_are_the_real_ones(self):
        from release_gate.demos.frontier_research import DEFAULT_SCENARIO, build_normalisation

        source = (ROOT / "release_gate" / "demos" / "frontier_research.py").read_text()
        docstring = ast.get_docstring(ast.parse(source)) or ""
        normalisation, _ = build_normalisation(DEFAULT_SCENARIO)
        tally = normalisation.records_seen_by_kind
        assert f"{tally['execution']:,}" in docstring
        assert f"{len(normalisation.evidence):,}" in docstring
        assert f"{len(normalisation.claims):,}" in docstring
