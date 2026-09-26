"""The seventeen threats, and the five defects exercising them found.

`test_assurance_anti_gaming.py` attacks the argument; this attacks the engine.
Each defect below is a regression test with a working exploit behind it.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from release_gate.assurance.hostile import (
    HOSTILE_SCHEMA_VERSION, THREATS, Attack, HostileError, Outcome,
    hostile_report, run_threat,
)


@pytest.fixture(scope="module")
def report():
    return hostile_report()


class TestTheThreatModel:

    def test_every_named_threat_is_exercised(self):
        assert set(THREATS) == {
            "approval_forgery", "digest_substitution", "replay", "case_confusion",
            "cross_tenant_evidence_mixing", "event_injection", "schema_abuse",
            "dos", "oversized_payload", "path_traversal", "ssrf",
            "malicious_artifact_links", "tampered_evidence_pack", "toctou",
            "forged_completeness", "fake_verifier_identity",
            "cross_case_evidence_replay"}

    def test_each_threat_behaves_as_its_nature_permits(self, report):
        wrong = [(r["name"], r["expected"], r["outcome"])
                 for r in report["results"] if not r["as_expected"]]
        assert wrong == []

    def test_an_undefended_threat_must_say_what_limits_it(self):
        """A gap with no stated bound is a shrug, and a threat model made of
        shrugs is worse than none."""
        with pytest.raises(HostileError, match="what limits it"):
            Attack("x", "an attack", Outcome.NOT_DEFENDED, lambda: None)

    def test_the_gaps_are_named_rather_than_graded(self, report):
        assert report["not_defended"] == ["cross_tenant_evidence_mixing"]
        gap = THREATS["cross_tenant_evidence_mixing"]
        assert "deployment" in gap.limited_by

    def test_the_report_round_trips(self, report):
        data = json.loads(json.dumps(report))
        assert data["schema_version"] == HOSTILE_SCHEMA_VERSION
        assert len(data["results"]) == len(THREATS)


# ── the five defects these attacks found ─────────────────────────────────────

class TestPathTraversal:
    """`recheck` hashed whatever the locator named and returned the result,
    which makes an unbounded read a digest oracle: guess a file's contents,
    submit the guess as the subject digest, read UNCHANGED or MUTATED."""

    def _subject(self, locator):
        from release_gate.assurance.subject import (
            AssuranceSubject, ContentReference, DigestMethod, DigestStatus,
            ReferenceKind, SubjectType)
        return AssuranceSubject(
            subject_type=SubjectType.CODE_CHANGE, requested_action="x",
            content_reference=ContentReference(kind=ReferenceKind.FILE,
                                               locator=locator),
            digest="sha256:" + hashlib.sha256(b"original").hexdigest(),
            digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED)

    @pytest.fixture
    def tree(self):
        directory = Path(tempfile.mkdtemp())
        (directory / "artifact.bin").write_bytes(b"original")
        return directory

    def test_a_root_is_enforced(self, tree):
        assert self._subject("artifact.bin").recheck(root=tree).status.value \
            == "UNCHANGED"

    @pytest.mark.parametrize("locator", [
        "/etc/passwd", "../../../../etc/hostname", "../..",
    ])
    def test_nothing_outside_the_root_is_read(self, tree, locator):
        check = self._subject(locator).recheck(root=tree)
        assert check.status.value == "UNVERIFIABLE"
        assert check.observed_digest is None

    def test_a_symlink_escaping_the_root_is_caught(self, tree):
        """Resolved before the containment test. Checking the unresolved path
        would let `evidence/link -> /etc/shadow` through on its spelling."""
        link = tree / "sneaky"
        link.symlink_to("/etc/hostname")
        assert self._subject("sneaky").recheck(root=tree).status.value \
            == "UNVERIFIABLE"

    def test_the_refusal_says_why(self, tree):
        detail = self._subject("/etc/passwd").recheck(root=tree).detail
        assert "outside the root" in detail

    def test_the_default_is_permissive_and_that_is_stated(self):
        """Deliberate, not an oversight: in every flow this engine owns the
        subject's locator comes from the file the operator named. A caller
        building subjects from data it did not choose passes a root — and the
        docstring says so, which is what a reader needs."""
        from release_gate.assurance.subject import AssuranceSubject
        assert "should pass one" in AssuranceSubject.recheck.__doc__
        assert "digest oracle" in AssuranceSubject.recheck.__doc__


class TestDenialOfService:

    def test_eighteen_kilobytes_no_longer_takes_the_gate_down(self):
        """Python's JSON decoder recurses per level with no limit of its own, so
        a small file crashed the process with RecursionError before release-gate
        saw a record."""
        from release_gate.assurance.zero_config import assure
        hostile = Path(tempfile.mkdtemp()) / "deep.jsonl"
        hostile.write_text('{"record_type":"evidence","evidence_id":"x",'
                           '"kind":"OTHER","producer":{"producer_id":"p",'
                           '"kind":"tool"},"metadata":'
                           + '{"nest":' * 2000 + '{}' + '}' * 2000 + '}\n')
        assert hostile.stat().st_size < 20_000
        with pytest.raises(Exception) as caught:
            assure(str(hostile))
        assert not isinstance(caught.value, RecursionError)

    def test_a_document_of_ordinary_depth_still_decides(self):
        from release_gate.assurance.zero_config import assure
        fine = Path(tempfile.mkdtemp()) / "fine.jsonl"
        fine.write_text('{"record_type":"evidence","evidence_id":"x",'
                        '"kind":"OTHER","producer":{"producer_id":"p",'
                        '"kind":"tool"},"metadata":'
                        + '{"nest":' * 10 + '{}' + '}' * 10 + '}\n')
        assert assure(str(fine)).case.verdict is not None

    def test_the_depth_scan_ignores_brackets_inside_strings(self):
        """A payload that spells `{{{{` in a field is not depth."""
        from release_gate.adapters.common import _too_deep
        assert _too_deep('{"a":' + '{"b":' * 200 + '1' + '}' * 200 + '}')
        assert not _too_deep('{"a": "' + '{' * 500 + '"}')


class TestOversizedPayload:

    def test_a_twenty_megabyte_field_is_refused_before_parsing(self):
        from release_gate.assurance.chaos import _assure, _base
        outcome = _assure(list(_base()) + [
            {"record_type": "evidence", "evidence_id": "big", "kind": "OTHER",
             "producer": {"producer_id": "x", "kind": "tool"},
             "coverage_note": "A" * 20_000_000}])
        biggest = 0
        for record in outcome.case.collection("evidence").materialised:
            data = record if isinstance(record, dict) else record.to_dict()
            biggest = max(biggest, len(str(data.get("coverage_note") or "")))
        assert biggest < 1_048_576

    def test_and_the_refusal_is_counted_not_dropped_silently(self):
        """A bound that quietly discards a record is itself evidence omission —
        the threat Invariant 13 names."""
        from release_gate.assurance.chaos import _assure, _base
        outcome = _assure(list(_base()) + [
            {"record_type": "evidence", "evidence_id": "big", "kind": "OTHER",
             "producer": {"producer_id": "x", "kind": "tool"},
             "coverage_note": "A" * 20_000_000}])
        assert outcome.normalisation.skipped_total == 1
        assert any("refused" in note for note in outcome.normalisation.notes)


class TestSchemaAbuse:

    @pytest.mark.parametrize("record_type", [{"evil": 1}, ["evidence"], 42, None])
    def test_a_record_type_that_is_not_a_string_is_refused_not_a_crash(
            self, record_type):
        """`record_type in ENVELOPE_RECORD_TYPES` raised TypeError on anything
        unhashable, in detection, before any guard could report it."""
        from release_gate.assurance.chaos import _assure, _base
        from release_gate.assurance.ingest import detect_document
        row = {"record_type": record_type, "evidence_id": "a"}
        assert detect_document([row], filename="x.jsonl") is not None
        outcome = _assure(list(_base()) + [row])
        assert outcome.case.verdict is not None


class TestDisplaySpoofing:
    """The packet is the authorization surface. A producer-controlled string
    reached it carrying a bidirectional override, so the stored producer id and
    the displayed one were different strings."""

    def _packet(self, producer_id):
        from release_gate.assurance.chaos import _assure, _base
        from release_gate.assurance.packet import build_packet, render_packet
        outcome = _assure(list(_base()) + [
            {"record_type": "evidence", "evidence_id": "t", "kind": "TEST_RESULT",
             "producer": {"producer_id": producer_id, "kind": "tool"},
             "coverage_note": "green"}])
        return outcome, render_packet(build_packet(outcome.case, outcome))

    def test_a_bidi_override_is_made_visible_rather_than_rendered(self):
        _outcome, text = self._packet("ci://real‮kcatta")
        assert "‮" not in text
        assert "<U+202E>" in text

    def test_a_newline_in_a_producer_id_cannot_forge_a_row(self):
        """It rendered as its own line, indistinguishable from a real evidence
        entry. Refused rather than escaped: no legitimate producer id has a line
        break in it."""
        outcome, text = self._packet(
            "ci://x\n  - FORGED: verified by security [VERIFIED]")
        assert not any(line.strip().startswith("- FORGED")
                       for line in text.splitlines())
        assert outcome.normalisation.skipped_total == 1

    def test_an_ordinary_producer_id_is_untouched(self):
        _outcome, text = self._packet("ci://pytest")
        assert "ci://pytest" in text

    def test_the_record_keeps_what_was_submitted(self):
        """Sanitising at render time, never at storage time. Rewriting a record
        to make it presentable would be release-gate editing evidence, and the
        digest would stop committing to what arrived."""
        from release_gate.assurance.canonical import display_text
        assert display_text("a‮b") == "a<U+202E>b"
        assert display_text("plain") == "plain"
        assert display_text("layout\nis\npreserved") == "layout\nis\npreserved"


# ── the threats that were already defended ───────────────────────────────────

class TestAlreadyHeld:

    def test_a_forged_approval_does_not_bind(self):
        assert run_threat("approval_forgery").detail["valid"] is False

    def test_fifty_restamped_copies_are_one_record(self):
        assert run_threat("replay").detail["records_held"] == 1

    def test_two_subjects_cannot_share_a_case_identity(self):
        assert run_threat("case_confusion").detail["distinct_ids"] is True

    def test_a_forged_emitter_cannot_self_upgrade_at_the_case_boundary(self):
        """The event asserts OBSERVED and a release_gate identity; the case
        re-derives it to DECLARED from an external, unauthenticated producer."""
        landed = run_threat("event_injection").detail["landed"]
        assert landed["status"] == "DECLARED"
        assert landed["kind"] == "external"
        assert landed["identity_basis"] == "unauthenticated"

    def test_a_tampered_pack_fails_its_own_digest(self):
        detail = run_threat("tampered_evidence_pack").detail
        assert detail["intact_before"] is True
        assert detail["intact_after_edit"] is False

    def test_the_core_imports_no_networking_module(self):
        """Checked in the AST, not by grepping for text — a grep for
        ``urlopen|requests.`` matched this threat's own source, which is the
        fourth time a substring check here has read text instead of meaning."""
        assert run_threat("ssrf").detail["modules_reaching_the_network"] == {}

    def test_hostile_links_are_recorded_and_never_followed(self):
        detail = run_threat("malicious_artifact_links").detail
        assert detail["dereferenced"] == 0
        assert detail["recorded"]

    def test_an_artifact_that_moves_after_the_decision_is_reported(self):
        detail = run_threat("toctou").detail
        assert detail["before"] == "UNCHANGED"
        assert detail["after"] == "MUTATED"
        assert detail["unchanged_after"] is False

    def test_self_certified_completeness_does_not_bound_completeness(self):
        assert run_threat("forged_completeness").detail[
            "bounds_completeness"] is False

    def test_a_self_declared_proof_buys_no_admissible_verification(self):
        assert run_threat("fake_verifier_identity").detail[
            "admissible_verifications"] == 0

    def test_another_cases_evidence_is_detected_as_drift(self):
        assert run_threat("cross_case_evidence_replay").detail["drift_rules"]


class TestExportCollisions:
    """Found while checking that a new export did not shadow an old one, which
    it did: `hostile.Threat` was silently replacing `trust.Threat` in the
    package namespace. Renaming that one fixed it and turned up two more.

    These two are **not fixed here**. Renaming a public export is a breaking
    change and not a call to make inside a security review, so the current
    resolution is pinned instead: it cannot get worse without this failing, and
    the collision is named rather than left for someone to hit at runtime.
    """

    def _owners(self):
        import ast
        import collections
        owners = collections.defaultdict(set)
        for path in sorted(Path("release_gate/assurance").glob("*.py")):
            if path.name == "__init__.py":
                continue
            for node in ast.parse(path.read_text()).body:
                if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                    owners[node.name].add(path.stem)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            owners[target.id].add(path.stem)
        return owners

    def test_the_known_collisions_are_exactly_these_two(self):
        import release_gate.assurance as package
        colliding = {name for name, modules in self._owners().items()
                     if len(modules) > 1 and name in package.__all__}
        assert colliding == {"EvidenceExpectation", "RetentionReason"}, (
            "a new export collides with an existing one; the package namespace "
            "resolves to whichever module was imported last, so one of the two "
            "types is unreachable through it")

    def test_and_they_really_are_different_types(self):
        from release_gate.assurance import (
            compaction, expectation, failed_branches, methodology)
        assert methodology.EvidenceExpectation is not expectation.EvidenceExpectation
        assert compaction.RetentionReason is not failed_branches.RetentionReason

    def test_which_one_the_package_currently_gives(self):
        """Pinned, so a change of winner is a deliberate edit."""
        import release_gate.assurance as package
        from release_gate.assurance import expectation, failed_branches
        assert package.EvidenceExpectation is expectation.EvidenceExpectation
        assert package.RetentionReason is failed_branches.RetentionReason

    def test_the_threat_dataclass_no_longer_shadows_the_trust_enum(self):
        import release_gate.assurance as package
        from release_gate.assurance import trust
        assert package.Threat is trust.Threat
        assert package.Attack.__module__.endswith("hostile")
