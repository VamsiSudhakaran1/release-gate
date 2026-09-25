"""`rg.assurance.v1` — one name for one exact set of schemas.

The guards here are the point of the module. A protocol that describes the code
is documentation; one that *fails* when the code moves without it is a protocol.
Both directions are checked: the manifest cannot claim a version the code does
not hold, and the code cannot hold a version the manifest forgot.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from release_gate.assurance.protocol import (
    CORE_SCHEMAS, PROTOCOL, PROTOCOL_ID, PROTOCOL_MAJOR, PROTOCOL_NAMESPACE,
    AssuranceProtocol, Compatibility, CompatibilityDecision, Consequence,
    ProtocolError, SchemaRef, read_compatibility, speaks,
)

ASSURANCE = Path(__file__).resolve().parent.parent / "release_gate" / "assurance"
CONSTANT = re.compile(
    r"^([A-Z][A-Z0-9_]*_(?:SCHEMA|MODEL|RULESET)_VERSION)\s*=", re.M)


def declared_constants() -> dict:
    """Every version constant the package actually defines."""
    found = {}
    for path in sorted(ASSURANCE.glob("*.py")):
        for name in CONSTANT.findall(path.read_text()):
            found[name] = path.stem
    return found


# ── the namespace ────────────────────────────────────────────────────────────

class TestNamespace:

    def test_the_protocol_is_named(self):
        assert PROTOCOL_ID == "rg.assurance.v1"
        assert PROTOCOL_NAMESPACE == "rg.assurance"
        assert PROTOCOL_MAJOR == 1

    def test_a_schema_is_qualified_by_it(self):
        assert PROTOCOL.schema("evidence").qualified == "rg.assurance.v1/evidence"

    def test_this_build_speaks_it(self):
        assert speaks("rg.assurance.v1")

    def test_a_different_major_is_a_different_protocol(self):
        """Not a later one to be read optimistically. That is what a major
        version is for."""
        assert not speaks("rg.assurance.v2")
        assert not speaks("rg.assurance.v0")
        assert not speaks("")


# ── the manifest pins the code, in both directions ───────────────────────────

class TestNoDrift:

    def test_every_pinned_version_matches_the_module_that_owns_it(self):
        """The manifest cannot claim a version the code does not hold."""
        import importlib
        for ref in PROTOCOL.schemas:
            module = importlib.import_module(
                f"release_gate.assurance.{ref.module}")
            actual = getattr(module, ref.constant)
            assert actual == ref.version, (
                f"{ref.name}: manifest pins {ref.version!r}, "
                f"{ref.module}.{ref.constant} holds {actual!r}")

    def test_every_constant_in_the_package_is_registered(self):
        """And the code cannot hold a version the manifest forgot. A new module
        with a new schema must join the protocol or fail here."""
        registered = {ref.constant for ref in PROTOCOL.schemas}
        declared = set(declared_constants())
        assert declared - registered == set(), (
            "unregistered version constants: " + ", ".join(sorted(declared - registered)))

    def test_the_manifest_is_content_addressed(self):
        """One value that changes when any member changes, which is the
        difference between a protocol and fifty numbers."""
        assert PROTOCOL.digest().startswith("sha256:")
        assert PROTOCOL.digest() == PROTOCOL.digest()

    def test_the_digest_moves_when_a_member_does(self):
        import dataclasses
        moved = dataclasses.replace(
            PROTOCOL,
            schemas=tuple(dataclasses.replace(s, version=99) if s.name == "claim"
                          else s for s in PROTOCOL.schemas))
        assert moved.digest() != PROTOCOL.digest()

    def test_the_count_is_what_was_measured(self):
        assert len(PROTOCOL.schemas) == len(declared_constants()) == 57


# ── the eight a consumer names ───────────────────────────────────────────────

class TestCoreSchemas:

    def test_there_are_eight(self):
        assert len(CORE_SCHEMAS) == 8

    @pytest.mark.parametrize("name", CORE_SCHEMAS)
    def test_each_is_pinned(self, name):
        ref = PROTOCOL.schema(name)
        assert ref.core
        assert ref.version is not None

    def test_a_protocol_missing_a_core_schema_is_refused(self):
        with pytest.raises(ProtocolError) as exc:
            AssuranceProtocol(protocol_id="x",
                              schemas=tuple(s for s in PROTOCOL.schemas
                                            if s.name != "claim"))
        assert "then find unversioned" in str(exc.value)

    def test_a_schema_cannot_be_pinned_twice(self):
        """A schema with two versions in one protocol has no version."""
        with pytest.raises(ProtocolError) as exc:
            AssuranceProtocol(protocol_id="x",
                              schemas=PROTOCOL.schemas + (PROTOCOL.schema("claim"),))
        assert "has no version" in str(exc.value)

    def test_verification_records_that_it_already_moved(self):
        """At 2, and it moved before anything recorded that it had."""
        assert PROTOCOL.schema("verification").version == 2
        assert "before anything recorded" in PROTOCOL.schema("verification").note

    def test_an_unknown_schema_is_refused_by_name(self):
        with pytest.raises(ProtocolError) as exc:
            PROTOCOL.schema("something_nobody_versioned")
        assert "it is one nobody has versioned" in str(exc.value)


# ── not every bump costs the same ────────────────────────────────────────────

class TestConsequence:

    def test_subject_and_case_are_digest_bearing(self):
        names = {s.name for s in PROTOCOL.digest_bearing}
        assert {"subject", "case"} <= names

    def test_a_digest_bearing_bump_really_does_move_the_digest(self):
        """Demonstrated, not asserted: this is the hazard the classification is
        for, and a claim about it should be checked."""
        from release_gate.demos import single_agent
        import release_gate.assurance.case as case_module

        before = single_agent.run().outcome.case.case_digest
        case_module.CASE_MODEL_VERSION = 2
        try:
            after = single_agent.run().outcome.case.case_digest
        finally:
            case_module.CASE_MODEL_VERSION = 1
        assert before != after
        assert single_agent.run().outcome.case.case_digest == before

    def test_the_subject_digest_moves_too(self):
        from release_gate.demos import single_agent
        import release_gate.assurance.subject as subject_module

        def subject_digest():
            case = single_agent.run().outcome.case
            return case.binding_state()["state"]["subject_state"]["state_digest"]

        before = subject_digest()
        subject_module.SUBJECT_MODEL_VERSION = 2
        try:
            assert subject_digest() != before
        finally:
            subject_module.SUBJECT_MODEL_VERSION = 1
        assert subject_digest() == before

    def test_it_is_never_called_backward_compatible(self):
        assert PROTOCOL.bumping_a_digest_bearing_version_is_backward_compatible \
            is False
        assert PROTOCOL.to_dict()[
            "bumping_a_digest_bearing_version_is_backward_compatible"] is False

    def test_a_digest_bearing_schema_must_be_exact(self):
        """A version inside a digest cannot be read loosely."""
        with pytest.raises(ProtocolError) as exc:
            SchemaRef(name="x", module="m", constant="C", version=1,
                      consequence=Consequence.DIGEST_BEARING,
                      compatibility=Compatibility.BACKWARD)
        assert "the binding an approval rests on" in str(exc.value)

    def test_every_digest_bearing_schema_says_why(self):
        for ref in PROTOCOL.digest_bearing:
            assert ref.note, f"{ref.name} carries no note"
            assert ref.compatibility is Compatibility.EXACT

    def test_the_render_warns_about_them(self):
        rendered = PROTOCOL.render()
        assert "DIGEST-BEARING" in rendered
        assert "nothing raises when it happens" in rendered


# ── reading a document that claims a version ─────────────────────────────────

class TestReadCompatibility:

    def test_the_current_version_reads(self):
        found = read_compatibility("evidence", 1)
        assert found.readable and not found.lossy

    def test_a_newer_version_is_refused(self):
        """Forty-five of fifty schemas silently accept any integer today; this
        is what they should be asking."""
        found = read_compatibility("evidence", 99)
        assert not found.readable
        assert "Upgrade release-gate" in found.reason

    def test_an_older_version_reads_where_declared_backward(self):
        found = read_compatibility("verification", 1)
        assert found.readable
        assert found.lossy

    def test_an_older_digest_bearing_version_is_refused(self):
        """Reading it as current would compute a different digest for the same
        content."""
        found = read_compatibility("case", 0)
        assert not found.readable
        assert "would not match the other" in found.reason

    def test_a_non_comparable_version_is_refused(self):
        found = read_compatibility("analysis_ruleset", "rg-structural-2")
        assert not found.readable
        assert "not comparable" in found.reason

    def test_a_ruleset_id_matches_itself(self):
        from release_gate.assurance.analysis import ANALYSIS_RULESET_VERSION
        assert read_compatibility("analysis_ruleset",
                                  ANALYSIS_RULESET_VERSION).readable

    def test_a_decision_never_claims_semantic_agreement(self):
        assert read_compatibility("evidence", 1).to_dict()[
            "a_version_match_is_a_semantic_match"] is False

    def test_the_protocol_says_the_same(self):
        """Two documents at evidence.v1 parse the same way; whether their
        producers meant the same thing is a question about the producers."""
        assert PROTOCOL.a_version_match_is_a_semantic_match is False

    def test_an_unknown_schema_name_is_refused(self):
        with pytest.raises(ProtocolError):
            read_compatibility("not_a_schema", 1)


# ── what the two existing refusals already do ────────────────────────────────

class TestExistingReaders:
    """Evidence and claims were the only two of fifty that refused a newer
    version. The protocol agrees with them rather than replacing them."""

    def test_evidence_refuses_a_newer_record(self):
        from release_gate.assurance.evidence import (
            EvidenceRecord, EvidenceSchemaError, EvidenceType, Producer,
            ProducerKind)
        with pytest.raises(EvidenceSchemaError):
            EvidenceRecord.declared(
                evidence_type=EvidenceType.TOOL_RESULT, source="s",
                producer=Producer("p", ProducerKind.AGENT), schema_version=99)

    def test_and_the_protocol_agrees(self):
        assert not read_compatibility("evidence", 99).readable

    def test_claims_refuses_a_newer_record(self):
        from release_gate.assurance.claims import Claim
        with pytest.raises(Exception) as exc:
            Claim.from_dict({"claim_id": "c", "statement": "s",
                             "producer": {"producer_id": "p", "kind": "agent"},
                             "schema_version": 99})
        assert "newer than this reader" in str(exc.value)
