"""The no-YAML default experience: it works with nothing configured.

Two entry points must work out of the box — one file through the CLI, and
records through a session — and optional organisation configuration must only
ever tighten what they do. The tests that matter most are the negative ones:
configuration cannot lower a structural finding, cannot waive a non-overridable
condition, and cannot be necessary.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.case import Decision
from release_gate.assurance.level import AssuranceLevel
from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.methodology import OverrideRule, VerifierRequired
from release_gate.assurance.organisation import (
    OrganisationConfig, OrganisationConfigError)
from release_gate.assurance.session import (
    AssuranceSession, SessionError, records_digest)
from release_gate.assurance.zero_config import assure

RECORDS = [
    {"record_type": "evidence", "evidence_id": "e1", "kind": "OBSERVATION",
     "producer": {"producer_id": "agent://a/1", "kind": "agent"},
     "coverage_note": "sent the reminder"},
    {"record_type": "consequence", "REVERSIBILITY": "REVERSIBLE",
     "SCOPE": "SINGLE_SUBJECT", "FINANCIAL_IMPACT": "NONE", "DATA_IMPACT": "READ",
     "SECURITY_IMPACT": "NONE", "LEGAL_IMPACT": "NONE"},
]


def written(tmp_path, records=RECORDS, name="run.json"):
    path = tmp_path / name
    path.write_text(json.dumps(records, sort_keys=True))
    return path


# ── one file, nothing configured ────────────────────────────────────────────

class TestOneFile:

    def test_a_file_decides_with_no_configuration(self, tmp_path):
        outcome = assure(str(written(tmp_path)), methodology=PROFILE)
        assert outcome.decision in (Decision.PROMOTE, Decision.HOLD, Decision.BLOCK)

    def test_no_methodology_holds_rather_than_failing(self, tmp_path):
        """Absent a yardstick the answer is HOLD with a reason, not an error."""
        outcome = assure(str(written(tmp_path)))
        assert outcome.decision is Decision.HOLD
        assert "RG-ZC-001" in outcome.case.verdict.fired_rules

    def test_nothing_on_disk_is_created(self, tmp_path):
        before = set(tmp_path.iterdir())
        assure(str(written(tmp_path)), methodology=PROFILE)
        assert set(tmp_path.iterdir()) == before | {tmp_path / "run.json"}


# ── post evidence, finalize, decision ───────────────────────────────────────

class TestSession:

    def test_the_whole_flow_needs_no_files(self):
        session = AssuranceSession.open(methodology=PROFILE)
        for record in RECORDS:
            session.add(record)
        outcome = session.finalize()
        assert outcome.decision in (Decision.PROMOTE, Decision.HOLD, Decision.BLOCK)

    def test_required_evidence_is_readable_while_open(self):
        """`GET /required-evidence` on an open case: the steering signal."""
        session = AssuranceSession.open(methodology=PROFILE).extend(RECORDS)
        assert not session.finalized
        assert session.required_evidence() is not None
        assert not session.finalized, "reading must not finalize"

    def test_a_decision_is_refused_before_finalize(self):
        session = AssuranceSession.open(methodology=PROFILE).extend(RECORDS)
        with pytest.raises(SessionError):
            session.decision

    def test_records_are_refused_after_finalize(self):
        """A decision names an exact state; a case that kept accepting evidence
        after being decided would make its own approval unfalsifiable."""
        session = AssuranceSession.open(methodology=PROFILE).extend(RECORDS)
        session.finalize()
        with pytest.raises(SessionError):
            session.add({"record_type": "evidence", "evidence_id": "late"})

    def test_finalize_is_idempotent(self):
        session = AssuranceSession.open(methodology=PROFILE).extend(RECORDS)
        assert session.finalize() is session.finalize()

    def test_typed_records_and_their_json_agree(self):
        """A session fed dicts and one fed the same content must not diverge."""
        a = AssuranceSession.open(methodology=PROFILE).extend(RECORDS).finalize()
        b = AssuranceSession.open(methodology=PROFILE).extend(
            [dict(r) for r in RECORDS]).finalize()
        assert records_digest(a.case) == records_digest(b.case)


class TestLocalParity:
    """A local reproduction must be able to check a decision made elsewhere."""

    def test_the_same_records_decide_the_same_way(self, tmp_path):
        path = written(tmp_path)
        from_file = assure(str(path), methodology=PROFILE)
        from_session = AssuranceSession.open(
            source_name=str(path), methodology=PROFILE).extend(RECORDS).finalize()
        assert from_file.decision is from_session.decision

    def test_the_submitted_records_fold_identically(self, tmp_path):
        path = written(tmp_path)
        from_file = assure(str(path), methodology=PROFILE)
        from_session = AssuranceSession.open(
            source_name=str(path), methodology=PROFILE).extend(RECORDS).finalize()
        assert records_digest(from_file.case) == records_digest(from_session.case)

    def test_case_digests_differ_because_the_inputs_differ(self, tmp_path):
        """Not a defect, and deliberately not papered over.

        Release-gate records the input container as evidence in its own right: a
        file is a FILE reference with a path, records posted over a wire are an
        INLINE reference with none. Forcing the digests equal would mean
        fabricating a file reference for a submission that never touched a disk.
        """
        path = written(tmp_path)
        from_file = assure(str(path), methodology=PROFILE)
        from_session = AssuranceSession.open(
            source_name=str(path), methodology=PROFILE).extend(RECORDS).finalize()
        assert from_file.case.case_digest != from_session.case.case_digest
        assert from_file.case.subject.digest == from_session.case.subject.digest

    def test_a_different_source_is_different_provenance(self):
        a = AssuranceSession.open(source_name="one", methodology=PROFILE
                                  ).extend(RECORDS).finalize()
        b = AssuranceSession.open(source_name="two", methodology=PROFILE
                                  ).extend(RECORDS).finalize()
        assert records_digest(a.case) != records_digest(b.case)


# ── configuration improves assurance; it does not constitute it ─────────────

class TestConfigurationIsOptional:

    def test_an_empty_config_returns_the_very_same_methodology(self):
        """The moment configuration changes an unconfigured run, configuration
        has started constituting the product."""
        assert OrganisationConfig().apply_to(PROFILE) is PROFILE

    def test_an_empty_config_is_empty(self):
        assert OrganisationConfig().is_empty

    def test_config_cannot_invent_a_methodology_from_nothing(self):
        config = OrganisationConfig(organisation_id="acme",
                                    required_verifiers=["semgrep"])
        assert config.apply_to(None) is None

    def test_a_configured_run_and_an_unconfigured_run_agree_without_config(self, tmp_path):
        path = written(tmp_path)
        plain = assure(str(path), methodology=PROFILE)
        through_empty = assure(str(path),
                               methodology=OrganisationConfig().apply_to(PROFILE))
        assert plain.case.case_digest == through_empty.case.case_digest


class TestConfigurationOnlyTightens:

    def test_it_cannot_waive_a_non_overridable_condition(self):
        config = OrganisationConfig(
            organisation_id="acme",
            override_rules=[OverrideRule(requirement_id="subject.identified",
                                         permitted=True, notes="inconvenient")])
        result = config.apply_to(PROFILE)
        assert not [r for r in result.override_rules
                    if r.requirement_id == "subject.identified" and r.permitted]
        assert "subject.identified" in result.non_overridable_conditions

    def test_it_inherits_every_requirement(self):
        config = OrganisationConfig(organisation_id="acme",
                                    required_verifiers=["semgrep"])
        result = config.apply_to(PROFILE)
        inherited = {r.requirement_id for r in PROFILE.requirements}
        assert inherited <= {r.requirement_id for r in result.requirements}

    def test_required_verifiers_add_a_requirement(self):
        result = OrganisationConfig(organisation_id="acme",
                                    required_verifiers=["semgrep"]).apply_to(PROFILE)
        assert len(result.requirements) > len(PROFILE.requirements)

    def test_risk_appetite_only_raises_the_floor(self):
        config = OrganisationConfig(risk_appetite="ORCHESTRATED")
        assert config.level_floor(AssuranceLevel.MINIMAL) is AssuranceLevel.ORCHESTRATED
        assert config.level_floor(AssuranceLevel.FRONTIER) is AssuranceLevel.FRONTIER

    def test_no_appetite_leaves_the_level_alone(self):
        assert (OrganisationConfig().level_floor(AssuranceLevel.MINIMAL)
                is AssuranceLevel.MINIMAL)

    def test_it_cannot_lower_a_structural_block(self, tmp_path):
        """A case whose own evidence refutes it is not made sound by config."""
        refuted = [
            {"record_type": "claim", "claim_id": "c1", "proposition": "it is safe",
             "is_root": True, "producer": {"producer_id": "a://1", "kind": "agent"},
             "contradicting_evidence": ["e9"],
             "verification_attempts": [{"evidence_id": "e9", "method": "TEST_SUITE",
                                        "outcome": "FAILED"}]},
            {"record_type": "evidence", "evidence_id": "e9", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://1", "kind": "tool"},
             "contradicts_claims": ["c1"], "coverage_note": "suite"},
        ]
        path = tmp_path / "refuted.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in refuted))
        permissive = OrganisationConfig(
            organisation_id="acme",
            override_rules=[OverrideRule(requirement_id=rid, permitted=True,
                                         notes="waive everything")
                            for rid in ("subject.identified",
                                        "contradictions.resolved")])
        outcome = assure(str(path), methodology=permissive.apply_to(PROFILE))
        assert outcome.decision is Decision.BLOCK


class TestConfigurationIsJsonOnly:

    def test_yaml_is_refused_with_a_reason(self, tmp_path):
        path = tmp_path / "org.yaml"
        path.write_text("risk_appetite: L3\n")
        with pytest.raises(OrganisationConfigError, match="JSON"):
            OrganisationConfig.from_path(path)

    def test_a_misspelled_key_is_refused_not_ignored(self):
        """A typo in a file whose job is to tighten a gate would silently not."""
        with pytest.raises(OrganisationConfigError, match="unknown"):
            OrganisationConfig.from_dict({"risk_apetite": "L3"})

    def test_it_round_trips_through_json(self):
        config = OrganisationConfig(organisation_id="acme", risk_appetite="CORROBORATED",
                                    required_verifiers=["semgrep"],
                                    approval_roles=["security-lead"])
        assert OrganisationConfig.from_dict(config.to_dict()) == config

    def test_a_permissive_override_must_name_its_organisation(self):
        with pytest.raises(OrganisationConfigError, match="identify itself"):
            OrganisationConfig(override_rules=[
                OverrideRule(requirement_id="x", permitted=True)])

    def test_risk_appetite_accepts_names_and_numbers(self):
        assert OrganisationConfig(risk_appetite="L3").risk_appetite \
            is AssuranceLevel.CORROBORATED
        assert OrganisationConfig(risk_appetite=3).risk_appetite \
            is AssuranceLevel.CORROBORATED

    def test_a_nonsense_appetite_is_refused(self):
        with pytest.raises(OrganisationConfigError):
            OrganisationConfig(risk_appetite="pretty relaxed")


class TestVerifierRequired:

    def test_it_names_what_it_wants(self):
        assert "semgrep" in VerifierRequired(verifiers=["semgrep"]).describe()

    def test_it_refuses_an_empty_list(self):
        from release_gate.assurance.methodology import MethodologyError
        with pytest.raises(MethodologyError):
            VerifierRequired(verifiers=[])

    def test_no_attempts_is_not_assessed_rather_than_failed(self, tmp_path):
        from release_gate.assurance.methodology import RequirementOutcome
        config = OrganisationConfig(organisation_id="acme",
                                    required_verifiers=["semgrep"])
        outcome = assure(str(written(tmp_path)),
                         methodology=config.apply_to(PROFILE))
        result = next(r for r in outcome.assessment.results
                      if r.requirement_id == "org.verifiers")
        assert result.outcome is RequirementOutcome.NOT_ASSESSED
