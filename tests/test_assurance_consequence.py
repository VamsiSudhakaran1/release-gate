"""Consequence — what is at stake, and whether anybody actually said so.

Most of this file is about what the module refuses to do. UNKNOWN is the default,
UNKNOWN never sorts as a middle value, nothing is derived from a guess, and there
is no total.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.capabilities import CapabilitySurface
from release_gate.assurance.consequence import (
    UNKNOWN,
    ConsequenceBasis,
    ConsequenceDescriptor,
    ConsequenceDimension,
    ConsequenceError,
    ConsequenceModel,
    ConsequenceProfile,
    ConsequenceRegistry,
    StructuralConsequenceModel,
    default_consequence_registry,
    descriptors_from_mapping,
    extend_vocabulary,
    rank_of,
    values_for,
)
from release_gate.assurance.methodology import (
    AssuranceMethodology, ConsequenceDeclared, Requirement, RequirementEffect,
    RequirementOutcome, assess,
)
from release_gate.assurance.zero_config import assure, render_text


def span(span_id, name, attrs):
    return {"traceId": "aa", "spanId": span_id, "name": name,
            "attributes": [{"key": k, "value": {"stringValue": str(v)}}
                           for k, v in attrs.items()]}


def otlp(*spans, **top):
    doc = {"resourceSpans": [{"resource": {"attributes": []},
                              "scopeSpans": [{"spans": list(spans)}]}]}
    doc.update(top)
    return doc


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return str(path)


EXTERNAL_TRACE = otlp(
    span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT"}),
    span("02", "m", {"messaging.system": "ses"}))

CONTAINED_TRACE = otlp(
    span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"}))


# ── unknown is the default and a real answer ─────────────────────────────────

class TestUnknownIsFirstClass:

    def test_an_empty_profile_is_valid_and_fully_unknown(self):
        profile = ConsequenceProfile()
        assert profile.fully_unknown
        assert len(profile.unknown) == len(ConsequenceDimension)
        assert profile.known == ()

    def test_every_dimension_is_always_present(self):
        profile = ConsequenceProfile()
        for dimension in ConsequenceDimension:
            assert profile.get(dimension).value == UNKNOWN

    def test_a_caller_never_has_to_distinguish_absent_from_unknown(self):
        profile = ConsequenceProfile(descriptors={
            ConsequenceDimension.REVERSIBILITY: ConsequenceDescriptor(
                dimension=ConsequenceDimension.REVERSIBILITY, value="IRREVERSIBLE",
                basis=ConsequenceBasis.DECLARED, source="person://a")})
        assert profile.value(ConsequenceDimension.LEGAL_IMPACT) == UNKNOWN

    def test_unknown_ranks_none_not_a_midpoint(self):
        """Scoring an unknown as average is the legacy defect in spec 18.1."""
        for dimension in ConsequenceDimension:
            assert rank_of(dimension, UNKNOWN) is None
            assert rank_of(dimension, values_for(dimension)[0]) == 0

    def test_unknown_is_in_every_vocabulary_and_always_last(self):
        for dimension in ConsequenceDimension:
            assert values_for(dimension)[-1] == UNKNOWN

    def test_declaring_unknown_declares_nothing(self):
        descriptors = descriptors_from_mapping(
            {"reversibility": "UNKNOWN"}, source="person://a")
        assert descriptors == []


# ── the value/basis invariant ────────────────────────────────────────────────

class TestDescriptorInvariants:

    def test_a_known_value_must_name_its_basis(self):
        with pytest.raises(ConsequenceError, match="disagree"):
            ConsequenceDescriptor(dimension=ConsequenceDimension.REVERSIBILITY,
                                  value="IRREVERSIBLE",
                                  basis=ConsequenceBasis.UNKNOWN)

    def test_an_unknown_value_cannot_claim_a_basis(self):
        with pytest.raises(ConsequenceError, match="disagree"):
            ConsequenceDescriptor(dimension=ConsequenceDimension.REVERSIBILITY,
                                  value=UNKNOWN, basis=ConsequenceBasis.DECLARED,
                                  source="person://a")

    def test_a_known_value_must_name_a_source(self):
        with pytest.raises(ConsequenceError, match="answerable"):
            ConsequenceDescriptor(dimension=ConsequenceDimension.REVERSIBILITY,
                                  value="IRREVERSIBLE",
                                  basis=ConsequenceBasis.DECLARED)

    def test_free_form_values_are_refused(self):
        with pytest.raises(ConsequenceError, match="admissible"):
            ConsequenceDescriptor(dimension=ConsequenceDimension.FINANCIAL_IMPACT,
                                  value="quite a lot",
                                  basis=ConsequenceBasis.DECLARED, source="x")

    def test_a_value_from_another_dimension_is_refused(self):
        with pytest.raises(ConsequenceError):
            ConsequenceDescriptor(dimension=ConsequenceDimension.FINANCIAL_IMPACT,
                                  value="IRREVERSIBLE",
                                  basis=ConsequenceBasis.DECLARED, source="x")


# ── no invention ─────────────────────────────────────────────────────────────

class TestNothingIsInvented:

    def test_reversibility_is_never_derived(self):
        """The dimension people most want and no telemetry supports."""
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        profile = default_consequence_registry().build(None, capabilities=surface)
        assert profile.value(ConsequenceDimension.REVERSIBILITY) == UNKNOWN

    def test_financial_and_legal_impact_are_never_derived(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        profile = default_consequence_registry().build(None, capabilities=surface)
        assert profile.value(ConsequenceDimension.FINANCIAL_IMPACT) == UNKNOWN
        assert profile.value(ConsequenceDimension.LEGAL_IMPACT) == UNKNOWN

    def test_an_inferred_capability_moves_nothing(self):
        """A tool merely named `db_write` is a guess; a consequence from a guess
        would be a guess wearing a better coat."""
        surface = CapabilitySurface.from_spans(
            otlp(span("01", "t", {"gen_ai.tool.name": "db_write"})))
        assert surface.observed == ()
        profile = default_consequence_registry().build(None, capabilities=surface)
        assert profile.fully_unknown

    def test_no_capabilities_means_no_derivation(self):
        profile = default_consequence_registry().build(None, capabilities=None)
        assert profile.fully_unknown

    def test_there_is_no_score(self):
        profile = default_consequence_registry().build(
            None, capabilities=CapabilitySurface.from_spans(EXTERNAL_TRACE))
        payload = profile.to_dict()
        for banned in ("score", "total", "level", "severity", "weight"):
            assert banned not in json.dumps(payload).lower(), banned

    def test_elevated_returns_dimensions_not_a_count(self):
        descriptors = descriptors_from_mapping(
            {"reversibility": "IRREVERSIBLE", "legal_impact": "REGULATED"},
            source="person://a")
        profile = ConsequenceRegistry(include_structural=False).build(
            None, declared=descriptors)
        elevated = profile.elevated()
        assert {d.dimension for d in elevated} == {
            ConsequenceDimension.REVERSIBILITY, ConsequenceDimension.LEGAL_IMPACT}


# ── structural derivation ────────────────────────────────────────────────────

class TestStructuralModel:

    def test_an_observed_external_capability_settles_externality(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        profile = default_consequence_registry().build(None, capabilities=surface)
        descriptor = profile.get(ConsequenceDimension.EXTERNALITY)
        assert descriptor.value == "CROSSES_SYSTEM_BOUNDARY"
        assert descriptor.basis is ConsequenceBasis.DERIVED

    def test_an_observed_write_settles_data_impact(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        assert default_consequence_registry().build(
            None, capabilities=surface).value(ConsequenceDimension.DATA_IMPACT) \
            == "MODIFIED"

    def test_reads_alone_on_a_bounded_surface_are_read(self):
        surface = CapabilitySurface.from_spans(CONTAINED_TRACE)
        assert surface.bounded
        profile = default_consequence_registry().build(None, capabilities=surface)
        assert profile.value(ConsequenceDimension.DATA_IMPACT) == "READ"
        assert profile.value(ConsequenceDimension.EXTERNALITY) == "CONTAINED"

    def test_an_unbounded_surface_cannot_prove_containment(self):
        """A shell could have reached out without appearing as itself."""
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"}),
            span("02", "s", {"process.command_line": "/bin/bash -c ls"})))
        assert surface.bounded is False
        profile = default_consequence_registry().build(None, capabilities=surface)
        assert profile.value(ConsequenceDimension.EXTERNALITY) == UNKNOWN
        assert profile.value(ConsequenceDimension.DATA_IMPACT) == UNKNOWN

    def test_a_write_is_never_promoted_to_destroyed(self):
        surface = CapabilitySurface.from_spans(otlp(
            span("01", "q", {"db.system": "postgresql",
                             "db.statement": "DELETE FROM accounts"})))
        profile = default_consequence_registry().build(None, capabilities=surface)
        assert profile.value(ConsequenceDimension.DATA_IMPACT) == "MODIFIED"


# ── precedence and conflict ──────────────────────────────────────────────────

class TestPrecedence:

    def test_a_declaration_outranks_a_derivation(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        declared = descriptors_from_mapping({"externality": "CONTAINED"},
                                            source="person://dba")
        profile = default_consequence_registry().build(
            None, capabilities=surface, declared=declared)
        descriptor = profile.get(ConsequenceDimension.EXTERNALITY)
        assert descriptor.value == "CONTAINED"
        assert descriptor.basis is ConsequenceBasis.DECLARED

    def test_the_overruled_derivation_is_recorded_not_dropped(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        declared = descriptors_from_mapping({"externality": "CONTAINED"},
                                            source="person://dba")
        profile = default_consequence_registry().build(
            None, capabilities=surface, declared=declared)
        conflict = next(c for c in profile.conflicts
                        if c.dimension is ConsequenceDimension.EXTERNALITY)
        assert conflict.rejected.value == "CROSSES_SYSTEM_BOUNDARY"
        assert conflict.rejected.basis is ConsequenceBasis.DERIVED

    def test_equal_standing_disagreement_prefers_neither_silently(self):
        first = descriptors_from_mapping({"scope": "BROAD"}, source="person://a")
        second = descriptors_from_mapping({"scope": "SINGLE_SUBJECT"},
                                          source="person://b")
        profile = ConsequenceRegistry(include_structural=False).build(
            None, declared=first + second)
        conflict = next(c for c in profile.conflicts)
        assert "neither is preferred" in conflict.reason

    def test_agreement_is_not_a_conflict(self):
        first = descriptors_from_mapping({"scope": "BROAD"}, source="person://a")
        second = descriptors_from_mapping({"scope": "BROAD"}, source="person://b")
        profile = ConsequenceRegistry(include_structural=False).build(
            None, declared=first + second)
        assert profile.conflicts == ()


# ── domain plugins ───────────────────────────────────────────────────────────

class TestDomainPlugins:

    class PaymentsModel(ConsequenceModel):
        model_id = "payments-v1"

        def describe(self, case, *, capabilities=None):
            return descriptors_from_mapping(
                {"financial_impact": "UNBOUNDED", "reversibility": "IRREVERSIBLE"},
                source="plugin://payments-v1")

    def test_a_plugin_can_supply_what_the_structural_model_cannot(self):
        registry = default_consequence_registry().register(self.PaymentsModel())
        profile = registry.build(None, capabilities=CapabilitySurface.from_spans(
            EXTERNAL_TRACE))
        assert profile.value(ConsequenceDimension.FINANCIAL_IMPACT) == "UNBOUNDED"
        assert profile.value(ConsequenceDimension.REVERSIBILITY) == "IRREVERSIBLE"

    def test_a_plugin_cannot_overwrite_a_human_declaration(self):
        registry = default_consequence_registry().register(self.PaymentsModel())
        declared = descriptors_from_mapping({"reversibility": "REVERSIBLE"},
                                            source="person://dba")
        profile = registry.build(None, declared=declared)
        assert profile.get(ConsequenceDimension.REVERSIBILITY).source == "person://dba"

    def test_a_plugin_still_outranks_structural_derivation(self):
        class Contained(ConsequenceModel):
            model_id = "contained-v1"

            def describe(self, case, *, capabilities=None):
                return descriptors_from_mapping({"externality": "CONTAINED"},
                                                source="plugin://contained-v1")

        registry = default_consequence_registry().register(Contained())
        profile = registry.build(
            None, capabilities=CapabilitySurface.from_spans(EXTERNAL_TRACE))
        assert profile.get(ConsequenceDimension.EXTERNALITY).source \
            == "plugin://contained-v1"

    def test_registering_the_same_id_twice_is_refused(self):
        registry = default_consequence_registry().register(self.PaymentsModel())
        with pytest.raises(ConsequenceError, match="already registered"):
            registry.register(self.PaymentsModel())

    def test_a_non_model_is_refused(self):
        with pytest.raises(ConsequenceError):
            default_consequence_registry().register(object())

    def test_a_registry_is_fresh_per_call(self):
        default_consequence_registry().register(self.PaymentsModel())
        assert all(m.model_id != "payments-v1"
                   for m in default_consequence_registry().models)

    def test_a_vocabulary_extension_appends_without_renumbering(self):
        """Extension is process-wide, so this restores it or later runs drift."""
        import release_gate.assurance.consequence as module

        dimension = ConsequenceDimension.FINANCIAL_IMPACT
        before = module._VOCABULARY[dimension]
        try:
            after = extend_vocabulary(dimension, ["CATASTROPHIC"])
            assert after[:len(before)] == before, "existing ranks must not move"
            assert "CATASTROPHIC" in values_for(dimension)
            assert rank_of(dimension, "NONE") == 0
            descriptor = ConsequenceDescriptor(
                dimension=dimension, value="CATASTROPHIC",
                basis=ConsequenceBasis.DECLARED, source="plugin://x")
            assert descriptor.rank == len(before)
        finally:
            module._VOCABULARY[dimension] = before

    def test_an_extension_is_idempotent(self):
        import release_gate.assurance.consequence as module

        dimension = ConsequenceDimension.SCOPE
        before = module._VOCABULARY[dimension]
        try:
            extend_vocabulary(dimension, ["FLEET_WIDE"])
            extend_vocabulary(dimension, ["FLEET_WIDE"])
            assert module._VOCABULARY[dimension].count("FLEET_WIDE") == 1
        finally:
            module._VOCABULARY[dimension] = before


# ── serialisation ────────────────────────────────────────────────────────────

class TestProfileMechanics:

    def test_the_digest_is_stable(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        a = default_consequence_registry().build(None, capabilities=surface)
        b = default_consequence_registry().build(None, capabilities=surface)
        assert a.digest() == b.digest()

    def test_an_empty_profile_and_a_populated_one_differ(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        assert (default_consequence_registry().build(None, capabilities=surface).digest()
                != ConsequenceProfile().digest())

    def test_it_round_trips(self):
        surface = CapabilitySurface.from_spans(EXTERNAL_TRACE)
        original = default_consequence_registry().build(None, capabilities=surface)
        restored = ConsequenceProfile.from_dict(json.loads(json.dumps(
            original.to_dict())))
        assert restored.digest() == original.digest()

    def test_unrecognised_declarations_are_skipped_not_guessed(self):
        assert descriptors_from_mapping({"vibes": "bad"}, source="x") == []
        assert descriptors_from_mapping(
            {"financial_impact": "enormous"}, source="x") == []

    def test_strict_mode_raises_for_an_api_caller(self):
        with pytest.raises(ConsequenceError):
            descriptors_from_mapping({"vibes": "bad"}, source="x", strict=True)
        with pytest.raises(ConsequenceError):
            descriptors_from_mapping({"financial_impact": "enormous"},
                                     source="x", strict=True)


# ── findings and the pipeline ────────────────────────────────────────────────

class TestConsequenceFindings:

    def _rules(self, path):
        return {f.rule_id: f for f in assure(path).analysis.findings}

    def test_nothing_known_is_advisory_not_a_violation(self, tmp_path):
        path = _write(tmp_path, "m.json", {"hello": "world"})
        finding = self._rules(path)["RG-CONS-001"]
        assert finding.effect is RequirementEffect.ADVISORY
        assert finding.domain is AnalysisDomain.CONSEQUENCE

    def test_a_declaration_contradicted_by_evidence_holds(self, tmp_path):
        path = _write(tmp_path, "c.json", otlp(
            span("01", "m", {"messaging.system": "ses"}),
            consequence={"externality": "CONTAINED"}))
        finding = self._rules(path)["RG-CONS-003"]
        assert finding.effect is RequirementEffect.HOLD

    def test_unstated_reversibility_on_an_external_action_holds(self, tmp_path):
        path = _write(tmp_path, "e.json", otlp(span("01", "m", {"messaging.system": "ses"})))
        finding = self._rules(path)["RG-CONS-005"]
        assert finding.effect is RequirementEffect.HOLD

    def test_declaring_reversibility_clears_that_hold(self, tmp_path):
        path = _write(tmp_path, "e.json", otlp(
            span("01", "m", {"messaging.system": "ses"}),
            consequence={"reversibility": "REVERSIBLE"}))
        assert "RG-CONS-005" not in self._rules(path)

    def test_elevated_stakes_are_surfaced_not_judged(self, tmp_path):
        path = _write(tmp_path, "e.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"}),
            consequence={"reversibility": "IRREVERSIBLE"}))
        finding = self._rules(path)["RG-CONS-004"]
        assert finding.effect is RequirementEffect.ADVISORY

    def test_consequence_never_blocks(self, tmp_path):
        path = _write(tmp_path, "e.json", otlp(
            span("01", "m", {"messaging.system": "ses"}),
            consequence={"externality": "CONTAINED", "legal_impact": "REGULATED"}))
        findings = [f for f in assure(path).analysis.findings
                    if f.domain is AnalysisDomain.CONSEQUENCE]
        assert findings
        assert all(f.effect is not RequirementEffect.BLOCK for f in findings)


class TestZeroConfigIntegration:

    @pytest.fixture
    def declared_file(self, tmp_path):
        return _write(tmp_path, "d.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT"}),
            consequence={"reversibility": "IRREVERSIBLE",
                         "production_impact": "PRODUCTION"}))

    def test_the_outcome_carries_the_profile(self, declared_file):
        profile = assure(declared_file).consequence
        assert profile.value(ConsequenceDimension.REVERSIBILITY) == "IRREVERSIBLE"
        assert profile.value(ConsequenceDimension.DATA_IMPACT) == "MODIFIED"

    def test_the_profile_lands_on_the_case(self, declared_file):
        records = [r.to_dict() for r in assure(declared_file).case.records("evidence")]
        profiles = [r for r in records if r.get("record_type") == "consequence"]
        assert len(profiles) == 1

    def test_a_fully_unknown_profile_is_still_recorded(self, tmp_path):
        """'Nobody stated the stakes' is a fact the case should carry."""
        path = _write(tmp_path, "m.json", {"hello": "world"})
        records = [r.to_dict() for r in assure(path).case.records("evidence")]
        profile = next(r for r in records if r.get("record_type") == "consequence")
        assert profile["fully_unknown"] is True

    def test_consequence_coverage_is_stated(self, declared_file):
        rows = [r.to_dict() for r in assure(declared_file).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "consequence")
        assert row["status"] == "ASSESSED"
        assert row["declared"] == 2

    def test_nothing_stated_is_not_assessed_coverage(self, tmp_path):
        path = _write(tmp_path, "m.json", {"hello": "world"})
        rows = [r.to_dict() for r in assure(path).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "consequence")
        assert row["status"] == "NOT_ASSESSED"

    def test_the_report_shows_stakes_and_what_is_unknown(self, declared_file):
        text = render_text(assure(declared_file))
        assert "WHAT IS AT STAKE" in text
        assert "IRREVERSIBLE" in text
        assert "UNKNOWN:" in text

    def test_the_report_says_plainly_when_nothing_is_stated(self, tmp_path):
        path = _write(tmp_path, "m.json", {"hello": "world"})
        assert "does not guess" in render_text(assure(path))

    def test_the_outcome_serialises(self, declared_file):
        payload = json.loads(json.dumps(assure(declared_file).to_dict()))
        assert payload["consequence"]["known"] >= 2


class TestMethodologyIntegration:
    """How consequence actually reaches the authorization boundary."""

    def _methodology(self, *dimensions):
        from release_gate.assurance.methodology import ALL_CASE_TYPES

        return AssuranceMethodology(
            methodology_id="stakes-required", version="1.0.0", domain="test",
            case_types=ALL_CASE_TYPES,
            description="requires the stakes to be stated",
            requirements=(Requirement(
                requirement_id="consequence.stated",
                description="consequence is stated for the named dimensions",
                predicate=ConsequenceDeclared(dimensions=tuple(dimensions)),
                effect=RequirementEffect.HOLD,
                remedy="declare the named consequence dimensions"),))

    def test_an_undeclared_dimension_is_unsatisfied(self, tmp_path):
        path = _write(tmp_path, "m.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"})))
        outcome = assure(path, methodology=self._methodology("REVERSIBILITY"))
        result = outcome.assessment.results[0]
        assert result.outcome is RequirementOutcome.UNSATISFIED
        assert "REVERSIBILITY" in result.detail

    def test_a_declared_dimension_satisfies_it(self, tmp_path):
        path = _write(tmp_path, "m.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "SELECT"}),
            consequence={"reversibility": "REVERSIBLE"}))
        outcome = assure(path, methodology=self._methodology("REVERSIBILITY"))
        assert outcome.assessment.results[0].outcome is RequirementOutcome.SATISFIED

    def test_a_derived_dimension_counts_as_stated(self, tmp_path):
        path = _write(tmp_path, "m.json", otlp(
            span("01", "q", {"db.system": "postgresql", "db.operation": "INSERT"})))
        outcome = assure(path, methodology=self._methodology("DATA_IMPACT"))
        assert outcome.assessment.results[0].outcome is RequirementOutcome.SATISFIED

    def test_the_predicate_serialises_for_transport(self):
        predicate = ConsequenceDeclared(dimensions=("REVERSIBILITY",))
        payload = predicate.to_dict()
        assert payload["kind"] == "consequence_declared"
        assert json.loads(json.dumps(payload))["dimensions"] == ["REVERSIBILITY"]
