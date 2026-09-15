"""AssuranceMethodology — the yardstick a class of decision is argued against.

The properties under test are the ones that distinguish a methodology from a
config file: it evaluates itself, it is honest when it cannot see enough of the
case, and it cannot change underneath a case that was already argued against it.
"""

import json

import pytest

from release_gate.assurance.case import AssuranceCaseBuilder, CaseType, MethodologyRef
from release_gate.assurance.methodologies import (
    BUILTIN_METHODOLOGIES,
    GENERAL_AGENT_ACTION_V1,
    PRODUCTION_DATABASE_CHANGE_V1,
    RESEARCH_MATHEMATICS_V1,
    SOFTWARE_CHANGE_V1,
    default_registry,
)
from release_gate.assurance.methodology import (
    ALL_CASE_TYPES,
    AssessmentStatus,
    AssuranceMethodology,
    CollectionSupplied,
    CoverageDimensionDeclared,
    CoverageExpectation,
    Criticality,
    CriticalityRule,
    EvidenceExpectation,
    IndependenceRequirement,
    IndependenceThreshold,
    MethodologyDriftError,
    MethodologyError,
    MethodologyRegistry,
    MinimumRecords,
    NoUnresolved,
    OverrideRule,
    Requirement,
    RequirementEffect,
    RequirementOutcome,
    SubjectIdentified,
    VerificationPresent,
    assess,
    assess_case,
    predicate_from_dict,
)
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.subject import AssuranceSubject, SubjectType


def _subject(**kw):
    return AssuranceSubject.from_text("CREATE INDEX CONCURRENTLY idx ON orders(id);",
                                      SubjectType.DATA_CHANGE,
                                      "apply this migration to prod-eu", **kw)


def _case(case_type=CaseType.DATA_CHANGE, subject=None, **records):
    b = AssuranceCaseBuilder(
        case_type=case_type, objective="add an index without downtime",
        requested_decision="authorise applying this migration to prod-eu",
        subject=subject or _subject())
    for kind, items in records.items():
        for i, payload in enumerate(items):
            b.add(kind, SimpleRecord(kind, f"{kind}_{i}", payload))
    return b.build()


def _rq(requirement_id="r.1", predicate=None, **kw):
    return Requirement(requirement_id=requirement_id, description="a requirement",
                       predicate=predicate or CollectionSupplied(collection="evidence"), **kw)


def _methodology(**kw):
    kw.setdefault("methodology_id", "test")
    kw.setdefault("version", "1.0.0")
    kw.setdefault("domain", "test")
    kw.setdefault("case_types", ALL_CASE_TYPES)
    return AssuranceMethodology(**kw)


# ── versioning and content addressing ───────────────────────────────────────

def test_a_methodology_must_be_versioned_in_an_orderable_way():
    with pytest.raises(MethodologyError, match="MAJOR.MINOR.PATCH"):
        _methodology(version="v1")


def test_identical_content_yields_an_identical_digest():
    assert _methodology().digest == _methodology().digest


def test_changing_any_content_changes_the_digest():
    base = _methodology()
    assert _methodology(requirements=(_rq(),)).digest != base.digest
    assert _methodology(domain="other").digest != base.digest
    assert _methodology(metadata={"note": "x"}).digest != base.digest


def test_a_methodology_edited_in_place_is_refused_by_the_registry():
    # The whole point of the abstraction: an existing case must never be
    # re-graded by a yardstick that moved underneath it.
    registry = MethodologyRegistry()
    registry.register(_methodology())
    with pytest.raises(MethodologyDriftError, match="already registered with different content"):
        registry.register(_methodology(requirements=(_rq(),)))


def test_re_registering_identical_content_is_a_no_op():
    registry = MethodologyRegistry()
    first = registry.register(_methodology())
    assert registry.register(_methodology()) is first


def test_a_case_reference_that_no_longer_matches_is_caught():
    registry = default_registry()
    stale = MethodologyRef("general-agent-action", "1.0.0", digest="sha256:" + "0" * 64)
    with pytest.raises(MethodologyDriftError, match="changed content without changing its version"):
        registry.resolve(stale)


def test_resolving_without_a_version_is_refused():
    # Resolving "the latest" implicitly is how a case silently acquires a new bar.
    registry = default_registry()
    with pytest.raises(MethodologyError, match="names no version"):
        registry.resolve("general-agent-action")


def test_latest_is_available_but_must_be_asked_for_by_name():
    registry = default_registry()
    registry.register(_methodology(methodology_id="general-agent-action", version="1.2.0"))
    assert registry.latest("general-agent-action").version == "1.2.0"
    assert registry.versions("general-agent-action") == ("1.0.0", "1.2.0")


def test_a_release_outranks_its_own_prereleases():
    registry = MethodologyRegistry()
    registry.register(_methodology(version="2.0.0-rc1"))
    registry.register(_methodology(version="2.0.0", domain="released"))
    assert registry.latest("test").version == "2.0.0"


def test_the_methodology_digest_travels_inside_the_case_digest():
    subject = _subject()

    def case_with(methodology):
        b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                                 requested_decision="d", subject=subject,
                                 methodology=methodology.ref())
        return b.build()

    edited = _methodology(methodology_id="m", version="1.0.0")
    tampered = _methodology(methodology_id="m", version="1.0.0", requirements=(_rq(),))
    assert case_with(edited).case_digest != case_with(tampered).case_digest


# ── inspectability ──────────────────────────────────────────────────────────

def test_every_requirement_explains_itself():
    explained = SOFTWARE_CHANGE_V1.explain()
    assert explained["methodology"] == "software-change@1.0.0"
    for row in explained["requirements"]:
        assert row["expects"] and row["description"] and row["effect"]
        assert isinstance(row["overridable"], bool)


def test_a_requirement_must_describe_itself():
    with pytest.raises(MethodologyError, match="describe itself"):
        Requirement(requirement_id="r", description="  ", predicate=SubjectIdentified())


def test_a_methodology_round_trips_through_plain_json():
    # API-native: no file format is privileged and nothing here parses YAML.
    for methodology in BUILTIN_METHODOLOGIES:
        back = AssuranceMethodology.from_dict(json.loads(json.dumps(methodology.to_dict())))
        assert back.digest == methodology.digest
        assert len(back.all_requirements()) == len(methodology.all_requirements())


def test_a_tampered_definition_document_is_rejected():
    doc = SOFTWARE_CHANGE_V1.to_dict()
    doc["non_overridable_conditions"] = []
    with pytest.raises(MethodologyDriftError, match="modified after it was written"):
        AssuranceMethodology.from_dict(doc)


def test_every_predicate_round_trips():
    for predicate in (CollectionSupplied(collection="claims"),
                      MinimumRecords(collection="evidence", minimum=3),
                      SubjectIdentified(require_mutation_detectable=True),
                      VerificationPresent(methods=("TEST_SUITE",), minimum=2),
                      IndependenceThreshold(minimum_groups=3),
                      NoUnresolved(collection="counterexamples"),
                      CoverageDimensionDeclared(dimension="overall")):
        assert predicate_from_dict(predicate.to_dict()) == predicate


def test_an_unknown_predicate_kind_is_refused_not_ignored():
    with pytest.raises(MethodologyError, match="unknown predicate kind"):
        predicate_from_dict({"kind": "believe_the_agent"})


# ── honesty under partial data (Invariant 3) ────────────────────────────────

def test_a_requirement_that_cannot_be_evaluated_is_not_satisfied():
    # NOT_ASSESSED is explicitly not met. This is the single most important
    # property in the module.
    case = _case()
    result = Requirement(requirement_id="r", description="d",
                         predicate=NoUnresolved(collection="contradictions")).evaluate(case)
    assert result.outcome is RequirementOutcome.NOT_ASSESSED
    assert result.is_met is False


def test_absence_of_recorded_contradictions_is_not_absence_of_contradictions():
    never_supplied = _case()
    assert (_rq(predicate=NoUnresolved(collection="contradictions"))
            .evaluate(never_supplied).outcome is RequirementOutcome.NOT_ASSESSED)

    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=_subject())
    b.declare_present("contradictions", "adversarial review ran; none found")
    looked = b.build()
    assert (_rq(predicate=NoUnresolved(collection="contradictions"))
            .evaluate(looked).outcome is RequirementOutcome.SATISFIED)


def test_a_negative_answer_that_unheld_records_could_overturn_is_not_assessed():
    b = AssuranceCaseBuilder(case_type=CaseType.RESEARCH_RESULT, objective="o",
                             requested_decision="d", subject=_subject())
    for i in range(50):
        b.add("verification", SimpleRecord("verification", f"v_{i}",
                                           {"verification_method": "HUMAN_REVIEW"}),
              materialise=(i < 2))
    case = b.build()
    result = _rq(predicate=VerificationPresent(methods=("FORMAL_PROOF",), minimum=1)).evaluate(case)
    # No proof among the two records held — but 48 were never looked at.
    assert result.outcome is RequirementOutcome.NOT_ASSESSED
    assert result.is_met is False


def test_a_positive_answer_stands_even_when_records_were_withheld():
    # More records can satisfy an at-least check but cannot un-satisfy it.
    b = AssuranceCaseBuilder(case_type=CaseType.RESEARCH_RESULT, objective="o",
                             requested_decision="d", subject=_subject())
    b.add("verification", SimpleRecord("verification", "v_0",
                                       {"verification_method": "FORMAL_PROOF"}))
    for i in range(1, 500):
        b.add("verification", SimpleRecord("verification", f"v_{i}",
                                           {"verification_method": "HUMAN_REVIEW"}),
              materialise=False)
    result = _rq(predicate=VerificationPresent(methods=("FORMAL_PROOF",))).evaluate(b.build())
    assert result.outcome is RequirementOutcome.SATISFIED


def test_a_violation_found_is_definitive_even_when_records_were_withheld():
    b = AssuranceCaseBuilder(case_type=CaseType.RESEARCH_RESULT, objective="o",
                             requested_decision="d", subject=_subject())
    b.add("counterexamples", SimpleRecord("counterexamples", "cx_0", {"resolved": False}))
    for i in range(1, 100):
        b.add("counterexamples", SimpleRecord("counterexamples", f"cx_{i}", {"resolved": True}),
              materialise=False)
    result = _rq(predicate=NoUnresolved(collection="counterexamples")).evaluate(b.build())
    assert result.outcome is RequirementOutcome.UNSATISFIED


def test_an_untyped_verification_is_not_credited(): 
    # Invariant 8: "verified" without a method is not a verification.
    case = _case(verification=[{"summary": "we checked it", "verified": True}])
    result = _rq(predicate=VerificationPresent(methods=("TEST_SUITE",))).evaluate(case)
    assert result.outcome is RequirementOutcome.NOT_ASSESSED
    assert "without naming a method" in result.detail


def test_agreement_without_established_independence_is_not_corroboration():
    # Invariant 6: ten thousand agreeing records with no attribution prove nothing
    # about independence, and must not be assumed independent OR identical.
    case = _case(verification=[{"verification_method": "HUMAN_REVIEW"} for _ in range(10)])
    result = _rq(predicate=IndependenceThreshold(minimum_groups=2)).evaluate(case)
    assert result.outcome is RequirementOutcome.NOT_ASSESSED
    assert result.observed["ungrouped_records"] == 10


def test_records_from_one_group_do_not_meet_an_independence_threshold():
    case = _case(verification=[{"verification_method": "HUMAN_REVIEW",
                                "independence_group": "g1"} for _ in range(10)])
    result = _rq(predicate=IndependenceThreshold(minimum_groups=2)).evaluate(case)
    assert result.outcome is RequirementOutcome.UNSATISFIED
    assert result.observed["independent_groups"] == 1


def test_independent_groups_satisfy_the_threshold():
    case = _case(verification=[{"verification_method": "FORMAL_PROOF", "independence_group": g}
                               for g in ("g1", "g2")])
    assert (_rq(predicate=IndependenceThreshold(minimum_groups=2))
            .evaluate(case).outcome is RequirementOutcome.SATISFIED)


# ── assessment ──────────────────────────────────────────────────────────────

def test_no_methodology_means_methodology_required_not_a_pass():
    assessment = assess(_case(), None)
    assert assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED
    assert assessment.all_met is False
    assert "sufficiency" in assessment.detail


def test_a_methodology_built_for_another_case_type_declines_to_rule():
    assessment = assess(_case(case_type=CaseType.FINANCIAL_ACTION), RESEARCH_MATHEMATICS_V1)
    assert assessment.status is AssessmentStatus.CASE_TYPE_NOT_COVERED
    assert assessment.all_met is False
    assert assessment.results == ()


def test_a_bare_case_does_not_satisfy_even_the_most_permissive_methodology():
    assessment = assess(_case(), GENERAL_AGENT_ACTION_V1)
    assert assessment.status is AssessmentStatus.ASSESSED
    assert assessment.all_met is False
    unmet = {r.requirement_id for r in assessment.unmet()}
    assert "coverage.overall" in unmet
    assert "contradictions.resolved" in unmet


def test_every_shipped_methodology_needs_coverage_before_it_is_content():
    # Invariant 9 holds in every domain.
    for methodology in BUILTIN_METHODOLOGIES:
        case_type = methodology.case_types[0]
        assessment = assess(_case(case_type=case_type), methodology)
        assert assessment.all_met is False
        assert any(r.requirement_id.startswith("coverage.") for r in assessment.unmet())


def test_an_assessment_says_what_would_resolve_each_gap():
    assessment = assess(_case(), PRODUCTION_DATABASE_CHANGE_V1)
    needed = assessment.required_evidence
    assert needed
    for row in needed:
        assert row["needed"] and row["because"]
    ids = {row["requirement_id"] for row in needed}
    assert "verification.rehearsal" in ids


def test_a_complete_case_satisfies_its_methodology(tmp_path):
    path = tmp_path / "migration.sql"
    path.write_text("CREATE INDEX CONCURRENTLY idx ON orders(id);", encoding="utf-8")
    subject = AssuranceSubject.from_file(path, SubjectType.DATA_CHANGE,
                                         "apply this migration to prod-eu")
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=subject,
                             methodology=PRODUCTION_DATABASE_CHANGE_V1.ref())
    b.declare_present("contradictions", "adversarial review ran; none found")
    b.add("verification", SimpleRecord("verification", "v_1",
                                       {"verification_method": "SIMULATION"}))
    b.add("coverage", SimpleRecord("coverage", "c_1", {"dimension": "overall"}))
    b.add("coverage", SimpleRecord("coverage", "c_2",
                                   {"dimension": "production data distribution"}))
    assessment = assess(b.build(), PRODUCTION_DATABASE_CHANGE_V1)
    assert assessment.all_met is True, [r.to_dict() for r in assessment.unmet()]


def test_an_unhashable_subject_blocks_a_database_change():
    subject = AssuranceSubject.from_external(
        "s3://migrations/latest.sql", SubjectType.DATA_CHANGE, "apply to prod-eu")
    assessment = assess(_case(subject=subject), PRODUCTION_DATABASE_CHANGE_V1)
    blocking = {r.requirement_id for r in assessment.unmet(RequirementEffect.BLOCK)}
    assert "subject.identified.recheckable" in blocking


def test_assessment_serialises_for_an_api_client():
    payload = assess(_case(), GENERAL_AGENT_ACTION_V1).to_dict()
    assert json.loads(json.dumps(payload))["status"] == "ASSESSED"
    assert payload["summary"]["SATISFIED"] + payload["summary"]["UNSATISFIED"] >= 1


# ── criticality ─────────────────────────────────────────────────────────────

def test_unmatched_criticality_stays_unknown():
    # Invariant 3: no comfortable middle default.
    assert PRODUCTION_DATABASE_CHANGE_V1.criticality_for("artifacts", {"statement_class": "SELECT"}) is None


def test_the_highest_matching_criticality_wins():
    methodology = _methodology(criticality_rules=(
        CriticalityRule("a", "claims", "kind", ("lemma",), Criticality.MEDIUM),
        CriticalityRule("b", "claims", "kind", ("lemma",), Criticality.CRITICAL)))
    assert methodology.criticality_for("claims", {"kind": "lemma"}) is Criticality.CRITICAL


# ── verification typing ─────────────────────────────────────────────────────

def test_a_methodology_says_which_verification_it_credits():
    assert RESEARCH_MATHEMATICS_V1.admits("THEOREM_PROVER") is True
    # Models agreeing about a proof is agreement, not verification.
    assert RESEARCH_MATHEMATICS_V1.admits("CROSS_MODEL_REVIEW") is False


def test_a_methodology_with_no_list_credits_any_typed_method():
    assert GENERAL_AGENT_ACTION_V1.admits("CROSS_MODEL_REVIEW") is True


# ── overrides ───────────────────────────────────────────────────────────────

def test_silence_means_a_requirement_stands():
    decision = GENERAL_AGENT_ACTION_V1.can_override("contradictions.resolved")
    assert decision.permitted is False
    assert "declares no override rule" in decision.reason


def test_a_non_overridable_condition_cannot_be_waived_by_anyone():
    decision = RESEARCH_MATHEMATICS_V1.can_override("verification.machine_checked")
    assert decision.permitted is False
    assert "no waiver by any role" in decision.reason


def test_a_permitted_override_names_its_terms():
    decision = SOFTWARE_CHANGE_V1.can_override("verification.automated")
    assert decision.permitted is True
    assert decision.requires_role == "code owner"
    assert decision.requires_rationale is True


def test_a_methodology_cannot_declare_a_requirement_both_waivable_and_not():
    with pytest.raises(MethodologyError, match="both overridable and non-overridable"):
        _methodology(requirements=(_rq("r.1"),),
                     override_rules=(OverrideRule("r.1", permitted=True),),
                     non_overridable_conditions=("r.1",))


def test_override_rules_must_name_a_real_requirement():
    with pytest.raises(MethodologyError, match="unknown requirement"):
        _methodology(override_rules=(OverrideRule("r.nope", permitted=True),))


# ── extension ───────────────────────────────────────────────────────────────

def test_an_organisation_can_tighten_a_shipped_methodology():
    org = SOFTWARE_CHANGE_V1.extend(
        methodology_id="acme-software-change", version="1.0.0",
        add_requirements=(Requirement(
            requirement_id="acme.human_review",
            description="a named human reviewed the change",
            predicate=VerificationPresent(methods=("HUMAN_REVIEW",)),
            effect=RequirementEffect.BLOCK),),
        add_non_overridable=("acme.human_review",))
    assert org.derived_from == f"software-change@1.0.0#{SOFTWARE_CHANGE_V1.digest}"
    assert org.provenance == "organization"
    parent_ids = {r.requirement_id for r in SOFTWARE_CHANGE_V1.all_requirements()}
    assert parent_ids <= {r.requirement_id for r in org.all_requirements()}


def test_an_extension_may_narrow_what_it_credits():
    strict = SOFTWARE_CHANGE_V1.extend(
        methodology_id="acme-strict", version="1.0.0",
        restrict_verification_types=("TEST_SUITE", "HUMAN_REVIEW"))
    assert strict.admits("STATIC_ANALYSIS") is False
    assert strict.admits("TEST_SUITE") is True


def test_an_extension_may_not_credit_what_its_parent_refused():
    # Otherwise "extends the regulated methodology" is a claim anyone can make
    # while removing the parts they found inconvenient.
    with pytest.raises(MethodologyError, match="cannot ADD verification types"):
        RESEARCH_MATHEMATICS_V1.extend(
            methodology_id="lax-maths", version="1.0.0",
            restrict_verification_types=("CROSS_MODEL_REVIEW",))


def test_an_extension_cannot_drop_an_inherited_non_overridable_condition():
    lax = RESEARCH_MATHEMATICS_V1.extend(
        methodology_id="acme-maths", version="1.0.0",
        add_override_rules=(OverrideRule("verification.machine_checked", permitted=True,
                                         requires_role="anyone"),))
    assert lax.can_override("verification.machine_checked").permitted is False
    assert "verification.machine_checked" in lax.non_overridable_conditions


# ── registry, plugins and provenance ────────────────────────────────────────

def test_the_default_registry_ships_the_builtins():
    registry = default_registry()
    assert set(registry.ids()) == {"general-agent-action", "software-change",
                                   "production-database-change", "research-mathematics",
                                   "research-assurance", "software-agent-assurance",
                                   "general-autonomous-action"}
    for row in registry.list():
        assert row["source"] == "builtin"


def test_each_call_returns_an_independent_registry():
    # A process-wide singleton would let one caller's plugin change another's bar.
    first, second = default_registry(), default_registry()
    first.register(_methodology(methodology_id="only-here"))
    assert "only-here" not in second.ids()


def test_a_plugin_methodology_is_registered_explicitly_and_attributed():
    registry = default_registry()
    registry.load_plugin(_methodology(methodology_id="vendor-x"), name="vendor-x-plugin")
    row = next(r for r in registry.list() if r["methodology"].startswith("vendor-x"))
    assert row["source"] == "plugin:vendor-x-plugin"
    assert row["provenance"] == "plugin"


def test_an_api_client_can_reference_a_methodology_by_id_and_version():
    registry = default_registry()
    resolved = registry.resolve("software-change@1.0.0")
    assert resolved is SOFTWARE_CHANGE_V1
    assert registry.resolve(resolved.ref()) is SOFTWARE_CHANGE_V1


def test_an_unknown_reference_is_an_error_not_a_default():
    with pytest.raises(MethodologyError, match="unknown methodology"):
        default_registry().resolve("made-up@9.9.9")


# ── construction rules ──────────────────────────────────────────────────────

def test_case_types_must_be_explicit():
    with pytest.raises(MethodologyError, match="case_types must be explicit"):
        AssuranceMethodology(methodology_id="m", version="1.0.0", domain="d", case_types=())


def test_duplicate_requirement_ids_are_refused():
    with pytest.raises(MethodologyError, match="duplicate requirement id"):
        _methodology(requirements=(_rq("r.1"), _rq("r.1")))


def test_expectations_compile_into_ordinary_requirements():
    # Sugar, not a second mechanism: one thing to evaluate, cite and override.
    methodology = _methodology(
        minimum_evidence_expectations=(EvidenceExpectation(collection="claims", minimum=2),),
        independence_requirements=(IndependenceRequirement(minimum_groups=3),),
        coverage_expectations=(CoverageExpectation(dimension="overall"),))
    ids = {r.requirement_id for r in methodology.all_requirements()}
    assert ids == {"evidence.claims.minimum", "independence.verification", "coverage.overall"}


def test_an_expectation_naming_an_unknown_collection_is_refused():
    with pytest.raises(MethodologyError, match="unknown collection"):
        EvidenceExpectation(collection="vibes")


def test_a_requirement_can_be_scoped_to_a_case_or_subject_type():
    requirement = _rq(predicate=SubjectIdentified(),
                      applies_to_subject_types=(SubjectType.FINANCIAL_ACTION,))
    assert requirement.evaluate(_case()).outcome is RequirementOutcome.NOT_APPLICABLE
    # NOT_APPLICABLE is met: a requirement that does not apply is not a gap.
    assert requirement.evaluate(_case()).is_met is True


# ── pairing a case with the right yardstick ─────────────────────────────────

def test_a_case_cannot_be_assessed_under_a_yardstick_it_does_not_record():
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=_subject(),
                             methodology=PRODUCTION_DATABASE_CHANGE_V1.ref())
    case = b.build()
    with pytest.raises(MethodologyError, match="not a different yardstick|is argued under"):
        assess(case, GENERAL_AGENT_ACTION_V1)


def test_a_what_if_is_permitted_but_labels_itself():
    b = AssuranceCaseBuilder(case_type=CaseType.DATA_CHANGE, objective="o",
                             requested_decision="d", subject=_subject(),
                             methodology=PRODUCTION_DATABASE_CHANGE_V1.ref())
    assessment = assess(b.build(), GENERAL_AGENT_ACTION_V1, hypothetical=True)
    assert "HYPOTHETICAL" in assessment.detail


def test_assessing_a_case_resolves_its_own_recorded_methodology():
    registry = default_registry()
    b = AssuranceCaseBuilder(case_type=CaseType.CODE_CHANGE, objective="o",
                             requested_decision="d",
                             subject=AssuranceSubject.from_text("x", SubjectType.CODE_CHANGE,
                                                                "merge to main"),
                             methodology=SOFTWARE_CHANGE_V1.ref())
    assessment = assess_case(b.build(), registry)
    assert assessment.methodology_ref == "software-change@1.0.0"
    assert assessment.status is AssessmentStatus.ASSESSED


def test_a_case_with_no_recorded_methodology_reports_methodology_required():
    assessment = assess_case(_case(), default_registry())
    assert assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED
