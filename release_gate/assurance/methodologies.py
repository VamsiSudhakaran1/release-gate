"""Methodologies that ship with release-gate.

**This module is data, not behaviour.** Nothing in the engine branches on a
methodology id, and nothing here is privileged over a methodology an organisation
writes or a plugin supplies. Deleting this file would leave the assurance layer
fully functional and every case reporting `METHODOLOGY_REQUIRED` — which is the
correct answer when no yardstick is in force, and the reason these exist: a
sensible default beats a fabricated one, and both beat nothing at all.

Four are shipped:

  general-agent-action-v1        the conservative default for any case
  software-change-v1             admitting an autonomous change to a codebase
  production-database-change-v1  an irreversible change to live data
  research-mathematics-v1        a worked example of a DOMAIN methodology

The last one is included because the frontier case is what the architecture was
designed around, and a methodology that credits a theorem prover but not a
cross-model review is the clearest illustration of why verification is typed
(Invariant 8). It is an example, not a claim to speak for mathematics.

Every one of them is deliberately unable to reach "all met" on a case that
carries no coverage, because a verdict without coverage is invalid whatever the
domain (Invariant 9).
"""

from __future__ import annotations

from release_gate.assurance.case import CaseType
from release_gate.assurance.methodology import (
    ALL_CASE_TYPES,
    AssuranceMethodology,
    CoverageExpectation,
    Criticality,
    CriticalityRule,
    EvidenceExpectation,
    IndependenceRequirement,
    MethodologyRegistry,
    NoUnresolved,
    OverrideRule,
    Requirement,
    RequirementEffect,
    SubjectIdentified,
    VerificationPresent,
)

# Verification method names, from the Invariant 8 taxonomy.
FORMAL_PROOF = "FORMAL_PROOF"
INDEPENDENT_REPLICATION = "INDEPENDENT_REPLICATION"
TEST_SUITE = "TEST_SUITE"
SIMULATION = "SIMULATION"
EXPERIMENT = "EXPERIMENT"
STATIC_ANALYSIS = "STATIC_ANALYSIS"
RUNTIME_ASSERTION = "RUNTIME_ASSERTION"
HUMAN_REVIEW = "HUMAN_REVIEW"
CROSS_MODEL_REVIEW = "CROSS_MODEL_REVIEW"
THEOREM_PROVER = "THEOREM_PROVER"
EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"
DOMAIN_CHECKER = "DOMAIN_CHECKER"
PROPERTY_TEST = "PROPERTY_TEST"
COMPILER = "COMPILER"
TYPE_CHECKER = "TYPE_CHECKER"


_SUBJECT_IDENTIFIED = Requirement(
    requirement_id="subject.identified",
    description="the subject carries a cryptographic digest",
    predicate=SubjectIdentified(),
    effect=RequirementEffect.BLOCK,
    remedy="supply content that can be hashed, or an attested digest from the store holding it",
    rationale=("An approval binds to a digest. Without one, nobody can later establish "
               "what was authorised, which makes the approval unfalsifiable."))

_NO_OPEN_CONTRADICTIONS = Requirement(
    requirement_id="contradictions.resolved",
    description="no unresolved contradictions remain",
    predicate=NoUnresolved(collection="contradictions"),
    effect=RequirementEffect.BLOCK,
    remedy="resolve each open contradiction, or record why it does not bear on the decision",
    rationale=("A contradiction is closed by evidence that answers it, never by a "
               "different branch succeeding (Invariant 7)."))

_NO_OPEN_COUNTEREXAMPLES = Requirement(
    requirement_id="counterexamples.resolved",
    description="no unresolved counterexamples remain",
    predicate=NoUnresolved(collection="counterexamples"),
    effect=RequirementEffect.BLOCK,
    remedy="address each counterexample, or record why it does not apply",
    rationale="A counterexample that nobody answered is the strongest evidence in the case.")

_COVERAGE_STATED = CoverageExpectation(
    dimension="overall",
    expected_source="the producing system's own account of what it did and did not assess",
    rationale="A verdict without coverage is invalid (Invariant 9).",
    effect=RequirementEffect.BLOCK)


GENERAL_AGENT_ACTION_V1 = AssuranceMethodology(
    methodology_id="general-agent-action",
    version="1.0.0",
    domain="general",
    description=("The conservative default. It asks only what any consequential machine "
                 "output should carry: an identified subject, a statement of coverage, and "
                 "no open contradictions. It credits any typed verification, because a "
                 "general methodology has no standing to rule one out."),
    case_types=ALL_CASE_TYPES,
    requirements=(_SUBJECT_IDENTIFIED, _NO_OPEN_CONTRADICTIONS),
    coverage_expectations=(_COVERAGE_STATED,),
    accepted_verification_types=(),   # any typed method; none is excluded
    non_overridable_conditions=("subject.identified",),
    metadata={"note": "Replace with a domain methodology where one exists."})


SOFTWARE_CHANGE_V1 = AssuranceMethodology(
    methodology_id="software-change",
    version="1.0.0",
    domain="software",
    description=("Admitting an autonomous change to a codebase. Static analysis and a test "
                 "suite are both credited; neither is required to be the only evidence."),
    case_types=(CaseType.CODE_CHANGE, CaseType.DEPLOYMENT),
    requirements=(_SUBJECT_IDENTIFIED, _NO_OPEN_CONTRADICTIONS,
                  Requirement(
                      requirement_id="verification.automated",
                      description="at least one automated verification of the change",
                      predicate=VerificationPresent(
                          methods=(TEST_SUITE, STATIC_ANALYSIS, PROPERTY_TEST,
                                   COMPILER, TYPE_CHECKER),
                          minimum=1),
                      effect=RequirementEffect.HOLD,
                      remedy="run the test suite or the static analyser against this exact revision",
                      rationale="A change nothing checked is a change nobody checked.")),
    accepted_verification_types=(TEST_SUITE, STATIC_ANALYSIS, PROPERTY_TEST, COMPILER,
                                 TYPE_CHECKER, HUMAN_REVIEW, RUNTIME_ASSERTION,
                                 INDEPENDENT_REPLICATION),
    coverage_expectations=(_COVERAGE_STATED,
                           CoverageExpectation(
                               dimension="changed code",
                               expected_source="the diff",
                               rationale="What the change touched bounds what was tested.")),
    override_rules=(OverrideRule(
        requirement_id="verification.automated", permitted=True,
        requires_role="code owner", requires_rationale=True,
        notes="Waivable for a change with no executable surface, e.g. documentation."),),
    non_overridable_conditions=("subject.identified", "contradictions.resolved"))


PRODUCTION_DATABASE_CHANGE_V1 = AssuranceMethodology(
    methodology_id="production-database-change",
    version="1.0.0",
    domain="data",
    description=("An irreversible change to live data. The subject must be re-checkable, "
                 "because a migration that changed between approval and application is the "
                 "failure this methodology exists to catch."),
    case_types=(CaseType.DATA_CHANGE, CaseType.INFRASTRUCTURE_CHANGE),
    requirements=(
        Requirement(
            requirement_id="subject.identified.recheckable",
            description="the subject is identified and its content can be re-checked",
            predicate=SubjectIdentified(require_mutation_detectable=True),
            effect=RequirementEffect.BLOCK,
            remedy="reference the migration as a file or inline content rather than a "
                   "remote handle nobody here can re-read",
            rationale="Irreversible action plus undetectable mutation is the worst pairing "
                      "in the model."),
        _NO_OPEN_CONTRADICTIONS,
        Requirement(
            requirement_id="verification.rehearsal",
            description="the change was rehearsed before being proposed",
            predicate=VerificationPresent(methods=(SIMULATION, EXPERIMENT, TEST_SUITE),
                                          minimum=1),
            effect=RequirementEffect.BLOCK,
            remedy="run the change against a representative snapshot and record the result",
            rationale="A migration nobody has ever run is a plan, not a change.")),
    accepted_verification_types=(SIMULATION, EXPERIMENT, TEST_SUITE, HUMAN_REVIEW,
                                 DOMAIN_CHECKER, RUNTIME_ASSERTION),
    coverage_expectations=(
        _COVERAGE_STATED,
        CoverageExpectation(
            dimension="production data distribution",
            expected_source="a profile of the target dataset, where one exists",
            rationale="A rehearsal against unrepresentative data proves less than it appears to.")),
    criticality_rules=(
        CriticalityRule(rule_id="irreversible-statements", collection="artifacts",
                        field_name="statement_class",
                        values=("DROP", "TRUNCATE", "DELETE", "ALTER"),
                        criticality=Criticality.CRITICAL,
                        rationale="Statements with no inverse carry the decision."),),
    non_overridable_conditions=("subject.identified.recheckable", "verification.rehearsal",
                                "contradictions.resolved"))


RESEARCH_MATHEMATICS_V1 = AssuranceMethodology(
    methodology_id="research-mathematics",
    version="1.0.0",
    domain="mathematics",
    description=("A worked example of a domain methodology. It credits machine-checkable "
                 "verification and human review, and deliberately does not credit "
                 "cross-model review: models agreeing about a proof is agreement, not "
                 "verification. Corroboration must span independent groups, because ten "
                 "thousand descendants of one derivation are one source (Invariant 6)."),
    case_types=(CaseType.RESEARCH_RESULT, CaseType.GENERAL_DECISION),
    requirements=(
        _SUBJECT_IDENTIFIED, _NO_OPEN_CONTRADICTIONS, _NO_OPEN_COUNTEREXAMPLES,
        Requirement(
            requirement_id="verification.machine_checked",
            description="the result is machine-checked",
            predicate=VerificationPresent(methods=(FORMAL_PROOF, THEOREM_PROVER), minimum=1),
            effect=RequirementEffect.BLOCK,
            remedy="submit the derivation to a proof assistant and record the checker's output",
            rationale="For a load-bearing mathematical claim, a machine check is the only "
                      "verification that does not reduce to someone's confidence.")),
    accepted_verification_types=(FORMAL_PROOF, THEOREM_PROVER, INDEPENDENT_REPLICATION,
                                 HUMAN_REVIEW, EXTERNAL_REFERENCE, DOMAIN_CHECKER),
    minimum_evidence_expectations=(
        EvidenceExpectation(collection="claims", minimum=1,
                            rationale="Without declared claims there is nothing to verify "
                                      "against, and claim coverage reads NOT_ASSESSED.",
                            effect=RequirementEffect.BLOCK),
        EvidenceExpectation(collection="assumptions", minimum=1,
                            rationale="A derivation with no stated assumptions has usually "
                                      "not had them found yet.")),
    independence_requirements=(
        IndependenceRequirement(scope="verification", minimum_groups=2,
                                rationale="Agreement among verifiers sharing a prompt, a "
                                          "model or an ancestor is one source reported many "
                                          "times.",
                                effect=RequirementEffect.HOLD),),
    coverage_expectations=(
        _COVERAGE_STATED,
        CoverageExpectation(dimension="lemma verification",
                            expected_source="the lemma manifest declared by the orchestrator",
                            rationale="A manifest is what turns 2,996 of 3,114 into a real "
                                      "ratio instead of a fabricated one.")),
    non_overridable_conditions=("verification.machine_checked", "counterexamples.resolved",
                                "contradictions.resolved", "subject.identified"))


BUILTIN_METHODOLOGIES = (
    GENERAL_AGENT_ACTION_V1,
    SOFTWARE_CHANGE_V1,
    PRODUCTION_DATABASE_CHANGE_V1,
    RESEARCH_MATHEMATICS_V1,
)


def default_registry() -> MethodologyRegistry:
    """A registry preloaded with the shipped methodologies.

    A fresh instance per call: a process-wide singleton would let one caller's
    plugin registration change the bar for another's case.
    """
    registry = MethodologyRegistry()
    for methodology in BUILTIN_METHODOLOGIES:
        registry.register(methodology, source="builtin")
    return registry
