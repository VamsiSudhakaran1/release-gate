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
    AdversarialReviewRequired,
    AppliesToCurrentState,
    AssumptionsExamined,
    AssuranceMethodology,
    ConsequenceDeclared,
    CoverageDimensionDeclared,
    CoverageExpectation,
    CriticalClaimsIdentified,
    CriticalClaimsVerified,
    Criticality,
    CriticalityRule,
    DeclaredIndependenceHolds,
    EvidenceExpectation,
    ExpectationDeclared,
    IndependenceRequirement,
    MethodologyRegistry,
    NoClaimInStatus,
    NoUnresolved,
    OverrideRule,
    ReplicationEstablished,
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

_COVERAGE_STATED_REQUIREMENT = Requirement(
    requirement_id="RG-SW-008",
    description="coverage is stated",
    predicate=CoverageDimensionDeclared(dimension="overall"),
    effect=RequirementEffect.BLOCK,
    remedy="state what was and was not assessed",
    rationale="A verdict without coverage is invalid whatever the domain (Invariant 9).")

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


RESEARCH_ASSURANCE_V1 = AssuranceMethodology(
    methodology_id="research-assurance",
    version="1.0.0",
    domain="research",
    description=(
        "The advanced research profile: mathematics, computer science, formal proofs, "
        "scientific hypotheses, engineering optimisation and algorithm discovery. Ten "
        "requirements over claim lineage, proof dependencies, assumptions, independent "
        "derivation, formal verification, counterexamples, replication, contradiction "
        "resolution, failed branches and artifact mutation.\n\n"
        "It does not say a result is true. It says the argument has the shape a "
        "research result should have: what it rests on is identified, what it rests on "
        "is checked, what checked it was independent of what it checked, what tried to "
        "break it is recorded, and nothing it rests on has moved since. A profile that "
        "claimed more than that would be a truth oracle, which is the one thing this "
        "system refuses to be (Invariant 10)."),
    case_types=(CaseType.RESEARCH_RESULT, CaseType.GENERAL_DECISION),
    requirements=(
        _SUBJECT_IDENTIFIED,

        # RG-CLAIM-001 CRITICAL_CLAIM_UNVERIFIED
        # Fires when: criticality is determinable, at least one claim is
        # load-bearing, and some load-bearing claim carries no PASSED verification
        # by an accepted method that names a target digest.
        # Does not fire when: the claim is verified by any accepted method; the
        # claim is not load-bearing; no claim is load-bearing.
        # NOT_ASSESSED when: criticality is undeterminable, or the load-bearing
        # set was truncated — an unverified claim and an unexamined one are
        # different facts (Invariant 3).
        Requirement(
            requirement_id="RG-CLAIM-001",
            description="every load-bearing claim is machine-checked",
            predicate=CriticalClaimsVerified(
                methods=(FORMAL_PROOF, THEOREM_PROVER, INDEPENDENT_REPLICATION,
                         PROPERTY_TEST, DOMAIN_CHECKER),
                require_applicable=True),
            effect=RequirementEffect.BLOCK,
            remedy="submit each unverified load-bearing claim to a checker and record "
                   "the output with the digest it ran against",
            rationale=("Cross-model review is deliberately absent from the accepted "
                       "methods: models agreeing about a derivation is agreement, not "
                       "verification (Invariant 8).")),

        # RG-CLAIM-002 LOAD_BEARING_ASSUMPTION_UNVERIFIED
        # Fires when: an assumption a conclusion rests on is stated and nothing in
        # the case bears on it either way.
        # Does not fire when: the assumption has supporting evidence or a
        # verification, or nothing rests on it.
        # NOT_ASSESSED when: no assumption graph could be derived.
        Requirement(
            requirement_id="RG-CLAIM-002",
            description="every load-bearing assumption has been examined",
            predicate=AssumptionsExamined(require_stated=True, require_checked=True),
            effect=RequirementEffect.BLOCK,
            remedy="supply evidence or a verification for each load-bearing "
                   "assumption, or restate the result so it does not rest on it",
            rationale=("A derivation is only as sound as what it takes for granted, "
                       "and the dangerous assumptions are the ones nobody wrote "
                       "down.")),

        # RG-CLAIM-003 FALSE_INDEPENDENCE
        # Fires when: more independence groups are declared than the traced
        # ancestry supports.
        # Does not fire when: declared groups are at most the derived lineage
        # count, or nothing declares a group.
        # NOT_ASSESSED when: ancestry is undeterminable, or no evidence is held.
        Requirement(
            requirement_id="RG-CLAIM-003",
            description="declared independence is borne out by traced lineage",
            predicate=DeclaredIndependenceHolds(tolerance=0),
            effect=RequirementEffect.BLOCK,
            remedy="record parent_evidence so the ancestry can be traced, or withdraw "
                   "the independence groups the lineage does not support",
            rationale=("The one rule a determined producer can defeat with a field. A "
                       "label claiming independence earns nothing against a lineage "
                       "that says otherwise (Invariant 1).")),

        # RG-CLAIM-004 OPEN_COUNTEREXAMPLE
        # Fires when: a counterexample was FOUND and nothing recorded resolves it.
        # Does not fire when: a search came back empty — that bounds the search and
        # never the claim.
        # NOT_ASSESSED when: the counterexamples collection was never supplied.
        Requirement(
            requirement_id="RG-CLAIM-004",
            description="no counterexample stands unanswered",
            predicate=NoUnresolved(collection="counterexamples"),
            effect=RequirementEffect.BLOCK,
            remedy="answer the counterexample and record what answers it, restate the "
                   "claim so it survives, or withdraw the claim",
            rationale=("A counterexample that nobody answered is the strongest "
                       "evidence in the case. Note what this rule does NOT fire on: "
                       "a search that came back empty, which bounds the search and "
                       "never the claim.")),

        # RG-CLAIM-005 FORMAL_VERIFICATION_MISMATCH
        # Fires when: a verification names a target digest and that target's
        # current digest differs — the proof is of a state the artifact has left.
        # Does not fire when: the digests match, or the attempt names no digest
        # (that is UNDETERMINED, reported by RG-VERIF-005, not a mismatch).
        # NOT_ASSESSED when: no verification attempts are recorded.
        Requirement(
            requirement_id="RG-CLAIM-005",
            description="no verification applies to a state its target has left",
            predicate=AppliesToCurrentState(scope="verification"),
            effect=RequirementEffect.BLOCK,
            remedy="re-run the check against the current state and record the new "
                   "target digest",
            rationale=("A proof of yesterday's file is not a proof of today's, and "
                       "the only way to stop that fiction is to make applicability a "
                       "computation (Invariant 5).")),

        # RG-CLAIM-006 CRITICAL_CLAIM_SINGLE_LINEAGE
        # Fires when: a load-bearing claim's support traces to exactly one
        # producer.
        # Does not fire when: two or more producers support it, or the claim is
        # not load-bearing. A claim with NO support is RG-COV-003's business, not
        # this rule's — zero producers is unsupported, not thin.
        # NOT_ASSESSED when: criticality is undeterminable.
        Requirement(
            requirement_id="RG-CLAIM-006",
            description="no load-bearing claim rests on a single producer",
            predicate=CriticalClaimsIdentified(maximum_thin=0),
            effect=RequirementEffect.HOLD,
            remedy="obtain support for each thin load-bearing claim from a producer "
                   "whose lineage is disjoint from the first",
            rationale=("HOLD rather than BLOCK: a single-producer derivation is "
                       "normal early and is a reason to look, not to refuse. A claim "
                       "one party emitted once is exactly as load-bearing as one many "
                       "parties discussed (Invariant 12).")),

        # RG-CLAIM-007 SUPERSEDED_EVIDENCE_USED
        # Fires when: an evidence record names applies_to_digest and no artifact in
        # the case currently carries that digest.
        # Does not fire when: the digest matches a current artifact, or the record
        # names no digest.
        # NOT_ASSESSED when: no artifact carries a digest to compare against.
        Requirement(
            requirement_id="RG-CLAIM-007",
            description="no evidence in use was produced against a superseded state",
            predicate=AppliesToCurrentState(scope="evidence"),
            effect=RequirementEffect.HOLD,
            remedy="re-produce the evidence against the current artifact, or record "
                   "why the earlier state is the one that matters",
            rationale=("Evidence about a previous revision is still evidence — about "
                       "the previous revision. What it is not is support for this "
                       "one.")),

        # RG-CLAIM-008 VERIFICATION_COVERAGE_GAP
        # Fires when: the lemma_verification dimension has no declared expectation,
        # or its expectation came from the party that produced the results, or
        # coverage falls below the stated floor.
        # Does not fire when: an independent source states a total and it is met.
        # NOT_ASSESSED when: no coverage row names the dimension at all.
        Requirement(
            requirement_id="RG-CLAIM-008",
            description="how many lemmas were expected is declared independently",
            predicate=ExpectationDeclared(dimension="lemma_verification",
                                          require_independent=True,
                                          minimum_coverage=1.0),
            effect=RequirementEffect.HOLD,
            remedy="have the orchestrator or lemma manifest declare the expected "
                   "total, rather than the system that produced the proofs",
            rationale=("2,996 verified is not a coverage figure until somebody says "
                       "of how many — and a denominator written by the prover cannot "
                       "detect a lemma it never attempted (Invariant 13).")),

        # RG-CLAIM-009 OPEN_CRITICAL_CONTRADICTION
        # Fires when: a contradiction is OPEN or UNKNOWN.
        # Does not fire when: every contradiction is RESOLVED, SUPERSEDED or
        # INVALID with a stated reason.
        # NOT_ASSESSED when: the contradictions collection was never supplied.
        Requirement(
            requirement_id="RG-CLAIM-009",
            description="no contradiction is left open",
            predicate=NoUnresolved(collection="contradictions"),
            effect=RequirementEffect.BLOCK,
            remedy="resolve each open disagreement and cite the evidence that "
                   "resolved it, or record why it does not bear on the result",
            rationale=("A contradiction is closed by evidence that answers it, never "
                       "by a different branch succeeding. UNKNOWN counts as open: "
                       "'we cannot tell whether this still stands' is not a closed "
                       "disagreement (Invariant 7).")),

        # RG-CLAIM-010 VERIFIED_ARTIFACT_MUTATED
        # Fires when: an artifact records a verified digest and its current digest
        # differs.
        # Does not fire when: they match, or no verified digest was recorded.
        # NOT_ASSESSED when: no artifact carries a digest.
        Requirement(
            requirement_id="RG-CLAIM-010",
            description="no verified artifact has been mutated since",
            predicate=AppliesToCurrentState(scope="artifact"),
            effect=RequirementEffect.BLOCK,
            remedy="re-verify the artifact at its current digest, or restore the "
                   "state that was verified",
            rationale=("An artifact that changed after being verified carries a "
                       "verification of something else (Invariant 5).")),

        # Beyond the ten: the research emphases that are requirements in their own
        # right rather than failure modes.
        Requirement(
            requirement_id="RG-CLAIM-011",
            description="the result is reproduced by an independently implemented path",
            predicate=ReplicationEstablished(minimum_paths=2,
                                             required_axes=("IMPLEMENTATION",)),
            effect=RequirementEffect.HOLD,
            remedy="obtain the result from a second implementation whose lineage is "
                   "disjoint from the first",
            rationale=("Independent derivation is the strongest evidence research can "
                       "carry and the easiest to fake: copies collapse, and a second "
                       "run of the same code is not a second path.")),
        Requirement(
            requirement_id="RG-CLAIM-012",
            description="something independent tried to break the result",
            predicate=AdversarialReviewRequired(minimum_attacks=1,
                                                require_independent=True,
                                                forbid_self_cleared=True),
            effect=RequirementEffect.HOLD,
            remedy="have a falsification agent, proof critic or counterexample search "
                   "attack the result, from a lineage disjoint from its author",
            rationale=("A derivation nobody attacked has not been shown robust; it has "
                       "been shown unchallenged. And a finding closed by the party it "
                       "was against has not been answered.")),
        Requirement(
            requirement_id="RG-CLAIM-013",
            description="what the result rests on is identified",
            predicate=CriticalClaimsIdentified(require_determinable=True,
                                               forbid_broken_chains=True),
            effect=RequirementEffect.BLOCK,
            remedy="mark the conclusion with is_root and record the dependency edges "
                   "connecting it to the lemmas it rests on",
            rationale=("Every other rule here asks about load-bearing claims. Where "
                       "criticality is undeterminable they all answer no, and the "
                       "case passes because nothing was checked.")),
    ),
    accepted_verification_types=(FORMAL_PROOF, THEOREM_PROVER, INDEPENDENT_REPLICATION,
                                 PROPERTY_TEST, DOMAIN_CHECKER, SIMULATION, EXPERIMENT,
                                 TYPE_CHECKER, COMPILER, HUMAN_REVIEW,
                                 EXTERNAL_REFERENCE),
    minimum_evidence_expectations=(
        EvidenceExpectation(collection="claims", minimum=1,
                            rationale="Without declared claims there is nothing to "
                                      "verify against, and claim coverage reads "
                                      "NOT_ASSESSED.",
                            effect=RequirementEffect.BLOCK),
        EvidenceExpectation(collection="assumptions", minimum=1,
                            rationale="A derivation with no stated assumptions has "
                                      "usually not had them found yet."),
        EvidenceExpectation(collection="failed_branches", minimum=1,
                            rationale=("A research record that reports only its "
                                       "successes looks exactly like its best branch. "
                                       "Advisory, because a first attempt that worked "
                                       "is a real thing that happens (Invariant 7)."),
                            effect=RequirementEffect.ADVISORY)),
    independence_requirements=(
        IndependenceRequirement(scope="verification", minimum_groups=2,
                                rationale="Agreement among verifiers sharing a prompt, "
                                          "a model or an ancestor is one source "
                                          "reported many times.",
                                effect=RequirementEffect.HOLD),),
    coverage_expectations=(
        _COVERAGE_STATED,
        CoverageExpectation(dimension="lemma_verification",
                            expected_source="the lemma manifest declared by the "
                                            "orchestrator, not by the prover",
                            rationale="A manifest is what turns 2,996 of 3,114 into a "
                                      "real ratio instead of a fabricated one.")),
    # These cannot be waived. Everything else here can, by a named party with a
    # stated reason — because a profile nobody can override in a real emergency
    # is a profile people route around entirely.
    non_overridable_conditions=("RG-CLAIM-001", "RG-CLAIM-003", "RG-CLAIM-004",
                                "RG-CLAIM-005", "RG-CLAIM-009", "RG-CLAIM-010",
                                "RG-CLAIM-013", "subject.identified"))


SOFTWARE_AGENT_ASSURANCE_V1 = AssuranceMethodology(
    methodology_id="software-agent-assurance",
    version="1.0.0",
    domain="software",
    description=(
        "The advanced software and agent profile. It grades exactly what "
        "release-gate's admission plane already computes — static analysis and "
        "taint, agent tool boundaries, PII and prompt-injection paths, execution "
        "sinks, evals, traces, tests, AIBOM and lock drift, PR diff and runtime "
        "evidence — against the same assurance machinery a research case uses.\n\n"
        "There is one product. An audit report ingests as claims with evidence for "
        "and against them, so a software case gets criticality, contradiction "
        "detection, attention ranking, a packet and an approval binding exactly "
        "like any other case. Nothing here re-implements a check; every rule is a "
        "sufficiency judgement over findings the existing engine already produces."),
    case_types=(CaseType.CODE_CHANGE, CaseType.AUTONOMOUS_ACTION,
                CaseType.DEPLOYMENT, CaseType.GENERAL_DECISION),
    requirements=(
        _SUBJECT_IDENTIFIED,

        # RG-SW-001 UNRESOLVED_CODE_FINDING
        # Fires when: a static, taint, PII, injection or sink finding argues
        # against a load-bearing claim and nothing answers it — the claim comes
        # out REFUTED, or DISPUTED where evidence also argues for it.
        # Does not fire when: the finding was answered, or bears on no
        # load-bearing claim.
        # NOT_ASSESSED when: no claims were supplied, or criticality could not
        # be derived, so there is no load-bearing set to read.
        #
        # Deliberately NOT `NoUnresolved(collection="contradictions")`. A
        # contradiction record is only written where evidence points BOTH ways at
        # one claim; a finding with nothing answering it is unanimous, so no
        # record exists and that predicate reported "all 0 contradictions
        # resolved" on a report carrying a live taint path to a subprocess.
        Requirement(
            requirement_id="RG-SW-001",
            description="no code finding stands unanswered against the change",
            predicate=NoClaimInStatus(statuses=("REFUTED", "DISPUTED"),
                                      scope="critical"),
            effect=RequirementEffect.BLOCK,
            remedy="fix the finding, or record why the sink is unreachable with the "
                   "evidence that establishes it",
            rationale=("A taint path to an execution sink is a counterexample to "
                       "'this change is safe to admit'. Answering it means evidence, "
                       "not a suppression comment.")),

        # RG-SW-002 SAFEGUARD_ABSENT
        # Fires when: a declared safeguard is load-bearing and release-gate looked
        # for it and did not find it.
        # Does not fire when: every safeguard the audit checks is present.
        # NOT_ASSESSED when: criticality is undeterminable.
        Requirement(
            requirement_id="RG-SW-002",
            description="what the change rests on is identified and unbroken",
            predicate=CriticalClaimsIdentified(require_determinable=True,
                                               forbid_broken_chains=True),
            effect=RequirementEffect.BLOCK,
            remedy="declare the safeguards in governance, or record why this change "
                   "does not need them",
            rationale=("A declared safeguard is DECLARED: a governance file saying a "
                       "kill switch exists is the team's account of their own system "
                       "and not a runtime guarantee (Invariant 1).")),

        # RG-SW-003 RUNTIME_EVIDENCE_ABSENT
        # Fires when: no trace, eval or test evidence carries a typed verification.
        # Does not fire when: any accepted runtime method is present.
        # NOT_ASSESSED when: the verification collection was never supplied.
        Requirement(
            requirement_id="RG-SW-003",
            description="the change is exercised, not only read",
            predicate=VerificationPresent(
                methods=(TEST_SUITE, SIMULATION, EXPERIMENT, RUNTIME_ASSERTION,
                         PROPERTY_TEST),
                minimum=1),
            effect=RequirementEffect.HOLD,
            remedy="supply a test run, an eval result or a trace from the change "
                   "actually running",
            rationale=("Static analysis bounds what the code can do; it does not "
                       "establish what it did. Runtime evidence is the other half "
                       "and neither substitutes for the other (Invariant 8).")),

        # RG-SW-004 CAPABILITY_UNDECLARED
        # Fires when: the capability_discovery row is NOT_ASSESSED — no execution
        # evidence to discover from, or a surface that is not an upper bound
        # because something in it (a shell, an eval) can reach capabilities
        # without appearing as them.
        # Does not fire when: the surface was observed AND bounds what ran.
        # NOT_ASSESSED when: never — a missing row is UNSATISFIED, since this
        # methodology holds that an undeclared blast radius is not a small one.
        #
        # `require_assessed` is the whole rule. A bare presence check passes on
        # the NOT_ASSESSED row that zero-config emits for every input, which is
        # exactly the case this is meant to catch.
        Requirement(
            requirement_id="RG-SW-004",
            description="what the agent can reach is declared",
            predicate=CoverageDimensionDeclared(dimension="capability_discovery",
                                                require_assessed=True),
            effect=RequirementEffect.HOLD,
            remedy="supply a tool manifest, or a trace from which the exercised "
                   "capability surface can be derived",
            rationale=("An agent's blast radius is what it can reach, not what it "
                       "reached this time. A manifest bounds the first; a trace only "
                       "ever samples the second.")),

        # RG-SW-005 ARTIFACT_MUTATED_AFTER_VERIFICATION
        # Fires when: an artifact's verified digest differs from its current one —
        # lock drift, a rebuilt image, a re-pushed branch.
        # Does not fire when: they match, or none was recorded.
        # NOT_ASSESSED when: no artifact carries a digest.
        Requirement(
            requirement_id="RG-SW-005",
            description="nothing verified has been rebuilt since",
            predicate=AppliesToCurrentState(scope="artifact"),
            effect=RequirementEffect.BLOCK,
            remedy="re-verify at the current digest, or pin the artifact that was "
                   "verified",
            rationale=("Lock drift and a re-pushed branch are the same failure: the "
                       "thing that was checked is not the thing that will run "
                       "(Invariant 5).")),

        # RG-SW-006 STALE_VERIFICATION
        # Fires when: a check names a target digest the target has left.
        # Does not fire when: digests match, or no digest was named.
        # NOT_ASSESSED when: no verification attempts are recorded.
        Requirement(
            requirement_id="RG-SW-006",
            description="no check applies to a state its target has left",
            predicate=AppliesToCurrentState(scope="verification"),
            effect=RequirementEffect.BLOCK,
            remedy="re-run the check against the current commit and record the digest",
            rationale="A green CI run on a superseded commit is not a green CI run.",),

        # RG-SW-007 EVIDENCE_AGAINST_A_SUPERSEDED_BUILD
        # Fires when: evidence names an applies_to_digest no current artifact has.
        # Does not fire when: it matches, or none was named.
        # NOT_ASSESSED when: no artifact carries a digest.
        Requirement(
            requirement_id="RG-SW-007",
            description="no evidence in use was produced against a superseded build",
            predicate=AppliesToCurrentState(scope="evidence"),
            effect=RequirementEffect.HOLD,
            remedy="re-produce the evidence against the current build, or record why "
                   "the earlier one is the relevant state",
            rationale="Evidence about the previous build is evidence about the "
                      "previous build."),

        # RG-SW-008 COVERAGE_UNSTATED
        # Fires when: the overall coverage dimension is absent.
        # Does not fire when: coverage is stated, whatever it says.
        # NOT_ASSESSED when: the coverage collection was never supplied at all.
        _COVERAGE_STATED_REQUIREMENT,

        # RG-SW-009 SUBMISSION_DENOMINATOR_SELF_REPORTED
        # Fires when: the denominator for what was submitted is the submitting
        # system's own count — which is the default, because a file that states
        # its own total is its own denominator.
        # Does not fire when: an independent source (a CI plan, an orchestration
        # manifest, a verifier inventory) declares the total instead.
        # NOT_ASSESSED when: no coverage row names the dimension.
        #
        # ADVISORY, not HOLD: most software cases genuinely have nobody but the
        # producer to state this, and blocking on it would demand evidence that
        # frequently does not exist. It is stated every time because the gap is
        # real every time, and it closes the moment an independent plan arrives.
        Requirement(
            requirement_id="RG-SW-009",
            description="the count of what was submitted comes from outside the "
                        "submitting system",
            predicate=ExpectationDeclared(dimension="record_mapping",
                                          require_independent=True),
            effect=RequirementEffect.ADVISORY,
            remedy="have CI declare the planned job list, rather than counting the "
                   "jobs that happened to run",
            rationale=("CI reporting '10 of 10 passed' cannot tell you about the job "
                       "that was silently never scheduled (Invariant 13).")),

        # RG-SW-010 CONSEQUENCE_UNSTATED
        # Fires when: no consequence dimension is stated for the action.
        # Does not fire when: at least reversibility is declared.
        # NOT_ASSESSED when: no consequence profile was built.
        Requirement(
            requirement_id="RG-SW-010",
            description="what shipping this would do is stated",
            predicate=ConsequenceDeclared(dimensions=("REVERSIBILITY",)),
            effect=RequirementEffect.HOLD,
            remedy="declare reversibility for this change",
            rationale=("Release-gate does not guess at whether a deployment can be "
                       "rolled back, and an unstated consequence is an unassessed "
                       "one rather than a small one.")),
    ),
    accepted_verification_types=(TEST_SUITE, SIMULATION, EXPERIMENT, PROPERTY_TEST,
                                 RUNTIME_ASSERTION, STATIC_ANALYSIS, TYPE_CHECKER,
                                 COMPILER, DOMAIN_CHECKER, HUMAN_REVIEW,
                                 INDEPENDENT_REPLICATION),
    minimum_evidence_expectations=(
        EvidenceExpectation(collection="claims", minimum=1,
                            rationale=("An audit report ingests as claims; a case "
                                       "with none has not been through the bridge."),
                            effect=RequirementEffect.BLOCK),
        EvidenceExpectation(collection="artifacts", minimum=1,
                            rationale="Without an artifact there is nothing whose "
                                      "mutation could be detected.")),
    coverage_expectations=(
        _COVERAGE_STATED,
        CoverageExpectation(dimension="capability_discovery",
                            expected_source="a tool manifest, or a trace the surface "
                                            "can be derived from",
                            rationale="An agent's reach is the blast radius."),),
    non_overridable_conditions=("RG-SW-001", "RG-SW-005", "RG-SW-006",
                                "subject.identified"))


BUILTIN_METHODOLOGIES = (
    GENERAL_AGENT_ACTION_V1,
    SOFTWARE_CHANGE_V1,
    PRODUCTION_DATABASE_CHANGE_V1,
    RESEARCH_MATHEMATICS_V1,
    RESEARCH_ASSURANCE_V1,
    SOFTWARE_AGENT_ASSURANCE_V1,
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
