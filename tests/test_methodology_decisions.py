"""The ten deferred methodology decisions, as decided in PROMPT 80.

Each had been flagged across several prompts as "yours, not mine" — whether a
finding should gate. Deciding them turned out to need a prior question answered
first: **by what mechanism does anything gate?**

Three layers, and only two of them reach a verdict:

* `Finding.effect` is the rule's own view of what it costs. Metadata. It does not
  compose a verdict — `RG-PROV-002` carries `HOLD` and the `missing-provenance`
  corpus case promotes.
* `methodology.requirements` are predicates evaluated against the case. These
  compose the verdict.
* `methodology.accepted_findings` name a rule the methodology has considered and
  decided not to gate on, with a rationale that appears in the report.

So "should X gate" is not a question about the engine. It is a question about
which methodology takes which position — and the answer that mattered is that a
methodology may hold a **third** position nobody chose: silence. Three corpus
cases are detected and promoted because no shipped methodology says anything
about independence, provenance or verifier attribution either way.
"""

from __future__ import annotations

import dataclasses

import pytest

from release_gate.assurance.evidence import TrustStatus, VerificationMethod
from release_gate.assurance.methodology import (
    TRUST_WITHHELD, VerificationPresent, VerifierRequired, _relied_upon)
from release_gate.assurance.verification import (
    VerificationAttempt, VerificationGraph, VerificationStatus,
    VerificationTarget)

DIGEST = "sha256:" + "a" * 64
TARGET = VerificationTarget.claim("C-1")


def _attempt(trust=TrustStatus.NOT_ESTABLISHED, verifier="prover://acme"):
    return VerificationAttempt(
        method=VerificationMethod.THEOREM_PROVER, target=TARGET, verifier=verifier,
        target_digest=DIGEST, status=VerificationStatus.PASSED, trust_status=trust)


def _graph(*attempts):
    return VerificationGraph(attempts, digests={TARGET.key: DIGEST})


# ── decisions 6 and 7: unvetted and withdrawn verifiers ─────────────────────

class TestAWithdrawnVerifierDoesNotVouch:
    """§10ar computed `VerifierStanding.relied_on` and **nothing in the verdict
    path read it**. A prover an organisation had revoked after a soundness bug
    satisfied a verification requirement exactly as a vetted one did.

    Decided: a ruling against a verifier withholds reliance on its results,
    everywhere a result is counted. Not a new rule — a trust decision that
    changes no decision is not a trust decision (Invariant 11).
    """

    @pytest.mark.parametrize("trust", [TrustStatus.REVOKED, TrustStatus.REJECTED])
    def test_a_ruled_against_verifier_does_not_verify(self, trust):
        reading = _graph(_attempt(trust)).assess(TARGET)
        assert reading.verified is False
        assert _attempt(trust).relied_upon is False

    @pytest.mark.parametrize("trust", [
        TrustStatus.ACCEPTED, TrustStatus.PROVISIONAL, TrustStatus.NOT_ESTABLISHED])
    def test_and_every_other_standing_still_does(self, trust):
        """`NOT_ESTABLISHED` is the important one here.

        Nobody having ruled on a verifier is the ordinary case — the vetting
        registry ships empty — so reading silence as rejection would refuse every
        check anyone submits (Invariant 3). Unvetted is not withdrawn.
        """
        assert _graph(_attempt(trust)).assess(TARGET).verified is True

    def test_the_basis_names_the_real_reason(self):
        """It read "invalidated, not run, or unknown", which sends a reviewer
        looking for a broken check when their own organisation withdrew the
        verifier."""
        basis = _graph(_attempt(TrustStatus.REVOKED)).assess(TARGET).basis
        assert "ruled against the verifier" in basis
        assert "prover://acme" in basis

    def test_one_good_check_beside_a_withdrawn_one_still_passes(self):
        """Withholding one result is not discarding the target's verification."""
        reading = _graph(_attempt(TrustStatus.REVOKED),
                         _attempt(TrustStatus.ACCEPTED, "prover://ok")).assess(TARGET)
        assert reading.verified is True

    def test_the_withheld_set_is_explicit_rulings_only(self):
        assert TRUST_WITHHELD == {"REVOKED", "REJECTED"}
        assert "NOT_ESTABLISHED" not in TRUST_WITHHELD

    @pytest.mark.parametrize("trust,relied", [
        ("ACCEPTED", True), ("PROVISIONAL", True), ("NOT_ESTABLISHED", True),
        ("REVOKED", False), ("REJECTED", False)])
    def test_the_requirement_layer_reads_it_too(self, trust, relied):
        assert _relied_upon({"trust_status": trust}) is relied

    def test_a_record_with_no_trust_field_is_relied_on(self):
        """Absence is not a ruling."""
        assert _relied_upon({}) is True


class TestTheRequirementsHonourIt:
    """The layer that actually composes the verdict."""

    @staticmethod
    @pytest.fixture(scope="class")
    def cases():
        from release_gate.assurance.zero_config import assure_normalisation
        from release_gate.demos import frontier_research as fr

        normalisation, _ = fr.build_normalisation(fr.DEFAULT_SCENARIO.scaled(400))
        report = normalisation.verifier_report

        def built(trust):
            attempts = tuple(dataclasses.replace(a, trust_status=trust)
                             for a in report.attempts)
            return assure_normalisation(
                dataclasses.replace(normalisation, verifier_report=dataclasses.replace(
                    report, attempts=attempts)),
                source_name="t", objective="t", requested_decision="t",
                requested_action="t").case

        return {"trusted": built(TrustStatus.ACCEPTED),
                "withdrawn": built(TrustStatus.REVOKED)}

    def test_verification_present_refuses_a_withdrawn_verifier(self, cases):
        present = VerificationPresent(methods=("THEOREM_PROVER",), minimum=1)
        assert present.evaluate(cases["trusted"]).outcome.value == "SATISFIED"
        assert present.evaluate(cases["withdrawn"]).outcome.value == "UNSATISFIED"

    def test_and_says_the_checks_were_not_counted_rather_than_absent(self, cases):
        """A reviewer told "no verification" would go looking for the missing
        check. It ran; it does not vouch."""
        finding = VerificationPresent(
            methods=("THEOREM_PROVER",), minimum=1).evaluate(cases["withdrawn"])
        assert "ruled against the verifier" in finding.detail
        assert finding.observed["withdrawn_verifier_not_credited"] > 0

    def test_verifier_required_refuses_one_that_ran_and_was_withdrawn(self, cases):
        required = VerifierRequired(verifiers=("lean@4.8.0",))
        assert required.evaluate(cases["trusted"]).outcome.value == "SATISFIED"
        result = required.evaluate(cases["withdrawn"])
        assert result.outcome.value == "UNSATISFIED"
        assert "ruled against" in result.detail
        assert result.observed["ran_but_withdrawn"] == ["lean@4.8.0"]


# ── decision 1: false independence ─────────────────────────────────────────

class TestFalseIndependenceIsSomethingAMethodologyCanRequire:
    """Decided: a domain whose standing rests on corroboration must require that
    support not concentrate in one lineage — and `research-mathematics@1.1.0`
    does, beside 1.0.0 rather than instead of it.

    Deciding this needed a measurement, not a reading. 1.0.0 already requires
    independence, scoped to `verification`, and on the frontier scenario that
    requirement reads SATISFIED — "85 record(s) across 8 independent group(s)" —
    while 8,913 of 10,254 evidence producers descend from one upstream
    derivation. Both are true. The checks really do span 8 groups; the evidence
    they check collapses to one lineage. The requirement asks about the wrong
    scope for the danger.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def frontier():
        from release_gate.demos import frontier_research as fr

        return fr.build_normalisation(fr.DEFAULT_SCENARIO.scaled(400))[0]

    def _assess(self, normalisation, methodology):
        from release_gate.assurance.zero_config import assure_normalisation

        outcome = assure_normalisation(
            normalisation, methodology=methodology, source_name="t", objective="t",
            requested_decision="t", requested_action="t")
        return {r.requirement_id: r for r in outcome.assessment.results}

    def test_the_scope_it_already_had_does_not_see_the_echo_chamber(self, frontier):
        from release_gate.assurance.methodologies import RESEARCH_MATHEMATICS_V1

        rows = self._assess(frontier, RESEARCH_MATHEMATICS_V1)
        assert rows["independence.verification"].outcome.value == "SATISFIED"
        assert "independence.evidence.ancestry" not in rows

    def test_and_the_new_scope_does(self, frontier):
        from release_gate.assurance.methodologies import RESEARCH_MATHEMATICS_V1_1

        rows = self._assess(frontier, RESEARCH_MATHEMATICS_V1_1)
        row = rows["independence.evidence.ancestry"]
        assert row.outcome.value == "UNSATISFIED"
        assert "one lineage" in row.detail

    def test_a_root_count_alone_would_not_have_caught_it(self, frontier):
        """The measurement that decided the shape of the requirement.

        `minimum_roots=2` reads SATISFIED on that case: 16 lineages exist, and
        77.3% of contributors sit in one of them. Only `maximum_concentration`
        sees the concentration, which is why the requirement carries it.
        """
        from release_gate.assurance.methodology import AncestryIndependence
        from release_gate.assurance.zero_config import assure_normalisation

        case = assure_normalisation(
            frontier, source_name="t", objective="t", requested_decision="t",
            requested_action="t").case
        roots_only = AncestryIndependence(minimum_roots=2, collection="evidence")
        with_ceiling = AncestryIndependence(
            minimum_roots=2, maximum_concentration=0.5, collection="evidence")
        assert roots_only.evaluate(case).outcome.value == "SATISFIED"
        assert with_ceiling.evaluate(case).outcome.value == "UNSATISFIED"

    def test_1_0_0_still_resolves_to_the_bar_it_always_had(self):
        """A case approved under 1.0.0 must keep resolving to 1.0.0. That is the
        whole reason `resolve` refuses a bare id."""
        from release_gate.assurance.methodologies import default_registry

        registry = default_registry()
        assert registry.resolve("research-mathematics@1.0.0").version == "1.0.0"
        assert len(registry.resolve("research-mathematics@1.0.0").requirements) == 4
        assert registry.resolve("research-mathematics@1.1.0").version == "1.1.0"

    def test_the_two_versions_are_different_yardsticks(self):
        from release_gate.assurance.methodologies import (
            RESEARCH_MATHEMATICS_V1, RESEARCH_MATHEMATICS_V1_1)

        assert RESEARCH_MATHEMATICS_V1.digest != RESEARCH_MATHEMATICS_V1_1.digest


# ── decision 10: what kind of check static analysis is ──────────────────────

class TestStaticAnalysisStaysEmpirical:
    """Decided: `EMPIRICAL`, not `MECHANICAL`.

    The case for MECHANICAL is that a *sound* analyser proving absence of a
    property is proving something. But soundness is a property of one analyser,
    not of the method class, and real analysers are unsound and incomplete: what
    they report is no instance of the patterns they look for, over the code they
    looked at. That is the empirical shape exactly.

    `MECHANICAL` means a fixed property the tool always checks, about the
    artifact — a compiler accepting a program. An organisation running a genuinely
    sound analyser declares its character (§10aw); that is what the declaration
    mechanism is for, and it keeps the claim attached to the party making it.
    """

    def test_static_analysis_is_empirical(self):
        from release_gate.assurance.methods import CHARACTERS, MethodCharacter

        assert CHARACTERS[VerificationMethod.STATIC_ANALYSIS] \
            is MethodCharacter.EMPIRICAL

    def test_it_therefore_does_not_count_as_formal_verification(self):
        from release_gate.assurance.quality import FORMAL_METHODS

        assert VerificationMethod.STATIC_ANALYSIS not in FORMAL_METHODS

    def test_and_an_organisation_can_still_declare_otherwise(self):
        """The escape hatch that makes the decision safe to make: a sound
        analyser's owner says so, visibly, in their own name."""
        from release_gate.assurance.methods import (
            CharacterBasis, MethodCharacter, MethodDeclaration, MethodRegistry,
            character_of)

        registry = MethodRegistry((MethodDeclaration(
            label="STATIC_ANALYSIS", character=MethodCharacter.PROOF_CARRYING,
            declared_by="org://acme/assurance-office",
            detail="our analyser is sound for the properties it reports"),))
        reading = character_of(
            _attempt(verifier="analyser://acme"), registry=registry)
        # The attempt above is a THEOREM_PROVER, so read the label form directly.
        reading = character_of(
            dataclasses.replace(_attempt(), method=VerificationMethod.STATIC_ANALYSIS),
            registry=registry)
        assert reading.character is MethodCharacter.PROOF_CARRYING
        assert reading.basis is CharacterBasis.DECLARED


# ── decision 8: missing domain authority stays three-valued ────────────────

class TestWithholdingIsNotAlwaysSafe:
    """Decided: missing domain authority cannot gate globally, and the
    three-valued field is the decision rather than an unfinished one.

    `WithholdingCost.holding_is_the_safe_default` is `Optional[bool]` on purpose.
    Holding a payment is usually safe; holding a containment action while an
    intrusion continues is not, and neither is holding a clinical recommendation
    indefinitely. A gate that held every act missing an authority claim would
    make release-gate the party taking the consequential decision — which is the
    one thing the product definition says it does not do.
    """

    def test_every_answer_including_the_absence_of_one_is_reachable(self):
        """`True`, `False` and `None` all occur across the five costs, so the
        three-valued answer is load-bearing rather than a type that is always
        one thing in practice."""
        from release_gate.assurance.authority import WithholdingCost

        answers = {c.holding_is_the_safe_default for c in WithholdingCost}
        assert answers == {True, False, None}

    def test_holding_is_unsafe_where_the_harm_continues(self):
        """The case that makes a global gate wrong. Isolating a compromised host
        is an act whose whole point is that not doing it is worse."""
        from release_gate.assurance.authority import WithholdingCost

        assert WithholdingCost.HARM_CONTINUES.holding_is_the_safe_default is False

    def test_and_unknown_supports_neither_direction(self):
        """The commonest value. Defaulting it to `True` is exactly the assumption
        that makes a gate dangerous in an incident."""
        from release_gate.assurance.authority import WithholdingCost

        assert WithholdingCost.UNKNOWN.holding_is_the_safe_default is None
        assert WithholdingCost.DEGRADES.holding_is_the_safe_default is None
