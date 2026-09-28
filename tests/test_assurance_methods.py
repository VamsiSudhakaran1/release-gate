"""Method character — the answer to "what if most validation becomes formal".

The red-team question PROMPT 78 asks is whether release-gate survives a world
whose verification methods it has never heard of. It did not. Three things were
wrong and each is under test here:

**A method release-gate did not model could not be recorded.** The enum refused
the value and the ingest caught the refusal with a bare `continue`, so the attempt
vanished with no skip count and no note. Release-gate omitting evidence is the
threat Invariant 13 names.

**An unmodelled method read as a negative finding.** "None is a passing formal
method" is a finding; "nobody established what kind of check that was" is the
absence of one. `FactState`'s own docstring calls conflating them the failure this
system exists to avoid, and the code did it.

**Three lists decided what "formal" meant and nothing made them agree.** They are
all derived from one table now.

And the shape this opens: an organisation declaring its own tool proof-carrying.
That is legal, visibly DECLARED, and refused outright where the declarer is also
the party behind the evidence.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.chaos import _assure, _base
from release_gate.assurance.evidence import VerificationMethod
from release_gate.assurance.methods import (
    CHARACTERS, METHODS_SCHEMA_VERSION, CharacterBasis, CharacterReading,
    MethodCharacter, MethodDeclaration, MethodError, MethodRegistry,
    character_of, proof_carrying,
)
from release_gate.assurance.quality import (
    FORMAL_METHODS, EvidenceFact, FactState, facts_for)
from release_gate.assurance.verification import (
    VerificationAttempt, VerificationError, VerificationStatus, VerificationTarget)

LABEL = "INTERACTIVE_ORACLE_PROOF"


def _attempt(method=VerificationMethod.OTHER, label=LABEL, verifier="iop://checker"):
    return VerificationAttempt(
        method=method, method_label=label if method is VerificationMethod.OTHER else "",
        target=VerificationTarget.claim("C-1"), verifier=verifier,
        status=VerificationStatus.PASSED)


def _document(method=LABEL):
    out = []
    for row in _base():
        row = dict(row)
        if row.get("record_type") == "claim":
            row["verification_attempts"] = [
                {"method": method, "outcome": "PASSED", "verifier": "iop://checker"}]
        out.append(row)
    return out


def _formal_fact(document, registry=None):
    outcome = _assure(document)
    sheet = facts_for("case", case=outcome.case, analysis=outcome.analysis,
                      methods=registry)
    return outcome, next(f for f in sheet.findings
                         if f.fact is EvidenceFact.FORMAL_VERIFIER_PASSED)


# ── one table, and it covers everything ──────────────────────────────────────

class TestTheTable:

    def test_every_modelled_method_has_a_row(self):
        """A method added to the enum with no row would read UNKNOWN silently —
        honest for a method nobody classified, wrong for one release-gate ships."""
        missing = [m.value for m in VerificationMethod if m not in CHARACTERS]
        assert missing == []

    def test_the_formal_set_is_derived_not_listed(self):
        """Three places kept their own copy of this and nothing made them agree."""
        assert set(FORMAL_METHODS) == {
            m for m, c in CHARACTERS.items()
            if c is MethodCharacter.PROOF_CARRYING}

    def test_and_all_three_readers_agree_by_construction(self):
        from release_gate.assurance.failed_branches import _OUTCOME_FOR_METHOD
        from release_gate.assurance.review import _FORMAL_METHODS

        derived = {m.value for m, c in CHARACTERS.items()
                   if c is MethodCharacter.PROOF_CARRYING}
        assert _FORMAL_METHODS == derived
        assert {m.value for m in FORMAL_METHODS} == derived
        proofs = {k for k, v in _OUTCOME_FOR_METHOD.items()
                  if v.value == "PROOF_FAILED"}
        assert proofs == derived

    def test_a_mechanical_check_is_not_a_proof_of_the_claim(self):
        """A compiler accepting a program proves well-formedness by its own rules.

        Merging that into PROOF_CARRYING silently widened "was this formally
        verified" to include a passing type check, which is the conflation that
        makes "verified" stop meaning anything (Invariant 8).
        """
        assert CHARACTERS[VerificationMethod.COMPILER] is MethodCharacter.MECHANICAL
        assert CHARACTERS[VerificationMethod.TYPE_CHECKER] is MethodCharacter.MECHANICAL
        assert VerificationMethod.COMPILER not in FORMAL_METHODS

    def test_the_formal_set_is_exactly_what_it_was_before_the_table(self):
        """Deriving it must not have changed which methods count."""
        assert sorted(m.value for m in FORMAL_METHODS) == [
            "FORMAL_PROOF", "THEOREM_PROVER"]


# ── a method release-gate does not model survives ───────────────────────────

class TestTheUnmodelledMethodIsKept:

    def test_the_attempt_is_not_dropped(self):
        outcome = _assure(_document())
        kept = [a for a in outcome.analysis.verification_graph.attempts
                if a.method_label == LABEL]
        assert kept, "the attempt was swallowed"

    def test_and_the_omission_would_not_have_been_silent(self):
        """It was: no skip count, no note, the attempt simply gone."""
        outcome = _assure(_document())
        assert any("does not model" in n for n in outcome.normalisation.notes)

    def test_the_label_is_part_of_what_the_attempt_is(self):
        """Two attempts differing only in their method's name are two checks.

        Collapsing them would deduplicate a proof-carrying check against an
        empirical one, because both arrive as OTHER.
        """
        a = _attempt(label="iop/v3")
        b = _attempt(label="iop/v4")
        assert a.verification_id != b.verification_id

    def test_it_round_trips(self):
        a = _attempt()
        assert VerificationAttempt.from_dict(a.to_dict()).method_label == LABEL

    def test_a_label_on_a_modelled_method_is_refused(self):
        """A second name for something already named is two names for one thing."""
        with pytest.raises(VerificationError) as exc:
            VerificationAttempt(method=VerificationMethod.THEOREM_PROVER,
                                method_label="lean", verifier="x")
        assert "only valid with method OTHER" in str(exc.value)


# ── unknown is not a negative finding ───────────────────────────────────────

class TestUnknownIsNotNotFormal:

    def test_an_unmodelled_method_reads_not_assessed(self):
        """It read DOES_NOT_HOLD — "none is a passing formal method" — which is a
        finding where the truth is that nobody established what kind of check it
        was (Invariant 3)."""
        _, fact = _formal_fact(_document())
        assert fact.state is FactState.NOT_ASSESSED
        assert "not established" in fact.basis

    def test_while_a_test_suite_still_reads_does_not_hold(self):
        """The distinction must cut both ways: a method release-gate *does* model
        and which is not a proof is a real finding, and must stay one."""
        _, fact = _formal_fact(_document("TEST_SUITE"))
        assert fact.state is FactState.DOES_NOT_HOLD

    def test_and_a_theorem_prover_still_holds(self):
        _, fact = _formal_fact(_document("THEOREM_PROVER"))
        assert fact.state is FactState.HOLDS

    def test_proof_carrying_is_three_valued(self):
        """`None` is the absence of a reading. Every caller that collapsed it to
        `False` reported an unmodelled formal method as no formal verification."""
        assert proof_carrying(_attempt()) is None
        assert proof_carrying(_attempt(VerificationMethod.THEOREM_PROVER)) is True
        assert proof_carrying(_attempt(VerificationMethod.TEST_SUITE)) is False


# ── a declaration is never an observation ───────────────────────────────────

class TestDeclarationsStayDeclared:

    @pytest.fixture
    def registry(self):
        return MethodRegistry((MethodDeclaration(
            label=LABEL, character=MethodCharacter.PROOF_CARRYING,
            declared_by="org://acme/assurance-office",
            not_for_producers=("agent://acme/prover",)),))

    def test_a_declared_character_is_usable(self, registry):
        reading = character_of(_attempt(), registry=registry,
                               producers=("ci://third-party",))
        assert reading.character is MethodCharacter.PROOF_CARRYING
        assert reading.basis is CharacterBasis.DECLARED

    def test_and_says_who_declared_it(self, registry):
        reading = character_of(_attempt(), registry=registry)
        assert reading.declared_by == "org://acme/assurance-office"

    def test_the_fact_says_so_too(self, registry):
        """Laundering a declaration into release-gate's voice is what §10ah
        settled for timestamps and `_PRODUCER_FORBIDDEN` for epistemic status."""
        _, fact = _formal_fact(_document(), registry)
        assert fact.state is FactState.HOLDS
        assert "DECLARED" in fact.basis
        assert "org://acme/assurance-office" in fact.basis

    def test_a_declaration_by_the_producing_party_is_refused(self, registry):
        """Self-certification. The one shape of this feature that would let a
        producer promote its own check (Invariant 1)."""
        reading = character_of(_attempt(), registry=registry,
                               producers=("agent://acme/prover",))
        assert reading.character is MethodCharacter.UNKNOWN
        assert reading.basis is CharacterBasis.NOT_ESTABLISHED
        assert "cannot classify its own check" in reading.refused

    def test_the_check_covers_every_party_the_caller_can_see(self, registry):
        """Not just the verifier: an estate where the declaring office is also the
        case's producer would slip past a check that looked only at one name."""
        reading = character_of(_attempt(verifier="ci://neutral"), registry=registry,
                               producers=("ci://neutral", "agent://acme/prover"))
        assert reading.character is MethodCharacter.UNKNOWN

    def test_a_declaration_with_nobody_behind_it_is_refused(self):
        with pytest.raises(MethodError) as exc:
            MethodDeclaration(label=LABEL,
                              character=MethodCharacter.PROOF_CARRYING,
                              declared_by="")
        assert "who declared it" in str(exc.value)

    def test_declaring_unknown_is_refused(self):
        """UNKNOWN is the state of a method nobody classified. A declaration is a
        classification, so declaring UNKNOWN is either a no-op or an attempt to
        unset a built-in character."""
        with pytest.raises(MethodError):
            MethodDeclaration(label=LABEL, character=MethodCharacter.UNKNOWN,
                              declared_by="org://a")

    def test_two_characters_for_one_method_are_refused(self):
        with pytest.raises(MethodError) as exc:
            MethodRegistry((
                MethodDeclaration(label=LABEL, character=MethodCharacter.PROOF_CARRYING,
                                  declared_by="org://a"),
                MethodDeclaration(label=LABEL.lower(), character=MethodCharacter.EMPIRICAL,
                                  declared_by="org://b")))
        assert "two answers to one question" in str(exc.value)

    def test_the_registry_ships_empty(self):
        """Release-gate has no view on what somebody else's tool is, and shipping
        a guess would be the vendor list §10ar exists not to have."""
        assert MethodRegistry().declarations == ()
        assert character_of(_attempt()).basis is CharacterBasis.NOT_ESTABLISHED

    def test_a_reading_cannot_claim_a_character_nobody_established(self):
        with pytest.raises(MethodError):
            CharacterReading(method="x", character=MethodCharacter.PROOF_CARRYING,
                             basis=CharacterBasis.NOT_ESTABLISHED)

    def test_nor_be_declared_by_nobody(self):
        with pytest.raises(MethodError):
            CharacterReading(method="x", character=MethodCharacter.PROOF_CARRYING,
                             basis=CharacterBasis.DECLARED)

    def test_character_never_claims_to_measure_strength(self):
        """`VerifierStanding` (§10ar) is the orthogonal question of whether this
        verifier may be relied on at all, and merging the two axes is what this
        architecture does not do."""
        assert character_of(_attempt()).proves_nothing_about_strength is True


# ── a methodology can require a method this release never heard of ──────────

class TestAMethodologyCanNameIt:

    def test_the_label_is_what_a_requirement_matches(self):
        """The path that matters most: a requirement drives the verdict.

        A domain whose validation is formal in a way release-gate does not model
        writes `methods=("INTERACTIVE_ORACLE_PROOF",)` and has it met.
        """
        from release_gate.assurance.methodology import _method_of

        assert _method_of({"method": "OTHER", "method_label": LABEL}) == LABEL

    def test_bare_other_does_not_match_a_labelled_method(self):
        """Otherwise a requirement naming OTHER would credit every unmodelled
        method indiscriminately — the opposite failure."""
        from release_gate.assurance.methodology import _method_of

        assert _method_of({"method": "OTHER", "method_label": LABEL}) != "OTHER"

    def test_an_unlabelled_other_still_reads_as_other(self):
        from release_gate.assurance.methodology import _method_of

        assert _method_of({"method": "OTHER"}) == "OTHER"
        assert _method_of({"method": "OTHER", "method_label": ""}) == "OTHER"


# ── the organisation surface ────────────────────────────────────────────────

class TestTheOrganisationConfig:

    def test_declarations_load_from_configuration(self):
        from release_gate.assurance.organisation import OrganisationConfig

        config = OrganisationConfig.from_json(json.dumps({
            "organisation_id": "org://acme",
            "method_declarations": [
                {"label": LABEL, "character": "PROOF_CARRYING",
                 "declared_by": "org://acme/assurance-office"}]}))
        assert config.method_registry.of(LABEL) is not None
        assert not config.is_empty

    def test_a_declaring_organisation_must_identify_itself(self):
        """Same rule as an override waiver, same reason: classifying a method
        changes what a requirement reads as met by."""
        from release_gate.assurance.organisation import (
            OrganisationConfig, OrganisationConfigError)

        with pytest.raises(OrganisationConfigError) as exc:
            OrganisationConfig(method_declarations=(MethodDeclaration(
                label=LABEL, character=MethodCharacter.PROOF_CARRYING,
                declared_by="somebody"),))
        assert "identify itself" in str(exc.value)

    def test_it_round_trips_through_serialisation(self):
        from release_gate.assurance.organisation import OrganisationConfig

        config = OrganisationConfig(
            organisation_id="org://acme",
            method_declarations=(MethodDeclaration(
                label=LABEL, character=MethodCharacter.EMPIRICAL,
                declared_by="org://acme/office"),))
        back = OrganisationConfig.from_dict(json.loads(json.dumps(config.to_dict())))
        assert back.method_declarations == config.method_declarations

    def test_a_declaration_cannot_loosen_anything(self):
        """A method with no declaration reads as of unknown character, which never
        satisfies a requirement. Declarations only ever let a check be recognised,
        never let a missing one pass."""
        _, without = _formal_fact(_document())
        assert without.state is FactState.NOT_ASSESSED
        empty = MethodRegistry()
        _, with_empty = _formal_fact(_document(), empty)
        assert with_empty.state is FactState.NOT_ASSESSED


# ── the harnesses ───────────────────────────────────────────────────────────

class TestTheHarnesses:

    def test_the_threat_is_registered_and_behaves(self):
        from release_gate.assurance.hostile import run_threat

        result = run_threat("method_character_self_declaration")
        assert result.was_possible is True
        assert result.detail["laundered_into_our_voice"] is False
        assert result.detail["formal_fact"] == "NOT_ASSESSED"

    def test_the_fault_is_registered_and_behaves(self):
        from release_gate.assurance.chaos import run_fault

        result = run_fault("unmodelled_verification_method")
        assert result.detail["kept"] > 0
        assert result.detail["noted"] is True
        assert result.detail["formal_fact"] == "NOT_ASSESSED"

    def test_the_schema_is_registered(self):
        from release_gate.assurance.protocol import PROTOCOL

        assert PROTOCOL.schema("methods").version == METHODS_SCHEMA_VERSION
