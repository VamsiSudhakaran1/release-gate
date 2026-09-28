"""What kind of check a verification method is, and who says so.

Invariant 8 says verification is typed: "verified" alone is not an answer. But a
*type* is only useful if something can be said about it, and the question every
methodology actually asks is not the method's name — it is what kind of check
this was. A theorem prover and a test suite are both verification and they
establish different things.

**Three lists used to answer that question and nothing made them agree.**
`quality.FORMAL_METHODS`, the review's own formal set and
`failed_branches._OUTCOME_FOR_METHOD` each hardcoded their own view of which
methods are formal. They are all built from `CHARACTERS` below now, from one
table, so the registry cannot disagree with itself.

**The closed enum was a coupling to today's verification landscape.** A method
release-gate does not model could not be recorded at all: the enum refused the
value and the ingest swallowed the attempt without a skip or a note, which is
release-gate omitting evidence — the threat Invariant 13 names. Such a method now
arrives as `OTHER` carrying the name its producer gave, so what it was survives.

**An unrecognised method is of UNKNOWN character, which is not "not formal".**
This is the whole point. A case checked by a formal method release-gate has never
heard of used to read as *"none is a passing formal method"* — a finding, where
the truth is that nobody established what kind of check it was. `FactState`'s own
docstring calls conflating those two "the failure this whole system exists to
avoid", and the code did it.

**Characters may be declared, and a declaration is never an observation.** An
organisation running a prover release-gate does not model can say what kind of
check it is. That statement is `DECLARED` and stays visibly declared wherever it
is used — laundering it into release-gate's voice would be exactly what §10ah
settled for timestamps and `_PRODUCER_FORBIDDEN` for epistemic status. A
declaration by the same party that produced the evidence is refused outright:
that is self-certification, and it is the one shape of this feature that would
let a producer promote its own check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.evidence import VerificationMethod

__all__ = [
    "METHODS_SCHEMA_VERSION",
    "CHARACTERS",
    "CharacterBasis",
    "CharacterReading",
    "MethodCharacter",
    "MethodDeclaration",
    "MethodError",
    "MethodRegistry",
    "character_of",
    "proof_carrying",
]

METHODS_SCHEMA_VERSION = 1


class MethodError(ValueError):
    """A method character that could not be established honestly."""


class MethodCharacter(str, Enum):
    """What kind of assurance a check produces.

    Not a ranking. `JUDGEMENT` is not a lesser character than `PROOF_CARRYING` —
    a referee reading a derivation catches things no prover does, and a prover
    establishes things no referee can. They answer different questions, and the
    reason to separate them is that a methodology is entitled to require one
    specifically.
    """

    #: Proves the property under check, over a stated model. What it establishes
    #: is bounded by the model and the axioms, never by how many times it ran.
    PROOF_CARRYING = "PROOF_CARRYING"
    #: Proves a fixed property the tool always checks, whatever the claim is. A
    #: compiler accepting a program proves the program is well-formed by that
    #: compiler's rules; it says nothing about the claim the program is evidence
    #: for. Separated from `PROOF_CARRYING` because merging them silently widened
    #: "was this formally verified" to include a passing type check — which is the
    #: conflation that makes "verified" stop meaning anything (Invariant 8).
    MECHANICAL = "MECHANICAL"
    #: Establishes a property by trial: tests, simulation, experiment. Absence of
    #: a failure over the space searched, which is not the same as a proof.
    EMPIRICAL = "EMPIRICAL"
    #: A person or a model read it and formed a view.
    JUDGEMENT = "JUDGEMENT"
    #: Nobody established what kind of check this was. **Never read as "not
    #: formal".** The distinction this value exists to hold is the whole reason
    #: this module exists.
    UNKNOWN = "UNKNOWN"


class CharacterBasis(str, Enum):
    """Who established a method's character."""

    BUILT_IN = "BUILT_IN"        # release-gate models this method
    DECLARED = "DECLARED"        # an organisation stated it
    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # nobody did


# ── the one table ────────────────────────────────────────────────────────────
#
# Every `VerificationMethod` member has a row, and the completeness of this table
# is tested rather than trusted: a method added to the enum with no row here would
# silently read as UNKNOWN, which is honest for a method nobody classified and
# wrong for one release-gate ships.

_C = MethodCharacter
_TABLE: Tuple[Tuple[VerificationMethod, MethodCharacter, str], ...] = (
    (VerificationMethod.FORMAL_PROOF, _C.PROOF_CARRYING,
     "a proof of the stated property, bounded by the axioms it assumes"),
    (VerificationMethod.THEOREM_PROVER, _C.PROOF_CARRYING,
     "machine-checked proof; what it establishes is what was formalised, which "
     "may not be what the author meant"),
    (VerificationMethod.TYPE_CHECKER, _C.MECHANICAL,
     "proves the properties its type system can express, about the artifact and "
     "not about the claim"),
    (VerificationMethod.COMPILER, _C.MECHANICAL,
     "acceptance proves well-formedness by this compiler's rules, not correctness"),
    (VerificationMethod.TEST_SUITE, _C.EMPIRICAL,
     "no failure over the cases written; says nothing about the cases nobody wrote"),
    (VerificationMethod.PROPERTY_TEST, _C.EMPIRICAL,
     "no counterexample over the space sampled"),
    (VerificationMethod.SIMULATION, _C.EMPIRICAL,
     "the modelled system behaved as expected; the model is not the system"),
    (VerificationMethod.EXPERIMENT, _C.EMPIRICAL,
     "an observation under stated conditions"),
    (VerificationMethod.INDEPENDENT_REPLICATION, _C.EMPIRICAL,
     "a second path reached the same result; agreement on a value is not a proof "
     "of it"),
    (VerificationMethod.RUNTIME_ASSERTION, _C.EMPIRICAL,
     "held on the executions that ran"),
    (VerificationMethod.STATIC_ANALYSIS, _C.EMPIRICAL,
     "found no instance of the patterns it looks for; precision and recall are "
     "the tool's, not release-gate's"),
    (VerificationMethod.DOMAIN_CHECKER, _C.EMPIRICAL,
     "a domain tool's own check, of whatever strength that tool has"),
    (VerificationMethod.HUMAN_REVIEW, _C.JUDGEMENT,
     "a person read it and formed a view"),
    (VerificationMethod.CROSS_MODEL_REVIEW, _C.JUDGEMENT,
     "a model read it; agreement among models sharing training or a prompt is "
     "correlation, not independence"),
    (VerificationMethod.EXTERNAL_REFERENCE, _C.UNKNOWN,
     "points at something outside the case; what kind of check happened there is "
     "not established by the reference"),
    (VerificationMethod.OTHER, _C.UNKNOWN,
     "a method release-gate does not model; the label says what the producer "
     "called it, and nothing here establishes what kind of check it was"),
)

#: Built from `_TABLE` in one pass, so the mapping cannot disagree with the rows.
CHARACTERS: Mapping[VerificationMethod, MethodCharacter] = {
    method: character for method, character, _ in _TABLE}

_NOTES: Mapping[VerificationMethod, str] = {
    method: note for method, _, note in _TABLE}


@dataclass(frozen=True)
class MethodDeclaration:
    """An organisation's statement about what kind of check a method is.

    `label` is the method's own name, as a producer spells it — the string that
    travels in `VerificationAttempt.method_label` when the method is `OTHER`.
    Matching is case-insensitive on a stripped label, because the same tool gets
    written four ways across one estate.

    `declared_by` is required and is not decoration: a character with nobody
    behind it is an assertion release-gate would be repeating in its own voice.
    """

    label: str
    character: MethodCharacter
    declared_by: str
    detail: str = ""
    #: Producers whose evidence this declaration may NOT be applied to, because
    #: the declarer is one of them. Populated by the caller from what it knows;
    #: `consult` refuses the match rather than weighing it.
    not_for_producers: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "character", MethodCharacter(self.character))
        label = (self.label or "").strip()
        if not label:
            raise MethodError("a declaration must name the method it is about")
        object.__setattr__(self, "label", label)
        if not (self.declared_by or "").strip():
            raise MethodError(
                f"the character of {label!r} must say who declared it — a "
                "character with nobody behind it is an assertion release-gate "
                "would be repeating as its own")
        object.__setattr__(self, "declared_by", self.declared_by.strip())
        if self.character is MethodCharacter.UNKNOWN:
            # Declaring UNKNOWN is either a no-op or an attempt to unset a
            # built-in character. Neither is something a declaration should do.
            raise MethodError(
                f"{label!r} cannot be declared UNKNOWN: that is the state of a "
                "method nobody classified, and a declaration is a classification")
        object.__setattr__(self, "not_for_producers", tuple(sorted(
            {str(p).strip() for p in self.not_for_producers if str(p).strip()})))

    @property
    def key(self) -> str:
        return self.label.strip().lower()

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "method_declaration", "record_id": self.label,
                "label": self.label, "character": self.character.value,
                "declared_by": self.declared_by, "detail": self.detail,
                "not_for_producers": list(self.not_for_producers)}


@dataclass(frozen=True)
class CharacterReading:
    """What kind of check this was, and on whose authority.

    `basis` travels with `character` always. A declared PROOF_CARRYING and a
    built-in one are not interchangeable, and a consumer that reads the character
    without the basis has lost the distinction Invariant 1 turns on.
    """

    method: str
    character: MethodCharacter
    basis: CharacterBasis
    detail: str = ""
    declared_by: str = ""
    #: Set when a declaration matched the label but was refused. The reading then
    #: falls back to the built-in character, and this says why.
    refused: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "character", MethodCharacter(self.character))
        object.__setattr__(self, "basis", CharacterBasis(self.basis))
        if self.basis is CharacterBasis.DECLARED and not self.declared_by:
            raise MethodError(
                "a DECLARED character must name the declarer")
        if self.basis is CharacterBasis.NOT_ESTABLISHED \
                and self.character is not MethodCharacter.UNKNOWN:
            raise MethodError(
                f"nobody established this method's character, so it cannot read "
                f"{self.character.value}")

    @property
    def established(self) -> bool:
        return self.character is not MethodCharacter.UNKNOWN

    @property
    def proves_nothing_about_strength(self) -> bool:
        """Unconditionally true.

        Character says what kind of check ran, never how good it was. A
        PROOF_CARRYING method run against the wrong formalisation establishes
        nothing, and `VerifierStanding` (§10ar) is the orthogonal question of
        whether this verifier may be relied on at all.
        """
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "method_character", "record_id": self.method,
                "method": self.method, "character": self.character.value,
                "basis": self.basis.value, "detail": self.detail,
                "declared_by": self.declared_by, "refused": self.refused,
                "established": self.established,
                "proves_nothing_about_strength":
                    self.proves_nothing_about_strength}


@dataclass(frozen=True)
class MethodRegistry:
    """Declarations an organisation supplies. Ships empty.

    Empty is the honest default: release-gate has no view on what somebody else's
    tool is, and shipping a guess would be the vendor list §10ar exists not to
    have.
    """

    declarations: Tuple[MethodDeclaration, ...] = ()

    def __post_init__(self) -> None:
        seen: Dict[str, str] = {}
        for declaration in self.declarations:
            if declaration.key in seen:
                raise MethodError(
                    f"{declaration.label!r} is declared twice, by "
                    f"{seen[declaration.key]} and {declaration.declared_by}; "
                    "two characters for one method is two answers to one question")
            seen[declaration.key] = declaration.declared_by

    def of(self, label: str) -> Optional[MethodDeclaration]:
        key = (label or "").strip().lower()
        if not key:
            return None
        return next((d for d in self.declarations if d.key == key), None)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "method_registry",
                "schema_version": METHODS_SCHEMA_VERSION,
                "declarations": [d.to_dict() for d in self.declarations]}


#: Ships empty. An organisation constructs its own.
EMPTY_REGISTRY = MethodRegistry()


def character_of(attempt: Any, *, registry: Optional[MethodRegistry] = None,
                 producers: Sequence[str] = ()) -> CharacterReading:
    """What kind of check one attempt was.

    `producers` are the parties behind this evidence — the attempt's verifier and,
    where the caller knows them, the producers on the case. When a declaration
    names any of them among the producers it may not cover, the declaration is
    **refused** and the reading falls back to the built-in character with
    `refused` saying why. An organisation declaring its own tool proof-carrying
    and then submitting that tool's output is self-certification, whatever the
    declaration says, and it is the one shape of this feature that would let a
    producer promote its own check (Invariant 1).

    A sequence rather than one name on purpose: the check is over every party the
    caller can see, so naming only the verifier would miss an estate where the
    declaring office is also the case's producer.
    """
    method = getattr(attempt, "method", attempt)
    name = str(getattr(method, "value", method) or "").strip().upper()
    label = str(getattr(attempt, "method_label", "") or "").strip()

    try:
        member = VerificationMethod(name)
    except ValueError:
        member = VerificationMethod.OTHER

    built_in = CHARACTERS.get(member, MethodCharacter.UNKNOWN)
    shown = label or member.value

    declaration = None
    refused = ""
    if registry is not None:
        # A label is what a declaration matches. Without one an `OTHER` attempt
        # has no name to look up, which is why the label matters more than the
        # enum member for anything release-gate does not model.
        declaration = registry.of(label) or (
            registry.of(member.value) if not label else None)
        if declaration is not None:
            seen = {str(p).strip() for p in producers if str(p).strip()}
            conflict = sorted(seen & set(declaration.not_for_producers))
            if conflict:
                refused = (f"{declaration.declared_by} declared this method's "
                           f"character and {conflict[0]} is behind the evidence; "
                           "a party cannot classify its own check")
                declaration = None

    if declaration is not None:
        return CharacterReading(
            method=shown, character=declaration.character,
            basis=CharacterBasis.DECLARED,
            detail=declaration.detail or (
                f"{declaration.declared_by} states this is a "
                f"{declaration.character.value} check"),
            declared_by=declaration.declared_by, refused=refused)

    if built_in is MethodCharacter.UNKNOWN:
        return CharacterReading(
            method=shown, character=MethodCharacter.UNKNOWN,
            basis=CharacterBasis.NOT_ESTABLISHED,
            detail=_NOTES.get(member, "") or (
                "nothing establishes what kind of check this was"),
            refused=refused)

    return CharacterReading(
        method=shown, character=built_in, basis=CharacterBasis.BUILT_IN,
        detail=_NOTES.get(member, ""), refused=refused)


def proof_carrying(attempt: Any, *, registry: Optional[MethodRegistry] = None,
                   producers: Sequence[str] = ()) -> Optional[bool]:
    """Is this a proof-carrying check? `None` when nobody established it.

    Three-valued on purpose. `False` is a finding — this is a check of another
    kind — and `None` is the absence of one. Every caller that collapsed the two
    reported a formal method release-gate does not model as no formal
    verification at all (Invariant 3).
    """
    reading = character_of(attempt, registry=registry, producers=producers)
    if reading.character is MethodCharacter.UNKNOWN:
        return None
    return reading.character is MethodCharacter.PROOF_CARRYING
