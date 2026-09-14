"""Consequence — what is at stake, and whether anybody actually said so.

The human authorization boundary depends partly on consequence: an irreversible
production change and a scratch notebook deserve different amounts of a person's
attention. So the engine needs somewhere to put that, and this is it.

What it emphatically does **not** do is work out the answer. release-gate cannot
know whether a database write costs a thousand dollars or nothing, whether a
result will be published, or whether a jurisdiction regulates it. Those are
domain facts, and a plausible-looking guess at them would be worse than an empty
field — it would be a number a reviewer trusts.

So the rules here are narrow and absolute:

* **Every dimension starts at UNKNOWN, and UNKNOWN is a real answer.** A profile
  with nothing in it is valid and honest, not an error and not a zero.
* **Nothing is invented.** A value appears only when someone DECLARED it, or when
  it follows structurally from evidence already in the case.
* **Derivation reads only OBSERVED capabilities.** An inferred capability — a
  tool merely *named* `db_write` — never moves a consequence dimension off
  UNKNOWN. Deriving a consequence from a guess would launder the guess.
* **UNKNOWN never sorts as a middle value.** Its rank is `None`, not the midpoint.
  Scoring an unknown as average is the exact defect recorded against the legacy
  readiness scorer in the architecture spec (§18.1), and it is not repeated here.
* **There is no total.** No score, no level, no aggregate. Dimensions are compared
  one at a time or not at all; collapsing them into a number would invent a
  trade-off between money and legality that nobody stated.

Vocabularies live in a table rather than in enums so that a domain plugin can
extend them — a closed enum cannot be enriched, and enrichment is the point of
`ConsequenceRegistry`. Values are still validated strictly at construction.

Not to be confused with `methodology.Criticality`, which is a weight a
methodology assigns to *records* inside a case. This describes what the *action*
would do to the world.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object

__all__ = [
    "CONSEQUENCE_SCHEMA_VERSION",
    "ConsequenceBasis",
    "ConsequenceConflict",
    "ConsequenceDimension",
    "ConsequenceDescriptor",
    "ConsequenceError",
    "ConsequenceProfile",
    "ConsequenceRegistry",
    "StructuralConsequenceModel",
    "UNKNOWN",
    "default_consequence_registry",
    "descriptors_from_mapping",
    "extend_vocabulary",
    "values_for",
]

CONSEQUENCE_SCHEMA_VERSION = 1

#: The one value every dimension shares, and every dimension's default.
UNKNOWN = "UNKNOWN"


class ConsequenceError(ValueError):
    """A descriptor was constructed in a state that cannot be relied on."""


class ConsequenceDimension(str, Enum):
    """The axes. Closed, because a profile nobody can compare is not a profile."""

    REVERSIBILITY = "REVERSIBILITY"
    EXTERNALITY = "EXTERNALITY"
    SCOPE = "SCOPE"
    USER_IMPACT = "USER_IMPACT"
    FINANCIAL_IMPACT = "FINANCIAL_IMPACT"
    DATA_IMPACT = "DATA_IMPACT"
    SECURITY_IMPACT = "SECURITY_IMPACT"
    PRODUCTION_IMPACT = "PRODUCTION_IMPACT"
    RESEARCH_IMPACT = "RESEARCH_IMPACT"
    LEGAL_IMPACT = "LEGAL_IMPACT"
    UNKNOWN_IMPACT = "UNKNOWN_IMPACT"


class ConsequenceBasis(str, Enum):
    """How a value came to be here."""

    DECLARED = "DECLARED"  # a person, methodology or plugin stated it
    DERIVED = "DERIVED"    # it follows structurally from evidence in the case
    UNKNOWN = "UNKNOWN"    # nobody said, and nothing determines it


#: Ordered least- to most-consequential. `UNKNOWN` is appended to every
#: vocabulary and is deliberately outside the ordering: it ranks `None`, never a
#: midpoint. Plugins extend these through `ConsequenceRegistry.extend_vocabulary`.
_VOCABULARY: Dict[ConsequenceDimension, Tuple[str, ...]] = {
    ConsequenceDimension.REVERSIBILITY: (
        "REVERSIBLE", "REVERSIBLE_WITH_EFFORT", "IRREVERSIBLE"),
    ConsequenceDimension.EXTERNALITY: (
        "CONTAINED", "CROSSES_SYSTEM_BOUNDARY", "CROSSES_ORGANISATION_BOUNDARY"),
    ConsequenceDimension.SCOPE: (
        "SINGLE_SUBJECT", "BOUNDED_SET", "BROAD"),
    ConsequenceDimension.USER_IMPACT: (
        "NONE", "INDIRECT", "DIRECT"),
    ConsequenceDimension.FINANCIAL_IMPACT: (
        "NONE", "BOUNDED", "UNBOUNDED"),
    ConsequenceDimension.DATA_IMPACT: (
        "NONE", "READ", "MODIFIED", "DESTROYED"),
    ConsequenceDimension.SECURITY_IMPACT: (
        "NONE", "AFFECTS_CONTROLS", "GRANTS_ACCESS"),
    ConsequenceDimension.PRODUCTION_IMPACT: (
        "NONE", "NON_PRODUCTION", "PRODUCTION"),
    ConsequenceDimension.RESEARCH_IMPACT: (
        "NONE", "INTERNAL_RESULT", "PUBLISHED_RESULT"),
    ConsequenceDimension.LEGAL_IMPACT: (
        "NONE", "POSSIBLE", "REGULATED"),
    # "There are consequences here of a kind this taxonomy has no dimension for."
    ConsequenceDimension.UNKNOWN_IMPACT: (
        "NOT_FLAGGED", "FLAGGED"),
}


def values_for(dimension: ConsequenceDimension) -> Tuple[str, ...]:
    """The admissible values for a dimension, UNKNOWN last."""
    return _VOCABULARY[ConsequenceDimension(dimension)] + (UNKNOWN,)


def rank_of(dimension: ConsequenceDimension, value: str) -> Optional[int]:
    """Ordinal position, or None for UNKNOWN.

    `None` rather than a number, everywhere, so that an unknown cannot be
    averaged, summed, or sorted into the middle of a list of known values.
    """
    ordered = _VOCABULARY[ConsequenceDimension(dimension)]
    return ordered.index(value) if value in ordered else None


@dataclass(frozen=True)
class ConsequenceDescriptor:
    """One dimension's value, and who is answerable for it."""

    dimension: ConsequenceDimension
    value: str = UNKNOWN
    basis: ConsequenceBasis = ConsequenceBasis.UNKNOWN
    source: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "dimension", ConsequenceDimension(self.dimension))
        object.__setattr__(self, "basis", ConsequenceBasis(self.basis))
        value = (self.value or UNKNOWN).strip().upper()
        if value not in values_for(self.dimension):
            raise ConsequenceError(
                f"{value!r} is not an admissible value for {self.dimension.value}; "
                f"known: {', '.join(values_for(self.dimension))}. Consequence values "
                "are never free-form — an unrecognised one would compare against "
                "nothing.")
        object.__setattr__(self, "value", value)

        # The invariant that keeps the two axes honest in both directions.
        if (value == UNKNOWN) != (self.basis is ConsequenceBasis.UNKNOWN):
            raise ConsequenceError(
                f"{self.dimension.value}: value {value!r} and basis "
                f"{self.basis.value} disagree. A known value must say who "
                "established it, and an UNKNOWN value cannot have been established "
                "by anyone.")
        if self.basis is not ConsequenceBasis.UNKNOWN and not (self.source or "").strip():
            raise ConsequenceError(
                f"{self.dimension.value}: a {self.basis.value} value must name its "
                "source — a consequence nobody is answerable for is not a declaration")

    @property
    def known(self) -> bool:
        return self.value != UNKNOWN

    @property
    def rank(self) -> Optional[int]:
        return rank_of(self.dimension, self.value)

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension.value, "value": self.value,
                "basis": self.basis.value, "source": self.source, "note": self.note,
                "rank": self.rank}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ConsequenceDescriptor":
        return cls(dimension=ConsequenceDimension(data["dimension"]),
                   value=data.get("value", UNKNOWN),
                   basis=ConsequenceBasis(data.get("basis", ConsequenceBasis.UNKNOWN.value)),
                   source=data.get("source", ""), note=data.get("note", ""))

    @classmethod
    def unknown(cls, dimension: ConsequenceDimension,
                note: str = "") -> "ConsequenceDescriptor":
        return cls(dimension=dimension, value=UNKNOWN,
                   basis=ConsequenceBasis.UNKNOWN, note=note)


@dataclass(frozen=True)
class ConsequenceConflict:
    """Two sources disagreed about one dimension. Recorded, never resolved silently."""

    dimension: ConsequenceDimension
    kept: ConsequenceDescriptor
    rejected: ConsequenceDescriptor
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension.value, "kept": self.kept.to_dict(),
                "rejected": self.rejected.to_dict(), "reason": self.reason}


@dataclass(frozen=True)
class ConsequenceProfile:
    """What is at stake, dimension by dimension, with UNKNOWN as a first-class answer."""

    descriptors: Mapping[ConsequenceDimension, ConsequenceDescriptor] = field(
        default_factory=dict)
    conflicts: Tuple[ConsequenceConflict, ...] = ()

    def __post_init__(self) -> None:
        # Every dimension is always present. A caller must never have to
        # distinguish "absent from the mapping" from "unknown".
        filled = {d: ConsequenceDescriptor.unknown(d) for d in ConsequenceDimension}
        for dimension, descriptor in (self.descriptors or {}).items():
            filled[ConsequenceDimension(dimension)] = descriptor
        object.__setattr__(self, "descriptors", filled)
        object.__setattr__(self, "conflicts", tuple(self.conflicts))

    def get(self, dimension: ConsequenceDimension) -> ConsequenceDescriptor:
        return self.descriptors[ConsequenceDimension(dimension)]

    def value(self, dimension: ConsequenceDimension) -> str:
        return self.get(dimension).value

    @property
    def known(self) -> Tuple[ConsequenceDescriptor, ...]:
        return tuple(self.descriptors[d] for d in ConsequenceDimension
                     if self.descriptors[d].known)

    @property
    def unknown(self) -> Tuple[ConsequenceDescriptor, ...]:
        return tuple(self.descriptors[d] for d in ConsequenceDimension
                     if not self.descriptors[d].known)

    @property
    def declared(self) -> Tuple[ConsequenceDescriptor, ...]:
        return tuple(d for d in self.known if d.basis is ConsequenceBasis.DECLARED)

    @property
    def derived(self) -> Tuple[ConsequenceDescriptor, ...]:
        return tuple(d for d in self.known if d.basis is ConsequenceBasis.DERIVED)

    @property
    def fully_unknown(self) -> bool:
        """Nothing at all is known about what this would do."""
        return not self.known

    def elevated(self) -> Tuple[ConsequenceDescriptor, ...]:
        """Dimensions sitting at the most consequential value their vocabulary has.

        Returned as a set of dimensions, never as a count or a score. "Three
        elevated dimensions" is not three times worse than one, and this module
        will not imply that it is.
        """
        out = []
        for descriptor in self.known:
            ordered = _VOCABULARY[descriptor.dimension]
            if descriptor.value == ordered[-1]:
                out.append(descriptor)
        return tuple(out)

    def digest(self) -> str:
        return digest_object({"descriptors": [self.descriptors[d].to_dict()
                                              for d in ConsequenceDimension],
                              "schema_version": CONSEQUENCE_SCHEMA_VERSION})

    # CaseRecord protocol — a profile is storable as evidence.
    @property
    def record_type(self) -> str:
        return "consequence"

    @property
    def record_id(self) -> str:
        return f"cons_{self.digest()[7:23]}"

    def summary(self) -> Dict[str, Any]:
        return {"known": len(self.known), "unknown": len(self.unknown),
                "declared": len(self.declared), "derived": len(self.derived),
                "fully_unknown": self.fully_unknown,
                "elevated": [d.dimension.value for d in self.elevated()],
                "conflicts": len(self.conflicts), "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "consequence", "record_id": self.record_id,
                **self.summary(),
                "dimensions": {d.value: self.descriptors[d].to_dict()
                               for d in ConsequenceDimension},
                "conflict_detail": [c.to_dict() for c in self.conflicts],
                "schema_version": CONSEQUENCE_SCHEMA_VERSION}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ConsequenceProfile":
        descriptors = {}
        for raw in (data.get("dimensions") or {}).values():
            descriptor = ConsequenceDescriptor.from_dict(raw)
            descriptors[descriptor.dimension] = descriptor
        return cls(descriptors=descriptors)


def descriptors_from_mapping(data: Mapping[str, Any], *, source: str,
                             basis: ConsequenceBasis = ConsequenceBasis.DECLARED,
                             strict: bool = False) -> List[ConsequenceDescriptor]:
    """Turn `{"reversibility": "IRREVERSIBLE"}` into descriptors.

    Unrecognised dimensions and values are skipped rather than guessed at. With
    `strict=True` they raise instead — an API caller should learn that its
    declaration was not understood, while a best-effort sweep of case metadata
    should not fail a run over a stray key.
    """
    out: List[ConsequenceDescriptor] = []
    for key, value in (data or {}).items():
        try:
            dimension = ConsequenceDimension(str(key).strip().upper())
        except ValueError:
            if strict:
                raise ConsequenceError(
                    f"unknown consequence dimension {key!r}; known: "
                    + ", ".join(d.value for d in ConsequenceDimension))
            continue
        text = str(value).strip().upper()
        if text == UNKNOWN:
            continue  # declaring UNKNOWN is the same as declaring nothing
        if text not in values_for(dimension):
            if strict:
                raise ConsequenceError(
                    f"{text!r} is not admissible for {dimension.value}; known: "
                    + ", ".join(values_for(dimension)))
            continue
        out.append(ConsequenceDescriptor(dimension=dimension, value=text,
                                         basis=basis, source=source))
    return out


# ── models ───────────────────────────────────────────────────────────────────

class ConsequenceModel:
    """A source of consequence descriptors. Subclass this to supply a domain model.

    A model returns descriptors; it never returns a profile, and it never sees
    another model's output. Composition and conflict are the registry's job, so a
    plugin cannot quietly overwrite a human's declaration.
    """

    model_id = "consequence-model"
    description = ""

    def describe(self, case: Any, *,
                 capabilities: Any = None) -> Iterable[ConsequenceDescriptor]:
        raise NotImplementedError


class StructuralConsequenceModel(ConsequenceModel):
    """The only built-in. Derives what follows structurally, and nothing else.

    Two dimensions are reachable without domain knowledge, and only from
    **OBSERVED** capabilities — a capability inferred from a tool's name is a
    guess, and a consequence derived from a guess is a guess wearing a better
    coat.

    Everything else stays UNKNOWN. In particular `REVERSIBILITY` is never derived:
    it is the dimension people most want and the one no telemetry supports, and a
    structural rule for it would be pure invention.
    """

    model_id = "structural-v1"
    description = ("derives externality and data impact from observed capabilities; "
                   "never derives reversibility, cost, legality or user impact")

    def describe(self, case: Any, *,
                 capabilities: Any = None) -> Iterable[ConsequenceDescriptor]:
        if capabilities is None:
            return ()
        observed = [r for r in getattr(capabilities, "observed", ()) or ()]
        if not observed:
            return ()

        out: List[ConsequenceDescriptor] = []
        source = f"release-gate/{self.model_id}"

        # Externality. An observed capability whose effect definitionally lands
        # outside the system settles this; if every observed capability is
        # contained AND the surface is an upper bound, so is the consequence.
        external = [r for r in observed if r.external_effect is True]
        if external:
            names = ", ".join(sorted(r.capability.value for r in external))
            out.append(ConsequenceDescriptor(
                dimension=ConsequenceDimension.EXTERNALITY,
                value="CROSSES_SYSTEM_BOUNDARY", basis=ConsequenceBasis.DERIVED,
                source=source,
                note=f"observed capabilities with effects outside the system: {names}"))
        elif (all(r.external_effect is False for r in observed)
                and getattr(capabilities, "bounded", False)):
            out.append(ConsequenceDescriptor(
                dimension=ConsequenceDimension.EXTERNALITY, value="CONTAINED",
                basis=ConsequenceBasis.DERIVED, source=source,
                note="every observed capability is contained, and the capability "
                     "surface is an upper bound on what ran"))
        # Where the surface is not an upper bound — a shell, an MCP server, an
        # unidentified tool — CONTAINED is unprovable and the dimension stays
        # UNKNOWN rather than being asserted from an incomplete list.

        # Data impact. A write is settled; a read alone is settled only when the
        # surface is bounded, because a shell could have written without showing.
        writes = [r for r in observed if r.capability.value == "DATABASE_WRITE"]
        reads = [r for r in observed if r.capability.value == "DATABASE_READ"]
        if writes:
            out.append(ConsequenceDescriptor(
                dimension=ConsequenceDimension.DATA_IMPACT, value="MODIFIED",
                basis=ConsequenceBasis.DERIVED, source=source,
                note="an observed database write; whether any row was destroyed is "
                     "not determinable from the telemetry"))
        elif reads and getattr(capabilities, "bounded", False):
            out.append(ConsequenceDescriptor(
                dimension=ConsequenceDimension.DATA_IMPACT, value="READ",
                basis=ConsequenceBasis.DERIVED, source=source,
                note="observed database reads and no observed write, on a bounded "
                     "capability surface"))
        return tuple(out)


class ConsequenceRegistry:
    """Composes descriptors from several sources under a stated precedence.

    Precedence, highest first:

    1. **Declarations** — a person, an API caller, a methodology. Someone is
       answerable for these.
    2. **Domain plugins** — richer models registered for a domain.
    3. **Structural derivation** — what follows from evidence already in the case.

    A lower tier never overwrites a higher one. Disagreement *within* a tier is a
    conflict: both values are recorded and neither is quietly preferred, because
    two sources of equal standing disagreeing about what is at stake is exactly
    the kind of thing a human should see.
    """

    def __init__(self, *, include_structural: bool = True) -> None:
        self._models: List[ConsequenceModel] = []
        if include_structural:
            self._models.append(StructuralConsequenceModel())

    def register(self, model: ConsequenceModel) -> "ConsequenceRegistry":
        if not isinstance(model, ConsequenceModel):
            raise ConsequenceError("a consequence model must subclass ConsequenceModel")
        if any(m.model_id == model.model_id for m in self._models):
            raise ConsequenceError(
                f"a model with id {model.model_id!r} is already registered; a second "
                "one would make the profile depend on registration order")
        self._models.append(model)
        return self

    @property
    def models(self) -> Tuple[ConsequenceModel, ...]:
        return tuple(self._models)

    def build(self, case: Any = None, *, capabilities: Any = None,
              declared: Optional[Iterable[ConsequenceDescriptor]] = None
              ) -> ConsequenceProfile:
        tiers: List[Tuple[int, List[ConsequenceDescriptor]]] = [
            (0, list(declared or ())),
            (1, [d for model in self._models
                 if not isinstance(model, StructuralConsequenceModel)
                 for d in (model.describe(case, capabilities=capabilities) or ())]),
            (2, [d for model in self._models
                 if isinstance(model, StructuralConsequenceModel)
                 for d in (model.describe(case, capabilities=capabilities) or ())]),
        ]

        chosen: Dict[ConsequenceDimension, Tuple[int, ConsequenceDescriptor]] = {}
        conflicts: List[ConsequenceConflict] = []

        for tier, descriptors in tiers:
            for descriptor in descriptors:
                if not descriptor.known:
                    continue
                existing = chosen.get(descriptor.dimension)
                if existing is None:
                    chosen[descriptor.dimension] = (tier, descriptor)
                    continue
                existing_tier, existing_descriptor = existing
                if existing_tier < tier:
                    conflicts.append(ConsequenceConflict(
                        dimension=descriptor.dimension, kept=existing_descriptor,
                        rejected=descriptor,
                        reason=("a lower-precedence source disagreed; the declaration "
                                "stands")))
                elif existing_descriptor.value != descriptor.value:
                    conflicts.append(ConsequenceConflict(
                        dimension=descriptor.dimension, kept=existing_descriptor,
                        rejected=descriptor,
                        reason=("two sources of equal standing disagree; the first is "
                                "shown and both are recorded — neither is preferred")))

        return ConsequenceProfile(
            descriptors={dimension: descriptor
                         for dimension, (_tier, descriptor) in chosen.items()},
            conflicts=tuple(sorted(conflicts, key=lambda c: c.dimension.value)))


def extend_vocabulary(dimension: ConsequenceDimension,
                      values: Sequence[str]) -> Tuple[str, ...]:
    """Let a domain plugin enrich a dimension's vocabulary.

    **Process-wide and append-only.** This is module-level rather than a method on
    a registry on purpose: the vocabulary is what `ConsequenceDescriptor` validates
    against, and descriptors are constructed by plugins that have no registry in
    hand. Making it look instance-scoped when it is not would be worse than
    stating the scope plainly — so call it once, at import time, before any
    profile is built.

    Values are appended, never reordered or replaced: existing ranks must not move,
    or a profile recorded before the extension would silently mean something else.
    A plugin needing a *less* consequential value than the existing floor should
    introduce its own dimension rather than renumbering this one.
    """
    dimension = ConsequenceDimension(dimension)
    current = _VOCABULARY[dimension]
    additions = tuple(v.strip().upper() for v in values
                      if v.strip().upper() not in current
                      and v.strip().upper() != UNKNOWN)
    if additions:
        _VOCABULARY[dimension] = current + additions
    return _VOCABULARY[dimension]


def default_consequence_registry() -> ConsequenceRegistry:
    """A fresh registry per call, so one caller's plugin is not another's surprise."""
    return ConsequenceRegistry()
