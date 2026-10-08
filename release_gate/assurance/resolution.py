"""Claim resolution — which claims this release needs, and where each one stands.

An admission decision is a decision about claims: *all transfers above the
threshold require affirmative human authorization before execution*; *the agent
cannot call the payments API without a ticket*. A score cannot say which of them
holds. This module answers, for every claim in a case, a status a person can act
on, the rule that produced it, and the evidence for, against, and set aside —
deterministically, from the case and a declared policy.

    ESTABLISHED          verification-grade support the policy accepts: a passed
                         proof bound to the candidate, or passed checks from enough
                         independent sources; every dependency established
    SUPPORTED            counted support, short of that
    PARTIALLY_SUPPORTED  counted support with a gap the claim itself names: an
                         unsettled check, an expected check that never ran, a
                         declared requirement unmet, a dependency not supported
    CONTRADICTED         a found counterexample, a failed check, or evidence against
                         it stands — however much else supports it
    UNSUPPORTED          things bear on it, and none of them counts as support
    UNKNOWN              what bears on it cannot settle it
    NOT_ASSESSED         nothing bears on it; nobody looked

**No averaging, anywhere.** There is no weight, no sum and no ratio. The rules are
an order, and the first that applies decides. Contradiction comes first, so one
open counterexample outranks any number of passing observations, and adding
support can never move a contradicted claim. The order is the whole of the logic
and it is pinned by tests rule by rule.

**What does not count, and is still shown.** Support bound to a different state
of the candidate (`candidate.py`) is set aside — a proof about the wrong artifact
does not count. So is evidence outside what the claim declares admissible, a
check by a verifier the organisation has ruled against, and an invalidated
result. Each is listed with the reason, because a resolution that silently
dropped evidence would be the omission Invariant 13 names.

**Strength is a kind, not a size.** A counted item is a proof, a mechanical check,
an empirical check, a judgement, an observation or a declaration — the method
characters of `methods.py`, plus the two kinds of evidence that are not checks.
Characters are not ranked; the policy says which kinds may *establish* a claim,
and a declaration never does.

**Independence decides corroboration, by groups.** Two passing checks from one
model session are one source (`correlation.py`). ESTABLISHED by corroboration
needs `min_independent_groups` groups the stated provenance separates; sources
that state too little to be placed are counted apart and never fill the quota.

**This module concludes; it does not decide.** The verdict reads it through one
structural finding (RG-CRIT-006, a required claim below the policy's admission
level) and the findings that already block on refutation. The claim graph's own
status is kept beside each resolution, unchanged, so the two can be compared.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.correlation import (
    DEFAULT_INDEPENDENCE_POLICY,
    READER_INDEPENDENCE_POLICY,
    IndependenceAssessment,
    IndependencePolicy,
    ProvenanceIndex,
    SourceProvenance,
    assess_independence,
)
from release_gate.assurance.escalation import EscalationScope
from release_gate.assurance.evidence import EpistemicStatus, TrustStatus, VerificationMethod
from release_gate.assurance.methods import CHARACTERS, MethodCharacter

__all__ = [
    "AdmissionEffect",
    "DEFAULT_RESOLUTION_POLICY",
    "RESOLUTION_SCHEMA_VERSION",
    "ClaimResolution",
    "ClaimResolutionReport",
    "CorroborationRoute",
    "ItemRole",
    "ResolutionPolicy",
    "ResolutionStatus",
    "ResolvedItem",
    "SemanticCorroboration",
    "Strength",
    "resolve_claims",
]

RESOLUTION_SCHEMA_VERSION = 1

#: Where a caller's resolution policy is stored on a case.
POLICY_METADATA_KEY = "resolution_policy"


class ResolutionError(ValueError):
    """A resolution policy was described in a way that could not be applied."""


class ResolutionStatus(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"
    NOT_ASSESSED = "NOT_ASSESSED"


#: The order a dependency caps a claim by. Used only for "is this dependency
#: at least as good as that level" — never added, never averaged.
_LEVEL = {ResolutionStatus.ESTABLISHED: 3, ResolutionStatus.SUPPORTED: 2,
          ResolutionStatus.PARTIALLY_SUPPORTED: 1}


class Strength(str, Enum):
    """What kind of support a counted item is. A kind, not a magnitude."""

    PROOF = "PROOF"                # a proof-carrying check
    MECHANICAL = "MECHANICAL"      # a fixed property a tool always checks
    EMPIRICAL = "EMPIRICAL"        # a test, a simulation, a runtime assertion
    JUDGEMENT = "JUDGEMENT"        # a person or a model read it
    OBSERVATION = "OBSERVATION"    # evidence release-gate observed or derived; not a check
    DECLARATION = "DECLARATION"    # an actor's account; never establishes
    UNCLASSIFIED = "UNCLASSIFIED"  # a method nobody classified


_FROM_CHARACTER = {MethodCharacter.PROOF_CARRYING: Strength.PROOF,
                   MethodCharacter.MECHANICAL: Strength.MECHANICAL,
                   MethodCharacter.EMPIRICAL: Strength.EMPIRICAL,
                   MethodCharacter.JUDGEMENT: Strength.JUDGEMENT,
                   MethodCharacter.UNKNOWN: Strength.UNCLASSIFIED}

#: Kinds that are checks — the only kinds that can establish.
_VERIFICATION_GRADE = frozenset({Strength.PROOF, Strength.MECHANICAL,
                                 Strength.EMPIRICAL, Strength.JUDGEMENT})


class SemanticSupport(str, Enum):
    """What a semantic verifier's "supported" does to a claim (semantic_verifier.py)."""

    RECORD_ONLY = "RECORD_ONLY"   # shown beside the claim, counted toward nothing
    COUNTS = "COUNTS"             # counts as support; never establishes


class AdmissionEffect(str, Enum):
    """What an unmet part of the resolution policy does to the case.

    HOLD or BLOCK, and nothing weaker: the policy can make a gap stop the
    release harder, never make it advisory.
    """

    HOLD = "HOLD"     # a person settles it before anything is admitted
    BLOCK = "BLOCK"


#: What a semantic verifier's "contradicted" does to the case (RG-SEM-001). The
#: same two effects; kept under its own name, which callers already use.
SemanticChallenge = AdmissionEffect


class CorroborationRoute(str, Enum):
    """What may corroborate a model's "supported" on a critical claim (RG-SEM-006)."""

    #: A check or an observation counts toward the claim: a test, a proof, a
    #: trace. Not a declaration, and not another reading.
    DETERMINISTIC_SUPPORT = "DETERMINISTIC_SUPPORT"
    #: Agreeing readings from verifiers the stated provenance shows independent.
    INDEPENDENT_READINGS = "INDEPENDENT_READINGS"
    #: A person approved or reviewed the claim.
    HUMAN_APPROVAL = "HUMAN_APPROVAL"

    @property
    def described(self) -> str:
        return _ROUTE_WORDS[self.value]


@dataclass(frozen=True)
class SemanticCorroboration:
    """When a model's "supported" on a critical claim counts at all. Declared.

    Read only under `semantic_support: COUNTS`, which is what lets a reading
    count; without this, a reading citing what the claim rests on counts.
    With it, a reading on a claim in `applies_to` counts only when one of the
    `routes` holds. Unmet, the reading is recorded and not counted, and
    RG-SEM-006 says what is missing, advisory unless `unmet` says HOLD or
    BLOCK.

    A corroborated reading is still a reading. It never establishes and never
    closes a gap (CR-08). Verifiers reading one packet share it, so an
    instruction written into it reaches all of them: agreement among readers
    corroborates a reading and never stands in for a check.
    """

    routes: Tuple[CorroborationRoute, ...] = tuple(CorroborationRoute)
    #: Readings that must agree, from this many groups under `independence`.
    min_independent_readings: int = 2
    applies_to: EscalationScope = EscalationScope.REQUIRED
    independence: IndependencePolicy = READER_INDEPENDENCE_POLICY
    unmet: Optional[AdmissionEffect] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "routes", tuple(sorted(
            {CorroborationRoute(r) for r in self.routes}, key=lambda r: r.value)))
        if not self.routes:
            raise ResolutionError("a corroboration policy names at least one route; with "
                                  "none, no reading on a critical claim could ever count")
        if (isinstance(self.min_independent_readings, bool)
                or int(self.min_independent_readings) < 2):
            raise ResolutionError(
                "min_independent_readings is at least 2: one reading does not corroborate "
                "itself")
        object.__setattr__(self, "min_independent_readings",
                           int(self.min_independent_readings))
        object.__setattr__(self, "applies_to", EscalationScope(self.applies_to))
        if self.unmet is not None:
            object.__setattr__(self, "unmet", AdmissionEffect(self.unmet))

    def to_dict(self) -> Dict[str, Any]:
        return {"routes": [r.value for r in self.routes],
                "min_independent_readings": self.min_independent_readings,
                "applies_to": self.applies_to.value,
                "independence": self.independence.to_dict(),
                "unmet": self.unmet.value if self.unmet else None}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SemanticCorroboration":
        if not isinstance(data, Mapping):
            raise ResolutionError("`semantic_corroboration` is an object")
        unknown = sorted(set(data) - {"routes", "min_independent_readings", "applies_to",
                                      "independence", "unmet"})
        if unknown:
            raise ResolutionError(f"unknown semantic_corroboration keys: {', '.join(unknown)}")
        try:
            return cls(
                routes=tuple(CorroborationRoute(str(r)) for r in (
                    data["routes"] if data.get("routes") is not None
                    else [r.value for r in CorroborationRoute])),
                min_independent_readings=data.get("min_independent_readings", 2),
                applies_to=EscalationScope(str(data.get("applies_to")
                                               or EscalationScope.REQUIRED.value)),
                independence=(IndependencePolicy.from_dict(data["independence"])
                              if isinstance(data.get("independence"), Mapping)
                              else READER_INDEPENDENCE_POLICY),
                unmet=AdmissionEffect(str(data["unmet"])) if data.get("unmet") else None)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ResolutionError):
                raise
            raise ResolutionError(f"unusable semantic_corroboration: {exc}") from exc


@dataclass(frozen=True)
class ResolutionPolicy:
    """What it takes to establish a claim, and what a required claim must reach.

    Declared and digested; a case records the policy it was resolved under.
    """

    policy_id: str = "rg-resolution"
    version: str = "1"
    independence: IndependencePolicy = DEFAULT_INDEPENDENCE_POLICY
    #: A passed proof-carrying check bound to the candidate establishes on its
    #: own: a proof does not need a second proof to be a proof of what it states.
    proof_establishes_alone: bool = True
    #: Kinds that count toward corroboration. A declaration and an observation
    #: support; they do not establish.
    establishing: Tuple[Strength, ...] = (Strength.PROOF, Strength.MECHANICAL,
                                          Strength.EMPIRICAL, Strength.JUDGEMENT)
    #: Methods that never establish, whatever their kind. A model reading a model
    #: is correlation until a methodology says otherwise (`methods.py`).
    non_establishing_methods: Tuple[VerificationMethod, ...] = (
        VerificationMethod.CROSS_MODEL_REVIEW,)
    #: What a required claim must reach for the case not to hold on it.
    admission_level: ResolutionStatus = ResolutionStatus.SUPPORTED
    #: A model's reading is recorded and counted toward nothing unless the
    #: policy says otherwise; even then it never establishes (CR-09).
    semantic_support: SemanticSupport = SemanticSupport.RECORD_ONLY
    #: A model reading the evidence as contradicting a claim holds the case by
    #: default: a reading raises the question, a person or a check settles it.
    semantic_contradiction: SemanticChallenge = SemanticChallenge.HOLD
    #: A genuine, unresolved contradiction on a critical claim (RG-CONTRA-005).
    #: Disagreements that are not contradictions — stale, mismatched, ambiguous —
    #: hold regardless (RG-CONTRA-006, -007): they are open, and not settled.
    critical_contradiction: AdmissionEffect = AdmissionEffect.HOLD
    #: The share of each dimension of a required claim's declared surface that
    #: must be assessed (claim_coverage.py, RG-COV-006). 1.0 is all of it.
    surface_coverage: float = 1.0
    surface_shortfall: AdmissionEffect = AdmissionEffect.HOLD
    #: Whether a required claim must declare a surface at all (RG-COV-007).
    require_surface: bool = False
    #: A valid counterexample against a critical claim (RG-CEX-001).
    counterexample_effect: AdmissionEffect = AdmissionEffect.BLOCK
    #: Whether a counterexample accepted as a documented risk — who, why, where,
    #: and for which state — stops blocking. Off: an exception is something a
    #: policy has to say it allows (counterexample.assess_standing).
    counterexample_exceptions: bool = False
    #: Whether a required claim must be checked by someone other than the author
    #: of what it is about (authorship.py). None reports and requires nothing:
    #: RG-INDEP-007/008 stay advisory. Set, a required claim every check of which
    #: shares its author takes this effect, and one whose independence from its
    #: author cannot be established holds — unknown is not a pass.
    author_independence: Optional[AdmissionEffect] = None
    #: What a model's uncertainty does to a required claim: a question it could
    #: not answer, or answered below the verifier policy's confidence (RG-SEM-002,
    #: -003). None: reported (RG-SEM-002 advisory) or held only where the verifier
    #: policy asks for more verification (RG-SEM-003). Low confidence never blocks
    #: unless this says BLOCK.
    semantic_uncertainty: Optional[AdmissionEffect] = None
    #: When a model's "supported" on a critical claim counts (RG-SEM-006). None:
    #: under COUNTS, a reading citing what the claim rests on counts, as before.
    semantic_corroboration: Optional[SemanticCorroboration] = None
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "semantic_support", SemanticSupport(self.semantic_support))
        if self.semantic_corroboration is not None and not isinstance(
                self.semantic_corroboration, SemanticCorroboration):
            raise ResolutionError("semantic_corroboration is a SemanticCorroboration")
        object.__setattr__(self, "semantic_contradiction",
                           SemanticChallenge(self.semantic_contradiction))
        object.__setattr__(self, "critical_contradiction",
                           AdmissionEffect(self.critical_contradiction))
        object.__setattr__(self, "surface_shortfall",
                           AdmissionEffect(self.surface_shortfall))
        if isinstance(self.surface_coverage, bool) or not isinstance(
                self.surface_coverage, (int, float)):
            raise ResolutionError("surface_coverage is a number")
        share = float(self.surface_coverage)
        if not 0.0 < share <= 1.0:
            raise ResolutionError(
                "surface_coverage is within (0, 1]: a policy that needed none of a "
                "required claim's surface assessed would read unassessed as passed")
        object.__setattr__(self, "surface_coverage", share)
        if not isinstance(self.require_surface, bool):
            raise ResolutionError("require_surface is true or false")
        object.__setattr__(self, "counterexample_effect",
                           AdmissionEffect(self.counterexample_effect))
        if not isinstance(self.counterexample_exceptions, bool):
            raise ResolutionError("counterexample_exceptions is true or false")
        if self.author_independence is not None:
            object.__setattr__(self, "author_independence",
                               AdmissionEffect(self.author_independence))
        if self.semantic_uncertainty is not None:
            object.__setattr__(self, "semantic_uncertainty",
                               AdmissionEffect(self.semantic_uncertainty))
        object.__setattr__(self, "establishing",
                           tuple(sorted({Strength(s) for s in self.establishing},
                                        key=lambda s: s.value)))
        object.__setattr__(self, "non_establishing_methods",
                           tuple(sorted({VerificationMethod(m)
                                         for m in self.non_establishing_methods},
                                        key=lambda m: m.value)))
        object.__setattr__(self, "admission_level", ResolutionStatus(self.admission_level))
        if self.admission_level not in (ResolutionStatus.ESTABLISHED,
                                        ResolutionStatus.SUPPORTED):
            raise ResolutionError(
                "admission_level is ESTABLISHED or SUPPORTED: a lower bar would admit "
                "a required claim nothing counted toward")
        if Strength.DECLARATION in self.establishing:
            raise ResolutionError("a declaration cannot establish a claim — it is an "
                                  "actor's account, with no check behind it")
        if Strength.UNCLASSIFIED in self.establishing:
            raise ResolutionError("an unclassified method cannot establish a claim — "
                                  "what nobody has said a check is cannot count as one")
        if Strength.OBSERVATION in self.establishing:
            raise ResolutionError(
                "an observation cannot establish a claim — a hundred clean traces show "
                "what happened, never that anything else cannot")

    @property
    def ref(self) -> str:
        return f"{self.policy_id}@{self.version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id, "version": self.version,
                "independence": self.independence.to_dict(),
                "proof_establishes_alone": self.proof_establishes_alone,
                "establishing": [s.value for s in self.establishing],
                "non_establishing_methods": [m.value for m in self.non_establishing_methods],
                "admission_level": self.admission_level.value,
                "semantic_support": self.semantic_support.value,
                "semantic_contradiction": self.semantic_contradiction.value,
                "critical_contradiction": self.critical_contradiction.value,
                "surface_coverage": self.surface_coverage,
                "surface_shortfall": self.surface_shortfall.value,
                "require_surface": self.require_surface,
                "counterexample_effect": self.counterexample_effect.value,
                "counterexample_exceptions": self.counterexample_exceptions,
                "author_independence": (self.author_independence.value
                                        if self.author_independence else None),
                "semantic_uncertainty": (self.semantic_uncertainty.value
                                         if self.semantic_uncertainty else None),
                # Present only when declared, so a policy without one digests
                # exactly as it did before the field existed.
                **({"semantic_corroboration": self.semantic_corroboration.to_dict()}
                   if self.semantic_corroboration is not None else {}),
                "note": self.note, "schema_version": RESOLUTION_SCHEMA_VERSION}

    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResolutionPolicy":
        default = DEFAULT_RESOLUTION_POLICY
        if not isinstance(data, Mapping):
            raise ResolutionError(
                f"a resolution policy is a JSON object, not {type(data).__name__}")
        if data.get("independence") is not None and not isinstance(
                data["independence"], Mapping):
            raise ResolutionError("`independence` is an object; anything else would be "
                                  "read as the default without saying so")
        try:
            return cls(
                policy_id=str(data.get("policy_id") or "custom"),
                version=str(data.get("version") or "1"),
                independence=(IndependencePolicy.from_dict(data["independence"])
                              if isinstance(data.get("independence"), Mapping)
                              else default.independence),
                proof_establishes_alone=bool(data.get(
                    "proof_establishes_alone", default.proof_establishes_alone)),
                establishing=tuple(Strength(str(s)) for s in (
                    data.get("establishing") or [s.value for s in default.establishing])),
                non_establishing_methods=tuple(VerificationMethod(str(m)) for m in (
                    data.get("non_establishing_methods")
                    if data.get("non_establishing_methods") is not None
                    else [m.value for m in default.non_establishing_methods])),
                admission_level=ResolutionStatus(str(
                    data.get("admission_level") or default.admission_level.value)),
                semantic_support=SemanticSupport(str(
                    data.get("semantic_support") or default.semantic_support.value)),
                semantic_contradiction=SemanticChallenge(str(
                    data.get("semantic_contradiction")
                    or default.semantic_contradiction.value)),
                critical_contradiction=AdmissionEffect(str(
                    data.get("critical_contradiction")
                    or default.critical_contradiction.value)),
                surface_coverage=data.get("surface_coverage", default.surface_coverage),
                surface_shortfall=AdmissionEffect(str(
                    data.get("surface_shortfall") or default.surface_shortfall.value)),
                require_surface=data.get("require_surface", default.require_surface),
                counterexample_effect=AdmissionEffect(str(
                    data.get("counterexample_effect")
                    or default.counterexample_effect.value)),
                counterexample_exceptions=data.get("counterexample_exceptions",
                                                   default.counterexample_exceptions),
                author_independence=(AdmissionEffect(str(data["author_independence"]))
                                     if data.get("author_independence") else None),
                semantic_uncertainty=(AdmissionEffect(str(data["semantic_uncertainty"]))
                                      if data.get("semantic_uncertainty") else None),
                semantic_corroboration=(
                    SemanticCorroboration.from_dict(data["semantic_corroboration"])
                    if data.get("semantic_corroboration") is not None else None),
                note=str(data.get("note") or ""))
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ResolutionError):
                raise
            raise ResolutionError(f"unusable resolution policy: {exc}") from exc


DEFAULT_RESOLUTION_POLICY = ResolutionPolicy(
    note="a bound proof establishes alone; otherwise two independent groups of "
         "passing checks; a required claim must be at least SUPPORTED")


# ── the items a resolution is made of ────────────────────────────────────────

class ItemRole(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    FAILED_CHECK = "FAILED_CHECK"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"
    SEARCHED_NOT_FOUND = "SEARCHED_NOT_FOUND"
    WITHHELD_STATE = "WITHHELD_STATE"            # bound to another state of the candidate
    NOT_ADMISSIBLE = "NOT_ADMISSIBLE"            # outside what the claim declares admissible
    NOT_RELIED_UPON = "NOT_RELIED_UPON"          # a verifier or source ruled against
    INVALIDATED = "INVALIDATED"
    RESOLVED = "RESOLVED"                        # a contradiction or counterexample answered
    # A semantic verifier's assertion (semantic_verifier.py), read under the policy.
    SEMANTIC_SUPPORT = "SEMANTIC_SUPPORT"        # "supported", recorded and not counted
    SEMANTIC_CHALLENGE = "SEMANTIC_CHALLENGE"    # "contradicted": a gap a person settles
    SEMANTIC_INSUFFICIENT = "SEMANTIC_INSUFFICIENT"  # "insufficient_evidence": a gap
    SEMANTIC_NEEDS_VERIFICATION = "SEMANTIC_NEEDS_VERIFICATION"  # low confidence, policy asks for more
    SEMANTIC_UNKNOWN = "SEMANTIC_UNKNOWN"        # no answer; moves nothing


#: Roles that are evidence *set aside*: they bear on the claim and do not count.
_SET_ASIDE = frozenset({ItemRole.WITHHELD_STATE, ItemRole.NOT_ADMISSIBLE,
                        ItemRole.NOT_RELIED_UPON, ItemRole.INVALIDATED})

#: A semantic reading that says nothing about the claim: an unanswered question,
#: or a "supported" the policy records without counting. Neither may move a
#: claim — not even from NOT_ASSESSED to UNSUPPORTED — so the rules look past them.
_INERT = frozenset({ItemRole.SEMANTIC_UNKNOWN, ItemRole.SEMANTIC_SUPPORT})

def _inert_reading(item: "ResolvedItem") -> bool:
    """A semantic reading that may not move a claim: unanswered, recorded-only, or
    made against another state of the release."""
    return item.item_kind == "semantic" and (
        item.role in _INERT or item.role is ItemRole.WITHHELD_STATE)


#: Support that corroborates a reading as a check or an observation would: not
#: a declaration, and not a judgement (another reading, a person's say-so).
_DETERMINISTIC = frozenset({Strength.PROOF, Strength.MECHANICAL, Strength.EMPIRICAL,
                            Strength.OBSERVATION})

_ROUTE_WORDS = {
    "DETERMINISTIC_SUPPORT": "a check or an observation that supports the claim",
    "INDEPENDENT_READINGS": "agreeing readings from independent verifiers",
    "HUMAN_APPROVAL": "a person's approval of the claim",
}

#: Semantic readings the rules treat as a named gap (CR-08).
_SEMANTIC_GAPS = {
    ItemRole.SEMANTIC_CHALLENGE: "a semantic verifier read its evidence as "
                                 "contradicting it, and a person has to settle that",
    ItemRole.SEMANTIC_INSUFFICIENT: "a semantic verifier found its evidence does not "
                                    "settle it",
    ItemRole.SEMANTIC_NEEDS_VERIFICATION: "a semantic reading was not confident enough "
                                          "and the verifier policy asks for more "
                                          "verification",
}


@dataclass(frozen=True)
class ResolvedItem:
    item_id: str
    item_kind: str                    # evidence | verification | counterexample
    role: ItemRole
    strength: Optional[Strength] = None
    method: str = ""
    binding: str = ""                 # the StateMatch, where the item was bound
    group: str = ""                   # its correlation group, for counted support
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"item_id": self.item_id, "item_kind": self.item_kind,
                "role": self.role.value,
                "strength": self.strength.value if self.strength else None,
                "method": self.method, "binding": self.binding, "group": self.group,
                "reason": self.reason}


@dataclass(frozen=True)
class ClaimResolution:
    claim_id: str
    statement: str
    status: ResolutionStatus
    rule: str
    basis: str
    required: Optional[bool] = None   # None: criticality could not be determined
    items: Tuple[ResolvedItem, ...] = ()
    independence: Optional[IndependenceAssessment] = None
    dependencies: Tuple[Tuple[str, str], ...] = ()
    claim_status: str = ""            # the claim graph's own status, beside
    #: The same grouping over only the support the policy lets establish — the
    #: one CR-09 reads. Declarations and observations can be as correlated as
    #: they like without moving a claim, so this, not `independence`, is the
    #: grouping that held a claim at SUPPORTED.
    establishing_independence: Optional[IndependenceAssessment] = None
    #: Whether a "supported" reading of this claim was corroborated, when the
    #: policy declares `semantic_corroboration` and the claim is in its scope.
    corroboration: Optional[Mapping[str, Any]] = None

    @property
    def held_by_independence(self) -> bool:
        """Several establishing checks, short of ESTABLISHED for want of independence."""
        grade = self.establishing_independence
        return (grade is not None and grade.sources > 1
                and self.status in (ResolutionStatus.SUPPORTED,
                                    ResolutionStatus.PARTIALLY_SUPPORTED)
                and grade.status.value in ("CORRELATED", "INDEPENDENCE_UNKNOWN"))

    def of(self, *roles: ItemRole) -> Tuple[ResolvedItem, ...]:
        wanted = set(roles)
        return tuple(i for i in self.items if i.role in wanted)

    @property
    def counted(self) -> Tuple[ResolvedItem, ...]:
        return self.of(ItemRole.SUPPORTS)

    @property
    def set_aside(self) -> Tuple[ResolvedItem, ...]:
        return tuple(i for i in self.items if i.role in _SET_ASIDE)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "claim_resolution", "record_id": self.claim_id,
                "claim_id": self.claim_id, "statement": self.statement,
                "status": self.status.value, "rule": self.rule, "basis": self.basis,
                "required": self.required, "claim_status": self.claim_status,
                "items": [i.to_dict() for i in self.items],
                "independence": self.independence.to_dict() if self.independence else None,
                "establishing_independence": (self.establishing_independence.to_dict()
                                              if self.establishing_independence else None),
                "dependencies": [{"claim_id": c, "status": s} for c, s in self.dependencies],
                **({"corroboration": dict(self.corroboration)}
                   if self.corroboration is not None else {})}


@dataclass(frozen=True)
class ClaimResolutionReport:
    resolutions: Tuple[ClaimResolution, ...] = ()
    policy: ResolutionPolicy = DEFAULT_RESOLUTION_POLICY
    criticality_determinable: bool = False
    notes: Tuple[str, ...] = ()

    def of(self, claim_id: str) -> Optional[ClaimResolution]:
        return next((r for r in self.resolutions if r.claim_id == claim_id), None)

    def required(self) -> Tuple[ClaimResolution, ...]:
        return tuple(r for r in self.resolutions if r.required)

    def below_admission(self) -> Tuple[ClaimResolution, ...]:
        """Required claims short of the policy's admission level, not contradicted.

        Contradicted claims are not here: they are already blocked on by the
        findings that read refutation, and listing them twice would count one
        disagreement as two reasons.
        """
        floor = _LEVEL[self.policy.admission_level]
        return tuple(r for r in self.required()
                     if r.status is not ResolutionStatus.CONTRADICTED
                     and _LEVEL.get(r.status, 0) < floor)

    def summary(self) -> Dict[str, Any]:
        return {"claims": len(self.resolutions),
                "required": len(self.required()),
                "criticality_determinable": self.criticality_determinable,
                "by_status": {s.value: sum(1 for r in self.resolutions if r.status is s)
                              for s in ResolutionStatus},
                "required_below_admission": len(self.below_admission()),
                "required_contradicted": sum(
                    1 for r in self.required()
                    if r.status is ResolutionStatus.CONTRADICTED),
                "policy": self.policy.ref, "policy_digest": self.policy.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "claim_resolution_report", **self.summary(),
                "policy_detail": self.policy.to_dict(),
                "resolutions": [r.to_dict() for r in self.resolutions],
                "notes": list(self.notes)}


# ── reading a claim's material ──────────────────────────────────────────────

def _admissible(claim: Any) -> Optional[Set[str]]:
    """What the claim declares may bear on it: methods, evidence types or lanes."""
    stated = (getattr(claim, "metadata", None) or {}).get("admissible_evidence")
    if not stated:
        return None
    items = stated if isinstance(stated, (list, tuple)) else [stated]
    return {str(x).strip().upper() for x in items if str(x).strip()}


def _required_methods(claim: Any) -> Tuple[str, ...]:
    stated = (getattr(claim, "metadata", None) or {}).get("requires")
    if not stated:
        return ()
    items = stated if isinstance(stated, (list, tuple)) else [stated]
    return tuple(sorted({str(x).strip().upper() for x in items if str(x).strip()}))


def _evidence_strength(record: Any) -> Tuple[Strength, str]:
    method = getattr(record, "verification_method", None)
    if method is not None and record.epistemic_status is EpistemicStatus.VERIFIED:
        return _FROM_CHARACTER[CHARACTERS.get(method, MethodCharacter.UNKNOWN)], method.value
    if record.epistemic_status in (EpistemicStatus.OBSERVED, EpistemicStatus.DERIVED):
        return Strength.OBSERVATION, ""
    return Strength.DECLARATION, ""


def _attempt_strength(attempt: Any) -> Tuple[Strength, str]:
    method = attempt.method
    return (_FROM_CHARACTER[CHARACTERS.get(method, MethodCharacter.UNKNOWN)],
            method.value if not getattr(attempt, "method_label", "")
            else f"OTHER:{attempt.method_label}")


def _matches(admissible: Optional[Set[str]], *names: str) -> bool:
    if admissible is None:
        return True
    return any(n and n.upper() in admissible for n in names)


# ── the resolver ─────────────────────────────────────────────────────────────

class _Resolver:
    def __init__(self, claim_graph: Any, *, counterexamples: Any, criticality: Any,
                 records: Sequence[Any], policy: ResolutionPolicy) -> None:
        self.graph = claim_graph
        self.policy = policy
        self.counterexamples = counterexamples
        self.critical: Optional[Set[str]] = (
            set(criticality.critical_ids) if criticality is not None
            and getattr(criticality, "determinable", False) else None)
        self.evidence = {r.evidence_id: r for r in records if hasattr(r, "evidence_id")}
        self.provenance = ProvenanceIndex(self.evidence.values(), policy.independence)
        binding = getattr(claim_graph, "state_binding", None)
        self.bindings = {b.record_id: b for b in (binding.bindings if binding else ())}
        self.explicit_candidate = bool(binding and binding.candidate.explicit)
        self.resolved_ids = set(getattr(claim_graph, "_resolved", set()))
        self.done: Dict[str, ClaimResolution] = {}
        self.stack: Set[str] = set()
        # Semantic assertions ride in evidence records and link to no claim; this
        # is the one place they reach one, read under the declared policy.
        from release_gate.assurance.semantic_verifier import assertions_from_records
        self.semantic: Dict[str, List[Tuple[str, Any]]] = {}
        for eid, assertion in assertions_from_records(self.evidence.values()):
            self.semantic.setdefault(assertion.claim_id, []).append((eid, assertion))
        # Only a stated candidate: an implied one includes the input file, which
        # a replayed assertion changes (semantic_verifier.state_hash_for).
        self.candidate_digest = (binding.candidate.digest()
                                 if binding is not None and binding.candidate.explicit
                                 else "")

    # Records named on either side, from both directions of the link.
    def _linked(self, claim: Any) -> Tuple[List[Any], List[Any]]:
        support = list(dict.fromkeys(
            [e for e in claim.supporting_evidence if e in self.evidence]
            + [r.evidence_id for r in self.evidence.values()
               if claim.claim_id in getattr(r, "supports_claims", ())]))
        against = list(dict.fromkeys(
            [e for e in claim.contradicting_evidence if e in self.evidence]
            + [r.evidence_id for r in self.evidence.values()
               if claim.claim_id in getattr(r, "contradicts_claims", ())]))
        return [self.evidence[e] for e in support], [self.evidence[e] for e in against]

    def resolve(self, claim_id: str) -> ClaimResolution:
        if claim_id in self.done:
            return self.done[claim_id]
        claim = self.graph.claim(claim_id)
        if claim is None:
            return ClaimResolution(claim_id, "", ResolutionStatus.UNKNOWN, "CR-07",
                                   "this claim is depended on and is not in the case")
        if claim_id in self.stack:
            return ClaimResolution(claim_id, claim.statement, ResolutionStatus.UNKNOWN,
                                   "CR-07", "a dependency cycle reaches this claim; "
                                   "nothing in a cycle can be grounded")
        self.stack.add(claim_id)
        try:
            result = self._resolve(claim)
        finally:
            self.stack.discard(claim_id)
        self.done[claim_id] = result
        return result

    def _resolve(self, claim: Any) -> ClaimResolution:
        cid = claim.claim_id
        admissible = _admissible(claim)
        items: List[ResolvedItem] = []
        sources: Dict[str, SourceProvenance] = {}
        grade: List[Tuple[ResolvedItem, SourceProvenance]] = []

        support, against = self._linked(claim)
        for record in support:
            strength, method = _evidence_strength(record)
            binding = self.bindings.get(record.evidence_id)
            bound = binding.match.value if binding is not None else ""
            if binding is not None and binding.withholds_support:
                items.append(ResolvedItem(record.evidence_id, "evidence",
                                          ItemRole.WITHHELD_STATE, strength, method, bound,
                                          reason=binding.reason))
                continue
            if not _matches(admissible, method, record.evidence_type.value):
                items.append(ResolvedItem(
                    record.evidence_id, "evidence", ItemRole.NOT_ADMISSIBLE, strength,
                    method, bound, reason=(f"{record.evidence_type.value} is not among "
                                           "the evidence this claim declares admissible")))
                continue
            if record.trust_status in (TrustStatus.REJECTED, TrustStatus.REVOKED):
                items.append(ResolvedItem(record.evidence_id, "evidence",
                                          ItemRole.NOT_RELIED_UPON, strength, method, bound,
                                          reason=f"its source is {record.trust_status.value}"))
                continue
            provenance = self.provenance.of(record.evidence_id)
            item = ResolvedItem(record.evidence_id, "evidence", ItemRole.SUPPORTS,
                                strength, method, bound)
            items.append(item)
            if provenance is not None:
                sources[record.evidence_id] = provenance
                if strength in _VERIFICATION_GRADE:
                    grade.append((item, provenance))

        for record in against:
            if record.evidence_id in self.resolved_ids:
                items.append(ResolvedItem(record.evidence_id, "evidence", ItemRole.RESOLVED,
                                          reason="a resolution answers it"))
                continue
            binding = self.bindings.get(record.evidence_id)
            items.append(ResolvedItem(
                record.evidence_id, "evidence", ItemRole.CONTRADICTS,
                _evidence_strength(record)[0], binding=binding.match.value if binding else "",
                reason=("bound to another state of the candidate, and a refutation from "
                        "an earlier state still stands") if binding is not None
                and binding.match.value in ("STALE", "INCOMPATIBLE") else ""))

        from release_gate.assurance.verification import VerificationStatus
        for attempt in claim.verification_attempts:
            strength, method = _attempt_strength(attempt)
            binding = self.bindings.get(attempt.verification_id)
            bound = binding.match.value if binding is not None else ""
            vid = attempt.verification_id
            status = attempt.status
            if status is VerificationStatus.NOT_RUN:
                items.append(ResolvedItem(vid, "verification", ItemRole.NOT_RUN, strength,
                                          method, reason="expected and never ran"))
            elif status is VerificationStatus.INVALIDATED:
                items.append(ResolvedItem(vid, "verification", ItemRole.INVALIDATED,
                                          strength, method, reason="its result was retracted"))
            elif not attempt.relied_upon:
                items.append(ResolvedItem(
                    vid, "verification", ItemRole.NOT_RELIED_UPON, strength, method, bound,
                    reason=f"its verifier is {attempt.trust_status.value}"))
            elif status is VerificationStatus.FAILED:
                items.append(ResolvedItem(vid, "verification", ItemRole.FAILED_CHECK,
                                          strength, method, bound, reason=attempt.detail))
            elif status in (VerificationStatus.INCONCLUSIVE, VerificationStatus.UNKNOWN):
                items.append(ResolvedItem(vid, "verification", ItemRole.INCONCLUSIVE,
                                          strength, method, bound))
            elif status is VerificationStatus.PASSED:
                if binding is not None and binding.withholds_support:
                    items.append(ResolvedItem(vid, "verification", ItemRole.WITHHELD_STATE,
                                              strength, method, bound, reason=binding.reason))
                    continue
                if not _matches(admissible, method, attempt.method.value):
                    items.append(ResolvedItem(
                        vid, "verification", ItemRole.NOT_ADMISSIBLE, strength, method,
                        bound, reason=(f"{method} is not among the evidence this claim "
                                       "declares admissible")))
                    continue
                # What it cites or relied on is folded in: a review of a model's
                # summary is in the model's group.
                provenance = self.provenance.attempt_source(attempt)
                item = ResolvedItem(vid, "verification", ItemRole.SUPPORTS, strength,
                                    method, bound)
                items.append(item)
                sources[vid] = provenance
                if (strength in _VERIFICATION_GRADE
                        and attempt.method not in self.policy.non_establishing_methods):
                    grade.append((item, provenance))

        if self.counterexamples is not None:
            for found in self.counterexamples.attempts:
                if found.target_claim != cid:
                    continue
                ident = f"cex:{found.producer or 'unnamed'}:{found.detail[:40]}"
                if found.stands:
                    # An accepted risk still stands: the claim as stated is false,
                    # and accepting that is a decision about admission, not an
                    # answer to the counterexample (counterexample.assess_standing).
                    accepted = found.status.value == "ACCEPTED_RISK"
                    items.append(ResolvedItem(
                        ident, "counterexample", ItemRole.COUNTEREXAMPLE,
                        method=found.method.value,
                        reason=(f"accepted as a documented risk by {found.accepted_by} "
                                f"({found.reference}); the claim is still false"
                                if accepted else found.detail)))
                elif found.found:
                    items.append(ResolvedItem(ident, "counterexample", ItemRole.RESOLVED,
                                              method=found.method.value,
                                              reason=found.resolution or "resolved"))
                elif found.result.value == "NOT_FOUND":
                    items.append(ResolvedItem(
                        ident, "counterexample", ItemRole.SEARCHED_NOT_FOUND,
                        method=found.method.value,
                        reason=f"searched {found.search_bound}; a search that "
                               "found nothing does not prove absence"))

        # What a reading may corroborate: the records and checks that bear on the
        # claim on their own account. A reading citing none of them read nothing
        # this claim rests on, and cannot stand in for evidence.
        bearing = {i.item_id for i in items
                   if i.role in (ItemRole.SUPPORTS, ItemRole.INCONCLUSIVE)}
        corroboration = self._corroboration(cid, items, self.semantic.get(cid, ()))
        for eid, assertion in self.semantic.get(cid, ()):
            item, provenance = self._semantic_item(eid, assertion, bearing, corroboration)
            items.append(item)
            if item.role is ItemRole.SUPPORTS and provenance is not None:
                # Counted under the policy, and grouped like any source; never in
                # `grade`, so a model's reading cannot establish a claim.
                sources[eid] = provenance

        # Groups over every counted source, and over the verification-grade ones
        # that may establish. Items carry their group so the reader can see which
        # agreements are one source.
        independence = assess_independence(list(sources.values()), self.policy.independence)
        group_of = {m: g.group_id for g in independence.groups for m in g.members}
        items = [ResolvedItem(i.item_id, i.item_kind, i.role, i.strength, i.method,
                              i.binding, group_of.get(i.item_id, ""), i.reason)
                 if i.role is ItemRole.SUPPORTS else i for i in items]
        establishing = [(it, prov) for it, prov in grade
                        if it.strength in self.policy.establishing]
        grade_independence = assess_independence([p for _, p in establishing],
                                                 self.policy.independence)

        dependencies = tuple((d, self.resolve(d).status.value) for d in claim.depends_on)
        status, rule, basis = self._rule(claim, items, establishing, grade_independence,
                                         dependencies)
        required = (None if self.critical is None else cid in self.critical)
        return ClaimResolution(
            claim_id=cid, statement=claim.statement, status=status, rule=rule, basis=basis,
            required=required, items=tuple(items), independence=independence,
            dependencies=dependencies,
            claim_status=self.graph.status(cid).value if self.graph else "",
            establishing_independence=grade_independence, corroboration=corroboration)

    def _stale(self, assertion: Any) -> bool:
        stated = assertion.state_hash
        return bool(stated and self.candidate_digest and stated != self.candidate_digest)

    def _human_approval(self, item: ResolvedItem) -> bool:
        """A counted item that is a person's approval or review of the claim: a
        HUMAN_REVIEW check, or a record typed as an approval or a review whose
        producer is not declared to be an agent, a tool or release-gate."""
        if item.item_kind == "verification":
            return item.method.upper() == VerificationMethod.HUMAN_REVIEW.value
        record = self.evidence.get(item.item_id)
        if record is None:
            return False
        producer = getattr(getattr(record, "producer", None), "kind", None)
        return (getattr(record.evidence_type, "value", "") in ("APPROVAL", "HUMAN_REVIEW")
                and getattr(producer, "value", "") not in ("agent", "tool", "release_gate"))

    def _corroboration(self, cid: str, items: Sequence[ResolvedItem],
                       readings: Sequence[Tuple[str, Any]]
                       ) -> Optional[Dict[str, Any]]:
        """Which declared route, if any, corroborates a "supported" reading of `cid`.

        None when the policy declares no corroboration, the claim is outside its
        scope, or no current reading says supported: there is nothing to judge.
        """
        policy = self.policy.semantic_corroboration
        if policy is None:
            return None
        required = None if self.critical is None else cid in self.critical
        if policy.applies_to is EscalationScope.REQUIRED and required is not True:
            return None
        if (policy.applies_to is EscalationScope.REQUIRED_OR_UNDETERMINED
                and required is False):
            return None
        current = [(eid, a) for eid, a in readings
                   if a.answered and a.verdict is not None and not self._stale(a)
                   and not getattr(a, "injection_markers", ())]
        supported = [(eid, a) for eid, a in current if a.verdict.value == "supported"]
        if not supported:
            return None
        routes = set(policy.routes)
        R = CorroborationRoute
        own = [i for i in items if i.role is ItemRole.SUPPORTS and i.item_kind != "semantic"]
        met: List[str] = []
        if R.DETERMINISTIC_SUPPORT in routes and any(
                i.strength in _DETERMINISTIC for i in own):
            met.append(R.DETERMINISTIC_SUPPORT.value)
        if R.HUMAN_APPROVAL in routes and any(self._human_approval(i) for i in own):
            met.append(R.HUMAN_APPROVAL.value)
        groups, disagree = 0, sorted({a.verdict.value for _, a in current} - {"supported"})
        if R.INDEPENDENT_READINGS in routes:
            from release_gate.assurance.semantic_panel import reading_provenance
            readers = assess_independence([reading_provenance(eid, a) for eid, a in supported],
                                          policy.independence)
            groups = readers.independent_groups
            if groups >= policy.min_independent_readings and not disagree:
                met.append(R.INDEPENDENT_READINGS.value)
        missing = [r.value for r in policy.routes if r.value not in met]
        return {"met": bool(met), "routes_met": sorted(met), "routes_missing": missing,
                "supported_readings": len(supported), "independent_reader_groups": groups,
                "readings_disagreeing": disagree,
                "min_independent_readings": policy.min_independent_readings}

    def _semantic_item(self, eid: str, assertion: Any, bearing: Set[str],
                       corroboration: Optional[Mapping[str, Any]] = None
                       ) -> Tuple[ResolvedItem, Optional[SourceProvenance]]:
        """One semantic assertion as an item, under the policy. Never a decision."""
        method = "SEMANTIC_VERIFIER"
        stated = assertion.state_hash
        if stated and self.candidate_digest and stated != self.candidate_digest:
            return ResolvedItem(eid, "semantic", ItemRole.WITHHELD_STATE,
                                Strength.JUDGEMENT, method, "STALE",
                                reason="the reading was made against another state of "
                                       "the release"), None
        binding = "EXACT" if stated and stated == self.candidate_digest else ""
        if not assertion.answered:
            role = (ItemRole.SEMANTIC_NEEDS_VERIFICATION if assertion.requires_verification
                    else ItemRole.SEMANTIC_UNKNOWN)
            return ResolvedItem(eid, "semantic", role, Strength.JUDGEMENT, method, binding,
                                reason=f"{assertion.unknown_reason.value}: "
                                       f"{assertion.detail}"[:240]), None
        verdict = assertion.verdict.value
        if verdict == "supported" and getattr(assertion, "injection_markers", ()):
            # The verifier refuses this itself; a record made some other way is
            # refused here, so no route lets hostile evidence content count.
            return ResolvedItem(eid, "semantic", ItemRole.SEMANTIC_UNKNOWN,
                                Strength.JUDGEMENT, method, binding,
                                reason=("INJECTION_SUSPECTED: a supported reading of "
                                        "evidence that addresses its reader ("
                                        + ", ".join(assertion.injection_markers[:3])
                                        + ")")[:240]), None
        if verdict == "contradicted":
            return ResolvedItem(eid, "semantic", ItemRole.SEMANTIC_CHALLENGE,
                                Strength.JUDGEMENT, method, binding,
                                reason=assertion.reason[:240]), None
        if verdict == "insufficient_evidence":
            return ResolvedItem(eid, "semantic", ItemRole.SEMANTIC_INSUFFICIENT,
                                Strength.JUDGEMENT, method, binding,
                                reason=assertion.reason[:240]), None
        if self.policy.semantic_support is not SemanticSupport.COUNTS:
            return ResolvedItem(eid, "semantic", ItemRole.SEMANTIC_SUPPORT,
                                Strength.JUDGEMENT, method, binding,
                                reason="recorded; the resolution policy does not count "
                                       "a model's reading as support"), None
        if not set(assertion.evidence_refs) & bearing:
            return ResolvedItem(eid, "semantic", ItemRole.SEMANTIC_SUPPORT,
                                Strength.JUDGEMENT, method, binding,
                                reason="recorded; it cites nothing this claim rests on, "
                                       "and a reading corroborates evidence — it does "
                                       "not replace it"), None
        if corroboration is not None and not corroboration["met"]:
            return ResolvedItem(eid, "semantic", ItemRole.SEMANTIC_SUPPORT,
                                Strength.JUDGEMENT, method, binding,
                                reason=("recorded; uncorroborated on a critical claim: "
                                        "the corroboration policy asks for "
                                        + " or ".join(CorroborationRoute(r).described
                                                      for r in
                                                      corroboration["routes_missing"])
                                        )[:240]), None
        return (ResolvedItem(eid, "semantic", ItemRole.SUPPORTS, Strength.JUDGEMENT,
                             method, binding, reason=assertion.reason[:240]),
                self.provenance.of(eid))

    # The order. First match decides; nothing is weighed against anything.
    def _rule(self, claim: Any, items: Sequence[ResolvedItem],
              establishing: Sequence[Tuple[ResolvedItem, SourceProvenance]],
              grade_independence: IndependenceAssessment,
              dependencies: Tuple[Tuple[str, str], ...]
              ) -> Tuple[ResolutionStatus, str, str]:
        roles = [i.role for i in items]
        counted = [i for i in items if i.role is ItemRole.SUPPORTS]
        S = ResolutionStatus

        open_cex = [i for i in items if i.role is ItemRole.COUNTEREXAMPLE]
        if open_cex:
            return (S.CONTRADICTED, "CR-01",
                    f"{len(open_cex)} found counterexample(s) stand unanswered: "
                    f"{open_cex[0].reason or open_cex[0].item_id}. A counterexample "
                    f"outranks any amount of support ({len(counted)} item(s) here)")
        failed = [i for i in items if i.role is ItemRole.FAILED_CHECK]
        if failed:
            return (S.CONTRADICTED, "CR-02",
                    f"{len(failed)} check(s) ran and failed ({failed[0].method}); a "
                    "failed check is a refutation, and passes alongside it do not "
                    "cancel it")
        refuting = [i for i in items if i.role is ItemRole.CONTRADICTS]
        if refuting:
            return (S.CONTRADICTED, "CR-03",
                    f"{len(refuting)} record(s) contradict it and nothing resolves them; "
                    "support does not make a contradiction go away")
        contradicted_dep = [c for c, s in dependencies if s == S.CONTRADICTED.value]
        if contradicted_dep:
            return (S.CONTRADICTED, "CR-04",
                    f"it rests on {', '.join(contradicted_dep)}, which is contradicted")

        if not counted:
            own = [i.role for i in items if i.role is not ItemRole.NOT_RUN
                   and not _inert_reading(i)]
            if own:
                if any(r is ItemRole.INCONCLUSIVE for r in roles):
                    return (S.UNKNOWN, "CR-07",
                            "the only checks that bear on it reached no conclusion")
                set_aside = [i for i in items if i.role in _SET_ASIDE
                             and not _inert_reading(i)]
                semantic = [_SEMANTIC_GAPS[r] for r in own if r in _SEMANTIC_GAPS]
                why = (semantic[0] if semantic else set_aside[0].reason if set_aside else
                       "a search for a counterexample that found none is not support"
                       if ItemRole.SEARCHED_NOT_FOUND in roles
                       else "what bears on it was answered or set aside")
                return (S.UNSUPPORTED, "CR-06",
                        f"{len(own)} item(s) bear on it and none counts as support: {why}")
            if not dependencies:
                expected = sum(1 for r in roles if r is ItemRole.NOT_RUN)
                return (S.NOT_ASSESSED, "CR-05",
                        "nothing bears on it — no evidence, no check that ran"
                        + (f"; {expected} expected check(s) never ran" if expected else "")
                        + ". Not assessed is not passed")
            # A conclusion with nothing of its own, resting on its dependencies.
            # It follows from them at best as far as they go, and never to
            # ESTABLISHED: the step from premises to conclusion is not itself
            # checked by anything in the case.
            levels = [_LEVEL.get(ResolutionStatus(s), 0) for _, s in dependencies]
            weakest = [c for c, s in dependencies
                       if _LEVEL.get(ResolutionStatus(s), 0) == min(levels)]
            if min(levels) >= _LEVEL[S.SUPPORTED]:
                return (S.SUPPORTED, "CR-11",
                        f"it rests on {len(dependencies)} claim(s), all at least "
                        "supported; nothing bears on it directly, and the step from "
                        "them to it is not itself checked")
            if min(levels) >= _LEVEL[S.PARTIALLY_SUPPORTED]:
                return (S.PARTIALLY_SUPPORTED, "CR-11",
                        f"it rests on {', '.join(weakest)}, which is only partially "
                        "supported, and nothing bears on it directly")
            return (S.UNKNOWN, "CR-07",
                    f"it rests on {', '.join(weakest)}, which cannot settle it, and "
                    "nothing bears on it directly")

        # From here something counts. Gaps the claim itself names come first.
        # A counted reading (semantic_support: COUNTS) corroborates and never
        # closes a gap: it cannot be the method a claim requires, nor the support
        # that names the candidate. Otherwise one "supported", which hostile text
        # in the evidence can produce, would carry a claim to the admission level.
        evidence_counted = [i for i in counted if i.item_kind != "semantic"]
        gaps: List[str] = []
        if any(r is ItemRole.INCONCLUSIVE for r in roles):
            gaps.append("a check reached no conclusion")
        if any(r is ItemRole.NOT_RUN for r in roles):
            gaps.append("an expected check never ran")
        for role, why in _SEMANTIC_GAPS.items():
            if role in roles:
                gaps.append(why)
        requires = _required_methods(claim)
        if requires:
            have = {i.method.upper() for i in evidence_counted} | {
                (i.strength.value if i.strength else "") for i in evidence_counted}
            missing = [m for m in requires if m not in have]
            if missing:
                gaps.append(f"it requires {', '.join(missing)} and none counted")
        weak_dep = [c for c, s in dependencies
                    if _LEVEL.get(ResolutionStatus(s), 0) < _LEVEL[S.SUPPORTED]]
        if weak_dep:
            gaps.append(f"it rests on {', '.join(weak_dep)}, which is not supported")
        if self.explicit_candidate and counted and all(
                i.binding in ("", "UNKNOWN") for i in evidence_counted):
            gaps.append("none of its support names the candidate it is about")
        if gaps:
            return (S.PARTIALLY_SUPPORTED, "CR-08",
                    f"{len(counted)} item(s) count toward it, but " + "; ".join(gaps))

        deps_established = all(s == S.ESTABLISHED.value for _, s in dependencies)
        proof = [it for it, _ in establishing if it.strength is Strength.PROOF
                 and it.binding in ("EXACT", "PARTIAL")]
        if deps_established and self.policy.proof_establishes_alone and proof:
            return (S.ESTABLISHED, "CR-09",
                    f"a passed proof-carrying check bound to the candidate "
                    f"({proof[0].method}, {proof[0].binding})")
        # Groups the stated provenance separates. A source that states nothing
        # about what generated it is in no counted group, so it can neither
        # supply a group nor take one away.
        needed = self.policy.independence.min_independent_groups
        groups = grade_independence.independent_groups
        if deps_established and groups >= needed:
            return (S.ESTABLISHED, "CR-09",
                    f"passing checks from {groups} independent group(s) "
                    f"(the policy asks for {needed})")

        why: List[str] = []
        if not establishing:
            kinds = sorted({i.strength.value for i in counted if i.strength})
            why.append(f"its support is {', '.join(kinds) or 'unclassified'}, which the "
                       "policy does not accept as establishing")
        elif groups < needed:
            why.append(f"its checks form {groups} independent group(s) and the policy asks "
                       f"for {needed} ({grade_independence.status.value}: "
                       f"{grade_independence.basis})")
        if not deps_established:
            why.append("not every dependency is established")
        return (S.SUPPORTED, "CR-10", f"{len(counted)} item(s) count toward it; "
                + "; ".join(why or ["the policy's establishing rule is not met"]))


def policy_for_case(case: Any) -> ResolutionPolicy:
    """The policy a case declares, or the built-in one. Never silently a third."""
    stored = (getattr(case, "metadata", None) or {}).get(POLICY_METADATA_KEY)
    if isinstance(stored, Mapping):
        return ResolutionPolicy.from_dict(stored)
    return DEFAULT_RESOLUTION_POLICY


def resolve_claims(claim_graph: Any, *, records: Iterable[Any] = (),
                   counterexamples: Any = None, criticality: Any = None,
                   policy: ResolutionPolicy = DEFAULT_RESOLUTION_POLICY
                   ) -> ClaimResolutionReport:
    """Resolve every claim in the graph, in a stable order."""
    if claim_graph is None or not claim_graph.claims:
        return ClaimResolutionReport(policy=policy, notes=(
            "no claims were stated, so no claim could be resolved",))
    resolver = _Resolver(claim_graph, counterexamples=counterexamples,
                         criticality=criticality, records=list(records), policy=policy)
    resolutions = tuple(resolver.resolve(c.claim_id) for c in claim_graph.claims)
    determinable = resolver.critical is not None
    notes: Tuple[str, ...] = () if determinable else (
        "which claims the decision rests on could not be determined, so no claim is "
        "marked required",)
    return ClaimResolutionReport(resolutions=resolutions, policy=policy,
                                 criticality_determinable=determinable, notes=notes)
