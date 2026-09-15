"""The required-evidence protocol — HOLD as something a machine can act on.

A HOLD that says "insufficient evidence" is a shrug. A HOLD that says

```json
{"target": "claim:C-184",
 "requirement": "independent_verification",
 "reason": "critical single-lineage dependency"}
```

is a work order: an external verifier can read it, decide whether it is able to
produce that, produce it, and submit it back. That loop — agents, Release-Gate,
required evidence, external verifiers, new evidence, Release-Gate — is what makes
autonomous work auditable without a human in the middle of every cycle.

Three things have to be typed for that to work at all, and all three were prose
before this module existed.

**What to act on.** A `target` is addressable — `claim:C-184`, `artifact:A-22` —
not a sentence. Requirements are therefore grouped by *(target, kind)*, not by the
text of a remedy: two claims needing independent verification are two requirements,
because a verifier can act on one and not the other, and collapsing them into
"verify the claims" is a sentence nobody can dispatch.

**What kind of evidence is wanted.** A closed vocabulary, so a consumer can switch
on it. Where a gap is real but nothing in the vocabulary names what would close
it, the answer is `unspecified` with the prose intact — never a nearby kind
chosen to look tidy (Invariant 3).

**What would count.** `constraints` carry the checkable part: which lineages the
new evidence must be independent of, which digest it must apply to, which method
family would satisfy it. Without them "independent verification" is advice.

Two boundaries this module holds.

**Release-Gate does not orchestrate.** There is no assignee, no priority, no
deadline, no scheduling, no callback, and no agent selection anywhere in the
protocol — and a test asserts the serialised form contains none of those keys, so
the boundary survives its author. Release-Gate says what would resolve what,
addressed to nobody. Who does the work, in what order, and whether at all, is
somebody else's authority.

**Satisfying every requirement does not yield PROMOTE.** `satisfies_decision` is
`False` unconditionally. The list is what would close the gaps *release-gate can
see*; sufficiency belongs to a methodology, and where none is stated the question
is not merely unanswered but unanswerable (Invariant 15). A protocol whose
completion implied authorisation would let an external system grind out evidence
until the gate opened, which is the exact inversion of an assurance boundary.

And one honesty rule about the return leg. Evidence produced *in response to* a
requirement was produced by a party told exactly what would close the gate. That
does not make it false and does not make it dependent — but it is a motive, and
motive is provenance. `in_response_to` is recorded on the way back in and is
never laundered out (Invariants 1 and 11).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.records import MaterialisationBasis
from release_gate.assurance.verification import TargetKind, VerificationTarget

__all__ = [
    "REQUIRED_EVIDENCE_SCHEMA_VERSION",
    "EvidenceRequirement",
    "EvidenceRequirementKind",
    "requirement_kind_for",
    "requirement_kind_for_predicate",
]

REQUIRED_EVIDENCE_SCHEMA_VERSION = 1

#: How many targets one rule may expand into before the rest are counted rather
#: than listed. A case with three hundred load-bearing claims resting on one
#: producer genuinely has three hundred requirements; what it does not need is an
#: unbounded payload, so the remainder is declared rather than dropped silently.
_TARGETS_PER_RULE = 200


class EvidenceRequirementKind(str, Enum):
    """What kind of evidence would close a gap.

    Closed, and lower-case because these values travel over the wire to systems
    that switch on them. Kind selects nothing inside release-gate: it is the
    dispatch surface for whoever is going to produce the evidence.
    """

    INDEPENDENT_VERIFICATION = "independent_verification"
    FORMAL_VERIFICATION = "formal_verification"
    RE_VERIFICATION = "re_verification"
    REPLICATION = "replication"
    COUNTEREXAMPLE_SEARCH = "counterexample_search"
    ADVERSARIAL_REVIEW = "adversarial_review"
    CONTRADICTION_RESOLUTION = "contradiction_resolution"
    ASSUMPTION_VERIFICATION = "assumption_verification"
    PROVENANCE_ATTESTATION = "provenance_attestation"
    CAPABILITY_DECLARATION = "capability_declaration"
    CONSEQUENCE_DECLARATION = "consequence_declaration"
    EXPECTATION_DECLARATION = "expectation_declaration"
    DEPENDENCY_DECLARATION = "dependency_declaration"
    MISSING_EVIDENCE = "missing_evidence"
    METHODOLOGY_DECLARATION = "methodology_declaration"
    HUMAN_REVIEW = "human_review"
    #: A gap release-gate can see and cannot name a closer for. Kept as its own
    #: value rather than mapped to something adjacent: a consumer that cannot
    #: dispatch on it should be told so, not handed a plausible wrong type.
    UNSPECIFIED = "unspecified"


_K = EvidenceRequirementKind

#: Rule → what would close it. Every rule in the analyser has an entry; a rule
#: with none falls to `unspecified`, which is honest but useless to a consumer,
#: so the table is tested for completeness rather than trusted.
_RULE_KIND: Mapping[str, EvidenceRequirementKind] = {
    "RG-PROV-001": _K.PROVENANCE_ATTESTATION,
    "RG-PROV-002": _K.INDEPENDENT_VERIFICATION,
    "RG-PROV-003": _K.PROVENANCE_ATTESTATION,
    "RG-VERIF-001": _K.FORMAL_VERIFICATION,
    "RG-VERIF-002": _K.CONTRADICTION_RESOLUTION,
    "RG-VERIF-003": _K.RE_VERIFICATION,
    "RG-VERIF-004": _K.RE_VERIFICATION,
    "RG-VERIF-005": _K.RE_VERIFICATION,
    "RG-VERIF-006": _K.RE_VERIFICATION,
    "RG-VERIF-007": _K.FORMAL_VERIFICATION,
    "RG-INDEP-001": _K.INDEPENDENT_VERIFICATION,
    "RG-INDEP-002": _K.INDEPENDENT_VERIFICATION,
    "RG-INDEP-003": _K.PROVENANCE_ATTESTATION,
    "RG-INDEP-004": _K.PROVENANCE_ATTESTATION,
    "RG-EXPECT-001": _K.MISSING_EVIDENCE,
    "RG-EXPECT-002": _K.EXPECTATION_DECLARATION,
    "RG-EXPECT-003": _K.EXPECTATION_DECLARATION,
    "RG-EXPECT-004": _K.EXPECTATION_DECLARATION,
    "RG-EXPECT-005": _K.EXPECTATION_DECLARATION,
    "RG-CRIT-001": _K.DEPENDENCY_DECLARATION,
    "RG-CRIT-002": _K.DEPENDENCY_DECLARATION,
    "RG-CRIT-003": _K.DEPENDENCY_DECLARATION,
    "RG-CRIT-004": _K.DEPENDENCY_DECLARATION,
    "RG-CRIT-005": _K.INDEPENDENT_VERIFICATION,
    "RG-ADV-001": _K.ADVERSARIAL_REVIEW,
    "RG-ADV-002": _K.ADVERSARIAL_REVIEW,
    "RG-ADV-003": _K.HUMAN_REVIEW,
    "RG-ADV-004": _K.ADVERSARIAL_REVIEW,
    "RG-ADV-005": _K.ADVERSARIAL_REVIEW,
    "RG-ADV-006": _K.ADVERSARIAL_REVIEW,
    "RG-ADV-007": _K.ADVERSARIAL_REVIEW,
    "RG-REPL-001": _K.REPLICATION,
    "RG-REPL-002": _K.REPLICATION,
    "RG-REPL-003": _K.REPLICATION,
    "RG-REPL-004": _K.REPLICATION,
    "RG-REPL-005": _K.REPLICATION,
    "RG-REPL-006": _K.PROVENANCE_ATTESTATION,
    "RG-ASSUME-001": _K.ASSUMPTION_VERIFICATION,
    "RG-ASSUME-002": _K.ASSUMPTION_VERIFICATION,
    "RG-CEX-001": _K.COUNTEREXAMPLE_SEARCH,
    "RG-CEX-002": _K.COUNTEREXAMPLE_SEARCH,
    "RG-CEX-003": _K.COUNTEREXAMPLE_SEARCH,
    "RG-BRANCH-001": _K.HUMAN_REVIEW,
    "RG-BRANCH-002": _K.MISSING_EVIDENCE,
    "RG-BRANCH-003": _K.MISSING_EVIDENCE,
    "RG-CONTRA-002": _K.CONTRADICTION_RESOLUTION,
    "RG-CONTRA-003": _K.CONTRADICTION_RESOLUTION,
    "RG-CONTRA-004": _K.CONTRADICTION_RESOLUTION,
    "RG-CONTRA-005": _K.CONTRADICTION_RESOLUTION,
    "RG-DRIFT-001": _K.RE_VERIFICATION,
    "RG-DRIFT-002": _K.PROVENANCE_ATTESTATION,
    "RG-DRIFT-003": _K.RE_VERIFICATION,
    "RG-DRIFT-004": _K.PROVENANCE_ATTESTATION,
    "RG-DRIFT-005": _K.PROVENANCE_ATTESTATION,
    "RG-COV-001": _K.MISSING_EVIDENCE,
    "RG-COV-002": _K.MISSING_EVIDENCE,
    "RG-COV-003": _K.FORMAL_VERIFICATION,
    "RG-COV-004": _K.EXPECTATION_DECLARATION,
    "RG-COV-005": _K.MISSING_EVIDENCE,
    "RG-CAP-001": _K.CAPABILITY_DECLARATION,
    "RG-CAP-002": _K.CAPABILITY_DECLARATION,
    "RG-CAP-003": _K.CAPABILITY_DECLARATION,
    "RG-CAP-004": _K.CAPABILITY_DECLARATION,
    "RG-CAP-005": _K.CAPABILITY_DECLARATION,
    "RG-CAP-006": _K.HUMAN_REVIEW,
    "RG-CAP-007": _K.HUMAN_REVIEW,
    "RG-CONS-001": _K.CONSEQUENCE_DECLARATION,
    "RG-CONS-002": _K.CONSEQUENCE_DECLARATION,
    "RG-CONS-003": _K.CONSEQUENCE_DECLARATION,
    "RG-CONS-004": _K.HUMAN_REVIEW,
    "RG-CONS-005": _K.CONSEQUENCE_DECLARATION,
    "RG-ZC-001": _K.METHODOLOGY_DECLARATION,
}

#: Focus kind → addressable target kind. Derived from `attention._FOCUS_KIND`
#: rather than maintained separately: that table already says, for every rule,
#: what kind of thing a reviewer should open, it is already tested for
#: completeness, and two tables answering the same question would drift until one
#: of them sent a verifier to the wrong object.
_FOCUS_TARGET: Mapping[str, TargetKind] = {
    "claim": TargetKind.CLAIM,
    "evidence": TargetKind.EVIDENCE,
    "artifact": TargetKind.ARTIFACT,
    "capability": TargetKind.CAPABILITY,
    "verification": TargetKind.VERIFICATION,
    "counterexample": TargetKind.COUNTEREXAMPLE,
    "adversarial_finding": TargetKind.ADVERSARIAL_FINDING,
    "assumption": TargetKind.ASSUMPTION,
    "contradiction": TargetKind.CONTRADICTION,
    "coverage_dimension": TargetKind.COVERAGE_DIMENSION,
    "requirement": TargetKind.METHODOLOGY,
    "subject": TargetKind.SUBJECT,
    "execution": TargetKind.EXECUTION,
}


def target_kind_for_focus(focus_kind: str) -> TargetKind:
    """What kind of thing this focus names, or CASE where it names the situation.

    A finding whose focus is the whole case — "all your evidence has one
    producer" — is not fixed by opening one record, and pointing a verifier at an
    arbitrary id would send it to do the wrong work. Those become `case:` targets,
    exactly as attention refuses to point a reviewer at one of them.
    """
    return _FOCUS_TARGET.get(focus_kind, TargetKind.CASE)


#: Methodology predicate → what would satisfy it. A methodology HOLD is the most
#: common HOLD there is, so it should be the most dispatchable: "this decision
#: requires independent ancestry" is actionable only if a consumer can read off
#: that what is wanted is an independent verification.
_PREDICATE_KIND: Mapping[str, EvidenceRequirementKind] = {
    "collection_supplied": _K.MISSING_EVIDENCE,
    "minimum_records": _K.MISSING_EVIDENCE,
    "subject_identified": _K.PROVENANCE_ATTESTATION,
    "verification_present": _K.FORMAL_VERIFICATION,
    "independence_threshold": _K.INDEPENDENT_VERIFICATION,
    "ancestry_independence": _K.INDEPENDENT_VERIFICATION,
    "no_unresolved": _K.CONTRADICTION_RESOLUTION,
    "no_claim_in_status": _K.CONTRADICTION_RESOLUTION,
    "record_field_required": _K.PROVENANCE_ATTESTATION,
    "coverage_dimension_declared": _K.EXPECTATION_DECLARATION,
    "expectation_declared": _K.EXPECTATION_DECLARATION,
    "consequence_declared": _K.CONSEQUENCE_DECLARATION,
    "adversarial_review_required": _K.ADVERSARIAL_REVIEW,
    "replication_established": _K.REPLICATION,
    "assumptions_examined": _K.ASSUMPTION_VERIFICATION,
    "critical_claims_identified": _K.DEPENDENCY_DECLARATION,
    "critical_claims_verified": _K.FORMAL_VERIFICATION,
    "declared_independence_holds": _K.PROVENANCE_ATTESTATION,
    "applies_to_current_state": _K.RE_VERIFICATION,
}


def requirement_kind_for_predicate(predicate_kind: str) -> EvidenceRequirementKind:
    """What would satisfy this predicate, or `unspecified` where nothing names it.

    An unmapped predicate — an organisation's own, arriving through the API —
    degrades to `unspecified` with its prose intact rather than to a nearby kind
    chosen to look tidy. Guessing what satisfies somebody else's yardstick is
    exactly the invention this system refuses.
    """
    return _PREDICATE_KIND.get(predicate_kind, EvidenceRequirementKind.UNSPECIFIED)


def requirement_kind_for(rule_id: str) -> EvidenceRequirementKind:
    """What would close this rule's gap, or `unspecified` if nothing names it."""
    return _RULE_KIND.get(rule_id, EvidenceRequirementKind.UNSPECIFIED)


def target_kind_for(rule_id: str) -> TargetKind:
    return _RULE_TARGET.get(rule_id, TargetKind.CASE)


@dataclass(frozen=True)
class EvidenceRequirement:
    """One addressable thing an external system could produce.

    The three fields the protocol promises — `target`, `requirement`, `reason` —
    are the contract. Everything else is there to make acting on it possible:
    what would count, what it would resolve, and whether supplying it can later
    be undone.
    """

    target: VerificationTarget
    requirement: EvidenceRequirementKind = EvidenceRequirementKind.UNSPECIFIED
    reason: str = ""
    effect: RequirementEffect = RequirementEffect.HOLD
    constraints: Mapping[str, Any] = field(default_factory=dict)
    acceptance: str = ""
    resolves: Tuple[str, ...] = ()
    monotone: bool = True
    detail: str = ""
    schema_version: int = REQUIRED_EVIDENCE_SCHEMA_VERSION

    requirement_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "requirement",
                           EvidenceRequirementKind(self.requirement))
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "resolves", tuple(sorted(set(self.resolves))))
        object.__setattr__(self, "constraints", dict(self.constraints or {}))
        object.__setattr__(self, "requirement_id",
                           short_id("req", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct ask. Stable across runs, so the return leg
        can cite it."""
        return {"schema_version": REQUIRED_EVIDENCE_SCHEMA_VERSION,
                "target": self.target.reference,
                "requirement": self.requirement.value,
                "constraints": dict(self.constraints)}

    @property
    def dispatchable(self) -> bool:
        """Whether a consumer can switch on this.

        `unspecified` is not dispatchable, and saying so is the point: a gap
        nobody can name a closer for should not look like work somebody can pick
        up.
        """
        return self.requirement is not EvidenceRequirementKind.UNSPECIFIED

    @property
    def record_type(self) -> str:
        return "required_evidence"

    @property
    def record_id(self) -> str:
        return self.requirement_id

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "required_evidence",
                "record_id": self.requirement_id,
                # The protocol's three, exactly as named on the wire.
                "target": self.target.reference,
                "requirement": self.requirement.value,
                "reason": self.reason,
                # What acting on it involves.
                "requirement_id": self.requirement_id,
                "effect": self.effect.value,
                "constraints": dict(self.constraints),
                "acceptance": self.acceptance,
                "resolves": list(self.resolves),
                "monotone": self.monotone,
                "dispatchable": self.dispatchable,
                "detail": self.detail,
                "schema_version": REQUIRED_EVIDENCE_SCHEMA_VERSION}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRequirement":
        return cls(
            target=VerificationTarget.parse(str(data.get("target") or "")),
            requirement=EvidenceRequirementKind(
                str(data.get("requirement") or "unspecified").lower()),
            reason=str(data.get("reason") or ""),
            effect=RequirementEffect(str(data.get("effect") or "HOLD").upper()),
            constraints=data.get("constraints") or {},
            acceptance=str(data.get("acceptance") or ""),
            resolves=tuple(data.get("resolves") or ()),
            monotone=bool(data.get("monotone", True)),
            detail=str(data.get("detail") or ""))

    def render(self) -> str:
        line = f"{self.target.reference} needs {self.requirement.value}: {self.reason}"
        if self.constraints:
            line += "\n    constraints: " + ", ".join(
                f"{k}={v}" for k, v in sorted(self.constraints.items()))[:300]
        if self.acceptance:
            line += f"\n    accepted when: {self.acceptance}"
        if not self.monotone:
            line += ("\n    note: supplying this can be undone by evidence that has "
                     "not arrived yet")
        return line


#: What would count, per kind. Stated once so every requirement of a kind says the
#: same thing, and so a consumer reading two cases gets the same contract.
_ACCEPTANCE: Mapping[EvidenceRequirementKind, str] = {
    _K.INDEPENDENT_VERIFICATION:
        "a verification attempt on this target whose independence_lineage is "
        "disjoint from the lineages already supporting it",
    _K.FORMAL_VERIFICATION:
        "a typed verification attempt on this target — a proof, a test run, a "
        "model check — carrying the digest it ran against",
    _K.RE_VERIFICATION:
        "a verification attempt whose target_digest equals the target's current "
        "content, so applicability is computable rather than assumed",
    _K.REPLICATION:
        "a result on this target from a path that differs in method, "
        "implementation, input or lineage from the one already recorded",
    _K.COUNTEREXAMPLE_SEARCH:
        "a counterexample attempt against this claim, stating the space searched; "
        "an empty search bounds the search and never the claim",
    _K.ADVERSARIAL_REVIEW:
        "an adversarial finding against this target from an adversary whose "
        "lineage is disjoint from the party that produced the target's support",
    _K.CONTRADICTION_RESOLUTION:
        "a resolution citing the evidence that answers it; a contradiction is "
        "closed by evidence, never by assertion that it is closed",
    _K.ASSUMPTION_VERIFICATION:
        "evidence or a verification bearing on this assumption, or a restatement "
        "of what it actually asserts",
    _K.PROVENANCE_ATTESTATION:
        "a record establishing where this came from — parent_evidence, a digest, "
        "or an authenticated producer identity",
    _K.CAPABILITY_DECLARATION:
        "a manifest declaring this capability, or evidence establishing why the "
        "system reached it",
    _K.CONSEQUENCE_DECLARATION:
        "a consequence descriptor for the dimensions this decision turns on",
    _K.EXPECTATION_DECLARATION:
        "a denominator for this dimension from a party other than the one that "
        "produced the evidence being counted",
    _K.DEPENDENCY_DECLARATION:
        "the dependency edges connecting this to what the decision is being asked "
        "about, or an is_root marking on the conclusion",
    _K.MISSING_EVIDENCE:
        "the evidence that was expected and did not arrive, or a record of why "
        "the expectation no longer applies",
    _K.METHODOLOGY_DECLARATION:
        "a methodology stating what evidence this class of decision requires",
    _K.HUMAN_REVIEW:
        "a person's judgement, recorded as evidence with the reviewer named",
    _K.UNSPECIFIED:
        "release-gate cannot say what would close this; the prose reason is all "
        "there is",
}


def acceptance_for(kind: EvidenceRequirementKind) -> str:
    return _ACCEPTANCE.get(kind, _ACCEPTANCE[EvidenceRequirementKind.UNSPECIFIED])
