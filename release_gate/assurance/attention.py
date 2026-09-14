"""Human attention and required evidence.

Two questions a person actually has, answered separately.

**What must I look at?** Not "here are forty findings" — a reviewer does not
inspect findings, they inspect *things*: a claim, an artifact, a producer, the
input itself. So attention items are keyed by the thing to inspect and carry
`leverage`: how many open findings looking at that one thing would settle.
Forty findings across three claims is three items, not forty. That is what makes
"the smallest number of things a human must inspect" a computation rather than a
slogan.

**What would let this proceed?** Required evidence is the other direction: the
named, checkable things whose arrival would resolve a hold. It is deliberately
not a promise that supplying them yields PROMOTE — sufficiency belongs to a
methodology, and where none is stated the honest answer is that the question
cannot be closed at all.

Neither set is a verdict, and neither claims completeness. Both are ordered
deterministically so two runs over the same case produce the same list in the
same order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.analysis import AnalysisDomain, AnalysisResult, Finding
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.required_evidence import (
    EvidenceRequirement, EvidenceRequirementKind, acceptance_for,
    requirement_kind_for, requirement_kind_for_predicate, target_kind_for_focus)
from release_gate.assurance.verification import TargetKind, VerificationTarget
from release_gate.assurance.methodology import (
    AssessmentStatus, MethodologyAssessment, RequirementEffect, RequirementOutcome,
)

__all__ = [
    "AttentionCriticality",
    "AttentionItem",
    "AttentionRanking",
    "AttentionReason",
    "ConsequenceWeight",
    "RequirementPressure",
    "HumanAttentionSet",
    "EvidenceRequirement",
    "EvidenceRequirementKind",
    "RequiredEvidenceItem",
    "RequiredEvidenceSet",
    "build_attention",
    "build_required_evidence",
]

# Ordering: what a person should look at first when everything is shouting.
_EFFECT_RANK = {RequirementEffect.BLOCK: 0, RequirementEffect.HOLD: 1,
                RequirementEffect.ADVISORY: 2}

# Which rules point at a thing worth inspecting, and what kind of thing it is.
_FOCUS_KIND = {
    "RG-PROV-001": "producer", "RG-PROV-002": "producer",
    "RG-PROV-003": "evidence",
    "RG-VERIF-001": "case", "RG-VERIF-002": "claim", "RG-VERIF-003": "claim",
    "RG-CONTRA-001": "evidence", "RG-CONTRA-002": "claim",
    "RG-CONTRA-003": "claim", "RG-CONTRA-004": "claim",
    "RG-CONTRA-005": "contradiction",
    "RG-ASSUME-001": "assumption", "RG-ASSUME-002": "assumption",
    "RG-CEX-001": "counterexample", "RG-CEX-002": "counterexample",
    "RG-CEX-003": "counterexample",
    "RG-BRANCH-001": "failure_point", "RG-BRANCH-002": "case",
    "RG-BRANCH-003": "case",
    "RG-DRIFT-001": "subject", "RG-DRIFT-002": "subject",
    "RG-DRIFT-003": "artifact", "RG-DRIFT-004": "artifact", "RG-DRIFT-005": "evidence",
    "RG-COV-001": "input", "RG-COV-002": "input", "RG-COV-003": "claim",
    "RG-COV-004": "execution", "RG-COV-005": "case",
    "RG-CAP-001": "manifest", "RG-CAP-002": "tools", "RG-CAP-003": "case",
    "RG-CAP-004": "case", "RG-CAP-005": "case", "RG-CAP-006": "capability",
    "RG-CAP-007": "capability",
    "RG-CONS-001": "case", "RG-CONS-002": "stakes", "RG-CONS-003": "stakes",
    "RG-CONS-004": "stakes", "RG-CONS-005": "stakes",
    "RG-REPL-001": "claim", "RG-REPL-002": "claim", "RG-REPL-003": "case",
    "RG-REPL-004": "case", "RG-REPL-005": "case", "RG-REPL-006": "case",
    # Adversarial findings key on the finding itself: a reviewer opens the attack
    # and its evidence, not the claim in the abstract.
    "RG-ADV-001": "adversarial_finding", "RG-ADV-002": "adversarial_finding",
    "RG-ADV-003": "adversarial_finding", "RG-ADV-004": "adversarial_finding",
    "RG-ADV-005": "case", "RG-ADV-006": "case", "RG-ADV-007": "case",
    # Every rule needs an entry. A rule with none falls through to "case", which
    # is sometimes right and sometimes points a reviewer at the whole case when
    # one claim was the problem — and eighteen rules were doing exactly that,
    # including every criticality and expectation rule.
    "RG-CRIT-001": "case", "RG-CRIT-002": "claim", "RG-CRIT-003": "claim",
    "RG-CRIT-004": "claim", "RG-CRIT-005": "claim",
    "RG-EXPECT-001": "coverage_dimension", "RG-EXPECT-002": "case",
    "RG-EXPECT-003": "coverage_dimension", "RG-EXPECT-004": "coverage_dimension",
    "RG-EXPECT-005": "coverage_dimension",
    "RG-INDEP-001": "case", "RG-INDEP-002": "case", "RG-INDEP-003": "case",
    "RG-INDEP-004": "evidence",
    "RG-VERIF-004": "claim", "RG-VERIF-005": "verification",
    "RG-VERIF-006": "verification", "RG-VERIF-007": "verification",
}


class AttentionReason(str, Enum):
    """Why this needs a person rather than another check."""

    REFUTED = "REFUTED"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    CONTRADICTION = "CONTRADICTION"
    SUBJECT_CHANGED = "SUBJECT_CHANGED"
    STALE_VERIFICATION = "STALE_VERIFICATION"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_CORROBORATED = "NOT_CORROBORATED"
    COVERAGE_GAP = "COVERAGE_GAP"
    UNDECLARED_CAPABILITY = "UNDECLARED_CAPABILITY"
    UNIDENTIFIED_TOOL = "UNIDENTIFIED_TOOL"
    CONSEQUENCE_UNSTATED = "CONSEQUENCE_UNSTATED"
    CONSEQUENCE_DISPUTED = "CONSEQUENCE_DISPUTED"
    UNRESOLVED_DISAGREEMENT = "UNRESOLVED_DISAGREEMENT"
    UNEXAMINED_ASSUMPTION = "UNEXAMINED_ASSUMPTION"
    LIVE_COUNTEREXAMPLE = "LIVE_COUNTEREXAMPLE"
    RECURRING_FAILURE = "RECURRING_FAILURE"
    METHODOLOGY_ABSENT = "METHODOLOGY_ABSENT"
    REQUIREMENT_UNMET = "REQUIREMENT_UNMET"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    ADVERSARIAL_FINDING = "ADVERSARIAL_FINDING"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    SELF_CLEARED = "SELF_CLEARED"
    APPROVAL_MISMATCH = "APPROVAL_MISMATCH"
    UNKNOWN_PROVENANCE = "UNKNOWN_PROVENANCE"
    # Evidence that was expected and did not arrive. Distinct from a coverage
    # gap: nobody looking is not the same as looking and finding a hole where
    # something was promised (Invariant 13).
    EVIDENCE_KNOWN_MISSING = "EVIDENCE_KNOWN_MISSING"
    SELECTIVE_EVIDENCE = "SELECTIVE_EVIDENCE"
    CONSEQUENTIAL_ACTION = "CONSEQUENTIAL_ACTION"
    CRITICALITY_UNDETERMINED = "CRITICALITY_UNDETERMINED"


_DOMAIN_REASON = {
    AnalysisDomain.CRITICALITY: AttentionReason.CRITICALITY_UNDETERMINED,
    AnalysisDomain.EXPECTATION: AttentionReason.EVIDENCE_KNOWN_MISSING,
    AnalysisDomain.CONTRADICTION: AttentionReason.CONTRADICTION,
    AnalysisDomain.VERIFICATION: AttentionReason.FAILED_VERIFICATION,
    AnalysisDomain.PROVENANCE: AttentionReason.NOT_CORROBORATED,
    AnalysisDomain.DRIFT: AttentionReason.STALE_VERIFICATION,
    AnalysisDomain.COVERAGE: AttentionReason.COVERAGE_GAP,
    AnalysisDomain.CAPABILITY: AttentionReason.UNDECLARED_CAPABILITY,
    AnalysisDomain.CONSEQUENCE: AttentionReason.CONSEQUENCE_UNSTATED,
    AnalysisDomain.ASSUMPTION: AttentionReason.UNEXAMINED_ASSUMPTION,
    AnalysisDomain.COUNTEREXAMPLE: AttentionReason.LIVE_COUNTEREXAMPLE,
    AnalysisDomain.FAILED_BRANCH: AttentionReason.RECURRING_FAILURE,
    AnalysisDomain.REPLICATION: AttentionReason.NOT_REPRODUCED,
    AnalysisDomain.ADVERSARIAL: AttentionReason.ADVERSARIAL_FINDING,
}

_RULE_REASON = {
    "RG-CONTRA-002": AttentionReason.REFUTED,
    "RG-VERIF-001": AttentionReason.NOT_VERIFIED,
    "RG-VERIF-002": AttentionReason.FAILED_VERIFICATION,
    "RG-DRIFT-001": AttentionReason.SUBJECT_CHANGED,
    "RG-DRIFT-002": AttentionReason.SUBJECT_CHANGED,
    "RG-CAP-002": AttentionReason.UNIDENTIFIED_TOOL,
    "RG-CONS-002": AttentionReason.CONSEQUENCE_DISPUTED,
    "RG-CONS-003": AttentionReason.CONSEQUENCE_DISPUTED,
    "RG-CONTRA-005": AttentionReason.UNRESOLVED_DISAGREEMENT,
    "RG-REPL-001": AttentionReason.UNRESOLVED_DISAGREEMENT,
    "RG-REPL-002": AttentionReason.UNRESOLVED_DISAGREEMENT,
    # An accepted risk and a self-cleared finding are distinct things to look at,
    # and neither reads correctly as a generic adversarial finding: the first asks
    # the authorizer to confirm what is being accepted on their behalf, the second
    # asks whether the answer came from a party entitled to give it.
    "RG-ADV-003": AttentionReason.ACCEPTED_RISK,
    "RG-ADV-004": AttentionReason.SELF_CLEARED,
    "RG-CRIT-001": AttentionReason.CRITICALITY_UNDETERMINED,
    "RG-CRIT-002": AttentionReason.CRITICALITY_UNDETERMINED,
    "RG-CRIT-005": AttentionReason.NOT_CORROBORATED,
    "RG-EXPECT-001": AttentionReason.EVIDENCE_KNOWN_MISSING,
    "RG-EXPECT-003": AttentionReason.EVIDENCE_KNOWN_MISSING,
    "RG-EXPECT-005": AttentionReason.SELECTIVE_EVIDENCE,
    "RG-PROV-002": AttentionReason.UNKNOWN_PROVENANCE,
    "RG-CONS-004": AttentionReason.CONSEQUENTIAL_ACTION,
    "RG-CONS-005": AttentionReason.CONSEQUENTIAL_ACTION,
    "RG-DRIFT-004": AttentionReason.APPROVAL_MISMATCH,
}


class AttentionCriticality(str, Enum):
    """Whether the decision rests on what this item is about.

    `UNDETERMINED` deliberately ranks *above* `OFF_PATH`. Not knowing whether
    something bears on the decision is a reason to look at it, and the natural
    implementation — sorting unknowns to the bottom with the unimportant — is how
    a case whose criticality could not be derived comes to look calm
    (Invariant 3).
    """

    ON_CRITICAL_PATH = "ON_CRITICAL_PATH"  # the decision rests on this
    UNDETERMINED = "UNDETERMINED"          # whether it bears on the decision is unknown
    SUPPORTING = "SUPPORTING"              # other claims rest on it; no conclusion does
    OFF_PATH = "OFF_PATH"                  # nothing the decision needs touches it


class RequirementPressure(str, Enum):
    """Whether an unresolved assurance requirement turns on this item."""

    BLOCKS = "BLOCKS"              # a requirement whose effect is BLOCK names it
    HOLDS = "HOLDS"                # a requirement whose effect is HOLD names it
    UNASSESSED = "UNASSESSED"      # a requirement could not be evaluated over it
    NONE = "NONE"                  # no unresolved requirement names it


class ConsequenceWeight(str, Enum):
    """What is at stake in the action this case authorises.

    `UNKNOWN` ranks above `BOUNDED` for the same reason `UNDETERMINED` does
    above: nobody having stated the stakes is not evidence that the stakes are
    low, and ordering it as though it were would make silence the safest thing a
    producer could do (Invariant 3).
    """

    IRREVERSIBLE = "IRREVERSIBLE"  # the action cannot be undone
    EXTERNAL = "EXTERNAL"          # effects land outside the system taking the action
    UNKNOWN = "UNKNOWN"            # nobody stated the stakes
    BOUNDED = "BOUNDED"            # stated, and contained


#: Rank orders. Lower sorts first. These are compared as an ordered tuple and are
#: never multiplied into a single number: a product is the "generic score alone"
#: that hides why an item ranks where it does, and a reviewer who cannot see the
#: reason cannot disagree with it.
_CRITICALITY_RANK = {AttentionCriticality.ON_CRITICAL_PATH: 0,
                     AttentionCriticality.UNDETERMINED: 1,
                     AttentionCriticality.SUPPORTING: 2,
                     AttentionCriticality.OFF_PATH: 3}
_PRESSURE_RANK = {RequirementPressure.BLOCKS: 0, RequirementPressure.HOLDS: 1,
                  RequirementPressure.UNASSESSED: 2, RequirementPressure.NONE: 3}
_CONSEQUENCE_RANK = {ConsequenceWeight.IRREVERSIBLE: 0, ConsequenceWeight.EXTERNAL: 1,
                     ConsequenceWeight.UNKNOWN: 2, ConsequenceWeight.BOUNDED: 3}


@dataclass(frozen=True)
class AttentionRanking:
    """Why an item sits where it sits, component by component.

    The ordering is lexicographic over the three factors the product cares
    about, in the order it cares about them: what the decision rests on, what an
    assurance requirement is waiting on, and what is at stake. Effect and
    leverage break remaining ties and are deliberately last — a count of findings
    is the weakest thing on this list and must never outrank a dependency
    (Invariant 12).
    """

    criticality: AttentionCriticality = AttentionCriticality.UNDETERMINED
    pressure: RequirementPressure = RequirementPressure.NONE
    consequence: ConsequenceWeight = ConsequenceWeight.UNKNOWN
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "criticality", AttentionCriticality(self.criticality))
        object.__setattr__(self, "pressure", RequirementPressure(self.pressure))
        object.__setattr__(self, "consequence", ConsequenceWeight(self.consequence))

    @property
    def key(self) -> Tuple[int, int, int]:
        return (_CRITICALITY_RANK[self.criticality], _PRESSURE_RANK[self.pressure],
                _CONSEQUENCE_RANK[self.consequence])

    def explain(self) -> str:
        return (f"dependency: {self.criticality.value}; "
                f"requirement: {self.pressure.value}; "
                f"consequence: {self.consequence.value}"
                + (f" — {self.basis}" if self.basis else ""))

    def to_dict(self) -> Dict[str, Any]:
        return {"criticality": self.criticality.value,
                "requirement_pressure": self.pressure.value,
                "consequence": self.consequence.value,
                "order": list(self.key), "basis": self.basis,
                # Stated in the record: there is no scalar priority to read.
                "composite_score": None,
                "explain": self.explain()}


@dataclass(frozen=True)
class AttentionItem:
    """One thing a person should look at, and everything they need to judge it.

    Nine questions, answered on the item rather than scattered across the case:
    what it is, why it matters, what depends on it, what supports it, what
    contradicts it, where it stands, what epistemic status that standing has,
    what the human can do, and what evidence would settle it.
    """

    item_id: str
    reason: AttentionReason
    effect: RequirementEffect
    focus: str
    focus_kind: str
    summary: str                                   # WHAT
    why_it_matters: str                            # WHY IT MATTERS
    remedy: str                                    # WHAT THE HUMAN CAN DO
    depends_on: Tuple[str, ...] = ()               # WHAT DEPENDS ON IT
    supporting_evidence: Tuple[str, ...] = ()      # SUPPORTING EVIDENCE
    contradicting_evidence: Tuple[str, ...] = ()   # CONTRADICTING EVIDENCE
    status: str = "OPEN"                           # STATUS
    epistemic_status: str = "UNKNOWN"              # EPISTEMIC STATUS
    resolving_evidence: Tuple[str, ...] = ()       # WHAT EVIDENCE WOULD RESOLVE IT
    ranking: AttentionRanking = field(default_factory=AttentionRanking)
    leverage: int = 1
    rule_ids: Tuple[str, ...] = ()
    refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", AttentionReason(self.reason))
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "rule_ids", tuple(self.rule_ids))
        object.__setattr__(self, "refs", tuple(self.refs))
        for name in ("depends_on", "supporting_evidence", "contradicting_evidence",
                     "resolving_evidence"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    @property
    def undroppable(self) -> bool:
        """No compression may omit this.

        A blocking item and an item on what the decision rests on are the two
        things a shortened list must never quietly lose. Compression here means
        collapsing many findings onto the one thing to inspect — not dropping an
        inspection to reach a target count.
        """
        return (self.effect is RequirementEffect.BLOCK
                or self.ranking.criticality is AttentionCriticality.ON_CRITICAL_PATH)

    @property
    def sort_key(self) -> Tuple[Any, ...]:
        """Dependency, then requirement, then consequence. Volume last, always."""
        return (*self.ranking.key, _EFFECT_RANK[self.effect], -self.leverage,
                self.item_id)

    def render(self) -> str:
        """The nine questions, in the order a reviewer asks them."""
        def block(label: str, value: Any) -> str:
            if not value:
                return f"  {label}: (none recorded)"
            if isinstance(value, tuple):
                shown = ", ".join(value[:6])
                more = f" (+{len(value) - 6} more)" if len(value) > 6 else ""
                return f"  {label}: {shown}{more}"
            return f"  {label}: {value}"
        return "\n".join([
            f"[{self.reason.value}] {self.summary}",
            block("WHY IT MATTERS", self.why_it_matters),
            block("WHAT DEPENDS ON IT", self.depends_on),
            block("SUPPORTING EVIDENCE", self.supporting_evidence),
            block("CONTRADICTING EVIDENCE", self.contradicting_evidence),
            block("STATUS", self.status),
            block("EPISTEMIC STATUS", self.epistemic_status),
            block("WHAT YOU CAN DO", self.remedy),
            block("WHAT WOULD RESOLVE IT", self.resolving_evidence),
            f"  RANKED BY: {self.ranking.explain()}",
        ])

    @property
    def record_type(self) -> str:
        return "attention_item"

    @property
    def record_id(self) -> str:
        return self.item_id

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "attention_item", "record_id": self.item_id,
                "reason": self.reason.value, "effect": self.effect.value,
                "focus": self.focus, "focus_kind": self.focus_kind,
                # The nine, named as the reviewer asks them.
                "what": self.summary,
                "why_it_matters": self.why_it_matters,
                "what_depends_on_it": list(self.depends_on),
                "supporting_evidence": list(self.supporting_evidence),
                "contradicting_evidence": list(self.contradicting_evidence),
                "status": self.status,
                "epistemic_status": self.epistemic_status,
                "what_the_human_can_do": self.remedy,
                "what_evidence_would_resolve_it": list(self.resolving_evidence),
                # Kept under their old names too, so existing readers hold.
                "summary": self.summary, "remedy": self.remedy,
                "ranking": self.ranking.to_dict(),
                "undroppable": self.undroppable,
                "leverage": self.leverage,
                "rule_ids": list(self.rule_ids), "refs": list(self.refs)}


@dataclass(frozen=True)
class HumanAttentionSet:
    """What to look at, hardest-first, with what it would settle."""

    items: Tuple[AttentionItem, ...] = ()
    basis: str = "structural analysis of the case as sealed"

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    @property
    def blocking(self) -> Tuple[AttentionItem, ...]:
        return tuple(i for i in self.items if i.effect is RequirementEffect.BLOCK)

    @property
    def total_leverage(self) -> int:
        return sum(i.leverage for i in self.items)

    @property
    def undroppable(self) -> Tuple[AttentionItem, ...]:
        return tuple(i for i in self.items if i.undroppable)

    def top(self, n: int = 7) -> Tuple[AttentionItem, ...]:
        """The n a person should read first — and never fewer than they must.

        A plain slice is how a critical issue disappears to make a list fit. So
        everything undroppable comes first and comes whole: if eleven items block
        or bear on what the decision rests on, `top(7)` returns eleven, and
        `withheld_note` says why the list is longer than asked for. Compression
        happens by collapsing findings onto one inspection, never by leaving an
        inspection out.
        """
        must = [i for i in self.items if i.undroppable]
        rest = [i for i in self.items if not i.undroppable]
        return tuple(must + rest[:max(0, n - len(must))])

    def withheld(self, n: int = 7) -> Tuple[AttentionItem, ...]:
        """What `top(n)` left out. Never anything undroppable."""
        shown = {i.item_id for i in self.top(n)}
        return tuple(i for i in self.items if i.item_id not in shown)

    def withheld_note(self, n: int = 7) -> str:
        """What a reader is not being shown, stated rather than implied."""
        must, held = len(self.undroppable), self.withheld(n)
        parts = []
        if must > n:
            parts.append(f"{must} item(s) are shown rather than {n}: they block or "
                         "bear on what this decision rests on, and a shorter list "
                         "would have to hide one")
        if held:
            by_reason: Dict[str, int] = {}
            for item in held:
                by_reason[item.reason.value] = by_reason.get(item.reason.value, 0) + 1
            parts.append(f"{len(held)} further item(s) are not shown: "
                         + ", ".join(f"{k} ({v})" for k, v in sorted(by_reason.items()))
                         + " — none of them blocking, none on the critical path")
        return "; ".join(parts) or "every item is shown"

    def to_dict(self, limit: Optional[int] = None) -> Dict[str, Any]:
        shown = self.items if limit is None else self.top(limit)
        return {"count": len(self.items), "basis": self.basis,
                "undroppable": len(self.undroppable),
                "shown": len(shown),
                "withheld": (0 if limit is None else len(self.withheld(limit))),
                "withheld_note": ("every item is shown" if limit is None
                                  else self.withheld_note(limit)),
                "items": [i.to_dict() for i in shown]}

    def render(self, limit: int = 7) -> str:
        if not self.items:
            return "Nothing in this case needs a person before the others."
        head = [f"{len(self.items)} thing(s) need a person; showing "
                f"{len(self.top(limit))}.", self.withheld_note(limit), ""]
        return "\n".join(head + [i.render() + "\n" for i in self.top(limit)])


@dataclass(frozen=True)
class RequiredEvidenceItem:
    """One checkable thing whose arrival would resolve a named gap."""

    requirement_id: str
    what: str
    why: str
    effect: RequirementEffect
    resolves: Tuple[str, ...] = ()
    monotone: bool = True
    #: The machine-readable form. Present on every item, so a consumer never has
    #: to parse `what` — which is prose for a person and was never a contract.
    requirement: Optional[EvidenceRequirement] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "resolves", tuple(self.resolves))

    @property
    def target(self) -> str:
        return self.requirement.target.reference if self.requirement else "case:this"

    @property
    def kind(self) -> EvidenceRequirementKind:
        return (self.requirement.requirement if self.requirement
                else EvidenceRequirementKind.UNSPECIFIED)

    @property
    def record_type(self) -> str:
        return "required_evidence"

    @property
    def record_id(self) -> str:
        return self.requirement_id

    def to_dict(self) -> Dict[str, Any]:
        payload = {"record_type": "required_evidence",
                   "record_id": self.requirement_id,
                   "what": self.what, "why": self.why, "effect": self.effect.value,
                   "resolves": list(self.resolves), "monotone": self.monotone}
        if self.requirement is not None:
            protocol = self.requirement.to_dict()
            # The wire form wins on the three protocol keys; the prose stays
            # under its own names for the reader.
            payload.update({k: v for k, v in protocol.items()
                            if k not in ("record_type", "record_id")})
        return payload


@dataclass(frozen=True)
class RequiredEvidenceSet:
    """What would move this case forward — never a promise that it would pass."""

    items: Tuple[RequiredEvidenceItem, ...] = ()
    methodology_required: bool = False
    note: str = ""
    targets_truncated: int = 0

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    @property
    def dispatchable(self) -> Tuple[RequiredEvidenceItem, ...]:
        """Requirements an external system can switch on and act upon."""
        return tuple(i for i in self.items
                     if i.requirement is not None and i.requirement.dispatchable)

    @property
    def unspecified(self) -> Tuple[RequiredEvidenceItem, ...]:
        """Gaps release-gate can see and cannot name a closer for.

        Reported as their own group rather than mixed in: a consumer that cannot
        dispatch on one should be told so, not handed a plausible wrong type.
        """
        return tuple(i for i in self.items if i not in self.dispatchable)

    def for_target(self, reference: str) -> Tuple[RequiredEvidenceItem, ...]:
        return tuple(i for i in self.items if i.target == reference)

    def protocol(self) -> Dict[str, Any]:
        """The machine-readable form an external system consumes.

        Deliberately contains no assignee, priority, deadline, schedule or
        callback. Release-Gate says what would resolve what, addressed to nobody;
        who does the work, in what order, and whether at all, is somebody else's
        authority. `satisfies_decision` is False for the same reason it is False
        everywhere: closing every gap release-gate can see is not the same as
        being sufficient, and a protocol whose completion implied authorisation
        would invert the boundary this system exists to hold.
        """
        return {
            "schema_version": 1,
            "required_evidence": [i.requirement.to_dict() for i in self.items
                                  if i.requirement is not None],
            "count": len(self.items),
            "dispatchable": len(self.dispatchable),
            "unspecified": len(self.unspecified),
            "targets_truncated": self.targets_truncated,
            "methodology_required": self.methodology_required,
            "satisfies_decision": False,
            "note": self.note,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"count": len(self.items),
                "methodology_required": self.methodology_required,
                "dispatchable": len(self.dispatchable),
                "unspecified": len(self.unspecified),
                "targets_truncated": self.targets_truncated,
                "satisfies_decision": False,
                "note": self.note, "items": [i.to_dict() for i in self.items]}


# ── attention ────────────────────────────────────────────────────────────────

# Kinds where the thing to inspect is the situation, not one of the records that
# revealed it. "All your evidence has one producer" is not fixed by opening one
# evidence record, so pointing a reviewer at an arbitrary id would waste the trip.
_WHOLE_CASE_KINDS = frozenset({"case", "input", "subject", "execution", "producer",
                               "manifest", "tools", "stakes", "contradiction",
                               "assumption", "failure_point", "coverage_dimension"})


def _focus_of(finding: Finding) -> Tuple[str, str]:
    """The thing to inspect, and what kind of thing it is."""
    kind = _FOCUS_KIND.get(finding.rule_id, "case")
    if finding.refs and kind not in _WHOLE_CASE_KINDS:
        return finding.refs[0], kind
    return finding.rule_id, kind


def _reason_of(finding: Finding) -> AttentionReason:
    return _RULE_REASON.get(finding.rule_id,
                            _DOMAIN_REASON.get(finding.domain, AttentionReason.COVERAGE_GAP))


def _rank(focus: str, kind: str, findings: Sequence[Finding],
          criticality: Any, consequence: Any,
          pressured: Mapping[str, RequirementEffect]) -> AttentionRanking:
    """The three factors, each derived and each reported.

    Never combined into a number. A reviewer who is told an item scored 0.82
    cannot argue with it; one told "the decision rests on this claim, a blocking
    requirement is waiting on it, and the action is irreversible" can.
    """
    standing = AttentionCriticality.UNDETERMINED
    basis_parts: List[str] = []
    if criticality is not None and getattr(criticality, "determinable", False):
        entry = criticality.of(focus) if kind == "claim" else None
        # A finding whose refs are counterexample or contradiction ids is still
        # about the claims it names, and those are carried in `critical_claims`
        # rather than left to be guessed from the shape of a ref. Without this a
        # finding whose own summary reads "against a critical claim" ranked
        # OFF_PATH — and an off-path item is droppable, which is the exact
        # failure "never hide critical issues for compression" forbids.
        touched = ({r for f in findings for r in f.refs} | {focus}
                   | {c for f in findings
                      for c in (f.observed.get("critical_claims") or ())})
        if entry is not None and entry.critical:
            standing = AttentionCriticality.ON_CRITICAL_PATH
            basis_parts.append(f"{focus} is load-bearing at depth {entry.depth}")
        elif touched & set(criticality.critical_ids):
            standing = AttentionCriticality.ON_CRITICAL_PATH
            named = sorted(touched & set(criticality.critical_ids))[:3]
            basis_parts.append("touches load-bearing " + ", ".join(named))
        elif entry is not None:
            standing = (AttentionCriticality.SUPPORTING
                        if entry.standing.value == "SUPPORTING"
                        else AttentionCriticality.OFF_PATH)
        elif kind in _WHOLE_CASE_KINDS:
            # A finding about the case as a whole bears on whatever the case
            # rests on; it is not off the path merely for naming no claim.
            standing = AttentionCriticality.UNDETERMINED
            basis_parts.append("about the case rather than one claim")
        else:
            standing = AttentionCriticality.OFF_PATH
    elif criticality is not None:
        basis_parts.append("criticality could not be derived for this case")

    pressure = RequirementPressure.NONE
    hit = [pressured[r] for r in ({focus} | {x for f in findings for x in f.refs})
           if r in pressured]
    hit += [pressured[r] for r in (f.rule_id for f in findings) if r in pressured]
    if RequirementEffect.BLOCK in hit:
        pressure = RequirementPressure.BLOCKS
    elif RequirementEffect.HOLD in hit:
        pressure = RequirementPressure.HOLDS
    elif hit:
        pressure = RequirementPressure.UNASSESSED
    if hit:
        basis_parts.append("an unresolved requirement names it")

    weight = ConsequenceWeight.UNKNOWN
    if consequence is not None:
        try:
            from release_gate.assurance.consequence import ConsequenceDimension
            reversibility = consequence.value(ConsequenceDimension.REVERSIBILITY)
            externality = consequence.value(ConsequenceDimension.EXTERNALITY)
            if reversibility == "IRREVERSIBLE":
                weight = ConsequenceWeight.IRREVERSIBLE
                basis_parts.append("the action is irreversible")
            elif externality in ("EXTERNAL", "THIRD_PARTY", "PUBLIC"):
                weight = ConsequenceWeight.EXTERNAL
                basis_parts.append("effects land outside this system")
            elif reversibility == "UNKNOWN":
                weight = ConsequenceWeight.UNKNOWN
            else:
                weight = ConsequenceWeight.BOUNDED
        except Exception:
            weight = ConsequenceWeight.UNKNOWN
    return AttentionRanking(criticality=standing, pressure=pressure,
                            consequence=weight, basis="; ".join(basis_parts))


def _evidence_for(focus: str, kind: str, findings: Sequence[Finding],
                  claim_graph: Any) -> Tuple[Tuple[str, ...], Tuple[str, ...],
                                             Tuple[str, ...], str]:
    """What depends on it, what supports it, what contradicts it, and how known.

    Read from the claim graph where the focus is a claim, and from the findings
    themselves otherwise. Where nothing is recorded the answer is an empty tuple
    rendered as "(none recorded)" — never a claim that nothing depends on it.
    """
    depends: Tuple[str, ...] = ()
    supporting: Tuple[str, ...] = ()
    contradicting: Tuple[str, ...] = ()
    epistemic = "UNKNOWN"
    if claim_graph is not None and kind == "claim":
        claim = claim_graph.claim(focus)
        if claim is not None:
            # What falls if this is wrong: every claim that rests on it.
            depends = tuple(sorted(
                c.claim_id for c in claim_graph.claims if focus in c.depends_on))[:12]
            supporting = tuple(claim.supporting_evidence)[:12]
            contradicting = tuple(claim.contradicting_evidence)[:12]
            epistemic = claim_graph.status(focus).value
    if not supporting:
        supporting = tuple(sorted({r for f in findings for r in f.refs}))[:12]
    return depends, supporting, contradicting, epistemic


def build_attention(case: AssuranceCase, analysis: AnalysisResult,
                    assessment: Optional[MethodologyAssessment] = None,
                    required: Optional["RequiredEvidenceSet"] = None
                    ) -> HumanAttentionSet:
    """Collapse findings onto the things a person would actually open.

    Grouping is by focus, so one bad claim named in four findings costs a reviewer
    one inspection, not four. Advisory findings never create an item of their own —
    they ride along on an item that already exists, or they stay in the findings
    list where a reader can find them. Attention is a scarce resource and padding
    it with things that do not change a decision is how it stops being read.
    """
    criticality = getattr(analysis, "criticality", None)
    consequence = getattr(analysis, "consequence", None)
    claim_graph = getattr(analysis, "claim_graph", None)
    critical_ids = (set(criticality.critical_ids)
                    if criticality is not None and criticality.determinable else set())

    # What an unresolved requirement is waiting on, keyed by whatever it names.
    pressured: Dict[str, RequirementEffect] = {}
    if assessment is not None:
        for result in assessment.unmet():
            for key in (result.requirement_id, *(str(v) for v in
                                                 (result.observed or {}).values()
                                                 if isinstance(v, str))):
                pressured.setdefault(key, result.effect)

    # What would resolve each gap, keyed by the rule that raised it, so an item
    # can answer "what evidence would settle this?" on its own rather than
    # sending the reader to a separate list.
    resolvers: Dict[str, List[str]] = {}
    for entry in (required.items if required is not None else ()):
        for rule in entry.resolves:
            resolvers.setdefault(rule, []).append(entry.what)

    groups: Dict[Tuple[str, str], List[Finding]] = {}
    for finding in analysis.findings:
        if finding.effect is RequirementEffect.ADVISORY:
            # Advisories ride along on an item that already exists — except where
            # they bear on what the decision rests on. "Never hide critical issues
            # for compression" outranks keeping the list short, and an advisory
            # about a load-bearing claim is exactly the thing that would otherwise
            # vanish for being merely advisory.
            if not (critical_ids and ({*finding.refs} & critical_ids)):
                continue
        groups.setdefault(_focus_of(finding), []).append(finding)

    items: List[AttentionItem] = []
    for (focus, kind), findings in groups.items():
        findings.sort(key=lambda f: (_EFFECT_RANK[f.effect], f.rule_id))
        worst = findings[0]
        # The reason comes from the most specific rule in the group rather than
        # simply the worst one. A rule with its own mapped reason says something a
        # domain default cannot — "this risk was accepted", "this was closed by the
        # party it was against" — and losing that to an alphabetically earlier
        # sibling would blur the one word a reviewer actually scans.
        named = [f for f in findings if f.rule_id in _RULE_REASON]
        reason_source = named[0] if named else worst
        rule_ids = tuple(sorted({f.rule_id for f in findings}))
        refs = tuple(sorted({r for f in findings for r in f.refs}))[:12]
        summary = (worst.summary if len(findings) == 1
                   else f"{worst.summary} (+{len(findings) - 1} more finding(s) here)")
        depends, supporting, contradicting, epistemic = _evidence_for(
            focus, kind, findings, claim_graph)
        resolving = tuple(dict.fromkeys(
            [w for rule in rule_ids for w in resolvers.get(rule, ())]
            or [f.remedy for f in findings if f.remedy]))[:6]
        items.append(AttentionItem(
            item_id=f"att_{kind}_{focus}".replace(" ", "_")[:96],
            reason=_reason_of(reason_source), effect=worst.effect,
            focus=focus, focus_kind=kind,
            summary=summary, why_it_matters=worst.detail, remedy=worst.remedy,
            depends_on=depends, supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            status=("BLOCKING" if worst.effect is RequirementEffect.BLOCK
                    else "OPEN" if worst.effect is RequirementEffect.HOLD
                    else "ADVISORY"),
            epistemic_status=epistemic,
            resolving_evidence=resolving,
            ranking=_rank(focus, kind, findings, criticality, consequence, pressured),
            leverage=len(findings), rule_ids=rule_ids, refs=refs))

    if assessment is not None:
        if assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED:
            items.append(AttentionItem(
                item_id="att_case_METHODOLOGY_REQUIRED",
                reason=AttentionReason.METHODOLOGY_ABSENT, effect=RequirementEffect.HOLD,
                focus="METHODOLOGY_REQUIRED", focus_kind="case",
                summary="no methodology states what evidence this decision requires",
                why_it_matters=(
                    "release-gate has reported everything structural it can see. Whether "
                    "that is ENOUGH is a domain question, and no yardstick was supplied. "
                    "Inventing one would be release-gate claiming a standard it does not "
                    "have (Invariant 10)."),
                remedy="state a methodology — a built-in, an organisation's own, or one "
                       "supplied through the API — and re-run",
                status="OPEN", epistemic_status="NOT_ASSESSED",
                resolving_evidence=("a stated methodology for this class of decision",),
                # Sufficiency is unassessable without a yardstick, and the
                # consequence of the action is unchanged by that — so this ranks
                # on the case's own stakes rather than at the bottom.
                ranking=_rank("METHODOLOGY_REQUIRED", "case", (), criticality,
                              consequence, pressured),
                leverage=1, rule_ids=("RG-ZC-001",)))
        else:
            for result in assessment.unmet():
                if result.effect is RequirementEffect.ADVISORY:
                    continue
                items.append(AttentionItem(
                    item_id=f"att_req_{result.requirement_id}"[:96],
                    reason=AttentionReason.REQUIREMENT_UNMET, effect=result.effect,
                    focus=result.requirement_id, focus_kind="requirement",
                    summary=f"{result.description} — {result.outcome.value}",
                    why_it_matters=result.detail,
                    remedy=result.remedy or "satisfy the requirement",
                    status=result.outcome.value,
                    epistemic_status=("NOT_ASSESSED"
                                      if result.outcome is RequirementOutcome.NOT_ASSESSED
                                      else "DERIVED"),
                    resolving_evidence=tuple(
                        resolvers.get(result.requirement_id,
                                      [result.remedy] if result.remedy else [])),
                    ranking=AttentionRanking(
                        criticality=(AttentionCriticality.ON_CRITICAL_PATH
                                     if critical_ids else
                                     AttentionCriticality.UNDETERMINED),
                        pressure=(RequirementPressure.BLOCKS
                                  if result.effect is RequirementEffect.BLOCK
                                  else RequirementPressure.HOLDS),
                        consequence=_rank(result.requirement_id, "requirement", (),
                                          None, consequence, {}).consequence,
                        basis="an assurance requirement this decision is held to is "
                              "unresolved"),
                    leverage=1, rule_ids=(result.requirement_id,)))

    # Dependency, then unresolved requirement, then consequence — the three the
    # product ranks on. Effect and leverage break the remaining ties and are
    # deliberately last: a count of findings must never outrank a dependency
    # (Invariant 12).
    items.sort(key=lambda i: i.sort_key)
    return HumanAttentionSet(
        items=tuple(items),
        basis=("ranked by what the decision rests on, then by what an unresolved "
               "assurance requirement is waiting on, then by what is at stake; "
               "no composite score is computed"))


# ── required evidence ────────────────────────────────────────────────────────

# Requirements of the at-least shape stay satisfied as evidence arrives. The rest
# can flip back, and a caller that treats them as monotone will be wrong later.
#: How many targets one rule may expand into before the rest are counted rather
#: than listed. Three hundred load-bearing claims resting on one producer really
#: are three hundred requirements; what they are not is an unbounded payload, so
#: the remainder is declared through `targets_truncated` rather than dropped.
_TARGETS_PER_RULE = 200

_NON_MONOTONE_RULES = frozenset({
    "RG-CONTRA-001", "RG-CONTRA-002", "RG-CONTRA-003", "RG-CONTRA-004",
    "RG-VERIF-002", "RG-VERIF-003", "RG-DRIFT-001", "RG-DRIFT-003", "RG-DRIFT-005",
    # More evidence can reveal a capability that was exercised and undeclared, so
    # a clean capability comparison is never settled by arrival.
    "RG-CAP-001", "RG-CAP-002",
    # A declared consequence can be contradicted by evidence that has not arrived.
    "RG-CONS-002", "RG-CONS-003",
    # A resolved contradiction can be reopened by evidence that has not arrived.
    "RG-CONTRA-005",
    # A resolved counterexample can be reopened by a search that has not run yet.
    "RG-CEX-001", "RG-CEX-002",
    # An agreeing set of paths can be split by a replication that has not run.
    "RG-REPL-001", "RG-REPL-002",
    # And an adversarial finding that was answered can be reopened by an attack
    # nobody has made yet: a clean adversarial result is never settled by arrival.
    "RG-ADV-001", "RG-ADV-002", "RG-ADV-003", "RG-ADV-004",
})


def build_required_evidence(case: AssuranceCase, analysis: AnalysisResult,
                            assessment: Optional[MethodologyAssessment] = None
                            ) -> RequiredEvidenceSet:
    """The named things that would close each open gap.

    Deduplicated by remedy, because two findings asking for the same evidence are
    one errand. Every item says what it would resolve and whether supplying it can
    be undone by later evidence.
    """
    # Grouped by (target, kind), not by the text of a remedy. Two claims that
    # both need independent verification are two requirements: a verifier can act
    # on one and not the other, and collapsing them into "verify the claims" is a
    # sentence nobody can dispatch. The old dedupe-by-remedy did exactly that.
    groups: Dict[Tuple[str, str], List[Finding]] = {}
    targets: Dict[Tuple[str, str], VerificationTarget] = {}
    truncated: Dict[str, int] = {}
    for finding in analysis.findings:
        if finding.effect is RequirementEffect.ADVISORY or not finding.remedy:
            continue
        kind = requirement_kind_for(finding.rule_id)
        # The same focus the attention engine computes, so a requirement and the
        # inspection it corresponds to always name the same object.
        focus, focus_kind = _focus_of(finding)
        target_kind = target_kind_for_focus(focus_kind)
        if target_kind is TargetKind.CASE or not finding.refs:
            refs: Sequence[str] = (finding.rule_id,)
            target_kind = TargetKind.CASE
        else:
            refs = finding.refs[:_TARGETS_PER_RULE]
            if len(finding.refs) > _TARGETS_PER_RULE:
                truncated[finding.rule_id] = len(finding.refs) - _TARGETS_PER_RULE
        for ref in refs:
            target = VerificationTarget(kind=target_kind, target_id=str(ref))
            key = (target.reference, kind.value)
            targets.setdefault(key, target)
            groups.setdefault(key, []).append(finding)

    items: List[RequiredEvidenceItem] = []
    for key in sorted(groups):
        findings = sorted(groups[key], key=lambda f: f.rule_id)
        effect = min((f.effect for f in findings), key=lambda e: _EFFECT_RANK[e])
        rule_ids = tuple(sorted({f.rule_id for f in findings}))
        kind = EvidenceRequirementKind(key[1])
        reason = "; ".join(dict.fromkeys(f.summary for f in findings))[:300]
        requirement = EvidenceRequirement(
            target=targets[key], requirement=kind, reason=reason, effect=effect,
            constraints=_constraints_for(findings, analysis),
            acceptance=acceptance_for(kind), resolves=rule_ids,
            monotone=not any(r in _NON_MONOTONE_RULES for r in rule_ids),
            detail="; ".join(dict.fromkeys(f.remedy for f in findings))[:400])
        items.append(RequiredEvidenceItem(
            requirement_id=requirement.requirement_id,
            what=requirement.detail or reason, why=reason,
            effect=effect, resolves=rule_ids,
            monotone=requirement.monotone, requirement=requirement))

    methodology_required = (assessment is not None
                            and assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED)
    if methodology_required:
        methodology = EvidenceRequirement(
            target=VerificationTarget(kind=TargetKind.METHODOLOGY,
                                      target_id="this-decision"),
            requirement=EvidenceRequirementKind.METHODOLOGY_DECLARATION,
            reason="no methodology states what evidence this decision requires",
            effect=RequirementEffect.HOLD,
            acceptance=acceptance_for(EvidenceRequirementKind.METHODOLOGY_DECLARATION),
            resolves=("RG-ZC-001",), monotone=True,
            detail="state a methodology and re-run")
        items.insert(0, RequiredEvidenceItem(
            requirement_id=methodology.requirement_id,
            what="a methodology stating what evidence this decision requires",
            why=("structural assurance is complete as far as it goes; sufficiency for "
                 "this domain is unanswerable without a stated yardstick"),
            effect=RequirementEffect.HOLD, resolves=("RG-ZC-001",), monotone=True,
            requirement=methodology))
    elif assessment is not None:
        for result in assessment.unmet():
            if result.effect is RequirementEffect.ADVISORY:
                continue
            # A methodology requirement names a yardstick, not a thing in the
            # case, so its target is the requirement itself. Its kind is
            # `unspecified` unless the requirement says otherwise: guessing what
            # would satisfy somebody else's yardstick is exactly the invention
            # this system refuses.
            # The predicate says what would satisfy it. An organisation's own
            # predicate, arriving through the API with no mapping, degrades to
            # `unspecified` with its prose intact rather than to a nearby kind
            # chosen to look tidy.
            kind = requirement_kind_for_predicate(result.predicate_kind)
            requirement = EvidenceRequirement(
                target=VerificationTarget(kind=TargetKind.METHODOLOGY,
                                          target_id=result.requirement_id),
                requirement=kind,
                reason=result.description, effect=result.effect,
                constraints=_methodology_constraints(result),
                acceptance=result.remedy or acceptance_for(kind),
                resolves=(result.requirement_id,),
                monotone=result.outcome is not RequirementOutcome.UNKNOWN,
                detail=result.detail or result.description)
            items.append(RequiredEvidenceItem(
                requirement_id=requirement.requirement_id,
                what=result.remedy or result.description,
                why=result.detail or result.description, effect=result.effect,
                resolves=(result.requirement_id,),
                monotone=result.outcome is not RequirementOutcome.UNKNOWN,
                requirement=requirement))

    note = ("This is what would resolve the gaps release-gate can see. It is not a "
            "list that, once satisfied, yields PROMOTE — no methodology has stated "
            "what sufficient looks like here."
            if methodology_required else
            "Supplying these resolves the named gaps; the methodology decides whether "
            "what remains is sufficient.")
    return RequiredEvidenceSet(items=tuple(items),
                               methodology_required=methodology_required, note=note,
                               targets_truncated=sum(truncated.values()))


def _constraints_for(findings: Sequence[Finding], analysis: AnalysisResult
                     ) -> Dict[str, Any]:
    """What new evidence would have to satisfy, in terms a machine can check.

    Read only from what the case actually establishes. A constraint invented to
    look precise — a lineage nobody recorded, a digest nobody computed — would
    send a verifier to produce evidence against a condition that was never true,
    which is worse than saying nothing.
    """
    constraints: Dict[str, Any] = {}
    observed: Dict[str, Any] = {}
    for finding in findings:
        observed.update(finding.observed or {})

    # Which lineages the new evidence must not rest on. Derived from the
    # independence profile rather than from any producer's account of itself.
    profile = getattr(analysis, "independence", None)
    if profile is not None and profile.clusters:
        largest = profile.clusters[0]
        if largest.contributors:
            constraints["independent_of"] = list(largest.contributors[:8])

    # Which state the check must apply to. Without it a re-verification can be
    # produced against yesterday's content and look current.
    subject = getattr(getattr(analysis, "artifact_graph", None), "artifacts", None)
    case_digest = observed.get("current_digest") or observed.get("subject_digest")
    if isinstance(case_digest, str) and case_digest:
        constraints["against_digest"] = case_digest

    for key, out in (("critical_claims", "affects_claims"),
                     ("known_missing_ids", "missing_ids"),
                     ("named", "missing_ids"),
                     ("missing", "missing_ids"),
                     ("dimensions", "dimensions"),
                     ("requirements", "answers_requirements")):
        value = observed.get(key)
        if isinstance(value, (list, tuple)) and value:
            constraints.setdefault(out, sorted({str(x) for x in value})[:12])

    expected = observed.get("expected")
    if isinstance(expected, int):
        constraints["expected_total"] = expected
    if observed.get("self_certified"):
        constraints["independent_of_producer"] = True
    return constraints


def _methodology_constraints(result: Any) -> Dict[str, Any]:
    """What an unmet methodology requirement is actually waiting on.

    Taken from what the predicate observed, so the numbers a verifier is asked to
    reach are the ones the predicate will check against — not a restatement that
    could drift from them.
    """
    observed = dict(getattr(result, "observed", None) or {})
    wanted = ("minimum_roots", "minimum_paths", "minimum_attacks", "minimum_coverage",
              "required_axes", "required_roles", "dimension", "expected",
              "independent_roots", "established_paths", "attacks", "target")
    return {k: observed[k] for k in wanted
            if k in observed and observed[k] not in (None, (), [], "")}
