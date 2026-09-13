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
from release_gate.assurance.methodology import (
    AssessmentStatus, MethodologyAssessment, RequirementEffect, RequirementOutcome,
)

__all__ = [
    "AttentionItem",
    "AttentionReason",
    "HumanAttentionSet",
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
    "RG-VERIF-001": "case", "RG-VERIF-002": "claim", "RG-VERIF-003": "claim",
    "RG-CONTRA-001": "evidence", "RG-CONTRA-002": "claim",
    "RG-CONTRA-003": "claim", "RG-CONTRA-004": "claim",
    "RG-DRIFT-001": "subject", "RG-DRIFT-002": "subject",
    "RG-DRIFT-003": "artifact", "RG-DRIFT-004": "artifact", "RG-DRIFT-005": "evidence",
    "RG-COV-001": "input", "RG-COV-002": "input", "RG-COV-003": "claim",
    "RG-COV-004": "execution", "RG-COV-005": "case",
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
    METHODOLOGY_ABSENT = "METHODOLOGY_ABSENT"
    REQUIREMENT_UNMET = "REQUIREMENT_UNMET"


_DOMAIN_REASON = {
    AnalysisDomain.CONTRADICTION: AttentionReason.CONTRADICTION,
    AnalysisDomain.VERIFICATION: AttentionReason.FAILED_VERIFICATION,
    AnalysisDomain.PROVENANCE: AttentionReason.NOT_CORROBORATED,
    AnalysisDomain.DRIFT: AttentionReason.STALE_VERIFICATION,
    AnalysisDomain.COVERAGE: AttentionReason.COVERAGE_GAP,
}

_RULE_REASON = {
    "RG-CONTRA-002": AttentionReason.REFUTED,
    "RG-VERIF-001": AttentionReason.NOT_VERIFIED,
    "RG-VERIF-002": AttentionReason.FAILED_VERIFICATION,
    "RG-DRIFT-001": AttentionReason.SUBJECT_CHANGED,
    "RG-DRIFT-002": AttentionReason.SUBJECT_CHANGED,
}


@dataclass(frozen=True)
class AttentionItem:
    """One thing a person should look at, and what looking would settle."""

    item_id: str
    reason: AttentionReason
    effect: RequirementEffect
    focus: str
    focus_kind: str
    summary: str
    why_it_matters: str
    remedy: str
    leverage: int = 1
    rule_ids: Tuple[str, ...] = ()
    refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", AttentionReason(self.reason))
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "rule_ids", tuple(self.rule_ids))
        object.__setattr__(self, "refs", tuple(self.refs))

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
                "summary": self.summary, "why_it_matters": self.why_it_matters,
                "remedy": self.remedy, "leverage": self.leverage,
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

    def top(self, n: int = 5) -> Tuple[AttentionItem, ...]:
        return self.items[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {"count": len(self.items), "basis": self.basis,
                "items": [i.to_dict() for i in self.items]}


@dataclass(frozen=True)
class RequiredEvidenceItem:
    """One checkable thing whose arrival would resolve a named gap."""

    requirement_id: str
    what: str
    why: str
    effect: RequirementEffect
    resolves: Tuple[str, ...] = ()
    monotone: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "resolves", tuple(self.resolves))

    @property
    def record_type(self) -> str:
        return "required_evidence"

    @property
    def record_id(self) -> str:
        return self.requirement_id

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "required_evidence", "record_id": self.requirement_id,
                "what": self.what, "why": self.why, "effect": self.effect.value,
                "resolves": list(self.resolves), "monotone": self.monotone}


@dataclass(frozen=True)
class RequiredEvidenceSet:
    """What would move this case forward — never a promise that it would pass."""

    items: Tuple[RequiredEvidenceItem, ...] = ()
    methodology_required: bool = False
    note: str = ""

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def to_dict(self) -> Dict[str, Any]:
        return {"count": len(self.items),
                "methodology_required": self.methodology_required,
                "note": self.note, "items": [i.to_dict() for i in self.items]}


# ── attention ────────────────────────────────────────────────────────────────

# Kinds where the thing to inspect is the situation, not one of the records that
# revealed it. "All your evidence has one producer" is not fixed by opening one
# evidence record, so pointing a reviewer at an arbitrary id would waste the trip.
_WHOLE_CASE_KINDS = frozenset({"case", "input", "subject", "execution", "producer"})


def _focus_of(finding: Finding) -> Tuple[str, str]:
    """The thing to inspect, and what kind of thing it is."""
    kind = _FOCUS_KIND.get(finding.rule_id, "case")
    if finding.refs and kind not in _WHOLE_CASE_KINDS:
        return finding.refs[0], kind
    return finding.rule_id, kind


def _reason_of(finding: Finding) -> AttentionReason:
    return _RULE_REASON.get(finding.rule_id,
                            _DOMAIN_REASON.get(finding.domain, AttentionReason.COVERAGE_GAP))


def build_attention(case: AssuranceCase, analysis: AnalysisResult,
                    assessment: Optional[MethodologyAssessment] = None
                    ) -> HumanAttentionSet:
    """Collapse findings onto the things a person would actually open.

    Grouping is by focus, so one bad claim named in four findings costs a reviewer
    one inspection, not four. Advisory findings never create an item of their own —
    they ride along on an item that already exists, or they stay in the findings
    list where a reader can find them. Attention is a scarce resource and padding
    it with things that do not change a decision is how it stops being read.
    """
    groups: Dict[Tuple[str, str], List[Finding]] = {}
    for finding in analysis.findings:
        if finding.effect is RequirementEffect.ADVISORY:
            continue
        groups.setdefault(_focus_of(finding), []).append(finding)

    items: List[AttentionItem] = []
    for (focus, kind), findings in groups.items():
        findings.sort(key=lambda f: (_EFFECT_RANK[f.effect], f.rule_id))
        worst = findings[0]
        rule_ids = tuple(sorted({f.rule_id for f in findings}))
        refs = tuple(sorted({r for f in findings for r in f.refs}))[:12]
        summary = (worst.summary if len(findings) == 1
                   else f"{worst.summary} (+{len(findings) - 1} more finding(s) here)")
        items.append(AttentionItem(
            item_id=f"att_{kind}_{focus}".replace(" ", "_")[:96],
            reason=_reason_of(worst), effect=worst.effect, focus=focus, focus_kind=kind,
            summary=summary, why_it_matters=worst.detail, remedy=worst.remedy,
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
                    leverage=1, rule_ids=(result.requirement_id,)))

    items.sort(key=lambda i: (_EFFECT_RANK[i.effect], -i.leverage, i.item_id))
    return HumanAttentionSet(items=tuple(items))


# ── required evidence ────────────────────────────────────────────────────────

# Requirements of the at-least shape stay satisfied as evidence arrives. The rest
# can flip back, and a caller that treats them as monotone will be wrong later.
_NON_MONOTONE_RULES = frozenset({
    "RG-CONTRA-001", "RG-CONTRA-002", "RG-CONTRA-003", "RG-CONTRA-004",
    "RG-VERIF-002", "RG-VERIF-003", "RG-DRIFT-001", "RG-DRIFT-003", "RG-DRIFT-005",
})


def build_required_evidence(case: AssuranceCase, analysis: AnalysisResult,
                            assessment: Optional[MethodologyAssessment] = None
                            ) -> RequiredEvidenceSet:
    """The named things that would close each open gap.

    Deduplicated by remedy, because two findings asking for the same evidence are
    one errand. Every item says what it would resolve and whether supplying it can
    be undone by later evidence.
    """
    by_remedy: Dict[str, List[Finding]] = {}
    for finding in analysis.findings:
        if finding.effect is RequirementEffect.ADVISORY or not finding.remedy:
            continue
        by_remedy.setdefault(finding.remedy, []).append(finding)

    items: List[RequiredEvidenceItem] = []
    for remedy in sorted(by_remedy):
        findings = sorted(by_remedy[remedy], key=lambda f: f.rule_id)
        effect = min((f.effect for f in findings), key=lambda e: _EFFECT_RANK[e])
        rule_ids = tuple(f.rule_id for f in findings)
        items.append(RequiredEvidenceItem(
            requirement_id=f"req_{findings[0].rule_id}",
            what=remedy,
            why="; ".join(sorted({f.summary for f in findings}))[:400],
            effect=effect, resolves=rule_ids,
            monotone=not any(r in _NON_MONOTONE_RULES for r in rule_ids)))

    methodology_required = (assessment is not None
                            and assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED)
    if methodology_required:
        items.insert(0, RequiredEvidenceItem(
            requirement_id="req_methodology",
            what="a methodology stating what evidence this decision requires",
            why=("structural assurance is complete as far as it goes; sufficiency for "
                 "this domain is unanswerable without a stated yardstick"),
            effect=RequirementEffect.HOLD, resolves=("RG-ZC-001",), monotone=True))
    elif assessment is not None:
        for result in assessment.unmet():
            if result.effect is RequirementEffect.ADVISORY:
                continue
            items.append(RequiredEvidenceItem(
                requirement_id=f"req_{result.requirement_id}",
                what=result.remedy or result.description,
                why=result.detail or result.description, effect=result.effect,
                resolves=(result.requirement_id,),
                monotone=result.outcome is not RequirementOutcome.UNKNOWN))

    note = ("This is what would resolve the gaps release-gate can see. It is not a "
            "list that, once satisfied, yields PROMOTE — no methodology has stated "
            "what sufficient looks like here."
            if methodology_required else
            "Supplying these resolves the named gaps; the methodology decides whether "
            "what remains is sufficient.")
    return RequiredEvidenceSet(items=tuple(items),
                               methodology_required=methodology_required, note=note)
