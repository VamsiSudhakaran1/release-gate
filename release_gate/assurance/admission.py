"""The admission decision — PROMOTE, HOLD or BLOCK, from claims and declared policy.

Everything before this point turns evidence into a case: records normalised from
whatever produced them, claims and what bears on them, each claim resolved under
the resolution policy, the candidate the evidence is bound to, the analyses
that say what is contradicted, stale, unverified, correlated or unknown, and the
methodology's account of what this decision requires. The admission decision is
a deterministic function of that case and nothing else. No scanner score, no
level, no count of passes and no model's confidence is an input: a summary may
be shown beside the decision, and none can stand in for it.

**One shape for every reason.** Each structural finding, each methodology
requirement, each unresolved disagreement on a critical claim and each
documented exception becomes an `AdmissionCondition`: what it is, which of the
admission dimensions it concerns, the claims it is about, the policy that
declared it, and its effect. The dimensions are the questions an admission
asks:

    critical_claims     what the decision rests on, and whether that is known
    claim_status        whether each mandatory claim reaches the policy's level
    coverage            whether the surface the claims declare was assessed
    counterexamples     what breaks a claim, and attempts to break one
    contradictions      evidence pointing both ways
    assumptions         what the argument takes for granted
    state_binding       whether the evidence is about this exact release
    independence        whether the support is more than one source
    required_evidence   what the methodology says this decision needs
    approvals           which people must approve, and whether they did, of this state
    exceptions          documented risk acceptances and accepted holds
    unknowns            what could not be read, determined or answered
    failed_branches     what was tried and did not work
    action_scope        what the system did and would do: capabilities, consequence

**The decision is the worst condition.** BLOCK when a declared blocking
condition is established — a counterexample to a critical claim, a refuted or
failed mandatory claim, a required approval refused for this state, a policy
threshold a methodology states as blocking. HOLD when anything is incomplete,
ambiguous, stale, insufficiently independent, unknown or needs a person — HOLD
is a first-class outcome with its reasons, never an error. PROMOTE only when a
methodology was supplied, assessed and met, at least one of its requirements
applied, and no condition holds or blocks: every mandatory claim satisfies the
declared policy, the required coverage is present, no blocking contradiction or
counterexample is open, and every required approval binds to the candidate.

**What a condition cannot do.** An ADVISORY condition is shown and moves
nothing. An ACCEPTED condition is a hold the methodology declared acceptable
for this class of decision, or a counterexample accepted as documented risk
under a policy that permits it: named on the verdict, never silent. Nothing
here can lower a BLOCK, and nothing here reads a score.

The verdict the case records (`CaseVerdict`) is composed from the conditions in
the order the engine has always written it, so the reasons a reader sees and
the rules it fires are unchanged; the conditions are the same reasons with
their dimension, claims and policy attached, and `AdmissionEvaluation.to_dict`
is that account in full.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.case import CaseVerdict, Decision
from release_gate.assurance.methodology import (
    AssessmentStatus,
    MethodologyAssessment,
    RequirementEffect,
    RequirementOutcome,
)

__all__ = [
    "ADMISSION_SCHEMA_VERSION",
    "RULE_METHODOLOGY_REQUIRED",
    "RULE_METHODOLOGY_SATISFIED",
    "RULE_STRUCTURAL_ACCEPTED",
    "RULE_STRUCTURAL_BLOCK",
    "RULE_STRUCTURAL_HOLD",
    "AdmissionCondition",
    "AdmissionDimension",
    "AdmissionEvaluation",
    "ClaimStanding",
    "ConditionEffect",
    "DimensionStanding",
    "dimension_of_rule",
    "evaluate_admission",
]

ADMISSION_SCHEMA_VERSION = 1

# The verdict's own rules. Named like any other rule so a verdict is traced to
# them; defined here because this is where the decision is taken.
RULE_METHODOLOGY_REQUIRED = "RG-ZC-001"
RULE_STRUCTURAL_BLOCK = "RG-ZC-002"
RULE_STRUCTURAL_HOLD = "RG-ZC-003"
RULE_METHODOLOGY_SATISFIED = "RG-ZC-004"
#: A structural HOLD the methodology accepted up front. Named on the verdict so
#: the audit trail shows an acceptance was applied rather than a shorter list.
RULE_STRUCTURAL_ACCEPTED = "RG-ZC-005"


class AdmissionDimension(str, Enum):
    CRITICAL_CLAIMS = "critical_claims"
    CLAIM_STATUS = "claim_status"
    COVERAGE = "coverage"
    COUNTEREXAMPLES = "counterexamples"
    CONTRADICTIONS = "contradictions"
    ASSUMPTIONS = "assumptions"
    STATE_BINDING = "state_binding"
    INDEPENDENCE = "independence"
    REQUIRED_EVIDENCE = "required_evidence"
    APPROVALS = "approvals"
    EXCEPTIONS = "exceptions"
    UNKNOWNS = "unknowns"
    FAILED_BRANCHES = "failed_branches"
    ACTION_SCOPE = "action_scope"
    #: A rule family this build does not know (an organisation's own analyser).
    #: Kept and shown rather than folded into a dimension it was not written for.
    OTHER = "other"


class ConditionEffect(str, Enum):
    BLOCK = "BLOCK"
    HOLD = "HOLD"
    ADVISORY = "ADVISORY"
    ACCEPTED = "ACCEPTED"          # a declared exception: named, and not holding
    SATISFIED = "SATISFIED"        # a requirement that was met
    NOT_APPLICABLE = "NOT_APPLICABLE"


_RANK = {ConditionEffect.BLOCK: 0, ConditionEffect.HOLD: 1, ConditionEffect.ACCEPTED: 2,
         ConditionEffect.ADVISORY: 3, ConditionEffect.SATISFIED: 4,
         ConditionEffect.NOT_APPLICABLE: 5}

_D = AdmissionDimension

#: Each rule family's dimension, and the rules that sit elsewhere than their
#: family. Every analyser rule has a dimension; the suite holds that.
_FAMILY = {
    "RG-CRIT": _D.CRITICAL_CLAIMS, "RG-VERIF": _D.CLAIM_STATUS, "RG-COV": _D.COVERAGE,
    "RG-CEX": _D.COUNTEREXAMPLES, "RG-ADV": _D.COUNTEREXAMPLES,
    "RG-CONTRA": _D.CONTRADICTIONS, "RG-ASSUME": _D.ASSUMPTIONS,
    "RG-DRIFT": _D.STATE_BINDING, "RG-INDEP": _D.INDEPENDENCE, "RG-PROV": _D.INDEPENDENCE,
    "RG-REPL": _D.INDEPENDENCE, "RG-EXPECT": _D.REQUIRED_EVIDENCE,
    "RG-BRANCH": _D.FAILED_BRANCHES, "RG-SEM": _D.UNKNOWNS, "RG-CAP": _D.ACTION_SCOPE,
    "RG-CONS": _D.ACTION_SCOPE,
}
_RULE = {
    # Below the admission level is the claim's status, not what it rests on.
    "RG-CRIT-006": _D.CLAIM_STATUS,
    # A claim with no evidence at all is a claim's status; an input nobody could
    # read, or a collection never supplied, is something unknown.
    "RG-COV-003": _D.CLAIM_STATUS,
    "RG-COV-001": _D.UNKNOWNS, "RG-COV-002": _D.UNKNOWNS, "RG-COV-004": _D.UNKNOWNS,
    "RG-COV-005": _D.UNKNOWNS,
    # Accepted risk, and a finding closed by the party it was raised against.
    "RG-CEX-005": _D.EXCEPTIONS, "RG-ADV-003": _D.EXCEPTIONS, "RG-ADV-004": _D.EXCEPTIONS,
    # Replications that disagree are a disagreement.
    "RG-REPL-001": _D.CONTRADICTIONS, "RG-REPL-002": _D.CONTRADICTIONS,
    # A check of superseded content, or of no stated state, is a binding question.
    "RG-VERIF-004": _D.STATE_BINDING, "RG-VERIF-005": _D.STATE_BINDING,
    "RG-SEM-001": _D.CONTRADICTIONS, "RG-SEM-004": _D.STATE_BINDING,
    "RG-SEM-006": _D.INDEPENDENCE, "RG-SEM-007": _D.CONTRADICTIONS,
    "RG-CONS-001": _D.UNKNOWNS, "RG-CONS-005": _D.UNKNOWNS,
    "RG-CAP-003": _D.UNKNOWNS, "RG-CAP-004": _D.UNKNOWNS, "RG-CAP-005": _D.UNKNOWNS,
    "RG-EXPECT-002": _D.UNKNOWNS,
}
#: A methodology requirement's dimension, by what its predicate asks.
_PREDICATE = {
    "approval_required": _D.APPROVALS, "approval_not_refused": _D.APPROVALS,
    "assumptions_examined": _D.ASSUMPTIONS,
    "critical_claims_identified": _D.CRITICAL_CLAIMS,
    "critical_claims_verified": _D.CLAIM_STATUS, "no_claim_in_status": _D.CLAIM_STATUS,
    "independence_threshold": _D.INDEPENDENCE, "ancestry_independence": _D.INDEPENDENCE,
    "declared_independence_holds": _D.INDEPENDENCE,
    "replication_established": _D.INDEPENDENCE,
    "applies_to_current_state": _D.STATE_BINDING, "no_unresolved": _D.CONTRADICTIONS,
    "adversarial_review_required": _D.COUNTEREXAMPLES,
    "consequence_declared": _D.ACTION_SCOPE,
}


def dimension_of_rule(rule_id: str) -> AdmissionDimension:
    """The admission dimension a structural rule speaks to."""
    if rule_id in _RULE:
        return _RULE[rule_id]
    family = rule_id.rsplit("-", 1)[0]
    return _FAMILY.get(family, _D.OTHER)


@dataclass(frozen=True)
class AdmissionCondition:
    """One reason the decision is what it is, with what it concerns and who declared it."""

    condition_id: str
    dimension: AdmissionDimension
    effect: ConditionEffect
    summary: str
    #: Where it comes from: a structural rule, a methodology requirement, an open
    #: disagreement on a critical claim, or a documented exception.
    source: str
    #: The policy or ruleset that declared it, by reference.
    declared_by: str
    claims: Tuple[str, ...] = ()
    refs: Tuple[str, ...] = ()
    remedy: str = ""
    #: For an ACCEPTED condition: who or what accepted it, and why.
    accepted_because: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"condition_id": self.condition_id, "dimension": self.dimension.value,
                "effect": self.effect.value, "summary": self.summary,
                "source": self.source, "declared_by": self.declared_by,
                "claims": list(self.claims), "refs": list(self.refs),
                "remedy": self.remedy, "accepted_because": self.accepted_because}


@dataclass(frozen=True)
class ClaimStanding:
    """One claim, where its resolution left it, and the conditions about it."""

    claim_id: str
    statement: str
    status: str
    rule: str
    required: Optional[bool]
    basis: str
    conditions: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"claim_id": self.claim_id, "statement": self.statement,
                "status": self.status, "rule": self.rule, "required": self.required,
                "basis": self.basis, "conditions": list(self.conditions)}


@dataclass(frozen=True)
class DimensionStanding:
    dimension: AdmissionDimension
    #: BLOCK, HOLD, ACCEPTED, ADVISORY or SATISFIED from its conditions;
    #: NOTHING_RAISED when none spoke to it; NOT_REQUIRED for approvals no policy asks for.
    status: str
    conditions: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension.value, "status": self.status,
                "conditions": list(self.conditions)}


@dataclass(frozen=True)
class AdmissionEvaluation:
    """The decision, every condition that produced it, and the policy it was taken under."""

    decision: Decision
    conditions: Tuple[AdmissionCondition, ...] = ()
    claims: Tuple[ClaimStanding, ...] = ()
    policy: Mapping[str, Any] = field(default_factory=dict)
    basis: str = ""
    #: The verdict composed from the conditions, in the engine's established order.
    fired_rules: Tuple[str, ...] = ()
    reasons: Tuple[str, ...] = ()
    methodology_assessed: bool = False

    def of(self, *effects: ConditionEffect) -> Tuple[AdmissionCondition, ...]:
        wanted = set(effects)
        return tuple(c for c in self.conditions if c.effect in wanted)

    @property
    def blocking(self) -> Tuple[AdmissionCondition, ...]:
        return self.of(ConditionEffect.BLOCK)

    @property
    def holding(self) -> Tuple[AdmissionCondition, ...]:
        return self.of(ConditionEffect.HOLD)

    def in_dimension(self, dimension: AdmissionDimension) -> Tuple[AdmissionCondition, ...]:
        """Conditions in one dimension. Exceptions also lists every ACCEPTED
        condition, wherever its own dimension is: an accepted hold on provenance
        is still an exception the policy granted."""
        dimension = AdmissionDimension(dimension)
        return tuple(c for c in self.conditions if c.dimension is dimension or (
            dimension is AdmissionDimension.EXCEPTIONS
            and c.effect is ConditionEffect.ACCEPTED))

    @property
    def mandatory_claims(self) -> Tuple[ClaimStanding, ...]:
        """Claims the decision rests on — required, or of undetermined criticality."""
        return tuple(c for c in self.claims if c.required is not False)

    def dimensions(self) -> Tuple[DimensionStanding, ...]:
        rows = []
        for dimension in AdmissionDimension:
            held = self.in_dimension(dimension)
            if dimension is AdmissionDimension.OTHER and not held:
                continue
            if held:
                worst = min(held, key=lambda c: _RANK[c.effect]).effect
                status = (worst.value if worst is not ConditionEffect.NOT_APPLICABLE
                          else "NOTHING_RAISED")
            elif dimension is AdmissionDimension.APPROVALS:
                status = "NOT_REQUIRED"
            else:
                status = "NOTHING_RAISED"
            rows.append(DimensionStanding(dimension, status,
                                          tuple(c.condition_id for c in held)))
        return tuple(rows)

    def verdict(self, *, engine_version: str = "", ruleset_version: str = ""
                ) -> CaseVerdict:
        return CaseVerdict(decision=self.decision, fired_rules=self.fired_rules,
                           reasons=self.reasons, engine_version=engine_version,
                           ruleset_version=ruleset_version)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "admission_evaluation",
                "schema_version": ADMISSION_SCHEMA_VERSION,
                "decision": self.decision.value, "basis": self.basis,
                "policy": dict(self.policy),
                "methodology_assessed": self.methodology_assessed,
                "dimensions": [d.to_dict() for d in self.dimensions()],
                "claims": [c.to_dict() for c in self.claims],
                "conditions": [c.to_dict() for c in self.conditions],
                "fired_rules": list(self.fired_rules),
                "decided_by_score": False}


# ── building it ──────────────────────────────────────────────────────────────

def _policy_of(analysis: Any, assessment: MethodologyAssessment) -> Dict[str, Any]:
    resolution = getattr(analysis, "resolution", None)
    policy = getattr(resolution, "policy", None)
    return {"ruleset": getattr(analysis, "ruleset_version", ""),
            "resolution_policy": policy.ref if policy is not None else None,
            "resolution_policy_digest": policy.digest() if policy is not None else None,
            "independence_policy": (policy.independence.ref if policy is not None
                                    else None),
            "methodology": assessment.methodology_ref,
            "methodology_digest": assessment.methodology_digest,
            "methodology_status": assessment.status.value}


def _effect(effect: RequirementEffect) -> ConditionEffect:
    return ConditionEffect(RequirementEffect(effect).value)


def evaluate_admission(analysis: Any, assessment: MethodologyAssessment, *,
                       methodology: Optional[Any] = None,
                       consequence: Optional[Any] = None) -> AdmissionEvaluation:
    """Every condition, the decision they come to, and the verdict that records it."""
    policy = _policy_of(analysis, assessment)
    ruleset = policy["ruleset"] or "structural"
    resolution = getattr(analysis, "resolution", None)
    claim_ids = {r.claim_id for r in (resolution.resolutions if resolution else ())}

    # A finding names claims directly, or through what it is about: a
    # counterexample or a disagreement carries the claims it targets.
    targets: Dict[str, Tuple[str, ...]] = {}
    ledger = getattr(analysis, "counterexamples", None)
    for attempt in (ledger.attempts if ledger is not None else ()):
        targets[attempt.counterexample_id] = (attempt.target_claim,)
    disagreements = getattr(analysis, "contradictions", None)
    for contradiction in (disagreements.contradictions if disagreements is not None
                          else ()):
        targets[contradiction.contradiction_id] = tuple(contradiction.target_claims)

    def about(refs: Iterable[str]) -> Tuple[str, ...]:
        named: List[str] = []
        for ref in refs:
            named.extend(c for c in ((ref,) if ref in claim_ids else targets.get(ref, ()))
                         if c in claim_ids)
        return tuple(dict.fromkeys(named))

    conditions: List[AdmissionCondition] = []
    fired: List[str] = []
    reasons: List[str] = []

    # Which structural holds this methodology has accepted, given what the case
    # actually states about consequence. Only a HOLD is eligible; a structural
    # BLOCK is never accepted (`AcceptedFinding`).
    findings = list(getattr(analysis, "findings", ()) or ())
    accepted: Dict[str, Any] = {}
    if methodology is not None:
        stated = {d.dimension.value: d.value
                  for d in (consequence.known if consequence else ())}
        for finding in findings:
            if finding.effect is RequirementEffect.HOLD:
                acceptance = methodology.acceptance_for(finding.rule_id, stated)
                if acceptance is not None:
                    accepted[finding.rule_id] = acceptance
    for finding in findings:
        acceptance = accepted.get(finding.rule_id)
        conditions.append(AdmissionCondition(
            condition_id=finding.rule_id, dimension=dimension_of_rule(finding.rule_id),
            effect=(ConditionEffect.ACCEPTED if acceptance is not None
                    else _effect(finding.effect)),
            summary=finding.summary, source="structural rule", declared_by=ruleset,
            claims=about(finding.refs), refs=tuple(finding.refs), remedy=finding.remedy,
            accepted_because=(f"accepted by {assessment.methodology_ref}: "
                              f"{acceptance.rationale}" if acceptance is not None else "")))
    for finding in findings:
        if finding.rule_id in accepted:
            reasons.append(
                f"{finding.rule_id}: accepted by {assessment.methodology_ref} — "
                f"{accepted[finding.rule_id].rationale}. The finding stands and is shown; "
                "this methodology does not treat it as disqualifying here.")

    blocking = [f for f in findings if f.effect is RequirementEffect.BLOCK]
    holding = [f for f in findings if f.effect is RequirementEffect.HOLD
               and f.rule_id not in accepted]
    decision = Decision.HOLD
    if blocking:
        decision = Decision.BLOCK
        fired.append(RULE_STRUCTURAL_BLOCK)
        fired.extend(sorted({f.rule_id for f in blocking}))
        reasons.extend(f"{f.rule_id}: {f.summary}" for f in blocking)

    # What the methodology says this decision needs.
    methodology_ref = assessment.methodology_ref or "no methodology"
    for result in assessment.results:
        dimension = _PREDICATE.get(result.predicate_kind, _D.REQUIRED_EVIDENCE)
        if result.outcome is RequirementOutcome.NOT_APPLICABLE:
            effect = ConditionEffect.NOT_APPLICABLE
        elif result.is_met:
            effect = ConditionEffect.SATISFIED
        else:
            effect = _effect(result.effect)
        conditions.append(AdmissionCondition(
            condition_id=result.requirement_id, dimension=dimension, effect=effect,
            summary=(f"{result.description} — {result.outcome.value}: {result.detail}"
                     if result.detail else f"{result.description} — "
                     f"{result.outcome.value}"),
            source="methodology requirement", declared_by=methodology_ref,
            remedy=result.remedy))

    applied = any(r.outcome is not RequirementOutcome.NOT_APPLICABLE
                  for r in assessment.results)
    if assessment.status is AssessmentStatus.ASSESSED and not applied:
        # A methodology none of whose requirements apply has stated nothing this
        # case meets. There is no basis on which to promote.
        conditions.append(AdmissionCondition(
            condition_id=RULE_STRUCTURAL_HOLD, dimension=_D.REQUIRED_EVIDENCE,
            effect=ConditionEffect.HOLD,
            summary=(f"no requirement of {methodology_ref} applies to this case; nothing "
                     "it requires was met, so there is no basis on which to promote"),
            source="admission", declared_by=methodology_ref,
            remedy="supply a methodology that covers this kind of decision"))

    if assessment.status is not AssessmentStatus.ASSESSED:
        detail = ("structural assurance is complete as far as it goes, but no "
                  "methodology states what evidence this decision requires. Domain "
                  "sufficiency is NOT_ASSESSED."
                  if assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED
                  else f"{assessment.detail or 'the supplied methodology does not cover this case type'}"
                       ". Domain sufficiency is NOT_ASSESSED.")
        conditions.append(AdmissionCondition(
            condition_id=RULE_METHODOLOGY_REQUIRED, dimension=_D.REQUIRED_EVIDENCE,
            effect=ConditionEffect.HOLD, summary=detail, source="admission",
            declared_by="release-gate: no PROMOTE without a methodology",
            remedy="state a methodology — a built-in, an organisation's own, or one "
                   "supplied through the API — and re-run"))
        fired.append(RULE_METHODOLOGY_REQUIRED)
        reasons.append(f"METHODOLOGY_REQUIRED: {detail}")
    else:
        unmet_block = assessment.unmet(RequirementEffect.BLOCK)
        unmet_hold = assessment.unmet(RequirementEffect.HOLD)
        if unmet_block:
            decision = Decision.BLOCK
            fired.extend(r.requirement_id for r in unmet_block)
            reasons.extend(f"{r.requirement_id}: {r.detail}" for r in unmet_block)
        elif unmet_hold or holding or not applied:
            fired.extend(r.requirement_id for r in unmet_hold)
            reasons.extend(f"{r.requirement_id}: {r.detail}" for r in unmet_hold)
        elif decision is not Decision.BLOCK:
            decision = Decision.PROMOTE
            fired.append(RULE_METHODOLOGY_SATISFIED)
            reasons.append(f"every requirement of {assessment.methodology_ref} is met, "
                           "with the coverage recorded on this case")

    # Every unresolved disagreement on a critical claim is named, whatever the
    # decision. Promoting over one is a decision a person may take; taking it
    # silently is not available.
    contradictions = getattr(analysis, "contradictions", None)
    for contradiction in (contradictions.unresolved_critical() if contradictions else ()):
        conditions.append(AdmissionCondition(
            condition_id=contradiction.contradiction_id, dimension=_D.CONTRADICTIONS,
            effect=ConditionEffect.HOLD,
            summary=(f"unresolved disagreement on {', '.join(contradiction.target_claims)} "
                     f"({contradiction.described})"),
            source="open disagreement on a critical claim",
            declared_by="release-gate: a critical claim is not promoted over an open "
                        "disagreement",
            claims=tuple(contradiction.target_claims),
            remedy="resolve it, or record why it does not bear on the decision"))
        fired.append(contradiction.contradiction_id)
        reasons.append(
            f"{contradiction.contradiction_id}: unresolved disagreement on "
            f"{', '.join(contradiction.target_claims)} ({contradiction.critical_basis}) — "
            + " vs ".join(f"{side.label} {len(side.evidence)} record(s)"
                          for side in contradiction.sides)
            + f" [{contradiction.described}]")
        if decision is Decision.PROMOTE:
            decision = Decision.HOLD

    # A counterexample accepted as documented risk does not block, and is never
    # silent: each is named, with who accepted it and where it is written.
    from release_gate.assurance.counterexample import CounterexampleStanding
    for standing in getattr(analysis, "counterexample_standings", ()) or ():
        if standing.standing is CounterexampleStanding.ACCEPTED:
            conditions.append(AdmissionCondition(
                condition_id=standing.counterexample_id, dimension=_D.EXCEPTIONS,
                effect=ConditionEffect.ACCEPTED,
                summary=f"a counterexample to {standing.target_claim} stands",
                source="documented exception",
                declared_by=policy["resolution_policy"] or "resolution policy",
                claims=(standing.target_claim,), accepted_because=standing.reason))
            fired.append(standing.counterexample_id)
            reasons.append(f"{standing.counterexample_id}: a counterexample to "
                           f"{standing.target_claim} stands, accepted as a documented "
                           f"risk — {standing.reason}")

    if holding and decision is Decision.HOLD and RULE_STRUCTURAL_HOLD not in fired:
        fired.append(RULE_STRUCTURAL_HOLD)
        fired.extend(sorted({f.rule_id for f in holding}))
        reasons.extend(f"{f.rule_id}: {f.summary}" for f in holding)
    if (assessment.status is AssessmentStatus.ASSESSED and not applied
            and decision is Decision.HOLD):
        if RULE_STRUCTURAL_HOLD not in fired:
            fired.append(RULE_STRUCTURAL_HOLD)
        reasons.append(f"no requirement of {methodology_ref} applied to this case; "
                       "there is no basis on which to promote")
    if accepted:
        fired.append(RULE_STRUCTURAL_ACCEPTED)
    if not fired:
        conditions.append(AdmissionCondition(
            condition_id=RULE_STRUCTURAL_HOLD, dimension=_D.REQUIRED_EVIDENCE,
            effect=ConditionEffect.HOLD,
            summary="no requirement applied and nothing structural was found",
            source="admission", declared_by=methodology_ref))
        fired.append(RULE_STRUCTURAL_HOLD)
        reasons.append("no requirement applied to this case and nothing structural "
                       "was found; there is no basis on which to promote")
        decision = Decision.HOLD

    # The decision is the worst condition. Composed above in the verdict's own
    # order; checked here against the conditions, so the two cannot drift.
    worst = min((c.effect for c in conditions), key=lambda e: _RANK[e], default=None)
    expected = (Decision.BLOCK if worst is ConditionEffect.BLOCK
                else Decision.HOLD if worst is ConditionEffect.HOLD
                or assessment.status is not AssessmentStatus.ASSESSED
                else Decision.PROMOTE)
    if expected is not decision:
        raise AssertionError(
            f"admission composed {decision.value} and its conditions come to "
            f"{expected.value}; the verdict and its reasons have drifted apart")

    claims = tuple(ClaimStanding(
        claim_id=r.claim_id, statement=r.statement, status=r.status.value, rule=r.rule,
        required=r.required, basis=r.basis,
        conditions=tuple(dict.fromkeys(c.condition_id for c in conditions
                                       if r.claim_id in c.claims)))
        for r in (resolution.resolutions if resolution else ()))
    return AdmissionEvaluation(
        decision=decision, conditions=tuple(conditions), claims=claims, policy=policy,
        basis=_basis(decision, conditions, policy),
        fired_rules=tuple(dict.fromkeys(fired)), reasons=tuple(reasons),
        methodology_assessed=assessment.status is AssessmentStatus.ASSESSED)


def _basis(decision: Decision, conditions: Sequence[AdmissionCondition],
           policy: Mapping[str, Any]) -> str:
    """The decision in one sentence, in terms of conditions and the policy."""
    def listed(selected: Sequence[AdmissionCondition]) -> str:
        shown = "; ".join(
            f"{c.condition_id} ({c.dimension.value}"
            + (f", on {', '.join(c.claims[:3])}" if c.claims else "") + ")"
            for c in selected[:6])
        return shown + (f" (+{len(selected) - 6} more)" if len(selected) > 6 else "")

    under = (f"under {policy.get('methodology') or 'no methodology'} and "
             f"{policy.get('resolution_policy') or 'the default resolution policy'}")
    if decision is Decision.BLOCK:
        block = [c for c in conditions if c.effect is ConditionEffect.BLOCK]
        return f"BLOCK {under}: {len(block)} blocking condition(s) established — " \
               + listed(block)
    if decision is Decision.HOLD:
        hold = [c for c in conditions if c.effect is ConditionEffect.HOLD]
        return f"HOLD {under}: {len(hold)} condition(s) to settle — " + listed(hold)
    return (f"PROMOTE {under}: every applicable requirement is met and no condition "
            "holds or blocks")
