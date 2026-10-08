"""Semantic escalation — which questions go to a model, decided before any model is asked.

The semantic verifier answers one question about one claim. This module decides
which questions are worth asking, and it decides deterministically: from the
declared policy, the deterministic analysis, the case's records and what the
provider declared it can do. The same inputs give the same plan, the plan is
persisted beside the answers it led to, and no part of it reads a model's output.

    deterministic analysis + records ─┐
    declared escalation policy ───────┼─▶ plan_escalation() ─▶ EscalationPlan
    provider capabilities (or none) ──┘        every claim and finding considered,
                                               each with a mode, a decision and why

**Every rule declares how it is adjudicated.**

* `DETERMINISTIC` — the rules decide, and a reading cannot bear on the result.
  Model output reaching `os.system` (RG-EXEC-001) is established by the source-to-
  sink path; a model that disagrees has an opinion about a fact. Every structural
  rule, and every scanner rule but one, is DETERMINISTIC.
* `HYBRID` — static analysis establishes a fact, and a reading weighs something
  the submission supplied about it. RG-GATE-001 establishes that an agent tool
  performs an irreversible action with no code-level approval gate on the path;
  whether an approval mechanism the submission supplies — an orchestrator rule, a
  platform policy, a procedure — actually controls that path is a reading. The
  question binds to the claim the mechanism argues for, never to the finding: the
  finding stays, and what it contradicts stays contradicted.
* `SEMANTIC` — only a reading can settle it: whether external evidence supports a
  claim, whether a fallback preserves the objective, whether two policy statements
  are consistent. In a case each of these is a claim whose support is declared
  rather than checked, and the question is the verifier's own: does what these
  records say bear on, and support, this statement?
* `EXTERNAL_ONLY` — an external producer's result (an evaluator's score, another
  scanner's finding) is ingested as that producer reported it and never re-graded.
  It is not sent to be read, and a claim whose only unchecked support is external
  results is not escalated.

**A model existing is never a reason.** Escalation needs a trigger the
deterministic analysis produced: a claim it left open with unchecked support,
or a HYBRID finding with a mechanism supplied against it. A case whose claims
are all settled, checked or empty asks nothing, however many models are
configured. And a reading cannot reach what the rules settled: a claim already
ESTABLISHED or CONTRADICTED is never asked about, which is what keeps a HIGH
static finding — evidence contradicting `sw:code-safety` — out of any model's
reach.

**What is weighed, in order:**

1. *deterministic completeness* — settled, already checked, nothing to read;
2. *adjudication mode* — DETERMINISTIC and EXTERNAL_ONLY are never asked;
3. *policy* — claims the policy excludes, or names as always worth a question;
4. *criticality* — required claims by default, and claims whose criticality could
   not be determined, because unknown is never read as "does not matter";
5. *prior readings* — an answer already recorded for the same question over the
   same packet is not asked again: re-asking until a model agrees is shopping. A
   question whose earlier attempt failed in transport may be asked again;
6. *availability* — no provider, a provider that cannot take the choices, a
   packet over the policy's size or the provider's declared context;
7. *budget* — at most `max_questions`, and within `max_cost` at the provider's
   declared cost per call. Under a cost budget, a provider that declared no cost
   is not asked: an unknown cost cannot be shown to fit.

What is left is asked in a fixed order — policy-named first, then required,
HYBRID before SEMANTIC, the most open claims first — so a budget cuts the same
questions every time.

**Nothing here changes what an answer does.** The plan decides only whether a
question is asked. What an answer does to a case is the resolution policy's
(resolution.py), the same for every question kind, and a reading never
establishes a claim nor lifts one the rules contradicted.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.semantic_verifier import (
    DECISION_CHOICES, DEFAULT_SEMANTIC_VERIFIER_POLICY, AssertionStatus, EvidencePacket,
    NoQuestion, ProviderCapabilities, ProviderInterface, QuestionKind, SemanticQuestion,
    SemanticVerifier, SemanticVerifierPolicy, UnknownReason, assertions_from_records,
    build_evidence_packet, question_for)

__all__ = [
    "DEFAULT_ESCALATION_POLICY",
    "ESCALATION_SCHEMA_VERSION",
    "QUESTION_MODES",
    "SCANNER_RULE_MODES",
    "AdjudicationMode",
    "EscalationDecision",
    "EscalationError",
    "EscalationPlan",
    "EscalationPolicy",
    "EscalationReason",
    "EscalationScope",
    "adjudication_mode",
    "is_external_result",
    "plan_escalation",
]

ESCALATION_SCHEMA_VERSION = 1


class EscalationError(ValueError):
    """An escalation policy that would let a reading reach what it may not."""


class AdjudicationMode(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"   # the rules decide; a reading cannot bear on it
    HYBRID = "HYBRID"                 # the rules establish the fact; a reading weighs a mechanism
    SEMANTIC = "SEMANTIC"             # only a reading can settle it; the policy weighs the reading
    EXTERNAL_ONLY = "EXTERNAL_ONLY"   # an external producer's result, never re-graded


_D, _H = AdjudicationMode.DETERMINISTIC, AdjudicationMode.HYBRID

#: Every scanner rule, by name. A test holds this equal to the static producer's
#: profiles, so a rule added to the catalogue has to state its mode.
SCANNER_RULE_MODES: Mapping[str, AdjudicationMode] = {
    "RG-EXEC-001": _D, "RG-EXEC-002": _D, "RG-EXEC-003": _D,
    "RG-ACTION-002": _D, "RG-ACTION-003": _D, "RG-ACTION-004": _D,
    "RG-PARSE-001": _D, "RG-TOOL-001": _D,
    #: The one static fact whose profile names what static analysis cannot see —
    #: an out-of-band control on the path — and a submission can supply.
    "RG-GATE-001": _H,
    "RG-PII-001": _D, "RG-PROMPT-001": _D, "RG-PROMPT-002": _D,
    "RG-COST-001": _D, "RG-COST-002": _D, "RG-LOOP-001": _D,
    "RG-SECRET-001": _D, "RG-SECRET-002": _D,
}

#: What each question kind is. The verifier's two questions, and nothing else.
QUESTION_MODES: Mapping[QuestionKind, AdjudicationMode] = {
    QuestionKind.EVIDENCE_SUPPORTS_CLAIM: AdjudicationMode.SEMANTIC,
    QuestionKind.MECHANISM_CONTROLS_PATH: AdjudicationMode.HYBRID,
}


def adjudication_mode(rule_id: str) -> AdjudicationMode:
    """A rule's declared mode. Scanner rules by name; every other rule is DETERMINISTIC.

    A structural rule reasons over the case's structure, so there is nothing
    for a reading to weigh. A rule id nobody registered is DETERMINISTIC too:
    the default never opens anything to a model.
    """
    return SCANNER_RULE_MODES.get(str(rule_id or "").strip(), AdjudicationMode.DETERMINISTIC)


def is_external_result(record: Any) -> bool:
    """A result an external producer reported through the producer contract."""
    content = getattr(record, "content", None) or {}
    return (isinstance(content, Mapping) and bool(content.get("result_kind"))
            and bool(content.get("producer_type")))


# ── policy ───────────────────────────────────────────────────────────────────

class EscalationScope(str, Enum):
    #: Required claims, and claims whose criticality could not be determined.
    REQUIRED_OR_UNDETERMINED = "REQUIRED_OR_UNDETERMINED"
    #: Only claims the criticality analysis marks required.
    REQUIRED = "REQUIRED"
    ALL = "ALL"


@dataclass(frozen=True)
class EscalationPolicy:
    """Which questions are worth asking. Declared, recorded, and read deterministically."""

    policy_id: str = "rg-escalation"
    version: str = "1"
    scope: EscalationScope = EscalationScope.REQUIRED_OR_UNDETERMINED
    #: Claims the policy requires a reading for whenever they are open, in or out
    #: of scope. Still subject to everything else: settled is settled.
    always: Tuple[str, ...] = ()
    #: Claims never sent, whatever else holds.
    never: Tuple[str, ...] = ()
    #: Whether HYBRID findings with a supplied mechanism are asked about at all.
    hybrid: bool = True
    max_questions: int = 10
    #: In the unit the provider's `cost_per_call` is declared in. None: no cost budget.
    max_cost: Optional[float] = None
    #: Rule id → mode. A policy may withdraw a rule from reading (DETERMINISTIC);
    #: it cannot open one the catalogue declares DETERMINISTIC.
    modes: Mapping[str, AdjudicationMode] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", EscalationScope(self.scope))
        for name in ("always", "never"):
            object.__setattr__(self, name, tuple(sorted({str(c) for c in getattr(self, name)
                                                         if str(c).strip()})))
        both = set(self.always) & set(self.never)
        if both:
            raise EscalationError(f"{', '.join(sorted(both))} cannot be both always and "
                                  "never asked about")
        if (isinstance(self.max_questions, bool) or not isinstance(self.max_questions, int)
                or self.max_questions < 0):
            raise EscalationError("max_questions is a non-negative integer")
        if self.max_cost is not None:
            if isinstance(self.max_cost, bool) or not isinstance(self.max_cost, (int, float)):
                raise EscalationError("max_cost is a number")
            if not 0 <= float(self.max_cost) < float("inf"):
                raise EscalationError("max_cost is a finite, non-negative number")
            object.__setattr__(self, "max_cost", float(self.max_cost))
        modes: Dict[str, AdjudicationMode] = {}
        for rule, mode in dict(self.modes or {}).items():
            declared, wanted = adjudication_mode(rule), AdjudicationMode(mode)
            if wanted is not declared and wanted is not AdjudicationMode.DETERMINISTIC:
                raise EscalationError(
                    f"{rule} is {declared.value}: a policy can withdraw a rule from "
                    f"reading (DETERMINISTIC) but cannot make it {wanted.value}")
            modes[str(rule)] = wanted
        object.__setattr__(self, "modes", dict(sorted(modes.items())))

    def mode_for(self, rule_id: str) -> AdjudicationMode:
        return self.modes.get(str(rule_id or ""), adjudication_mode(rule_id))

    @property
    def ref(self) -> str:
        return f"{self.policy_id}@{self.version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id, "version": self.version,
                "scope": self.scope.value, "always": list(self.always),
                "never": list(self.never), "hybrid": self.hybrid,
                "max_questions": self.max_questions, "max_cost": self.max_cost,
                "modes": {k: v.value for k, v in self.modes.items()},
                "schema_version": ESCALATION_SCHEMA_VERSION}

    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EscalationPolicy":
        if not isinstance(data, Mapping):
            raise EscalationError("an escalation policy is a JSON object")
        unknown = sorted(set(data) - {"policy_id", "version", "scope", "always", "never",
                                      "hybrid", "max_questions", "max_cost", "modes",
                                      "schema_version"})
        if unknown:
            raise EscalationError(f"unknown escalation policy field(s): {', '.join(unknown)}")
        default = DEFAULT_ESCALATION_POLICY
        modes = data.get("modes", {})
        if not isinstance(modes, Mapping):
            raise EscalationError("modes is an object of rule id → mode")
        for name in ("always", "never"):
            if not isinstance(data.get(name, ()), (list, tuple)):
                raise EscalationError(f"{name} is a list of claim ids")
        if not isinstance(data.get("hybrid", True), bool):
            raise EscalationError("hybrid is true or false")
        try:
            return cls(policy_id=str(data.get("policy_id") or default.policy_id),
                       version=str(data.get("version") or default.version),
                       scope=EscalationScope(str(data.get("scope") or default.scope.value)),
                       always=tuple(data.get("always") or ()),
                       never=tuple(data.get("never") or ()),
                       hybrid=data.get("hybrid", True),
                       max_questions=data.get("max_questions", default.max_questions),
                       max_cost=data.get("max_cost"),
                       modes={str(k): AdjudicationMode(str(v)) for k, v in modes.items()})
        except ValueError as exc:
            if isinstance(exc, EscalationError):
                raise
            raise EscalationError(f"unusable escalation policy: {exc}") from exc


DEFAULT_ESCALATION_POLICY = EscalationPolicy()


# ── decisions ────────────────────────────────────────────────────────────────

class EscalationReason(str, Enum):
    # asked
    OPEN_CLAIM = "OPEN_CLAIM"                  # left open, with unchecked support
    MECHANISM_SUPPLIED = "MECHANISM_SUPPLIED"  # a HYBRID fact, and a mechanism against it
    # not asked: the deterministic analysis
    SETTLED = "SETTLED"
    CHECKED = "CHECKED"
    NOTHING_TO_READ = "NOTHING_TO_READ"
    # not asked: the mode
    DETERMINISTIC_RULE = "DETERMINISTIC_RULE"
    EXTERNAL_ONLY = "EXTERNAL_ONLY"
    NO_MECHANISM = "NO_MECHANISM"
    MECHANISM_UNBOUND = "MECHANISM_UNBOUND"
    # not asked: the policy
    EXCLUDED_BY_POLICY = "EXCLUDED_BY_POLICY"
    HYBRID_DISABLED = "HYBRID_DISABLED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    ALREADY_READ = "ALREADY_READ"
    # not asked: availability and budget
    NO_MODEL = "NO_MODEL"
    UNSUPPORTED_BY_PROVIDER = "UNSUPPORTED_BY_PROVIDER"
    PACKET_TOO_LARGE = "PACKET_TOO_LARGE"
    EXCEEDS_CONTEXT = "EXCEEDS_CONTEXT"
    QUESTION_BUDGET = "QUESTION_BUDGET"
    COST_BUDGET = "COST_BUDGET"
    UNKNOWN_COST = "UNKNOWN_COST"


_ASKED = frozenset({EscalationReason.OPEN_CLAIM, EscalationReason.MECHANISM_SUPPLIED})

_FROM_NO_QUESTION = {NoQuestion.SETTLED: EscalationReason.SETTLED,
                     NoQuestion.CHECKED: EscalationReason.CHECKED,
                     NoQuestion.NOTHING_TO_READ: EscalationReason.NOTHING_TO_READ}

#: UNKNOWN reasons that are the model's own answer — asking again is shopping.
#: Anything else (unreachable, timed out, not sent) never reached a reading.
_ANSWERED_UNKNOWNS = frozenset({
    UnknownReason.MALFORMED_RESPONSE, UnknownReason.MISMATCHED_QUESTION,
    UnknownReason.OUT_OF_PACKET_REFERENCE, UnknownReason.LOW_CONFIDENCE,
    UnknownReason.NO_PROBABILITY, UnknownReason.NO_DECISION})


@dataclass(frozen=True)
class EscalationDecision:
    """One claim or finding, its mode, and whether a question about it is asked."""

    subject: str                    # a claim id, or a finding's evidence id
    subject_kind: str               # "claim" | "finding"
    mode: AdjudicationMode
    reason: EscalationReason
    detail: str
    rule_id: str = ""
    claim_id: str = ""
    question: Optional[SemanticQuestion] = None
    packet_hash: str = ""
    estimated_cost: Optional[float] = None
    #: 1-based position among the questions asked; 0 when not asked.
    rank: int = 0

    @property
    def escalated(self) -> bool:
        return self.reason in _ASKED

    def to_dict(self) -> Dict[str, Any]:
        return {"subject": self.subject, "subject_kind": self.subject_kind,
                "mode": self.mode.value, "escalated": self.escalated,
                "reason": self.reason.value, "detail": self.detail,
                "rule_id": self.rule_id or None, "claim_id": self.claim_id or None,
                "question": self.question.to_dict() if self.question else None,
                "packet_hash": self.packet_hash or None,
                "estimated_cost": self.estimated_cost, "rank": self.rank}


@dataclass(frozen=True)
class EscalationPlan:
    """Every subject considered, in a fixed order, and the packets of those asked."""

    decisions: Tuple[EscalationDecision, ...]
    packets: Tuple[EvidencePacket, ...]
    policy: EscalationPolicy
    capabilities: Optional[ProviderCapabilities] = None
    state_hash: str = ""

    @property
    def escalated(self) -> Tuple[EscalationDecision, ...]:
        return tuple(sorted((d for d in self.decisions if d.escalated),
                            key=lambda d: d.rank))

    @property
    def questions(self) -> Tuple[SemanticQuestion, ...]:
        return tuple(d.question for d in self.escalated if d.question is not None)

    @property
    def estimated_cost(self) -> Optional[float]:
        costs = [d.estimated_cost for d in self.escalated]
        if not costs:
            return 0.0
        return None if any(c is None for c in costs) else round(sum(costs), 9)

    def counts(self) -> Dict[str, int]:
        found: Dict[str, int] = {}
        for decision in self.decisions:
            found[decision.reason.value] = found.get(decision.reason.value, 0) + 1
        return dict(sorted(found.items()))

    def to_dict(self) -> Dict[str, Any]:
        body = {"schema_version": ESCALATION_SCHEMA_VERSION,
                "policy": self.policy.ref, "policy_detail": self.policy.to_dict(),
                "policy_digest": self.policy.digest(),
                "capabilities": (self.capabilities.to_dict()
                                 if self.capabilities is not None else None),
                "state_hash": self.state_hash,
                "decisions": [d.to_dict() for d in self.decisions],
                "asked": len(self.escalated), "considered": len(self.decisions),
                "estimated_cost": self.estimated_cost, "by_reason": self.counts()}
        return {"record_type": "escalation_plan", "plan_digest": digest_object(body),
                **body}


# ── reading the case ─────────────────────────────────────────────────────────

def _payload(record: Any) -> Mapping[str, Any]:
    """The record's own fields — at the top of its content, or one level down when
    a serialised record was read back as an envelope row."""
    content = getattr(record, "content", None) or {}
    if not isinstance(content, Mapping):
        return {}
    inner = content.get("content")
    if isinstance(inner, Mapping) and ("rule_id" in inner or "addresses" in inner
                                       or "safeguard" in inner):
        return {**inner, **{k: v for k, v in content.items() if k in ("addresses",)}}
    return content


def _finding_rule(record: Any) -> Optional[str]:
    """The rule a static finding was raised under, or None for any other record."""
    if getattr(getattr(record, "evidence_type", None), "value", "") != "STATIC_FINDING":
        return None
    if not tuple(getattr(record, "contradicts_claims", ()) or ()):
        return None
    payload = _payload(record)
    if isinstance(payload.get("rule_id"), str) and payload["rule_id"].strip():
        return payload["rule_id"].strip()
    if isinstance(payload.get("safeguard"), str):
        return f"safeguard:{payload['safeguard']}"
    return "unidentified"


def _addresses(record: Any) -> Tuple[str, ...]:
    stated = _payload(record).get("addresses")
    items = stated if isinstance(stated, (list, tuple)) else [stated] if stated else []
    return tuple(sorted({str(x).strip() for x in items if str(x).strip()}))


def _where(record: Any) -> str:
    payload = _payload(record)
    file, line = payload.get("file"), payload.get("line")
    return f" at {file}:{line}" if file else ""


_STATUS_RANK = {"UNKNOWN": 0, "PARTIALLY_SUPPORTED": 1, "SUPPORTED": 2}


def _required_rank(required: Optional[bool]) -> int:
    return 0 if required is True else 1 if required is None else 2


def _in_scope(policy: EscalationPolicy, *required: Optional[bool]) -> bool:
    if policy.scope is EscalationScope.ALL:
        return True
    if any(r is True for r in required):
        return True
    return (policy.scope is EscalationScope.REQUIRED_OR_UNDETERMINED
            and any(r is None for r in required))


def _request_chars(packet: EvidencePacket, capabilities: ProviderCapabilities,
                   verifier_policy: SemanticVerifierPolicy) -> int:
    """What the verifier would send this provider — computed by the verifier itself."""
    shaper = SemanticVerifier(None, policy=verifier_policy)
    if capabilities.interface is ProviderInterface.DECISION:
        return len(shaper.decision_request_for(packet).as_text())
    request = shaper.request_for(packet)
    return len(request.system) + len(request.user)


# ── the plan ─────────────────────────────────────────────────────────────────

def plan_escalation(resolution: Any, records: Iterable[Any], *,
                    attempts: Optional[Mapping[str, Any]] = None,
                    policy: EscalationPolicy = DEFAULT_ESCALATION_POLICY,
                    verifier_policy: SemanticVerifierPolicy = DEFAULT_SEMANTIC_VERIFIER_POLICY,
                    capabilities: Optional[ProviderCapabilities] = None,
                    state_hash: str = "",
                    asked_of: Optional[Tuple[str, str]] = None) -> EscalationPlan:
    """Decide, for every claim and every static finding, whether a question is asked.

    `resolution` is the deterministic claim resolution (`analysis.resolution`);
    `records` the case's evidence; `capabilities` what the provider declared, or
    None when no provider is available. `asked_of` is the (provider, model) a
    panel member is: only its own earlier readings count as already asked
    (semantic_panel.py). Without it, any reading of the question does. Pure:
    nothing here asks anything.
    """
    evidence = [r for r in records if getattr(r, "evidence_id", None)]
    by_id = {r.evidence_id: r for r in evidence}
    resolutions = sorted(getattr(resolution, "resolutions", ()) or (),
                         key=lambda r: r.claim_id)
    by_claim = {r.claim_id: r for r in resolutions}
    prior = {(a.question_id, a.packet_hash) for _, a in assertions_from_records(evidence)
             if (a.status is AssertionStatus.ANSWERED
                 or a.unknown_reason in _ANSWERED_UNKNOWNS)
             and (asked_of is None or (a.provider, a.model) == tuple(asked_of))}

    decisions: List[EscalationDecision] = []
    candidates: List[Tuple[Tuple[Any, ...], EscalationDecision]] = []

    def settle(decision: EscalationDecision) -> None:
        decisions.append(decision)

    def candidate(decision: EscalationDecision, status: str,
                  required: Tuple[Optional[bool], ...]) -> None:
        key = (0 if decision.claim_id in policy.always else 1,
               min(_required_rank(r) for r in required),
               0 if decision.mode is AdjudicationMode.HYBRID else 1,
               _STATUS_RANK.get(status, 3), decision.claim_id, decision.subject,
               decision.question.question_id if decision.question else "")
        candidates.append((key, decision))

    # ── claims: SEMANTIC ────────────────────────────────────────────────────
    for res in resolutions:
        base = dict(subject=res.claim_id, subject_kind="claim", claim_id=res.claim_id,
                    mode=AdjudicationMode.SEMANTIC)
        if res.claim_id in policy.never:
            settle(EscalationDecision(**base, reason=EscalationReason.EXCLUDED_BY_POLICY,
                                      detail="the policy never sends this claim"))
            continue
        question, why = question_for(res)
        if question is None:
            settle(EscalationDecision(**base, reason=_FROM_NO_QUESTION[why], detail=(
                f"{res.status.value} under {res.rule}: the deterministic rules settled "
                "it, and a reading cannot move it" if why is NoQuestion.SETTLED else
                f"{res.status.value}: everything readable is already a check of an "
                "establishing kind" if why is NoQuestion.CHECKED else
                f"{res.status.value}: nothing readable bears on it")))
            continue
        external = {i.item_id for i in res.items if is_external_result(by_id.get(i.item_id))}
        if external:
            view = dataclasses.replace(res, items=tuple(
                i for i in res.items if i.item_id not in external))
            question, _ = question_for(view)
            if question is None:
                settle(EscalationDecision(**base, reason=EscalationReason.EXTERNAL_ONLY,
                                          detail=f"its only unchecked support is "
                                                 f"{len(external)} external result(s), "
                                                 "which are ingested and not re-graded"))
                continue
        if res.claim_id not in policy.always and not _in_scope(policy, res.required):
            settle(EscalationDecision(**base, reason=EscalationReason.OUT_OF_SCOPE, detail=(
                f"not a required claim, and the policy's scope is {policy.scope.value}")))
            continue
        candidate(EscalationDecision(**base, reason=EscalationReason.OPEN_CLAIM,
                                     question=question,
                                     detail=question.unresolved_because),
                  res.status.value, (res.required,))

    # ── findings: DETERMINISTIC, HYBRID, EXTERNAL_ONLY ──────────────────────
    findings = [(r, rule) for r in sorted(evidence, key=lambda r: r.evidence_id)
                for rule in (_finding_rule(r),) if rule is not None]
    # Another producer's findings are listed too, so the plan shows them set
    # aside rather than leaving them out: they are reported, never re-graded.
    findings += [(r, str(r.content.get("native_id") or ""))
                 for r in sorted(evidence, key=lambda r: r.evidence_id)
                 if is_external_result(r) and _finding_rule(r) is None
                 and r.content.get("result_kind") == "FINDING"]
    finding_ids = {r.evidence_id for r, _ in findings}
    mechanisms = [r for r in sorted(evidence, key=lambda r: r.evidence_id)
                  if r.evidence_id not in finding_ids and _addresses(r)]
    for record, rule in findings:
        against = tuple(sorted(record.contradicts_claims))
        base = dict(subject=record.evidence_id, subject_kind="finding", rule_id=rule)
        if is_external_result(record):
            settle(EscalationDecision(**base, mode=AdjudicationMode.EXTERNAL_ONLY,
                                      reason=EscalationReason.EXTERNAL_ONLY,
                                      detail="an external producer's result, ingested as "
                                             "reported and not re-graded"))
            continue
        mode = policy.mode_for(rule)
        if mode is not AdjudicationMode.HYBRID:
            settle(EscalationDecision(**base, mode=mode,
                                      reason=EscalationReason.DETERMINISTIC_RULE,
                                      detail=f"{rule}{_where(record)} is established by "
                                             f"the rules and contradicts "
                                             f"{', '.join(against)}; a reading may explain "
                                             "it and cannot change it"))
            continue
        if not policy.hybrid:
            settle(EscalationDecision(**base, mode=mode,
                                      reason=EscalationReason.HYBRID_DISABLED,
                                      detail="the policy does not ask HYBRID questions"))
            continue
        supplied = [m for m in mechanisms
                    if rule in _addresses(m) or record.evidence_id in _addresses(m)]
        if not supplied:
            settle(EscalationDecision(**base, mode=mode, reason=EscalationReason.NO_MECHANISM,
                                      detail=f"{rule}{_where(record)} stands; nothing in the "
                                             "case says it addresses it, so there is "
                                             "nothing to weigh"))
            continue
        bound = sorted({c for m in supplied for c in m.supports_claims if c in by_claim})
        if not bound:
            settle(EscalationDecision(**base, mode=mode,
                                      reason=EscalationReason.MECHANISM_UNBOUND,
                                      detail=f"{len(supplied)} record(s) address {rule} and "
                                             "support no claim in this case, so a reading "
                                             "would bear on nothing"))
            continue
        for claim_id in bound:
            res = by_claim[claim_id]
            sub = dict(base, subject=f"{record.evidence_id}->{claim_id}", claim_id=claim_id,
                       mode=mode)
            if claim_id in policy.never:
                settle(EscalationDecision(**sub, reason=EscalationReason.EXCLUDED_BY_POLICY,
                                          detail="the policy never sends this claim"))
                continue
            if res.status.value in ("ESTABLISHED", "CONTRADICTED"):
                settle(EscalationDecision(**sub, reason=EscalationReason.SETTLED,
                                          detail=f"{claim_id} is {res.status.value} under "
                                                 f"{res.rule}; a reading cannot move it"))
                continue
            readable = {i.item_id for i in res.items
                        if i.role.value in ("SUPPORTS", "INCONCLUSIVE")}
            refs = [m.evidence_id for m in supplied
                    if claim_id in m.supports_claims and m.evidence_id in readable]
            if not refs:
                settle(EscalationDecision(**sub, reason=EscalationReason.NOTHING_TO_READ,
                                          detail=f"the rules set aside the mechanism "
                                                 f"record(s) for {claim_id}"))
                continue
            required = (res.required, *(by_claim[c].required for c in against
                                        if c in by_claim))
            if claim_id not in policy.always and not _in_scope(policy, *required):
                settle(EscalationDecision(**sub, reason=EscalationReason.OUT_OF_SCOPE,
                                          detail=f"neither {claim_id} nor what the finding "
                                                 "contradicts is required, and the "
                                                 f"policy's scope is {policy.scope.value}"))
                continue
            question = SemanticQuestion(
                claim_id=claim_id, statement=res.statement,
                evidence_refs=(record.evidence_id, *refs),
                kind=QuestionKind.MECHANISM_CONTROLS_PATH,
                unresolved_because=(f"{rule}{_where(record)}: static analysis established "
                                    f"the action and contradicts {', '.join(against)}; "
                                    f"{len(refs)} supplied record(s) say a mechanism "
                                    "controls it"))
            candidate(EscalationDecision(**sub, reason=EscalationReason.MECHANISM_SUPPLIED,
                                         question=question,
                                         detail=question.unresolved_because),
                      res.status.value, required)

    # ── availability, prior readings and budget, in priority order ──────────
    packets: List[EvidencePacket] = []
    asked = 0
    spent = 0.0
    cost = capabilities.cost_per_call if capabilities is not None else None
    for _, decision in sorted(candidates, key=lambda c: c[0]):
        question = decision.question
        packet = build_evidence_packet(question, records=by_id, attempts=attempts,
                                       state_hash=state_hash, policy=verifier_policy)
        stamped = dataclasses.replace(decision, packet_hash=packet.packet_hash)

        def refuse(reason: EscalationReason, detail: str) -> None:
            settle(dataclasses.replace(stamped, reason=reason, detail=detail))

        if (question.question_id, packet.packet_hash) in prior:
            refuse(EscalationReason.ALREADY_READ,
                   "this question over this packet already has a reading in the case; "
                   "asking again until a model agrees would be shopping")
            continue
        if not packet.items:
            refuse(EscalationReason.NOTHING_TO_READ,
                   "none of the records the question names is held by this case")
            continue
        if packet.over_budget:
            refuse(EscalationReason.PACKET_TOO_LARGE,
                   f"the packet is {packet.size()} characters; the verifier policy "
                   f"allows {verifier_policy.max_packet_chars}")
            continue
        if capabilities is None:
            refuse(EscalationReason.NO_MODEL,
                   "would be asked; no provider is available, so the claim stays where "
                   "the deterministic rules put it")
            continue
        if (capabilities.max_choices is not None
                and capabilities.max_choices < len(DECISION_CHOICES)):
            refuse(EscalationReason.UNSUPPORTED_BY_PROVIDER,
                   f"the provider takes {capabilities.max_choices} choices; a question "
                   f"offers {len(DECISION_CHOICES)}")
            continue
        size = _request_chars(packet, capabilities, verifier_policy)
        if capabilities.max_input_chars is not None and size > capabilities.max_input_chars:
            refuse(EscalationReason.EXCEEDS_CONTEXT,
                   f"the request is {size} characters; the provider declares "
                   f"{capabilities.max_input_chars}")
            continue
        if asked >= policy.max_questions:
            refuse(EscalationReason.QUESTION_BUDGET,
                   f"the policy asks at most {policy.max_questions} question(s)")
            continue
        if policy.max_cost is not None:
            if cost is None:
                refuse(EscalationReason.UNKNOWN_COST,
                       f"the policy budgets {policy.max_cost} and the provider declared "
                       "no cost per call, so no call can be shown to fit")
                continue
            if spent + cost > policy.max_cost + 1e-12:
                refuse(EscalationReason.COST_BUDGET,
                       f"{spent} of {policy.max_cost} spent; one more call costs {cost}")
                continue
            spent += cost
        asked += 1
        packets.append(packet)
        settle(dataclasses.replace(stamped, rank=asked, estimated_cost=cost))

    ordered = tuple(sorted(decisions, key=lambda d: (d.subject_kind, d.subject,
                                                     d.claim_id)))
    return EscalationPlan(decisions=ordered, packets=tuple(packets), policy=policy,
                          capabilities=capabilities, state_hash=state_hash)
