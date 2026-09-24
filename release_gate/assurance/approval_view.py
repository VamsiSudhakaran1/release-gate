"""The last surface before a person acts, built around one question.

    What exactly am I taking responsibility for if I click Approve?

Everything here exists to make that answerable *before* the click rather than
reconstructible after it. The packet already answers eleven reviewer questions
and owns what a human reads (§9); this is the layer that puts those answers in
the order the question demands, binds each of the three actions to exact state,
and makes "do not bury unresolved high-impact issues" something a test can check.

**Un-burying is structural, not a convention.** A rendering habit drifts the
first time someone adds a section. So `ApprovalView` refuses to construct if any
blocking or undroppable item is missing from the body it rendered, and every such
item is placed above the supporting evidence and above the actions. A reviewer
who scrolls past the problems did so knowing they were there.

**Three actions, each bound.** APPROVE carries the exact acknowledgement
`submit_approval` will verify against the live case — not a token, but the
version, the subject state and the evidence state named, so a client approving
something other than what it read is refused rather than recorded. REJECT is a
decision on the record. REQUEST EVIDENCE is `DEFERRED` with the required-evidence
protocol attached: a work order an external verifier can act on, which is what
makes a hold something other than a shrug.

There is deliberately no fourth action and no "approve with reservations". A
reservation that changes nothing is a comment; one that changes something is a
different decision, and both belong in the record as what they are.

**The view never authorises.** `authorises` returns `False` unconditionally.
This is a document; the act is a person's, and a document that could stand in for
it is exactly the substitution Invariant 15 exists to prevent.

**Nothing here computes.** Every figure is read from the packet, the offer, the
attention set or the required-evidence set. A view that derived its own numbers
would be a second opinion presented as the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.approval import (
    ApprovalAcknowledgement, ApprovalDecision, ApprovalOffer, offer_approval)
from release_gate.assurance.packet import SectionKey

__all__ = [
    "VIEW_SCHEMA_VERSION",
    "ActionOffer",
    "ApprovalAction",
    "ApprovalView",
    "ApprovalViewError",
    "build_view",
    "render_view",
]

VIEW_SCHEMA_VERSION = 1


class ApprovalViewError(ValueError):
    """A view was built in a state that would mislead the person reading it."""


class ApprovalAction(str, Enum):
    """The three. Each maps to a decision the record already models.

    `REQUEST_EVIDENCE` is not a fourth kind of decision: on the record it is
    `DEFERRED`, with the difference that it carries a work order saying exactly
    what would resolve the hold. Deferring without one is a shrug; deferring with
    one is a request an external verifier can act on without a human in the
    middle of the cycle.
    """

    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUEST_EVIDENCE = "REQUEST_EVIDENCE"


_DECISION: Mapping[ApprovalAction, ApprovalDecision] = {
    ApprovalAction.APPROVE: ApprovalDecision.APPROVED,
    ApprovalAction.REJECT: ApprovalDecision.REJECTED,
    ApprovalAction.REQUEST_EVIDENCE: ApprovalDecision.DEFERRED,
}


@dataclass(frozen=True)
class ActionOffer:
    """One action, what taking it means, and exactly what it would bind to.

    `binds_to` is the whole point. An action offered without the state it
    attaches to is a button; an action offered with it is something a person can
    be held to and a record can be checked against six weeks later.
    """

    action: ApprovalAction
    decision: ApprovalDecision
    means: str
    binds_to: Mapping[str, Any] = field(default_factory=dict)
    payload: Mapping[str, Any] = field(default_factory=dict)
    caution: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", ApprovalAction(self.action))
        object.__setattr__(self, "decision", ApprovalDecision(self.decision))
        if not str(self.means or "").strip():
            raise ApprovalViewError(
                f"{self.action.value}: an action must say what taking it means. A "
                "button whose consequence is not stated is one a person cannot be "
                "held to")

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action.value, "decision": self.decision.value,
                "means": self.means, "binds_to": dict(self.binds_to),
                "payload": dict(self.payload), "caution": self.caution}


#: The nine things a person must be able to read before acting, in the order the
#: question demands rather than the order the packet stores them. Named as a
#: constant so "is anything missing" is a comparison rather than a reading.
REQUIRED_DISPLAYS: Tuple[str, ...] = (
    "subject",              # what exactly
    "expected_effect",      # what happens if I do
    "unresolved",           # what stands against it — before the evidence for it
    "critical_evidence",    # what it rests on
    "coverage",             # what was examined
    "completeness",         # whether all of it arrived
    "not_assessed",         # what nobody looked at
    "subject_digest",       # the exact bytes
    "case_state",           # the exact case and evidence state
)


@dataclass(frozen=True)
class ApprovalView:
    """What a person reads, and the three things they can do about it."""

    case_id: str
    case_version: int
    recommendation: str
    offer: ApprovalOffer
    displays: Mapping[str, Any] = field(default_factory=dict)
    actions: Tuple[ActionOffer, ...] = ()
    unresolved: Tuple[Mapping[str, Any], ...] = ()
    withheld_note: str = ""
    schema_version: int = VIEW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", tuple(self.actions))
        object.__setattr__(self, "unresolved", tuple(self.unresolved))

        missing = [k for k in REQUIRED_DISPLAYS if k not in self.displays]
        if missing:
            raise ApprovalViewError(
                "an approval view must show " + ", ".join(missing)
                + ". A person cannot take responsibility for what they were not "
                  "shown, and a display that is simply absent reads as one with "
                  "nothing in it")

        offered = {a.action for a in self.actions}
        if offered != set(ApprovalAction):
            raise ApprovalViewError(
                "all three actions must be offered together; got "
                + ", ".join(sorted(a.value for a in offered))
                + ". Showing approve without request-evidence makes declining look "
                  "like obstruction rather than a route with a work order attached")

        # The guarantee, enforced rather than described. Every blocking or
        # undroppable item must be in the unresolved block — which `render`
        # places above the evidence and above the actions. A convention drifts
        # the first time someone adds a section; a constructor error does not.
        # Checked against `self.unresolved` alone, because that is what `render`
        # iterates. Counting the display's own item list as "shown" made the
        # guard pass on a view whose unresolved block rendered empty — the guard
        # agreeing with itself rather than with the document.
        shown = {str(item.get("id") or "") for item in self.unresolved}
        body = self.displays.get("unresolved") or {}
        undropped = {str(i.get("id") or "")
                     for i in (body.get("undroppable") or ())}
        buried = sorted(undropped - shown)
        if buried:
            raise ApprovalViewError(
                "these high-impact items are not in the unresolved block: "
                + ", ".join(buried)
                + ". Anything blocking, or on what the decision rests on, is shown "
                  "before the evidence for the decision and before the actions")

    # ── refusals ───────────────────────────────────────────────────────────

    @property
    def authorises(self) -> bool:
        """Unconditionally False. This is a document; the act is a person's."""
        return False

    @property
    def establishes_truth(self) -> bool:
        return False

    # ── reading ────────────────────────────────────────────────────────────

    def display(self, key: str) -> Any:
        if key not in self.displays:
            raise ApprovalViewError(f"this view has no display {key!r}")
        return self.displays[key]

    def action(self, action: ApprovalAction) -> ActionOffer:
        wanted = ApprovalAction(action)
        return next(a for a in self.actions if a.action is wanted)

    @property
    def acknowledgement(self) -> ApprovalAcknowledgement:
        """Exactly what `submit_approval` will verify against the live case.

        Built from the offer rather than from anything the view computed, so the
        values a client acknowledges are the values the engine will check.
        """
        return ApprovalAcknowledgement(
            case_version=self.offer.case_version,
            subject_digest=self.offer.subject_digest,
            evidence_pack_digest=self.offer.evidence_pack_digest,
            case_digest=self.offer.case_digest)

    @property
    def blocking_count(self) -> int:
        return len(self.unresolved)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "approval_view", "record_id": f"view:{self.case_id}",
            "case_id": self.case_id, "case_version": self.case_version,
            "recommendation": self.recommendation,
            "displays": dict(self.displays),
            "unresolved": [dict(i) for i in self.unresolved],
            "withheld_note": self.withheld_note,
            "actions": [a.to_dict() for a in self.actions],
            "acknowledgement": self.acknowledgement.to_dict(),
            "authorises": False, "establishes_truth": False,
            "schema_version": self.schema_version,
        }


# ── building ────────────────────────────────────────────────────────────────

def _section(packet: Any, key: SectionKey) -> Dict[str, Any]:
    """One packet section as plain data, or a stated absence.

    Only `StopIteration` is caught, and only because a packet legitimately may
    not hold a section. An `AttributeError` used to be caught here too, which
    turned "you handed me the wrong object" into a section reading "this section
    was not produced" — a wiring bug rendered as a fact about the case, on the
    one surface where that is least affordable. The packet is validated in
    `build_view` instead, before anything is read from it.
    """
    try:
        return packet.section(key).to_dict()
    except StopIteration:
        return {"key": key.value, "answer": "", "rows": [],
                "note": "this packet holds no such section"}


def _item(item: Any) -> Dict[str, Any]:
    payload = item.to_dict()
    return {"id": payload.get("record_id"), "focus": payload.get("focus"),
            "focus_kind": payload.get("focus_kind"),
            "reason": payload.get("reason"), "effect": payload.get("effect"),
            "what": payload.get("what"),
            "why_it_matters": payload.get("why_it_matters"),
            "what_you_can_do": payload.get("what_the_human_can_do"),
            "undroppable": bool(payload.get("undroppable"))}


def build_view(outcome: Any, *, completeness: Any = None,
               attention_limit: int = 8, override: Any = None) -> ApprovalView:
    """Assemble the view from what the engine already produced.

    `completeness` is a `StreamLedger`, supplied by the caller for the same
    reason `facts_for` and `build_pack` take one: `AnalysisResult` has no such
    field, and reading it off the analysis would leave the display permanently
    silent with nothing to say it was unreachable.

    `override` adds a tenth display rather than a fourth action. An override is
    a precondition for approving, not a button beside APPROVE: offering it as an
    action would put "proceed anyway" on the same row as "approve", which is the
    one place a person should have to arrive deliberately.
    """
    case = getattr(outcome, "case", None)
    if case is None or not getattr(case, "case_id", ""):
        raise ApprovalViewError("build_view needs a decided outcome")

    # `AssuranceOutcome.packet` is a method, not an attribute. Taking it as one
    # yields a bound method that is truthy and has no `section`, which is how
    # every display came back blank while looking like a stated absence.
    packet = getattr(outcome, "packet", None)
    if callable(packet):
        packet = packet()
    if packet is None:
        from release_gate.assurance.packet import build_packet
        packet = build_packet(case, outcome)
    if not hasattr(packet, "section"):
        raise ApprovalViewError(
            f"{type(packet).__name__} is not an approval packet; a view built "
            "from one would report every section as absent, which reads as a "
            "fact about the case rather than a wiring error")
    offer = offer_approval(case, outcome)
    attention = getattr(outcome, "attention", None)
    required = getattr(outcome, "required_evidence", None)
    verdict = getattr(case, "verdict", None)
    recommendation = verdict.decision.value if verdict else "HOLD"

    items = tuple(attention.top(attention_limit)) if attention is not None else ()
    undroppable = tuple(attention.undroppable) if attention is not None else ()
    # Everything undroppable, whether or not it made the shortened list. `top()`
    # already refuses to drop these, and taking the union rather than trusting
    # that keeps the guarantee true if the limit ever changes shape.
    unresolved = tuple(_item(i) for i in
                       {id(x): x for x in (*undroppable, *items)}.values())
    withheld = getattr(attention, "withheld_note", "") if attention is not None else ""
    if callable(withheld):
        withheld = withheld()

    subject = case.subject
    subject_state = (case.binding_state().get("state") or {}).get(
        "subject_state") or {}

    displays: Dict[str, Any] = {
        "subject": {
            "what": subject.content_reference.locator if subject.content_reference
                    else "(no content reference)",
            "action": subject.requested_action,
            "type": subject.subject_type.value,
            "objective": case.objective,
            "section": _section(packet, SectionKey.SUBJECT)},
        "expected_effect": _section(packet, SectionKey.CONSEQUENCE),
        "unresolved": {
            "items": [dict(i) for i in unresolved],
            "undroppable": [_item(i) for i in undroppable],
            "withheld_note": withheld,
            "section": _section(packet, SectionKey.UNRESOLVED)},
        "critical_evidence": _section(packet, SectionKey.SUPPORTING_EVIDENCE),
        "coverage": _section(packet, SectionKey.NOT_ASSESSED),
        "completeness": (
            {"status": str(getattr(getattr(completeness, "status", None),
                                   "value", "") or ""),
             "note": completeness.note() if completeness is not None else "",
             "uncheckable_streams": list(
                 getattr(completeness, "uncheckable_streams", ()) or ())}
            if completeness is not None else
            {"status": "NOT_ASSESSED",
             "note": ("no stream completeness ledger was supplied, so whether all "
                      "of the evidence arrived was never asked. This is an "
                      "unanswered question, not a clean answer")}),
        "not_assessed": _section(packet, SectionKey.NOT_ASSESSED),
        # Two digests, and they are not interchangeable. `subject_digest` is the
        # content; `binds_to` is identity plus what was on the page, and it is
        # the one an approval attaches to. Showing one and calling it "the
        # subject digest" is a mistake this codebase has already paid for.
        "subject_digest": {
            "content": subject.digest,
            "binds_to": subject_state.get("state_digest"),
            "status": subject.digest_status.value,
            "basis": subject.digest_basis},
        "case_state": {
            "case_id": case.case_id, "case_version": case.case_version,
            "case_digest": case.case_digest,
            "evidence_digest": case.evidence_digest,
            "collections": offer.collection_digests,
            "section": _section(packet, SectionKey.BINDING)},
    }

    binds = {"case_id": offer.case_id, "case_version": offer.case_version,
             "subject_digest": offer.subject_digest,
             "case_digest": offer.case_digest,
             "evidence_pack_digest": offer.evidence_pack_digest}

    approve_caution = ("release-gate recommends " + recommendation
                       + ("; approving over that is a decision you are recorded "
                          "as having made" if recommendation != "PROMOTE" else ""))
    if override is not None:
        stale = override.stale_against(case)
        if stale:
            displays["override"] = {
                "title": "Override on record",
                "applies": False,
                "note": ("an override was granted against a different state ("
                         + ", ".join(stale) + " moved). It does not carry over, "
                         "and nothing here is permitted by it"),
                "override": override.to_dict()}
            approve_caution += ("; the override you were shown no longer applies "
                                "to this state")
        else:
            displays["override"] = {
                "title": "Override on record",
                "applies": True,
                "note": (f"{override.approver} recorded a decision to proceed over "
                         f"{len(override.issues)} unresolved issue(s). The verdict "
                         f"is still {override.machine_verdict}; those issues are "
                         "still open; approving accepts that"),
                "waived": list(override.waived),
                "not_authorised": list(override.unauthorised),
                "fully_authorised": override.fully_authorised,
                "override": override.to_dict()}
            approve_caution += ("; you approve under override "
                                f"{override.override_id}, over "
                                f"{len(override.issues)} issue(s) that remain open")

    actions = (
        ActionOffer(
            action=ApprovalAction.APPROVE,
            decision=ApprovalDecision.APPROVED,
            means=("you authorise this action at exactly the state named below. "
                   "The authorisation attaches to these digests and to nothing "
                   "else: if any of them moves, it stops applying rather than "
                   "carrying over"),
            binds_to=binds,
            caution=approve_caution),
        ActionOffer(
            action=ApprovalAction.REJECT,
            decision=ApprovalDecision.REJECTED,
            means=("you refuse this action at this state. The refusal is recorded "
                   "against the same digests, so a later submission can be "
                   "compared against what was refused"),
            binds_to=binds),
        ActionOffer(
            action=ApprovalAction.REQUEST_EVIDENCE,
            decision=ApprovalDecision.DEFERRED,
            means=("you decline to decide yet and say precisely what would let "
                   "you. The payload below is a work order an external verifier "
                   "can act on without a person in the middle of the cycle"),
            binds_to=binds,
            payload=(required.protocol() if required is not None else
                     {"required_evidence": [],
                      "note": ("no required-evidence set was produced, so nothing "
                               "can be named as the thing that would resolve this")})),
    )

    return ApprovalView(
        case_id=case.case_id, case_version=case.case_version,
        recommendation=recommendation, offer=offer, displays=displays,
        actions=actions, unresolved=unresolved, withheld_note=str(withheld or ""))


# ── rendering ───────────────────────────────────────────────────────────────

RULE_WIDTH = 60


def render_view(view: ApprovalView) -> str:
    """The text a person reads. Order is the argument this module makes.

    The question comes first, then what is being taken responsibility for, then
    **what stands against it** — above the evidence for it, because a reviewer
    who reads the case for something before the case against it has already been
    led. The actions come last, so nothing offered can be clicked before the
    problems have been passed.
    """
    displays = view.displays
    subject = displays["subject"]
    digests = displays["subject_digest"]
    state = displays["case_state"]
    completeness = displays["completeness"]

    lines = [
        "WHAT EXACTLY AM I TAKING RESPONSIBILITY FOR?",
        "=" * RULE_WIDTH,
        "",
        "THE ACTION",
        f"  {subject['action']}",
        f"  on: {subject['what']}",
        f"  objective: {subject['objective']}",
        "",
        "EXACTLY WHICH BYTES",
        f"  content digest   {digests['content'] or '(not hashable)'}"
        f"   [{digests['status']}]",
        f"  your approval binds to  {digests['binds_to'] or '(none)'}",
        f"  {digests['basis']}",
        "",
        "EXPECTED EFFECT",
        "  " + (displays["expected_effect"].get("answer") or "(not stated)"),
    ]
    for row in (displays["expected_effect"].get("rows") or ())[:8]:
        lines.append(f"    - {row.get('label', '')}: {row.get('detail', '')}")

    # Before the evidence for it. This placement is the module's whole claim and
    # `ApprovalView.__post_init__` refuses to construct if anything undroppable
    # is not in this block.
    lines += ["", "UNRESOLVED — READ BEFORE ANYTHING BELOW", "-" * RULE_WIDTH]
    if not view.unresolved:
        lines.append("  Nothing unresolved was found. That is a report of what was "
                     "looked for, not a guarantee that nothing exists.")
    for index, item in enumerate(view.unresolved, start=1):
        mark = "!!" if item.get("effect") == "BLOCK" else " ·"
        lines.append(f" {mark} {index}. {item.get('focus')}  [{item.get('reason')}]")
        if item.get("why_it_matters"):
            lines.append(f"      {item['why_it_matters']}")
        if item.get("what_you_can_do"):
            lines.append(f"      you can: {item['what_you_can_do']}")
    if view.withheld_note:
        lines.append(f"  {view.withheld_note}")

    lines += ["", "WHAT IT RESTS ON",
              "  " + (displays["critical_evidence"].get("answer") or "(none recorded)")]
    for row in (displays["critical_evidence"].get("rows") or ())[:6]:
        lines.append(f"    - {row.get('label', '')}: {row.get('detail', '')}")

    lines += ["", "WHAT WAS NOT ASSESSED",
              "  " + (displays["not_assessed"].get("answer") or "(nothing recorded)")]
    for row in (displays["not_assessed"].get("rows") or ())[:8]:
        lines.append(f"    - {row.get('label', '')}: {row.get('detail', '')}")

    lines += ["", "WHETHER ALL OF IT ARRIVED",
              f"  {completeness['status']}",
              f"  {completeness.get('note', '')}"]

    lines += ["", "THE EXACT STATE YOU WOULD BE BINDING TO",
              f"  case      {state['case_id']} v{state['case_version']}",
              f"  case      {state['case_digest']}",
              f"  evidence  {state['evidence_digest']}"]

    lines += ["", "=" * RULE_WIDTH, "",
              f"RELEASE-GATE RECOMMENDS: {view.recommendation}", ""]
    for offer in view.actions:
        lines.append(f"  [{offer.action.value}]")
        lines.append(f"     {offer.means}")
        if offer.caution:
            lines.append(f"     note: {offer.caution}")
        if offer.action is ApprovalAction.REQUEST_EVIDENCE:
            requirements = (offer.payload.get("required_evidence") or ())
            lines.append(f"     {len(requirements)} named requirement(s) would be "
                         "dispatched")
        lines.append("")

    lines.append("Release-gate recommends and records. The authorisation is yours.")
    return "\n".join(lines)
