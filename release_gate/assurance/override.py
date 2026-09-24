"""Proceeding despite unresolved issues, on the record.

Experts sometimes go ahead knowing what is unresolved. That is legitimate and
occasionally necessary, and a system that cannot express it will be worked
around by people who turn the gate off — which loses the record too. So this
models it, under four constraints that are the whole point of the module.

**Only where the methodology permits.** `AssuranceMethodology.can_override()`
has been the authority on this since §11; this is the thing that finally asks
it, per named requirement. Silence reads as no, which is where `can_override`
already stood: a requirement nobody wrote a waiver rule for is not waivable.

**Never a silent conversion.** Nothing here returns a verdict, mutates one, or
offers a PROMOTE. `Override.machine_verdict` is a required field and
`Override.converts_verdict` is unconditionally `False`. A HOLD that was
overridden is still a HOLD, with the same exit code, and the case reads that way
for everyone downstream.

**A separate authorization state.** `AuthorizationState` is its own type
alongside `Decision` (what the engine found) and `ApprovalDecision` (what the
person did). `AUTHORISED_BY_OVERRIDE` is not a synonym for `AUTHORISED` and
neither is a synonym for PROMOTE. A reader who wants to know whether something
proceeded on clean evidence or on a person's judgement can tell them apart by
the value, not by reading a comment field.

**Name everything you are waiving.** An override granted over three of five open
issues is an override whose holder was asked about a smaller case than the one
they have — the selective-omission attack from §10p, arriving through the front
door. `request_override` derives the unresolved set from the case itself and
refuses a request that names less than all of it.

An override is *not* an approval. `Override.authorises` is `False`: it makes an
authorisation permissible, and the authorising act is still a person's signature
recorded as a `BoundApproval` (Invariant 15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.approval import (
    ApprovalDecision, AuthSource, binding_of,
)
from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.case import Decision

__all__ = [
    "OVERRIDE_SCHEMA_VERSION",
    "Authorization",
    "AuthorizationState",
    "Override",
    "OverrideError",
    "OverrideOutcome",
    "OverrideRequest",
    "OverrideReview",
    "UnresolvedIssue",
    "authorisation_of",
    "request_override",
    "unresolved_issues",
]

OVERRIDE_SCHEMA_VERSION = 1


class OverrideError(ValueError):
    """An override was requested in a form that would record less than it does."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── the separate authorization state ─────────────────────────────────────────

class AuthorizationState(str, Enum):
    """Whether an action may proceed, and on whose authority.

    Deliberately not `Decision` and deliberately not `ApprovalDecision`. The
    engine's verdict says what the evidence supports; the approval says what a
    person did; this says what the two come to together. Keeping them as three
    types is what stops "overridden" from being readable as "promoted".

    `NOT_AUTHORISED` is the default and the only value a machine can reach on its
    own. Nothing in release-gate can produce any of the others without a human
    act on the record.
    """

    NOT_AUTHORISED = "NOT_AUTHORISED"
    #: A person approved, on a case the methodology cleared.
    AUTHORISED = "AUTHORISED"
    #: A person approved over named unresolved issues the methodology permits
    #: waiving. Distinct from AUTHORISED because the difference is the entire
    #: reason a record exists.
    AUTHORISED_BY_OVERRIDE = "AUTHORISED_BY_OVERRIDE"
    #: An override was sought and the methodology forbade it. Recorded, because
    #: an attempt that was refused is a fact about the case's history.
    OVERRIDE_REFUSED = "OVERRIDE_REFUSED"
    #: A person refused.
    REFUSED = "REFUSED"


# ── what is being waived ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class UnresolvedIssue:
    """One open thing, named by the requirement that keeps it open.

    `requirement_id` is what `can_override` is asked about, so an issue that
    cannot name one cannot be overridden — there is nothing for a methodology to
    have an opinion on.
    """

    requirement_id: str
    summary: str
    effect: str = "HOLD"
    item_id: str = ""
    focus: str = ""
    epistemic_status: str = "UNKNOWN"

    def __post_init__(self) -> None:
        if not (self.requirement_id or "").strip():
            raise OverrideError(
                "an unresolved issue must name the requirement behind it; an "
                "unnamed issue cannot be put to a methodology, so it cannot be "
                "waived by one")
        object.__setattr__(self, "requirement_id", self.requirement_id.strip())

    @property
    def blocking(self) -> bool:
        return self.effect == "BLOCK"

    def to_dict(self) -> Dict[str, Any]:
        return {"requirement_id": self.requirement_id, "summary": self.summary,
                "effect": self.effect, "item_id": self.item_id,
                "focus": self.focus, "epistemic_status": self.epistemic_status,
                "blocking": self.blocking}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "UnresolvedIssue":
        return cls(requirement_id=str(data.get("requirement_id") or ""),
                   summary=str(data.get("summary") or ""),
                   effect=str(data.get("effect") or "HOLD"),
                   item_id=str(data.get("item_id") or ""),
                   focus=str(data.get("focus") or ""),
                   epistemic_status=str(data.get("epistemic_status") or "UNKNOWN"))


def unresolved_issues(outcome: Any) -> Tuple[UnresolvedIssue, ...]:
    """Everything this case has open, derived from the case rather than supplied.

    Read from three places, because no one of them is the whole set and they are
    in different id namespaces:

    * the **methodology assessment's** unmet requirements — the only ids in the
      methodology's own vocabulary, so the only ones it can be asked to waive;
    * the **attention set**, which carries the prose a person actually reads;
    * the verdict's **`fired_rules`**, which is what decided the verdict.

    Taking any one alone loses issues the others hold. A rule that fired with no
    attention item still appears — thinly, but present, because an issue that has
    no description is not an issue that has gone away.
    """
    verdict = getattr(getattr(outcome, "case", outcome), "verdict", None)
    decision = getattr(verdict, "decision", None)
    # `fired_rules` is every rule that produced the verdict, including the ones
    # that produced a PROMOTE. On an adverse verdict they are what went against
    # the case and belong here; on a PROMOTE they are the reasoning behind it,
    # and calling them open issues would report a cleared case as a held one.
    fired: Tuple[str, ...] = (() if decision is Decision.PROMOTE
                              else tuple(getattr(verdict, "fired_rules", ()) or ()))

    described: Dict[str, UnresolvedIssue] = {}

    # The methodology assessment first, because its ids are the only ones in the
    # methodology's own namespace — the only ones `can_override` can answer
    # about at all. A case can be held by an unmet requirement that no policy
    # rule fired on and no attention item describes.
    assessment = getattr(outcome, "assessment", None)
    if assessment is not None and hasattr(assessment, "unmet"):
        for result in assessment.unmet():
            effect = getattr(getattr(result, "effect", None), "value", "HOLD")
            if effect == "ADVISORY":
                continue
            described[result.requirement_id] = UnresolvedIssue(
                requirement_id=result.requirement_id,
                summary=(getattr(result, "detail", "")
                         or getattr(result, "description", "") or ""),
                effect=effect,
                focus=getattr(result, "predicate_kind", "") or "",
                epistemic_status=getattr(getattr(result, "outcome", None),
                                         "value", "UNKNOWN"))

    attention = getattr(outcome, "attention", None)
    for item in (getattr(attention, "items", ()) or ()):
        effect = getattr(getattr(item, "effect", None), "value", "HOLD")
        if effect == "ADVISORY":
            # Advisory findings do not hold the case, so there is nothing to
            # waive; including them would pad the acknowledgement with items the
            # approver is not actually proceeding despite.
            continue
        for rule_id in (getattr(item, "rule_ids", ()) or ()):
            if rule_id in described:
                continue
            described[rule_id] = UnresolvedIssue(
                requirement_id=rule_id,
                summary=getattr(item, "summary", "") or "",
                effect=effect,
                item_id=getattr(item, "item_id", "") or "",
                focus=getattr(item, "focus", "") or "",
                epistemic_status=getattr(item, "epistemic_status", "UNKNOWN") or "UNKNOWN")

    # The union, not either one alone. The two lists are in different id
    # namespaces and neither contains the other: a zero-config policy rule can
    # fire with no attention item, and an attention item can name a methodology
    # requirement that no policy rule fired on. Taking only `fired_rules` drops
    # the item the person is actually looking at; taking only the attention set
    # drops what decided the verdict.
    issues: List[UnresolvedIssue] = []
    seen: set = set()
    for rule_id in tuple(described) + tuple(fired):
        if rule_id in seen:
            continue
        seen.add(rule_id)
        if rule_id in described:
            issues.append(described[rule_id])
        else:
            issues.append(UnresolvedIssue(
                requirement_id=rule_id,
                summary=("this rule fired against the case and no attention item "
                         "describes it; it is open, and what it is must be read "
                         "from the methodology"),
                effect=("BLOCK" if getattr(verdict, "decision", None) is Decision.BLOCK
                        else "HOLD")))
    return tuple(issues)


# ── the request ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class OverrideRequest:
    """What a person asks for, before anything has checked whether they may.

    `acknowledged` is the requirement ids they say they are proceeding despite.
    It is supplied rather than derived on purpose: derived, it would record that
    release-gate knew what was open, which is never in doubt. Supplied, it
    records what the person was asked about — and lets the gate catch a request
    that names fewer issues than the case holds.
    """

    approver: str
    reason: str
    scope: str
    acknowledged: Tuple[str, ...] = ()
    role: str = ""
    auth_source: AuthSource = AuthSource.ASSERTED
    expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "auth_source", AuthSource(self.auth_source))
        object.__setattr__(self, "acknowledged", tuple(self.acknowledged))
        for name in ("approver", "reason", "scope"):
            object.__setattr__(self, name, (getattr(self, name) or "").strip())

    @property
    def missing(self) -> Tuple[str, ...]:
        absent = [name for name in ("approver", "reason", "scope")
                  if not getattr(self, name)]
        if not self.acknowledged:
            absent.append("acknowledged")
        return tuple(absent)

    @property
    def complete(self) -> bool:
        return not self.missing

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "override_request", "approver": self.approver,
                "reason": self.reason, "scope": self.scope,
                "acknowledged": list(self.acknowledged), "role": self.role,
                "auth_source": self.auth_source.value,
                "expires_at": self.expires_at,
                "complete": self.complete, "missing": list(self.missing)}


# ── the record ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Override:
    """One decision to proceed despite named unresolved issues, bound to a state.

    Holds the seven things an override has to record — approver, reason, the
    issues, scope, subject digest, case digest, timestamp — plus the machine
    verdict it did *not* change and the methodology decisions that permitted it.
    """

    case_id: str
    case_version: int
    approver: str
    reason: str
    scope: str
    subject_digest: str
    case_digest: str
    #: The verdict as the engine produced it. Required, and never rewritten: an
    #: override that did not preserve what it overrode would be indistinguishable
    #: from the case having been clean.
    machine_verdict: str
    #: Everything open that this override proceeds over — permitted or not.
    issues: Tuple[UnresolvedIssue, ...] = ()
    #: Open issues the methodology does not define, so nothing authorised
    #: proceeding over them. Recorded rather than dropped: a case is held by
    #: structural findings and policy rules as well as by methodology
    #: requirements, and an override that listed only the waivable ones would
    #: read as covering a smaller case than the one that proceeded.
    unauthorised_issues: Tuple[UnresolvedIssue, ...] = ()
    #: One `OverrideDecision` payload per waived issue, so a reader can see which
    #: rule permitted each waiver rather than take the grant on trust.
    permitted_by: Tuple[Mapping[str, Any], ...] = ()
    methodology_ref: str = ""
    role: str = ""
    subject_id: str = ""
    bound_collections: Mapping[str, str] = field(default_factory=dict)
    auth_source: AuthSource = AuthSource.ASSERTED
    timestamp: str = field(default_factory=_utc_now)
    expires_at: Optional[str] = None
    schema_version: int = OVERRIDE_SCHEMA_VERSION

    override_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "auth_source", AuthSource(self.auth_source))
        object.__setattr__(self, "issues", tuple(self.issues))
        object.__setattr__(self, "unauthorised_issues",
                           tuple(self.unauthorised_issues))
        object.__setattr__(self, "permitted_by",
                           tuple(dict(p) for p in self.permitted_by))
        object.__setattr__(self, "bound_collections",
                           dict(self.bound_collections or {}))
        for name in ("approver", "reason", "scope"):
            object.__setattr__(self, name, (getattr(self, name) or "").strip())

        if self.auth_source is AuthSource.RELEASE_GATE:
            raise OverrideError(
                "release-gate cannot override its own finding. Deciding to proceed "
                "despite unresolved evidence is exactly the judgement this engine "
                "refuses to make on a person's behalf (Invariant 15)")
        for name in ("approver", "reason", "scope"):
            if not getattr(self, name):
                raise OverrideError(
                    f"an override must record its {name}; without it the record "
                    "says something was waived but not who, why, or over what")
        for name in ("case_id", "subject_digest", "case_digest", "machine_verdict"):
            if not (getattr(self, name) or "").strip():
                raise OverrideError(
                    f"{name} is required: an override that does not bind to an "
                    "exact state and preserve the verdict it overrode is a waiver "
                    "of whatever anyone later says it was")
        if not self.issues:
            raise OverrideError(
                "an override must name what it is overriding; a blanket waiver is "
                "a signature on an unread page")
        if self.machine_verdict == Decision.PROMOTE.value:
            raise OverrideError(
                "there is nothing to override on a PROMOTE. Recording one would "
                "put a waiver on a case that did not need it, and a reader would "
                "have no way to tell it from a case that did")
        if self.expires_at and self.expires_at <= self.timestamp:
            raise OverrideError(
                "expires_at must be after the override was granted; one that "
                "expired before it was made is a record of nothing")
        object.__setattr__(self, "override_id",
                           short_id("ovrd", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        return {"schema_version": OVERRIDE_SCHEMA_VERSION,
                "case_id": self.case_id, "case_version": self.case_version,
                "approver": self.approver, "reason": self.reason,
                "scope": self.scope, "subject_digest": self.subject_digest,
                "case_digest": self.case_digest,
                "machine_verdict": self.machine_verdict,
                "issues": [i.requirement_id for i in self.issues],
                "timestamp": self.timestamp,
                "auth_source": self.auth_source.value}

    # ── the refusals, unconditional ─────────────────────────────────────────

    @property
    def converts_verdict(self) -> bool:
        """Unconditionally False. A HOLD that was overridden is still a HOLD."""
        return False

    @property
    def resolves_issues(self) -> bool:
        """Unconditionally False. Every issue named here is still open; a waiver
        is a decision about proceeding, not a finding about evidence."""
        return False

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False, for the same reason a verdict does not."""
        return False

    @property
    def authorises(self) -> bool:
        """Unconditionally False. An override makes an authorisation permissible.
        The authorising act is a person's, recorded as a `BoundApproval`."""
        return False

    # ── what it says about the case ─────────────────────────────────────────

    @property
    def effective_decision(self) -> str:
        """The verdict, unchanged. Present so the preservation is a value a
        caller can read rather than a promise in a docstring."""
        return self.machine_verdict

    @property
    def waived(self) -> Tuple[str, ...]:
        """The ids a methodology actually permitted waiving — not everything the
        override proceeds over."""
        return tuple(str(p.get("requirement_id") or "") for p in self.permitted_by)

    @property
    def unauthorised(self) -> Tuple[str, ...]:
        return tuple(i.requirement_id for i in self.unauthorised_issues)

    @property
    def fully_authorised(self) -> bool:
        """Whether a methodology permitted every issue this proceeds over.

        `False` is the ordinary case, not an error: most of what holds a case is
        structural findings and policy rules, which methodologies govern through
        acceptance rather than through waivers. It is here so a reader is never
        left to infer that everything on the list was sanctioned.
        """
        return not self.unauthorised_issues

    @property
    def blocking_waived(self) -> Tuple[str, ...]:
        waived = set(self.waived)
        return tuple(i.requirement_id for i in self.issues
                     if i.blocking and i.requirement_id in waived)

    @property
    def identity_established(self) -> bool:
        from release_gate.assurance.approval import _ESTABLISHED
        return self.auth_source in _ESTABLISHED

    def expired(self, now: Optional[str] = None) -> bool:
        if not self.expires_at:
            return False
        return (now or _utc_now()) >= self.expires_at

    def binds_to(self, case: Any) -> bool:
        """Whether this override still describes the case in front of you."""
        bound = binding_of(case)
        return (bound["case_id"] == self.case_id
                and bound["subject_digest"] == self.subject_digest
                and bound["case_digest"] == self.case_digest)

    def stale_against(self, case: Any) -> Tuple[str, ...]:
        """Which parts moved, so a reader is told what changed and not only that
        something did."""
        bound = binding_of(case)
        moved = []
        for name in ("case_id", "subject_digest", "case_digest"):
            if bound[name] != getattr(self, name):
                moved.append(name)
        return tuple(moved)

    # ── serialisation ───────────────────────────────────────────────────────

    @property
    def record_type(self) -> str:
        return "override"

    @property
    def record_id(self) -> str:
        return self.override_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "override", "record_id": self.override_id,
            "override_id": self.override_id,
            "case_id": self.case_id, "case_version": self.case_version,
            "approver": self.approver, "reason": self.reason, "scope": self.scope,
            "role": self.role,
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
            "case_digest": self.case_digest,
            "bound_collections": dict(self.bound_collections),
            "machine_verdict": self.machine_verdict,
            "effective_decision": self.effective_decision,
            "issues": [i.to_dict() for i in self.issues],
            "unauthorised_issues": [i.to_dict() for i in self.unauthorised_issues],
            "waived": list(self.waived),
            "unauthorised": list(self.unauthorised),
            "fully_authorised": self.fully_authorised,
            "blocking_waived": list(self.blocking_waived),
            "permitted_by": [dict(p) for p in self.permitted_by],
            "methodology": self.methodology_ref,
            "auth_source": self.auth_source.value,
            "identity_established": self.identity_established,
            "timestamp": self.timestamp, "expires_at": self.expires_at,
            # In the payload, for every override, so a consumer finds them rather
            # than having to know them.
            "converts_verdict": False, "resolves_issues": False,
            "establishes_truth": False, "authorises": False,
            "note": self.note(), "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Override":
        return cls(
            case_id=str(data.get("case_id") or ""),
            case_version=int(data.get("case_version") or 1),
            approver=str(data.get("approver") or ""),
            reason=str(data.get("reason") or ""),
            scope=str(data.get("scope") or ""),
            subject_digest=str(data.get("subject_digest") or ""),
            case_digest=str(data.get("case_digest") or ""),
            machine_verdict=str(data.get("machine_verdict") or ""),
            issues=tuple(UnresolvedIssue.from_dict(i)
                         for i in (data.get("issues") or ())),
            unauthorised_issues=tuple(
                UnresolvedIssue.from_dict(i)
                for i in (data.get("unauthorised_issues") or ())),
            permitted_by=tuple(dict(p) for p in (data.get("permitted_by") or ())),
            methodology_ref=str(data.get("methodology") or ""),
            role=str(data.get("role") or ""),
            subject_id=str(data.get("subject_id") or ""),
            bound_collections=data.get("bound_collections") or {},
            auth_source=AuthSource(str(data.get("auth_source") or "ASSERTED").upper()),
            timestamp=str(data.get("timestamp") or _utc_now()),
            expires_at=(str(data["expires_at"]) if data.get("expires_at") else None))

    def note(self) -> str:
        return (f"{self.approver} proceeded over {len(self.issues)} unresolved "
                f"issue(s) at {self.timestamp}. The verdict remains "
                f"{self.machine_verdict}; these issues remain open; this is a "
                f"decision to act despite them, scoped to: {self.scope}")

    def render(self) -> str:
        lines = [
            f"OVERRIDE {self.override_id} by {self.approver} at {self.timestamp}",
            f"  machine verdict: {self.machine_verdict} — unchanged by this override",
            f"  scope: {self.scope}",
            f"  reason: {self.reason}",
            f"  identity: {self.auth_source.value}"
            + ("" if self.identity_established
               else " — attributable to a claim of identity, not an established one"),
            f"  bound to case {self.case_id} v{self.case_version} ({self.case_digest})",
            f"  subject {self.subject_digest}",
            f"  proceeding despite {len(self.issues)} unresolved issue(s):"]
        waived = set(self.waived)
        for issue in self.issues:
            mark = "waived" if issue.requirement_id in waived else "NOT AUTHORISED"
            lines.append(f"    · [{issue.effect}] {issue.requirement_id} ({mark})"
                         + (f" — {issue.summary}" if issue.summary else ""))
        if not self.fully_authorised:
            lines.append(f"  {len(self.unauthorised_issues)} of these are outside "
                         f"{self.methodology_ref or 'this methodology'}'s "
                         "requirements, so nothing permitted waiving them. They are "
                         "proceeded over on this approver's judgement alone.")
        if self.role:
            lines.append(f"  role claimed: {self.role}")
        lines.append("  These issues are not resolved by this record. It authorises "
                     "nothing on its own.")
        return "\n".join(lines)


# ── the gate ─────────────────────────────────────────────────────────────────

class OverrideOutcome(str, Enum):
    """What came of asking. Every refusal says which kind it was."""

    GRANTED = "GRANTED"
    #: The verdict is PROMOTE. Nothing is being proceeded-despite.
    NOT_REQUIRED = "NOT_REQUIRED"
    #: At least one issue is named in `non_overridable_conditions`.
    REFUSED_NON_OVERRIDABLE = "REFUSED_NON_OVERRIDABLE"
    #: The methodology declares no waiver rule, or forbids one. Silence is a no.
    REFUSED_NOT_PERMITTED = "REFUSED_NOT_PERMITTED"
    #: approver, reason, scope or acknowledged was absent.
    REFUSED_INCOMPLETE = "REFUSED_INCOMPLETE"
    #: The request named fewer issues than the case holds.
    REFUSED_UNDER_NAMED = "REFUSED_UNDER_NAMED"
    #: A waiver rule requires a role the request did not state.
    REFUSED_ROLE = "REFUSED_ROLE"
    #: The methodology does not define the requirement, so it has no position on
    #: waiving it. Distinct from NOT_PERMITTED: silence inside a vocabulary is a
    #: considered no; silence outside it is the wrong authority having been asked.
    REFUSED_UNKNOWN_REQUIREMENT = "REFUSED_UNKNOWN_REQUIREMENT"
    #: The case has no verdict, so there is nothing to override.
    REFUSED_NO_VERDICT = "REFUSED_NO_VERDICT"


@dataclass(frozen=True)
class OverrideReview:
    """The answer, with the override when there is one."""

    outcome: OverrideOutcome
    override: Optional[Override] = None
    reasons: Tuple[str, ...] = ()
    #: The issues that stopped it, with the methodology's reason for each.
    refused_issues: Tuple[Mapping[str, Any], ...] = ()
    #: Requirement ids the case holds open that the request did not name.
    unacknowledged: Tuple[str, ...] = ()
    #: Everything open on the case, whatever the request said.
    open_issues: Tuple[UnresolvedIssue, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", OverrideOutcome(self.outcome))
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "refused_issues",
                           tuple(dict(r) for r in self.refused_issues))
        object.__setattr__(self, "unacknowledged", tuple(sorted(self.unacknowledged)))
        object.__setattr__(self, "open_issues", tuple(self.open_issues))

    @property
    def granted(self) -> bool:
        return self.outcome is OverrideOutcome.GRANTED

    @property
    def permanently_refused(self) -> bool:
        """Whether more paperwork would help.

        `REFUSED_NON_OVERRIDABLE` is the one refusal no resubmission fixes: the
        methodology says no role and no rationale satisfies it. The others are
        about the request and can be made again properly.
        """
        return self.outcome is OverrideOutcome.REFUSED_NON_OVERRIDABLE

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "override_review", "outcome": self.outcome.value,
                "granted": self.granted,
                "permanently_refused": self.permanently_refused,
                "reasons": list(self.reasons),
                "refused_issues": [dict(r) for r in self.refused_issues],
                "unacknowledged": list(self.unacknowledged),
                "open_issues": [i.to_dict() for i in self.open_issues],
                "override": self.override.to_dict() if self.override else None}


def request_override(case: Any, outcome: Any, request: OverrideRequest, *,
                     methodology: Any) -> OverrideReview:
    """Ask whether this person may proceed despite these issues.

    `methodology` is required and has no default. "Support explicit override only
    where methodology/policy permits" has no meaning without something to do the
    permitting, and a default would make the permissive case the easy one to
    reach by accident.
    """
    if methodology is None or not hasattr(methodology, "can_override"):
        raise OverrideError(
            f"{type(methodology).__name__} cannot say whether a requirement may be "
            "waived; pass the AssuranceMethodology itself, resolved from the "
            "case's MethodologyRef. There is no override without one, because "
            "there is nothing to have permitted it")

    verdict = getattr(getattr(outcome, "case", case), "verdict", None)
    if verdict is None:
        return OverrideReview(
            outcome=OverrideOutcome.REFUSED_NO_VERDICT,
            reasons=("this case has no verdict; there is no finding to proceed "
                     "despite, and an override recorded against nothing would "
                     "later read as one recorded against anything",))

    open_issues = unresolved_issues(outcome)

    if verdict.decision is Decision.PROMOTE:
        return OverrideReview(
            outcome=OverrideOutcome.NOT_REQUIRED, open_issues=open_issues,
            reasons=("the verdict is PROMOTE; nothing is being proceeded-despite. "
                     "Recording an override here would put a waiver on a case that "
                     "did not need one, and nobody reading the record later could "
                     "tell it from a case that did",))

    if not request.complete:
        return OverrideReview(
            outcome=OverrideOutcome.REFUSED_INCOMPLETE, open_issues=open_issues,
            reasons=("the request did not state " + ", ".join(request.missing)
                     + "; an override missing any of these records that something "
                       "was waived without recording enough to hold anyone to it",))

    open_ids = {i.requirement_id for i in open_issues}
    acknowledged = set(request.acknowledged)
    unacknowledged = open_ids - acknowledged
    if unacknowledged:
        return OverrideReview(
            outcome=OverrideOutcome.REFUSED_UNDER_NAMED, open_issues=open_issues,
            unacknowledged=tuple(unacknowledged),
            reasons=("the request names " + str(len(acknowledged & open_ids))
                     + " of " + str(len(open_ids)) + " open issues; "
                     + ", ".join(sorted(unacknowledged)) + " were not named. An "
                     "override granted over a smaller case than the one in hand is "
                     "the same omission attack arriving through the front door: "
                     "the approver would be answering for something narrower than "
                     "what proceeds",))

    # Only the issues the case actually holds are put to the methodology. A
    # request naming extra ids does not get them waived by mentioning them.
    subjects = tuple(i for i in open_issues if i.requirement_id in acknowledged)

    # Only the issues the methodology defines can be put to it. The rest are
    # open too, and are disclosed on the record rather than checked — a
    # methodology governs structural findings through `accepted_findings`, not
    # through waivers, and asking it to waive a policy rule id it has never
    # heard of would turn "outside my authority" into "I refused".
    recognised = tuple(i for i in subjects
                       if methodology.recognises(i.requirement_id))
    unrecognised = tuple(i for i in subjects
                         if i not in recognised)

    permitted: List[Mapping[str, Any]] = []
    refused: List[Mapping[str, Any]] = []
    role_gaps: List[Mapping[str, Any]] = []
    non_overridable = False
    declared = set(getattr(methodology, "non_overridable_conditions", ()) or ())

    for issue in recognised:
        decision = methodology.can_override(issue.requirement_id)
        payload = dict(decision.to_dict())
        payload["effect"] = issue.effect
        if not decision.permitted:
            if issue.requirement_id in declared:
                non_overridable = True
            refused.append(payload)
            continue
        if decision.requires_role and not request.role:
            role_gaps.append(payload)
            continue
        permitted.append(payload)

    if refused:
        # Worst-first: NON_OVERRIDABLE outranks the rest because it is the only
        # refusal no resubmission can fix.
        if non_overridable:
            closing = ("at least one of these is non-overridable under this "
                       "methodology: no role and no rationale satisfies it, and "
                       "this refusal does not become a grant by being asked again")
        else:
            closing = ("absent an explicit waiver rule a requirement stands; "
                       "silence from a methodology is a no, not an omission to be "
                       "read around")
        return OverrideReview(
            outcome=(OverrideOutcome.REFUSED_NON_OVERRIDABLE if non_overridable
                     else OverrideOutcome.REFUSED_NOT_PERMITTED),
            open_issues=open_issues, refused_issues=tuple(refused),
            reasons=tuple(str(r.get("reason") or "") for r in refused) + (closing,))

    if role_gaps:
        return OverrideReview(
            outcome=OverrideOutcome.REFUSED_ROLE, open_issues=open_issues,
            refused_issues=tuple(role_gaps),
            reasons=tuple(f"{r['requirement_id']} may be waived only by "
                          f"{r['requires_role']}, and the request stated no role"
                          for r in role_gaps))

    if not permitted:
        # Nothing here is something this methodology permits waiving. "Only where
        # methodology or policy permits" is not satisfied by a methodology that
        # permits none of it, and granting anyway would make the record say a
        # methodology authorised something no methodology looked at.
        return OverrideReview(
            outcome=OverrideOutcome.REFUSED_UNKNOWN_REQUIREMENT,
            open_issues=open_issues,
            refused_issues=tuple(
                dict(methodology.can_override(i.requirement_id).to_dict(),
                     effect=i.effect) for i in unrecognised),
            reasons=(f"{getattr(methodology, 'ref_string', 'this methodology')} "
                     f"defines none of the {len(subjects)} open issue(s), so it "
                     "permits waiving none of them. An override needs something a "
                     "methodology allowed; structural findings are governed by an "
                     "AcceptedFinding with a consequence ceiling, which is a "
                     "decision made in advance rather than at the gate",))

    bound = binding_of(case)
    try:
        override = Override(
            case_id=bound["case_id"], case_version=bound["case_version"],
            approver=request.approver, reason=request.reason, scope=request.scope,
            subject_id=bound["subject_id"],
            subject_digest=bound["subject_digest"],
            case_digest=bound["case_digest"],
            bound_collections=bound["bound_collections"],
            machine_verdict=verdict.decision.value,
            issues=subjects, unauthorised_issues=unrecognised,
            permitted_by=tuple(permitted),
            methodology_ref=getattr(methodology, "ref_string", ""),
            role=request.role, auth_source=request.auth_source,
            expires_at=request.expires_at)
    except OverrideError as exc:
        return OverrideReview(outcome=OverrideOutcome.REFUSED_INCOMPLETE,
                              open_issues=open_issues, reasons=(str(exc),))

    return OverrideReview(
        outcome=OverrideOutcome.GRANTED, override=override, open_issues=open_issues,
        reasons=(f"{len(permitted)} requirement(s) may be waived under "
                 f"{override.methodology_ref}. The verdict remains "
                 f"{override.machine_verdict} and these issues remain open; what "
                 f"this records is that {override.approver} decided to proceed "
                 f"knowing them",)
        + ((f"{len(unrecognised)} further open issue(s) are outside that "
            "methodology's requirements; nothing permitted proceeding over them "
            "and the record says so",) if unrecognised else ()))


# ── the combined state ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Authorization:
    """What a verdict, an approval and an override come to together.

    The one object that answers "may this proceed, and on whose authority" —
    and the reason it is a separate object is that answering it by looking at the
    verdict alone is the mistake this whole sequence is against.
    """

    state: AuthorizationState
    machine_verdict: Optional[str] = None
    approval: Any = None
    override: Optional[Override] = None
    review: Optional[OverrideReview] = None
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", AuthorizationState(self.state))
        object.__setattr__(self, "notes", tuple(self.notes))

    @property
    def authorised(self) -> bool:
        return self.state in (AuthorizationState.AUTHORISED,
                              AuthorizationState.AUTHORISED_BY_OVERRIDE)

    @property
    def proceeds_over_open_issues(self) -> bool:
        return self.state is AuthorizationState.AUTHORISED_BY_OVERRIDE

    @property
    def machine_verdict_preserved(self) -> bool:
        """Unconditionally True: nothing on this path can write a verdict.

        The companion to `Override.converts_verdict`. One says the override does
        not change it; this says the combined state does not either.
        """
        return True

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False, at every state including AUTHORISED."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "authorization", "state": self.state.value,
                "authorised": self.authorised,
                "proceeds_over_open_issues": self.proceeds_over_open_issues,
                "machine_verdict": self.machine_verdict,
                "machine_verdict_preserved": True,
                "establishes_truth": False,
                "notes": list(self.notes),
                "approval": (self.approval.to_dict() if self.approval is not None
                             else None),
                "override": self.override.to_dict() if self.override else None,
                "review": self.review.to_dict() if self.review else None}

    def render(self) -> str:
        lines = [f"AUTHORIZATION: {self.state.value}"]
        if self.machine_verdict:
            lines.append(f"  machine verdict: {self.machine_verdict} "
                         "(unchanged — an authorization is not a verdict)")
        for note in self.notes:
            lines.append(f"  {note}")
        if self.override is not None:
            lines.append("")
            lines.append(self.override.render())
        return "\n".join(lines)


def authorisation_of(case: Any, *, approval: Any = None,
                     override: Optional[Override] = None,
                     review: Optional[OverrideReview] = None) -> Authorization:
    """Read the authorization state off what actually exists.

    Never derived from the verdict: a PROMOTE with no approval is
    `NOT_AUTHORISED`, which is the whole of §10x.2's fourth refusal expressed as
    a state rather than a sentence.
    """
    verdict = getattr(case, "verdict", None)
    machine = getattr(getattr(verdict, "decision", None), "value", None)
    notes: List[str] = []

    if override is not None and not override.binds_to(case):
        moved = override.stale_against(case)
        notes.append("the override on hand was granted against a different state ("
                     + ", ".join(moved) + " moved); it does not carry over")
        override = None

    if approval is None:
        if review is not None and not review.granted:
            return Authorization(
                state=AuthorizationState.OVERRIDE_REFUSED, machine_verdict=machine,
                review=review, notes=tuple(notes + [
                    "an override was sought and refused; nothing here authorises "
                    "anything"]))
        return Authorization(
            state=AuthorizationState.NOT_AUTHORISED, machine_verdict=machine,
            override=override, review=review,
            notes=tuple(notes + [
                "no human act is on record. A verdict is not an authorization, "
                "whatever it says"]))

    decision = getattr(approval, "decision", None)
    if decision is ApprovalDecision.REJECTED:
        return Authorization(state=AuthorizationState.REFUSED,
                             machine_verdict=machine, approval=approval,
                             override=override, review=review, notes=tuple(notes))
    if decision is not ApprovalDecision.APPROVED:
        return Authorization(
            state=AuthorizationState.NOT_AUTHORISED, machine_verdict=machine,
            approval=approval, override=override, review=review,
            notes=tuple(notes + ["the human act on record is "
                                 f"{getattr(decision, 'value', decision)}, which "
                                 "decides nothing either way"]))

    if override is not None:
        return Authorization(
            state=AuthorizationState.AUTHORISED_BY_OVERRIDE, machine_verdict=machine,
            approval=approval, override=override, review=review,
            notes=tuple(notes + [
                f"proceeding over {len(override.issues)} unresolved issue(s), "
                f"which remain unresolved",
                f"the verdict is still {machine}; this state is not PROMOTE and "
                "does not become it"]))

    if machine is not None and machine != Decision.PROMOTE.value:
        # Approved over a non-PROMOTE with no override on record. Legitimate —
        # `BoundApproval.overrides_recommendation` has always recorded it — but
        # it is not the same act as a permitted override and is not dressed as
        # one here.
        notes.append(f"approved over a {machine} with no override on record; the "
                     "methodology was never asked whether these requirements may "
                     "be waived")
    return Authorization(state=AuthorizationState.AUTHORISED, machine_verdict=machine,
                         approval=approval, review=review, notes=tuple(notes))
