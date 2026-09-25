"""Human approval, bound to an exact state and attributable to an exact person.

An approval is the moment a person accepts responsibility for what a machine
did. Everything else in this system exists to make that moment informed; this
module exists to make it *specific* — bound to one state of one case, attributed
to one party, and incapable of quietly outliving either.

Four behaviours carry the weight, and the differences between them are the
product.

**If the subject changes, the approval is invalidated.** Not stale, not
reviewable — invalidated. The subject is the thing being authorised, so a subject
that moved means the human authorised something else. There is no repair short of
a new human act (Invariant 5).

**If relevant evidence changes, review is required.** The distinction from the
above is the whole point. What was authorised has not changed; what is *known
about it* has. The human's act still attaches to the right thing, and the basis
underneath it moved, so a person should look again — and blocking outright would
train people to re-approve reflexively, which is worse than asking.

"Relevant" is derived rather than asserted: only the collections that constitute
the evidentiary state count. Release-gate's own derived outputs — attention items,
required evidence, coverage rows — change whenever it finds different things to
say, and treating that as an evidence change would raise review on noise until
nobody read the signal (Invariant 13).

**If a verification target changes, the relevant verification goes stale.** That
is already true of `VerificationAttempt.applicability()`; what this module adds is
naming the attempts that went `SUPERSEDED` under an approval, so the reviewer is
told which checks stopped applying rather than being left to notice.

**If an approval is replayed against another case, it is rejected.** Checked
first and reported hardest: an approval arriving against a case it was not issued
for is not an expired approval or a stale one, it is an approval being used for
something it was never given for.

Two refusals beyond those.

**Release-gate cannot approve.** `AuthSource.RELEASE_GATE` is refused in the
constructor, and an approval with no approver is refused with it. An approval
whose `auth_source` is `ASSERTED` is attributable to a *claim* of identity and
not to an established one — `identity_established` says so, because signing
establishes which party made a statement and never that the statement is right
(Invariant 11).

**An approval never rewrites a verdict.** It records what release-gate
recommended alongside what the human did, so approving over a BLOCK is visible as
exactly that — a person taking responsibility despite the recommendation, which
is a legitimate and sometimes necessary act, and never a case that became clean
because somebody signed it (Invariant 15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id

__all__ = [
    "APPROVAL_SCHEMA_VERSION",
    "ApprovalAcknowledgement",
    "ApprovalCheck",
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalOffer",
    "ApprovalStanding",
    "ApprovalSubmission",
    "AuthSource",
    "BoundApproval",
    "SubmissionOutcome",
    "binding_of",
    "check_approval",
    "offer_approval",
    "submit_approval",
]

APPROVAL_SCHEMA_VERSION = 1


class ApprovalError(ValueError):
    """An approval was recorded in a state that would misattribute or misbind it."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ApprovalDecision(str, Enum):
    """What the human did. Separate from what release-gate recommended."""

    APPROVED = "APPROVED"    # authorises the action, at the bound state
    REJECTED = "REJECTED"    # refuses it
    DEFERRED = "DEFERRED"    # declines to decide now, and says so on the record


class AuthSource(str, Enum):
    """How the approver's identity was established.

    `ASSERTED` is the honest default for an identity nobody checked: the approval
    is attributable to a claim of identity rather than to an established one. It
    is not a lesser kind of approval, and it is not the same kind either.
    """

    OIDC = "OIDC"
    SIGNED_TOKEN = "SIGNED_TOKEN"
    SSH_KEY = "SSH_KEY"
    GPG_KEY = "GPG_KEY"
    PLATFORM_SSO = "PLATFORM_SSO"
    API_KEY = "API_KEY"
    ASSERTED = "ASSERTED"      # the caller said who they were; nothing checked it
    UNKNOWN = "UNKNOWN"
    #: Present so it can be refused by name rather than by omission.
    RELEASE_GATE = "RELEASE_GATE"


#: Sources where a third party established the identity. An API key proves
#: possession of a key, which is weaker than a person authenticating and is
#: deliberately not in here.
_ESTABLISHED = frozenset({AuthSource.OIDC, AuthSource.SIGNED_TOKEN,
                          AuthSource.SSH_KEY, AuthSource.GPG_KEY,
                          AuthSource.PLATFORM_SSO})


class ApprovalStanding(str, Enum):
    """Where an approval stands against a case, now."""

    VALID = "VALID"
    APPROVAL_REVIEW_REQUIRED = "APPROVAL_REVIEW_REQUIRED"  # the basis moved
    APPROVAL_SCOPE_MISMATCH = "APPROVAL_SCOPE_MISMATCH"    # given for something else
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_INVALIDATED = "APPROVAL_INVALIDATED"          # the subject moved
    APPROVAL_FOREIGN = "APPROVAL_FOREIGN"                  # issued for another case


#: Worst-first. Every applicable condition is reported; this decides which one
#: names the standing. FOREIGN outranks everything because an approval used
#: against a case it was not issued for is a different kind of problem from an
#: approval that has gone out of date.
_SEVERITY: Tuple[ApprovalStanding, ...] = (
    ApprovalStanding.APPROVAL_FOREIGN,
    ApprovalStanding.APPROVAL_INVALIDATED,
    ApprovalStanding.APPROVAL_EXPIRED,
    ApprovalStanding.APPROVAL_SCOPE_MISMATCH,
    ApprovalStanding.APPROVAL_REVIEW_REQUIRED,
    ApprovalStanding.VALID,
)


def _identity_from(data: Any) -> Any:
    """Rebuild an approver's identity claim, without importing at module level.

    Deferred because `identity` imports `approval` for `AuthSource`, and a
    top-level import here would close that circle.
    """
    if not data:
        return None
    from release_gate.assurance.identity import IdentityClaim
    return IdentityClaim.from_dict(data)


def binding_of(case: Any) -> Dict[str, Any]:
    """The exact state any human act on this case must bind to.

    One reader, so an approval and an override cannot end up bound to
    differently-computed versions of the same state. The digests are read from
    the case and never accepted from a caller: a binding a caller could choose
    is a binding to whatever the caller wanted it to be.
    """
    state = case.binding_state()
    inner = state.get("state") or {}
    subject_state = inner.get("subject_state") or {}
    return {
        "case_id": str(state.get("case_id") or ""),
        "case_version": int(state.get("case_version") or 1),
        "case_digest": str(state.get("case_digest") or ""),
        "subject_id": str(subject_state.get("subject_id") or ""),
        # The state an act attaches to, not the subject's content identity. The
        # two are different digests and conflating them is how an approval
        # survives a change it should not have survived.
        "subject_digest": str(subject_state.get("state_digest") or ""),
        "evidence_pack_digest": str(inner.get("evidence_digest") or "") or None,
        "bound_collections": {
            kind: str((component or {}).get("fold_digest") or "")
            for kind, component in (inner.get("collections") or {}).items()},
    }


@dataclass(frozen=True)
class BoundApproval:
    """One human act, bound to one exact state of one case."""

    case_id: str
    case_version: int
    approver: str
    subject_digest: str
    case_digest: str
    #: The subject's id as of approval. Carried so a later revision that names it
    #: in `supersedes` can be recognised as a revision of *this* subject rather
    #: than of some other one.
    subject_id: str = ""
    decision: ApprovalDecision = ApprovalDecision.APPROVED
    scope: str = ""
    evidence_pack_digest: Optional[str] = None
    #: Per-collection fold digests as of approval, so a later check can say which
    #: part of the case moved rather than only that something did.
    bound_collections: Mapping[str, str] = field(default_factory=dict)
    #: What release-gate recommended at the time. Kept beside `decision` so an
    #: approval over a BLOCK is visible as an override rather than as agreement.
    case_decision: Optional[str] = None
    auth_source: AuthSource = AuthSource.ASSERTED
    timestamp: str = field(default_factory=_utc_now)
    expires_at: Optional[str] = None
    comment: str = ""
    #: The `Override` that made approving this permissible, where one was
    #: granted. Empty means none was — which is not the same as none being
    #: needed, and `overrides_recommendation` is what says which.
    override_id: str = ""
    #: The `IdentityClaim` this approver was established by, where a host
    #: supplied one. `approver` is a display string; this is what an auditor can
    #: look up in an issuer months later. Optional, because a CLI run against a
    #: local file has no identity provider and should not have to invent one.
    approver_identity: Any = None
    schema_version: int = APPROVAL_SCHEMA_VERSION

    approval_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", ApprovalDecision(self.decision))
        object.__setattr__(self, "auth_source", AuthSource(self.auth_source))
        object.__setattr__(self, "bound_collections", dict(self.bound_collections or {}))

        if self.auth_source is AuthSource.RELEASE_GATE:
            raise ApprovalError(
                "release-gate cannot approve. It can report what the evidence shows "
                "and what it recommends; accepting responsibility for acting on that "
                "is a human act and an engine signing its own homework is the thing "
                "this system exists to prevent (Invariant 15)")
        if not (self.approver or "").strip():
            raise ApprovalError(
                "an approval must name its approver — an authorisation nobody is "
                "answerable for is not an audit trail")
        for name in ("case_id", "subject_digest", "case_digest"):
            if not (getattr(self, name) or "").strip():
                raise ApprovalError(
                    f"{name} is required: an approval that does not bind to an exact "
                    "state binds to whatever that state becomes")
        if self.case_version < 1:
            raise ApprovalError("case_version must be a real version")
        if self.expires_at and self.expires_at <= self.timestamp:
            raise ApprovalError(
                "expires_at must be after the approval was given; an approval that "
                "expired before it was made is a record of nothing")

        object.__setattr__(self, "approver", self.approver.strip())
        object.__setattr__(self, "approval_id",
                           short_id("appr", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct act of authorisation.

        `override_id` joins it only when there is one. Approving on clean
        evidence and approving under a granted override are different acts and
        should not share an id — but adding the key unconditionally would change
        the digest of every approval ever recorded, so it appears when it says
        something and is absent when it does not.
        """
        identity = {"schema_version": APPROVAL_SCHEMA_VERSION,
                    "case_id": self.case_id, "case_version": self.case_version,
                    "approver": self.approver, "scope": self.scope,
                    "subject_digest": self.subject_digest,
                    "case_digest": self.case_digest,
                    "evidence_pack_digest": self.evidence_pack_digest,
                    "decision": self.decision.value, "timestamp": self.timestamp,
                    "auth_source": self.auth_source.value}
        if self.override_id:
            identity["override_id"] = self.override_id
        if self.approver_identity is not None:
            # Same conditional as `override_id`, for the same reason: an approval
            # established by a named identity is a different act from one taken
            # on a bare string, but adding the key unconditionally would change
            # the digest of every approval ever recorded.
            identity["approver_identity"] = self.approver_identity.claim_id
        return identity

    # ── standing ────────────────────────────────────────────────────────────

    @property
    def identity_established(self) -> bool:
        """Whether a third party checked who this was.

        `False` does not make the approval void. It makes it attributable to a
        claim of identity, which is a different and weaker fact than an
        established one, and the difference belongs on the record rather than in
        a reader's assumptions (Invariant 11).
        """
        return self.auth_source in _ESTABLISHED

    @property
    def authorises(self) -> bool:
        return self.decision is ApprovalDecision.APPROVED

    @property
    def overrides_recommendation(self) -> bool:
        """Approved despite release-gate recommending against it.

        Legitimate and sometimes necessary. Recorded because a case does not
        become clean by being signed, and a reader must be able to see that a
        person went ahead rather than that the evidence improved (Invariant 15).
        """
        return (self.authorises
                and self.case_decision is not None
                and self.case_decision != "PROMOTE")

    @property
    def attributable_to(self) -> str:
        """What this approval can be traced back to.

        The identity's provider-scoped handle when one was supplied, and the bare
        approver string otherwise — which is a name somebody typed, and says so
        through `identity_established` being False.
        """
        if self.approver_identity is not None:
            return self.approver_identity.attributable_to
        return self.approver

    @property
    def approver_is_a_person(self) -> Optional[bool]:
        """Whether a person is behind this. `None` when no identity was supplied.

        `None` rather than `False`: a missing identity claim means nobody said,
        and reporting that as "not a person" would be a determination this record
        does not hold.
        """
        if self.approver_identity is None:
            return None
        return self.approver_identity.is_a_person

    @property
    def proceeds_under_override(self) -> bool:
        """Whether a methodology was asked, and said yes, before this was given.

        The companion to `overrides_recommendation`: that one says a person went
        ahead of the recommendation, this one says something permitted them to.
        An approval where the first is True and this is False is someone
        proceeding on their own authority, which is allowed and is not the same
        thing.
        """
        return bool(self.override_id)

    @property
    def expiry_basis(self) -> str:
        """Stated rather than silent: no expiry is a decision, not an absence."""
        return (f"expires {self.expires_at}" if self.expires_at
                else "no expiry was set; this approval does not lapse on its own, "
                     "and only a change to what it binds to will unseat it")

    def expired(self, now: Optional[str] = None) -> bool:
        if not self.expires_at:
            return False
        return (now or _utc_now()) >= self.expires_at

    # ── serialisation ───────────────────────────────────────────────────────

    @property
    def record_type(self) -> str:
        return "approval"

    @property
    def record_id(self) -> str:
        return self.approval_id

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "approval", "record_id": self.approval_id,
                "approval_id": self.approval_id,
                "case_id": self.case_id, "case_version": self.case_version,
                "approver": self.approver, "scope": self.scope,
                "subject_id": self.subject_id,
                "subject_digest": self.subject_digest,
                "case_digest": self.case_digest,
                "evidence_pack_digest": self.evidence_pack_digest,
                "bound_collections": dict(self.bound_collections),
                "timestamp": self.timestamp, "expires_at": self.expires_at,
                "expiry_basis": self.expiry_basis,
                "decision": self.decision.value,
                "case_decision": self.case_decision,
                "overrides_recommendation": self.overrides_recommendation,
                "override_id": self.override_id,
                "proceeds_under_override": self.proceeds_under_override,
                "attributable_to": self.attributable_to,
                "approver_is_a_person": self.approver_is_a_person,
                "approver_identity": (self.approver_identity.to_dict()
                                      if self.approver_identity is not None
                                      else None),
                "comment": self.comment,
                "auth_source": self.auth_source.value,
                "identity_established": self.identity_established,
                "schema_version": APPROVAL_SCHEMA_VERSION}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BoundApproval":
        return cls(
            case_id=str(data.get("case_id") or ""),
            case_version=int(data.get("case_version") or 1),
            approver=str(data.get("approver") or ""),
            subject_id=str(data.get("subject_id") or ""),
            subject_digest=str(data.get("subject_digest") or ""),
            case_digest=str(data.get("case_digest") or ""),
            decision=ApprovalDecision(str(data.get("decision") or "APPROVED").upper()),
            scope=str(data.get("scope") or ""),
            evidence_pack_digest=(str(data["evidence_pack_digest"])
                                  if data.get("evidence_pack_digest") else None),
            bound_collections=data.get("bound_collections") or {},
            case_decision=(str(data["case_decision"]) if data.get("case_decision")
                           else None),
            auth_source=AuthSource(str(data.get("auth_source") or "ASSERTED").upper()),
            timestamp=str(data.get("timestamp") or _utc_now()),
            expires_at=(str(data["expires_at"]) if data.get("expires_at") else None),
            override_id=str(data.get("override_id") or ""),
            approver_identity=_identity_from(data.get("approver_identity")),
            comment=str(data.get("comment") or ""))

    @classmethod
    def for_case(cls, case: Any, *, approver: str, scope: str = "",
                 decision: ApprovalDecision = ApprovalDecision.APPROVED,
                 auth_source: AuthSource = AuthSource.ASSERTED,
                 identity: Any = None,
                 **kwargs: Any) -> "BoundApproval":
        """Bind an approval to a sealed case's exact current state.

        The digests are read from the case rather than accepted from a caller: an
        approval whose binding a caller could choose is an approval that binds to
        whatever the caller wanted it to.
        """
        bound = binding_of(case)
        return cls(
            case_id=bound["case_id"], case_version=bound["case_version"],
            approver=approver, scope=scope, decision=decision,
            subject_id=bound["subject_id"],
            subject_digest=bound["subject_digest"],
            case_digest=bound["case_digest"],
            evidence_pack_digest=bound["evidence_pack_digest"],
            bound_collections=bound["bound_collections"],
            case_decision=(case.verdict.decision.value if case.verdict else None),
            auth_source=auth_source, approver_identity=identity, **kwargs)

    def render(self) -> str:
        lines = [f"{self.decision.value} by {self.approver} at {self.timestamp}",
                 f"  bound to case {self.case_id} v{self.case_version} "
                 f"({self.case_digest})",
                 f"  subject {self.subject_digest}",
                 f"  scope: {self.scope or 'not stated'}",
                 f"  identity: {self.auth_source.value}"
                 + ("" if self.identity_established
                    else " — attributable to a claim of identity, not an "
                         "established one"),
                 f"  attributable to: {self.attributable_to}",
                 f"  {self.expiry_basis}"]
        if self.overrides_recommendation:
            lines.append(f"  OVERRIDE: release-gate recommended "
                         f"{self.case_decision}; this approval proceeds anyway")
            lines.append("  " + (f"permitted by override {self.override_id}"
                                 if self.override_id else
                                 "no override is on record; nothing was asked "
                                 "whether these requirements may be waived"))
        if self.comment:
            lines.append(f"  comment: {self.comment}")
        return "\n".join(lines)


# ── checking ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ApprovalCheck:
    """Where an approval stands against a case, and everything that bears on it.

    `conditions` holds every condition that applies, not only the one that names
    the standing. An approval that is both expired and bound to a moved subject
    has two problems, and a reader told about one of them would fix it and be
    surprised.
    """

    approval_id: str
    standing: ApprovalStanding = ApprovalStanding.VALID
    conditions: Tuple[ApprovalStanding, ...] = ()
    reasons: Tuple[str, ...] = ()
    moved_collections: Tuple[str, ...] = ()
    derived_only_changes: Tuple[str, ...] = ()
    stale_verifications: Tuple[str, ...] = ()
    checked_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "standing", ApprovalStanding(self.standing))
        object.__setattr__(self, "conditions", tuple(self.conditions))
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "moved_collections", tuple(sorted(self.moved_collections)))
        object.__setattr__(self, "derived_only_changes",
                           tuple(sorted(self.derived_only_changes)))
        object.__setattr__(self, "stale_verifications", tuple(self.stale_verifications))

    @property
    def valid(self) -> bool:
        return self.standing is ApprovalStanding.VALID

    @property
    def needs_new_approval(self) -> bool:
        """Whether nothing short of another human act will do.

        Review-required is deliberately not in here: the thing authorised has not
        changed, so a person looking again may reasonably let the approval stand.
        """
        return self.standing in (ApprovalStanding.APPROVAL_FOREIGN,
                                 ApprovalStanding.APPROVAL_INVALIDATED,
                                 ApprovalStanding.APPROVAL_EXPIRED,
                                 ApprovalStanding.APPROVAL_SCOPE_MISMATCH)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "approval_check", "record_id": self.approval_id,
                "approval_id": self.approval_id,
                "standing": self.standing.value,
                "valid": self.valid,
                "needs_new_approval": self.needs_new_approval,
                "conditions": [c.value for c in self.conditions],
                "reasons": list(self.reasons),
                "moved_collections": list(self.moved_collections),
                "derived_only_changes": list(self.derived_only_changes),
                "stale_verifications": list(self.stale_verifications),
                "checked_at": self.checked_at}

    def render(self) -> str:
        lines = [f"{self.standing.value} — {self.approval_id}"]
        lines.extend(f"  {reason}" for reason in self.reasons)
        if self.stale_verifications:
            lines.append(f"  {len(self.stale_verifications)} verification(s) no "
                         "longer apply to the current target state")
        if self.derived_only_changes:
            lines.append("  (release-gate's own outputs also moved: "
                         + ", ".join(self.derived_only_changes)
                         + " — that is this engine finding different things to say, "
                           "not the evidence moving)")
        return "\n".join(lines)


def check_approval(approval: BoundApproval, case: Any, *,
                   now: Optional[str] = None,
                   scope: Optional[str] = None) -> ApprovalCheck:
    """Where this approval stands against this case, right now.

    Pure. Checking an approval never refreshes it, never extends its expiry and
    never mutates the case: a re-check that could repair an approval would make
    the binding a formality.
    """
    from release_gate.assurance.case import EVIDENCE_KINDS

    state = case.binding_state()
    inner = state.get("state") or {}
    subject_state = inner.get("subject_state") or {}
    conditions: List[ApprovalStanding] = []
    reasons: List[str] = []

    # A different case id is either a revision of what was approved or an approval
    # being used somewhere it was never given for, and the two need different
    # words. `case_id` folds in the subject id, which folds in the subject's
    # content digest — so revising the subject always lands here, and calling that
    # a replay would send a reviewer looking for an attacker when a colleague
    # edited a file. Supersession is what tells them apart.
    current_case_id = str(state.get("case_id") or "")
    if current_case_id != approval.case_id:
        # `case.supersedes` is "<case_id>@v<n>", so the id is the part before the
        # marker. Both links must name *this* approval's case or subject: a case
        # that supersedes some other case is not a revision of what was approved
        # here, and treating it as one would silence a genuine replay.
        supersedes = str(getattr(case, "supersedes", "") or "").split("@")[0]
        subject_supersedes = str((subject_state.get("identity") or {}).get("supersedes")
                                 or "")
        revision = (supersedes == approval.case_id
                    or (bool(approval.subject_id)
                        and subject_supersedes == approval.subject_id))
        if revision:
            conditions.append(ApprovalStanding.APPROVAL_INVALIDATED)
            reasons.append(
                f"case {current_case_id} supersedes {approval.case_id}: the thing "
                "that was approved has been revised, so the approval applies to the "
                "previous revision only and this one needs its own")
        else:
            conditions.append(ApprovalStanding.APPROVAL_FOREIGN)
            reasons.append(
                f"this approval was issued for case {approval.case_id} and is being "
                f"checked against {current_case_id}, and nothing links them; an "
                "approval is not transferable between cases")
        return ApprovalCheck(
            approval_id=approval.approval_id, standing=conditions[0],
            conditions=tuple(conditions), reasons=tuple(reasons),
            stale_verifications=_stale_verifications(case),
            checked_at=now or _utc_now())

    # A new version of the same case. `AssuranceCase.revise()` states the rule
    # and enforces half of it — it drops the approvals collection when it opens a
    # revision — but a caller holding an approval and a revised case would
    # otherwise get VALID for an approval the case model says applies to the
    # previous version only. The subject may well be unchanged; the argument was
    # re-opened, and that is what the approval was given against.
    current_version = int(state.get("case_version") or 1)
    if current_version != approval.case_version:
        conditions.append(ApprovalStanding.APPROVAL_INVALIDATED)
        reasons.append(
            f"this approval was given against version {approval.case_version} and "
            f"the case is now at version {current_version}; a revision re-opens the "
            "argument, so the approval applies to the previous version only")

    # The subject moved: the human authorised a different thing.
    current_subject = str(subject_state.get("state_digest") or "")
    if current_subject != approval.subject_digest:
        conditions.append(ApprovalStanding.APPROVAL_INVALIDATED)
        reasons.append(
            f"the subject moved from {approval.subject_digest} to {current_subject}; "
            "what was authorised is not what is now in front of you, and no "
            "re-check repairs that")

    if approval.expired(now):
        conditions.append(ApprovalStanding.APPROVAL_EXPIRED)
        reasons.append(f"the approval expired at {approval.expires_at}")

    if scope is not None and scope != approval.scope:
        conditions.append(ApprovalStanding.APPROVAL_SCOPE_MISMATCH)
        reasons.append(
            f"this approval covers {approval.scope or '(no scope stated)'} and is "
            f"being used for {scope}")

    # What moved, split the way the evidentiary state is split. Only the
    # collections that constitute the argument count as an evidence change;
    # release-gate's own outputs move whenever it finds different things to say.
    current_collections = {
        kind: str((component or {}).get("fold_digest") or "")
        for kind, component in (inner.get("collections") or {}).items()}
    moved = sorted(kind for kind, digest in current_collections.items()
                   if kind in approval.bound_collections
                   and approval.bound_collections[kind] != digest)
    moved += sorted(kind for kind in current_collections
                    if kind not in approval.bound_collections
                    and approval.bound_collections)
    evidentiary = tuple(sorted({k for k in moved if k in EVIDENCE_KINDS}))
    derived = tuple(sorted({k for k in moved if k not in EVIDENCE_KINDS}))

    if evidentiary:
        conditions.append(ApprovalStanding.APPROVAL_REVIEW_REQUIRED)
        reasons.append(
            "evidence this approval rested on has changed (" +
            ", ".join(evidentiary) + "); what was authorised is unchanged, but what "
            "is known about it has moved, so a person should look again")
    elif (approval.case_digest != str(state.get("case_digest") or "")
          and not conditions):
        # The case digest moved but no evidentiary collection did. Worth saying
        # plainly rather than passing in silence or raising review on nothing.
        reasons.append(
            "the case digest moved but no evidentiary collection did; the change is "
            "in release-gate's own output, not in the evidence")

    standing = next((s for s in _SEVERITY if s in conditions), ApprovalStanding.VALID)
    if standing is ApprovalStanding.VALID and not reasons:
        reasons.append(
            f"bound to case {approval.case_id} v{approval.case_version} at "
            f"{approval.case_digest}; subject and evidentiary state are unchanged")

    return ApprovalCheck(
        approval_id=approval.approval_id, standing=standing,
        conditions=tuple(conditions), reasons=tuple(reasons),
        moved_collections=evidentiary, derived_only_changes=derived,
        stale_verifications=_stale_verifications(case),
        checked_at=now or _utc_now())


def _stale_verifications(case: Any) -> Tuple[str, ...]:
    """Attempts that no longer apply because their target moved.

    Read from the verification graph rather than recomputed: applicability is
    already a computation there, and a second implementation of it would
    eventually disagree with the first about the same attempt.
    """
    try:
        from release_gate.assurance.verification import VerificationGraph
        graph = VerificationGraph.from_case(case)
        return tuple(a.verification_id for a in graph.superseded_attempts())
    except Exception:
        return ()


# ── the two-step: offer, then submit ─────────────────────────────────────────

class SubmissionOutcome(str, Enum):
    """What happened to an attempt to record an approval."""

    ACCEPTED = "ACCEPTED"
    #: The state moved between the read and the write. The client is handed the
    #: current state so it can decide whether the change matters, re-present to
    #: the human if it does, and try again.
    CONFLICT = "CONFLICT"
    #: Some acknowledgement field was absent. Not a weaker acknowledgement — a
    #: refusal: acknowledging the version but not the subject digest is exactly
    #: the hole this two-step exists to close.
    INCOMPLETE_ACKNOWLEDGEMENT = "INCOMPLETE_ACKNOWLEDGEMENT"
    #: The case is not in a state where an approval means anything.
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class ApprovalAcknowledgement:
    """What the client asserts it read and understood it was approving.

    Three values, all required. An opaque precondition token says "the case you
    read"; naming the version, the subject and the evidence state says *what the
    client took that case to be* — and a mismatch in any one of them is a client
    approving something other than what it believes it is approving.
    """

    case_version: Optional[int] = None
    subject_digest: Optional[str] = None
    evidence_pack_digest: Optional[str] = None
    case_digest: Optional[str] = None

    @property
    def complete(self) -> bool:
        return (self.case_version is not None
                and bool((self.subject_digest or "").strip())
                and bool((self.evidence_pack_digest or "").strip()))

    @property
    def missing(self) -> Tuple[str, ...]:
        absent = []
        if self.case_version is None:
            absent.append("case_version")
        if not (self.subject_digest or "").strip():
            absent.append("subject_digest")
        if not (self.evidence_pack_digest or "").strip():
            absent.append("evidence_pack_digest")
        return tuple(absent)

    def to_dict(self) -> Dict[str, Any]:
        return {"case_version": self.case_version,
                "subject_digest": self.subject_digest,
                "evidence_pack_digest": self.evidence_pack_digest,
                "case_digest": self.case_digest,
                "complete": self.complete, "missing": list(self.missing)}


@dataclass(frozen=True)
class ApprovalOffer:
    """The read half: exactly what would be approved, before anything is accepted.

    An offer is **not a lock**. Optimistic concurrency reserves nothing: two
    clients may hold offers against the same state, the first to submit wins and
    the second is told the state moved. An offer that looked like a lock would be
    worse than no offer at all, because a client would stop checking.
    """

    case_id: str
    case_version: int
    subject_digest: str
    case_digest: str
    evidence_pack_digest: Optional[str] = None
    collection_digests: Mapping[str, str] = field(default_factory=dict)
    recommendation: Optional[str] = None
    packet: Any = None
    offered_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "collection_digests",
                           dict(self.collection_digests or {}))

    @property
    def required_acknowledgement(self) -> Tuple[str, ...]:
        """Named so a client cannot discover the contract by trial and error."""
        return ("case_version", "subject_digest", "evidence_pack_digest")

    def acknowledgement(self) -> ApprovalAcknowledgement:
        """The acknowledgement a client would send having read this offer.

        A convenience for a client that genuinely read the offer — and not a
        shortcut past the check, because submission verifies against the live
        case and never against this object.
        """
        return ApprovalAcknowledgement(
            case_version=self.case_version, subject_digest=self.subject_digest,
            evidence_pack_digest=self.evidence_pack_digest,
            case_digest=self.case_digest)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "approval_offer",
                "case_id": self.case_id, "case_version": self.case_version,
                "subject_digest": self.subject_digest,
                "case_digest": self.case_digest,
                "evidence_pack_digest": self.evidence_pack_digest,
                "collection_digests": dict(self.collection_digests),
                "recommendation": self.recommendation,
                "required_acknowledgement": list(self.required_acknowledgement),
                "offered_at": self.offered_at,
                # Stated in the payload so no client infers otherwise from the
                # existence of an offer.
                "is_a_lock": False,
                "note": ("This offer reserves nothing. If the case moves before you "
                         "submit, your submission conflicts and you will be handed "
                         "the current state."),
                "packet": (self.packet.to_dict() if self.packet is not None else None)}


@dataclass(frozen=True)
class ApprovalSubmission:
    """What came of an attempt to record an approval."""

    outcome: SubmissionOutcome
    approval: Optional[BoundApproval] = None
    reasons: Tuple[str, ...] = ()
    current: Optional[ApprovalOffer] = None
    mismatched: Tuple[str, ...] = ()
    evidentiary_change: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", SubmissionOutcome(self.outcome))
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "mismatched", tuple(sorted(self.mismatched)))

    @property
    def accepted(self) -> bool:
        return self.outcome is SubmissionOutcome.ACCEPTED

    @property
    def human_must_re_read(self) -> bool:
        """Whether the human has to look again, or only the client re-acknowledge.

        A conflict where nothing evidentiary moved means release-gate found
        different things to say about the same evidence — the thing the person
        approved is unchanged, so re-acknowledging is honest. Where evidence
        moved, the basis of their decision moved with it.
        """
        return self.outcome is SubmissionOutcome.CONFLICT and self.evidentiary_change

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "approval_submission",
                "outcome": self.outcome.value, "accepted": self.accepted,
                "reasons": list(self.reasons),
                "mismatched": list(self.mismatched),
                "evidentiary_change": self.evidentiary_change,
                "human_must_re_read": self.human_must_re_read,
                "approval": self.approval.to_dict() if self.approval else None,
                "current": self.current.to_dict() if self.current else None}


def offer_approval(case: Any, outcome: Any = None) -> ApprovalOffer:
    """Return the exact state an approval would bind to, before accepting one.

    The read half of the two-step. Everything a client must acknowledge is here,
    named, alongside the packet the human reads — so the values being
    acknowledged and the document being read come from one snapshot rather than
    two calls that could straddle a change.
    """
    state = case.binding_state()
    inner = state.get("state") or {}
    subject_state = inner.get("subject_state") or {}
    packet = None
    if outcome is not None:
        try:
            from release_gate.assurance.packet import build_packet
            packet = build_packet(case, outcome)
        except Exception:
            packet = None
    return ApprovalOffer(
        case_id=str(state.get("case_id") or ""),
        case_version=int(state.get("case_version") or 1),
        subject_digest=str(subject_state.get("state_digest") or ""),
        case_digest=str(state.get("case_digest") or ""),
        evidence_pack_digest=str(inner.get("evidence_digest") or "") or None,
        collection_digests={
            kind: str((component or {}).get("fold_digest") or "")
            for kind, component in (inner.get("collections") or {}).items()},
        recommendation=(case.verdict.decision.value if case.verdict else None),
        packet=packet)


def submit_approval(case: Any, acknowledgement: ApprovalAcknowledgement, *,
                    approver: str,
                    decision: ApprovalDecision = ApprovalDecision.APPROVED,
                    auth_source: AuthSource = AuthSource.ASSERTED,
                    scope: str = "", comment: str = "",
                    expires_at: Optional[str] = None,
                    override: Any = None,
                    identity: Any = None) -> ApprovalSubmission:
    """Record an approval, but only against the exact state the client acknowledged.

    There is deliberately no way to express "approve the latest". The only
    approval this function can record is an approval of one named state, because
    a read and a write that are not bound to the same version are a race with a
    human signature on the losing side.

    The acknowledgement is verified against the **live case**, never against any
    offer object the caller happens to be holding. An offer is a convenience for
    the human; treating it as the authority would let a fabricated one authorise
    anything.

    An `identity` is optional too, and is an `IdentityClaim` a host boundary
    established. Supplied, the approval becomes traceable to an issuer and a
    subject rather than to a string; `auth_source` should be derived from it with
    `identity.auth_source_for` so the two cannot disagree.

    An `override` is optional and is never required: approving over a HOLD has
    always been allowed and has always been recorded as such. Supplied, it is
    checked to bind to this same state — an override granted against a different
    case, or against this one before it moved, permits nothing here — and its id
    is carried on the approval.
    """
    from release_gate.assurance.case import EVIDENCE_KINDS

    current = offer_approval(case)

    if not acknowledgement.complete:
        return ApprovalSubmission(
            outcome=SubmissionOutcome.INCOMPLETE_ACKNOWLEDGEMENT,
            current=current, mismatched=acknowledgement.missing,
            reasons=("the client did not acknowledge "
                     + ", ".join(acknowledgement.missing)
                     + "; a partial acknowledgement is not a weaker one, it is the "
                       "gap between what was read and what would be signed",))

    if getattr(case, "verdict", None) is None:
        return ApprovalSubmission(
            outcome=SubmissionOutcome.REFUSED, current=current,
            reasons=("this case has no verdict; there is nothing yet for a human to "
                     "accept responsibility for",))

    mismatched: List[str] = []
    if acknowledgement.case_version != current.case_version:
        mismatched.append("case_version")
    if acknowledgement.subject_digest != current.subject_digest:
        mismatched.append("subject_digest")
    if acknowledgement.evidence_pack_digest != current.evidence_pack_digest:
        mismatched.append("evidence_pack_digest")
    # Optional, and checked when supplied: a client that read the case digest is
    # entitled to have it enforced too.
    if (acknowledgement.case_digest is not None
            and acknowledgement.case_digest != current.case_digest):
        mismatched.append("case_digest")

    if mismatched:
        evidentiary = ("subject_digest" in mismatched
                       or "evidence_pack_digest" in mismatched
                       or "case_version" in mismatched)
        return ApprovalSubmission(
            outcome=SubmissionOutcome.CONFLICT, current=current,
            mismatched=mismatched, evidentiary_change=evidentiary,
            reasons=("the case moved between the read and this submission ("
                     + ", ".join(mismatched) + "); the current state is returned so "
                     "you can decide whether the change matters"
                     + (", and it does — what the person approved has changed"
                        if evidentiary else
                        ", and only release-gate's own output moved: the evidence "
                        "and the subject are unchanged"),))

    override_id = ""
    if override is not None:
        if not override.binds_to(case):
            moved = ", ".join(override.stale_against(case))
            return ApprovalSubmission(
                outcome=SubmissionOutcome.REFUSED, current=current,
                mismatched=tuple(override.stale_against(case)),
                reasons=("the override supplied was granted against a different "
                         f"state ({moved} moved); it permits nothing here. An "
                         "override that carried over would waive requirements "
                         "against evidence nobody checked it against",))
        if override.expired():
            return ApprovalSubmission(
                outcome=SubmissionOutcome.REFUSED, current=current,
                reasons=(f"the override expired at {override.expires_at}; a lapsed "
                         "waiver is not a weaker waiver",))
        override_id = override.override_id

    try:
        approval = BoundApproval.for_case(
            case, approver=approver, scope=scope, decision=decision,
            auth_source=auth_source, comment=comment, expires_at=expires_at,
            override_id=override_id, identity=identity)
    except ApprovalError as exc:
        return ApprovalSubmission(outcome=SubmissionOutcome.REFUSED, current=current,
                                  reasons=(str(exc),))
    return ApprovalSubmission(
        outcome=SubmissionOutcome.ACCEPTED, approval=approval, current=current,
        reasons=(f"bound to case {approval.case_id} v{approval.case_version} at "
                 f"{approval.case_digest}",))
