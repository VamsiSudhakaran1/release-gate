"""Authorize *what*, exactly — and does this approval finish the job or hand it on.

Six domains asked for the same thing and meant six different acts:

    research        publish a claim, or rely on one in further work
    finance         execute a payment
    healthcare      present a recommendation for a clinician to authorize
    infrastructure  apply a production change
    cybersecurity   execute containment
    aerospace       authorize a mission plan

Not one of those is a regulation, and none of them belongs in this package. What
belongs here is the **structure** they share, which turns out to be two questions
the engine could not previously ask.

## Question one: does this approval complete the authorization?

Healthcare is the sharpest case and the reason `ActClass` exists. "Present a
recommendation for clinician authorization" means release-gate authorizes the
*presenting*. The clinician authorizes the care. An engine that recorded those as
one approval would be claiming clinical authority it does not have and cannot
have, and it would be claiming it in the record a hospital keeps.

So `ActClass.REFER` is a first-class value and `completes_authorization` is `False`
for it. Invariant 15 says approval is authorization rather than truth
certification; this is the same invariant one step further in — approval is
authorization **of a named act**, and which act it is changes what the signature
means.

`PERFORM`, `PUBLISH` and `RELY` complete it. `REFER` does not, and a `REFER` act
must name the authority it defers to, because "somebody else decides next" with no
somebody is a gap wearing a process's clothes.

## Question two: who has standing, and can release-gate ever know?

A platform engineer is not a clinician. A payments approver is not a flight
director. So an act declares the authority it requires, by a name the **domain**
supplies, and a claim to hold that authority arrives with a basis:

* `DECLARED` — the approver said so.
* `ATTRIBUTED` — an identity provider named the role (§10z). Somebody else's
  assertion, which is the strongest thing release-gate normally sees.
* `VETTED` — the organisation's own vetting registry records this person as a
  reviewer it relies on (§10ar). An explicit decision, still not a licence.
* `NOT_ESTABLISHED` — nobody said.

**Release-gate cannot verify a professional qualification and does not try.**
`DomainAct.establishes_qualification` and `AuthorityReading.verifies_credentials`
are unconditionally `False`. What this module records is which authority a domain
required, who claimed it, and on whose word — and a reviewer who wants more than
that is asking a question about a licensing board, not about an assurance engine.

## The asymmetry the cybersecurity example exposed

Every one of `consequence`'s eleven dimensions measures the harm of **acting**:
reversibility, blast radius, money, data, production. Containment inverts that. The
whole point of isolating a compromised host is that *not* doing it is worse, so
HOLD — release-gate's safe answer everywhere else — is the harmful answer there,
and nothing in the consequence model could say so.

`WithholdingCost` says it, and `holding_is_the_safe_default` returns
`Optional[bool]` rather than a bool because "nobody established which direction is
safer" is a real third answer and the commonest one.

**It is deliberately not a twelfth consequence dimension.**
`ConsequenceProfile.to_dict` serialises every member of `ConsequenceDimension`, so
adding one adds a key to every profile in every case, changes the profile record's
digest, changes every `case_digest`, and thereby unseats every `BoundApproval` ever
recorded in a deployment — the exact cost §10ae exists to make visible. That is
why `UNKNOWN_IMPACT` is an escape hatch inside the enum rather than the enum being
open, and it is why this lives beside a profile instead of in one.

## Nothing here names a domain

`ActRegistry` ships **empty**, for §10ar's reason: the four act classes are
structure and release-gate can state them, while `finance.execute_payment` is a
domain's own vocabulary and shipping it would be this engine deciding what a
payment is. A domain declares its acts through `DomainPlugin.acts`, alongside the
methodologies, rules and consequence models it already declared, so an author has
one place to look rather than seven.

All six examples above are expressible with no change to this module, and there is
a test that builds every one of them — in the tests, where a domain's vocabulary
belongs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence,
                    Tuple)

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.expectation import EvidenceExpectation

AUTHORITY_SCHEMA_VERSION = 1


class AuthorityError(ValueError):
    """An act or a claim described in a way that would read as more authority than it is."""


# ── what kind of act is being authorized ─────────────────────────────────────

class ActClass(str, Enum):
    """The structure of the act, with no domain in it.

    Four classes cover the six domains in the brief, which is the argument for
    them being structural rather than a coincidence: what an act *does* to the
    world has a shape, and the shape is what decides whether an approval finishes
    anything.
    """

    #: The world changes when this is authorized. A payment moves, a change
    #: deploys, a host is isolated.
    PERFORM = "PERFORM"
    #: Another authority decides next. Release-gate authorizes putting the
    #: question to them and nothing beyond that.
    REFER = "REFER"
    #: A claim enters a record others will rely on.
    PUBLISH = "PUBLISH"
    #: Further work will depend on a claim. Nothing external changes, and being
    #: wrong propagates.
    RELY = "RELY"
    #: Something these four do not describe. Reads as incomplete, deliberately.
    OTHER = "OTHER"

    @property
    def completes_authorization(self) -> bool:
        """Whether an approval of this act is the whole authorization.

        `REFER` is `False` and `OTHER` is `False`. The first because another
        authority decides next by definition; the second because an act nobody
        classified must not be read as finished.
        """
        return self in (ActClass.PERFORM, ActClass.PUBLISH, ActClass.RELY)

    @property
    def defers(self) -> bool:
        return self is ActClass.REFER

    def describe(self) -> str:
        return _ACT_CLASS_NOTE[self]


_ACT_CLASS_NOTE: Mapping[ActClass, str] = {
    ActClass.PERFORM: (
        "the world changes when this is authorized, so the approval is the last "
        "thing standing between the evidence and the effect"),
    ActClass.REFER: (
        "another authority decides next; this approval authorizes putting the "
        "question to them and says nothing about what they should conclude"),
    ActClass.PUBLISH: (
        "a claim enters a record others will rely on, where withdrawing it later "
        "does not unmake the reliance"),
    ActClass.RELY: (
        "further work will depend on this claim, so being wrong propagates inside "
        "the organisation rather than outside it"),
    ActClass.OTHER: (
        "an act none of the four classes describes; it reads as unclassified "
        "rather than as complete, because guessing would be the one error that "
        "matters here"),
}


class WithholdingCost(str, Enum):
    """What it costs if nobody authorizes this at all.

    The axis `consequence` does not have. Every dimension there measures the harm
    of acting; this measures the harm of the engine's own default.
    """

    NONE = "NONE"                        # nothing happens, and nothing needed to
    DELAY_ONLY = "DELAY_ONLY"            # the act waits; the cost is the wait
    DEGRADES = "DEGRADES"                # something gets worse while this is held
    HARM_CONTINUES = "HARM_CONTINUES"    # the harm this act would stop goes on
    UNKNOWN = "UNKNOWN"                  # nobody established which way is worse

    @property
    def holding_is_the_safe_default(self) -> Optional[bool]:
        """Is HOLD the cautious answer here? `None` when nobody established it.

        Three-valued on purpose. `True` and `False` are both strong claims about a
        domain, and `UNKNOWN` — the commonest value — supports neither. Returning
        `True` by default would be exactly the assumption that makes a gate
        dangerous in an incident.
        """
        if self in (WithholdingCost.NONE, WithholdingCost.DELAY_ONLY):
            return True
        if self is WithholdingCost.HARM_CONTINUES:
            return False
        return None

    def describe(self) -> str:
        return _WITHHOLDING_NOTE[self]


_WITHHOLDING_NOTE: Mapping[WithholdingCost, str] = {
    WithholdingCost.NONE: "nothing is lost by not authorizing this",
    WithholdingCost.DELAY_ONLY: (
        "the act waits and the cost is the waiting, which is what a gate is for"),
    WithholdingCost.DEGRADES: (
        "something gets worse while this is held, so holding is not free and is not "
        "obviously wrong either"),
    WithholdingCost.HARM_CONTINUES: (
        "the harm this act exists to stop continues while it is held, so HOLD is "
        "the dangerous answer and a reviewer must be told that in those words"),
    WithholdingCost.UNKNOWN: (
        "nobody established what not acting costs, so which direction is safer was "
        "not assessed — not that holding is safe"),
}


# ── one act a domain declares ────────────────────────────────────────────────

@dataclass(frozen=True)
class DomainAct:
    """An act in a domain's own words, classified in the core's.

    `act_id` is namespaced under the domain, so two domains cannot collide and
    neither can shadow the other — the rule `plugin.VocabularyTerm` already applies
    to claim and verification types, applied here for the same reason.
    """

    act_id: str
    act_class: ActClass
    description: str = ""
    #: Authority names the domain supplies. Empty is legitimate and means anybody
    #: whom the deployment lets approve may approve this — which is a statement,
    #: and `requires_domain_expertise` is how a reader sees which it is.
    required_authority: Tuple[str, ...] = ()
    withholding: WithholdingCost = WithholdingCost.UNKNOWN
    #: For `REFER`: the authority that decides next. Required, because "somebody
    #: else decides" with no somebody is a gap wearing a process's clothes.
    refers_to: str = ""
    declared_by: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "act_class", ActClass(self.act_class))
        object.__setattr__(self, "withholding", WithholdingCost(self.withholding))
        object.__setattr__(self, "required_authority",
                           tuple(a.strip() for a in self.required_authority
                                 if str(a).strip()))
        act_id = (self.act_id or "").strip()
        if not act_id:
            raise AuthorityError("an act needs an id so an approval can name what it authorized")
        if "." not in act_id or act_id.startswith(".") or act_id.endswith("."):
            raise AuthorityError(
                f"{act_id!r} must be namespaced as <domain>.<act> — "
                "'execute_payment' belongs to whoever declared it, and an "
                "un-namespaced act would let two domains mean different things by "
                "one name")
        object.__setattr__(self, "act_id", act_id)
        if self.act_class is ActClass.REFER and not self.refers_to.strip():
            raise AuthorityError(
                f"{act_id}: a REFER act must name the authority it defers to. This "
                "approval does not complete the authorization, and a record that "
                "did not say who completes it would read as though it did")
        if self.act_class is not ActClass.REFER and self.refers_to.strip():
            raise AuthorityError(
                f"{act_id}: refers_to is set on a {self.act_class.value} act, which "
                "completes its own authorization. Either it defers — classify it "
                "REFER — or it does not, and naming a further authority implies a "
                "step that is not there")

    @property
    def domain(self) -> str:
        return self.act_id.split(".", 1)[0]

    @property
    def completes_authorization(self) -> bool:
        return self.act_class.completes_authorization

    @property
    def requires_domain_expertise(self) -> bool:
        return bool(self.required_authority)

    @property
    def establishes_qualification(self) -> bool:
        """Unconditionally False.

        Naming `clinician` as a required authority records what the domain asks
        for. It does not make release-gate a licensing board, and nothing here ever
        establishes that a person holds a qualification (Invariant 11).
        """
        return False

    @property
    def authorization_note(self) -> str:
        if self.act_class.defers:
            return (f"an approval of {self.act_id} authorizes putting the question to "
                    f"{self.refers_to}, and nothing more. {self.refers_to} decides "
                    "what happens next")
        if self.act_class is ActClass.OTHER:
            return (f"{self.act_id} is unclassified, so whether an approval of it "
                    "completes the authorization was never established")
        return (f"an approval of {self.act_id} is the authorization: "
                f"{self.act_class.describe()}")

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "domain_act", "record_id": self.act_id,
                "act_id": self.act_id, "domain": self.domain,
                "act_class": self.act_class.value,
                "description": self.description,
                "required_authority": list(self.required_authority),
                "requires_domain_expertise": self.requires_domain_expertise,
                "withholding": self.withholding.value,
                "holding_is_the_safe_default": self.withholding.holding_is_the_safe_default,
                "refers_to": self.refers_to,
                "completes_authorization": self.completes_authorization,
                "establishes_qualification": False,
                "declared_by": self.declared_by,
                "schema_version": AUTHORITY_SCHEMA_VERSION}


# ── who claims the standing ──────────────────────────────────────────────────

class AuthorityBasis(str, Enum):
    """On whose word this person holds the authority they claim.

    Graded, and none of the grades is a verified qualification. The strongest thing
    release-gate normally sees is an identity provider's assertion about a role,
    which is somebody else's claim carefully transported (§10z).
    """

    DECLARED = "DECLARED"                # the approver said so
    ATTRIBUTED = "ATTRIBUTED"            # an identity provider named the role
    VETTED = "VETTED"                    # the organisation's own registry says so (§10ar)
    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # nobody said

    @property
    def rests_on_a_third_party(self) -> bool:
        return self in (AuthorityBasis.ATTRIBUTED, AuthorityBasis.VETTED)

    def describe(self) -> str:
        return _BASIS_NOTE[self]


_BASIS_NOTE: Mapping[AuthorityBasis, str] = {
    AuthorityBasis.DECLARED: (
        "the approver stated the role themselves, which is a claim and is recorded "
        "as one"),
    AuthorityBasis.ATTRIBUTED: (
        "an identity provider named the role; somebody else's assertion, carefully "
        "transported, and the strongest thing release-gate normally sees"),
    AuthorityBasis.VETTED: (
        "the organisation's own vetting registry records this reviewer as one it "
        "relies on — an explicit decision by a named decider, and still not a "
        "licence"),
    AuthorityBasis.NOT_ESTABLISHED: (
        "nobody recorded that this person holds the authority the act requires"),
}


@dataclass(frozen=True)
class AuthorityClaim:
    """Somebody claiming to hold an authority an act requires, and on whose word."""

    authority: str
    held_by: str
    basis: AuthorityBasis = AuthorityBasis.DECLARED
    attributed_by: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "basis", AuthorityBasis(self.basis))
        if not str(self.authority or "").strip():
            raise AuthorityError("an authority claim must name the authority claimed")
        if not str(self.held_by or "").strip():
            raise AuthorityError(
                f"{self.authority}: a claim must name who holds it; an authority with "
                "nobody behind it cannot be weighed or asked about")
        object.__setattr__(self, "authority", self.authority.strip())
        if (self.basis.rests_on_a_third_party
                and not str(self.attributed_by or "").strip()):
            raise AuthorityError(
                f"{self.authority}: basis {self.basis.value} means somebody else "
                "vouched for this role, so that somebody must be named. An "
                "unattributed attribution is a declaration with better wording")

    @property
    def is_a_verified_qualification(self) -> bool:
        """Unconditionally False, at every basis.

        `VETTED` is the strongest value and it means an organisation decided to
        rely on this reviewer. That is a decision, not a credential check.
        """
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "authority_claim",
                "record_id": f"{self.authority}:{self.held_by}",
                "authority": self.authority, "held_by": self.held_by,
                "basis": self.basis.value, "attributed_by": self.attributed_by,
                "rests_on_a_third_party": self.basis.rests_on_a_third_party,
                "is_a_verified_qualification": False,
                "note": self.note,
                "schema_version": AUTHORITY_SCHEMA_VERSION}


class AuthorityFinding(str, Enum):
    """Whether one required authority was claimed, and how well."""

    NOT_REQUIRED = "NOT_REQUIRED"        # the act asks for none
    ATTRIBUTED = "ATTRIBUTED"            # claimed, and a third party vouched
    CLAIMED_ONLY = "CLAIMED_ONLY"        # claimed by the person themselves
    ABSENT = "ABSENT"                    # required and nobody claimed it

    @property
    def satisfied(self) -> bool:
        """Whether the act's ask was answered at all. Never whether it was verified."""
        return self in (AuthorityFinding.NOT_REQUIRED, AuthorityFinding.ATTRIBUTED,
                        AuthorityFinding.CLAIMED_ONLY)


# ── the reading ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuthorityReading:
    """What an approval of this act would and would not authorize.

    Named a reading rather than a decision. `override.Authorization` is what a
    verdict, an approval and an override come to together; this is the narrower
    question of whether the act was named, whether the standing it asks for was
    claimed, and whether an approval of it finishes anything.
    """

    act: DomainAct
    claims: Tuple[AuthorityClaim, ...] = ()
    findings: Mapping[str, AuthorityFinding] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "claims", tuple(self.claims))
        object.__setattr__(self, "findings", dict(self.findings))

    @property
    def authority_satisfied(self) -> bool:
        """Every authority the act requires was claimed by somebody.

        Deliberately not called `authorized`. It says the asks were answered, and
        the basis of each answer is a separate field a reader must look at.
        """
        return all(f.satisfied for f in self.findings.values())

    @property
    def absent(self) -> Tuple[str, ...]:
        return tuple(sorted(a for a, f in self.findings.items()
                            if f is AuthorityFinding.ABSENT))

    @property
    def claimed_only(self) -> Tuple[str, ...]:
        return tuple(sorted(a for a, f in self.findings.items()
                            if f is AuthorityFinding.CLAIMED_ONLY))

    @property
    def completes_authorization(self) -> bool:
        return self.act.completes_authorization

    @property
    def verifies_credentials(self) -> bool:
        """Unconditionally False. Release-gate is not a licensing board."""
        return False

    @property
    def holding_is_the_safe_default(self) -> Optional[bool]:
        return self.act.withholding.holding_is_the_safe_default

    def expectations(self) -> Tuple[EvidenceExpectation, ...]:
        """Missing and self-declared authority, and an unsafe default, as coverage rows.

        Coverage rather than a verdict, for the reason the last four sections give:
        whether a missing authority should hold a case is a methodology decision.
        What the core owes a reviewer is that the gap appears beside every other
        gap (Invariants 3, 9).
        """
        rows: List[EvidenceExpectation] = []
        if self.absent:
            rows.append(EvidenceExpectation(
                dimension=f"authority.{self.act.act_id}", assessed=False,
                observed_from=f"act {self.act.act_id} declared by "
                              f"{self.act.declared_by or 'an unnamed party'}",
                note=(f"this act requires {', '.join(self.absent)} and nobody claimed "
                      f"{'it' if len(self.absent) == 1 else 'them'}. Whether an "
                      "authorized person is behind this was not established")))
        if self.claimed_only:
            rows.append(EvidenceExpectation(
                dimension=f"authority.self_declared.{self.act.act_id}", assessed=False,
                observed_from=f"act {self.act.act_id}",
                note=(f"{', '.join(self.claimed_only)} was claimed by the person "
                      "holding it and nobody else vouched for the role. Release-gate "
                      "verifies no qualification at any basis")))
        if self.act.withholding is WithholdingCost.HARM_CONTINUES:
            rows.append(EvidenceExpectation(
                dimension=f"authority.withholding.{self.act.act_id}", assessed=False,
                observed_from=f"act {self.act.act_id}",
                note=("HOLD is the dangerous answer for this act: "
                      f"{self.act.withholding.describe()}. Release-gate's default is "
                      "not the cautious direction here and cannot make it so")))
        return tuple(rows)

    def render(self) -> str:
        lines = ["AUTHORIZATION",
                 f"  act: {self.act.act_id} [{self.act.act_class.value}]"]
        if self.act.description:
            lines.append(f"       {self.act.description}")
        lines.append(f"  {self.act.authorization_note}")
        lines.append("")
        if not self.findings:
            lines.append("  this act requires no named authority")
        for authority in sorted(self.findings):
            finding = self.findings[authority]
            claim = next((c for c in self.claims if c.authority == authority), None)
            who = f" — {claim.held_by}" if claim else ""
            basis = f" ({claim.basis.value})" if claim else ""
            lines.append(f"    {finding.value:14s} {authority}{who}{basis}")
        lines.append("")
        # `holding_is_the_safe_default` is None for two different reasons and they
        # must not share a sentence: DEGRADES was assessed and landed in between,
        # UNKNOWN means nobody looked. Reporting the first as the second would be
        # the same conflation between "we weighed it" and "nobody weighed it" that
        # the coverage model exists to prevent.
        if self.act.withholding is WithholdingCost.UNKNOWN:
            lines.append("  withholding cost: not assessed, so which direction is")
            lines.append("  safer was never established")
        elif self.holding_is_the_safe_default is False:
            lines.append("  WITHHOLDING: " + self.act.withholding.describe())
        elif self.holding_is_the_safe_default is None:
            lines.append("  withholding cost: " + self.act.withholding.describe())
        lines.append("")
        lines.append("  This records which authority the domain asked for and who")
        lines.append("  claimed it. No basis here verifies a qualification.")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "authority_reading",
                "record_id": short_id("auth", digest_object(
                    {"act": self.act.act_id,
                     "findings": {k: v.value for k, v in self.findings.items()}})),
                "act": self.act.to_dict(),
                "claims": [c.to_dict() for c in self.claims],
                "findings": {k: v.value for k, v in self.findings.items()},
                "authority_satisfied": self.authority_satisfied,
                "absent": list(self.absent),
                "claimed_only": list(self.claimed_only),
                "completes_authorization": self.completes_authorization,
                "holding_is_the_safe_default": self.holding_is_the_safe_default,
                "verifies_credentials": False,
                "schema_version": AUTHORITY_SCHEMA_VERSION}


def read_authority(act: DomainAct,
                   claims: Sequence[AuthorityClaim] = ()) -> AuthorityReading:
    """Hold an act's authority requirements against what was claimed.

    A claim naming an authority the act does not require is kept rather than
    dropped: somebody thought it was relevant, and silently discarding it would
    lose the only trace of that. It simply satisfies nothing.
    """
    claims = tuple(claims)
    findings: Dict[str, AuthorityFinding] = {}
    for authority in act.required_authority:
        held = [c for c in claims if c.authority.lower() == authority.lower()]
        if not held:
            findings[authority] = AuthorityFinding.ABSENT
        elif any(c.basis.rests_on_a_third_party for c in held):
            findings[authority] = AuthorityFinding.ATTRIBUTED
        elif any(c.basis is AuthorityBasis.DECLARED for c in held):
            findings[authority] = AuthorityFinding.CLAIMED_ONLY
        else:
            findings[authority] = AuthorityFinding.ABSENT
    return AuthorityReading(act=act, claims=claims, findings=findings)


# ── the registry a domain fills ──────────────────────────────────────────────

class ActRegistry:
    """The acts a deployment's domains declared. Empty until they do.

    Empty for §10ar's reason: `ActClass` is structure and release-gate can state
    it, while what a payment is belongs to whoever executes payments. A shipped
    `finance.execute_payment` would be this engine deciding that, in a package that
    has no business knowing.
    """

    def __init__(self) -> None:
        self._acts: Dict[str, DomainAct] = {}

    @property
    def ships_domain_acts(self) -> bool:
        """Unconditionally False. Every act here was declared by somebody else."""
        return False

    def __len__(self) -> int:
        return len(self._acts)

    def __bool__(self) -> bool:
        return bool(self._acts)

    def __iter__(self):
        return iter(tuple(self._acts[k] for k in sorted(self._acts)))

    def register(self, act: DomainAct) -> "ActRegistry":
        if not isinstance(act, DomainAct):
            raise AuthorityError("only a DomainAct can be registered")
        if act.act_id in self._acts:
            raise AuthorityError(
                f"{act.act_id} is already declared; a second definition would make "
                "what an approval authorized depend on registration order")
        self._acts[act.act_id] = act
        return self

    def of(self, act_id: str) -> Optional[DomainAct]:
        return self._acts.get((act_id or "").strip())

    def for_domain(self, domain: str) -> Tuple[DomainAct, ...]:
        wanted = (domain or "").strip().lower()
        return tuple(a for a in self if a.domain == wanted)

    @property
    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted({a.domain for a in self}))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "act_registry",
                "record_id": short_id("acts", digest_object(
                    [a.to_dict() for a in self])),
                "count": len(self._acts), "domains": list(self.domains),
                "acts": [a.to_dict() for a in self],
                "ships_domain_acts": False,
                "schema_version": AUTHORITY_SCHEMA_VERSION}


def empty_act_registry() -> ActRegistry:
    """An act registry with nothing in it, which is the only kind this package ships."""
    return ActRegistry()


__all__ = [
    "AUTHORITY_SCHEMA_VERSION",
    "ActClass",
    "ActRegistry",
    "AuthorityBasis",
    "AuthorityClaim",
    "AuthorityError",
    "AuthorityFinding",
    "AuthorityReading",
    "DomainAct",
    "WithholdingCost",
    "empty_act_registry",
    "read_authority",
]
