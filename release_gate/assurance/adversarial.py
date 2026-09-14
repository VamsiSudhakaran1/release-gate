"""Adversarial verification — verifiers whose job is to make the candidate fail.

A counterexample agent, a red team, a proof critic, a security adversary, a
falsification agent, an independent tester: all of them do the same structural
thing, which is to try to break the candidate rather than to confirm it. That
stance is the whole content, because evidence from a party trying to fail you is
worth something evidence from a party trying to agree with you is not.

**Release-Gate never requires them.** Most decisions have no adversary and are
not worse for it. A case with none reports `NOT_ASSESSED`, not a penalty; only a
methodology that says this class of decision needs adversarial review can turn
their absence into a verdict, through `AdversarialReviewRequired`.

Four things this module exists to get right.

**Breaking the argument is not breaking the claim.** A proof critic who finds
that step 7 does not follow has not shown the theorem false — they have shown the
proof does not establish it. `ARGUMENT_DEFECT` and `CANDIDATE_REFUTED` are
therefore separate outcomes. Collapsing them one way would call true claims
false; collapsing them the other would let broken support read as clean.

**An adversary that shares origin with the candidate is not an adversary.** A red
team running the same model, from the same prompt lineage, staffed by the team
that built the thing, will systematically miss what the builders missed. Stance
is derived — from who produced the candidate's support and from declared
lineage — never accepted as a claim, and an unrecorded stance is `UNDETERMINED`
rather than independent (Invariants 1 and 3).

**A finding closed by the party it was against is not closed.** The oldest
failure in assurance is the team that wrote the code resolving the red-team
ticket with "not exploitable". `self_cleared` is computed, and a self-cleared
finding reaches Human Attention whatever its recorded status.

**Accepting a risk is not resolving it.** `ACCEPTED_RISK` is a distinct status
and counts as open for attention. Someone deciding to ship a known weakness is
exercising authority, and the person authorizing the release is exactly who needs
to see it — approval is authorization, not truth certification (Invariant 15).

What an adversary that found nothing establishes is bounded by the search and
nothing more. That refusal is not re-implemented here: a refutation converts to
`CounterexampleAttempt`, whose `proves_absence` is `False` unconditionally and
whose route to `Contradiction` and `render_verdict` already exists. One
enforcement path, not two that drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Tuple)

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.counterexample import (
    CounterexampleAttempt, CounterexampleResult, CounterexampleStatus)
from release_gate.assurance.evidence import VerificationMethod

__all__ = [
    "ADVERSARIAL_SCHEMA_VERSION",
    "AdversarialError",
    "AdversarialFinding",
    "AdversarialOutcome",
    "AdversarialReview",
    "AdversarialRole",
    "AdversarialStance",
    "AdversarialStatus",
    "analyse_adversarial",
]

ADVERSARIAL_SCHEMA_VERSION = 1


class AdversarialError(ValueError):
    """A finding was recorded in a state that would misreport what it found."""


class AdversarialRole(str, Enum):
    """What kind of adversary this is. Selects the default method, nothing else.

    Role never affects weight, status, or how seriously a finding is taken. A
    security adversary's finding and an independent tester's finding are the same
    kind of fact; what differs is what each searched.
    """

    COUNTEREXAMPLE_AGENT = "COUNTEREXAMPLE_AGENT"
    RED_TEAM = "RED_TEAM"
    PROOF_CRITIC = "PROOF_CRITIC"
    SECURITY_ADVERSARY = "SECURITY_ADVERSARY"
    FALSIFICATION_AGENT = "FALSIFICATION_AGENT"
    INDEPENDENT_TESTER = "INDEPENDENT_TESTER"
    REVIEW_CRITIC = "REVIEW_CRITIC"
    OTHER = "OTHER"


_ROLE_METHOD: Mapping[AdversarialRole, VerificationMethod] = {
    AdversarialRole.COUNTEREXAMPLE_AGENT: VerificationMethod.PROPERTY_TEST,
    AdversarialRole.RED_TEAM: VerificationMethod.EXPERIMENT,
    AdversarialRole.PROOF_CRITIC: VerificationMethod.HUMAN_REVIEW,
    AdversarialRole.SECURITY_ADVERSARY: VerificationMethod.EXPERIMENT,
    AdversarialRole.FALSIFICATION_AGENT: VerificationMethod.PROPERTY_TEST,
    AdversarialRole.INDEPENDENT_TESTER: VerificationMethod.TEST_SUITE,
    AdversarialRole.REVIEW_CRITIC: VerificationMethod.CROSS_MODEL_REVIEW,
    AdversarialRole.OTHER: VerificationMethod.OTHER,
}

#: What each role's empty result does *not* establish. Stated once so no adversary
#: has to be trusted to say it, and so "the red team found nothing" never reads as
#: "there is nothing to find".
_ROLE_LIMIT: Mapping[AdversarialRole, str] = {
    AdversarialRole.COUNTEREXAMPLE_AGENT:
        "inputs the generator did not produce",
    AdversarialRole.RED_TEAM:
        "attacks this team did not think of, and capabilities they could not reach",
    AdversarialRole.PROOF_CRITIC:
        "errors the critic did not recognise as errors",
    AdversarialRole.SECURITY_ADVERSARY:
        "classes of attack outside this engagement's scope",
    AdversarialRole.FALSIFICATION_AGENT:
        "falsifiers outside the space actually searched",
    AdversarialRole.INDEPENDENT_TESTER:
        "behaviour the tests do not exercise",
    AdversarialRole.REVIEW_CRITIC:
        "anything the reviewer did not look at",
    AdversarialRole.OTHER:
        "nothing is recorded about what this search covered",
}


class AdversarialOutcome(str, Enum):
    """What the attack came back with.

    `CANDIDATE_REFUTED` and `ARGUMENT_DEFECT` are the load-bearing distinction: a
    broken proof of a true theorem is a real finding about the support and not a
    finding about the conclusion.
    """

    CANDIDATE_REFUTED = "CANDIDATE_REFUTED"  # the claim as stated is false
    ARGUMENT_DEFECT = "ARGUMENT_DEFECT"      # the support does not establish it
    WEAKNESS_FOUND = "WEAKNESS_FOUND"        # a concern that does neither
    NO_FINDING = "NO_FINDING"                # this attack found nothing; see the limit
    INCONCLUSIVE = "INCONCLUSIVE"            # the attack did not complete
    NOT_RUN = "NOT_RUN"                      # an adversary was expected and never ran


#: Outcomes that put something on the table. NO_FINDING is deliberately absent:
#: an attack that came back empty has produced no finding to stand or be answered.
_SUBSTANTIVE = frozenset({AdversarialOutcome.CANDIDATE_REFUTED,
                          AdversarialOutcome.ARGUMENT_DEFECT,
                          AdversarialOutcome.WEAKNESS_FOUND})


class AdversarialStatus(str, Enum):
    """Where a finding now stands."""

    OPEN = "OPEN"                      # stands, unanswered
    ADDRESSED = "ADDRESSED"            # answered, and the answer cites evidence
    ACCEPTED_RISK = "ACCEPTED_RISK"    # acknowledged, not fixed, someone chose to proceed
    SUPERSEDED = "SUPERSEDED"          # what it was about moved on
    INVALID = "INVALID"                # not a real finding, and someone said why
    UNKNOWN = "UNKNOWN"                # whether it stands cannot be determined
    NOT_APPLICABLE = "NOT_APPLICABLE"  # nothing was found, so nothing to answer


#: ACCEPTED_RISK is open. Someone deciding to ship a known weakness has not
#: answered it, and the person authorizing the release is precisely who must see
#: it (Invariant 15). UNKNOWN is open for the usual reason: "we cannot tell
#: whether this still stands" is not a closed finding.
_OPEN_STATUSES = frozenset({AdversarialStatus.OPEN, AdversarialStatus.UNKNOWN,
                            AdversarialStatus.ACCEPTED_RISK})
_CLOSED_STATUSES = frozenset({AdversarialStatus.ADDRESSED,
                              AdversarialStatus.SUPERSEDED,
                              AdversarialStatus.INVALID})


class AdversarialStance(str, Enum):
    """How independent the adversary is of what it attacked.

    Derived, never declared. An adversary that says it is independent has said
    something about itself; where its evidence and lineage came from is a fact
    about the world.
    """

    INDEPENDENT = "INDEPENDENT"      # disjoint producers and disjoint lineage, both recorded
    SHARED_ORIGIN = "SHARED_ORIGIN"  # shares a lineage with what it attacked
    SELF_REVIEW = "SELF_REVIEW"      # the adversary produced the candidate's own support
    UNDETERMINED = "UNDETERMINED"    # not enough recorded to tell


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── one finding ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AdversarialFinding:
    """One attempt to make the candidate fail, and what came of it."""

    target_claim: str
    role: AdversarialRole = AdversarialRole.OTHER
    adversary: str = ""
    method: Optional[VerificationMethod] = None
    outcome: AdversarialOutcome = AdversarialOutcome.NOT_RUN
    status: AdversarialStatus = AdversarialStatus.UNKNOWN
    evidence: Tuple[str, ...] = ()
    independence_lineage: Tuple[str, ...] = ()
    attacked: str = ""             # what space this attack actually covered
    resolution: str = ""
    resolution_evidence: Tuple[str, ...] = ()
    resolved_by: str = ""
    accepted_by: str = ""          # who chose to proceed, for ACCEPTED_RISK
    detail: str = ""
    attempted_at: str = field(default_factory=_utc_now)
    schema_version: int = ADVERSARIAL_SCHEMA_VERSION

    finding_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", AdversarialRole(self.role))
        object.__setattr__(self, "outcome", AdversarialOutcome(self.outcome))
        object.__setattr__(self, "status", AdversarialStatus(self.status))
        object.__setattr__(self, "method",
                           VerificationMethod(self.method) if self.method
                           else _ROLE_METHOD[self.role])
        for name in ("evidence", "resolution_evidence"):
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        object.__setattr__(self, "independence_lineage",
                           tuple(sorted(set(self.independence_lineage))))

        if not (self.target_claim or "").strip():
            raise AdversarialError(
                "target_claim is required: an attack on nothing cannot be weighed, "
                "surfaced, or answered")
        object.__setattr__(self, "target_claim", self.target_claim.strip())

        if self.outcome in _SUBSTANTIVE:
            if self.status is AdversarialStatus.NOT_APPLICABLE:
                raise AdversarialError(
                    f"a {self.outcome.value} finding always has something to answer; "
                    "NOT_APPLICABLE would file a live finding as nothing to do")
            if not (self.adversary or "").strip():
                raise AdversarialError(
                    "a finding must name the adversary that produced it — an attack "
                    "nobody is answerable for cannot be weighed (Invariant 11)")
        elif self.status in (AdversarialStatus.OPEN, AdversarialStatus.ADDRESSED,
                             AdversarialStatus.ACCEPTED_RISK):
            raise AdversarialError(
                f"outcome {self.outcome.value} has nothing to be {self.status.value} "
                "about; an attack that found nothing is NOT_APPLICABLE, which is a "
                "different fact from having found something and dealt with it")

        if self.status is AdversarialStatus.ADDRESSED:
            if not self.resolution.strip():
                raise AdversarialError(
                    "an ADDRESSED finding must state what answered it")
            if not self.resolution_evidence:
                raise AdversarialError(
                    "an ADDRESSED finding must cite resolution_evidence; an attack is "
                    "answered by evidence, never by assertion that it was answered")
        if self.status is AdversarialStatus.ACCEPTED_RISK:
            if not self.resolution.strip():
                raise AdversarialError(
                    "an ACCEPTED_RISK finding must state the basis for accepting it; "
                    "an unexplained acceptance is indistinguishable from ignoring it")
            if not (self.accepted_by or "").strip():
                raise AdversarialError(
                    "an ACCEPTED_RISK finding must name who accepted it: proceeding "
                    "with a known weakness is an act of authority and somebody has to "
                    "be answerable for it (Invariant 15)")
        if self.status in (AdversarialStatus.INVALID, AdversarialStatus.SUPERSEDED) \
                and not self.resolution.strip():
            raise AdversarialError(
                f"a {self.status.value} finding must say why; dismissing an "
                "adversarial finding is a claim somebody has to be answerable for")

        object.__setattr__(self, "finding_id",
                           short_id("adv", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct attack — never how it was later handled."""
        return {"schema_version": ADVERSARIAL_SCHEMA_VERSION,
                "target_claim": self.target_claim, "role": self.role.value,
                "adversary": self.adversary, "method": self.method.value,
                "outcome": self.outcome.value, "evidence": list(self.evidence),
                "lineage": list(self.independence_lineage),
                "attacked": self.attacked, "attempted_at": self.attempted_at}

    # ── standing ────────────────────────────────────────────────────────────

    @property
    def found_something(self) -> bool:
        return self.outcome in _SUBSTANTIVE

    @property
    def refutes(self) -> bool:
        """Only a refutation refutes. A broken argument is not a false claim."""
        return self.outcome is AdversarialOutcome.CANDIDATE_REFUTED

    @property
    def is_open(self) -> bool:
        return self.found_something and self.status in _OPEN_STATUSES

    @property
    def addressed(self) -> bool:
        return self.status in _CLOSED_STATUSES

    @property
    def accepted(self) -> bool:
        return self.status is AdversarialStatus.ACCEPTED_RISK

    @property
    def proves_absence(self) -> bool:
        """Always False. Not a computation — a refusal.

        An adversary that found nothing bounds its own search. No role, no
        thoroughness anyone declares, and no number of empty attacks changes
        that — and where several adversaries share a lineage, the independence
        analysis will show they were one attack anyway.
        """
        return False

    @property
    def search_bound(self) -> str:
        """What was actually attacked, and what an empty result cannot cover."""
        covered = self.attacked.strip() or "the extent of this attack was not recorded"
        return f"{covered}; does not cover {_ROLE_LIMIT[self.role]}"

    def stance(self, candidate_producers: Iterable[str] = (),
               candidate_lineage: Iterable[str] = ()) -> AdversarialStance:
        """How independent this adversary is of what it attacked.

        `UNDETERMINED` whenever nothing on either side could establish it. Silence
        is never independence: the cheapest way to look adversarial is to record
        nothing about where you came from.
        """
        producers = {p for p in candidate_producers if p}
        lineage = {x for x in candidate_lineage if x}
        if self.adversary and self.adversary in producers:
            return AdversarialStance.SELF_REVIEW
        if self.independence_lineage and lineage:
            if set(self.independence_lineage) & lineage:
                return AdversarialStance.SHARED_ORIGIN
            if producers and self.adversary:
                return AdversarialStance.INDEPENDENT
        return AdversarialStance.UNDETERMINED

    def self_cleared(self, candidate_producers: Iterable[str] = ()) -> bool:
        """Was this closed by the party it was against?

        Derived from who produced the candidate's support, not from anything the
        resolver said about themselves.
        """
        if not self.addressed and not self.accepted:
            return False
        closer = (self.resolved_by or self.accepted_by or "").strip()
        return bool(closer) and closer in {p for p in candidate_producers if p}

    # ── transitions ─────────────────────────────────────────────────────────

    def address(self, resolution: str, evidence: Iterable[str], *,
                by: str = "") -> "AdversarialFinding":
        import dataclasses
        return dataclasses.replace(self, status=AdversarialStatus.ADDRESSED,
                                   resolution=resolution,
                                   resolution_evidence=tuple(evidence),
                                   resolved_by=by)

    def accept_risk(self, basis: str, *, by: str) -> "AdversarialFinding":
        """Record that someone chose to proceed. Never a resolution."""
        import dataclasses
        return dataclasses.replace(self, status=AdversarialStatus.ACCEPTED_RISK,
                                   resolution=basis, accepted_by=by)

    def invalidate(self, reason: str) -> "AdversarialFinding":
        import dataclasses
        return dataclasses.replace(self, status=AdversarialStatus.INVALID,
                                   resolution=reason)

    # ── conversion ──────────────────────────────────────────────────────────

    def to_counterexample(self) -> Optional[CounterexampleAttempt]:
        """A refutation, as the record the existing enforcement path already reads.

        Only `CANDIDATE_REFUTED` converts. An argument defect is not a
        counterexample and filing it as one would assert a claim is false when
        what was shown is that its support does not establish it.

        `ACCEPTED_RISK` maps to an *open* counterexample, not a resolved one:
        `CounterexampleStatus` has no way to say "acknowledged and shipped
        anyway", and RESOLVED would be the erasure this module exists to prevent.
        """
        if not self.refutes:
            return None
        if self.status is AdversarialStatus.ADDRESSED:
            status = CounterexampleStatus.RESOLVED
        elif self.status in (AdversarialStatus.SUPERSEDED, AdversarialStatus.INVALID):
            status = CounterexampleStatus(self.status.value)
        else:
            status = CounterexampleStatus.OPEN
        return CounterexampleAttempt(
            target_claim=self.target_claim, producer=self.adversary,
            method=self.method, result=CounterexampleResult.FOUND,
            evidence=self.evidence, resolution=self.resolution,
            resolution_evidence=self.resolution_evidence, status=status,
            searched=self.attacked,
            detail=f"{self.role.value}: {self.detail}".strip(": "),
            attempted_at=self.attempted_at)

    # ── serialisation ───────────────────────────────────────────────────────

    @property
    def record_type(self) -> str:
        return "adversarial"

    @property
    def record_id(self) -> str:
        return self.finding_id

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "adversarial", "record_id": self.finding_id,
                "target_claim": self.target_claim, "role": self.role.value,
                "adversary": self.adversary, "method": self.method.value,
                "outcome": self.outcome.value, "status": self.status.value,
                "open": self.is_open, "accepted": self.accepted,
                "refutes": self.refutes, "proves_absence": False,
                "evidence": list(self.evidence),
                "independence_lineage": list(self.independence_lineage),
                "attacked": self.attacked, "search_bound": self.search_bound,
                "resolution": self.resolution,
                "resolution_evidence": list(self.resolution_evidence),
                "resolved_by": self.resolved_by, "accepted_by": self.accepted_by,
                "detail": self.detail, "attempted_at": self.attempted_at,
                "schema_version": ADVERSARIAL_SCHEMA_VERSION}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdversarialFinding":
        return cls(
            target_claim=str(data.get("target_claim") or ""),
            role=AdversarialRole(str(data.get("role") or "OTHER").upper()),
            adversary=str(data.get("adversary") or ""),
            method=(VerificationMethod(str(data["method"]).upper())
                    if data.get("method") else None),
            outcome=AdversarialOutcome(str(data.get("outcome") or "NOT_RUN").upper()),
            status=AdversarialStatus(str(data.get("status") or "UNKNOWN").upper()),
            evidence=tuple(data.get("evidence") or ()),
            independence_lineage=tuple(data.get("independence_lineage") or ()),
            attacked=str(data.get("attacked") or ""),
            resolution=str(data.get("resolution") or ""),
            resolution_evidence=tuple(data.get("resolution_evidence") or ()),
            resolved_by=str(data.get("resolved_by") or ""),
            accepted_by=str(data.get("accepted_by") or ""),
            detail=str(data.get("detail") or ""),
            attempted_at=str(data.get("attempted_at") or _utc_now()))

    @classmethod
    def nothing_found(cls, target_claim: str, *, adversary: str,
                      role: AdversarialRole, attacked: str = "",
                      **kwargs: Any) -> "AdversarialFinding":
        """An attack that came back empty. Recorded, and credited with nothing."""
        return cls(target_claim=target_claim, adversary=adversary, role=role,
                   outcome=AdversarialOutcome.NO_FINDING,
                   status=AdversarialStatus.NOT_APPLICABLE, attacked=attacked,
                   **kwargs)

    def render(self) -> str:
        if not self.found_something:
            return (f"{self.role.value} {self.adversary or 'unnamed'} attacked "
                    f"{self.target_claim} and reported {self.outcome.value}. "
                    f"Covers {self.search_bound}.")
        return (f"{self.role.value} {self.adversary} found "
                f"{self.outcome.value} against {self.target_claim} "
                f"[{self.status.value}]. {self.detail}".strip())


# ── the review ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AdversarialReview:
    """Every adversarial attack on a case, and what each amounts to."""

    findings: Tuple[AdversarialFinding, ...] = ()
    stances: Mapping[str, AdversarialStance] = field(default_factory=dict)
    self_cleared_ids: Tuple[str, ...] = ()
    claims_attacked: Tuple[str, ...] = ()
    adversaries: Tuple[str, ...] = ()
    basis: str = ""

    def __iter__(self):
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def present(self) -> bool:
        """Whether any adversary attacked anything. False is not a failure."""
        return bool(self.findings)

    def open(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings if f.is_open)

    def refutations(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings if f.refutes)

    def argument_defects(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings
                     if f.outcome is AdversarialOutcome.ARGUMENT_DEFECT)

    def accepted_risks(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings if f.accepted)

    def self_cleared(self) -> Tuple[AdversarialFinding, ...]:
        held = set(self.self_cleared_ids)
        return tuple(f for f in self.findings if f.finding_id in held)

    def empty_searches(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings
                     if f.outcome is AdversarialOutcome.NO_FINDING)

    def unbounded_searches(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.empty_searches() if not f.attacked.strip())

    def independent(self) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings
                     if self.stances.get(f.finding_id) is AdversarialStance.INDEPENDENT)

    def non_independent(self) -> Tuple[AdversarialFinding, ...]:
        """Adversaries shown to share origin with what they attacked.

        `UNDETERMINED` is deliberately not in here: not knowing is not the same as
        knowing they are related, and reporting it as such would be as wrong as
        the credit it refuses.
        """
        related = (AdversarialStance.SELF_REVIEW, AdversarialStance.SHARED_ORIGIN)
        return tuple(f for f in self.findings
                     if self.stances.get(f.finding_id) in related)

    def for_claim(self, claim_id: str) -> Tuple[AdversarialFinding, ...]:
        return tuple(f for f in self.findings if f.target_claim == claim_id)

    def unattacked(self, claims: Iterable[str]) -> Tuple[str, ...]:
        """Which of these claims no adversary went after. Reported, never charged."""
        attacked = set(self.claims_attacked)
        return tuple(sorted({c for c in claims if c and c not in attacked}))

    @property
    def proves_absence(self) -> bool:
        """Always False, at the set level too, for the same reason."""
        return False

    def to_counterexamples(self) -> Tuple[CounterexampleAttempt, ...]:
        """Refutations, as the records the existing counterexample path reads."""
        out = []
        for finding in self.findings:
            converted = finding.to_counterexample()
            if converted is not None:
                out.append(converted)
        return tuple(out)

    def digest(self) -> str:
        return digest_object({"findings": [f.to_dict() for f in self.findings],
                              "stances": {k: v.value for k, v in self.stances.items()},
                              "schema_version": ADVERSARIAL_SCHEMA_VERSION})

    @property
    def record_type(self) -> str:
        return "adversarial_review"

    @property
    def record_id(self) -> str:
        return short_id("advrev", self.digest())

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self.findings), "present": self.present,
                "adversaries": len(self.adversaries),
                "claims_attacked": len(self.claims_attacked),
                "open": len(self.open()), "refutations": len(self.refutations()),
                "argument_defects": len(self.argument_defects()),
                "accepted_risks": len(self.accepted_risks()),
                "self_cleared": len(self.self_cleared_ids),
                "empty_searches": len(self.empty_searches()),
                "unbounded_searches": len(self.unbounded_searches()),
                "independent": len(self.independent()),
                "non_independent": len(self.non_independent()),
                "by_outcome": {o.value: sum(1 for f in self.findings if f.outcome is o)
                               for o in AdversarialOutcome},
                "by_stance": {s.value: sum(1 for v in self.stances.values() if v is s)
                              for s in AdversarialStance},
                "proves_absence": False,
                "basis": self.basis}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "adversarial_review", "record_id": self.record_id,
                **self.summary(),
                "claims_attacked_ids": list(self.claims_attacked[:64]),
                "claims_attacked_truncated": max(0, len(self.claims_attacked) - 64),
                "findings": [f.to_dict() for f in self.findings[:32]],
                "findings_truncated": max(0, len(self.findings) - 32),
                "stances": {k: v.value for k, v in sorted(self.stances.items())},
                "schema_version": ADVERSARIAL_SCHEMA_VERSION}

    def render(self) -> str:
        if not self.findings:
            return ("No adversarial verification is recorded. That is not a finding "
                    "against this case — adversaries are never required.")
        lines = [f"{len(self.findings)} adversarial attack(s) by "
                 f"{len(self.adversaries)} adversary(ies) on "
                 f"{len(self.claims_attacked)} claim(s)"]
        if self.open():
            lines.append(f"  {len(self.open())} unresolved, of which "
                         f"{len(self.accepted_risks())} accepted as risk")
        if self.self_cleared_ids:
            lines.append(f"  {len(self.self_cleared_ids)} closed by the party they "
                         "were against")
        if self.non_independent():
            lines.append(f"  {len(self.non_independent())} produced by an adversary "
                         "sharing origin with what it attacked")
        if self.empty_searches():
            lines.append(f"  {len(self.empty_searches())} attack(s) found nothing, "
                         "which bounds the search and not the claim")
        return "\n".join(lines)


def analyse_adversarial(findings: Iterable[Any], *,
                        claim_producers: Optional[Mapping[str, Sequence[str]]] = None,
                        claim_lineage: Optional[Mapping[str, Sequence[str]]] = None
                        ) -> AdversarialReview:
    """Assemble the adversarial picture, deriving stance rather than accepting it.

    `claim_producers` maps each claim to the parties that produced its support,
    and `claim_lineage` to the lineage that support rests on. Both come from the
    case rather than from the adversaries, which is what makes self-review and
    self-clearing findable at all: an adversary will not tell you it is the
    builder, and the builder will not tell you it closed its own ticket.
    """
    held = [f for f in findings if isinstance(f, AdversarialFinding)]
    if not held:
        return AdversarialReview(
            basis="no adversarial verification is recorded; adversaries are never "
                  "required, so this is NOT_ASSESSED rather than a shortfall")

    held.sort(key=lambda f: (not f.is_open, not f.found_something, f.target_claim,
                             f.finding_id))
    producers = dict(claim_producers or {})
    lineage = dict(claim_lineage or {})

    stances: Dict[str, AdversarialStance] = {}
    self_cleared: List[str] = []
    for finding in held:
        candidate_producers = producers.get(finding.target_claim, ())
        stances[finding.finding_id] = finding.stance(
            candidate_producers, lineage.get(finding.target_claim, ()))
        if finding.self_cleared(candidate_producers):
            self_cleared.append(finding.finding_id)

    undetermined = sum(1 for s in stances.values()
                       if s is AdversarialStance.UNDETERMINED)
    basis = (f"{len(held)} attack(s) recorded; "
             f"{sum(1 for s in stances.values() if s is AdversarialStance.INDEPENDENT)} "
             f"from an adversary shown independent of what it attacked")
    if undetermined:
        basis += (f", {undetermined} where independence could not be derived from "
                  "what is recorded")

    return AdversarialReview(
        findings=tuple(held), stances=stances,
        self_cleared_ids=tuple(sorted(self_cleared)),
        claims_attacked=tuple(sorted({f.target_claim for f in held})),
        adversaries=tuple(sorted({f.adversary for f in held if f.adversary})),
        basis=basis)
