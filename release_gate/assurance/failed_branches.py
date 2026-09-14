"""Failed branches — what was tried and did not work, kept as structure not transcript.

A case that records only its successes looks exactly like its best branch. Five
hundred approaches that failed and one that worked reads, in the final report,
identically to one approach that worked first time — and those are very different
situations for whoever is signing (Invariant 7).

So failures are retained. But **not every token**: a frontier run produces
millions of dead ends, and hoarding transcripts would make the case unreadable
and unstorable while adding nothing a reviewer can act on. What is kept instead
is the *structure* of each failure — where it broke, what it violated, how far it
got — plus a reference to wherever the full record lives.

Two properties make that honest at scale.

**The aggregate is never sampled.** Retention drops *branches*; it never drops
*failure points*. If 7,992 proof attempts all died at lemma 48, the ledger says
so whether it kept three of those branches or none. Losing a branch costs a
reviewer an example; losing the count would cost them the finding.

**The policy is stated and its shortfall counted.** `MaterialisationBasis` is
reused rather than invented — the same vocabulary the case already uses for why a
collection holds what it holds — and `observed` versus `retained` is always
reported, so nobody reads a sampled ledger as a complete one.

The inline-detail cap is enforced rather than advised: a branch whose detail
exceeds it is refused, with a message pointing at the content reference. A rule
that is only documented is a rule that erodes the first time somebody is in a
hurry.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.records import MaterialisationBasis
from release_gate.assurance.subject import ContentReference

__all__ = [
    "FAILED_BRANCH_SCHEMA_VERSION",
    "MAX_INLINE_DETAIL",
    "BranchOutcome",
    "FailedBranch",
    "FailedBranchError",
    "FailedBranchLedger",
    "FailedBranchRecorder",
    "FailurePoint",
    "FailureLocus",
    "RetentionReason",
    "branches_from_verification",
]

FAILED_BRANCH_SCHEMA_VERSION = 1

#: Characters of free text a branch may carry inline. Past this the content
#: belongs behind a reference: the point of this module is structure, and a
#: transcript pasted into `detail` is the retention failure it exists to prevent.
MAX_INLINE_DETAIL = 2048

#: Branches retained per failure locus once the always-keep rules are satisfied.
DEFAULT_PER_LOCUS_CAP = 3


class FailedBranchError(ValueError):
    """A branch was recorded in a way that would defeat the retention discipline."""


class BranchOutcome(str, Enum):
    """How the attempt ended."""

    PROOF_FAILED = "PROOF_FAILED"                    # a proof branch died at a step
    INVARIANT_VIOLATED = "INVARIANT_VIOLATED"        # a simulation broke a property
    TEST_FAILED = "TEST_FAILED"
    CANDIDATE_REFUTED = "CANDIDATE_REFUTED"          # a proposed solution did not hold
    ARTIFACT_REJECTED = "ARTIFACT_REJECTED"          # a verifier refused the output
    EVIDENCE_INCOMPATIBLE = "EVIDENCE_INCOMPATIBLE"  # what was found did not fit
    ABANDONED = "ABANDONED"                          # stopped without a result
    TIMED_OUT = "TIMED_OUT"
    OTHER = "OTHER"


class RetentionReason(str, Enum):
    """Why this particular branch was kept when others were not.

    Stated per branch so a reviewer can tell a deliberately-kept example from an
    arbitrary one, and so the retention policy is auditable rather than implicit.
    """

    DEEPEST_AT_LOCUS = "DEEPEST_AT_LOCUS"
    BEARS_ON_CLAIM = "BEARS_ON_CLAIM"
    FIRST_AT_LOCUS = "FIRST_AT_LOCUS"
    WITHIN_CAP = "WITHIN_CAP"
    ALL_RETAINED = "ALL_RETAINED"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FailureLocus:
    """*Where* it broke, structured enough to group on.

    `step` is the name a person would use — "lemma 48", "invariant X". `ordinal`
    is the number inside it where there is one, so depth is comparable without
    parsing the name back out.
    """

    step: str = ""
    ordinal: Optional[int] = None
    invariant: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "step", (self.step or "").strip())
        object.__setattr__(self, "invariant", (self.invariant or "").strip())
        if self.ordinal is not None and int(self.ordinal) < 0:
            raise FailedBranchError("ordinal cannot be negative")

    @property
    def key(self) -> str:
        """What branches are grouped by. Empty when nothing identifies the point."""
        parts = [p for p in (self.step, self.invariant) if p]
        return " / ".join(parts) if parts else "unidentified failure point"

    @property
    def identified(self) -> bool:
        return bool(self.step or self.invariant)

    def to_dict(self) -> Dict[str, Any]:
        return {"step": self.step, "ordinal": self.ordinal,
                "invariant": self.invariant, "key": self.key,
                "identified": self.identified}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FailureLocus":
        return cls(step=data.get("step", ""), ordinal=data.get("ordinal"),
                   invariant=data.get("invariant", ""))


@dataclass(frozen=True)
class FailedBranch:
    """One attempt that did not work out, as structure and a reference."""

    outcome: BranchOutcome
    locus: FailureLocus = field(default_factory=FailureLocus)
    produced_by: str = ""
    bears_on_claims: Tuple[str, ...] = ()
    evidence: Tuple[str, ...] = ()
    reference: Optional[ContentReference] = None
    digest: Optional[str] = None
    depth: Optional[int] = None
    detail: str = ""
    retained_because: RetentionReason = RetentionReason.ALL_RETAINED
    occurred_at: str = field(default_factory=_utc_now)
    schema_version: int = FAILED_BRANCH_SCHEMA_VERSION

    branch_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", BranchOutcome(self.outcome))
        object.__setattr__(self, "retained_because",
                           RetentionReason(self.retained_because))
        object.__setattr__(self, "bears_on_claims",
                           tuple(sorted(set(self.bears_on_claims))))
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))
        object.__setattr__(self, "detail", (self.detail or "").strip())

        if len(self.detail) > MAX_INLINE_DETAIL:
            raise FailedBranchError(
                f"branch detail is {len(self.detail)} characters, over the "
                f"{MAX_INLINE_DETAIL} allowed inline. What failed belongs here as "
                "structure — the locus, the outcome, the depth — and the full record "
                "belongs behind `reference`. Retaining transcripts is the failure this "
                "module exists to prevent.")
        if self.depth is not None and int(self.depth) < 0:
            raise FailedBranchError("depth cannot be negative")

        object.__setattr__(self, "branch_id",
                           short_id("branch", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        return {"schema_version": FAILED_BRANCH_SCHEMA_VERSION,
                "outcome": self.outcome.value, "locus": self.locus.to_dict(),
                "produced_by": self.produced_by, "depth": self.depth,
                "digest": self.digest, "occurred_at": self.occurred_at,
                "bears_on_claims": list(self.bears_on_claims)}

    @property
    def reachable(self) -> bool:
        """Can a reviewer get from here to the thing itself?"""
        return self.reference is not None or bool(self.evidence) or bool(self.digest)

    @property
    def record_type(self) -> str:
        return "failed_branch"

    @property
    def record_id(self) -> str:
        return self.branch_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "failed_branch",
            "record_id": self.branch_id,
            "branch_id": self.branch_id,
            "outcome": self.outcome.value,
            "locus": self.locus.to_dict(),
            "produced_by": self.produced_by,
            "bears_on_claims": list(self.bears_on_claims),
            "evidence": list(self.evidence),
            "reference": self.reference.to_dict() if self.reference else None,
            "digest": self.digest,
            "depth": self.depth,
            "detail": self.detail,
            "reachable": self.reachable,
            "retained_because": self.retained_because.value,
            "occurred_at": self.occurred_at,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FailedBranch":
        reference = data.get("reference")
        return cls(
            outcome=BranchOutcome(data.get("outcome", BranchOutcome.OTHER.value)),
            locus=FailureLocus.from_dict(data.get("locus") or {}),
            produced_by=data.get("produced_by", ""),
            bears_on_claims=tuple(data.get("bears_on_claims") or ()),
            evidence=tuple(data.get("evidence") or ()),
            reference=ContentReference.from_dict(reference) if reference else None,
            digest=data.get("digest"), depth=data.get("depth"),
            detail=data.get("detail", ""),
            occurred_at=data.get("occurred_at") or _utc_now())

    def render(self) -> str:
        head = f"{self.branch_id}  {self.outcome.value}"
        if self.locus.identified:
            head += f"  at {self.locus.key}"
        if self.depth is not None:
            head += f"  (depth {self.depth})"
        lines = [head]
        if self.produced_by:
            lines.append(f"    by {self.produced_by}")
        if self.bears_on_claims:
            lines.append(f"    bears on {', '.join(self.bears_on_claims)}")
        if self.detail:
            lines.append(f"    {self.detail[:160]}")
        if not self.reachable:
            lines.append("    no reference: the branch itself cannot be reopened")
        return "\n".join(lines)


@dataclass(frozen=True)
class FailurePoint:
    """Everything that died at one place. Counted over *all* branches, not the kept ones."""

    key: str
    count: int = 0
    outcomes: Tuple[str, ...] = ()
    producers: Tuple[str, ...] = ()
    deepest: Optional[int] = None
    retained: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "count": self.count,
                "outcomes": list(self.outcomes),
                "producers": list(self.producers[:16]),
                "producers_truncated": max(0, len(self.producers) - 16),
                "deepest": self.deepest, "retained": list(self.retained)}


class FailedBranchLedger:
    """What was tried and failed: examples kept, failure points counted in full."""

    def __init__(self, branches: Iterable[FailedBranch] = (), *,
                 failure_points: Iterable[FailurePoint] = (),
                 observed: int = 0,
                 basis: MaterialisationBasis = MaterialisationBasis.COMPLETE,
                 notes: Iterable[str] = ()) -> None:
        held = sorted(branches, key=lambda b: (b.locus.key, -(b.depth or 0),
                                               b.branch_id))
        self._held: Tuple[FailedBranch, ...] = tuple(held)
        self._points: Tuple[FailurePoint, ...] = tuple(
            sorted(failure_points, key=lambda p: (-p.count, p.key)))
        self._observed = max(observed, len(self._held))
        self._basis = MaterialisationBasis(basis)
        self._notes = tuple(notes)

    def __iter__(self):
        return iter(self._held)

    def __len__(self) -> int:
        return len(self._held)

    @property
    def branches(self) -> Tuple[FailedBranch, ...]:
        return self._held

    @property
    def failure_points(self) -> Tuple[FailurePoint, ...]:
        return self._points

    @property
    def observed(self) -> int:
        """Every branch that was seen, whether or not one was kept."""
        return self._observed

    @property
    def retained(self) -> int:
        return len(self._held)

    @property
    def dropped(self) -> int:
        return max(0, self._observed - self.retained)

    @property
    def basis(self) -> MaterialisationBasis:
        return self._basis

    @property
    def complete(self) -> bool:
        return self._basis is MaterialisationBasis.COMPLETE and self.dropped == 0

    @property
    def notes(self) -> Tuple[str, ...]:
        return self._notes

    def recurring(self, minimum: int = 2) -> Tuple[FailurePoint, ...]:
        """Places more than one attempt died. Usually where the real problem is."""
        return tuple(p for p in self._points
                     if p.count >= minimum and p.key != "unidentified failure point")

    def for_claim(self, claim_id: str) -> Tuple[FailedBranch, ...]:
        return tuple(b for b in self._held if claim_id in b.bears_on_claims)

    def unreachable(self) -> Tuple[FailedBranch, ...]:
        """Retained branches that cannot actually be reopened."""
        return tuple(b for b in self._held if not b.reachable)

    def digest(self) -> str:
        return digest_object({"branches": [b.to_dict() for b in self._held],
                              "points": [p.to_dict() for p in self._points],
                              "observed": self._observed, "basis": self._basis.value,
                              "schema_version": FAILED_BRANCH_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"observed": self.observed, "retained": self.retained,
                "dropped": self.dropped, "basis": self._basis.value,
                "complete": self.complete,
                "failure_points": len(self._points),
                "recurring": len(self.recurring()),
                "by_outcome": {o.value: sum(1 for b in self._held if b.outcome is o)
                               for o in BranchOutcome},
                "unreachable": len(self.unreachable()),
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(),
                "points": [p.to_dict() for p in self._points[:32]],
                "points_truncated": max(0, len(self._points) - 32),
                "detail": [b.to_dict() for b in self._held],
                "notes": list(self._notes)}

    def render(self) -> str:
        if not self._observed:
            return "No failed branches recorded."
        lines = [f"{self.observed:,} branch(es) failed; {self.retained} retained "
                 f"as examples ({self._basis.value})"]
        for point in self._points[:8]:
            lines.append(f"  {point.count:,} at {point.key}"
                         + (f", deepest {point.deepest}" if point.deepest is not None
                            else ""))
        for branch in self._held[:8]:
            for line in branch.render().splitlines():
                lines.append(f"  {line}")
        if self.dropped:
            lines.append(f"  {self.dropped:,} branch(es) counted but not retained; "
                         "their failure points are above")
        return "\n".join(lines)


class FailedBranchRecorder:
    """Folds branches in under a retention policy, in constant memory.

    The policy, in order: a branch bearing on a claim is always kept; the first
    and the deepest at each failure point are kept; after that a per-locus cap
    applies and further branches are counted only. Every branch updates the
    aggregate whether or not it is kept, so the count at a locus is exact even
    when the examples are a sample.
    """

    def __init__(self, *, per_locus_cap: int = DEFAULT_PER_LOCUS_CAP,
                 keep_claim_bearing: bool = True) -> None:
        if per_locus_cap < 1:
            raise FailedBranchError(
                "per_locus_cap must keep at least one example per failure point; "
                "a ledger with counts and no examples cannot be investigated")
        self._cap = per_locus_cap
        self._keep_claim_bearing = keep_claim_bearing
        self._observed = 0
        self._kept: Dict[str, List[FailedBranch]] = {}
        self._counts: Dict[str, int] = {}
        self._outcomes: Dict[str, Set[str]] = {}
        self._producers: Dict[str, Set[str]] = {}
        self._deepest: Dict[str, Optional[int]] = {}

    @staticmethod
    def _priority(branch: FailedBranch) -> Tuple[int, int]:
        """What makes a branch worth keeping over another, highest first.

        A branch bearing on a claim outranks one that does not; among equals the
        deeper attempt wins, since it got further and says more about where the
        obstacle actually is.
        """
        return (1 if branch.bears_on_claims else 0,
                branch.depth if branch.depth is not None else -1)

    def record(self, branch: FailedBranch) -> "FailedBranchRecorder":
        """Fold one branch in. The aggregate always takes it; retention may not.

        Retention is a bounded priority queue per failure point, not a sequence of
        "keep if better" rules. An earlier version appended whenever a branch beat
        the deepest so far, which meant a run whose depth merely increased retained
        everything — the cap never bound, and at frontier scale that is the
        transcript-hoarding this module exists to prevent.
        """
        key = branch.locus.key
        self._observed += 1
        self._counts[key] = self._counts.get(key, 0) + 1
        self._outcomes.setdefault(key, set()).add(branch.outcome.value)
        if branch.produced_by:
            self._producers.setdefault(key, set()).add(branch.produced_by)
        previous = self._deepest.get(key)
        if branch.depth is not None and (previous is None or branch.depth > previous):
            self._deepest[key] = branch.depth

        kept = self._kept.setdefault(key, [])
        if len(kept) < self._cap:
            kept.append(branch)
            return self
        weakest = min(range(len(kept)), key=lambda i: self._priority(kept[i]))
        if self._priority(branch) > self._priority(kept[weakest]):
            kept[weakest] = branch
        return self

    def extend(self, branches: Iterable[FailedBranch]) -> "FailedBranchRecorder":
        for branch in branches:
            self.record(branch)
        return self

    def build(self) -> FailedBranchLedger:
        retained: List[FailedBranch] = []
        points: List[FailurePoint] = []
        for key in sorted(self._counts):
            kept = sorted(self._kept.get(key, []), key=self._priority, reverse=True)
            deepest = self._deepest.get(key)
            attributed: List[FailedBranch] = []
            for index, branch in enumerate(kept):
                if branch.bears_on_claims:
                    reason = RetentionReason.BEARS_ON_CLAIM
                elif branch.depth is not None and branch.depth == deepest:
                    reason = RetentionReason.DEEPEST_AT_LOCUS
                elif index == 0:
                    reason = RetentionReason.FIRST_AT_LOCUS
                else:
                    reason = RetentionReason.WITHIN_CAP
                attributed.append(dataclasses.replace(branch,
                                                      retained_because=reason))
            retained.extend(attributed)
            points.append(FailurePoint(
                key=key, count=self._counts[key],
                outcomes=tuple(sorted(self._outcomes.get(key, set()))),
                producers=tuple(sorted(self._producers.get(key, set()))),
                deepest=deepest,
                retained=tuple(b.branch_id for b in attributed)))

        dropped = self._observed - len(retained)
        if dropped:
            basis = MaterialisationBasis.CAPPED
            notes = (f"{dropped} branch(es) were counted and not retained; the "
                     f"per-failure-point cap is {self._cap}. Their failure points and "
                     "counts are exact — retention drops examples, never the aggregate.",)
        else:
            basis = MaterialisationBasis.COMPLETE
            notes = ()
        return FailedBranchLedger(retained, failure_points=points,
                                  observed=self._observed, basis=basis, notes=notes)


def branches_from_verification(graph: Any) -> Tuple[FailedBranch, ...]:
    """Lift failed verification attempts into branches.

    A check that ran and did not pass *is* an attempt that did not work out, and
    it is already in the case — so this costs a producer nothing and makes the
    exploration record honest by default rather than by discipline.
    """
    if graph is None:
        return ()
    out: List[FailedBranch] = []
    for attempt in getattr(graph, "attempts", ()) or ():
        if attempt.status.value != "FAILED":
            continue
        target = attempt.target
        out.append(FailedBranch(
            outcome=_OUTCOME_FOR_METHOD.get(attempt.method.value,
                                            BranchOutcome.TEST_FAILED),
            locus=FailureLocus(step=attempt.method.value),
            produced_by=attempt.verifier,
            bears_on_claims=((target.target_id,)
                             if target is not None and target.kind.value == "CLAIM"
                             else ()),
            evidence=attempt.evidence,
            digest=attempt.target_digest,
            detail=attempt.detail[:MAX_INLINE_DETAIL],
            occurred_at=attempt.timestamp))
    return tuple(out)


_OUTCOME_FOR_METHOD = {
    "FORMAL_PROOF": BranchOutcome.PROOF_FAILED,
    "THEOREM_PROVER": BranchOutcome.PROOF_FAILED,
    "SIMULATION": BranchOutcome.INVARIANT_VIOLATED,
    "PROPERTY_TEST": BranchOutcome.CANDIDATE_REFUTED,
    "TEST_SUITE": BranchOutcome.TEST_FAILED,
    "HUMAN_REVIEW": BranchOutcome.ARTIFACT_REJECTED,
    "CROSS_MODEL_REVIEW": BranchOutcome.ARTIFACT_REJECTED,
    "COMPILER": BranchOutcome.ARTIFACT_REJECTED,
    "TYPE_CHECKER": BranchOutcome.ARTIFACT_REJECTED,
}
