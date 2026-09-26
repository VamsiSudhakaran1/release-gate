"""Verification as a graph, not a boolean.

"Is it verified?" is the wrong question, and answering it with a bool is how
assurance systems mislead people. The right questions are plural: *what was
checked, by whom, with what method, against which exact state, what did it say,
what challenged it, and does any of it still apply?*

So verification is a set of typed attempts hanging off a target:

```text
Claim C-12
 ├── verified_by  FormalProof    V-1
 ├── tested_by    Simulation     V-8
 ├── challenged_by Counterexample CE-2
 └── reviewed_by  Agent 818
```

Three properties carry the weight.

**An attempt binds to an exact target state.** `target_digest` is the content the
verification actually ran against. When the target moves, the attempt does not
move with it — it becomes `SUPERSEDED` and stops counting toward the target's
status. A proof of yesterday's file is not a proof of today's, and the only way
to stop that fiction is to make applicability a computation rather than an
assumption.

**Failure is kept.** `FAILED` and `INVALIDATED` are first-class and never pruned.
A graph that recorded only successes would make every case look like its best
branch (Invariant 7).

**`NOT_RUN` is a status.** A verification that was expected and never happened is
a fact about the case, not an absence of one — and without somewhere to put it,
"we meant to check that" is invisible.

`INVALIDATED` and `SUPERSEDED` are deliberately different things. Invalidation is
a property of the attempt (the verifier was wrong, compromised, or retracted it);
supersession is a property of the attempt's *relationship to a target that moved*.
An attempt can be perfectly sound and still not apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.evidence import TrustStatus, VerificationMethod

__all__ = [
    "VERIFICATION_SCHEMA_VERSION",
    "Applicability",
    "TargetKind",
    "TargetVerification",
    "VerificationAttempt",
    "VerificationEdge",
    "VerificationEdgeType",
    "VerificationError",
    "VerificationGraph",
    "VerificationStatus",
    "VerificationTarget",
]

VERIFICATION_SCHEMA_VERSION = 3


class VerificationError(ValueError):
    """An attempt was constructed in a state that cannot be relied on."""


class VerificationStatus(str, Enum):
    """What an attempt came to.

    `NOT_RUN` and `UNKNOWN` are distinct: the first means it was expected and did
    not happen, the second that nothing says what happened. `INVALIDATED` means it
    ran and its result can no longer be relied on — which is not the same as
    having failed.
    """

    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"
    INVALIDATED = "INVALIDATED"
    UNKNOWN = "UNKNOWN"


#: Statuses that may contribute to a target's standing. An invalidated pass is
#: not a pass, and an attempt that never ran says nothing either way.
_COUNTS_TOWARD_STATUS = frozenset({
    VerificationStatus.PASSED, VerificationStatus.FAILED,
    VerificationStatus.INCONCLUSIVE})


class Applicability(str, Enum):
    """Whether an attempt still bears on the target it was run against."""

    APPLIES = "APPLIES"            # ran against the target's current content
    SUPERSEDED = "SUPERSEDED"      # the target has moved since
    UNDETERMINED = "UNDETERMINED"  # no digest on one side; applicability unknowable


class TargetKind(str, Enum):
    """What kind of thing is being pointed at.

    Shared with the required-evidence protocol, which addresses the same things
    from the other direction: a verification attempt names what it checked, and a
    requirement names what still needs checking. One vocabulary rather than two
    that would drift.
    """

    CLAIM = "CLAIM"
    ARTIFACT = "ARTIFACT"
    SUBJECT = "SUBJECT"
    EVIDENCE = "EVIDENCE"
    EXECUTION = "EXECUTION"
    # Addressable by a requirement though never by a verification attempt: you
    # cannot verify a producer, but you can require an attestation about one.
    PRODUCER = "PRODUCER"
    CAPABILITY = "CAPABILITY"
    VERIFICATION = "VERIFICATION"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    ADVERSARIAL_FINDING = "ADVERSARIAL_FINDING"
    ASSUMPTION = "ASSUMPTION"
    CONTRADICTION = "CONTRADICTION"
    COVERAGE_DIMENSION = "COVERAGE_DIMENSION"
    METHODOLOGY = "METHODOLOGY"
    CASE = "CASE"
    OTHER = "OTHER"


class VerificationEdgeType(str, Enum):
    VERIFIED_BY = "VERIFIED_BY"      # a proof-shaped check
    TESTED_BY = "TESTED_BY"          # an execution-shaped check
    CHALLENGED_BY = "CHALLENGED_BY"  # something that argues against the target
    REVIEWED_BY = "REVIEWED_BY"      # a judgement by a person or a model


#: Method → edge type. One source of truth: a caller supplies the method, and the
#: relationship follows, so the two can never disagree about what a check was.
_METHOD_EDGE: Mapping[VerificationMethod, VerificationEdgeType] = {
    VerificationMethod.FORMAL_PROOF: VerificationEdgeType.VERIFIED_BY,
    VerificationMethod.THEOREM_PROVER: VerificationEdgeType.VERIFIED_BY,
    VerificationMethod.TYPE_CHECKER: VerificationEdgeType.VERIFIED_BY,
    VerificationMethod.COMPILER: VerificationEdgeType.VERIFIED_BY,
    VerificationMethod.TEST_SUITE: VerificationEdgeType.TESTED_BY,
    VerificationMethod.SIMULATION: VerificationEdgeType.TESTED_BY,
    VerificationMethod.EXPERIMENT: VerificationEdgeType.TESTED_BY,
    VerificationMethod.PROPERTY_TEST: VerificationEdgeType.TESTED_BY,
    VerificationMethod.RUNTIME_ASSERTION: VerificationEdgeType.TESTED_BY,
    VerificationMethod.STATIC_ANALYSIS: VerificationEdgeType.TESTED_BY,
    VerificationMethod.DOMAIN_CHECKER: VerificationEdgeType.TESTED_BY,
    VerificationMethod.INDEPENDENT_REPLICATION: VerificationEdgeType.TESTED_BY,
    VerificationMethod.HUMAN_REVIEW: VerificationEdgeType.REVIEWED_BY,
    VerificationMethod.CROSS_MODEL_REVIEW: VerificationEdgeType.REVIEWED_BY,
    VerificationMethod.EXTERNAL_REFERENCE: VerificationEdgeType.REVIEWED_BY,
    VerificationMethod.OTHER: VerificationEdgeType.TESTED_BY,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class VerificationTarget:
    """What was verified."""

    kind: TargetKind
    target_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", TargetKind(self.kind))
        if not (self.target_id or "").strip():
            raise VerificationError(
                "target_id is required: a verification of nothing cannot be weighed")
        object.__setattr__(self, "target_id", self.target_id.strip())

    @property
    def key(self) -> Tuple[str, str]:
        return (self.kind.value, self.target_id)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "target_id": self.target_id}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationTarget":
        return cls(kind=TargetKind(data["kind"]), target_id=data["target_id"])

    @classmethod
    def claim(cls, claim_id: str) -> "VerificationTarget":
        return cls(kind=TargetKind.CLAIM, target_id=claim_id)

    @property
    def reference(self) -> str:
        """`claim:C-184` — the addressable form the protocol speaks."""
        return f"{self.kind.value.lower()}:{self.target_id}"

    @classmethod
    def parse(cls, reference: str) -> "VerificationTarget":
        """Read `claim:C-184` back. Unknown prefixes become OTHER, not an error.

        A consumer that invents a target kind has said something about a thing
        this case does not model, and refusing to read it back would lose the id
        it named.
        """
        head, _, rest = str(reference or "").partition(":")
        if not rest:
            return cls(kind=TargetKind.OTHER, target_id=str(reference or "").strip())
        try:
            kind = TargetKind(head.strip().upper())
        except ValueError:
            kind = TargetKind.OTHER
        return cls(kind=kind, target_id=rest.strip())

    @classmethod
    def artifact(cls, logical_id: str) -> "VerificationTarget":
        return cls(kind=TargetKind.ARTIFACT, target_id=logical_id)


@dataclass(frozen=True)
class VerificationAttempt:
    """One attempt to verify something, kept whatever it came to.

    `verification_id` is derived from content rather than accepted from a caller,
    for the same reason `evidence_id` is: an id a producer chooses can collide,
    can be reused across runs, and cannot be checked. Two byte-identical attempts
    are the same attempt.
    """

    method: VerificationMethod
    target: Optional[VerificationTarget] = None
    verifier: str = ""
    target_digest: Optional[str] = None
    input_state: Optional[str] = None
    result: Mapping[str, Any] = field(default_factory=dict)
    evidence: Tuple[str, ...] = ()
    #: Left empty to mean "release-gate stamps it on arrival", which is what
    #: `stamped_on_arrival` then records. A caller that knows when the check
    #: actually ran passes it, and that value is part of the attempt's identity.
    timestamp: str = ""
    independence_lineage: Tuple[str, ...] = ()
    trust_status: TrustStatus = TrustStatus.NOT_ESTABLISHED
    status: VerificationStatus = VerificationStatus.UNKNOWN
    edge_type: Optional[VerificationEdgeType] = None
    detail: str = ""
    schema_version: int = VERIFICATION_SCHEMA_VERSION

    verification_id: str = field(default="", init=False)
    #: True when the timestamp is release-gate's arrival clock rather than a time
    #: anybody observed. Set here, never by a caller (Invariant 1).
    stamped_on_arrival: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", VerificationMethod(self.method))
        object.__setattr__(self, "status", VerificationStatus(self.status))
        object.__setattr__(self, "trust_status", TrustStatus(self.trust_status))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "independence_lineage",
                           tuple(self.independence_lineage))
        object.__setattr__(self, "result", dict(self.result or {}))
        if self.edge_type is not None:
            object.__setattr__(self, "edge_type", VerificationEdgeType(self.edge_type))

        if self.status is VerificationStatus.NOT_RUN and self.evidence:
            raise VerificationError(
                "a NOT_RUN attempt cannot cite evidence — nothing ran to produce it")
        if self.status is not VerificationStatus.NOT_RUN and not (self.verifier or "").strip():
            raise VerificationError(
                "verifier is required for an attempt that ran: a check nobody is "
                "answerable for cannot be weighed or corroborated (Invariant 11)")

        if not str(self.timestamp or "").strip():
            object.__setattr__(self, "stamped_on_arrival", True)
            object.__setattr__(self, "timestamp", _utc_now())

        object.__setattr__(self, "verification_id",
                           short_id("ver", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """Everything that makes this a distinct attempt.

        `target_digest` is in here, so the same check re-run against changed
        content is a different attempt rather than an update of the old one.

        `independence_lineage` is in here too, at schema version 2. Two checks
        that differ only in what they rest on are two attempts — that is the
        entire difference between corroboration and an echo — and while it was
        absent, two labs reporting the same outcome collided into one record and
        a case could not hold both. Ids from version 1 do not survive the change;
        the version in the digest makes that explicit rather than silent.

        **At version 3 an arrival stamp is excluded.** `timestamp` defaulted to
        release-gate's own clock, so an attempt built without one got a different
        id every second — which moved the replication group ids derived from it,
        the evidence fold containing those, and the case digest. Two identical
        sessions a second apart produced two different cases, and the
        determinism §10al claims for a restart held only within a single second.
        It surfaced as an intermittent failure in the chaos suite's own
        `duplicate_case` and `restart` faults.
        
        A timestamp a caller *supplied* stays in: that is a claim about when the
        check ran, and two runs an hour apart really are two attempts. An arrival
        stamp is not such a claim — it is when the record reached us — and
        `EvidenceRecord` had already drawn exactly this line (§10ah). This is the
        same fix, one layer down, and the version bump makes the id change
        explicit rather than silent.
        """
        return {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "method": self.method.value,
            "target": self.target.to_dict() if self.target else None,
            "verifier": self.verifier,
            "target_digest": self.target_digest,
            "input_state": self.input_state,
            "independence_lineage": list(self.independence_lineage),
            "status": self.status.value,
            # Excluded when release-gate stamped it: see the note above.
            "timestamp": "" if self.stamped_on_arrival else self.timestamp,
            "evidence": list(self.evidence),
            "result": dict(self.result),
        }

    # ── relationship ────────────────────────────────────────────────────────

    @property
    def relationship(self) -> VerificationEdgeType:
        """How this attempt relates to its target.

        A failure argues *against* the target whatever method produced it, so a
        failed proof is a challenge rather than a verification. That is why the
        edge type is computed from method and status together.
        """
        if self.edge_type is not None:
            return self.edge_type
        if self.status is VerificationStatus.FAILED:
            return VerificationEdgeType.CHALLENGED_BY
        return _METHOD_EDGE.get(self.method, VerificationEdgeType.TESTED_BY)

    def applicability(self, current_digest: Optional[str]) -> Applicability:
        """Does this attempt still bear on the target?

        `UNDETERMINED` whenever either side has no digest. It is emphatically not
        `APPLIES`: "we cannot tell whether this still holds" must never be read as
        "it holds".
        """
        if not self.target_digest or not current_digest:
            return Applicability.UNDETERMINED
        return (Applicability.APPLIES if self.target_digest == current_digest
                else Applicability.SUPERSEDED)

    @property
    def counts_toward_status(self) -> bool:
        return self.status in _COUNTS_TOWARD_STATUS

    @property
    def lineage_established(self) -> bool:
        return bool(self.independence_lineage)

    def independent_of(self, other: "VerificationAttempt") -> Optional[bool]:
        """Do these two rest on disjoint lineages?

        `None` when either lineage is unrecorded — two checks whose provenance
        nobody stated are not known to be independent, and saying `True` there
        would manufacture corroboration out of missing data.
        """
        if not self.independence_lineage or not other.independence_lineage:
            return None
        return not (set(self.independence_lineage) & set(other.independence_lineage))

    # ── serialisation ───────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "verification",
            "record_id": self.verification_id,
            "verification_id": self.verification_id,
            # Carried, so a round trip does not turn an arrival stamp into a
            # caller-supplied one. `from_dict` re-supplied the timestamp it had
            # just written, which made it explicit again and put the clock back
            # into the id — the fix undone by its own serialisation.
            "stamped_on_arrival": self.stamped_on_arrival,
            "verifier": self.verifier,
            "method": self.method.value,
            "target": self.target.to_dict() if self.target else None,
            "target_digest": self.target_digest,
            "input_state": self.input_state,
            "result": dict(self.result),
            "evidence": list(self.evidence),
            "timestamp": self.timestamp,
            "independence_lineage": list(self.independence_lineage),
            "trust_status": self.trust_status.value,
            "status": self.status.value,
            "relationship": self.relationship.value,
            "detail": self.detail,
            "schema_version": self.schema_version,
        }

    @property
    def record_type(self) -> str:
        return "verification"

    @property
    def record_id(self) -> str:
        return self.verification_id

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationAttempt":
        target = data.get("target")
        return cls(
            method=VerificationMethod(data["method"]),
            target=VerificationTarget.from_dict(target) if target else None,
            verifier=data.get("verifier", ""),
            target_digest=data.get("target_digest"),
            input_state=data.get("input_state"),
            result=data.get("result") or {},
            evidence=tuple(data.get("evidence") or ()),
            timestamp=("" if data.get("stamped_on_arrival")
                       else (data.get("timestamp") or "")),
            independence_lineage=tuple(data.get("independence_lineage") or ()),
            trust_status=TrustStatus(data.get("trust_status",
                                              TrustStatus.NOT_ESTABLISHED.value)),
            status=VerificationStatus(data.get("status", VerificationStatus.UNKNOWN.value)),
            detail=data.get("detail", ""))

    @classmethod
    def not_run(cls, method: VerificationMethod, *, target: VerificationTarget,
                reason: str) -> "VerificationAttempt":
        """A check that was expected and did not happen. A fact, not an absence."""
        return cls(method=method, target=target,
                   status=VerificationStatus.NOT_RUN, detail=reason)


@dataclass(frozen=True)
class VerificationEdge:
    """One typed link from a target to an attempt."""

    edge_type: VerificationEdgeType
    target: VerificationTarget
    verification_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_type", VerificationEdgeType(self.edge_type))

    def to_dict(self) -> Dict[str, Any]:
        return {"edge_type": self.edge_type.value, "target": self.target.to_dict(),
                "verification_id": self.verification_id}


@dataclass(frozen=True)
class TargetVerification:
    """What the attempts on one target add up to. Never a boolean."""

    target: VerificationTarget
    status: VerificationStatus
    current_digest: Optional[str] = None
    attempts_total: int = 0
    applies: int = 0
    superseded: int = 0
    undetermined: int = 0
    by_status: Mapping[str, int] = field(default_factory=dict)
    independent_confirmations: int = 0
    unattributed_confirmations: int = 0
    methods: Tuple[str, ...] = ()
    challenges: Tuple[str, ...] = ()
    basis: str = ""

    @property
    def verified(self) -> bool:
        """True only for PASSED. A property rather than truthiness on the status,
        so no caller can write `if summary.status` and read INCONCLUSIVE as yes."""
        return self.status is VerificationStatus.PASSED

    @property
    def corroborated(self) -> bool:
        """Passed, by at least two attempts on disjoint lineages."""
        return self.verified and self.independent_confirmations >= 2

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target.to_dict(), "status": self.status.value,
                "verified": self.verified, "corroborated": self.corroborated,
                "current_digest": self.current_digest,
                "attempts_total": self.attempts_total, "applies": self.applies,
                "superseded": self.superseded, "undetermined": self.undetermined,
                "by_status": dict(self.by_status),
                "independent_confirmations": self.independent_confirmations,
                "unattributed_confirmations": self.unattributed_confirmations,
                "methods": list(self.methods), "challenges": list(self.challenges),
                "basis": self.basis}


def _lineage_groups(attempts: Sequence[VerificationAttempt]) -> Tuple[int, int]:
    """Count disjoint lineage groups, and attempts whose lineage is unrecorded.

    Union-find over lineage elements: two attempts sharing any element are in one
    group and corroborate each other only once. Attempts with no lineage at all
    are counted apart rather than credited — provenance nobody recorded is not
    independence, and counting it as such would manufacture corroboration.
    """
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    unattributed = 0
    roots: Set[str] = set()
    for index, attempt in enumerate(attempts):
        if not attempt.independence_lineage:
            unattributed += 1
            continue
        marker = f"__attempt_{index}"
        find(marker)
        for element in attempt.independence_lineage:
            union(marker, element)
    for index, attempt in enumerate(attempts):
        if attempt.independence_lineage:
            roots.add(find(f"__attempt_{index}"))
    return len(roots), unattributed


class VerificationGraph:
    """Attempts, hung off the targets they bear on."""

    def __init__(self, attempts: Iterable[VerificationAttempt] = (), *,
                 digests: Optional[Mapping[Tuple[str, str], str]] = None) -> None:
        held = [a for a in attempts if isinstance(a, VerificationAttempt)]
        held.sort(key=lambda a: (a.target.key if a.target else ("", ""),
                                 a.timestamp, a.verification_id))
        self._attempts: Tuple[VerificationAttempt, ...] = tuple(held)
        # Current content digest per target, so applicability is computable.
        self._digests: Dict[Tuple[str, str], str] = dict(digests or {})
        self._by_target: Dict[Tuple[str, str], List[VerificationAttempt]] = {}
        for attempt in self._attempts:
            if attempt.target is not None:
                self._by_target.setdefault(attempt.target.key, []).append(attempt)

    # ── access ──────────────────────────────────────────────────────────────

    @property
    def attempts(self) -> Tuple[VerificationAttempt, ...]:
        return self._attempts

    @property
    def edges(self) -> Tuple[VerificationEdge, ...]:
        return tuple(VerificationEdge(edge_type=a.relationship, target=a.target,
                                      verification_id=a.verification_id)
                     for a in self._attempts if a.target is not None)

    def targets(self) -> Tuple[VerificationTarget, ...]:
        seen: Dict[Tuple[str, str], VerificationTarget] = {}
        for attempt in self._attempts:
            if attempt.target is not None:
                seen.setdefault(attempt.target.key, attempt.target)
        return tuple(seen[key] for key in sorted(seen))

    def attempts_for(self, target: VerificationTarget) -> Tuple[VerificationAttempt, ...]:
        return tuple(self._by_target.get(VerificationTarget(
            kind=target.kind, target_id=target.target_id).key, ()))

    def current_digest(self, target: VerificationTarget) -> Optional[str]:
        return self._digests.get(target.key)

    def with_digest(self, target: VerificationTarget,
                    digest: str) -> "VerificationGraph":
        digests = dict(self._digests)
        digests[target.key] = digest
        return VerificationGraph(self._attempts, digests=digests)

    # ── the fold ────────────────────────────────────────────────────────────

    def assess(self, target: VerificationTarget,
               current_digest: Optional[str] = None) -> TargetVerification:
        """What the attempts on this target add up to, against its current state.

        Only attempts that still apply can move the status. An attempt whose
        target has moved is counted and reported, and contributes nothing — which
        is the point of recording `target_digest` at all.

        A challenge outranks a pass. If one applicable attempt failed and another
        passed, the target is FAILED: a check that found a problem is not
        cancelled by a check that did not look for it (Invariant 7).
        """
        attempts = self.attempts_for(target)
        digest = current_digest if current_digest is not None else self.current_digest(target)

        applies: List[VerificationAttempt] = []
        superseded = 0
        undetermined = 0
        for attempt in attempts:
            state = attempt.applicability(digest)
            if state is Applicability.APPLIES:
                applies.append(attempt)
            elif state is Applicability.SUPERSEDED:
                superseded += 1
            else:
                undetermined += 1
                # Undetermined applicability is not applicability. Such an attempt
                # is reported but never folded, because crediting it would let a
                # verification with no recorded target state count as current.

        by_status: Dict[str, int] = {}
        for attempt in attempts:
            by_status[attempt.status.value] = by_status.get(attempt.status.value, 0) + 1

        counting = [a for a in applies if a.counts_toward_status]
        failed = [a for a in counting if a.status is VerificationStatus.FAILED]
        passed = [a for a in counting if a.status is VerificationStatus.PASSED]
        inconclusive = [a for a in counting if a.status is VerificationStatus.INCONCLUSIVE]

        if failed:
            status = VerificationStatus.FAILED
            basis = (f"{len(failed)} applicable attempt(s) failed; a challenge is not "
                     "cancelled by a check that passed")
        elif passed:
            status = VerificationStatus.PASSED
            basis = f"{len(passed)} applicable attempt(s) passed and none failed"
        elif inconclusive:
            status = VerificationStatus.INCONCLUSIVE
            basis = "every applicable attempt was inconclusive"
        elif applies:
            status = VerificationStatus.UNKNOWN
            basis = ("attempts apply but none of them reached a usable result "
                     "(invalidated, not run, or unknown)")
        elif superseded:
            status = VerificationStatus.UNKNOWN
            basis = (f"all {superseded} attempt(s) were run against an earlier state "
                     "of this target and no longer apply")
        elif undetermined:
            status = VerificationStatus.UNKNOWN
            basis = (f"{undetermined} attempt(s) exist but nothing records which state "
                     "they ran against, so whether they still apply is unknowable")
        else:
            status = VerificationStatus.UNKNOWN
            basis = "no verification attempts on this target"

        independent, unattributed = _lineage_groups(passed)
        return TargetVerification(
            target=target, status=status, current_digest=digest,
            attempts_total=len(attempts), applies=len(applies),
            superseded=superseded, undetermined=undetermined, by_status=by_status,
            independent_confirmations=independent,
            unattributed_confirmations=unattributed,
            methods=tuple(sorted({a.method.value for a in attempts})),
            challenges=tuple(a.verification_id for a in failed), basis=basis)

    def superseded_attempts(self) -> Tuple[VerificationAttempt, ...]:
        """Every attempt that no longer applies to the target it was run against."""
        out = []
        for attempt in self._attempts:
            if attempt.target is None:
                continue
            if attempt.applicability(self.current_digest(attempt.target)) \
                    is Applicability.SUPERSEDED:
                out.append(attempt)
        return tuple(out)

    def challenges(self, target: VerificationTarget) -> Tuple[VerificationAttempt, ...]:
        return tuple(a for a in self.attempts_for(target)
                     if a.relationship is VerificationEdgeType.CHALLENGED_BY)

    def invalidated(self) -> Tuple[VerificationAttempt, ...]:
        return tuple(a for a in self._attempts
                     if a.status is VerificationStatus.INVALIDATED)

    def not_run(self) -> Tuple[VerificationAttempt, ...]:
        return tuple(a for a in self._attempts
                     if a.status is VerificationStatus.NOT_RUN)

    # ── rendering ───────────────────────────────────────────────────────────

    def render(self, target: VerificationTarget) -> str:
        """The tree a person reads."""
        attempts = self.attempts_for(target)
        lines = [f"{target.kind.value} {target.target_id}"]
        digest = self.current_digest(target)
        for index, attempt in enumerate(attempts):
            last = index == len(attempts) - 1
            stem = " └──" if last else " ├──"
            state = attempt.applicability(digest)
            marker = "" if state is Applicability.APPLIES else f"  [{state.value}]"
            lines.append(
                f"{stem} {attempt.relationship.value.lower()} "
                f"{attempt.method.value} {attempt.verification_id} "
                f"({attempt.status.value}){marker}")
        return "\n".join(lines)

    # ── commitments ─────────────────────────────────────────────────────────

    def digest(self) -> str:
        """A commitment to what these attempts *are*.

        Built from each attempt's `identity()` rather than its full
        serialisation, so an arrival stamp does not enter it. Hashing `to_dict()`
        put the clock back in one layer above the attempt ids: the ids were
        stable and the graph digest still moved every second, which moved the
        coverage row that carries it and with it the case digest.

        Nothing is lost by the narrowing. `identity()` is already the complete
        set of things that make an attempt distinct — it is what the ids are
        derived from — so two graphs with equal digests hold the same checks on
        the same targets with the same results.
        """
        return digest_object({"attempts": [a.identity() for a in self._attempts],
                              "schema_version": VERIFICATION_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for attempt in self._attempts:
            by_status[attempt.status.value] = by_status.get(attempt.status.value, 0) + 1
        return {"attempts": len(self._attempts), "targets": len(self.targets()),
                "by_status": by_status,
                "by_relationship": {
                    t.value: sum(1 for a in self._attempts if a.relationship is t)
                    for t in VerificationEdgeType},
                "superseded": len(self.superseded_attempts()),
                "invalidated": len(self.invalidated()),
                "not_run": len(self.not_run()),
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(),
                "attempt_detail": [a.to_dict() for a in self._attempts],
                "edges": [e.to_dict() for e in self.edges],
                "targets": [t.to_dict() for t in self.targets()]}

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_claims(cls, claims: Iterable[Any], *,
                    digests: Optional[Mapping[Tuple[str, str], str]] = None
                    ) -> "VerificationGraph":
        """Lift the attempts embedded in claims into a graph.

        An attempt that arrived on a claim carries no target of its own, so one is
        attached here. It usually carries no `target_digest` either, and that is
        preserved rather than filled in: such an attempt is `UNDETERMINED` against
        any state, which is the truthful reading of a check that never recorded
        what it ran against.
        """
        attempts: List[VerificationAttempt] = []
        for claim in claims:
            claim_id = getattr(claim, "claim_id", None)
            if not claim_id:
                continue
            target = VerificationTarget.claim(claim_id)
            for attempt in getattr(claim, "verification_attempts", ()) or ():
                if attempt.target is None:
                    attempt = _retarget(attempt, target)
                attempts.append(attempt)
        return cls(attempts, digests=digests)

    @classmethod
    def from_case(cls, case: Any, *,
                  digests: Optional[Mapping[Tuple[str, str], str]] = None
                  ) -> "VerificationGraph":
        """Read every attempt a case holds, from both places they live.

        Standalone attempts sit in the `verification` collection; embedded ones
        hang off claims. Both are folded into one graph so a reviewer sees every
        check on a target together, whichever door it came through.
        """
        attempts: List[VerificationAttempt] = []
        seen: Set[str] = set()

        for record in case.records("verification"):
            if isinstance(record, VerificationAttempt):
                if record.verification_id not in seen:
                    seen.add(record.verification_id)
                    attempts.append(record)

        for claim in case.records("claims"):
            claim_id = getattr(claim, "claim_id", None)
            if not claim_id:
                continue
            target = VerificationTarget.claim(claim_id)
            for attempt in getattr(claim, "verification_attempts", ()) or ():
                if attempt.target is None:
                    attempt = _retarget(attempt, target)
                if attempt.verification_id not in seen:
                    seen.add(attempt.verification_id)
                    attempts.append(attempt)

        resolved = dict(digests or {})
        # The subject's digest is always known, so verification of the subject can
        # always be checked for currency.
        subject = getattr(case, "subject", None)
        if subject is not None and getattr(subject, "digest", None):
            resolved.setdefault(
                VerificationTarget(kind=TargetKind.SUBJECT,
                                   target_id=subject.subject_id).key, subject.digest)
        return cls(attempts, digests=resolved)


def _retarget(attempt: VerificationAttempt,
              target: VerificationTarget) -> VerificationAttempt:
    """Attach a target to an attempt that arrived without one.

    `dataclasses.replace` re-passes every init field to the constructor, so the
    arrival timestamp it had already filled in came back as a *caller-supplied*
    one and `stamped_on_arrival` — which is `init=False` and cannot ride along —
    reset to False. The clock went straight back into the attempt's identity, and
    the id moved every second again: the fix undone by a retarget.
    
    So the flag is carried across deliberately. The timestamp is rebuilt as an
    arrival stamp and then the original value is put back, which keeps the
    recorded arrival time exact while leaving it out of the identity.
    """
    import dataclasses
    rebuilt = dataclasses.replace(
        attempt, target=target,
        timestamp="" if attempt.stamped_on_arrival else attempt.timestamp)
    if attempt.stamped_on_arrival:
        object.__setattr__(rebuilt, "timestamp", attempt.timestamp)
    return rebuilt
