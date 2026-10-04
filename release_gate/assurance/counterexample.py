"""Counterexamples — the searches that try to break a claim, and what came back.

A counterexample search is a verification attempt with its semantics inverted,
and the inversion is where systems go wrong. Finding one is decisive: the claim,
as stated, is false. Finding none is almost nothing — it bounds the search, not
the claim. So the two outcomes must never be folded into one "pass/fail" field,
because the asymmetry is the entire content.

Two rules follow, and both are enforced rather than documented.

**A search that found nothing never proves absence.** `proves_absence` returns
`False` unconditionally, whatever the method, however many searches ran, however
large the space. Ten thousand searches that came back empty are ten thousand
bounded searches — and per the independence analysis, if they share a generator
they are one. A field that could be read as "proven safe" is not offered.

**A found counterexample becomes a contradiction.** Rather than building a second
enforcement path, an unresolved counterexample against a claim is converted into
a `Contradiction`, which `AssuranceCase.render_verdict()` already refuses to omit
when the claim is critical. That is what makes "the case cannot silently appear
clean" true by machinery instead of by intention — and it means there is one
guard to keep correct, not two that can drift apart.

`status` and `result` are deliberately separate fields. `result` is what the
search came back with; `status` is where the finding now stands. A search that
found nothing has nothing to resolve, which is `NOT_APPLICABLE` — a distinct
thing from `RESOLVED`, and conflating them would let "we looked and found
nothing" read as "we found something and dealt with it".

**One counterexample outweighs any amount of generic support.** Ninety-nine
passing authorization tests and one reproducible unauthorized transfer are not
a 99% authorization score; they are a false claim. There is nothing here that
averages, and the claim resolution reads a standing counterexample before it
reads any support (CR-01). What a counterexample *does* to the admission is its
standing against the release being admitted (`assess_standing`):

* `VALID` — it stands, and against this candidate. Against a critical claim it
  blocks (RG-CEX-001; the policy's `counterexample_effect`).
* `STALE` — it stands, and was found against another state of the release. It
  does not block the new state, and it is not dropped: it holds until it is
  re-run against the candidate (RG-CEX-004).
* `ACCEPTED` — a named person accepted it as a documented risk (rationale,
  reference), the declared policy permits documented exceptions, and the
  exception was made for this state. It no longer blocks; it stays on the
  record and in the verdict (RG-CEX-005), and the claim is still contradicted:
  accepting a risk does not make the claim true.
* `INVALIDATED`, `RESOLVED`, `SUPERSEDED` — answered, each with what answered it.

A documented exception the policy does not permit, or one made for another
state, is not an exception: the counterexample stays `VALID`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.contradiction import (
    Contradiction, ContradictionKind, ContradictionSide, ContradictionStatus,
)
from release_gate.assurance.evidence import EvidenceRecord, EvidenceType, VerificationMethod

__all__ = [
    "COUNTEREXAMPLE_SCHEMA_VERSION",
    "CounterexampleAttempt",
    "CounterexampleError",
    "CounterexampleLedger",
    "CounterexampleResult",
    "CounterexampleStanding",
    "CounterexampleStatus",
    "StandingAssessment",
    "assess_standing",
    "counterexamples_from_evidence",
]

COUNTEREXAMPLE_SCHEMA_VERSION = 1


class CounterexampleError(ValueError):
    """An attempt was recorded in a state that would misreport what it found."""


class CounterexampleResult(str, Enum):
    """What the search came back with."""

    FOUND = "FOUND"                  # the claim as stated is false
    NOT_FOUND = "NOT_FOUND"          # this search found none; see `proves_absence`
    INCONCLUSIVE = "INCONCLUSIVE"    # the search did not complete
    NOT_RUN = "NOT_RUN"              # nobody looked
    UNKNOWN = "UNKNOWN"              # nothing records what happened


class CounterexampleStatus(str, Enum):
    """Where a finding now stands. Only meaningful once something was found."""

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    SUPERSEDED = "SUPERSEDED"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"  # nothing was found, so nothing to resolve
    #: Found, unanswered, and a named person accepted it as a documented risk.
    #: Not an answer: the claim is still false. Whether it lifts the block is
    #: the declared policy's (`counterexample_exceptions`).
    ACCEPTED_RISK = "ACCEPTED_RISK"


_OPEN_STATUSES = frozenset({CounterexampleStatus.OPEN, CounterexampleStatus.UNKNOWN})
#: The claim as stated is false and nothing has answered that.
_STANDING_STATUSES = _OPEN_STATUSES | {CounterexampleStatus.ACCEPTED_RISK}
_CLOSED_STATUSES = frozenset({
    CounterexampleStatus.RESOLVED, CounterexampleStatus.SUPERSEDED,
    CounterexampleStatus.INVALID})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class CounterexampleAttempt:
    """One attempt to break a claim, and what it came back with."""

    target_claim: str
    producer: str = ""
    method: VerificationMethod = VerificationMethod.PROPERTY_TEST
    result: CounterexampleResult = CounterexampleResult.UNKNOWN
    evidence: Tuple[str, ...] = ()
    resolution: str = ""
    resolution_evidence: Tuple[str, ...] = ()
    status: CounterexampleStatus = CounterexampleStatus.UNKNOWN
    searched: str = ""          # what space was covered, if anyone said
    detail: str = ""
    attempted_at: str = field(default_factory=_utc_now)
    #: The state of the release it was found against, in candidate components
    #: (candidate.py). Unstated is taken to be the candidate, as for evidence.
    state: Mapping[str, Any] = field(default_factory=dict)
    #: A documented exception: who accepted the risk, and where it is written
    #: down. The rationale is `resolution`. Only with ACCEPTED_RISK.
    accepted_by: str = ""
    reference: str = ""
    #: The state the exception was made for. An exception is for a release,
    #: and lapses when the candidate moves past it.
    accepted_for: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = COUNTEREXAMPLE_SCHEMA_VERSION

    counterexample_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", VerificationMethod(self.method))
        object.__setattr__(self, "result", CounterexampleResult(self.result))
        object.__setattr__(self, "status", CounterexampleStatus(self.status))
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))
        object.__setattr__(self, "resolution_evidence",
                           tuple(sorted(set(self.resolution_evidence))))
        object.__setattr__(self, "state", {str(k): str(v) for k, v in
                                           sorted(dict(self.state or {}).items())})
        object.__setattr__(self, "accepted_for", {str(k): str(v) for k, v in sorted(
            dict(self.accepted_for or {}).items())})

        if not (self.target_claim or "").strip():
            raise CounterexampleError(
                "target_claim is required: a counterexample against nothing cannot be "
                "weighed or surfaced")
        object.__setattr__(self, "target_claim", self.target_claim.strip())

        if self.result is CounterexampleResult.FOUND:
            if self.status is CounterexampleStatus.NOT_APPLICABLE:
                raise CounterexampleError(
                    "a FOUND counterexample always has something to resolve; "
                    "NOT_APPLICABLE would file a live refutation as nothing to do")
            if not (self.producer or "").strip():
                raise CounterexampleError(
                    "a FOUND counterexample must name its producer — a refutation "
                    "nobody is answerable for cannot be weighed (Invariant 11)")
        elif self.status in (CounterexampleStatus.OPEN, CounterexampleStatus.RESOLVED):
            raise CounterexampleError(
                f"result {self.result.value} has nothing to be {self.status.value} "
                "about; a search that found nothing is NOT_APPLICABLE, which is a "
                "different fact from having found something and dealt with it")

        if self.status is CounterexampleStatus.RESOLVED:
            if not self.resolution.strip():
                raise CounterexampleError(
                    "a RESOLVED counterexample must state its resolution")
            if not self.resolution_evidence:
                raise CounterexampleError(
                    "a RESOLVED counterexample must cite resolution_evidence; a "
                    "refutation is answered by evidence, never by assertion")
        if self.status in (CounterexampleStatus.INVALID, CounterexampleStatus.SUPERSEDED) \
                and not self.resolution.strip():
            raise CounterexampleError(
                f"a {self.status.value} counterexample must say why; dismissing a "
                "refutation is a claim somebody has to be answerable for")
        if self.status is CounterexampleStatus.ACCEPTED_RISK:
            if not self.found:
                raise CounterexampleError(
                    "only a found counterexample can be accepted as a risk")
            missing = [name for name, value in (
                ("resolution (the rationale)", self.resolution),
                ("accepted_by", self.accepted_by), ("reference", self.reference))
                if not str(value or "").strip()]
            if missing:
                raise CounterexampleError(
                    "a documented exception names who accepted the risk, why, and "
                    f"where it is written down; missing: {', '.join(missing)}")
        elif self.accepted_by or self.reference or self.accepted_for:
            raise CounterexampleError(
                "accepted_by, reference and accepted_for belong to an ACCEPTED_RISK "
                "exception; on anything else they would read as one")

        object.__setattr__(self, "counterexample_id",
                           short_id("cex", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct search — never when it was recorded.

        `attempted_at` is a clock: an envelope that does not state it is stamped
        on arrival, and an id that moved with the clock gave the same input a
        different case every second. The state it was found against is part of
        what it is, and is included only when stated, so a search that names no
        state keeps the id it always had.
        """
        found = {"schema_version": COUNTEREXAMPLE_SCHEMA_VERSION,
                 "target_claim": self.target_claim, "producer": self.producer,
                 "method": self.method.value, "result": self.result.value,
                 "evidence": list(self.evidence), "searched": self.searched}
        if self.state:
            found["state"] = dict(self.state)
        return found

    # ── standing ────────────────────────────────────────────────────────────

    @property
    def found(self) -> bool:
        return self.result is CounterexampleResult.FOUND

    @property
    def is_open(self) -> bool:
        """A live refutation: something was found and nothing has answered it."""
        return self.found and self.status in _OPEN_STATUSES

    @property
    def stands(self) -> bool:
        """The claim as stated is false and nothing has answered that — including
        a risk somebody accepted, which is a decision, not an answer."""
        return self.found and self.status in _STANDING_STATUSES

    @property
    def resolved(self) -> bool:
        return self.status in _CLOSED_STATUSES

    @property
    def proves_absence(self) -> bool:
        """Always False. Not a computation — a refusal.

        A search that came back empty bounds the search, not the claim. No number
        of empty searches changes that, and if they share a generator the
        independence analysis will show they were one search anyway. Offering a
        field that could be read as "proven safe" would be the most dangerous
        convenience in this module.
        """
        return False

    @property
    def search_bound(self) -> str:
        """What was actually covered, or a statement that nobody said."""
        return self.searched.strip() or "the extent of this search was not recorded"

    def resolve(self, resolution: str,
                evidence: Iterable[str]) -> "CounterexampleAttempt":
        import dataclasses
        return dataclasses.replace(self, status=CounterexampleStatus.RESOLVED,
                                   resolution=resolution,
                                   resolution_evidence=tuple(evidence))

    def invalidate(self, reason: str) -> "CounterexampleAttempt":
        import dataclasses
        return dataclasses.replace(self, status=CounterexampleStatus.INVALID,
                                   resolution=reason)

    # ── serialisation ───────────────────────────────────────────────────────

    @property
    def record_type(self) -> str:
        return "counterexample"

    @property
    def record_id(self) -> str:
        return self.counterexample_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "counterexample",
            "record_id": self.counterexample_id,
            "counterexample_id": self.counterexample_id,
            "target_claim": self.target_claim,
            "producer": self.producer,
            "method": self.method.value,
            "result": self.result.value,
            "evidence": list(self.evidence),
            "resolution": self.resolution,
            "resolution_evidence": list(self.resolution_evidence),
            "status": self.status.value,
            "searched": self.searched,
            "search_bound": self.search_bound,
            "proves_absence": self.proves_absence,
            "open": self.is_open,
            "resolved": self.resolved,
            "detail": self.detail,
            "attempted_at": self.attempted_at,
            "state": dict(self.state),
            "accepted_by": self.accepted_by,
            "reference": self.reference,
            "accepted_for": dict(self.accepted_for),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CounterexampleAttempt":
        return cls(
            target_claim=data["target_claim"], producer=data.get("producer", ""),
            method=VerificationMethod(data.get("method",
                                               VerificationMethod.PROPERTY_TEST.value)),
            result=CounterexampleResult(data.get("result",
                                                 CounterexampleResult.UNKNOWN.value)),
            evidence=tuple(data.get("evidence") or ()),
            resolution=data.get("resolution", ""),
            resolution_evidence=tuple(data.get("resolution_evidence") or ()),
            status=CounterexampleStatus(data.get("status",
                                                 CounterexampleStatus.UNKNOWN.value)),
            searched=data.get("searched", ""), detail=data.get("detail", ""),
            attempted_at=data.get("attempted_at") or _utc_now(),
            state=dict(data.get("state") or {}),
            accepted_by=data.get("accepted_by", ""),
            reference=data.get("reference", ""),
            accepted_for=dict(data.get("accepted_for") or {}))

    @classmethod
    def not_found(cls, target_claim: str, *, producer: str,
                  method: VerificationMethod = VerificationMethod.PROPERTY_TEST,
                  searched: str = "") -> "CounterexampleAttempt":
        """A search that came back empty. Evidence about the search, not the claim."""
        return cls(target_claim=target_claim, producer=producer, method=method,
                   result=CounterexampleResult.NOT_FOUND,
                   status=CounterexampleStatus.NOT_APPLICABLE, searched=searched)

    def render(self) -> str:
        lines = [f"{self.counterexample_id}  {self.target_claim}  "
                 f"{self.result.value}"
                 + (f" / {self.status.value}" if self.found else "")]
        lines.append(f"    {self.method.value} by {self.producer or 'an unnamed producer'}")
        if self.result is CounterexampleResult.NOT_FOUND:
            lines.append(f"    found none over: {self.search_bound}")
            lines.append("    this bounds the search, not the claim")
        if self.status is CounterexampleStatus.ACCEPTED_RISK:
            lines.append(f"    accepted as a documented risk by {self.accepted_by} "
                         f"({self.reference}): {self.resolution}")
        elif self.found and self.resolution:
            lines.append(f"    resolution: {self.resolution}")
        return "\n".join(lines)


class CounterexampleLedger:
    """Every attempt to break a claim, and what each came back with."""

    def __init__(self, attempts: Iterable[CounterexampleAttempt] = ()) -> None:
        # Deduplicated by id, because two byte-identical attempts are one attempt
        # by the same reasoning that derives the id from content. Attempts now
        # arrive from three places — the envelope, evidence, and adversarial
        # findings — and the same search reported through two of them must not
        # become two refutations, nor collide when the collection rejects a
        # duplicate record_id.
        by_id = {a.counterexample_id: a for a in attempts}
        held = list(by_id.values())
        held.sort(key=lambda a: (not a.is_open, not a.found, a.target_claim,
                                 a.counterexample_id))
        self._held: Tuple[CounterexampleAttempt, ...] = tuple(held)

    def __iter__(self):
        return iter(self._held)

    def __len__(self) -> int:
        return len(self._held)

    @property
    def attempts(self) -> Tuple[CounterexampleAttempt, ...]:
        return self._held

    def found(self) -> Tuple[CounterexampleAttempt, ...]:
        return tuple(a for a in self._held if a.found)

    def open(self) -> Tuple[CounterexampleAttempt, ...]:
        """Found, and nothing has answered it."""
        return tuple(a for a in self._held if a.is_open)

    def searched_without_finding(self) -> Tuple[CounterexampleAttempt, ...]:
        return tuple(a for a in self._held
                     if a.result is CounterexampleResult.NOT_FOUND)

    def for_claim(self, claim_id: str) -> Tuple[CounterexampleAttempt, ...]:
        return tuple(a for a in self._held if a.target_claim == claim_id)

    def unresolved_against(self, claim_ids: Iterable[str]
                           ) -> Tuple[CounterexampleAttempt, ...]:
        wanted = set(claim_ids)
        return tuple(a for a in self.open() if a.target_claim in wanted)

    def to_contradictions(self, *, critical_claims: Iterable[str] = (),
                          stale: Iterable[str] = ()) -> Tuple[Contradiction, ...]:
        """Turn live refutations into contradictions the verdict cannot omit.

        Deliberately reusing `Contradiction` rather than adding a second
        enforcement path: `render_verdict` already refuses a verdict that fails to
        name an unresolved critical one, and one guard kept correct beats two that
        drift. A counterexample found against another state (`stale`, by id)
        becomes a STALE disagreement: still named, never called current.
        """
        from release_gate.assurance.contradiction import ConflictClass
        critical = set(critical_claims)
        stale_ids = set(stale)
        out: List[Contradiction] = []
        for attempt in self.open():
            contradiction = Contradiction(
                target_claims=(attempt.target_claim,),
                kind=ContradictionKind.CLAIM_EVIDENCE_CONFLICT,
                status=ContradictionStatus.OPEN,
                sides=(
                    ContradictionSide(
                        label="the claim as stated", note="asserted"),
                    ContradictionSide(
                        label="counterexample", evidence=attempt.evidence,
                        participants=(attempt.producer,) if attempt.producer else (),
                        note=f"{attempt.method.value} found a counterexample")),
                detected_by=f"release-gate/counterexample/{attempt.counterexample_id}",
                detail=(f"{attempt.method.value} by "
                        f"{attempt.producer or 'an unnamed producer'} found a "
                        f"counterexample to {attempt.target_claim} and nothing "
                        "recorded resolves it"))
            if attempt.counterexample_id in stale_ids:
                import dataclasses
                contradiction = dataclasses.replace(
                    contradiction, classification=ConflictClass.STALE,
                    classification_basis=("the counterexample was found against a state "
                                          "other than the candidate's"))
            if attempt.target_claim in critical:
                contradiction = contradiction.mark_critical(
                    "a counterexample stands against a critical claim")
            out.append(contradiction)
        return tuple(out)

    def digest(self) -> str:
        """Clock-free, for the reason `records.CLOCK_FIELDS` gives: this digest
        travels inside a coverage row, and `attempted_at` stamped on arrival made
        the same input a different case every second."""
        from release_gate.assurance.records import strip_clocks
        return digest_object({"attempts": [strip_clocks(a.to_dict()) for a in self._held],
                              "schema_version": COUNTEREXAMPLE_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self._held), "found": len(self.found()),
                "open": len(self.open()),
                "searched_without_finding": len(self.searched_without_finding()),
                "by_result": {r.value: sum(1 for a in self._held if a.result is r)
                              for r in CounterexampleResult},
                "by_status": {s.value: sum(1 for a in self._held if a.status is s)
                              for s in CounterexampleStatus},
                # Stated flatly so no reader of the summary can infer otherwise.
                "absence_proven": False,
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(), "detail": [a.to_dict() for a in self._held]}

    def render(self) -> str:
        if not self._held:
            return "No counterexample searches recorded."
        return "\n".join(a.render() for a in self._held)


def counterexamples_from_evidence(evidence: Sequence[EvidenceRecord]
                                  ) -> Tuple[CounterexampleAttempt, ...]:
    """Lift counterexample evidence already in a case into typed attempts.

    Evidence typed `COUNTEREXAMPLE` that contradicts a claim is a found
    counterexample, whether or not anybody recorded it as one — so existing
    envelopes get this tracking without changing what they emit.

    Such a record is OPEN by default. Nothing in the evidence itself can say a
    refutation was answered; only an explicit resolution can, and inferring one
    from silence is the failure this module exists to prevent.
    """
    from release_gate.assurance.candidate import record_state
    out: List[CounterexampleAttempt] = []
    for record in sorted(evidence, key=lambda r: r.evidence_id):
        if record.evidence_type is not EvidenceType.COUNTEREXAMPLE:
            continue
        for claim_id in sorted(record.contradicts_claims):
            out.append(CounterexampleAttempt(
                target_claim=claim_id,
                producer=record.producer.producer_id,
                method=record.verification_method or VerificationMethod.OTHER,
                result=CounterexampleResult.FOUND,
                evidence=(record.evidence_id,),
                status=CounterexampleStatus.OPEN,
                attempted_at=record.timestamp,
                state={str(k): str(v) for k, v in record_state(record).items()},
                detail=("lifted from counterexample evidence; no resolution is "
                        "recorded, and silence is not a resolution")))
    return tuple(out)


# ── standing against the release being admitted ──────────────────────────────

class CounterexampleStanding(str, Enum):
    """What a counterexample does to this admission. Derived, never declared."""

    VALID = "VALID"                  # stands, against this candidate
    STALE = "STALE"                  # stands, found against another state
    ACCEPTED = "ACCEPTED"            # stands, a documented exception the policy permits
    INVALIDATED = "INVALIDATED"
    RESOLVED = "RESOLVED"
    SUPERSEDED = "SUPERSEDED"
    NOT_FOUND = "NOT_FOUND"          # the search found nothing: not a counterexample


@dataclass(frozen=True)
class StandingAssessment:
    counterexample_id: str
    target_claim: str
    standing: CounterexampleStanding
    reason: str
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"counterexample_id": self.counterexample_id,
                "target_claim": self.target_claim, "standing": self.standing.value,
                "reason": self.reason, "evidence": list(self.evidence)}


def _bound_elsewhere(state: Mapping[str, Any], candidate: Any, record_id: str
                     ) -> Optional[str]:
    """Why `state` is not the candidate's, or None when it is (or cannot be told)."""
    if candidate is None or not state:
        return None
    from release_gate.assurance.candidate import WITHHELD, bind
    binding = bind(candidate, state=state, record_id=record_id,
                   record_kind="counterexample")
    if binding.match not in WITHHELD:
        return None
    where = ("a different subject" if binding.match.value == "INCOMPATIBLE"
             else "another state of the release")
    return where + ": " + ("; ".join(
        f"{c.component} is {c.record_value} here and {c.candidate_value} in the candidate"
        for c in binding.mismatches()) or binding.match.value)


def assess_standing(attempt: CounterexampleAttempt, *, candidate: Any = None,
                    permit_exceptions: bool = False) -> StandingAssessment:
    """Where one counterexample stands against the candidate, under the policy.

    The order matters and is fixed: what answered it, then which state it was
    found against, then whether an exception is documented, permitted and made
    for this state. A counterexample nobody answered is VALID unless one of
    those says otherwise in so many words.
    """
    def out(standing: CounterexampleStanding, reason: str) -> StandingAssessment:
        return StandingAssessment(attempt.counterexample_id, attempt.target_claim,
                                  standing, reason, attempt.evidence)

    if not attempt.found:
        return out(CounterexampleStanding.NOT_FOUND,
                   f"the search found nothing over {attempt.search_bound}; that "
                   "bounds the search and proves nothing about the claim")
    if attempt.status is CounterexampleStatus.INVALID:
        return out(CounterexampleStanding.INVALIDATED, attempt.resolution)
    if attempt.status is CounterexampleStatus.RESOLVED:
        return out(CounterexampleStanding.RESOLVED,
                   f"{attempt.resolution} (answered by "
                   f"{', '.join(attempt.resolution_evidence)})")
    if attempt.status is CounterexampleStatus.SUPERSEDED:
        return out(CounterexampleStanding.SUPERSEDED, attempt.resolution)
    elsewhere = _bound_elsewhere(attempt.state, candidate, attempt.counterexample_id)
    if elsewhere:
        return out(CounterexampleStanding.STALE,
                   f"found against {elsewhere}; it has not been shown on the candidate, "
                   "and it has not been shown to be gone")
    if attempt.status is CounterexampleStatus.ACCEPTED_RISK:
        who = f"accepted by {attempt.accepted_by} ({attempt.reference})"
        if not permit_exceptions:
            return out(CounterexampleStanding.VALID,
                       f"a documented exception is recorded ({who}), and the resolution "
                       "policy does not permit documented exceptions")
        if candidate is not None and getattr(candidate, "explicit", False) \
                and not attempt.accepted_for:
            return out(CounterexampleStanding.VALID,
                       f"the exception ({who}) names no state, and an exception is for "
                       "a release: against a stated candidate it cannot be honoured")
        lapsed = _bound_elsewhere(attempt.accepted_for, candidate,
                                  f"{attempt.counterexample_id}:exception")
        if lapsed:
            return out(CounterexampleStanding.VALID,
                       f"the exception ({who}) was made for {lapsed}, and lapsed when "
                       "the candidate moved")
        return out(CounterexampleStanding.ACCEPTED,
                   f"{who}: {attempt.resolution}. The claim as stated is still false")
    return out(CounterexampleStanding.VALID,
               "it stands against the candidate and nothing answers it")
