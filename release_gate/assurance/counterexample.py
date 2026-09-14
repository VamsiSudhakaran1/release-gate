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
    "CounterexampleStatus",
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


_OPEN_STATUSES = frozenset({CounterexampleStatus.OPEN, CounterexampleStatus.UNKNOWN})
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
    schema_version: int = COUNTEREXAMPLE_SCHEMA_VERSION

    counterexample_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", VerificationMethod(self.method))
        object.__setattr__(self, "result", CounterexampleResult(self.result))
        object.__setattr__(self, "status", CounterexampleStatus(self.status))
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))
        object.__setattr__(self, "resolution_evidence",
                           tuple(sorted(set(self.resolution_evidence))))

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

        object.__setattr__(self, "counterexample_id",
                           short_id("cex", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        return {"schema_version": COUNTEREXAMPLE_SCHEMA_VERSION,
                "target_claim": self.target_claim, "producer": self.producer,
                "method": self.method.value, "result": self.result.value,
                "evidence": list(self.evidence), "searched": self.searched,
                "attempted_at": self.attempted_at}

    # ── standing ────────────────────────────────────────────────────────────

    @property
    def found(self) -> bool:
        return self.result is CounterexampleResult.FOUND

    @property
    def is_open(self) -> bool:
        """A live refutation: something was found and nothing has answered it."""
        return self.found and self.status in _OPEN_STATUSES

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
            attempted_at=data.get("attempted_at") or _utc_now())

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
        if self.found and self.resolution:
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

    def to_contradictions(self, *, critical_claims: Iterable[str] = ()
                          ) -> Tuple[Contradiction, ...]:
        """Turn live refutations into contradictions the verdict cannot omit.

        Deliberately reusing `Contradiction` rather than adding a second
        enforcement path: `render_verdict` already refuses a verdict that fails to
        name an unresolved critical one, and one guard kept correct beats two that
        drift.
        """
        critical = set(critical_claims)
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
            if attempt.target_claim in critical:
                contradiction = contradiction.mark_critical(
                    "a counterexample stands against a critical claim")
            out.append(contradiction)
        return tuple(out)

    def digest(self) -> str:
        return digest_object({"attempts": [a.to_dict() for a in self._held],
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
                detail=("lifted from counterexample evidence; no resolution is "
                        "recorded, and silence is not a resolution")))
    return tuple(out)
