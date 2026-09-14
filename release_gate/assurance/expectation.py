"""Evidence expectation — a percentage needs a denominator, and a denominator
needs a source.

Coverage is where assurance systems tell their most comfortable lie. Nine
verifier results arrive, nine are recorded, and the report says 100%. It is not
100% of anything until somebody says how many there should have been, and the
difference between those two situations is the difference between:

```text
Expected verifier results: 10      Observed verifier results: 9
Observed: 9                        Expected total: UNKNOWN
Known missing: 1                   Coverage: UNKNOWN
Coverage: 90%
```

Both are honest. Neither is 100%. The second is the common case, and a system
that renders it as complete has manufactured the one number its reader most
wants to believe.

Five states, kept apart because each says something the others do not:

* `NOT_ASSESSED` — nobody looked at this dimension.
* `UNKNOWN` — we looked and counted, but nothing establishes how many to expect,
  so no ratio exists. `coverage` is `None`, serialised as `null`, never `0` and
  never `1`.
* `EXPECTED` — an expectation stands and nothing has arrived against it. Not the
  same message as a partial arrival: this dimension has not started.
* `KNOWN_MISSING` — an expectation stands and some of it did not arrive.
* `OBSERVED` — everything the expectation named arrived.

`OBSERVED` is deliberately not called COMPLETE. **An expectation is itself a
declaration.** "The manifest said ten and ten arrived" does not establish there
were not twelve, and `bounds_completeness` returns `False` unconditionally to
keep that from being quietly forgotten. This is the same refusal
`CompletenessStatus` makes by having no `COMPLETE` member, applied one level up
(Invariant 13).

**The sharpest rule here is about who is counting.** An expectation declared by
the same party that produced the observations cannot detect omission: a producer
that dropped a record drops it from its own count too, and the coverage reads
100% precisely because something is missing. So `ExpectationStanding`
distinguishes `ESTABLISHED` from `SELF_REPORTED`, the ratio is still reported
because it is a real if weaker fact, and `matches_expectation` refuses to hold
for a self-report. Signing does not change this: a signed manifest establishes
*which* party declared the number, not that the party was disinterested
(Invariant 11).

**An over-count is not 110%, and not 100% either.** If eleven arrive where ten
were expected, either the expectation is wrong or something unplanned came in —
and in both cases the denominator is no longer known, so the state degrades to
`UNKNOWN`. Clamping to 100% would report the anomaly as perfection.

An enumerated expectation is strictly stronger than a count and is worth asking
for: it names *which* record is missing rather than how many, and it separates
"what was planned arrived" from "something unplanned also arrived" — a
distinction a bare cardinality cannot make at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id

__all__ = [
    "EXPECTATION_SCHEMA_VERSION",
    "CoverageLedger",
    "CoverageState",
    "EvidenceExpectation",
    "ExpectationError",
    "ExpectationSource",
    "ExpectationSourceKind",
    "ExpectationStanding",
]

EXPECTATION_SCHEMA_VERSION = 1


class ExpectationError(ValueError):
    """An expectation was recorded in a state that would misreport coverage."""


class CoverageState(str, Enum):
    """What can be said about one coverage dimension.

    `UNKNOWN` and `NOT_ASSESSED` are the two that get conflated, and conflating
    them is how a dimension nobody examined comes to look the same as one that
    was examined and found unmeasurable. The first says the question was never
    put; the second says it was put and the answer is that no denominator exists.
    """

    NOT_ASSESSED = "NOT_ASSESSED"    # the dimension was never examined
    UNKNOWN = "UNKNOWN"              # examined; no expectation, so no ratio exists
    EXPECTED = "EXPECTED"            # an expectation stands; nothing has arrived yet
    KNOWN_MISSING = "KNOWN_MISSING"  # an expectation stands; part of it did not arrive
    OBSERVED = "OBSERVED"            # everything the expectation named arrived


class ExpectationSourceKind(str, Enum):
    """Where a denominator came from. Selects no behaviour on its own.

    Kind never changes the arithmetic or the standing: a CI plan and a signed
    producer manifest are weighed the same way, and what separates them is
    whether the party that wrote them also produced the observations.
    """

    METHODOLOGY = "METHODOLOGY"
    ORCHESTRATION_MANIFEST = "ORCHESTRATION_MANIFEST"
    PRODUCER_MANIFEST = "PRODUCER_MANIFEST"
    AGENT_ROSTER = "AGENT_ROSTER"
    VERIFIER_INVENTORY = "VERIFIER_INVENTORY"
    EXPERIMENT_MATRIX = "EXPERIMENT_MATRIX"
    CI_PLAN = "CI_PLAN"
    SEQUENCE_DECLARATION = "SEQUENCE_DECLARATION"
    OTHER = "OTHER"


class ExpectationStanding(str, Enum):
    """Whether the denominator could detect an omission.

    Derived from who declared it against who produced the observations, never
    from anything the declaration says about itself.
    """

    ESTABLISHED = "ESTABLISHED"          # a party other than the producer states it
    SELF_REPORTED = "SELF_REPORTED"      # the producer of the observations states it
    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # nobody states it


@dataclass(frozen=True)
class ExpectationSource:
    """Who says how much to expect."""

    kind: ExpectationSourceKind = ExpectationSourceKind.OTHER
    declared_by: str = ""
    authenticated: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ExpectationSourceKind(self.kind))
        object.__setattr__(self, "declared_by", (self.declared_by or "").strip())
        if not self.declared_by:
            raise ExpectationError(
                "an expectation source must name who declared it; a denominator "
                "nobody is answerable for cannot be weighed (Invariant 11)")

    @property
    def identity_basis(self) -> str:
        """What authentication establishes, stated so it is not overread.

        A signature says which party wrote the number. It says nothing about
        whether that party was in a position to know, or disinterested.
        """
        return ("authenticated: the declaring party's identity is established, which "
                "is not evidence that the number is right"
                if self.authenticated else "unauthenticated")

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "declared_by": self.declared_by,
                "authenticated": self.authenticated,
                "identity_basis": self.identity_basis, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExpectationSource":
        return cls(kind=ExpectationSourceKind(str(data.get("kind") or "OTHER").upper()),
                   declared_by=str(data.get("declared_by") or ""),
                   authenticated=bool(data.get("authenticated")),
                   detail=str(data.get("detail") or ""))


@dataclass(frozen=True)
class EvidenceExpectation:
    """What one coverage dimension expected, what arrived, and what follows.

    `expected_ids` is preferred over `expected` wherever a producer can supply
    it: a set names which record is missing and separates the planned from the
    unplanned, where a count can only say how many.
    """

    dimension: str
    observed: int = 0
    expected: Optional[int] = None
    expected_ids: Tuple[str, ...] = ()
    observed_ids: Tuple[str, ...] = ()
    source: Optional[ExpectationSource] = None
    observed_from: str = ""
    assessed: bool = True
    note: str = ""
    schema_version: int = EXPECTATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not (self.dimension or "").strip():
            raise ExpectationError("an expectation must name the dimension it is about")
        object.__setattr__(self, "dimension", self.dimension.strip())
        object.__setattr__(self, "expected_ids", tuple(sorted(set(self.expected_ids))))
        object.__setattr__(self, "observed_ids", tuple(sorted(set(self.observed_ids))))
        if self.observed_ids and not self.observed:
            object.__setattr__(self, "observed", len(self.observed_ids))
        if self.expected_ids:
            # The enumeration is the expectation; a count beside it that disagrees
            # would leave two answers to one question.
            object.__setattr__(self, "expected", len(self.expected_ids))
        if self.expected is not None and self.expected < 0:
            raise ExpectationError("expected cannot be negative")
        if self.observed < 0:
            raise ExpectationError("observed cannot be negative")
        if self.expected is not None and self.source is None:
            raise ExpectationError(
                "an expectation must name its source: a denominator from nowhere is "
                "the false completeness this record exists to prevent")

    # ── standing ────────────────────────────────────────────────────────────

    @property
    def standing(self) -> ExpectationStanding:
        if self.source is None or self.expected is None:
            return ExpectationStanding.NOT_ESTABLISHED
        if self.observed_from and self.source.declared_by == self.observed_from:
            return ExpectationStanding.SELF_REPORTED
        return ExpectationStanding.ESTABLISHED

    @property
    def self_certified(self) -> bool:
        """The counted party is also the counting party.

        The number can still be right. What it cannot do is detect an omission,
        because whatever was dropped from the evidence was dropped from the
        denominator with it (Invariant 13).
        """
        return self.standing is ExpectationStanding.SELF_REPORTED

    @property
    def enumerated(self) -> bool:
        return bool(self.expected_ids)

    # ── the arithmetic ──────────────────────────────────────────────────────

    @property
    def known_missing_ids(self) -> Tuple[str, ...]:
        """Which records were named and never arrived. Only an enumeration knows."""
        if not self.expected_ids or not self.observed_ids:
            return ()
        return tuple(sorted(set(self.expected_ids) - set(self.observed_ids)))

    @property
    def unexpected_ids(self) -> Tuple[str, ...]:
        """Records that arrived which no expectation named."""
        if not self.expected_ids or not self.observed_ids:
            return ()
        return tuple(sorted(set(self.observed_ids) - set(self.expected_ids)))

    @property
    def known_missing(self) -> Optional[int]:
        """How many did not arrive. `None` where there is no denominator."""
        if self.expected is None or not self.assessed:
            return None
        if self.expected_ids:
            return len(self.known_missing_ids)
        if self.observed > self.expected:
            return None
        return self.expected - self.observed

    @property
    def over_count(self) -> bool:
        """More arrived than a bare count expected.

        Only meaningful for a cardinality: an enumeration answers this precisely
        through `unexpected_ids`, which is a different and better fact.
        """
        return (self.expected is not None and not self.expected_ids
                and self.observed > self.expected)

    @property
    def state(self) -> CoverageState:
        if not self.assessed:
            return CoverageState.NOT_ASSESSED
        if self.expected is None:
            return CoverageState.UNKNOWN
        if self.over_count:
            # Neither 110% nor 100%. Either the expectation is wrong or something
            # unplanned arrived, and in both cases the denominator is no longer
            # known — so the honest answer is that coverage cannot be computed.
            return CoverageState.UNKNOWN
        missing = self.known_missing or 0
        if self.expected == 0:
            return CoverageState.OBSERVED
        if not missing:
            return CoverageState.OBSERVED
        if missing >= self.expected:
            return CoverageState.EXPECTED
        return CoverageState.KNOWN_MISSING

    @property
    def coverage(self) -> Optional[float]:
        """The ratio, or `None`.

        `None` is the whole point. It serialises as `null` and is never rendered
        as a number: a dimension with no denominator has no percentage, and zero
        and one are both claims that nothing here supports.
        """
        if self.state in (CoverageState.NOT_ASSESSED, CoverageState.UNKNOWN):
            return None
        if not self.expected:
            return 1.0
        arrived = self.expected - (self.known_missing or 0)
        return round(max(0, arrived) / self.expected, 4)

    @property
    def matches_expectation(self) -> bool:
        """Everything the expectation named arrived, and someone else named it.

        Deliberately not called `complete`. It is the strongest thing this record
        offers and it is still not a completeness claim — see
        `bounds_completeness`.
        """
        return (self.state is CoverageState.OBSERVED
                and self.standing is ExpectationStanding.ESTABLISHED)

    @property
    def bounds_completeness(self) -> bool:
        """Always False. Not a computation — a refusal.

        An expectation is a declaration. "Ten were declared and ten arrived" does
        not establish that there were not twelve, whatever the source, however it
        was signed. `CompletenessStatus` makes the same refusal by having no
        COMPLETE member; this is that refusal one level up (Invariant 13).
        """
        return False

    @property
    def basis(self) -> str:
        """The sentence a reader needs, with the refusal built in."""
        if not self.assessed:
            return f"{self.dimension} was not examined"
        if self.expected is None:
            return (f"observed {self.observed}; expected total UNKNOWN, so coverage is "
                    "UNKNOWN — nothing here states how many there should have been")
        if self.over_count:
            return (f"observed {self.observed} where {self.expected} were expected; "
                    "more arrived than the denominator allows, so either the "
                    "expectation is wrong or something unplanned arrived and coverage "
                    "cannot be computed")
        missing = self.known_missing or 0
        if self.enumerated:
            # Counting arrivals against the plan rather than in total: with an
            # enumeration, `observed` includes records the plan never named, and
            # reporting "observed 4, missing 1" of an expected 4 reads as an
            # arithmetic error rather than as an unplanned arrival.
            arrived = self.expected - missing
            head = (f"expected {self.expected}, of which {arrived} arrived; "
                    f"known missing {missing}"
                    + (f" ({', '.join(self.known_missing_ids[:4])})"
                       if self.known_missing_ids else ""))
            if self.unexpected_ids:
                head += (f"; {len(self.unexpected_ids)} record(s) arrived that the "
                         f"expectation did not name "
                         f"({', '.join(self.unexpected_ids[:3])})")
        else:
            head = (f"expected {self.expected}, observed {self.observed}, "
                    f"known missing {missing}")
        if self.standing is ExpectationStanding.SELF_REPORTED:
            return (head + f"; the expectation comes from {self.source.declared_by}, "
                    "which also produced the evidence, so it cannot detect an omission")
        return head + (f"; expected by {self.source.declared_by}"
                       if self.source else "")

    # ── serialisation ───────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "coverage", "record_id": f"cov_{self.dimension}",
                "dimension": self.dimension,
                # Kept so a reader of the old two-state rows is not surprised; the
                # five-state answer is `state`.
                "status": "ASSESSED" if self.assessed else "NOT_ASSESSED",
                "state": self.state.value,
                "expected": self.expected, "observed": self.observed,
                "known_missing": self.known_missing,
                "known_missing_ids": list(self.known_missing_ids[:32]),
                "unexpected_ids": list(self.unexpected_ids[:32]),
                "coverage": self.coverage,
                "enumerated": self.enumerated,
                "expectation_standing": self.standing.value,
                "self_certified": self.self_certified,
                "bounds_completeness": False,
                "source": self.source.to_dict() if self.source else None,
                "observed_from": self.observed_from,
                "note": self.note or self.basis,
                "basis": self.basis,
                "schema_version": EXPECTATION_SCHEMA_VERSION}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceExpectation":
        raw = data.get("source")
        return cls(
            dimension=str(data.get("dimension") or ""),
            observed=int(data.get("observed") or 0),
            expected=(int(data["expected"]) if data.get("expected") is not None
                      else None),
            expected_ids=tuple(data.get("expected_ids") or ()),
            observed_ids=tuple(data.get("observed_ids") or ()),
            source=(ExpectationSource.from_dict(raw) if isinstance(raw, Mapping)
                    else None),
            observed_from=str(data.get("observed_from") or ""),
            assessed=bool(data.get("assessed", True)),
            note=str(data.get("note") or ""))

    def render(self) -> str:
        # NOT_ASSESSED must never render as "coverage UNKNOWN". A dimension nobody
        # examined and one examined without a denominator are the two absences
        # this record exists to keep apart, and the rendering is where they would
        # quietly become one line.
        if self.state is CoverageState.NOT_ASSESSED:
            return f"{self.dimension}: NOT_ASSESSED — {self.basis}"
        if self.coverage is None:
            return f"{self.dimension}: coverage UNKNOWN — {self.basis}"
        return (f"{self.dimension}: coverage {self.coverage:.0%} "
                f"[{self.state.value}] — {self.basis}")


# ── the ledger ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CoverageLedger:
    """Every coverage dimension in a case, and what each can honestly say."""

    rows: Tuple[EvidenceExpectation, ...] = ()

    def __iter__(self):
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def of(self, dimension: str) -> Optional[EvidenceExpectation]:
        return next((r for r in self.rows if r.dimension == dimension), None)

    def in_state(self, state: CoverageState) -> Tuple[EvidenceExpectation, ...]:
        return tuple(r for r in self.rows if r.state is state)

    def known_missing(self) -> Tuple[EvidenceExpectation, ...]:
        return self.in_state(CoverageState.KNOWN_MISSING)

    def unknown(self) -> Tuple[EvidenceExpectation, ...]:
        return self.in_state(CoverageState.UNKNOWN)

    def not_assessed(self) -> Tuple[EvidenceExpectation, ...]:
        return self.in_state(CoverageState.NOT_ASSESSED)

    def self_certified(self) -> Tuple[EvidenceExpectation, ...]:
        return tuple(r for r in self.rows if r.self_certified)

    def over_counted(self) -> Tuple[EvidenceExpectation, ...]:
        return tuple(r for r in self.rows if r.over_count)

    def unexpected(self) -> Tuple[EvidenceExpectation, ...]:
        return tuple(r for r in self.rows if r.unexpected_ids)

    def with_expectation(self) -> Tuple[EvidenceExpectation, ...]:
        return tuple(r for r in self.rows if r.expected is not None)

    @property
    def overall_coverage(self) -> Optional[float]:
        """Never computed. A refusal, not an omission.

        Averaging the dimensions that happen to have denominators and calling the
        result "coverage" is the false completeness this module exists to
        prevent: it would let a case with one measurable dimension out of fifteen
        report a confident number. A reader wants the rows, and the rows are what
        they get.
        """
        return None

    @property
    def bounds_completeness(self) -> bool:
        return False

    def digest(self) -> str:
        return digest_object({"rows": [r.to_dict() for r in self.rows],
                              "schema_version": EXPECTATION_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"dimensions": len(self.rows),
                "with_expectation": len(self.with_expectation()),
                "by_state": {s.value: len(self.in_state(s)) for s in CoverageState},
                "known_missing_total": sum(r.known_missing or 0
                                           for r in self.known_missing()),
                "self_certified": len(self.self_certified()),
                "over_counted": len(self.over_counted()),
                "overall_coverage": None,
                "bounds_completeness": False}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "coverage_ledger",
                "record_id": short_id("cov", self.digest()),
                **self.summary(), "rows": [r.to_dict() for r in self.rows]}

    def render(self) -> str:
        if not self.rows:
            return "No coverage dimensions were recorded."
        lines = [r.render() for r in self.rows]
        measured = self.with_expectation()
        lines.append(
            f"{len(measured)} of {len(self.rows)} dimension(s) have a denominator; "
            "no overall percentage is offered, because averaging the measurable ones "
            "would report confidence the unmeasured ones do not support")
        return "\n".join(lines)
