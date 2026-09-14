"""Assumptions, and what falls over if one of them is wrong.

Every argument rests on things nobody checked. Usually they are fine. The danger
is not that assumptions exist — it is that they are invisible, so a reviewer
approving a conclusion has no way to ask the only question that matters about
them:

> If this assumption fails, what conclusions collapse?

This module answers that by computation rather than by narrative. An assumption's
**criticality is its collapse set**: load-bearing means a root conclusion falls
with it, supporting means other claims do, isolated means nothing does. That is
derived from the graph, not a severity scale someone invented — which is the only
way it can be trusted to mean the same thing twice.

An assumption is not a new kind of record. `ClaimType.ASSUMPTION` already exists
and `Claim.depends_on` already folds `assumptions` in beside `parents`, so status
already propagates through them. What was missing was the *view*: which claims
rest on each assumption, and what happens to them if it gives way.

The case this module cares most about is the one the claim graph could not see at
all. A claim that says "this rests on X" where X is nowhere described yields an
`Assumption` with `stated=False` — because an assumption nobody wrote down is the
hardest kind to evaluate and the easiest kind to miss.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.claims import Claim, ClaimGraph, ClaimProvenance, ClaimStatus

__all__ = [
    "ASSUMPTION_SCHEMA_VERSION",
    "Assumption",
    "AssumptionCriticality",
    "AssumptionGraph",
    "AssumptionSource",
    "CollapseSet",
]

ASSUMPTION_SCHEMA_VERSION = 1


class AssumptionCriticality(str, Enum):
    """What an assumption holds up — derived from its collapse set, never declared.

    This is deliberately not a severity scale. "Load-bearing" is a fact about the
    graph: the conclusion the case is about falls if this assumption does.
    """

    LOAD_BEARING = "LOAD_BEARING"  # a root conclusion collapses with it
    SUPPORTING = "SUPPORTING"      # other claims collapse, but no conclusion
    ISOLATED = "ISOLATED"          # nothing in this case rests on it
    UNKNOWN = "UNKNOWN"            # the graph cannot say


@dataclass(frozen=True)
class AssumptionSource:
    """Where an assumption came from, and whether anyone actually wrote it down."""

    producer_id: str = ""
    provenance: str = ClaimProvenance.DECLARED.value
    model_extracted: Optional[str] = None
    stated: bool = True

    @property
    def attributable(self) -> bool:
        return bool(self.producer_id.strip())

    def to_dict(self) -> Dict[str, Any]:
        return {"producer_id": self.producer_id, "provenance": self.provenance,
                "model_extracted": self.model_extracted, "stated": self.stated,
                "attributable": self.attributable}

    @classmethod
    def unstated(cls, referenced_by: str) -> "AssumptionSource":
        """An assumption named by a claim and described nowhere."""
        return cls(producer_id="", provenance=ClaimProvenance.DECLARED.value,
                   stated=False)


@dataclass(frozen=True)
class CollapseSet:
    """What falls over if one assumption does. The reviewer's question, answered."""

    assumption_id: str
    direct: Tuple[str, ...] = ()
    transitive: Tuple[str, ...] = ()
    roots_affected: Tuple[str, ...] = ()
    verified_among_collapsed: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "direct", tuple(sorted(set(self.direct))))
        object.__setattr__(self, "transitive", tuple(sorted(set(self.transitive))))
        object.__setattr__(self, "roots_affected", tuple(sorted(set(self.roots_affected))))
        object.__setattr__(self, "verified_among_collapsed",
                           tuple(sorted(set(self.verified_among_collapsed))))

    @property
    def all(self) -> Tuple[str, ...]:
        return tuple(sorted(set(self.direct) | set(self.transitive)))

    @property
    def size(self) -> int:
        return len(self.all)

    @property
    def conclusion_collapses(self) -> bool:
        return bool(self.roots_affected)

    def to_dict(self) -> Dict[str, Any]:
        return {"assumption_id": self.assumption_id, "direct": list(self.direct),
                "transitive": list(self.transitive), "all": list(self.all),
                "size": self.size, "roots_affected": list(self.roots_affected),
                "conclusion_collapses": self.conclusion_collapses,
                "verified_among_collapsed": list(self.verified_among_collapsed)}


@dataclass(frozen=True)
class Assumption:
    """One thing the argument takes for granted, and what rests on it."""

    assumption_id: str
    statement: str = ""
    source: AssumptionSource = field(default_factory=AssumptionSource)
    dependent_claims: Tuple[str, ...] = ()
    supporting_evidence: Tuple[str, ...] = ()
    verification: Tuple[Any, ...] = ()
    status: ClaimStatus = ClaimStatus.UNKNOWN
    criticality: AssumptionCriticality = AssumptionCriticality.UNKNOWN
    declared_criticality: Optional[str] = None
    collapse: Optional[CollapseSet] = None
    referenced_by: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ClaimStatus(self.status))
        object.__setattr__(self, "criticality", AssumptionCriticality(self.criticality))
        for name in ("dependent_claims", "supporting_evidence", "referenced_by"):
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        object.__setattr__(self, "verification", tuple(self.verification))

    @property
    def stated(self) -> bool:
        """Did anyone actually write this assumption down?"""
        return self.source.stated

    @property
    def load_bearing(self) -> bool:
        return self.criticality is AssumptionCriticality.LOAD_BEARING

    @property
    def checked(self) -> bool:
        """Is there anything at all bearing on whether it holds?"""
        return bool(self.supporting_evidence) or bool(self.verification)

    @property
    def unexamined(self) -> bool:
        """Load-bearing and nothing has looked at it. The sharp case."""
        return self.load_bearing and not self.checked

    # CaseRecord protocol.
    @property
    def record_type(self) -> str:
        return "assumption"

    @property
    def record_id(self) -> str:
        return self.assumption_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "assumption",
            "record_id": self.assumption_id,
            "assumption_id": self.assumption_id,
            "statement": self.statement,
            "source": self.source.to_dict(),
            "dependent_claims": list(self.dependent_claims),
            "supporting_evidence": list(self.supporting_evidence),
            "verification": [v.to_dict() if hasattr(v, "to_dict") else str(v)
                             for v in self.verification],
            "status": self.status.value,
            "criticality": self.criticality.value,
            "declared_criticality": self.declared_criticality,
            "collapse": self.collapse.to_dict() if self.collapse else None,
            "stated": self.stated,
            "checked": self.checked,
            "referenced_by": list(self.referenced_by),
            "schema_version": ASSUMPTION_SCHEMA_VERSION,
        }

    def explain(self) -> str:
        """The answer to the question, in the form a reviewer asks it."""
        lines = [f"{self.assumption_id}  [{self.status.value}]  "
                 f"{self.criticality.value}"]
        if self.statement:
            lines.append(f"    \"{self.statement}\"")
        if not self.stated:
            lines.append("    NOT STATED: referenced by "
                         f"{', '.join(self.referenced_by)} and described nowhere")
        if not self.checked:
            lines.append("    nothing bears on whether this holds")
        collapse = self.collapse
        if collapse is None or not collapse.size:
            lines.append("    If it fails: nothing in this case rests on it.")
            return "\n".join(lines)
        lines.append(f"    If it fails, {collapse.size} claim(s) collapse:")
        if collapse.direct:
            lines.append(f"      directly:     {', '.join(collapse.direct)}")
        if collapse.transitive:
            lines.append(f"      and then:     {', '.join(collapse.transitive)}")
        if collapse.conclusion_collapses:
            lines.append(f"      THE CONCLUSION FALLS: "
                         f"{', '.join(collapse.roots_affected)}")
        if collapse.verified_among_collapsed:
            lines.append(
                f"      note: {', '.join(collapse.verified_among_collapsed)} also carry "
                "their own verification; whether they survive this assumption failing "
                "is a judgement release-gate cannot make")
        return "\n".join(lines)


class AssumptionGraph:
    """Every assumption in a case, and what each holds up."""

    def __init__(self, assumptions: Iterable[Assumption] = ()) -> None:
        held = list(assumptions)
        held.sort(key=lambda a: (_CRITICALITY_ORDER[a.criticality],
                                 -(a.collapse.size if a.collapse else 0),
                                 a.assumption_id))
        self._held: Tuple[Assumption, ...] = tuple(held)
        self._by_id = {a.assumption_id: a for a in self._held}

    def __iter__(self):
        return iter(self._held)

    def __len__(self) -> int:
        return len(self._held)

    @property
    def assumptions(self) -> Tuple[Assumption, ...]:
        return self._held

    def assumption(self, assumption_id: str) -> Optional[Assumption]:
        return self._by_id.get(assumption_id)

    def of_criticality(self, criticality: AssumptionCriticality
                       ) -> Tuple[Assumption, ...]:
        wanted = AssumptionCriticality(criticality)
        return tuple(a for a in self._held if a.criticality is wanted)

    def load_bearing(self) -> Tuple[Assumption, ...]:
        return self.of_criticality(AssumptionCriticality.LOAD_BEARING)

    def unstated(self) -> Tuple[Assumption, ...]:
        """Named by a claim, described nowhere."""
        return tuple(a for a in self._held if not a.stated)

    def unexamined(self) -> Tuple[Assumption, ...]:
        """Load-bearing, and nothing has looked at whether it holds."""
        return tuple(a for a in self._held if a.unexamined)

    def collapse(self, assumption_id: str) -> Optional[CollapseSet]:
        found = self._by_id.get(assumption_id)
        return found.collapse if found else None

    def explain(self, assumption_id: Optional[str] = None) -> str:
        if assumption_id is not None:
            found = self._by_id.get(assumption_id)
            return found.explain() if found else f"{assumption_id}: not an assumption "\
                                                 "in this case"
        if not self._held:
            return "No assumptions recorded."
        return "\n".join(a.explain() for a in self._held)

    def digest(self) -> str:
        return digest_object({"assumptions": [a.to_dict() for a in self._held],
                              "schema_version": ASSUMPTION_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self._held),
                "load_bearing": len(self.load_bearing()),
                "unstated": len(self.unstated()),
                "unexamined": len(self.unexamined()),
                "by_criticality": {c.value: len(self.of_criticality(c))
                                   for c in AssumptionCriticality},
                "by_status": {s.value: sum(1 for a in self._held if a.status is s)
                              for s in ClaimStatus},
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(), "detail": [a.to_dict() for a in self._held]}

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_claim_graph(cls, graph: Optional[ClaimGraph]) -> "AssumptionGraph":
        """Derive every assumption and its collapse set from the claim graph."""
        if graph is None or not graph.claims:
            return cls()

        claims = {c.claim_id: c for c in graph.claims}
        root_ids = {c.claim_id for c in graph.roots()}

        # Who rests on whom. `depends_on` already folds assumptions in beside
        # parents, so one index serves both.
        dependents: Dict[str, Set[str]] = {}
        for claim in graph.claims:
            for parent in claim.depends_on:
                dependents.setdefault(parent, set()).add(claim.claim_id)

        # Every id anyone called an assumption, plus every claim typed as one.
        named: Dict[str, Set[str]] = {}
        for claim in graph.claims:
            for assumption_id in claim.assumptions:
                named.setdefault(assumption_id, set()).add(claim.claim_id)
        identifiers = set(named) | {c.claim_id for c in graph.assumptions()}

        built: List[Assumption] = []
        for assumption_id in sorted(identifiers):
            claim = claims.get(assumption_id)
            collapse = _collapse_from(assumption_id, dependents, claims, root_ids)
            built.append(_assume(assumption_id, claim, collapse,
                                 referenced_by=named.get(assumption_id, set()),
                                 status=(graph.status(assumption_id) if claim
                                         else ClaimStatus.UNKNOWN)))
        return cls(built)


_CRITICALITY_ORDER = {
    AssumptionCriticality.LOAD_BEARING: 0,
    AssumptionCriticality.SUPPORTING: 1,
    AssumptionCriticality.ISOLATED: 2,
    AssumptionCriticality.UNKNOWN: 3,
}


def _collapse_from(assumption_id: str, dependents: Mapping[str, Set[str]],
                   claims: Mapping[str, Claim], root_ids: Set[str]) -> CollapseSet:
    """Breadth-first over what rests on this, and what rests on that.

    A claim that names an assumption declared that it depends on it, so it
    collapses; anything depending on that collapses in turn. release-gate does not
    try to work out whether a claim might survive its assumption failing — that is
    a domain judgement. Where a collapsing claim carries its own verification, it
    is flagged for exactly that judgement rather than quietly excused.

    Cycle-safe: a claim already seen is not expanded again.
    """
    direct = set(dependents.get(assumption_id, set()))
    seen: Set[str] = set(direct)
    frontier = list(direct)
    while frontier:
        current = frontier.pop()
        for child in dependents.get(current, set()):
            if child not in seen and child != assumption_id:
                seen.add(child)
                frontier.append(child)

    transitive = seen - direct
    verified = {cid for cid in seen
                if cid in claims and claims[cid].verification_attempts}
    return CollapseSet(assumption_id=assumption_id, direct=tuple(direct),
                       transitive=tuple(transitive),
                       roots_affected=tuple(seen & root_ids),
                       verified_among_collapsed=tuple(verified))


def _assume(assumption_id: str, claim: Optional[Claim], collapse: CollapseSet,
            *, referenced_by: Set[str], status: ClaimStatus) -> Assumption:
    if claim is None:
        # Named by somebody, described by nobody. The hardest kind to evaluate and
        # the easiest to miss, so it is materialised rather than skipped.
        source = AssumptionSource.unstated(", ".join(sorted(referenced_by)))
        statement = ""
        evidence: Tuple[str, ...] = ()
        attempts: Tuple[Any, ...] = ()
        declared = None
    else:
        source = AssumptionSource(
            producer_id=claim.producer.producer_id if claim.producer else "",
            provenance=claim.provenance.value,
            model_extracted=claim.extracted_by_model, stated=True)
        statement = claim.statement
        evidence = claim.supporting_evidence
        attempts = claim.verification_attempts
        declared = claim.criticality

    if collapse.conclusion_collapses:
        criticality = AssumptionCriticality.LOAD_BEARING
    elif collapse.size:
        criticality = AssumptionCriticality.SUPPORTING
    elif claim is not None or referenced_by:
        criticality = AssumptionCriticality.ISOLATED
    else:
        criticality = AssumptionCriticality.UNKNOWN

    return Assumption(
        assumption_id=assumption_id, statement=statement, source=source,
        dependent_claims=collapse.direct, supporting_evidence=evidence,
        verification=attempts, status=status, criticality=criticality,
        declared_criticality=declared, collapse=collapse,
        referenced_by=tuple(referenced_by))
