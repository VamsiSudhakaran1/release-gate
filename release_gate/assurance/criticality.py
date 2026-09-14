"""Criticality — what the human decision actually rests on.

A claim is critical when the decision being asked for depends on it. That is the
whole definition, and everything difficult about it follows from what the
definition *excludes*.

**Volume is never an input.** Not the number of agents that mentioned a claim,
not how many messages discussed it, not how much evidence piled up behind it, not
how central it looks in a graph drawing. A claim four hundred agents argued about
that the decision does not rest on is not critical. A claim one agent emitted
once, five links down a dependency chain, is critical if the conclusion falls
without it (Invariant 12).

**Depth is not a discount.** In `Decision -> A -> B -> C`, claim C is load-bearing
exactly as much as claim A. Nothing here decays with distance, and no threshold
stops the propagation at some depth. Distance from the conclusion is a fact worth
reporting to a reader and is never a weight.

**A label is not a dependency.** `Claim.criticality` is a string a producer set.
It is read, kept, and compared against what the graph says — but a producer
calling their own claim critical does not make the decision rest on it, and a
producer omitting the label does not make it stop resting on it (Invariant 1).
Where the two disagree, the disagreement is the finding.

**An empty critical set is not "nothing is critical".** This is the sharpest
refusal in the module, because the failure is silent. Every critical-claim guard
in this system — unresolved counterexamples, adversarial argument defects,
divergent replication, the contradiction `render_verdict` may not omit — asks
whether a claim is critical, and a case whose criticality could not be derived
would answer "no" to all of them and look clean for the worst possible reason.
So `determinable` is carried explicitly, `UNKNOWN` is a first-class answer, and a
case that cannot say what its decision rests on says so rather than passing.

Propagation is a single multi-source breadth-first walk from the decision's
claims over `depends_on`, which already unifies declared parents with declared
assumptions — an assumption the conclusion rests on is load-bearing in exactly
the sense this module means. Linear in claims and edges, iterative, and
cycle-safe, because a ten-thousand-deep chain is a legitimate input and a stack
overflow is not an analysis result.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Tuple)

from release_gate.assurance.canonical import digest_object, short_id

__all__ = [
    "CRITICALITY_SCHEMA_VERSION",
    "ClaimCriticality",
    "CriticalPath",
    "CriticalitySet",
    "DecisionLink",
    "LoadBearing",
    "analyse_criticality",
]

CRITICALITY_SCHEMA_VERSION = 1

#: A rendered path is a reading aid; the depth is the measurement. Long chains are
#: elided in the middle so a reader sees where a claim sits without ten thousand
#: ids, and `depth` still reports the real distance.
_PATH_RENDER_HEAD = 3
_PATH_RENDER_TAIL = 2

#: How many rendered paths a serialised set carries. Paths are reconstructed on
#: demand from the predecessor recorded on each entry rather than materialised
#: during propagation: holding every claim's full chain would cost the square of
#: the chain length, and a ten-thousand-link chain is a legitimate input.
_RENDERED_PATHS = 8


class LoadBearing(str, Enum):
    """What a thing holds up — derived from the dependency graph, never declared.

    Deliberately not a severity scale. "Load-bearing" is a fact: the conclusion
    the case is about falls if this does. Shared by claims and assumptions,
    because an assumption the decision rests on and a claim the decision rests on
    are the same kind of fact about the same graph, and two vocabularies for it
    would eventually disagree.
    """

    LOAD_BEARING = "LOAD_BEARING"  # the decision rests on it; a conclusion falls with it
    SUPPORTING = "SUPPORTING"      # other claims rest on it, but no conclusion does
    ISOLATED = "ISOLATED"          # nothing in this case rests on it
    UNKNOWN = "UNKNOWN"            # the graph cannot say


class DecisionLink(str, Enum):
    """How the decision's own claims were identified.

    Recorded because the three are not equally strong, and a reader deciding how
    much to trust a criticality set needs to know which one they are looking at.
    """

    DECLARED_ROOT = "DECLARED_ROOT"  # a producer flagged the conclusion claims
    GRAPH_SINK = "GRAPH_SINK"        # nothing depends on them, so they are conclusions
    NONE = "NONE"                    # neither; criticality cannot be derived


@dataclass(frozen=True)
class CriticalPath:
    """One chain from the decision to a claim.

    `depth` is reported and never used as a weight. It answers "how far from the
    conclusion is this?", which a reader wants, and not "how much does this
    matter?", which would be the volume error wearing a different hat.
    """

    claims: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "claims", tuple(self.claims))

    @property
    def depth(self) -> int:
        return max(0, len(self.claims) - 1)

    @property
    def origin(self) -> Optional[str]:
        return self.claims[0] if self.claims else None

    def render(self, decision: str = "decision") -> str:
        if not self.claims:
            return decision
        shown: Sequence[str] = self.claims
        if len(self.claims) > _PATH_RENDER_HEAD + _PATH_RENDER_TAIL + 1:
            shown = (list(self.claims[:_PATH_RENDER_HEAD])
                     + [f"... {len(self.claims) - _PATH_RENDER_HEAD - _PATH_RENDER_TAIL}"
                        " more ..."]
                     + list(self.claims[-_PATH_RENDER_TAIL:]))
        return " -> ".join([decision, *shown])

    def to_dict(self) -> Dict[str, Any]:
        return {"claims": list(self.claims), "depth": self.depth,
                "render": self.render()}


@dataclass(frozen=True)
class ClaimCriticality:
    """Where one claim stands relative to the decision."""

    claim_id: str
    standing: LoadBearing = LoadBearing.UNKNOWN
    via: Optional[str] = None
    depth: Optional[int] = None
    declared: Optional[str] = None
    supporting_records: int = 0
    supporting_producers: int = 0
    missing_dependencies: Tuple[str, ...] = ()
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "standing", LoadBearing(self.standing))
        object.__setattr__(self, "missing_dependencies",
                           tuple(sorted(set(self.missing_dependencies))))

    @property
    def critical(self) -> bool:
        """The one question every guard in the system asks."""
        return self.standing is LoadBearing.LOAD_BEARING

    @property
    def declared_critical(self) -> bool:
        """What a producer said, kept separate from what the graph says."""
        return str(self.declared or "").strip().upper() in ("CRITICAL", "HIGH",
                                                            "LOAD_BEARING")

    @property
    def disagrees_with_declaration(self) -> bool:
        """A producer called it critical and nothing the decision needs rests on it.

        Not resolved in either direction here. Either the label is wrong or the
        dependency edges are missing, and which of those is true is not something
        a graph can settle.
        """
        return self.declared_critical and not self.critical

    @property
    def thin(self) -> bool:
        """Load-bearing and resting on exactly one producer.

        Reported precisely *because* it is not a discount: a claim one agent
        emitted once is exactly as load-bearing as one four hundred agents
        discussed, and this flag exists so a reviewer sees the thinness rather
        than so the system can dock it (Invariant 12).

        Zero producers is deliberately not "thin". A load-bearing claim nobody
        supported is an unsupported claim, which the coverage analysers already
        report; folding it in here would blur a sharp signal into a common one.
        """
        return self.critical and self.supporting_producers == 1

    def to_dict(self) -> Dict[str, Any]:
        return {"claim_id": self.claim_id, "standing": self.standing.value,
                "critical": self.critical, "depth": self.depth,
                "declared": self.declared,
                "declared_critical": self.declared_critical,
                "disagrees_with_declaration": self.disagrees_with_declaration,
                # Recorded next to the verdict so the refusal is visible: these
                # numbers are outputs of the analysis and never inputs to it.
                "supporting_records": self.supporting_records,
                "supporting_producers": self.supporting_producers,
                "volume_affects_criticality": False,
                "missing_dependencies": list(self.missing_dependencies),
                "via": self.via, "basis": self.basis}

    def render(self) -> str:
        if not self.critical:
            return f"{self.claim_id}: {self.standing.value} — {self.basis}"
        route = f" via {self.via}" if self.via else " (the decision is about it)"
        return (f"{self.claim_id}: LOAD_BEARING at depth {self.depth}{route}"
                + ("; rests on a single producer" if self.thin else ""))


@dataclass(frozen=True)
class CriticalitySet:
    """What the decision rests on, and whether that could be established at all."""

    entries: Tuple[ClaimCriticality, ...] = ()
    decision_claims: Tuple[str, ...] = ()
    link: DecisionLink = DecisionLink.NONE
    unreachable_conclusions: Tuple[str, ...] = ()
    claims_examined: int = 0
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "link", DecisionLink(self.link))
        object.__setattr__(self, "decision_claims", tuple(sorted(self.decision_claims)))
        object.__setattr__(self, "unreachable_conclusions",
                           tuple(sorted(self.unreachable_conclusions)))

    @property
    def determinable(self) -> bool:
        """Whether criticality could be derived at all.

        Callers must consult this before reading `critical_ids` as an answer. An
        empty set from an undeterminable case means "we cannot say", and reading
        it as "nothing is critical" would silently disable every critical-claim
        guard in the system.
        """
        return self.link is not DecisionLink.NONE

    @property
    def critical_ids(self) -> frozenset:
        """The set every guard reads. Empty and undeterminable are not the same."""
        return frozenset(e.claim_id for e in self.entries if e.critical)

    def critical(self) -> Tuple[ClaimCriticality, ...]:
        return tuple(e for e in self.entries if e.critical)

    def of(self, claim_id: str) -> Optional[ClaimCriticality]:
        return next((e for e in self.entries if e.claim_id == claim_id), None)

    def path_to(self, claim_id: str) -> Optional[CriticalPath]:
        """The chain from the decision down to this claim, walked on demand.

        Reconstructed from each entry's `via` rather than stored, so propagation
        stays linear: a chain of ten thousand links costs ten thousand steps to
        walk once, and nothing at all for the claims nobody asks about. The
        visited guard is not decoration — a producer can declare a dependency
        cycle, and a walk that trusted the map would not terminate.
        """
        by_id = {e.claim_id: e for e in self.entries}
        entry = by_id.get(claim_id)
        if entry is None or not entry.critical:
            return None
        chain: List[str] = []
        seen: Set[str] = set()
        while entry is not None and entry.claim_id not in seen:
            seen.add(entry.claim_id)
            chain.append(entry.claim_id)
            entry = by_id.get(entry.via) if entry.via else None
        return CriticalPath(claims=tuple(reversed(chain)))

    def is_critical(self, claim_id: str) -> Optional[bool]:
        """`None` where criticality is undeterminable — never a bare False."""
        if not self.determinable:
            return None
        entry = self.of(claim_id)
        return bool(entry and entry.critical)

    def disagreements(self) -> Tuple[ClaimCriticality, ...]:
        return tuple(e for e in self.entries if e.disagrees_with_declaration)

    def thin(self) -> Tuple[ClaimCriticality, ...]:
        return tuple(e for e in self.entries if e.thin)

    def broken_chains(self) -> Tuple[ClaimCriticality, ...]:
        return tuple(e for e in self.entries
                     if e.critical and e.missing_dependencies)

    @property
    def max_depth(self) -> int:
        return max((e.depth or 0 for e in self.critical()), default=0)

    def digest(self) -> str:
        return digest_object({"entries": [e.to_dict() for e in self.entries],
                              "decision_claims": list(self.decision_claims),
                              "link": self.link.value,
                              "schema_version": CRITICALITY_SCHEMA_VERSION})

    @property
    def record_type(self) -> str:
        return "criticality"

    @property
    def record_id(self) -> str:
        return short_id("crit", self.digest())

    def summary(self) -> Dict[str, Any]:
        return {"determinable": self.determinable, "link": self.link.value,
                "decision_claims": list(self.decision_claims[:16]),
                "claims_examined": self.claims_examined,
                "critical": len(self.critical()),
                "max_depth": self.max_depth,
                "disagreements": len(self.disagreements()),
                "thin_critical": len(self.thin()),
                "broken_chains": len(self.broken_chains()),
                "unreachable_conclusions": len(self.unreachable_conclusions),
                "by_standing": {s.value: sum(1 for e in self.entries
                                             if e.standing is s)
                                for s in LoadBearing},
                # Stated in the record itself, not only in the docstring.
                "volume_affects_criticality": False,
                "basis": self.basis}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "criticality", "record_id": self.record_id,
                **self.summary(),
                "critical_ids": sorted(self.critical_ids)[:64],
                "critical_ids_truncated": max(0, len(self.critical_ids) - 64),
                "paths": [p.to_dict() for p in
                          (self.path_to(e.claim_id) for e in
                           self.critical()[:_RENDERED_PATHS]) if p is not None],
                "entries": [e.to_dict() for e in self.entries[:32]],
                "entries_truncated": max(0, len(self.entries) - 32),
                "schema_version": CRITICALITY_SCHEMA_VERSION}

    def render(self) -> str:
        if not self.determinable:
            return ("What this decision rests on could not be established, so no "
                    "claim here is known to be critical — which is not the same as "
                    "none being critical.\n  " + self.basis)
        lines = [f"The decision rests on {len(self.critical())} of "
                 f"{self.claims_examined} claim(s), by {self.link.value}"]
        for entry in self.critical()[:6]:
            route = self.path_to(entry.claim_id)
            lines.append(f"  {entry.claim_id}: LOAD_BEARING at depth {entry.depth}"
                         + (f" — {route.render()}" if route else "")
                         + ("; rests on a single producer" if entry.thin else ""))
        if self.thin():
            lines.append(f"  {len(self.thin())} load-bearing claim(s) rest on a "
                         "single producer; that is thinness, not unimportance")
        return "\n".join(lines)


# ── propagation ──────────────────────────────────────────────────────────────

def _decision_claims(claims: Mapping[str, Any]) -> Tuple[Tuple[str, ...], DecisionLink]:
    """What the decision is about: declared conclusions, or the graph's sinks.

    A declared root wins because a producer saying "this is what I am asking you
    to decide" is the closest thing to the decision itself that a case carries.
    Where nobody said, claims nothing depends on are the conclusions by
    construction. Where neither exists — every claim depends on another, which
    means a cycle — there is nothing to propagate from, and that is `NONE` rather
    than a guess.
    """
    declared = tuple(sorted(cid for cid, c in claims.items()
                            if getattr(c, "is_root", False)))
    if declared:
        return declared, DecisionLink.DECLARED_ROOT
    depended_on = {p for c in claims.values() for p in c.depends_on}
    sinks = tuple(sorted(cid for cid in claims if cid not in depended_on))
    if sinks:
        return sinks, DecisionLink.GRAPH_SINK
    return (), DecisionLink.NONE


def _propagate(claims: Mapping[str, Any], sources: Sequence[str]
               ) -> Tuple[Dict[str, int], Dict[str, Optional[str]]]:
    """Multi-source breadth-first walk from the decision over `depends_on`.

    One walk for all sources rather than one per source, so a case with four
    hundred conclusions costs the same as a case with one. Breadth-first, so the
    predecessor recorded for each claim is its shortest route from the decision —
    the one a reader should be shown. Iterative, because a ten-thousand-link
    chain must not become a stack overflow, and linear, because storing each
    claim's full chain instead of one predecessor would cost the square of the
    chain length.

    No depth limit and no decay. Reaching a claim at depth one and reaching it at
    depth five hundred are the same fact: the decision rests on it.
    """
    depth: Dict[str, int] = {}
    via: Dict[str, Optional[str]] = {}
    queue: deque = deque()

    for source in sources:
        if source in claims and source not in depth:
            depth[source] = 0
            via[source] = None
            queue.append(source)

    while queue:
        current = queue.popleft()
        claim = claims.get(current)
        if claim is None:
            continue
        for parent in claim.depends_on:
            # A claim already reached keeps its first (shortest) predecessor; a
            # cycle therefore terminates here rather than being followed round.
            if parent in depth:
                continue
            depth[parent] = depth[current] + 1
            via[parent] = current
            queue.append(parent)
    return depth, via


def analyse_criticality(claim_graph: Any, *,
                        evidence_producers: Optional[Mapping[str, str]] = None
                        ) -> CriticalitySet:
    """Derive what the requested decision rests on.

    `evidence_producers` maps evidence ids to producers, and is used only to
    report how thinly a load-bearing claim is supported. It never affects whether
    a claim is critical: that is settled entirely by the dependency graph, and
    passing a different set of producers must not change a single verdict here.
    """
    claims = {c.claim_id: c for c in getattr(claim_graph, "claims", ())} \
        if claim_graph is not None else {}
    if not claims:
        return CriticalitySet(
            link=DecisionLink.NONE,
            basis="this case declares no claims, so there is no dependency structure "
                  "in which criticality could be derived")

    sources, link = _decision_claims(claims)
    if link is DecisionLink.NONE:
        return CriticalitySet(
            claims_examined=len(claims), link=link,
            basis=(f"none of the {len(claims)} claim(s) is declared a conclusion and "
                   "every one is depended on by another, so nothing identifies what "
                   "this decision is being asked about; criticality is UNDETERMINED "
                   "rather than empty"))

    depth, via = _propagate(claims, sources)
    # Claims that hold something up without holding up a conclusion. Computed from
    # the same edges, so the two answers can never disagree about the graph.
    depended_on = {p for c in claims.values() for p in c.depends_on}
    producers = dict(evidence_producers or {})

    entries: List[ClaimCriticality] = []
    for claim_id, claim in sorted(claims.items()):
        reached = claim_id in depth
        support = tuple(getattr(claim, "supporting_evidence", ()) or ())
        distinct = {producers[e] for e in support if e in producers}
        missing = tuple(p for p in claim.depends_on if p not in claims)

        if reached:
            standing = LoadBearing.LOAD_BEARING
            basis = (f"the decision rests on this through {depth[claim_id]} "
                     "dependency link(s); distance does not reduce that")
        elif claim_id in depended_on:
            standing = LoadBearing.SUPPORTING
            basis = ("other claims rest on this, but nothing the decision is about "
                     "does")
        else:
            standing = LoadBearing.ISOLATED
            basis = "nothing in this case rests on this claim"

        entries.append(ClaimCriticality(
            claim_id=claim_id, standing=standing,
            via=via.get(claim_id), depth=depth.get(claim_id),
            declared=getattr(claim, "criticality", None),
            supporting_records=len(support),
            supporting_producers=len(distinct),
            missing_dependencies=missing, basis=basis))

    # Conclusions the decision's roots cannot reach. Where a producer declared one
    # root, a second genuine sink is a second conclusion nobody linked up, and
    # everything under it is outside every critical-claim guard.
    sinks = {cid for cid in claims if cid not in depended_on}
    unreachable = tuple(sorted(s for s in sinks if s not in depth))

    critical_count = sum(1 for e in entries if e.critical)
    return CriticalitySet(
        entries=tuple(entries), decision_claims=tuple(sources), link=link,
        unreachable_conclusions=unreachable, claims_examined=len(claims),
        basis=(f"{critical_count} of {len(claims)} claim(s) are reachable from "
               f"{len(sources)} decision claim(s) identified by "
               f"{link.value.lower().replace('_', ' ')}; reachability is the whole "
               "test, and no count of records, producers or messages enters it"))
