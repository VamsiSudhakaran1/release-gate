"""Human Attention Compression — how much a person does not have to read.

    10,258 evidence records observed
     2,420 claims held
        48 critical claims derived
    ────────
        13 human review items, of which 7 may never be dropped

**This is not a safety metric, and the refusals below say so unconditionally.**
It measures one thing: the reduction between what arrived and what a person is
asked to look at. It says nothing about whether the case is sound, whether the
evidence is sufficient, or whether a bigger number is better — and a metric this
shaped invites all three misreadings, which is why each is refused as a property
rather than discouraged in prose.

**A larger ratio is not a better case.** It can mean the argument narrowed
cleanly; it can equally mean detection got worse. Invariant 6 — scale is not
confidence — applies directly, so `retained_critical` sits beside the number
always and is never itself compressed.

**Every stage carries its basis, because two of the obvious numbers are not
ours.** The frontier scenario *declares* 2,184,992 events and 91,481 claims; the
case observed no execution graph and holds 2,420 claims. Printing the declared
figures as release-gate's own would launder a producer's self-report into our
voice, which is Invariant 1 and precisely what §10ah settled for timestamps. So a
stage says whether its count was OBSERVED by release-gate, DECLARED by somebody
else, or NOT_ASSESSED — and a `DECLARED` stage is visibly declared wherever the
funnel is shown.

**A stage with no number yields no ratio.** On the single-agent demo criticality
is `UNDETERMINABLE`; a metric printing `0 critical claims` there would assert
zero where the truth is that it cannot be derived. `ratio` returns `None` in that
case rather than a figure computed over a gap (Invariant 3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple

__all__ = [
    "COMPRESSION_SCHEMA_VERSION",
    "Basis",
    "CompressionError",
    "FunnelStage",
    "HumanAttentionCompression",
    "measure_compression",
]

COMPRESSION_SCHEMA_VERSION = 1


class CompressionError(ValueError):
    """A funnel stage that cannot be counted honestly."""


class Basis(str, Enum):
    """Who established a stage's count.

    The distinction the metric turns on. `DECLARED` is not a lesser number — a
    CI plan's job count is often the only denominator there is — but it is
    somebody else's number, and a funnel that hid that would be release-gate
    reporting a producer's self-report as an observation.
    """

    OBSERVED = "OBSERVED"          # release-gate counted it
    DECLARED = "DECLARED"          # somebody else stated it
    NOT_ASSESSED = "NOT_ASSESSED"  # nobody established it


@dataclass(frozen=True)
class FunnelStage:
    """One rung of the funnel: how many of what, and who says so."""

    name: str
    #: `None` where nothing established a count. Not zero — zero is a claim.
    count: Optional[int]
    basis: Basis
    #: What the count is a count *of*, in the words a reader needs.
    of: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "basis", Basis(self.basis))
        if self.count is not None and self.count < 0:
            raise CompressionError(f"{self.name}: a stage cannot hold {self.count}")
        if self.basis is Basis.NOT_ASSESSED and self.count is not None:
            raise CompressionError(
                f"{self.name}: a stage nobody assessed cannot also carry a count "
                f"of {self.count}. If something established it, say who")
        if self.basis is not Basis.NOT_ASSESSED and self.count is None:
            raise CompressionError(
                f"{self.name}: basis {self.basis.value} claims somebody counted "
                "this, so it needs a count")

    @property
    def known(self) -> bool:
        return self.count is not None

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "funnel_stage", "record_id": self.name,
                "name": self.name, "count": self.count,
                "basis": self.basis.value, "of": self.of, "detail": self.detail}

    def render(self) -> str:
        shown = f"{self.count:,}" if self.known else "not assessed"
        mark = "" if self.basis is Basis.OBSERVED else f" [{self.basis.value}]"
        return f"{shown:>12}  {self.of or self.name}{mark}"


@dataclass(frozen=True)
class HumanAttentionCompression:
    """What arrived, what a person is asked to read, and what may never be cut."""

    stages: Tuple[FunnelStage, ...] = ()
    review_items: int = 0
    #: Items no compression may omit — blocking, or on the critical path. Beside
    #: the ratio always, because the one dangerous misreading of this metric is
    #: that a bigger number is a better case.
    retained_critical: int = 0
    #: The ids of those items, so "7 retained" can be opened rather than trusted.
    retained_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "stages", tuple(self.stages))
        object.__setattr__(self, "retained_ids", tuple(self.retained_ids))
        if self.retained_critical > self.review_items:
            raise CompressionError(
                f"{self.retained_critical} retained critical item(s) but only "
                f"{self.review_items} review item(s): the retained set is a "
                "subset of what is shown, and a count that exceeds it means "
                "something was dropped that should not have been")

    # ── the refusals ────────────────────────────────────────────────────────

    @property
    def is_a_safety_metric(self) -> bool:
        """No. It measures reading volume, not whether anything is safe.

        The brief that introduced it said so, and saying so in a docstring is
        weaker than saying so in a property that cannot return anything else.
        """
        return False

    @property
    def establishes_sufficiency(self) -> bool:
        """No. Four items may be four adequate reviews or four of forty needed."""
        return False

    @property
    def higher_is_better(self) -> bool:
        """No, and this is the one that would do damage.

        A larger ratio can mean the argument narrowed cleanly or that detection
        got worse, and nothing in the number tells them apart. Optimising it is
        optimising for a shorter list, which is available by finding less
        (Invariant 6).
        """
        return False

    @property
    def is_comparable_across_cases(self) -> bool:
        """No. Two cases with different subjects have different denominators."""
        return False

    # ── the number ──────────────────────────────────────────────────────────

    @property
    def widest_known_stage(self) -> Optional[FunnelStage]:
        """The largest stage anybody established a count for."""
        known = [s for s in self.stages if s.known]
        return max(known, key=lambda s: s.count or 0) if known else None

    @property
    def ratio(self) -> Optional[float]:
        """Records per review item, or `None`.

        `None` where no stage has a count — a ratio computed over a gap would
        put a number on something nobody measured, and a reader would take the
        number rather than the gap.
        """
        widest = self.widest_known_stage
        if widest is None or not self.review_items:
            return None
        return round((widest.count or 0) / self.review_items, 1)

    @property
    def basis_of_ratio(self) -> Optional[str]:
        """Which stage the ratio was taken over, and on whose authority.

        Reported because a ratio over a `DECLARED` stage is a different claim
        from one over an `OBSERVED` stage, and the figure alone does not say
        which it is.
        """
        widest = self.widest_known_stage
        if widest is None:
            return None
        return f"{widest.count:,} {widest.of or widest.name} ({widest.basis.value})"

    @property
    def unassessed_stages(self) -> Tuple[str, ...]:
        return tuple(s.name for s in self.stages if not s.known)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "human_attention_compression",
                "record_id": "compression",
                "schema_version": COMPRESSION_SCHEMA_VERSION,
                "stages": [s.to_dict() for s in self.stages],
                "review_items": self.review_items,
                "retained_critical": self.retained_critical,
                "retained_ids": list(self.retained_ids),
                "ratio": self.ratio, "basis_of_ratio": self.basis_of_ratio,
                "unassessed_stages": list(self.unassessed_stages),
                "is_a_safety_metric": self.is_a_safety_metric,
                "establishes_sufficiency": self.establishes_sufficiency,
                "higher_is_better": self.higher_is_better,
                "is_comparable_across_cases": self.is_comparable_across_cases}

    def render(self) -> str:
        lines = ["HUMAN ATTENTION COMPRESSION"]
        lines += [f"  {s.render()}" for s in self.stages]
        lines.append("  " + "─" * 12)
        lines.append(f"  {self.review_items:>12}  human review items")
        lines.append(f"  {self.retained_critical:>12}  of those may never be "
                     "dropped (blocking, or on the critical path)")
        if self.ratio is not None:
            lines.append(f"\n  {self.ratio:,.1f} records per review item, over "
                         f"{self.basis_of_ratio}")
        else:
            lines.append("\n  no ratio: " + (
                "nothing established a count to take one over"
                if self.widest_known_stage is None else
                "there are no review items to divide by"))
        if self.unassessed_stages:
            lines.append("  not assessed: " + ", ".join(self.unassessed_stages))
        lines.append("\n  This is a measure of reading volume. It is not a safety "
                     "metric, it does not")
        lines.append("  establish sufficiency, and a larger number is not a "
                     "better case.")
        return "\n".join(lines)


# ── reading the funnel off a decided outcome ─────────────────────────────────

def _collection_stage(case: Any, kind: str, of: str) -> FunnelStage:
    """One collection's count, with the basis it already records.

    `MaterialisationBasis` was there before this metric existed and already says
    whether a collection holds everything it saw. A `SUMMARY_ONLY` collection
    counted records it did not keep, which is still release-gate's own count —
    so the basis here is about *who counted*, not about what was retained, and
    the retention detail rides along in `detail` rather than being conflated with
    it.
    """
    from release_gate.assurance.records import Presence
    collection = case.collection(kind)
    if collection.presence is not Presence.PRESENT:
        return FunnelStage(name=kind, count=None, basis=Basis.NOT_ASSESSED, of=of,
                           detail=f"the {kind} collection was never supplied, so "
                                  "nothing counted them")
    return FunnelStage(
        name=kind, count=collection.total_count, basis=Basis.OBSERVED, of=of,
        detail=f"counted at ingest; {len(collection.materialised):,} held, "
               f"basis {collection.basis.value}")


def _declared_count(outcome: Any, dimension: str) -> Optional[Tuple[int, str]]:
    """A count somebody else stated for this dimension, and who stated it.

    Read off the coverage ledger, where a declared denominator already lives with
    its `ExpectationSource`. Without this the `DECLARED` basis would be
    unreachable — a distinction the whole module is built on, present only in an
    enum nothing could produce, which is its own kind of dishonesty.
    """
    ledger = getattr(outcome.analysis, "coverage_ledger", None)
    row = ledger.of(dimension) if ledger is not None else None
    if row is None or row.expected is None:
        return None
    source = getattr(row, "source", None)
    who = getattr(source, "declared_by", "") or "an unnamed party"
    standing = getattr(getattr(row, "standing", None), "value", "UNKNOWN")
    return int(row.expected), f"declared by {who} ({standing})"


def _execution_stage(outcome: Any) -> FunnelStage:
    """Events, which is the stage most likely to be quoted and least often ours.

    A scenario that declares two million events and supplies no trace has told
    release-gate a number, not shown it one. That reads `NOT_ASSESSED` here, and
    the difference between "two million events" and "no execution record" is the
    whole reason this stage carries a basis at all.
    """
    graph = getattr(outcome.analysis, "execution_graph", None)
    if graph is None:
        declared = _declared_count(outcome, "events")
        if declared is not None:
            count, who = declared
            return FunnelStage(
                name="events", count=count, basis=Basis.DECLARED,
                of="events", detail=who + "; release-gate observed none of them, "
                                         "so this is their number and not ours")
        return FunnelStage(
            name="events", count=None, basis=Basis.NOT_ASSESSED, of="events",
            detail="no execution graph was reconstructed and nothing declared a "
                   "count, so release-gate observed no events; a count stated "
                   "outside the case is not one it can report as its own")
    nodes = len(getattr(graph, "nodes", ()) or ())
    return FunnelStage(
        name="events", count=nodes, basis=Basis.OBSERVED,
        of="execution steps observed",
        detail=f"nodes in the reconstructed execution graph; completeness "
               f"{graph.completeness.status.value}")


def _critical_stage(outcome: Any) -> FunnelStage:
    """Critical claims, or the honest absence of a number.

    `CriticalitySet.determinable` is false when reachability could not be
    derived, and printing `0` there would assert that nothing is critical. That
    is the single most damaging number this funnel could produce, because it is
    the stage a reader scans for reassurance.
    """
    criticality = getattr(outcome.analysis, "criticality", None)
    if criticality is None or not criticality.determinable:
        return FunnelStage(
            name="critical_claims", count=None, basis=Basis.NOT_ASSESSED,
            of="critical claims",
            detail="criticality could not be derived for this case, so how many "
                   "claims the decision rests on is unknown — which is not zero")
    return FunnelStage(
        name="critical_claims", count=len(criticality.critical_ids),
        basis=Basis.OBSERVED, of="critical claims",
        detail="claims the decision was found to rest on, by reachability")


def measure_compression(outcome: Any) -> HumanAttentionCompression:
    """Read the funnel off a decided outcome. Counts nothing new.

    Every number here already exists on the case or the analysis. This assembles
    them, attaches the basis each one already had, and refuses to compute a ratio
    where a stage has none.
    """
    verdict = getattr(outcome.case, "verdict", None)
    if verdict is None:
        raise CompressionError(
            "this case has not been decided, so there is no review list to "
            "compress toward. A funnel over an open case measures a work in "
            "progress and reads as a result")

    stages = (
        _execution_stage(outcome),
        _collection_stage(outcome.case, "evidence", "evidence records"),
        _collection_stage(outcome.case, "claims", "claims"),
        _critical_stage(outcome),
    )
    items = list(outcome.attention.items)
    retained = [i for i in items if i.undroppable]
    return HumanAttentionCompression(
        stages=stages, review_items=len(items),
        retained_critical=len(retained),
        retained_ids=tuple(i.item_id for i in retained))
