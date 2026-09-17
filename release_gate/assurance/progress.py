"""What changed since last time, so nobody rereads a case they have already read.

A frontier case does not get read twice. It gets read once and then *watched*,
and what a watcher needs is four sentences: the counts moved this way, these
things resolved and here is what resolved them, these things are new, and this is
what I can no longer see.

The state is already defined. §10l made the eleven questions machine-readable, so
the answer to "what changed" is the diff of those answers between two cases —
not a second definition of assurance state that would drift from the first.

## The lie this module exists to refuse

A row that was there and is gone now means one of two completely different things:

* the thing was **resolved** — the claim got verified, the contradiction was
  answered, the artifact was re-verified at its current digest; or
* the analysis **stopped running**, so the row is not gone, it is *invisible*.

Reporting the second as the first would manufacture progress out of a coverage
regression: "3 contradictions resolved" when contradiction detection simply did
not run this time is the most flattering possible way to describe getting worse.
So a query that goes `FOUND → NOT_ASSESSED` reports `lost_visibility`, never
`resolved`, and `AssuranceProgress.regressed` is true when it happens.

The mirror case matters too. `NOT_ASSESSED → FOUND` is not new breakage; it is
newly *visible* breakage that may have been there all along, and calling it
"introduced" would blame this run for what the last one could not see.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.query import QUERIES, QueryOutcome, QueryResult, run_all

PROGRESS_SCHEMA_VERSION = 1


class ProgressError(ValueError):
    """A comparison that cannot be made."""


#: How to identify "the same row" across two runs, per query. Without this, a
#: claim that gained a verification would read as one row vanishing and another
#: appearing, and every delta would be pure churn.
_ROW_KEY: Mapping[str, Tuple[str, ...]] = {
    "unverified_critical_claims": ("claim_id",),
    "blockers": ("rule_id", "reason"),
    "missing_evidence": ("requirement", "target"),
    "artifacts_changed_after_verification": ("logical_id",),
    "single_root_claims": ("claim_id",),
    "open_contradictions": ("contradiction_id",),
    "assumptions_affecting_result": ("assumption_id",),
    "unresolved_verifier_failures": ("verification_id",),
    "stale_approvals": ("approval_id",),
    "unknown_completeness_sources": ("stream_id",),
    "hold_resolution": ("requirement", "target"),
}

#: Queries that name a *thing* — a claim, a contradiction, an artifact. These are
#: itemised in the narrative because "C-184 now carries a passed verification" is
#: a fact a person can act on.
#:
#: The rest are derived views of the same facts: `blockers` restates the verdict,
#: `missing_evidence` and `hold_resolution` restate the findings underneath it.
#: Itemising them turned three real changes into nine lines, each a different
#: phrasing of the same three — which is exactly the rereading this module exists
#: to prevent. They still contribute counts, so the movement is visible without
#: the echo.
_ITEMISED: Tuple[str, ...] = (
    "unverified_critical_claims",
    "open_contradictions",
    "artifacts_changed_after_verification",
    "unresolved_verifier_failures",
    "single_root_claims",
    "assumptions_affecting_result",
    "stale_approvals",
    "unknown_completeness_sources",
)


#: What a row leaving this query means, in words a person reads. Per query,
#: because "gone" means something different for each: a critical claim leaving
#: `unverified_critical_claims` was verified; an artifact leaving
#: `artifacts_changed_after_verification` was re-verified at its current digest.
_RESOLUTION: Mapping[str, str] = {
    "unverified_critical_claims": "now carries a passed verification",
    "blockers": "no longer blocks",
    "missing_evidence": "the evidence arrived",
    "artifacts_changed_after_verification": "re-verified at its current digest",
    "single_root_claims": "a second independent producer now supports it",
    "open_contradictions": "contradiction resolved",
    "assumptions_affecting_result": "no longer load-bearing",
    "unresolved_verifier_failures": "the check no longer fails",
    "stale_approvals": "the approval binds again",
    "unknown_completeness_sources": "completeness is now checkable",
    "hold_resolution": "the evidence arrived",
}


def _key(query: str, row: Mapping[str, Any]) -> str:
    """Stable identity for a row across two runs.

    Joins only the key fields the row actually carries. `blockers` emits two row
    shapes — one with `rule_id`, one with `reason` — and joining both produced
    keys like `contradictions.resolved|` and `|contradictions.resolved: ...`,
    which read as two different things and diffed as churn.
    """
    fields = _ROW_KEY.get(query)
    if not fields:
        return repr(sorted(row.items()))
    parts = [str(row[f]) for f in fields if row.get(f)]
    if not parts:
        return repr(sorted(row.items()))
    return "|".join(parts)


@dataclass(frozen=True)
class QueryDelta:
    """How one question's answer changed."""

    query: str
    previous_outcome: QueryOutcome
    current_outcome: QueryOutcome
    resolved: Tuple[Mapping[str, Any], ...] = ()
    introduced: Tuple[Mapping[str, Any], ...] = ()
    persisting: Tuple[Mapping[str, Any], ...] = ()
    previous_count: int = 0
    current_count: int = 0

    def __post_init__(self) -> None:
        for name in ("previous_outcome", "current_outcome"):
            object.__setattr__(self, name, QueryOutcome(getattr(self, name)))
        for name in ("resolved", "introduced", "persisting"):
            object.__setattr__(self, name,
                               tuple(dict(r) for r in getattr(self, name)))

    @property
    def lost_visibility(self) -> bool:
        """The analysis stopped running. Rows did not resolve, they vanished."""
        return (self.previous_outcome is not QueryOutcome.NOT_ASSESSED
                and self.current_outcome is QueryOutcome.NOT_ASSESSED)

    @property
    def gained_visibility(self) -> bool:
        """The analysis started running. Anything it finds may be long-standing."""
        return (self.previous_outcome is QueryOutcome.NOT_ASSESSED
                and self.current_outcome is not QueryOutcome.NOT_ASSESSED)

    @property
    def changed(self) -> bool:
        return bool(self.resolved or self.introduced
                    or self.previous_outcome is not self.current_outcome)

    @property
    def improved(self) -> bool:
        """Strictly better: things resolved, nothing new, nothing lost from view."""
        return bool(self.resolved) and not self.introduced and not self.lost_visibility

    def headline(self) -> str:
        """The counted line, in the shape a watcher scans for."""
        if self.lost_visibility:
            return (f"{self.query}: {self.previous_count} → not assessed "
                    "(the analysis stopped running; these are invisible, not gone)")
        if self.gained_visibility:
            return (f"{self.query}: not assessed → {self.current_count} "
                    "(newly visible, and possibly long-standing)")
        return f"{self.query}: {self.previous_count} → {self.current_count}"

    def resolution_reason(self) -> str:
        return _RESOLUTION.get(self.query, "no longer reported")

    def to_dict(self) -> Dict[str, Any]:
        return {"query": self.query,
                "previous_outcome": self.previous_outcome.value,
                "current_outcome": self.current_outcome.value,
                "previous_count": self.previous_count,
                "current_count": self.current_count,
                "resolved": [dict(r) for r in self.resolved],
                "introduced": [dict(r) for r in self.introduced],
                "persisting": len(self.persisting),
                "lost_visibility": self.lost_visibility,
                "gained_visibility": self.gained_visibility,
                "improved": self.improved,
                "headline": self.headline(),
                "resolution_reason": self.resolution_reason()}


def diff_query(previous: QueryResult, current: QueryResult) -> QueryDelta:
    """Diff one query's answers. Identity comes from `_ROW_KEY`, not row equality.

    Row equality would make a claim that gained a verification look like one row
    vanishing and an unrelated one appearing, and every delta would be churn.
    """
    if previous.query != current.query:
        raise ProgressError(
            f"cannot diff {previous.query!r} against {current.query!r}")

    name = previous.query
    before = {_key(name, r): r for r in previous.rows}
    after = {_key(name, r): r for r in current.rows}

    lost = (previous.outcome is not QueryOutcome.NOT_ASSESSED
            and current.outcome is QueryOutcome.NOT_ASSESSED)
    gained = (previous.outcome is QueryOutcome.NOT_ASSESSED
              and current.outcome is not QueryOutcome.NOT_ASSESSED)

    # A row absent because nobody looked is not a row that resolved. This is the
    # whole point of the module, so it is a branch rather than a filter that
    # someone could later "simplify" away.
    resolved = () if lost else tuple(before[k] for k in sorted(set(before) - set(after)))
    introduced = tuple(after[k] for k in sorted(set(after) - set(before)))
    persisting = tuple(after[k] for k in sorted(set(before) & set(after)))

    return QueryDelta(query=name, previous_outcome=previous.outcome,
                      current_outcome=current.outcome, resolved=resolved,
                      introduced=introduced, persisting=persisting,
                      previous_count=len(previous.rows),
                      current_count=len(current.rows))


@dataclass(frozen=True)
class AssuranceProgress:
    """Every question's change between two readings of a case."""

    deltas: Mapping[str, QueryDelta] = field(default_factory=dict)
    previous_decision: str = ""
    current_decision: str = ""
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "deltas", dict(self.deltas))

    @property
    def changed(self) -> Tuple[QueryDelta, ...]:
        return tuple(d for d in self.deltas.values() if d.changed)

    @property
    def resolved(self) -> Tuple[Tuple[str, Mapping[str, Any]], ...]:
        """Named things that went away, from the queries that name things."""
        return tuple((d.query, row) for d in self.deltas.values()
                     if d.query in _ITEMISED for row in d.resolved)

    @property
    def introduced(self) -> Tuple[Tuple[str, Mapping[str, Any]], ...]:
        return tuple((d.query, row) for d in self.deltas.values()
                     if d.query in _ITEMISED for row in d.introduced)

    @property
    def resolved_everywhere(self) -> Tuple[Tuple[str, Mapping[str, Any]], ...]:
        """Including the derived views. For a consumer that wants the full diff."""
        return tuple((d.query, row) for d in self.deltas.values() for row in d.resolved)

    @property
    def lost_visibility(self) -> Tuple[QueryDelta, ...]:
        return tuple(d for d in self.deltas.values() if d.lost_visibility)

    @property
    def regressed(self) -> bool:
        """Something got worse, or something stopped being visible.

        Coverage going backwards counts. A case that can no longer see whether it
        has contradictions has not improved by losing the ability to tell.
        """
        return bool(self.introduced or self.lost_visibility
                    or (self.previous_decision == "PROMOTE"
                        and self.current_decision != "PROMOTE"))

    @property
    def quiet(self) -> bool:
        return not self.changed and self.previous_decision == self.current_decision

    def render(self) -> str:
        """The four sentences a watcher needs, and nothing else."""
        if self.quiet:
            return "No assurance-relevant state changed."
        lines: List[str] = []
        if self.previous_decision != self.current_decision:
            lines.append(f"Decision {self.previous_decision or 'none'} → "
                         f"{self.current_decision or 'none'}")
        for delta in self.changed:
            if delta.previous_count or delta.current_count or delta.lost_visibility:
                lines.append("  " + delta.headline())
        if self.resolved:
            lines.append(f"\nResolved ({len(self.resolved)}):")
            for query, row in self.resolved[:12]:
                identity = _key(query, row)
                lines.append(f"  {identity} — "
                             f"{_RESOLUTION.get(query, 'no longer reported')}")
        if self.introduced:
            lines.append(f"\nNew ({len(self.introduced)}):")
            for query, row in self.introduced[:12]:
                lines.append(f"  {_key(query, row)} — {query}")
        if self.lost_visibility:
            lines.append(f"\nNo longer visible ({len(self.lost_visibility)}):")
            for delta in self.lost_visibility:
                lines.append(f"  {delta.query} — the analysis stopped running, so "
                             f"its {delta.previous_count} finding(s) are invisible "
                             "rather than resolved")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_progress",
                "previous_decision": self.previous_decision,
                "current_decision": self.current_decision,
                "deltas": {k: v.to_dict() for k, v in self.deltas.items()},
                "resolved": [{"query": q, "row": dict(r)} for q, r in self.resolved],
                "introduced": [{"query": q, "row": dict(r)}
                               for q, r in self.introduced],
                "lost_visibility": [d.query for d in self.lost_visibility],
                "regressed": self.regressed, "quiet": self.quiet,
                "render": self.render(), "notes": list(self.notes),
                "schema_version": PROGRESS_SCHEMA_VERSION}


def _decision_of(outcome: Any) -> str:
    return str(getattr(getattr(outcome, "decision", None), "value", "")
               or getattr(outcome, "decision", "") or "")


def compare(previous: Any, current: Any, **kwargs: Any) -> AssuranceProgress:
    """What changed between two readings of a case.

    Both sides are swept with the same eleven queries, so the comparison is
    between like and like. A query that could not be answered on either side
    still appears — a watcher must see that a question went unanswered rather
    than find it missing and assume it did not apply.
    """
    if previous is None:
        raise ProgressError(
            "a delta needs something to compare against; a first reading has no "
            "previous state and should be reported as a first reading")
    before = run_all(previous, **kwargs)
    after = run_all(current, **kwargs)
    deltas = {name: diff_query(before[name], after[name]) for name in QUERIES}
    return AssuranceProgress(deltas=deltas,
                             previous_decision=_decision_of(previous),
                             current_decision=_decision_of(current))
