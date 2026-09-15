"""The eleven questions, answered from the case rather than recomputed.

Every query here reads an analysis the engine already performed. None of them
re-derives criticality, re-detects contradictions or re-walks the artifact graph,
because a query that computed its own answer would eventually disagree with the
verdict that was actually rendered — and a reviewer would have two numbers and no
way to tell which one the gate used.

**Every answer can say it does not know.** A query returning an empty list means
one of two things and must never be allowed to blur them: *nothing matched*, or
*the analysis this question needs was never performed*. `RESOLVED` and
`NOT_ASSESSED` are different outcomes, and "which critical claims are unverified"
answering "none" on a case where criticality could not be derived would be the
most comfortable lie this system could tell.

**Answers are data.** Each result carries typed rows, the source it read, and a
sentence a person can act on. Nothing here formats a report; the packet does
that, and it does it from the same analyses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

QUERY_SCHEMA_VERSION = 1


class QueryError(ValueError):
    """A query that cannot be run against what was supplied."""


class QueryOutcome(str, Enum):
    """Whether the question was answered, and if not, why not."""

    #: The question was asked and nothing matched. A real, load-bearing answer.
    NONE_FOUND = "NONE_FOUND"
    #: The question was asked and these are the matches.
    FOUND = "FOUND"
    #: The analysis this question needs was never performed, so the answer is
    #: unknown rather than empty.
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True)
class QueryResult:
    """One answer: what matched, what it was read from, and what it means."""

    query: str
    outcome: QueryOutcome
    rows: Tuple[Mapping[str, Any], ...] = ()
    source: str = ""
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", QueryOutcome(self.outcome))
        object.__setattr__(self, "rows", tuple(dict(r) for r in self.rows))

    def __len__(self) -> int:
        return len(self.rows)

    def __bool__(self) -> bool:
        """True when something matched. NOT_ASSESSED is falsey but not empty.

        Deliberate: `if result:` reads as "is there a problem here", and an
        unassessed question has not shown one. Callers that must distinguish it
        read `outcome`, and `answered` exists so they do not have to remember to.
        """
        return self.outcome is QueryOutcome.FOUND

    @property
    def answered(self) -> bool:
        return self.outcome is not QueryOutcome.NOT_ASSESSED

    def note(self) -> str:
        if self.outcome is QueryOutcome.NOT_ASSESSED:
            return (f"{self.query}: not assessed — {self.basis}. This is unknown, "
                    "not none.")
        if self.outcome is QueryOutcome.NONE_FOUND:
            return f"{self.query}: none, from {self.source}. {self.basis}".strip()
        return f"{self.query}: {len(self.rows)} — {self.basis}".strip()

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_query", "query": self.query,
                "outcome": self.outcome.value, "answered": self.answered,
                "count": len(self.rows), "rows": [dict(r) for r in self.rows],
                "source": self.source, "basis": self.basis, "note": self.note(),
                "schema_version": QUERY_SCHEMA_VERSION}


def _found(query: str, rows: Sequence[Mapping[str, Any]], *, source: str,
           basis: str = "", empty_basis: str = "") -> QueryResult:
    rows = list(rows)
    if rows:
        return QueryResult(query, QueryOutcome.FOUND, tuple(rows), source, basis)
    return QueryResult(query, QueryOutcome.NONE_FOUND, (), source,
                       empty_basis or basis)


def _unknown(query: str, basis: str, *, source: str = "") -> QueryResult:
    return QueryResult(query, QueryOutcome.NOT_ASSESSED, (), source, basis)


def _criticality(outcome: Any) -> Any:
    return getattr(outcome, "criticality", None)


# ── the eleven ──────────────────────────────────────────────────────────────

def unverified_critical_claims(outcome: Any) -> QueryResult:
    """Which critical claims remain unverified?"""
    name = "unverified_critical_claims"
    criticality = _criticality(outcome)
    if criticality is None or not getattr(criticality, "determinable", False):
        return _unknown(name, "what this decision rests on could not be derived, "
                              "so which of those claims is unverified cannot be "
                              "asked", source="criticality")
    verified = set()
    graph = getattr(outcome, "verification", None)
    for attempt in (getattr(graph, "attempts", ()) if graph else ()):
        target = getattr(attempt, "target", None)
        if (target is not None
                and str(getattr(getattr(target, "kind", None), "value", "")) == "CLAIM"
                and str(getattr(getattr(attempt, "status", None), "value", "")) == "PASSED"):
            verified.add(str(getattr(target, "target_id", "")))
    rows = [{"claim_id": c, "verified": False}
            for c in sorted(set(criticality.critical_ids or ()) - verified)]
    return _found(name, rows, source="criticality + verification",
                  basis="load-bearing claims carrying no passed verification",
                  empty_basis="every load-bearing claim carries a passed verification")


def blockers(outcome: Any) -> QueryResult:
    """What prevents PROMOTE?

    Read off the rendered verdict, not recomputed. The answer to "why is this not
    promoting" must be the reasons the gate actually used.
    """
    name = "blockers"
    verdict = getattr(getattr(outcome, "case", None), "verdict", None)
    if verdict is None:
        return _unknown(name, "no verdict has been rendered on this case",
                        source="verdict")
    decision = str(getattr(getattr(verdict, "decision", None), "value", ""))
    if decision == "PROMOTE":
        return QueryResult(name, QueryOutcome.NONE_FOUND, (), "verdict",
                           "nothing: this case promotes")
    rows = [{"rule_id": rule} for rule in (verdict.fired_rules or ())]
    for reason in (verdict.reasons or ()):
        rows.append({"reason": str(reason)[:300]})
    return _found(name, rows, source="verdict",
                  basis=f"the case is {decision} on these rules and reasons")


def missing_evidence(outcome: Any) -> QueryResult:
    """Which evidence is missing?"""
    name = "missing_evidence"
    required = getattr(outcome, "required_evidence", None)
    if required is None:
        return _unknown(name, "no required-evidence set was produced",
                        source="required_evidence")
    rows = []
    for item in getattr(required, "items", ()):
        payload = item.to_dict()
        rows.append({"requirement": payload.get("requirement"),
                     "target": payload.get("target"), "what": payload.get("what"),
                     "effect": payload.get("effect")})
    return _found(name, rows, source="required_evidence",
                  basis="what release-gate can name as absent",
                  empty_basis="nothing is named as missing; that is not the same "
                              "as nothing being missing")


def artifacts_changed_after_verification(outcome: Any) -> QueryResult:
    """Which artifacts changed after verification?"""
    name = "artifacts_changed_after_verification"
    case = getattr(outcome, "case", None)
    try:
        from release_gate.assurance.artifacts import ArtifactGraph
        graph = ArtifactGraph.from_case(case) if case is not None else None
    except Exception:
        graph = None
    if graph is None:
        return _unknown(name, "no artifact graph could be built from this case",
                        source="artifacts")
    # `stale_verifications()` is the graph's own answer to this question.
    # `verification_currency()` takes one logical id and returns that artifact's
    # standing; calling it bare raised, and the sweep's guard turned the raise
    # into NOT_ASSESSED — a broken query reporting "not assessed" rather than
    # failing is precisely the shape this module must not ship.
    rows = [{"logical_id": currency.logical_id,
             "current_digest": currency.current_digest,
             "revisions_since_verification": currency.revisions_since_verification,
             "detail": currency.detail}
            for currency in graph.stale_verifications()]
    return _found(name, rows, source="artifacts",
                  basis="verified at a digest the artifact has since left",
                  empty_basis="no artifact was verified and then changed")


def single_root_claims(outcome: Any) -> QueryResult:
    """Which claims have one evidence root?"""
    name = "single_root_claims"
    criticality = _criticality(outcome)
    if criticality is None or not getattr(criticality, "determinable", False):
        return _unknown(name, "criticality could not be derived, so which claims "
                              "rest on a single root cannot be asked",
                        source="criticality")
    # `supporting_producers` is a count, not a collection.
    rows = [{"claim_id": entry.claim_id,
             "producers": int(entry.supporting_producers or 0),
             "basis": entry.basis}
            for entry in criticality.thin()]
    return _found(name, rows, source="criticality",
                  basis="load-bearing claims whose support traces to one producer; "
                        "a systematic error there is invisible to this case",
                  empty_basis="no load-bearing claim rests on a single producer")


def open_contradictions(outcome: Any) -> QueryResult:
    """Which contradictions remain open?"""
    name = "open_contradictions"
    ledger = getattr(outcome, "contradictions", None)
    case = getattr(outcome, "case", None)
    if case is not None:
        collection = case.collection("contradictions")
        if str(getattr(getattr(collection, "presence", None), "value", "")) != "PRESENT":
            return _unknown(name, "contradiction detection did not run",
                            source="contradictions")
    if ledger is None:
        return _unknown(name, "no contradiction ledger was produced",
                        source="contradictions")
    # Called directly rather than through `getattr(..., default)`: this read
    # `unresolved`, which the ledger does not have, so the default returned an
    # empty tuple and the query reported "no contradictions" on a case holding
    # one. A missing method must fail loudly, not answer reassuringly.
    rows = []
    for contradiction in ledger.open():
        rows.append({"contradiction_id": getattr(contradiction, "contradiction_id", ""),
                     "target_claims": list(getattr(contradiction, "target_claims", ())),
                     "kind": str(getattr(getattr(contradiction, "kind", None), "value", "")),
                     "critical": bool(getattr(contradiction, "critical_basis", ""))})
    return _found(name, rows, source="contradictions",
                  basis="disagreements nothing has answered",
                  empty_basis="no contradiction was observed among what was "
                              "submitted, which is not the same as none existing")


def assumptions_affecting_result(outcome: Any) -> QueryResult:
    """Which assumptions affect the final result?"""
    name = "assumptions_affecting_result"
    graph = getattr(outcome, "assumptions", None)
    case = getattr(outcome, "case", None)
    if case is not None:
        collection = case.collection("assumptions")
        if str(getattr(getattr(collection, "presence", None), "value", "")) != "PRESENT":
            return _unknown(name, "no assumption graph was supplied",
                            source="assumptions")
    if graph is None:
        return _unknown(name, "no assumption graph was supplied", source="assumptions")
    load_bearing = graph.load_bearing()
    rows = [{"assumption_id": str(getattr(a, "assumption_id", a)),
             "statement": str(getattr(a, "statement", ""))[:160],
             "load_bearing": True}
            for a in load_bearing]
    return _found(name, rows, source="assumptions",
                  basis="assumptions the conclusion rests on; each is taken as "
                        "given rather than established",
                  empty_basis="no recorded assumption is load-bearing; an argument "
                              "that declares none is not an argument without any")


def unresolved_verifier_failures(outcome: Any) -> QueryResult:
    """Which verifier failures remain unresolved?"""
    name = "unresolved_verifier_failures"
    graph = getattr(outcome, "verification", None)
    if graph is None:
        return _unknown(name, "no verification attempts are recorded",
                        source="verification")
    rows = []
    for attempt in getattr(graph, "attempts", ()):
        status = str(getattr(getattr(attempt, "status", None), "value", ""))
        if status in ("FAILED", "INVALIDATED"):
            target = getattr(attempt, "target", None)
            rows.append({"verification_id": getattr(attempt, "verification_id", ""),
                         "verifier": str(getattr(attempt, "verifier", "") or ""),
                         "status": status,
                         "target": str(getattr(target, "target_id", "") if target else "")})
    return _found(name, rows, source="verification",
                  basis="checks that ran and did not pass",
                  empty_basis="no recorded check failed")


def stale_approvals(outcome: Any, approvals: Sequence[Any] = ()) -> QueryResult:
    """Which approvals are stale?

    Approvals are supplied rather than read off the case, because an approval is
    held by whoever collected it and a case does not go looking for one.
    """
    name = "stale_approvals"
    case = getattr(outcome, "case", None)
    if case is None:
        return _unknown(name, "no case to check approvals against", source="approval")
    if not approvals:
        return _unknown(name, "no approval was supplied to check; a case does not "
                              "go looking for approvals it was not given",
                        source="approval")
    from release_gate.assurance.approval import check_approval
    rows = []
    for approval in approvals:
        try:
            check = check_approval(approval, case)
        except Exception as exc:
            rows.append({"approval_id": getattr(approval, "approval_id", ""),
                         "standing": "UNCHECKABLE", "detail": str(exc)[:160]})
            continue
        standing = str(getattr(getattr(check, "standing", None), "value", ""))
        if standing != "VALID":
            rows.append({"approval_id": check.approval_id, "standing": standing,
                         "reasons": [str(r)[:160] for r in (check.reasons or ())[:4]]})
    return _found(name, rows, source="approval",
                  basis="approvals that no longer bind to this state",
                  empty_basis="every supplied approval still binds")


def unknown_completeness_sources(outcome: Any, ledger: Any = None) -> QueryResult:
    """Which sources have unknown completeness?"""
    name = "unknown_completeness_sources"
    if ledger is None:
        return _unknown(name, "no stream completeness ledger was supplied, so "
                              "whether any source is whole has not been assessed",
                        source="completeness")
    status = str(getattr(getattr(ledger, "status", None), "value", ""))
    rows = []
    for stream in getattr(ledger, "streams", ()):
        if not stream.observed_sequences or stream.self_certified:
            rows.append({"stream_id": stream.stream_id,
                         "producer_id": stream.producer_id,
                         "self_certified": stream.self_certified,
                         "reason": ("the producer counted its own output"
                                    if stream.self_certified
                                    else "no sequence numbering, so a hole would "
                                         "leave no trace")})
    for silent in getattr(ledger, "silent_streams", ()):
        rows.append({"stream_id": silent, "reason": "expected and never reported"})
    return _found(name, rows, source="completeness",
                  basis=f"ledger status {status}",
                  empty_basis=f"every stream has a checkable shape (ledger {status})")


def hold_resolution(outcome: Any) -> QueryResult:
    """What evidence would resolve the HOLD?"""
    name = "hold_resolution"
    decision = str(getattr(getattr(outcome, "decision", None), "value", "")
                   or getattr(outcome, "decision", ""))
    if decision != "HOLD":
        return QueryResult(name, QueryOutcome.NONE_FOUND, (), "required_evidence",
                           f"this case is {decision or 'undecided'}, not on hold")
    required = getattr(outcome, "required_evidence", None)
    if required is None:
        return _unknown(name, "no required-evidence set was produced",
                        source="required_evidence")
    rows = []
    for item in getattr(required, "items", ()):
        payload = item.to_dict()
        if str(payload.get("effect")) in ("HOLD", "RequirementEffect.HOLD"):
            rows.append({"requirement": payload.get("requirement"),
                         "target": payload.get("target"),
                         "what": payload.get("what"),
                         "acceptance": payload.get("acceptance")})
    return _found(name, rows, source="required_evidence",
                  basis="supplying these would lift the hold, if nothing new arrives",
                  empty_basis="the hold is not attributable to nameable missing "
                              "evidence; read the blockers query")


#: Every query by name, so a caller can dispatch without a chain of ifs and a
#: consumer can discover what may be asked.
QUERIES: Mapping[str, Callable[..., QueryResult]] = {
    "unverified_critical_claims": unverified_critical_claims,
    "blockers": blockers,
    "missing_evidence": missing_evidence,
    "artifacts_changed_after_verification": artifacts_changed_after_verification,
    "single_root_claims": single_root_claims,
    "open_contradictions": open_contradictions,
    "assumptions_affecting_result": assumptions_affecting_result,
    "unresolved_verifier_failures": unresolved_verifier_failures,
    "stale_approvals": stale_approvals,
    "unknown_completeness_sources": unknown_completeness_sources,
    "hold_resolution": hold_resolution,
}


def run_query(name: str, outcome: Any, **kwargs: Any) -> QueryResult:
    """Run one query by name."""
    query = QUERIES.get(name)
    if query is None:
        raise QueryError(
            f"{name!r} is not a query this API answers. Known: "
            + ", ".join(sorted(QUERIES)))
    return query(outcome, **kwargs)


def run_all(outcome: Any, **kwargs: Any) -> Dict[str, QueryResult]:
    """Every query against one outcome, for a consumer that wants the sweep.

    Queries taking extra arguments get them where supplied and answer
    NOT_ASSESSED where not, rather than being skipped: a caller reading the sweep
    should see that a question was asked and could not be answered, not find it
    missing and assume it did not apply.
    """
    results: Dict[str, QueryResult] = {}
    for name, query in QUERIES.items():
        try:
            if name == "stale_approvals":
                results[name] = query(outcome, approvals=kwargs.get("approvals", ()))
            elif name == "unknown_completeness_sources":
                results[name] = query(outcome, ledger=kwargs.get("ledger"))
            else:
                results[name] = query(outcome)
        except Exception as exc:  # a broken query must not take the sweep down
            results[name] = _unknown(name, f"query failed: {type(exc).__name__}")
    return results
