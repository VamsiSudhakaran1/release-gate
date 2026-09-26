"""Why this verdict — the whole walk, from every reason the verdict names.

    verdict → condition/rule → subject/claim/action → evidence → source

`EvidenceGraph.explain_verdict` already walks that chain, and it descends from
the **methodology assessment**. That is the right source for a case with a
methodology and it is silent for one without, which is the shape a zero-config
run takes — the most common verdict this product produces:

    verdict: HOLD   fired: ['RG-ZC-001', 'contra_1e59…', 'RG-ZC-003']
    unresolved_count: 0

Three reasons named on the verdict, nothing explained, and the actual cause
(`RG-CONTRA-003`, `RG-CONTRA-005`) nowhere in the answer. A reviewer asking
"Why HOLD?" got an empty trace.

**So the walk starts from `fired_rules`, which is the verdict's own list of what
produced it.** A verdict may name four different kinds of thing and each needs a
different first step:

* a **methodology requirement** (`contradictions.resolved`) — the assessment
  holds its result, and the graph descends from there
* a **structural rule** (`RG-CONTRA-003`) — the finding holds `refs` naming what
  it is about, and `observed` naming what its predicate measured
* a **policy clause** (`RG-ZC-003`) — §10aj established these are clauses of the
  decision procedure rather than findings; they are explained by what they state
  and by the verdict's own reasons
* a **ledger id** (`contra_1e59…`) — a contradiction or counterexample, which
  holds its sides and the evidence on each

**`unexplained` is the load-bearing field.** A trace that silently covered four
of five reasons would be worse than none, because a reader would stop looking.
Every fired entry either reaches a source or is named there with why it could
not.

**No step is inferred.** Each `TraceStep` carries a `basis` naming the record it
was read from, and `derived` marks a step whose value was computed rather than
read. Nothing model-assisted appears as a link at all: a semantic proposal is a
candidate permanently (§10r) and never becomes a node on this path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "TRACE_SCHEMA_VERSION",
    "Level",
    "ReasonKind",
    "TraceStep",
    "VerdictTrace",
    "explain_hold",
    "trace_verdict",
]

TRACE_SCHEMA_VERSION = 1


class Level(str, Enum):
    """The five rungs, named so a step cannot sit between two of them."""

    VERDICT = "VERDICT"
    CONDITION = "CONDITION"
    SUBJECT = "SUBJECT"
    EVIDENCE = "EVIDENCE"
    SOURCE = "SOURCE"


class ReasonKind(str, Enum):
    """What kind of thing the verdict named, which decides the first step."""

    REQUIREMENT = "REQUIREMENT"    # a methodology requirement result
    STRUCTURAL = "STRUCTURAL"      # a finding an analyser raised
    POLICY_CLAUSE = "POLICY_CLAUSE"  # a clause of the decision procedure (§10aj)
    LEDGER_ENTRY = "LEDGER_ENTRY"  # a contradiction or counterexample id
    UNRECOGNISED = "UNRECOGNISED"  # named on the verdict and nothing owns it


@dataclass(frozen=True)
class TraceStep:
    """One rung, and where it was read from.

    `basis` is required. A step that cannot say which record it came from is the
    opaque link this module exists to make impossible — and an empty string
    would be one, so it is refused rather than allowed through.
    """

    level: Level
    identifier: str
    label: str = ""
    basis: str = ""
    #: True when the value was computed from records rather than read off one.
    #: Not a weakness — most of the interesting steps are derived — but a reader
    #: is entitled to know which is which (Invariant 1).
    derived: bool = False
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "level", Level(self.level))
        object.__setattr__(self, "detail", dict(self.detail))
        if not str(self.basis or "").strip():
            raise TraceError(
                f"{self.level.value} step {self.identifier!r} names no basis. A "
                "rung that cannot say which record it was read from is exactly "
                "the opaque link that breaks this path")

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level.value, "id": self.identifier,
                "label": self.label, "basis": self.basis,
                "derived": self.derived, "detail": dict(self.detail)}


class TraceError(ValueError):
    """A trace step that cannot be justified, or a walk that cannot be built."""


@dataclass(frozen=True)
class VerdictTrace:
    """Every reason the verdict named, and how far each one walks."""

    decision: str
    chains: Tuple[Tuple[TraceStep, ...], ...] = ()
    #: fired entry → why the walk could not descend from it.
    unexplained: Mapping[str, str] = field(default_factory=dict)
    reasons: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "chains", tuple(tuple(c) for c in self.chains))
        object.__setattr__(self, "unexplained", dict(self.unexplained))
        object.__setattr__(self, "reasons", tuple(self.reasons))

    @property
    def complete(self) -> bool:
        """Whether every reason the verdict named was walked.

        `False` is a real answer and not always a defect — a clause that fired on
        a PROMOTE has no unresolved subject to descend to — but it is never a
        silent one.
        """
        return not self.unexplained

    @property
    def reaches_source(self) -> Tuple[str, ...]:
        """Reasons whose chain got all the way down to a named source.

        Keyed on the *condition*, not on `chain[0]` — that one is the verdict
        step and every chain shares it, so reading it back gave the decision
        repeated once per chain instead of the reasons.
        """
        found: List[str] = []
        for chain in self.chains:
            if not any(step.level is Level.SOURCE for step in chain):
                continue
            condition = next((s.identifier for s in chain
                              if s.level is Level.CONDITION), None)
            if condition is not None:
                found.append(condition)
        return tuple(found)

    @property
    def walked(self) -> Tuple[str, ...]:
        """Every reason that got a chain, however far down it went.

        The accessor a completeness check wants. `reaches_source` and
        `stopped_at_condition` between them miss the middle — a chain that got
        to a subject and found no evidence under it was walked, and reading only
        those two made it look skipped.
        """
        found: List[str] = []
        for chain in self.chains:
            condition = next((s.identifier for s in chain
                              if s.level is Level.CONDITION), None)
            if condition is not None and condition not in found:
                found.append(condition)
        return tuple(found)

    @property
    def stopped_at_condition(self) -> Tuple[str, ...]:
        """Reasons whose walk legitimately stops at level 2.

        A policy clause states how the decision was reached rather than being
        *about* a subject, so it has nothing below it. Reported separately from
        `unexplained`, because "there is nothing under this by its nature" and "I
        could not get under this" are different answers.
        """
        return tuple(s.identifier for chain in self.chains for s in chain
                     if s.level is Level.CONDITION
                     and not any(x.level is Level.SUBJECT for x in chain))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "verdict_trace", "record_id": "why",
                "schema_version": TRACE_SCHEMA_VERSION,
                "decision": self.decision,
                "chains": [[step.to_dict() for step in chain]
                           for chain in self.chains],
                "unexplained": dict(self.unexplained),
                "walked": list(self.walked),
                "reaches_source": list(self.reaches_source),
                "stopped_at_condition": list(self.stopped_at_condition),
                "complete": self.complete,
                "reasons": list(self.reasons)}

    def render(self) -> str:
        """The walk as indented text, one block per reason."""
        out = [f"VERDICT {self.decision}"]
        indent = {Level.CONDITION: 1, Level.SUBJECT: 2,
                  Level.EVIDENCE: 3, Level.SOURCE: 4}
        for chain in self.chains:
            for step in chain:
                # The verdict rung is the same for every chain, so it is printed
                # once at the top rather than repeated per reason.
                if step.level is Level.VERDICT:
                    continue
                pad = "  " * indent[step.level] + "└─ "
                mark = " (derived)" if step.derived else ""
                out.append(f"{pad}{step.level.value} {step.identifier}"
                           + (f" — {step.label}" if step.label else "") + mark)
                out.append("  " * (indent[step.level] + 1) + f"   via {step.basis}")
        for reason, why in sorted(self.unexplained.items()):
            out.append(f"  └─ CONDITION {reason} — NOT TRACED: {why}")
        return "\n".join(out)


# ── classifying what the verdict named ───────────────────────────────────────

def _classify(reason: str, outcome: Any) -> ReasonKind:
    """Which of the four kinds this fired entry is.

    Ordered so the most specific wins. A requirement id is checked against the
    assessment's own results rather than by shape, because `RG-SW-003` is a
    requirement id that looks exactly like a structural rule id — the two
    namespaces overlap and only the assessment knows which it holds.
    """
    from release_gate.assurance.rules_registry import POLICY_RULES
    results = getattr(getattr(outcome, "assessment", None), "results", ()) or ()
    if any(getattr(r, "requirement_id", None) == reason for r in results):
        return ReasonKind.REQUIREMENT
    if reason in POLICY_RULES:
        return ReasonKind.POLICY_CLAUSE
    if any(f.rule_id == reason for f in outcome.analysis.findings):
        return ReasonKind.STRUCTURAL
    if _ledger_entry(reason, outcome) is not None:
        return ReasonKind.LEDGER_ENTRY
    return ReasonKind.UNRECOGNISED


def _ledger_entry(reason: str, outcome: Any) -> Any:
    """The contradiction or counterexample this id names, if either holds it.

    `contra_…` ids reach `fired_rules` — `decide()` puts every unresolved
    critical contradiction there by id — and the rule registry refuses them,
    correctly, because they are not rules. They are still reasons a verdict
    named, so they still have to be walkable.
    """
    ledger = getattr(outcome.analysis, "contradictions", None)
    for entry in (getattr(ledger, "all", lambda: ())() if ledger else ()):
        if getattr(entry, "contradiction_id", None) == reason:
            return entry
    for entry in (ledger.open() if ledger and hasattr(ledger, "open") else ()):
        if getattr(entry, "contradiction_id", None) == reason:
            return entry
    counterexamples = getattr(outcome.analysis, "counterexamples", None)
    for entry in (counterexamples.open()
                  if counterexamples and hasattr(counterexamples, "open") else ()):
        if getattr(entry, "target_claim", None) == reason:
            return entry
    return None


# ── the walk ─────────────────────────────────────────────────────────────────

def _descend(graph: Any, target: str, basis: str,
             max_evidence: int) -> List[TraceStep]:
    """Levels 3–5 for one subject, read off the evidence graph.

    Reuses `trace_target` rather than re-walking the edges: one implementation of
    "what bears on this and who produced it" is the point, and a second would
    drift from the first exactly where it mattered.
    """
    steps: List[TraceStep] = []
    traced = graph.trace_target(target, max_evidence=max_evidence)
    steps.append(TraceStep(
        level=Level.SUBJECT, identifier=target,
        label=traced.get("label") or traced.get("kind", ""),
        basis=basis, derived=True,
        detail={"kind": traced.get("kind"),
                "evidence_count": traced.get("evidence_count", 0)}))
    if not traced.get("evidence"):
        # Level 3 reached and level 4 empty. Said out loud, because a chain that
        # simply stopped here looked identical to one nobody had walked — and
        # "no evidence bears on this" is itself the finding a reviewer needs
        # (Invariant 3).
        steps.append(TraceStep(
            level=Level.EVIDENCE, identifier="(none)",
            label="no evidence in this case bears on that subject",
            basis=f"evidence graph holds no edge to {target}", derived=True,
            detail={"evidence_count": 0}))
    for item in traced.get("evidence", ()):
        steps.append(TraceStep(
            level=Level.EVIDENCE, identifier=str(item.get("evidence_id")),
            label=str(item.get("label") or ""),
            basis=f"evidence graph edge: {item.get('direction')} {target}",
            detail={"epistemic_status": item.get("epistemic_status"),
                    "verification_method": item.get("verification_method"),
                    "current": item.get("current"),
                    "held_by_case": item.get("present")}))
        for source in item.get("sources", ()):
            steps.append(TraceStep(
                level=Level.SOURCE, identifier=str(source.get("source_id")),
                label=str(source.get("label") or ""),
                basis=f"producer of {item.get('evidence_id')}",
                detail={"identity_basis": source.get("identity_basis"),
                        "trust_status": source.get("trust_status"),
                        "independence_basis": source.get("independence_basis")}))
        if not item.get("sources"):
            steps.append(TraceStep(
                level=Level.SOURCE, identifier="(unattributed)",
                label="this evidence names no producer",
                basis=f"absence of a producer on {item.get('evidence_id')}",
                derived=True,
                detail={"note": "the chain ends here, and that is the finding: "
                                "evidence nobody is answerable for cannot be "
                                "weighed"}))
    return steps


def _subjects_for(reason: str, kind: ReasonKind, outcome: Any,
                  graph: Any) -> Tuple[List[Tuple[str, str]], str]:
    """The subjects this reason is about, and why those.

    Returns `(subjects, basis)` where each subject is `(id, basis)`. An empty
    list is a real answer — some reasons are about the case as a whole — and the
    caller turns that into an `unexplained` entry rather than an empty chain.
    """
    from release_gate.assurance.evidence_graph import NodeKind
    actions = [n.node_id for n in graph.nodes_of(NodeKind.ACTION)]

    if kind is ReasonKind.REQUIREMENT:
        results = getattr(outcome.assessment, "results", ()) or ()
        result = next((r for r in results
                       if getattr(r, "requirement_id", None) == reason), None)
        observed = [str(v) for v in (getattr(result, "observed", {}) or {}).values()
                    if isinstance(v, str)]
        named: List[Tuple[str, str]] = []
        for value in observed:
            if graph.node(value) is not None:
                named.append((value, f"named in {reason}'s observed values"))
                continue
            # One real hop: an observed value may name a ledger record rather
            # than a graph node — `contra_157c…` is not evidence, it is a
            # disagreement *about* evidence — and the record itself names the
            # claims it is about. Following that is reading a link the record
            # states, not guessing one from the requirement's name.
            entry = _ledger_entry(value, outcome)
            for claim in (getattr(entry, "target_claims", ()) or ()) if entry else ():
                if graph.node(claim) is not None:
                    named.append(
                        (claim, f"a target claim of {value}, which {reason} "
                                "reported unresolved"))
        if named:
            return (named, f"assessment result for {reason}")
        return ([(a, "the action itself; this requirement names no target")
                 for a in actions], f"assessment result for {reason}")

    if kind is ReasonKind.STRUCTURAL:
        finding = next(f for f in outcome.analysis.findings if f.rule_id == reason)
        refs = [r for r in finding.refs if graph.node(r) is not None]
        if refs:
            return ([(r, f"cited in {reason}.refs") for r in refs],
                    f"finding {reason}")
        return ([(a, f"{reason} names no record the graph holds, so it bears on "
                     "the action itself") for a in actions],
                f"finding {reason}")

    if kind is ReasonKind.LEDGER_ENTRY:
        entry = _ledger_entry(reason, outcome)
        claims = list(getattr(entry, "target_claims", ())
                      or ([getattr(entry, "target_claim", "")]
                          if getattr(entry, "target_claim", "") else []))
        return ([(c, f"a target claim of {reason}") for c in claims if c],
                f"contradiction ledger entry {reason}")

    return ([], "")


def trace_verdict(outcome: Any, *, max_evidence: int = 4) -> VerdictTrace:
    """Walk every reason this verdict named down to the sources beneath it."""
    from release_gate.assurance.evidence_graph import EvidenceGraph
    from release_gate.assurance.rules_registry import POLICY_RULES

    verdict = outcome.case.verdict
    if verdict is None:
        raise TraceError(
            "this case has no verdict, so there is nothing to explain. An "
            "undecided case is not a decision whose reasons can be walked")
    graph = EvidenceGraph.from_case(outcome.case)
    decision = verdict.decision.value

    chains: List[Tuple[TraceStep, ...]] = []
    unexplained: Dict[str, str] = {}

    for reason in verdict.fired_rules:
        kind = _classify(reason, outcome)
        if kind is ReasonKind.UNRECOGNISED:
            unexplained[reason] = (
                "the verdict names this and nothing in the case owns it: no "
                "assessment result, no finding, no policy clause and no ledger "
                "entry. A reason nobody can look up is not a reason")
            continue

        head: List[TraceStep] = [TraceStep(
            level=Level.VERDICT, identifier=decision,
            label=f"because of {reason}",
            basis=f"CaseVerdict.fired_rules names {reason}")]

        if kind is ReasonKind.POLICY_CLAUSE:
            clause = POLICY_RULES[reason]
            head.append(TraceStep(
                level=Level.CONDITION, identifier=reason,
                label=clause.states, basis="the decision procedure's own clause",
                detail={"resolution": clause.resolution or None,
                        "verdict_reasons": list(verdict.reasons)}))
            # A clause states how the decision was reached; it is not *about* a
            # subject, so the walk stops here honestly rather than inventing one.
            chains.append(tuple(head))
            continue

        head.append(_condition_step(reason, kind, outcome))
        subjects, basis = _subjects_for(reason, kind, outcome, graph)
        if not subjects:
            unexplained[reason] = (
                f"recognised as a {kind.value.lower()} but it names no subject "
                "the evidence graph holds, so there is nothing to descend to")
            continue
        steps = list(head)
        for subject, subject_basis in subjects:
            steps.extend(_descend(graph, subject, subject_basis, max_evidence))
        chains.append(tuple(steps))

    return VerdictTrace(decision=decision, chains=tuple(chains),
                        unexplained=unexplained,
                        reasons=tuple(verdict.reasons))


def _condition_step(reason: str, kind: ReasonKind, outcome: Any) -> TraceStep:
    """Level 2: the condition, read off whichever record holds it."""
    if kind is ReasonKind.REQUIREMENT:
        result = next(r for r in (outcome.assessment.results or ())
                      if r.requirement_id == reason)
        return TraceStep(
            level=Level.CONDITION, identifier=reason,
            label=getattr(result, "description", ""),
            basis=f"MethodologyAssessment result for {reason}",
            detail={"outcome": result.outcome.value, "effect": result.effect.value,
                    "detail": result.detail, "remedy": result.remedy,
                    "observed": dict(result.observed)})
    if kind is ReasonKind.STRUCTURAL:
        finding = next(f for f in outcome.analysis.findings if f.rule_id == reason)
        return TraceStep(
            level=Level.CONDITION, identifier=reason, label=finding.summary,
            basis=f"structural finding {reason} from the {finding.domain.value} "
                  "analyser",
            detail={"effect": finding.effect.value, "detail": finding.detail,
                    "remedy": finding.remedy, "observed": dict(finding.observed)})
    entry = _ledger_entry(reason, outcome)
    return TraceStep(
        level=Level.CONDITION, identifier=reason,
        label=getattr(entry, "critical_basis", "") or "an unresolved disagreement",
        basis=f"contradiction ledger entry {reason}",
        detail={"sides": [getattr(s, "label", "") for s in
                          getattr(entry, "sides", ())],
                "status": getattr(getattr(entry, "status", None), "value", None)})


def explain_hold(outcome: Any) -> str:
    """"Why HOLD?" — the answer as text, for a terminal or a packet."""
    return trace_verdict(outcome).render()
