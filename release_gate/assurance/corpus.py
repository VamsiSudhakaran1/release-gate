"""The assurance benchmark corpus — sixteen constructed cases, scored honestly.

`benchmark/run.py` measures the **scanner**: code in, rule ids out, precision
and recall against "this snippet contains this vulnerability". Since §10ag the
scanner is one Evidence Producer among seven, which makes it the wrong layer to
say anything about assurance. This corpus is the other benchmark. Its unit is an
assurance case, and what it predicts is a verdict, a finding set, a coverage
ledger and an invalidation report.

**What the ground truth is, and is not.** A benchmark that scored *"did
release-gate correctly judge this release safe"* would need release-gate to hold
a truth about release safety. It does not, and Invariant 10 forbids claiming
one. What is checkable is whether it correctly reports **the structure of the
evidence it was given** — every case here is constructed, so its structure is
known by construction rather than by judgement. A case labelled
`invalid_release` therefore means *a case whose evidence structure carries a
named defect that was put there*, never *a release that was actually bad*.
`BenchmarkScope` says so as unconditional properties, because the instruction
this corpus was built under ends "do not publish broader claims than benchmark
scope supports" and prose does not enforce anything.

**Precision is not meaningful for every case, and the corpus says which.**
Sixteen kinds split three ways:

* `DETECTION` — a named defect is present. Did the right rule fire? Precision,
  recall, false positives and false negatives all mean something.
* `QUIET` — nothing is structurally wrong. Did the engine stay quiet? A false
  positive rate means something; recall does not, because there is nothing to
  recall.
* `BEHAVIOUR` — the question is not detection at all. Did coverage report
  `UNKNOWN` rather than guessing? Did the approval stop binding when the case
  moved? Neither precision nor recall applies; the check is an assertion that
  passes or fails.

Reporting one precision figure across all sixteen would average a detection rate
together with "did it correctly say it did not know", which is the over-claim
the scope object exists to refuse. `score` computes each rate over its own class
and states the denominator.

Every case runs through `ingest.normalise` and `zero_config.assure_normalisation`
— the same path the CLI and the demos take — so the corpus exercises what ships
rather than a harness that agrees with it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Callable, Dict, List, Mapping, Optional, Sequence,
                    Tuple)

__all__ = [
    "BEHAVIOURS",
    "CORPUS_SCHEMA_VERSION",
    "KINDS",
    "BehaviourCheck",
    "BenchmarkScope",
    "CaseClass",
    "CaseResult",
    "CorpusCase",
    "CorpusError",
    "CorpusResult",
    "ClassScore",
    "build_corpus",
    "run_case",
    "score",
]

CORPUS_SCHEMA_VERSION = 1


class CorpusError(ValueError):
    """A case, expectation or behaviour check that cannot be evaluated."""


#: The sixteen named kinds, in the order the brief names them. A constant, so
#: "is every kind covered" is a comparison rather than a count that drifts.
KINDS: Tuple[str, ...] = (
    "valid_release",
    "invalid_release",
    "incomplete_evidence",
    "false_independence",
    "fake_verifier",
    "stale_approval",
    "artifact_mutation",
    "open_contradiction",
    "resolved_contradiction",
    "unresolved_counterexample",
    "missing_provenance",
    "single_agent_legitimate_action",
    "evidence_omission",
    "unknown_completeness",
    "wrong_target_digest",
    "ten_thousand_agent_workflow",
)


class CaseClass(str, Enum):
    """What kind of question a case asks, which decides what may be measured.

    The distinction is not presentational. A `QUIET` case has no defect to
    recall, and scoring one as a recall miss would mean the engine improved its
    recall by finding something that is not there. A `BEHAVIOUR` case is not a
    detection at all — "did it report UNKNOWN rather than guess" has no positive
    class.
    """

    DETECTION = "DETECTION"
    QUIET = "QUIET"
    BEHAVIOUR = "BEHAVIOUR"


# ── what this benchmark does and does not support ───────────────────────────

@dataclass(frozen=True)
class BenchmarkScope:
    """What may be claimed from a run of this corpus.

    Every refusal is an unconditional `False` property rather than a flag,
    because a scope that can be argued into a wider claim is not a scope. These
    are the sentences someone would otherwise write in a launch post.
    """

    cases: int = 0
    kinds: int = 0
    constructed: bool = True

    @property
    def measures_release_safety(self) -> bool:
        """No. It measures whether the reported structure matches the built one.

        A case here is safe or unsafe in no sense at all: it is a document with
        a known shape. Reading a detection rate as a safety rate would be
        exactly the universal truth claim Invariant 10 refuses.
        """
        return False

    @property
    def measures_the_scanner(self) -> bool:
        """No. `benchmark/run.py` does that, over a different corpus.

        Held separate on purpose: the scanner's 100% precision over 93 code
        snippets says nothing about assurance, and a reader who finds one number
        and assumes it covers the other layer has been over-claimed at.
        """
        return False

    @property
    def generalises_to_unseen_shapes(self) -> bool:
        """No. Constructed cases prove the engine handles these constructions.

        Real evidence arrives in shapes nobody anticipated, and a corpus whose
        author also wrote the engine is a consistency check, not a sample.
        """
        return False

    @property
    def is_a_third_party_audit(self) -> bool:
        """No. Same author, same assumptions, published so it can be re-run."""
        return False

    @property
    def establishes_that_a_promote_was_correct(self) -> bool:
        """No. A PROMOTE is a recommendation to a person (Invariant 15).

        A quiet case passing means the engine found no structural defect in a
        case built without one — not that promoting it was the right call.
        """
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "benchmark_scope", "record_id": "assurance-corpus",
                "cases": self.cases, "kinds": self.kinds,
                "constructed": self.constructed,
                "measures_release_safety": self.measures_release_safety,
                "measures_the_scanner": self.measures_the_scanner,
                "generalises_to_unseen_shapes": self.generalises_to_unseen_shapes,
                "is_a_third_party_audit": self.is_a_third_party_audit,
                "establishes_that_a_promote_was_correct":
                    self.establishes_that_a_promote_was_correct}


# ── a case ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CorpusCase:
    """One constructed case, and what its construction entitles us to expect.

    `defect` is written from the construction — what was *put there* — and not
    from what the engine reports. That ordering is the discipline this file
    depends on: an expectation written after running the engine records what the
    engine does, which is a tautology dressed as a test.
    """

    case_id: str
    kind: str
    case_class: CaseClass
    #: The structure that was built in, in one sentence. For a QUIET case, what
    #: was deliberately left *clean* — a quiet case with no stated construction
    #: is indistinguishable from a case nobody thought about.
    defect: str
    document: Tuple[Mapping[str, Any], ...]
    #: Rule ids a DETECTION case must raise. Every id is checked against the
    #: family registry (§10aj), so a typo is refused rather than scored a miss.
    expect_rules: Tuple[str, ...] = ()
    #: The decision this case must reach, where the construction fixes one.
    #: `None` means the construction does not determine it and asserting one
    #: would be pinning current behaviour.
    expect_decision: Optional[str] = None
    #: Named checks from `BEHAVIOURS`. The only thing a BEHAVIOUR case scores.
    behaviours: Tuple[str, ...] = ()
    #: A named generator from `GENERATORS`, for the two cases whose evidence is
    #: a whole simulated workflow rather than a document anyone would hand-write.
    #: Reuses the shipped demos rather than reimplementing them: a corpus that
    #: built its own ten-thousand-agent workflow would be scoring a second
    #: generator, not the product.
    generator: str = ""
    #: A second document: the same case after something moved. Only the two
    #: kinds that are *about* a case changing carry one.
    revision: Tuple[Mapping[str, Any], ...] = ()
    #: Take an approval against the first state, through the real two-step.
    approve: bool = False
    #: Methodology id, or "" for the zero-config path. Zero-config cannot
    #: PROMOTE by construction, so a case expecting one must name a yardstick.
    methodology: str = ""
    objective: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_class", CaseClass(self.case_class))
        object.__setattr__(self, "document", tuple(self.document))
        object.__setattr__(self, "revision", tuple(self.revision))
        for name in ("expect_rules", "behaviours"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if self.kind not in KINDS:
            raise CorpusError(
                f"{self.case_id}: {self.kind!r} is not one of the sixteen named "
                "kinds. A case outside the brief's vocabulary is one the results "
                "table cannot honestly label")
        if not self.document and not self.generator:
            raise CorpusError(
                f"{self.case_id}: a case needs either a document or a generator")
        if self.generator and self.generator not in GENERATORS:
            raise CorpusError(
                f"{self.case_id}: unknown generator {self.generator!r}. Known: "
                + ", ".join(sorted(GENERATORS)))
        if self.case_class is CaseClass.DETECTION and not self.expect_rules:
            raise CorpusError(
                f"{self.case_id}: a DETECTION case must name the rules its defect "
                "should raise, or it is scored against nothing")
        if self.case_class is CaseClass.QUIET and self.expect_rules:
            raise CorpusError(
                f"{self.case_id}: a QUIET case has no defect to detect; naming "
                "expected rules here would score a false positive as a hit")
        if self.case_class is CaseClass.BEHAVIOUR and not self.behaviours:
            raise CorpusError(
                f"{self.case_id}: a BEHAVIOUR case is scored only by its named "
                "checks, so one without any is scored by nothing")
        unknown = [b for b in self.behaviours if b not in BEHAVIOURS]
        if unknown:
            raise CorpusError(
                f"{self.case_id}: unknown behaviour check(s) "
                + ", ".join(unknown) + ". Known: " + ", ".join(sorted(BEHAVIOURS)))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "corpus_case", "record_id": self.case_id,
                "case_id": self.case_id, "kind": self.kind,
                "class": self.case_class.value, "defect": self.defect,
                "expect_rules": list(self.expect_rules),
                "expect_decision": self.expect_decision,
                "behaviours": list(self.behaviours),
                "methodology": self.methodology, "notes": self.notes,
                "records": len(self.document)}


@dataclass(frozen=True)
class CaseRun:
    """Everything one corpus case produced, in one object.

    A check reads this rather than a bare outcome because two of the sixteen
    kinds are about a case *changing*: a stale approval is an approval taken
    against one state and checked against the next, and a mutation is a
    verification that was sound until the artifact moved underneath it. Neither
    can be expressed by a single snapshot, and a corpus that could not express
    them would quietly drop the two kinds where release-gate's binding rules do
    their actual work.
    """

    case: "CorpusCase"
    outcome: Any
    #: The outcome after the case's `revision` document, where it has one.
    revised: Any = None
    #: A `BoundApproval` taken against `outcome`, through the real two-step.
    approval: Any = None
    #: `check_approval(approval, revised.case)` — where that approval stands now.
    standing: Any = None
    #: `InvalidationReport` for a mutation case.
    invalidation: Any = None


@dataclass(frozen=True)
class BehaviourCheck:
    """One named, executable assertion about what the engine did.

    Executable rather than free text, so a behaviour a reader can see in the
    results table is one the runner actually evaluated. `check` returns
    `(passed, detail)`; the detail is what the engine reported, so a failure
    reads as a disagreement rather than a bare False.
    """

    name: str
    question: str
    check: Callable[["CaseRun"], Tuple[bool, str]]

    def run(self, run: "CaseRun") -> Tuple[bool, str]:
        try:
            return self.check(run)
        except Exception as exc:                       # pragma: no cover - guard
            return False, f"the check itself raised {type(exc).__name__}: {exc}"


# ── the behaviour checks ─────────────────────────────────────────────────────
#
# Each answers a question precision cannot. They read what the engine returned
# and never the corpus's own expectations, so a check cannot pass by agreeing
# with the case that produced it.

def _decision(outcome: Any) -> str:
    verdict = getattr(outcome, "case", None) and outcome.case.verdict
    return verdict.decision.value if verdict is not None else "NONE"


def _rows(outcome: Any) -> List[Any]:
    ledger = outcome.analysis.coverage_ledger
    return list(ledger) if ledger is not None else []


def _coverage_reported(run: "CaseRun") -> Tuple[bool, str]:
    rows = _rows(run.outcome)
    return bool(rows), f"{len(rows)} coverage dimension(s) reported with the verdict"


def _unassessed_is_visible(run: "CaseRun") -> Tuple[bool, str]:
    """A dimension nobody assessed is shown rather than omitted.

    An omitted row and a row reading NOT_ASSESSED look identical in a summary
    and mean opposite things, which is why the ledger carries the row.
    """
    rows = _rows(run.outcome)
    unassessed = [r for r in rows if r.state.value in ("NOT_ASSESSED", "UNKNOWN")]
    return bool(unassessed), (
        f"{len(unassessed)} of {len(rows)} dimension(s) report NOT_ASSESSED or UNKNOWN")


def _completeness_unknown(run: "CaseRun") -> Tuple[bool, str]:
    """UNKNOWN, not "complete" and not "incomplete".

    The distinction Invariant 3 turns on: an execution record with gaps nobody
    can bound is not a short execution, and reporting it as either would be a
    guess wearing a status.
    """
    graph = run.outcome.analysis.execution_graph
    if graph is None:
        return False, "no execution graph was built, so completeness was not reached"
    status = graph.completeness.status.value
    return status == "UNKNOWN", f"execution completeness reported {status}"


def _completeness_not_claimed_complete(run: "CaseRun") -> Tuple[bool, str]:
    graph = run.outcome.analysis.execution_graph
    if graph is None:
        return True, "no execution graph, so nothing claimed completeness"
    status = graph.completeness.status.value
    return status != "COMPLETE", f"execution completeness reported {status}"


def _did_not_promote(run: "CaseRun") -> Tuple[bool, str]:
    decision = _decision(run.outcome)
    return decision != "PROMOTE", f"the verdict was {decision}"


def _promoted(run: "CaseRun") -> Tuple[bool, str]:
    decision = _decision(run.outcome)
    return decision == "PROMOTE", f"the verdict was {decision}"


def _verdict_names_its_rules(run: "CaseRun") -> Tuple[bool, str]:
    """No unattributed verdict, whatever the decision."""
    verdict = run.outcome.case.verdict
    fired = list(verdict.fired_rules) if verdict is not None else []
    return bool(fired), f"the verdict names {len(fired)} rule(s)"


def _required_evidence_named(run: "CaseRun") -> Tuple[bool, str]:
    """The gap is stated as a work order, not as a shrug."""
    items = list(run.outcome.required_evidence.items)
    return bool(items), f"{len(items)} piece(s) of required evidence named"


def _nothing_blocking(run: "CaseRun") -> Tuple[bool, str]:
    blocking = list(run.outcome.analysis.blocking)
    return not blocking, (
        "no blocking finding" if not blocking else
        "blocking: " + ", ".join(sorted({f.rule_id for f in blocking})))


def _scale_did_not_buy_a_verdict(run: "CaseRun") -> Tuple[bool, str]:
    """Invariant 6, as an assertion rather than a hope.

    A workflow with thousands of agents must still report what it does not know.
    A case that went quiet as the worker count rose — fewer gaps, fewer things to
    look at — is the failure mode this checks for.
    """
    rows = _rows(run.outcome)
    gaps = [r for r in rows if r.state.value in ("NOT_ASSESSED", "UNKNOWN",
                                                 "KNOWN_MISSING")]
    attention = list(run.outcome.attention.items)
    return bool(gaps) and bool(attention), (
        f"{len(gaps)} coverage gap(s) and {len(attention)} attention item(s) "
        f"survive at this scale; verdict {_decision(run.outcome)}")


def _no_verification_covers_the_subject(run: "CaseRun") -> Tuple[bool, str]:
    """A check bound to a digest that is not the subject's does not cover it.

    The whole point of `applies_to_digest`: a verification is a statement about
    one state, and crediting it to a different one is how a case inherits
    assurance it never had.
    """
    graph = run.outcome.analysis.verification_graph
    if graph is None:
        return True, "no verification graph was built, so nothing covers the subject"
    # A check applies to the state it names only where the case still holds that
    # state. `applicability` against the target's current digest is the engine's
    # own answer, and UNDETERMINED is not APPLICABLE — a check that never said
    # what it ran against has not been shown to cover anything.
    applying = [a for a in graph.attempts
                if a.target is not None
                and a.applicability(graph.current_digest(a.target)).value == "APPLICABLE"]
    return not applying, (
        f"{len(applying)} of {len(graph.attempts)} attempt(s) are APPLICABLE to the "
        "state this case is in")


# ── the two that need a case to have moved ──────────────────────────────────

def _approval_stops_binding(run: "CaseRun") -> Tuple[bool, str]:
    """An approval of one state does not carry to the next.

    Invariant 11 as a measurement rather than a design note. The approval is
    taken through the real two-step against the first state and checked against
    the revision; anything but a clean `binds` is the correct answer.
    """
    if run.standing is None:
        return False, "no approval was taken, so nothing was checked"
    binds = bool(getattr(run.standing, "binds", False))
    conditions = [c.value for c in getattr(run.standing, "conditions", ())]
    return not binds, ("the approval still binds to the revised case"
                       if binds else
                       "the approval no longer binds: " + ", ".join(conditions or
                                                                    ["(no reason given)"]))


def _approval_says_why_it_stopped(run: "CaseRun") -> Tuple[bool, str]:
    """Not binding is half an answer; a reviewer needs the reason.

    An approval that silently stops counting is indistinguishable from one that
    was never recorded, and the difference matters to the person who gave it.
    """
    if run.standing is None:
        return False, "no approval was taken, so nothing was checked"
    reasons = [r for r in getattr(run.standing, "reasons", ()) if str(r).strip()]
    conditions = [c.value for c in getattr(run.standing, "conditions", ())]
    return bool(reasons) and bool(conditions), (
        f"{len(conditions)} condition(s), {len(reasons)} stated reason(s)")


def _mutation_invalidates_its_verifications(run: "CaseRun") -> Tuple[bool, str]:
    """A verification of content that has changed is reported as no longer applying.

    Not deleted and not downgraded: the check really did run and really did pass
    against what it saw. What changed is what it is now evidence *about*.
    """
    report = run.invalidation
    if report is None:
        return False, "no invalidation report was produced"
    invalidated = [r for r in report.results
                   if r.affect.value == "INVALIDATED"]
    return bool(invalidated), (
        f"{len(invalidated)} of {len(report.results)} verification(s) reported as "
        "no longer applying: "
        + "; ".join(f"{r.verifier} ({r.reason})" for r in invalidated[:3]))


#: name → check. Built from one list so the registry cannot disagree with
#: itself about which behaviours exist.
_BEHAVIOUR_LIST: Tuple[BehaviourCheck, ...] = (
    BehaviourCheck("coverage_reported",
                   "Is coverage reported alongside the verdict? (Invariant 9)",
                   _coverage_reported),
    BehaviourCheck("unassessed_is_visible",
                   "Is a dimension nobody assessed shown rather than omitted?",
                   _unassessed_is_visible),
    BehaviourCheck("completeness_unknown",
                   "Is execution completeness reported UNKNOWN rather than guessed?",
                   _completeness_unknown),
    BehaviourCheck("completeness_not_claimed_complete",
                   "Does the engine refrain from claiming a complete execution?",
                   _completeness_not_claimed_complete),
    BehaviourCheck("did_not_promote", "Did the engine decline to promote?",
                   _did_not_promote),
    BehaviourCheck("promoted", "Did the engine promote?", _promoted),
    BehaviourCheck("verdict_names_its_rules",
                   "Is the verdict attributable to named rules?",
                   _verdict_names_its_rules),
    BehaviourCheck("required_evidence_named",
                   "Is the gap stated as a work order rather than a shrug?",
                   _required_evidence_named),
    BehaviourCheck("nothing_blocking",
                   "Did the structural analysis find nothing disqualifying?",
                   _nothing_blocking),
    BehaviourCheck("scale_did_not_buy_a_verdict",
                   "Does a large workflow still report what it does not know? "
                   "(Invariant 6)", _scale_did_not_buy_a_verdict),
    BehaviourCheck("no_verification_covers_the_subject",
                   "Is a check bound to another digest refused as coverage of "
                   "this subject?", _no_verification_covers_the_subject),
    BehaviourCheck("approval_stops_binding",
                   "Does an approval of one state stop binding when the case "
                   "moves? (Invariant 11)", _approval_stops_binding),
    BehaviourCheck("approval_says_why_it_stopped",
                   "Does it say why, rather than going quiet?",
                   _approval_says_why_it_stopped),
    BehaviourCheck("mutation_invalidates_its_verifications",
                   "Is a verification of changed content reported as no longer "
                   "applying?", _mutation_invalidates_its_verifications),
)

BEHAVIOURS: Mapping[str, BehaviourCheck] = {b.name: b for b in _BEHAVIOUR_LIST}


# ── the sixteen cases ────────────────────────────────────────────────────────
#
# Every `defect` below states what was *built in*, and every `expect_rules` was
# written from that construction before the engine was run against it. The
# ordering matters: an expectation written after a run records what the engine
# does, which is a tautology wearing a test's clothes. Where a run then
# disagreed, the disagreement was investigated — the notes say which.

def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


SERVICE_V1 = _digest("def charge(order):\n    return gateway.charge(order.total)\n")
SERVICE_V2 = _digest("def charge(order):\n    return gateway.charge(order.total * 2)\n")
SUITE_LOG = _digest("42 passed in 3.10s\n")

_RUN_AT = "2026-03-01T09:00:00Z"


def _artifact(artifact_id: str, digest: str, producer: str = "agent://builder",
              kind: str = "CODE") -> Dict[str, Any]:
    return {"record_type": "artifact", "artifact_id": artifact_id, "kind": kind,
            "digest": digest, "created_by": producer,
            "producer": {"producer_id": producer, "kind": "agent"}}


def _evidence(evidence_id: str, kind: str, producer: str, method: str,
              applies_to: Optional[str] = None, parents: Sequence[str] = (),
              coverage_note: str = "", producer_kind: str = "tool",
              **extra: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "record_type": "evidence", "evidence_id": evidence_id, "kind": kind,
        "producer": {"producer_id": producer, "kind": producer_kind},
        "timestamp": _RUN_AT}
    if method:
        row["verification_method"] = method
    if applies_to:
        row["applies_to_digest"] = applies_to
    if parents:
        row["parent_evidence"] = list(parents)
    if coverage_note:
        row["coverage_note"] = coverage_note
    row.update(extra)
    return row


def _claim(claim_id: str, proposition: str, supporting: Sequence[str] = (),
           contradicting: Sequence[str] = (), attempts: Sequence[Mapping] = (),
           is_root: bool = True, **extra: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "record_type": "claim", "claim_id": claim_id, "proposition": proposition,
        "is_root": is_root}
    if supporting:
        row["supporting_evidence"] = list(supporting)
    if contradicting:
        row["contradicting_evidence"] = list(contradicting)
    if attempts:
        row["verification_attempts"] = [dict(a) for a in attempts]
    row.update(extra)
    return row


def _consequence(**dimensions: str) -> Dict[str, Any]:
    row: Dict[str, Any] = {"record_type": "consequence"}
    row.update({k.upper(): v for k, v in dimensions.items()})
    return row


#: A clean, complete software change. Everything else in the corpus is this
#: document with exactly one thing broken, so a difference in outcome is
#: attributable to the break rather than to two unrelated documents.
def _clean_release(digest: str = SERVICE_V1) -> List[Dict[str, Any]]:
    return [
        # The run, so "what did it actually do" is answerable. Without one the
        # execution_reconstruction dimension is NOT_ASSESSED and no profile that
        # promotes on an action's own record has anything to promote on.
        {"record_type": "execution", "trace_id": "release-run-01", "steps": [
            {"type": "tool_call", "tool": "read_file"},
            {"type": "llm_call", "model": "coder", "tokens": 1_800},
            {"type": "tool_call", "tool": "write_file"},
            {"type": "tool_call", "tool": "run_command"},
            {"type": "tool_call", "tool": "read_file"},
            {"type": "tool_call", "tool": "deploy"},
        ]},
        _artifact("service.py", digest),
        _evidence("tests", "TEST_RESULT", "ci://pytest", "TEST_SUITE",
                  applies_to=digest,
                  coverage_note="the payment suite; does not cover the gateway sandbox"),
        _evidence("static", "ANALYSIS_RESULT", "tool://semgrep", "STATIC_ANALYSIS",
                  applies_to=digest,
                  coverage_note="the changed file only"),
        _claim("c-behaviour", "the change preserves charge() semantics",
               supporting=["tests", "static"],
               attempts=[{"method": "TEST_SUITE", "outcome": "PASSED",
                          "verifier": "ci://pytest", "evidence": ["tests"],
                          "target_digest": digest},
                         {"method": "STATIC_ANALYSIS", "outcome": "PASSED",
                          "verifier": "tool://semgrep", "evidence": ["static"],
                          "target_digest": digest}]),
        _consequence(reversibility="REVERSIBLE", scope="SINGLE_SUBJECT",
                     externality="CONTAINED", user_impact="INDIRECT",
                     financial_impact="NONE", data_impact="NONE",
                     security_impact="NONE", production_impact="NON_PRODUCTION",
                     legal_impact="NONE"),
    ]


# ── running one case ─────────────────────────────────────────────────────────

def _methodology(name: str) -> Any:
    if not name:
        return None
    from release_gate.assurance.methodologies import default_registry
    registry = default_registry()
    found = registry.latest(name)
    if found is None:
        raise CorpusError(
            f"{name!r} is not a registered methodology. Known: "
            + ", ".join(sorted(registry.ids())))
    return found


def _assure(document: Sequence[Mapping[str, Any]], *, case: "CorpusCase",
            source: str) -> Any:
    """Through `normalise` and `assure_normalisation` — the path the CLI takes.

    Deliberately not a shortcut that builds an `AssuranceCase` directly: a
    corpus that bypassed ingest would score an engine the product does not ship,
    and every boundary defect found in this architecture so far lived in exactly
    that gap.
    """
    from release_gate.assurance.ingest import detect_document, normalise
    from release_gate.assurance.zero_config import assure_normalisation
    rows = [dict(r) for r in document]
    content = ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()
    detection = detect_document(rows, filename=source)
    normalisation = normalise(rows, detection, source=source, content=content)
    return assure_normalisation(
        normalisation, source_name=source,
        methodology=_methodology(case.methodology),
        objective=case.objective or f"Assurance of {case.case_id}")


#: name → a callable returning a decided outcome. The shipped demos, unmodified.
GENERATORS: Mapping[str, Callable[[], Any]] = {
    "frontier_research": lambda: __import__(
        "release_gate.demos.frontier_research", fromlist=["run"]).run().outcome,
    "single_agent": lambda: __import__(
        "release_gate.demos.single_agent", fromlist=["run"]).run().outcome,
}


def run_case(case: "CorpusCase") -> CaseRun:
    """Put one corpus case through the engine, and through whatever moved."""
    if case.generator:
        return CaseRun(case=case, outcome=GENERATORS[case.generator]())
    outcome = _assure(case.document, case=case, source=f"{case.case_id}.jsonl")
    revised = approval = standing = invalidation = None

    if case.revision:
        revised = _assure(case.revision, case=case,
                          source=f"{case.case_id}.jsonl")

    if case.approve:
        from release_gate.assurance.approval import (
            ApprovalAcknowledgement, offer_approval, submit_approval, check_approval)
        offer = offer_approval(outcome.case, outcome)
        submission = submit_approval(
            outcome.case,
            ApprovalAcknowledgement(
                case_version=offer.case_version,
                subject_digest=offer.subject_digest,
                evidence_pack_digest=offer.evidence_pack_digest,
                case_digest=offer.case_digest),
            approver="reviewer@example.test", scope="the corpus case as offered")
        approval = submission.approval
        if approval is not None and revised is not None:
            standing = check_approval(approval, revised.case)

    if case.revision and revised is not None:
        from release_gate.assurance.mutation import dependencies_from_case
        index = dependencies_from_case(outcome.case)
        moved = _moved_content(outcome.case, revised.case)
        if moved:
            invalidation = index.apply(moved)

    return CaseRun(case=case, outcome=outcome, revised=revised,
                   approval=approval, standing=standing, invalidation=invalidation)


def _moved_content(before: Any, after: Any) -> Tuple[Any, ...]:
    """What the verifications ran against, and what it is now.

    Derived by comparing the two cases rather than declared by the corpus: a
    mutation the corpus asserted would test the assertion, not the engine.

    Keyed on the verification's own `target_id` and `target_digest`, because
    that is what `dependencies_from_case` indexes. An artifact's `artifact_id`
    is content-addressed at ingest, so "service.py at two digests" is two
    records with two ids and comparing *those* finds nothing — which is how this
    was first written and why it reported no mutation at all.
    """
    from release_gate.assurance.mutation import DependencyKind, MutationEvent
    from release_gate.assurance.verification import VerificationGraph

    def bound(case: Any) -> Dict[str, str]:
        found: Dict[str, str] = {}
        try:
            attempts = VerificationGraph.from_case(case).attempts
        except Exception:
            return found
        for attempt in attempts:
            target = getattr(attempt, "target", None)
            target_id = str(getattr(target, "target_id", "") or "")
            digest = str(getattr(attempt, "target_digest", "") or "")
            if target_id and digest:
                found[target_id] = digest
        return found

    old, new_state = bound(before), bound(after)
    events = []
    for target_id, was in old.items():
        now = new_state.get(target_id)
        if now and now != was:
            events.append(MutationEvent(
                logical_id=target_id, kind=DependencyKind.TARGET,
                previous_digest=was, current_digest=now,
                detail="the content this check ran against was rebuilt"))
    return tuple(events)


def _without(document: Sequence[Mapping[str, Any]], *,
             record_type: str = "", key: str = "") -> List[Dict[str, Any]]:
    rows = [dict(r) for r in document]
    for row in rows:
        if not record_type or row.get("record_type") == record_type:
            row.pop(key, None)
    return rows


def _with_claim(document: Sequence[Mapping[str, Any]],
                mutate: Callable[[Dict[str, Any]], None]) -> List[Dict[str, Any]]:
    rows = [dict(r) for r in document]
    for row in rows:
        if row.get("record_type") == "claim":
            mutate(row)
    return rows


def build_corpus() -> Tuple[CorpusCase, ...]:
    """The sixteen, each one the clean release with a single thing changed.

    One baseline with one break per case, so a difference in outcome is
    attributable to the break rather than to two unrelated documents. Where a
    kind needs more than one case to say anything — `incomplete_evidence` needs
    both a partial shortfall and a total one — it gets more than one.
    """
    cases: List[CorpusCase] = []
    add = cases.append

    # 1 — a clean, complete change. Nothing is wrong and nothing should be said
    #     to be wrong. This is the false-positive control for the whole corpus.
    add(CorpusCase(
        case_id="valid-release", kind="valid_release", case_class=CaseClass.QUIET,
        defect="none: subject identified, execution reconstructed, consequence "
               "stated, two producers, no contradiction, no mutation",
        document=_clean_release(), methodology="general-autonomous-action",
        expect_decision="PROMOTE",
        behaviours=("coverage_reported", "verdict_names_its_rules",
                    "nothing_blocking", "promoted"),
        notes="Promotes without needing an acceptance — RG-ZC-005 does not fire — "
              "so it is a cleaner baseline than a case promoted by waiver."))

    # 2 — a check ran and failed. The clearest form of a release that should not go.
    add(CorpusCase(
        case_id="invalid-release", kind="invalid_release",
        case_class=CaseClass.DETECTION,
        defect="the test-suite verification attempt on the load-bearing claim "
               "reports FAILED, while the static-analysis one still reports PASSED",
        document=_with_claim(_clean_release(), lambda c: c["verification_attempts"][0]
                             .__setitem__("outcome", "FAILED")),
        methodology="general-autonomous-action",
        expect_rules=("RG-VERIF-002", "RG-VERIF-003"), expect_decision="BLOCK",
        behaviours=("did_not_promote",),
        notes="RG-VERIF-003 is the pair: a claim with both a passing and a failing "
              "attempt is not a claim with one result."))

    # 3 — a declared denominator, partly unmet.
    add(CorpusCase(
        case_id="incomplete-evidence", kind="incomplete_evidence",
        case_class=CaseClass.DETECTION,
        defect="CI declares a five-job matrix; two jobs reported",
        document=list(_clean_release()) + [
            {"record_type": "expectation", "dimension": "ci jobs", "expected": 5,
             "observed": 2,
             "source": {"kind": "CI_PLAN", "declared_by": "ci://github",
                        "authenticated": True, "detail": "the declared job matrix"}}],
        methodology="general-autonomous-action",
        expect_rules=("RG-EXPECT-001",), expect_decision="HOLD",
        behaviours=("did_not_promote", "required_evidence_named")))

    # 4 — two "independent" checks that both descend from one record.
    add(CorpusCase(
        case_id="false-independence", kind="false_independence",
        case_class=CaseClass.DETECTION,
        defect="the test run and the static analysis have different producers but "
               "both derive from one build fixture, so the second opinion is the "
               "first opinion twice",
        document=(lambda rows: rows)([
            *(_clean_release()[:2]),
            _evidence("build-fixture", "OTHER", "agent://builder", "",
                      producer_kind="agent"),
            *[{**r, "parent_evidence": ["build-fixture"]}
              if r.get("record_type") == "evidence" else r
              for r in _clean_release()[2:]]]),
        methodology="general-autonomous-action",
        expect_rules=("RG-INDEP-001", "RG-INDEP-002"),
        behaviours=("coverage_reported",),
        notes="Detected and ADVISORY: the case still promotes. Reported as found, "
              "not as blocked — see the results table, which keeps detection and "
              "decision in separate columns for exactly this reason."))

    # 5 — a verifier that asserts a result and cites nothing.
    add(CorpusCase(
        case_id="fake-verifier", kind="fake_verifier",
        case_class=CaseClass.DETECTION,
        defect="a third attempt claims a FORMAL_PROOF passed while citing no "
               "evidence and recording no independence lineage",
        document=_with_claim(_clean_release(), lambda c: c["verification_attempts"]
                             .append({"method": "FORMAL_PROOF", "outcome": "PASSED",
                                      "verifier": "tool://prover", "evidence": [],
                                      "detail": "proved"})),
        methodology="general-autonomous-action",
        expect_rules=("RG-REPL-006",),
        behaviours=("coverage_reported",),
        notes="The engine never credits a declared attempt as admissible "
              "verification at all (§10r), so the finding is about corroboration: "
              "a second opinion that says nothing about where it came from cannot "
              "be shown to rest on anything different from the first."))

    # 6 — an approval taken against one state, checked against the next.
    add(CorpusCase(
        case_id="stale-approval", kind="stale_approval",
        case_class=CaseClass.BEHAVIOUR,
        defect="a reviewer approves the case; the service is then rebuilt and the "
               "same evidence resubmitted against the new digest",
        document=_clean_release(), revision=_clean_release(SERVICE_V2),
        approve=True, methodology="general-autonomous-action",
        behaviours=("approval_stops_binding", "approval_says_why_it_stopped"),
        notes="The approval is taken through the real two-step — offer, "
              "acknowledge, submit — because an approval the corpus constructed "
              "by hand would not exercise the binding that is the whole point."))

    # 7 — the artifact moves after it was checked.
    add(CorpusCase(
        case_id="artifact-mutation", kind="artifact_mutation",
        case_class=CaseClass.BEHAVIOUR,
        defect="service.py changes digest between the two states while the "
               "verifications still name the old one",
        document=_clean_release(),
        revision=_clean_release(SERVICE_V2),
        methodology="general-autonomous-action",
        behaviours=("mutation_invalidates_its_verifications",),
        notes="The mutation events are computed by comparing the two cases, not "
              "declared by the corpus: a mutation the corpus asserted would test "
              "the assertion rather than the engine."))

    # 8 — evidence that contradicts the claim its sibling supports.
    add(CorpusCase(
        case_id="open-contradiction", kind="open_contradiction",
        case_class=CaseClass.DETECTION,
        defect="a nightly run contradicts the load-bearing claim and nothing "
               "answers it",
        document=[*_clean_release(),
                  _evidence("counter-run", "TEST_RESULT", "ci://nightly", "",
                            contradicts_claims=["c-behaviour"])],
        methodology="general-autonomous-action",
        expect_rules=("RG-CONTRA-003", "RG-CONTRA-005"), expect_decision="BLOCK",
        behaviours=("did_not_promote",)))

    # 9 — a challenge that was raised and answered. Must not hold the case.
    add(CorpusCase(
        case_id="resolved-contradiction", kind="resolved_contradiction",
        case_class=CaseClass.QUIET,
        defect="none: a counterexample was found, traced to a stale fixture, and "
               "resolved with the evidence that settled it",
        document=[*_clean_release(),
                  {"record_type": "counterexample", "target_claim": "c-behaviour",
                   "method": "PROPERTY_TEST", "result": "FOUND", "status": "RESOLVED",
                   "producer_id": "tool://hypothesis",
                   "resolution": "the failing sequence hit a fixture bug; fixed and re-run",
                   "resolution_evidence": ["tests"],
                   "searched": "1e6 randomised order sequences"}],
        methodology="general-autonomous-action", expect_decision="PROMOTE",
        behaviours=("promoted", "nothing_blocking"),
        notes="The pair to case 10. Same record type, same target, opposite status — "
              "so a scorer that confused 'a challenge exists' with 'a challenge "
              "stands' would fail one of the two."))

    # 10 — the same challenge, unanswered.
    add(CorpusCase(
        case_id="unresolved-counterexample", kind="unresolved_counterexample",
        case_class=CaseClass.DETECTION,
        defect="a property test found a double-charge sequence and nothing "
               "answers it",
        document=[*_clean_release(),
                  {"record_type": "counterexample", "target_claim": "c-behaviour",
                   "method": "PROPERTY_TEST", "result": "FOUND", "status": "OPEN",
                   "producer_id": "tool://hypothesis",
                   "detail": "charge() double-charges on a retried order",
                   "searched": "1e6 randomised order sequences"}],
        methodology="general-autonomous-action",
        expect_rules=("RG-CEX-001",), expect_decision="BLOCK",
        behaviours=("did_not_promote",)))

    # 11 — evidence nobody is answerable for.
    add(CorpusCase(
        case_id="missing-provenance", kind="missing_provenance",
        case_class=CaseClass.DETECTION,
        defect="no evidence record names a producer, so every record falls back "
               "to the document's own envelope",
        document=_without(_clean_release(), record_type="evidence", key="producer"),
        methodology="general-autonomous-action",
        expect_rules=("RG-PROV-001", "RG-PROV-002"),
        behaviours=("coverage_reported",),
        notes="RG-PROV-002 is the sharper of the two: everything tracing to one "
              "producer means the corroboration in this case is one party agreeing "
              "with itself."))

    # 12 — one agent, one task, done properly. The shipped demo, unmodified.
    add(CorpusCase(
        case_id="single-agent-action", kind="single_agent_legitimate_action",
        case_class=CaseClass.QUIET,
        defect="none: a migration with tests, a dry run and a stated consequence",
        document=(), generator="single_agent", expect_decision="PROMOTE",
        behaviours=("promoted", "coverage_reported", "unassessed_is_visible"),
        notes="Promotes *with* an acceptance (RG-ZC-005), unlike case 1 — the "
              "methodology tolerates the single-producer and no-independent-check "
              "holds for a bounded, reversible action. The finding still shows."))

    # 13 — the whole declared denominator missing. The case that found the defect.
    add(CorpusCase(
        case_id="evidence-omission", kind="evidence_omission",
        case_class=CaseClass.DETECTION,
        defect="CI declares a five-job matrix and none of the five reported — "
               "total omission, not a shortfall",
        document=[*_clean_release(),
                  {"record_type": "expectation", "dimension": "ci jobs",
                   "expected": 5, "observed": 0,
                   "source": {"kind": "CI_PLAN", "declared_by": "ci://github",
                              "authenticated": True,
                              "detail": "the declared job matrix"}}],
        methodology="general-autonomous-action",
        expect_rules=("RG-EXPECT-001",), expect_decision="HOLD",
        behaviours=("did_not_promote",),
        notes="This case failed when it was written. Four of five arriving held "
              "the case; none of five arriving PROMOTED it, because the ledger "
              "routed total absence to a state no rule read. The pair with case 3 "
              "is the regression guard (Invariant 13)."))

    # 14 — an execution nobody can bound. UNKNOWN is the right answer.
    add(CorpusCase(
        case_id="unknown-completeness", kind="unknown_completeness",
        case_class=CaseClass.BEHAVIOUR,
        defect="a trace with no declared step count, so whether it is the whole "
               "run cannot be established either way",
        document=_clean_release(), methodology="general-autonomous-action",
        behaviours=("completeness_unknown", "completeness_not_claimed_complete",
                    "unassessed_is_visible"),
        notes="Scored as behaviour, never as detection. 'Correctly said it did not "
              "know' has no positive class, and counting it as a hit would let a "
              "detection rate rise by declining to answer (Invariant 3)."))

    # 15 — a check bound to a state the case is not in.
    add(CorpusCase(
        case_id="wrong-target-digest", kind="wrong_target_digest",
        case_class=CaseClass.DETECTION,
        defect="both verifications name an applies_to_digest that no artifact in "
               "the case carries",
        document=[dict(r, applies_to_digest=SERVICE_V2)
                  if r.get("record_type") == "evidence" else r
                  for r in _clean_release()],
        methodology="general-autonomous-action",
        expect_rules=("RG-DRIFT-005",), expect_decision="HOLD",
        behaviours=("did_not_promote", "no_verification_covers_the_subject"),
        notes="RG-ACT-004 fires too, but that is the methodology's requirement "
              "rather than a structural finding, so it is not scored here."))

    # 16 — ten thousand agents, legitimately. Scale must not buy a verdict.
    add(CorpusCase(
        case_id="ten-thousand-agents", kind="ten_thousand_agent_workflow",
        case_class=CaseClass.BEHAVIOUR,
        defect="none injected: a full-scale research workflow with the phenomena "
               "that occur naturally at that size",
        document=(), generator="frontier_research",
        behaviours=("coverage_reported", "unassessed_is_visible",
                    "scale_did_not_buy_a_verdict", "verdict_names_its_rules"),
        notes="Not a detection case. There is no injected defect to find, and the "
              "question is whether a workflow with thousands of contributors still "
              "reports what it does not know (Invariant 6)."))

    return tuple(cases)


# ── scoring ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CaseResult:
    """What one case produced, scored against what its construction expected."""

    case_id: str
    kind: str
    case_class: CaseClass
    decision: str
    found: Tuple[str, ...] = ()
    #: Expected rules that fired, and expected rules that did not.
    hits: Tuple[str, ...] = ()
    misses: Tuple[str, ...] = ()
    #: For a QUIET case: findings that would disqualify. Advisories are not here
    #: — see `score` for why an advisory is not a false positive.
    false_positives: Tuple[str, ...] = ()
    #: name → (passed, what the engine reported)
    behaviours: Mapping[str, Tuple[bool, str]] = field(default_factory=dict)
    decision_matched: Optional[bool] = None
    #: Did the gate stop this case — that is, was the verdict anything other
    #: than PROMOTE? Recorded for every class, because it is the numerator and
    #: the denominator of the only precision this corpus reports.
    #:
    #: Decision-based rather than finding-based, because the gate is what a user
    #: experiences. `wrong-target-digest` raises no *structural* blocking finding
    #: and is still held, by the methodology's own requirement; counting it as
    #: "not gated" would have described a case that was, in fact, stopped.
    flagged: bool = False

    @property
    def passed(self) -> bool:
        """Everything this case's class can be wrong about, and nothing else."""
        return (not self.misses and not self.false_positives
                and all(ok for ok, _ in self.behaviours.values())
                and self.decision_matched is not False)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "corpus_case_result", "record_id": self.case_id,
                "case_id": self.case_id, "kind": self.kind,
                "class": self.case_class.value, "decision": self.decision,
                "hits": list(self.hits), "misses": list(self.misses),
                "false_positives": list(self.false_positives),
                "behaviours": {k: {"passed": v[0], "reported": v[1]}
                               for k, v in self.behaviours.items()},
                "decision_matched": self.decision_matched, "flagged": self.flagged,
                "passed": self.passed}


@dataclass(frozen=True)
class ClassScore:
    """One case class's numbers, with the denominator stated.

    The denominator is a field rather than a footnote because a rate over four
    cases and a rate over four hundred are different claims, and a table that
    shows only the percentage invites the second reading.
    """

    case_class: CaseClass
    cases: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    behaviours_run: int = 0
    behaviours_passed: int = 0

    #: How many of this class's cases raised something disqualifying.
    flagged: int = 0

    @property
    def recall(self) -> Optional[float]:
        """Of the rules a construction should raise, how many fired.

        Rule-level and `DETECTION`-only. A `QUIET` case has nothing to recall
        and a `BEHAVIOUR` case has no positive class at all, so both answer
        `None` rather than a 1.0 that would be quoted out of its table.
        """
        if self.case_class is not CaseClass.DETECTION or not (self.tp + self.fn):
            return None
        return round(self.tp / (self.tp + self.fn), 4)

    @property
    def precision(self) -> None:
        """Deliberately `None`, at every class.

        There is no honest per-class precision here. A false positive is only
        ever counted against a `QUIET` case, so a `DETECTION`-class precision
        would be 1.0 by construction — a number that can only ever be perfect,
        which is worse than no number. And a structural defect legitimately
        produces a *cascade*: a failed verification really does create a
        contradiction and a replication disagreement, so counting the
        unexpected-but-correct siblings as false positives would be wrong in the
        other direction.

        Precision lives at the case level instead, on `CorpusResult`, where the
        question has an answer: of the cases where the engine raised something
        disqualifying, how many had a defect built in.
        """
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "corpus_class_score", "record_id": self.case_class.value,
                "class": self.case_class.value, "cases": self.cases,
                "tp": self.tp, "fp": self.fp, "fn": self.fn,
                "flagged": self.flagged, "recall": self.recall,
                "behaviours_run": self.behaviours_run,
                "behaviours_passed": self.behaviours_passed}


@dataclass(frozen=True)
class CorpusResult:
    """The whole run, and what it entitles anyone to say."""

    results: Tuple[CaseResult, ...] = ()
    by_class: Mapping[str, ClassScore] = field(default_factory=dict)
    scope: BenchmarkScope = field(default_factory=BenchmarkScope)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def flagged_with_defect(self) -> int:
        """DETECTION cases the gate stopped."""
        return sum(1 for r in self.results
                   if r.case_class is CaseClass.DETECTION and r.flagged)

    @property
    def flagged_without_defect(self) -> int:
        """QUIET cases it stopped anyway. These are the real false positives."""
        return sum(1 for r in self.results
                   if r.case_class is CaseClass.QUIET and r.flagged)

    @property
    def precision(self) -> Optional[float]:
        """Of the cases the gate stopped, how many had a defect built in.

        Case-level, and the only precision this corpus reports. Computed over
        `DETECTION` and `QUIET` cases together, because a precision that never
        looks at the clean cases cannot come out wrong — which was true of the
        first version of this metric and is the reason it moved here.
        """
        flagged = self.flagged_with_defect + self.flagged_without_defect
        return round(self.flagged_with_defect / flagged, 4) if flagged else None

    @property
    def detected_but_not_gated(self) -> Tuple[str, ...]:
        """Defects the engine found and did not stop the release for.

        Not a failure, and reported rather than folded away: `false_independence`
        raises only advisories, so the case is detected *and promoted*. A table
        that showed detection alone would let a rule that fires read as a rule
        that stopped something.
        """
        return tuple(r.case_id for r in self.results
                     if r.case_class is CaseClass.DETECTION and r.hits
                     and not r.flagged)

    @property
    def failures(self) -> Tuple[CaseResult, ...]:
        return tuple(r for r in self.results if not r.passed)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "corpus_result", "record_id": "assurance-corpus",
                "schema_version": CORPUS_SCHEMA_VERSION,
                "cases": len(self.results), "passed": self.passed,
                "precision": self.precision,
                "flagged_with_defect": self.flagged_with_defect,
                "flagged_without_defect": self.flagged_without_defect,
                "detected_but_not_gated": list(self.detected_but_not_gated),
                "by_class": {k: v.to_dict() for k, v in self.by_class.items()},
                "scope": self.scope.to_dict(),
                "results": [r.to_dict() for r in self.results]}


def _disqualifying(outcome: Any, methodology: Any = None) -> Tuple[str, ...]:
    """Findings that would stop a release, for false-positive scoring.

    Two exclusions, both deliberate.

    **Advisories.** "Nothing declared what this system is permitted to do" is a
    true statement about a case with no manifest. Counting it against a clean
    case would make the corpus reward silence, which is the opposite of what
    this engine is for. What a clean case must not attract is a finding that
    says *do not proceed*.

    **Findings the methodology accepted.** An acceptance is a decision taken in
    advance that a structural fact does not disqualify *here*, under a stated
    consequence ceiling — the single-agent profile accepts `RG-VERIF-001`
    because one agent doing one task has no independent check by construction
    (§10aj). The finding still stands and is still shown; scoring it as a false
    positive would mark the engine wrong for reporting something true that the
    methodology had already weighed.
    """
    findings = list(outcome.analysis.blocking) + list(outcome.analysis.holding)
    rule_ids = {f.rule_id for f in findings}
    if methodology is not None and hasattr(methodology, "acceptance_for"):
        profile = getattr(outcome, "consequence", None)
        stated = {d.dimension.value: d.value
                  for d in (getattr(profile, "known", ()) or ())}
        rule_ids = {r for r in rule_ids
                    if methodology.acceptance_for(r, stated) is None}
    return tuple(sorted(rule_ids))


def _active_methodology(case: "CorpusCase", outcome: Any) -> Any:
    """The methodology this run was actually assessed under.

    Read back from the outcome for a generated case, whose methodology the demo
    chose rather than the corpus.
    """
    if case.methodology:
        return _methodology(case.methodology)
    ref = str(getattr(outcome.assessment, "methodology_ref", "") or "")
    if not ref:
        return None
    from release_gate.assurance.methodologies import default_registry
    return default_registry().latest(ref.split("@")[0])


def score(cases: Optional[Sequence[CorpusCase]] = None) -> CorpusResult:
    """Run every case and score each one against what its class can measure."""
    from release_gate.assurance.rules_registry import RuleRegistryError, family_of

    corpus = tuple(cases) if cases is not None else build_corpus()
    results: List[CaseResult] = []
    tallies: Dict[CaseClass, Dict[str, int]] = {
        c: {"cases": 0, "tp": 0, "fp": 0, "fn": 0, "run": 0, "passed": 0,
            "flagged": 0}
        for c in CaseClass}

    for case in corpus:
        for rule_id in case.expect_rules:
            try:
                family_of(rule_id)
            except RuleRegistryError as exc:
                raise CorpusError(
                    f"{case.case_id}: expects {rule_id!r}, which no rule family "
                    "owns. An expectation naming a rule that cannot exist scores "
                    "a permanent miss and reads as an engine failure") from exc

        run = run_case(case)
        outcome = run.outcome
        found = tuple(sorted({f.rule_id for f in outcome.analysis.findings}))
        hits = tuple(r for r in case.expect_rules if r in found)
        misses = tuple(r for r in case.expect_rules if r not in found)
        disqualifying = _disqualifying(outcome, _active_methodology(case, outcome))
        false_positives = (disqualifying
                           if case.case_class is CaseClass.QUIET else ())
        behaviours = {name: BEHAVIOURS[name].run(run) for name in case.behaviours}
        decision = _decision(outcome)
        matched = (None if case.expect_decision is None
                   else decision == case.expect_decision)

        results.append(CaseResult(
            case_id=case.case_id, kind=case.kind, case_class=case.case_class,
            decision=decision, found=found, hits=hits, misses=misses,
            false_positives=false_positives, behaviours=behaviours,
            decision_matched=matched, flagged=decision != "PROMOTE"))

        tally = tallies[case.case_class]
        tally["cases"] += 1
        tally["tp"] += len(hits)
        tally["fn"] += len(misses)
        tally["fp"] += len(false_positives)
        tally["run"] += len(behaviours)
        tally["passed"] += sum(1 for ok, _ in behaviours.values() if ok)
        tally["flagged"] += 1 if decision != "PROMOTE" else 0

    by_class = {
        c.value: ClassScore(case_class=c, cases=t["cases"], tp=t["tp"],
                            fp=t["fp"], fn=t["fn"], flagged=t["flagged"],
                            behaviours_run=t["run"],
                            behaviours_passed=t["passed"])
        for c, t in tallies.items()}
    return CorpusResult(
        results=tuple(results), by_class=by_class,
        scope=BenchmarkScope(cases=len(corpus),
                             kinds=len({c.kind for c in corpus})))
