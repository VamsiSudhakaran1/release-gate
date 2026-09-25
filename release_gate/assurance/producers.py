"""Seven ways evidence arrives, and what each one can and cannot establish.

The static scanner is preserved exactly as it is — 139 rule ids, the benchmark
corpus, the precision-first tier system, all untouched — and repositioned. It is
not the product with an assurance layer bolted on; it is one **Evidence
Producer** feeding an assurance case, alongside runtime traces, formal verifiers,
tests, evals, human review and whatever a customer already has.

    Agent Code Scanner ───┐
    Runtime Trace ─────────┤
    Formal Verifier ───────┤
    Tests ─────────────────┤
    Evals ─────────────────┤
    Human Review ──────────┤
    External Evidence ─────┤
                          ▼
                    Assurance Case

Repositioning is only real if the lanes have different powers, so each one states
what it **cannot** establish. The scanner's limit is the load-bearing one:

**A static finding is a claim about code, not about a run.** `eval(resp)` being
reachable from model output is a fact about the program text. Whether that line
executed, how often, and on what input are facts about an execution, and only the
trace lane holds them. `establishes_runtime_behaviour` is unconditionally `False`
for the scanner — which is not a demotion. A scanner sees every path including the
ones a test run missed, and a trace sees only what happened. Neither subsumes the
other, and a case that had both would be stronger than one with either.

**Measured credibility travels beside a finding, never inside it.** The benchmark
is 93 labeled cases with per-rule true and false positives, and it is real
evidence about a *rule* — not about the finding that rule raised today. So
`credibility_for` reports it and nothing folds it into a score: a verdict that
moved because a benchmark file changed would make the deterministic path depend
on a measurement, and precision is a property of a rule against a corpus, not a
probability that this finding is correct.

Sixteen of the 139 rules carry benchmark data. The other 123 report as
**unmeasured** — not as good. A rule nobody benchmarked is a rule nobody
benchmarked, and defaulting it to the corpus average would manufacture exactly
the confidence this engine refuses everywhere else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

__all__ = [
    "CREDIBILITY",
    "LANES",
    "PRODUCERS_SCHEMA_VERSION",
    "BENCHMARK_CORPUS",
    "EvidenceLane",
    "EvidenceProducer",
    "ProducerError",
    "RuleCredibility",
    "credibility_for",
    "lane_for",
]

PRODUCERS_SCHEMA_VERSION = 1


class ProducerError(ValueError):
    """A producer was described in a way that would overstate what it sees."""


class EvidenceLane(str, Enum):
    """The seven ways evidence reaches a case."""

    CODE_SCANNER = "CODE_SCANNER"
    RUNTIME_TRACE = "RUNTIME_TRACE"
    FORMAL_VERIFIER = "FORMAL_VERIFIER"
    TESTS = "TESTS"
    EVALS = "EVALS"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    EXTERNAL_EVIDENCE = "EXTERNAL_EVIDENCE"


@dataclass(frozen=True)
class EvidenceProducer:
    """One lane: what it sees, what it cannot, and what its output is worth.

    `cannot_establish` is required and must be non-empty. Every producer has
    limits, and the lane that listed none would be the one a reviewer weighted
    hardest — the same rule §10aa applies to a port binding.
    """

    lane: EvidenceLane
    label: str
    establishes: Tuple[str, ...] = ()
    cannot_establish: Tuple[str, ...] = ()
    #: The epistemic status this lane's output carries when nothing further
    #: establishes it. Assigned at the ingest boundary as always; named here so
    #: the lanes can be compared.
    default_status: str = "DECLARED"
    #: Whether this lane is structurally independent of the thing it assesses.
    #: A scanner reading the code is not the agent that wrote it; an agent's own
    #: trace of itself is not independent of it.
    independent_of_subject: bool = True
    evidence_types: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane", EvidenceLane(self.lane))
        for name in ("establishes", "cannot_establish", "evidence_types"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not self.cannot_establish:
            raise ProducerError(
                f"{self.lane.value}: state what this producer cannot establish. "
                "Every lane has limits, and the one that lists none is the one a "
                "reviewer will weight hardest")

    @property
    def establishes_runtime_behaviour(self) -> bool:
        """Whether this lane can say what actually happened when the thing ran.

        `False` for everything but the runtime trace. The scanner sees every path
        including ones no run took; the trace sees only the paths a run took.
        Neither subsumes the other, and reading a static finding as a runtime
        fact is the single most available mistake here.
        """
        return self.lane is EvidenceLane.RUNTIME_TRACE

    @property
    def establishes_correctness(self) -> bool:
        """`True` only for a formal verifier, and only within its stated scope.

        Tests and evals sample; a scanner pattern-matches; a human reads. A proof
        is the one thing here that settles a property rather than sampling it,
        and even then only the property it was asked about.
        """
        return self.lane is EvidenceLane.FORMAL_VERIFIER

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "evidence_producer", "record_id": self.lane.value,
                "lane": self.lane.value, "label": self.label,
                "establishes": list(self.establishes),
                "cannot_establish": list(self.cannot_establish),
                "default_status": self.default_status,
                "independent_of_subject": self.independent_of_subject,
                "evidence_types": list(self.evidence_types),
                "establishes_runtime_behaviour": self.establishes_runtime_behaviour,
                "establishes_correctness": self.establishes_correctness,
                "notes": self.notes}


_LANE_LIST: Tuple[EvidenceProducer, ...] = (
    EvidenceProducer(
        lane=EvidenceLane.CODE_SCANNER,
        label="agent code scanner (release-gate's own static analysis)",
        establishes=("that a pattern is present in the program text",
                     "that a tainted value can reach a sink along some path",
                     "that a declared safeguard is absent from the code"),
        cannot_establish=("that the path it found was ever taken",
                          "how often, on what input, or with what consequence",
                          "that a path it did not find does not exist — taint is "
                          "intra-procedural, and cross-function flows are "
                          "deliberately missed rather than inferred",
                          "that code it could not parse is safe"),
        default_status="DERIVED",
        evidence_types=("STATIC_FINDING",),
        notes="Precision-first by design: a HIGH may never rest on a variable "
              "name, because a name is spelling and not provenance. 139 rule "
              "ids, 16 of them benchmarked."),
    EvidenceProducer(
        lane=EvidenceLane.RUNTIME_TRACE,
        label="runtime trace (OTLP, Langfuse, Arize, an orchestrator export)",
        establishes=("that a step ran, in what order, and against what digest",
                     "which tools were reached and which agents delegated"),
        cannot_establish=("that a path not taken in this run cannot be taken",
                          "that the producer's account of its own run is complete",
                          "that a step reported as successful did what it claims"),
        default_status="DECLARED",
        independent_of_subject=False,
        evidence_types=("TRACE", "TOOL_RESULT"),
        notes="The only lane that sees what happened — and it sees exactly one "
              "run. An agent's trace of itself is not independent of it, which "
              "is why this lane defaults to not-independent."),
    EvidenceProducer(
        lane=EvidenceLane.FORMAL_VERIFIER,
        label="formal verifier (SMT, model checker, proof assistant)",
        establishes=("that a stated property holds over the modelled system",
                     "a counterexample when it does not"),
        cannot_establish=("that the model matches the system it stands for",
                          "anything about a property nobody asked it about",
                          "that an unbounded search which timed out found nothing"),
        default_status="DECLARED",
        evidence_types=("FORMAL_PROOF",),
        notes="The one lane that settles rather than samples, and only inside "
              "the scope it was given. A proof about a model is a proof about "
              "the model."),
    EvidenceProducer(
        lane=EvidenceLane.TESTS,
        label="tests (unit, integration, dry run)",
        establishes=("that the cases which ran, passed",
                     "that a regression the suite covers has not returned"),
        cannot_establish=("that a case nobody wrote would pass",
                          "coverage of anything the suite does not exercise",
                          "that passing here means passing in production"),
        default_status="DECLARED",
        evidence_types=("TEST_RESULT",),
        notes="Samples. A green suite is a statement about the suite."),
    EvidenceProducer(
        lane=EvidenceLane.EVALS,
        label="evals (promptfoo, a scoring harness, an LLM judge)",
        establishes=("a score against a stated dataset and rubric",
                     "a comparison between two candidates on that dataset"),
        cannot_establish=("that the dataset represents production traffic",
                          "that a judge model's score is the property it names",
                          "that a threshold somebody picked is a safety margin"),
        default_status="DECLARED",
        evidence_types=("EVAL_RESULT",),
        notes="A score is a measurement against a rubric, and the rubric is an "
              "assumption. Where a model produced the score it is DERIVED and "
              "carries its model identity (§10r)."),
    EvidenceProducer(
        lane=EvidenceLane.HUMAN_REVIEW,
        label="human review",
        establishes=("that a named person looked and recorded what they found",
                     "a judgement about consequence that no tool holds"),
        cannot_establish=("what the reviewer did not look at",
                          "that reading found what execution would have",
                          "that approval means the evidence was sufficient — an "
                          "approval is an authorization, not a truth certificate"),
        default_status="DECLARED",
        evidence_types=("HUMAN_REVIEW",),
        notes="The only lane that can weigh consequence. Also the only one whose "
              "coverage is entirely unobservable from its output."),
    EvidenceProducer(
        lane=EvidenceLane.EXTERNAL_EVIDENCE,
        label="external evidence (anything a customer already produces)",
        establishes=("whatever the producing system establishes, as it says",),
        cannot_establish=("more than the producing system claims",
                          "its own independence, which has to come from elsewhere",
                          "that release-gate understood a shape it did not "
                          "recognise — an unmapped record is counted, not guessed"),
        default_status="DECLARED",
        evidence_types=("EXTERNAL_REFERENCE", "ATTESTATION"),
        notes="The lane that keeps the other six from being a closed list. A "
              "shape release-gate cannot read is reported as unread."),
)

#: lane → producer, built from one list so the registry cannot disagree with
#: itself about which lanes exist.
LANES: Mapping[EvidenceLane, EvidenceProducer] = {p.lane: p for p in _LANE_LIST}


def lane_for(lane: Any) -> EvidenceProducer:
    found = LANES.get(EvidenceLane(lane))
    if found is None:  # pragma: no cover - EvidenceLane() already validates
        raise ProducerError(f"no producer described for {lane!r}")
    return found


# ── what the benchmark measured ──────────────────────────────────────────────

#: The corpus the per-rule numbers below come from. Named so a credibility
#: record cites a measurement rather than floating free.
BENCHMARK_CORPUS = "release-gate benchmark corpus: 93 labeled cases, 43 vulnerable and 50 clean look-alikes"


@dataclass(frozen=True)
class RuleCredibility:
    """What was measured about one rule, against a named corpus.

    Evidence about a *rule*, not about a finding. A rule with 100% precision on
    93 cases can still be wrong on the ninety-fourth, and the number says how the
    rule behaved on a corpus rather than how likely today's finding is to hold.
    """

    rule_id: str
    true_positives: int
    false_positives: int
    false_negatives: int
    corpus: str = BENCHMARK_CORPUS

    def __post_init__(self) -> None:
        if not str(self.rule_id or "").strip():
            raise ProducerError("a credibility record must name its rule")
        for name in ("true_positives", "false_positives", "false_negatives"):
            if getattr(self, name) < 0:
                raise ProducerError(f"{self.rule_id}: {name} cannot be negative")

    @property
    def precision(self) -> Optional[float]:
        """None when the rule fired on nothing — no denominator, no number."""
        fired = self.true_positives + self.false_positives
        return (self.true_positives / fired) if fired else None

    @property
    def recall(self) -> Optional[float]:
        present = self.true_positives + self.false_negatives
        return (self.true_positives / present) if present else None

    @property
    def measured(self) -> bool:
        return True

    @property
    def predicts_this_finding(self) -> bool:
        """Unconditionally False.

        Precision is how a rule behaved against a corpus. Treating it as the
        probability that today's finding holds would turn a measurement into a
        confidence score, and the corpus is not this codebase.
        """
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "rule_credibility", "record_id": self.rule_id,
                "rule_id": self.rule_id, "measured": True,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
                "precision": self.precision, "recall": self.recall,
                "corpus": self.corpus, "predicts_this_finding": False}


def _cred(rule_id: str, tp: int, fp: int, fn: int) -> RuleCredibility:
    return RuleCredibility(rule_id=rule_id, true_positives=tp,
                           false_positives=fp, false_negatives=fn)


#: Per-rule results, transcribed from `benchmark/RESULTS.md`. Literals rather
#: than a parse of the file at import time: the pure layer reads no files, and a
#: test checks these against the document so the two cannot drift — the same
#: shape as the protocol manifest in §10ae.
_CREDIBILITY_LIST: Tuple[RuleCredibility, ...] = (
    _cred("RG-ACTION-002", 2, 0, 0),
    _cred("RG-ACTION-003", 1, 0, 0),
    _cred("RG-ACTION-004", 1, 0, 0),
    _cred("RG-COST-001", 2, 0, 0),
    _cred("RG-EXEC-001", 15, 0, 0),
    _cred("RG-EXEC-002", 2, 0, 0),
    _cred("RG-EXEC-003", 1, 0, 0),
    _cred("RG-GATE-001", 4, 0, 0),
    _cred("RG-LOOP-001", 3, 0, 0),
    _cred("RG-PARSE-001", 1, 0, 0),
    _cred("RG-PII-001", 1, 0, 0),
    _cred("RG-PROMPT-001", 3, 0, 0),
    _cred("RG-PROMPT-002", 4, 0, 0),
    _cred("RG-SECRET-001", 1, 0, 0),
    _cred("RG-SECRET-002", 2, 0, 0),
    _cred("RG-TOOL-001", 1, 0, 0),
)

CREDIBILITY: Mapping[str, RuleCredibility] = {
    c.rule_id: c for c in _CREDIBILITY_LIST}


def credibility_for(rule_id: str) -> Optional[RuleCredibility]:
    """What was measured about this rule, or `None` for unmeasured.

    `None` means nobody benchmarked it — not that it is unreliable, and not that
    it is fine. Sixteen of the catalogue's rules carry data; defaulting the rest
    to the corpus average would manufacture exactly the confidence this engine
    refuses everywhere else, and a caller that cannot tell "measured at 100%"
    from "never measured" will report the second as the first.
    """
    return CREDIBILITY.get((rule_id or "").strip())
