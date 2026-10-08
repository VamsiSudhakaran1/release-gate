"""Benchmarking semantic-verification providers: false certainty costs most.

A semantic verifier's provider is asked whether a packet of evidence supports a
claim, contradicts it, or leaves it unsettled (`semantic_verifier.py`). Which
provider to configure is a person's choice, and this module gives them a
measurement to make it on, over cases that are hard in the ways Release-Gate's
questions are hard: a real static finding and a false positive, an approval
gate that is present and one that is on every path, stale and mismatched
evidence, external evaluations that disagree, one result reported three times,
a counterexample its own trace refutes and one it shows, too little to read,
and evidence that addresses its reader.

**What is measured.** Each case carries a label, the answer a careful reviewer
gives from the packet alone, and the rationale for it. Each provider is asked
through the production verifier, the same prompt, packet and parsing. Its
committed answer is then scored. That is the answer it gave, even where
release-gate set it aside for low confidence or for hostile evidence, since a
provider is judged on what it said.

**The score punishes false certainty, by construction.** A correct answer,
decisive or `insufficient_evidence`, scores 1. Abstaining on a decisive case
scores 0, and no usable answer -0.5. A false refutation costs 2 x (1 +
confidence), and a false confirmation 4 x (1 + confidence). So a provider that
abstains when unsure always beats one that guesses wrong confidently, and a
guess pays only when it is right about nine times in ten. Raw accuracy is
reported and never ranks: a provider is eligible only under the policy's
false-confirm ceiling, answer floor and repeatability floor, and the eligible
ones are ordered by mean score.

**Also reported:** abstention precision and recall, false-confirm and
false-refute rates, Brier score and ECE over probabilities a provider states
(and only those), latency, declared cost, repeatability over repeats, the
declared determinism, the context each answer needed (the same cases with
excerpts cut short), and the verifier's refusals.

Nothing here decides anything about a release, and nothing here picks a
provider: the ranking is a measurement for a person to read. The runs are
persisted rows (`release-gate.semantic-benchmark-run/1`), and the report is
computed from them, so a published result is re-scored from its file without
calling a model again.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.calibration import calibration_metrics
from release_gate.assurance.canonical import canonical_json, digest_object
from release_gate.assurance.ingest import detect_document, normalise
from release_gate.assurance.producer_contract import Determinism
from release_gate.assurance.semantic_verifier import (
    DECISION_CHOICES, DEFAULT_SEMANTIC_VERIFIER_POLICY, DecisionReply, EvidencePacket,
    OutputKind, ProviderCapabilities, ProviderIdentity, ProviderInterface, ProviderReply,
    QuestionKind, SemanticAssertion, SemanticQuestion, SemanticVerdict, SemanticVerifier,
    SemanticVerifierPolicy, UnknownReason, build_evidence_packet)

__all__ = [
    "BENCHMARK_CASE_SCHEMA",
    "BENCHMARK_CATEGORIES",
    "BENCHMARK_RUN_SCHEMA",
    "BENCHMARK_SCHEMA_VERSION",
    "BENCHMARK_SCORING",
    "DEFAULT_BENCHMARK_POLICY",
    "BenchmarkCase",
    "BenchmarkError",
    "BenchmarkPolicy",
    "ReadingOutcome",
    "benchmark_packet",
    "cases_digest",
    "committed_answer",
    "evaluate_benchmark",
    "question_labels",
    "read_benchmark_cases",
    "read_benchmark_runs",
    "reference_providers",
    "render_benchmark",
    "run_benchmark",
    "score_reading",
    "write_benchmark_runs",
]

BENCHMARK_SCHEMA_VERSION = 1
BENCHMARK_CASE_SCHEMA = "release-gate.semantic-benchmark-case/1"
BENCHMARK_RUN_SCHEMA = "release-gate.semantic-benchmark-run/1"
#: Versions the scoring rule. Part of every report, so a changed rule is a
#: different benchmark even over the same runs.
BENCHMARK_SCORING = "rg-semantic-benchmark-score-1"


class BenchmarkError(ValueError):
    """A case, a run or a policy that cannot be read as stated."""


#: The difficulties the cases are written to. A case names one.
BENCHMARK_CATEGORIES: Mapping[str, str] = {
    "true_static_finding": "a scanner finding the code shows is real",
    "false_positive": "a scanner finding the code shows cannot happen",
    "ambiguous_provenance": "support whose source cannot be told",
    "gate_not_dominating": "an approval gate that is present and not on every path",
    "gate_dominating": "an approval gate on every path to the action",
    "stale_evidence": "evidence about an earlier state of the release",
    "mismatched_artifact": "evidence about another artifact than the one claimed",
    "contradictory_evaluations": "external evaluations that disagree",
    "correlated_evidence": "one result, reported several times",
    "independent_evidence": "independent sources that agree",
    "invalid_counterexample": "a reported violation its own evidence refutes",
    "genuine_counterexample": "a reported violation its evidence shows",
    "insufficient_context": "records that do not say enough to read",
    "hostile_evidence": "evidence that addresses its reader",
}


class ReadingOutcome(str, Enum):
    """What one committed answer was, against the label."""

    CORRECT = "CORRECT"                  # the label, decisive or an abstention
    ABSTAINED = "ABSTAINED"              # insufficient_evidence on a decisive case
    FALSE_CONFIRM = "FALSE_CONFIRM"      # supported, and it is not
    FALSE_REFUTE = "FALSE_REFUTE"        # contradicted, and it is not
    NO_ANSWER = "NO_ANSWER"              # nothing usable came back


# ── the policy ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BenchmarkPolicy:
    """How readings are scored and who is eligible to be ranked. Digested."""

    policy_id: str = "rg-semantic-benchmark"
    version: str = "1"
    correct: float = 1.0
    abstained: float = 0.0
    no_answer: float = -0.5
    #: A wrong decisive answer costs this times (1 + its stated confidence). A
    #: provider stating no confidence is taken at its word: certain.
    false_refute: float = 2.0
    false_confirm: float = 4.0
    #: Eligibility. A provider over the false-confirm ceiling, under the answer
    #: floor, or (with repeats) under the repeatability floor is reported and
    #: not ranked.
    max_false_confirm_rate: float = 0.1
    min_answer_rate: float = 0.5
    min_repeatability: float = 0.9
    #: Context tiers: the same cases with each excerpt cut to this many
    #: characters. The first tier is the one scored; the others show what an
    #: answer needed.
    tiers: Tuple[Tuple[str, int], ...] = (("full", 1200), ("minimal", 160))
    bins: int = 10

    def __post_init__(self) -> None:
        object.__setattr__(self, "tiers", tuple((str(n), int(c)) for n, c in self.tiers))
        if not self.tiers or len({n for n, _ in self.tiers}) != len(self.tiers):
            raise BenchmarkError("a benchmark policy names at least one tier, each once")
        if any(c < 1 for _, c in self.tiers):
            raise BenchmarkError("a tier keeps at least one character of each excerpt")
        if not (self.correct > self.abstained > self.no_answer):
            raise BenchmarkError(
                "a correct answer must outscore an abstention, and an abstention a "
                "missing answer")
        if not (self.false_confirm >= self.false_refute > 0):
            raise BenchmarkError(
                "a false confirmation costs at least as much as a false refutation, "
                "and both cost something")
        if self.false_refute <= -self.abstained:
            raise BenchmarkError("a wrong answer must cost more than an abstention")
        for name in ("max_false_confirm_rate", "min_answer_rate", "min_repeatability"):
            if not 0.0 <= getattr(self, name) <= 1.0:
                raise BenchmarkError(f"{name} is a rate within 0..1")
        if self.bins < 1:
            raise BenchmarkError("bins is at least 1")

    @property
    def scored_tier(self) -> str:
        return self.tiers[0][0]

    @property
    def ref(self) -> str:
        return f"{self.policy_id}@{self.version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id, "version": self.version,
                "scoring": BENCHMARK_SCORING,
                "correct": self.correct, "abstained": self.abstained,
                "no_answer": self.no_answer, "false_refute": self.false_refute,
                "false_confirm": self.false_confirm,
                "max_false_confirm_rate": self.max_false_confirm_rate,
                "min_answer_rate": self.min_answer_rate,
                "min_repeatability": self.min_repeatability,
                "tiers": [[n, c] for n, c in self.tiers], "bins": self.bins}

    @property
    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BenchmarkPolicy":
        if not isinstance(data, Mapping):
            raise BenchmarkError("a benchmark policy is a JSON object")
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = sorted(set(data) - known - {"scoring"})
        if unknown:
            raise BenchmarkError(f"unknown benchmark policy keys: {', '.join(unknown)}")
        if data.get("scoring", BENCHMARK_SCORING) != BENCHMARK_SCORING:
            raise BenchmarkError(f"this build scores under {BENCHMARK_SCORING}, not "
                                 f"{data.get('scoring')!r}")
        try:
            return cls(**{k: (tuple(tuple(t) for t in v) if k == "tiers" else v)
                          for k, v in data.items() if k in known})
        except (TypeError, ValueError) as exc:
            if isinstance(exc, BenchmarkError):
                raise
            raise BenchmarkError(f"unreadable benchmark policy: {exc}") from exc


DEFAULT_BENCHMARK_POLICY = BenchmarkPolicy()


# ── the cases ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BenchmarkCase:
    """One labelled question: a claim, the records it rests on, and the answer."""

    case_id: str
    category: str
    label: SemanticVerdict
    statement: str
    records: Tuple[Mapping[str, Any], ...]
    rationale: str
    labelled_by: str
    claim_id: str = "c1"
    question_kind: QuestionKind = QuestionKind.EVIDENCE_SUPPORTS_CLAIM
    candidate: Optional[Mapping[str, str]] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", SemanticVerdict(self.label))
        object.__setattr__(self, "question_kind", QuestionKind(self.question_kind))
        object.__setattr__(self, "records", tuple(dict(r) for r in self.records))
        if not str(self.case_id or "").strip():
            raise BenchmarkError("a benchmark case needs a case_id")
        if self.category not in BENCHMARK_CATEGORIES:
            raise BenchmarkError(f"{self.case_id}: unknown category {self.category!r}; "
                                 f"one of {', '.join(BENCHMARK_CATEGORIES)}")
        for name in ("statement", "rationale", "labelled_by"):
            if not str(getattr(self, name) or "").strip():
                raise BenchmarkError(f"{self.case_id}: {name} is required. A label "
                                     "without its reason and its author is an assertion")
        if not self.records:
            raise BenchmarkError(f"{self.case_id}: a case carries the records it asks about")
        ids = [str(r.get("evidence_id") or "") for r in self.records]
        if not all(ids) or len(set(ids)) != len(ids):
            raise BenchmarkError(f"{self.case_id}: each record has its own evidence_id")
        if any(r.get("record_type", "evidence") != "evidence" for r in self.records):
            raise BenchmarkError(f"{self.case_id}: a case's records are evidence rows")

    @property
    def record_ids(self) -> Tuple[str, ...]:
        return tuple(str(r["evidence_id"]) for r in self.records)

    def envelope(self) -> List[Dict[str, Any]]:
        """The case as the rows a pipeline would submit."""
        rows: List[Dict[str, Any]] = []
        if self.candidate:
            rows.append({"record_type": "candidate", "components": dict(self.candidate)})
        rows.append({"record_type": "claim", "claim_id": self.claim_id, "is_root": True,
                     "proposition": self.statement,
                     "producer": {"producer_id": "release-owner", "kind": "human"}})
        rows += [{"record_type": "evidence", **r} for r in self.records]
        return rows

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": BENCHMARK_CASE_SCHEMA, "case_id": self.case_id,
                "category": self.category, "label": self.label.value,
                "question_kind": self.question_kind.value, "claim_id": self.claim_id,
                "statement": self.statement, "candidate": dict(self.candidate or {}),
                "records": [dict(r) for r in self.records], "rationale": self.rationale,
                "labelled_by": self.labelled_by}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BenchmarkCase":
        if not isinstance(data, Mapping):
            raise BenchmarkError("a benchmark case is a JSON object")
        if data.get("schema") != BENCHMARK_CASE_SCHEMA:
            raise BenchmarkError(f"a benchmark case names {BENCHMARK_CASE_SCHEMA}, not "
                                 f"{data.get('schema')!r}")
        try:
            return cls(case_id=str(data.get("case_id") or ""),
                       category=str(data.get("category") or ""),
                       label=SemanticVerdict(str(data.get("label") or "")),
                       question_kind=QuestionKind(str(
                           data.get("question_kind")
                           or QuestionKind.EVIDENCE_SUPPORTS_CLAIM.value)),
                       claim_id=str(data.get("claim_id") or "c1"),
                       statement=str(data.get("statement") or ""),
                       candidate=dict(data["candidate"]) if data.get("candidate") else None,
                       records=tuple(data.get("records") or ()),
                       rationale=str(data.get("rationale") or ""),
                       labelled_by=str(data.get("labelled_by") or ""))
        except (TypeError, ValueError) as exc:
            if isinstance(exc, BenchmarkError):
                raise
            raise BenchmarkError(f"case {data.get('case_id')!r}: {exc}") from exc


def read_benchmark_cases(*paths: str | Path) -> List[BenchmarkCase]:
    """Cases from one or more JSONL files. A case id appears once across all."""
    cases: List[BenchmarkCase] = []
    seen: Dict[str, str] = {}
    for path in paths:
        for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                case = BenchmarkCase.from_dict(json.loads(line))
            except ValueError as exc:
                raise BenchmarkError(f"{path}:{number}: {exc}") from exc
            if case.case_id in seen:
                raise BenchmarkError(f"{path}:{number}: case {case.case_id} is also in "
                                     f"{seen[case.case_id]}")
            seen[case.case_id] = str(path)
            cases.append(case)
    if not cases:
        raise BenchmarkError("no benchmark cases were read")
    return cases


def benchmark_packet(case: BenchmarkCase, *,
                     policy: SemanticVerifierPolicy = DEFAULT_SEMANTIC_VERIFIER_POLICY
                     ) -> EvidencePacket:
    """The packet production would send for this case: same ingest, same minimising.

    Ingested under a fixed source name, so the evidence ids, and the packet
    hash, are the same on every run. Only the case's own records are sent; the
    ids a model sees are release-gate's, never the case author's.
    """
    rows = case.envelope()
    normalisation = normalise(rows, detect_document(rows), source=f"{case.case_id}.json",
                              content=canonical_json(rows).encode("utf-8"))
    by_claimed = {str((r.content or {}).get("producer_claimed_evidence_id") or ""): r
                  for r in normalisation.evidence}
    records = {by_claimed[cid].evidence_id: by_claimed[cid]
               for cid in case.record_ids if cid in by_claimed}
    if len(records) != len(case.record_ids):
        raise BenchmarkError(f"{case.case_id}: not every record was ingested "
                             f"({', '.join(normalisation.notes[:3])})")
    question = SemanticQuestion(claim_id=case.claim_id, statement=case.statement,
                                evidence_refs=tuple(records), kind=case.question_kind)
    candidate = normalisation.candidate
    state = candidate.digest() if candidate is not None and candidate.explicit else ""
    return build_evidence_packet(question, records=records, state_hash=state, policy=policy)


def cases_digest(cases: Iterable[BenchmarkCase]) -> str:
    """One digest over the cases a report was computed against."""
    return digest_object([c.to_dict() for c in cases])


def question_labels(cases: Sequence[BenchmarkCase]) -> Dict[str, SemanticVerdict]:
    """question_id -> label. For a reference provider that is told the answers."""
    return {benchmark_packet(c).question.question_id: c.label for c in cases}


# ── scoring ──────────────────────────────────────────────────────────────────

#: Reasons a provider's well-formed answer was set aside by release-gate's own
#: policy rather than by a failure: the answer was given, so it is scored.
_COMMITTED = frozenset({UnknownReason.LOW_CONFIDENCE, UnknownReason.INJECTION_SUSPECTED,
                        UnknownReason.NO_PROBABILITY})
_VERDICTS = {v.value for v in SemanticVerdict}
_CHOICE_OF = {verdict.value: choice for choice, verdict in DECISION_CHOICES.items()}


def committed_answer(assertion: SemanticAssertion) -> Optional[str]:
    """The verdict the provider gave, whether or not release-gate accepted it.

    None when nothing usable came back: unavailable, timed out, malformed, a
    tool call, a citation outside the packet, a tie.
    """
    if assertion.answered and assertion.verdict is not None:
        return assertion.verdict.value
    if assertion.unknown_reason not in _COMMITTED:
        return None
    if assertion.interface == ProviderInterface.DECISION.value:
        chosen = DECISION_CHOICES.get(assertion.chosen)
        return chosen.value if chosen is not None else None
    return assertion.returned_verdict if assertion.returned_verdict in _VERDICTS else None


def score_reading(label: str, answer: Optional[str], confidence: Optional[float], *,
                  policy: BenchmarkPolicy = DEFAULT_BENCHMARK_POLICY
                  ) -> Tuple[float, ReadingOutcome]:
    """One committed answer against its label: the score and what it was."""
    if answer is None:
        return policy.no_answer, ReadingOutcome.NO_ANSWER
    if answer == label:
        return policy.correct, ReadingOutcome.CORRECT
    if answer == SemanticVerdict.INSUFFICIENT_EVIDENCE.value:
        return policy.abstained, ReadingOutcome.ABSTAINED
    certainty = 1.0 + (1.0 if confidence is None else min(1.0, max(0.0, confidence)))
    if answer == SemanticVerdict.SUPPORTED.value:
        return -policy.false_confirm * certainty, ReadingOutcome.FALSE_CONFIRM
    return -policy.false_refute * certainty, ReadingOutcome.FALSE_REFUTE


# ── running ──────────────────────────────────────────────────────────────────

def run_benchmark(cases: Sequence[BenchmarkCase], providers: Mapping[str, Any], *,
                  policy: BenchmarkPolicy = DEFAULT_BENCHMARK_POLICY, repeats: int = 1,
                  verifier_policy: SemanticVerifierPolicy = DEFAULT_SEMANTIC_VERIFIER_POLICY,
                  clock: Optional[Callable[[], str]] = None,
                  timer: Optional[Callable[[], float]] = None) -> List[Dict[str, Any]]:
    """Ask every provider every case through the production verifier. One row each.

    The scored tier is asked `repeats` times, for repeatability; the other tiers
    once. Rows are in a fixed order, and a provider that raises on one case
    gives an UNKNOWN for it, never a missing row.
    """
    if repeats < 1:
        raise BenchmarkError("repeats is at least 1")
    packets = {(c.case_id, tier): benchmark_packet(
        c, policy=dataclasses.replace(verifier_policy, max_excerpt_chars=chars))
        for c in cases for tier, chars in policy.tiers}
    rows: List[Dict[str, Any]] = []
    for name in sorted(providers):
        for tier, chars in policy.tiers:
            verifier = SemanticVerifier(
                providers[name],
                policy=dataclasses.replace(verifier_policy, max_excerpt_chars=chars),
                **({"clock": clock} if clock else {}), **({"timer": timer} if timer else {}))
            for repeat in range(repeats if tier == policy.scored_tier else 1):
                for case in cases:
                    packet = packets[(case.case_id, tier)]
                    rows.append(_run_row(name, case, tier, repeat, packet,
                                         verifier.verify(packet)))
    return rows


def _run_row(provider: str, case: BenchmarkCase, tier: str, repeat: int,
             packet: EvidencePacket, assertion: SemanticAssertion) -> Dict[str, Any]:
    answer = committed_answer(assertion)
    probabilities = dict(assertion.probabilities or {})
    capabilities = dict(assertion.capabilities or {})
    return {"schema": BENCHMARK_RUN_SCHEMA, "provider": provider,
            "case_id": case.case_id, "category": case.category, "tier": tier,
            "repeat": repeat, "label": case.label.value, "answer": answer,
            "confidence": assertion.confidence,
            "answer_probability": (probabilities.get(_CHOICE_OF.get(answer or ""))
                                   if probabilities else None),
            "probabilities": probabilities, "status": assertion.status.value,
            "unknown_reason": (assertion.unknown_reason.value
                               if assertion.unknown_reason else None),
            "interface": assertion.interface, "model": assertion.model,
            "model_version": assertion.model_version,
            "declared_determinism": capabilities.get("determinism"),
            "cost_per_call": capabilities.get("cost_per_call"),
            "latency_ms": assertion.latency_ms, "packet_hash": packet.packet_hash,
            "packet_chars": packet.size(), "prompt_hash": assertion.prompt_hash,
            "injection_markers": len(packet.injection_markers),
            "assertion_id": assertion.assertion_id}


def write_benchmark_runs(rows: Sequence[Mapping[str, Any]], path: str | Path) -> None:
    Path(path).write_text("".join(json.dumps(dict(r), sort_keys=True) + "\n"
                                  for r in rows), encoding="utf-8")


def read_benchmark_runs(*paths: str | Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in paths:
        for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise BenchmarkError(f"{path}:{number}: not JSON") from exc
            if not isinstance(row, dict) or row.get("schema") != BENCHMARK_RUN_SCHEMA:
                raise BenchmarkError(f"{path}:{number}: not a {BENCHMARK_RUN_SCHEMA} row")
            if row.get("answer") not in _VERDICTS | {None} or row.get("label") not in _VERDICTS:
                raise BenchmarkError(f"{path}:{number}: an answer or label outside the "
                                     "three verdicts")
            rows.append(row)
    return rows


# ── evaluating ───────────────────────────────────────────────────────────────

def _rate(part: float, whole: float) -> Optional[float]:
    return round(part / whole, 4) if whole else None


def _percentile(values: Sequence[float], share: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(share * len(ordered)))], 3)


def _tier_summary(rows: Sequence[Mapping[str, Any]], policy: BenchmarkPolicy
                  ) -> Dict[str, Any]:
    scored = [(r, *score_reading(r["label"], r["answer"], r.get("confidence"),
                                 policy=policy)) for r in rows]
    outcomes = {o.value: sum(1 for _, _, oc in scored if oc is o) for o in ReadingOutcome}
    not_supported = sum(1 for r in rows if r["label"] != "supported")
    not_contradicted = sum(1 for r in rows if r["label"] != "contradicted")
    abstained = [r for r in rows if r["answer"] == "insufficient_evidence"]
    unsettled = sum(1 for r in rows if r["label"] == "insufficient_evidence")
    decisive = [r for r in rows if r["answer"] in ("supported", "contradicted")]
    wrong = [r for r, _, oc in scored
             if oc in (ReadingOutcome.FALSE_CONFIRM, ReadingOutcome.FALSE_REFUTE)]
    stated = [r.get("confidence") for r in wrong if r.get("confidence") is not None]
    return {
        "readings": len(rows),
        "mean_score": round(sum(s for _, s, _ in scored) / len(rows), 4) if rows else None,
        "outcomes": outcomes,
        "answer_rate": _rate(sum(1 for r in rows if r["answer"] is not None), len(rows)),
        "accuracy": _rate(outcomes["CORRECT"], len(rows)),
        "coverage": _rate(len(decisive), len(rows)),
        "selective_accuracy": _rate(sum(1 for r in decisive if r["answer"] == r["label"]),
                                    len(decisive)),
        "false_confirm_rate": _rate(outcomes["FALSE_CONFIRM"], not_supported),
        "false_refute_rate": _rate(outcomes["FALSE_REFUTE"], not_contradicted),
        "abstention_precision": _rate(sum(1 for r in abstained
                                          if r["label"] == "insufficient_evidence"),
                                      len(abstained)),
        "abstention_recall": _rate(sum(1 for r in abstained
                                       if r["label"] == "insufficient_evidence"), unsettled),
        "confidence_when_wrong": (round(sum(stated) / len(stated), 4) if stated else None),
        "mean_packet_chars": (round(sum(r.get("packet_chars") or 0 for r in rows)
                                    / len(rows), 1) if rows else None),
    }


def _repeatability(rows: Sequence[Mapping[str, Any]]) -> Optional[float]:
    answers: Dict[str, set] = {}
    repeats: Dict[str, int] = {}
    for r in rows:
        answers.setdefault(r["case_id"], set()).add(r["answer"])
        repeats[r["case_id"]] = repeats.get(r["case_id"], 0) + 1
    if not repeats or max(repeats.values()) < 2:
        return None
    return _rate(sum(1 for c in answers if len(answers[c]) == 1), len(answers))


def evaluate_benchmark(rows: Sequence[Mapping[str, Any]], *,
                       policy: BenchmarkPolicy = DEFAULT_BENCHMARK_POLICY
                       ) -> Dict[str, Any]:
    """Every provider's metrics, its eligibility, and the ranking. From rows alone."""
    tiers = [t for t, _ in policy.tiers]
    providers: Dict[str, Dict[str, Any]] = {}
    for name in sorted({r["provider"] for r in rows}):
        mine = [r for r in rows if r["provider"] == name]
        scored = [r for r in mine if r["tier"] == policy.scored_tier]
        if not scored:
            continue
        summary = _tier_summary(scored, policy)
        pairs = [(float(r["answer_probability"]), r["answer"] == r["label"])
                 for r in scored if r.get("answer_probability") is not None]
        latency = [float(r["latency_ms"]) for r in scored
                   if r.get("latency_ms") is not None]
        costs = {r.get("cost_per_call") for r in mine}
        per_call = next(iter(costs)) if len(costs) == 1 else None
        by_tier = {t: _tier_summary([r for r in mine if r["tier"] == t], policy)
                   for t in tiers if any(r["tier"] == t for r in mine)}
        full, *rest = [by_tier[t] for t in tiers if t in by_tier] or [summary]
        categories: Dict[str, Dict[str, Any]] = {}
        for category in sorted({r["category"] for r in scored}):
            these = [r for r in scored if r["category"] == category]
            part = _tier_summary(these, policy)
            categories[category] = {
                "readings": len(these), "mean_score": part["mean_score"],
                "answers": sorted({str(r["answer"]) for r in these}),
                "label": these[0]["label"] if len({r["label"] for r in these}) == 1
                else "mixed"}
        refusals: Dict[str, int] = {}
        for r in scored:
            if r.get("unknown_reason"):
                refusals[r["unknown_reason"]] = refusals.get(r["unknown_reason"], 0) + 1
        repeatability = _repeatability(scored)
        reasons = []
        if (summary["false_confirm_rate"] or 0.0) > policy.max_false_confirm_rate:
            reasons.append(f"false-confirm rate {summary['false_confirm_rate']:.1%} is over "
                           f"the policy's {policy.max_false_confirm_rate:.0%}")
        if (summary["answer_rate"] or 0.0) < policy.min_answer_rate:
            reasons.append(f"answered {summary['answer_rate'] or 0:.0%}, under the "
                           f"policy's {policy.min_answer_rate:.0%}")
        if repeatability is not None and repeatability < policy.min_repeatability:
            reasons.append(f"repeatability {repeatability:.0%} is under the policy's "
                           f"{policy.min_repeatability:.0%}")
        providers[name] = {
            **summary,
            "models": sorted({f"{r.get('model') or '?'}"
                              + (f"@{r['model_version']}" if r.get("model_version") else "")
                              for r in scored}),
            "interface": sorted({str(r.get("interface")) for r in scored}),
            "calibration": calibration_metrics(pairs, policy.bins),
            "latency_ms": {"mean": (round(sum(latency) / len(latency), 3)
                                    if latency else None),
                           "p50": _percentile(latency, 0.5), "p95": _percentile(latency, 0.95)},
            "cost": {"per_call": per_call, "calls": len(mine),
                     "total": (round(per_call * len(mine), 6)
                               if isinstance(per_call, (int, float)) else None)},
            "determinism": {"declared": sorted({str(r.get("declared_determinism"))
                                                for r in scored}),
                            "repeatability": repeatability},
            "context": {"tiers": {t: {k: by_tier[t][k] for k in (
                            "mean_packet_chars", "accuracy", "answer_rate",
                            "false_confirm_rate", "mean_score")} for t in by_tier},
                        "accuracy_retained": (
                            _rate(rest[-1]["accuracy"] or 0.0, full["accuracy"])
                            if rest and full["accuracy"] else None)},
            "categories": categories, "refusals": refusals,
            "eligible": not reasons, "ineligible_because": reasons}
    eligible = sorted((n for n, p in providers.items() if p["eligible"]),
                      key=lambda n: (-(providers[n]["mean_score"] or 0.0),
                                     providers[n]["false_confirm_rate"] or 0.0,
                                     providers[n]["false_refute_rate"] or 0.0, n))
    by_accuracy = sorted(providers, key=lambda n: (-(providers[n]["accuracy"] or 0.0), n))
    return {"schema": BENCHMARK_RUN_SCHEMA, "scoring": BENCHMARK_SCORING,
            "policy": policy.to_dict(), "policy_digest": policy.digest,
            "cases": len({r["case_id"] for r in rows}),
            "readings": len(rows), "providers": providers,
            "ranking": eligible,
            "not_ranked": sorted(n for n, p in providers.items() if not p["eligible"]),
            "by_raw_accuracy_for_reference_only": by_accuracy,
            "makes_admission_decision": False, "chooses_a_provider": False}


def _pct(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.0%}"


def _num(value: Optional[float], places: int = 2) -> str:
    return "—" if value is None else f"{value:.{places}f}"


def render_benchmark(report: Mapping[str, Any]) -> str:
    """The report as a reader takes it in: ranked first, then the reasons."""
    providers = report["providers"]
    lines = [f"Semantic provider benchmark — {report['cases']} cases, "
             f"{report['readings']} readings, scored under {report['scoring']}",
             "Ranked by mean score among eligible providers; raw accuracy never ranks.",
             ""]
    head = (f"{'provider':<30} {'score':>6} {'acc':>5} {'decis':>5} {'f-conf':>6} "
            f"{'f-ref':>6} {'abst p/r':>9} {'brier':>6} {'repeat':>6} {'ctx kept':>8} "
            f"{'p50 ms':>7}")
    lines += [head, "-" * len(head)]
    for name in report["ranking"] + report["not_ranked"]:
        p = providers[name]
        lines.append(
            f"{name[:30]:<30} {_num(p['mean_score']):>6} {_pct(p['accuracy']):>5} "
            f"{_pct(p['coverage']):>5} "
            f"{_pct(p['false_confirm_rate']):>6} {_pct(p['false_refute_rate']):>6} "
            f"{_pct(p['abstention_precision']) + '/' + _pct(p['abstention_recall']):>9} "
            f"{_num(p['calibration']['brier']):>6} "
            f"{_pct(p['determinism']['repeatability']):>6} "
            f"{_pct(p['context']['accuracy_retained']):>8} "
            f"{_num(p['latency_ms']['p50'], 1):>7}")
    if report["not_ranked"]:
        lines += ["", "Not ranked:"]
        lines += [f"  {n}: {'; '.join(providers[n]['ineligible_because'])}"
                  for n in report["not_ranked"]]
    return "\n".join(lines)


# ── reference providers ──────────────────────────────────────────────────────

class _Reference:
    """An in-process provider with a fixed way of answering. For calibrating the scale."""

    interface = ProviderInterface.CHAT

    def __init__(self, name: str, answer: Callable[[Mapping[str, Any], int], Tuple[str, float]],
                 *, determinism: str = "DETERMINISTIC") -> None:
        self.name, self._answer, self._calls = name, answer, 0
        self._determinism = determinism

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(provider="reference", model=self.name,
                                model_family="reference", endpoint="local://reference",
                                local=True)

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            interface=self.interface,
            outputs=((OutputKind.PROBABILITY, OutputKind.CHOICE)
                     if self.interface is ProviderInterface.DECISION
                     else (OutputKind.CHOICE, OutputKind.FREE_FORM_REASONING)),
            determinism=Determinism(self._determinism), cost_per_call=0.0,
            declared_by="release-gate: an in-process reference provider")

    def complete(self, request: Any) -> ProviderReply:
        packet = json.loads(request.user)["evidence_packet"]
        self._calls += 1
        verdict, confidence = self._answer(packet, self._calls)
        return ProviderReply(text=json.dumps({
            "question_id": packet["question"]["question_id"],
            "claim_id": packet["question"]["claim_id"], "verdict": verdict,
            "confidence": confidence,
            "evidence_refs": [i["ref"] for i in packet["items"]],
            "reason": f"reference provider {self.name}"}), model_version="1")


class _ReferenceDecider(_Reference):
    interface = ProviderInterface.DECISION

    def decide(self, request: Any) -> DecisionReply:
        lines = [line for line in request.state.split("\n") if line]
        packet = {"question": {"question_id": "", "statement": request.question},
                  "items": [{"excerpt": line} for line in lines]}
        self._calls += 1
        verdict, confidence = self._answer(packet, self._calls)
        chosen = _CHOICE_OF[verdict]
        rest = (1.0 - confidence) / 2
        return DecisionReply(probabilities={c: (confidence if c == chosen else rest)
                                            for c in DECISION_CHOICES},
                             choice=chosen, model_version="1")


#: What the keyword reference reads as a contradiction, and as support. It reads
#: words, not meaning, which is the point of having it: a provider has to do
#: better than this to be worth asking.
_REFUTING_WORDS = ("without approval", "no approve", "failed", "disclosed", "bypass",
                   "proceeding", "os.system", "not approved")
_SUPPORTING_WORDS = ("passed", "approved", "redacted", "approve_transfer",
                     "require_human_approval")


def _keyword(packet: Mapping[str, Any], _: int) -> Tuple[str, float]:
    text = " ".join(str(i.get("excerpt") or "") for i in packet.get("items") or ()).lower()
    if any(w in text for w in _REFUTING_WORDS):
        return "contradicted", 0.8
    if any(w in text for w in _SUPPORTING_WORDS):
        return "supported", 0.8
    return "insufficient_evidence", 0.6


def reference_providers(labels: Optional[Mapping[str, SemanticVerdict]] = None
                        ) -> Dict[str, Any]:
    """In-process providers that anchor the scale. None of them is a model.

    - `oracle` is told the labels (`question_labels`) and is the ceiling;
    - `always-supported` confirms everything, confidently: false certainty;
    - `always-abstain` says insufficient_evidence to everything;
    - `keyword` reads words, not meaning, as a chat provider and as a decision
      provider that states probabilities;
    - `unstable` answers the same question differently on each call.
    """
    labels = dict(labels or {})
    verdicts = [v.value for v in SemanticVerdict]

    def oracle(packet: Mapping[str, Any], _: int) -> Tuple[str, float]:
        label = labels.get(packet["question"]["question_id"])
        return (label.value if label is not None else "insufficient_evidence"), 0.9

    def unstable(packet: Mapping[str, Any], call: int) -> Tuple[str, float]:
        seed = digest_object([packet["question"]["question_id"], call])
        return verdicts[int(seed[-6:], 16) % 3], 0.9

    found: Dict[str, Any] = {
        "reference/always-supported": _Reference(
            "always-supported", lambda p, c: ("supported", 0.99)),
        "reference/always-abstain": _Reference(
            "always-abstain", lambda p, c: ("insufficient_evidence", 0.9)),
        "reference/keyword": _Reference("keyword", _keyword),
        "reference/keyword-decider": _ReferenceDecider("keyword-decider", _keyword),
        "reference/unstable": _Reference("unstable", unstable,
                                         determinism="NON_DETERMINISTIC"),
    }
    if labels:
        found["reference/oracle"] = _Reference("oracle", oracle)
    return found
