"""Evidence quality, as facts a reviewer can check — and no score.

There is no number in this module. No grade, no tier, no percentage, no
confidence, no stars, nothing that could be sorted on and quoted in a summary.
`FactSheet.establishes_quality`, `ranks_evidence` and `combines_into_a_score`
all return `False` unconditionally, and they are properties rather than comments
so that anything relying on the opposite fails loudly.

The reason is not squeamishness about numbers. A score is a claim release-gate
is not in a position to make, and worse, it is a claim that cannot be argued
with. Told "this evidence scores 0.82", a reviewer has nothing to disagree with
— they can only accept it or distrust the whole system. Told

    provenance available     HOLDS         a named producer, unsigned (ATTRIBUTED)
    digest matches           HOLDS         sha256:9f2c… is an artifact this case holds
    independent root exists  DOES_NOT_HOLD all 47 records trace to one lineage
    formal verifier passed   NOT_ASSESSED  no verification collection was supplied
    contradiction unresolved HOLDS         C-184 is open against claim c1

they can disagree with any line, go and look at C-184, or notice that the third
line is the one that matters here and the other four are decoration. Every fact
names what it was read from, so every fact is falsifiable.

**Eleven facts, four states.** The states are the same discipline this codebase
applies everywhere: `HOLDS`, `DOES_NOT_HOLD`, `NOT_ASSESSED` (the input needed to
ask was not there) and `NOT_APPLICABLE` (the question does not arise for this
subject). A fact nobody could ask is never rendered as a fact that failed —
that conflation is how a sparse case comes to look like a bad one (Invariant 3).

**Polarity is not weight.** Each fact declares whether its holding is reassuring
or concerning, so a render can group "what stands behind this" against "what
stands against it". That is presentation. The polarities are never counted,
compared or summed: eight supporting facts do not outweigh one unresolved
counterexample, and a module that let them would have re-invented the score by
addition (Invariant 12).

**Nothing here derives anything.** Every fact is read off an existing
derivation — `IndependenceProfile`, `ReplicationProfile`, `ContradictionLedger`,
`CounterexampleLedger`, `TrustSurface`, `StreamLedger`, `VerificationGraph`, the
case's own artifact digests. This module is a reading, which is why it can be
honest about NOT_ASSESSED: when the analysis did not produce something, there is
nothing to read and the fact says so rather than guessing.

**Models may classify; they may not write facts.** `model_assisted_evidence()`
is the seam for an optional classifier or explainer. What it produces is an
ordinary `DERIVED` evidence record naming the model that produced it — which
means the model's output gets a fact sheet of its own, in this same vocabulary,
showing exactly how thin it is. A model can add evidence to a case. It cannot
add a fact, cannot raise an epistemic status, and cannot make one record's sheet
read better. Independent verification of the model's output is the only thing
that changes its standing, and that arrives as verification, not as a better
adjective.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.case import AssuranceCase, declared_digests, held_digests
from release_gate.assurance.evidence import (
    CoverageStatus,
    EpistemicStatus,
    EvidenceRecord,
    EvidenceType,
    Producer,
    ProducerKind,
    ProvenanceStatus,
    TrustStatus,
    VerificationMethod,
)
from release_gate.assurance.verification import VerificationStatus

__all__ = [
    "EvidenceFact",
    "FactFinding",
    "FactPolarity",
    "FactSheet",
    "QUALITY_SCHEMA_VERSION",
    "QualityError",
    "FORMAL_METHODS",
    "facts_for",
    "model_assisted_evidence",
    "sheets_for_case",
]

QUALITY_SCHEMA_VERSION = 1


class QualityError(ValueError):
    """A fact sheet was asked for something it cannot describe."""


class FactState(str, Enum):
    """What was established about one fact.

    The last two are not the same and collapsing them is the failure this whole
    system exists to avoid: `DOES_NOT_HOLD` is a finding, `NOT_ASSESSED` is an
    absence of one, and a reviewer shown the second as the first will go looking
    for a problem that was never reported.
    """

    HOLDS = "HOLDS"                    # established, with a basis
    DOES_NOT_HOLD = "DOES_NOT_HOLD"    # looked; it is not so
    NOT_ASSESSED = "NOT_ASSESSED"      # the input needed to ask was not present
    NOT_APPLICABLE = "NOT_APPLICABLE"  # the question does not arise here


class FactPolarity(str, Enum):
    """Which direction a holding fact points. Never a weight, never summed."""

    SUPPORTING = "SUPPORTING"    # holding is reassuring
    DETRACTING = "DETRACTING"    # holding is concerning


class EvidenceFact(str, Enum):
    """The structural questions, in place of a judgement.

    Each is a question with a checkable answer and a named source. None is a
    proxy for "good": `PROVENANCE_AVAILABLE` holding tells you somebody is named,
    not that they are right, and the basis string preserves the difference
    between a signature and a self-attestation that any score would erase.
    """

    PROVENANCE_AVAILABLE = "PROVENANCE_AVAILABLE"
    DIGEST_MATCHES = "DIGEST_MATCHES"
    INDEPENDENT_ROOT_EXISTS = "INDEPENDENT_ROOT_EXISTS"
    FORMAL_VERIFIER_PASSED = "FORMAL_VERIFIER_PASSED"
    REPLICATION_SUCCEEDED = "REPLICATION_SUCCEEDED"
    CONTRADICTION_UNRESOLVED = "CONTRADICTION_UNRESOLVED"
    TARGET_CHANGED = "TARGET_CHANGED"
    COVERAGE_KNOWN = "COVERAGE_KNOWN"
    COUNTEREXAMPLE_UNRESOLVED = "COUNTEREXAMPLE_UNRESOLVED"
    VERIFIER_TRUSTED = "VERIFIER_TRUSTED"
    COMPLETENESS_ESTABLISHED = "COMPLETENESS_ESTABLISHED"


#: Which way each fact points when it holds. Presentation only — see the module
#: docstring on why these are never counted.
_POLARITY: Mapping[EvidenceFact, FactPolarity] = {
    EvidenceFact.PROVENANCE_AVAILABLE: FactPolarity.SUPPORTING,
    EvidenceFact.DIGEST_MATCHES: FactPolarity.SUPPORTING,
    EvidenceFact.INDEPENDENT_ROOT_EXISTS: FactPolarity.SUPPORTING,
    EvidenceFact.FORMAL_VERIFIER_PASSED: FactPolarity.SUPPORTING,
    EvidenceFact.REPLICATION_SUCCEEDED: FactPolarity.SUPPORTING,
    EvidenceFact.CONTRADICTION_UNRESOLVED: FactPolarity.DETRACTING,
    EvidenceFact.TARGET_CHANGED: FactPolarity.DETRACTING,
    EvidenceFact.COVERAGE_KNOWN: FactPolarity.SUPPORTING,
    EvidenceFact.COUNTEREXAMPLE_UNRESOLVED: FactPolarity.DETRACTING,
    EvidenceFact.VERIFIER_TRUSTED: FactPolarity.SUPPORTING,
    EvidenceFact.COMPLETENESS_ESTABLISHED: FactPolarity.SUPPORTING,
}

#: The question each fact answers, as a reviewer would ask it.
_QUESTION: Mapping[EvidenceFact, str] = {
    EvidenceFact.PROVENANCE_AVAILABLE: "is there a named producer behind this",
    EvidenceFact.DIGEST_MATCHES: "does what this was produced against match what the case holds",
    EvidenceFact.INDEPENDENT_ROOT_EXISTS: "does anything here trace to a second lineage",
    EvidenceFact.FORMAL_VERIFIER_PASSED: "did a formal method return a positive result",
    EvidenceFact.REPLICATION_SUCCEEDED: "did a second path reach the same answer",
    EvidenceFact.CONTRADICTION_UNRESOLVED: "is a contradiction still open here",
    EvidenceFact.TARGET_CHANGED: "has the thing this is about moved since",
    EvidenceFact.COVERAGE_KNOWN: "is it stated what this does and does not cover",
    EvidenceFact.COUNTEREXAMPLE_UNRESOLVED: "is a counterexample still standing",
    EvidenceFact.VERIFIER_TRUSTED: "did somebody rule on whether this source may be relied on",
    EvidenceFact.COMPLETENESS_ESTABLISHED: "is it established that all of it arrived",
}

#: Methods that count for `FORMAL_VERIFIER_PASSED`. A test suite is verification
#: and is not a formal method; conflating the two is how "verified" stops meaning
#: anything (Invariant 8).
FORMAL_METHODS: Tuple[VerificationMethod, ...] = (
    VerificationMethod.FORMAL_PROOF,
    VerificationMethod.THEOREM_PROVER,
)

#: Provenance statuses under which somebody is named. `SELF_ATTESTED` is here on
#: purpose: the producer vouching for itself is weak provenance, not absent
#: provenance, and the basis string says which it is.
_ATTRIBUTED = (ProvenanceStatus.SIGNED, ProvenanceStatus.CHAIN_VERIFIED,
               ProvenanceStatus.ATTRIBUTED, ProvenanceStatus.SELF_ATTESTED)


@dataclass(frozen=True)
class FactFinding:
    """One fact, its state, and where that came from.

    `read_from` is not decoration. A fact whose provenance inside release-gate is
    untraceable is the same opaque judgement a score would be, one level down: a
    reviewer who cannot see which derivation answered cannot tell a real finding
    from a default.
    """

    fact: EvidenceFact
    state: FactState
    basis: str
    read_from: str
    refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "fact", EvidenceFact(self.fact))
        object.__setattr__(self, "state", FactState(self.state))
        object.__setattr__(self, "refs", tuple(self.refs))
        if not (self.basis or "").strip():
            raise QualityError(
                f"{self.fact.value} was recorded without a basis; a fact a reviewer "
                "cannot check is the opaque judgement this module exists to avoid")
        if not (self.read_from or "").strip():
            raise QualityError(
                f"{self.fact.value} does not say what it was read from")

    @property
    def polarity(self) -> FactPolarity:
        return _POLARITY[self.fact]

    @property
    def question(self) -> str:
        return _QUESTION[self.fact]

    @property
    def answered(self) -> bool:
        """Whether anything was established either way."""
        return self.state in (FactState.HOLDS, FactState.DOES_NOT_HOLD)

    def line(self) -> str:
        return f"{self.fact.value:26} {self.state.value:15} {self.basis}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "evidence_fact", "fact": self.fact.value,
                "state": self.state.value, "polarity": self.polarity.value,
                "question": self.question, "basis": self.basis,
                "read_from": self.read_from, "refs": list(self.refs),
                "answered": self.answered}


@dataclass(frozen=True)
class FactSheet:
    """Every fact about one subject, and no verdict over them.

    There is deliberately no ordering between two sheets and no method that
    reduces one to a value. Both would be a score wearing a different word, and
    the second would be quoted in a summary within a week.
    """

    subject: str
    findings: Tuple[FactFinding, ...] = ()
    notes: Tuple[str, ...] = ()
    schema_version: int = QUALITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not str(self.subject or "").strip():
            raise QualityError(
                "a fact sheet must name its subject: eleven facts about nothing in "
                "particular cannot be checked by anyone")
        object.__setattr__(self, "subject", str(self.subject).strip())
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "notes", tuple(self.notes))
        seen = [f.fact for f in self.findings]
        if len(seen) != len(set(seen)):
            raise QualityError(
                f"{self.subject}: a fact appears twice, so the sheet holds two "
                "answers to one question and no way to choose")

    # ── refusals, stated as properties so they can be relied on ─────────────

    @property
    def establishes_quality(self) -> bool:
        """Unconditionally False. There is no quality verdict here to read."""
        return False

    @property
    def ranks_evidence(self) -> bool:
        """Unconditionally False. Two sheets are not comparable, by design."""
        return False

    @property
    def combines_into_a_score(self) -> bool:
        """Unconditionally False, including by counting polarities."""
        return False

    # ── reading ────────────────────────────────────────────────────────────

    def finding(self, fact: EvidenceFact) -> Optional[FactFinding]:
        return next((f for f in self.findings if f.fact is EvidenceFact(fact)), None)

    def state(self, fact: EvidenceFact) -> FactState:
        """`NOT_ASSESSED` for a fact this sheet does not carry, never a default pass."""
        found = self.finding(fact)
        return found.state if found is not None else FactState.NOT_ASSESSED

    def in_state(self, state: FactState) -> Tuple[FactFinding, ...]:
        return tuple(f for f in self.findings if f.state is FactState(state))

    @property
    def standing_behind(self) -> Tuple[FactFinding, ...]:
        """Supporting facts that hold. A list to read, not a total."""
        return tuple(f for f in self.findings
                     if f.state is FactState.HOLDS
                     and f.polarity is FactPolarity.SUPPORTING)

    @property
    def standing_against(self) -> Tuple[FactFinding, ...]:
        """Detracting facts that hold, plus supporting ones positively refuted."""
        return tuple(f for f in self.findings
                     if (f.state is FactState.HOLDS
                         and f.polarity is FactPolarity.DETRACTING)
                     or (f.state is FactState.DOES_NOT_HOLD
                         and f.polarity is FactPolarity.SUPPORTING))

    @property
    def unassessed(self) -> Tuple[FactFinding, ...]:
        return self.in_state(FactState.NOT_ASSESSED)

    @property
    def fully_assessed(self) -> bool:
        """Whether every applicable fact was reached. Not a grade — a coverage statement."""
        return not any(f.state is FactState.NOT_ASSESSED for f in self.findings)

    def digest(self) -> str:
        return digest_object({"subject": self.subject,
                              "findings": [f.to_dict() for f in self.findings],
                              "schema_version": self.schema_version})

    @property
    def record_type(self) -> str:
        return "fact_sheet"

    @property
    def record_id(self) -> str:
        return f"facts:{self.subject}"

    def render(self) -> str:
        lines = [f"FACTS — {self.subject}", ""]
        lines += [f"  {f.line()}" for f in self.findings]
        if self.notes:
            lines += ["", *(f"  note: {n}" for n in self.notes)]
        lines += ["",
                  "  These are facts, not a grade. There is no overall quality "
                  "value here,",
                  "  and the facts are not weighed against one another — that is "
                  "the reader's",
                  "  judgement to make, on a methodology's terms."]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": self.record_type, "record_id": self.record_id,
            "subject": self.subject,
            "findings": [f.to_dict() for f in self.findings],
            "standing_behind": [f.fact.value for f in self.standing_behind],
            "standing_against": [f.fact.value for f in self.standing_against],
            "not_assessed": [f.fact.value for f in self.unassessed],
            "fully_assessed": self.fully_assessed,
            "notes": list(self.notes),
            # Stated in the record rather than merely absent, so a consumer
            # looking for a number finds an explicit refusal instead of a gap it
            # might fill in itself.
            "score": None, "grade": None, "composite_score": None,
            "establishes_quality": False, "ranks_evidence": False,
            "combines_into_a_score": False,
            "schema_version": self.schema_version,
        }


# ── resolving a subject ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Context:
    """What one fact needs to know about the thing it is describing.

    Resolved once. Every fact function reads this rather than walking the case
    again, so eleven facts cost one pass and a fact cannot accidentally disagree
    with its neighbour about which claims the subject touches.
    """

    subject: str
    kind: str                       # "evidence" | "claim" | "case"
    case: AssuranceCase
    analysis: Any = None
    completeness: Any = None        # a StreamLedger, supplied by the caller
    record: Mapping[str, Any] = field(default_factory=dict)
    claim_ids: Tuple[str, ...] = ()       # claims this subject bears on
    evidence_ids: Tuple[str, ...] = ()    # evidence records in scope
    producers: Tuple[str, ...] = ()       # producers behind those records

    def analysed(self, attribute: str) -> Any:
        return getattr(self.analysis, attribute, None) if self.analysis else None


def _record_map(case: AssuranceCase, kind: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for record in case.records(kind):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        key = str(payload.get("record_id") or "")
        if key:
            out[key] = payload
    return out


def _context(subject: str, case: AssuranceCase, analysis: Any,
             completeness: Any = None) -> _Context:
    reference = str(subject or "").strip()
    if not reference:
        raise QualityError("name what the facts are about: an evidence id, a claim "
                           "id, or 'case'")
    if reference == "case":
        evidence = _record_map(case, "evidence")
        claims = _record_map(case, "claims")
        return _Context(
            subject=reference, kind="case", case=case, analysis=analysis,
            completeness=completeness, claim_ids=tuple(sorted(claims)), evidence_ids=tuple(sorted(evidence)),
            producers=tuple(sorted({_producer_of(r) for r in evidence.values()
                                    if _producer_of(r)})))

    kind, _, identifier = reference.partition(":")
    if kind not in ("evidence", "claim") or not identifier:
        raise QualityError(
            f"{reference!r} is not a subject this module can describe; use "
            "'evidence:<id>', 'claim:<id>' or 'case'")

    if kind == "evidence":
        record = _record_map(case, "evidence").get(identifier)
        if record is None:
            raise QualityError(
                f"this case holds no evidence record {identifier!r}. A sheet about "
                "a record the case does not hold would be eleven answers about "
                "nothing")
        return _Context(
            subject=reference, kind=kind, case=case, analysis=analysis,
            completeness=completeness, record=record,
            claim_ids=tuple(sorted(
                {*(record.get("supports_claims") or ()),
                 *(record.get("contradicts_claims") or ())})),
            evidence_ids=(identifier,),
            producers=tuple(p for p in (_producer_of(record),) if p))

    record = _record_map(case, "claims").get(identifier)
    if record is None:
        raise QualityError(f"this case holds no claim {identifier!r}")
    supporting = tuple(str(e) for e in (record.get("supporting_evidence") or ()))
    contradicting = tuple(str(e) for e in (record.get("contradicting_evidence") or ()))
    evidence = _record_map(case, "evidence")
    related = tuple(sorted({*supporting, *contradicting}))
    return _Context(
        subject=reference, kind=kind, case=case, analysis=analysis,
        completeness=completeness, record=record,
        claim_ids=(identifier,), evidence_ids=related,
        producers=tuple(sorted({_producer_of(evidence[e]) for e in related
                                if e in evidence and _producer_of(evidence[e])})))


def _producer_of(record: Mapping[str, Any]) -> str:
    producer = record.get("producer")
    if isinstance(producer, Mapping):
        return str(producer.get("producer_id") or "")
    return str(producer or "")


def _records_in_scope(context: _Context) -> List[Mapping[str, Any]]:
    """Evidence records in scope, and only those.

    The `evidence` collection also carries release-gate's own derived analysis
    records — a consequence profile, an independence profile — which are not
    evidence from a producer and have no provenance to report. Counting them here
    made two facts report that most of the case "carries no identifiable
    producer", which is a finding about a record type that was never claiming one.
    """
    evidence = _record_map(context.case, "evidence")
    return [evidence[e] for e in context.evidence_ids
            if e in evidence and str(evidence[e].get("record_type") or "") == "evidence"]


# ── the eleven facts ────────────────────────────────────────────────────────
#
# Each function owns one question end to end, including when the question does
# not arise. That is why they take the whole context rather than pre-filtered
# arguments: a fact that cannot see why it has nothing to read cannot tell
# NOT_ASSESSED from DOES_NOT_HOLD, and the two are the difference between an
# absent finding and a reported one.


def _provenance_available(context: _Context) -> FactFinding:
    records = _records_in_scope(context)
    if not records:
        return FactFinding(
            EvidenceFact.PROVENANCE_AVAILABLE, FactState.NOT_ASSESSED,
            "no evidence record is in scope for this subject, so there is nobody "
            "to be named", "case.evidence")
    statuses = {str(r.get("provenance_status") or "") for r in records}
    unattributed = [r for r in records
                    if str(r.get("provenance_status") or "")
                    not in {s.value for s in _ATTRIBUTED}]
    refs = tuple(sorted(str(r.get("record_id") or "") for r in unattributed))[:12]
    if unattributed:
        return FactFinding(
            EvidenceFact.PROVENANCE_AVAILABLE, FactState.DOES_NOT_HOLD,
            f"{len(unattributed)} of {len(records)} record(s) carry no identifiable "
            f"producer ({', '.join(sorted(statuses))})", "evidence.provenance_status",
            refs)
    return FactFinding(
        EvidenceFact.PROVENANCE_AVAILABLE, FactState.HOLDS,
        f"a named producer on every record in scope ({', '.join(sorted(statuses))})"
        + (" — self-attestation is a named producer vouching for itself, not an "
           "independent one"
           if ProvenanceStatus.SELF_ATTESTED.value in statuses else ""),
        "evidence.provenance_status")


def _digest_matches(context: _Context) -> FactFinding:
    records = [r for r in _records_in_scope(context)
               if str(r.get("applies_to_digest") or "")]
    if not records:
        return FactFinding(
            EvidenceFact.DIGEST_MATCHES, FactState.NOT_ASSESSED,
            "nothing in scope states what it was produced against, so there is no "
            "binding to check", "evidence.applies_to_digest")
    held = held_digests(context.case)
    if not held:
        return FactFinding(
            EvidenceFact.DIGEST_MATCHES, FactState.NOT_ASSESSED,
            "this case holds no content digest to compare a binding against",
            "case.held_digests")
    unmatched = [r for r in records
                 if str(r.get("applies_to_digest")) not in held]
    if unmatched:
        return FactFinding(
            EvidenceFact.DIGEST_MATCHES, FactState.DOES_NOT_HOLD,
            f"{len(unmatched)} of {len(records)} bound record(s) name a digest "
            "nothing in this case carries", "case.held_digests",
            tuple(sorted(str(r.get("record_id") or "") for r in unmatched))[:12])
    return FactFinding(
        EvidenceFact.DIGEST_MATCHES, FactState.HOLDS,
        f"every one of {len(records)} bound record(s) names content this case holds",
        "case.held_digests")


def _independent_root_exists(context: _Context) -> FactFinding:
    profile = context.analysed("independence")
    if profile is None:
        return FactFinding(
            EvidenceFact.INDEPENDENT_ROOT_EXISTS, FactState.NOT_ASSESSED,
            "no independence profile was produced, so lineage was never traced",
            "analysis.independence")
    if not getattr(profile, "determinable", False):
        return FactFinding(
            EvidenceFact.INDEPENDENT_ROOT_EXISTS, FactState.NOT_ASSESSED,
            "lineage concentration could not be determined from what arrived",
            "analysis.independence")
    roots = int(getattr(profile, "independent_roots", 0) or 0)
    if roots >= 2:
        return FactFinding(
            EvidenceFact.INDEPENDENT_ROOT_EXISTS, FactState.HOLDS,
            f"{roots} distinct lineages behind this case; agreement between them "
            "is capable of being corroboration", "analysis.independence")
    return FactFinding(
        EvidenceFact.INDEPENDENT_ROOT_EXISTS, FactState.DOES_NOT_HOLD,
        f"{getattr(profile, 'records_examined', 0)} record(s) trace to "
        f"{roots} lineage; however many parties agree, one thing being wrong "
        "makes all of them wrong", "analysis.independence")


def _formal_verifier_passed(context: _Context) -> FactFinding:
    graph = context.analysed("verification_graph")
    if graph is None:
        return FactFinding(
            EvidenceFact.FORMAL_VERIFIER_PASSED, FactState.NOT_ASSESSED,
            "no verification graph was produced; nothing typed was submitted to "
            "read", "analysis.verification_graph")
    attempts = tuple(getattr(graph, "attempts", ()) or ())
    if not attempts:
        return FactFinding(
            EvidenceFact.FORMAL_VERIFIER_PASSED, FactState.NOT_ASSESSED,
            "the verification graph holds no attempts, so whether a formal method "
            "ran cannot be asked", "analysis.verification_graph")
    scoped = [a for a in attempts if _attempt_in_scope(a, context)]
    if not scoped:
        return FactFinding(
            EvidenceFact.FORMAL_VERIFIER_PASSED, FactState.NOT_APPLICABLE,
            f"{len(attempts)} verification attempt(s) on record, none of them "
            "against this subject", "analysis.verification_graph")
    # Compared against the enum, never a string literal: `VerificationStatus` is
    # `PASSED`, and a hand-written "PASS" silently matched nothing — a passing
    # theorem prover read as no formal verification at all.
    passed = [a for a in scoped
              if getattr(a, "method", None) in FORMAL_METHODS
              and getattr(a, "status", None) is VerificationStatus.PASSED]
    if passed:
        return FactFinding(
            EvidenceFact.FORMAL_VERIFIER_PASSED, FactState.HOLDS,
            f"{len(passed)} formal verification(s) returned PASS against this "
            "subject", "analysis.verification_graph",
            tuple(str(getattr(a, "verification_id", "")) for a in passed)[:12])
    methods = sorted({str(getattr(getattr(a, "method", None), "value", "?"))
                      for a in scoped})
    return FactFinding(
        EvidenceFact.FORMAL_VERIFIER_PASSED, FactState.DOES_NOT_HOLD,
        f"{len(scoped)} attempt(s) against this subject ({', '.join(methods)}) and "
        "none is a passing formal method", "analysis.verification_graph")


def _attempt_in_scope(attempt: Any, context: _Context) -> bool:
    if context.kind == "case":
        return True
    target = getattr(attempt, "target", None)
    target_id = str(getattr(target, "target_id", "") or "")
    if context.kind == "claim":
        return target_id in context.claim_ids
    # An evidence subject: the attempt bears on it if it names one of the claims
    # this record bears on, or the record itself.
    return target_id in context.claim_ids or target_id in context.evidence_ids


def _replication_succeeded(context: _Context) -> FactFinding:
    profile = context.analysed("replication")
    if profile is None:
        return FactFinding(
            EvidenceFact.REPLICATION_SUCCEEDED, FactState.NOT_ASSESSED,
            "no replication profile was produced", "analysis.replication")
    if not getattr(profile, "determinable", False):
        return FactFinding(
            EvidenceFact.REPLICATION_SUCCEEDED, FactState.NOT_ASSESSED,
            "replication could not be determined from what arrived",
            "analysis.replication")
    confirmed = tuple(getattr(profile, "confirmed", ()) or ())
    scoped = [t for t in confirmed if _target_in_scope(t, context)]
    if scoped:
        return FactFinding(
            EvidenceFact.REPLICATION_SUCCEEDED, FactState.HOLDS,
            f"{len(scoped)} target(s) in scope were reached by a second path "
            "capable of being wrong differently", "analysis.replication")
    single = tuple(getattr(profile, "single_path", ()) or ())
    if any(_target_in_scope(t, context) for t in single):
        return FactFinding(
            EvidenceFact.REPLICATION_SUCCEEDED, FactState.DOES_NOT_HOLD,
            "every attempt in scope runs down one path; agreement between copies "
            "is not replication", "analysis.replication")
    return FactFinding(
        EvidenceFact.REPLICATION_SUCCEEDED, FactState.NOT_ASSESSED,
        "the replication profile describes no target in scope for this subject",
        "analysis.replication")


def _target_in_scope(target_replication: Any, context: _Context) -> bool:
    if context.kind == "case":
        return True
    target = getattr(target_replication, "target", None)
    target_id = str(getattr(target, "target_id", "") or "")
    return target_id in context.claim_ids or target_id in context.evidence_ids


def _contradiction_unresolved(context: _Context) -> FactFinding:
    ledger = context.analysed("contradictions")
    if ledger is None:
        return FactFinding(
            EvidenceFact.CONTRADICTION_UNRESOLVED, FactState.NOT_ASSESSED,
            "no contradiction ledger was produced, so nothing looked",
            "analysis.contradictions")
    # An empty ledger means one of two very different things. Structural
    # detection runs over the claim graph, so with a graph present an empty
    # ledger is "looked, found none"; without one, nothing ran and reporting
    # DOES_NOT_HOLD would be a clean bill nobody issued.
    if not len(ledger) and context.analysed("claim_graph") is None:
        return FactFinding(
            EvidenceFact.CONTRADICTION_UNRESOLVED, FactState.NOT_ASSESSED,
            "the ledger is empty and no claim graph was built, so contradiction "
            "detection never ran over anything", "analysis.contradictions")
    open_ones = tuple(ledger.open())
    scoped = [c for c in open_ones if _contradiction_in_scope(c, context)]
    if scoped:
        return FactFinding(
            EvidenceFact.CONTRADICTION_UNRESOLVED, FactState.HOLDS,
            f"{len(scoped)} contradiction(s) bearing on this subject are open",
            "analysis.contradictions",
            tuple(str(getattr(c, "contradiction_id", "")) for c in scoped)[:12])
    return FactFinding(
        EvidenceFact.CONTRADICTION_UNRESOLVED, FactState.DOES_NOT_HOLD,
        f"{len(open_ones)} open contradiction(s) in this case, none of them "
        "bearing on this subject — observed, which is not the same as none "
        "existing", "analysis.contradictions")


def _contradiction_in_scope(contradiction: Any, context: _Context) -> bool:
    """Whether a contradiction bears on this subject.

    `target_claims` and the sides' `evidence`, not `claim_id` and `participants`:
    a contradiction targets claims (plural), and `participants` holds *producer*
    ids, so matching evidence ids against it would never fire and every sheet
    would come back clean. That is the failure this codebase has already had
    once, from a method name that did not exist, and it is worth naming here.
    """
    if context.kind == "case":
        return True
    targets = {str(c) for c in (getattr(contradiction, "target_claims", ()) or ())}
    if targets & set(context.claim_ids):
        return True
    evidence: Set[str] = set()
    for side in getattr(contradiction, "sides", ()) or ():
        evidence |= {str(e) for e in (getattr(side, "evidence", ()) or ())}
    return bool(evidence & set(context.evidence_ids))


def _target_changed(context: _Context) -> FactFinding:
    declared = declared_digests(context.case)
    conflicted = sorted(handle for handle, digests in declared.items()
                        if len(digests) > 1)
    if conflicted:
        return FactFinding(
            EvidenceFact.TARGET_CHANGED, FactState.HOLDS,
            f"{len(conflicted)} artifact handle(s) are declared with more than one "
            f"digest ({', '.join(conflicted[:4])}); the thing being decided on is "
            "not one thing", "case.declared_digests", tuple(conflicted)[:12])
    bound = [r for r in _records_in_scope(context)
             if str(r.get("applies_to_digest") or "")]
    if not declared:
        return FactFinding(
            EvidenceFact.TARGET_CHANGED, FactState.NOT_ASSESSED,
            "no artifact carries a digest, so whether anything moved cannot be "
            "asked", "case.declared_digests")
    if not bound:
        return FactFinding(
            EvidenceFact.TARGET_CHANGED, FactState.NOT_ASSESSED,
            "nothing in scope states what it was produced against, so movement "
            "away from it cannot be detected", "evidence.applies_to_digest")
    held = held_digests(context.case)
    stale = [r for r in bound if str(r.get("applies_to_digest")) not in held]
    if stale:
        return FactFinding(
            EvidenceFact.TARGET_CHANGED, FactState.HOLDS,
            f"{len(stale)} record(s) in scope were produced against content this "
            "case no longer holds", "case.held_digests",
            tuple(sorted(str(r.get("record_id") or "") for r in stale))[:12])
    return FactFinding(
        EvidenceFact.TARGET_CHANGED, FactState.DOES_NOT_HOLD,
        f"every one of {len(bound)} bound record(s) still names content this case "
        "holds", "case.held_digests")


def _coverage_known(context: _Context) -> FactFinding:
    records = _records_in_scope(context)
    if not records:
        return FactFinding(
            EvidenceFact.COVERAGE_KNOWN, FactState.NOT_ASSESSED,
            "no evidence record is in scope, so there is no coverage to state",
            "evidence.coverage_status")
    unknown = [r for r in records
               if str(r.get("coverage_status") or CoverageStatus.UNKNOWN.value)
               == CoverageStatus.UNKNOWN.value
               and not str(r.get("coverage_note") or "").strip()]
    if unknown:
        return FactFinding(
            EvidenceFact.COVERAGE_KNOWN, FactState.DOES_NOT_HOLD,
            f"{len(unknown)} of {len(records)} record(s) say nothing about what "
            "they do and do not cover", "evidence.coverage_status",
            tuple(sorted(str(r.get("record_id") or "") for r in unknown))[:12])
    return FactFinding(
        EvidenceFact.COVERAGE_KNOWN, FactState.HOLDS,
        f"all {len(records)} record(s) in scope state their coverage",
        "evidence.coverage_status")


def _counterexample_unresolved(context: _Context) -> FactFinding:
    ledger = context.analysed("counterexamples")
    if ledger is None:
        return FactFinding(
            EvidenceFact.COUNTEREXAMPLE_UNRESOLVED, FactState.NOT_ASSESSED,
            "no counterexample ledger was produced; nobody recorded an attempt to "
            "break anything", "analysis.counterexamples")
    if not context.claim_ids:
        return FactFinding(
            EvidenceFact.COUNTEREXAMPLE_UNRESOLVED, FactState.NOT_APPLICABLE,
            "this subject bears on no claim, and a counterexample is against a "
            "claim", "analysis.counterexamples")
    standing = tuple(ledger.unresolved_against(context.claim_ids))
    if standing:
        return FactFinding(
            EvidenceFact.COUNTEREXAMPLE_UNRESOLVED, FactState.HOLDS,
            f"{len(standing)} counterexample(s) stand unanswered against "
            f"{len(context.claim_ids)} claim(s) in scope",
            "analysis.counterexamples",
            tuple(str(getattr(a, "counterexample_id", "")) for a in standing)[:12])
    searched = tuple(ledger.searched_without_finding())
    if not searched and not tuple(ledger.attempts):
        return FactFinding(
            EvidenceFact.COUNTEREXAMPLE_UNRESOLVED, FactState.NOT_ASSESSED,
            "the ledger holds no attempt at all, so nothing was searched",
            "analysis.counterexamples")
    return FactFinding(
        EvidenceFact.COUNTEREXAMPLE_UNRESOLVED, FactState.DOES_NOT_HOLD,
        f"{len(searched)} search(es) found nothing standing against the claims in "
        "scope — searched and not found, which is not the same as none existing",
        "analysis.counterexamples")


def _verifier_trusted(context: _Context) -> FactFinding:
    if not context.producers:
        return FactFinding(
            EvidenceFact.VERIFIER_TRUSTED, FactState.NOT_ASSESSED,
            "no producer is in scope, so there is nobody to have been ruled on",
            "evidence.producer")
    records = _records_in_scope(context)
    decisions = [r.get("trust") for r in records if isinstance(r.get("trust"), Mapping)]
    statuses = {str(d.get("status") or "") for d in decisions}
    rejected = statuses & {TrustStatus.REVOKED.value, TrustStatus.REJECTED.value}
    if rejected:
        return FactFinding(
            EvidenceFact.VERIFIER_TRUSTED, FactState.DOES_NOT_HOLD,
            f"a source in scope is {', '.join(sorted(rejected))} — somebody ruled, "
            "and ruled against relying on it", "evidence.trust")
    accepted = statuses & {TrustStatus.ACCEPTED.value, TrustStatus.PROVISIONAL.value}
    if accepted and len(decisions) == len(records):
        return FactFinding(
            EvidenceFact.VERIFIER_TRUSTED, FactState.HOLDS,
            f"every source in scope carries a trust decision "
            f"({', '.join(sorted(accepted))}), each naming who decided",
            "evidence.trust")
    # The default, and the honest one: nobody has ruled. Not a failing grade —
    # an unanswered question, which is exactly what TrustStatus.NOT_ESTABLISHED
    # means and what a score would have quietly rendered as "low".
    return FactFinding(
        EvidenceFact.VERIFIER_TRUSTED, FactState.NOT_ASSESSED,
        f"{len(records) - len(decisions)} of {len(records)} source(s) in scope "
        f"carry no trust decision; nobody has ruled on "
        f"{', '.join(context.producers[:3])}", "evidence.trust")


def _completeness_established(context: _Context) -> FactFinding:
    # Supplied by the caller, not read off the analysis: a stream ledger is built
    # from the event stream a caller holds, which is the same convention
    # `run_query` follows. Reading it off `AnalysisResult` — which has no such
    # field — would have made this fact permanently NOT_ASSESSED with nothing to
    # say it was unreachable.
    ledger = context.completeness
    if ledger is None:
        return FactFinding(
            EvidenceFact.COMPLETENESS_ESTABLISHED, FactState.NOT_ASSESSED,
            "no stream completeness ledger was supplied, so whether all of it "
            "arrived was never asked", "analysis.completeness")
    status = str(getattr(getattr(ledger, "status", None), "value", "") or "")
    if status == "COMPLETE":
        return FactFinding(
            EvidenceFact.COMPLETENESS_ESTABLISHED, FactState.HOLDS,
            "every stream an independent enumeration names arrived, with no gap "
            "detected — complete against that enumeration, which does not "
            "establish that nothing exists it failed to mention",
            "analysis.completeness")
    if status in ("KNOWN_GAPS", "PARTIALLY_COMPLETE"):
        return FactFinding(
            EvidenceFact.COMPLETENESS_ESTABLISHED, FactState.DOES_NOT_HOLD,
            f"the stream ledger reports {status}: " + (ledger.note() or ""),
            "analysis.completeness")
    return FactFinding(
        EvidenceFact.COMPLETENESS_ESTABLISHED, FactState.NOT_ASSESSED,
        "nothing states what should have arrived, so arrival cannot be checked "
        "against anything", "analysis.completeness")


#: In the order a reviewer reads them: who produced it and is it about the right
#: thing, then what independently supports it, then what stands against it, then
#: what is known about the edges. The order is a reading order, not a ranking.
_DERIVATIONS = (
    _provenance_available,
    _digest_matches,
    _independent_root_exists,
    _formal_verifier_passed,
    _replication_succeeded,
    _contradiction_unresolved,
    _target_changed,
    _coverage_known,
    _counterexample_unresolved,
    _verifier_trusted,
    _completeness_established,
)


# ── the public reading ──────────────────────────────────────────────────────

def facts_for(subject: str, *, case: AssuranceCase, analysis: Any = None,
              completeness: Any = None) -> FactSheet:
    """Every structural fact about one subject, and nothing above them.

    `subject` is `evidence:<id>`, `claim:<id>` or `case`. Claim-level facts reach
    an evidence record through the claims it bears on, so asking about a piece of
    evidence gives a reviewer the contradictions and counterexamples touching
    what it supports — which is what they actually wanted to know.

    `analysis` is the `AnalysisResult` the case was decided with. Without it the
    facts that read derivations answer `NOT_ASSESSED` rather than guessing, which
    is the honest degradation: a sheet produced from a case alone says plainly
    that most of it was never computed. `completeness` is a `StreamLedger`, passed
    the same way `run_query` takes it, because a ledger is built from the event
    stream the caller holds rather than derived from the case.
    """
    context = _context(subject, case, analysis, completeness)
    notes: List[str] = []
    if analysis is None:
        notes.append(
            "no analysis was supplied, so every fact read from a derivation is "
            "NOT_ASSESSED here; that is an absence of a reading, not a finding")
    return FactSheet(subject=context.subject,
                     findings=tuple(derive(context) for derive in _DERIVATIONS),
                     notes=tuple(notes))


def sheets_for_case(outcome: Any, *, subjects: Sequence[str] = (),
                    completeness: Any = None) -> Dict[str, FactSheet]:
    """Fact sheets for a whole case, keyed by subject reference.

    Takes an `AssuranceOutcome` so the analysis travels with the case rather than
    being passed separately and possibly mismatched. With no `subjects`, returns
    the case sheet and one per claim — claims being what a decision rests on. Per
    evidence sheets are available by asking for them, because at ten thousand
    records the caller, not this function, decides which ones matter.
    """
    case = getattr(outcome, "case", outcome)
    analysis = getattr(outcome, "analysis", None)
    wanted = tuple(subjects) or ("case", *(f"claim:{c}" for c in sorted(
        _record_map(case, "claims"))))
    out: Dict[str, FactSheet] = {}
    for subject in wanted:
        try:
            out[subject] = facts_for(subject, case=case, analysis=analysis,
                                     completeness=completeness)
        except QualityError:
            # A subject the case does not hold is skipped rather than raised:
            # this is a bulk reading, and one bad reference should not cost the
            # caller the other nine thousand.
            continue
    return out


# ── the model seam ──────────────────────────────────────────────────────────

def model_assisted_evidence(*, model: str, classification: str,
                            source: str = "model-assisted classification",
                            parent_evidence: Iterable[str] = (),
                            evidence_type: EvidenceType = EvidenceType.CLAIM_DERIVATION,
                            coverage_note: str = "",
                            content: Optional[Mapping[str, Any]] = None,
                            **kwargs: Any) -> EvidenceRecord:
    """A model's classification or explanation, entered as what it is.

    The result is a `DERIVED` evidence record naming the model that produced it.
    That is the whole contract, and each half of it matters:

    * **It is evidence.** A model reading a diff and saying "this touches the
      payment path" is useful, and throwing it away because a model said it would
      lose something real. It goes in the case, where it can be argued with.
    * **It is `DERIVED`, and stays there.** No argument to this function can make
      it `VERIFIED` or `OBSERVED` — the status is not a parameter. A model's
      confidence, however expressed, is the model's confidence; it is recorded in
      the content where a reader can see it, and it moves nothing.

    What changes a model's standing is independent verification of its output,
    which arrives as a verification record against this one — a different party,
    a named method, a result. Not a better adjective on the same record.

    The record gets a fact sheet like any other, and its sheet will say what it
    is: one producer, no independent root, no formal method, coverage as stated.
    A reviewer sees the thinness in the same vocabulary as everything else,
    rather than having to know that this particular record came from a model.
    """
    if not str(model or "").strip():
        raise QualityError(
            "name the model: an unattributed classification is an anonymous "
            "opinion, and the point of recording it is that a reader can weigh "
            "who produced it")
    for forbidden in ("epistemic_status", "status", "verified"):
        if forbidden in kwargs:
            raise QualityError(
                f"{forbidden!r} is not settable here. A model's output is DERIVED "
                "evidence; independent verification is what changes that, and it "
                "arrives as a verification record, not as an argument")
    producer = Producer(producer_id=f"model://{str(model).strip()}",
                        kind=ProducerKind.AGENT, model=str(model).strip())
    payload = {"classification": str(classification),
               "produced_by_model": str(model).strip(), **dict(content or {})}
    return EvidenceRecord.derived(
        evidence_type, source=source, producer=producer,
        parent_evidence=tuple(parent_evidence), content=payload,
        coverage_note=(coverage_note or
                       "a model's reading of the records it was given; it covers "
                       "what those records cover and establishes nothing beyond "
                       "them"),
        **kwargs)
