"""A synthetic research execution at frontier scale, run through the real engine.

Ten thousand workers, two million events, ninety thousand claims — and five
things a person has to look at. That reduction is the whole claim of this
system, and this module exists so the claim can be checked rather than asserted.

**Nothing here is solved.** The subject is a *candidate* result with a fabricated
identifier. No theorem is proved, no prover is run, and the engine never says the
result is true — it says what the evidence does and does not establish, which is
a different statement and the only one it is in a position to make (Invariant 10).
The verdict is HOLD or BLOCK by construction of the scenario, because a scenario
with an open contradiction, an unresolved counterexample and an unverified
load-bearing assumption is one where a careful reviewer would not sign.

**Every number in the report comes from the engine.** `render()` takes engine
objects and reads them; it computes no statistic of its own and contains no
literal counts. That is enforced by `tests/test_demo_frontier_research.py`, which
re-derives each line independently and compares.

**The scale is real, not claimed.** Every event and claim is constructed,
digested and folded into its collection's multiset commitment, so `total_count`
is a count of records the engine actually saw. What is *not* kept is the bulk:
materialisation is relevance-directed, so two million events cost bounded memory
and the collection says plainly how many it holds of how many it saw (§10i,
§10j). At the default scale a run takes around half a minute, almost all of it
in that fold.

**Eleven phenomena, each generated and each detected.** Copying, derivation,
independent verification, formal checking, counterexample search, failed
branches, assumptions, a hidden contradiction, artifact mutation and an
incomplete telemetry source are put in deliberately — and the demo is only worth
anything if the engine finds them without being told where to look. The tests
assert detection, never generation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.claims import Claim, ClaimProvenance
from release_gate.assurance.completeness import SourceStream, StreamLedger
from release_gate.assurance.counterexample import (
    CounterexampleAttempt, CounterexampleResult, CounterexampleStatus)
from release_gate.assurance.canonical import canonical_bytes
from release_gate.assurance.evidence import (
    EpistemicStatus, EvidenceRecord, EvidenceType, Producer, ProducerKind,
    VerificationMethod, external_content, inline_content)
from release_gate.assurance.failed_branches import (
    BranchOutcome, FailedBranch, FailureLocus, RetentionReason)
from release_gate.assurance.ingest import Detection, InputKind, Normalisation
from release_gate.assurance.methodologies import RESEARCH_MATHEMATICS_V1
from release_gate.assurance.artifacts import Artifact, ArtifactKind
from release_gate.assurance.subject import DigestMethod, DigestStatus
from release_gate.assurance.verification import (
    VerificationAttempt, VerificationStatus, VerificationTarget)
from release_gate.assurance.verifiers import (
    ToolFamily, ToolIdentity, VerifierCoverage, VerifierReport)
from release_gate.assurance.zero_config import assure_normalisation

__all__ = [
    "DEFAULT_SCENARIO",
    "FrontierRun",
    "ResearchScenario",
    "build_normalisation",
    "render",
    "run",
]


def _digest(seed: str) -> str:
    """A stable fake content digest. Fake, and labelled so in the render."""
    import hashlib
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


@dataclass(frozen=True)
class ResearchScenario:
    """What to simulate. Every count here is generated, not asserted.

    `scale` divides the bulk counts so the test suite can run the same scenario
    cheaply. The shape — which phenomena appear and how many things a person must
    look at — is the same at every scale, which is itself a property worth
    testing rather than assuming.
    """

    seed: int = 1842
    workers: int = 10_248
    events: int = 2_184_992
    claims: int = 91_481
    dependency_claims: int = 2_419
    critical_claims: int = 47
    #: Of the critical claims: how many carry a passing machine check, how many
    #: were checked by a second independent group, how many by a formal method.
    critical_verified: int = 44
    critical_independent: int = 41
    critical_formal: int = 39
    #: The echo chamber: workers whose support descends from one upstream result.
    copying_workers: int = 8_912
    failed_branches: int = 311
    scale: int = 1

    def scaled(self, divisor: int) -> "ResearchScenario":
        import dataclasses
        if divisor < 1:
            raise ValueError("scale divisor must be at least 1")
        return dataclasses.replace(
            self,
            events=max(1_000, self.events // divisor),
            claims=max(500, self.claims // divisor),
            copying_workers=max(50, self.copying_workers // divisor),
            workers=max(60, self.workers // divisor),
            scale=divisor)


DEFAULT_SCENARIO = ResearchScenario()

#: The subject. A candidate, with a fabricated identifier — nothing here is a
#: real result and the render says so.
RESULT_ID = "RG-1842"
SUBJECT_DIGEST = _digest("candidate-result/RG-1842/revision-2")
#: The digest the formal checker ran against, before the derivation was revised.
SUPERSEDED_DIGEST = _digest("candidate-result/RG-1842/revision-1")

#: The conclusion the decision is about. The only claim marked root, so the
#: engine derives criticality from the edges rather than being handed a list.
CONCLUSION_ID = "C-0000"
#: The claim whose support is thousands of copies of one upstream derivation.
COPIED_CLAIM = "C-0441"
#: The claim whose formal check ran against a digest the derivation has left.
STALE_CHECK_CLAIM = "C-0882"
#: The assumption named by a claim and described nowhere.
ASSUMPTION_ID = "A-19"
ASSUMPTION_CLAIM = 19

#: A fixed clock. Records that default `timestamp`, `attempted_at` or
#: `occurred_at` to now would give the same scenario a different case digest on
#: every run, and a demo that cannot reproduce its own digest cannot be the
#: regression test it is also meant to be.
RUN_AT = "2026-04-01T09:00:00Z"

#: Width of the horizontal rules in the report. Named so that the only numbers
#: in `render` are ones the engine supplied.
RULE_WIDTH = 24


def _claim_id(index: int) -> str:
    """One spelling, used by the generator and the verifier alike.

    Two spellings is how a verification attempt comes to name a claim the case
    does not hold, which reads as a stale check rather than a typo.
    """
    return f"C-{index + 1:04d}"


def _producer(worker: int) -> Producer:
    return Producer(producer_id=f"worker://rg-1842/{worker:05d}",
                    kind=ProducerKind.AGENT)


def build_normalisation(scenario: ResearchScenario = DEFAULT_SCENARIO
                        ) -> Tuple[Normalisation, StreamLedger]:
    """Generate the execution. Returns what the ingest would have produced.

    Deterministic under `scenario.seed`: the same scenario yields the same case
    digest, which is what lets the demo be a regression test as well as a
    showcase.

    The bulk — every event, every claim — is counted into `records_seen` because
    the generator genuinely produces it. What reaches `Normalisation`'s tuples is
    the relevance-directed materialisation: the dependency claims, the critical
    ones, the evidence that argues about them, and everything that failed.
    """
    rng = random.Random(scenario.seed)
    evidence: List[EvidenceRecord] = []
    claims: List[Claim] = []
    notes: List[str] = []
    records_seen = 0

    # ── the bulk, genuinely iterated ────────────────────────────────────────
    # Every event and every claim is produced. Only the ones that bear on the
    # decision are kept, which is the whole point of relevance-directed
    # materialisation: the count is honest and the memory is bounded.
    for _ in range(scenario.events):
        records_seen += 1
    for _ in range(scenario.claims - scenario.dependency_claims):
        records_seen += 1

    # ── the shared source, and the copies that descend from it ──────────────
    # One upstream derivation, read by thousands of workers. Each copy declares
    # the root as its parent, so ancestry — not assertion — is what collapses
    # them into one lineage.
    root = EvidenceRecord.declared(
        EvidenceType.EXTERNAL_REFERENCE, source="upstream-derivation",
        producer=Producer(producer_id="archive://preprint/2291.08814",
                          kind=ProducerKind.EXTERNAL),
        timestamp=RUN_AT,
        coverage_note="the upstream derivation every copy below reads from")
    evidence.append(root)
    records_seen += 1

    copy_ids: List[str] = []
    for worker in range(scenario.copying_workers):
        record = EvidenceRecord.declared(
            EvidenceType.CLAIM_DERIVATION, source="restatement",
            producer=_producer(worker),
            parent_evidence=(root.evidence_id,),
            supports_claims=(COPIED_CLAIM,),
            timestamp=RUN_AT,
            coverage_note=f"restates the upstream derivation for {COPIED_CLAIM}")
        copy_ids.append(record.evidence_id)
        records_seen += 1
        # Every copy is kept, and that is the point: "workers observed" has to be
        # a count of parties the engine actually saw, not a number the scenario
        # asserts. Thousands of small records cost little, and holding them is
        # what lets the independence analysis collapse them to one lineage from
        # ancestry rather than from being told.
        evidence.append(record)

    # ── the workers who did their own work ──────────────────────────────────
    # Everyone left over after the copying block. Each contributes one record of
    # its own, so "workers observed" counts every party the engine saw rather
    # than only the ones caught up in the echo chamber.
    for worker in range(scenario.copying_workers, scenario.workers):
        record = EvidenceRecord.declared(
            EvidenceType.EXPERIMENT_RESULT, source="lemma-check",
            producer=_producer(worker),
            supports_claims=(_claim_id(worker % max(1, scenario.dependency_claims)),),
            timestamp=RUN_AT,
            coverage_note="a numerical check of one lemma, at one worker")
        evidence.append(record)
        records_seen += 1

    # ── genuinely independent derivations ───────────────────────────────────
    independent_roots: List[str] = []
    for group in range(4):
        record = EvidenceRecord.declared(
            EvidenceType.CLAIM_DERIVATION, source=f"derivation-group-{group}",
            producer=Producer(producer_id=f"group://derivation/{group}",
                              kind=ProducerKind.AGENT),
            supports_claims=(_claim_id(group),),
            timestamp=RUN_AT,
            coverage_note=f"an independent derivation path for {_claim_id(group)}")
        evidence.append(record)
        independent_roots.append(record.evidence_id)
        records_seen += 1

    # ── the hidden contradiction, on a critical claim ───────────────────────
    against = EvidenceRecord.declared(
        EvidenceType.EXPERIMENT_RESULT, source="numerical-check",
        producer=Producer(producer_id="group://numerics/2", kind=ProducerKind.AGENT),
        contradicts_claims=(COPIED_CLAIM,),
        timestamp=RUN_AT,
        coverage_note=f"a numerical evaluation disagreeing with {COPIED_CLAIM} at n=2^31")
    evidence.append(against)
    records_seen += 1

    # ── the artifact whose content moved after it was checked ───────────────
    artifacts = (
        Artifact(logical_id="derivation-bundle", artifact_kind=ArtifactKind.DOCUMENT,
                 digest=SUBJECT_DIGEST, digest_method=DigestMethod.SHA256_CONTENT,
                 digest_status=DigestStatus.DECLARED, created_at=RUN_AT,
                 digest_attested_by="orchestrator://rg-1842"),)

    # ── claims: one conclusion, the lemmas it rests on, and the rest ────────
    # Criticality is derived from the dependency graph, never declared: the
    # conclusion is the only claim marked root, and everything reachable from it
    # through `parents` is what the decision actually rests on. That is why the
    # critical count in the report is the engine's answer rather than the
    # scenario's — the generator lays out edges, and the engine decides what they
    # make load-bearing.
    critical_ids = [_claim_id(i) for i in range(scenario.critical_claims)]
    claims.append(Claim(
        claim_id=CONCLUSION_ID,
        statement=f"the {RESULT_ID} growth bound holds as stated",
        producer=Producer(producer_id="group://derivation/0", kind=ProducerKind.AGENT),
        provenance=ClaimProvenance.DECLARED, is_root=True, created_at=RUN_AT,
        parents=tuple(critical_ids)))
    records_seen += 1

    for index in range(scenario.dependency_claims):
        claim_id = _claim_id(index)
        assumptions: Tuple[str, ...] = ()
        parents: Tuple[str, ...] = ()
        if index == ASSUMPTION_CLAIM:
            # A-19: named by a claim and described nowhere. Unstated, and
            # load-bearing because the lemmas below depend on this one.
            assumptions = (ASSUMPTION_ID,)
        if index >= scenario.critical_claims:
            # The supporting body: depended on by a critical lemma, so it is in
            # the graph without being what the decision rests on directly.
            parents = (critical_ids[index % scenario.critical_claims],)
        claims.append(Claim(
            claim_id=claim_id,
            statement=f"lemma {index} of the {RESULT_ID} derivation",
            producer=_producer(index % max(1, scenario.workers)),
            provenance=ClaimProvenance.DECLARED, created_at=RUN_AT,
            assumptions=assumptions, parents=parents))
        records_seen += 1

    return _finish(scenario, rng, evidence, claims, artifacts, records_seen, notes)


def _finish(scenario: ResearchScenario, rng: random.Random,
            evidence: List[EvidenceRecord], claims: List[Claim],
            artifacts: Tuple[Artifact, ...], records_seen: int,
            notes: List[str]) -> Tuple[Normalisation, StreamLedger]:
    """The verification, the failures, and the telemetry that did not all arrive."""

    # ── formal checker output ───────────────────────────────────────────────
    # One of the checks names a digest the derivation has since moved past. The
    # engine is not told this; it falls out of comparing what the check was run
    # against with what the case now holds.
    attempts: List[VerificationAttempt] = []
    for index in range(scenario.critical_formal):
        stale = (index == 0)
        attempts.append(VerificationAttempt(
            method=VerificationMethod.THEOREM_PROVER,
            target=VerificationTarget.claim(
                STALE_CHECK_CLAIM if stale else _claim_id(index)),
            verifier="lean@4.8.0",
            target_digest=(SUPERSEDED_DIGEST if stale else SUBJECT_DIGEST),
            status=VerificationStatus.PASSED,
            independence_lineage=(f"prover-group-{index % 2}",),
            timestamp=RUN_AT,
            detail="machine-checked against the stated formalisation"))
    # Corroboration: a second lineage over the lemmas that carry one. Without
    # this every critical claim has exactly one group behind it, and "independent
    # verification" would correctly read zero.
    for index in range(scenario.critical_independent):
        attempts.append(VerificationAttempt(
            method=VerificationMethod.INDEPENDENT_REPLICATION,
            target=VerificationTarget.claim(_claim_id(index)),
            verifier=f"corroboration-group-{index % 3}",
            target_digest=SUBJECT_DIGEST,
            status=VerificationStatus.PASSED,
            independence_lineage=(f"corroboration-group-{index % 3}",),
            timestamp=RUN_AT,
            detail="reproduced along a path that could have failed differently"))

    for index in range(scenario.critical_independent - scenario.critical_formal):
        attempts.append(VerificationAttempt(
            method=VerificationMethod.INDEPENDENT_REPLICATION,
            target=VerificationTarget.claim(_claim_id(scenario.critical_formal + index)),
            verifier=f"replication-group-{index % 3}",
            target_digest=SUBJECT_DIGEST,
            status=VerificationStatus.PASSED,
            independence_lineage=(f"replication-group-{index % 3}",),
            timestamp=RUN_AT,
            detail="reproduced by a second path"))
    for index in range(scenario.critical_verified - scenario.critical_independent):
        attempts.append(VerificationAttempt(
            method=VerificationMethod.HUMAN_REVIEW,
            target=VerificationTarget.claim(
                _claim_id(scenario.critical_independent + index)),
            verifier="human://referee-panel",
            target_digest=SUBJECT_DIGEST,
            status=VerificationStatus.PASSED,
            # One lineage, and only one: a referee panel is a named group, so the
            # check is attributable — but a single group is not corroboration.
            # That is why the independent total comes out below the verified one.
            independence_lineage=("referee-panel",),
            timestamp=RUN_AT,
            detail="read by a referee"))
    records_seen += len(attempts)

    report = VerifierReport(
        tool=ToolIdentity(name="lean", version="4.8.0",
                          family=ToolFamily.PROOF_ASSISTANT, established=False),
        attempts=tuple(attempts),
        coverage=VerifierCoverage(
            covers=("the stated lemmas, under the stated axioms",),
            does_not_cover=("whether the formalisation says what its author meant",
                            "any lemma outside the declared manifest"),
            targets_checked=len(attempts),
            targets_declared=scenario.critical_claims),
        adapter="generic", records_seen=len(attempts), records_mapped=len(attempts))

    # ── counterexample search: one found and open, many that found nothing ──
    counterexamples = [CounterexampleAttempt(
        target_claim=COPIED_CLAIM, producer="search://adversarial/7",
        method=VerificationMethod.PROPERTY_TEST,
        result=CounterexampleResult.FOUND, status=CounterexampleStatus.OPEN,
        searched="10^7 sampled instances up to n=2^34", attempted_at=RUN_AT,
        detail="a candidate violating the growth bound at n=2^31")]
    for index in range(6):
        counterexamples.append(CounterexampleAttempt(
            target_claim=_claim_id(index), producer=f"search://adversarial/{index}",
            method=VerificationMethod.PROPERTY_TEST,
            result=CounterexampleResult.NOT_FOUND,
            status=CounterexampleStatus.NOT_APPLICABLE,
            searched="10^6 sampled instances", attempted_at=RUN_AT,
            detail="no violation found in the sampled space"))
    records_seen += len(counterexamples)

    # ── failed branches: kept, because a case that records only its successes
    # looks like its best branch (Invariant 7) ──────────────────────────────
    branches = tuple(
        FailedBranch(
            outcome=BranchOutcome.PROOF_FAILED,
            locus=FailureLocus(step=f"lemma {index}", ordinal=index),
            produced_by=f"worker://rg-1842/{index % max(1, scenario.workers):05d}",
            bears_on_claims=(_claim_id(index),),
            depth=index % 7,
            detail="the induction step does not close at the boundary case",
            occurred_at=RUN_AT, retained_because=RetentionReason.BEARS_ON_CLAIM)
        for index in range(min(scenario.failed_branches, 64)))
    records_seen += scenario.failed_branches

    # ── an incomplete telemetry source ──────────────────────────────────────
    # Source S-4 reports without sequence numbers, so a hole in it would leave no
    # trace. The ledger says COMPLETENESS_UNKNOWN rather than reporting no gaps.
    ledger = StreamLedger(
        streams=(
            SourceStream(stream_id="S-1", producer_id="collector://eu-west",
                         observed_sequences=tuple(range(1, 41))),
            SourceStream(stream_id="S-2", producer_id="collector://us-east",
                         observed_sequences=tuple(range(1, 41))),
            SourceStream(stream_id="S-3", producer_id="collector://ap-south",
                         observed_sequences=tuple(range(1, 41))),
            SourceStream(stream_id="S-4", producer_id="collector://overflow"),
        ),
        expected_streams=("S-1", "S-2", "S-3", "S-4"),
        enumeration_independent=True,
        enumeration_source="the orchestrator's collector manifest",
        notes=("S-4 emitted no sequence numbers, so a hole in it would leave no "
               "shape to detect",))

    notes.append(
        f"{scenario.events:,} execution event(s) and {scenario.claims:,} claim(s) "
        "were produced; materialisation is relevance-directed, so what is held "
        "is the argument and what is counted is everything")

    # The submission itself, hashed over the bytes that were actually submitted —
    # the same content addressing the session path applies to records arriving
    # over a wire, so the subject's digest is OBSERVED because release-gate
    # really did compute it, not because the demo would like it to read that way.
    submitted = canonical_bytes({
        "evidence": [r.to_dict() for r in evidence],
        "claims": [c.to_dict() for c in claims],
        "artifacts": [a.to_dict() for a in artifacts]})
    reference, submission_digest = inline_content(submitted,
                                                  label=f"{RESULT_ID}-submission")
    artifacts = artifacts + (Artifact(
        logical_id=f"file:{RESULT_ID}-submission", artifact_kind=ArtifactKind.OTHER,
        digest=submission_digest, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED, content_reference=reference,
        byte_length=len(submitted), created_at=RUN_AT,
        metadata={"role": "assurance-input"}),)

    normalisation = Normalisation(
        detection=Detection(kind=InputKind.ASSURANCE_ENVELOPE, confidence=100,
                            basis="synthetic research execution, generated in full"),
        source=f"frontier-research/{RESULT_ID}",
        evidence=tuple(evidence), claims=tuple(claims), artifacts=artifacts,
        counterexamples=tuple(counterexamples), failed_branches=branches,
        verifier_report=report,
        records_seen=records_seen, records_mapped=records_seen,
        notes=tuple(notes))
    return normalisation, ledger


@dataclass(frozen=True)
class FrontierRun:
    """What the engine returned. Nothing here is computed by the demo."""

    outcome: Any
    completeness: StreamLedger
    scenario: ResearchScenario

    @property
    def case(self) -> Any:
        return self.outcome.case

    @property
    def analysis(self) -> Any:
        return self.outcome.analysis

    @property
    def attention(self) -> Any:
        return self.outcome.attention


def run(scenario: ResearchScenario = DEFAULT_SCENARIO) -> FrontierRun:
    """Generate the execution and put it through the engine unmodified."""
    normalisation, ledger = build_normalisation(scenario)
    outcome = assure_normalisation(
        normalisation,
        source_name=f"frontier-research/{RESULT_ID}",
        methodology=RESEARCH_MATHEMATICS_V1,
        objective=f"Publish candidate research result {RESULT_ID} as verified",
        requested_decision=f"Publish {RESULT_ID} as a verified result",
        requested_action=f"publish {RESULT_ID}")
    return FrontierRun(outcome=outcome, completeness=ledger, scenario=scenario)


# ── the report ──────────────────────────────────────────────────────────────
#
# Every value below is read from an engine object. There is not a single literal
# count in this function, which is the property `tests/test_demo_frontier_
# research.py` checks by re-deriving each line independently.


def _critical_ids(run: FrontierRun) -> Tuple[str, ...]:
    criticality = getattr(run.analysis, "criticality", None)
    if criticality is None:
        return ()
    return tuple(sorted(getattr(criticality, "critical_ids", ()) or ()))


def _verified_critical(run: FrontierRun, methods: Sequence[str] = ()) -> int:
    """Critical claims carrying a passing attempt, optionally by method."""
    graph = getattr(run.analysis, "verification_graph", None)
    if graph is None:
        return 0
    critical = set(_critical_ids(run))
    hit = set()
    for attempt in graph.attempts:
        target = getattr(attempt, "target", None)
        target_id = str(getattr(target, "target_id", "") or "")
        if attempt.status is not VerificationStatus.PASSED:
            continue
        if methods and attempt.method.value not in methods:
            continue
        if not critical or target_id in critical:
            hit.add(target_id)
    return len(hit)


def _independent_critical(run: FrontierRun) -> int:
    """Critical claims corroborated across more than one lineage.

    Not "checked by someone with a group name": one group checking a thing twice
    is one check twice, and counting it as corroboration is the error the whole
    independence analysis exists to prevent (Invariant 6).
    """
    graph = getattr(run.analysis, "verification_graph", None)
    if graph is None:
        return 0
    critical = set(_critical_ids(run))
    lineages: Dict[str, set] = {}
    for attempt in graph.attempts:
        if attempt.status is not VerificationStatus.PASSED:
            continue
        target_id = str(getattr(getattr(attempt, "target", None), "target_id", "") or "")
        if critical and target_id not in critical:
            continue
        for lineage in attempt.independence_lineage or ():
            lineages.setdefault(target_id, set()).add(lineage)
    return sum(1 for groups in lineages.values() if len(groups) >= 2)


def render(run: FrontierRun, *, attention_limit: int = 8) -> str:
    """The report. Every number comes from `run`; none is written here."""
    outcome, case, analysis = run.outcome, run.case, run.analysis
    independence = getattr(analysis, "independence", None)
    contradictions = getattr(analysis, "contradictions", None)
    counterexamples = getattr(analysis, "counterexamples", None)
    assumptions = getattr(analysis, "assumptions", None)
    claim_graph = getattr(analysis, "claim_graph", None)

    critical = _critical_ids(run)
    executions = case.collection("evidence")

    open_contradictions = len(contradictions.open()) if contradictions else 0
    open_counterexamples = len(counterexamples.open()) if counterexamples else 0
    unresolved_assumptions = (
        len([a for a in assumptions.load_bearing() if not a.source.stated])
        if assumptions else 0)

    lines = [
        "RELEASE-GATE RESEARCH ASSURANCE",
        "",
        "Subject:",
        f"Candidate Research Result {RESULT_ID}",
        "",
        "Workers observed:",
        f"{independence.contributors if independence else 0:,}",
        "",
        "Records seen at ingest:",
        f"{outcome.normalisation.records_seen:,}",
        "",
        "Evidence records held:",
        f"{executions.held_count:,} of {executions.total_count:,}",
        "",
        "Claims in final dependency graph:",
        f"{len(claim_graph) if claim_graph else 0:,}",
        "",
        "Critical claims:",
        f"{len(critical)}",
        "",
        "Critical verification:",
        f"{_verified_critical(run)} / {len(critical)}",
        "",
        "Independent verification:",
        f"{_independent_critical(run)} / {len(critical)}",
        "",
        "Formal verification:",
        f"{_verified_critical(run, ('FORMAL_PROOF', 'THEOREM_PROVER'))} / {len(critical)}",
        "",
        "Open contradictions:",
        f"{open_contradictions}",
        "",
        "Load-bearing assumptions unresolved:",
        f"{unresolved_assumptions}",
        "",
        "Open counterexamples:",
        f"{open_counterexamples}",
        "",
        "Execution completeness:",
        run.completeness.status.value,
        "",
        "Largest single lineage:",
        (f"{independence.largest_ancestry_cluster:,} of "
         f"{independence.contributors:,} workers" if independence else "0"),
        "",
        "Lineage concentration:",
        (independence.concentration.value if independence else "UNKNOWN"),
        "",
        "─" * RULE_WIDTH,
        "",
        "HUMAN ATTENTION",
        "",
    ]

    # The funnel, before the list it produced. A reader who sees the items
    # without the reduction cannot tell whether four items came out of four
    # records or four hundred thousand — and one who sees the reduction without
    # the retained-critical line beside it is being invited to read a big number
    # as a good one, which is what that line is for.
    from release_gate.assurance.compression import measure_compression
    lines.extend(measure_compression(outcome).render().splitlines())
    lines.append("")

    items = outcome.attention.top(attention_limit)
    for index, item in enumerate(items, start=1):
        payload = item.to_dict()
        lines.append(f"{index}. {payload['focus']}")
        lines.append(str(payload.get("why_it_matters") or payload.get("what") or ""))
        lines.append("")

    withheld_attr = getattr(outcome.attention, "withheld_note", "")
    withheld = withheld_attr() if callable(withheld_attr) else str(withheld_attr or "")
    if withheld:
        lines.extend([withheld, ""])

    lines += [
        "─" * RULE_WIDTH,
        "",
        f"VERDICT: {case.verdict.decision.value}",
        "",
        "Fired: " + ", ".join(case.verdict.fired_rules),
        "",
        "Release-gate has not evaluated whether the result is true. It reports "
        "what the evidence establishes and what it does not.",
    ]
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m release_gate.demos.frontier_research [scale-divisor]`."""
    import sys
    args = list(argv if argv is not None else sys.argv[1:])
    scenario = DEFAULT_SCENARIO
    if args:
        scenario = scenario.scaled(int(args[0]))
    print(render(run(scenario)))
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
