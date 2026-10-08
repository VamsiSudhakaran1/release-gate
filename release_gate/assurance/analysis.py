"""Structural analysis that needs no configuration.

These are the questions release-gate can answer about *any* case without being
told anything about the domain: who produced this, does it contradict itself,
was anything verified, does the verification still apply, and what is missing.
None of them require knowing whether the underlying result is *correct* — that
is the question release-gate refuses to answer (Invariant 10).

Every finding carries a stable `RG-*` rule id, the ids it was computed from, and
a remedy. A finding a reviewer cannot trace back to records is the opaque
judgement this system exists to avoid, so `refs` is populated everywhere it can
be and the absence is itself reported.

Effects reuse `RequirementEffect` rather than inventing a severity scale, so a
structural finding and a methodology requirement compose in one policy step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.artifacts import ArtifactGraph, CurrencyStatus
from release_gate.assurance.assumptions import AssumptionGraph
from release_gate.assurance.capabilities import CapabilitySurface, CapabilityStatus
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.consequence import (
    ConsequenceBasis, ConsequenceDimension, ConsequenceProfile,
)
from release_gate.assurance.claims import ClaimGraph, ClaimStatus
from release_gate.assurance.contradiction import (
    ContradictionKind, ContradictionLedger, detect_contradictions,
)
from release_gate.assurance.counterexample import (
    CounterexampleLedger, CounterexampleResult, counterexamples_from_evidence,
)
from release_gate.assurance.failed_branches import (
    FailedBranchLedger, FailedBranchRecorder, branches_from_verification,
)
from release_gate.assurance.evidence import EvidenceRecord, ProducerKind
from release_gate.assurance.expectation import (
    CoverageLedger, CoverageState, EvidenceExpectation, ExpectationStanding)
from release_gate.assurance.criticality import (
    CriticalitySet, DecisionLink, LoadBearing, analyse_criticality)
from release_gate.assurance.adversarial import (
    AdversarialOutcome, AdversarialReview, AdversarialStance, analyse_adversarial)
from release_gate.assurance.replication import (
    ReplicationOutcome, ReplicationProfile, ResultEquivalence, analyse_replication)
from release_gate.assurance.independence import (
    IndependenceProfile, LineageConcentration, analyse_independence,
)
from release_gate.assurance.execution_graph import CompletenessStatus, ExecutionGraph
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.records import Presence
from release_gate.assurance.subject import MutationStatus
from release_gate.assurance.verification import (
    Applicability, TargetKind, VerificationGraph, VerificationStatus, VerificationTarget,
)

__all__ = [
    "AnalysisDomain",
    "AnalysisResult",
    "Finding",
    "analyse",
]

ANALYSIS_RULESET_VERSION = "rg-structural-1"


class AnalysisDomain(str, Enum):
    CAPABILITY = "CAPABILITY"
    CONSEQUENCE = "CONSEQUENCE"
    INDEPENDENCE = "INDEPENDENCE"
    REPLICATION = "REPLICATION"
    ADVERSARIAL = "ADVERSARIAL"
    CRITICALITY = "CRITICALITY"
    EXPECTATION = "EXPECTATION"
    ASSUMPTION = "ASSUMPTION"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    FAILED_BRANCH = "FAILED_BRANCH"
    PROVENANCE = "PROVENANCE"
    CONTRADICTION = "CONTRADICTION"
    VERIFICATION = "VERIFICATION"
    COVERAGE = "COVERAGE"
    DRIFT = "DRIFT"


@dataclass(frozen=True)
class Finding:
    """One structural observation, traceable to the records that produced it."""

    rule_id: str
    domain: AnalysisDomain
    effect: RequirementEffect
    summary: str
    detail: str
    remedy: str
    refs: Tuple[str, ...] = ()
    observed: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain", AnalysisDomain(self.domain))
        object.__setattr__(self, "effect", RequirementEffect(self.effect))
        object.__setattr__(self, "refs", tuple(self.refs))

    # CaseRecord protocol — a finding is storable in a case collection.
    @property
    def record_type(self) -> str:
        return "finding"

    @property
    def record_id(self) -> str:
        return self.rule_id if not self.refs else f"{self.rule_id}:{self.refs[0]}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "finding", "record_id": self.record_id,
                "rule_id": self.rule_id, "domain": self.domain.value,
                "effect": self.effect.value, "summary": self.summary,
                "detail": self.detail, "remedy": self.remedy,
                "refs": list(self.refs), "observed": dict(self.observed)}


@dataclass(frozen=True)
class AnalysisResult:
    """Everything the config-free analysers found."""

    findings: Tuple[Finding, ...] = ()
    ruleset_version: str = ANALYSIS_RULESET_VERSION
    claim_graph: Optional[ClaimGraph] = None
    artifact_graph: Optional[ArtifactGraph] = None
    execution_graph: Optional[ExecutionGraph] = None
    verification_graph: Optional[VerificationGraph] = None
    capabilities: Optional[CapabilitySurface] = None
    consequence: Optional[ConsequenceProfile] = None
    independence: Optional[IndependenceProfile] = None
    replication: Optional[ReplicationProfile] = None
    adversarial: Optional[AdversarialReview] = None
    criticality: Optional[CriticalitySet] = None
    coverage_ledger: Optional[CoverageLedger] = None
    contradictions: Optional[ContradictionLedger] = None
    assumptions: Optional[AssumptionGraph] = None
    counterexamples: Optional[CounterexampleLedger] = None
    failed_branches: Optional[FailedBranchLedger] = None
    #: How each claim-bearing record binds to the candidate (candidate.py), or
    #: None when the case has no candidate and holds no artifact digest.
    state_binding: Optional[Any] = None
    #: Every claim's resolution under the case's resolution policy
    #: (resolution.py): which claims the decision needs, and where each stands.
    resolution: Optional[Any] = None
    #: Each claim's declared surface and what was assessed of it
    #: (claim_coverage.py). Claims with no surface are listed as undeclared.
    claim_coverage: Optional[Any] = None
    #: What each counterexample does to this admission: VALID, STALE, ACCEPTED…
    #: (counterexample.assess_standing), in ledger order.
    counterexample_standings: Tuple[Any, ...] = ()
    #: Each claim's support against the stated authors of what it is about
    #: (authorship.py). AUTHOR_UNKNOWN throughout when nobody stated authorship.
    authorship: Optional[Any] = None

    def by_effect(self, effect: RequirementEffect) -> Tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.effect is effect)

    def by_domain(self, domain: AnalysisDomain) -> Tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.domain is domain)

    @property
    def blocking(self) -> Tuple[Finding, ...]:
        return self.by_effect(RequirementEffect.BLOCK)

    @property
    def holding(self) -> Tuple[Finding, ...]:
        return self.by_effect(RequirementEffect.HOLD)

    def to_dict(self) -> Dict[str, Any]:
        return {"ruleset_version": self.ruleset_version,
                "findings": [f.to_dict() for f in self.findings],
                "counts": {e.value: len(self.by_effect(e)) for e in RequirementEffect},
                "claim_resolution": (self.resolution.to_dict()
                                     if self.resolution is not None else None),
                "state_binding": (self.state_binding.to_dict()
                                  if self.state_binding is not None else None),
                "claim_coverage": (self.claim_coverage.to_dict()
                                   if self.claim_coverage is not None else None),
                "counterexample_standings": [s.to_dict()
                                             for s in self.counterexample_standings],
                "authorship": (self.authorship.to_dict()
                               if self.authorship is not None else None)}


# ── helpers ──────────────────────────────────────────────────────────────────

def _evidence_records(case: AssuranceCase) -> List[EvidenceRecord]:
    """The evidence the structural analysers read: everything but model readings.

    A semantic verifier's reading (semantic_verifier.py) is a statement about
    records already here. Counted as evidence, five readings were five more
    producers, and RG-PROV-002 — all evidence traces to a single producer, a
    HOLD — disappeared because a model was asked about the one producer there
    was. Readings reach the case through the resolver alone, which reads them
    under the declared policy, and the RG-SEM rules report what it did.
    """
    from release_gate.assurance.semantic_verifier import is_semantic_reading
    return [r for r in case.records("evidence")
            if isinstance(r, EvidenceRecord) and not is_semantic_reading(r)]


def _sorted_ids(values: Iterable[str], limit: int = 12) -> Tuple[str, ...]:
    ordered = sorted({str(v) for v in values})
    return tuple(ordered[:limit])


# ── provenance (RG-PROV-*) ───────────────────────────────────────────────────

def _analyse_provenance(case: AssuranceCase, records: Sequence[EvidenceRecord]
                        ) -> List[Finding]:
    findings: List[Finding] = []
    if not records:
        return findings

    unauthenticated = [r for r in records if r.independence_basis != "authenticated"]
    if unauthenticated:
        findings.append(Finding(
            rule_id="RG-PROV-001", domain=AnalysisDomain.PROVENANCE,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(unauthenticated)} of {len(records)} evidence records carry no "
                    "authenticated producer identity",
            detail="Producer identity was asserted by the document, not established. "
                   "This is expected for a file on disk and is recorded so it is not "
                   "mistaken for attribution (Invariant 11: provenance is not trust).",
            remedy="sign the evidence envelope, or ingest through a producer whose "
                   "identity is established at the boundary (CI OIDC, an API key)",
            refs=_sorted_ids(r.evidence_id for r in unauthenticated),
            observed={"unauthenticated": len(unauthenticated), "total": len(records)}))

    # Independence: how many distinct producers are behind the evidence, ignoring
    # release-gate's own derived records — corroborating yourself is not corroboration.
    external = [r for r in records if r.producer.kind is not ProducerKind.RELEASE_GATE]
    fingerprints = {r.independence_fingerprint() for r in external}
    if external and len(fingerprints) == 1:
        findings.append(Finding(
            rule_id="RG-PROV-002", domain=AnalysisDomain.PROVENANCE,
            effect=RequirementEffect.HOLD,
            summary="all evidence traces to a single producer",
            detail=f"{len(external)} external evidence record(s) share one independence "
                   "fingerprint. Nothing here is corroborated by a second source, so a "
                   "systematic error in that producer is invisible to this case.",
            remedy="add evidence from an independently-operated producer — a different "
                   "runner, a different harness, or a human review",
            refs=_sorted_ids(r.evidence_id for r in external),
            observed={"producers": 1, "external_records": len(external)}))
    return findings


# ── verification (RG-VERIF-*) ────────────────────────────────────────────────

def _analyse_solicited(records: Sequence[EvidenceRecord]) -> List[Finding]:
    """Evidence produced because release-gate asked for it.

    Not a fault and not a discount: answering a stated requirement is the loop
    working. What it is, is a fact about why the evidence exists — a party told
    exactly what would close a gate produced exactly that — and a reviewer
    weighing corroboration should be able to see it rather than have it look
    like evidence that arrived on its own (Invariants 1 and 11).
    """
    solicited = [r for r in records if (r.metadata or {}).get("solicited_by")]
    if not solicited:
        return []
    return [Finding(
        rule_id="RG-PROV-003", domain=AnalysisDomain.PROVENANCE,
        effect=RequirementEffect.ADVISORY,
        summary=f"{len(solicited)} evidence record(s) were produced in response to a "
                "stated requirement",
        detail="; ".join(f"{r.evidence_id} from {r.producer.producer_id} answers "
                         f"{r.metadata['solicited_by']}"
                         for r in solicited[:4])[:600]
               + ". Recorded because it bears on how the evidence came to exist: a "
                 "producer told exactly what would close a gate produced exactly "
                 "that. This is the required-evidence loop working, and it is not a "
                 "reason to weigh the evidence less.",
        remedy="none required; the solicitation is recorded so corroboration is not "
               "read as spontaneous agreement",
        refs=tuple(r.evidence_id for r in solicited[:12]),
        observed={"solicited": len(solicited),
                  "requirements": sorted({str(r.metadata["solicited_by"])
                                          for r in solicited})[:12]})]


def _analyse_verification(case: AssuranceCase, records: Sequence[EvidenceRecord],
                          claim_graph: Optional[ClaimGraph]) -> List[Finding]:
    findings: List[Finding] = []
    verifications = [r for r in records if r.is_verification]

    if not verifications and not (claim_graph and any(
            c.verification_attempts for c in claim_graph.claims)):
        findings.append(Finding(
            rule_id="RG-VERIF-001", domain=AnalysisDomain.VERIFICATION,
            effect=RequirementEffect.HOLD,
            summary="nothing in this case was verified",
            detail="No evidence record carries a verification method and no claim "
                   "records a verification attempt. Everything present is a report of "
                   "what happened, not a check that it was right.",
            remedy="supply a typed verification — a test run, a proof, a replication, "
                   "or a human review — naming what it covered",
            observed={"verification_records": 0}))

    if claim_graph is not None:
        failed: List[str] = []
        conflicting: List[str] = []
        for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
            outcomes = {a.status.value for a in claim.verification_attempts}
            if "FAILED" in outcomes:
                failed.append(claim.claim_id)
            if "FAILED" in outcomes and "PASSED" in outcomes:
                conflicting.append(claim.claim_id)
        if failed:
            findings.append(Finding(
                rule_id="RG-VERIF-002", domain=AnalysisDomain.VERIFICATION,
                effect=RequirementEffect.BLOCK,
                summary=f"{len(failed)} claim(s) have a failed verification attempt",
                detail="A verification was run and did not pass. A failed check is "
                       "evidence, not an absence of evidence (Invariant 7), and it is "
                       "reported here rather than averaged away.",
                remedy="resolve the failure, or record why the failing check does not "
                       "apply to the claim it was run against",
                refs=_sorted_ids(failed), observed={"claims_failed": len(failed)}))
        if conflicting:
            findings.append(Finding(
                rule_id="RG-VERIF-003", domain=AnalysisDomain.VERIFICATION,
                effect=RequirementEffect.HOLD,
                summary=f"{len(conflicting)} claim(s) have both passing and failing "
                        "verification attempts",
                detail="The same claim was checked more than once with different "
                       "outcomes. Which check was right is a domain question; that they "
                       "disagree is a structural one.",
                remedy="record which attempt supersedes the other and on what basis",
                refs=_sorted_ids(conflicting),
                observed={"claims_conflicting": len(conflicting)}))
    return findings


def _analyse_verification_graph(graph: Optional[VerificationGraph]) -> List[Finding]:
    """What the verification graph says that a per-claim status cannot.

    The sharp one is supersession: an attempt that passed against content the
    target no longer has. A boolean "verified" carries that forward silently;
    a graph that binds each attempt to a digest cannot.
    """
    findings: List[Finding] = []
    if graph is None or not graph.attempts:
        return findings

    superseded = graph.superseded_attempts()
    if superseded:
        findings.append(Finding(
            rule_id="RG-VERIF-004", domain=AnalysisDomain.VERIFICATION,
            effect=RequirementEffect.BLOCK,
            summary=f"{len(superseded)} verification(s) ran against content the target "
                    "no longer has",
            detail="These checks were sound when they ran and do not apply now: "
                   + "; ".join(
                       f"{a.verification_id} ({a.method.value}, {a.status.value}) on "
                       f"{a.target.kind.value} {a.target.target_id}"
                       for a in superseded[:6])
                   + ". A proof of an earlier state is not a proof of this one.",
            remedy="re-run the verification against the current target state",
            refs=tuple(a.verification_id for a in superseded[:12]),
            observed={"superseded": len(superseded)}))

    undetermined = [a for a in graph.attempts
                    if a.target is not None
                    and a.applicability(graph.current_digest(a.target))
                    is Applicability.UNDETERMINED
                    and a.counts_toward_status]
    if undetermined:
        findings.append(Finding(
            rule_id="RG-VERIF-005", domain=AnalysisDomain.VERIFICATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(undetermined)} verification(s) do not record what state they "
                    "ran against",
            detail="Without a target digest on the attempt, or a current digest for the "
                   "target, whether these still apply cannot be computed. They are "
                   "reported and not counted as current — 'cannot tell' is not 'still "
                   "holds'.",
            remedy="record target_digest on each verification attempt, so its "
                   "applicability becomes a computation rather than an assumption",
            refs=tuple(a.verification_id for a in undetermined[:12]),
            observed={"undetermined": len(undetermined)}))

    invalidated = graph.invalidated()
    if invalidated:
        findings.append(Finding(
            rule_id="RG-VERIF-006", domain=AnalysisDomain.VERIFICATION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(invalidated)} verification(s) have been invalidated",
            detail="These ran, and their results have since been withdrawn or found "
                   "unreliable: "
                   + "; ".join(f"{a.verification_id} ({a.method.value})"
                               for a in invalidated[:6])
                   + ". An invalidated pass is not a pass, and is not counted as one.",
            remedy="re-run the invalidated checks, or record why the target stands "
                   "without them",
            refs=tuple(a.verification_id for a in invalidated[:12]),
            observed={"invalidated": len(invalidated)}))

    not_run = graph.not_run()
    if not_run:
        findings.append(Finding(
            rule_id="RG-VERIF-007", domain=AnalysisDomain.VERIFICATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(not_run)} expected verification(s) were never run",
            detail="; ".join(f"{a.method.value} on "
                             f"{a.target.kind.value if a.target else 'an unnamed target'}"
                             f"{': ' + a.detail if a.detail else ''}"
                             for a in not_run[:6])
                   + ". Recorded because a check somebody expected and did not run is a "
                     "fact about this case, not an absence of one.",
            remedy="run them, or withdraw the expectation",
            refs=tuple(a.verification_id for a in not_run[:12]),
            observed={"not_run": len(not_run)}))
    return findings


# ── independence (RG-INDEP-*) ────────────────────────────────────────────────

def _analyse_independence(profile: Optional[IndependenceProfile]) -> List[Finding]:
    """Where support actually comes from — reported, never penalised.

    Every finding here is ADVISORY, deliberately. Many parties legitimately
    relying on one authoritative source is a normal and often correct workflow,
    and a gate that docked it would be punishing good practice. Concentration
    becomes blocking only where a methodology says it needs independence, through
    `AncestryIndependence`.
    """
    findings: List[Finding] = []
    if profile is None or not profile.contributors:
        return findings

    if profile.concentration is LineageConcentration.HIGH:
        largest = profile.clusters[0] if profile.clusters else None
        findings.append(Finding(
            rule_id="RG-INDEP-001", domain=AnalysisDomain.INDEPENDENCE,
            effect=RequirementEffect.ADVISORY,
            summary=(f"{profile.largest_ancestry_cluster:,} of {profile.contributors:,} "
                     f"contributor(s) share one evidence lineage"),
            detail=(f"Support traces to {profile.independent_roots} distinct lineage(s). "
                    "Agreement among parties that derive from one source is one "
                    "validation observed many times, not many validations. This is "
                    "reported, not penalised — relying on one authoritative source is "
                    "often exactly right."),
            remedy=("none required; obtain support from an independent lineage only if "
                    "the decision needs corroboration rather than a single source"),
            refs=(largest.cluster_id,) if largest else (),
            observed=profile.summary()))

    if profile.independent_roots == 1 and profile.contributors > 1:
        findings.append(Finding(
            rule_id="RG-INDEP-002", domain=AnalysisDomain.INDEPENDENCE,
            effect=RequirementEffect.ADVISORY,
            summary=f"all {profile.contributors:,} contributor(s) trace to a single "
                    "evidence root",
            detail="There is exactly one lineage here. However many parties agree, a "
                   "fault in that root is invisible to all of them.",
            remedy="none required; add an independently-rooted check if a single point "
                   "of failure is unacceptable for this decision",
            observed={"contributors": profile.contributors, "roots": 1}))

    if profile.unknown_ancestry:
        findings.append(Finding(
            rule_id="RG-INDEP-003", domain=AnalysisDomain.INDEPENDENCE,
            effect=RequirementEffect.ADVISORY,
            summary=f"{profile.unknown_ancestry:,} contributor(s) record no ancestry",
            detail=("Their evidence cites no parents, so whether it is original or "
                    "derived is unknown. Such contributors are neither assumed "
                    "independent nor assumed identical" +
                    ("; and here they are numerous enough that the lineage ranking "
                     "itself is undetermined." if not profile.determinable else ".")),
            remedy="record parent_evidence on derived records, so ancestry can be traced "
                   "rather than guessed",
            observed={"unknown_ancestry": profile.unknown_ancestry,
                      "contributors": profile.contributors,
                      "determinable": profile.determinable}))

    if profile.cycles_detected:
        findings.append(Finding(
            rule_id="RG-INDEP-004", domain=AnalysisDomain.INDEPENDENCE,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(profile.cycles_detected)} evidence record(s) sit in a "
                    "derivation cycle",
            detail="These records are reachable from themselves through "
                   "parent_evidence. Each was treated as its own root rather than the "
                   "loop being followed, so their true ancestry is unresolved.",
            remedy="correct the parent_evidence chain so derivation is acyclic",
            refs=profile.cycles_detected[:12],
            observed={"cycles": len(profile.cycles_detected)}))
    return findings


# ── expectation (RG-EXPECT-*) ────────────────────────────────────────────────

def _coverage_ledger(case: AssuranceCase,
                     normalisation: Optional[Any]) -> CoverageLedger:
    """Every coverage dimension the case holds, plus any declared expectations.

    Where a declared expectation names a dimension the case already has a row
    for, the one with the stronger standing wins: an orchestrator's denominator
    tells you something a producer's count of itself cannot, so it is not
    overwritten by the row that happened to be built first. Equal standing keeps
    the declaration, because someone went to the trouble of writing it down.
    """
    rows: Dict[str, EvidenceExpectation] = {}
    for record in case.records("coverage"):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        dimension = str(payload.get("dimension") or "")
        if not dimension:
            continue
        try:
            rows[dimension] = EvidenceExpectation.from_dict(
                {**payload, "assessed": payload.get("status") == "ASSESSED"})
        except Exception:
            continue

    rank = {ExpectationStanding.NOT_ESTABLISHED: 0,
            ExpectationStanding.SELF_REPORTED: 1,
            ExpectationStanding.ESTABLISHED: 2}
    for declared in (getattr(normalisation, "expectations", ()) or ()):
        held = rows.get(declared.dimension)
        if held is None or rank[declared.standing] >= rank[held.standing]:
            rows[declared.dimension] = declared
    return CoverageLedger(tuple(rows[k] for k in sorted(rows)))


def _analyse_expectation(ledger: Optional[CoverageLedger]) -> List[Finding]:
    """What was expected against what arrived, and what can honestly be divided.

    `RG-EXPECT-002` is advisory on purpose and will fire on most cases: a
    dimension with no denominator is the normal state of the world, not a fault.
    What would be a fault is rendering it as complete, and that is prevented in
    the record rather than by a finding. A methodology that needs a real
    denominator for a named dimension says so through `ExpectationDeclared`.
    """
    findings: List[Finding] = []
    if ledger is None or not len(ledger):
        return findings

    # Both states where a denominator stands and evidence is absent. `EXPECTED`
    # means *none* of it arrived and `KNOWN_MISSING` means *some* did, and the
    # ledger keeps them apart because they are different messages to a reader.
    # Reading only the second is what this rule used to do, and the effect was an
    # inversion: a CI plan declaring five jobs held the case when four arrived
    # and promoted it when none did. The worst case was the only one that went
    # quiet, because the state machine routed it down a branch nothing read
    # (Invariant 13 — evidence omission is a threat, and total omission most of
    # all). The distinction is preserved in the detail rather than by dropping
    # half the finding.
    started = ledger.known_missing()
    never_started = ledger.in_state(CoverageState.EXPECTED)
    missing = list(started) + list(never_started)
    if missing:
        total = sum(r.known_missing or 0 for r in missing)
        findings.append(Finding(
            rule_id="RG-EXPECT-001", domain=AnalysisDomain.EXPECTATION,
            effect=RequirementEffect.HOLD,
            summary=f"{total} expected piece(s) of evidence did not arrive across "
                    f"{len(missing)} dimension(s)",
            detail="; ".join(r.basis for r in missing[:4])[:700]
                   + ". This is evidence known to be absent, which is a different "
                     "and much stronger fact than evidence nobody looked for."
                   + (f" {len(never_started)} of these dimension(s) received "
                      "nothing at all." if never_started else ""),
            remedy="supply the missing evidence, or record why the expectation no "
                   "longer applies",
            refs=tuple(r.dimension for r in missing[:12]),
            observed={"known_missing_total": total,
                      "dimensions": [r.dimension for r in missing[:12]],
                      "nothing_arrived": [r.dimension for r in never_started[:12]],
                      "named": [i for r in missing for i in r.known_missing_ids[:4]]}))

    unknown = [r for r in ledger.unknown() if not r.over_count]
    if unknown:
        findings.append(Finding(
            rule_id="RG-EXPECT-002", domain=AnalysisDomain.EXPECTATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(unknown)} coverage dimension(s) have no expectation, so "
                    "their coverage is UNKNOWN rather than a percentage",
            detail="; ".join(f"{r.dimension}: observed {r.observed}, expected UNKNOWN"
                             for r in unknown[:6])[:600]
                   + ". Observations without a denominator cannot be divided into a "
                     "ratio, and reporting one would be inventing the number a reader "
                     "most wants to believe. UNKNOWN here is not a fault — most "
                     "dimensions genuinely have nobody to state a total.",
            remedy="declare an expectation for the dimensions this decision depends "
                   "on — an orchestration manifest, a verifier inventory, an "
                   "experiment matrix or a CI plan will do",
            refs=tuple(r.dimension for r in unknown[:12]),
            observed={"unknown_dimensions": len(unknown),
                      "with_expectation": len(ledger.with_expectation()),
                      "overall_coverage": None}))

    over = ledger.over_counted()
    if over:
        findings.append(Finding(
            rule_id="RG-EXPECT-003", domain=AnalysisDomain.EXPECTATION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(over)} dimension(s) received more evidence than was "
                    "expected, so their denominator is not trustworthy",
            detail="; ".join(r.basis for r in over[:4])[:600]
                   + ". Coverage for these is reported UNKNOWN rather than clamped to "
                     "100%: an over-count is an anomaly, and rounding it down would "
                     "render it as perfection.",
            remedy="reconcile the expectation with what arrived — either the total "
                   "was wrong or records arrived that nothing planned for",
            refs=tuple(r.dimension for r in over[:12]),
            observed={"over_counted": len(over)}))

    unplanned = ledger.unexpected()
    if unplanned:
        findings.append(Finding(
            rule_id="RG-EXPECT-004", domain=AnalysisDomain.EXPECTATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{sum(len(r.unexpected_ids) for r in unplanned)} record(s) "
                    "arrived that no expectation named",
            detail="; ".join(f"{r.dimension}: {', '.join(r.unexpected_ids[:4])}"
                             for r in unplanned[:4])[:600]
                   + ". An enumerated expectation can tell the planned from the "
                     "unplanned; a bare count cannot see this at all.",
            remedy="none required; extend the expectation if these were meant to be "
                   "part of it",
            refs=tuple(r.dimension for r in unplanned[:12]),
            observed={"unexpected": sum(len(r.unexpected_ids) for r in unplanned)}))

    certified = ledger.self_certified()
    if certified:
        findings.append(Finding(
            rule_id="RG-EXPECT-005", domain=AnalysisDomain.EXPECTATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(certified)} coverage dimension(s) are measured against an "
                    "expectation declared by the party that produced the evidence",
            detail="; ".join(f"{r.dimension}: expected by {r.source.declared_by}, "
                             "which also produced it" for r in certified[:5])[:600]
                   + ". The count may be right. What it cannot do is detect an "
                     "omission: whatever was dropped from the evidence was dropped "
                     "from the denominator with it, and the coverage reads high "
                     "precisely because something is missing (Invariant 13). Signing "
                     "does not change this — it establishes which party declared the "
                     "number, not that they were disinterested.",
            remedy="obtain the expectation from an orchestrator, a roster or a plan "
                   "written before the evidence, rather than from its producer",
            refs=tuple(r.dimension for r in certified[:12]),
            observed={"self_certified": len(certified),
                      "authenticated": sum(1 for r in certified
                                           if r.source and r.source.authenticated)}))
    return findings


# ── criticality (RG-CRIT-*) ──────────────────────────────────────────────────

def _analyse_criticality(criticality: Optional[CriticalitySet]) -> List[Finding]:
    """What the decision rests on, and whether that could be established.

    `RG-CRIT-001` is the one that matters. Every critical-claim guard in this
    system — unresolved counterexamples, adversarial argument defects, divergent
    replication, the contradiction a verdict may not omit — asks whether a claim
    is critical. A case whose criticality could not be derived answers "no" to all
    of them and comes out looking clean for the worst possible reason. So the gap
    is reported loudly rather than allowed to pass as an absence of problems.
    """
    findings: List[Finding] = []
    if criticality is None or not criticality.claims_examined:
        return findings

    if not criticality.determinable:
        findings.append(Finding(
            rule_id="RG-CRIT-001", domain=AnalysisDomain.CRITICALITY,
            effect=RequirementEffect.HOLD,
            summary="what this decision rests on could not be established, so no "
                    "claim is known to be critical",
            detail=(criticality.basis +
                    ". Every critical-claim guard in this analysis asks whether a "
                    "claim is critical, and with criticality undetermined they all "
                    "answer no — so a clean result here means nothing was checked, "
                    "not that nothing was found."),
            remedy="mark the claim this decision is being asked about with is_root, "
                   "or record the dependency edges that connect the conclusion to "
                   "what it rests on",
            observed={"claims": criticality.claims_examined,
                      "determinable": False, "link": criticality.link.value}))
        return findings

    broken = criticality.broken_chains()
    if broken:
        missing = sorted({m for e in broken for m in e.missing_dependencies})
        findings.append(Finding(
            rule_id="RG-CRIT-002", domain=AnalysisDomain.CRITICALITY,
            effect=RequirementEffect.HOLD,
            summary=f"{len(broken)} load-bearing claim(s) depend on "
                    f"{len(missing)} claim(s) this case does not hold",
            detail="; ".join(f"{e.claim_id} rests on "
                             + ", ".join(e.missing_dependencies[:3])
                             for e in broken[:4])[:600]
                   + ". The decision rests on these through the broken link, so part "
                     "of what it rests on is outside this case entirely.",
            remedy="supply the missing claims, or correct the dependency edges that "
                   "name them",
            refs=tuple(missing[:12]),
            observed={"broken_chains": len(broken), "missing": missing[:12]}))

    disagreements = criticality.disagreements()
    if disagreements:
        findings.append(Finding(
            rule_id="RG-CRIT-003", domain=AnalysisDomain.CRITICALITY,
            effect=RequirementEffect.HOLD,
            summary=f"{len(disagreements)} claim(s) are declared critical but nothing "
                    "the decision rests on depends on them",
            detail="; ".join(f"{e.claim_id} (declared {e.declared}) is "
                             f"{e.standing.value}" for e in disagreements[:5])[:600]
                   + ". A producer calling a claim critical does not make the "
                     "decision rest on it, and this is not resolved either way: "
                     "either the label is wrong or a dependency edge is missing, and "
                     "a graph cannot settle which.",
            remedy="record the dependency that makes the claim load-bearing, or drop "
                   "the criticality label",
            refs=tuple(e.claim_id for e in disagreements[:12]),
            observed={"disagreements": len(disagreements)}))

    if criticality.unreachable_conclusions:
        findings.append(Finding(
            rule_id="RG-CRIT-004", domain=AnalysisDomain.CRITICALITY,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(criticality.unreachable_conclusions)} conclusion(s) are not "
                    "reachable from what this decision is about",
            detail="Nothing depends on these and the decision does not reach them, so "
                   "they are a second conclusion nobody linked up. Everything under "
                   "them sits outside every critical-claim guard.",
            remedy="link them to the decision, or record that they are incidental",
            refs=criticality.unreachable_conclusions[:12],
            observed={"unreachable": len(criticality.unreachable_conclusions),
                      "decision_claims": list(criticality.decision_claims[:8])}))

    thin = criticality.thin()
    if thin:
        findings.append(Finding(
            rule_id="RG-CRIT-005", domain=AnalysisDomain.CRITICALITY,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(thin)} load-bearing claim(s) rest on a single producer",
            detail="; ".join(f"{e.claim_id} at depth {e.depth}" for e in thin[:6])[:500]
                   + ". Reported so a reviewer sees how thinly the decision is "
                     "supported — not as a discount. A claim one agent emitted once "
                     "is exactly as load-bearing as one four hundred agents "
                     "discussed, and nothing here weighs criticality by volume "
                     "(Invariant 12).",
            remedy="none required; obtain support from a second producer only if this "
                   "decision needs corroboration on the claims it rests on",
            refs=tuple(e.claim_id for e in thin[:12]),
            observed={"thin_critical": len(thin),
                      "max_depth": criticality.max_depth,
                      "volume_affects_criticality": False}))
    return findings


# ── adversarial (RG-ADV-*) ───────────────────────────────────────────────────

def _analyse_adversarial(review: Optional[AdversarialReview],
                         critical: Set[str]) -> List[Finding]:
    """Verifiers whose job was to make the candidate fail, and what came of it.

    Refutations are deliberately *not* re-reported here. An adversarial finding
    of `CANDIDATE_REFUTED` converts to a `CounterexampleAttempt` and is handled by
    `RG-CEX-*` all the way through to the contradiction the verdict cannot omit.
    Filing it twice under two rule ids would double a reviewer's work and let the
    two copies drift apart. What this analyser reports is everything the
    counterexample path cannot see: a broken argument, a risk somebody accepted,
    a finding closed by the party it was against, and an adversary that shares
    origin with what it attacked.

    The absence of adversaries is never a finding. Most decisions have none.
    """
    findings: List[Finding] = []
    if review is None or not review.present:
        return findings

    defects = [f for f in review.argument_defects() if f.is_open]
    against_critical = [f for f in defects if f.target_claim in critical]
    if against_critical:
        findings.append(Finding(
            rule_id="RG-ADV-001", domain=AnalysisDomain.ADVERSARIAL,
            effect=RequirementEffect.BLOCK,
            summary=f"{len(against_critical)} unanswered adversarial finding(s) break "
                    "the argument for a critical claim",
            detail="; ".join(f"{f.finding_id}: {f.role.value} {f.adversary} found "
                             f"{f.target_claim}'s support does not establish it"
                             for f in against_critical[:4])[:700]
                   + ". This does not say the claim is false — it says nothing here "
                     "shows it true. The support has to be repaired or replaced.",
            remedy="repair the support the critic identified and record what answers "
                   "the finding, or withdraw the claim",
            refs=tuple(f.finding_id for f in against_critical[:12]),
            observed={"open_argument_defects_critical": len(against_critical),
                      "critical_claims": sorted({f.target_claim
                                                 for f in against_critical})[:12]}))

    # Everything else still standing, minus the accepted risks: those are reported
    # by RG-ADV-003, which says something this rule cannot, and counting them here
    # too would bill a reviewer twice for one finding.
    remaining = [f for f in review.open()
                 if not f.accepted and f not in against_critical
                 and f.outcome is not AdversarialOutcome.CANDIDATE_REFUTED]
    if remaining:
        findings.append(Finding(
            rule_id="RG-ADV-002", domain=AnalysisDomain.ADVERSARIAL,
            effect=RequirementEffect.HOLD,
            summary=f"{len(remaining)} unanswered adversarial finding(s) stand",
            detail="; ".join(f"{f.finding_id} ({f.outcome.value}) by {f.adversary} "
                             f"against {f.target_claim}"
                             for f in remaining[:6])[:600],
            remedy="answer these and record what answers them, or record why they do "
                   "not bear on the decision",
            refs=tuple(f.finding_id for f in remaining[:12]),
            observed={"open": len(remaining),
                      "against_critical": sum(1 for f in remaining
                                              if f.target_claim in critical)}))

    accepted = review.accepted_risks()
    if accepted:
        critical_accepts = [f for f in accepted if f.target_claim in critical]
        findings.append(Finding(
            rule_id="RG-ADV-003", domain=AnalysisDomain.ADVERSARIAL,
            effect=(RequirementEffect.HOLD if critical_accepts
                    else RequirementEffect.ADVISORY),
            summary=f"{len(accepted)} adversarial finding(s) were accepted as risk "
                    "rather than answered",
            detail="; ".join(f"{f.finding_id} against {f.target_claim}, accepted by "
                             f"{f.accepted_by or 'an unnamed party'}: {f.resolution}"
                             for f in accepted[:4])[:700]
                   + ". Accepting a risk is a decision to proceed, not a resolution. "
                     "It is surfaced because the person authorizing this release is "
                     "exactly who should be told what is being accepted on their "
                     "behalf (Invariant 15).",
            remedy="none required if the acceptance is intended; the authorizer needs "
                   "to see it either way",
            refs=tuple(f.finding_id for f in accepted[:12]),
            observed={"accepted_risks": len(accepted),
                      "against_critical": len(critical_accepts),
                      "critical_claims": sorted({f.target_claim
                                                 for f in critical_accepts})[:12]}))

    cleared = review.self_cleared()
    if cleared:
        critical_cleared = [f for f in cleared if f.target_claim in critical]
        findings.append(Finding(
            rule_id="RG-ADV-004", domain=AnalysisDomain.ADVERSARIAL,
            effect=(RequirementEffect.BLOCK if critical_cleared
                    else RequirementEffect.HOLD),
            summary=f"{len(cleared)} adversarial finding(s) were closed by the party "
                    "they were against",
            detail="; ".join(f"{f.finding_id} against {f.target_claim} was closed by "
                             f"{f.resolved_by or f.accepted_by}, who also produced "
                             "that claim's support" for f in cleared[:4])[:700]
                   + ". A finding answered by the party it argues against has not "
                     "been independently answered, whatever its recorded status says.",
            remedy="have the resolution reviewed by a party that did not produce the "
                   "claim's support, and cite that review as resolution_evidence",
            refs=tuple(f.finding_id for f in cleared[:12]),
            observed={"self_cleared": len(cleared),
                      "against_critical": len(critical_cleared),
                      "critical_claims": sorted({f.target_claim
                                                 for f in critical_cleared})[:12]}))

    related = review.non_independent()
    if related:
        by_stance = {s.value: sum(1 for f in related
                                  if review.stances.get(f.finding_id) is s)
                     for s in AdversarialStance}
        findings.append(Finding(
            rule_id="RG-ADV-005", domain=AnalysisDomain.ADVERSARIAL,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(related)} adversarial attack(s) came from an adversary "
                    "sharing origin with what it attacked",
            detail="An adversary that produced the candidate's own support, or rests "
                   "on the same lineage, will tend to miss what the builder missed. "
                   "Their findings still count for everything they found; what they "
                   "did not find covers less than it appears to (Invariant 6).",
            remedy="none required; obtain an attack from an adversary with a separate "
                   "lineage if the decision needs the search to be genuinely other",
            refs=tuple(f.finding_id for f in related[:12]),
            observed={"non_independent": len(related), "by_stance": by_stance}))

    empty = review.empty_searches()
    if empty:
        unbounded = review.unbounded_searches()
        findings.append(Finding(
            rule_id="RG-ADV-006", domain=AnalysisDomain.ADVERSARIAL,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(empty)} adversarial attack(s) found nothing",
            detail="; ".join(f"{f.role.value} {f.adversary} on {f.target_claim}: "
                             f"{f.search_bound}" for f in empty[:3])[:700]
                   + ". Recorded as evidence about the search and credited with "
                     "nothing about the claim: an attack that came back empty bounds "
                     "what was tried, however many of them there are."
                   + (f" {len(unbounded)} of these recorded no search extent at all."
                      if unbounded else ""),
            remedy="state what each attack actually covered, so a reviewer can see "
                   "what an empty result does and does not bound",
            refs=tuple(f.finding_id for f in empty[:12]),
            observed={"empty_searches": len(empty), "unbounded": len(unbounded),
                      "proves_absence": False}))

    unattacked = review.unattacked(critical)
    if unattacked:
        findings.append(Finding(
            rule_id="RG-ADV-007", domain=AnalysisDomain.ADVERSARIAL,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(unattacked)} critical claim(s) had adversarial review "
                    "elsewhere in this case but not on them",
            detail="Adversaries attacked this case but did not attack these claims. "
                   "Reported so the presence of a red team is not read as coverage of "
                   "everything (Invariant 9). Adversarial review is never required.",
            remedy="none required; point an adversary at these claims if the decision "
                   "needs them attacked too",
            refs=tuple(unattacked[:12]),
            observed={"unattacked_critical": len(unattacked),
                      "claims_attacked": len(review.claims_attacked)}))
    return findings


# ── replication (RG-REPL-*) ──────────────────────────────────────────────────

def _analyse_replication(profile: Optional[ReplicationProfile],
                         critical: Set[str]) -> List[Finding]:
    """What has actually been reproduced, once copies have collapsed.

    The asymmetry between the two outcomes is deliberate. Divergence holds the
    decision: paths that disagree are a disagreement, and the ones that agree do
    not settle it however many there are. Everything else is advisory, because a
    workflow that legitimately rests on one path is normal and a gate that docked
    it would punish good practice — only a methodology that says it needs
    independent reproduction can turn a single path into a verdict, through
    `ReplicationEstablished`.
    """
    findings: List[Finding] = []
    if profile is None or not profile.targets:
        return findings

    divergent = profile.divergent
    against_critical = [t for t in divergent
                        if t.target.kind is TargetKind.CLAIM
                        and t.target.target_id in critical]
    if against_critical:
        findings.append(Finding(
            rule_id="RG-REPL-001", domain=AnalysisDomain.REPLICATION,
            effect=RequirementEffect.BLOCK,
            summary=f"{len(against_critical)} critical target(s) have replications that "
                    "disagree with each other",
            detail="; ".join(
                f"{t.target.target_id}: {t.established_paths} established path(s) "
                f"reached {' and '.join(t.divergent_verdicts)}"
                for t in against_critical[:4])[:700]
                   + ". This is a disagreement, not a majority: the paths that agree "
                     "do not settle it, and averaging them would erase the one that "
                     "did not.",
            remedy="find out why the paths differ and record what settles it, or "
                   "withdraw the result until they agree",
            refs=tuple(t.target.target_id for t in against_critical[:12]),
            observed={"divergent_critical": len(against_critical),
                      "critical_claims": sorted({t.target.target_id
                                                 for t in against_critical})[:12]}))

    other = [t for t in divergent if t not in against_critical]
    if other:
        findings.append(Finding(
            rule_id="RG-REPL-002", domain=AnalysisDomain.REPLICATION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(other)} target(s) have replications that disagree",
            detail="; ".join(f"{t.target.target_id} reached "
                             f"{' and '.join(t.divergent_verdicts)} on different paths"
                             for t in other[:6])[:500],
            remedy="reconcile the paths or record why the difference does not bear on "
                   "the decision",
            refs=tuple(t.target.target_id for t in other[:12]),
            observed={"divergent": len(other)}))

    echoed = [t for t in profile.single_path if t.attempts_examined > 1]
    if echoed:
        findings.append(Finding(
            rule_id="RG-REPL-003", domain=AnalysisDomain.REPLICATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(echoed)} target(s) have agreeing attempts that all collapse "
                    "to one path",
            detail="; ".join(f"{t.target.target_id}: {t.attempts_examined:,} attempt(s) "
                             f"-> 1 path ({t.copies_collapsed:,} collapsed)"
                             for t in echoed[:4])[:600]
                   + ". Agreement among attempts that share a lineage, an "
                     "implementation and an input is one result observed many times. "
                     "This is reported, not penalised — resting on one authoritative "
                     "path is often exactly right.",
            remedy="none required; obtain a result from a path that could fail "
                   "differently only if this decision needs reproduction rather than "
                   "repetition",
            refs=tuple(t.target.target_id for t in echoed[:12]),
            observed={"single_path_targets": len(echoed),
                      "attempts": sum(t.attempts_examined for t in echoed),
                      "copies_collapsed": sum(t.copies_collapsed for t in echoed)}))

    unachieved = profile.not_achieved
    if unachieved:
        findings.append(Finding(
            rule_id="RG-REPL-004", domain=AnalysisDomain.REPLICATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(unachieved)} target(s) had a reproduction attempted that "
                    "reached no verdict",
            detail="; ".join(f"{t.target.target_id}: {len(t.not_achieved)} "
                             "inconclusive attempt(s)" for t in unachieved[:4])[:500]
                   + ". Kept as evidence about the attempt, credited with nothing "
                     "about the result (Invariant 7).",
            remedy="none required; record why the reproduction could not complete if a "
                   "reviewer needs to know what was in the way",
            refs=tuple(t.target.target_id for t in unachieved[:12]),
            observed={"not_achieved": len(unachieved)}))

    verdict_only = [t for t in profile.confirmed
                    if t.equivalence in (ResultEquivalence.VERDICT_ONLY,
                                         ResultEquivalence.UNDETERMINED)]
    if verdict_only:
        findings.append(Finding(
            rule_id="RG-REPL-005", domain=AnalysisDomain.REPLICATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(verdict_only)} reproduced target(s) agree on the verdict but "
                    "not demonstrably on the result",
            detail="; ".join(f"{t.target.target_id}: {t.equivalence.value}"
                             for t in verdict_only[:6])[:500]
                   + ". The paths reached the same pass or fail; whether they computed "
                     "the same thing is not established, and release-gate cannot "
                     "decide that — tolerance is domain knowledge and has to be "
                     "declared.",
            remedy="declare an equivalence basis on the results (and a tolerance where "
                   "one applies) so agreement on the value is recorded rather than "
                   "inferred",
            refs=tuple(t.target.target_id for t in verdict_only[:12]),
            observed={"verdict_only": len(verdict_only)}))

    unattributed = [t for t in profile.targets if t.unattributed_paths]
    if unattributed:
        findings.append(Finding(
            rule_id="RG-REPL-006", domain=AnalysisDomain.REPLICATION,
            effect=RequirementEffect.ADVISORY,
            summary=f"{sum(t.unattributed_paths for t in unattributed)} path(s) record "
                    "no lineage and cite no evidence",
            detail="They are counted apart rather than credited: a second opinion that "
                   "says nothing about where it came from cannot be shown to rest on "
                   "anything different from the first.",
            remedy="record independence_lineage on verification attempts, or cite the "
                   "evidence they rest on, so reproduction can be derived rather than "
                   "assumed",
            refs=tuple(t.target.target_id for t in unattributed[:12]),
            observed={"unattributed_paths": sum(t.unattributed_paths
                                                for t in unattributed)}))
    return findings


# ── assumptions (RG-ASSUME-*) ────────────────────────────────────────────────

def _analyse_assumptions(graph: Optional[AssumptionGraph]) -> List[Finding]:
    """What the argument takes for granted, and what would fall with it.

    Two findings, both about not knowing. An assumption that holds up the
    conclusion and that nothing has examined is the case this whole module exists
    for; an assumption named by a claim and described nowhere is worse, because
    nobody can even begin to evaluate it.
    """
    findings: List[Finding] = []
    if graph is None or not len(graph):
        return findings

    unexamined = graph.unexamined()
    if unexamined:
        findings.append(Finding(
            rule_id="RG-ASSUME-001", domain=AnalysisDomain.ASSUMPTION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(unexamined)} load-bearing assumption(s) have nothing bearing "
                    "on whether they hold",
            detail="; ".join(
                f"{a.assumption_id}"
                + (f" (\"{a.statement}\")" if a.statement else "")
                + f" — if it fails, {a.collapse.size} claim(s) collapse including "
                + ", ".join(a.collapse.roots_affected)
                for a in unexamined[:4])[:700],
            remedy="supply evidence or a verification for these assumptions, or record "
                   "why they are safe to take for granted",
            refs=tuple(a.assumption_id for a in unexamined[:12]),
            observed={"unexamined": len(unexamined),
                      "assumption_ids": [a.assumption_id for a in unexamined[:12]]}))

    unstated = graph.unstated()
    if unstated:
        findings.append(Finding(
            rule_id="RG-ASSUME-002", domain=AnalysisDomain.ASSUMPTION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(unstated)} assumption(s) are referenced but never stated",
            detail="; ".join(
                f"{a.assumption_id} is named by {', '.join(a.referenced_by)} and "
                "described nowhere" for a in unstated[:4])[:700]
                   + ". An assumption nobody wrote down cannot be evaluated, agreed "
                     "with, or argued against.",
            remedy="state what each of these assumptions actually asserts",
            refs=tuple(a.assumption_id for a in unstated[:12]),
            observed={"unstated": len(unstated)}))
    return findings


# ── counterexamples (RG-CEX-*) ───────────────────────────────────────────────

def _analyse_counterexamples(ledger: Optional[CounterexampleLedger],
                             critical: Set[str], standings: Sequence[Any] = (),
                             policy: Optional[Any] = None) -> List[Finding]:
    """Attempts to break a claim, and the asymmetry between the two outcomes.

    A counterexample VALID against the candidate on a critical claim blocks — the
    claim as stated is false and nothing has answered it, however much support
    sits beside it. One found against another state of the release holds until
    it is re-run on this one. One accepted as a documented risk, under a policy
    that permits exceptions, is reported and named and no longer blocks. A
    search that came back empty is reported and credited with nothing, because
    it bounds the search rather than the claim.
    """
    findings: List[Finding] = []
    if ledger is None or not len(ledger):
        return findings
    from release_gate.assurance.counterexample import CounterexampleStanding as Standing
    by_id = {a.counterexample_id: a for a in ledger.attempts}
    standing_of = {s.counterexample_id: s for s in standings}
    if not standing_of:   # called without standings: every open one is valid
        from release_gate.assurance.counterexample import assess_standing
        standing_of = {a.counterexample_id: assess_standing(a) for a in ledger.attempts}

    def of(kind: Any) -> List[Any]:
        return [by_id[i] for i, s in standing_of.items() if s.standing is kind]

    live = of(Standing.VALID)
    against_critical = [a for a in live if a.target_claim in critical]
    effect = (RequirementEffect.HOLD
              if policy is not None and policy.counterexample_effect.value == "HOLD"
              else RequirementEffect.BLOCK)
    if against_critical:
        findings.append(Finding(
            rule_id="RG-CEX-001", domain=AnalysisDomain.COUNTEREXAMPLE,
            effect=effect,
            summary=f"{len(against_critical)} unresolved counterexample(s) stand "
                    "against a critical claim",
            detail="; ".join(
                f"{a.counterexample_id}: {a.method.value} by "
                f"{a.producer or 'an unnamed producer'} broke {a.target_claim}"
                + (f" — {standing_of[a.counterexample_id].reason}"
                   if a.status.value == "ACCEPTED_RISK" else "")
                for a in against_critical[:4])[:700]
                   + ". The claim as stated is false unless something answers this; "
                     "no amount of support beside it changes that.",
            remedy="answer the counterexample and record what answers it, restate the "
                   "claim so it survives, or withdraw the claim",
            refs=tuple(a.counterexample_id for a in against_critical[:12]),
            observed={"open_against_critical": len(against_critical),
                      "critical_claims": sorted({a.target_claim
                                                 for a in against_critical})[:12],
                      "policy_effect": effect.value}))

    other = [a for a in live if a.target_claim not in critical]
    if other:
        findings.append(Finding(
            rule_id="RG-CEX-002", domain=AnalysisDomain.COUNTEREXAMPLE,
            effect=RequirementEffect.HOLD,
            summary=f"{len(other)} unresolved counterexample(s) stand against "
                    "non-critical claims",
            detail="; ".join(f"{a.counterexample_id} broke {a.target_claim}"
                             for a in other[:6])[:500],
            remedy="answer or withdraw these, or record why they do not bear on the "
                   "decision",
            refs=tuple(a.counterexample_id for a in other[:12]),
            observed={"open": len(other)}))

    stale = of(Standing.STALE)
    if stale:
        findings.append(Finding(
            rule_id="RG-CEX-004", domain=AnalysisDomain.COUNTEREXAMPLE,
            effect=RequirementEffect.HOLD,
            summary=(f"{len(stale)} counterexample(s) were found against another state "
                     "of the release and have not been re-run on this one"),
            detail="; ".join(f"{a.counterexample_id} on {a.target_claim}: "
                             f"{standing_of[a.counterexample_id].reason}"
                             for a in stale[:4])[:700]
                   + ". The candidate moved, so this no longer shows the claim false "
                     "for it; nothing shows the defect gone either.",
            remedy="re-run the counterexample against the candidate and record what "
                   "came back",
            refs=tuple(a.counterexample_id for a in stale[:12]),
            observed={"stale": len(stale),
                      "claims": sorted({a.target_claim for a in stale})[:12]}))

    accepted = of(Standing.ACCEPTED)
    if accepted:
        findings.append(Finding(
            rule_id="RG-CEX-005", domain=AnalysisDomain.COUNTEREXAMPLE,
            effect=RequirementEffect.ADVISORY,
            summary=(f"{len(accepted)} counterexample(s) stand and were accepted as "
                     "documented risk under a policy that permits exceptions"),
            detail="; ".join(f"{a.counterexample_id} on {a.target_claim}: "
                             f"{standing_of[a.counterexample_id].reason}"
                             for a in accepted[:4])[:700]
                   + ". Each claim is still false as stated; the exception is a "
                     "decision about this admission, on the record.",
            remedy="none required for this admission; the exception lapses when the "
                   "candidate moves past the state it was made for",
            refs=tuple(a.counterexample_id for a in accepted[:12]),
            observed={"accepted": len(accepted),
                      "accepted_by": sorted({a.accepted_by for a in accepted})[:12],
                      "references": sorted({a.reference for a in accepted})[:12]}))

    empty = ledger.searched_without_finding()
    if empty:
        findings.append(Finding(
            rule_id="RG-CEX-003", domain=AnalysisDomain.COUNTEREXAMPLE,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(empty)} counterexample search(es) came back empty",
            detail="; ".join(f"{a.method.value} on {a.target_claim} over "
                             f"{a.search_bound}" for a in empty[:4])[:600]
                   + ". Recorded as evidence about the search, not about the claim: "
                     "an empty search bounds what was looked at and nothing more, "
                     "however many of them there are.",
            remedy="none required; state the search space if a reviewer needs to know "
                   "what was actually covered",
            refs=tuple(a.counterexample_id for a in empty[:12]),
            observed={"searched_without_finding": len(empty),
                      "unbounded": sum(1 for a in empty if not a.searched.strip()),
                      "absence_proven": False}))
    return findings


# ── failed branches (RG-BRANCH-*) ────────────────────────────────────────────

def _analyse_failed_branches(ledger: Optional[FailedBranchLedger]) -> List[Finding]:
    """What was tried and did not work. Reported, and never treated as waste.

    Nothing here blocks. A run with failures is a run where somebody looked, and
    penalising that would teach producers to stop recording them — which is the
    outcome this whole area is designed against.
    """
    findings: List[Finding] = []
    if ledger is None or not ledger.observed:
        return findings

    recurring = ledger.recurring()
    if recurring:
        findings.append(Finding(
            rule_id="RG-BRANCH-001", domain=AnalysisDomain.FAILED_BRANCH,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(recurring)} failure point(s) stopped more than one attempt",
            detail="; ".join(
                f"{point.count:,} attempt(s) failed at {point.key}"
                + (f", deepest reaching {point.deepest}" if point.deepest is not None
                   else "")
                for point in recurring[:5])[:700]
                   + ". Where many attempts die in the same place, that place is "
                     "usually the real obstacle.",
            remedy="none required; the recurring point is where a reviewer's attention "
                   "is likely to be worth most",
            refs=tuple(point.key for point in recurring[:12]),
            observed={"recurring": len(recurring),
                      "points": [{"key": p.key, "count": p.count}
                                 for p in recurring[:8]]}))

    if ledger.dropped:
        findings.append(Finding(
            rule_id="RG-BRANCH-002", domain=AnalysisDomain.FAILED_BRANCH,
            effect=RequirementEffect.ADVISORY,
            summary=f"{ledger.dropped:,} failed branch(es) were counted but not retained",
            detail=(f"Retention basis is {ledger.basis.value}. Failure points and their "
                    "counts are exact; what was dropped is examples, not the aggregate. "
                    "A branch that is not retained cannot be reopened from this case."),
            remedy="raise the retention cap, or reference the branches externally so "
                   "they stay reachable",
            observed={"observed": ledger.observed, "retained": ledger.retained,
                      "dropped": ledger.dropped, "basis": ledger.basis.value}))

    unreachable = ledger.unreachable()
    if unreachable:
        findings.append(Finding(
            rule_id="RG-BRANCH-003", domain=AnalysisDomain.FAILED_BRANCH,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(unreachable)} retained branch(es) carry no reference back "
                    "to the attempt itself",
            detail="These are recorded as structure — outcome, locus, depth — with "
                   "nothing that would let a reviewer open the original. That is a "
                   "deliberate trade against retaining transcripts, and it is stated "
                   "rather than hidden.",
            remedy="record a content reference or an evidence id alongside each branch",
            refs=tuple(b.branch_id for b in unreachable[:12]),
            observed={"unreachable": len(unreachable)}))
    return findings


# ── contradiction (RG-CONTRA-*) ──────────────────────────────────────────────

def _analyse_contradiction(claim_graph: Optional[ClaimGraph],
                           records: Sequence[EvidenceRecord],
                           ledger: Optional[ContradictionLedger] = None,
                           policy: Optional[Any] = None,
                           excused: Optional[Set[str]] = None) -> List[Finding]:
    from release_gate.assurance.contradiction import MISMATCHES, ConflictClass
    findings: List[Finding] = []
    ledger = ledger if ledger is not None else ContradictionLedger()

    # RG-CONTRA-001 used to scan here for a record that both supports and
    # contradicts one claim. It could never fire: `EvidenceRecord` refuses that
    # construction outright, so no such record reaches analysis. The real case —
    # a producer declaring both in an envelope — is now handled at the ingest
    # boundary, which splits the record into its two halves so the disagreement
    # survives as a contradiction instead of the record being dropped. A rule that
    # cannot fire is worse than no rule, because it implies a check is happening.

    # The ones the verdict is structurally forbidden from omitting, split by what
    # they are. Every one of them holds; only a genuine contradiction can be made
    # to block, and only by the declared resolution policy.
    unresolved = ledger.unresolved_critical()
    critical = [c for c in unresolved if c.classification is ConflictClass.GENUINE]
    mismatched = [c for c in unresolved if c.classification in MISMATCHES]
    ambiguous = [c for c in unresolved if c.classification is ConflictClass.AMBIGUOUS]
    effect = (RequirementEffect.BLOCK
              if policy is not None and policy.critical_contradiction.value == "BLOCK"
              else RequirementEffect.HOLD)
    if critical:
        findings.append(Finding(
            rule_id="RG-CONTRA-005", domain=AnalysisDomain.CONTRADICTION,
            effect=effect,
            summary=f"{len(critical)} unresolved contradiction(s) affect a critical claim",
            detail="; ".join(
                f"{c.contradiction_id} on {', '.join(c.target_claims)} "
                f"({c.critical_basis}); "
                + " vs ".join(f"{s.label}: {len(s.evidence)} record(s) across "
                              f"{s.independent_roots} lineage(s)" for s in c.sides)
                for c in critical[:4])[:700],
            remedy="resolve the disagreement and record what resolved it, or record why "
                   "it does not bear on the decision",
            refs=tuple(c.contradiction_id for c in critical[:12]),
            observed={"unresolved_critical": len(critical),
                      "critical_claims": sorted({c for x in critical
                                                 for c in x.target_claims})[:12],
                      "contradiction_ids": [c.contradiction_id for c in critical[:12]],
                      "cross_source": sum(1 for c in critical if c.cross_source),
                      "policy_effect": effect.value}))

    if mismatched:
        by_class = sorted({c.classification.value for c in mismatched})
        findings.append(Finding(
            rule_id="RG-CONTRA-006", domain=AnalysisDomain.CONTRADICTION,
            effect=RequirementEffect.HOLD,
            summary=(f"{len(mismatched)} unresolved disagreement(s) on a critical claim "
                     f"are not contradictions ({', '.join(by_class).lower()})"),
            detail="; ".join(
                f"{c.contradiction_id} on {', '.join(c.target_claims)}: "
                f"{c.classification.value} — {c.classification_basis}"
                for c in mismatched[:4])[:700]
                   + ". The sides are about different things, so both can be true; the "
                     "failing side still stands against the claim on its own terms, "
                     "and nothing here has assessed what the other side did not.",
            remedy=("re-produce the evidence against the candidate (STALE); assess the "
                    "claim on the scope, data or environment the passing side did not "
                    "cover; or narrow the claim and say so"),
            refs=tuple(c.contradiction_id for c in mismatched[:12]),
            observed={"disagreements": len(mismatched),
                      "by_classification": {k: sum(1 for c in mismatched
                                                   if c.classification.value == k)
                                            for k in by_class},
                      "critical_claims": sorted({c for x in mismatched
                                                 for c in x.target_claims})[:12]}))

    if ambiguous:
        findings.append(Finding(
            rule_id="RG-CONTRA-007", domain=AnalysisDomain.CONTRADICTION,
            effect=RequirementEffect.HOLD,
            summary=(f"{len(ambiguous)} unresolved disagreement(s) on a critical claim "
                     "cannot be classified: whether the sides are comparable is unknown"),
            detail="; ".join(f"{c.contradiction_id} on {', '.join(c.target_claims)}: "
                             f"{c.classification_basis}" for c in ambiguous[:4])[:700]
                   + ". Unresolved ambiguity is not settled in either direction.",
            remedy=("state on both sides the element each covers in a shared dimension "
                    "(the same tool, path, environment), so they can be compared"),
            refs=tuple(c.contradiction_id for c in ambiguous[:12]),
            observed={"disagreements": len(ambiguous)}))

    if claim_graph is None:
        return findings

    refuted: List[str] = []
    disputed: List[str] = []
    excused = excused or set()
    for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
        status = claim_graph.status(claim.claim_id)
        # Refuted only by counterexample evidence found against another state:
        # RG-CEX-004 holds on that, as what it is, and the candidate having moved
        # is exactly what keeps it from blocking (counterexample.assess_standing).
        against = claim_graph.unresolved_against(claim.claim_id)
        if excused and against and set(against) <= excused and not any(
                a.status.value == "FAILED" for a in claim.verification_attempts):
            continue
        if status is ClaimStatus.REFUTED:
            refuted.append(claim.claim_id)
        elif status is ClaimStatus.DISPUTED:
            disputed.append(claim.claim_id)

    if refuted:
        findings.append(Finding(
            rule_id="RG-CONTRA-002", domain=AnalysisDomain.CONTRADICTION,
            effect=RequirementEffect.BLOCK,
            summary=f"{len(refuted)} claim(s) are refuted by the evidence in this case",
            detail="The case contains evidence against these claims that nothing "
                   "resolves. A case whose own evidence refutes it cannot be argued "
                   "forward without addressing that first.",
            remedy="withdraw the claim, or supply evidence that resolves the refutation",
            refs=tuple(refuted[:12]), observed={"claims_refuted": len(refuted)}))

    if disputed:
        findings.append(Finding(
            rule_id="RG-CONTRA-003", domain=AnalysisDomain.CONTRADICTION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(disputed)} claim(s) carry unresolved contradicting evidence",
            detail="Evidence points both ways and nothing in the case says which "
                   "prevails.",
            remedy="resolve the contradiction explicitly, or record it as an open "
                   "question a human must settle",
            refs=tuple(disputed[:12]), observed={"claims_disputed": len(disputed)}))

    anomalies = list(getattr(claim_graph, "anomalies", ()) or ())
    if anomalies:
        findings.append(Finding(
            rule_id="RG-CONTRA-004", domain=AnalysisDomain.CONTRADICTION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(anomalies)} structural anomal(y/ies) in the claim graph",
            detail="; ".join(sorted(f"{a.kind}: {a.detail}" for a in anomalies))[:600],
            remedy="repair the claim relationships named above",
            refs=_sorted_ids(cid for a in anomalies for cid in a.claims),
            observed={"anomalies": len(anomalies)}))
    return findings


# ── drift (RG-DRIFT-*) ───────────────────────────────────────────────────────

def _analyse_drift(case: AssuranceCase, artifact_graph: Optional[ArtifactGraph],
                   records: Sequence[EvidenceRecord]) -> List[Finding]:
    findings: List[Finding] = []

    check = case.check_subject()
    if check.status is MutationStatus.MUTATED:
        findings.append(Finding(
            rule_id="RG-DRIFT-001", domain=AnalysisDomain.DRIFT,
            effect=RequirementEffect.BLOCK,
            summary="the subject has changed since this case was opened",
            detail=f"{check.detail} An argument about one state of the subject says "
                   "nothing about another (Invariant 5).",
            remedy="re-open the case against the current subject",
            observed={"status": check.status.value}))
    elif check.status is MutationStatus.UNVERIFIABLE:
        findings.append(Finding(
            rule_id="RG-DRIFT-002", domain=AnalysisDomain.DRIFT,
            effect=RequirementEffect.HOLD,
            summary="the subject cannot be re-checked for mutation",
            detail=f"{check.detail} Whether the subject still matches what was "
                   "assessed is unknown, and unknown is not the same as unchanged.",
            remedy="give the subject a resolvable content reference so mutation can "
                   "be detected",
            observed={"status": check.status.value}))

    if artifact_graph is not None:
        stale: List[str] = []
        unverifiable: List[str] = []
        for logical_id in sorted(artifact_graph.logical_ids()):
            currency = artifact_graph.verification_currency(logical_id)
            if currency.status is CurrencyStatus.VERIFIED_STALE:
                stale.append(logical_id)
            elif currency.status is CurrencyStatus.UNVERIFIABLE:
                unverifiable.append(logical_id)
        if stale:
            findings.append(Finding(
                rule_id="RG-DRIFT-003", domain=AnalysisDomain.DRIFT,
                effect=RequirementEffect.BLOCK,
                summary=f"{len(stale)} artifact(s) were verified at an earlier revision "
                        "than the current one",
                detail="A verification binds to the exact content it ran against. These "
                       "artifacts have moved on, so the verification no longer applies "
                       "to what a decision would act on.",
                remedy="re-run the verification against the current artifact",
                refs=tuple(stale[:12]), observed={"stale": len(stale)}))
        if unverifiable:
            findings.append(Finding(
                rule_id="RG-DRIFT-004", domain=AnalysisDomain.DRIFT,
                effect=RequirementEffect.ADVISORY,
                summary=f"{len(unverifiable)} artifact(s) have no digest, so staleness "
                        "cannot be determined",
                detail="Without a content digest there is no way to tell whether a "
                       "verification still applies. The answer is not 'current'.",
                remedy="record a digest for these artifacts",
                refs=tuple(unverifiable[:12]),
                observed={"unverifiable": len(unverifiable)}))

    known_digests = {a.digest for a in (artifact_graph.artifacts if artifact_graph else ())
                     if a.digest}
    dangling = sorted({r.applies_to_digest for r in records
                       if r.applies_to_digest and r.applies_to_digest not in known_digests})
    if dangling:
        findings.append(Finding(
            rule_id="RG-DRIFT-005", domain=AnalysisDomain.DRIFT,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(dangling)} evidence record(s) apply to content not present "
                    "in this case",
            detail="The evidence names a digest no artifact in the case carries, so "
                   "what it applies to cannot be checked from here.",
            remedy="include the artifact the evidence was produced against",
            refs=tuple(dangling[:12]), observed={"digests": len(dangling)}))
    return findings


def _analyse_state_binding(report: Optional[Any]) -> List[Finding]:
    """RG-DRIFT-006 to -009: evidence about a state that is not the candidate's.

    The claim graph has already withheld the support (claims.py); these findings
    are what makes the withholding visible and what would resolve it. They share
    the drift family because drift is what this is — RG-DRIFT-005 reports a record
    naming content the case does not hold; these report what that does to claims.
    """
    if report is None:
        return []
    from release_gate.assurance.candidate import StateMatch
    findings: List[Finding] = []

    def reasons(bindings: Sequence[Any]) -> str:
        shown = "; ".join(f"{b.record_id}: {b.reason}" for b in bindings[:4])
        more = f" (+{len(bindings) - 4} more)" if len(bindings) > 4 else ""
        return shown + more

    stale = report.of(StateMatch.STALE)
    if stale:
        withheld = sum(1 for b in stale if b.withholds_support)
        findings.append(Finding(
            rule_id="RG-DRIFT-006", domain=AnalysisDomain.DRIFT,
            effect=RequirementEffect.HOLD,
            summary=(f"{len(stale)} record(s) bearing on claims are bound to a different "
                     f"state of the candidate; support from {withheld} was withheld"),
            detail=("Evidence about a previous revision is evidence about the previous "
                    "revision. Its support no longer counts toward the claim it names; "
                    "a refutation among these still stands, because a defect is not "
                    "answered by the state having moved. " + reasons(stale)),
            remedy="re-produce the evidence against the candidate, or state why the "
                   "earlier state is the one that matters",
            refs=tuple(b.record_id for b in stale[:12]),
            observed={"stale": len(stale), "support_withheld": withheld,
                      "candidate_digest": report.candidate.digest()}))
    incompatible = report.of(StateMatch.INCOMPATIBLE)
    if incompatible:
        withheld = sum(1 for b in incompatible if b.withholds_support)
        findings.append(Finding(
            rule_id="RG-DRIFT-007", domain=AnalysisDomain.DRIFT,
            effect=RequirementEffect.HOLD,
            summary=(f"{len(incompatible)} record(s) bearing on claims are about a "
                     f"different subject; support from {withheld} was withheld"),
            detail=("They name another repository or environment than the candidate. "
                    "That is not an older version of this release; it is evidence "
                    "about something else. " + reasons(incompatible)),
            remedy="supply evidence produced against the candidate's own repository "
                   "and environment",
            refs=tuple(b.record_id for b in incompatible[:12]),
            observed={"incompatible": len(incompatible), "support_withheld": withheld}))
    if report.candidate.explicit:
        unbound = [b for b in report.of(StateMatch.UNKNOWN) if b.supports]
        if unbound:
            findings.append(Finding(
                rule_id="RG-DRIFT-008", domain=AnalysisDomain.DRIFT,
                effect=RequirementEffect.HOLD,
                summary=(f"{len(unbound)} supporting record(s) name no component of the "
                         "candidate, so whether they are about it cannot be checked"),
                detail=("A candidate was stated, and this support does not say what it "
                        "was produced against. It still counts — nothing shows it is "
                        "about another state — but an admission made against an exact "
                        "candidate should not rest on evidence that could be about any. "
                        + reasons(unbound)),
                remedy="have the producer record the commit, model, prompt or artifact "
                       "digest it ran against (`state` on each record)",
                refs=tuple(b.record_id for b in unbound[:12]),
                observed={"unbound_support": len(unbound)}))
        unchecked = report.unchecked_components()
        if unchecked:
            findings.append(Finding(
                rule_id="RG-DRIFT-009", domain=AnalysisDomain.DRIFT,
                effect=RequirementEffect.ADVISORY,
                summary=(f"the candidate does not state {len(unchecked)} component(s) "
                         f"its evidence is bound to: {', '.join(unchecked)}"),
                detail=("Evidence names these, and the candidate is silent on them, so "
                        "those bindings were not checked. An incomplete candidate "
                        "identity is not a mismatch; it is a comparison nobody could "
                        "make."),
                remedy="add these components to the candidate state",
                refs=tuple(unchecked[:12]),
                observed={"unchecked_components": list(unchecked),
                          "missing_named_components": list(report.candidate.missing())}))
    return findings


def _analyse_semantic(report: Optional[Any]) -> List[Finding]:
    """RG-SEM-001..004: what the semantic verifier's assertions leave open.

    The verifier answers questions; these rules, under the declared resolution
    policy, decide what an answer does. A "contradicted" holds the case by
    default (the policy may make it block): a model's reading raises the
    question, and a person or a check settles it. A "supported" raises nothing.
    An unanswered question is advisory and moves nothing — it is reported so its
    absence is not read as an answer.
    """
    if report is None or not report.resolutions:
        return []
    by_role: Dict[str, List[Tuple[str, Any]]] = {}
    for resolution in report.resolutions:
        for item in resolution.items:
            if item.item_kind == "semantic":
                by_role.setdefault(item.role.value, []).append((resolution.claim_id, item))

    def listed(pairs: List[Tuple[str, Any]]) -> str:
        return "; ".join(f"{cid}: {item.reason}" for cid, item in pairs[:4]) + (
            f" (+{len(pairs) - 4} more)" if len(pairs) > 4 else "")

    findings: List[Finding] = []
    challenged = by_role.get("SEMANTIC_CHALLENGE", [])
    if challenged:
        effect = (RequirementEffect.BLOCK
                  if report.policy.semantic_contradiction.value == "BLOCK"
                  else RequirementEffect.HOLD)
        findings.append(Finding(
            rule_id="RG-SEM-001", domain=AnalysisDomain.VERIFICATION, effect=effect,
            summary=(f"a semantic verifier read the evidence as contradicting "
                     f"{len({c for c, _ in challenged})} claim(s)"),
            detail=("A model read the records that bear on these claims and found "
                    "them contradicting what is claimed. That is a reading, not a "
                    "refutation: it is held for a person, or a check, to settle "
                    f"({report.policy.ref} sets this to {effect.value}). "
                    + listed(challenged)),
            remedy="review the cited records; record a check or a resolution that "
                   "settles the claim either way",
            refs=tuple(dict.fromkeys(c for c, _ in challenged))[:12],
            observed={"claims": len({c for c, _ in challenged}),
                      "policy": report.policy.ref}))
    # A model's uncertainty moves a required claim only when the resolution
    # policy says so (`semantic_uncertainty`); low confidence never blocks
    # because a model said it, only because a declared policy does.
    uncertain = report.policy.semantic_uncertainty

    def required(pairs: List[Tuple[str, Any]]) -> bool:
        return any(getattr(report.of(c), "required", None) is not False for c, _ in pairs)

    unknown = by_role.get("SEMANTIC_UNKNOWN", [])
    if unknown:
        reasons: Dict[str, int] = {}
        for _, item in unknown:
            key = item.reason.split(":", 1)[0]
            reasons[key] = reasons.get(key, 0) + 1
        findings.append(Finding(
            rule_id="RG-SEM-002", domain=AnalysisDomain.VERIFICATION,
            effect=(RequirementEffect(uncertain.value)
                    if uncertain is not None and required(unknown)
                    else RequirementEffect.ADVISORY),
            summary=(f"{len(unknown)} semantic question(s) got no usable answer"),
            detail=("Unknown is not a pass: these questions were asked and not "
                    "answered, so each claim stands where the deterministic rules "
                    "left it. Reasons: "
                    + ", ".join(f"{k} ({v})" for k, v in sorted(reasons.items()))
                    + ". " + listed(unknown)),
            remedy="ask again, ask another provider, or settle the claim with a "
                   "check",
            refs=tuple(dict.fromkeys(c for c, _ in unknown))[:12],
            observed={"questions": len(unknown), "reasons": reasons}))
    needs = by_role.get("SEMANTIC_NEEDS_VERIFICATION", [])
    if needs:
        findings.append(Finding(
            rule_id="RG-SEM-003", domain=AnalysisDomain.VERIFICATION,
            effect=(RequirementEffect.BLOCK
                    if uncertain is not None and uncertain.value == "BLOCK"
                    and required(needs)
                    else RequirementEffect.HOLD),
            summary=(f"{len(needs)} semantic reading(s) were not confident enough, and "
                     "the verifier policy asks for more verification"),
            detail=("A model answered below the policy's confidence threshold, and "
                    "the policy says such an answer requires further verification "
                    "rather than being set aside. " + listed(needs)),
            remedy="supply a check of the claim — a test, a proof, a human review",
            refs=tuple(dict.fromkeys(c for c, _ in needs))[:12],
            observed={"readings": len(needs)}))
    stale = [(c, i) for c, i in by_role.get("WITHHELD_STATE", [])]
    if stale:
        findings.append(Finding(
            rule_id="RG-SEM-004", domain=AnalysisDomain.VERIFICATION,
            effect=RequirementEffect.ADVISORY,
            summary=(f"{len(stale)} semantic reading(s) were made against another "
                     "state of the release and were set aside"),
            detail=("Each assertion records the candidate state its packet was "
                    "built from; these name a different one. " + listed(stale)),
            remedy="ask the question again against the release being admitted",
            refs=tuple(dict.fromkeys(c for c, _ in stale))[:12],
            observed={"readings": len(stale)}))
    return findings


def _analyse_injection(records: Sequence[Any]) -> List[Finding]:
    """RG-SEM-005: evidence a semantic verifier read carried text addressed to it.

    Code, logs or documents that tell their reader to ignore its rules, mark
    something safe or return a decision are reported where they are, by record
    and pattern, so a person can look. Advisory, deliberately: the content of
    the evidence never moves the admission decision, in either direction. A
    "supported" reading of such a packet was already refused (INJECTION_SUSPECTED,
    under RG-SEM-002), and the rules decide the claim as they would have.
    """
    from release_gate.assurance.semantic_verifier import assertions_from_records
    flagged = [(eid, a) for eid, a in assertions_from_records(records)
               if a.injection_markers]
    if not flagged:
        return []
    patterns: Dict[str, int] = {}
    for _, assertion in flagged:
        for marker in assertion.injection_markers:
            key = marker.split(" in ", 1)[0]
            patterns[key] = patterns.get(key, 0) + 1
    refused = sum(1 for _, a in flagged
                  if getattr(a.unknown_reason, "value", "") == "INJECTION_SUSPECTED")
    shown = "; ".join(f"{a.claim_id}: {', '.join(a.injection_markers[:3])}"
                      for _, a in flagged[:4]) + (
        f" (+{len(flagged) - 4} more)" if len(flagged) > 4 else "")
    return [Finding(
        rule_id="RG-SEM-005", domain=AnalysisDomain.VERIFICATION,
        effect=RequirementEffect.ADVISORY,
        summary=(f"{len(flagged)} semantic reading(s) were made of evidence that "
                 "carries text addressed to a verifier"),
        detail=("The evidence was sent as data and kept unchanged; text in it reads "
                "as an instruction to the model reading it. It was assessed as "
                "content, and a supported reading of it is not accepted "
                f"({refused} refused). The decision is the rules', as it would have "
                "been without it. " + shown),
        remedy="look at the cited records: an instruction to a reviewer inside code, "
               "a log or a document is worth knowing about whoever put it there",
        refs=tuple(dict.fromkeys(a.claim_id for _, a in flagged))[:12],
        observed={"readings": len(flagged), "patterns": patterns,
                  "support_refused": refused})]


def _analyse_readers(report: Optional[Any], records: Sequence[Any]) -> List[Finding]:
    """RG-SEM-006/007: whether readings of a critical claim corroborate, and where
    readings disagree.

    Each reading is its own evidence and stays its own: what a verifier answered
    and the probability or confidence it stated are listed beside the others',
    and nothing combines them. A disagreement is never averaged into an answer;
    it is a CONTRADICTION (independent verifiers, the same evidence, opposite
    answers) or REQUIRES_REVIEW (any other), and either way a person settles it.
    """
    if report is None or not report.resolutions:
        return []
    from release_gate.assurance.correlation import READER_INDEPENDENCE_POLICY
    from release_gate.assurance.semantic_panel import semantic_disagreements
    findings: List[Finding] = []
    corroboration = report.policy.semantic_corroboration
    unmet = [r for r in report.resolutions
             if r.corroboration is not None and not r.corroboration["met"]]
    if unmet and corroboration is not None:
        findings.append(Finding(
            rule_id="RG-SEM-006", domain=AnalysisDomain.VERIFICATION,
            effect=(RequirementEffect(corroboration.unmet.value)
                    if corroboration.unmet is not None else RequirementEffect.ADVISORY),
            summary=(f"{len(unmet)} critical claim(s) have a supported reading that "
                     "nothing corroborates"),
            detail=("The corroboration policy lets a model's \"supported\" count on a "
                    "critical claim only beside "
                    + " or ".join(r.described for r in corroboration.routes)
                    + ". These readings are recorded and count toward nothing. "
                    + "; ".join(
                        f"{r.claim_id}: {r.corroboration['supported_readings']} supported "
                        f"reading(s) from {r.corroboration['independent_reader_groups']} "
                        "independent verifier group(s)"
                        + (f", and readings answering "
                           f"{', '.join(r.corroboration['readings_disagreeing'])}"
                           if r.corroboration["readings_disagreeing"] else "")
                        for r in unmet[:4])
                    + (f" (+{len(unmet) - 4} more)" if len(unmet) > 4 else "")),
            remedy="supply a check or an observation of the claim, a person's approval of "
                   "it, or readings from verifiers whose stated provenance is independent",
            refs=tuple(r.claim_id for r in unmet)[:12],
            observed={"claims": [{"claim_id": r.claim_id, **dict(r.corroboration)}
                                 for r in unmet[:12]],
                      "policy": corroboration.to_dict()}))
    disagreements = semantic_disagreements(
        report, records, independence=(corroboration.independence if corroboration
                                       else READER_INDEPENDENCE_POLICY))
    if disagreements:
        contradictions = sum(1 for d in disagreements
                             if d.classification.value == "CONTRADICTION")

        def stated(row: Mapping[str, Any]) -> str:
            value = row.get("confidence")
            return (f"{row['verifier']}: {row['verdict']} at {value:g}"
                    if isinstance(value, (int, float))
                    else f"{row['verifier']}: {row['verdict']}, no stated confidence")

        findings.append(Finding(
            rule_id="RG-SEM-007", domain=AnalysisDomain.VERIFICATION,
            effect=(RequirementEffect.HOLD
                    if any(d.required is not False for d in disagreements)
                    else RequirementEffect.ADVISORY),
            summary=(f"semantic readings disagree on {len(disagreements)} claim(s): "
                     f"{contradictions} contradiction(s), "
                     f"{len(disagreements) - contradictions} requiring review"),
            detail=("Readings are never averaged or put to a vote: each answer stands as "
                    "its verifier gave it, and a person settles which holds. "
                    + "; ".join(f"{d.claim_id} {d.classification.value} ({d.basis}): "
                                + " / ".join(stated(r) for r in d.readings[:4])
                                for d in disagreements[:3])
                    + (f" (+{len(disagreements) - 3} more)"
                       if len(disagreements) > 3 else "")),
            remedy="read the cited records and settle each claim with a check or a "
                   "recorded resolution; the readings stay on the record beside each other",
            refs=tuple(d.claim_id for d in disagreements)[:12],
            observed={"disagreements": [d.to_dict() for d in disagreements[:12]],
                      "contradictions": contradictions,
                      "requires_review": len(disagreements) - contradictions}))
    return findings


def _analyse_authorship(assessment: Optional[Any], policy: Any) -> List[Finding]:
    """RG-INDEP-007/008: whether anyone but the author checked the work.

    Correlation, never a judgement of who or what wrote the code: a person who
    writes a change, its tests and its approval is reported exactly as one agent
    session doing the same is, and an agent's work checked by others is not
    reported at all. Advisory unless the policy requires independence from the
    author for required claims (`ResolutionPolicy.author_independence`); then a
    required claim checked only by its author takes the declared effect, and one
    whose independence cannot be established — including one whose author
    nobody stated — holds. Without that requirement, nothing fires on a case
    that states no authorship: an unknown author is reported, not flagged.
    """
    if assessment is None:
        return []
    from release_gate.assurance.authorship import AuthorIndependence as A
    required = getattr(policy, "author_independence", None)
    findings: List[Finding] = []

    low = assessment.of(A.LOW)
    if low:
        binding = [c for c in low if c.required]
        effect = (RequirementEffect(required.value) if required is not None and binding
                  else RequirementEffect.ADVISORY)
        findings.append(Finding(
            rule_id="RG-INDEP-007", domain=AnalysisDomain.INDEPENDENCE, effect=effect,
            summary=(f"verification independence low: {len(low)} claim(s) were checked "
                     "only by the author of what they are about"),
            detail=("; ".join(f"{c.claim_id}: {c.basis}" for c in low[:4])
                    + (f" (+{len(low) - 4} more)" if len(low) > 4 else "")
                    + ". This is a statement about correlation — the work was checked "
                      "by the source that did it — and not about whether code written "
                      "by an agent, a model or a person is safe."),
            remedy=("add a check from a source that shares none of the author's "
                    "provenance: a person who did not write it, a static analyser, a "
                    "model of another provider or family, a formal verifier"),
            refs=tuple(c.claim_id for c in low[:12]),
            observed={"claims": len(low), "required": len(binding),
                      "policy_requires_independence": required is not None,
                      "shared": sorted({k for c in low for v in c.verifiers
                                        for k in v.shared})[:12]}))

    undetermined = list(assessment.of(A.UNDETERMINED))
    if required is not None:
        undetermined += [c for c in assessment.of(A.AUTHOR_UNKNOWN) if c.required]
    if undetermined and (assessment.present or required is not None):
        binding = [c for c in undetermined if c.required]
        effect = (RequirementEffect.HOLD if required is not None and binding
                  else RequirementEffect.ADVISORY)
        findings.append(Finding(
            rule_id="RG-INDEP-008", domain=AnalysisDomain.INDEPENDENCE, effect=effect,
            summary=(f"{len(undetermined)} claim(s) cannot be shown to have been "
                     "checked by anyone but their author"),
            detail=("; ".join(f"{c.claim_id}: {c.basis}" for c in undetermined[:4])
                    + (f" (+{len(undetermined) - 4} more)" if len(undetermined) > 4
                       else "")
                    + ". A source that states nothing about what produced it, or an "
                      "author nobody named, is UNKNOWN — never counted as independent."),
            remedy=("state authorship (`authorship` records, from CI or declared) and "
                    "provenance on the checks: provider, model_family, session, agent, "
                    "person, toolchain"),
            refs=tuple(c.claim_id for c in undetermined[:12]),
            observed={"claims": len(undetermined), "required": len(binding),
                      "author_unknown": sum(1 for c in undetermined
                                            if c.status is A.AUTHOR_UNKNOWN),
                      "policy_requires_independence": required is not None}))
    return findings


def _analyse_resolution(report: Optional[Any]) -> List[Finding]:
    """RG-CRIT-006 and RG-INDEP-005/006: what the claim resolution says the case lacks.

    One HOLD, for required claims short of the policy's admission level. A
    contradicted required claim is not counted here: the refutation, failed check
    or counterexample that contradicts it already blocks through the rule that
    reads it, and a second reason for one disagreement would double-count it.
    The independence findings are advisory — what independence *does* to a claim
    is already in its status (ESTABLISHED needs independent groups under the
    policy), so reporting it again as a verdict would weigh it twice.
    """
    if report is None or not report.resolutions:
        return []
    findings: List[Finding] = []
    below = report.below_admission()
    if below:
        shown = "; ".join(f"{r.claim_id}: {r.status.value} ({r.rule}) — {r.basis}"
                          for r in below[:4])
        findings.append(Finding(
            rule_id="RG-CRIT-006", domain=AnalysisDomain.CRITICALITY,
            effect=RequirementEffect.HOLD,
            summary=(f"{len(below)} required claim(s) are below the admission level "
                     f"{report.policy.admission_level.value}"),
            detail=("The decision rests on these claims, and what the case holds for "
                    "them does not reach what the resolution policy "
                    f"({report.policy.ref}) asks of a required claim. Not assessed "
                    "and unknown are not passed. " + shown
                    + (f" (+{len(below) - 4} more)" if len(below) > 4 else "")),
            remedy="supply evidence bound to the candidate for each claim, or the "
                   "check its status says is missing",
            refs=tuple(r.claim_id for r in below[:12]),
            observed={"below_admission": len(below),
                      "statuses": {r.claim_id: r.status.value for r in below[:12]},
                      "policy": report.policy.ref}))

    # Only where independence is what held the claim back: several checks that
    # could establish it, and the policy could not count them apart. Correlated
    # declarations move nothing, so reporting them would be noise.
    held = [r for r in report.resolutions if r.held_by_independence]
    correlated = [r for r in held
                  if r.establishing_independence.status.value == "CORRELATED"]
    if correlated:
        findings.append(Finding(
            rule_id="RG-INDEP-005", domain=AnalysisDomain.INDEPENDENCE,
            effect=RequirementEffect.ADVISORY,
            summary=(f"{len(correlated)} claim(s) have several checks that are one "
                     "correlated source"),
            detail=("; ".join(f"{r.claim_id}: {r.establishing_independence.sources} "
                              f"check(s), {r.establishing_independence.independent_groups}"
                              f" group — {r.establishing_independence.basis}"
                              for r in correlated[:4])
                    + ". Five artifacts from one model session are one opinion, "
                    "however they are labelled."),
            remedy="add a check from a source that shares none of these: another "
                   "model family, a person, a formal verifier, a different dataset",
            refs=tuple(r.claim_id for r in correlated[:12]),
            observed={"claims": len(correlated)}))
    unknown = [r for r in held
               if r.establishing_independence.status.value == "INDEPENDENCE_UNKNOWN"]
    if unknown:
        findings.append(Finding(
            rule_id="RG-INDEP-006", domain=AnalysisDomain.INDEPENDENCE,
            effect=RequirementEffect.ADVISORY,
            summary=(f"{len(unknown)} claim(s) rest on checks whose independence "
                     "cannot be determined"),
            detail=("Some checks state nothing about what produced them — no model "
                    "family, reviewer, toolchain, session, agent or lineage — so they "
                    "were not counted as independent, and the claim stays short of "
                    "established. "
                    + "; ".join(f"{r.claim_id}: {r.establishing_independence.basis}"
                                for r in unknown[:4])),
            remedy="record `provenance` on the evidence: provider, model_family, "
                   "session, agent, reviewer, toolchain",
            refs=tuple(r.claim_id for r in unknown[:12]),
            observed={"claims": len(unknown)}))
    return findings


# ── coverage (RG-COV-*) ──────────────────────────────────────────────────────

def _analyse_claim_coverage(report: Optional[Any], policy: Optional[Any]) -> List[Finding]:
    """RG-COV-006 to -008: what portion of each required claim's surface was assessed.

    A required claim — or one whose criticality could not be determined, which is
    never read as unimportant — is held to the policy's share of every dimension
    of its declared surface. An assessed failure is already a refutation the
    claim's resolution blocks on, so it is named here and not counted again.
    """
    if report is None or policy is None or not report.claims:
        return []
    findings: List[Finding] = []
    share = policy.surface_coverage
    in_scope = [c for c in report.claims if c.required is not False]

    short = [c for c in in_scope if c.surface.stated and not c.meets(share)]
    if short:
        def gap(c: Any) -> str:
            if c.surface.problem:
                return f"{c.claim_id}: surface unreadable ({c.surface.problem})"
            missing = ", ".join(f"{e.dimension} {e.element} {e.status.value}"
                                for e in c.missing[:6])
            failed = ", ".join(f"{e.dimension} {e.element}" for e in c.failed[:4])
            return (f"{c.claim_id}: " + "; ".join(f"{d.dimension} {d.summary()}"
                                                  for d in c.dimensions)
                    + (f" — missing {missing}" if missing else "")
                    + (f" — failed {failed}" if failed else ""))
        effect = (RequirementEffect.BLOCK if policy.surface_shortfall.value == "BLOCK"
                  else RequirementEffect.HOLD)
        findings.append(Finding(
            rule_id="RG-COV-006", domain=AnalysisDomain.COVERAGE, effect=effect,
            summary=(f"{len(short)} required claim(s) have unassessed surface: less than "
                     f"{share:.0%} of a declared dimension was assessed"),
            detail=("; ".join(gap(c) for c in short[:4])
                    + (f" (+{len(short) - 4} more)" if len(short) > 4 else "")
                    + ". Not assessed is not passed: the elements nobody looked at are "
                      "the ones listed, and what was assessed elsewhere says nothing "
                      "about them."),
            remedy=("assess each missing element and say which element each record "
                    "covers (`covers`), or narrow the claim and declare what is out of "
                    "scope and why"),
            refs=tuple(c.claim_id for c in short[:12]),
            observed={"claims": len(short), "required_share": share,
                      "missing": {c.claim_id: [f"{e.dimension}:{e.element}"
                                               for e in c.missing[:12]]
                                  for c in short[:12]},
                      "failed": {c.claim_id: [f"{e.dimension}:{e.element}"
                                              for e in c.failed[:12]]
                                 for c in short[:12] if c.failed}}))

    if policy.require_surface:
        undeclared = [c for c in in_scope if not c.surface.stated]
        if undeclared:
            findings.append(Finding(
                rule_id="RG-COV-007", domain=AnalysisDomain.COVERAGE,
                effect=RequirementEffect.HOLD,
                summary=(f"{len(undeclared)} required claim(s) declare no surface, and the "
                         "resolution policy requires one"),
                detail=("Without a surface, what portion of the claim was assessed "
                        "cannot be measured, and it is not assumed: "
                        + ", ".join(c.claim_id for c in undeclared[:8])),
                remedy="declare each claim's surface: the tools, paths, environments, "
                       "datasets or obligations it is about",
                refs=tuple(c.claim_id for c in undeclared[:12]),
                observed={"claims": len(undeclared)}))

    counted = [c for c in report.claims
               if c.declared and c.unattributed.get("SUPPORTS")]
    if counted:
        findings.append(Finding(
            rule_id="RG-COV-008", domain=AnalysisDomain.COVERAGE,
            effect=RequirementEffect.ADVISORY,
            summary=(f"{sum(len(c.unattributed['SUPPORTS']) for c in counted)} supporting "
                     f"item(s) on {len(counted)} claim(s) with a declared surface do not "
                     "say which part of it they cover"),
            detail=("They count toward the claim's resolution and cover no element of "
                    "its surface: a passing check that does not name what it exercised "
                    "has not shown that any one element was. "
                    + "; ".join(f"{c.claim_id}: {len(c.unattributed['SUPPORTS'])}"
                                for c in counted[:6])),
            remedy="record which elements each check covers (`covers`)",
            refs=tuple(c.claim_id for c in counted[:12]),
            observed={"claims": len(counted)}))
    return findings


def _analyse_coverage(case: AssuranceCase, claim_graph: Optional[ClaimGraph],
                      execution: Optional[ExecutionGraph],
                      normalisation: Optional[Any]) -> List[Finding]:
    findings: List[Finding] = []

    if normalisation is not None:
        if not normalisation.detection.recognised:
            findings.append(Finding(
                rule_id="RG-COV-001", domain=AnalysisDomain.COVERAGE,
                effect=RequirementEffect.HOLD,
                summary="the input format was not recognised",
                detail=normalisation.detection.basis + " The file was hashed and "
                       "recorded, but its contents were not interpreted, so almost "
                       "nothing about them has been assessed.",
                remedy="pass a supported export (OTLP, Langfuse, Arize/Phoenix, "
                       "promptfoo, a release-gate audit report, or an assurance "
                       "envelope), or emit the assurance envelope directly",
                observed={"confidence": normalisation.detection.confidence}))
        if normalisation.skipped_total:
            findings.append(Finding(
                rule_id="RG-COV-002", domain=AnalysisDomain.COVERAGE,
                effect=RequirementEffect.HOLD,
                summary=f"{normalisation.skipped_total} record(s) in the input could "
                        "not be mapped",
                detail="; ".join(f"{reason} ({count})" for reason, count
                                 in sorted(normalisation.skipped.items()))[:600],
                remedy="correct the unmapped records, or accept that they are outside "
                       "what this case assessed",
                observed={"skipped": normalisation.skipped_total,
                          "seen": normalisation.records_seen,
                          "mapped": normalisation.records_mapped}))

    if claim_graph is not None:
        # Contradicting evidence counts as evidence. A claim something argues
        # against has been assessed and found wanting, which is a different fact
        # from one nothing in the case bears on either way — and reporting a
        # refuted claim as "rests on no evidence at all" tells a reviewer to go
        # looking for evidence that is already in front of them.
        unsupported = sorted(
            c.claim_id for c in claim_graph.claims
            if not c.supporting_evidence and not c.verification_attempts
            and not c.contradicting_evidence)
        if unsupported:
            # `load_bearing()` returns claim ids, not Claim objects. The defensive
            # getattr here was hiding that: the branch only runs when the graph has
            # both an unsupported claim and a load-bearing one, so the mistake sat
            # latent until an assumption chain produced both at once.
            load_bearing = set(claim_graph.load_bearing())
            critical = sorted(set(unsupported) & load_bearing) or unsupported
            findings.append(Finding(
                rule_id="RG-COV-003", domain=AnalysisDomain.COVERAGE,
                effect=RequirementEffect.HOLD,
                summary=f"{len(unsupported)} claim(s) rest on no evidence at all",
                detail="These claims are asserted and nothing in the case bears on "
                       "them either way. An unsupported claim is not a false one; it "
                       "is an unassessed one (Invariant 3).",
                remedy="supply evidence for these claims, or mark them as assumptions "
                       "so they are argued as assumptions",
                refs=tuple(critical[:12]),
                observed={"unsupported": len(unsupported),
                          "load_bearing": len(set(unsupported) & load_bearing)}))

    if execution is not None:
        completeness = execution.completeness
        if completeness.status is not CompletenessStatus.MATCHES_DECLARATION:
            gaps = len(completeness.unobserved_parents) + len(completeness.sequence_gaps)
            findings.append(Finding(
                rule_id="RG-COV-004", domain=AnalysisDomain.COVERAGE,
                effect=(RequirementEffect.HOLD if gaps else RequirementEffect.ADVISORY),
                summary=f"execution completeness is {completeness.status.value}",
                detail=("Nobody declared how much execution to expect, so whether this "
                        "trace is whole is unknown."
                        if completeness.status is CompletenessStatus.UNKNOWN else
                        f"{len(completeness.unobserved_parents)} referenced parent span(s) "
                        f"were never observed and {len(completeness.sequence_gaps)} "
                        "sequence gap(s) were detected."),
                remedy=("declare the expected extent of the run so a shortfall becomes "
                        "detectable" if completeness.status is CompletenessStatus.UNKNOWN
                        else "supply the missing spans"),
                observed={"status": completeness.status.value,
                          "spans_seen": completeness.spans_seen,
                          "unobserved_parents": len(completeness.unobserved_parents),
                          "sequence_gaps": len(completeness.sequence_gaps)}))

    absent = [k for k in case.absent_collections if k in ("evidence", "claims", "verification")]
    if absent:
        findings.append(Finding(
            rule_id="RG-COV-005", domain=AnalysisDomain.COVERAGE,
            effect=RequirementEffect.HOLD,
            summary=f"{len(absent)} core collection(s) were never supplied: "
                    + ", ".join(sorted(absent)),
            detail="Nobody supplied these, which is different from supplying them and "
                   "finding nothing. The distinction is preserved rather than collapsed.",
            remedy="supply the collection, or declare it present-and-empty so the case "
                   "records that someone looked",
            observed={"absent": sorted(absent)}))
    return findings


# ── capability (RG-CAP-*) ────────────────────────────────────────────────────

def _analyse_capabilities(surface: Optional[CapabilitySurface]) -> List[Finding]:
    """What the system reached for — surfaced, never judged.

    Nothing here BLOCKs. "The agent sent an email" is not structurally wrong;
    whether it was permitted is a domain question, and a methodology is where that
    belongs. Two findings HOLD, and both are about *not knowing*: a capability
    exercised outside what was declared, and a tool nobody could identify.
    """
    findings: List[Finding] = []
    if surface is None:
        return findings

    declared_anything = any(r.declared for r in surface.records)

    if declared_anything:
        # The sharp one. A manifest exists and the system went outside it.
        outside = [r for r in surface.undeclared
                   if r.capability.value != "UNKNOWN_TOOL"]
        if outside:
            findings.append(Finding(
                rule_id="RG-CAP-001", domain=AnalysisDomain.CAPABILITY,
                effect=RequirementEffect.HOLD,
                summary=f"{len(outside)} capabilit(y/ies) were exercised that the tool "
                        "manifest does not declare",
                detail="The system reached for something nobody said it could: "
                       + ", ".join(sorted(r.capability.value for r in outside))
                       + ". Whether that is acceptable is a domain question; that it "
                         "was unannounced is a structural one.",
                remedy="declare these capabilities, or establish why the system reached "
                       "for them",
                refs=_sorted_ids(r.capability.value for r in outside),
                observed={"undeclared": sorted(r.capability.value for r in outside)}))
    else:
        findings.append(Finding(
            rule_id="RG-CAP-003", domain=AnalysisDomain.CAPABILITY,
            effect=RequirementEffect.ADVISORY,
            summary="nothing declared what this system is permitted to do",
            detail="No tool manifest was present, so every capability below is "
                   "reported without a denominator. There is nothing to have exceeded, "
                   "which is not the same as having stayed within bounds.",
            remedy="supply a tool manifest so exercised capabilities can be compared "
                   "against declared ones",
            observed={"declared": 0, "exercised": len(surface.undeclared)}))

    if surface.unclassified_tools:
        findings.append(Finding(
            rule_id="RG-CAP-002", domain=AnalysisDomain.CAPABILITY,
            effect=RequirementEffect.HOLD,
            summary=f"{len(surface.unclassified_tools)} tool(s) were invoked that could "
                    "not be identified",
            detail="These tools ran and nothing here can say what they can do: "
                   + ", ".join(surface.unclassified_tools[:8])
                   + ". An unidentified tool is an unassessed part of the execution, "
                     "not an absent one.",
            remedy="name these tools in a manifest, or emit the protocol attributes "
                   "(db.system, url.full, process.command_line) that would classify them",
            refs=surface.unclassified_tools[:12],
            observed={"tools": list(surface.unclassified_tools[:12])}))

    if not surface.bounded:
        subsuming = sorted(r.capability.value for r in surface.subsuming)
        findings.append(Finding(
            rule_id="RG-CAP-004", domain=AnalysisDomain.CAPABILITY,
            effect=RequirementEffect.ADVISORY,
            summary="the capability list is not an upper bound on what the system did",
            detail=f"{', '.join(subsuming)} can reach any other capability without it "
                   "appearing separately — a shell can make a network call, an MCP "
                   "server exposes whatever its author wrote. Read the list as what was "
                   "seen, never as an inventory.",
            remedy="instrument inside the subsuming capability, or constrain it, if the "
                   "decision depends on knowing the full surface",
            refs=tuple(subsuming), observed={"subsuming": subsuming}))

    if not surface.can_observe and surface.records:
        findings.append(Finding(
            rule_id="RG-CAP-005", domain=AnalysisDomain.CAPABILITY,
            effect=RequirementEffect.ADVISORY,
            summary="every capability here was inferred from a name, not observed",
            detail=f"Classification ran against {surface.attribute_basis}, which carries "
                   "no protocol attributes. A tool called `db_write` is evidence of a "
                   "naming convention, not of a database write.",
            remedy="run capability discovery against the raw trace, where db.system, "
                   "url.full and process.command_line settle several of these outright",
            observed={"attribute_basis": surface.attribute_basis}))

    unexercised = surface.declared_only
    if unexercised:
        findings.append(Finding(
            rule_id="RG-CAP-006", domain=AnalysisDomain.CAPABILITY,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(unexercised)} declared capabilit(y/ies) were never exercised "
                    "in this evidence",
            detail="The system may do more than this run shows: "
                   + ", ".join(sorted(r.capability.value for r in unexercised))
                   + ". The blast radius of the system is wider than the trace.",
            remedy="none required; recorded so the decision is made against the "
                   "declared surface rather than one run's worth of it",
            refs=_sorted_ids(r.capability.value for r in unexercised),
            observed={"declared_unexercised": sorted(r.capability.value
                                                     for r in unexercised)}))

    external = surface.mutating_external
    if external:
        findings.append(Finding(
            rule_id="RG-CAP-007", domain=AnalysisDomain.CAPABILITY,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(external)} capabilit(y/ies) with effects outside the system "
                    "were exercised",
            detail=", ".join(f"{r.capability.value} ({r.status.value})"
                             for r in external)
                   + ". These change state that release-gate cannot see and cannot undo. "
                     "This is a statement of what happened, not a judgement about it.",
            remedy="none required; a methodology decides whether these need human "
                   "authorisation",
            refs=_sorted_ids(r.capability.value for r in external),
            observed={"capabilities": sorted(r.capability.value for r in external),
                      "statuses": sorted({r.status.value for r in external})}))
    return findings


# ── consequence (RG-CONS-*) ──────────────────────────────────────────────────

def _analyse_consequence(profile: Optional[ConsequenceProfile],
                         surface: Optional[CapabilitySurface]) -> List[Finding]:
    """What is at stake — reported, never invented.

    Nothing here decides that an irreversible change needs a second approver; a
    methodology does that through `ConsequenceDeclared`. These findings say only
    what was stated, what was not, and where two sources disagree.
    """
    findings: List[Finding] = []
    if profile is None:
        return findings

    if profile.fully_unknown:
        findings.append(Finding(
            rule_id="RG-CONS-001", domain=AnalysisDomain.CONSEQUENCE,
            effect=RequirementEffect.ADVISORY,
            summary="nothing is known about what this action would do",
            detail="Every consequence dimension is UNKNOWN. release-gate does not "
                   "guess at reversibility, cost or legality, so the authorization "
                   "boundary here rests on the reviewer's own knowledge of the stakes "
                   "rather than on anything in the case.",
            remedy="declare the consequence dimensions that bear on this decision, or "
                   "supply a domain model that derives them",
            observed={"known": 0, "dimensions": len(ConsequenceDimension)}))

    # A declaration the evidence disagrees with. Sharper than a plain conflict:
    # somebody stated the stakes and the trace shows otherwise.
    contradicted = [c for c in profile.conflicts
                    if c.rejected.basis is ConsequenceBasis.DERIVED
                    and c.kept.basis is ConsequenceBasis.DECLARED]
    if contradicted:
        findings.append(Finding(
            rule_id="RG-CONS-003", domain=AnalysisDomain.CONSEQUENCE,
            effect=RequirementEffect.HOLD,
            summary=f"{len(contradicted)} declared consequence value(s) are "
                    "contradicted by the evidence",
            detail="; ".join(
                f"{c.dimension.value} was declared {c.kept.value!r} by "
                f"{c.kept.source} but the evidence derives {c.rejected.value!r} "
                f"({c.rejected.note})" for c in contradicted)[:700],
            remedy="reconcile the declaration with the evidence, or record why the "
                   "declaration holds despite it",
            refs=tuple(c.dimension.value for c in contradicted),
            observed={"dimensions": [c.dimension.value for c in contradicted]}))

    peer = [c for c in profile.conflicts if c not in contradicted]
    if peer:
        findings.append(Finding(
            rule_id="RG-CONS-002", domain=AnalysisDomain.CONSEQUENCE,
            effect=RequirementEffect.HOLD,
            summary=f"{len(peer)} consequence dimension(s) have disagreeing sources",
            detail="; ".join(f"{c.dimension.value}: {c.kept.value!r} "
                             f"({c.kept.source}) vs {c.rejected.value!r} "
                             f"({c.rejected.source})" for c in peer)[:700],
            remedy="establish which source is authoritative for these dimensions",
            refs=tuple(c.dimension.value for c in peer),
            observed={"dimensions": [c.dimension.value for c in peer]}))

    elevated = profile.elevated()
    if elevated:
        findings.append(Finding(
            rule_id="RG-CONS-004", domain=AnalysisDomain.CONSEQUENCE,
            effect=RequirementEffect.ADVISORY,
            summary=f"{len(elevated)} consequence dimension(s) are at their most "
                    "consequential stated value",
            detail=", ".join(f"{d.dimension.value}={d.value} ({d.basis.value})"
                             for d in elevated)
                   + ". Reported so a reviewer sees the stakes; whether these require "
                     "more than one signature is a methodology's decision, not this "
                     "analyser's.",
            remedy="none required; a methodology decides what these stakes demand",
            refs=tuple(d.dimension.value for d in elevated),
            observed={"dimensions": [d.dimension.value for d in elevated]}))

    # The specific gap that matters most: the system did something that leaves the
    # boundary and changes state, and nobody said whether it can be undone.
    if surface is not None and profile.value(ConsequenceDimension.REVERSIBILITY) == "UNKNOWN":
        irreversible_risk = surface.mutating_external
        if irreversible_risk:
            findings.append(Finding(
                rule_id="RG-CONS-005", domain=AnalysisDomain.CONSEQUENCE,
                effect=RequirementEffect.HOLD,
                summary="reversibility is unstated for an action with effects outside "
                        "the system",
                detail=", ".join(sorted(r.capability.value for r in irreversible_risk))
                       + " changed state that release-gate cannot see and cannot undo, "
                         "and nothing says whether anyone else can. A person is being "
                         "asked to authorise without being told if it is recoverable.",
                remedy="declare REVERSIBILITY for this action",
                refs=tuple(sorted(r.capability.value for r in irreversible_risk)),
                observed={"capabilities": sorted(r.capability.value
                                                 for r in irreversible_risk)}))
    return findings


# ── the entry point ──────────────────────────────────────────────────────────

def analyse(case: AssuranceCase, *, normalisation: Optional[Any] = None,
            claim_graph: Optional[ClaimGraph] = None,
            artifact_graph: Optional[ArtifactGraph] = None,
            execution: Optional[ExecutionGraph] = None,
            capabilities: Optional[CapabilitySurface] = None,
            consequence: Optional[ConsequenceProfile] = None) -> AnalysisResult:
    """Run every config-free analyser over a case.

    Graphs are read from the case when not supplied. Order of findings is stable:
    domain, then rule id, then first ref — a diff of two runs should show what
    changed about the case, not what changed about iteration order.
    """
    records = _evidence_records(case)

    if claim_graph is None:
        try:
            claim_graph = ClaimGraph.from_case(case)
        except Exception:
            claim_graph = None
    if claim_graph is not None and not claim_graph.claims:
        claim_graph = None

    if artifact_graph is None:
        try:
            artifact_graph = ArtifactGraph.from_case(case)
        except Exception:
            artifact_graph = None
    if artifact_graph is not None and not artifact_graph.artifacts:
        artifact_graph = None

    if execution is None:
        try:
            execution = ExecutionGraph.from_case(case)
        except Exception:
            execution = None

    # Current digests per target, so applicability is a computation. Without them
    # every attempt is UNDETERMINED, which is honest but says nothing.
    digests: Dict[Tuple[str, str], str] = {}
    if artifact_graph is not None:
        for logical_id in artifact_graph.logical_ids():
            current = artifact_graph.current_version(logical_id)
            if current is not None and current.digest:
                digests[(TargetKind.ARTIFACT.value, logical_id)] = current.digest
    try:
        verification_graph = VerificationGraph.from_case(case, digests=digests)
    except Exception:
        verification_graph = None

    findings: List[Finding] = []
    from release_gate.assurance.resolution import policy_for_case, resolve_claims
    policy = policy_for_case(case)
    independence = analyse_independence(records)
    detected = detect_contradictions(
        claim_graph=claim_graph, evidence=records, verification_graph=verification_graph,
        bindings=claim_graph.state_binding if claim_graph is not None else None)
    assumption_graph = AssumptionGraph.from_claim_graph(claim_graph)

    # Which claims a refutation would actually matter to. One derived definition,
    # read by every guard below, rather than a set computed inline here: an
    # unresolved counterexample, an adversarial argument defect, divergent
    # replication and the contradiction a verdict may not omit all turn on this
    # answer, and three approximations of it would eventually disagree about the
    # same case. Criticality is reachability from what the decision is being asked
    # about — never volume, never depth-weighted (Invariant 12).
    coverage_ledger = _coverage_ledger(case, normalisation)

    criticality = analyse_criticality(
        claim_graph,
        evidence_producers={r.evidence_id: r.producer.producer_id for r in records})
    critical: Set[str] = set(criticality.critical_ids)

    # Declared attempts from the envelope, plus any lifted from counterexample
    # evidence already in the case. Both paths matter: only the envelope can say a
    # search came back empty, and only the lift picks up producers that never
    # thought to call their finding a counterexample.
    # Declared branches, plus every failed verification attempt already in the
    # case — a check that ran and did not pass is an attempt that did not work
    # out, so this costs a producer nothing.
    branch_recorder = FailedBranchRecorder()
    branch_recorder.extend(getattr(normalisation, "failed_branches", ()) or ())
    branch_recorder.extend(branches_from_verification(verification_graph))
    failed_branches = branch_recorder.build()

    # Replication reads the same attempts the verification graph holds, so the two
    # can never disagree about what ran; what it adds is which of them are copies.
    replication = analyse_replication(
        verification_graph.attempts if verification_graph is not None else (),
        records=records)

    # Who produced each claim's support, and what lineage that support rests on.
    # Both come from the case rather than from the adversaries, which is the only
    # way self-review and self-clearing are findable at all: an adversary will not
    # tell you it is the builder, and the builder will not tell you it closed its
    # own ticket.
    claim_producers: Dict[str, Set[str]] = {}
    claim_lineage: Dict[str, Set[str]] = {}
    by_evidence = {r.evidence_id: r for r in records}
    for claim in (claim_graph.claims if claim_graph is not None else ()):
        producers = claim_producers.setdefault(claim.claim_id, set())
        lineage = claim_lineage.setdefault(claim.claim_id, set())
        if claim.producer is not None:
            producers.add(claim.producer.producer_id)
        for evidence_id in claim.supporting_evidence:
            supporting = by_evidence.get(evidence_id)
            if supporting is not None:
                producers.add(supporting.producer.producer_id)
                lineage.add(supporting.producer.producer_id)
                lineage.update(supporting.parent_evidence)

    adversarial = analyse_adversarial(
        getattr(normalisation, "adversarial", ()) or (),
        claim_producers=claim_producers, claim_lineage=claim_lineage)

    declared_attempts = tuple(getattr(normalisation, "counterexamples", ()) or ())
    # Adversarial refutations join the counterexample ledger rather than getting a
    # second enforcement path: `render_verdict` already refuses to omit an
    # unresolved critical one, and one guard kept correct beats two that drift.
    counterexamples = CounterexampleLedger(
        declared_attempts + counterexamples_from_evidence(records)
        + adversarial.to_counterexamples())
    # Where each one stands against the release being admitted, under the policy:
    # what answered it, the state it was found against, a permitted exception.
    from release_gate.assurance.counterexample import CounterexampleStanding, assess_standing
    binding_report = claim_graph.state_binding if claim_graph is not None else None
    standings = tuple(assess_standing(
        a, candidate=binding_report.candidate if binding_report is not None else None,
        permit_exceptions=policy.counterexample_exceptions)
        for a in counterexamples.attempts)
    stale_cex = [s for s in standings if s.standing is CounterexampleStanding.STALE]
    # A live refutation becomes a contradiction so `render_verdict` cannot omit it.
    # Claims that already produced a claim/evidence conflict are skipped, or the
    # same disagreement would be filed twice under two ids.
    already = {c for contradiction in detected
               if contradiction.kind is ContradictionKind.CLAIM_EVIDENCE_CONFLICT
               for c in contradiction.target_claims}
    lifted = tuple(c for c in counterexamples.to_contradictions(
        critical_claims=critical, stale=[s.counterexample_id for s in stale_cex])
                   if not set(c.target_claims) & already)
    # Paths that disagree become a disagreement the verdict cannot omit. Filed
    # under VERIFICATION_CONFLICT like any other check that contradicts another,
    # and skipped where the contradiction detector already filed the same clash
    # from the attempts themselves, so one disagreement gets one id.
    seen_conflicts = {c for contradiction in tuple(detected.contradictions) + lifted
                      if contradiction.kind is ContradictionKind.VERIFICATION_CONFLICT
                      for c in contradiction.target_claims}
    diverged = tuple(c for c in replication.to_contradictions(critical_claims=critical)
                     if not set(c.target_claims) & seen_conflicts)
    ledger = ContradictionLedger(tuple(detected.contradictions) + lifted + diverged)

    findings: List[Finding] = []
    findings.extend(_analyse_provenance(case, records))
    findings.extend(_analyse_solicited(records))
    findings.extend(_analyse_independence(independence))
    findings.extend(_analyse_replication(replication, critical))
    findings.extend(_analyse_criticality(criticality))
    findings.extend(_analyse_expectation(coverage_ledger))
    findings.extend(_analyse_adversarial(adversarial, critical))
    findings.extend(_analyse_verification(case, records, claim_graph))
    findings.extend(_analyse_verification_graph(verification_graph))
    findings.extend(_analyse_contradiction(
        claim_graph, records, ledger, policy,
        excused={e for s in stale_cex for e in s.evidence}))
    findings.extend(_analyse_assumptions(assumption_graph))
    findings.extend(_analyse_counterexamples(counterexamples, critical, standings, policy))
    findings.extend(_analyse_failed_branches(failed_branches))
    findings.extend(_analyse_drift(case, artifact_graph, records))
    state_binding = claim_graph.state_binding if claim_graph is not None else None
    findings.extend(_analyse_state_binding(state_binding))

    resolved_records = [r for kind in ("evidence", "verification",
                                       "contradictions", "counterexamples")
                        for r in case.records(kind) if isinstance(r, EvidenceRecord)]
    resolution = resolve_claims(
        claim_graph, records=resolved_records,
        counterexamples=counterexamples, criticality=criticality,
        policy=policy)
    findings.extend(_analyse_resolution(resolution))
    from release_gate.assurance.claim_coverage import assess_claim_coverage
    claim_coverage = assess_claim_coverage(claim_graph, resolution, records)
    findings.extend(_analyse_claim_coverage(claim_coverage, policy))
    findings.extend(_analyse_semantic(resolution))
    findings.extend(_analyse_injection(resolved_records))
    findings.extend(_analyse_readers(resolution, resolved_records))
    from release_gate.assurance.authorship import assess_authorship
    authorship = assess_authorship(
        claim_graph, resolution,
        records + [r for r in case.records("verification") if isinstance(r, EvidenceRecord)],
        policy=policy.independence)
    findings.extend(_analyse_authorship(authorship, policy))
    findings.extend(_analyse_coverage(case, claim_graph, execution, normalisation))
    if capabilities is None and normalisation is not None:
        capabilities = getattr(normalisation, "capabilities", None)
    findings.extend(_analyse_capabilities(capabilities))
    findings.extend(_analyse_consequence(consequence, capabilities))

    findings.sort(key=lambda f: (f.domain.value, f.rule_id, f.refs[0] if f.refs else ""))
    return AnalysisResult(findings=tuple(findings), claim_graph=claim_graph,
                          artifact_graph=artifact_graph, execution_graph=execution,
                          verification_graph=verification_graph,
                          capabilities=capabilities, consequence=consequence,
                          independence=independence, replication=replication,
                          adversarial=adversarial,
                          criticality=criticality,
                          coverage_ledger=coverage_ledger,
                          contradictions=ledger,
                          assumptions=assumption_graph,
                          counterexamples=counterexamples,
                          failed_branches=failed_branches,
                          state_binding=state_binding,
                          resolution=resolution,
                          claim_coverage=claim_coverage,
                          counterexample_standings=standings,
                          authorship=authorship)
