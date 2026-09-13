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
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.artifacts import ArtifactGraph, CurrencyStatus
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.claims import ClaimGraph, ClaimStatus
from release_gate.assurance.evidence import EvidenceRecord, ProducerKind
from release_gate.assurance.execution_graph import CompletenessStatus, ExecutionGraph
from release_gate.assurance.methodology import RequirementEffect
from release_gate.assurance.records import Presence
from release_gate.assurance.subject import MutationStatus

__all__ = [
    "AnalysisDomain",
    "AnalysisResult",
    "Finding",
    "analyse",
]

ANALYSIS_RULESET_VERSION = "rg-structural-1"


class AnalysisDomain(str, Enum):
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
                "counts": {e.value: len(self.by_effect(e)) for e in RequirementEffect}}


# ── helpers ──────────────────────────────────────────────────────────────────

def _evidence_records(case: AssuranceCase) -> List[EvidenceRecord]:
    return [r for r in case.records("evidence") if isinstance(r, EvidenceRecord)]


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
            outcomes = {a.outcome.value for a in claim.verification_attempts}
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


# ── contradiction (RG-CONTRA-*) ──────────────────────────────────────────────

def _analyse_contradiction(claim_graph: Optional[ClaimGraph],
                           records: Sequence[EvidenceRecord]) -> List[Finding]:
    findings: List[Finding] = []

    # Evidence that both supports and contradicts the same claim: a producer
    # disagreeing with itself inside one record.
    self_conflicted = sorted(
        r.evidence_id for r in records
        if set(r.supports_claims) & set(r.contradicts_claims))
    if self_conflicted:
        findings.append(Finding(
            rule_id="RG-CONTRA-001", domain=AnalysisDomain.CONTRADICTION,
            effect=RequirementEffect.HOLD,
            summary=f"{len(self_conflicted)} evidence record(s) both support and "
                    "contradict the same claim",
            detail="One record cannot be read as evidence for and against the same "
                   "proposition without saying which reading applies.",
            remedy="split the record, or state which relationship holds",
            refs=tuple(self_conflicted[:12]),
            observed={"records": len(self_conflicted)}))

    if claim_graph is None:
        return findings

    refuted: List[str] = []
    disputed: List[str] = []
    for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
        status = claim_graph.status(claim.claim_id)
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


# ── coverage (RG-COV-*) ──────────────────────────────────────────────────────

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
        unsupported = sorted(
            c.claim_id for c in claim_graph.claims
            if not c.supporting_evidence and not c.verification_attempts)
        if unsupported:
            load_bearing = {c.claim_id for c in claim_graph.load_bearing()} \
                if callable(getattr(claim_graph, "load_bearing", None)) else set()
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


# ── the entry point ──────────────────────────────────────────────────────────

def analyse(case: AssuranceCase, *, normalisation: Optional[Any] = None,
            claim_graph: Optional[ClaimGraph] = None,
            artifact_graph: Optional[ArtifactGraph] = None,
            execution: Optional[ExecutionGraph] = None) -> AnalysisResult:
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

    findings: List[Finding] = []
    findings.extend(_analyse_provenance(case, records))
    findings.extend(_analyse_verification(case, records, claim_graph))
    findings.extend(_analyse_contradiction(claim_graph, records))
    findings.extend(_analyse_drift(case, artifact_graph, records))
    findings.extend(_analyse_coverage(case, claim_graph, execution, normalisation))

    findings.sort(key=lambda f: (f.domain.value, f.rule_id, f.refs[0] if f.refs else ""))
    return AnalysisResult(findings=tuple(findings), claim_graph=claim_graph,
                          artifact_graph=artifact_graph, execution_graph=execution)
