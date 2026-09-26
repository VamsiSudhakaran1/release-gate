"""Zero-config assurance — `release-gate assure <file>`.

One file, no configuration, and a real answer about the *structure* of the
evidence: where it came from, whether it contradicts itself, what was verified,
whether the verification still applies, and what is missing.

The boundary this module exists to hold:

> Zero configuration produces structural assurance. It never produces domain
> sufficiency.

So a run with no methodology can return BLOCK and can return HOLD, and **cannot
return PROMOTE** — enforced below, not merely intended. Refusal needs less
authority than permission: "this case contradicts itself" is a fact about the
evidence, while "this is enough evidence to proceed" is a claim about a domain
that nobody has told release-gate anything about. Inventing a universal
methodology to close that gap would be the single most damaging thing this
system could do, because it would look exactly like an answer.

Where the gap cannot be closed, the run says so in the vocabulary the rest of
the system already uses: `METHODOLOGY_REQUIRED`, `NOT_ASSESSED`, `HOLD`.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from release_gate.assurance.analysis import (
    ANALYSIS_RULESET_VERSION, AnalysisDomain, AnalysisResult, Finding, analyse,
)
from release_gate.assurance.attention import (
    HumanAttentionSet, RequiredEvidenceSet, build_attention, build_required_evidence,
)
from release_gate.assurance.capabilities import CapabilitySurface
from release_gate.assurance.level import LevelAssessment, assess_level
from release_gate.assurance.consequence import (
    ConsequenceProfile, ConsequenceRegistry, default_consequence_registry,
)
from release_gate.assurance.case import (
    COLLECTION_KINDS,
    AssuranceCase, AssuranceCaseBuilder, CaseVerdict, Decision, MethodologyRef,
    default_case_type,
)
from release_gate.assurance.ingest import (
    Detection, InputKind, Normalisation, ingest_path, subject_type_for,
)
from release_gate.assurance.methodology import (
    AssessmentStatus, AssuranceMethodology, MethodologyAssessment, RequirementEffect,
    assess,
)
from release_gate.assurance.assumptions import AssumptionGraph
from release_gate.assurance.contradiction import Contradiction, ContradictionLedger
from release_gate.assurance.counterexample import CounterexampleLedger
from release_gate.assurance.failed_branches import FailedBranchLedger
from release_gate.assurance.independence import IndependenceProfile, LineageConcentration
from release_gate.assurance.adversarial import AdversarialReview
from release_gate.assurance.criticality import CriticalitySet
from release_gate.assurance.packet import ApprovalPacket
from release_gate.assurance.expectation import (
    CoverageLedger, EvidenceExpectation, ExpectationSource,
    ExpectationSourceKind, ExpectationStanding)
from release_gate.assurance.replication import ReplicationOutcome, ReplicationProfile
from release_gate.assurance.records import MaterialisationBasis, SimpleRecord
from release_gate.assurance.verification import (
    Applicability, VerificationGraph, VerificationStatus,
)
from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, file_content,
)
from release_gate.assurance.subject import AssuranceSubject, DigestMethod, DigestStatus

__all__ = [
    "AssuranceOutcome",
    "ZERO_CONFIG_RULESET_VERSION",
    "ZeroConfigError",
    "assure",
    "decide",
    "exit_code_for",
]

ZERO_CONFIG_RULESET_VERSION = "zero-config-1"

# The rule that fires when sufficiency cannot be assessed at all. It is a rule
# rather than a bare string so the verdict names it like any other.
RULE_METHODOLOGY_REQUIRED = "RG-ZC-001"
RULE_STRUCTURAL_BLOCK = "RG-ZC-002"
RULE_STRUCTURAL_HOLD = "RG-ZC-003"
RULE_METHODOLOGY_SATISFIED = "RG-ZC-004"
#: A structural HOLD the methodology accepted up front. Named on the verdict so
#: the audit trail shows an acceptance was applied rather than a shorter list.
RULE_STRUCTURAL_ACCEPTED = "RG-ZC-005"

_EXIT = {Decision.PROMOTE: 0, Decision.HOLD: 10, Decision.BLOCK: 1}


class ZeroConfigError(RuntimeError):
    """The zero-config path could not run at all."""


@dataclass(frozen=True)
class AssuranceOutcome:
    """Everything one `assure` run produced."""

    case: AssuranceCase
    normalisation: Normalisation
    analysis: AnalysisResult
    assessment: MethodologyAssessment
    attention: HumanAttentionSet
    required_evidence: RequiredEvidenceSet
    consequence: ConsequenceProfile = field(default_factory=ConsequenceProfile)
    #: How deep this case goes and how deep it needs to go. Derived after the
    #: fact and consumed only by reporting: no analyser reads it, and it can
    #: neither soften a finding nor change a verdict.
    level: LevelAssessment = field(
        default_factory=lambda: assess_level())

    @property
    def decision(self) -> Decision:
        return self.case.verdict.decision if self.case.verdict else Decision.HOLD

    @property
    def detection(self) -> Detection:
        return self.normalisation.detection

    @property
    def failed_branches(self) -> FailedBranchLedger:
        """What was tried and did not work, as structure rather than transcript."""
        return self.analysis.failed_branches or FailedBranchLedger()

    @property
    def counterexamples(self) -> CounterexampleLedger:
        """Attempts to break the claims, and what each came back with."""
        return self.analysis.counterexamples or CounterexampleLedger()

    @property
    def assumptions(self) -> AssumptionGraph:
        """What the argument takes for granted, and what falls with each."""
        return self.analysis.assumptions or AssumptionGraph()

    @property
    def contradictions(self) -> ContradictionLedger:
        """Every disagreement found, and what became of each."""
        return self.analysis.contradictions or ContradictionLedger()

    @property
    def independence(self) -> Optional[IndependenceProfile]:
        """Where the support actually comes from. Structure, never a probability."""
        return self.analysis.independence

    @property
    def criticality(self) -> Optional[CriticalitySet]:
        """What the decision rests on. Reachability, never volume."""
        return self.analysis.criticality

    @property
    def adversarial(self) -> Optional[AdversarialReview]:
        """Verifiers that set out to disprove this. Absent is normal, not a gap."""
        return self.analysis.adversarial

    @property
    def replication(self) -> Optional[ReplicationProfile]:
        """What has actually been reproduced, once copies have collapsed."""
        return self.analysis.replication

    @property
    def verification(self) -> Optional[VerificationGraph]:
        """Every check on every target, with whether each still applies."""
        return self.analysis.verification_graph

    @property
    def capabilities(self) -> Optional[CapabilitySurface]:
        """What the system reached for. Evidence on the case, not a verdict input."""
        return self.normalisation.capabilities

    def packet(self, *, previous: Any = None) -> "ApprovalPacket":
        """The eleven questions, answered against this run's sealed case.

        Built on demand rather than eagerly: it is a rendering for a person, and
        a run whose output is being piped into another system should not pay for
        one. `previous` is an earlier case or its stored binding state; without
        it section 8 says there was nothing to compare against, which is the
        honest answer and not "nothing changed".
        """
        from release_gate.assurance.packet import build_packet
        return build_packet(self.case, self, previous=previous)

    @property
    def exit_code(self) -> int:
        return _EXIT[self.decision]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "case": self.case.summary(),
            "ingest": self.normalisation.to_dict(),
            "analysis": self.analysis.to_dict(),
            "assessment": self.assessment.to_dict(),
            "capabilities": (self.capabilities.to_dict() if self.capabilities
                             else None),
            "consequence": self.consequence.to_dict(),
            "verification": (self.verification.to_dict() if self.verification
                             else None),
            "independence": (self.independence.to_dict() if self.independence
                             else None),
            "replication": (self.replication.to_dict()
                            if self.replication is not None else None),
            "adversarial": (self.adversarial.to_dict()
                            if self.adversarial is not None else None),
            "criticality": (self.criticality.to_dict()
                            if self.criticality is not None else None),
            "contradictions": self.contradictions.to_dict(),
            "assumptions": self.assumptions.to_dict(),
            "counterexamples": self.counterexamples.to_dict(),
            "failed_branches": self.failed_branches.to_dict(),
            "attention": self.attention.to_dict(),
            "required_evidence": self.required_evidence.to_dict(),
            "ruleset_version": ZERO_CONFIG_RULESET_VERSION,
        }


# ── case construction ────────────────────────────────────────────────────────

def _coverage_row(dimension: str, assessed: bool, note: str, *,
                  expectation: Optional[EvidenceExpectation] = None,
                  **observed: Any) -> SimpleRecord:
    """One statement of what was and was not assessed.

    `assessed=False` is a `NOT_ASSESSED` row — a first-class result, never an
    omission and never a zero.

    Where a dimension has a real denominator, pass an `EvidenceExpectation` and
    the row carries the five-state answer: how many were expected, how many
    arrived, how many are known missing, and the ratio — or `null` where no
    ratio exists. Where it does not, the row still says `UNKNOWN` rather than
    implying that what arrived was all there was. The old two-state `status`
    field is kept beside the new `state` so existing readers are not broken.
    """
    if expectation is not None:
        payload = expectation.to_dict()
        payload.update({"note": note, **observed})
        return SimpleRecord(record_type="coverage",
                            record_id=f"cov_{dimension}", payload=payload)
    bare = EvidenceExpectation(dimension=dimension, assessed=assessed, note=note)
    payload = bare.to_dict()
    payload.update({"note": note, **observed})
    return SimpleRecord(record_type="coverage", record_id=f"cov_{dimension}",
                        payload=payload)


def _ingest_coverage(normalisation: Normalisation,
                     consequence: ConsequenceProfile,
                     verification: Optional[VerificationGraph],
                     independence: Optional[IndependenceProfile],
                     replication: Optional[ReplicationProfile] = None,
                     adversarial: Optional[AdversarialReview] = None,
                     criticality: Optional[CriticalitySet] = None,
                     contradictions: Optional[ContradictionLedger] = None,
                     assumptions: Optional[AssumptionGraph] = None,
                     counterexamples: Optional[CounterexampleLedger] = None,
                     failed_branches: Optional[FailedBranchLedger] = None
                     ) -> List[SimpleRecord]:
    detection = normalisation.detection
    rows = [
        _coverage_row("input_identification", detection.recognised,
                      detection.basis, confidence=detection.confidence,
                      kind=detection.kind.value),
        _coverage_row("input_integrity", True,
                      "the input file was hashed by release-gate; its bytes are OBSERVED"),
        _coverage_row("record_mapping", normalisation.skipped_total == 0,
                      (f"{normalisation.records_mapped} of {normalisation.records_seen} "
                       f"record(s) mapped; {normalisation.skipped_total} skipped"),
                      # The file states its own total, so this denominator is
                      # self-reported by construction: it can say how many records
                      # failed to map, and nothing about a record the producer
                      # never wrote.
                      expectation=EvidenceExpectation(
                          dimension="record_mapping",
                          expected=normalisation.records_seen,
                          observed=normalisation.records_mapped,
                          source=ExpectationSource(
                              kind=ExpectationSourceKind.PRODUCER_MANIFEST,
                              declared_by=detection.kind.value,
                              detail="the input document is its own denominator"),
                          observed_from=detection.kind.value),
                      seen=normalisation.records_seen,
                      mapped=normalisation.records_mapped,
                      skipped=normalisation.skipped_total),
        _coverage_row("execution_reconstruction", normalisation.execution is not None,
                      ("execution graph reconstructed from the input"
                       if normalisation.execution is not None else
                       "no execution telemetry was present in this input")),
        _capability_coverage(normalisation.capabilities),
        _consequence_coverage(consequence),
        _verification_coverage(verification),
        _independence_coverage(independence),
        _replication_coverage(replication),
        _adversarial_coverage(adversarial),
        _criticality_coverage(criticality),
        _contradiction_coverage(contradictions),
        _assumption_coverage(assumptions),
        _counterexample_coverage(counterexamples),
        _failed_branch_coverage(failed_branches),
        # The one release-gate can never answer on its own.
        _coverage_row("domain_sufficiency", False,
                      "whether this evidence is sufficient for the decision is a domain "
                      "question; no methodology was supplied, so it was not assessed"),
        # `overall` is the dimension a general methodology asks for, and the honest
        # answer is partial: structure assessed, sufficiency not. Stating it as
        # ASSESSED would claim the second half.
        _coverage_row("overall", False,
                      (f"the structure of this {detection.kind.value} input was assessed "
                       "(provenance, contradiction, verification status, drift, and what "
                       "the ingest could not map). Whether the evidence is sufficient for "
                       "the decision was not."),
                      assessed_dimensions=["input_identification", "input_integrity",
                                           "record_mapping", "execution_reconstruction",
                                           "structural_analysis"],
                      not_assessed_dimensions=["domain_sufficiency"]),
    ]
    return rows


def _capability_coverage(surface: Optional[CapabilitySurface]) -> SimpleRecord:
    """Coverage for capability discovery, including what it cannot bound.

    Marked ASSESSED only when the surface could in principle contain an observed
    capability *and* is an upper bound on what ran. A tidy list built from names,
    or one with a shell in it, has not assessed the capability surface — it has
    sampled it.
    """
    if surface is None:
        return _coverage_row("capability_discovery", False,
                             "no execution evidence was present, so nothing can be said "
                             "about what the system reached for")
    assessed = surface.can_observe and surface.bounded
    if surface.bounded:
        bound_note = "the list is an upper bound on what was reached for"
    else:
        bound_note = ("the list is NOT an upper bound: "
                      + ", ".join(sorted(r.capability.value for r in surface.subsuming))
                      + " can reach other capabilities without appearing as them")
    return _coverage_row(
        "capability_discovery", assessed,
        (f"{len(surface.records)} capabilit(y/ies) from {surface.spans_examined} "
         f"span(s) via {surface.attribute_basis}; {bound_note}"),
        observed=len(surface.observed), inferred=len(surface.inferred),
        declared_only=len(surface.declared_only), unknown=len(surface.unknown),
        bounded=surface.bounded, observation_possible=surface.can_observe,
        surface_digest=surface.digest())


def _failed_branch_coverage(ledger: Optional[FailedBranchLedger]) -> SimpleRecord:
    """Coverage for the exploration record.

    Never ASSESSED on the strength of an empty ledger. A case with no failed
    branches is either a run where nothing failed or a run where the failures were
    dropped before they reached here, and release-gate cannot tell which — so it
    says so rather than reading silence as a clean sweep.
    """
    if ledger is None or not ledger.observed:
        return _coverage_row(
            "failed_branches", False,
            "no failed branches are recorded; that is either a run where nothing "
            "failed or one where the failures never reached this case, and nothing "
            "here distinguishes them")
    summary = ledger.summary()
    return _coverage_row(
        "failed_branches", ledger.complete,
        (f"{summary['observed']:,} branch(es) failed across "
         f"{summary['failure_points']} failure point(s); {summary['retained']} retained "
         f"as examples under {summary['basis']}. Counts are exact; retention drops "
         "examples, never the aggregate"),
        observed=summary["observed"], retained=summary["retained"],
        dropped=summary["dropped"], basis=summary["basis"],
        failure_points=summary["failure_points"], recurring=summary["recurring"],
        ledger_digest=summary["digest"])


def _counterexample_coverage(ledger: Optional[CounterexampleLedger]) -> SimpleRecord:
    """Coverage for attempts to break the claims, and the asymmetry between them.

    Never ASSESSED on the strength of empty searches. A run where every search
    came back clean has not established that no counterexample exists — it has
    established what those searches covered, which is a different and much smaller
    statement.
    """
    if ledger is None or not len(ledger):
        return _coverage_row(
            "counterexamples", False,
            "nobody tried to break the claims in this case; no counterexample search "
            "is recorded")
    summary = ledger.summary()
    return _coverage_row(
        "counterexamples", summary["open"] == 0 and summary["found"] == 0,
        (f"{summary['total']} search(es): {summary['found']} found a counterexample, "
         f"{summary['open']} of those unresolved, "
         f"{summary['searched_without_finding']} came back empty. An empty search "
         "bounds the search, not the claim — absence is never established here"),
        total=summary["total"], found=summary["found"], open=summary["open"],
        searched_without_finding=summary["searched_without_finding"],
        absence_proven=False, ledger_digest=summary["digest"])


def _assumption_coverage(graph: Optional[AssumptionGraph]) -> SimpleRecord:
    """Coverage for assumptions, and a refusal to imply the list is complete.

    ASSESSED means every load-bearing assumption is stated and something bears on
    it. It never means the argument makes no other assumptions: these are the ones
    somebody *wrote down*, and the dangerous ones are usually the ones nobody
    thought to mention.
    """
    if graph is None or not len(graph):
        return _coverage_row(
            "assumptions", False,
            "no assumptions are recorded; an argument that declares none is not an "
            "argument that makes none")
    summary = graph.summary()
    settled = summary["unstated"] == 0 and summary["unexamined"] == 0
    return _coverage_row(
        "assumptions", settled,
        (f"{summary['total']} assumption(s) recorded, {summary['load_bearing']} "
         f"load-bearing, {summary['unstated']} never stated, {summary['unexamined']} "
         "load-bearing and unexamined; only declared assumptions are visible here"),
        total=summary["total"], load_bearing=summary["load_bearing"],
        unstated=summary["unstated"], unexamined=summary["unexamined"],
        graph_digest=summary["digest"])


def _contradiction_coverage(ledger: Optional[ContradictionLedger]) -> SimpleRecord:
    """Coverage for contradictions, and a refusal to imply completeness.

    ASSESSED means the detectors ran and every disagreement they found is closed.
    It never means no disagreement exists: these detectors see structural conflict
    in what the case holds, and two claims that contradict each other in meaning
    alone pass straight through.
    """
    if ledger is None:
        return _coverage_row("contradiction", False,
                             "contradiction detection did not run")
    summary = ledger.summary()
    return _coverage_row(
        "contradiction", summary["open"] == 0,
        (f"{summary['total']} contradiction(s) detected, {summary['open']} still open, "
         f"{summary['unresolved_critical']} of those on a critical claim; structural "
         "conflict only — semantic disagreement is not assessed"),
        total=summary["total"], open=summary["open"],
        unresolved_critical=summary["unresolved_critical"],
        by_status=summary["by_status"], ledger_digest=summary["digest"])


def _independence_coverage(profile: Optional[IndependenceProfile]) -> SimpleRecord:
    """Coverage for independence, keyed on whether ancestry could be derived at all.

    ASSESSED only when the lineage ranking is determined. A concentration figure
    computed over a minority of contributors whose ancestry happens to be recorded
    is not an assessment of independence — it is a measurement of the subset that
    bothered to say.
    """
    if profile is None or not profile.contributors:
        return _coverage_row("independence", False,
                             "no contributing evidence, so independence cannot be "
                             "assessed")
    return _coverage_row(
        "independence", profile.determinable,
        (f"{profile.contributors:,} contributor(s) across "
         f"{profile.independent_roots} lineage(s); {profile.basis}"),
        contributors=profile.contributors,
        root_evidence_count=profile.root_evidence_count,
        largest_ancestry_cluster=profile.largest_ancestry_cluster,
        shared_ancestry_concentration=profile.shared_ancestry_concentration,
        unknown_ancestry=profile.unknown_ancestry,
        concentration=profile.concentration.value,
        profile_digest=profile.digest())


def _merge_declared_expectations(rows: List[SimpleRecord],
                                 normalisation: Normalisation) -> List[SimpleRecord]:
    """Fold envelope-declared expectations into the case's coverage collection.

    Without this, a declared denominator reaches the analyser's ledger and never
    the case — so every methodology predicate, which reads the case, reported
    NOT_ASSESSED for a dimension somebody had explicitly stated. The whole
    sufficiency layer was blind to the one thing PROMPT 24 exists to supply.

    Where a dimension already has a row, the stronger standing wins: an
    orchestrator's denominator says something a producer's count of itself
    cannot, and should not lose to whichever row was built first.
    """
    declared = tuple(getattr(normalisation, "expectations", ()) or ())
    if not declared:
        return rows
    rank = {ExpectationStanding.NOT_ESTABLISHED: 0,
            ExpectationStanding.SELF_REPORTED: 1,
            ExpectationStanding.ESTABLISHED: 2}
    by_dimension = {str(r.to_dict().get("dimension") or ""): r for r in rows}
    for expectation in declared:
        held = by_dimension.get(expectation.dimension)
        if held is not None:
            try:
                existing = EvidenceExpectation.from_dict(
                    {**held.to_dict(),
                     "assessed": held.to_dict().get("status") == "ASSESSED"})
            except Exception:
                existing = None
            if existing is not None and rank[expectation.standing] < rank[existing.standing]:
                continue
        by_dimension[expectation.dimension] = SimpleRecord(
            record_type="coverage", record_id=f"cov_{expectation.dimension}",
            payload=expectation.to_dict())
    return [by_dimension[k] for k in sorted(by_dimension)]


def _criticality_coverage(criticality: Optional[CriticalitySet]) -> SimpleRecord:
    """Coverage for criticality, which gates every other critical-claim guard.

    This row exists because the failure it reports is otherwise invisible. A case
    whose criticality could not be derived produces no critical claims, so every
    guard that asks "is this claim critical?" answers no and the case reads clean.
    NOT_ASSESSED here says the guards did not run — a different fact from their
    having run and found nothing.
    """
    if criticality is None or not criticality.claims_examined:
        return _coverage_row("criticality", False,
                             "this case declares no claims, so there is no dependency "
                             "structure in which criticality could be derived")
    if not criticality.determinable:
        return _coverage_row(
            "criticality", False,
            ("what this decision rests on could not be established, so every "
             "critical-claim guard in this analysis was inactive. " +
             criticality.basis),
            claims=criticality.claims_examined, critical=0, determinable=False,
            link=criticality.link.value)
    return _coverage_row(
        "criticality", True,
        (f"the decision rests on {len(criticality.critical())} of "
         f"{criticality.claims_examined} claim(s), reached through up to "
         f"{criticality.max_depth} dependency link(s) from "
         f"{len(criticality.decision_claims)} conclusion(s) identified by "
         f"{criticality.link.value.lower().replace('_', ' ')}"),
        claims=criticality.claims_examined,
        critical=len(criticality.critical()),
        determinable=True, link=criticality.link.value,
        max_depth=criticality.max_depth,
        thin_critical=len(criticality.thin()),
        disagreements=len(criticality.disagreements()),
        broken_chains=len(criticality.broken_chains()),
        volume_affects_criticality=False)


def _adversarial_coverage(review: Optional[AdversarialReview]) -> SimpleRecord:
    """Coverage for adversarial review, which is NOT_ASSESSED by default.

    Absence is the normal case and never a shortfall: most decisions have no
    adversary and are not worse for it. Where adversaries are present the row says
    what they attacked and, deliberately, that an attack finding nothing bounds
    the search rather than the claim — so a red team in the case never reads as
    the case having been cleared.
    """
    if review is None or not review.present:
        return _coverage_row("adversarial_review", False,
                             "no verifier set out to disprove this candidate; "
                             "adversarial review is never required, so this is "
                             "NOT_ASSESSED rather than a gap")
    return _coverage_row(
        "adversarial_review", True,
        (f"{len(review)} attack(s) by {len(review.adversaries)} adversary(ies) on "
         f"{len(review.claims_attacked)} claim(s); {len(review.open())} unresolved, "
         f"{len(review.empty_searches())} found nothing (which bounds the search, not "
         f"the claim). {review.basis}"),
        attacks=len(review), adversaries=len(review.adversaries),
        claims_attacked=len(review.claims_attacked), open=len(review.open()),
        refutations=len(review.refutations()),
        argument_defects=len(review.argument_defects()),
        accepted_risks=len(review.accepted_risks()),
        self_cleared=len(review.self_cleared_ids),
        independent=len(review.independent()),
        non_independent=len(review.non_independent()),
        empty_searches=len(review.empty_searches()),
        proves_absence=False)


def _replication_coverage(profile: Optional[ReplicationProfile]) -> SimpleRecord:
    """Coverage for replication, keyed on whether any second path exists at all.

    A case whose every target sits on one path has not had replication assessed
    as insufficient — it has had nothing to assess. That distinction is the point
    of the row: `SINGLE_PATH` everywhere reports as not-assessed rather than as a
    failure, because resting on one path is a normal workflow and this row is not
    where that becomes a verdict.
    """
    if profile is None or not profile.targets:
        return _coverage_row("replication", False,
                             "no verification attempt names a target, so nothing here "
                             "could be reproduced or compared")
    reproduced = len(profile.confirmed) + len(profile.divergent)
    return _coverage_row(
        "replication", reproduced > 0,
        (f"{len(profile.targets)} target(s); {len(profile.confirmed)} reproduced, "
         f"{len(profile.divergent)} divergent, {len(profile.single_path)} on a single "
         f"path. {profile.basis}"),
        targets=len(profile.targets),
        confirmed=len(profile.confirmed),
        divergent=len(profile.divergent),
        single_path=len(profile.single_path),
        not_achieved=len(profile.not_achieved),
        max_replications=max((t.replications for t in profile.targets), default=0),
        attempts_examined=profile.attempts_examined)


def _verification_coverage(graph: Optional[VerificationGraph]) -> SimpleRecord:
    """Coverage for verification, keyed on whether applicability is computable.

    ASSESSED only when every attempt that could move a status records what state
    it ran against. A case full of verifications that never said what they checked
    has not assessed verification currency — it has recorded checks whose
    applicability is unknowable.
    """
    if graph is None or not graph.attempts:
        return _coverage_row("verification_currency", False,
                             "no verification attempts are recorded, so whether "
                             "anything still applies cannot be asked")
    undetermined = sum(
        1 for a in graph.attempts
        if a.target is not None and a.counts_toward_status
        and a.applicability(graph.current_digest(a.target)) is Applicability.UNDETERMINED)
    superseded = len(graph.superseded_attempts())
    summary = graph.summary()
    return _coverage_row(
        "verification_currency", undetermined == 0,
        (f"{summary['attempts']} attempt(s) on {summary['targets']} target(s); "
         f"{superseded} superseded, {undetermined} with no recorded target state"),
        attempts=summary["attempts"], targets=summary["targets"],
        superseded=superseded, undetermined=undetermined,
        invalidated=summary["invalidated"], not_run=summary["not_run"],
        graph_digest=summary["digest"])


def _consequence_coverage(profile: ConsequenceProfile) -> SimpleRecord:
    """Coverage for the stakes.

    ASSESSED only when something is actually known. A profile of eleven UNKNOWNs
    has not assessed consequence — it has recorded that nobody stated it, which is
    a different and equally honest thing.
    """
    known = profile.known
    if not known:
        return _coverage_row(
            "consequence", False,
            "no consequence dimension is stated; release-gate does not guess at "
            "reversibility, cost or legality",
            known=0, unknown=len(profile.unknown))
    return _coverage_row(
        "consequence", True,
        (f"{len(known)} of {len(profile.descriptors)} dimension(s) stated "
         f"({len(profile.declared)} declared, {len(profile.derived)} derived); "
         f"{len(profile.unknown)} remain UNKNOWN"),
        known=len(known), unknown=len(profile.unknown),
        declared=len(profile.declared), derived=len(profile.derived),
        elevated=[d.dimension.value for d in profile.elevated()],
        conflicts=len(profile.conflicts), profile_digest=profile.digest())


def _capability_evidence(surface: Optional[CapabilitySurface],
                         applies_to: Optional[str]) -> List[EvidenceRecord]:
    """The capability surface as one DERIVED evidence record.

    One record, not thirteen. Capabilities are evidence about the execution, and
    release-gate computed them from records already in the case — folding each
    capability in separately would let a summary inflate the evidence count that
    methodologies measure.
    """
    if surface is None:
        return []
    return [EvidenceRecord.derived(
        EvidenceType.TRACE, source="release-gate/capability-discovery",
        producer=Producer.release_gate("assurance/capabilities"),
        applies_to_digest=applies_to,
        content={"capability_surface": surface.summary(),
                 "capabilities": [r.to_dict() for r in surface.records]},
        coverage_note=(
            "capabilities as classified from execution evidence; OBSERVED entries rest "
            "on protocol attributes, INFERRED entries on tool names only"))]


def _analysis_records(analysis: AnalysisResult
                      ) -> Tuple[List[Any], List[SimpleRecord]]:
    # Real contradiction objects, not the findings that mention them: the
    # collection is what a verdict is checked against and what `NoUnresolved`
    # reads, so it has to carry the disagreements themselves.
    ledger = analysis.contradictions or ContradictionLedger()
    contradictions: List[Any] = list(ledger.contradictions)
    rows = [
        _coverage_row(
            "structural_analysis", True,
            f"{len(analysis.findings)} structural finding(s) under ruleset "
            f"{ANALYSIS_RULESET_VERSION}",
            findings=len(analysis.findings),
            blocking=len(analysis.blocking), holding=len(analysis.holding)),
    ]
    # CONTRADICTION is deliberately absent: `_contradiction_coverage` reports the
    # ledger itself, which says more than a count of findings that mention it.
    for domain in (AnalysisDomain.PROVENANCE, AnalysisDomain.VERIFICATION,
                   AnalysisDomain.DRIFT):
        found = analysis.by_domain(domain)
        rows.append(_coverage_row(
            domain.value.lower(), True,
            f"{len(found)} finding(s) in the {domain.value.lower()} analysers",
            findings=len(found)))
    return contradictions, rows


def _build_case(subject: AssuranceSubject, normalisation: Normalisation, *,
                objective: str, requested_decision: str,
                methodology: Optional[AssuranceMethodology],
                consequence: ConsequenceProfile,
                verification: Optional[VerificationGraph] = None,
                independence: Optional[IndependenceProfile] = None,
                replication: Optional[ReplicationProfile] = None,
                adversarial: Optional[AdversarialReview] = None,
                criticality: Optional[CriticalitySet] = None,
                contradictions: Optional[ContradictionLedger] = None,
                assumptions: Optional[AssumptionGraph] = None,
                counterexamples: Optional[CounterexampleLedger] = None,
                failed_branches: Optional[FailedBranchLedger] = None,
                extra: Optional[Mapping[str, List[Any]]] = None) -> AssuranceCase:
    builder = AssuranceCaseBuilder(
        case_type=default_case_type(subject.subject_type), objective=objective,
        requested_decision=requested_decision, subject=subject,
        methodology=(MethodologyRef(methodology_id=methodology.methodology_id,
                                    version=methodology.version,
                                    digest=methodology.digest)
                     if methodology is not None else None),
        metadata={
            "zero_config": True,
            "ruleset_version": ZERO_CONFIG_RULESET_VERSION,
            "objective_basis": ("default" if objective.startswith("Assurance of ")
                                else "supplied"),
            "input_kind": normalisation.detection.kind.value,
        })

    builder.collection("evidence", basis=MaterialisationBasis.COMPLETE)
    builder.extend("evidence", normalisation.evidence)
    builder.extend("evidence", _capability_evidence(
        normalisation.capabilities,
        normalisation.evidence[0].digest if normalisation.evidence else None))
    # The profile goes in whole rather than wrapped: it is one object, it already
    # satisfies the record protocol, and `ConsequenceDeclared` finds it here by
    # record_type. A profile of all-UNKNOWNs is still added — "nobody stated the
    # stakes" is a fact the case should carry, not an empty slot.
    builder.add("evidence", consequence)
    if independence is not None:
        # Same reasoning as the consequence profile: one object, already a record,
        # and the predicate finds it here by record_type.
        builder.add("evidence", independence)
    if criticality is not None and criticality.claims_examined:
        # Stored even when undeterminable, unlike the reviews above. "We could not
        # establish what this decision rests on" is the finding, not an absence of
        # one, and a predicate reading NOT_ASSESSED off a missing record could not
        # tell that apart from a case with no claims at all.
        builder.add("evidence", criticality)

    if adversarial is not None and adversarial.present:
        # Only when adversaries actually attacked something. An empty review is
        # left out rather than stored as a zero: `AdversarialReviewRequired`
        # reports NOT_ASSESSED on its absence, which is the honest reading of a
        # case nobody tried to break, and a stored empty review would invite
        # reading it as "we checked, there was nothing".
        builder.add("evidence", adversarial)

    if replication is not None and replication.targets:
        # Same again. Empty is left out rather than stored: a profile over no
        # targets says nothing, and `ReplicationEstablished` reports NOT_ASSESSED
        # on its absence, which is the honest reading of "nothing was compared".
        builder.add("evidence", replication)

    # Present-but-empty is not the same as never supplied. The ingest looked for
    # claims and artifacts, so the collections are declared present either way.
    builder.declare_present("claims", "the ingest looked for claims in this input")
    builder.extend("claims", normalisation.claims)
    builder.declare_present("artifacts", "the input file itself is always an artifact")
    builder.extend("artifacts", normalisation.artifacts)

    if normalisation.execution is not None:
        builder.declare_present("executions", "reconstructed from the input telemetry")
        builder.add("executions", SimpleRecord(
            record_type="execution", record_id=normalisation.execution.digest(),
            payload=normalisation.execution.summary()))

    # CAPPED where retention dropped examples: the collection says how it came to
    # hold what it holds, rather than implying it holds everything.
    builder.collection(
        "failed_branches",
        basis=(failed_branches.basis if failed_branches
               else MaterialisationBasis.COMPLETE))
    builder.declare_present(
        "failed_branches",
        "attempts that did not work out, declared or lifted from failed verification")
    builder.extend("failed_branches",
                   list(failed_branches) if failed_branches else [])

    builder.declare_present(
        "counterexamples",
        "attempts to break the claims in this case, found here or lifted from "
        "counterexample evidence")
    builder.extend("counterexamples",
                   list(counterexamples) if counterexamples else [])

    builder.declare_present(
        "assumptions",
        "derived from what the claims in this case declare they rest on")
    builder.extend("assumptions", list(assumptions) if assumptions else [])

    # A verifier's attempts go in whole: they are typed verification records the
    # tool produced, and the VerificationGraph reads them from here.
    report = normalisation.verifier_report
    verifications = list(report.attempts) if report else []
    verifications += [r for r in normalisation.evidence if r.is_verification]
    builder.declare_present(
        "verification",
        "the ingest looked for typed verification in this input"
        if not verifications else "typed verification found in this input")
    builder.extend("verification", verifications)

    builder.collection("coverage", basis=MaterialisationBasis.COMPLETE)
    builder.extend("coverage", _merge_declared_expectations(
        _ingest_coverage(normalisation, consequence, verification, independence,
                         replication, adversarial, criticality, contradictions,
                         assumptions, counterexamples, failed_branches),
        normalisation))

    for kind, records in (extra or {}).items():
        builder.declare_present(kind, "produced by the zero-config analysis")
        builder.extend(kind, records)

    return builder.build()


def _subject_for(path: Path, normalisation: Normalisation,
                 requested_action: str) -> AssuranceSubject:
    """The subject, digested from what the ingest already hashed.

    Read off the normalisation's own input artifact rather than re-hashing the
    path. Two reasons, and the second is why it is worth doing: re-hashing gave
    two independent computations of one digest that had to agree forever, and it
    assumed the input was a file at all — which an incremental session, whose
    records arrive over a wire, is not. Same bytes, hashed once, by release-gate,
    so the status stays OBSERVED in both shapes.
    """
    inputs = [a for a in normalisation.artifacts
              if (a.metadata or {}).get("role") == "assurance-input"]
    if inputs:
        artifact = inputs[0]
        reference, digest = artifact.content_reference, artifact.digest
        basis = ("sha256 over the input's bytes, computed by release-gate at ingest")
    else:
        # A normalisation with no input artifact should not happen; re-deriving
        # from the path is the honest fallback rather than a subject with no
        # digest, which `subject.identified` would refuse anyway.
        reference, digest = file_content(path)
        basis = "sha256 over the input file's bytes, computed by release-gate"
    return AssuranceSubject(
        subject_type=subject_type_for(normalisation.detection.kind),
        requested_action=requested_action, content_reference=reference, digest=digest,
        digest_method=DigestMethod.SHA256_CONTENT, digest_status=DigestStatus.OBSERVED,
        digest_basis=basis,
        metadata={"filename": path.name,
                  "detected_kind": normalisation.detection.kind.value})


# ── the decision ─────────────────────────────────────────────────────────────

def decide(analysis: AnalysisResult, assessment: MethodologyAssessment, *,
           has_methodology: bool,
           methodology: Optional[AssuranceMethodology] = None,
           consequence: Optional[ConsequenceProfile] = None) -> CaseVerdict:
    """Compose structural findings and methodology assessment into one verdict.

    The ordering is deliberate. Structural BLOCKs come first because they are
    facts about the evidence that no methodology can wave through: a case whose
    own evidence refutes it is not made sound by a yardstick that does not
    mention refutation.

    Then sufficiency. With no methodology the answer is HOLD and the reason is
    `METHODOLOGY_REQUIRED` — never PROMOTE, and never a silently generous
    default. That branch is the whole point of this module.

    **Accepted structural holds.** A methodology may declare, up front, that a
    named structural HOLD is not disqualifying for the class of decision it
    covers (`AcceptedFinding`). This exists because some findings are
    tautological at a given scale: "all evidence traces to a single producer" is
    true by construction of every one-agent case, and holding on it means an
    ordinary single-agent action can never be promoted however much evidence it
    carries — penalising a case for being small, which is the volume judgement
    Invariants 6 and 12 refuse.

    The acceptance is narrow and loud. Only HOLD findings are eligible; a
    structural BLOCK is never accepted, and `blocking` is not consulted here at
    all. Each acceptance is recorded in `reasons` with the methodology's own
    rationale, so the verdict states what was accepted and why rather than
    quietly showing a shorter list. The finding itself still reaches Human
    Attention and the packet: this narrows what *blocks*, never what is *shown*.
    """
    fired: List[str] = []
    reasons: List[str] = []

    blocking = analysis.blocking
    holding = analysis.holding
    decision = Decision.HOLD

    # Which structural holds this methodology has accepted, given what the case
    # actually states about consequence. Computed before any branch so that the
    # acceptance is recorded even on a case that BLOCKs for another reason.
    accepted_holds: List[Tuple[Finding, Any]] = []
    if methodology is not None and holding:
        stated = {d.dimension.value: d.value for d in (consequence.known if consequence
                                                       else ())}
        for finding in holding:
            accepted = methodology.acceptance_for(finding.rule_id, stated)
            if accepted is not None:
                accepted_holds.append((finding, accepted))
    if accepted_holds:
        accepted_ids = {f.rule_id for f, _ in accepted_holds}
        holding = tuple(f for f in holding if f.rule_id not in accepted_ids)
        for finding, acceptance in accepted_holds:
            reasons.append(
                f"{finding.rule_id}: accepted by {assessment.methodology_ref} — "
                f"{acceptance.rationale}. The finding stands and is shown; this "
                "methodology does not treat it as disqualifying here.")

    if blocking:
        decision = Decision.BLOCK
        fired.append(RULE_STRUCTURAL_BLOCK)
        fired.extend(sorted({f.rule_id for f in blocking}))
        reasons.extend(f"{f.rule_id}: {f.summary}" for f in blocking)

    if assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED:
        fired.append(RULE_METHODOLOGY_REQUIRED)
        reasons.append(
            "METHODOLOGY_REQUIRED: structural assurance is complete as far as it goes, "
            "but no methodology states what evidence this decision requires. Domain "
            "sufficiency is NOT_ASSESSED.")
        if decision is not Decision.BLOCK:
            decision = Decision.HOLD
    elif assessment.status is AssessmentStatus.CASE_TYPE_NOT_COVERED:
        fired.append(RULE_METHODOLOGY_REQUIRED)
        detail = assessment.detail or "the supplied methodology does not cover this case type"
        reasons.append(
            f"METHODOLOGY_REQUIRED: {detail}. Domain sufficiency is NOT_ASSESSED.")
        if decision is not Decision.BLOCK:
            decision = Decision.HOLD
    else:
        unmet_block = assessment.unmet(RequirementEffect.BLOCK)
        unmet_hold = assessment.unmet(RequirementEffect.HOLD)
        if unmet_block:
            decision = Decision.BLOCK
            fired.extend(r.requirement_id for r in unmet_block)
            reasons.extend(f"{r.requirement_id}: {r.detail}" for r in unmet_block)
        elif unmet_hold or holding:
            if decision is not Decision.BLOCK:
                decision = Decision.HOLD
            fired.extend(r.requirement_id for r in unmet_hold)
            reasons.extend(f"{r.requirement_id}: {r.detail}" for r in unmet_hold)
        elif decision is not Decision.BLOCK:
            decision = Decision.PROMOTE
            fired.append(RULE_METHODOLOGY_SATISFIED)
            reasons.append(
                f"every requirement of {assessment.methodology_ref} is met, with the "
                "coverage recorded on this case")

    # Every unresolved disagreement on a critical claim is named here, whatever
    # the decision turns out to be. `render_verdict` refuses a verdict that omits
    # one, so this is not decoration — it is the clause that makes the refusal
    # satisfiable rather than a wall.
    for contradiction in (analysis.contradictions.unresolved_critical()
                          if analysis.contradictions else ()):
        fired.append(contradiction.contradiction_id)
        reasons.append(
            f"{contradiction.contradiction_id}: unresolved disagreement on "
            f"{', '.join(contradiction.target_claims)} ({contradiction.critical_basis}) — "
            + " vs ".join(f"{side.label} {len(side.evidence)} record(s)"
                          for side in contradiction.sides))
        if decision is Decision.PROMOTE:
            # Reachable only with a methodology whose requirements are all met.
            # Promoting over an open disagreement on a load-bearing claim is a
            # decision a person may take; taking it silently is not available.
            decision = Decision.HOLD

    if holding and decision is Decision.HOLD and RULE_STRUCTURAL_HOLD not in fired:
        fired.append(RULE_STRUCTURAL_HOLD)
        # The holding rule ids, not only their summaries. `RG-ZC-002` above
        # already extends `fired` with every blocking rule id, and this branch
        # did not — so a BLOCK could be traced from the verdict down to the
        # findings that caused it and a HOLD could not. `RG-ZC-003` said
        # "structure held this" and a reviewer asking *which* structure had
        # nowhere to go, because the ids were only ever inside prose.
        fired.extend(sorted({f.rule_id for f in holding}))
        reasons.extend(f"{f.rule_id}: {f.summary}" for f in holding)

    if accepted_holds:
        fired.append(RULE_STRUCTURAL_ACCEPTED)

    if not fired:
        # Reachable only with a methodology that has no applicable requirements.
        fired.append(RULE_STRUCTURAL_HOLD)
        reasons.append("no requirement applied to this case and nothing structural "
                       "was found; there is no basis on which to promote")
        decision = Decision.HOLD

    # The invariant this module exists to hold. An assertion rather than a
    # comment, because a future edit that relaxes it must fail loudly.
    if decision is Decision.PROMOTE and not has_methodology:
        raise ZeroConfigError(
            "zero-config assurance produced PROMOTE without a methodology. Structural "
            "analysis can refuse, and can decline to answer; it cannot authorise. "
            "This is a bug in the decision function, not a case that should proceed.")

    return CaseVerdict(
        decision=decision, fired_rules=tuple(dict.fromkeys(fired)),
        reasons=tuple(reasons), engine_version=_engine_version(),
        ruleset_version=ZERO_CONFIG_RULESET_VERSION)


def _engine_version() -> str:
    try:
        from release_gate import __version__
        return str(__version__)
    except Exception:
        return "unknown"


def exit_code_for(decision: Decision) -> int:
    """0 PROMOTE · 10 HOLD · 1 BLOCK — the convention the rest of the CLI uses."""
    return _EXIT[Decision(decision)]


# ── the one call ─────────────────────────────────────────────────────────────

def assure(path: str | Path, *, methodology: Optional[AssuranceMethodology] = None,
           objective: Optional[str] = None,
           requested_decision: Optional[str] = None,
           requested_action: Optional[str] = None,
           consequence_registry: Optional[ConsequenceRegistry] = None,
           declared_consequence: Optional[Any] = None) -> AssuranceOutcome:
    """Ingest, analyse, assess and decide — with nothing configured.

    Built in two passes. The first case carries the ingested records and is what
    the structural analysers read. The second carries their conclusions as well,
    and is the one that is sealed and rendered.

    The assessment is computed on the first case deliberately: a methodology
    judges the evidence in a case, not release-gate's own conclusions about that
    evidence. Folding attention items back in before assessing would let the
    engine's output become its own input.
    """
    source = Path(path)
    return assure_normalisation(
        ingest_path(source), source_name=source.name, source_path=source,
        methodology=methodology, objective=objective,
        requested_decision=requested_decision, requested_action=requested_action,
        consequence_registry=consequence_registry,
        declared_consequence=declared_consequence)


def assure_normalisation(normalisation: Normalisation, *, source_name: str,
                         source_path: Optional[Path] = None,
                         methodology: Optional[AssuranceMethodology] = None,
                         objective: Optional[str] = None,
                         requested_decision: Optional[str] = None,
                         requested_action: Optional[str] = None,
                         consequence_registry: Optional[ConsequenceRegistry] = None,
                         declared_consequence: Optional[Any] = None
                         ) -> AssuranceOutcome:
    """Everything `assure` does after reading the file.

    Split out so the incremental session and the one-shot file path are the same
    code rather than two implementations that agree for now. The protocol spec
    requires that a case built locally and a case built through the API from the
    same records produce the same `case_digest` (§15); sharing this function is
    what makes that structural instead of coincidental.
    """
    source = source_path if source_path is not None else Path(source_name)

    objective = objective or f"Assurance of {source.name}"
    requested_decision = requested_decision or (
        "Is the evidence in this file structurally sound enough to put to a human?")
    requested_action = requested_action or (
        f"authorise the result described by {source.name}")

    subject = _subject_for(source, normalisation, requested_action)

    registry = consequence_registry or default_consequence_registry()
    declared = list(normalisation.declared_consequence)
    declared.extend(declared_consequence or ())
    consequence = registry.build(None, capabilities=normalisation.capabilities,
                                 declared=declared)

    provisional = _build_case(subject, normalisation, objective=objective,
                              requested_decision=requested_decision,
                              methodology=methodology, consequence=consequence)
    analysis = analyse(provisional, normalisation=normalisation,
                       claim_graph=None, artifact_graph=None,
                       execution=normalisation.execution,
                       capabilities=normalisation.capabilities,
                       consequence=consequence)

    # The analysed case: the ingest, plus what the analysers concluded about it.
    # This is what the methodology is held against — assessing the provisional
    # case would report `contradictions` as NOT_ASSESSED when contradiction
    # analysis had in fact run and found none, which is the exact conflation
    # between "nobody looked" and "we looked and found nothing" that the presence
    # model exists to prevent.
    contradictions, coverage_rows = _analysis_records(analysis)
    analysed = _build_case(
        subject, normalisation, objective=objective,
        requested_decision=requested_decision, methodology=methodology,
        consequence=consequence, verification=analysis.verification_graph,
        independence=analysis.independence, replication=analysis.replication,
        adversarial=analysis.adversarial, criticality=analysis.criticality,
        contradictions=analysis.contradictions,
        assumptions=analysis.assumptions, counterexamples=analysis.counterexamples,
        failed_branches=analysis.failed_branches,
        extra={"contradictions": contradictions, "coverage": coverage_rows})

    assessment = assess(analysed, methodology)

    # Required evidence first: each attention item carries what would resolve it,
    # so the reader is not sent to a second list to find out what to ask for.
    required = build_required_evidence(analysed, analysis, assessment)
    attention = build_attention(analysed, analysis, assessment, required=required)

    # Attention and required evidence are release-gate's own conclusions, folded in
    # for the record only. They are deliberately not present when the methodology
    # is assessed: a yardstick judges the evidence in a case, never the engine's
    # reading of that evidence.
    final = _build_case(
        subject, normalisation, objective=objective,
        requested_decision=requested_decision, methodology=methodology,
        consequence=consequence, verification=analysis.verification_graph,
        independence=analysis.independence, replication=analysis.replication,
        adversarial=analysis.adversarial, criticality=analysis.criticality,
        contradictions=analysis.contradictions,
        assumptions=analysis.assumptions, counterexamples=analysis.counterexamples,
        failed_branches=analysis.failed_branches,
        extra={"contradictions": contradictions,
               "coverage": coverage_rows,
               "attention_items": list(attention.items),
               "required_evidence": list(required.items)})

    verdict = decide(analysis, assessment, has_methodology=methodology is not None,
                     methodology=methodology, consequence=consequence)
    decided = final.seal().render_verdict(verdict)

    # Derived last, from the sealed case, and deliberately AFTER `decide`. The
    # level describes a case that has already been analysed and ruled on in full;
    # computing it earlier would invite a future edit to branch analysis on it,
    # which is exactly the suppression channel this must never become.
    level = assess_level(
        case_type=decided.case_type, methodology=methodology,
        consequence=consequence,
        # Collections that HOLD something, not ones merely marked PRESENT:
        # PRESENT means "this was looked for", so every case has empty frontier
        # ledgers and reading presence here rated an email send as FRONTIER.
        populated_collections={kind: decided.collection(kind).total_count
                               for kind in COLLECTION_KINDS
                               if decided.collection(kind).total_count > 0},
        dimensions=[str(r.to_dict().get("dimension") or "")
                    for r in decided.collection("coverage").materialised],
        signals={
            "subject_digest": bool(getattr(decided.subject, "digest", "")),
            "execution_reconstructed": normalisation.execution is not None,
            "producers_identified": any(
                getattr(getattr(r, "producer", None), "producer_id", "")
                for r in decided.collection("evidence").materialised)})

    # Proportionate asks first. Nothing is dropped — an above-level requirement
    # describes a real gap — but a Level 1 case should be told to state its
    # consequence before it is told to find a second independent producer.
    required = dataclasses.replace(
        required, items=level.order_requirements(required.items))

    return AssuranceOutcome(case=decided, normalisation=normalisation,
                            analysis=analysis, assessment=assessment,
                            attention=attention, required_evidence=required,
                            consequence=consequence, level=level)


# ── rendering ────────────────────────────────────────────────────────────────

_DECISION_MARK = {Decision.PROMOTE: "PROMOTE", Decision.HOLD: "HOLD", Decision.BLOCK: "BLOCK"}


def render_text(outcome: AssuranceOutcome, *, full: bool = False) -> str:
    """The terminal report.

    Ordered the way a person reads: what was decided, what it rests on, what to
    look at, what would move it. The coverage line is not a footnote — a verdict
    without it is invalid (Invariant 9), so it is printed at the same level as
    the decision itself.
    """
    case = outcome.case
    detection = outcome.detection
    lines: List[str] = []
    add = lines.append

    add("")
    add("=" * 78)
    add(f"  {_DECISION_MARK[outcome.decision]}   {case.objective}")
    add("=" * 78)

    add("")
    add(f"  Subject    {case.subject.subject_id}  ({case.subject.subject_type.value})")
    add(f"  Input      {detection.kind.value} at {detection.confidence}% — {detection.basis}")
    add(f"  Case       {case.case_id} v{case.case_version}  digest {case.case_digest[:23]}…")
    methodology = case.methodology.ref if case.methodology else "NONE"
    add(f"  Methodology {methodology}")

    # Before anything else. An unresolved disagreement on a load-bearing claim is
    # the one thing a reader must not scroll past, so it sits above coverage,
    # findings and attention rather than being filed among them.
    critical = outcome.contradictions.unresolved_critical()
    if critical:
        add("")
        add("  " + "!" * 74)
        add(f"  UNRESOLVED DISAGREEMENT ({len(critical)}) — this decision is being put "
            "to you")
        add("  with the following still contested:")
        for contradiction in critical:
            for line in contradiction.render().splitlines():
                add(f"  {line}")
        add("  " + "!" * 74)

    add("")
    add("  WHAT WAS ASSESSED")
    for row in case.records("coverage"):
        data = row.to_dict()
        mark = "assessed" if data.get("status") == "ASSESSED" else "NOT_ASSESSED"
        add(f"    [{mark:>12}]  {data.get('dimension')}: {data.get('note')}")

    profile = outcome.consequence
    add("")
    add("  WHAT IS AT STAKE")
    if profile.fully_unknown:
        add("    Nothing is stated. release-gate does not guess at reversibility,")
        add("    cost or legality — every dimension is UNKNOWN.")
    else:
        for descriptor in profile.known:
            add(f"    {descriptor.dimension.value:<20} {descriptor.value:<28} "
                f"({descriptor.basis.value} by {descriptor.source})")
    unstated = [d.dimension.value for d in profile.unknown]
    if unstated:
        add(f"    UNKNOWN: {', '.join(unstated)}")
    for conflict in profile.conflicts:
        add(f"    DISPUTED {conflict.dimension.value}: {conflict.kept.value!r} "
            f"({conflict.kept.source}) vs {conflict.rejected.value!r} "
            f"({conflict.rejected.source})")

    branches = outcome.failed_branches
    if branches.observed:
        add("")
        add(f"  WHAT DID NOT WORK ({branches.observed:,} failed branch(es))")
        for line in branches.render().splitlines():
            add(f"    {line}")

    breaking = outcome.counterexamples
    if len(breaking):
        add("")
        add(f"  ATTEMPTS TO BREAK IT ({len(breaking)})")
        for line in breaking.render().splitlines():
            add(f"    {line}")

    assumptions = outcome.assumptions
    if len(assumptions):
        add("")
        add(f"  WHAT THIS RESTS ON ({len(assumptions)} assumption(s))")
        for line in assumptions.explain().splitlines():
            add(f"    {line}")

    ledger = outcome.contradictions
    if len(ledger):
        add("")
        add(f"  CONTRADICTIONS ({len(ledger)})")
        for line in ledger.render().splitlines():
            add(f"    {line}")

    lineage = outcome.independence
    if lineage is not None and lineage.contributors:
        add("")
        add("  WHERE THE SUPPORT COMES FROM")
        for line in lineage.render().splitlines():
            add(f"    {line}")
        if lineage.concentration is LineageConcentration.HIGH:
            add("    Reported, not penalised: relying on one authoritative source is")
            add("    often exactly right. Only a methodology can make this a verdict.")

    graph = outcome.verification
    if graph is not None and graph.attempts:
        add("")
        add(f"  VERIFICATION ({len(graph.attempts)} attempt(s))")
        for target in graph.targets():
            assessment = graph.assess(target)
            add(f"    {graph.render(target)}".replace("\n", "\n    "))
            note = (f"      -> {assessment.status.value}: {assessment.basis}")
            add(note)
            if assessment.status is VerificationStatus.PASSED:
                add(f"      -> {assessment.independent_confirmations} independent "
                    f"confirmation(s), {assessment.unattributed_confirmations} whose "
                    "independence is unrecorded")

    surface = outcome.capabilities
    if surface is not None and len(surface):
        add("")
        add(f"  OBSERVED CAPABILITIES ({len(surface)})")
        for record in surface.records:
            flags = []
            if record.mutating is True:
                flags.append("mutating")
            elif record.mutating is None:
                flags.append("direction unknown")
            if record.external_effect is True:
                flags.append("external effect")
            if record.subsuming:
                flags.append("can reach other capabilities")
            if record.declared:
                flags.append("declared")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            count = f"x{record.occurrences}" if record.occurrences else "not exercised"
            add(f"    {record.status.value:<22} {record.capability.value:<20} "
                f"{count}{suffix}")
            if full:
                add(f"                             {record.basis}")
        if not surface.bounded:
            add("    This list is NOT an inventory: "
                + ", ".join(sorted(r.capability.value for r in surface.subsuming))
                + " can reach other capabilities without appearing as them.")
        if not surface.can_observe:
            add("    Every entry was inferred from a name; none was observed. "
                "Run against the raw trace for protocol-level classification.")

    if outcome.analysis.findings:
        add("")
        add(f"  STRUCTURAL FINDINGS ({len(outcome.analysis.findings)})")
        for finding in outcome.analysis.findings:
            if finding.effect is RequirementEffect.ADVISORY and not full:
                continue
            add(f"    [{finding.effect.value:>8}]  {finding.rule_id}  {finding.summary}")
            if full:
                add(f"                  {finding.detail}")
        advisory = len(outcome.analysis.by_effect(RequirementEffect.ADVISORY))
        if advisory and not full:
            add(f"    ({advisory} advisory finding(s) hidden — pass --full)")

    if len(outcome.attention):
        add("")
        add(f"  HUMAN ATTENTION ({len(outcome.attention)} item(s), hardest first)")
        for item in outcome.attention:
            add(f"    [{item.effect.value:>8}]  {item.focus_kind}: {item.focus}")
            add(f"                  {item.summary}")
            if item.leverage > 1:
                add(f"                  resolves {item.leverage} findings: "
                    f"{', '.join(item.rule_ids)}")
            add(f"                  -> {item.remedy}")

    if len(outcome.required_evidence):
        add("")
        add(f"  REQUIRED EVIDENCE ({len(outcome.required_evidence)} item(s))")
        for item in outcome.required_evidence:
            flag = "" if item.monotone else "  (can be undone by later evidence)"
            add(f"    [{item.effect.value:>8}]  {item.what}{flag}")
        add(f"    {outcome.required_evidence.note}")

    add("")
    if outcome.assessment.status is AssessmentStatus.METHODOLOGY_REQUIRED:
        add("  METHODOLOGY_REQUIRED")
        add("    Structural assurance is complete as far as it goes. Whether this is")
        add("    ENOUGH evidence for the decision is a domain question, and no")
        add("    methodology was supplied — so domain sufficiency is NOT_ASSESSED.")
        add("    release-gate will not invent a universal standard to close that gap.")
        add("")
        add("    Supply one with --methodology, or see:")
        add("      release-gate assure --list-methodologies")
    add(f"  Decision: {_DECISION_MARK[outcome.decision]} "
        f"(rules: {', '.join(case.verdict.fired_rules)})")
    add("=" * 78)
    add("")
    return "\n".join(lines)
