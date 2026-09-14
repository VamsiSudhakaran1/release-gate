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
from release_gate.assurance.consequence import (
    ConsequenceProfile, ConsequenceRegistry, default_consequence_registry,
)
from release_gate.assurance.case import (
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
from release_gate.assurance.records import MaterialisationBasis, SimpleRecord
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

    @property
    def decision(self) -> Decision:
        return self.case.verdict.decision if self.case.verdict else Decision.HOLD

    @property
    def detection(self) -> Detection:
        return self.normalisation.detection

    @property
    def capabilities(self) -> Optional[CapabilitySurface]:
        """What the system reached for. Evidence on the case, not a verdict input."""
        return self.normalisation.capabilities

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
            "attention": self.attention.to_dict(),
            "required_evidence": self.required_evidence.to_dict(),
            "ruleset_version": ZERO_CONFIG_RULESET_VERSION,
        }


# ── case construction ────────────────────────────────────────────────────────

def _coverage_row(dimension: str, assessed: bool, note: str,
                  **observed: Any) -> SimpleRecord:
    """One statement of what was and was not assessed.

    `assessed=False` is a `NOT_ASSESSED` row — a first-class result, never an
    omission and never a zero.
    """
    return SimpleRecord(
        record_type="coverage", record_id=f"cov_{dimension}",
        payload={"dimension": dimension,
                 "status": "ASSESSED" if assessed else "NOT_ASSESSED",
                 "note": note, **observed})


def _ingest_coverage(normalisation: Normalisation,
                     consequence: ConsequenceProfile) -> List[SimpleRecord]:
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
                      seen=normalisation.records_seen,
                      mapped=normalisation.records_mapped,
                      skipped=normalisation.skipped_total),
        _coverage_row("execution_reconstruction", normalisation.execution is not None,
                      ("execution graph reconstructed from the input"
                       if normalisation.execution is not None else
                       "no execution telemetry was present in this input")),
        _capability_coverage(normalisation.capabilities),
        _consequence_coverage(consequence),
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


def _analysis_records(analysis: AnalysisResult) -> Tuple[List[Finding], List[SimpleRecord]]:
    contradictions = [f for f in analysis.findings
                      if f.domain is AnalysisDomain.CONTRADICTION]
    rows = [
        _coverage_row(
            "structural_analysis", True,
            f"{len(analysis.findings)} structural finding(s) under ruleset "
            f"{ANALYSIS_RULESET_VERSION}",
            findings=len(analysis.findings),
            blocking=len(analysis.blocking), holding=len(analysis.holding)),
    ]
    for domain in (AnalysisDomain.PROVENANCE, AnalysisDomain.VERIFICATION,
                   AnalysisDomain.DRIFT, AnalysisDomain.CONTRADICTION):
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

    verifications = [r for r in normalisation.evidence if r.is_verification]
    builder.declare_present(
        "verification",
        "the ingest looked for typed verification in this input"
        if not verifications else "typed verification found in this input")
    builder.extend("verification", verifications)

    builder.collection("coverage", basis=MaterialisationBasis.COMPLETE)
    builder.extend("coverage", _ingest_coverage(normalisation, consequence))

    for kind, records in (extra or {}).items():
        builder.declare_present(kind, "produced by the zero-config analysis")
        builder.extend(kind, records)

    return builder.build()


def _subject_for(path: Path, normalisation: Normalisation,
                 requested_action: str) -> AssuranceSubject:
    reference, digest = file_content(path)
    return AssuranceSubject(
        subject_type=subject_type_for(normalisation.detection.kind),
        requested_action=requested_action, content_reference=reference, digest=digest,
        digest_method=DigestMethod.SHA256_CONTENT, digest_status=DigestStatus.OBSERVED,
        digest_basis="sha256 over the input file's bytes, computed by release-gate",
        metadata={"filename": path.name,
                  "detected_kind": normalisation.detection.kind.value})


# ── the decision ─────────────────────────────────────────────────────────────

def decide(analysis: AnalysisResult, assessment: MethodologyAssessment, *,
           has_methodology: bool) -> CaseVerdict:
    """Compose structural findings and methodology assessment into one verdict.

    The ordering is deliberate. Structural BLOCKs come first because they are
    facts about the evidence that no methodology can wave through: a case whose
    own evidence refutes it is not made sound by a yardstick that does not
    mention refutation.

    Then sufficiency. With no methodology the answer is HOLD and the reason is
    `METHODOLOGY_REQUIRED` — never PROMOTE, and never a silently generous
    default. That branch is the whole point of this module.
    """
    fired: List[str] = []
    reasons: List[str] = []

    blocking = analysis.blocking
    holding = analysis.holding
    decision = Decision.HOLD

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

    if holding and decision is Decision.HOLD and RULE_STRUCTURAL_HOLD not in fired:
        fired.append(RULE_STRUCTURAL_HOLD)
        reasons.extend(f"{f.rule_id}: {f.summary}" for f in holding)

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
    normalisation = ingest_path(source)

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
        consequence=consequence,
        extra={"contradictions": contradictions, "coverage": coverage_rows})

    assessment = assess(analysed, methodology)

    attention = build_attention(analysed, analysis, assessment)
    required = build_required_evidence(analysed, analysis, assessment)

    # Attention and required evidence are release-gate's own conclusions, folded in
    # for the record only. They are deliberately not present when the methodology
    # is assessed: a yardstick judges the evidence in a case, never the engine's
    # reading of that evidence.
    final = _build_case(
        subject, normalisation, objective=objective,
        requested_decision=requested_decision, methodology=methodology,
        consequence=consequence,
        extra={"contradictions": contradictions,
               "coverage": coverage_rows,
               "attention_items": list(attention.items),
               "required_evidence": list(required.items)})

    verdict = decide(analysis, assessment, has_methodology=methodology is not None)
    decided = final.seal().render_verdict(verdict)

    return AssuranceOutcome(case=decided, normalisation=normalisation,
                            analysis=analysis, assessment=assessment,
                            attention=attention, required_evidence=required,
                            consequence=consequence)


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
