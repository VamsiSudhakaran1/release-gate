"""Model-assisted semantic processing — proposals, never decisions.

Some questions release-gate needs answered are not decidable by structure.
Whether two claims say the same thing, which of forty thousand records bear on
one lemma, whether a paragraph of prose asserts something that contradicts a
measurement — these are reading problems, and a model is good at them where a
digest comparison is useless. Refusing the help would not make the engine more
rigorous; it would make it blind to things a reviewer can see at a glance.

What the help must not do is decide. So one shape governs this module:

    **a model proposes; the deterministic path disposes.**

A `SemanticProposal` is a candidate. It enters the case as `DERIVED` evidence
through the same seam as any other model output, it names the model and version
that produced it, it names the records the model was shown, and it is never
applied to anything. `applied` returns `False` unconditionally. A clustering
proposal does not make two claims equivalent — `Claim.equivalent_to` is
"declared, never inferred" and stays that way; the proposal sits beside it as a
candidate for a human or a deterministic check to accept or reject.

**Confidence is recorded and never read.** `model_reported_confidence` travels
with the proposal because hiding it would be dishonest — the producer said it,
and a reviewer may want to know. Nothing in this module or any other compares
it, sorts on it, thresholds it, or lets it change a state. There is deliberately
no ordering over proposals and no "best candidate", because a mechanism that
acts above 0.9 has made a model's self-assessment authoritative, which is the
one thing this module exists to prevent.

**Every proposal names what it read.** `read_from` is required and a proposal
without it is refused. A model saying "these two claims are duplicates" is worth
considering; a model saying so without naming the two claims is an opinion with
nothing under it, and a reviewer cannot check it. That is the inspectability
requirement, and it is a constructor error rather than a convention.

**The deterministic path comes first where there is one.** Four of the seven
tasks have a deterministic counterpart that release-gate already implements —
exact-digest duplicates, structural contradiction detection, the claim/evidence
index, declared equivalence. `DETERMINISTIC_COUNTERPART` names them, and
`deterministic_first()` runs the deterministic answer so a proposal can be
reported as confirming it, extending it, or disagreeing with it. Three tasks —
extraction, explanation, summarisation — have none, and the table says so rather
than implying a check happened.

**A methodology decides whether a model's reading counts as verification.**
It is `AssuranceMethodology.model_verification`, it defaults to `UNSTATED`, and
`UNSTATED` means no. Nothing in this module can change that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.evidence import EvidenceRecord, EvidenceType
from release_gate.assurance.quality import model_assisted_evidence
from release_gate.assurance.verifiers import ToolFamily, ToolIdentity

__all__ = [
    "DETERMINISTIC_COUNTERPART",
    "SEMANTIC_SCHEMA_VERSION",
    "DeterministicCounterpart",
    "DeterministicOutcome",
    "ProposalDisposition",
    "SemanticError",
    "SemanticProposal",
    "SemanticTask",
    "deterministic_first",
    "model_identity",
    "proposals_to_records",
]

SEMANTIC_SCHEMA_VERSION = 1


class SemanticError(ValueError):
    """A proposal was constructed in a state a reviewer could not check."""


class SemanticTask(str, Enum):
    """The reading problems a model is allowed to help with.

    Enumerated rather than free-form, because each has a different relationship
    to a deterministic answer and a different consequence if it is wrong. A
    duplicate-claim proposal that is wrong inflates coverage; a summarisation
    that is wrong misleads a reader but changes no computation. Those are not the
    same risk and should not share a name.
    """

    CLAIM_EXTRACTION = "CLAIM_EXTRACTION"
    CLAIM_CLUSTERING = "CLAIM_CLUSTERING"
    DUPLICATE_CANDIDATE = "DUPLICATE_CANDIDATE"
    EVIDENCE_RETRIEVAL = "EVIDENCE_RETRIEVAL"
    CONTRADICTION_CANDIDATE = "CONTRADICTION_CANDIDATE"
    EXPLANATION = "EXPLANATION"
    SUMMARISATION = "SUMMARISATION"


class ProposalDisposition(str, Enum):
    """What became of a proposal. `PROPOSED` is where every one starts.

    There is no value meaning "applied automatically", and that absence is the
    design. A proposal moves out of `PROPOSED` because a deterministic check
    agreed with it or a person accepted it — both of which are acts by something
    other than the model that made it.
    """

    PROPOSED = "PROPOSED"
    CONFIRMED_DETERMINISTICALLY = "CONFIRMED_DETERMINISTICALLY"
    CONFIRMED_BY_HUMAN = "CONFIRMED_BY_HUMAN"
    REJECTED = "REJECTED"
    NOT_ACTED_ON = "NOT_ACTED_ON"   # seen, left standing, and recorded as such


class DeterministicOutcome(str, Enum):
    """How a proposal stood against the deterministic answer."""

    AGREES = "AGREES"              # the deterministic path found the same thing
    EXTENDS = "EXTENDS"            # beyond what structure could reach
    DISAGREES = "DISAGREES"        # structure found the opposite
    NO_COUNTERPART = "NO_COUNTERPART"   # no deterministic answer exists for this
    NOT_RUN = "NOT_RUN"            # one exists and was not run


@dataclass(frozen=True)
class DeterministicCounterpart:
    """The non-model way to answer a task, where there is one.

    `note` is what the deterministic path can and cannot reach, which is the
    honest reason a model is being asked at all. Exact-digest duplicate detection
    is complete for identical statements and finds nothing for two sentences that
    mean the same thing — saying that plainly is better than implying either
    that the model is redundant or that the structure is useless.
    """

    task: SemanticTask
    available: bool
    mechanism: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"task": self.task.value, "available": self.available,
                "mechanism": self.mechanism, "note": self.note}


#: What release-gate can answer without a model, per task. Four of seven.
DETERMINISTIC_COUNTERPART: Mapping[SemanticTask, DeterministicCounterpart] = {
    SemanticTask.CLAIM_EXTRACTION: DeterministicCounterpart(
        SemanticTask.CLAIM_EXTRACTION, available=False,
        note="claims arrive declared or they do not arrive; there is no structural "
             "way to read a proposition out of prose, which is exactly why this "
             "task is on the list"),
    SemanticTask.CLAIM_CLUSTERING: DeterministicCounterpart(
        SemanticTask.CLAIM_CLUSTERING, available=True,
        mechanism="Claim.equivalent_to — declared equivalence, never inferred",
        note="declared equivalence is exact and covers only what somebody wrote "
             "down; two claims nobody linked stay unlinked however alike they read"),
    SemanticTask.DUPLICATE_CANDIDATE: DeterministicCounterpart(
        SemanticTask.DUPLICATE_CANDIDATE, available=True,
        mechanism="statement equality over the claims collection",
        note="identical statements are found completely and cheaply; two "
             "statements that differ by a word are invisible to it"),
    SemanticTask.EVIDENCE_RETRIEVAL: DeterministicCounterpart(
        SemanticTask.EVIDENCE_RETRIEVAL, available=True,
        mechanism="supports_claims / contradicts_claims on the evidence records",
        note="the declared index is exact and complete for evidence that named "
             "its claims; evidence that bears on a claim without saying so is not "
             "in it"),
    SemanticTask.CONTRADICTION_CANDIDATE: DeterministicCounterpart(
        SemanticTask.CONTRADICTION_CANDIDATE, available=True,
        mechanism="contradiction.detect_contradictions — structural detection",
        note="evidence pointing both ways at one claim, and checks that disagree, "
             "are found structurally; two records whose PROSE conflicts while "
             "their links agree are not"),
    SemanticTask.EXPLANATION: DeterministicCounterpart(
        SemanticTask.EXPLANATION, available=False,
        note="release-gate renders what it found; turning that into prose for a "
             "particular reader is not a structural operation and is not claimed "
             "to be one"),
    SemanticTask.SUMMARISATION: DeterministicCounterpart(
        SemanticTask.SUMMARISATION, available=False,
        note="compaction reduces a case deterministically and by stated retention "
             "rules (§10j); summarising in prose is a different act and this is "
             "not it"),
}


def model_identity(name: str, *, version: str = "", digest: Optional[str] = None,
                   invocation: str = "", established: bool = False) -> ToolIdentity:
    """A model's identity, in the same shape every other tool gets.

    Deliberately `ToolIdentity` rather than a model-specific type. The questions
    are identical — which one, which version, was that established or asserted,
    is it pinned by content — and a parallel class would have to answer them
    again and would drift. `established=False` is the honest default: a model
    name in a payload is a claim about which model ran, and release-gate did not
    watch it run.
    """
    return ToolIdentity(name=name, version=version, family=ToolFamily.LANGUAGE_MODEL,
                        digest=digest, invocation=invocation, established=established)


@dataclass(frozen=True)
class SemanticProposal:
    """One thing a model proposes, and everything needed to check it.

    Frozen and content-addressed like every other record here, so the same
    proposal submitted twice is one proposal and a reviewer quoting an id is
    quoting exact content.
    """

    task: SemanticTask
    model: ToolIdentity
    read_from: Tuple[str, ...]           # the records the model was shown
    proposes: Mapping[str, Any] = field(default_factory=dict)
    subjects: Tuple[str, ...] = ()       # what the proposal is about
    rationale: str = ""
    model_reported_confidence: Optional[float] = None
    disposition: ProposalDisposition = ProposalDisposition.PROPOSED
    deterministic: DeterministicOutcome = DeterministicOutcome.NOT_RUN
    deterministic_detail: str = ""
    disposed_by: str = ""
    schema_version: int = SEMANTIC_SCHEMA_VERSION

    proposal_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "task", SemanticTask(self.task))
        object.__setattr__(self, "disposition", ProposalDisposition(self.disposition))
        object.__setattr__(self, "deterministic",
                           DeterministicOutcome(self.deterministic))
        object.__setattr__(self, "read_from", tuple(dict.fromkeys(self.read_from)))
        object.__setattr__(self, "subjects", tuple(dict.fromkeys(self.subjects)))

        if not isinstance(self.model, ToolIdentity):
            raise SemanticError(
                "a proposal must name the model that produced it, as a ToolIdentity; "
                "an unattributed reading cannot be weighed, repeated or withdrawn")
        if not self.read_from:
            raise SemanticError(
                f"{self.task.value}: read_from is required. A model's reading is "
                "worth considering when a reviewer can go and look at what it read; "
                "without that it is an opinion with nothing under it, and no "
                "confidence value substitutes for the link (Invariant 1)")
        if self.model_reported_confidence is not None:
            value = float(self.model_reported_confidence)
            if not 0.0 <= value <= 1.0:
                raise SemanticError(
                    f"model_reported_confidence {value} is outside 0..1; it is "
                    "recorded as the producer stated it and read by nothing, but a "
                    "value outside the range it claims to be in is a malformed "
                    "record rather than a bold one")
            object.__setattr__(self, "model_reported_confidence", value)
        if (self.disposition in (ProposalDisposition.CONFIRMED_BY_HUMAN,
                                 ProposalDisposition.REJECTED)
                and not str(self.disposed_by or "").strip()):
            raise SemanticError(
                f"{self.disposition.value} requires disposed_by: a proposal accepted "
                "or rejected by nobody in particular is a decision with no author, "
                "which is the thing an approval exists to prevent")
        object.__setattr__(self, "proposal_id",
                           short_id("prop", digest_object(self.identity())))

    # ── refusals ───────────────────────────────────────────────────────────

    @property
    def applied(self) -> bool:
        """Unconditionally False. A proposal changes nothing by existing.

        Not a mutable flag that happens to start false: there is no code path
        that sets it, because the moment one exists, the next reader assumes a
        confirmed proposal is applied and stops checking.
        """
        return False

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False, at every disposition including confirmed."""
        return False

    @property
    def confidence_is_authoritative(self) -> bool:
        """Unconditionally False. Recorded, never read."""
        return False

    # ── reading ────────────────────────────────────────────────────────────

    @property
    def counterpart(self) -> DeterministicCounterpart:
        return DETERMINISTIC_COUNTERPART[self.task]

    @property
    def awaiting_disposition(self) -> bool:
        return self.disposition is ProposalDisposition.PROPOSED

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct proposal. Disposition is excluded.

        A proposal accepted by a person is the same proposal it was before; what
        changed is what somebody did about it. Folding that into the id would mean
        the record a reviewer approved no longer exists under the id they quoted.
        """
        return {"schema_version": self.schema_version, "task": self.task.value,
                "model": self.model.to_dict(), "read_from": list(self.read_from),
                "subjects": list(self.subjects),
                "proposes": dict(self.proposes), "rationale": self.rationale,
                "model_reported_confidence": self.model_reported_confidence}

    def dispose(self, disposition: ProposalDisposition, *, by: str = "",
                detail: str = "") -> "SemanticProposal":
        """Record what was decided about this proposal, without changing it."""
        import dataclasses
        return dataclasses.replace(
            self, disposition=disposition, disposed_by=by,
            deterministic_detail=detail or self.deterministic_detail)

    def note(self) -> str:
        counterpart = self.counterpart
        lines = [f"{self.task.value} proposed by {self.model.reference}",
                 f"  read: {', '.join(self.read_from[:6])}"
                 + (f" (+{len(self.read_from) - 6} more)"
                    if len(self.read_from) > 6 else ""),
                 f"  disposition: {self.disposition.value}",
                 f"  deterministic: {self.deterministic.value}"
                 + (f" — {self.deterministic_detail}" if self.deterministic_detail
                    else "")]
        if not counterpart.available:
            lines.append(f"  no deterministic counterpart: {counterpart.note}")
        if self.model_reported_confidence is not None:
            lines.append(
                f"  the model reported {self.model_reported_confidence} confidence; "
                "release-gate records that and reads nothing from it")
        lines.append("  This is a proposal. It has not been applied to anything.")
        return "\n".join(lines)

    @property
    def record_type(self) -> str:
        return "semantic_proposal"

    @property
    def record_id(self) -> str:
        return self.proposal_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": self.record_type, "record_id": self.proposal_id,
            "proposal_id": self.proposal_id, "task": self.task.value,
            "model": self.model.to_dict(), "model_reference": self.model.reference,
            "model_identity_established": self.model.established,
            "read_from": list(self.read_from), "subjects": list(self.subjects),
            "proposes": dict(self.proposes), "rationale": self.rationale,
            "model_reported_confidence": self.model_reported_confidence,
            "disposition": self.disposition.value, "disposed_by": self.disposed_by,
            "deterministic": self.deterministic.value,
            "deterministic_detail": self.deterministic_detail,
            "deterministic_counterpart": self.counterpart.to_dict(),
            # Stated, not merely absent — see `quality.FactSheet.to_dict`.
            "applied": False, "establishes_truth": False,
            "confidence_is_authoritative": False,
            "schema_version": self.schema_version,
        }


# ── the deterministic path, run first ───────────────────────────────────────

def _claim_records(case: AssuranceCase) -> Dict[str, Mapping[str, Any]]:
    out: Dict[str, Mapping[str, Any]] = {}
    for record in case.records("claims"):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        key = str(payload.get("claim_id") or payload.get("record_id") or "")
        if key:
            out[key] = payload
    return out


def _deterministic_duplicates(case: AssuranceCase,
                              subjects: Sequence[str]) -> Tuple[bool, str]:
    """Do these claims have identical statements?

    Complete for exact matches and blind to everything else, which is the whole
    reason a model is being asked. Returns whether structure found them the same
    and what it looked at.
    """
    claims = _claim_records(case)
    statements = {s: str(claims[s].get("statement") or "")
                  for s in subjects if s in claims}
    missing = [s for s in subjects if s not in claims]
    if missing or len(statements) < 2:
        return False, (f"{len(statements)} of {len(subjects)} named claim(s) are in "
                       "this case, so statement equality could not be asked")
    distinct = set(statements.values())
    if len(distinct) == 1:
        return True, "the named claims have identical statements"
    return False, ("the named claims have different statements; exact equality "
                   "cannot see whether they mean the same thing")


def _deterministic_equivalence(case: AssuranceCase,
                               subjects: Sequence[str]) -> Tuple[bool, str]:
    """Has somebody DECLARED these claims equivalent?"""
    claims = _claim_records(case)
    for subject in subjects:
        declared = {str(e) for e in (claims.get(subject, {}).get("equivalent_to") or ())}
        if declared & {s for s in subjects if s != subject}:
            return True, f"{subject} declares equivalence to another named claim"
    return False, ("no claim declares equivalence to another here; declared "
                   "equivalence is exact and covers only what somebody wrote down")


def _deterministic_retrieval(case: AssuranceCase,
                             subjects: Sequence[str]) -> Tuple[bool, str]:
    """What does the declared index already say bears on these claims?"""
    found: List[str] = []
    for record in case.records("evidence"):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        if str(payload.get("record_type") or "") != "evidence":
            continue
        linked = {*(payload.get("supports_claims") or ()),
                  *(payload.get("contradicts_claims") or ())}
        if linked & set(subjects):
            found.append(str(payload.get("record_id") or ""))
    if found:
        return True, (f"the declared index already links {len(found)} record(s) to "
                      "the named claim(s)")
    return False, ("nothing in the declared index names these claims; evidence that "
                   "bears on a claim without saying so is not in it")


def _deterministic_contradiction(case: AssuranceCase, subjects: Sequence[str],
                                 analysis: Any) -> Tuple[bool, str]:
    """Did structural detection already find a disagreement here?"""
    ledger = getattr(analysis, "contradictions", None) if analysis else None
    if ledger is None:
        return False, ("no contradiction ledger was produced, so structural "
                       "detection did not run over this case")
    for contradiction in ledger.open():
        targets = {str(c) for c in (getattr(contradiction, "target_claims", ()) or ())}
        if targets & set(subjects):
            return True, (f"structural detection already holds an open contradiction "
                          f"on {', '.join(sorted(targets & set(subjects)))}")
    return False, ("structural detection found no open contradiction on the named "
                   "claims; prose that conflicts while the links agree is outside "
                   "what it can see")


def deterministic_first(proposal: SemanticProposal, *, case: AssuranceCase,
                        analysis: Any = None) -> SemanticProposal:
    """Run the deterministic answer and record how the proposal stood against it.

    The ordering in the name is the point. Where structure can answer, it answers
    first and the model's reading is reported as agreeing with it, reaching past
    it, or disagreeing with it — which is a far more useful thing to hand a
    reviewer than a proposal on its own. Where structure cannot answer,
    `NO_COUNTERPART` says so plainly, and the proposal is not dressed up as
    having survived a check that never ran.

    `AGREES` is not a promotion. A proposal that the deterministic path also
    found is confirmed as a *finding*, and its disposition moves to
    `CONFIRMED_DETERMINISTICALLY` — but `establishes_truth` and `applied` are
    still `False`, because what was confirmed is that two methods agree, not that
    the thing is so.
    """
    import dataclasses

    counterpart = DETERMINISTIC_COUNTERPART[proposal.task]
    if not counterpart.available:
        return dataclasses.replace(
            proposal, deterministic=DeterministicOutcome.NO_COUNTERPART,
            deterministic_detail=counterpart.note)

    if proposal.task is SemanticTask.DUPLICATE_CANDIDATE:
        agreed, detail = _deterministic_duplicates(case, proposal.subjects)
    elif proposal.task is SemanticTask.CLAIM_CLUSTERING:
        agreed, detail = _deterministic_equivalence(case, proposal.subjects)
    elif proposal.task is SemanticTask.EVIDENCE_RETRIEVAL:
        agreed, detail = _deterministic_retrieval(case, proposal.subjects)
    else:
        agreed, detail = _deterministic_contradiction(case, proposal.subjects, analysis)

    if agreed:
        return dataclasses.replace(
            proposal, deterministic=DeterministicOutcome.AGREES,
            deterministic_detail=detail,
            disposition=(ProposalDisposition.CONFIRMED_DETERMINISTICALLY
                         if proposal.awaiting_disposition else proposal.disposition))
    # Not disagreement: structure looked and found nothing, which for every
    # counterpart here means "outside what I can see" rather than "not so". A
    # model reaching past a method's blind spot is the case for asking it, and
    # calling that DISAGREES would make the useful answer look like a conflict.
    return dataclasses.replace(
        proposal, deterministic=DeterministicOutcome.EXTENDS,
        deterministic_detail=detail)


# ── entering the case ───────────────────────────────────────────────────────

def proposals_to_records(proposals: Iterable[SemanticProposal]
                         ) -> List[EvidenceRecord]:
    """Proposals as evidence records, through the one model seam there is.

    Not a second entry path: `model_assisted_evidence` is where a model's output
    becomes a case record, and it is what guarantees `DERIVED` and refuses any
    argument that would raise the status. Everything this function adds is the
    proposal's own structure — task, subjects, disposition, what the
    deterministic path said — carried in the content where a reviewer can read it.

    `parent_evidence` is the proposal's `read_from`, so the records the model was
    shown become the record's ancestry. That is what puts a model's output where
    the independence analysis can see it: a hundred proposals derived from one
    source are one lineage, and they show up as one (Invariant 6). That holds
    only while `read_from` names records the analysis counts — it excludes
    release-gate's own, so a proposal pointed at the input artifact release-gate
    hashed is correctly its own root rather than a member of anything.

    **These records are `DERIVED` in process and `DECLARED` over the wire**, and
    the difference is not a bug to route around. `epistemic_status` is one of the
    fields a producer may not set, so the same content submitted through the
    envelope arrives as a declaration — which is *weaker* than what this function
    returns, not stronger. A caller building a case in process gets DERIVED
    because release-gate did the deriving; a caller posting JSON gets DECLARED
    because release-gate has only their word for it. Neither is authoritative,
    and nothing about a model's output should be able to travel upward.
    """
    out: List[EvidenceRecord] = []
    for proposal in proposals:
        out.append(model_assisted_evidence(
            model=proposal.model.reference,
            classification=f"{proposal.task.value}: {proposal.rationale}"
                           if proposal.rationale else proposal.task.value,
            source=f"semantic:{proposal.task.value.lower()}",
            parent_evidence=proposal.read_from,
            evidence_type=EvidenceType.CLAIM_DERIVATION,
            content={"semantic_proposal": proposal.to_dict()},
            coverage_note=(
                f"a model's reading of {len(proposal.read_from)} record(s), "
                f"{proposal.disposition.value.lower().replace('_', ' ')}; it covers "
                "what those records cover and establishes nothing beyond them")))
    return out
