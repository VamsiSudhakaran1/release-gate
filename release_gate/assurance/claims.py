"""ClaimGraph — what is being asserted, and how well each assertion stands.

The execution graph answers *what happened*. This answers *what is being claimed
about it*, which is a different question with a different shape: propositions
resting on other propositions, supported and refuted by evidence, and capped by
the assumptions they depend on.

**Status is computed, never declared.** A producer supplies a claim's statement,
its dependencies and its evidence links. It does not supply the status — that is
derived on every build from the evidence actually present, which is what stops
"I verified this" from being the thing that makes something verified
(Invariants 1 and 2).

**A conclusion cannot outrank its assumptions.** Each claim carries two values: a
`direct_status` from evidence about the claim itself, and an `inherited_ceiling`
that is the weakest status among everything it DEPENDS_ON. The effective status is
the lower of the two. A machine-checked proof resting on an unproven lemma is not
verified, however good the proof — and expressing that as a minimum rather than a
warning is what makes it impossible to lose.

The distinction between `DEPENDS_ON` and `SUPPORTS` carries that rule. Depending
on something means the conclusion rests on it and is capped by it; supporting
means corroborating without carrying. The producer chooses, and the choice is
visible in the graph rather than inferred.

**No model is in the authoritative path.** Claims are matched by explicit id and
nothing else: there is no fuzzy matching, no semantic clustering, no
natural-language comparison. Model-assisted extraction is supported and its claims
carry `DERIVED` provenance, are listed separately, and — critically — any
equivalence those claims assert is recorded without being applied. A model may
propose that two statements mean the same thing; it may not make them the same
thing in a computation that gates a release (Invariant 4).

**Failed attempts are kept and count.** A verification that ran and rejected is a
refutation; one that ran and could not tell is an inconclusive attempt. Both stay
on the claim, and both move its status. A graph that recorded only successes would
make every case look like its best branch (Invariant 7).

The graph is optional. A migration case with one artifact and one action has
nothing to model here, and `from_case` returns `None` rather than an empty graph.
"""

from __future__ import annotations

import dataclasses
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Tuple)

from release_gate.assurance.canonical import (
    CanonicalisationError,
    digest_object,
    freeze_value,
    short_id,
    thaw_value,
)
from release_gate.assurance.case import AssuranceCase
from release_gate.assurance.verification import (
    VerificationAttempt,
    VerificationStatus,
    VerificationTarget,
)
from release_gate.assurance.evidence import (
    EpistemicStatus,
    EvidenceRecord,
    Producer,
    VerificationMethod,
)
from release_gate.assurance.records import Presence
from release_gate.assurance.subject import ContentReference

CLAIM_SCHEMA_VERSION = 1

#: Historical name for the attempt vocabulary. It is now `VerificationStatus`,
#: which is a superset: the old three values could not express a check that was
#: expected and never ran, or one whose result was later retracted. Kept as an
#: alias so existing callers and stored records keep working.
AttemptOutcome = VerificationStatus


class ClaimType(str, Enum):
    ASSERTION = "ASSERTION"          # a plain statement about the world
    LEMMA = "LEMMA"                  # an intermediate result others rest on
    ASSUMPTION = "ASSUMPTION"        # taken as given; load-bearing by nature
    CONCLUSION = "CONCLUSION"        # what the case is ultimately asking about
    MEASUREMENT = "MEASUREMENT"      # a recorded quantity
    RECOMMENDATION = "RECOMMENDATION"
    REQUIREMENT_SATISFACTION = "REQUIREMENT_SATISFACTION"
    OTHER = "OTHER"


class ClaimStatus(str, Enum):
    """How well a proposition stands. Computed from evidence and dependencies."""

    REFUTED = "REFUTED"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"                        # nothing bears on it at all
    UNVERIFIED = "UNVERIFIED"                  # evidence exists; none of it verifies
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"  # some attempts passed, others did not settle
    VERIFIED = "VERIFIED"
    SUPERSEDED = "SUPERSEDED"                  # a later claim replaced it


class ClaimProvenance(str, Enum):
    """Who produced the claim itself, as distinct from the evidence for it."""

    DECLARED = "DECLARED"   # a producing system stated it
    HUMAN = "HUMAN"         # a person wrote it
    DERIVED = "DERIVED"     # model-assisted extraction; never authoritative alone


class ClaimEdgeType(str, Enum):
    DEPENDS_ON = "DEPENDS_ON"        # caps the parent's status at the child's
    SUPPORTS = "SUPPORTS"            # corroborates without carrying
    CONTRADICTS = "CONTRADICTS"
    DERIVED_FROM = "DERIVED_FROM"
    SUPERSEDES = "SUPERSEDES"
    EQUIVALENT_TO = "EQUIVALENT_TO"  # declared, never inferred


class ClaimError(ValueError):
    """A claim was constructed in a state that cannot be reasoned about."""


#: Weakest to strongest. The ordering that makes "a conclusion cannot outrank its
#: assumptions" a minimum rather than a warning. SUPERSEDED sits outside it.
_STATUS_ORDER: Mapping[ClaimStatus, int] = {
    ClaimStatus.REFUTED: 0,
    ClaimStatus.DISPUTED: 1,
    ClaimStatus.UNKNOWN: 2,
    ClaimStatus.UNVERIFIED: 3,
    ClaimStatus.PARTIALLY_VERIFIED: 4,
    ClaimStatus.VERIFIED: 5,
}

#: How much evidential weight each epistemic status carries when supporting or
#: refuting a claim. Only VERIFIED evidence can make a claim VERIFIED.
_EVIDENCE_WEIGHT: Mapping[EpistemicStatus, int] = {
    EpistemicStatus.NOT_ASSESSED: 0,
    EpistemicStatus.UNKNOWN: 0,
    EpistemicStatus.DECLARED: 1,
    EpistemicStatus.OBSERVED: 2,
    EpistemicStatus.DERIVED: 2,
    EpistemicStatus.DISPUTED: 2,
    EpistemicStatus.REFUTED: 3,
    EpistemicStatus.VERIFIED: 3,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def link_evidence(claims: Iterable[Claim],
                  evidence: Mapping[str, EvidenceRecord]) -> List[Claim]:
    """Fold each record's claim references back onto the claims themselves.

    Evidence declares which claims it supports or contradicts; a claim written
    before that evidence existed cannot have listed it. Both directions end up on
    the claim so the status calculus has one place to look.
    """
    materialised = list(claims)
    supporting: Dict[str, List[str]] = defaultdict(list)
    contradicting: Dict[str, List[str]] = defaultdict(list)
    known = {c.claim_id for c in materialised}
    for record in evidence.values():
        for claim_id in record.supports_claims:
            if claim_id in known:
                supporting[claim_id].append(record.evidence_id)
        for claim_id in record.contradicts_claims:
            if claim_id in known:
                contradicting[claim_id].append(record.evidence_id)

    linked: List[Claim] = []
    for claim in materialised:
        extra_support = [e for e in supporting.get(claim.claim_id, ())
                         if e not in claim.supporting_evidence]
        extra_against = [e for e in contradicting.get(claim.claim_id, ())
                         if e not in claim.contradicting_evidence]
        if not extra_support and not extra_against:
            linked.append(claim)
            continue
        linked.append(dataclasses.replace(
            claim,
            supporting_evidence=claim.supporting_evidence + tuple(extra_support),
            contradicting_evidence=claim.contradicting_evidence + tuple(extra_against)))
    return linked


def weakest(statuses: Iterable[ClaimStatus]) -> Optional[ClaimStatus]:
    ranked = [s for s in statuses if s in _STATUS_ORDER]
    return min(ranked, key=lambda s: _STATUS_ORDER[s]) if ranked else None


@dataclass(frozen=True)
class Claim:
    """One proposition. Its status is computed by the graph, never set here."""

    claim_id: str
    statement: str
    claim_type: ClaimType = ClaimType.ASSERTION
    producer: Optional[Producer] = None
    provenance: ClaimProvenance = ClaimProvenance.DECLARED
    statement_reference: Optional[ContentReference] = None
    parents: Tuple[str, ...] = ()          # DEPENDS_ON: this claim rests on them
    supports: Tuple[str, ...] = ()         # corroborates without carrying
    assumptions: Tuple[str, ...] = ()      # DEPENDS_ON, and flagged as assumptions
    supporting_evidence: Tuple[str, ...] = ()
    contradicting_evidence: Tuple[str, ...] = ()
    verification_attempts: Tuple[VerificationAttempt, ...] = ()
    equivalent_to: Tuple[str, ...] = ()    # declared equivalence only
    supersedes: Optional[str] = None
    criticality: Optional[str] = None      # None means nobody assigned one
    is_root: bool = False
    extracted_by_model: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = CLAIM_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_type", ClaimType(self.claim_type))
        object.__setattr__(self, "provenance", ClaimProvenance(self.provenance))
        for name in ("parents", "supports", "assumptions", "supporting_evidence",
                     "contradicting_evidence", "equivalent_to"):
            object.__setattr__(self, name, tuple(dict.fromkeys(getattr(self, name))))
        object.__setattr__(self, "verification_attempts", tuple(self.verification_attempts))

        if not (self.claim_id or "").strip():
            raise ClaimError("claim_id is required")
        if not (self.statement or "").strip():
            raise ClaimError(
                f"{self.claim_id}: a claim must state something. A proposition nobody "
                "wrote down cannot be verified, disputed, or put to a reviewer.")
        object.__setattr__(self, "statement", self.statement.strip())

        if self.provenance is ClaimProvenance.DERIVED and not self.extracted_by_model:
            raise ClaimError(
                f"{self.claim_id}: a DERIVED claim must name the model that extracted it. "
                "Model-assisted extraction is supported; unattributed extraction is not "
                "(Invariant 4).")
        if self.extracted_by_model and self.provenance is not ClaimProvenance.DERIVED:
            raise ClaimError(
                f"{self.claim_id}: a claim extracted by {self.extracted_by_model} carries "
                "DERIVED provenance, whatever else it is labelled")

        overlap = set(self.supporting_evidence) & set(self.contradicting_evidence)
        if overlap:
            raise ClaimError(
                f"{self.claim_id}: evidence {sorted(overlap)} is listed as both supporting "
                "and contradicting; split the record into the parts that do each")
        if self.claim_id in set(self.parents) | set(self.assumptions):
            raise ClaimError(f"{self.claim_id}: a claim cannot depend on itself")

        try:
            object.__setattr__(self, "metadata", freeze_value(self.metadata or {}, "metadata"))
        except CanonicalisationError as exc:
            raise ClaimError(f"{self.claim_id} metadata: {exc}") from exc

    # ── the case record protocol ────────────────────────────────────────────

    @property
    def record_id(self) -> str:
        return self.claim_id

    @property
    def record_type(self) -> str:
        return "claim"

    @property
    def depends_on(self) -> Tuple[str, ...]:
        """Everything that caps this claim: declared parents and assumptions alike."""
        return tuple(dict.fromkeys(self.parents + self.assumptions))

    @property
    def is_model_derived(self) -> bool:
        return self.provenance is ClaimProvenance.DERIVED

    def digest(self) -> str:
        return digest_object(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "claim",
            "record_id": self.claim_id,
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "statement": self.statement,
            "claim_type": self.claim_type.value,
            "producer": self.producer.to_dict() if self.producer else None,
            "provenance": self.provenance.value,
            "statement_reference": (self.statement_reference.to_dict()
                                    if self.statement_reference else None),
            "parents": list(self.parents),
            "supports": list(self.supports),
            "assumptions": list(self.assumptions),
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "verification_attempts": [a.to_dict() for a in self.verification_attempts],
            "equivalent_to": list(self.equivalent_to),
            "supersedes": self.supersedes,
            "criticality": self.criticality,
            "is_root": self.is_root,
            "extracted_by_model": self.extracted_by_model,
            "created_at": self.created_at,
            "metadata": thaw_value(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Claim":
        if int(data.get("schema_version", CLAIM_SCHEMA_VERSION)) > CLAIM_SCHEMA_VERSION:
            raise ClaimError(
                f"claim schema version {data['schema_version']} is newer than this reader "
                f"understands ({CLAIM_SCHEMA_VERSION})")
        reference = data.get("statement_reference")
        # A producer-supplied status is ignored on purpose: status is computed
        # from evidence on every build, not carried in the document.
        return cls(
            claim_id=data["claim_id"], statement=data["statement"],
            claim_type=ClaimType(data.get("claim_type", ClaimType.ASSERTION.value)),
            producer=Producer.from_dict(data["producer"]) if data.get("producer") else None,
            provenance=ClaimProvenance(data.get("provenance", ClaimProvenance.DECLARED.value)),
            statement_reference=ContentReference.from_dict(reference) if reference else None,
            parents=tuple(data.get("parents", ())),
            supports=tuple(data.get("supports", ())),
            assumptions=tuple(data.get("assumptions", ())),
            supporting_evidence=tuple(data.get("supporting_evidence", ())),
            contradicting_evidence=tuple(data.get("contradicting_evidence", ())),
            verification_attempts=tuple(VerificationAttempt.from_dict(a)
                                        for a in data.get("verification_attempts", ())),
            equivalent_to=tuple(data.get("equivalent_to", ())),
            supersedes=data.get("supersedes"), criticality=data.get("criticality"),
            is_root=bool(data.get("is_root")),
            extracted_by_model=data.get("extracted_by_model"),
            created_at=data.get("created_at") or _utc_now(),
            metadata=data.get("metadata") or {})

    @classmethod
    def model_extracted(cls, claim_id: str, statement: str, *, model: str,
                        **kwargs: Any) -> "Claim":
        """A claim a model proposed from unstructured output.

        Supported, attributed, and never authoritative on its own. It enters the
        graph as an ordinary claim whose provenance says where it came from, so a
        methodology can require human confirmation before it counts.
        """
        kwargs.pop("provenance", None)
        return cls(claim_id=claim_id, statement=statement,
                   provenance=ClaimProvenance.DERIVED, extracted_by_model=model, **kwargs)


@dataclass(frozen=True)
class ClaimAssessment:
    """The computed standing of one claim."""

    claim_id: str
    direct_status: ClaimStatus
    inherited_ceiling: Optional[ClaimStatus]
    effective_status: ClaimStatus
    basis: str
    supporting: int = 0
    contradicting: int = 0
    unresolved_contradictions: int = 0
    passed_attempts: int = 0
    failed_attempts: int = 0
    inconclusive_attempts: int = 0
    capped_by: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "direct_status": self.direct_status.value,
            "inherited_ceiling": (self.inherited_ceiling.value
                                  if self.inherited_ceiling else None),
            "effective_status": self.effective_status.value,
            "basis": self.basis,
            "supporting": self.supporting,
            "contradicting": self.contradicting,
            "unresolved_contradictions": self.unresolved_contradictions,
            "attempts": {"passed": self.passed_attempts, "failed": self.failed_attempts,
                         "inconclusive": self.inconclusive_attempts},
            "capped_by": list(self.capped_by),
        }


@dataclass(frozen=True)
class ClaimAnomaly:
    kind: str
    detail: str
    claims: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "claims": list(self.claims)}


class ClaimGraph:
    """Claims, their dependencies, and the status each one actually earns."""

    def __init__(self, claims: Iterable[Claim],
                 evidence: Optional[Mapping[str, EvidenceRecord]] = None,
                 *, resolved_contradictions: Iterable[str] = (),
                 notes: Iterable[str] = ()) -> None:
        self._evidence: Dict[str, EvidenceRecord] = dict(evidence or {})
        # Evidence names the claims it bears on, so a claim need not know in
        # advance which records will arrive. Linking happens here rather than in
        # one construction path, or the same inputs would mean different things
        # depending on how the graph was built.
        self._claims: Dict[str, Claim] = {
            c.claim_id: c for c in link_evidence(claims, self._evidence)}
        self._resolved: Set[str] = set(resolved_contradictions)
        self.notes: Tuple[str, ...] = tuple(notes)
        self._anomalies: List[ClaimAnomaly] = []
        self._assessments: Dict[str, ClaimAssessment] = {}
        self._compute()

    # ── access ──────────────────────────────────────────────────────────────

    @property
    def claims(self) -> Tuple[Claim, ...]:
        return tuple(self._claims[k] for k in sorted(self._claims))

    @property
    def anomalies(self) -> Tuple[ClaimAnomaly, ...]:
        return tuple(self._anomalies)

    def claim(self, claim_id: str) -> Optional[Claim]:
        return self._claims.get(claim_id)

    def assessment(self, claim_id: str) -> Optional[ClaimAssessment]:
        return self._assessments.get(claim_id)

    def status(self, claim_id: str) -> ClaimStatus:
        """Effective status — UNKNOWN for a claim this graph has never seen.

        Not an exception and not a default of convenience: a claim nobody
        supplied is exactly as unestablished as one with no evidence.
        """
        assessment = self._assessments.get(claim_id)
        return assessment.effective_status if assessment else ClaimStatus.UNKNOWN

    def __len__(self) -> int:
        return len(self._claims)

    def __contains__(self, claim_id: object) -> bool:
        return claim_id in self._claims

    def roots(self) -> Tuple[Claim, ...]:
        declared = tuple(c for c in self.claims if c.is_root)
        if declared:
            return declared
        depended_on = {p for c in self.claims for p in c.depends_on}
        return tuple(c for c in self.claims if c.claim_id not in depended_on)

    def of_status(self, status: ClaimStatus) -> Tuple[Claim, ...]:
        return tuple(c for c in self.claims
                     if self.status(c.claim_id) is status)

    def model_derived_claims(self) -> Tuple[Claim, ...]:
        """Claims a model proposed. Listed separately so they can be treated so."""
        return tuple(c for c in self.claims if c.is_model_derived)

    def assumptions(self) -> Tuple[Claim, ...]:
        declared = {a for c in self.claims for a in c.assumptions}
        return tuple(c for c in self.claims
                     if c.claim_type is ClaimType.ASSUMPTION or c.claim_id in declared)

    # ── dependency structure ────────────────────────────────────────────────

    def depends_closure(self, claim_id: str) -> Tuple[str, ...]:
        """Everything a claim rests on, transitively. Iterative and cycle-safe."""
        seen: Set[str] = set()
        frontier = [claim_id]
        while frontier:
            current = frontier.pop()
            claim = self._claims.get(current)
            if claim is None:
                continue
            for parent in claim.depends_on:
                if parent not in seen:
                    seen.add(parent)
                    frontier.append(parent)
        return tuple(sorted(seen))

    def load_bearing(self, root_id: Optional[str] = None) -> Tuple[str, ...]:
        """Everything the root rests on — the claims that can bring it down."""
        if root_id is None:
            roots = self.roots()
            if not roots:
                return ()
            return tuple(sorted({c for r in roots for c in self.depends_closure(r.claim_id)}))
        return self.depends_closure(root_id)

    def binding_constraints(self, root_id: Optional[str] = None) -> Tuple[str, ...]:
        """The load-bearing claims whose status is what actually caps the root.

        The difference between "these 3,114 lemmas matter" and "these three are
        why the result is not verified". The second is what a human needs.
        """
        roots = ([self._claims[root_id]] if root_id and root_id in self._claims
                 else list(self.roots()))
        binding: Set[str] = set()
        for root in roots:
            root_status = self.status(root.claim_id)
            if root_status is ClaimStatus.SUPERSEDED:
                continue
            for claim_id in self.depends_closure(root.claim_id):
                if self.status(claim_id) is root_status:
                    binding.add(claim_id)
        return tuple(sorted(binding))

    def counterfactual(self, claim_id: str,
                       root_id: Optional[str] = None) -> Dict[str, Any]:
        """What the root becomes if this claim were settled either way.

        Deterministic, and the raw material of attention ranking: an item that
        changes the root's standing outranks one that does not, however many
        events sit behind it (Invariant 12).
        """
        roots = self.roots()
        root = (self._claims.get(root_id) if root_id else (roots[0] if roots else None))
        if root is None:
            return {"claim_id": claim_id, "root": None, "if_verified": None,
                    "if_refuted": None, "changes_root": False}

        def replay(forced: ClaimStatus) -> ClaimStatus:
            return ClaimGraph(self._claims.values(), self._evidence,
                              resolved_contradictions=self._resolved,
                              notes=self.notes)._recompute_with(
                                  {claim_id: forced}).get(root.claim_id, ClaimStatus.UNKNOWN)

        best, worst = replay(ClaimStatus.VERIFIED), replay(ClaimStatus.REFUTED)
        return {"claim_id": claim_id, "root": root.claim_id,
                "current_root_status": self.status(root.claim_id).value,
                "if_verified": best.value, "if_refuted": worst.value,
                "changes_root": best is not worst}

    def equivalence_classes(self, *, include_model_derived: bool = False
                            ) -> Tuple[Tuple[str, ...], ...]:
        """Groups of claims declared equivalent.

        Model-derived equivalence is excluded by default and must be asked for
        explicitly. A model may propose that two statements mean the same thing;
        it may not make them the same thing in a computation that gates a release
        (Invariant 4).
        """
        parent: Dict[str, str] = {c.claim_id: c.claim_id for c in self.claims}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        for claim in self.claims:
            if claim.is_model_derived and not include_model_derived:
                continue
            for other in claim.equivalent_to:
                if other in parent:
                    parent[find(other)] = find(claim.claim_id)

        groups: Dict[str, List[str]] = defaultdict(list)
        for claim_id in sorted(parent):
            groups[find(claim_id)].append(claim_id)
        return tuple(tuple(g) for g in sorted(groups.values()) if len(g) > 1)

    # ── the status calculus ─────────────────────────────────────────────────

    def _compute(self) -> None:
        self._detect_dependency_cycles()
        self._detect_dangling()
        effective = self._recompute_with({})
        for claim_id, assessment in self._assessments.items():
            if effective.get(claim_id) != assessment.effective_status:  # pragma: no cover
                self._assessments[claim_id] = dataclasses.replace(
                    assessment, effective_status=effective[claim_id])

    def _recompute_with(self, forced: Mapping[str, ClaimStatus]) -> Dict[str, ClaimStatus]:
        """Resolve every claim's effective status, honouring forced overrides.

        Iterative and order-independent: statuses are relaxed to a fixed point,
        so a dependency declared after its dependant makes no difference, and a
        cycle terminates instead of recursing.
        """
        superseded = {c.supersedes for c in self.claims if c.supersedes}
        direct: Dict[str, ClaimAssessment] = {}
        for claim in self.claims:
            direct[claim.claim_id] = self._direct_assessment(claim, superseded)
            if not forced:
                self._assessments[claim.claim_id] = direct[claim.claim_id]

        effective: Dict[str, ClaimStatus] = {
            cid: forced.get(cid, a.direct_status) for cid, a in direct.items()}

        cycle_claims = {c for a in self._anomalies if a.kind == "DEPENDENCY_CYCLE"
                        for c in a.claims}

        for _ in range(len(self._claims) + 1):
            changed = False
            for claim in self.claims:
                cid = claim.claim_id
                if cid in forced or effective[cid] is ClaimStatus.SUPERSEDED:
                    continue
                ceiling_ids = [p for p in claim.depends_on if p in effective]
                unknown_parents = [p for p in claim.depends_on if p not in effective]
                statuses = [effective[p] for p in ceiling_ids]
                if unknown_parents or cid in cycle_claims:
                    # A dependency nobody supplied, or a cycle that cannot be
                    # grounded, caps the claim at UNKNOWN rather than being ignored.
                    statuses.append(ClaimStatus.UNKNOWN)
                ceiling = weakest(statuses)
                if ceiling is None:
                    continue
                capped = weakest([direct[cid].direct_status, ceiling])
                if capped is not None and capped is not effective[cid]:
                    effective[cid] = capped
                    changed = True
            if not changed:
                break

        if not forced:
            for claim in self.claims:
                cid = claim.claim_id
                assessment = self._assessments[cid]
                ceiling_ids = [p for p in claim.depends_on]
                ceiling = weakest([effective.get(p, ClaimStatus.UNKNOWN) for p in ceiling_ids])
                capped_by = tuple(sorted(
                    p for p in ceiling_ids
                    if ceiling is not None and effective.get(p, ClaimStatus.UNKNOWN) is ceiling
                    and _STATUS_ORDER.get(ceiling, 9) < _STATUS_ORDER.get(
                        assessment.direct_status, 9)))
                self._assessments[cid] = dataclasses.replace(
                    assessment, inherited_ceiling=ceiling,
                    effective_status=effective[cid], capped_by=capped_by)
        return effective

    def _direct_assessment(self, claim: Claim,
                           superseded: Set[Optional[str]]) -> ClaimAssessment:
        """Status from evidence about this claim alone, before inheritance."""
        if claim.claim_id in superseded:
            return ClaimAssessment(
                claim.claim_id, ClaimStatus.SUPERSEDED, None, ClaimStatus.SUPERSEDED,
                "a later claim supersedes this one")

        supporting = [self._evidence[e] for e in claim.supporting_evidence
                      if e in self._evidence]
        contradicting = [self._evidence[e] for e in claim.contradicting_evidence
                         if e in self._evidence]
        unresolved = [e for e in contradicting if e.evidence_id not in self._resolved]

        passed = [a for a in claim.verification_attempts
                  if a.status is VerificationStatus.PASSED]
        failed = [a for a in claim.verification_attempts
                  if a.status is VerificationStatus.FAILED]
        inconclusive = [a for a in claim.verification_attempts
                        if a.status is VerificationStatus.INCONCLUSIVE]

        counts = dict(supporting=len(claim.supporting_evidence),
                      contradicting=len(claim.contradicting_evidence),
                      unresolved_contradictions=len(unresolved) + len(failed),
                      passed_attempts=len(passed), failed_attempts=len(failed),
                      inconclusive_attempts=len(inconclusive))

        support_weight = max((_EVIDENCE_WEIGHT.get(e.epistemic_status, 0)
                              for e in supporting), default=0)
        refute_weight = max([_EVIDENCE_WEIGHT.get(e.epistemic_status, 0)
                             for e in unresolved] + ([3] if failed else []), default=0)

        def build(status: ClaimStatus, basis: str) -> ClaimAssessment:
            return ClaimAssessment(claim.claim_id, status, None, status, basis, **counts)

        if refute_weight:
            if support_weight == 0:
                return build(ClaimStatus.REFUTED,
                             "refuting evidence stands and nothing supports the claim")
            # Support does not make a contradiction go away; only resolving it does.
            return build(ClaimStatus.DISPUTED,
                         f"{counts['unresolved_contradictions']} unresolved contradiction(s) "
                         "alongside supporting evidence")

        verified_support = any(e.epistemic_status is EpistemicStatus.VERIFIED
                               for e in supporting)
        if passed and not inconclusive:
            return build(ClaimStatus.VERIFIED,
                         f"{len(passed)} verification attempt(s) passed, none outstanding")
        if passed and inconclusive:
            return build(ClaimStatus.PARTIALLY_VERIFIED,
                         f"{len(passed)} attempt(s) passed and {len(inconclusive)} could "
                         "not be settled")
        if verified_support:
            return build(ClaimStatus.VERIFIED, "verified evidence supports this claim")
        if inconclusive:
            return build(ClaimStatus.UNVERIFIED,
                         f"{len(inconclusive)} verification attempt(s) reached no conclusion")
        if supporting:
            return build(ClaimStatus.UNVERIFIED,
                         "evidence supports this claim, but none of it is a verification")
        if claim.supporting_evidence:
            return build(ClaimStatus.UNKNOWN,
                         "the evidence this claim cites is not present in the case")
        return build(ClaimStatus.UNKNOWN, "nothing on record bears on this claim")

    # ── structural checks ───────────────────────────────────────────────────

    def _detect_dependency_cycles(self) -> None:
        colour: Dict[str, int] = {}
        for start in sorted(self._claims):
            if colour.get(start) == 1:
                continue
            stack: List[Tuple[str, List[str]]] = [
                (start, list(self._claims[start].depends_on))]
            path = [start]
            colour[start] = 0
            while stack:
                node, pending = stack[-1]
                advanced = False
                while pending:
                    nxt = pending.pop(0)
                    if nxt not in self._claims:
                        continue
                    state = colour.get(nxt)
                    if state == 0:
                        cycle = path[path.index(nxt):] + [nxt]
                        self._anomalies.append(ClaimAnomaly(
                            "DEPENDENCY_CYCLE",
                            "claims depend on each other in a circle: "
                            f"{' → '.join(cycle)}; nothing in the cycle can be grounded",
                            tuple(cycle)))
                        continue
                    if state is None:
                        colour[nxt] = 0
                        path.append(nxt)
                        stack.append((nxt, list(self._claims[nxt].depends_on)))
                        advanced = True
                        break
                if not advanced:
                    colour[node] = 1
                    stack.pop()
                    if path and path[-1] == node:
                        path.pop()
        unique: Dict[frozenset, ClaimAnomaly] = {}
        for anomaly in list(self._anomalies):
            if anomaly.kind == "DEPENDENCY_CYCLE":
                unique.setdefault(frozenset(anomaly.claims), anomaly)
        self._anomalies = [a for a in self._anomalies if a.kind != "DEPENDENCY_CYCLE"]
        self._anomalies.extend(unique.values())

    def _detect_dangling(self) -> None:
        for claim in self.claims:
            missing = [p for p in claim.depends_on if p not in self._claims]
            if missing:
                self._anomalies.append(ClaimAnomaly(
                    "MISSING_DEPENDENCY",
                    f"{claim.claim_id} depends on {missing}, which the case does not "
                    "contain; it is capped at UNKNOWN rather than assumed sound",
                    (claim.claim_id, *missing)))
            absent = [e for e in claim.supporting_evidence + claim.contradicting_evidence
                      if e not in self._evidence]
            if absent:
                self._anomalies.append(ClaimAnomaly(
                    "MISSING_EVIDENCE",
                    f"{claim.claim_id} cites {len(absent)} evidence record(s) the case "
                    "does not hold, so they count for nothing",
                    (claim.claim_id,)))

    # ── output ──────────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = defaultdict(int)
        for claim in self.claims:
            by_status[self.status(claim.claim_id).value] += 1
        roots = self.roots()
        return {
            "schema_version": CLAIM_SCHEMA_VERSION,
            "claims": len(self._claims),
            "by_status": dict(sorted(by_status.items())),
            "roots": [r.claim_id for r in roots],
            "root_status": {r.claim_id: self.status(r.claim_id).value for r in roots},
            "assumptions": len(self.assumptions()),
            "load_bearing": len(self.load_bearing()),
            "binding_constraints": list(self.binding_constraints()),
            "model_derived_claims": len(self.model_derived_claims()),
            "anomalies": [a.to_dict() for a in self.anomalies],
            "notes": list(self.notes),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "claim_graph",
            "schema_version": CLAIM_SCHEMA_VERSION,
            "claims": [c.to_dict() for c in self.claims],
            "assessments": [self._assessments[c.claim_id].to_dict() for c in self.claims],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "digest": self.digest(),
        }

    def digest(self) -> str:
        return digest_object({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "claims": [c.to_dict() for c in self.claims],
            "assessments": [self._assessments[c.claim_id].to_dict() for c in self.claims]})

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_case(cls, case: AssuranceCase, *,
                  evidence_collections: Sequence[str] = ("evidence", "verification",
                                                         "contradictions",
                                                         "counterexamples"),
                  ) -> Optional["ClaimGraph"]:
        """Build from a case's claims, or return `None` when it declares none.

        `None` rather than an empty graph: a transactional case has nothing to
        model here, and an empty claim graph would read as "nothing is asserted"
        rather than "claims were not part of this case" (Invariant 14).
        """
        collection = case.collection("claims")
        if collection.presence is not Presence.PRESENT:
            return None

        claims = [c for c in collection.materialised if isinstance(c, Claim)]
        notes: List[str] = []
        skipped = collection.held_count - len(claims)
        if skipped:
            notes.append(f"{skipped} record(s) in the claims collection are not Claims and "
                         "were not modelled")
        if collection.not_materialised:
            notes.append(f"{collection.not_materialised} claim(s) were counted but not "
                         "materialised; they are absent from this graph")

        evidence: Dict[str, EvidenceRecord] = {}
        resolved: List[str] = []
        for kind in evidence_collections:
            for record in case.collection(kind).materialised:
                if isinstance(record, EvidenceRecord):
                    evidence[record.evidence_id] = record
                    if record.content.get("resolved"):
                        resolved.append(record.evidence_id)

        return cls(claims, evidence, resolved_contradictions=resolved, notes=notes)
