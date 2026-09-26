"""AssuranceCase — the central domain object.

A case is one question put to one human: *given this subject, this objective and
this evidence, is there enough to authorise the requested decision?* Everything
else in release-gate's assurance layer either fills a case in or reads one out.

Three decisions shape the object, and each is the kind that is expensive to
change later.

**Identity is the question; the digest is the answer.** `case_id` derives from
the question — case type, objective, requested decision, subject identity — so it
is stable while evidence accumulates and across versions of the argument.
`case_version` counts revisions. `case_digest` covers the exact state, and it is
what an approval binds to. Re-running the same case against more evidence yields
the same `case_id`, a higher `case_version`, and a different `case_digest`, which
is exactly what a reviewer needs in order to ask "what changed since I looked?".

**State is a one-way lifecycle.** DRAFT accumulates. SEALED freezes the evidence
so a verdict means something. A verdict may only be set on a sealed case, and
only when coverage is present — that is where Invariant 9 becomes structural
rather than aspirational: there is no code path to a verdict without coverage.

**Nothing here knows any industry.** `case_type` selects no thresholds, no
required collections and no behaviour anywhere in this module. What a given class
of decision *requires* is a methodology question, and methodologies are data
supplied from outside the core. A case type that changed the engine's behaviour
would be a domain assumption compiled into the one object that must stay neutral.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import (
    CanonicalisationError,
    canonical_json,
    digest_object,
    freeze_value,
    short_id,
    thaw_value,
)
from release_gate.assurance.records import (
    CaseRecord,
    MaterialisationBasis,
    Presence,
    RecordCollection,
    RecordCollectionBuilder,
    RecordError,
)
from release_gate.assurance.subject import AssuranceSubject, SubjectType

CASE_MODEL_VERSION = 1
CASE_BINDING_ALGO = "rg-bind-1"

#: The twelve slices of an argument. Every one is optional: a migration case
#: populates two, a frontier research case populates all of them.
COLLECTION_KINDS: Tuple[str, ...] = (
    "evidence",
    "claims",
    "artifacts",
    "executions",
    "verification",
    "contradictions",
    "assumptions",
    "counterexamples",
    # Attempts that did not work out. Evidence, not waste: a case that records
    # only its successes looks exactly like its best branch (Invariant 7).
    "failed_branches",
    "coverage",
    "attention_items",
    "required_evidence",
    "approvals",
)

#: Collections that constitute the evidentiary state of the argument. Excludes
#: coverage and the derived human-facing outputs, and excludes approvals — an
#: approval binds TO this digest, so folding it back in would be circular.
EVIDENCE_KINDS: Tuple[str, ...] = (
    "evidence", "claims", "artifacts", "executions", "verification",
    "contradictions", "assumptions", "counterexamples", "failed_branches",
)


class CaseType(str, Enum):
    """What class of decision this is. Selects no behaviour in the core."""

    DEPLOYMENT = "DEPLOYMENT"
    AUTONOMOUS_ACTION = "AUTONOMOUS_ACTION"
    RESEARCH_RESULT = "RESEARCH_RESULT"
    CODE_CHANGE = "CODE_CHANGE"
    DATA_CHANGE = "DATA_CHANGE"
    FINANCIAL_ACTION = "FINANCIAL_ACTION"
    INFRASTRUCTURE_CHANGE = "INFRASTRUCTURE_CHANGE"
    GENERAL_DECISION = "GENERAL_DECISION"
    CUSTOM = "CUSTOM"


class CaseState(str, Enum):
    """Lifecycle. Forward-only, and every transition is explicit."""

    DRAFT = "DRAFT"              # accumulating; no verdict may be attached
    SEALED = "SEALED"            # evidence frozen; a verdict may be rendered
    APPROVED = "APPROVED"        # a bound approval is attached
    SUPERSEDED = "SUPERSEDED"    # a later case version replaced this one
    INVALIDATED = "INVALIDATED"  # integrity or subject mutation broke the case


class Decision(str, Enum):
    """The three verdicts, and what each one means.

    The meanings live here rather than in prose elsewhere because a verdict
    travelling to an API client, a CI job or a packet has to carry them: every
    misuse of this system begins with someone reading PROMOTE as permission.
    """

    PROMOTE = "PROMOTE"
    HOLD = "HOLD"
    BLOCK = "BLOCK"

    @property
    def definition(self) -> str:
        return _DECISION_DEFINITION[self]

    @property
    def does_not_mean(self) -> Tuple[str, ...]:
        """What this verdict is NOT. Empty for none of them.

        PROMOTE carries four, and they are the four things people actually read
        into it. A verdict that stated only what it meant would be read as
        meaning more.
        """
        return _DECISION_DOES_NOT_MEAN.get(self, ())

    @property
    def exit_code(self) -> int:
        """0 PROMOTE · 10 HOLD · 1 BLOCK.

        Delegates to `zero_config.exit_code_for` rather than restating the
        mapping: two copies of a CI contract drift, and the one that drifts is
        the one nobody is running.
        """
        from release_gate.assurance.zero_config import exit_code_for
        return exit_code_for(self)


_DECISION_DEFINITION: Mapping[Decision, str] = {
    Decision.PROMOTE: (
        "Evidence is sufficient under the active AssuranceMethodology and known "
        "coverage for the case to proceed to its next authorization boundary."),
    Decision.HOLD: (
        "More evidence, verification, methodology or resolution is required."),
    Decision.BLOCK: (
        "Known evidence demonstrates a non-overridable violation, or invalidates "
        "the candidate under the active methodology."),
}

#: The four readings of PROMOTE that this system exists to prevent. Held as data
#: so they can travel with the verdict and be asserted on, rather than as a
#: paragraph a caller can skip.
_DECISION_DOES_NOT_MEAN: Mapping[Decision, Tuple[str, ...]] = {
    Decision.PROMOTE: (
        "that the action will be executed automatically",
        "that the result is true",
        "that the result is safe",
        "that human approval already exists"),
}


#: Legal state transitions. Absent edges are refused, including every backward
#: one: a sealed case does not return to draft, because a reviewer's "I looked at
#: the sealed case" must keep meaning what it said.
_TRANSITIONS: Mapping[CaseState, Tuple[CaseState, ...]] = {
    CaseState.DRAFT: (CaseState.SEALED, CaseState.INVALIDATED, CaseState.SUPERSEDED),
    CaseState.SEALED: (CaseState.APPROVED, CaseState.SUPERSEDED, CaseState.INVALIDATED),
    CaseState.APPROVED: (CaseState.SUPERSEDED, CaseState.INVALIDATED),
    CaseState.SUPERSEDED: (),
    CaseState.INVALIDATED: (),
}


class CaseValidationError(ValueError):
    """A case was constructed or transitioned into a state it cannot hold."""


class CaseIntegrityError(ValueError):
    """A serialised case's stored digests disagree with its content."""


class CaseStateError(ValueError):
    """An operation was attempted from a state that does not allow it."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class MethodologyRef:
    """Which yardstick the case is argued against.

    A reference, not the methodology itself: methodologies are data, resolved and
    evaluated elsewhere. What matters here is that the id, version AND content
    digest travel inside the case digest. The version says which yardstick was
    used; the digest proves it is still the same one, which is what catches an
    organisation editing a methodology in place without renaming it.
    """

    methodology_id: str
    version: str
    provenance: str = "builtin"   # builtin | plugin | api | organization
    digest: Optional[str] = None  # content digest of the methodology definition

    def __post_init__(self) -> None:
        for name in ("methodology_id", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CaseValidationError(f"MethodologyRef.{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip())

    @property
    def ref(self) -> str:
        return f"{self.methodology_id}@{self.version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"methodology_id": self.methodology_id, "version": self.version,
                "provenance": self.provenance, "digest": self.digest}

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> Optional["MethodologyRef"]:
        if not data:
            return None
        return cls(methodology_id=data["methodology_id"], version=data["version"],
                   provenance=data.get("provenance", "builtin"),
                   digest=data.get("digest"))


@dataclass(frozen=True)
class CaseVerdict:
    """The authoritative outcome, plus what produced it.

    `fired_rules` is not decoration. A verdict a reviewer cannot trace to named
    rules is the opaque judgement this whole system exists to avoid, so an empty
    rule list is refused.

    Coverage is not a field here because coverage lives on the case as a
    collection; `AssuranceCase.render_verdict()` is therefore the enforcement
    point for Invariant 9. (The architecture spec put that check in the verdict
    constructor; moving it to the case is the same guarantee at the seam where
    the coverage data actually is.)
    """

    decision: Decision
    fired_rules: Tuple[str, ...]
    reasons: Tuple[str, ...] = ()
    engine_version: str = ""
    ruleset_version: str = ""
    decided_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", Decision(self.decision))
        object.__setattr__(self, "fired_rules", tuple(self.fired_rules))
        object.__setattr__(self, "reasons", tuple(self.reasons))
        if not self.fired_rules:
            raise CaseValidationError(
                "a verdict must name the rules that produced it — an unattributed "
                "PROMOTE/HOLD/BLOCK is exactly the opaque judgement release-gate refuses to make")

    def to_dict(self) -> Dict[str, Any]:
        return {"decision": self.decision.value, "fired_rules": list(self.fired_rules),
                "reasons": list(self.reasons), "engine_version": self.engine_version,
                "ruleset_version": self.ruleset_version, "decided_at": self.decided_at}

    def digest_component(self) -> Dict[str, Any]:
        """What the human read, minus when the engine happened to run.

        `reasons` is included: the stated reasons are what a person relied on, so
        re-wording them changes what was approved. `decided_at` is excluded — the
        clock is not part of the decision.
        """
        return {"decision": self.decision.value, "fired_rules": list(self.fired_rules),
                "reasons": list(self.reasons), "engine_version": self.engine_version,
                "ruleset_version": self.ruleset_version}

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> Optional["CaseVerdict"]:
        if not data:
            return None
        return cls(decision=Decision(data["decision"]),
                   fired_rules=tuple(data.get("fired_rules", ())),
                   reasons=tuple(data.get("reasons", ())),
                   engine_version=data.get("engine_version", ""),
                   ruleset_version=data.get("ruleset_version", ""),
                   decided_at=data.get("decided_at") or _utc_now())


@dataclass(frozen=True)
class AssuranceCase:
    """The proposition, the subject, the evidence, and what was decided.

    Immutable. Every change returns a new instance, so a case someone reviewed
    cannot be edited out from under them; revisions are explicit through
    `revise()` and linked by `supersedes`.
    """

    case_type: CaseType
    objective: str
    requested_decision: str
    subject: AssuranceSubject
    methodology: Optional[MethodologyRef] = None
    custom_type: Optional[str] = None
    state: CaseState = CaseState.DRAFT
    case_version: int = 1
    supersedes: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    collections: Mapping[str, RecordCollection] = field(default_factory=dict)
    verdict: Optional[CaseVerdict] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # Derived at construction; never accepted from a caller or a file.
    case_id: str = field(default="", init=False)
    subject_digest: str = field(default="", init=False)
    evidence_digest: str = field(default="", init=False)
    case_digest: str = field(default="", init=False)

    # ── construction ────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_type", CaseType(self.case_type))
        object.__setattr__(self, "state", CaseState(self.state))

        for name in ("objective", "requested_decision"):
            value = (getattr(self, name) or "").strip()
            if not value:
                raise CaseValidationError(
                    f"{name} is required. objective says what the work was trying to "
                    "achieve; requested_decision says what the human is being asked to "
                    "decide. A case missing either cannot be put to a person.")
            object.__setattr__(self, name, value)

        if not isinstance(self.subject, AssuranceSubject):
            raise CaseValidationError("subject must be an AssuranceSubject")

        if self.case_type is CaseType.CUSTOM:
            label = (self.custom_type or "").strip()
            if not label:
                raise CaseValidationError(
                    "case_type CUSTOM requires custom_type — an unlabelled custom case "
                    "cannot be matched to a methodology or explained to a reviewer")
            object.__setattr__(self, "custom_type", label)
        elif self.custom_type is not None:
            raise CaseValidationError(
                f"custom_type is only valid with case_type CUSTOM (got {self.case_type.value})")

        if not isinstance(self.case_version, int) or self.case_version < 1:
            raise CaseValidationError("case_version must be a positive integer")
        if self.supersedes is not None and self.case_version == 1:
            raise CaseValidationError(
                "a case that supersedes another is at least version 2")
        if self.verdict is not None and self.state is CaseState.DRAFT:
            raise CaseValidationError(
                "a draft case cannot carry a verdict: sealing is what makes the "
                "evidence a verdict refers to stable")

        object.__setattr__(self, "collections", _normalise_collections(self.collections))
        try:
            # Frozen, not copied: a mutable nested value would let a caller change
            # what the human saw while case_digest went on saying otherwise.
            object.__setattr__(self, "metadata", freeze_value(self.metadata or {}, "metadata"))
        except CanonicalisationError as exc:
            raise CaseValidationError(f"case metadata: {exc}") from exc

        object.__setattr__(self, "subject_digest", self.subject.state_digest)
        object.__setattr__(self, "case_id", short_id("case", digest_object(self.identity())))
        object.__setattr__(self, "evidence_digest", digest_object(self._evidence_state()))
        object.__setattr__(self, "case_digest", digest_object(self._binding_state()))

    # ── identity and digests ────────────────────────────────────────────────

    def identity(self) -> Dict[str, Any]:
        """The QUESTION, not the argument.

        Stable while evidence accumulates, so every version of a case shares one
        id and a reviewer can follow the thread. A revised subject produces a
        different id, because a different subject is a different question.
        """
        return {
            "model_version": CASE_MODEL_VERSION,
            "case_type": self.case_type.value,
            "custom_type": self.custom_type,
            "objective": self.objective,
            "requested_decision": self.requested_decision,
            "subject_id": self.subject.subject_id,
        }

    def _evidence_state(self) -> Dict[str, Any]:
        """The evidentiary state: every evidence-bearing collection's commitment.

        Folds cover records that were counted but never materialised, so this
        stays a statement about the whole body of evidence at any scale.
        """
        return {
            "fold_algo": CASE_BINDING_ALGO,
            "collections": {kind: self.collection(kind).digest_component()
                            for kind in EVIDENCE_KINDS},
        }

    def _binding_state(self) -> Dict[str, Any]:
        """Everything an approval binds to.

        Excludes `approvals` (an approval binds to this digest; including it would
        be circular) and excludes `created_at` / `updated_at` (when the engine ran
        is not what was decided).
        """
        return {
            "binding_algo": CASE_BINDING_ALGO,
            "case_id": self.case_id,
            "case_version": self.case_version,
            "identity": self.identity(),
            "subject_state": self.subject.binding_state(),
            "methodology": (self.methodology.to_dict() if self.methodology else "NONE"),
            "evidence_digest": self.evidence_digest,
            "collections": {kind: self.collection(kind).digest_component()
                            for kind in COLLECTION_KINDS if kind != "approvals"},
            "verdict": self.verdict.digest_component() if self.verdict else None,
            "supersedes": self.supersedes,
            "metadata": thaw_value(self.metadata),
        }

    def binding_state(self) -> Dict[str, Any]:
        """Public view of what a BoundApproval must cover."""
        return {"case_id": self.case_id, "case_version": self.case_version,
                "case_digest": self.case_digest, "state": self._binding_state()}

    # ── collections ─────────────────────────────────────────────────────────

    def collection(self, kind: str) -> RecordCollection:
        """Always returns a collection — ABSENT where nothing was supplied.

        Never raises for a missing kind and never returns None: a caller asking
        about a part of the case that was never populated should get an explicit
        "not supplied", not an exception to handle or a falsy value to misread.
        """
        if kind not in COLLECTION_KINDS:
            raise KeyError(f"unknown collection {kind!r}; known: {', '.join(COLLECTION_KINDS)}")
        existing = self.collections.get(kind)
        # `is None`, never `or`: a collection that was supplied and holds no
        # materialised records is a real, PRESENT collection, and treating it as
        # missing would turn "we looked and found none" back into "nobody looked".
        return existing if existing is not None else RecordCollection(
            kind=kind, presence=Presence.ABSENT)

    def records(self, kind: str) -> Tuple[CaseRecord, ...]:
        return self.collection(kind).materialised

    @property
    def is_sparse(self) -> bool:
        """True when at most a couple of collections were supplied.

        A simple case is the normal case, not a degraded one: one engineer, one
        migration, a subject and an action.
        """
        return sum(1 for k in COLLECTION_KINDS
                   if self.collection(k).presence is Presence.PRESENT) <= 2

    @property
    def total_records(self) -> int:
        """Records SEEN across every collection, materialised or not."""
        return sum(self.collection(k).total_count for k in COLLECTION_KINDS)

    @property
    def materialised_records(self) -> int:
        return sum(self.collection(k).held_count for k in COLLECTION_KINDS)

    @property
    def absent_collections(self) -> Tuple[str, ...]:
        """What was never supplied — the raw material of the NOT_ASSESSED rows."""
        return tuple(k for k in COLLECTION_KINDS
                     if self.collection(k).presence is Presence.ABSENT)

    def summary(self) -> Dict[str, Any]:
        """The header a human or a dashboard reads without loading the records.

        The reason a ten-million-record case is inspectable at all: counts,
        commitments and the verdict, with no record bodies.
        """
        return {
            "case_id": self.case_id,
            "case_version": self.case_version,
            "case_type": self.case_type.value,
            "custom_type": self.custom_type,
            "state": self.state.value,
            "objective": self.objective,
            "requested_decision": self.requested_decision,
            "subject_id": self.subject.subject_id,
            "subject_digest": self.subject_digest,
            "subject_mutation_detectable": self.subject.mutation_detectable,
            "methodology": self.methodology.ref if self.methodology else "NONE",
            "methodology_digest": self.methodology.digest if self.methodology else None,
            "evidence_digest": self.evidence_digest,
            "case_digest": self.case_digest,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "total_records": self.total_records,
            "materialised_records": self.materialised_records,
            "absent_collections": list(self.absent_collections),
            "collections": {k: self.collection(k).summary() for k in COLLECTION_KINDS},
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    # ── lifecycle ───────────────────────────────────────────────────────────

    def _transition(self, new_state: CaseState, **changes: Any) -> "AssuranceCase":
        if new_state not in _TRANSITIONS[self.state]:
            allowed = ", ".join(s.value for s in _TRANSITIONS[self.state]) or "nothing"
            raise CaseStateError(
                f"cannot move a {self.state.value} case to {new_state.value}; "
                f"from {self.state.value} the only legal transitions are: {allowed}")
        changes.setdefault("updated_at", _utc_now())
        return dataclasses.replace(self, state=new_state, **changes)

    def seal(self) -> "AssuranceCase":
        """Freeze the evidence so a verdict can refer to something stable."""
        return self._transition(CaseState.SEALED)

    def render_verdict(self, verdict: CaseVerdict) -> "AssuranceCase":
        """Attach the authoritative outcome. Refused without coverage.

        This is Invariant 9 made structural: coverage is not a field a caller may
        forget, it is a precondition with no bypass. A verdict without a statement
        of what was and was not assessed is invalid, however confident it looks.
        """
        if self.state is not CaseState.SEALED:
            raise CaseStateError(
                f"a verdict may only be rendered on a SEALED case (this one is "
                f"{self.state.value}); seal() freezes the evidence the verdict refers to")
        coverage = self.collection("coverage")
        if coverage.presence is not Presence.PRESENT or coverage.total_count == 0:
            raise CaseValidationError(
                "a verdict requires coverage: what this case assessed and what it did "
                "not. A verdict without coverage is invalid (Invariant 9)")
        self._require_open_contradictions_named(verdict)
        return dataclasses.replace(self, verdict=verdict, updated_at=_utc_now())

    def _require_open_contradictions_named(self, verdict: "CaseVerdict") -> None:
        """A verdict may not quietly omit an unresolved critical disagreement.

        The same shape of enforcement as the coverage check above, for the same
        reason: the harm is silence, not falsehood. A case can carry an open
        contradiction on a load-bearing claim and still reach a verdict — the
        engine does not decide that for anyone — but the verdict has to *say so*,
        by naming the contradiction in its fired rules or its reasons.

        Only records that are actually contradiction objects are checked, so
        collections holding other shapes are unaffected.
        """
        collection = self.collection("contradictions")
        if collection.presence is not Presence.PRESENT:
            return
        spoken = " ".join(tuple(verdict.fired_rules) + tuple(verdict.reasons))
        unnamed = []
        for record in collection.materialised:
            data = record.to_dict() if hasattr(record, "to_dict") else {}
            if data.get("record_type") != "contradiction":
                continue
            if data.get("resolved") or not data.get("affects_critical"):
                continue
            identifier = str(data.get("contradiction_id") or record.record_id)
            if identifier not in spoken:
                unnamed.append(identifier)
        if unnamed:
            raise CaseValidationError(
                f"{len(unnamed)} unresolved contradiction(s) affect a critical claim and "
                f"are not named in this verdict: {', '.join(sorted(unnamed))}. A verdict "
                "may reach any decision it likes over an open disagreement, and may not "
                "reach one without mentioning it — silently dropping it is the erasure "
                "the contradiction record exists to prevent.")

    def with_approval(self, approval: CaseRecord) -> "AssuranceCase":
        """Attach a bound approval.

        Approvals sit outside `case_digest` by construction: an approval binds to
        that digest, so folding it back in would make the digest depend on the
        thing that depends on it.
        """
        if self.state not in (CaseState.SEALED, CaseState.APPROVED):
            raise CaseStateError(
                f"approvals attach to a SEALED case; this one is {self.state.value}")
        if self.verdict is None:
            raise CaseStateError(
                "a case cannot be approved before a verdict has been rendered — "
                "there is nothing yet for a human to accept responsibility for")
        current = self.collection("approvals")
        if current.not_materialised:
            raise CaseValidationError(
                f"{current.not_materialised} approval(s) were counted but not held; "
                "approvals must always be materialised — an approval nobody can read "
                "back is not an audit trail")
        builder = RecordCollectionBuilder("approvals")
        for existing in current:
            builder.add(existing)
        builder.add(approval)
        collections = dict(self.collections)
        collections["approvals"] = builder.build()
        if self.state is CaseState.APPROVED:
            return dataclasses.replace(self, collections=collections, updated_at=_utc_now())
        return self._transition(CaseState.APPROVED, collections=collections)

    def check_subject(self, resolver=None, items=None):
        """Is the subject still the thing this case argues about? (Invariant 5)

        Returns the subject's `MutationCheck`. Acting on it — invalidating the
        case, opening a revision — is the caller's decision, because a mutated
        subject after approval and a mutated subject mid-draft are different
        situations with different remedies.
        """
        return self.subject.recheck(resolver=resolver, items=items)

    def invalidate(self, reason: str) -> "AssuranceCase":
        """Mark the case unusable — integrity broken, or the subject moved."""
        if not reason.strip():
            raise CaseValidationError("invalidate() requires a reason")
        metadata = thaw_value(self.metadata)
        metadata["invalidation_reason"] = reason.strip()
        return self._transition(CaseState.INVALIDATED, metadata=metadata)

    def supersede(self) -> "AssuranceCase":
        """Retire this version because a later one replaced it."""
        return self._transition(CaseState.SUPERSEDED)

    def revise(self, **changes: Any) -> "AssuranceCase":
        """Open the next version of this case, linked to this one.

        Returns a DRAFT: new evidence means the argument is open again, and any
        approval of the previous version applies to the previous version only.
        """
        changes.setdefault("case_version", self.case_version + 1)
        changes.setdefault("supersedes", f"{self.case_id}@v{self.case_version}")
        changes.setdefault("state", CaseState.DRAFT)
        changes.setdefault("verdict", None)
        changes.setdefault("created_at", self.created_at)
        changes.setdefault("updated_at", _utc_now())
        if changes["state"] is not CaseState.DRAFT or changes["verdict"] is not None:
            raise CaseValidationError("a revision opens as a DRAFT with no verdict")
        collections = dict(changes.pop("collections", dict(self.collections)))
        # A new version's argument is re-argued; approvals never ride along.
        collections.pop("approvals", None)
        return dataclasses.replace(self, collections=collections, **changes)

    # ── serialisation ───────────────────────────────────────────────────────

    def to_dict(self, include_records: bool = True) -> Dict[str, Any]:
        return {
            "record_type": "assurance_case",
            "model_version": CASE_MODEL_VERSION,
            "case_id": self.case_id,
            "case_version": self.case_version,
            "case_type": self.case_type.value,
            "custom_type": self.custom_type,
            "state": self.state.value,
            "objective": self.objective,
            "requested_decision": self.requested_decision,
            "subject": self.subject.to_dict(),
            "methodology": self.methodology.to_dict() if self.methodology else None,
            "supersedes": self.supersedes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "collections": {k: self.collection(k).to_dict(include_records=include_records)
                            for k in COLLECTION_KINDS},
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "metadata": thaw_value(self.metadata),
            "subject_digest": self.subject_digest,
            "evidence_digest": self.evidence_digest,
            "case_digest": self.case_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], record_factory=None) -> "AssuranceCase":
        """Rebuild a case, recomputing its digests and refusing to trust stored ones.

        A stored digest that disagrees with the content means the record was
        edited after it was written. For a case that carries an approval, that is
        the difference between an audit trail and a document.
        """
        collections = {
            kind: RecordCollection.from_dict(payload, record_factory=record_factory)
            for kind, payload in (data.get("collections") or {}).items()
            if kind in COLLECTION_KINDS
        }
        case = cls(
            case_type=CaseType(data["case_type"]),
            objective=data["objective"],
            requested_decision=data["requested_decision"],
            subject=AssuranceSubject.from_dict(data["subject"]),
            methodology=MethodologyRef.from_dict(data.get("methodology")),
            custom_type=data.get("custom_type"),
            state=CaseState(data.get("state", CaseState.DRAFT.value)),
            case_version=int(data.get("case_version", 1)),
            supersedes=data.get("supersedes"),
            created_at=data.get("created_at") or _utc_now(),
            updated_at=data.get("updated_at") or _utc_now(),
            collections=collections,
            verdict=CaseVerdict.from_dict(data.get("verdict")),
            metadata=data.get("metadata") or {},
        )
        for field_name in ("case_id", "subject_digest", "evidence_digest", "case_digest"):
            stored = data.get(field_name)
            if stored and stored != getattr(case, field_name):
                raise CaseIntegrityError(
                    f"{field_name} in the record ({stored}) does not match the value "
                    f"recomputed from its content ({getattr(case, field_name)}) — "
                    "the case was modified after it was written")
        return case


def _normalise_collections(collections: Mapping[str, RecordCollection]
                           ) -> Dict[str, RecordCollection]:
    out: Dict[str, RecordCollection] = {}
    for kind, collection in (collections or {}).items():
        if kind not in COLLECTION_KINDS:
            raise CaseValidationError(
                f"unknown collection {kind!r}; known: {', '.join(COLLECTION_KINDS)}")
        if not isinstance(collection, RecordCollection):
            raise CaseValidationError(f"collection {kind!r} must be a RecordCollection")
        if collection.kind != kind:
            raise CaseValidationError(
                f"collection filed under {kind!r} declares itself {collection.kind!r}")
        out[kind] = collection
    return out


def default_case_type(subject_type: SubjectType) -> CaseType:
    """A suggestion, not a rule.

    Case type and subject type are different axes — a DOCUMENT subject can belong
    to a RESEARCH_RESULT case or a GENERAL_DECISION one — so this maps the obvious
    pairs and falls back to GENERAL_DECISION. Nothing validates the pairing, and
    nothing in the engine behaves differently because of it.
    """
    mapping = {
        SubjectType.DEPLOYMENT: CaseType.DEPLOYMENT,
        SubjectType.CODE_CHANGE: CaseType.CODE_CHANGE,
        SubjectType.AUTONOMOUS_ACTION: CaseType.AUTONOMOUS_ACTION,
        SubjectType.RESEARCH_RESULT: CaseType.RESEARCH_RESULT,
        SubjectType.DATA_CHANGE: CaseType.DATA_CHANGE,
        SubjectType.FINANCIAL_ACTION: CaseType.FINANCIAL_ACTION,
        SubjectType.INFRASTRUCTURE_CHANGE: CaseType.INFRASTRUCTURE_CHANGE,
    }
    return mapping.get(subject_type, CaseType.GENERAL_DECISION)


def declared_digests(case: "AssuranceCase") -> Dict[str, Set[str]]:
    """Every content digest declared under each artifact handle.

    A set per handle, never a single value, because one logical artifact declared
    twice with different digests is not a case where the second supersedes the
    first — it is a case that cannot say which content it is about. Collapsing
    that to the last record read answers a question nobody can answer, and hides
    the collision that is itself the finding.
    """
    out: Dict[str, Set[str]] = {}
    for record in case.records("artifacts"):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        logical = str(payload.get("logical_id") or payload.get("artifact_id") or "")
        digest = str(payload.get("digest") or "")
        if logical and digest:
            out.setdefault(logical, set()).add(digest)
    return out


def held_digests(case: "AssuranceCase",
                 kinds: Sequence[str] = ("artifacts", "claims", "evidence",
                                         "verification")) -> Set[str]:
    """Every content digest this case actually holds, across collections.

    The denominator for "does this reference point at anything we have". Not just
    artifacts: a verifier may legitimately name a claim or a piece of evidence by
    its digest, and treating only artifact digests as real would call those
    honest references unanchored.
    """
    out: Set[str] = set()
    for kind in kinds:
        for record in case.records(kind):
            payload = record.to_dict() if hasattr(record, "to_dict") else {}
            digest = str(payload.get("digest") or "")
            if digest:
                out.add(digest)
    return out


class AssuranceCaseBuilder:
    """Accumulates a case from records arriving in any order, from any producer.

    Mutable by design — the case it produces is not. Ingest is messy and
    concurrent; the object a human is shown must not be.
    """

    def __init__(self, *, case_type: CaseType, objective: str, requested_decision: str,
                 subject: AssuranceSubject, methodology: Optional[MethodologyRef] = None,
                 custom_type: Optional[str] = None,
                 metadata: Optional[Mapping[str, Any]] = None) -> None:
        self.case_type = CaseType(case_type)
        self.objective = objective
        self.requested_decision = requested_decision
        self.subject = subject
        self.methodology = methodology
        self.custom_type = custom_type
        self.metadata = dict(metadata or {})
        self._builders: Dict[str, RecordCollectionBuilder] = {}

    def collection(self, kind: str, *, basis: MaterialisationBasis = MaterialisationBasis.COMPLETE,
                   track_ids: bool = True) -> RecordCollectionBuilder:
        """The builder for one collection, created on first use."""
        if kind not in COLLECTION_KINDS:
            raise KeyError(f"unknown collection {kind!r}; known: {', '.join(COLLECTION_KINDS)}")
        if kind not in self._builders:
            self._builders[kind] = RecordCollectionBuilder(kind, basis=basis, track_ids=track_ids)
        return self._builders[kind]

    def add(self, kind: str, record: CaseRecord, *, materialise: bool = True
            ) -> "AssuranceCaseBuilder":
        self.collection(kind).add(record, materialise=materialise)
        return self

    def extend(self, kind: str, records: Iterable[CaseRecord], *, materialise: bool = True
               ) -> "AssuranceCaseBuilder":
        self.collection(kind).extend(records, materialise=materialise)
        return self

    def declare_present(self, kind: str, note: str = "") -> "AssuranceCaseBuilder":
        """Record that a collection was supplied even though it holds nothing."""
        self.collection(kind).declare_present(note)
        return self

    def note(self, kind: str, message: str) -> "AssuranceCaseBuilder":
        self.collection(kind).note(message)
        return self

    def fork(self) -> "AssuranceCaseBuilder":
        """A copy that shares this builder's folded records and nothing mutable.

        For the case where several cases over the same evidence differ only in what
        the engine concluded about it. The zero-config path builds three — the
        provisional case the analysers read, the analysed case the methodology is
        held against, and the final case carrying the attention list — and before
        this they were three full folds of one record set.

        Collection order is not preserved across a fork and does not need to be:
        `case_digest` reads collections through the fixed `COLLECTION_KINDS`
        tuple, so which order they were created in cannot reach the digest an
        approval binds to.
        """
        clone = AssuranceCaseBuilder(
            case_type=self.case_type, objective=self.objective,
            requested_decision=self.requested_decision, subject=self.subject,
            methodology=self.methodology, custom_type=self.custom_type,
            metadata=dict(self.metadata))
        clone._builders = {kind: builder.fork()
                           for kind, builder in self._builders.items()}
        return clone

    def build(self, **case_kwargs: Any) -> AssuranceCase:
        collections = {kind: builder.build() for kind, builder in self._builders.items()}
        return AssuranceCase(
            case_type=self.case_type, objective=self.objective,
            requested_decision=self.requested_decision, subject=self.subject,
            methodology=self.methodology, custom_type=self.custom_type,
            collections=collections, metadata=self.metadata, **case_kwargs)
