"""Assurance Evidence Pack v3 — the durable artefact, over a case rather than a score.

The pack that shipped before this one belongs to the `governance.yaml` era:
`release_gate/evidence_pack.py` renders a readiness score and dimension bars to
JSON, Markdown and HTML from a scoring dict. It still serves that path and is
untouched. What it cannot do is answer the question an auditor actually arrives
with six weeks later — *what exactly was decided, on what evidence, and is this
still that?* — because a score is not a thing you can re-check.

V3 is the same job computed over an `AssuranceCase`. Three properties carry it.

**Everything is a digest or a handle. Never raw content.** There is no size
threshold to tune and no way for a pack to grow with the evidence it describes,
because it never carries evidence: it carries the digests of what was argued and
the external references by which the bytes can be fetched. A case holding four
million spans and one holding four produce packs of the same order. That is the
same discipline `compact_case` applies — a record with a non-inline content
reference is kept as its handle, because "the evidence still exists, it just
does not live in here."

**Absent, empty and not-assessed stay three different answers.** A case with no
execution telemetry has an ABSENT execution graph, not an empty one; a case whose
caller supplied no completeness ledger has a NOT_ASSESSED completeness section,
not a clean one. Collapsing those is how a sparse pack comes to read like a
thorough one, and this sequence has paid for that mistake more than once.

**The pack is signable, and does not sign.** `assurance/` computes and refuses to
import a crypto library; `attestation.py` set the precedent and the reason — a
valid signature over an incomplete manifest is a valid signature, so verifying
one here would not change what the pack establishes. The pack is
content-addressed; a signature over `pack_digest` is applied outside and travels
as recorded metadata. `verify_pack()` answers the question that *is* answerable
here: does this pack's content still hash to the digest it carries, and does each
section still hash to what the pack says it did.

**A pack is not an approval.** `authorises` is unconditionally `False`. It
records that an approval happened, who made it and what it bound to; the act
itself was a person's, and a document that could stand in for it would be exactly
the substitution Invariant 15 exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.records import MaterialisationBasis

__all__ = [
    "PACK_SCHEMA_VERSION",
    "AssuranceEvidencePack",
    "ExternalReference",
    "PackError",
    "PackSection",
    "SectionState",
    "build_pack",
    "verify_pack",
]

PACK_SCHEMA_VERSION = 3


class PackError(ValueError):
    """A pack was built or read in a state that would overstate what it holds."""


class SectionState(str, Enum):
    """Why a section holds what it holds. Three answers, never two.

    `ABSENT` is a finding: the component was derivable and there was nothing to
    derive it from — a case with no execution telemetry, no counterexample
    attempts, no assumptions. `NOT_ASSESSED` is the absence of a finding: an
    input the caller never supplied, so nothing looked. Reading the second as the
    first turns "nobody checked" into "checked and clean", which is the single
    failure mode this whole system is built against (Invariant 3).
    """

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True)
class ExternalReference:
    """Where raw evidence lives, for evidence too large to travel.

    The pack holds the handle and the digest, never the bytes. `digest` is what
    makes the handle worth having: a locator alone says where to look, and a
    locator with a digest says whether what you found is what was argued.
    """

    record_id: str
    kind: str
    locator: str
    digest: Optional[str] = None
    byte_length: Optional[int] = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.record_id or "").strip():
            raise PackError("an external reference must name the record it stands for")
        if not str(self.locator or "").strip():
            raise PackError(
                f"{self.record_id}: an external reference with no locator points "
                "nowhere; a handle that cannot be followed is not a handle")

    @property
    def resolvable(self) -> bool:
        """Whether following this reference could be checked against anything."""
        return bool(self.digest)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_id": self.record_id, "kind": self.kind,
                "locator": self.locator, "digest": self.digest,
                "byte_length": self.byte_length, "resolvable": self.resolvable,
                "detail": dict(self.detail)}


@dataclass(frozen=True)
class PackSection:
    """One named component: what it is, whether it is here, and its digest.

    `digest` is the component's own — `ClaimGraph.digest()`, `CriticalitySet
    .digest()` and the rest — folded rather than recomputed, so a section in a
    pack and the object it came from are provably the same thing.
    """

    key: str
    state: SectionState
    digest: Optional[str] = None
    count: Optional[int] = None
    basis: MaterialisationBasis = MaterialisationBasis.COMPLETE
    summary: Mapping[str, Any] = field(default_factory=dict)
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", SectionState(self.state))
        object.__setattr__(self, "basis", MaterialisationBasis(self.basis))
        if not str(self.key or "").strip():
            raise PackError("a pack section must be named")
        object.__setattr__(self, "key", self.key.strip())
        if self.state is SectionState.PRESENT and not self.digest:
            raise PackError(
                f"{self.key}: a PRESENT section must carry a digest — a section "
                "asserting the component exists while holding nothing to check it "
                "against is the shape of a pack that looks complete and is not")
        if self.state is not SectionState.PRESENT and not self.note:
            raise PackError(
                f"{self.key}: a section that is {self.state.value} must say why. "
                "An unexplained absence reads as an oversight rather than a fact "
                "about the case")

    @property
    def present(self) -> bool:
        return self.state is SectionState.PRESENT

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "state": self.state.value, "digest": self.digest,
                "count": self.count, "basis": self.basis.value,
                "summary": dict(self.summary), "note": self.note,
                # A section is a commitment to a component's content, never a
                # statement that the component covered everything there was.
                "bounds_completeness": False}


#: Every section the pack answers, in the order it answers them. Named as a
#: constant so "is this pack complete" is a comparison rather than a count, and
#: so adding a section is a visible edit rather than a silent one.
SECTION_KEYS: Tuple[str, ...] = (
    "evidence_graph",
    "execution_graph",
    "claim_graph",
    "artifact_manifest",
    "critical_claims",
    "assumptions",
    "verification",
    "replications",
    "counterexamples",
    "contradictions",
    "coverage",
    "completeness",
    "human_attention",
    "required_evidence",
    "verdict",
    "approval_state",
)


@dataclass(frozen=True)
class AssuranceEvidencePack:
    """What was decided, on what, and whether this is still that.

    Content-addressed over everything below. `pack_digest` is not decoration: it
    is what a signature is applied to outside this module, and what
    `verify_pack()` recomputes.
    """

    # ── identity: what decision is this about ──────────────────────────────
    case_id: str
    case_version: int
    case_digest: str
    objective: str
    requested_authorization: str

    # ── the subject: two digests, and they are not interchangeable ─────────
    #: Identity — type, version, content digest, reference, action, lineage.
    #: Stable across annotation; what makes two submissions the same subject.
    subject_id: str = ""
    #: The subject's own content digest, or None where content cannot be hashed.
    subject_digest: Optional[str] = None
    #: What the human saw — identity plus metadata — and the ONLY thing an
    #: approval binds to. Carrying one and calling it "the subject digest" is a
    #: mistake this codebase has already made once: re-tagging a subject leaves
    #: `subject_digest` untouched and moves `subject_state_digest`, and only the
    #: second may invalidate an approval.
    subject_state_digest: Optional[str] = None
    subject_reference: Mapping[str, Any] = field(default_factory=dict)
    requested_action: str = ""

    methodology: Optional[Mapping[str, Any]] = None
    sections: Tuple[PackSection, ...] = ()
    external_references: Tuple[ExternalReference, ...] = ()

    engine_version: str = ""
    schema_version: int = PACK_SCHEMA_VERSION
    case_created_at: str = ""
    case_updated_at: str = ""
    built_at: str = ""
    notes: Tuple[str, ...] = ()

    pack_digest: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sections", tuple(self.sections))
        object.__setattr__(self, "external_references",
                           tuple(self.external_references))
        object.__setattr__(self, "notes", tuple(self.notes))
        if not str(self.case_id or "").strip():
            raise PackError("a pack must name the case it describes")

        keys = [s.key for s in self.sections]
        if len(keys) != len(set(keys)):
            raise PackError("a pack holds two sections under one key")
        missing = [k for k in SECTION_KEYS if k not in keys]
        if missing:
            raise PackError(
                "an evidence pack must account for every section; missing "
                + ", ".join(missing)
                + ". A section that is absent says so — one that is simply not "
                  "there reads as one that was fine")
        object.__setattr__(self, "pack_digest", digest_object(self.content()))

    # ── refusals ───────────────────────────────────────────────────────────

    @property
    def authorises(self) -> bool:
        """Unconditionally False. A pack records an approval; it is not one."""
        return False

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False, whatever the verdict section says."""
        return False

    @property
    def bounds_completeness(self) -> bool:
        """Unconditionally False. A pack describes what was argued, not what existed."""
        return False

    # ── reading ────────────────────────────────────────────────────────────

    def section(self, key: str) -> PackSection:
        found = next((s for s in self.sections if s.key == key), None)
        if found is None:
            raise PackError(f"this pack holds no section {key!r}")
        return found

    def state(self, key: str) -> SectionState:
        return self.section(key).state

    @property
    def present_sections(self) -> Tuple[PackSection, ...]:
        return tuple(s for s in self.sections if s.present)

    @property
    def absent_sections(self) -> Tuple[PackSection, ...]:
        return tuple(s for s in self.sections
                     if s.state is SectionState.ABSENT)

    @property
    def unassessed_sections(self) -> Tuple[PackSection, ...]:
        return tuple(s for s in self.sections
                     if s.state is SectionState.NOT_ASSESSED)

    @property
    def verdict(self) -> Mapping[str, Any]:
        return dict(self.section("verdict").summary)

    @property
    def decision(self) -> str:
        return str(self.verdict.get("decision") or "HOLD")

    def content(self) -> Dict[str, Any]:
        """Everything the digest covers. `built_at` is excluded.

        When the pack was written is not part of what it says: building the same
        pack twice from one sealed case must produce one digest, or the artefact
        cannot be used to show that two parties are holding the same thing.
        """
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id, "case_version": self.case_version,
            "case_digest": self.case_digest,
            "objective": self.objective,
            "requested_authorization": self.requested_authorization,
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
            "subject_state_digest": self.subject_state_digest,
            "subject_reference": dict(self.subject_reference),
            "requested_action": self.requested_action,
            "methodology": dict(self.methodology) if self.methodology else None,
            "sections": [s.to_dict() for s in self.sections],
            "external_references": [r.to_dict() for r in self.external_references],
            "engine_version": self.engine_version,
            "case_created_at": self.case_created_at,
            "case_updated_at": self.case_updated_at,
            "notes": list(self.notes),
        }

    @property
    def record_type(self) -> str:
        return "assurance_evidence_pack"

    @property
    def record_id(self) -> str:
        return f"pack:{self.case_id}@v{self.case_version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": self.record_type, "record_id": self.record_id,
                "pack_digest": self.pack_digest, "built_at": self.built_at,
                "decision": self.decision,
                "sections_present": [s.key for s in self.present_sections],
                "sections_absent": [s.key for s in self.absent_sections],
                "sections_not_assessed": [s.key for s in self.unassessed_sections],
                "authorises": False, "establishes_truth": False,
                "bounds_completeness": False,
                "carries_raw_evidence": False,
                **self.content()}

    def render(self) -> str:
        lines = [
            f"ASSURANCE EVIDENCE PACK v{self.schema_version}",
            f"  case        {self.case_id} v{self.case_version}",
            f"  objective   {self.objective}",
            f"  authorising {self.requested_authorization}",
            f"  subject     {self.subject_id}",
            f"    content   {self.subject_digest or '(not hashable)'}",
            f"    approval binds to {self.subject_state_digest or '(none)'}",
            f"  methodology {(self.methodology or {}).get('ref') or '(none)'}",
            f"  decision    {self.decision}",
            "",
            "  sections:",
        ]
        for section in self.sections:
            mark = {SectionState.PRESENT: "+", SectionState.ABSENT: "-",
                    SectionState.NOT_ASSESSED: "?"}[section.state]
            detail = section.digest[:23] if section.digest else section.note[:52]
            lines.append(f"    {mark} {section.key:20} {detail}")
        if self.external_references:
            lines += ["", f"  {len(self.external_references)} external reference(s); "
                          "this pack carries no raw evidence"]
        lines += ["", f"  pack digest {self.pack_digest}",
                  "  This pack records an approval where one exists. It is not one."]
        return "\n".join(lines)


# ── building ────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _digest_of(component: Any) -> Tuple[Optional[str], str]:
    """A component's own digest where it has one, and where the digest came from.

    Folded rather than recomputed wherever possible, so a section and the object
    it describes are provably the same thing — recomputing would give a number
    that agrees today and drifts the first time either side changes what it
    covers. `digest` is a method on most components and a property on some.

    A component exposing neither is digested over its serialised form instead,
    and the section says so. That distinction is worth carrying: a folded digest
    commits to whatever the component decided its identity was, while a
    serialised one commits to this pack's view of it, and an auditor comparing
    two packs built by different versions should be able to see which they have.
    """
    if component is None:
        return None, "none"
    value = getattr(component, "digest", None)
    if callable(value):
        try:
            value = value()
        except Exception:
            value = None
    if value:
        return str(value), "component"
    serialise = getattr(component, "to_dict", None)
    if callable(serialise):
        try:
            return digest_object(serialise()), "serialised"
        except Exception:
            return None, "none"
    return None, "none"


def _derived_section(key: str, component: Any, *, absent_note: str,
                     count: Optional[int] = None,
                     summary: Optional[Mapping[str, Any]] = None) -> PackSection:
    """A section over an analysis component that may legitimately not exist."""
    if component is None:
        return PackSection(key=key, state=SectionState.ABSENT, note=absent_note)
    digest, source = _digest_of(component)
    if digest is None:
        return PackSection(
            key=key, state=SectionState.ABSENT,
            note=f"a {key} was produced but exposes neither a digest nor a "
                 "serialisable form, so nothing in this pack could commit to its "
                 "content")
    return PackSection(key=key, state=SectionState.PRESENT, digest=digest,
                       count=count,
                       summary={**dict(summary or {}), "digest_source": source})


def _artifact_manifest(case: Any) -> PackSection:
    """Every artifact the case holds, by handle and content digest.

    A manifest rather than a graph digest: an auditor checking whether the thing
    that shipped is the thing that was argued needs the individual digests, and
    a single fold over them answers a different question.
    """
    rows: List[Dict[str, Any]] = []
    for record in case.records("artifacts"):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        logical = str(payload.get("logical_id") or payload.get("artifact_id") or "")
        if not logical:
            continue
        rows.append({
            "logical_id": logical,
            "digest": payload.get("digest"),
            "digest_status": payload.get("digest_status"),
            "kind": payload.get("artifact_kind"),
            "content_identified": bool(payload.get("digest"))})
    collection = case.collection("artifacts")
    if not rows:
        return PackSection(
            key="artifact_manifest", state=SectionState.ABSENT,
            note="this case names no artifact; the decision is not about a thing "
                 "with content that could be listed")
    rows.sort(key=lambda r: (r["logical_id"], str(r.get("digest") or "")))
    return PackSection(
        key="artifact_manifest", state=SectionState.PRESENT,
        digest=digest_object({"artifacts": rows}), count=len(rows),
        basis=collection.basis, summary={"artifacts": rows[:64],
                                         "truncated": max(0, len(rows) - 64)})


def _external_references(case: Any) -> List[ExternalReference]:
    """Handles for evidence whose bytes live elsewhere.

    Inline content is skipped: it is already in the case and needs no handle.
    Everything else — an object store key, a URL, a file path, a git range — is
    recorded with its digest, which is what turns "where to look" into "whether
    what you found is what was argued".
    """
    out: List[ExternalReference] = []
    for kind in ("evidence", "artifacts"):
        for record in case.records(kind):
            payload = record.to_dict() if hasattr(record, "to_dict") else {}
            reference = payload.get("content_reference")
            if not isinstance(reference, Mapping):
                continue
            ref_kind = str(reference.get("kind") or "")
            if ref_kind in ("", "INLINE"):
                continue
            out.append(ExternalReference(
                record_id=str(payload.get("record_id") or ""),
                kind=ref_kind, locator=str(reference.get("locator") or ""),
                digest=payload.get("digest") or payload.get("applies_to_digest"),
                byte_length=(reference.get("detail") or {}).get("byte_length"),
                detail={k: v for k, v in (reference.get("detail") or {}).items()
                        if k != "inline"}))
    out.sort(key=lambda r: (r.record_id, r.locator))
    return out


def _verdict_section(case: Any) -> PackSection:
    verdict = getattr(case, "verdict", None)
    if verdict is None:
        return PackSection(
            key="verdict", state=SectionState.ABSENT,
            note="no verdict has been rendered on this case; there is nothing yet "
                 "for a human to accept responsibility for")
    payload = verdict.to_dict()
    return PackSection(
        key="verdict", state=SectionState.PRESENT,
        digest=digest_object(verdict.digest_component()),
        count=len(payload.get("fired_rules") or ()),
        summary={"decision": payload.get("decision"),
                 "fired_rules": payload.get("fired_rules"),
                 "reasons": payload.get("reasons"),
                 "engine_version": payload.get("engine_version"),
                 "ruleset_version": payload.get("ruleset_version"),
                 "decided_at": payload.get("decided_at")})


def _approval_section(case: Any) -> PackSection:
    """Who bound themselves to what, if anyone has.

    `NOT_ASSESSED` rather than `ABSENT` when the collection was never supplied:
    a case that nobody has been asked to approve and a case whose approvals were
    not loaded are different situations, and only the first is a fact about the
    decision.
    """
    from release_gate.assurance.records import Presence

    collection = case.collection("approvals")
    if collection.presence is not Presence.PRESENT:
        return PackSection(
            key="approval_state", state=SectionState.NOT_ASSESSED,
            note="no approvals collection was supplied, so whether anyone has "
                 "authorised this was not asked here")
    rows: List[Dict[str, Any]] = []
    for record in collection.materialised:
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        rows.append({k: payload.get(k) for k in
                     ("record_id", "approver", "decision", "scope", "timestamp",
                      "expires_at", "auth_source", "case_version",
                      "subject_digest", "case_digest")})
    if not rows:
        return PackSection(
            key="approval_state", state=SectionState.ABSENT,
            note="the approvals collection was supplied and holds none; nobody has "
                 "authorised this yet")
    rows.sort(key=lambda r: str(r.get("record_id") or ""))
    return PackSection(
        key="approval_state", state=SectionState.PRESENT,
        digest=digest_object({"approvals": rows}), count=len(rows),
        basis=collection.basis, summary={"approvals": rows[:16]})


def build_pack(outcome: Any, *, completeness: Any = None,
               engine_version: str = "", notes: Sequence[str] = ()
               ) -> AssuranceEvidencePack:
    """Build the pack from a decided outcome.

    Takes the `AssuranceOutcome` rather than a case so the analysis travels with
    the case it describes; handing them separately is how a pack comes to carry
    one case's digests under another's id.

    `completeness` is a `StreamLedger`, supplied by the caller for the same
    reason `facts_for()` takes one: `AnalysisResult` has no completeness field,
    a ledger is built from the event stream a caller holds, and reading it off
    the analysis would leave this section permanently NOT_ASSESSED with nothing
    to say it was unreachable.
    """
    case = getattr(outcome, "case", outcome)
    analysis = getattr(outcome, "analysis", None)
    if case is None or not getattr(case, "case_id", ""):
        raise PackError("build_pack needs a decided outcome or a case")

    def analysed(name: str) -> Any:
        return getattr(analysis, name, None) if analysis is not None else None

    subject = getattr(case, "subject", None)
    subject_state = (case.binding_state().get("state") or {}).get("subject_state") or {}
    methodology = getattr(case, "methodology", None)

    attention = getattr(outcome, "attention", None)
    required = getattr(outcome, "required_evidence", None)
    criticality = analysed("criticality")
    coverage = analysed("coverage_ledger")

    sections = (
        _derived_section(
            "evidence_graph", analysed("evidence_graph"),
            # The true reason, not a plausible one: `AnalysisResult` declares this
            # field and nothing in the current analysis populates it, so it is
            # None for every case regardless of what the case holds. Saying "this
            # case carries no evidence-to-evidence relations" would be a statement
            # about the case that is not so, which is the kind of confident wrong
            # answer a pack must never give an auditor. `EvidenceGraph.from_case`
            # exists; wiring it is analysis work, and the pack folds rather than
            # derives so that every digest here corresponds to something the case
            # was actually decided with.
            absent_note="the analysis that decided this case produced no evidence "
                        "graph — nothing populates that component today, so this "
                        "says nothing about whether such relations exist"),
        _derived_section(
            "execution_graph", analysed("execution_graph"),
            absent_note="no execution telemetry was supplied, so what happened "
                        "was not reconstructed. This is not a record of nothing "
                        "happening"),
        _derived_section(
            "claim_graph", analysed("claim_graph"),
            absent_note="this case declares no claims; there is nothing asserted "
                        "for a graph to model"),
        _artifact_manifest(case),
        _derived_section(
            "critical_claims", criticality,
            absent_note="criticality could not be derived, so what this decision "
                        "rests on was not identified",
            summary=(criticality.summary() if hasattr(criticality, "summary")
                     else {})),
        _derived_section(
            "assumptions", analysed("assumptions"),
            absent_note="no assumption graph was produced; nothing in this case "
                        "declares what it rests on"),
        _derived_section(
            "verification", analysed("verification_graph"),
            absent_note="no typed verification was submitted, so nothing was "
                        "checked by a named method"),
        _derived_section(
            "replications", analysed("replication"),
            absent_note="no replication profile was produced; whether a second "
                        "path reached the same answer was not derived"),
        _derived_section(
            "counterexamples", analysed("counterexamples"),
            absent_note="no counterexample ledger was produced; nobody recorded "
                        "an attempt to break anything here"),
        _derived_section(
            "contradictions", analysed("contradictions"),
            absent_note="no contradiction ledger was produced, so no disagreement "
                        "was looked for. Nothing observed is not nothing present"),
        _derived_section(
            "coverage", coverage,
            absent_note="no coverage ledger was produced, so what was and was not "
                        "examined is unstated (Invariant 9)"),
        (_derived_section(
            "completeness", completeness,
            absent_note="unreachable",
            summary={"status": str(getattr(getattr(completeness, "status", None),
                                           "value", "") or "")})
         if completeness is not None else PackSection(
            key="completeness", state=SectionState.NOT_ASSESSED,
            note="no stream completeness ledger was supplied, so whether all of "
                 "the evidence arrived was never asked")),
        (PackSection(
            key="human_attention", state=SectionState.PRESENT,
            digest=digest_object(attention.to_dict()), count=len(attention.items)
            if hasattr(attention, "items") else None,
            summary={"items": [
                {"item_id": i.item_id, "focus": i.focus, "focus_kind": i.focus_kind,
                 "reason": getattr(i.reason, "value", str(i.reason)),
                 "effect": getattr(i.effect, "value", str(i.effect))}
                for i in getattr(attention, "items", ())[:32]]})
         if attention is not None else PackSection(
            key="human_attention", state=SectionState.ABSENT,
            note="no attention set was produced; nothing was ranked for a person "
                 "to look at")),
        (PackSection(
            key="required_evidence", state=SectionState.PRESENT,
            digest=digest_object(required.protocol()),
            count=len(tuple(required)),
            summary={"requirements": required.protocol().get(
                "required_evidence", [])[:32],
                "satisfies_decision": False})
         if required is not None else PackSection(
            key="required_evidence", state=SectionState.ABSENT,
            note="no required-evidence set was produced; what would resolve this "
                 "was not derived")),
        _verdict_section(case),
        _approval_section(case),
    )

    return AssuranceEvidencePack(
        case_id=case.case_id,
        case_version=int(getattr(case, "case_version", 1) or 1),
        case_digest=str(getattr(case, "case_digest", "") or ""),
        objective=str(getattr(case, "objective", "") or ""),
        requested_authorization=str(getattr(case, "requested_decision", "") or ""),
        subject_id=str(getattr(subject, "subject_id", "") or ""),
        subject_digest=getattr(subject, "digest", None),
        subject_state_digest=str(subject_state.get("state_digest") or "") or None,
        subject_reference=((subject.content_reference.to_dict()
                            if getattr(subject, "content_reference", None) is not None
                            else {}) if subject is not None else {}),
        requested_action=str(getattr(subject, "requested_action", "") or ""),
        # `ref` is a property on MethodologyRef and absent from its to_dict, so an
        # auditor reading the JSON would have to concatenate two fields to learn
        # which methodology decided this. Carried explicitly.
        methodology=({**methodology.to_dict(), "ref": methodology.ref}
                     if methodology is not None else None),
        sections=sections,
        external_references=tuple(_external_references(case)),
        engine_version=engine_version or _engine_version(),
        case_created_at=str(getattr(case, "created_at", "") or ""),
        case_updated_at=str(getattr(case, "updated_at", "") or ""),
        built_at=_utc_now(),
        notes=tuple(notes))


def _engine_version() -> str:
    try:
        from release_gate import __version__
        return str(__version__)
    except Exception:
        return "unknown"


def verify_pack(pack: Any, *, expected_digest: Optional[str] = None
                ) -> Dict[str, Any]:
    """Does this pack still hash to what it says, and does each section?

    The question this module can answer. Whether a *signature* over the digest is
    valid is a different question, answered outside `assurance/` by the crypto
    facilities — and answering it here would not change what the pack
    establishes, because a valid signature over an incomplete manifest is a valid
    signature.

    Takes a pack or its serialised form, so an auditor can check a JSON file
    without reconstructing the objects that produced it.
    """
    payload = pack.to_dict() if hasattr(pack, "to_dict") else dict(pack)
    stated = str(payload.get("pack_digest") or "")
    content = {k: v for k, v in payload.items()
               if k in AssuranceEvidencePack.__dataclass_fields__
               or k in ("sections", "external_references", "methodology",
                        "subject_reference", "notes")}
    # Rebuild exactly what `content()` covers, from the serialised form.
    rebuilt = {
        "schema_version": payload.get("schema_version"),
        "case_id": payload.get("case_id"),
        "case_version": payload.get("case_version"),
        "case_digest": payload.get("case_digest"),
        "objective": payload.get("objective"),
        "requested_authorization": payload.get("requested_authorization"),
        "subject_id": payload.get("subject_id"),
        "subject_digest": payload.get("subject_digest"),
        "subject_state_digest": payload.get("subject_state_digest"),
        "subject_reference": dict(payload.get("subject_reference") or {}),
        "requested_action": payload.get("requested_action"),
        "methodology": (dict(payload["methodology"])
                        if payload.get("methodology") else None),
        "sections": list(payload.get("sections") or ()),
        "external_references": list(payload.get("external_references") or ()),
        "engine_version": payload.get("engine_version"),
        "case_created_at": payload.get("case_created_at"),
        "case_updated_at": payload.get("case_updated_at"),
        "notes": list(payload.get("notes") or ()),
    }
    recomputed = digest_object(rebuilt)
    intact = bool(stated) and recomputed == stated
    matches_expected = (expected_digest is None or recomputed == expected_digest)

    sections = [s for s in (payload.get("sections") or ())]
    unbacked = [s.get("key") for s in sections
                if s.get("state") == SectionState.PRESENT.value and not s.get("digest")]
    unexplained = [s.get("key") for s in sections
                   if s.get("state") != SectionState.PRESENT.value and not s.get("note")]
    missing = [k for k in SECTION_KEYS
               if k not in {s.get("key") for s in sections}]

    return {
        "record_type": "pack_verification",
        "intact": intact and not unbacked and not missing,
        "digest_matches": intact,
        "matches_expected": matches_expected,
        "stated_digest": stated, "recomputed_digest": recomputed,
        "missing_sections": missing,
        "present_without_digest": unbacked,
        "unexplained_absences": unexplained,
        # What a passing verification does and does not mean, in the record
        # rather than in a doc nobody reads next to the result.
        "establishes": "that this pack's content is the content its digest names",
        "does_not_establish": [
            "that the evidence the pack describes is correct",
            "that a signature over this digest is valid — that is asked outside",
            "that everything relevant reached the case (Invariant 3)"],
    }
