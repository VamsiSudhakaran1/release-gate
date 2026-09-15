"""The human approval packet — the eleven questions, in the order a person asks them.

Everything upstream of this module exists so that one person, about to accept
responsibility for something a machine did, can answer eleven questions and know
where each answer came from. The packet is the place those answers are put side
by side. It computes no new judgement: it is a projection of a sealed case, and
it can never be more confident than the case it renders.

The questions are numbered because the order is the product. A reviewer asks what
they are authorising before they ask what supports it, and asks what is
unresolved before they are told what is recommended. A packet that led with the
recommendation would be asking for assent rather than judgement.

Four things this module refuses.

**No section is ever omitted.** All eleven are always present. A section with
nothing to say says so — "no previous verified state", "nothing recorded" — and
never disappears, because an absent section reads as an answered one. This is the
presence model applied to the document a human actually reads.

**"What has not been assessed" is section nine, not a footnote.** It carries the
same numbering and the same weight as the evidence that supports the case.
Burying it is the single most comfortable thing an assurance report can do, and
the reason coverage is part of the verdict rather than an appendix (Invariant 9).

**Filtering is never hiding.** Section seven shows relevant failures, and
"relevant" is a filter, so it obeys the same rule the attention engine does: a
failure bearing on what the decision rests on is never dropped to shorten the
list, and whatever is left out is counted and named by kind.

**The packet binds; it does not approve.** Section ten is a *recommendation* and
`authorises` is unconditionally `False`. Section eleven states the exact digests
an approval would bind to, so that a human act of authorisation attaches to a
specific state of a specific case and to nothing else. Approval is authorisation,
not truth certification, and a packet whose rendering implied otherwise would be
the most load-bearing lie in this system (Invariant 15).

Section eight — what changed since the previous verified state — is the one thing
here that is not a view of the current case. Where no previous state was
supplied it says exactly that. It never says "nothing changed", because a first
run and an unchanged run are different facts and only one of them is reassuring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Tuple)

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.records import MaterialisationBasis

__all__ = [
    "PACKET_SCHEMA_VERSION",
    "ApprovalPacket",
    "AssuranceDelta",
    "PacketSection",
    "SectionKey",
    "build_packet",
    "compare_cases",
    "render_packet",
]

PACKET_SCHEMA_VERSION = 1

#: How many drill-down rows a section carries before the rest are counted rather
#: than listed. Every section declares its basis, so a truncated one is visibly
#: truncated rather than quietly short.
_ROWS_PER_SECTION = 12


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class SectionKey(str, Enum):
    """The eleven, in the order a reviewer asks them."""

    SUBJECT = "SUBJECT"                          # 1  what am I authorising?
    CONSEQUENCE = "CONSEQUENCE"                  # 2  what happens if I do?
    SUPPORTING_EVIDENCE = "SUPPORTING_EVIDENCE"  # 3  what supports it?
    VERIFICATION = "VERIFICATION"                # 4  what was verified?
    UNRESOLVED = "UNRESOLVED"                    # 5  what remains open?
    INDEPENDENCE = "INDEPENDENCE"                # 6  how independent is support?
    FAILURES = "FAILURES"                        # 7  what failed?
    DELTA = "DELTA"                              # 8  what changed since?
    NOT_ASSESSED = "NOT_ASSESSED"                # 9  what was never looked at?
    RECOMMENDATION = "RECOMMENDATION"            # 10 what does release-gate say?
    BINDING = "BINDING"                          # 11 what exactly does this bind to?


#: The question each section answers, in the reviewer's words rather than the
#: system's. Held here so the packet asks the same question every time and a
#: reader comparing two packets is comparing answers, not phrasings.
_QUESTION: Mapping[SectionKey, str] = {
    SectionKey.SUBJECT: "What exactly am I being asked to authorize?",
    SectionKey.CONSEQUENCE: "What happens if I authorize it?",
    SectionKey.SUPPORTING_EVIDENCE: "What evidence supports it?",
    SectionKey.VERIFICATION: "What verification was performed?",
    SectionKey.UNRESOLVED: "What remains unresolved?",
    SectionKey.INDEPENDENCE: "How independent is supporting evidence?",
    SectionKey.FAILURES: "What failed?",
    SectionKey.DELTA: "What changed since the previous verified state?",
    SectionKey.NOT_ASSESSED: "What has not been assessed?",
    SectionKey.RECOMMENDATION: "What does Release-Gate recommend?",
    SectionKey.BINDING: "What exact digests will approval bind to?",
}

_ORDER: Tuple[SectionKey, ...] = tuple(SectionKey)


@dataclass(frozen=True)
class PacketSection:
    """One answered question, with the rows a reviewer can open."""

    key: SectionKey
    answer: str = ""
    rows: Tuple[Mapping[str, Any], ...] = ()
    basis: MaterialisationBasis = MaterialisationBasis.COMPLETE
    truncated: int = 0
    total: int = 0
    drill_down: Tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", SectionKey(self.key))
        object.__setattr__(self, "basis", MaterialisationBasis(self.basis))
        object.__setattr__(self, "rows", tuple(self.rows))
        object.__setattr__(self, "drill_down", tuple(self.drill_down))

    @property
    def number(self) -> int:
        return _ORDER.index(self.key) + 1

    @property
    def question(self) -> str:
        return _QUESTION[self.key]

    @property
    def complete(self) -> bool:
        """Whether every row is shown. Never a claim that every row exists."""
        return self.truncated == 0 and self.basis is MaterialisationBasis.COMPLETE

    def to_dict(self) -> Dict[str, Any]:
        return {"section": self.number, "key": self.key.value,
                "question": self.question, "answer": self.answer,
                "rows": [dict(r) for r in self.rows],
                "row_count": len(self.rows), "total": self.total,
                "truncated": self.truncated, "basis": self.basis.value,
                "shows_every_row": self.complete,
                # A section is a view of what the case holds, never a statement
                # that the case holds everything there was.
                "bounds_completeness": False,
                "drill_down": list(self.drill_down), "note": self.note}

    def render(self) -> str:
        head = [f"## {self.number}. {self.question}", "", self.answer or "(nothing recorded)"]
        if self.rows:
            head.append("")
            for row in self.rows:
                label = str(row.get("label") or row.get("id") or "")
                detail = str(row.get("detail") or "")
                head.append(f"  - {label}{': ' + detail if detail else ''}")
        if self.truncated:
            head.append(f"  … {self.truncated} more not shown of {self.total} "
                        f"({self.basis.value})")
        if self.note:
            head.extend(["", self.note])
        return "\n".join(head)


# ── section 8: what changed ──────────────────────────────────────────────────

@dataclass(frozen=True)
class AssuranceDelta:
    """What moved between a previous state and this one.

    `has_previous` is the field that matters most. A first run and a run where
    nothing changed are different facts, and only one of them is reassuring — so
    an absent previous state is reported as absent rather than as no change.
    """

    has_previous: bool = False
    previous_case_digest: Optional[str] = None
    current_case_digest: Optional[str] = None
    previous_subject_digest: Optional[str] = None
    current_subject_digest: Optional[str] = None
    subject_changed: bool = False
    changed_fields: Tuple[str, ...] = ()
    collection_deltas: Mapping[str, Tuple[int, int]] = field(default_factory=dict)
    previous_decision: Optional[str] = None
    current_decision: Optional[str] = None
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "changed_fields", tuple(sorted(self.changed_fields)))
        object.__setattr__(self, "collection_deltas", dict(self.collection_deltas))

    @property
    def case_changed(self) -> bool:
        return bool(self.has_previous
                    and self.previous_case_digest != self.current_case_digest)

    @property
    def approval_carryover_permitted(self) -> bool:
        """Always False. Not a policy knob — a refusal.

        Re-approval after a change is a new human act. A field that could ever be
        True would eventually be set to True by something automated at 3am, which
        is the whole reason `describe_supersession` refuses it too.
        """
        return False

    @property
    def grew(self) -> Tuple[str, ...]:
        return tuple(sorted(k for k, (before, after) in self.collection_deltas.items()
                            if after > before))

    @property
    def shrank(self) -> Tuple[str, ...]:
        """Evidentiary collections that lost records.

        Worth its own accessor: evidence disappearing between two states is the
        shape of selective disclosure, and it should be as easy to ask about as
        evidence arriving (Invariant 13).

        Restricted to the collections that constitute the evidentiary state.
        Release-gate's own derived outputs — attention items, required evidence —
        shrink whenever it finds less to say, and reporting that as "evidence
        present before and absent now" would cry wolf on the one signal here that
        most needs to be believed.
        """
        from release_gate.assurance.case import EVIDENCE_KINDS
        return tuple(sorted(k for k, (before, after) in self.collection_deltas.items()
                            if after < before and k in EVIDENCE_KINDS))

    @property
    def derived_shrank(self) -> Tuple[str, ...]:
        """Release-gate's own outputs that got smaller. Not a disclosure signal."""
        from release_gate.assurance.case import EVIDENCE_KINDS
        return tuple(sorted(k for k, (before, after) in self.collection_deltas.items()
                            if after < before and k not in EVIDENCE_KINDS))

    def to_dict(self) -> Dict[str, Any]:
        return {"has_previous": self.has_previous,
                "case_changed": self.case_changed,
                "subject_changed": self.subject_changed,
                "changed_fields": list(self.changed_fields),
                "previous_case_digest": self.previous_case_digest,
                "current_case_digest": self.current_case_digest,
                "previous_subject_digest": self.previous_subject_digest,
                "current_subject_digest": self.current_subject_digest,
                "previous_decision": self.previous_decision,
                "current_decision": self.current_decision,
                "collections_grew": list(self.grew),
                "evidence_shrank": list(self.shrank),
                "derived_shrank": list(self.derived_shrank),
                "collection_deltas": {k: list(v)
                                      for k, v in sorted(self.collection_deltas.items())},
                "approval_carryover_permitted": False,
                "basis": self.basis}

    def render(self) -> str:
        if not self.has_previous:
            return ("No previous verified state was supplied, so nothing here is a "
                    "comparison. This is not the same as nothing having changed.")
        if not self.case_changed:
            return (f"The case is byte-identical to {self.previous_case_digest}; "
                    "no collection gained or lost a record.")
        parts = [f"The case moved from {self.previous_case_digest} to "
                 f"{self.current_case_digest}."]
        if self.subject_changed:
            what = (", ".join(self.changed_fields) if self.changed_fields
                    else "its content digest moved, though no identity field did")
            parts.append(f"The subject itself changed ({what}), so any approval of "
                         "the previous subject applies to the previous subject only.")
        if self.grew:
            parts.append("Gained records: " + ", ".join(self.grew) + ".")
        if self.shrank:
            parts.append("LOST evidence: " + ", ".join(self.shrank) +
                         " — records present before and absent now.")
        if self.derived_shrank:
            parts.append("(Release-gate's own outputs also got smaller: "
                         + ", ".join(self.derived_shrank)
                         + " — that is this engine finding less to say, not "
                           "evidence going missing.)")
        if self.previous_decision != self.current_decision:
            parts.append(f"The recommendation moved "
                         f"{self.previous_decision} -> {self.current_decision}.")
        return " ".join(parts)


def compare_cases(previous: Any, current: Any) -> AssuranceDelta:
    """What changed between two cases, or that there was no previous one.

    `previous` may be a full `AssuranceCase` or the `binding_state()` dict of one,
    so a caller can compare against a stored state without keeping the whole case
    alive. `None` yields a delta that says plainly there was nothing to compare
    against, which is the honest answer and never silence.
    """
    current_state = current.binding_state()
    current_digest = current_state.get("case_digest")
    current_subject = (current_state.get("state") or {}).get("subject_state") or {}
    current_decision = (current.verdict.decision.value if current.verdict else None)

    if previous is None:
        return AssuranceDelta(
            has_previous=False, current_case_digest=current_digest,
            current_subject_digest=current_subject.get("state_digest"),
            current_decision=current_decision,
            basis="no previous verified state was supplied; this is a first "
                  "assessment rather than a comparison")

    previous_state = (previous if isinstance(previous, Mapping)
                      else previous.binding_state())
    prev_inner = previous_state.get("state") or {}
    prev_subject = prev_inner.get("subject_state") or {}

    changed = [key for key, value in (prev_subject.get("identity") or {}).items()
               if (current_subject.get("identity") or {}).get(key) != value]

    deltas: Dict[str, Tuple[int, int]] = {}
    prev_collections = prev_inner.get("collections") or {}
    cur_collections = (current_state.get("state") or {}).get("collections") or {}
    for kind in sorted(set(prev_collections) | set(cur_collections)):
        before = int((prev_collections.get(kind) or {}).get("total_count") or 0)
        after = int((cur_collections.get(kind) or {}).get("total_count") or 0)
        if before != after:
            deltas[kind] = (before, after)

    prev_verdict = prev_inner.get("verdict") or {}
    return AssuranceDelta(
        has_previous=True,
        previous_case_digest=previous_state.get("case_digest"),
        current_case_digest=current_digest,
        previous_subject_digest=prev_subject.get("state_digest"),
        current_subject_digest=current_subject.get("state_digest"),
        subject_changed=bool(changed) or (
            prev_subject.get("state_digest") != current_subject.get("state_digest")),
        changed_fields=tuple(changed),
        collection_deltas=deltas,
        previous_decision=(prev_verdict.get("decision") if isinstance(prev_verdict, Mapping)
                           else None),
        current_decision=current_decision,
        basis="compared against the supplied previous binding state")


# ── the packet ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ApprovalPacket:
    """The eleven questions, answered against one sealed case."""

    sections: Tuple[PacketSection, ...] = ()
    case_digest: Optional[str] = None
    binding_state: Mapping[str, Any] = field(default_factory=dict)
    decision: str = "HOLD"
    built_at: str = field(default_factory=_utc_now)
    schema_version: int = PACKET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "sections", tuple(self.sections))
        present = [s.key for s in self.sections]
        missing = [k for k in _ORDER if k not in present]
        if missing:
            raise ValueError(
                "an approval packet must answer all eleven questions; missing "
                + ", ".join(k.value for k in missing)
                + ". A section with nothing to say says so — an absent one reads "
                  "as an answered one.")

    def section(self, key: SectionKey) -> PacketSection:
        return next(s for s in self.sections if s.key is SectionKey(key))

    @property
    def authorises(self) -> bool:
        """Always False. The packet binds; a person approves.

        Section ten is a recommendation. Rendering it as an authorisation would
        let the document that exists to inform a human decision stand in for the
        decision (Invariant 15).
        """
        return False

    @property
    def truncated_sections(self) -> Tuple[PacketSection, ...]:
        return tuple(s for s in self.sections if not s.complete)

    def matches(self, case: Any) -> bool:
        """Whether this packet still describes that case.

        A packet is a view of one exact state. If the case has moved, the packet
        is stale and everything in it — including section eleven's digests —
        describes something that is no longer what would be authorised.
        """
        try:
            return case.binding_state().get("case_digest") == self.case_digest
        except Exception:
            return False

    def digest(self) -> str:
        return digest_object({"sections": [s.to_dict() for s in self.sections],
                              "case_digest": self.case_digest,
                              "schema_version": PACKET_SCHEMA_VERSION})

    @property
    def packet_id(self) -> str:
        return short_id("pkt", self.digest())

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "approval_packet", "record_id": self.packet_id,
                "schema_version": PACKET_SCHEMA_VERSION,
                "case_digest": self.case_digest,
                "recommendation": self.decision,
                "authorises": False,
                "built_at": self.built_at,
                "sections": [s.to_dict() for s in self.sections],
                "binds_to": dict(self.binding_state)}

    def render(self) -> str:
        head = [f"# Approval packet {self.packet_id}",
                f"Case {self.case_digest}",
                "",
                "This packet states what is known and what is not. It does not "
                "authorise anything: approval is a human act, and section 11 says "
                "exactly what such an act would bind to.",
                ""]
        return "\n".join(head + [s.render() + "\n" for s in self.sections])


def _rows(entries: Sequence[Mapping[str, Any]], total: Optional[int] = None,
          basis: MaterialisationBasis = MaterialisationBasis.COMPLETE
          ) -> Tuple[Tuple[Mapping[str, Any], ...], int, int, MaterialisationBasis]:
    """Cap drill-down rows, and report the cap rather than absorbing it."""
    count = total if total is not None else len(entries)
    shown = tuple(entries[:_ROWS_PER_SECTION])
    hidden = max(0, count - len(shown))
    if hidden:
        basis = MaterialisationBasis.CAPPED
    return shown, hidden, count, basis


# ── the eleven builders ──────────────────────────────────────────────────────

def _subject_section(case: Any) -> PacketSection:
    subject = case.subject
    state = subject.binding_state()
    rows = [{"label": "subject_id", "detail": subject.subject_id},
            {"label": "type", "detail": subject.subject_type.value},
            {"label": "requested action", "detail": subject.requested_action},
            {"label": "content", "detail": str(subject.content_reference.locator
                                               if subject.content_reference else "-")},
            {"label": "digest", "detail": str(subject.digest or "not recorded")},
            {"label": "digest basis", "detail": subject.digest_basis or "-"},
            {"label": "digest status", "detail": subject.digest_status.value}]
    shown, hidden, total, basis = _rows(rows)
    return PacketSection(
        key=SectionKey.SUBJECT,
        answer=(f"{subject.requested_action} — {subject.subject_type.value} "
                f"{subject.subject_id}, content {subject.digest or 'undigested'}"),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("subject",),
        note=("The digest is what makes this exact. A subject whose digest status "
              "is not OBSERVED was not hashed by release-gate, and what you are "
              "authorising is then whatever that reference resolves to at the time "
              "somebody acts on it."
              if state.get("identity", {}).get("digest_status") != "OBSERVED" else ""))


def _consequence_section(analysis: Any, outcome: Any) -> PacketSection:
    profile = getattr(outcome, "consequence", None)
    if profile is None:
        return PacketSection(
            key=SectionKey.CONSEQUENCE,
            answer="No consequence profile was built, so what happens if you "
                   "authorise this has not been assessed.",
            note="Nobody having stated the stakes is not evidence that the stakes "
                 "are low.")
    known = list(profile.known)
    unknown = list(profile.unknown)
    rows = [{"label": d.dimension.value, "detail": f"{d.value} ({d.basis.value})"}
            for d in known]
    rows += [{"label": d.dimension.value, "detail": "UNKNOWN — nobody stated this"}
             for d in unknown]
    shown, hidden, total, basis = _rows(rows)
    return PacketSection(
        key=SectionKey.CONSEQUENCE,
        answer=(f"{len(known)} of {len(known) + len(unknown)} consequence "
                f"dimension(s) are stated"
                + (f"; {len(unknown)} are UNKNOWN" if unknown else "")),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("consequence",),
        note=("UNKNOWN dimensions are listed rather than omitted: an unstated "
              "consequence is an unassessed one, not a small one (Invariant 3)."
              if unknown else ""))


def _supporting_section(case: Any, analysis: Any) -> PacketSection:
    criticality = getattr(analysis, "criticality", None)
    critical = set(criticality.critical_ids) if (
        criticality is not None and criticality.determinable) else set()
    records = [r for r in case.records("evidence")
               if getattr(r, "record_type", "") == "evidence"]

    def weight(record: Any) -> Tuple[int, str]:
        # Critical evidence first, as the question asks. Support for a claim the
        # decision rests on is what a reviewer reads before anything else.
        supports = set(getattr(record, "supports_claims", ()) or ())
        return (0 if supports & critical else 1, getattr(record, "evidence_id", ""))

    ordered = sorted(records, key=weight)
    rows = [{"label": r.evidence_id,
             "detail": (f"{r.evidence_type.value} from {r.producer.producer_id} "
                        f"[{r.epistemic_status.value}]"
                        + (" — supports a load-bearing claim"
                           if set(r.supports_claims or ()) & critical else "")),
             "critical": bool(set(r.supports_claims or ()) & critical)}
            for r in ordered]
    shown, hidden, total, basis = _rows(rows)
    on_critical = sum(1 for r in rows if r["critical"])
    return PacketSection(
        key=SectionKey.SUPPORTING_EVIDENCE,
        answer=(f"{total} evidence record(s), {on_critical} of them supporting a "
                "claim the decision rests on"
                if total else "No evidence records are held on this case."),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("evidence", "claims"),
        note=("Ordered with load-bearing support first. Epistemic status is shown "
              "on every row: DECLARED is what a producer asserted, not what "
              "release-gate established." if total else ""))


def _verification_section(analysis: Any) -> PacketSection:
    graph = getattr(analysis, "verification_graph", None)
    attempts = list(graph.attempts) if graph is not None else []
    if not attempts:
        return PacketSection(
            key=SectionKey.VERIFICATION,
            answer="No typed verification is recorded on this case.",
            drill_down=("verification",),
            note="Nothing here was checked by a named method against a named "
                 "state. That is a fact about the case, not about the subject.")
    rows = [{"label": a.verification_id,
             "detail": (f"{a.method.value} by {a.verifier or 'unnamed'} -> "
                        f"{a.status.value}"
                        + ("" if a.target_digest
                           else " (no target digest: applicability undetermined)"))}
            for a in sorted(attempts, key=lambda x: (x.status.value, x.verification_id))]
    shown, hidden, total, basis = _rows(rows)
    by_status: Dict[str, int] = {}
    for attempt in attempts:
        by_status[attempt.status.value] = by_status.get(attempt.status.value, 0) + 1
    return PacketSection(
        key=SectionKey.VERIFICATION,
        answer=f"{total} attempt(s): "
               + ", ".join(f"{v} {k}" for k, v in sorted(by_status.items())),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("verification",),
        note="An attempt with no target digest cannot be shown to apply to the "
             "current state; UNDETERMINED is not APPLIES.")


def _unresolved_section(outcome: Any, analysis: Any) -> PacketSection:
    rows: List[Dict[str, Any]] = []
    contradictions = outcome.contradictions
    for item in contradictions.open():
        rows.append({"label": item.contradiction_id,
                     "detail": f"contradiction on {', '.join(item.target_claims)}"
                               + (" (critical)" if item.affects_critical else "")})
    for attempt in outcome.counterexamples.open():
        rows.append({"label": attempt.counterexample_id,
                     "detail": f"counterexample against {attempt.target_claim}"})
    assumptions = outcome.assumptions
    for assumption in getattr(assumptions, "unexamined", lambda: ())():
        rows.append({"label": assumption.assumption_id,
                     "detail": f"unexamined assumption: {assumption.statement[:60]}"})
    review = getattr(analysis, "adversarial", None)
    if review is not None:
        for finding in review.open():
            rows.append({"label": finding.finding_id,
                         "detail": f"{finding.outcome.value} against "
                                   f"{finding.target_claim}"})
    ledger = getattr(analysis, "coverage_ledger", None)
    if ledger is not None:
        for row in ledger.known_missing():
            rows.append({"label": row.dimension,
                         "detail": f"{row.known_missing} expected record(s) never "
                                   "arrived"})
    shown, hidden, total, basis = _rows(rows)
    return PacketSection(
        key=SectionKey.UNRESOLVED,
        answer=(f"{total} unresolved item(s): contradictions, counterexamples, "
                "unexamined assumptions, open adversarial findings and evidence "
                "known to be missing" if total
                else "Nothing recorded on this case is unresolved."),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("contradictions", "counterexamples", "assumptions", "coverage"),
        note=("Nothing here has been resolved by being listed. Each is open until "
              "something answers it and that something is named."
              if total else ""))


def _independence_section(analysis: Any) -> PacketSection:
    profile = getattr(analysis, "independence", None)
    if profile is None or not profile.contributors:
        return PacketSection(
            key=SectionKey.INDEPENDENCE,
            answer="No contributing evidence, so independence cannot be assessed.",
            drill_down=("evidence",))
    rows = [{"label": cluster.cluster_id,
             "detail": f"{cluster.size} contributor(s), {len(cluster.roots)} root(s)"}
            for cluster in profile.clusters]
    shown, hidden, total, basis = _rows(rows)
    return PacketSection(
        key=SectionKey.INDEPENDENCE,
        answer=(f"{profile.contributors:,} contributor(s) across "
                f"{profile.independent_roots} lineage(s); concentration "
                f"{profile.concentration.value}"),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("evidence",),
        note=("Structure, not probability. Agreement among parties that derive "
              "from one source is one validation observed many times, and this "
              "says which shape you have rather than how likely the result is."))


def _failures_section(outcome: Any, analysis: Any) -> PacketSection:
    criticality = getattr(analysis, "criticality", None)
    critical = set(criticality.critical_ids) if (
        criticality is not None and criticality.determinable) else set()
    ledger = outcome.failed_branches
    branches = list(ledger.branches)

    def relevant(branch: Any) -> bool:
        return bool(set(getattr(branch, "bears_on_claims", ()) or ()) & critical)

    # "Relevant only" is a filter, and a filter is compression. It obeys the same
    # rule the attention engine does: a failure bearing on what the decision rests
    # on is never dropped to shorten the list.
    load_bearing = [b for b in branches if relevant(b)]
    other = [b for b in branches if not relevant(b)]
    rows = ([{"label": b.branch_id,
              "detail": f"{b.failure_point} — bears on "
                        f"{', '.join(b.bears_on_claims[:3])}"}
             for b in load_bearing]
            + [{"label": p.key, "detail": f"{p.count} attempt(s) died here"}
               for p in ledger.recurring()])
    dropped = max(0, len(other) - max(0, _ROWS_PER_SECTION - len(rows)))
    shown, hidden, total, basis = _rows(rows, total=len(rows) + dropped)
    return PacketSection(
        key=SectionKey.FAILURES,
        answer=(f"{len(load_bearing)} failure(s) bear on what the decision rests "
                f"on; {len(ledger.recurring())} failure point(s) recur"
                if branches or ledger.recurring()
                else "No failed attempts are recorded on this case."),
        rows=shown, truncated=hidden + dropped, total=total,
        basis=(MaterialisationBasis.RELEVANCE_DIRECTED if dropped else basis),
        drill_down=("failed_branches",),
        note=(f"{dropped} failure(s) not bearing on the critical path are counted "
              "and not listed. Nothing load-bearing is ever withheld here."
              if dropped else ""))


def _not_assessed_section(case: Any, analysis: Any,
                          level: Any = None) -> PacketSection:
    """What was never looked at, read from the sealed case rather than the analysis.

    The analysis carries a coverage ledger built while it was still running, so
    the dimensions the analysers themselves fill in — criticality, contradiction,
    adversarial review — are NOT_ASSESSED in it whatever the analysers went on to
    find. The case is the authoritative record of what was assessed, and this
    section is a projection of the case. Reading the analysis here reported
    dimensions as never examined that section 5 was simultaneously reporting
    findings from.
    """
    # Never-examined and examined-without-a-denominator are both things a reviewer
    # must know and are not the same fact, so they are counted and labelled
    # separately rather than merged into one number. Never-examined comes first.
    unexamined: List[Dict[str, Any]] = []
    unmeasured: List[Dict[str, Any]] = []
    for record in case.records("coverage"):
        payload = record.to_dict() if hasattr(record, "to_dict") else {}
        dimension = str(payload.get("dimension") or "")
        if not dimension:
            continue
        state = str(payload.get("state") or payload.get("status") or "")
        note = str(payload.get("note") or "")[:110]
        if state == "NOT_ASSESSED":
            # A dimension that applies above this decision's depth is still
            # listed — it is genuinely NOT_ASSESSED and Invariant 3 does not
            # bend — but it is labelled as out of depth rather than left to read
            # as a gap. A Level 1 action that has not been replicated is not a
            # Level 1 action with a replication problem.
            above = bool(level is not None and dimension in (level.out_of_scope or ()))
            unexamined.append({"label": f"NOT ASSESSED — {dimension}",
                               "detail": ((note + " " if note else "")
                                          + f"(applies above {level.required.label}; "
                                            "not expected at this depth)").strip()
                                         if above else (note or "never examined"),
                               "state": "NOT_ASSESSED",
                               "above_level": above})
        elif state == "UNKNOWN":
            unmeasured.append({"label": f"NO DENOMINATOR — {dimension}",
                               "detail": note or ("examined; nothing states how much "
                                                  "there should have been, so no "
                                                  "proportion exists"),
                               "state": "UNKNOWN"})
    # In-depth gaps first: a dimension this decision was expected to populate and
    # did not is the one a reviewer must act on, and it must not be buried under
    # frontier structures a small case was never going to carry. Sorted before
    # the concatenation, because sorting afterwards leaves `rows` untouched.
    unexamined.sort(key=lambda r: bool(r.get("above_level")))
    above_count = sum(1 for r in unexamined if r.get("above_level"))
    in_depth = len(unexamined) - above_count
    rows: List[Dict[str, Any]] = unexamined + unmeasured
    criticality = getattr(analysis, "criticality", None)
    if criticality is not None and not criticality.determinable:
        rows.append({"label": "criticality",
                     "detail": "what this decision rests on could not be derived, "
                               "so every critical-claim guard was inactive"})
    for kind in ("claims", "artifacts", "executions", "verification",
                 "contradictions", "assumptions", "counterexamples"):
        collection = case.collection(kind)
        if collection.presence.value == "ABSENT":
            rows.append({"label": kind, "detail": "collection never supplied"})
    shown, hidden, total, basis = _rows(rows)
    if total and above_count:
        answer = (f"{in_depth} dimension(s) this decision was expected to cover were "
                  f"never examined; a further {above_count} apply above "
                  f"{level.required.label} and are not expected at this depth; "
                  f"{len(unmeasured)} were examined with no denominator")
    elif total:
        answer = (f"{len(unexamined)} dimension(s) were never examined; "
                  f"{len(unmeasured)} were examined with no denominator, so their "
                  "coverage is UNKNOWN rather than a percentage")
    else:
        answer = "Every dimension release-gate examines was assessed."
    return PacketSection(
        key=SectionKey.NOT_ASSESSED,
        answer=answer,
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("coverage",),
        note=("This section carries the same weight as section 3. An unassessed "
              "dimension is not a passed one, and a dimension examined without a "
              "denominator has no percentage — the two are listed apart because "
              "they are different facts (Invariant 9)."))


def _recommendation_section(case: Any, outcome: Any) -> PacketSection:
    verdict = case.verdict
    if verdict is None:
        return PacketSection(
            key=SectionKey.RECOMMENDATION,
            answer="No verdict was rendered on this case.",
            note="A packet without a verdict recommends nothing.")
    rows = [{"label": rule, "detail": ""} for rule in verdict.fired_rules]
    rows += [{"label": "reason", "detail": reason} for reason in verdict.reasons]
    shown, hidden, total, basis = _rows(rows)
    assessment = getattr(outcome, "assessment", None)
    unmet = len(assessment.unmet()) if assessment is not None else 0
    return PacketSection(
        key=SectionKey.RECOMMENDATION,
        answer=(f"{verdict.decision.value} — from {len(verdict.fired_rules)} fired "
                f"rule(s)" + (f", {unmet} unmet requirement(s)" if unmet else "")),
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("coverage", "attention_items", "required_evidence"),
        note=("This is a recommendation about evidence, not an authorisation. "
              "Release-gate can say this case contradicts itself; it cannot say "
              "this is enough to proceed — that judgement, and the responsibility "
              "for it, is yours (Invariant 15)."))


def _binding_section(case: Any) -> PacketSection:
    state = case.binding_state()
    inner = state.get("state") or {}
    subject_state = inner.get("subject_state") or {}
    rows = [{"label": "case_digest", "detail": str(state.get("case_digest"))},
            {"label": "case_version", "detail": str(state.get("case_version"))},
            {"label": "binding_algo", "detail": str(inner.get("binding_algo"))},
            {"label": "subject_state_digest",
             "detail": str(subject_state.get("state_digest"))},
            {"label": "evidence_digest", "detail": str(inner.get("evidence_digest"))}]
    for kind, component in sorted((inner.get("collections") or {}).items()):
        if isinstance(component, Mapping) and component.get("digest"):
            rows.append({"label": f"collection:{kind}",
                         "detail": str(component.get("digest"))})
    shown, hidden, total, basis = _rows(rows)
    return PacketSection(
        key=SectionKey.BINDING,
        answer=f"An approval would bind to case {state.get('case_digest')} at "
               f"version {state.get('case_version')}",
        rows=shown, truncated=hidden, total=total, basis=basis,
        drill_down=("approvals",),
        note=("These digests are what an approval attaches to. If any of them "
              "moves, the approval describes a state that no longer exists and "
              "does not carry to the new one."))


def build_packet(case: Any, outcome: Any = None, *,
                 previous: Any = None) -> ApprovalPacket:
    """Answer the eleven questions against one sealed case.

    `outcome` supplies the analysis views the case does not itself hold. Where it
    is absent the sections fall back to what the case carries and say so, rather
    than omitting themselves.
    """
    analysis = getattr(outcome, "analysis", None)
    delta = compare_cases(previous, case)
    sections = (
        _subject_section(case),
        _consequence_section(analysis, outcome),
        _supporting_section(case, analysis),
        _verification_section(analysis),
        _unresolved_section(outcome, analysis) if outcome is not None else
        PacketSection(key=SectionKey.UNRESOLVED,
                      answer="No analysis was supplied, so what remains unresolved "
                             "has not been derived."),
        _independence_section(analysis),
        _failures_section(outcome, analysis) if outcome is not None else
        PacketSection(key=SectionKey.FAILURES,
                      answer="No analysis was supplied, so failures were not "
                             "collected."),
        PacketSection(key=SectionKey.DELTA, answer=delta.render(),
                      rows=({"label": "approval_carryover_permitted",
                             "detail": "False — re-approval after a change is a "
                                       "new human act"},),
                      drill_down=("approvals",), total=1,
                      note=delta.basis),
        _not_assessed_section(case, analysis, getattr(outcome, "level", None)),
        _recommendation_section(case, outcome),
        _binding_section(case),
    )
    state = case.binding_state()
    return ApprovalPacket(
        sections=sections, case_digest=state.get("case_digest"),
        binding_state=state,
        decision=(case.verdict.decision.value if case.verdict else "HOLD"))


def render_packet(packet: ApprovalPacket) -> str:
    return packet.render()
