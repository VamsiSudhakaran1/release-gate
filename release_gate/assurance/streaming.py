"""Long-running cases: what phase the work is in, observed rather than directed.

A case can stay open for hours. Agents keep working, evidence keeps arriving, and
a reviewer wants to know where things stand *now* — not after everything stops.
This module answers that, and the whole design is shaped by one constraint:

**Release-gate must not become the orchestrator.**

So every phase here is an **observation about evidence**, never an instruction.
There is no `begin_verification()`, no `request_review()`, nothing that tells an
external system what to do next. `observe_phase()` is a pure function of a case:
the same case always yields the same phase, reading it changes nothing, and
release-gate reports `VERIFYING` because verification attempts are arriving — not
to announce that verification should now begin. `PhaseObservation.directs_work`
is an unconditional `False` property, so no caller can read this as a command.

The difference matters at the point where it would be tempting to cross it. When
a case sits in `EVIDENCE_ACCUMULATING` with an unresolved contradiction,
release-gate says so and stops. It does not pause the agents, does not schedule a
verifier, does not retry anything. An orchestrator watching this may do all three;
that is its job, and the separation is what lets one assurance engine sit behind
many orchestrators without owning any of them.

**Two axes, deliberately not merged.** `CaseState` (DRAFT / SEALED / APPROVED /
SUPERSEDED / INVALIDATED) is the *record's* integrity lifecycle: SEALED means the
digest is fixed and a verdict may be attached. `AssurancePhase` is the *work's*
progress. Folding them together would mean a case could not be both "evidence
still arriving" and "this snapshot is sealed and digested", which is exactly the
state a long-running case is in every time somebody reads it.

**Transitions are reported, never enforced.** Release-gate cannot refuse a
transition, because it does not control the world: if evidence arrives after a
human started reviewing, that happened. A backward move is a *finding* — the
reviewer is looking at a case that has since changed — not an error to reject.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

STREAMING_SCHEMA_VERSION = 1


class AssurancePhase(str, Enum):
    """Where the work stands, as read off the evidence.

    Ordered by normal progression so `>` means "further along", which is what
    makes a regression detectable. The order is a reading aid, not a ranking:
    `OPEN` is not a worse phase than `APPROVED`, it is an earlier one.
    """

    OPEN = "OPEN"                                    # nothing has arrived
    EVIDENCE_ACCUMULATING = "EVIDENCE_ACCUMULATING"  # work is producing records
    CANDIDATE_READY = "CANDIDATE_READY"              # something identifiable to judge
    VERIFYING = "VERIFYING"                          # checks are running or unsettled
    HUMAN_REVIEW = "HUMAN_REVIEW"                    # a verdict is rendered, awaiting a person
    APPROVED = "APPROVED"                            # a bound approval stands
    REJECTED = "REJECTED"                            # a person declined
    INVALIDATED = "INVALIDATED"                      # the thing judged has moved

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    @property
    def terminal(self) -> bool:
        """No further phase follows from evidence alone."""
        return self in (AssurancePhase.APPROVED, AssurancePhase.REJECTED,
                        AssurancePhase.INVALIDATED)

    def describe(self) -> str:
        return _DESCRIPTION[self]


_ORDER: Tuple[AssurancePhase, ...] = (
    AssurancePhase.OPEN,
    AssurancePhase.EVIDENCE_ACCUMULATING,
    AssurancePhase.CANDIDATE_READY,
    AssurancePhase.VERIFYING,
    AssurancePhase.HUMAN_REVIEW,
    AssurancePhase.APPROVED,
    AssurancePhase.REJECTED,
    AssurancePhase.INVALIDATED,
)

_DESCRIPTION: Mapping[AssurancePhase, str] = {
    AssurancePhase.OPEN: "the case exists and nothing has been submitted to it",
    AssurancePhase.EVIDENCE_ACCUMULATING:
        "records are arriving and there is not yet an identified thing to judge",
    AssurancePhase.CANDIDATE_READY:
        "there is an identified subject with evidence about it, and nothing has "
        "checked it yet",
    AssurancePhase.VERIFYING:
        "typed checks are recorded and at least one has not settled",
    AssurancePhase.HUMAN_REVIEW:
        "a verdict has been rendered on a sealed case and a person has not "
        "answered it",
    AssurancePhase.APPROVED: "a bound approval stands against this exact state",
    AssurancePhase.REJECTED: "a person declined to authorise this",
    AssurancePhase.INVALIDATED:
        "the subject or the case moved, so what was judged is not what is here",
}


@dataclass(frozen=True)
class PhaseObservation:
    """What phase a case is in, why, and what release-gate is not doing about it."""

    phase: AssurancePhase
    basis: str = ""
    #: Counts the phase was read from, so the reading can be checked rather than
    #: taken on trust.
    observed: Mapping[str, Any] = field(default_factory=dict)
    #: Live concerns, available while the work continues. This is the point of
    #: streaming assurance: a weakness that surfaces at minute three is worth far
    #: more than the same weakness at hour six.
    open_concerns: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "phase", AssurancePhase(self.phase))
        object.__setattr__(self, "observed", dict(self.observed or {}))
        object.__setattr__(self, "open_concerns", tuple(self.open_concerns))

    @property
    def directs_work(self) -> bool:
        """Unconditionally False. A phase is a reading, never an instruction.

        Release-gate reports `VERIFYING` because verification attempts are
        arriving, not to announce that verification should begin. Nothing here
        pauses an agent, schedules a verifier or retries anything — an
        orchestrator watching this may do all three, and that separation is what
        lets one assurance engine sit behind many orchestrators.
        """
        return False

    @property
    def settled(self) -> bool:
        return self.phase.terminal

    def note(self) -> str:
        line = f"{self.phase.value}: {self.phase.describe()}."
        if self.open_concerns:
            line += (f" {len(self.open_concerns)} concern(s) are already visible "
                     "and do not need the work to finish.")
        return line

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_phase", "phase": self.phase.value,
                "rank": self.phase.rank, "terminal": self.phase.terminal,
                "basis": self.basis, "observed": dict(self.observed),
                "open_concerns": list(self.open_concerns),
                "directs_work": False, "note": self.note(),
                "schema_version": STREAMING_SCHEMA_VERSION}


@dataclass(frozen=True)
class PhaseTransition:
    """One observed move, and whether it went the way work normally goes."""

    previous: AssurancePhase
    current: AssurancePhase

    def __post_init__(self) -> None:
        object.__setattr__(self, "previous", AssurancePhase(self.previous))
        object.__setattr__(self, "current", AssurancePhase(self.current))

    @property
    def regressed(self) -> bool:
        """Work moved backwards. A finding, not an error.

        Release-gate cannot refuse this: it does not control the world, and if
        evidence arrived after a human started reviewing then that happened. What
        it can do is say so, because a reviewer holding an opinion about a case
        that has since changed is exactly who needs telling.
        """
        if self.current is AssurancePhase.INVALIDATED:
            # Reachable from anywhere and never a regression: the subject moving
            # is new information, not a step backwards.
            return False
        return self.current.rank < self.previous.rank

    @property
    def reopens_a_settled_case(self) -> bool:
        return self.previous.terminal and self.current is not self.previous

    def note(self) -> str:
        if self.previous is self.current:
            return f"still {self.current.value}"
        if self.reopens_a_settled_case:
            return (f"{self.previous.value} → {self.current.value}: a settled case "
                    "changed. Any decision taken on the earlier state was taken on "
                    "a state that no longer holds.")
        if self.regressed:
            return (f"{self.previous.value} → {self.current.value}: the work moved "
                    "backwards. Evidence arrived after the case had progressed "
                    "past the point that evidence belongs to, so anyone holding a "
                    "view formed earlier is holding it about a different case.")
        return f"{self.previous.value} → {self.current.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {"previous": self.previous.value, "current": self.current.value,
                "regressed": self.regressed,
                "reopens_a_settled_case": self.reopens_a_settled_case,
                "note": self.note()}


def _count(case: Any, kind: str) -> int:
    try:
        collection = case.collection(kind)
    except Exception:
        return 0
    return int(getattr(collection, "total_count", 0) or 0)


def _submitted(case: Any, kind: str) -> int:
    """Records somebody other than release-gate put in.

    The engine records its own work as evidence — the input container it hashed,
    and the consequence, independence and criticality profiles it derived — so a
    case with nothing submitted still holds several evidence records. Counting
    those made `OPEN` and `EVIDENCE_ACCUMULATING` unreachable: every session
    reported `CANDIDATE_READY` before anyone had sent anything.

    Producer kind is the honest discriminator. "Has any work arrived" is a
    question about work, and release-gate hashing its own input is not work
    arriving.
    """
    try:
        records = case.collection(kind).materialised
    except Exception:
        return 0
    total = 0
    for record in records:
        producer = getattr(record, "producer", None)
        producer_id = str(getattr(producer, "producer_id", "") or "")
        kind_value = str(getattr(getattr(producer, "kind", None), "value", "") or "")
        if kind_value == "release_gate" or not producer_id:
            # Release-gate's own: the input container it hashed, and the
            # consequence, independence and criticality profiles it derived and
            # folded in as summary rows with no producer at all. Submitted work
            # names who submitted it; a record nobody claims was not submitted by
            # anybody.
            continue
        total += 1
    return total


def _attempts(case: Any) -> Tuple[Any, ...]:
    """Every verification attempt, from both places they live.

    Read through the graph rather than the `verification` collection, because
    attempts submitted through the envelope arrive embedded on their claims and
    that collection stays empty. Counting the collection reported "nothing has
    checked it" on a case carrying a passed test suite.
    """
    try:
        from release_gate.assurance.verification import VerificationGraph
        return tuple(VerificationGraph.from_case(case).attempts)
    except Exception:
        return ()


def _unsettled_verifications(case: Any) -> int:
    """Attempts recorded that have not reached a verdict."""
    open_states = {"NOT_RUN", "INCONCLUSIVE", "UNKNOWN"}
    return sum(1 for a in _attempts(case)
               if str(getattr(getattr(a, "status", None), "value", "")) in open_states)


def _candidate_present(case: Any) -> bool:
    """Is there something identifiable to judge, as opposed to work in progress?

    Not the subject digest: release-gate always sets one, because it hashes
    whatever it was handed, so every case would look like it had a candidate from
    the first record. What makes a candidate is somebody asserting something — a
    claim, or an artifact submitted with a digest. Raw trace evidence piling up is
    work happening, which is a different thing and is what
    `EVIDENCE_ACCUMULATING` is for.
    """
    if _count(case, "claims"):
        return True
    return _submitted(case, "artifacts") > 0


def observe_phase(case: Any, *, finalized: bool = False,
                  approval: Any = None,
                  open_concerns: Sequence[str] = ()) -> PhaseObservation:
    """Read the phase off a case. Pure, and it commands nothing.

    `finalized` says whether the caller sealed this snapshot for a decision;
    `approval` is a bound approval if one exists. Both are facts the caller
    already holds — asking for them keeps this a reading of state rather than a
    thing that goes and looks for work to do.
    """
    evidence = _submitted(case, "evidence")
    claims = _count(case, "claims")
    attempts = _attempts(case)
    verifications = len(attempts)
    unsettled = _unsettled_verifications(case)
    observed = {"evidence": evidence, "claims": claims,
                "verifications": verifications, "unsettled_verifications": unsettled,
                "candidate_present": _candidate_present(case),
                "finalized": bool(finalized)}

    state = str(getattr(getattr(case, "state", None), "value", "") or "")
    if state == "INVALIDATED":
        return PhaseObservation(AssurancePhase.INVALIDATED,
                                basis="the case record is marked invalidated",
                                observed=observed, open_concerns=open_concerns)

    if approval is not None:
        standing = str(getattr(getattr(approval, "standing", None), "value", "")
                       or getattr(approval, "standing", "") or "")
        decision = str(getattr(getattr(approval, "decision", None), "value", "")
                       or getattr(approval, "decision", "") or "")
        if standing == "APPROVAL_INVALIDATED":
            return PhaseObservation(
                AssurancePhase.INVALIDATED,
                basis="the approval no longer binds: what it named has moved",
                observed=observed, open_concerns=open_concerns)
        if decision == "REJECTED":
            return PhaseObservation(AssurancePhase.REJECTED,
                                    basis="a person declined to authorise this",
                                    observed=observed, open_concerns=open_concerns)
        if decision == "APPROVED":
            return PhaseObservation(
                AssurancePhase.APPROVED,
                basis="a bound approval stands against this state",
                observed=observed, open_concerns=open_concerns)

    if finalized:
        return PhaseObservation(
            AssurancePhase.HUMAN_REVIEW,
            basis="a verdict has been rendered and no person has answered it",
            observed=observed, open_concerns=open_concerns)

    if unsettled:
        return PhaseObservation(
            AssurancePhase.VERIFYING,
            basis=f"{unsettled} verification attempt(s) have not settled",
            observed=observed, open_concerns=open_concerns)
    if verifications:
        return PhaseObservation(
            AssurancePhase.VERIFYING,
            basis=f"{verifications} verification attempt(s) are recorded and the "
                  "case is still open to more",
            observed=observed, open_concerns=open_concerns)

    if _candidate_present(case):
        return PhaseObservation(
            AssurancePhase.CANDIDATE_READY,
            basis="something identifiable has been asserted and nothing has "
                  "checked it yet",
            observed=observed, open_concerns=open_concerns)

    if evidence or claims:
        return PhaseObservation(
            AssurancePhase.EVIDENCE_ACCUMULATING,
            basis=f"{evidence} evidence and {claims} claim record(s) have arrived",
            observed=observed, open_concerns=open_concerns)

    return PhaseObservation(AssurancePhase.OPEN,
                            basis="nothing has been submitted to this case",
                            observed=observed, open_concerns=open_concerns)


def observe_session(session: Any) -> PhaseObservation:
    """The phase of a live session, with the concerns already visible.

    Runs the provisional analysis, so a caller gets the weaknesses release-gate
    can already see while the external system is still working. Reading does not
    finalize the session and does not change it.
    """
    outcome = session.outcome if session.finalized else session.provisional()
    concerns = tuple(item.summary for item in outcome.attention.top(8))
    return observe_phase(outcome.case, finalized=session.finalized,
                         open_concerns=concerns)
