"""Replication — whether a second answer could have been wrong differently.

Independent reproduction is the strongest evidence this system can carry, and
the easiest to fake. Ten thousand agents that all query one upstream service and
all report the same number look, in every summary anyone would write, exactly
like ten thousand independent replications. They are one result, echoed. The
question this module answers is therefore never "did someone else get the same
answer" but:

    **is the second answer capable of being wrong differently from the first?**

A copy is not. It shares whatever could be wrong, so it adds nothing however
many times it appears. `SINGLE_PATH` — one distinct path, however many attempts
agree — is the default reading of mass agreement here, and it is usually the
correct one.

Replication is a *relation between verification attempts*, not a new kind of
record. `VerificationAttempt` already carries everything the question needs:
what method ran, which implementation ran it, against what input state, resting
on what lineage, citing what evidence, reaching what result. So this is a
projection over the `verification` collection, in the same way `VerificationGraph`
is, and a producer gets no new field to certify themselves with.

Four rules constrain what comes out.

**Copies never count.** Group formation collapses attempts that share a
signature, a declared lineage element, or an evidence root. There is no setting
that turns that off, because a system in which copies can be made to count is a
system whose replication number means nothing.

**Missing data never manufactures independence.** An axis is `UNDETERMINED` when
either side recorded nothing for it — never "differs". Two attempts that both
recorded no input state have not been shown to use different inputs. This is the
single rule the naive implementation gets wrong, and it is the one that matters:
the cheapest way to look independent is to record nothing.

**A label is not a path.** `VerificationMethod.INDEPENDENT_REPLICATION` is what a
producer called their own work. It earns nothing here. An attempt that declares
itself an independent replication and shares a lineage with what it replicates
collapses into that lineage's group like anything else (Invariant 1).

**Disagreement is never outvoted.** Nine confirming paths and one divergent one
is not ninety percent replicated. It is an open disagreement, and it becomes a
`Contradiction` so that final synthesis cannot present it as clean (Invariant 7).

What this module does *not* produce is a probability. `replications` is a count
of structurally distinct paths that reached the same verdict. Five of them do not
make a claim five times more likely to be true, and nothing here should ever be
read that way (Invariants 6 and 10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set,
                    Tuple)

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.contradiction import (
    Contradiction, ContradictionKind, ContradictionSide, ContradictionStatus)
from release_gate.assurance.evidence import EvidenceRecord
# The union-find and the ancestry walk are imported rather than re-implemented.
# Replication's group rule *extends* independence's lineage rule, and two copies
# of that logic would eventually disagree about the same case.
from release_gate.assurance.independence import _UnionFind, _root_sets
from release_gate.assurance.records import MaterialisationBasis
from release_gate.assurance.verification import (
    TargetKind, VerificationAttempt, VerificationStatus, VerificationTarget)

__all__ = [
    "REPLICATION_SCHEMA_VERSION",
    "CollapseReason",
    "ReplicationAxis",
    "ReplicationGroup",
    "ReplicationOutcome",
    "ReplicationPair",
    "ReplicationProfile",
    "ReplicationRelation",
    "ResultEquivalence",
    "TargetReplication",
    "analyse_replication",
]

REPLICATION_SCHEMA_VERSION = 1

#: Pairwise axis comparison runs between group representatives, never between
#: attempts, so a ten-thousand-attempt target costs ten thousand union operations
#: rather than fifty million comparisons. Representatives are still capped, because
#: a case with hundreds of genuine paths does not need hundreds of rendered pairs
#: to be understood — and the cap is declared rather than silent.
_PAIR_REPRESENTATIVE_CAP = 24


class ReplicationAxis(str, Enum):
    """A dimension along which a second attempt could be wrong differently.

    None of these is sufficient alone, and they are never summed. Two teams
    running the identical script over the identical data differ on nothing that
    could fail independently, however many teams there are.
    """

    METHOD = "METHOD"                  # a different strategy: another proof, another test shape
    IMPLEMENTATION = "IMPLEMENTATION"  # a different tool or codebase did the work
    INPUT = "INPUT"                    # a different input state was used
    LINEAGE = "LINEAGE"                # disjoint declared independence lineage
    PRODUCER = "PRODUCER"              # different parties produced the cited evidence


class CollapseReason(str, Enum):
    """Why two attempts turned out to be one path.

    Recorded rather than implied: a producer whose ten thousand attempts became
    one path is owed the reason, and a copy detector nobody can audit is a copy
    detector nobody should believe.
    """

    IDENTICAL_SIGNATURE = "IDENTICAL_SIGNATURE"      # same method, tool, input, lineage, result
    SHARED_LINEAGE = "SHARED_LINEAGE"                # a declared independence element in common
    SHARED_EVIDENCE_ROOT = "SHARED_EVIDENCE_ROOT"    # the same evidence stands behind both


#: LINEAGE is privileged in exactly one place: `INDEPENDENT` requires it. Not
#: because it outranks the others, but because it is the axis that catches the
#: echo — an attempt whose lineage nobody recorded cannot be shown to rest on
#: anything different, whatever else about it differs.
_REQUIRED_FOR_INDEPENDENT = ReplicationAxis.LINEAGE


class ReplicationRelation(str, Enum):
    """How one path stands to another on the same target.

    Attempts that are byte-identical, share a lineage, or share an evidence root
    have already merged into one path by the time relations are computed, so
    there is no "this is a copy of that" between paths — the copy is recorded as
    the reason two attempts became one, on `ReplicationGroup.collapse_reasons`.
    """

    COPY = "COPY"                  # distinct paths, but nothing that could be wrong differs
    PARTIAL = "PARTIAL"            # some axes differ, some are shared or unrecorded
    INDEPENDENT = "INDEPENDENT"    # every axis examined differs, lineage included
    UNDETERMINED = "UNDETERMINED"  # too little recorded to say anything


class ReplicationOutcome(str, Enum):
    """What the paths on one target amount to."""

    CONFIRMED = "CONFIRMED"        # two or more distinct paths reached the same verdict
    DIVERGENT = "DIVERGENT"        # distinct paths reached different verdicts
    NOT_ACHIEVED = "NOT_ACHIEVED"  # a second path ran and reached no verdict
    SINGLE_PATH = "SINGLE_PATH"    # however many attempts, there is one path
    UNDETERMINED = "UNDETERMINED"  # the additional paths cannot be credited


class ResultEquivalence(str, Enum):
    """On what basis two results are called the same.

    Release-Gate cannot decide whether two numbers are the same number: tolerance
    is domain knowledge, and inferring it would be a universal truth claim about
    somebody else's field (Invariant 10). So equivalence beyond byte-identity has
    to be *declared*, and is recorded as a declaration.
    """

    IDENTICAL = "IDENTICAL"        # the result payloads are the same content
    DECLARED = "DECLARED"          # a producer stated they are equivalent, and why
    TOLERANCE = "TOLERANCE"        # a producer applied a tolerance they stated
    VERDICT_ONLY = "VERDICT_ONLY"  # same verdict, different payloads, no basis given
    DIVERGENT = "DIVERGENT"        # the payloads disagree
    UNDETERMINED = "UNDETERMINED"  # one or both recorded no result payload


#: Verdict classes. Two attempts replicate each other when they land in the same
#: class; a group holding a FAILED did not confirm, whatever else it holds,
#: because a check that found a problem is not cancelled by one that did not look
#: for it (Invariant 7).
_VERDICT_CLASS: Mapping[VerificationStatus, str] = {
    VerificationStatus.PASSED: "PASSED",
    VerificationStatus.FAILED: "FAILED",
    VerificationStatus.INCONCLUSIVE: "NO_VERDICT",
    VerificationStatus.UNKNOWN: "NO_VERDICT",
    VerificationStatus.NOT_RUN: "NOT_RUN",
    VerificationStatus.INVALIDATED: "WITHDRAWN",
}

_VERDICT_CLASSES = ("FAILED", "PASSED", "NO_VERDICT", "WITHDRAWN", "NOT_RUN")


# ── one path ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ReplicationGroup:
    """One distinct path to a result, and everything that travelled it.

    Every axis is held as the *set* over the path's members rather than as one
    representative's value. A path of four hundred attempts has no canonical
    member, and picking one would make the reported comparison depend on an
    arbitrary sort rather than on the evidence.

    `size` is attempts, and is deliberately not what gets reported as
    replication: a group of four hundred attempts is one path.
    """

    group_id: str
    members: Tuple[str, ...] = ()
    verifiers: Tuple[str, ...] = ()
    methods: Tuple[str, ...] = ()
    inputs: Tuple[str, ...] = ()
    lineage: Tuple[str, ...] = ()
    producers: Tuple[str, ...] = ()
    result_digests: Tuple[str, ...] = ()
    equivalence_basis: str = ""
    tolerance: Optional[str] = None
    collapse_reasons: Tuple[CollapseReason, ...] = ()
    verdict: str = "NO_VERDICT"
    attributed: bool = False

    def __post_init__(self) -> None:
        for name in ("members", "verifiers", "methods", "inputs", "lineage",
                     "producers", "result_digests"):
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        object.__setattr__(self, "collapse_reasons",
                           tuple(sorted(set(self.collapse_reasons),
                                        key=lambda r: r.value)))

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def confirming(self) -> bool:
        return self.verdict in ("PASSED", "FAILED")

    def to_dict(self) -> Dict[str, Any]:
        return {"group_id": self.group_id, "size": self.size,
                "members": list(self.members[:16]),
                "members_truncated": max(0, len(self.members) - 16),
                "verifiers": list(self.verifiers[:8]),
                "methods": list(self.methods),
                "inputs": list(self.inputs[:8]),
                "producers": list(self.producers[:8]),
                "distinct_results": len(self.result_digests),
                "collapse_reasons": [r.value for r in self.collapse_reasons],
                "verdict": self.verdict, "attributed": self.attributed,
                "lineage": list(self.lineage[:8])}


@dataclass(frozen=True)
class ReplicationPair:
    """Two paths, and what actually differs between them."""

    left: str
    right: str
    relation: ReplicationRelation = ReplicationRelation.UNDETERMINED
    axes_differ: Tuple[ReplicationAxis, ...] = ()
    axes_shared: Tuple[ReplicationAxis, ...] = ()
    axes_undetermined: Tuple[ReplicationAxis, ...] = ()
    equivalence: ResultEquivalence = ResultEquivalence.UNDETERMINED
    basis: str = ""

    def __post_init__(self) -> None:
        for name in ("axes_differ", "axes_shared", "axes_undetermined"):
            object.__setattr__(self, name,
                               tuple(sorted(set(getattr(self, name)), key=lambda a: a.value)))

    @property
    def independent(self) -> bool:
        return self.relation is ReplicationRelation.INDEPENDENT

    def to_dict(self) -> Dict[str, Any]:
        return {"left": self.left, "right": self.right,
                "relation": self.relation.value,
                "axes_differ": [a.value for a in self.axes_differ],
                "axes_shared": [a.value for a in self.axes_shared],
                "axes_undetermined": [a.value for a in self.axes_undetermined],
                "equivalence": self.equivalence.value, "basis": self.basis}


# ── one target ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TargetReplication:
    """What the attempts on one target amount to, once copies have collapsed."""

    target: VerificationTarget
    outcome: ReplicationOutcome = ReplicationOutcome.UNDETERMINED
    groups: Tuple[ReplicationGroup, ...] = ()
    pairs: Tuple[ReplicationPair, ...] = ()
    pairs_basis: MaterialisationBasis = MaterialisationBasis.COMPLETE
    attempts_examined: int = 0
    copies_collapsed: int = 0
    unattributed_paths: int = 0
    divergent_verdicts: Tuple[str, ...] = ()
    not_achieved: Tuple[str, ...] = ()
    equivalence: ResultEquivalence = ResultEquivalence.UNDETERMINED
    basis: str = ""

    @property
    def paths(self) -> int:
        """Distinct paths, copies collapsed. Not a confidence, not a score."""
        return len(self.groups)

    @property
    def established_paths(self) -> int:
        """Paths whose independence rests on something recorded.

        An unattributed path is counted apart rather than credited, exactly as
        `TargetVerification` counts unattributed confirmations apart: a nameless
        second opinion is not corroboration.
        """
        return sum(1 for g in self.groups if g.attributed)

    @property
    def replications(self) -> int:
        """Additional established paths that agree. Zero for a lone result.

        The first path is the result; replication is what comes *after* it. This
        is a count of paths, and nothing about it scales with agreement: forty
        attempts down one lineage still replicate nothing.
        """
        if self.outcome is not ReplicationOutcome.CONFIRMED:
            return 0
        agreeing = {g.verdict for g in self.groups if g.attributed and g.confirming}
        if len(agreeing) != 1:
            return 0
        return max(0, sum(1 for g in self.groups if g.attributed and g.confirming) - 1)

    @property
    def divergent(self) -> bool:
        return self.outcome is ReplicationOutcome.DIVERGENT

    def axes_established(self) -> Tuple[ReplicationAxis, ...]:
        """Axes shown to differ across at least one pair of distinct paths.

        The intersection would be too strict and the union too generous; this is
        the union, and it is reported as "somewhere here, these differed" rather
        than as a property of the whole set. A methodology that needs an axis to
        differ everywhere has to say so.
        """
        seen: Set[ReplicationAxis] = set()
        for pair in self.pairs:
            if pair.relation in (ReplicationRelation.INDEPENDENT,
                                 ReplicationRelation.PARTIAL):
                seen |= set(pair.axes_differ)
        return tuple(sorted(seen, key=lambda a: a.value))

    def summary(self) -> Dict[str, Any]:
        return {"target": self.target.to_dict(), "outcome": self.outcome.value,
                "paths": self.paths, "established_paths": self.established_paths,
                "replications": self.replications,
                "attempts_examined": self.attempts_examined,
                "copies_collapsed": self.copies_collapsed,
                "unattributed_paths": self.unattributed_paths,
                "divergent_verdicts": list(self.divergent_verdicts),
                "not_achieved": len(self.not_achieved),
                "equivalence": self.equivalence.value,
                "axes_established": [a.value for a in self.axes_established()],
                "pairs_basis": self.pairs_basis.value,
                "basis": self.basis}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(),
                "groups": [g.to_dict() for g in self.groups[:16]],
                "groups_truncated": max(0, len(self.groups) - 16),
                "pairs": [p.to_dict() for p in self.pairs[:32]]}

    def render(self) -> str:
        lines = [f"{self.target.kind.value} {self.target.target_id}: "
                 f"{self.outcome.value}",
                 f"  {self.attempts_examined:,} attempt(s) -> {self.paths:,} distinct "
                 f"path(s), {self.established_paths:,} established"]
        if self.copies_collapsed:
            lines.append(f"  {self.copies_collapsed:,} attempt(s) collapsed as copies")
        if self.divergent_verdicts:
            lines.append(f"  paths disagree: {', '.join(self.divergent_verdicts)}")
        if self.equivalence in (ResultEquivalence.VERDICT_ONLY,
                                ResultEquivalence.UNDETERMINED):
            lines.append(f"  result equivalence: {self.equivalence.value} — the paths "
                         "are not established to have computed the same thing")
        lines.append(f"  {self.basis}")
        return "\n".join(lines)


# ── the profile ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ReplicationProfile:
    """Replication across every target in a case."""

    targets: Tuple[TargetReplication, ...] = ()
    attempts_examined: int = 0
    basis: str = ""

    # Deliberately no __len__: an empty profile is a real result ("nothing here
    # could be compared") and making it falsy would let `if profile` silently
    # discard that, collapsing "we looked and found nothing to compare" back into
    # "nobody looked" — the exact distinction the presence model exists to keep.

    def for_target(self, target: VerificationTarget) -> Optional[TargetReplication]:
        return next((t for t in self.targets if t.target.key == target.key), None)

    @property
    def confirmed(self) -> Tuple[TargetReplication, ...]:
        return tuple(t for t in self.targets
                     if t.outcome is ReplicationOutcome.CONFIRMED)

    @property
    def divergent(self) -> Tuple[TargetReplication, ...]:
        """Targets whose paths disagree. Never averaged away, never outvoted."""
        return tuple(t for t in self.targets if t.divergent)

    @property
    def single_path(self) -> Tuple[TargetReplication, ...]:
        return tuple(t for t in self.targets
                     if t.outcome is ReplicationOutcome.SINGLE_PATH)

    @property
    def not_achieved(self) -> Tuple[TargetReplication, ...]:
        return tuple(t for t in self.targets
                     if t.outcome is ReplicationOutcome.NOT_ACHIEVED)

    @property
    def determinable(self) -> bool:
        return bool(self.targets)

    def digest(self) -> str:
        return digest_object({"targets": [t.summary() for t in self.targets],
                              "schema_version": REPLICATION_SCHEMA_VERSION})

    @property
    def record_type(self) -> str:
        return "replication"

    @property
    def record_id(self) -> str:
        return short_id("repl", self.digest())

    def summary(self) -> Dict[str, Any]:
        return {"targets": len(self.targets),
                "attempts_examined": self.attempts_examined,
                "confirmed": len(self.confirmed),
                "divergent": len(self.divergent),
                "single_path": len(self.single_path),
                "not_achieved": len(self.not_achieved),
                "max_replications": max((t.replications for t in self.targets),
                                        default=0),
                "determinable": self.determinable,
                "basis": self.basis}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "replication", "record_id": self.record_id,
                **self.summary(),
                "by_target": [t.to_dict() for t in self.targets[:16]],
                "by_target_truncated": max(0, len(self.targets) - 16),
                "schema_version": REPLICATION_SCHEMA_VERSION}

    def render(self) -> str:
        if not self.targets:
            return ("No verification attempts share a target, so nothing here "
                    "replicates anything.")
        return "\n".join(t.render() for t in self.targets[:8])

    def to_contradictions(self, *, critical_claims: Iterable[str] = ()
                          ) -> Tuple[Contradiction, ...]:
        """Divergent replication, as disagreements a verdict cannot omit.

        Only claim-shaped targets become contradictions, because a `Contradiction`
        names claims and putting an artifact id in that field would produce a
        disagreement no claim graph can resolve. Divergence on other targets is
        carried by the findings instead, which hold the decision on their own.
        """
        critical = set(critical_claims)
        out: List[Contradiction] = []
        for entry in self.divergent:
            if entry.target.kind is not TargetKind.CLAIM:
                continue
            sides: List[ContradictionSide] = []
            for verdict in _VERDICT_CLASSES:
                members = [g for g in entry.groups if g.verdict == verdict]
                if not members:
                    continue
                sides.append(ContradictionSide(
                    label=f"{verdict} ({len(members)} path(s))",
                    evidence=tuple(m for g in members for m in g.members),
                    participants=tuple(v for g in members for v in g.verifiers),
                    independent_roots=len(members),
                    roots=tuple(x for g in members for x in g.lineage),
                    note=f"{len(members)} distinct path(s) reached {verdict}"))
            if len(sides) < 2:
                continue
            claim_id = entry.target.target_id
            out.append(Contradiction(
                target_claims=(claim_id,),
                sides=tuple(sides),
                kind=ContradictionKind.VERIFICATION_CONFLICT,
                status=ContradictionStatus.OPEN,
                affects_critical=claim_id in critical,
                critical_basis=("the replication of a claim the decision rests on "
                                "disagrees with itself" if claim_id in critical else ""),
                detected_by="release-gate/assurance/replication",
                detail=("Independent paths reached different verdicts. This is a "
                        "disagreement, not a majority: the paths that agree do not "
                        "settle it, however many of them there are.")))
        return tuple(out)


# ── grouping ─────────────────────────────────────────────────────────────────

def _signature(attempt: VerificationAttempt) -> str:
    """What makes two attempts the same path through the same machinery.

    Timestamp is deliberately absent. A cron job that re-runs one script hourly
    is not twenty-four replications a day, and a second run with nothing recorded
    to distinguish it from the first has not been shown to be a second path.
    """
    return digest_object({
        "method": attempt.method.value,
        "verifier": attempt.verifier,
        "input_state": attempt.input_state,
        "lineage": sorted(attempt.independence_lineage),
        "result": dict(attempt.result),
        "status": attempt.status.value,
    })


def _producers_of(attempt: VerificationAttempt,
                  by_evidence: Mapping[str, EvidenceRecord]) -> Tuple[str, ...]:
    """Who produced the evidence this attempt cites.

    Derived from the records rather than read off a field the attempt could
    declare about itself: a producer that wants to look like a second party can
    write any name, but it cannot write somebody else's evidence.
    """
    seen = {by_evidence[e].producer.producer_id
            for e in attempt.evidence if e in by_evidence}
    return tuple(sorted(seen))


def _equivalence(left: "ReplicationGroup",
                 right: "ReplicationGroup") -> Tuple[ResultEquivalence, str]:
    """On what basis these two paths produced the same result — or that nothing
    says so.

    Compared as sets over each path's members, so the answer does not depend on
    which attempt happens to sort first. Any recorded result on one path matching
    any on the other is enough: the question is whether these paths ever produced
    the same thing, not whether every run within them did.
    """
    if not left.result_digests or not right.result_digests:
        return (ResultEquivalence.UNDETERMINED,
                "at least one path recorded no result payload, so what it produced "
                "cannot be compared")
    if set(left.result_digests) & set(right.result_digests):
        return (ResultEquivalence.IDENTICAL, "the paths produced the same result content")
    basis = left.equivalence_basis or right.equivalence_basis
    tolerance = left.tolerance if left.tolerance is not None else right.tolerance
    if basis and tolerance is not None:
        return (ResultEquivalence.TOLERANCE,
                f"a producer applied a declared tolerance ({tolerance}): {basis}")
    if basis:
        return (ResultEquivalence.DECLARED,
                f"a producer declared these results equivalent: {basis}")
    if left.verdict == right.verdict:
        return (ResultEquivalence.VERDICT_ONLY,
                "both paths reached the same verdict, but their results differ and "
                "nothing declares them equivalent; whether they computed the same "
                "thing is not established")
    return (ResultEquivalence.DIVERGENT, "the paths produced different results")


def _classify(left: "ReplicationGroup", right: "ReplicationGroup") -> ReplicationPair:
    """Compare two paths axis by axis.

    An unrecorded axis is `UNDETERMINED` and never a difference. That is the
    guard against the cheapest way to look independent, which is to record
    nothing: two attempts that both recorded no input state have not been shown
    to use different inputs, and a system that read silence as difference would
    hand its highest rating to whoever documented least.
    """
    differ: Set[ReplicationAxis] = set()
    shared: Set[ReplicationAxis] = set()
    unknown: Set[ReplicationAxis] = set()

    def axis(kind: ReplicationAxis, a: Sequence[str], b: Sequence[str]) -> None:
        if not a or not b:
            unknown.add(kind)
        elif set(a) & set(b):
            shared.add(kind)
        else:
            differ.add(kind)

    axis(ReplicationAxis.METHOD, left.methods, right.methods)
    axis(ReplicationAxis.IMPLEMENTATION, left.verifiers, right.verifiers)
    axis(ReplicationAxis.INPUT, left.inputs, right.inputs)
    axis(ReplicationAxis.LINEAGE, left.lineage, right.lineage)
    axis(ReplicationAxis.PRODUCER, left.producers, right.producers)

    equivalence, eq_basis = _equivalence(left, right)

    if not differ and shared:
        relation, basis = (ReplicationRelation.COPY,
                           "nothing that could be wrong differs: " +
                           ", ".join(sorted(a.value for a in shared)) + " are shared")
    elif not differ:
        relation, basis = (ReplicationRelation.UNDETERMINED,
                           "nothing is recorded on either path that could distinguish "
                           "them; a repeat with nothing to tell it apart is not an "
                           "established second path")
    elif shared:
        relation, basis = (ReplicationRelation.PARTIAL,
                           ", ".join(sorted(a.value for a in differ)) + " differ, but " +
                           ", ".join(sorted(a.value for a in shared)) + " are shared")
    elif _REQUIRED_FOR_INDEPENDENT in unknown:
        relation, basis = (ReplicationRelation.PARTIAL,
                           ", ".join(sorted(a.value for a in differ)) + " differ, but "
                           "neither path recorded its independence lineage, so whether "
                           "they rest on the same thing is unknown")
    else:
        relation, basis = (ReplicationRelation.INDEPENDENT,
                           ", ".join(sorted(a.value for a in differ)) +
                           " differ and nothing is shared")

    if unknown and relation in (ReplicationRelation.PARTIAL,
                                ReplicationRelation.INDEPENDENT):
        basis += ("; unrecorded: " + ", ".join(sorted(a.value for a in unknown)))

    return ReplicationPair(left=left.group_id, right=right.group_id,
                           relation=relation, axes_differ=tuple(differ),
                           axes_shared=tuple(shared), axes_undetermined=tuple(unknown),
                           equivalence=equivalence, basis=f"{basis}; {eq_basis}")


def _group(attempts: Sequence[VerificationAttempt],
           roots: Mapping[str, Set[str]]
           ) -> Tuple[Dict[str, List[VerificationAttempt]],
                      Dict[str, Set[CollapseReason]]]:
    """Collapse attempts into distinct paths, and say why each collapse happened.

    Three inverted indexes rather than a pairwise sweep, so ten thousand attempts
    on one target cost ten thousand union operations instead of fifty million
    comparisons: identical signature, a shared declared lineage element, a shared
    evidence root. All three mean the same thing — a fault here would be
    invisible to both — and each is the cheapest way to detect it.
    """
    union = _UnionFind()
    for attempt in attempts:
        union.find(attempt.verification_id)

    first_by_key: Dict[str, str] = {}
    reasons: Dict[str, Set[CollapseReason]] = {}

    def link(namespace: str, key: str, attempt_id: str,
             reason: CollapseReason) -> None:
        composite = f"{namespace}:{key}"
        held = first_by_key.get(composite)
        if held is None:
            first_by_key[composite] = attempt_id
            return
        if union.find(held) != union.find(attempt_id) or held != attempt_id:
            reasons.setdefault(attempt_id, set()).add(reason)
            reasons.setdefault(held, set()).add(reason)
        union.union(held, attempt_id)

    for attempt in attempts:
        link("sig", _signature(attempt), attempt.verification_id,
             CollapseReason.IDENTICAL_SIGNATURE)
        for element in attempt.independence_lineage:
            link("lin", element, attempt.verification_id, CollapseReason.SHARED_LINEAGE)
        for evidence_id in attempt.evidence:
            for root in roots.get(evidence_id, ()):
                link("root", root, attempt.verification_id,
                     CollapseReason.SHARED_EVIDENCE_ROOT)

    buckets: Dict[str, List[VerificationAttempt]] = {}
    bucket_reasons: Dict[str, Set[CollapseReason]] = {}
    for attempt in attempts:
        key = union.find(attempt.verification_id)
        buckets.setdefault(key, []).append(attempt)
        bucket_reasons.setdefault(key, set())
    for attempt_id, found in reasons.items():
        bucket_reasons.setdefault(union.find(attempt_id), set()).update(found)

    # A path of one collapsed nothing, whatever index touched it: a lone attempt
    # sharing a lineage with nobody has not been shown to be a copy of anything.
    for key, members in buckets.items():
        if len(members) == 1:
            bucket_reasons[key] = set()
    return buckets, bucket_reasons


def _verdict_of(attempts: Sequence[VerificationAttempt]) -> str:
    """One path's verdict. A failure in the group means the path did not confirm."""
    classes = {_VERDICT_CLASS.get(a.status, "NO_VERDICT") for a in attempts}
    for verdict in _VERDICT_CLASSES:      # FAILED first: Invariant 7
        if verdict in classes:
            return verdict
    return "NO_VERDICT"


def _outcome(groups: Sequence[ReplicationGroup]
             ) -> Tuple[ReplicationOutcome, Tuple[str, ...], str]:
    """What the paths amount to, and why.

    `SINGLE_PATH` is the honest reading of mass agreement and is not a criticism:
    a workflow that deliberately rests on one authoritative source belongs here
    and nothing is wrong with it.
    """
    established = [g for g in groups if g.attributed]
    verdicts = sorted({g.verdict for g in established if g.confirming})

    if len(verdicts) > 1:
        return (ReplicationOutcome.DIVERGENT, tuple(verdicts),
                f"{len(established)} established path(s) reached different verdicts "
                f"({', '.join(verdicts)}); the paths that agree do not settle this")
    if len(groups) <= 1:
        return (ReplicationOutcome.SINGLE_PATH, (),
                "every attempt collapses to one path, so nothing here has been "
                "independently reproduced; this is normal where a workflow rests on "
                "one authoritative source")

    confirming = [g for g in established if g.confirming]
    if len(confirming) >= 2:
        return (ReplicationOutcome.CONFIRMED, tuple(verdicts),
                f"{len(confirming)} established path(s) reached {verdicts[0]}")

    if any(g.verdict == "NO_VERDICT" for g in groups) and len(groups) > 1:
        return (ReplicationOutcome.NOT_ACHIEVED, tuple(verdicts),
                "a second path ran and reached no verdict; the attempt to reproduce "
                "is recorded and credited with nothing")

    unattributed = len(groups) - len(established)
    if unattributed:
        return (ReplicationOutcome.UNDETERMINED, tuple(verdicts),
                f"{unattributed} of {len(groups)} path(s) record no independence "
                "lineage and cite no evidence, so whether they rest on the same thing "
                "is unknown; they are counted apart rather than credited")
    return (ReplicationOutcome.UNDETERMINED, tuple(verdicts),
            "the paths here reach no common verdict that could be reproduced")


def _target_replication(target: VerificationTarget,
                        attempts: Sequence[VerificationAttempt], *,
                        by_evidence: Mapping[str, EvidenceRecord],
                        roots: Mapping[str, Set[str]]) -> TargetReplication:
    buckets, reasons = _group(attempts, roots)

    groups: List[ReplicationGroup] = []
    for key, members in buckets.items():
        ordered = sorted(members, key=lambda a: a.verification_id)
        # Attributed means "something recorded says where this came from" —
        # a declared lineage, or evidence whose producer the case actually holds.
        # An attempt with neither is counted apart rather than credited.
        attributed = any(a.independence_lineage or
                         any(e in by_evidence for e in a.evidence)
                         for a in ordered)
        basis = next((str(a.result.get("equivalence_basis")) for a in ordered
                      if a.result.get("equivalence_basis")), "")
        tolerance = next((str(a.result.get("tolerance")) for a in ordered
                          if a.result.get("tolerance") is not None), None)
        groups.append(ReplicationGroup(
            group_id=short_id("path", digest_object(
                sorted(a.verification_id for a in ordered))),
            members=tuple(a.verification_id for a in ordered),
            verifiers=tuple(a.verifier for a in ordered if a.verifier),
            methods=tuple(a.method.value for a in ordered),
            inputs=tuple(a.input_state for a in ordered if a.input_state),
            lineage=tuple(x for a in ordered for x in a.independence_lineage),
            producers=tuple(x for a in ordered
                            for x in _producers_of(a, by_evidence)),
            result_digests=tuple(digest_object(dict(a.result))
                                 for a in ordered if a.result),
            equivalence_basis=basis, tolerance=tolerance,
            collapse_reasons=tuple(reasons.get(key, ())),
            verdict=_verdict_of(ordered), attributed=attributed))

    groups.sort(key=lambda g: (-g.size, g.group_id))

    reps = groups[:_PAIR_REPRESENTATIVE_CAP]
    pairs_basis = (MaterialisationBasis.CAPPED if len(groups) > len(reps)
                   else MaterialisationBasis.COMPLETE)
    pairs = tuple(_classify(left, right)
                  for i, left in enumerate(reps) for right in reps[i + 1:])

    outcome, verdicts, basis = _outcome(groups)
    divergent = verdicts if outcome is ReplicationOutcome.DIVERGENT else ()

    equivalences = [p.equivalence for p in pairs]
    if not equivalences:
        equivalence = ResultEquivalence.UNDETERMINED
    else:
        # The weakest basis in the set, because the set is only as established as
        # its least established member. One VERDICT_ONLY pair means the target's
        # results are not known to be the same thing, whatever the rest agree on.
        order = (ResultEquivalence.DIVERGENT, ResultEquivalence.UNDETERMINED,
                 ResultEquivalence.VERDICT_ONLY, ResultEquivalence.DECLARED,
                 ResultEquivalence.TOLERANCE, ResultEquivalence.IDENTICAL)
        equivalence = next(e for e in order if e in equivalences)

    return TargetReplication(
        target=target, outcome=outcome, groups=tuple(groups), pairs=pairs,
        pairs_basis=pairs_basis, attempts_examined=len(attempts),
        copies_collapsed=max(0, len(attempts) - len(groups)),
        unattributed_paths=sum(1 for g in groups if not g.attributed),
        divergent_verdicts=divergent,
        not_achieved=tuple(a.verification_id for a in attempts
                           if a.status is VerificationStatus.INCONCLUSIVE),
        equivalence=equivalence, basis=basis)


def analyse_replication(attempts: Iterable[Any], *,
                        records: Iterable[Any] = ()) -> ReplicationProfile:
    """Derive what has actually been independently reproduced.

    Linear in attempts and in the evidence edges they cite. A target carrying ten
    thousand attempts is a normal input: grouping is three hash-indexed union
    passes, and the quadratic axis comparison runs only between capped group
    representatives.
    """
    held = [a for a in attempts if isinstance(a, VerificationAttempt) and a.target]
    evidence = [r for r in records if isinstance(r, EvidenceRecord)]
    by_evidence = {r.evidence_id: r for r in evidence}
    roots, _cycles = _root_sets(evidence) if evidence else ({}, ())

    if not held:
        return ReplicationProfile(
            attempts_examined=0,
            basis="no verification attempt names a target, so nothing here could be "
                  "reproduced or compared")

    by_target: Dict[Tuple[str, str], List[VerificationAttempt]] = {}
    targets: Dict[Tuple[str, str], VerificationTarget] = {}
    for attempt in held:
        assert attempt.target is not None
        key = attempt.target.key
        by_target.setdefault(key, []).append(attempt)
        targets.setdefault(key, attempt.target)

    # Targets with a single attempt are kept: `SINGLE_PATH` on the proposition the
    # case is about is exactly the fact a reviewer needs, and dropping it would
    # leave the profile silent about the targets that were never reproduced.
    entries = tuple(sorted(
        (_target_replication(targets[key], group, by_evidence=by_evidence, roots=roots)
         for key, group in by_target.items()),
        key=lambda t: (t.target.kind.value, t.target.target_id)))

    return ReplicationProfile(
        targets=entries, attempts_examined=len(held),
        basis=(f"{len(held):,} attempt(s) across {len(entries)} target(s); "
               f"{sum(t.copies_collapsed for t in entries):,} collapsed as copies"))
