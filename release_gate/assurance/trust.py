"""Threat-modelling the producers, and keeping five questions apart.

Everything upstream of release-gate can be wrong, and wrong in different ways
that need different answers. An agent can lie. A verifier can be compromised. An
orchestrator can decline to mention the run that failed. Telemetry can arrive
with holes in it. A tool's output can be poisoned. A source can be spoofed. A
human can approve a state that has since moved. A prover's output can be about an
artifact that no longer exists.

Those are eight different failures and they are not interchangeable, so this
module refuses to reduce them to one number.

## Five axes, and no score

    source            who or what emitted this
    provenance        what establishes that they emitted it
    trust             whether anyone decided to rely on them
    integrity         whether what arrived is what they sent
    completeness      whether all of it arrived

**There is deliberately no overall trust score.** `TrustBoundary` has no
`score`, no `level`, no `ok` — because a signed record from a verifier nobody has
vetted and an unsigned assertion from a trusted vendor would land on the same
number while being opposite situations, and the number is what a reader would
carry forward. A boundary that cannot be summarised in one value is a boundary
that has to be read, which is the point.

The axes are independent in both directions. Strong provenance does not establish
trust: a signature proves who wrote something, not that they were right or honest
(Invariant 11). Intact integrity does not establish completeness: a perfectly
transmitted subset is still a subset. And trust does not establish integrity —
deciding to rely on a producer says nothing about whether this particular
delivery was tampered with in transit.

## Honesty about what cannot be seen

The valuable half of a threat model is the half that says "not this one".
Release-gate can detect a stale approval, because approval binds to a digest. It
cannot detect an agent that lies consistently and alone, because there is nothing
to disagree with — the evidence is internally coherent and entirely false.

Saying so is worth more than implying coverage. Each threat below carries a
`Detectability`, and two of the values are admissions: `MITIGATED_ONLY` means the
threat is reduced by corroboration rather than caught, and `OUTSIDE_VISIBILITY`
means release-gate cannot see it at all and a reader should not believe otherwise
(Invariant 10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

TRUST_SCHEMA_VERSION = 1


class TrustBoundaryError(ValueError):
    """A boundary that cannot be represented."""


class IntegrityStatus(str, Enum):
    """Whether what arrived is what was sent. The axis that was missing.

    Distinct from provenance, which is about *who* sent it. A record can be
    signed by exactly the right party and still have been truncated in transit,
    and a record with no attribution at all can arrive byte-perfect.
    """

    VERIFIED = "VERIFIED"          # a digest was recomputed and matched
    DECLARED = "DECLARED"          # a digest was supplied and nobody rechecked it
    BROKEN = "BROKEN"              # a digest was supplied and does not match
    NOT_ASSESSED = "NOT_ASSESSED"  # no digest, so nothing to check against


class Threat(str, Enum):
    """The eight failures, named so a case can say which it addressed."""

    AGENT_LIES = "AGENT_LIES"
    VERIFIER_COMPROMISED = "VERIFIER_COMPROMISED"
    TELEMETRY_INCOMPLETE = "TELEMETRY_INCOMPLETE"
    ORCHESTRATOR_OMITS_FAILURES = "ORCHESTRATOR_OMITS_FAILURES"
    TOOL_OUTPUT_POISONED = "TOOL_OUTPUT_POISONED"
    SOURCE_SPOOFED = "SOURCE_SPOOFED"
    HUMAN_APPROVES_STALE_STATE = "HUMAN_APPROVES_STALE_STATE"
    VERIFICATION_APPLIES_TO_OLD_ARTIFACT = "VERIFICATION_APPLIES_TO_OLD_ARTIFACT"


class Detectability(str, Enum):
    """What release-gate can actually do about a threat.

    The last two are admissions rather than capabilities, and they are the
    reason this enum exists: a threat model that graded everything "handled"
    would be worse than none, because a reader would stop looking.
    """

    #: A structural check finds it. Digests, sequence numbers, binding.
    DETECTED = "DETECTED"
    #: A structural check would find it, but the evidence needed is absent here.
    DETECTABLE_IF_SUPPLIED = "DETECTABLE_IF_SUPPLIED"
    #: Not caught; made less likely by corroboration from an independent source.
    MITIGATED_ONLY = "MITIGATED_ONLY"
    #: Release-gate cannot see this. Saying so is the only honest answer.
    OUTSIDE_VISIBILITY = "OUTSIDE_VISIBILITY"


#: Threat -> how release-gate stands on it, and why. The `why` is the load-bearing
#: half: an operator deciding whether to rely on this gate needs the reasoning,
#: not the grade.
_THREAT_MODEL: Mapping[Threat, Tuple[Detectability, str, str]] = {
    Threat.AGENT_LIES: (
        Detectability.MITIGATED_ONLY,
        "an agent that lies consistently and alone produces internally coherent "
        "evidence with nothing to disagree with; there is no structural signal in "
        "a well-formed falsehood",
        "corroboration from an independently-operated producer, which turns a lie "
        "into a contradiction"),
    Threat.VERIFIER_COMPROMISED: (
        Detectability.MITIGATED_ONLY,
        "a compromised verifier emits well-formed passing results; release-gate "
        "credits typed verification and cannot audit the verifier itself",
        "independent replication by a verifier from a disjoint lineage, and "
        "recording the verifier binary digest so a swapped build is visible"),
    Threat.TELEMETRY_INCOMPLETE: (
        Detectability.DETECTABLE_IF_SUPPLIED,
        "a hole in a numbered sequence or a span naming a parent that never "
        "arrived is structural and gets caught; an unnumbered stream has no shape "
        "for a hole to show up in",
        "sequence numbers, stream ids and monotonic counters"),
    Threat.ORCHESTRATOR_OMITS_FAILURES: (
        Detectability.DETECTABLE_IF_SUPPLIED,
        "the hardest of the eight: a party that omits a failing run omits it from "
        "its own manifest too, and its signature over that manifest is valid. "
        "Self-certified completeness cannot detect its own omission",
        "an enumeration from a party other than the producer — a CI plan, an "
        "orchestration manifest, a verifier inventory"),
    Threat.TOOL_OUTPUT_POISONED: (
        Detectability.OUTSIDE_VISIBILITY,
        "release-gate reads what a tool reported and has no model of what the "
        "tool should have reported; poisoned output that is well-formed is "
        "indistinguishable from correct output",
        "nothing release-gate can do alone; this lives with whoever operates the "
        "tool and its supply chain"),
    Threat.SOURCE_SPOOFED: (
        Detectability.MITIGATED_ONLY,
        "a signature establishes which key signed, and release-gate records that "
        "rather than verifying it; an unsigned record proves nothing either way, "
        "so absence of a signature is not evidence of spoofing",
        "signed evidence with keys managed outside release-gate, and provenance "
        "recorded per record so an unattributed one is visible as such"),
    Threat.HUMAN_APPROVES_STALE_STATE: (
        Detectability.DETECTED,
        "an approval binds to an exact case digest, subject digest and version; a "
        "state that has moved invalidates it structurally",
        "already structural — approval binding refuses a replayed or superseded "
        "approval"),
    Threat.VERIFICATION_APPLIES_TO_OLD_ARTIFACT: (
        Detectability.DETECTED,
        "a verification names the digest it ran against; when the artifact has "
        "left that digest the check is stale and the dependency index names "
        "exactly which checks are affected",
        "already structural — target digests and dependency declarations"),
}


@dataclass(frozen=True)
class ThreatAssessment:
    """Where a case stands on one threat."""

    threat: Threat
    detectability: Detectability
    basis: str = ""
    mitigation: str = ""
    #: Findings in this case that bear on the threat, if any.
    observed: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "threat", Threat(self.threat))
        object.__setattr__(self, "detectability", Detectability(self.detectability))
        object.__setattr__(self, "observed", tuple(self.observed))

    @property
    def release_gate_can_catch_it(self) -> bool:
        return self.detectability in (Detectability.DETECTED,
                                      Detectability.DETECTABLE_IF_SUPPLIED)

    def note(self) -> str:
        return (f"{self.threat.value} — {self.detectability.value}: {self.basis}. "
                f"Mitigation: {self.mitigation}.")

    def to_dict(self) -> Dict[str, Any]:
        return {"threat": self.threat.value,
                "detectability": self.detectability.value,
                "release_gate_can_catch_it": self.release_gate_can_catch_it,
                "basis": self.basis, "mitigation": self.mitigation,
                "observed": list(self.observed), "note": self.note()}


@dataclass(frozen=True)
class TrustBoundary:
    """The five axes for one producer, held apart.

    There is no method on this class that returns a single verdict, and that is
    the design rather than an omission. Any such method would be called, its
    result stored, and the four axes it flattened would stop travelling with it.
    """

    source: str
    provenance: str = "UNATTRIBUTED"
    trust: str = "NOT_ESTABLISHED"
    integrity: IntegrityStatus = IntegrityStatus.NOT_ASSESSED
    completeness: str = "COMPLETENESS_UNKNOWN"
    records: int = 0
    detail: str = ""

    def __post_init__(self) -> None:
        if not str(self.source or "").strip():
            raise TrustBoundaryError(
                "a trust boundary must name its source: the four other axes are "
                "statements about somebody, and an anonymous boundary is four "
                "statements about nobody")
        object.__setattr__(self, "source", str(self.source).strip())
        object.__setattr__(self, "integrity", IntegrityStatus(self.integrity))

    @property
    def attributed(self) -> bool:
        """Somebody is named. Says nothing about whether they are trusted."""
        return self.provenance not in ("UNATTRIBUTED", "BROKEN")

    @property
    def relied_upon(self) -> bool:
        """Somebody decided to rely on this. Says nothing about integrity."""
        return self.trust in ("ACCEPTED", "PROVISIONAL")

    @property
    def axes(self) -> Dict[str, str]:
        """The five, as a mapping — the only aggregate view offered."""
        return {"source": self.source, "provenance": self.provenance,
                "trust": self.trust, "integrity": self.integrity.value,
                "completeness": self.completeness}

    def note(self) -> str:
        return (f"{self.source}: provenance {self.provenance}, trust "
                f"{self.trust}, integrity {self.integrity.value}, completeness "
                f"{self.completeness} — five separate answers, not one verdict.")

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "trust_boundary", **self.axes,
                "records": self.records, "attributed": self.attributed,
                "relied_upon": self.relied_upon, "detail": self.detail,
                "note": self.note(), "schema_version": TRUST_SCHEMA_VERSION}


@dataclass(frozen=True)
class TrustSurface:
    """Every producer behind a case, and the threat model over them."""

    boundaries: Tuple[TrustBoundary, ...] = ()
    threats: Tuple[ThreatAssessment, ...] = ()
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "boundaries", tuple(self.boundaries))
        object.__setattr__(self, "threats", tuple(self.threats))

    @property
    def unattributed(self) -> Tuple[TrustBoundary, ...]:
        return tuple(b for b in self.boundaries if not b.attributed)

    @property
    def broken_integrity(self) -> Tuple[TrustBoundary, ...]:
        return tuple(b for b in self.boundaries
                     if b.integrity is IntegrityStatus.BROKEN)

    @property
    def outside_visibility(self) -> Tuple[ThreatAssessment, ...]:
        """Threats release-gate cannot see. The list a reader must not skip."""
        return tuple(t for t in self.threats
                     if t.detectability is Detectability.OUTSIDE_VISIBILITY)

    @property
    def mitigated_only(self) -> Tuple[ThreatAssessment, ...]:
        return tuple(t for t in self.threats
                     if t.detectability is Detectability.MITIGATED_ONLY)

    @property
    def single_producer(self) -> bool:
        """One source behind everything, so nothing corroborates anything.

        The condition under which every MITIGATED_ONLY threat loses its
        mitigation — because the mitigation is corroboration, and there is none.
        """
        return len(self.boundaries) == 1

    def note(self) -> str:
        lines = [f"{len(self.boundaries)} producer(s) behind this case."]
        if self.single_producer:
            lines.append(
                "All evidence comes from one producer, so the threats that are "
                "only mitigated by corroboration are not mitigated here at all: "
                "a lie, a compromised verifier or poisoned tool output would be "
                "internally consistent and invisible.")
        if self.unattributed:
            lines.append(f"{len(self.unattributed)} producer(s) are unattributed.")
        if self.broken_integrity:
            lines.append(
                f"{len(self.broken_integrity)} producer(s) delivered records whose "
                "digests do not match what was declared.")
        lines.append(
            f"{len(self.outside_visibility)} of {len(self.threats)} modelled "
            "threats are outside what release-gate can see at all.")
        return " ".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "trust_surface",
                "boundaries": [b.to_dict() for b in self.boundaries],
                "threats": [t.to_dict() for t in self.threats],
                "single_producer": self.single_producer,
                "unattributed": len(self.unattributed),
                "broken_integrity": len(self.broken_integrity),
                "outside_visibility": [t.threat.value for t in self.outside_visibility],
                "note": self.note(), "notes": list(self.notes),
                "schema_version": TRUST_SCHEMA_VERSION}


def _integrity_of(record: Any) -> IntegrityStatus:
    """Whether what arrived matches what was declared, per record.

    `DECLARED` rather than `VERIFIED` for a digest release-gate did not recompute:
    a digest somebody supplied alongside their own content establishes that they
    are consistent with themselves.
    """
    digest = str(getattr(record, "digest", "") or "")
    if not digest:
        return IntegrityStatus.NOT_ASSESSED
    reference = getattr(record, "content_reference", None)
    kind = str(getattr(getattr(reference, "kind", None), "value",
                       getattr(reference, "kind", "")) or "")
    if kind in ("FILE", "INLINE"):
        # Release-gate hashed these itself at ingest.
        return IntegrityStatus.VERIFIED
    return IntegrityStatus.DECLARED


def _worst_integrity(statuses: Sequence[IntegrityStatus]) -> IntegrityStatus:
    for candidate in (IntegrityStatus.BROKEN, IntegrityStatus.NOT_ASSESSED,
                      IntegrityStatus.DECLARED, IntegrityStatus.VERIFIED):
        if candidate in statuses:
            return candidate
    return IntegrityStatus.NOT_ASSESSED


def boundaries_from_case(case: Any) -> Tuple[TrustBoundary, ...]:
    """One boundary per producer, with the five axes read separately.

    Grouped by producer because a trust boundary is a statement about a party.
    Release-gate's own derived records are excluded: it is not a producer whose
    trustworthiness this case is weighing, and including it would put a
    self-attested row in every surface.
    """
    grouped: Dict[str, Dict[str, Any]] = {}
    for record in case.collection("evidence").materialised:
        producer = getattr(record, "producer", None)
        producer_id = str(getattr(producer, "producer_id", "") or "")
        kind = str(getattr(getattr(producer, "kind", None), "value", "") or "")
        if not producer_id or kind == "release_gate":
            continue
        bucket = grouped.setdefault(producer_id, {"integrity": [], "records": 0,
                                                  "provenance": set(),
                                                  "trust": set()})
        bucket["records"] += 1
        bucket["integrity"].append(_integrity_of(record))
        bucket["provenance"].add(
            str(getattr(getattr(record, "provenance_status", None), "value", "")
                or "UNATTRIBUTED"))
        trust = getattr(record, "trust", None)
        bucket["trust"].add(
            str(getattr(getattr(trust, "status", None), "value", "")
                or "NOT_ESTABLISHED"))

    out: List[TrustBoundary] = []
    for producer_id, bucket in sorted(grouped.items()):
        out.append(TrustBoundary(
            source=producer_id,
            provenance=sorted(bucket["provenance"])[0] if bucket["provenance"]
            else "UNATTRIBUTED",
            trust=sorted(bucket["trust"])[0] if bucket["trust"] else "NOT_ESTABLISHED",
            integrity=_worst_integrity(bucket["integrity"]),
            completeness="COMPLETENESS_UNKNOWN",
            records=bucket["records"]))
    return tuple(out)


def assess_threats(case: Any = None, *, ledger: Any = None,
                   boundaries: Sequence[TrustBoundary] = ()) -> Tuple[ThreatAssessment, ...]:
    """The eight threats, with what this case can and cannot say about each.

    The static model supplies the reasoning; the case supplies observations that
    sharpen it — a completeness ledger showing gaps, a single producer removing
    the corroboration that other threats are mitigated by.
    """
    single = len(boundaries) == 1
    out: List[ThreatAssessment] = []
    for threat, (detectability, basis, mitigation) in _THREAT_MODEL.items():
        observed: List[str] = []

        if threat is Threat.TELEMETRY_INCOMPLETE and ledger is not None:
            status = str(getattr(getattr(ledger, "status", None), "value", ""))
            if status == "KNOWN_GAPS":
                detectability = Detectability.DETECTED
                observed.append(f"the completeness ledger reports {status}")
            elif status == "COMPLETENESS_UNKNOWN":
                observed.append(
                    "no stream states what should have arrived, so a hole would "
                    "leave no trace")

        if threat is Threat.ORCHESTRATOR_OMITS_FAILURES and ledger is not None:
            if getattr(ledger, "any_self_certified", False):
                observed.append(
                    "at least one stream was declared complete by the party that "
                    "produced it, which cannot detect its own omission")

        if single and detectability is Detectability.MITIGATED_ONLY:
            observed.append(
                "all evidence comes from one producer, so the corroboration this "
                "threat is mitigated by does not exist in this case")

        out.append(ThreatAssessment(threat=threat, detectability=detectability,
                                    basis=basis, mitigation=mitigation,
                                    observed=tuple(observed)))
    return tuple(out)


def trust_surface(case: Any, *, ledger: Any = None) -> TrustSurface:
    """The producers behind a case and the threat model over them."""
    boundaries = boundaries_from_case(case)
    return TrustSurface(boundaries=boundaries,
                        threats=assess_threats(case, ledger=ledger,
                                               boundaries=boundaries))
