"""When something changes, which verifications stop meaning anything?

A proof is edited, a dataset is regenerated, a config flag flips, an agent's
answer is revised. Some checks that passed yesterday are now about a thing that
no longer exists. Most are not. Telling those apart precisely is the whole job:
invalidating everything is safe and useless, and invalidating nothing is cheap
and dangerous.

## Three answers, not two

The instinct is to sort verifications into *invalidated* and *unaffected*. That
is one bucket short, and the missing one is the important one.

A verification that **declared what it depended on** can be judged. If the
changed thing is in its dependency set, it is invalidated; if it is not, it is
provably unaffected and must be left alone.

A verification that **declared nothing** cannot be judged either way. The dataset
changed; did this check read the dataset? Nobody knows. Calling that "unaffected"
is the failure mode this module exists to prevent — it is how a stale
verification survives a mutation and goes on being counted as a passed check.
Calling it "invalidated" would be the other failure: throwing away good work to
avoid thinking, which is the blunt instrument the prompt rules out.

So it reports `UNDETERMINED`, which is neither, and says why.

That asymmetry is deliberate and it creates a gradient: a verifier that declares
its inputs gets spared when unrelated things move, and one that does not gets
flagged every time anything moves. Precision is available to those who say what
they used.

## Dependencies are declared, and that is a limit worth stating

Release-gate cannot observe what a verifier read. It can only record what the
verifier said it read, which is DECLARED (Invariant 1). A check that depended on
a dataset and did not mention it will be reported unaffected when that dataset
changes — correctly, given what was said, and wrongly, given what happened. The
defence is not to guess: it is that an undeclared dependency makes the whole
verification `UNDETERMINED` the moment *anything* moves, so silence is not free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object, is_digest, short_id

MUTATION_SCHEMA_VERSION = 1


class MutationError(ValueError):
    """A dependency or mutation that cannot be represented."""


class DependencyKind(str, Enum):
    """What a verification rested on. The prompt's list, named.

    The kind is documentation rather than logic — invalidation keys on digests,
    not on kinds — but it is what makes a report readable: "invalidated because
    the dataset changed" is actionable in a way that "invalidated because
    sha256:9f2c… changed" is not.
    """

    PROOF = "PROOF"
    DATASET = "DATASET"
    CODE = "CODE"
    CONFIGURATION = "CONFIGURATION"
    ANSWER = "ANSWER"
    ACTION_PAYLOAD = "ACTION_PAYLOAD"
    TARGET = "TARGET"            # the thing being checked
    OTHER = "OTHER"


class Affect(str, Enum):
    """What a mutation did to one verification."""

    INVALIDATED = "INVALIDATED"      # it declared a dependency on what changed
    UNAFFECTED = "UNAFFECTED"        # it declared dependencies; this is not one
    UNDETERMINED = "UNDETERMINED"    # it declared nothing, so nobody can tell


@dataclass(frozen=True)
class Dependency:
    """One thing a verification rested on, and the state it rested on."""

    kind: DependencyKind
    logical_id: str
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", DependencyKind(self.kind))
        logical_id = str(self.logical_id or "").strip()
        if not logical_id:
            raise MutationError(
                "a dependency must name what it is: an anonymous digest cannot be "
                "matched against a mutation of anything in particular")
        object.__setattr__(self, "logical_id", logical_id)
        digest = str(self.digest or "").strip()
        if not is_digest(digest):
            raise MutationError(
                f"dependency {logical_id!r} carries {digest!r}, which is not a "
                "sha256 content digest; a dependency without one cannot be "
                "compared to anything and would silently never invalidate")
        object.__setattr__(self, "digest", digest)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "logical_id": self.logical_id,
                "digest": self.digest}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Dependency":
        return cls(kind=data.get("kind", DependencyKind.OTHER),
                   logical_id=data.get("logical_id", ""),
                   digest=data.get("digest", ""))


@dataclass(frozen=True)
class MutationEvent:
    """Something changed: what it was, and from what to what."""

    logical_id: str
    kind: DependencyKind = DependencyKind.OTHER
    previous_digest: str = ""
    current_digest: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", DependencyKind(self.kind))
        logical_id = str(self.logical_id or "").strip()
        if not logical_id:
            raise MutationError("a mutation must name what changed")
        object.__setattr__(self, "logical_id", logical_id)
        for name in ("previous_digest", "current_digest"):
            value = str(getattr(self, name) or "").strip()
            if value and not is_digest(value):
                raise MutationError(
                    f"{name} {value!r} is not a sha256 content digest")
            object.__setattr__(self, name, value)
        if self.previous_digest and self.previous_digest == self.current_digest:
            raise MutationError(
                f"{logical_id} did not change: both digests are "
                f"{self.previous_digest[:23]}…. A mutation event that records no "
                "mutation would invalidate work for nothing")

    @property
    def describes_a_change(self) -> bool:
        return self.previous_digest != self.current_digest

    def note(self) -> str:
        return (f"{self.kind.value.lower()} {self.logical_id} changed"
                + (f": {self.detail}" if self.detail else ""))

    def to_dict(self) -> Dict[str, Any]:
        return {"logical_id": self.logical_id, "kind": self.kind.value,
                "previous_digest": self.previous_digest,
                "current_digest": self.current_digest,
                "detail": self.detail, "note": self.note()}


@dataclass(frozen=True)
class VerificationDependencies:
    """What one verification declared it rested on."""

    verification_id: str
    dependencies: Tuple[Dependency, ...] = ()
    verifier: str = ""

    def __post_init__(self) -> None:
        if not str(self.verification_id or "").strip():
            raise MutationError("a dependency set must name its verification")
        object.__setattr__(self, "dependencies", tuple(self.dependencies))

    @property
    def declared(self) -> bool:
        """Did this verification say what it used?

        The field everything turns on. A check that declared nothing cannot be
        shown unaffected by anything.
        """
        return bool(self.dependencies)

    @property
    def digests(self) -> Set[str]:
        return {d.digest for d in self.dependencies}

    @property
    def logical_ids(self) -> Set[str]:
        return {d.logical_id for d in self.dependencies}

    def depends_on(self, event: MutationEvent) -> Optional[Dependency]:
        """The dependency this mutation hits, if any.

        Matched on logical id *and* on the digest the verification rested on.
        Logical id alone would miss a thing renamed between runs; digest alone
        would miss a mutation whose previous digest nobody recorded. Either match
        is enough, because a false invalidation costs a re-run and a missed one
        costs a wrong verdict.
        """
        for dependency in self.dependencies:
            if dependency.logical_id == event.logical_id:
                return dependency
            if event.previous_digest and dependency.digest == event.previous_digest:
                return dependency
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {"verification_id": self.verification_id, "verifier": self.verifier,
                "declared": self.declared,
                "dependencies": [d.to_dict() for d in self.dependencies]}


@dataclass(frozen=True)
class AffectedVerification:
    """One verification's fate under one set of mutations."""

    verification_id: str
    affect: Affect
    reason: str = ""
    via: Tuple[str, ...] = ()          # the logical ids that hit it
    verifier: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "affect", Affect(self.affect))
        object.__setattr__(self, "via", tuple(self.via))

    def to_dict(self) -> Dict[str, Any]:
        return {"verification_id": self.verification_id, "affect": self.affect.value,
                "reason": self.reason, "via": list(self.via), "verifier": self.verifier}


@dataclass(frozen=True)
class InvalidationReport:
    """What a set of mutations did, and — as loudly — what it did not."""

    events: Tuple[MutationEvent, ...] = ()
    results: Tuple[AffectedVerification, ...] = ()
    notes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(self, "results", tuple(self.results))

    def _of(self, affect: Affect) -> Tuple[AffectedVerification, ...]:
        return tuple(r for r in self.results if r.affect is affect)

    @property
    def invalidated(self) -> Tuple[AffectedVerification, ...]:
        return self._of(Affect.INVALIDATED)

    @property
    def unaffected(self) -> Tuple[AffectedVerification, ...]:
        return self._of(Affect.UNAFFECTED)

    @property
    def undetermined(self) -> Tuple[AffectedVerification, ...]:
        return self._of(Affect.UNDETERMINED)

    @property
    def precise(self) -> bool:
        """Every verification could be judged one way or the other.

        False as soon as one check declared no dependencies: the blast radius is
        then a lower bound rather than an answer.
        """
        return not self.undetermined

    def note(self) -> str:
        if not self.events:
            return "Nothing changed, so no verification was affected."
        parts = [f"{len(self.events)} change(s): "
                 + "; ".join(e.note() for e in self.events[:4])]
        parts.append(
            f"{len(self.invalidated)} verification(s) invalidated, "
            f"{len(self.unaffected)} provably unaffected and left alone")
        if self.undetermined:
            parts.append(
                f"{len(self.undetermined)} could not be judged because they "
                "declared no dependencies — these are not known to be fine, they "
                "are unknown, and the blast radius above is a lower bound")
        return ". ".join(parts) + "."

    @property
    def report_id(self) -> str:
        return short_id("mut", digest_object(
            {"events": [e.to_dict() for e in self.events],
             "results": [r.to_dict() for r in self.results]}))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "invalidation_report", "record_id": self.report_id,
                "events": [e.to_dict() for e in self.events],
                "invalidated": [r.to_dict() for r in self.invalidated],
                "unaffected": [r.to_dict() for r in self.unaffected],
                "undetermined": [r.to_dict() for r in self.undetermined],
                "precise": self.precise, "note": self.note(),
                "notes": list(self.notes),
                "schema_version": MUTATION_SCHEMA_VERSION}


class DependencyIndex:
    """Digest and logical id → the verifications that declared them.

    Built once and queried per mutation, rather than scanning every verification
    for every change. At the scale §10i measures, a scan per event is the
    quadratic that turns a routine config change into a minutes-long stall.
    """

    def __init__(self, sets: Iterable[VerificationDependencies] = ()) -> None:
        self._sets: Dict[str, VerificationDependencies] = {}
        self._by_logical: Dict[str, Set[str]] = {}
        self._by_digest: Dict[str, Set[str]] = {}
        for dependency_set in sets:
            self.add(dependency_set)

    def add(self, dependency_set: VerificationDependencies) -> "DependencyIndex":
        self._sets[dependency_set.verification_id] = dependency_set
        for dependency in dependency_set.dependencies:
            self._by_logical.setdefault(dependency.logical_id, set()).add(
                dependency_set.verification_id)
            self._by_digest.setdefault(dependency.digest, set()).add(
                dependency_set.verification_id)
        return self

    def __len__(self) -> int:
        return len(self._sets)

    @property
    def undeclared(self) -> Tuple[VerificationDependencies, ...]:
        return tuple(s for s in self._sets.values() if not s.declared)

    def hit_by(self, event: MutationEvent) -> Set[str]:
        """Verification ids that declared a dependency this mutation touches."""
        hits = set(self._by_logical.get(event.logical_id, ()))
        if event.previous_digest:
            hits |= set(self._by_digest.get(event.previous_digest, ()))
        return hits

    def apply(self, events: Sequence[MutationEvent]) -> InvalidationReport:
        """Judge every known verification against every mutation."""
        changes = [e for e in events if e.describes_a_change]
        if not changes:
            return InvalidationReport(events=(), results=(), notes=(
                "no event described an actual change",) if events else ())

        hits: Dict[str, List[MutationEvent]] = {}
        for event in changes:
            for verification_id in self.hit_by(event):
                hits.setdefault(verification_id, []).append(event)

        results: List[AffectedVerification] = []
        for verification_id, dependency_set in sorted(self._sets.items()):
            struck = hits.get(verification_id, [])
            if struck:
                via = tuple(sorted({e.logical_id for e in struck}))
                kinds = sorted({e.kind.value.lower() for e in struck})
                results.append(AffectedVerification(
                    verification_id=verification_id, affect=Affect.INVALIDATED,
                    verifier=dependency_set.verifier, via=via,
                    reason=("it declared a dependency on "
                            + ", ".join(via) + f" ({', '.join(kinds)}), which changed")))
            elif dependency_set.declared:
                results.append(AffectedVerification(
                    verification_id=verification_id, affect=Affect.UNAFFECTED,
                    verifier=dependency_set.verifier,
                    reason=(f"it declared {len(dependency_set.dependencies)} "
                            "dependency(ies) and none of them changed")))
            else:
                # The bucket that matters. Not fine, and not broken: unknown.
                results.append(AffectedVerification(
                    verification_id=verification_id, affect=Affect.UNDETERMINED,
                    verifier=dependency_set.verifier,
                    reason=("it declared no dependencies, so whether it read any "
                            "of what changed cannot be established; it is not "
                            "known to be unaffected")))
        return InvalidationReport(events=tuple(changes), results=tuple(results))


def dependencies_from_case(case: Any) -> DependencyIndex:
    """Read declared dependencies off a case's verification attempts.

    `target_digest` becomes a TARGET dependency and `input_state` an OTHER one,
    because both already mean "the state this check ran against". Richer
    dependencies arrive in an attempt's `result` under `dependencies`, which is
    where a verifier that knows what it read can say so without a new record
    type.
    """
    index = DependencyIndex()
    try:
        from release_gate.assurance.verification import VerificationGraph
        attempts = tuple(VerificationGraph.from_case(case).attempts)
    except Exception:
        return index

    for attempt in attempts:
        declared: List[Dependency] = []
        target = getattr(attempt, "target", None)
        target_id = str(getattr(target, "target_id", "") or "") if target else ""
        target_digest = str(getattr(attempt, "target_digest", "") or "")
        if target_id and is_digest(target_digest):
            declared.append(Dependency(kind=DependencyKind.TARGET,
                                       logical_id=target_id, digest=target_digest))
        input_state = str(getattr(attempt, "input_state", "") or "")
        if is_digest(input_state):
            declared.append(Dependency(kind=DependencyKind.OTHER,
                                       logical_id=f"{target_id or 'input'}:input_state",
                                       digest=input_state))
        for row in ((getattr(attempt, "result", None) or {}).get("dependencies") or ()):
            if not isinstance(row, Mapping):
                continue
            try:
                declared.append(Dependency.from_dict(row))
            except MutationError:
                # A malformed dependency is skipped rather than fatal, and the
                # verification keeps whatever else it declared.
                continue
        index.add(VerificationDependencies(
            verification_id=str(getattr(attempt, "verification_id", "") or ""),
            dependencies=tuple(declared),
            verifier=str(getattr(attempt, "verifier", "") or "")))
    return index
