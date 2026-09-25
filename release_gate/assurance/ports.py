"""The seams an enterprise deployment binds, and what the base install binds instead.

Local use is a CLI and a file. Enterprise use is an API, a durable metadata
store, an external object store for evidence too large to travel, event
ingestion, and workers. Both run the same engine, and the way that stays true is
that the engine depends on **protocols defined here** rather than on any
particular backend.

Nothing in this module imports a driver, a client library, or a framework, and
nothing in it can: it is stdlib-only, like the rest of `assurance`. A Postgres
`CaseStore` or an S3 `ObjectStore` is an *adapter* that lives outside this
package and is passed in. That is the whole point — without a seam, the first
enterprise integration has two options, and both are bad: import `psycopg2` into
the deterministic core, or fork the engine.

**A store is not an authority.** This is the invariant the module exists to
protect. Retrieving a case from a database does not make it the case that was
argued, and reading bytes back from an object store does not make them the bytes
that were digested. So `ObjectStore.get` re-digests what it read and raises on a
mismatch, `put` computes the digest itself rather than trusting one it was
handed, and `CaseStore.retrieval_establishes_validity` is unconditionally
`False`. Provenance is not trust, and a storage layer is provenance (Invariant
11).

**Delivery is at least once.** `EventLog.delivery_is_exactly_once` is
unconditionally `False`, because no queue worth deploying offers otherwise and a
consumer written as though it did will double-count. Folding a duplicate
harmlessly is only possible because records are content-addressed: the same
evidence submitted twice has the same `evidence_id`, so a fold that keys on it
converges. That property was not free — it was broken until the arrival-clock fix
— and at-least-once ingestion is what it buys.

**A worker is a producer, not a verifier.** `WorkQueue.results_are_verified` is
unconditionally `False`. Work coming back from a pool arrives DECLARED like
anything else from outside, and a worker that marked its own output verified
would be the self-attestation problem with a job queue in front of it.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (Any, Dict, Iterable, Iterator, List, Mapping, Optional,
                    Protocol, Sequence, Tuple)

from release_gate.assurance.canonical import (
    canonical_bytes, digest_bytes, digest_object, short_id,
)

__all__ = [
    "PORTS_SCHEMA_VERSION",
    "CaseStore",
    "Deployment",
    "DeploymentProfile",
    "EventLog",
    "InMemoryCaseStore",
    "InMemoryEventLog",
    "InMemoryWorkQueue",
    "LocalFileCaseStore",
    "LocalFileObjectStore",
    "ObjectStore",
    "Port",
    "PortBinding",
    "PortError",
    "StoredCase",
    "WorkQueue",
    "WorkUnit",
    "enterprise_profile",
    "local_profile",
]

PORTS_SCHEMA_VERSION = 1


class PortError(ValueError):
    """A backend returned something other than what it was given."""


class Port(str, Enum):
    """The five things an enterprise deployment supplies and a local one does not.

    `API` has no protocol here on purpose: it is a transport in front of the same
    engine, not a capability the engine calls out to. It is named so a deployment
    can state whether one is in front of it.
    """

    API = "API"
    CASE_STORE = "CASE_STORE"
    OBJECT_STORE = "OBJECT_STORE"
    EVENT_LOG = "EVENT_LOG"
    WORK_QUEUE = "WORK_QUEUE"


# ── durable metadata ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StoredCase:
    """What a metadata store holds for one case.

    Not the case object. A case is a fold over collections, and rehydrating one
    from a row would make the store the authority on what it contains. This is
    the *binding state* plus the verdict and the human acts — enough to answer
    "what was decided, against what, by whom", and not enough to be mistaken for
    the case itself.
    """

    case_id: str
    case_version: int
    case_digest: str
    subject_digest: str
    binding_state: Mapping[str, Any] = field(default_factory=dict)
    verdict: Optional[Mapping[str, Any]] = None
    approvals: Tuple[Mapping[str, Any], ...] = ()
    overrides: Tuple[Mapping[str, Any], ...] = ()
    #: Where the full evidence lives, when it was too large to store inline.
    #: `ExternalReference` payloads (§10t), carrying locator and digest.
    external_refs: Tuple[Mapping[str, Any], ...] = ()
    stored_at: Optional[str] = None
    schema_version: int = PORTS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("case_id", "case_digest", "subject_digest"):
            if not str(getattr(self, name) or "").strip():
                raise PortError(
                    f"{name} is required: a stored case that cannot be matched "
                    "against the state it was decided on is a row, not a record")
        object.__setattr__(self, "binding_state", dict(self.binding_state or {}))
        for name in ("approvals", "overrides", "external_refs"):
            object.__setattr__(self, name,
                               tuple(dict(x) for x in getattr(self, name)))

    @property
    def key(self) -> str:
        """The address. Version included: a case at v2 is not the case at v1, and
        an approval bound to one must not resolve to the other."""
        return f"{self.case_id}@{self.case_version}"

    def matches(self, case: Any) -> bool:
        """Whether this row still describes the case in front of you."""
        state = case.binding_state()
        inner = state.get("state") or {}
        subject = (inner.get("subject_state") or {})
        return (str(state.get("case_id") or "") == self.case_id
                and int(state.get("case_version") or 0) == self.case_version
                and str(state.get("case_digest") or "") == self.case_digest
                and str(subject.get("state_digest") or "") == self.subject_digest)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "stored_case", "record_id": self.key,
                "case_id": self.case_id, "case_version": self.case_version,
                "case_digest": self.case_digest,
                "subject_digest": self.subject_digest,
                "binding_state": dict(self.binding_state),
                "verdict": dict(self.verdict) if self.verdict else None,
                "approvals": [dict(a) for a in self.approvals],
                "overrides": [dict(o) for o in self.overrides],
                "external_refs": [dict(r) for r in self.external_refs],
                "stored_at": self.stored_at,
                "schema_version": self.schema_version}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StoredCase":
        return cls(case_id=str(data.get("case_id") or ""),
                   case_version=int(data.get("case_version") or 1),
                   case_digest=str(data.get("case_digest") or ""),
                   subject_digest=str(data.get("subject_digest") or ""),
                   binding_state=data.get("binding_state") or {},
                   verdict=data.get("verdict"),
                   approvals=tuple(data.get("approvals") or ()),
                   overrides=tuple(data.get("overrides") or ()),
                   external_refs=tuple(data.get("external_refs") or ()),
                   stored_at=(str(data["stored_at"]) if data.get("stored_at")
                              else None))

    @classmethod
    def of(cls, case: Any, *, verdict: Optional[Mapping[str, Any]] = None,
           stored_at: Optional[str] = None, **kw: Any) -> "StoredCase":
        state = case.binding_state()
        inner = state.get("state") or {}
        subject = inner.get("subject_state") or {}
        found = getattr(case, "verdict", None)
        return cls(case_id=str(state.get("case_id") or ""),
                   case_version=int(state.get("case_version") or 1),
                   case_digest=str(state.get("case_digest") or ""),
                   subject_digest=str(subject.get("state_digest") or ""),
                   binding_state=state,
                   verdict=(verdict if verdict is not None
                            else (found.to_dict() if found is not None
                                  and hasattr(found, "to_dict") else None)),
                   stored_at=stored_at, **kw)


class CaseStore(Protocol):
    """Durable metadata. Implemented against Postgres, DynamoDB, a file, a dict.

    Keyed by `case_id@case_version`, never by `case_id` alone: a case that moved
    is a different thing to bind an approval to, and a store that overwrote v1
    with v2 would silently re-point every approval issued against v1.
    """

    def put(self, stored: StoredCase) -> str:
        """Persist, returning the key. Idempotent on the same key and content."""
        ...

    def get(self, key: str) -> Optional[StoredCase]:
        """The row, or None. None means absent — never an empty case."""
        ...

    def versions(self, case_id: str) -> Tuple[int, ...]:
        """Every version held, ascending. A partial history is still a history,
        and a caller that assumes contiguity will misread a gap as an absence."""
        ...

    @property
    def retrieval_establishes_validity(self) -> bool:
        """Unconditionally False for every implementation.

        A row came back; that is all. Whether it describes the case in hand is
        `StoredCase.matches`, which re-checks the digests. A store that vouched
        for its own contents would be the trust boundary moved into the database
        (Invariant 11).
        """
        ...

    @property
    def durable(self) -> bool:
        """Whether this survives the process. Stated, because a local deployment
        that read as durable would be the worst kind of wrong."""
        ...


class _CaseStoreMixin:
    """The parts every `CaseStore` answers the same way."""

    @property
    def retrieval_establishes_validity(self) -> bool:
        return False


class InMemoryCaseStore(_CaseStoreMixin):
    """The default. Not durable, and says so."""

    def __init__(self) -> None:
        self._rows: Dict[str, StoredCase] = {}

    durable = False

    def put(self, stored: StoredCase) -> str:
        self._rows[stored.key] = stored
        return stored.key

    def get(self, key: str) -> Optional[StoredCase]:
        return self._rows.get(key)

    def versions(self, case_id: str) -> Tuple[int, ...]:
        return tuple(sorted(row.case_version for row in self._rows.values()
                            if row.case_id == case_id))

    def __len__(self) -> int:
        return len(self._rows)


class LocalFileCaseStore(_CaseStoreMixin):
    """One JSON file per case version, under a directory. What local use needs.

    Durable in the sense that matters locally — it survives the process — and not
    in the sense an enterprise deployment means: no replication, no transactions
    across two writes, no concurrent-writer story beyond the atomic rename below.
    `Deployment` says so rather than leaving it to be discovered.
    """

    def __init__(self, root: Any) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    durable = True

    def _path(self, key: str) -> Path:
        # The key is derived from a case id and an integer, but it reaches here
        # as a string and a store must not be talked into writing outside its
        # own root by one containing a separator.
        if "/" in key or "\\" in key or key.startswith("."):
            raise PortError(
                f"{key!r} is not a usable key: a store writes inside its root "
                "and nowhere else")
        return self.root / f"{key}.json"

    def put(self, stored: StoredCase) -> str:
        path = self._path(stored.key)
        # Write-then-rename. A reader that caught a half-written file would get
        # a JSON error at best and a truncated case at worst, and the second is
        # the kind of thing that reads as evidence having been absent.
        handle, tmp = tempfile.mkstemp(dir=str(self.root), suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(stored.to_dict(), fh, sort_keys=True)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return stored.key

    def get(self, key: str) -> Optional[StoredCase]:
        path = self._path(key)
        if not path.exists():
            return None
        return StoredCase.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def versions(self, case_id: str) -> Tuple[int, ...]:
        found = []
        for path in self.root.glob(f"{case_id}@*.json"):
            try:
                found.append(int(path.stem.rsplit("@", 1)[1]))
            except (IndexError, ValueError):
                continue
        return tuple(sorted(found))


# ── external evidence / object store ─────────────────────────────────────────

class ObjectStore(Protocol):
    """Where raw evidence lives when it is too large to travel in a pack.

    Content-addressed, so the address *is* the check. `put` returns the digest it
    computed rather than accepting one, and `get` re-digests what it read and
    raises on a mismatch. Without that, a locator points at whatever the bucket
    currently holds, and §10t's whole reason for keeping the digest beside the
    handle is lost.
    """

    def put(self, data: bytes, *, kind: str = "") -> str:
        """Store, returning `sha256:<hex>`. The digest is computed here."""
        ...

    def get(self, digest: str) -> bytes:
        """The bytes at this digest, re-checked. Raises on mismatch or absence."""
        ...

    def locator(self, digest: str) -> str:
        """A handle a reader can follow, for an `ExternalReference`."""
        ...

    def has(self, digest: str) -> bool:
        ...


class _ObjectStoreMixin:
    """Verification on read, once, so no backend can skip it."""

    def _check(self, digest: str, data: bytes) -> bytes:
        found = digest_bytes(data)
        if found != digest:
            raise PortError(
                f"the object store returned {len(data)} bytes digesting to "
                f"{found}, for {digest}. Either the bytes changed or the address "
                "did; a locator whose contents are not what was argued is worse "
                "than a missing one, because it reads as resolved")
        return data


class LocalFileObjectStore(_ObjectStoreMixin):
    """Digest-named files under a directory. Sharded two levels, as a CAS is."""

    def __init__(self, root: Any) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise PortError(
                f"{digest!r} is not a content address; an object store addressed "
                "by anything else is a filesystem with extra steps")
        hexpart = digest.split(":", 1)[1]
        if not all(c in "0123456789abcdef" for c in hexpart):
            raise PortError(f"{digest!r} is not a hex digest")
        return self.root / hexpart[:2] / hexpart[2:4] / hexpart

    def put(self, data: bytes, *, kind: str = "") -> str:
        digest = digest_bytes(data)
        path = self._path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            handle, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(handle, "wb") as fh:
                    fh.write(data)
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        return digest

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        if not path.exists():
            raise PortError(
                f"nothing stored at {digest}. An external reference that cannot "
                "be followed is a coverage gap, not a clean read")
        return self._check(digest, path.read_bytes())

    def locator(self, digest: str) -> str:
        return self._path(digest).as_uri()

    def has(self, digest: str) -> bool:
        try:
            return self._path(digest).exists()
        except PortError:
            return False


# ── event ingestion ──────────────────────────────────────────────────────────

class EventLog(Protocol):
    """Append-only ingestion. Kafka, Kinesis, SQS, a table, a list.

    At least once, always. `delivery_is_exactly_once` is unconditionally `False`
    and a consumer must be idempotent — which is possible because records are
    content-addressed, so the same evidence arriving twice carries the same id
    and folds once. That is what the arrival-clock fix bought.
    """

    def append(self, records: Sequence[Mapping[str, Any]]) -> int:
        """Append a batch, returning how many were accepted."""
        ...

    def read(self, *, cursor: int = 0, limit: int = 1000
             ) -> Tuple[Tuple[Mapping[str, Any], ...], int]:
        """A batch and the next cursor. The cursor is a position, not a promise:
        a reader that resumes from it may see records it has already seen."""
        ...

    @property
    def delivery_is_exactly_once(self) -> bool:
        """Unconditionally False for every implementation."""
        ...


class InMemoryEventLog:
    """The default, and the reference for what a real log must behave like."""

    def __init__(self) -> None:
        self._records: List[Mapping[str, Any]] = []

    @property
    def delivery_is_exactly_once(self) -> bool:
        return False

    def append(self, records: Sequence[Mapping[str, Any]]) -> int:
        added = [dict(r) for r in records]
        self._records.extend(added)
        return len(added)

    def read(self, *, cursor: int = 0, limit: int = 1000
             ) -> Tuple[Tuple[Mapping[str, Any], ...], int]:
        if cursor < 0:
            raise PortError("a cursor is a position and cannot be negative")
        window = self._records[cursor:cursor + limit]
        return tuple(window), cursor + len(window)

    def __len__(self) -> int:
        return len(self._records)


# ── workers ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WorkUnit:
    """One thing to do, addressed by what it is rather than by when it was queued.

    `unit_id` is derived from the payload, so the same work submitted twice is
    the same unit — the queue's half of the idempotence the event log needs.
    """

    kind: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    case_key: str = ""
    attempts: int = 0

    unit_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if not str(self.kind or "").strip():
            raise PortError("a work unit must say what kind of work it is")
        object.__setattr__(self, "payload", dict(self.payload or {}))
        object.__setattr__(self, "unit_id", short_id("wu", digest_object(
            {"kind": self.kind, "payload": dict(self.payload),
             "case_key": self.case_key})))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "work_unit", "record_id": self.unit_id,
                "unit_id": self.unit_id, "kind": self.kind,
                "payload": dict(self.payload), "case_key": self.case_key,
                "attempts": self.attempts}


class WorkQueue(Protocol):
    """Fan-out for work the engine does not do inline. Celery, SQS, a thread pool.

    A worker is a **producer**. `results_are_verified` is unconditionally `False`:
    what comes back is DECLARED like anything else from outside, and a pool that
    marked its own output verified would be self-attestation with a job queue in
    front of it (Invariant 1).
    """

    def submit(self, unit: WorkUnit) -> str:
        """Enqueue, returning the unit id. Idempotent on the same unit."""
        ...

    def claim(self, *, limit: int = 1) -> Tuple[WorkUnit, ...]:
        """Take up to `limit` units. A claim may be lost, so a unit may be
        claimed twice — which is why the id is content-derived."""
        ...

    def complete(self, unit_id: str, result: Mapping[str, Any]) -> None:
        ...

    @property
    def results_are_verified(self) -> bool:
        """Unconditionally False for every implementation."""
        ...


class InMemoryWorkQueue:
    """The default. Deterministic order, so a test is a test."""

    def __init__(self) -> None:
        self._pending: List[WorkUnit] = []
        self._claimed: Dict[str, WorkUnit] = {}
        self._results: Dict[str, Mapping[str, Any]] = {}

    @property
    def results_are_verified(self) -> bool:
        return False

    def submit(self, unit: WorkUnit) -> str:
        known = {u.unit_id for u in self._pending} | set(self._claimed)
        if unit.unit_id not in known and unit.unit_id not in self._results:
            self._pending.append(unit)
        return unit.unit_id

    def claim(self, *, limit: int = 1) -> Tuple[WorkUnit, ...]:
        taken = self._pending[:limit]
        self._pending = self._pending[limit:]
        for unit in taken:
            self._claimed[unit.unit_id] = unit
        return tuple(taken)

    def complete(self, unit_id: str, result: Mapping[str, Any]) -> None:
        if unit_id not in self._claimed:
            raise PortError(
                f"{unit_id} was completed without having been claimed; a result "
                "for work nobody took is a result from somewhere unaccounted for")
        self._claimed.pop(unit_id)
        self._results[unit_id] = dict(result)

    def result(self, unit_id: str) -> Optional[Mapping[str, Any]]:
        return self._results.get(unit_id)

    @property
    def depth(self) -> int:
        return len(self._pending)


# ── what a deployment is ─────────────────────────────────────────────────────

class DeploymentProfile(str, Enum):
    """Two shapes, and the difference is which ports are bound."""

    LOCAL = "LOCAL"            # a CLI and files
    ENTERPRISE = "ENTERPRISE"  # an API in front, and the four backends behind


@dataclass(frozen=True)
class PortBinding:
    """One port, what is behind it, and what that thing does not do.

    `limitations` is required and must be non-empty. Every backend has them, and
    a binding that listed none would be the one a reader trusted furthest.
    """

    port: Port
    backend: str
    bound: bool = True
    limitations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "port", Port(self.port))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if not str(self.backend or "").strip():
            raise PortError(
                f"{self.port.value}: a binding must name what is behind it")
        if self.bound and not self.limitations:
            raise PortError(
                f"{self.port.value}: state what {self.backend} does not do. "
                "Every backend has limits, and the binding that claims none is "
                "the one a reader will trust furthest")

    def to_dict(self) -> Dict[str, Any]:
        return {"port": self.port.value, "backend": self.backend,
                "bound": self.bound, "limitations": list(self.limitations)}


@dataclass(frozen=True)
class Deployment:
    """Which ports are bound here, and what this deployment cannot do.

    The review artefact, executable. A deployment that cannot say what it is
    missing will be asked to stand behind capabilities it does not have.
    """

    profile: DeploymentProfile
    bindings: Tuple[PortBinding, ...] = ()
    schema_version: int = PORTS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile", DeploymentProfile(self.profile))
        object.__setattr__(self, "bindings", tuple(self.bindings))
        seen = [b.port for b in self.bindings]
        if len(seen) != len(set(seen)):
            raise PortError("a port cannot be bound twice in one deployment")
        missing = [p.value for p in Port if p not in set(seen)]
        if missing:
            raise PortError(
                "every port must be accounted for, bound or not: "
                + ", ".join(missing) + ". A port left out of the list reads as "
                "one nobody thought about, which is exactly what it is")

    def binding(self, port: Any) -> Optional[PortBinding]:
        wanted = Port(port)
        return next((b for b in self.bindings if b.port is wanted), None)

    @property
    def unbound(self) -> Tuple[Port, ...]:
        return tuple(b.port for b in self.bindings if not b.bound)

    @property
    def requires_third_party(self) -> bool:
        """Whether running this needs anything beyond the standard library.

        `False` for LOCAL, and that is measured rather than claimed: a guard test
        blocks every third-party module and runs the decision path.
        """
        return self.profile is DeploymentProfile.ENTERPRISE

    @property
    def decides_differently(self) -> bool:
        """Unconditionally False. The same evidence reaches the same verdict
        whichever ports are bound.

        Ports are I/O. A deployment that decided differently would mean the
        authoritative path was not deterministic after all, and the verdict would
        be a property of the infrastructure rather than of the evidence
        (Invariant 4).
        """
        return False

    def cannot(self) -> Tuple[str, ...]:
        """Everything this deployment does not do, gathered in one place."""
        out: List[str] = []
        for binding in self.bindings:
            if not binding.bound:
                out.append(f"{binding.port.value}: not bound — "
                           + "; ".join(binding.limitations))
            else:
                out += [f"{binding.port.value} ({binding.backend}): {limit}"
                        for limit in binding.limitations]
        return tuple(out)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "deployment", "profile": self.profile.value,
                "bindings": [b.to_dict() for b in self.bindings],
                "unbound": [p.value for p in self.unbound],
                "requires_third_party": self.requires_third_party,
                "decides_differently": False,
                "cannot": list(self.cannot()),
                "schema_version": self.schema_version}

    def render(self) -> str:
        lines = [f"DEPLOYMENT: {self.profile.value}",
                 f"  needs anything beyond the standard library: "
                 f"{self.requires_third_party}"]
        for binding in self.bindings:
            mark = binding.backend if binding.bound else "NOT BOUND"
            lines.append(f"  {binding.port.value}: {mark}")
            for limit in binding.limitations:
                lines.append(f"      - {limit}")
        lines.append("  The verdict does not depend on any of this. Ports carry "
                     "evidence; they do not decide.")
        return "\n".join(lines)


def local_profile() -> Deployment:
    """What `release-gate assure <file>` is, stated.

    Every port accounted for. Three are genuinely absent, and naming them as
    absent is the difference between a deployment that is small and one that is
    quietly incomplete.
    """
    return Deployment(profile=DeploymentProfile.LOCAL, bindings=(
        PortBinding(Port.API, "none — the CLI is the interface", bound=False,
                    limitations=("no remote submission; a case is read from a "
                                 "file on this machine",
                                 "no multi-user access and no authentication, "
                                 "because there is no server to authenticate to")),
        PortBinding(Port.CASE_STORE, "LocalFileCaseStore (or nothing)",
                    limitations=("no replication and no cross-write transaction: "
                                 "two writes can leave two files, one new and one "
                                 "old",
                                 "concurrent writers are safe only to the extent "
                                 "an atomic rename makes them safe",
                                 "history is whatever is on this disk, and a "
                                 "deleted file is indistinguishable from a case "
                                 "that never ran")),
        PortBinding(Port.OBJECT_STORE, "LocalFileObjectStore (or nothing)",
                    limitations=("evidence lives beside the machine that produced "
                                 "it, so an external reference is followable from "
                                 "here and nowhere else",
                                 "no lifecycle, no retention, no size ceiling "
                                 "beyond the disk")),
        PortBinding(Port.EVENT_LOG, "none — one file, read once", bound=False,
                    limitations=("no streaming ingestion; a case is a snapshot of "
                                 "what was in the file when it was read",
                                 "evidence produced after that read is not in the "
                                 "case, and the case says so through coverage "
                                 "rather than by including it")),
        PortBinding(Port.WORK_QUEUE, "none — everything runs inline", bound=False,
                    limitations=("analysis is bounded by this process's memory and "
                                 "the time a person will wait",
                                 "the counted-but-not-materialised path is what "
                                 "makes large inputs tractable here, not fan-out")),
    ))


def enterprise_profile(*, case_store: str = "PostgreSQL",
                       object_store: str = "S3-compatible",
                       event_log: str = "Kafka or equivalent",
                       work_queue: str = "a worker pool",
                       api: str = "the hosted API") -> Deployment:
    """The shape of an enterprise deployment, with the backends named.

    The names are labels for a report, not imports: nothing here knows how to
    talk to any of them. What each one actually does is an adapter satisfying the
    protocol above, written outside this package, where a driver dependency
    belongs.
    """
    return Deployment(profile=DeploymentProfile.ENTERPRISE, bindings=(
        PortBinding(Port.API, api,
                    limitations=("a transport in front of the same engine; it "
                                 "does not decide anything the CLI would not",
                                 "identity arrives here as a claim established at "
                                 "this boundary, and the boundary is what stands "
                                 "behind it")),
        PortBinding(Port.CASE_STORE, case_store,
                    limitations=("retrieval is not validation: a row must be "
                                 "matched against the digests of the case in hand",
                                 "a store holding a subset reports a subset; it "
                                 "cannot know what it was never sent")),
        PortBinding(Port.OBJECT_STORE, object_store,
                    limitations=("bytes must be re-digested on read; a locator "
                                 "alone says where to look, not whether what is "
                                 "there is what was argued",
                                 "an object deleted by a retention policy turns a "
                                 "resolved reference into a coverage gap, and that "
                                 "has to read as a gap rather than as clean")),
        PortBinding(Port.EVENT_LOG, event_log,
                    limitations=("at least once, so a consumer must be idempotent; "
                                 "content addressing is what makes that possible",
                                 "ordering across partitions is not guaranteed, and "
                                 "a fold that depended on arrival order would be "
                                 "deciding on the queue's behaviour")),
        PortBinding(Port.WORK_QUEUE, work_queue,
                    limitations=("a worker's output is DECLARED; scale is not "
                                 "confidence (Invariant 6)",
                                 "a claim can be lost and a unit run twice, which "
                                 "is why a unit is addressed by its content")),
    ))
