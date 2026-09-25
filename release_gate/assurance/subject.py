"""AssuranceSubject — the exact thing a human is being asked to authorise.

Release-gate's whole register depends on this object being precise. An approval
that attaches to "the migration" is worth nothing; an approval that attaches to
`sha256:9f2c…` of `migrations/2026_09_12_add_index.sql`, with the action *apply
to prod-eu*, is worth something, because six weeks later anyone can ask whether
that is still the thing that ran.

So a subject answers three questions and refuses to guess at any of them:

1. **What exactly is it?**  `digest` + `content_reference` + `version`.
2. **Is it still that?**  `recheck()` — UNCHANGED / MUTATED / UNVERIFIABLE.
3. **Is it the same as that other one?**  `subject_id`, derived from content, so
   two submissions of identical content under the same action collide by design
   and a revision cannot be mistaken for its predecessor.

Three design decisions carry the invariants, and each is the kind of thing that
looks like a detail until it is wrong:

* **Two digests, not one.** `subject_id` is *identity* (type, version, digest,
  reference, action, lineage) and is stable across annotation. `state_digest` is
  *what the human saw* — identity plus metadata — and is what an approval binds
  to. Re-tagging a subject does not change what it is, but it does change what
  was on the page, and only the second one may invalidate an approval.
* **`created_at` is excluded from both.** Identity is content, not clock. The
  same bytes submitted twice are one subject; otherwise every re-run would
  manufacture a new thing to approve and dedup would be impossible.
* **A digest we did not compute is `DECLARED`, never `OBSERVED`.** A digest
  handed to us by an object store is that store's claim. It is usable, it is
  recorded, and it is not evidence that we verified anything (Invariant 1).

Where content genuinely cannot be hashed — a live external system, a dataset too
large to pull — the subject is still constructible with `digest=None`,
`digest_status=UNKNOWN` and `mutation_detectable=False`. That is an honest
subject with a stated limitation. What is not permitted is inventing a digest so
the field looks populated (Invariant 3).
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from release_gate.assurance.canonical import (
    CanonicalisationError,
    GIT_PREFIX,
    MERKLE_ORDERED,
    MERKLE_UNORDERED,
    canonical_json,
    digest_bytes,
    digest_file,
    digest_items,
    digest_object,
    freeze_value,
    is_digest,
    is_git_object_id,
    require_content_id,
    require_digest,
    short_id,
    thaw_value,
)

SUBJECT_MODEL_VERSION = 1

#: Inline content is embedded (and therefore re-verifiable offline) only below
#: this size. Above it we keep the digest and say mutation is unverifiable
#: rather than silently carrying a payload into every evidence pack.
MAX_INLINE_BYTES = 64 * 1024


class SubjectType(str, Enum):
    """What class of thing is being authorised.

    Closed enum plus `CUSTOM`, which requires a `custom_type` label — an
    unlabelled "custom" tells a reviewer nothing and cannot be reasoned about by
    a methodology.
    """

    DEPLOYMENT = "DEPLOYMENT"
    CODE_CHANGE = "CODE_CHANGE"
    AUTONOMOUS_ACTION = "AUTONOMOUS_ACTION"
    RESEARCH_RESULT = "RESEARCH_RESULT"
    DATA_CHANGE = "DATA_CHANGE"
    FINANCIAL_ACTION = "FINANCIAL_ACTION"
    INFRASTRUCTURE_CHANGE = "INFRASTRUCTURE_CHANGE"
    DOCUMENT = "DOCUMENT"
    MODEL_CHANGE = "MODEL_CHANGE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    GENERAL_RESULT = "GENERAL_RESULT"
    CUSTOM = "CUSTOM"


class ReferenceKind(str, Enum):
    """Where the content lives — which determines whether we can re-check it."""

    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    INLINE = "INLINE"
    ITEM_SET = "ITEM_SET"
    GIT_COMMIT = "GIT_COMMIT"
    GIT_RANGE = "GIT_RANGE"
    OBJECT_STORE = "OBJECT_STORE"
    URL = "URL"
    EXTERNAL = "EXTERNAL"


class DigestMethod(str, Enum):
    """How the digest was produced. Part of the record, not folklore."""

    SHA256_CONTENT = "SHA256_CONTENT"      # we hashed the bytes
    SHA256_MANIFEST = "SHA256_MANIFEST"    # we hashed a manifest of per-file digests
    MERKLE_UNORDERED = "MERKLE_UNORDERED"  # item set, order-independent
    MERKLE_ORDERED = "MERKLE_ORDERED"      # item sequence, order significant
    GIT_OBJECT = "GIT_OBJECT"              # the git object id IS the digest
    EXTERNAL_ATTESTED = "EXTERNAL_ATTESTED"  # someone else says this is the digest
    NONE = "NONE"                          # no digest available


class DigestStatus(str, Enum):
    """The epistemic status of the digest itself (Invariants 1, 2, 3)."""

    OBSERVED = "OBSERVED"    # release-gate computed it from the bytes
    DECLARED = "DECLARED"    # an external party asserts it
    UNKNOWN = "UNKNOWN"      # no digest exists for this subject


class VersionBasis(str, Enum):
    """Where the version string came from. `UNKNOWN` is a legal answer."""

    DECLARED = "DECLARED"
    GIT_COMMIT = "GIT_COMMIT"
    EXTERNAL = "EXTERNAL"
    DERIVED = "DERIVED"
    UNKNOWN = "UNKNOWN"


class MutationStatus(str, Enum):
    """Outcome of re-checking a subject against its recorded digest."""

    UNCHANGED = "UNCHANGED"
    MUTATED = "MUTATED"
    UNVERIFIABLE = "UNVERIFIABLE"


#: Methods where OBSERVED is an honest label. The first four are digests
#: release-gate computed itself; GIT_OBJECT qualifies only when the caller
#: actually resolved the object (git verifies the content hash on read), which is
#: why `from_git_commit` makes that an explicit opt-in rather than the default.
_OBSERVABLE_METHODS = {
    DigestMethod.SHA256_CONTENT,
    DigestMethod.SHA256_MANIFEST,
    DigestMethod.MERKLE_UNORDERED,
    DigestMethod.MERKLE_ORDERED,
    DigestMethod.GIT_OBJECT,
}

#: Reference kinds we can re-hash locally with no help from the caller.
_LOCALLY_RECHECKABLE = {ReferenceKind.FILE, ReferenceKind.DIRECTORY, ReferenceKind.INLINE}


class SubjectValidationError(ValueError):
    """A subject was constructed in a state that cannot be authorised."""


class SubjectIntegrityError(ValueError):
    """A serialised subject's stored ids disagree with its content."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _freeze(value: Any, path: str = "metadata") -> Any:
    """Deep-freeze, re-raising as a subject error so callers catch one type."""
    try:
        return freeze_value(value, path)
    except CanonicalisationError as exc:
        raise SubjectValidationError(str(exc)) from exc


def _thaw(value: Any) -> Any:
    return thaw_value(value)


@dataclass(frozen=True)
class ContentReference:
    """Where the subject's content lives, and how to find it again."""

    kind: ReferenceKind
    locator: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ReferenceKind(self.kind))
        if not isinstance(self.locator, str) or not self.locator.strip():
            raise SubjectValidationError("content_reference.locator must be a non-empty string")
        object.__setattr__(self, "locator", self.locator.strip())
        object.__setattr__(self, "detail", _freeze(self.detail or {}, "content_reference.detail"))

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "locator": self.locator, "detail": _thaw(self.detail)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ContentReference":
        return cls(kind=ReferenceKind(data["kind"]), locator=data["locator"],
                   detail=data.get("detail") or {})


@dataclass(frozen=True)
class MutationCheck:
    """Result of asking whether a subject is still what it was."""

    status: MutationStatus
    expected_digest: Optional[str]
    observed_digest: Optional[str]
    detail: str

    @property
    def unchanged(self) -> bool:
        """True only for a positive confirmation.

        `UNVERIFIABLE` is deliberately falsy here: code that asks "is this still
        fine?" must not read "I could not tell" as yes.
        """
        return self.status is MutationStatus.UNCHANGED

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status.value, "expected_digest": self.expected_digest,
                "observed_digest": self.observed_digest, "detail": self.detail}


@dataclass(frozen=True)
class AssuranceSubject:
    """The exact object presented for human authorisation.

    Construct through the `from_*` helpers where possible — they set the digest
    method and status correctly, which is the part that is easy to get wrong by
    hand.
    """

    subject_type: SubjectType
    requested_action: str
    content_reference: ContentReference
    digest: Optional[str] = None
    digest_method: DigestMethod = DigestMethod.NONE
    digest_status: DigestStatus = DigestStatus.UNKNOWN
    digest_basis: str = ""
    digest_attested_by: Optional[str] = None
    version: Optional[str] = None
    version_basis: VersionBasis = VersionBasis.UNKNOWN
    supersedes: Optional[str] = None
    custom_type: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # Derived at construction; never accepted from a caller or a file.
    subject_id: str = field(default="", init=False)
    state_digest: str = field(default="", init=False)

    # ── construction ────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_type", SubjectType(self.subject_type))
        object.__setattr__(self, "digest_method", DigestMethod(self.digest_method))
        object.__setattr__(self, "digest_status", DigestStatus(self.digest_status))
        object.__setattr__(self, "version_basis", VersionBasis(self.version_basis))

        action = (self.requested_action or "").strip()
        if not action:
            raise SubjectValidationError(
                "requested_action is required: approval authorises an ACTION on a "
                "subject, never a subject alone. Say what approving this permits, "
                "e.g. 'apply this migration to prod-eu'")
        object.__setattr__(self, "requested_action", action)

        if self.subject_type is SubjectType.CUSTOM:
            label = (self.custom_type or "").strip()
            if not label:
                raise SubjectValidationError(
                    "subject_type CUSTOM requires custom_type — an unlabelled custom "
                    "subject cannot be matched to a methodology or explained to a reviewer")
            object.__setattr__(self, "custom_type", label)
        elif self.custom_type is not None:
            raise SubjectValidationError(
                f"custom_type is only valid with subject_type CUSTOM (got {self.subject_type.value})")

        self._validate_digest_fields()
        self._validate_version_fields()

        if self.supersedes is not None and not (
                isinstance(self.supersedes, str) and self.supersedes.startswith("subj_")):
            raise SubjectValidationError(
                f"supersedes must be a subject id like 'subj_…', got {self.supersedes!r}")

        object.__setattr__(self, "metadata", _freeze(self.metadata or {}))
        object.__setattr__(self, "digest_basis", (self.digest_basis or "").strip())

        try:
            canonical_json(self._state())
        except CanonicalisationError as exc:
            raise SubjectValidationError(str(exc)) from exc

        object.__setattr__(self, "subject_id", short_id("subj", digest_object(self.identity())))
        object.__setattr__(self, "state_digest", digest_object(self._state()))

    def _validate_digest_fields(self) -> None:
        if self.digest is None:
            if self.digest_method is not DigestMethod.NONE:
                raise SubjectValidationError(
                    f"digest is None but digest_method is {self.digest_method.value}; "
                    "a method without a digest is a half-recorded claim")
            if self.digest_status is not DigestStatus.UNKNOWN:
                raise SubjectValidationError(
                    "a subject with no digest must carry digest_status UNKNOWN — "
                    "missing must not read as verified (Invariant 3)")
            return

        require_content_id(self.digest)
        if self.digest_method is DigestMethod.NONE:
            raise SubjectValidationError("a digest was supplied but digest_method is NONE")
        if self.digest_method is DigestMethod.GIT_OBJECT and not is_git_object_id(self.digest):
            raise SubjectValidationError(
                f"digest_method GIT_OBJECT requires a '{GIT_PREFIX}<sha>' content id, "
                f"got {self.digest!r}")
        if self.digest_method is not DigestMethod.GIT_OBJECT and not is_digest(self.digest):
            raise SubjectValidationError(
                f"digest_method {self.digest_method.value} requires a 'sha256:' digest, "
                f"got {self.digest!r}")
        if self.digest_status is DigestStatus.UNKNOWN:
            raise SubjectValidationError(
                "a digest was supplied but digest_status is UNKNOWN; say whether "
                "release-gate computed it (OBSERVED) or someone asserted it (DECLARED)")
        if self.digest_status is DigestStatus.OBSERVED and self.digest_method not in _OBSERVABLE_METHODS:
            raise SubjectValidationError(
                f"digest_status OBSERVED is only honest for a digest release-gate computed; "
                f"{self.digest_method.value} is someone else's claim, so it is DECLARED "
                "(Invariant 1)")
        if self.digest_status is DigestStatus.DECLARED and not self.digest_attested_by:
            raise SubjectValidationError(
                "a DECLARED digest must name who attested it — provenance is part of "
                "the claim, not an optional annotation (Invariant 11)")

    def _validate_version_fields(self) -> None:
        if self.version is None:
            if self.version_basis is not VersionBasis.UNKNOWN:
                raise SubjectValidationError(
                    f"version is None but version_basis is {self.version_basis.value}")
            return
        if not isinstance(self.version, str) or not self.version.strip():
            raise SubjectValidationError("version must be a non-empty string when present")
        object.__setattr__(self, "version", self.version.strip())
        if self.version_basis is VersionBasis.UNKNOWN:
            raise SubjectValidationError(
                "a version was supplied but version_basis is UNKNOWN; record where it "
                "came from (DECLARED / GIT_COMMIT / EXTERNAL / DERIVED)")

    # ── identity ────────────────────────────────────────────────────────────

    def identity(self) -> Dict[str, Any]:
        """What the subject IS. Stable across annotation; excludes `created_at`.

        Lineage (`supersedes`) is part of identity on purpose: "v2 of X" and "a
        standalone artifact with identical bytes" are different things to
        authorise, and conflating them is exactly how an approval would carry
        over silently.
        """
        return {
            "model_version": SUBJECT_MODEL_VERSION,
            "subject_type": self.subject_type.value,
            "custom_type": self.custom_type,
            "version": self.version,
            "version_basis": self.version_basis.value,
            "digest": self.digest,
            "digest_method": self.digest_method.value,
            "digest_status": self.digest_status.value,
            "digest_attested_by": self.digest_attested_by,
            "content_reference": self.content_reference.to_dict(),
            "requested_action": self.requested_action,
            "supersedes": self.supersedes,
        }

    def _state(self) -> Dict[str, Any]:
        """Identity plus everything else a human would have seen on the page."""
        return {
            "subject_id": short_id("subj", digest_object(self.identity())),
            "identity": self.identity(),
            "digest_basis": self.digest_basis,
            "metadata": _thaw(self.metadata),
        }

    def binding_state(self) -> Dict[str, Any]:
        """The exact subject state to embed in a BoundApproval (Invariant 5).

        Self-contained by design: a reviewer holding only the approval can
        recompute `state_digest` and see precisely what was authorised, without
        needing the case, the store, or the original artifact.
        """
        return {
            "subject_id": self.subject_id,
            "state_digest": self.state_digest,
            "state": self._state(),
            "mutation_detectable": self.mutation_detectable,
        }

    # ── properties ──────────────────────────────────────────────────────────

    @property
    def mutation_detectable(self) -> bool:
        """Can `recheck()` answer without outside help?

        False is a real and common answer — an object-store subject, a live
        external system. It belongs on the packet next to the verdict, because an
        approval over content nobody can re-verify is a weaker thing than one
        over content anybody can.
        """
        if self.digest is None:
            return False
        if self.content_reference.kind is ReferenceKind.INLINE:
            # A binary payload keeps its digest but is not embedded, so there is
            # nothing to re-hash offline. Claiming otherwise would promise a
            # re-check that recheck() cannot deliver.
            return "inline" in self.content_reference.detail
        return self.content_reference.kind in _LOCALLY_RECHECKABLE

    @property
    def is_hashed(self) -> bool:
        return self.digest is not None

    # ── mutation detection ──────────────────────────────────────────────────

    def recheck(self, resolver: Optional[Callable[["AssuranceSubject"], Optional[str]]] = None,
                items: Optional[Iterable[Any]] = None) -> MutationCheck:
        """Is this still the thing that was recorded?

        `resolver` lets a caller supply an observed digest for references this
        module cannot reach on its own (object store, URL, git object). `items`
        re-supplies the members of an ITEM_SET subject.

        Never returns UNCHANGED on a guess: anything we cannot confirm is
        UNVERIFIABLE, which is a distinct answer from "fine".
        """
        if self.digest is None:
            return MutationCheck(
                MutationStatus.UNVERIFIABLE, None, None,
                "subject has no digest, so mutation cannot be detected at all")

        try:
            observed = self._observe(resolver=resolver, items=items)
        except Exception as exc:
            # An object store that is down, a revoked credential, an I/O error.
            # `UNVERIFIABLE` is what this method promises for anything it cannot
            # confirm, and an exception is the loudest form of "cannot confirm" —
            # letting it propagate turned "is this still the thing?" into a
            # crash in the approval path, which is the one place that question is
            # asked. The failure is named rather than swallowed, because "the
            # store was unreachable" and "the reference resolves to nothing" are
            # different problems with different fixes.
            return MutationCheck(
                MutationStatus.UNVERIFIABLE, self.digest, None,
                f"content could not be re-read from {self.content_reference.kind.value} "
                f"reference {self.content_reference.locator!r}: "
                f"{type(exc).__name__}: {exc}")
        if observed is None:
            return MutationCheck(
                MutationStatus.UNVERIFIABLE, self.digest, None,
                f"content could not be re-read from {self.content_reference.kind.value} "
                f"reference {self.content_reference.locator!r}"
                + ("" if resolver else "; pass a resolver to verify this reference kind"))

        if observed == self.digest:
            return MutationCheck(MutationStatus.UNCHANGED, self.digest, observed,
                                 "content digest matches the recorded subject")
        return MutationCheck(
            MutationStatus.MUTATED, self.digest, observed,
            "content digest differs from the recorded subject — any approval bound "
            "to this subject no longer applies")

    def _observe(self, resolver=None, items=None) -> Optional[str]:
        kind = self.content_reference.kind

        if kind is ReferenceKind.FILE:
            path = Path(self.content_reference.locator)
            return digest_file(path) if path.is_file() else None

        if kind is ReferenceKind.DIRECTORY:
            path = Path(self.content_reference.locator)
            return directory_manifest_digest(path)[0] if path.is_dir() else None

        if kind is ReferenceKind.INLINE:
            payload = self.content_reference.detail.get("inline")
            if payload is None:
                return None
            return digest_bytes(payload.encode("utf-8") if isinstance(payload, str) else payload)

        if kind is ReferenceKind.ITEM_SET and items is not None:
            ordered = self.digest_method is DigestMethod.MERKLE_ORDERED
            return digest_items(items, ordered=ordered)

        return resolver(self) if resolver else None

    # ── supersession ────────────────────────────────────────────────────────

    def superseding(self, **changes: Any) -> "AssuranceSubject":
        """Build the next revision of this subject, linked to it.

        The new subject gets a different `subject_id` by construction, because
        `supersedes` is part of identity. That is the mechanism behind "a
        superseding subject must not inherit approval silently": there is no code
        path by which an approval bound to the old id matches the new one.
        """
        changes.setdefault("supersedes", self.subject_id)
        changes.setdefault("created_at", _utc_now())
        return dataclasses.replace(self, **changes)

    # ── serialisation ───────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "subject",
            "model_version": SUBJECT_MODEL_VERSION,
            "subject_id": self.subject_id,
            "state_digest": self.state_digest,
            "subject_type": self.subject_type.value,
            "custom_type": self.custom_type,
            "version": self.version,
            "version_basis": self.version_basis.value,
            "digest": self.digest,
            "digest_method": self.digest_method.value,
            "digest_status": self.digest_status.value,
            "digest_basis": self.digest_basis,
            "digest_attested_by": self.digest_attested_by,
            "content_reference": self.content_reference.to_dict(),
            "requested_action": self.requested_action,
            "supersedes": self.supersedes,
            "created_at": self.created_at,
            "mutation_detectable": self.mutation_detectable,
            "metadata": _thaw(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AssuranceSubject":
        """Rebuild a subject, recomputing its ids and refusing to trust the stored ones.

        A record whose stored `subject_id` or `state_digest` disagrees with its
        content has been edited after the fact. That is tamper detection on the
        record itself, and it is a hard error rather than a repair.
        """
        subject = cls(
            subject_type=SubjectType(data["subject_type"]),
            requested_action=data["requested_action"],
            content_reference=ContentReference.from_dict(data["content_reference"]),
            digest=data.get("digest"),
            digest_method=DigestMethod(data.get("digest_method", DigestMethod.NONE.value)),
            digest_status=DigestStatus(data.get("digest_status", DigestStatus.UNKNOWN.value)),
            digest_basis=data.get("digest_basis", ""),
            digest_attested_by=data.get("digest_attested_by"),
            version=data.get("version"),
            version_basis=VersionBasis(data.get("version_basis", VersionBasis.UNKNOWN.value)),
            supersedes=data.get("supersedes"),
            custom_type=data.get("custom_type"),
            created_at=data.get("created_at") or _utc_now(),
            metadata=data.get("metadata") or {},
        )
        for field_name in ("subject_id", "state_digest"):
            stored = data.get(field_name)
            if stored and stored != getattr(subject, field_name):
                raise SubjectIntegrityError(
                    f"{field_name} in the record ({stored}) does not match the value "
                    f"recomputed from its content ({getattr(subject, field_name)}) — "
                    "the record was modified after it was written")
        return subject

    # ── constructors ────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str | Path, subject_type: SubjectType, requested_action: str,
                  **kwargs: Any) -> "AssuranceSubject":
        """A single file: a migration, a generated document, a plan."""
        p = Path(path)
        if not p.is_file():
            raise SubjectValidationError(f"not a file: {p}")
        return cls(
            subject_type=subject_type, requested_action=requested_action,
            content_reference=ContentReference(ReferenceKind.FILE, str(p)),
            digest=digest_file(p), digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED,
            digest_basis=f"sha256 over the bytes of {p.name}",
            **kwargs)

    @classmethod
    def from_directory(cls, path: str | Path, subject_type: SubjectType,
                       requested_action: str, **kwargs: Any) -> "AssuranceSubject":
        """A tree: a deployment package, a generated codebase, a dataset dump."""
        p = Path(path)
        if not p.is_dir():
            raise SubjectValidationError(f"not a directory: {p}")
        digest, entry_count = directory_manifest_digest(p)
        return cls(
            subject_type=subject_type, requested_action=requested_action,
            content_reference=ContentReference(ReferenceKind.DIRECTORY, str(p),
                                               {"entry_count": entry_count}),
            digest=digest, digest_method=DigestMethod.SHA256_MANIFEST,
            digest_status=DigestStatus.OBSERVED,
            digest_basis=f"sha256 over a sorted manifest of {entry_count} entries",
            **kwargs)

    @classmethod
    def from_bytes(cls, data: bytes, subject_type: SubjectType, requested_action: str,
                   *, label: str = "inline", **kwargs: Any) -> "AssuranceSubject":
        """Content held in memory — a generated result, a message body."""
        detail: Dict[str, Any] = {"byte_length": len(data)}
        if len(data) <= MAX_INLINE_BYTES:
            try:
                detail["inline"] = data.decode("utf-8")
            except UnicodeDecodeError:
                # Binary payloads keep their digest; we do not base64 them into
                # every evidence pack just to make recheck() offline-capable.
                detail["encoding"] = "binary (not embedded)"
        else:
            detail["encoding"] = f"not embedded (> {MAX_INLINE_BYTES} bytes)"
        return cls(
            subject_type=subject_type, requested_action=requested_action,
            content_reference=ContentReference(ReferenceKind.INLINE, label, detail),
            digest=digest_bytes(data), digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED,
            digest_basis="sha256 over the supplied bytes",
            **kwargs)

    @classmethod
    def from_text(cls, text: str, subject_type: SubjectType, requested_action: str,
                  **kwargs: Any) -> "AssuranceSubject":
        return cls.from_bytes(text.encode("utf-8"), subject_type, requested_action, **kwargs)

    @classmethod
    def from_items(cls, items: Iterable[Any], subject_type: SubjectType,
                   requested_action: str, *, ordered: bool = False,
                   label: str = "item-set", **kwargs: Any) -> "AssuranceSubject":
        """A batch: 8,214 refunds, a set of messages, a list of resources to change.

        Unordered by default — the same refunds in a different order are the same
        batch — and one changed item changes the root, which is what makes "the
        batch I approved" a checkable statement.
        """
        materialised = list(items)
        digest = digest_items(materialised, ordered=ordered)
        method = DigestMethod.MERKLE_ORDERED if ordered else DigestMethod.MERKLE_UNORDERED
        algo = MERKLE_ORDERED if ordered else MERKLE_UNORDERED
        return cls(
            subject_type=subject_type, requested_action=requested_action,
            content_reference=ContentReference(ReferenceKind.ITEM_SET, label,
                                               {"item_count": len(materialised), "algo": algo}),
            digest=digest, digest_method=method, digest_status=DigestStatus.OBSERVED,
            digest_basis=f"{algo} over {len(materialised)} canonicalised items",
            **kwargs)

    @classmethod
    def from_git_commit(cls, commit: str, subject_type: SubjectType, requested_action: str,
                        *, repository: Optional[str] = None, observed: bool = False,
                        attested_by: Optional[str] = None, **kwargs: Any) -> "AssuranceSubject":
        """A commit or PR head. The git object id is itself the content identifier.

        Recorded as `git:<sha>` rather than squeezed into the `sha256:` namespace:
        a sha-1 object id identified that content, and relabelling it would
        misstate which algorithm did the identifying.

        `observed` defaults to False. Unless the caller actually resolved the
        object — at which point git has verified the content hash on read — a
        commit id handed to us is a claim about what that id contains, and it is
        recorded as DECLARED with its attestor named (Invariant 1).

        Abbreviated ids are refused outright. A 7-character prefix is ambiguous by
        design, and an ambiguous subject is the one thing an approval cannot bind to.
        """
        sha = (commit or "").strip().lower()
        if len(sha) not in (40, 64) or any(c not in "0123456789abcdef" for c in sha):
            raise SubjectValidationError(
                f"expected a full git object id (40 or 64 hex characters), got {commit!r}; "
                "abbreviated ids are ambiguous and cannot identify a subject")
        kwargs.setdefault("version", sha)
        kwargs.setdefault("version_basis", VersionBasis.GIT_COMMIT)
        status = DigestStatus.OBSERVED if observed else DigestStatus.DECLARED
        return cls(
            subject_type=subject_type, requested_action=requested_action,
            content_reference=ContentReference(ReferenceKind.GIT_COMMIT, sha,
                                               {"repository": repository} if repository else {}),
            digest=f"{GIT_PREFIX}{sha}", digest_method=DigestMethod.GIT_OBJECT,
            digest_status=status,
            digest_attested_by=None if observed else (attested_by or repository or "git"),
            digest_basis=("git object resolved and verified by git"
                          if observed else "git object id as supplied; object not resolved here"),
            **kwargs)

    @classmethod
    def from_external(cls, locator: str, subject_type: SubjectType, requested_action: str,
                      *, digest: Optional[str] = None, attested_by: Optional[str] = None,
                      kind: ReferenceKind = ReferenceKind.EXTERNAL,
                      detail: Optional[Mapping[str, Any]] = None,
                      **kwargs: Any) -> "AssuranceSubject":
        """A subject too large or too remote to hash here.

        With a digest the store attests to, the subject is identified but the
        binding is DECLARED. With no digest it is still a valid subject, carrying
        `digest_status=UNKNOWN` and `mutation_detectable=False` — an honest
        statement that nobody can later prove it did not change.
        """
        if digest is not None:
            if not attested_by:
                raise SubjectValidationError(
                    "an external digest must name its attestor (attested_by)")
            return cls(
                subject_type=subject_type, requested_action=requested_action,
                content_reference=ContentReference(kind, locator, detail or {}),
                digest=require_digest(digest), digest_method=DigestMethod.EXTERNAL_ATTESTED,
                digest_status=DigestStatus.DECLARED, digest_attested_by=attested_by,
                digest_basis=f"digest asserted by {attested_by}; not computed by release-gate",
                **kwargs)
        return cls(
            subject_type=subject_type, requested_action=requested_action,
            content_reference=ContentReference(kind, locator, detail or {}),
            digest=None, digest_method=DigestMethod.NONE, digest_status=DigestStatus.UNKNOWN,
            digest_basis="content is not hashable from here; mutation cannot be detected",
            **kwargs)


def directory_manifest_digest(root: str | Path) -> tuple[str, int]:
    """Digest a directory tree as a sorted manifest of per-entry digests.

    Symlinks — to files and to directories alike — are recorded by target rather
    than followed: following them would let a subject's digest depend on
    something outside the tree, and skipping them silently would hide a real part
    of the content.

    The manifest covers files and symlinks. An empty directory has no entry, so
    two trees differing only in empty directories digest identically; that is a
    deliberate simplification, and it is stated here rather than discovered.
    """
    root = Path(root)
    manifest: Dict[str, Any] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(dirnames):
            if name == ".git":
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                # os.walk neither descends into a symlinked directory nor lists
                # it as a file, so without this it would vanish from the digest.
                manifest[full.relative_to(root).as_posix()] = {"symlink": os.readlink(full)}
            else:
                kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                manifest[rel] = {"symlink": os.readlink(full)}
            elif full.is_file():
                manifest[rel] = digest_file(full)
    return digest_object(manifest), len(manifest)


def describe_supersession(previous: AssuranceSubject,
                          current: AssuranceSubject) -> Dict[str, Any]:
    """State plainly what changed between two revisions, and that approval does not carry.

    `approval_carryover_permitted` is unconditionally False. It is not a policy
    knob: re-approval after a change is a new human act, and a field that could
    ever be True would eventually be set to True by something automated at 3am.
    """
    prev_state, cur_state = previous._state(), current._state()
    changed: List[str] = []
    for key, prev_value in prev_state["identity"].items():
        if cur_state["identity"].get(key) != prev_value:
            changed.append(key)
    if prev_state["metadata"] != cur_state["metadata"]:
        changed.append("metadata")

    return {
        "previous_subject_id": previous.subject_id,
        "current_subject_id": current.subject_id,
        "previous_state_digest": previous.state_digest,
        "current_state_digest": current.state_digest,
        "linked": current.supersedes == previous.subject_id,
        "changed": sorted(changed),
        "approval_carryover_permitted": False,
        "reason": ("A superseding subject is a different thing to authorise. Any "
                   "approval of the previous subject applies to the previous subject "
                   "only; this revision requires its own authorisation."),
    }
