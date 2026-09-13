"""release-gate assurance layer.

The evidence and authorisation model described in
`docs/specs/universal-assurance-architecture.md`. Built incrementally; this
package currently provides the root identity object — the exact subject a human
is asked to authorise — and the canonical digest machinery it rests on.

Nothing here imports an LLM client, makes a network call, or executes ingested
content. The authoritative assurance path is deterministic, and these are its
foundations.
"""

from __future__ import annotations

from release_gate.assurance.canonical import (
    CanonicalisationError,
    canonical_json,
    digest_bytes,
    digest_file,
    digest_items,
    digest_object,
    is_content_id,
    is_digest,
    is_git_object_id,
    merkle_root,
)
from release_gate.assurance.subject import (
    AssuranceSubject,
    ContentReference,
    DigestMethod,
    DigestStatus,
    MutationCheck,
    MutationStatus,
    ReferenceKind,
    SubjectIntegrityError,
    SubjectType,
    SubjectValidationError,
    VersionBasis,
    describe_supersession,
    directory_manifest_digest,
)

__all__ = [
    "AssuranceSubject",
    "CanonicalisationError",
    "ContentReference",
    "DigestMethod",
    "DigestStatus",
    "MutationCheck",
    "MutationStatus",
    "ReferenceKind",
    "SubjectIntegrityError",
    "SubjectType",
    "SubjectValidationError",
    "VersionBasis",
    "canonical_json",
    "describe_supersession",
    "digest_bytes",
    "digest_file",
    "digest_items",
    "digest_object",
    "directory_manifest_digest",
    "is_content_id",
    "is_digest",
    "is_git_object_id",
    "merkle_root",
]
