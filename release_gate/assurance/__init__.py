"""release-gate assurance layer.

The evidence and authorisation model described in
`docs/specs/universal-assurance-architecture.md`. Built incrementally; this
package currently provides the central case object, the exact subject a human is
asked to authorise, the record collections a case is built from, and the
canonical digest machinery they rest on.

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
from release_gate.assurance.case import (
    CASE_BINDING_ALGO,
    COLLECTION_KINDS,
    EVIDENCE_KINDS,
    AssuranceCase,
    AssuranceCaseBuilder,
    CaseIntegrityError,
    CaseState,
    CaseStateError,
    CaseType,
    CaseValidationError,
    CaseVerdict,
    Decision,
    MethodologyRef,
    default_case_type,
)
from release_gate.assurance.records import (
    CaseRecord,
    DedupeBasis,
    MaterialisationBasis,
    Presence,
    RecordCollection,
    RecordCollectionBuilder,
    RecordError,
    SimpleRecord,
    record_digest,
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
    "CASE_BINDING_ALGO",
    "COLLECTION_KINDS",
    "EVIDENCE_KINDS",
    "AssuranceCase",
    "AssuranceCaseBuilder",
    "AssuranceSubject",
    "CaseIntegrityError",
    "CaseRecord",
    "CaseState",
    "CaseStateError",
    "CaseType",
    "CaseValidationError",
    "CaseVerdict",
    "DedupeBasis",
    "Decision",
    "MaterialisationBasis",
    "MethodologyRef",
    "Presence",
    "RecordCollection",
    "RecordCollectionBuilder",
    "RecordError",
    "SimpleRecord",
    "default_case_type",
    "record_digest",
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
