"""AssuranceSubject — the exact thing a human is asked to authorise.

These tests are written against the invariants in
`docs/specs/universal-assurance-architecture.md`, not against the implementation:
each one names the property it protects, so a future refactor that breaks the
property fails loudly rather than quietly re-grading what an approval means.
"""

import json
import os

import pytest

from release_gate.assurance import canonical as C
from release_gate.assurance.subject import (
    AssuranceSubject,
    ContentReference,
    DigestMethod,
    DigestStatus,
    MutationStatus,
    ReferenceKind,
    SubjectIntegrityError,
    SubjectType,
    SubjectValidationError,
    VersionBasis,
    describe_supersession,
    directory_manifest_digest,
)

ACTION = "apply this migration to prod-eu"


def _subject(text="CREATE INDEX CONCURRENTLY idx_orders ON orders(id);", **kw):
    return AssuranceSubject.from_text(text, SubjectType.DATA_CHANGE, ACTION, **kw)


# ── canonical form and digests ──────────────────────────────────────────────

def test_canonical_json_is_key_order_independent():
    assert C.digest_object({"b": 1, "a": 2}) == C.digest_object({"a": 2, "b": 1})


def test_canonical_json_rejects_nan():
    # json.dumps emits a bare NaN by default, which no parser round-trips —
    # a digest over unparseable output is not a digest.
    with pytest.raises(C.CanonicalisationError):
        C.canonical_json({"x": float("nan")})


def test_canonical_json_rejects_sets():
    with pytest.raises(C.CanonicalisationError):
        C.canonical_json({"x": {1, 2}})


def test_digest_carries_its_algorithm():
    assert C.digest_bytes(b"x").startswith("sha256:")
    assert C.is_digest(C.digest_bytes(b"x"))
    assert not C.is_digest("sha256:short")
    assert not C.is_digest("deadbeef")


def test_git_object_ids_live_in_their_own_namespace():
    assert C.is_git_object_id("git:" + "a" * 40)
    assert C.is_git_object_id("git:" + "a" * 64)
    assert not C.is_git_object_id("git:" + "a" * 12)
    assert not C.is_digest("git:" + "a" * 40)
    assert C.is_content_id("git:" + "a" * 40)


def test_empty_item_set_is_refused():
    # An authorisation over nothing is malformed, not empty.
    with pytest.raises(C.CanonicalisationError):
        C.digest_items([])


# ── requirement: the action is mandatory ────────────────────────────────────

@pytest.mark.parametrize("action", ["", "   ", None])
def test_subject_requires_a_requested_action(action):
    with pytest.raises(SubjectValidationError, match="requested_action"):
        AssuranceSubject.from_text("x", SubjectType.DOCUMENT, action)


def test_requested_action_is_normalised():
    s = AssuranceSubject.from_text("x", SubjectType.DOCUMENT, "  publish this  ")
    assert s.requested_action == "publish this"


# ── requirement: subject types, including CUSTOM ────────────────────────────

def test_all_contract_subject_types_exist():
    expected = {
        "DEPLOYMENT", "CODE_CHANGE", "AUTONOMOUS_ACTION", "RESEARCH_RESULT",
        "DATA_CHANGE", "FINANCIAL_ACTION", "INFRASTRUCTURE_CHANGE", "DOCUMENT",
        "MODEL_CHANGE", "CONFIG_CHANGE", "GENERAL_RESULT", "CUSTOM",
    }
    assert {t.value for t in SubjectType} == expected


def test_custom_type_requires_a_label():
    with pytest.raises(SubjectValidationError, match="custom_type"):
        AssuranceSubject.from_text("x", SubjectType.CUSTOM, ACTION)


def test_custom_label_is_rejected_on_a_non_custom_type():
    with pytest.raises(SubjectValidationError, match="only valid with subject_type CUSTOM"):
        AssuranceSubject.from_text("x", SubjectType.DOCUMENT, ACTION, custom_type="clinical-note")


# ── requirement: digest is cryptographic where content can be hashed ────────

def test_file_subject_hashes_the_bytes(tmp_path):
    path = tmp_path / "migration.sql"
    path.write_text("CREATE INDEX x;", encoding="utf-8")
    s = AssuranceSubject.from_file(path, SubjectType.DATA_CHANGE, ACTION)
    assert s.digest == C.digest_bytes(b"CREATE INDEX x;")
    assert s.digest_method is DigestMethod.SHA256_CONTENT
    assert s.digest_status is DigestStatus.OBSERVED
    assert s.mutation_detectable is True


def test_directory_subject_digests_a_sorted_manifest(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("a", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("b", encoding="utf-8")
    s = AssuranceSubject.from_directory(tmp_path / "pkg", SubjectType.DEPLOYMENT, "ship v2.4")
    assert s.digest_method is DigestMethod.SHA256_MANIFEST
    assert s.content_reference.detail["entry_count"] == 2

    (tmp_path / "pkg" / "b.py").write_text("b!", encoding="utf-8")
    s2 = AssuranceSubject.from_directory(tmp_path / "pkg", SubjectType.DEPLOYMENT, "ship v2.4")
    assert s2.digest != s.digest


def test_directory_digest_records_symlinks_without_following_them(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "real.txt").write_text("real", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    os.symlink(outside, root / "link.txt")

    digest_before, count = directory_manifest_digest(root)
    outside.write_text("CHANGED", encoding="utf-8")
    digest_after, _ = directory_manifest_digest(root)
    # Following the link would make the subject's digest depend on content
    # outside the tree; the link is recorded by target instead.
    assert digest_before == digest_after
    assert count == 2


# ── requirement: item sets (the 8,214 refunds case) ─────────────────────────

def test_item_set_is_order_independent_by_default():
    items = [{"id": i, "amount": i * 10} for i in range(50)]
    a = AssuranceSubject.from_items(items, SubjectType.FINANCIAL_ACTION, "execute these refunds")
    b = AssuranceSubject.from_items(list(reversed(items)), SubjectType.FINANCIAL_ACTION,
                                    "execute these refunds")
    assert a.digest == b.digest
    assert a.subject_id == b.subject_id


def test_ordered_item_set_treats_sequence_as_meaning():
    items = [{"step": i} for i in range(5)]
    a = AssuranceSubject.from_items(items, SubjectType.AUTONOMOUS_ACTION, "send", ordered=True)
    b = AssuranceSubject.from_items(list(reversed(items)), SubjectType.AUTONOMOUS_ACTION,
                                    "send", ordered=True)
    assert a.digest != b.digest
    assert a.digest_method is DigestMethod.MERKLE_ORDERED


def test_one_changed_item_changes_the_batch():
    items = [{"refund_id": i, "cents": 500} for i in range(8214)]
    before = AssuranceSubject.from_items(items, SubjectType.FINANCIAL_ACTION, "execute refunds")
    items[4100] = {"refund_id": 4100, "cents": 50000}
    after = AssuranceSubject.from_items(items, SubjectType.FINANCIAL_ACTION, "execute refunds")
    assert before.digest != after.digest
    assert before.content_reference.detail["item_count"] == 8214


def test_item_set_recheck_needs_the_items_back():
    items = [{"id": 1}, {"id": 2}]
    s = AssuranceSubject.from_items(items, SubjectType.FINANCIAL_ACTION, "pay")
    assert s.recheck(items=items).status is MutationStatus.UNCHANGED
    assert s.recheck(items=[{"id": 1}, {"id": 3}]).status is MutationStatus.MUTATED
    assert s.recheck().status is MutationStatus.UNVERIFIABLE


# ── requirement: large subjects may be referenced externally ────────────────

def test_external_subject_without_a_digest_is_legal_and_says_so():
    s = AssuranceSubject.from_external(
        "s3://warehouse/exports/2026-09-12/", SubjectType.DATA_CHANGE,
        "replace the production feature table", kind=ReferenceKind.OBJECT_STORE)
    assert s.digest is None
    assert s.digest_status is DigestStatus.UNKNOWN
    assert s.digest_method is DigestMethod.NONE
    assert s.mutation_detectable is False
    assert s.recheck().status is MutationStatus.UNVERIFIABLE


def test_externally_attested_digest_is_declared_not_observed():
    # Invariant 1: a digest someone else computed is their claim, not our observation.
    s = AssuranceSubject.from_external(
        "s3://warehouse/model.bin", SubjectType.MODEL_CHANGE, "promote to serving",
        digest=C.digest_bytes(b"weights"), attested_by="s3://warehouse",
        kind=ReferenceKind.OBJECT_STORE)
    assert s.digest_status is DigestStatus.DECLARED
    assert s.digest_attested_by == "s3://warehouse"
    assert "not computed by release-gate" in s.digest_basis


def test_a_declared_digest_must_name_its_attestor():
    # Invariant 11: provenance is part of the claim, not an optional annotation.
    with pytest.raises(SubjectValidationError, match="attest"):
        AssuranceSubject.from_external("s3://x", SubjectType.DOCUMENT, "publish",
                                       digest=C.digest_bytes(b"x"))


def test_observed_is_refused_for_a_digest_we_did_not_compute():
    with pytest.raises(SubjectValidationError, match="OBSERVED"):
        AssuranceSubject(
            subject_type=SubjectType.DOCUMENT, requested_action="publish",
            content_reference=ContentReference(ReferenceKind.URL, "https://x/y"),
            digest=C.digest_bytes(b"x"), digest_method=DigestMethod.EXTERNAL_ATTESTED,
            digest_status=DigestStatus.OBSERVED, digest_attested_by="someone")


def test_a_digest_may_not_be_half_recorded():
    with pytest.raises(SubjectValidationError):
        AssuranceSubject(subject_type=SubjectType.DOCUMENT, requested_action="publish",
                         content_reference=ContentReference(ReferenceKind.EXTERNAL, "x"),
                         digest=None, digest_method=DigestMethod.SHA256_CONTENT)
    with pytest.raises(SubjectValidationError):
        AssuranceSubject(subject_type=SubjectType.DOCUMENT, requested_action="publish",
                         content_reference=ContentReference(ReferenceKind.EXTERNAL, "x"),
                         digest=C.digest_bytes(b"x"), digest_method=DigestMethod.NONE)


def test_missing_digest_never_reads_as_verified():
    # Invariant 3: absent must not become safe.
    with pytest.raises(SubjectValidationError, match="Invariant 3"):
        AssuranceSubject(subject_type=SubjectType.DOCUMENT, requested_action="publish",
                         content_reference=ContentReference(ReferenceKind.EXTERNAL, "x"),
                         digest=None, digest_method=DigestMethod.NONE,
                         digest_status=DigestStatus.OBSERVED)


# ── requirement: version explicit where possible ────────────────────────────

def test_version_is_never_invented():
    s = _subject()
    assert s.version is None
    assert s.version_basis is VersionBasis.UNKNOWN


def test_declared_version_records_where_it_came_from():
    s = _subject(version="v3", version_basis=VersionBasis.DECLARED)
    assert (s.version, s.version_basis) == ("v3", VersionBasis.DECLARED)


def test_a_version_without_a_basis_is_refused():
    with pytest.raises(SubjectValidationError, match="version_basis"):
        _subject(version="v3")


def test_git_commit_subject_uses_the_commit_as_its_version():
    sha = "0" * 39 + "1"
    s = AssuranceSubject.from_git_commit(sha, SubjectType.CODE_CHANGE, "merge to main",
                                         repository="acme/api")
    assert s.version == sha
    assert s.version_basis is VersionBasis.GIT_COMMIT
    assert s.digest == f"git:{sha}"
    assert s.digest_method is DigestMethod.GIT_OBJECT
    # Not resolved here, so the id is someone else's claim about that content.
    assert s.digest_status is DigestStatus.DECLARED
    assert s.digest_attested_by == "acme/api"


def test_resolved_git_object_may_be_observed():
    s = AssuranceSubject.from_git_commit("a" * 40, SubjectType.CODE_CHANGE, "merge",
                                         observed=True)
    assert s.digest_status is DigestStatus.OBSERVED


def test_abbreviated_commit_ids_are_refused():
    with pytest.raises(SubjectValidationError, match="ambiguous"):
        AssuranceSubject.from_git_commit("abc1234", SubjectType.CODE_CHANGE, "merge")


# ── identity: what is the same thing, and what is not ───────────────────────

def test_identical_content_and_action_yield_the_same_subject():
    assert _subject().subject_id == _subject().subject_id


def test_subject_id_does_not_depend_on_when_it_was_created():
    # Identity is content, not clock; otherwise every re-run manufactures a new
    # thing to approve and dedup becomes impossible.
    a = _subject(created_at="2026-09-12T09:00:00Z")
    b = _subject(created_at="2026-09-13T22:41:07Z")
    assert a.subject_id == b.subject_id
    assert a.state_digest == b.state_digest


def test_a_different_action_is_a_different_subject():
    a = AssuranceSubject.from_text("x", SubjectType.DATA_CHANGE, "apply to staging")
    b = AssuranceSubject.from_text("x", SubjectType.DATA_CHANGE, "apply to prod-eu")
    assert a.subject_id != b.subject_id


def test_metadata_changes_the_state_but_not_the_identity():
    # Re-tagging does not change what the thing IS, but it does change what was
    # on the page — and only the second one may invalidate an approval.
    a = _subject(metadata={"ticket": "OPS-1"})
    b = _subject(metadata={"ticket": "OPS-2"})
    assert a.subject_id == b.subject_id
    assert a.state_digest != b.state_digest


def test_binding_state_is_self_contained():
    s = _subject(version="v1", version_basis=VersionBasis.DECLARED, metadata={"ticket": "OPS-1"})
    state = s.binding_state()
    assert state["subject_id"] == s.subject_id
    assert state["state_digest"] == s.state_digest
    assert state["state"]["identity"]["digest"] == s.digest
    assert state["state"]["identity"]["requested_action"] == ACTION
    assert state["state"]["identity"]["version"] == "v1"
    assert state["mutation_detectable"] is True
    assert "created_at" not in json.dumps(state)


# ── requirement: mutation must be detectable ────────────────────────────────

def test_mutation_of_a_file_subject_is_detected(tmp_path):
    path = tmp_path / "plan.tf"
    path.write_text("resource a {}", encoding="utf-8")
    s = AssuranceSubject.from_file(path, SubjectType.INFRASTRUCTURE_CHANGE, "apply this plan")
    assert s.recheck().status is MutationStatus.UNCHANGED

    path.write_text("resource a {}\nresource evil {}", encoding="utf-8")
    check = s.recheck()
    assert check.status is MutationStatus.MUTATED
    assert check.unchanged is False
    assert check.observed_digest != s.digest


def test_a_vanished_subject_is_unverifiable_not_unchanged(tmp_path):
    path = tmp_path / "doc.md"
    path.write_text("hello", encoding="utf-8")
    s = AssuranceSubject.from_file(path, SubjectType.DOCUMENT, "publish this")
    path.unlink()
    check = s.recheck()
    assert check.status is MutationStatus.UNVERIFIABLE
    # The property that matters: "I could not tell" must never read as "fine".
    assert check.unchanged is False


def test_a_resolver_can_verify_reference_kinds_we_cannot_reach():
    digest = C.digest_bytes(b"weights")
    s = AssuranceSubject.from_external("s3://w/model.bin", SubjectType.MODEL_CHANGE,
                                       "promote to serving", digest=digest,
                                       attested_by="s3://w", kind=ReferenceKind.OBJECT_STORE)
    assert s.recheck(resolver=lambda _s: digest).status is MutationStatus.UNCHANGED
    assert s.recheck(resolver=lambda _s: C.digest_bytes(b"other")).status is MutationStatus.MUTATED
    assert s.recheck(resolver=lambda _s: None).status is MutationStatus.UNVERIFIABLE


def test_inline_subjects_stay_verifiable_offline():
    s = AssuranceSubject.from_text("a generated research conclusion",
                                   SubjectType.RESEARCH_RESULT, "publish this result")
    assert s.mutation_detectable is True
    assert s.recheck().status is MutationStatus.UNCHANGED


# ── requirement: superseding must not inherit approval silently ─────────────

def test_a_superseding_subject_is_a_different_target():
    v1 = _subject()
    v2 = v1.superseding()
    assert v2.supersedes == v1.subject_id
    assert v2.subject_id != v1.subject_id
    assert v2.state_digest != v1.state_digest


def test_supersession_is_described_and_never_carries_approval():
    v1 = _subject(metadata={"ticket": "OPS-1"})
    v2 = v1.superseding(metadata={"ticket": "OPS-1", "reviewed_by": "alice"})
    notice = describe_supersession(v1, v2)
    assert notice["approval_carryover_permitted"] is False
    assert notice["linked"] is True
    assert "metadata" in notice["changed"] and "supersedes" in notice["changed"]
    assert notice["previous_subject_id"] == v1.subject_id


def test_carryover_is_refused_even_when_nothing_visible_changed():
    # The guard is structural, not a judgement about how big the change was.
    v1 = _subject()
    v2 = v1.superseding()
    assert describe_supersession(v1, v2)["approval_carryover_permitted"] is False


def test_identical_content_submitted_fresh_is_not_a_revision():
    v1 = _subject()
    fresh = _subject()
    v2 = v1.superseding()
    assert fresh.subject_id == v1.subject_id
    assert v2.subject_id != fresh.subject_id


def test_supersedes_must_be_a_subject_id():
    with pytest.raises(SubjectValidationError, match="supersedes"):
        _subject(supersedes="the-old-one")


# ── serialisation and tamper detection ──────────────────────────────────────

def test_round_trip_preserves_identity():
    s = _subject(version="v2", version_basis=VersionBasis.DECLARED,
                 metadata={"owner": "platform", "nested": {"a": [1, 2, 3]}})
    back = AssuranceSubject.from_dict(json.loads(json.dumps(s.to_dict())))
    assert back.subject_id == s.subject_id
    assert back.state_digest == s.state_digest
    assert back.requested_action == s.requested_action
    # Nested metadata reads back immutably (lists become tuples) so a subject
    # cannot drift out from under the state_digest computed at construction.
    # `to_dict()` is the JSON-shaped view.
    assert back.metadata["nested"]["a"] == (1, 2, 3)
    assert back.to_dict()["metadata"]["nested"]["a"] == [1, 2, 3]


def test_an_edited_record_is_rejected_rather_than_repaired():
    s = _subject()
    tampered = s.to_dict()
    tampered["requested_action"] = "apply this migration to prod-us"
    with pytest.raises(SubjectIntegrityError, match="modified after it was written"):
        AssuranceSubject.from_dict(tampered)


def test_stored_ids_are_never_trusted_over_content():
    s = _subject()
    tampered = s.to_dict()
    tampered["state_digest"] = C.digest_bytes(b"whatever-i-want")
    with pytest.raises(SubjectIntegrityError):
        AssuranceSubject.from_dict(tampered)


# ── immutability ────────────────────────────────────────────────────────────

def test_a_subject_cannot_be_mutated_after_construction():
    s = _subject()
    with pytest.raises(Exception):
        s.requested_action = "something else"
    with pytest.raises(Exception):
        s.metadata["injected"] = True
    with pytest.raises(Exception):
        s.metadata["nested"] = {}


def test_nested_metadata_is_frozen_all_the_way_down():
    # A mutable nested value would let a caller change what the human saw while
    # the state_digest, computed once at construction, went on saying otherwise.
    s = _subject(metadata={"reviewers": ["alice"], "ctx": {"env": "prod"}})
    assert s.metadata["reviewers"] == ("alice",)
    with pytest.raises(Exception):
        s.metadata["ctx"]["env"] = "staging"


def test_metadata_must_be_json_values():
    with pytest.raises(SubjectValidationError, match="JSON values"):
        _subject(metadata={"when": object()})


def test_metadata_keys_must_be_strings():
    with pytest.raises(SubjectValidationError, match="keys must be strings"):
        _subject(metadata={1: "one"})


def test_a_binary_inline_subject_does_not_promise_an_offline_recheck():
    # The digest is kept; the payload is not embedded. Claiming detectability
    # here would promise a re-check recheck() cannot deliver.
    s = AssuranceSubject.from_bytes(b"\x00\x01\x02\xff", SubjectType.MODEL_CHANGE,
                                    "promote these weights")
    assert s.digest is not None
    assert s.mutation_detectable is False
    assert s.recheck().status is MutationStatus.UNVERIFIABLE


def test_symlinked_directories_are_recorded_not_silently_dropped(tmp_path):
    root = tmp_path / "pkg"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.py").write_text("a", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "secret.py").write_text("secret", encoding="utf-8")

    before, _ = directory_manifest_digest(root)
    os.symlink(outside, root / "linked")
    after, count = directory_manifest_digest(root)
    assert before != after          # the link is part of the content
    assert count == 2               # a.py plus the recorded symlink


def test_a_nan_buried_in_metadata_fails_as_a_subject_error():
    with pytest.raises(SubjectValidationError):
        _subject(metadata={"ratio": float("inf")})
