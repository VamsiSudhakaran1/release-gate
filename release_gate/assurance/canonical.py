"""Canonical serialisation and content digests for the assurance layer.

Two things in release-gate's assurance model are load-bearing enough to deserve
their own module: **a byte-stable serialisation** (so the same case digests to
the same value on any machine, in any process, in any key order) and **content
digests** (so "is this still the thing that was approved?" is a comparison, not
an opinion).

Stdlib only, like the ingest adapters: the assurance core must not add a fourth
library to `pip install release-gate`.

Design notes worth keeping:

* **No Unicode normalisation.** Normalising strings before hashing would silently
  alter a caller's data, and two genuinely different strings could collapse to
  one digest. The caller owns its encoding; we hash exactly what we are given.
* **NaN/Infinity are rejected.** `json.dumps` emits them by default as bare
  `NaN`, which is not JSON and which no other implementation will parse back to
  the same value. A digest over unparseable output is not a digest.
* **Merkle trees are domain-separated and count-bound.** Leaves and interior
  nodes are tagged with distinct prefixes, odd nodes are *promoted* rather than
  duplicated, and the leaf count is folded into the root — the three cheap
  defences against a set being re-shaped into the same root.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Sequence

#: Every digest this package emits carries its algorithm inline.
DIGEST_PREFIX = "sha256:"
GIT_PREFIX = "git:"
DIGEST_HEX_LEN = 64

#: Versioned algorithm ids. They travel in records so a digest computed today
#: stays interpretable after the algorithm changes.
CANONICAL_ALGO = "rg-canon-1"
MERKLE_UNORDERED = "rg-merkle-unordered-1"
MERKLE_ORDERED = "rg-merkle-ordered-1"

_LEAF_TAG = b"\x00"
_NODE_TAG = b"\x01"
_ROOT_TAG = b"rg-merkle-1"

_FILE_CHUNK = 1024 * 1024


class CanonicalisationError(ValueError):
    """Raised when a value cannot be canonically serialised.

    Deliberately an error rather than a best-effort coercion: a silent fallback
    would let two different objects share a digest, which is the one failure this
    module exists to prevent.
    """


def _fallback(obj: Any) -> Any:
    """Handle the few container types `json` does not serialise natively."""
    if isinstance(obj, Mapping):
        # types.MappingProxyType — the read-only metadata wrapper subjects use.
        return dict(obj)
    if isinstance(obj, (set, frozenset)):
        raise CanonicalisationError(
            "sets have no defined order and cannot be canonically serialised; "
            "pass a sorted list, or use digest_items(..., ordered=False)")
    raise CanonicalisationError(
        f"{type(obj).__name__} is not canonically serialisable; convert it to a "
        "JSON value (str/int/float/bool/None/list/dict) first")


def canonical_json(obj: Any) -> str:
    """Serialise `obj` to the one JSON form this package hashes.

    Sorted keys, no insignificant whitespace, no NaN/Infinity, UTF-8 text.
    """
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False,
                          default=_fallback)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, CanonicalisationError):
            raise
        raise CanonicalisationError(f"value is not canonically serialisable: {exc}") from exc


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_bytes(data: bytes) -> str:
    """Digest raw bytes — the form used for file content and inline payloads."""
    return DIGEST_PREFIX + sha256_hex(data)


def digest_object(obj: Any) -> str:
    """Digest a JSON-able object through the canonical form."""
    return digest_bytes(canonical_bytes(obj))


def digest_file(path: str | Path) -> str:
    """Stream a file into a digest.

    Streamed rather than read whole: an assurance subject can legitimately be a
    multi-gigabyte artifact, and a gate that runs out of memory on the thing it
    is meant to gate is not a gate.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_FILE_CHUNK), b""):
            h.update(chunk)
    return DIGEST_PREFIX + h.hexdigest()


def is_digest(value: Any) -> bool:
    """True for a well-formed `sha256:<64 hex>` string."""
    if not isinstance(value, str) or not value.startswith(DIGEST_PREFIX):
        return False
    hexpart = value[len(DIGEST_PREFIX):]
    if len(hexpart) != DIGEST_HEX_LEN:
        return False
    return all(c in "0123456789abcdef" for c in hexpart)


def require_digest(value: Any, field: str = "digest") -> str:
    if not is_digest(value):
        raise CanonicalisationError(
            f"{field} must be a '{DIGEST_PREFIX}<64 lowercase hex>' string, got {value!r}")
    return value


def is_git_object_id(value: Any) -> bool:
    """True for `git:<40 or 64 hex>` — a git object id as a content identifier.

    Git object ids are content identifiers produced by a different algorithm
    (sha-1, or sha-256 in a sha256 repository). They are recorded in their own
    namespace rather than dressed up as one of ours: a 40-hex sha-1 padded into a
    `sha256:` field would be a lie about which algorithm identified the content.
    """
    if not isinstance(value, str) or not value.startswith(GIT_PREFIX):
        return False
    hexpart = value[len(GIT_PREFIX):]
    if len(hexpart) not in (40, 64):
        return False
    return all(c in "0123456789abcdef" for c in hexpart)


def is_content_id(value: Any) -> bool:
    """True for any content identifier this package understands."""
    return is_digest(value) or is_git_object_id(value)


def require_content_id(value: Any, field: str = "digest") -> str:
    if not is_content_id(value):
        raise CanonicalisationError(
            f"{field} must be '{DIGEST_PREFIX}<64 hex>' or '{GIT_PREFIX}<40|64 hex>', "
            f"got {value!r}")
    return value


def _raw(digest: str) -> bytes:
    return bytes.fromhex(require_digest(digest)[len(DIGEST_PREFIX):])


def merkle_root(leaf_digests: Sequence[str], ordered: bool = False) -> str:
    """Fold leaf digests into one root.

    `ordered=False` (the default) sorts the leaves first, so a set of items — the
    8,214 refunds in a payment batch — digests the same however the producer
    happened to order them. `ordered=True` keeps producer order, for subjects
    where sequence is part of the meaning (a message set, a migration series).
    """
    if not leaf_digests:
        raise CanonicalisationError(
            "cannot digest an empty item set — an authorisation over nothing is "
            "a malformed subject, not an empty one")

    leaves = [_raw(d) for d in leaf_digests]
    if not ordered:
        leaves = sorted(leaves)

    level: List[bytes] = [hashlib.sha256(_LEAF_TAG + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hashlib.sha256(_NODE_TAG + level[i] + level[i + 1]).digest())
            else:
                # Promote an odd node unchanged. Duplicating it (the classic
                # implementation) lets two different leaf sets collide.
                nxt.append(level[i])
        level = nxt

    count = str(len(leaves)).encode("ascii")
    return digest_bytes(_ROOT_TAG + b"|" + count + b"|" + level[0])


def digest_items(items: Iterable[Any], ordered: bool = False) -> str:
    """Digest a collection of JSON-able items via their Merkle root."""
    return merkle_root([digest_object(item) for item in items], ordered=ordered)


def short_id(prefix: str, digest: str, length: int = 16) -> str:
    """`subj_9f2c4a1b8e3d5c70` — a readable handle derived from a digest.

    The full digest stays in the record; this is what appears in a packet a human
    reads, and it is derived rather than random so the same content always yields
    the same handle.
    """
    return f"{prefix}_{require_digest(digest)[len(DIGEST_PREFIX):][:length]}"
