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
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Sequence

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


def freeze_value(value: Any, path: str = "value") -> Any:
    """Deep-freeze caller data so a digested structure cannot drift out from under it.

    Mapping keys must be strings: canonical JSON sorts keys, and mixed-type keys
    are not orderable — which would make a digest depend on insertion order.
    """
    if isinstance(value, Mapping):
        frozen: Dict[str, Any] = {}
        for key, val in value.items():
            if not isinstance(key, str):
                raise CanonicalisationError(
                    f"{path} keys must be strings (got {type(key).__name__}); "
                    "non-string keys have no canonical ordering")
            frozen[key] = freeze_value(val, f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_value(v, f"{path}[]") for v in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise CanonicalisationError(
        f"{path} may only contain JSON values (str/int/float/bool/None/list/dict), "
        f"got {type(value).__name__}")


def thaw_value(value: Any) -> Any:
    """Inverse of `freeze_value`, for serialisation."""
    if isinstance(value, Mapping):
        return {k: thaw_value(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [thaw_value(v) for v in value]
    return value


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


# ── multiset commitment ─────────────────────────────────────────────────────
#
# A case can hold millions of records, which rules out both "sort them all" and
# "keep them all in memory" for the purpose of digesting. What is needed is a
# fold that is commutative (any ingest order, serial or parallel, gives the same
# answer), associative (partial folds can be merged), and constant-memory.
#
# MSet-Add-Hash does exactly that: sum the record digests as integers modulo
# 2^256, then commit to the sum together with the cardinality. Two honest
# limitations, stated because a commitment whose limits are not stated will be
# mistaken for a Merkle tree:
#
#   * It commits to a MULTISET, not a sequence. Order is not recoverable, and
#     adding the same record twice is a different multiset — at-least-once
#     delivery must be deduplicated by the caller, not by this fold.
#   * It supports no inclusion proofs. Use a Merkle root where a member needs to
#     be proven present (that is what `merkle_root` is for).

MULTISET_ALGO = "rg-mset-1"
_MULTISET_MODULUS = 1 << 256


#: Characters that change what a string *looks like* without changing what it
#: *is*. Bidirectional overrides are the dangerous ones: `ci://real\u202ekcatta`
#: stores one producer and displays another, and the display is what a person
#: reads before authorising.
_DECEPTIVE = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",   # bidi embedding/override
    "\u2066", "\u2067", "\u2068", "\u2069",             # bidi isolates
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",   # zero-width, BOM
    "\u00ad",                                            # soft hyphen
}


def display_text(rendered: str) -> str:
    """A whole rendered report, made safe to show without touching its layout.

    The same substitution as `safe_for_display` for deceptive characters, but
    newlines and tabs are left alone because here they are the report's own
    structure rather than a producer's content. Applied at the render
    chokepoints, so a field added later is covered without anyone remembering to
    wrap it.
    """
    if not any(char in rendered for char in _DECEPTIVE):
        return rendered
    return "".join(f"<U+{ord(c):04X}>" if c in _DECEPTIVE else c for c in rendered)


def safe_for_display(value: Any) -> str:
    """One producer-controlled string, made safe to show a person.

    Applied at **render** time and never at storage time. What a producer sent is
    kept exactly as sent — rewriting a record to make it presentable would be
    release-gate editing evidence, and the digest would no longer commit to what
    arrived. What a human reads is a different artifact with a different job, and
    its job includes not lying about its own direction.

    Deceptive characters become a visible `<U+XXXX>`, so the reader sees that
    something was there rather than the string silently losing it. Control
    characters that would break a line-oriented report are escaped for the same
    reason: a newline inside a producer id can forge a row in a rendered table.
    """
    text = str(value)
    out = []
    for char in text:
        if char in _DECEPTIVE:
            out.append(f"<U+{ord(char):04X}>")
        elif char in ("\n", "\r"):
            out.append("\\n" if char == "\n" else "\\r")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(f"<U+{ord(char):04X}>")
        else:
            out.append(char)
    return "".join(out)


def multiset_add(accumulator: int, digest: str) -> int:
    """Fold one record digest into a multiset accumulator. Order-independent."""
    value = int(content_id_hex(digest)[:DIGEST_HEX_LEN].rjust(DIGEST_HEX_LEN, "0"), 16)
    return (accumulator + value) % _MULTISET_MODULUS


def multiset_merge(left: int, right: int) -> int:
    """Merge two partial accumulators — the associativity that makes parallel ingest safe."""
    return (left + right) % _MULTISET_MODULUS


def multiset_digest(accumulator: int, count: int) -> str:
    """Commit to an accumulator and its cardinality.

    The count is folded in so that a differently-sized multiset cannot present
    the same commitment as a smaller one that happens to sum alike.
    """
    if count < 0:
        raise CanonicalisationError("multiset cardinality cannot be negative")
    payload = f"{MULTISET_ALGO}|{count}|{accumulator:064x}".encode("ascii")
    return digest_bytes(payload)


def content_id_hex(value: str) -> str:
    """The hex body of a content identifier, whichever namespace it is in."""
    require_content_id(value)
    prefix = DIGEST_PREFIX if value.startswith(DIGEST_PREFIX) else GIT_PREFIX
    return value[len(prefix):]


def short_id(prefix: str, digest: str, length: int = 16) -> str:
    """`subj_9f2c4a1b8e3d5c70` — a readable handle derived from a digest.

    The full digest stays in the record; this is what appears in a packet a human
    reads, and it is derived rather than random so the same content always yields
    the same handle.
    """
    return f"{prefix}_{require_digest(digest)[len(DIGEST_PREFIX):][:length]}"
