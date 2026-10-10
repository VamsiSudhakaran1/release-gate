"""Sign and verify DSSE envelopes — the host boundary for authenticated evidence.

The assurance layer imports no cryptography (`assurance/signed.py`). This module
is where a signature is actually checked, against the keys an organisation
trusts, and it hands the assurance layer a `SignatureVerdict` and nothing else.

A trust store names each key, what it may speak for, and who decided to trust it:

    {"schema": "release-gate.trusted-keys/1",
     "keys": [{"keyid": "acme-evals-ci",
               "public_key": "-----BEGIN PUBLIC KEY-----\\n…",
               "producers": ["acme-evals"],
               "decided_by": "security@acme.example"}]}

`producers` is required and is the point: a key the eval harness signs with is
trusted for the eval harness, so it cannot make a person's approval, another
team's red team or release-gate's own output read as authenticated.

Ed25519, ECDSA (P-256 with SHA-256, P-384 with SHA-384, DER signatures, as
cosign writes them) and RSA-PSS with SHA-256 are read. A signature is over
DSSE's pre-authentication encoding of the payload type and payload.

What each verdict means:

    VALID         a signature by a trusted key verifies
    INVALID       a signature naming a trusted key does not verify — or one
                  trusted signature verifies and another does not, which is
                  not an envelope anyone should read as clean
    UNVERIFIABLE  no signature names a key in the trust store
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from release_gate.assurance.attestation import SignatureState
from release_gate.assurance.signed import (
    DSSE_PAYLOAD_TYPE,
    SignatureVerdict,
    envelope_digest,
    envelope_keyids,
    is_signed_envelope,
    pae,
    payload_bytes,
)

__all__ = [
    "TRUSTED_KEYS_SCHEMA",
    "TrustedKey",
    "TrustedKeys",
    "TrustedKeysError",
    "VERIFIED_BY",
    "generate_keypair",
    "load_trusted_keys",
    "sign_document",
    "verify_envelope",
]

TRUSTED_KEYS_SCHEMA = "release-gate.trusted-keys/1"
#: Who checked a signature, as every verdict this module returns names it.
VERIFIED_BY = "release-gate/crypto (signature checked in this run)"


class TrustedKeysError(ValueError):
    """A trust store or key that cannot be used as stated."""


PublicKey = Union[ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey, rsa.RSAPublicKey]


@dataclass(frozen=True)
class TrustedKey:
    keyid: str
    public_key: Any
    producers: Tuple[str, ...]
    decided_by: str
    note: str = ""

    @property
    def algorithm(self) -> str:
        return _algorithm(self.public_key)


@dataclass(frozen=True)
class TrustedKeys:
    keys: Mapping[str, TrustedKey]

    def get(self, keyid: str) -> Optional[TrustedKey]:
        return self.keys.get(keyid)


def _algorithm(key: Any) -> str:
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "ed25519"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return f"ecdsa-{key.curve.name}"
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "rsa-pss-sha256"
    raise TrustedKeysError(f"a {type(key).__name__} is not a key type release-gate reads; "
                           "use Ed25519, ECDSA P-256/P-384 or RSA")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def load_trusted_keys(source: Union[str, Path, Mapping[str, Any]]) -> TrustedKeys:
    """Read a trust store. Every key must say what it speaks for and who trusts it."""
    if isinstance(source, Mapping):
        data: Any = source
    else:
        try:
            data = json.loads(Path(source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TrustedKeysError(f"{source}: not a readable trust store: {exc}") from exc
    if not isinstance(data, Mapping) or not isinstance(data.get("keys"), list) \
            or not data["keys"]:
        raise TrustedKeysError("a trust store is an object with a non-empty `keys` list")
    schema = data.get("schema")
    if schema is not None and schema != TRUSTED_KEYS_SCHEMA:
        raise TrustedKeysError(f"schema {schema!r} is not {TRUSTED_KEYS_SCHEMA}")
    keys: Dict[str, TrustedKey] = {}
    for index, entry in enumerate(data["keys"]):
        where = f"key {index + 1}"
        if not isinstance(entry, Mapping):
            raise TrustedKeysError(f"{where} is not an object")
        keyid = _text(entry.get("keyid"))
        if not keyid:
            raise TrustedKeysError(f"{where} names no keyid")
        where = f"key {keyid!r}"
        pem = _text(entry.get("public_key"))
        if not pem:
            raise TrustedKeysError(f"{where} carries no public_key")
        producers = entry.get("producers")
        if not isinstance(producers, list) or not [p for p in producers if _text(p)]:
            raise TrustedKeysError(
                f"{where} names no producers: a key is trusted to speak for named "
                "producers, and one trusted for everything would authenticate anything")
        if any(_text(p) == "*" for p in producers):
            raise TrustedKeysError(
                f"{where} is trusted for `*`, which is every producer: name the "
                "producers it speaks for, or a family such as `release-gate/*`")
        decided_by = _text(entry.get("decided_by"))
        if not decided_by:
            raise TrustedKeysError(
                f"{where} names nobody in decided_by: trust that cannot be traced to "
                "someone's decision is an assumption")
        if keyid in keys:
            raise TrustedKeysError(f"{where} is listed twice")
        try:
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise TrustedKeysError(f"{where}: public_key is not a PEM public key: "
                                   f"{exc}") from exc
        _algorithm(public_key)
        keys[keyid] = TrustedKey(keyid=keyid, public_key=public_key,
                                 producers=tuple(_text(p) for p in producers if _text(p)),
                                 decided_by=decided_by, note=_text(entry.get("note")))
    return TrustedKeys(keys=keys)


def _verifies(key: Any, signature: bytes, message: bytes) -> bool:
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            digest = hashes.SHA384() if key.curve.key_size >= 384 else hashes.SHA256()
            key.verify(signature, message, ec.ECDSA(digest))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                   salt_length=padding.PSS.AUTO),
                       hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    return True


def verify_envelope(envelope: Mapping[str, Any], trusted: TrustedKeys) -> SignatureVerdict:
    """Check every signature an envelope carries against the trust store."""
    digest = envelope_digest(envelope) if isinstance(envelope, Mapping) else ""
    keyids = envelope_keyids(envelope) if isinstance(envelope, Mapping) else ()

    def verdict(state: SignatureState, detail: str,
                key: Optional[TrustedKey] = None) -> SignatureVerdict:
        return SignatureVerdict(
            envelope_digest=digest, state=state, detail=detail, keyids=keyids,
            key_id=key.keyid if key else "", algorithm=key.algorithm if key else "",
            producers=key.producers if key else (),
            decided_by=key.decided_by if key else "",
            verified_by=VERIFIED_BY)

    if not is_signed_envelope(envelope):
        return verdict(SignatureState.INVALID, "not a signed envelope")
    try:
        message = pae(str(envelope["payloadType"]), payload_bytes(envelope))
    except ValueError as exc:
        return verdict(SignatureState.INVALID, f"the payload cannot be read: {exc}")
    valid: Optional[TrustedKey] = None
    for entry in envelope["signatures"]:
        key = trusted.get(str(entry.get("keyid") or ""))
        if key is None:
            continue
        try:
            raw = base64.b64decode(str(entry.get("sig") or ""), validate=True)
        except ValueError:
            return verdict(SignatureState.INVALID,
                           f"the signature for key {key.keyid!r} is not base64", key)
        if not _verifies(key.public_key, raw, message):
            return verdict(SignatureState.INVALID,
                           f"the signature for trusted key {key.keyid!r} does not verify",
                           key)
        valid = valid or key
    if valid is None:
        return verdict(SignatureState.UNVERIFIABLE,
                       "no signature names a key in the trust store"
                       + (f" (signed by {', '.join(k or '?' for k in keyids)})"
                          if keyids else ""))
    return verdict(SignatureState.VALID,
                   f"signed by trusted key {valid.keyid!r} ({valid.algorithm})", valid)


def _sign(private_key: Any, message: bytes) -> bytes:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(message)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        digest = hashes.SHA384() if private_key.curve.key_size >= 384 else hashes.SHA256()
        return private_key.sign(message, ec.ECDSA(digest))
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(message,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH),
                                hashes.SHA256())
    raise TrustedKeysError(f"a {type(private_key).__name__} cannot sign here")


def sign_document(document: bytes, *, private_key_pem: bytes, keyid: str,
                  payload_type: str = DSSE_PAYLOAD_TYPE) -> Dict[str, Any]:
    """A DSSE envelope over `document`'s exact bytes, signed with one key."""
    if not _text(keyid):
        raise TrustedKeysError("a signature names its keyid")
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise TrustedKeysError(f"not an unencrypted PEM private key: {exc}") from exc
    signature = _sign(private_key, pae(payload_type, document))
    return {"payloadType": payload_type,
            "payload": base64.b64encode(document).decode("ascii"),
            "signatures": [{"keyid": keyid.strip(),
                            "sig": base64.b64encode(signature).decode("ascii")}]}


def generate_keypair(kind: str = "ed25519") -> Tuple[bytes, bytes]:
    """(private PEM, public PEM). The private key is unencrypted: keep it in a secret store."""
    if kind == "ed25519":
        private_key: Any = ed25519.Ed25519PrivateKey.generate()
    elif kind == "ecdsa-p256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif kind == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    else:
        raise TrustedKeysError(f"{kind!r} is not ed25519, ecdsa-p256 or rsa")
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem
