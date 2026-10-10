"""Authenticated evidence: signed envelopes, verified against keys an organisation trusts.

Before this, every producer identity a document carried was asserted: RG-PROV-001
said so on every case, and nothing could change it short of the Python API. A
document can now arrive inside a DSSE envelope (the signing format in-toto and
Sigstore use), and a run given `--trusted-keys` verifies it at the host boundary.
The pure core never verifies anything; it is handed each verdict and applies it.

What these tests pin:

* a valid signature from a key trusted for the record's producer authenticates the
  record, and nothing else does — not a field in the file, not a key trusted for a
  different producer;
* a signature that does not verify means the envelope's contents are not read at
  all, and the case holds — a tampered payload is never weighed as what it says;
* a key nobody trusts leaves the document read exactly as an unsigned one is;
* authentication sits outside the evidence's identity, so signing a document does
  not change what any claim cites;
* a policy can require authenticated support for required claims (RG-PROV-004).
"""
from __future__ import annotations

import base64
import copy
import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.evidence import EvidenceRecord, EvidenceType, Producer
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.resolution import DEFAULT_RESOLUTION_POLICY
from release_gate.assurance.signed import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_PAYLOAD_TYPE,
    collect_signed_envelopes,
    envelope_digest,
    inner_document,
    is_signed_envelope,
)
from release_gate.assurance.attestation import SignatureState
from release_gate.assurance.zero_config import assure
from release_gate.crypto.envelope import (
    TrustedKeysError,
    generate_keypair,
    load_trusted_keys,
    sign_document,
    verify_envelope,
)

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "examples" / "agents" / "02-release-promoted.jsonl"
GENERAL = default_registry().resolve("general-agent-action@1.0.0")
DIGEST = "sha256:9c2f1e4a7b83d05fe6c1a9b4d72e8f3016a5c9d84b2e7f1a3c6d0985b7e4f2a1"


def _eval_doc(producer="acme-evals", outcome="passed", claim="C-1"):
    return {"schema": "release-gate.eval/1",
            "producer": {"id": producer, "version": "2.0"},
            "provenance": {"provider": "acme", "session": "ev-77"},
            "cases": [{"id": "round-half-even", "outcome": outcome, "claim_id": claim,
                       "state": {"applies_to": DIGEST}}]}


def _bytes(doc) -> bytes:
    return json.dumps(doc, sort_keys=True).encode("utf-8")


@pytest.fixture(scope="module")
def keys():
    """Two Ed25519 keys: one the organisation trusts for acme-evals, one it does not."""
    trusted_private, trusted_public = generate_keypair()
    stranger_private, _ = generate_keypair()
    store = load_trusted_keys({
        "schema": "release-gate.trusted-keys/1",
        "keys": [{"keyid": "acme-evals-ci", "public_key": trusted_public.decode(),
                  "producers": ["acme-evals"], "decided_by": "security@acme.example"}]})
    return {"private": trusted_private, "public": trusted_public,
            "stranger": stranger_private, "store": store}


def _signed(doc, private, keyid="acme-evals-ci", payload_type=DSSE_PAYLOAD_TYPE):
    return sign_document(_bytes(doc), private_key_pem=private, keyid=keyid,
                         payload_type=payload_type)


def _run(tmp_path, *docs, store=None, name="ev", **kwargs):
    paths = []
    for index, doc in enumerate(docs):
        path = tmp_path / f"{name}-{index}.json"
        path.write_text(json.dumps(doc))
        paths.append(path)
    verdicts = {}
    if store is not None:
        for found in collect_signed_envelopes(RELEASE, paths):
            verdict = verify_envelope(found, store)
            verdicts[verdict.envelope_digest] = verdict
    return assure(str(RELEASE), methodology=GENERAL, evidence=[str(p) for p in paths],
                  signatures=verdicts, **kwargs)


def _records(outcome, producer="acme-evals"):
    return [r for r in outcome.case.collection("evidence").materialised
            if getattr(getattr(r, "producer", None), "producer_id", None) == producer]


def _fired(outcome):
    return sorted({f.rule_id for f in outcome.analysis.findings
                   if f.effect.value != "ADVISORY"})


# ── the envelope ─────────────────────────────────────────────────────────────

def test_a_signed_envelope_is_recognised_by_shape_alone(keys):
    envelope = _signed(_eval_doc(), keys["private"])
    assert is_signed_envelope(envelope)
    assert set(envelope) == {"payloadType", "payload", "signatures"}
    assert not is_signed_envelope(_eval_doc())
    assert not is_signed_envelope({"payloadType": "x", "payload": "e30=", "signatures": []})
    document, _ = inner_document(envelope)
    assert document == _eval_doc()


def test_the_digest_names_the_envelope_and_nothing_else(keys):
    envelope = _signed(_eval_doc(), keys["private"])
    noisy = dict(envelope, comment="added later")
    assert envelope_digest(envelope) == envelope_digest(noisy)
    changed = dict(envelope, payload=base64.b64encode(_bytes(_eval_doc(outcome="failed")))
                   .decode())
    assert envelope_digest(changed) != envelope_digest(envelope)


@pytest.mark.parametrize("kind", ["ed25519", "ecdsa-p256", "rsa"])
def test_each_key_type_signs_and_verifies(kind):
    private, public = generate_keypair(kind)
    store = load_trusted_keys({"keys": [{"keyid": "k", "public_key": public.decode(),
                                         "producers": ["acme-evals"],
                                         "decided_by": "security@acme.example"}]})
    verdict = verify_envelope(_signed(_eval_doc(), private, keyid="k"), store)
    assert verdict.state is SignatureState.VALID
    assert verdict.key_id == "k" and verdict.decided_by == "security@acme.example"


def test_a_changed_payload_does_not_verify(keys):
    envelope = _signed(_eval_doc(), keys["private"])
    envelope["payload"] = base64.b64encode(_bytes(_eval_doc(outcome="failed"))).decode()
    assert verify_envelope(envelope, keys["store"]).state is SignatureState.INVALID


def test_a_key_nobody_trusts_is_unverifiable_not_invalid(keys):
    envelope = _signed(_eval_doc(), keys["stranger"], keyid="someone")
    assert verify_envelope(envelope, keys["store"]).state is SignatureState.UNVERIFIABLE


def test_a_trusted_keyid_with_a_stranger_signature_is_invalid(keys):
    envelope = _signed(_eval_doc(), keys["stranger"], keyid="acme-evals-ci")
    assert verify_envelope(envelope, keys["store"]).state is SignatureState.INVALID


@pytest.mark.parametrize("entry,error", [
    ({"keyid": "k", "producers": ["x"], "decided_by": "s"}, "public_key"),
    ({"keyid": "k", "public_key": "PEM", "decided_by": "s"}, "producers"),
    ({"keyid": "k", "public_key": "PEM", "producers": ["x"]}, "decided_by"),
    ({"public_key": "PEM", "producers": ["x"], "decided_by": "s"}, "keyid"),
])
def test_a_trusted_key_must_say_what_it_speaks_for_and_who_trusts_it(entry, error):
    with pytest.raises(TrustedKeysError, match=error):
        load_trusted_keys({"keys": [entry]})


def test_an_in_toto_statement_is_read_through_its_predicate(keys):
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": "agent", "digest": {"sha256": DIGEST[7:]}}],
                 "predicateType": "https://release-gate.dev/eval/v1",
                 "predicate": _eval_doc()}
    envelope = _signed(statement, keys["private"], payload_type=IN_TOTO_PAYLOAD_TYPE)
    document, note = inner_document(envelope)
    assert document == _eval_doc()
    assert "in-toto" in note and "1 subject" in note


# ── what verification does to a case ─────────────────────────────────────────

def test_a_verified_signature_authenticates_the_records_of_its_producer(tmp_path, keys):
    outcome = _run(tmp_path, _signed(_eval_doc(), keys["private"]), store=keys["store"])
    held = _records(outcome)
    assert held
    for record in held:
        assert record.independence_basis == "authenticated"
        assert record.authentication.state is SignatureState.VALID
        assert record.authentication.key_id == "acme-evals-ci"
        assert "release-gate" in record.authentication.verified_by


def test_signing_changes_no_evidence_id(tmp_path, keys):
    plain = _run(tmp_path, _eval_doc(), name="plain")
    signed = _run(tmp_path, _signed(_eval_doc(), keys["private"]), store=keys["store"],
                  name="plain")
    assert ({r.evidence_id for r in _records(plain)}
            == {r.evidence_id for r in _records(signed)})
    assert plain.case.verdict.decision is signed.case.verdict.decision


def test_without_a_trust_store_a_signed_document_reads_as_unsigned(tmp_path, keys):
    outcome = _run(tmp_path, _signed(_eval_doc(), keys["private"]))
    held = _records(outcome)
    assert held and all(r.independence_basis == "asserted" for r in held)
    assert any("no trusted key verified it" in n for n in outcome.normalisation.notes)


def test_a_key_trusted_for_another_producer_authenticates_nothing(tmp_path, keys):
    doc = _eval_doc(producer="globex-evals")
    outcome = _run(tmp_path, _signed(doc, keys["private"]), store=keys["store"])
    held = _records(outcome, "globex-evals")
    assert held and all(r.independence_basis == "asserted" for r in held)
    assert any("not trusted to speak for" in n for n in outcome.normalisation.notes)


def test_a_signature_that_does_not_verify_is_never_read(tmp_path, keys):
    """The failure would promote if the payload were read: it is not."""
    envelope = _signed(_eval_doc(outcome="failed"), keys["private"])
    forged = copy.deepcopy(envelope)
    forged["payload"] = base64.b64encode(_bytes(_eval_doc(outcome="passed"))).decode()
    outcome = _run(tmp_path, forged, store=keys["store"])
    assert not _records(outcome)
    assert outcome.case.verdict.decision.value == "HOLD"
    assert any("signature does not verify" in reason
               for reason in outcome.normalisation.skipped)


def test_a_file_cannot_claim_its_own_authentication(tmp_path):
    record = EvidenceRecord.from_producer(
        {}, evidence_type=EvidenceType.TEST_RESULT, source="s.json",
        producer=Producer("acme-evals"), applies_to_digest=DIGEST)
    row = record.to_dict()
    row["authentication"] = {"signer": "me", "key_id": "acme-evals-ci", "state": "VALID",
                             "verified_by": "release-gate"}
    assert EvidenceRecord.from_dict(row).authentication is None
    envelope_row = {"record_type": "evidence", "evidence_id": "e9", "kind": "TEST_RESULT",
                    "producer": {"producer_id": "acme-evals", "identity_basis": "in-process"},
                    "authentication": row["authentication"], "applies_to": DIGEST}
    path = tmp_path / "release.jsonl"
    lines = RELEASE.read_text().splitlines() + [json.dumps(envelope_row)]
    path.write_text("\n".join(lines) + "\n")
    outcome = assure(str(path), methodology=GENERAL)
    assert all(r.independence_basis == "asserted" for r in _records(outcome))


def test_authentication_survives_the_round_trip_only_as_a_record(tmp_path, keys):
    outcome = _run(tmp_path, _signed(_eval_doc(), keys["private"]), store=keys["store"])
    record = _records(outcome)[0]
    serialised = record.to_dict()
    assert serialised["authentication"]["state"] == "VALID"
    assert serialised["independence_basis"] == "authenticated"
    assert EvidenceRecord.from_dict(serialised).authentication is None


def test_rg_prov_001_counts_only_what_nobody_authenticated(tmp_path, keys):
    plain = _run(tmp_path, _eval_doc(), name="p")
    signed = _run(tmp_path, _signed(_eval_doc(), keys["private"]), store=keys["store"],
                  name="s")

    def unauthenticated(outcome):
        found = [f for f in outcome.analysis.findings if f.rule_id == "RG-PROV-001"]
        return found[0].observed["unauthenticated"] if found else 0
    assert unauthenticated(signed) == unauthenticated(plain) - len(_records(signed))


# ── which identity bases are authenticated ───────────────────────────────────

@pytest.mark.parametrize("basis,expected", [
    ("unauthenticated", "asserted"),
    ("none", "asserted"),
    ("", "asserted"),
    ("pinned-digest", "asserted"),
    ("ingested-document: attributed to release-gate by the document, not established "
     "here", "asserted"),
    ("declared-document: the file's own account of the system it describes", "asserted"),
    ("self_asserted:declared", "asserted"),
    ("github_actions:not_assessed", "asserted"),
    ("in-process", "authenticated"),
    ("github-oidc", "authenticated"),
    ("github_actions:verified", "authenticated"),
    ("mtls:observed", "authenticated"),
])
def test_a_basis_that_says_a_document_stated_it_is_asserted(basis, expected):
    record = EvidenceRecord.from_producer(
        {}, evidence_type=EvidenceType.TEST_RESULT, source="s.json",
        producer=Producer("p", identity_basis=basis), applies_to_digest=DIGEST)
    assert record.independence_basis == expected


# ── requiring it ─────────────────────────────────────────────────────────────

def _requiring(effect="HOLD"):
    return dataclasses.replace(DEFAULT_RESOLUTION_POLICY,
                               require_authenticated_support=effect)


def test_a_policy_can_require_authenticated_support(tmp_path, keys):
    plain = _run(tmp_path, _eval_doc(), name="p", resolution_policy=_requiring())
    assert "RG-PROV-004" in _fired(plain)
    assert plain.case.verdict.decision.value == "HOLD"
    signed = _run(tmp_path, _signed(_eval_doc(), keys["private"]), store=keys["store"],
                  name="s", resolution_policy=_requiring())
    assert "RG-PROV-004" not in _fired(signed)


def test_requiring_it_can_block(tmp_path):
    outcome = _run(tmp_path, _eval_doc(), resolution_policy=_requiring("BLOCK"))
    assert outcome.case.verdict.decision.value == "BLOCK"


def test_the_requirement_is_absent_unless_declared():
    assert DEFAULT_RESOLUTION_POLICY.require_authenticated_support is None
    assert "require_authenticated_support" not in DEFAULT_RESOLUTION_POLICY.to_dict()
    declared = _requiring().to_dict()
    assert declared["require_authenticated_support"] == "HOLD"
    from release_gate.assurance.resolution import ResolutionPolicy
    assert ResolutionPolicy.from_dict(declared).require_authenticated_support.value == "HOLD"


# ── from the command line ────────────────────────────────────────────────────

def _cli(*args, cwd=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args], cwd=cwd,
                          capture_output=True, text=True, env=env, timeout=300)


def test_keygen_sign_check_and_assure_end_to_end(tmp_path):
    made = _cli("keygen", str(tmp_path / "acme-ci"))
    assert made.returncode == 0, made.stderr
    private, public = tmp_path / "acme-ci.key", tmp_path / "acme-ci.pub"
    assert private.exists() and public.exists()
    store = tmp_path / "trusted-keys.json"
    store.write_text(json.dumps({"schema": "release-gate.trusted-keys/1", "keys": [{
        "keyid": "acme-ci", "public_key": public.read_text(), "producers": ["acme-evals"],
        "decided_by": "security@acme.example"}]}))
    doc = tmp_path / "evals.json"
    doc.write_text(json.dumps(_eval_doc()))
    signed = tmp_path / "evals.signed.json"
    run = _cli("sign", str(doc), "--key", str(private), "--keyid", "acme-ci",
               "--out", str(signed))
    assert run.returncode == 0, run.stderr
    assert _cli("check-signature", str(signed), "--trusted-keys", str(store)).returncode == 0
    tampered = json.loads(signed.read_text())
    tampered["payload"] = base64.b64encode(_bytes(_eval_doc(outcome="failed"))).decode()
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(tampered))
    assert _cli("check-signature", str(bad), "--trusted-keys", str(store)).returncode == 1
    def unauthenticated(*extra):
        run = _cli("assure", str(RELEASE), "--evidence", str(signed), *extra,
                   "--methodology", "general-agent-action@1.0.0", "--json")
        found = [f for f in json.loads(run.stdout)["analysis"]["findings"]
                 if f["rule_id"] == "RG-PROV-001"]
        return found[0]["observed"]["unauthenticated"] if found else 0
    # The signed eval case is one record; trusting its key authenticates exactly it.
    assert unauthenticated("--trusted-keys", str(store)) == unauthenticated() - 1


def test_a_signed_file_can_be_the_primary_input(tmp_path, keys):
    rows = [json.loads(line) for line in RELEASE.read_text().splitlines() if line.strip()]
    envelope = sign_document("\n".join(json.dumps(r) for r in rows).encode(),
                             private_key_pem=keys["private"], keyid="acme-evals-ci")
    primary = tmp_path / "release.signed.json"
    primary.write_text(json.dumps(envelope))
    verdicts = {}
    for found in collect_signed_envelopes(primary, []):
        verdict = verify_envelope(found, keys["store"])
        verdicts[verdict.envelope_digest] = verdict
    signed = assure(str(primary), methodology=GENERAL, signatures=verdicts)
    plain = assure(str(RELEASE), methodology=GENERAL)
    assert signed.case.verdict.decision is plain.case.verdict.decision


def test_a_model_reading_the_record_is_not_shown_its_authentication(tmp_path, keys):
    """Who verified a record is a ruling about it, like `trust`: a semantic
    verifier reads what the producer said, not the custody around it."""
    from release_gate.assurance.semantic_verifier import _what_it_says
    record = _records(_run(tmp_path, _signed(_eval_doc(), keys["private"]),
                           store=keys["store"]))[0]
    said = _what_it_says(record.to_dict())
    assert "authentication" not in said
    assert "acme-evals-ci" not in json.dumps(said)


def test_a_key_cannot_be_trusted_for_every_producer(keys):
    """`release-gate/*` names a family; a bare `*` would name everyone, so one key
    could authenticate a person's approval and release-gate's own output alike."""
    for pattern in ("*", " * "):
        with pytest.raises(TrustedKeysError, match="every producer"):
            load_trusted_keys({"keys": [{"keyid": "k", "public_key": keys["public"].decode(),
                                         "producers": ["acme-evals", pattern],
                                         "decided_by": "security@acme.example"}]})
    family = load_trusted_keys({"keys": [{"keyid": "k", "public_key": keys["public"].decode(),
                                          "producers": ["release-gate/*"],
                                          "decided_by": "security@acme.example"}]})
    assert family.get("k").producers == ("release-gate/*",)
