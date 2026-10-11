"""The Admission Report says what was signed, and what each counterexample found.

Two things a reviewer needs from the report and could only get from `--json`
or the sealed case before:

* **Signed inputs.** Every signed envelope the run met, with what the check
  found and what that did: verified and authenticating N records, signed but
  read as unsigned (no trust store, or no key in it signed this), or not read at
  all (its signature does not verify). Each evidence source also says how many
  of its records a trusted key authenticated, and which key.
* **What each counterexample found**, in the producer's own words: a drill that
  halted after its bound, an attack that got through, an incident. The standing
  says what the counterexample does to this release; this says what it is.

Neither changes a decision: the report reads the outcome and computes nothing.
A report with no signed inputs serialises exactly as before.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from release_gate.assurance.admission_report import (
    build_admission_report,
    render_admission_report,
)
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.signed import collect_signed_envelopes
from release_gate.assurance.zero_config import assure
from release_gate.crypto.envelope import (
    generate_keypair,
    load_trusted_keys,
    sign_document,
    verify_envelope,
)

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "examples" / "evidence"
RELEASE = ROOT / "examples" / "agents" / "02-release-promoted.jsonl"
GENERAL = default_registry().resolve("general-agent-action@1.0.0")


@pytest.fixture(scope="module")
def keys():
    private, public = generate_keypair()
    store = load_trusted_keys({"keys": [{
        "keyid": "acme-ci", "public_key": public.decode(), "producers": ["acme-evals"],
        "decided_by": "security@acme.example"}]})
    return {"private": private, "store": store}


def _signed_eval(keys, producer="acme-evals"):
    doc = json.loads((EVIDENCE / "eval.json").read_text())
    doc["producer"]["id"] = producer
    return sign_document(json.dumps(doc).encode(), private_key_pem=keys["private"],
                         keyid="acme-ci")


def _report(tmp_path, envelope, store=None):
    path = tmp_path / "eval.signed.json"
    path.write_text(json.dumps(envelope))
    verdicts = None
    if store is not None:
        verdicts = {}
        for found in collect_signed_envelopes(path):
            verdict = verify_envelope(found, store)
            verdicts[verdict.envelope_digest] = verdict
    outcome = assure(str(path), signatures=verdicts)
    report = build_admission_report(outcome)
    return report, report.to_dict(), render_admission_report(report)


# ── signed inputs ────────────────────────────────────────────────────────────

def test_a_verified_signature_is_listed_with_what_it_authenticated(tmp_path, keys):
    report, data, text = _report(tmp_path, _signed_eval(keys), keys["store"])
    [entry] = data["signed_inputs"]
    assert entry["verdict"] == "VALID" and entry["read"] is True
    assert entry["key_id"] == "acme-ci"
    assert entry["trusted_by"] == "security@acme.example"
    assert entry["trusted_for"] == ["acme-evals"]
    assert entry["authenticated_records"] == 4
    assert entry["not_trusted_for"] == []
    assert "SIGNED INPUTS (1)" in text
    assert "4 record(s) authenticated by key acme-ci" in text


def test_each_source_says_how_many_of_its_records_a_key_authenticated(tmp_path, keys):
    _, data, text = _report(tmp_path, _signed_eval(keys), keys["store"])
    [source] = [s for s in data["evidence_sources"]["imported"]
                if s["producer"].startswith("acme-evals")]
    assert source["authenticated"] == source["records"] == 4
    assert any("acme-ci" in signer for signer in source["signed_by"])
    assert "signed: 4 of 4 record(s) authenticated" in text


def test_a_signed_file_read_without_a_trust_store_says_so(tmp_path, keys):
    _, data, text = _report(tmp_path, _signed_eval(keys))
    [entry] = data["signed_inputs"]
    assert entry["verdict"] == "NOT_VERIFIED" and entry["read"] is True
    assert entry["authenticated_records"] == 0
    assert "read as unsigned: no trust store was given" in text
    assert all("authenticated" not in s for s in data["evidence_sources"]["imported"])


def test_a_signature_that_does_not_verify_is_listed_as_not_read(tmp_path, keys):
    envelope = _signed_eval(keys)
    forged = copy.deepcopy(envelope)
    sig = forged["signatures"][0]["sig"]
    forged["signatures"][0]["sig"] = ("B" if sig[0] == "A" else "A") + sig[1:]
    _, data, text = _report(tmp_path, forged, keys["store"])
    [entry] = data["signed_inputs"]
    assert entry["verdict"] == "INVALID" and entry["read"] is False
    assert "not read: its signature does not verify" in text


def test_a_key_trusted_for_another_producer_is_named_as_such(tmp_path, keys):
    _, data, text = _report(tmp_path, _signed_eval(keys, producer="globex-evals"),
                            keys["store"])
    [entry] = data["signed_inputs"]
    assert entry["verdict"] == "VALID"
    assert entry["authenticated_records"] == 0
    assert entry["not_trusted_for"] == ["globex-evals"]
    assert "not trusted for globex-evals" in text


def test_the_section_sits_just_before_the_evidence_sources(tmp_path, keys):
    _, _, text = _report(tmp_path, _signed_eval(keys), keys["store"])
    assert text.index("INDEPENDENCE CONCERNS") < text.index("SIGNED INPUTS") \
        < text.index("EVIDENCE SOURCES")


def test_a_report_with_nothing_signed_serialises_as_before():
    data = build_admission_report(assure(str(RELEASE), methodology=GENERAL)).to_dict()
    text = render_admission_report(build_admission_report(
        assure(str(RELEASE), methodology=GENERAL)))
    assert "signed_inputs" not in data
    assert "SIGNED INPUTS" not in text
    for group in data["evidence_sources"].values():
        assert all("authenticated" not in s and "signed_by" not in s for s in group)


# ── what each counterexample found ───────────────────────────────────────────

def _counterexamples(path, **kwargs):
    report = build_admission_report(assure(str(path), **kwargs))
    return report.to_dict()["counterexamples"], render_admission_report(report)


def test_a_failed_drill_says_how_it_failed():
    found, text = _counterexamples(EVIDENCE / "containment.json")
    words = sorted(c["found"] for c in found)
    assert any("after its 30-second bound" in w for w in words)
    assert any("2 action(s) the system had started ran after the halt" in w for w in words)
    assert "found: spend circuit breaker at 500 USD per hour halted the system after " \
           "41 seconds" in text


def test_an_attack_that_got_through_says_what_it_did():
    found, text = _counterexamples(EVIDENCE / "red-team.json")
    assert [c["found"] for c in found] == [
        "a 500.00 transfer executed with no authorization step"]
    assert "found: a 500.00 transfer executed with no authorization step" in text


def test_an_incident_says_which_failure_it_is():
    found, _ = _counterexamples(EVIDENCE / "incident.jsonl", methodology=GENERAL)
    [incident] = found
    assert incident["found"].startswith("incident INC-2291: a refund was paid twice")
    assert "disclosure disclosed" in incident["found"]


def test_a_declared_counterexample_keeps_its_own_words(tmp_path):
    rows = [{"record_type": "claim", "claim_id": "c", "is_root": True,
             "proposition": "no transfer without authorization",
             "producer": {"producer_id": "owners", "kind": "human"}},
            {"record_type": "counterexample", "target_claim": "c", "result": "FOUND",
             "producer_id": "red-team", "method": "SIMULATION",
             "detail": "an unauthorized transfer of 50,000 succeeded; reproducible"}]
    path = tmp_path / "cex.json"
    path.write_text(json.dumps(rows))
    found, _ = _counterexamples(path)
    assert [c["found"] for c in found] == [
        "an unauthorized transfer of 50,000 succeeded; reproducible"]


def test_a_counterexample_that_states_nothing_finds_nothing_it_did_not_say(tmp_path):
    rows = [{"record_type": "claim", "claim_id": "c", "is_root": True,
             "proposition": "p", "producer": {"producer_id": "o", "kind": "human"}},
            {"record_type": "counterexample", "target_claim": "c", "result": "FOUND",
             "producer_id": "red-team", "method": "SIMULATION"}]
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(rows))
    found, text = _counterexamples(path)
    assert [c["found"] for c in found] == [""]
    assert "found:" not in text


def test_words_cut_for_length_say_they_were_cut(tmp_path):
    rows = [{"record_type": "claim", "claim_id": "c", "is_root": True,
             "proposition": "p", "producer": {"producer_id": "o", "kind": "human"}},
            {"record_type": "counterexample", "target_claim": "c", "result": "FOUND",
             "producer_id": "red-team", "method": "SIMULATION", "detail": "x" * 1000}]
    path = tmp_path / "long.json"
    path.write_text(json.dumps(rows))
    [entry], _ = _counterexamples(path)
    assert entry["found"] == "x" * 400 + " … (cut; 1000 characters in all)"
