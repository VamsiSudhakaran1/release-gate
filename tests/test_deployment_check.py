"""The deploy-time check: what runs is what was admitted.

An admission is about one exact candidate state. Between `assure` and the
deploy, anything can change — a rebuilt image, a moved tag, a model alias that
now resolves elsewhere — and an admission that is not checked at deploy time
admits whatever is deployed under its name. `check_deployment` compares the
deployed components with the admitted ones, component by component, and with
the admitted state hash.

What these tests pin:

* MATCH only when every admitted component is stated by the deployment and
  equal, and nothing the admission did not cover is deployed;
* a component that differs is a MISMATCH (exit 1); one the deployment does not
  state, or a revision the admission never covered, is UNVERIFIABLE (exit 10) —
  unknown is not a match;
* an admission that is not a PROMOTE admits nothing, and one whose state hash
  does not match its own components was edited and is refused;
* with a trust store, the admission must be signed by a key trusted for
  `release-gate/admission`, so an edited report cannot pass as admitted.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.attestation import SignatureState
from release_gate.assurance.candidate import CandidateState, ComponentOutcome
from release_gate.assurance.deployment import (
    ADMISSION_PRODUCER,
    DeploymentCheckError,
    DeploymentOutcome,
    check_deployment,
    render_deployment_check,
)
from release_gate.assurance.signed import SignatureVerdict

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "examples" / "agents" / "02-release-promoted.jsonl"
IMAGE = "sha256:" + "a" * 64
OTHER_IMAGE = "sha256:" + "b" * 64
COMMIT = "4f1c2d3e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"
ADMITTED = {"repository": "github.com/acme/billing", "commit": COMMIT, "image": IMAGE,
            "prompt": "sha256:" + "c" * 64}


def _admission(components=ADMITTED, decision="PROMOTE", state_hash=None):
    digest = CandidateState(components=components).digest() if components else "sha256:" + "d" * 64
    return {"record_type": "admission_report", "schema_version": 1,
            "decision": decision, "exit_code": {"PROMOTE": 0, "HOLD": 10, "BLOCK": 1}[decision],
            "case_id": "case-1", "case_digest": "sha256:" + "e" * 64,
            "candidate": {"components": dict(components), "source": "DECLARED_BY_CALLER",
                          "state_hash": state_hash or digest,
                          "state_hash_basis": "digest of the candidate's components"}}


def _verdict(state=SignatureState.VALID, producers=(ADMISSION_PRODUCER,)):
    if state is SignatureState.VALID:
        return SignatureVerdict(envelope_digest="sha256:" + "f" * 64, state=state,
                                key_id="rg-ci", algorithm="ed25519", producers=producers,
                                decided_by="security@acme.example",
                                verified_by="release-gate/crypto", detail="signed")
    return SignatureVerdict(envelope_digest="sha256:" + "f" * 64, state=state,
                            verified_by="release-gate/crypto", detail="does not verify")


def _outcomes(check):
    return {c.component: c.outcome for c in check.comparisons}


# ── comparing components ─────────────────────────────────────────────────────

def test_what_runs_is_what_was_admitted():
    check = check_deployment(_admission(), dict(ADMITTED))
    assert check.outcome is DeploymentOutcome.MATCH
    assert check.exit_code == 0
    assert check.deployed_state_hash == check.admitted_state_hash
    assert set(_outcomes(check).values()) == {ComponentOutcome.MATCH}


def test_a_different_image_is_a_mismatch():
    check = check_deployment(_admission(), {**ADMITTED, "image": OTHER_IMAGE})
    assert check.outcome is DeploymentOutcome.MISMATCH
    assert check.exit_code == 1
    assert _outcomes(check)["image"] is ComponentOutcome.MISMATCH
    assert check.deployed_state_hash != check.admitted_state_hash
    assert any("image" in reason for reason in check.reasons)


def test_an_abbreviated_commit_names_the_same_commit():
    check = check_deployment(_admission(), {**ADMITTED, "commit": COMMIT[:12]})
    assert check.outcome is DeploymentOutcome.MATCH


def test_a_component_the_deployment_does_not_state_is_unverifiable():
    deployed = {k: v for k, v in ADMITTED.items() if k != "prompt"}
    check = check_deployment(_admission(), deployed)
    assert check.outcome is DeploymentOutcome.UNVERIFIABLE
    assert check.exit_code == 10
    assert _outcomes(check)["prompt"] is ComponentOutcome.NOT_BOUND


def test_a_revision_the_admission_never_covered_is_unverifiable():
    check = check_deployment(_admission(), {**ADMITTED, "model": "claude-x-2"})
    assert check.outcome is DeploymentOutcome.UNVERIFIABLE
    assert _outcomes(check)["model"] is ComponentOutcome.NOT_IN_CANDIDATE
    assert any("model" in reason and "did not cover" in reason for reason in check.reasons)


def test_an_identity_the_admission_did_not_name_is_noted_not_held():
    check = check_deployment(_admission(), {**ADMITTED, "environment": "production"})
    assert check.outcome is DeploymentOutcome.MATCH
    assert any("environment" in note for note in check.notes)


def test_a_mismatch_outranks_what_could_not_be_compared():
    deployed = {k: v for k, v in ADMITTED.items() if k != "prompt"}
    deployed["image"] = OTHER_IMAGE
    assert check_deployment(_admission(), deployed).outcome is DeploymentOutcome.MISMATCH


# ── what was admitted ────────────────────────────────────────────────────────

@pytest.mark.parametrize("decision,code", [("HOLD", 10), ("BLOCK", 1)])
def test_an_admission_that_did_not_promote_admits_nothing(decision, code):
    check = check_deployment(_admission(decision=decision), dict(ADMITTED))
    assert check.outcome is DeploymentOutcome.NOT_ADMITTED
    assert check.exit_code == code


def test_an_admission_with_no_candidate_state_cannot_be_checked():
    check = check_deployment(_admission(components={}), dict(ADMITTED))
    assert check.outcome is DeploymentOutcome.UNVERIFIABLE
    assert any("names no candidate" in reason for reason in check.reasons)


def test_an_edited_component_is_caught_by_the_report_s_own_state_hash():
    edited = _admission()
    edited["candidate"]["components"]["image"] = OTHER_IMAGE
    check = check_deployment(edited, {**ADMITTED, "image": OTHER_IMAGE})
    assert check.outcome is DeploymentOutcome.NOT_ADMITTED
    assert check.exit_code == 1
    assert any("does not match its own components" in reason for reason in check.reasons)


def test_a_document_that_is_not_an_admission_report_is_refused():
    with pytest.raises(DeploymentCheckError):
        check_deployment({"decision": "PROMOTE"}, dict(ADMITTED))
    with pytest.raises(DeploymentCheckError):
        check_deployment(_admission(), {"not_a_component": "x"})
    newer = _admission()
    newer["schema_version"] = 99
    with pytest.raises(DeploymentCheckError):
        check_deployment(newer, dict(ADMITTED))


# ── a signed admission ───────────────────────────────────────────────────────

def test_requiring_a_signature_holds_an_unsigned_admission():
    check = check_deployment(_admission(), dict(ADMITTED), require_signed=True)
    assert check.outcome is DeploymentOutcome.UNVERIFIABLE
    assert any("not signed" in reason for reason in check.reasons)


def test_a_signature_trusted_for_admissions_lets_the_comparison_stand():
    check = check_deployment(_admission(), dict(ADMITTED), require_signed=True,
                             admission_signature=_verdict())
    assert check.outcome is DeploymentOutcome.MATCH
    assert check.to_dict()["admission_signature"]["state"] == "VALID"


def test_a_key_trusted_for_something_else_does_not_vouch_for_an_admission():
    check = check_deployment(_admission(), dict(ADMITTED), require_signed=True,
                             admission_signature=_verdict(producers=("acme-evals",)))
    assert check.outcome is DeploymentOutcome.UNVERIFIABLE
    assert any("not trusted to speak for" in reason for reason in check.reasons)


def test_an_admission_whose_signature_does_not_verify_is_refused():
    check = check_deployment(_admission(), dict(ADMITTED), require_signed=True,
                             admission_signature=_verdict(SignatureState.INVALID))
    assert check.outcome is DeploymentOutcome.NOT_ADMITTED
    assert check.exit_code == 1


def test_the_rendering_says_what_was_compared():
    text = render_deployment_check(check_deployment(_admission(),
                                                    {**ADMITTED, "image": OTHER_IMAGE}))
    assert "MISMATCH" in text and "image" in text


def test_the_check_is_reproducible():
    one = check_deployment(_admission(), dict(ADMITTED)).to_dict()
    two = check_deployment(copy.deepcopy(_admission()), dict(ADMITTED)).to_dict()
    assert one == two
    assert one["record_type"] == "deployment_check"


# ── from the command line ────────────────────────────────────────────────────

def _cli(*args):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args],
                          capture_output=True, text=True, env=env, timeout=300)


def test_assure_then_deploy_check_end_to_end(tmp_path):
    admission = tmp_path / "admission.json"
    run = _cli("assure", str(RELEASE), "--methodology", "general-agent-action@1.0.0",
               "--admission-out", str(admission))
    assert run.returncode == 0, run.stdout + run.stderr
    report = json.loads(admission.read_text())
    assert report["decision"] == "PROMOTE"
    # No --candidate: the case's own artifacts stand in, and are what was admitted.
    admitted = report["candidate"]["components"]
    assert "artifact:src/billing/rounding.py" in admitted

    deployed = tmp_path / "deployed.json"
    deployed.write_text(json.dumps(admitted))
    check = _cli("deploy-check", "--admission", str(admission), "--deployed", str(deployed),
                 "--json")
    body = json.loads(check.stdout)
    assert body["outcome"] == "MATCH" and check.returncode == 0
    assert body["deployed_state_hash"] == report["candidate"]["state_hash"]

    moved = tmp_path / "moved.json"
    moved.write_text(json.dumps({**admitted, "artifact:src/billing/rounding.py":
                                 "sha256:" + "0" * 64}))
    mismatch = _cli("deploy-check", "--admission", str(admission), "--deployed", str(moved))
    assert mismatch.returncode == 1
    assert "MISMATCH" in mismatch.stdout and "rounding.py" in mismatch.stdout

    # Sign the admission; a store that trusts the key for admissions accepts it.
    assert _cli("keygen", str(tmp_path / "rg-ci")).returncode == 0
    store = tmp_path / "trusted-keys.json"
    store.write_text(json.dumps({"schema": "release-gate.trusted-keys/1", "keys": [{
        "keyid": "rg-ci", "public_key": (tmp_path / "rg-ci.pub").read_text(),
        "producers": [ADMISSION_PRODUCER], "decided_by": "security@acme.example"}]}))
    signed = tmp_path / "admission.signed.json"
    assert _cli("sign", str(admission), "--key", str(tmp_path / "rg-ci.key"),
                "--keyid", "rg-ci", "--out", str(signed)).returncode == 0
    trusted = _cli("deploy-check", "--admission", str(signed), "--deployed", str(deployed),
                   "--trusted-keys", str(store), "--json")
    assert json.loads(trusted.stdout)["outcome"] == "MATCH" and trusted.returncode == 0
    # Once a trust store is named, the unsigned report is not read as admitted.
    unsigned = _cli("deploy-check", "--admission", str(admission), "--deployed",
                    str(deployed), "--trusted-keys", str(store), "--json")
    assert json.loads(unsigned.stdout)["outcome"] == "UNVERIFIABLE"
    assert unsigned.returncode == 10
    # And an edited decision inside a signed report does not verify.
    envelope = json.loads(signed.read_text())
    edited = dict(report, decision="PROMOTE", basis="edited")
    envelope["payload"] = base64.b64encode(json.dumps(edited).encode()).decode()
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(envelope))
    refused = _cli("deploy-check", "--admission", str(forged), "--deployed", str(deployed),
                   "--trusted-keys", str(store), "--json")
    assert json.loads(refused.stdout)["outcome"] == "NOT_ADMITTED"
    assert refused.returncode == 1
