"""The diversity-strict preset: critical claims need independent, diverse support.

`diversity-strict@1` is a built-in resolution policy, named on the command line
like a methodology. Under it a required claim must be ESTABLISHED — a bound
proof, or passing checks from at least two independent groups — where a shared
provider correlates as well as a shared model family, session, agent, reviewer
or toolchain; and every required claim must be checked by someone other than
its author, with an author nobody stated holding the case.

What these tests pin: the preset's fields, how it is named, that two model
families from one provider are one group under it and two under the default,
that a claim with diverse support and an independent checker is established
under it, and that the CLI takes the name where it takes a file.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.correlation import ProvenanceDimension
from release_gate.assurance.methodologies import default_registry
from release_gate.assurance.resolution import (
    BUILTIN_RESOLUTION_POLICIES,
    DEFAULT_RESOLUTION_POLICY,
    DIVERSITY_STRICT_POLICY,
    AdmissionEffect,
    ResolutionError,
    ResolutionPolicy,
    ResolutionStatus,
    resolution_policy_named,
)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "examples" / "agents" / "02-release-promoted.jsonl"
GENERAL = default_registry().resolve("general-agent-action@1.0.0")
DIGEST = "sha256:9c2f1e4a7b83d05fe6c1a9b4d72e8f3016a5c9d84b2e7f1a3c6d0985b7e4f2a1"


# ── the preset ───────────────────────────────────────────────────────────────

def test_the_preset_says_what_it_requires():
    policy = DIVERSITY_STRICT_POLICY
    assert policy.ref == "rg-diversity-strict@1"
    assert policy.admission_level is ResolutionStatus.ESTABLISHED
    assert policy.author_independence is AdmissionEffect.HOLD
    assert ProvenanceDimension.PROVIDER in policy.independence.correlate_on
    assert set(policy.independence.correlate_on) == set(ProvenanceDimension)
    assert policy.independence.min_independent_groups == 2
    # Nothing in it lets a model's reading count, and nothing is weaker than the
    # default anywhere.
    assert policy.semantic_support is DEFAULT_RESOLUTION_POLICY.semantic_support
    assert policy.counterexample_effect is AdmissionEffect.BLOCK
    assert policy.counterexample_exceptions is False
    assert policy.non_establishing_methods == DEFAULT_RESOLUTION_POLICY.non_establishing_methods


@pytest.mark.parametrize("name", ["diversity-strict@1", "diversity-strict",
                                  "rg-diversity-strict@1"])
def test_it_is_named_like_a_methodology(name):
    assert resolution_policy_named(name) is DIVERSITY_STRICT_POLICY


def test_the_default_is_named_too():
    assert resolution_policy_named("rg-resolution@1") is DEFAULT_RESOLUTION_POLICY
    assert set(BUILTIN_RESOLUTION_POLICIES) == {"rg-resolution@1", "diversity-strict@1"}


def test_an_unknown_name_is_refused_and_says_what_exists():
    with pytest.raises(ResolutionError, match="diversity-strict@1"):
        resolution_policy_named("lenient@1")


def test_it_round_trips_and_digests_as_itself():
    assert ResolutionPolicy.from_dict(DIVERSITY_STRICT_POLICY.to_dict()) == \
        DIVERSITY_STRICT_POLICY
    assert DIVERSITY_STRICT_POLICY.digest() != DEFAULT_RESOLUTION_POLICY.digest()


# ── what it does to a case ───────────────────────────────────────────────────

def _eval(producer, provider, family, session):
    return {"schema": "release-gate.eval/1", "producer": {"id": producer},
            "provenance": {"provider": provider, "model_family": family,
                           "session": session},
            "cases": [{"id": f"{producer}-case", "outcome": "passed", "claim_id": "C-1",
                       "state": {"applies_to": DIGEST}}]}


def _envelope(tmp_path, *evals, author=None):
    rows = [{"record_type": "artifact", "logical_id": "src/billing/rounding.py",
             "artifact_kind": "SOURCE_PATCH", "digest_method": "SHA256_CONTENT",
             "digest": DIGEST},
            {"record_type": "claim", "claim_id": "C-1", "is_root": True,
             "proposition": "the rounding fix is correct",
             "producer": {"producer_id": "owners", "kind": "human"}}]
    rows += [{"record_type": "producer_export", "source": f"eval-{i}.json", "document": doc}
             for i, doc in enumerate(evals)]
    if author:
        rows.append({"record_type": "authorship", "role": "implementation",
                     "provenance": author, "claims": ["C-1"]})
    path = tmp_path / "release.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


def _status(path, policy):
    outcome = assure(str(path), methodology=GENERAL, resolution_policy=policy)
    return outcome, outcome.analysis.resolution.of("C-1").status


def test_two_families_from_one_provider_are_one_group_under_it(tmp_path):
    path = _envelope(tmp_path, _eval("evals-a", "acme-ai", "family-a", "s1"),
                     _eval("evals-b", "acme-ai", "family-b", "s2"))
    _, default_status = _status(path, DEFAULT_RESOLUTION_POLICY)
    strict, strict_status = _status(path, DIVERSITY_STRICT_POLICY)
    assert default_status is ResolutionStatus.ESTABLISHED
    assert strict_status is not ResolutionStatus.ESTABLISHED
    assert "RG-CRIT-006" in {f.rule_id for f in strict.analysis.findings}
    assert strict.decision.value != "PROMOTE"


def test_diverse_support_checked_by_someone_else_is_established(tmp_path):
    path = _envelope(tmp_path, _eval("evals-a", "acme-ai", "family-a", "s1"),
                     _eval("evals-b", "globex-ai", "family-b", "s2"),
                     author={"agent": "builder-7", "model_family": "family-c",
                             "provider": "initech-ai", "session": "s0"})
    outcome, status = _status(path, DIVERSITY_STRICT_POLICY)
    assert status is ResolutionStatus.ESTABLISHED
    held = {f.rule_id for f in outcome.analysis.findings if f.effect.value != "ADVISORY"}
    assert not held & {"RG-CRIT-006", "RG-INDEP-007", "RG-INDEP-008"}


def test_an_author_nobody_stated_holds_a_required_claim(tmp_path):
    path = _envelope(tmp_path, _eval("evals-a", "acme-ai", "family-a", "s1"),
                     _eval("evals-b", "globex-ai", "family-b", "s2"))
    outcome, status = _status(path, DIVERSITY_STRICT_POLICY)
    assert status is ResolutionStatus.ESTABLISHED
    rg008 = [f for f in outcome.analysis.findings if f.rule_id == "RG-INDEP-008"]
    assert rg008 and rg008[0].effect.value == "HOLD"


def test_checks_that_all_share_the_author_s_provenance_hold_under_it(tmp_path):
    author = {"agent": "builder-7", "model_family": "family-a", "provider": "acme-ai",
              "session": "s1"}
    path = _envelope(tmp_path, _eval("evals-a", "acme-ai", "family-a", "s1"),
                     _eval("evals-b", "acme-ai", "family-a", "s9"), author=author)

    def rg007(policy):
        outcome, _ = _status(path, policy)
        found = [f for f in outcome.analysis.findings if f.rule_id == "RG-INDEP-007"]
        return outcome, found[0].effect.value if found else None
    strict, effect = rg007(DIVERSITY_STRICT_POLICY)
    assert effect == "HOLD"
    assert strict.decision.value != "PROMOTE"
    _, default_effect = rg007(DEFAULT_RESOLUTION_POLICY)
    assert default_effect == "ADVISORY"


# ── from the command line ────────────────────────────────────────────────────

def _cli(*args):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "release_gate.cli", *args],
                          capture_output=True, text=True, env=env, timeout=300)


def test_the_cli_takes_the_name_where_it_takes_a_file():
    run = _cli("assure", str(RELEASE), "--methodology", "general-agent-action@1.0.0",
               "--resolution-policy", "diversity-strict@1", "--json")
    body = json.loads(run.stdout)
    assert body["decision"] == "HOLD"
    assert run.returncode == 10
    assert "rg-diversity-strict@1" in run.stdout


def test_the_cli_refuses_a_name_it_does_not_know():
    run = _cli("assure", str(RELEASE), "--resolution-policy", "lenient@1")
    assert run.returncode == 1
    assert "diversity-strict@1" in run.stdout
