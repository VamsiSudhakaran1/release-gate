"""Chain of custody over the links the case already records.

The tests that carry this file are the ones asserting what a chain does NOT
establish. An unbroken, fully signed chain is exactly the artefact somebody will
eventually wave at a reviewer as proof the thing is fine, and it is not that.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.attestation import (
    ATTESTATION_SCHEMA_VERSION, AttestationChain, AttestationError, AttestationRef,
    ChainStatus, CustodyLink, LinkStatus, SignatureMetadata, SignatureState,
    chain_from_case,
)
from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.session import AssuranceSession

D = lambda n: "sha256:" + str(n) * 64


def link(**kwargs):
    kwargs.setdefault("from_ref", "a")
    kwargs.setdefault("to_ref", "b")
    return CustodyLink(**kwargs)


def case_from(records):
    return AssuranceSession.open(methodology=PROFILE).extend(records).finalize().case


# ── what a chain does not establish ─────────────────────────────────────────

class TestAChainIsNotATruthClaim:

    def _perfect(self):
        return AttestationChain(terminal_ref="approval", links=(
            link(from_ref="agent-event", to_ref="tool-output",
                 asserted_digest=D(1), actual_digest=D(1)),
            link(from_ref="tool-output", to_ref="verifier-result",
                 asserted_digest=D(2), actual_digest=D(2)),
            link(from_ref="verifier-result", to_ref="evidence-pack",
                 asserted_digest=D(3), actual_digest=D(3)),
            link(from_ref="evidence-pack", to_ref="approval",
                 asserted_digest=D(4), actual_digest=D(4),
                 signature=SignatureMetadata(signer="person://lead",
                                             algorithm="ed25519"))))

    def test_a_continuous_signed_chain_still_establishes_no_truth(self):
        chain = self._perfect()
        assert chain.status is ChainStatus.CONTINUOUS
        assert chain.establishes_truth is False

    def test_the_note_says_what_it_does_not_mean(self):
        assert "does not establish that any of them was right" in self._perfect().note()

    def test_the_dict_carries_the_refusal(self):
        assert self._perfect().to_dict()["establishes_truth"] is False

    def test_a_signature_establishes_no_correctness(self):
        assert SignatureMetadata(signer="x").establishes_correctness is False
        assert SignatureMetadata(signer="x").to_dict()["establishes_correctness"] is False

    def test_the_prompts_five_step_chain_walks(self):
        assert len(self._perfect().linked) == 4
        assert self._perfect().reaches("approval")


class TestSignaturesAreRecordedNotVerified:

    def test_the_default_state_is_not_assessed(self):
        assert SignatureMetadata(signer="x").state is SignatureState.NOT_ASSESSED

    def test_an_anonymous_signature_is_refused(self):
        """Worse than no signature: it establishes nothing at all."""
        with pytest.raises(AttestationError, match="signer"):
            SignatureMetadata(signer="   ")

    def test_a_valid_result_must_name_who_checked_it(self):
        """This package verifies nothing, so an unattributed result has no
        standing."""
        with pytest.raises(AttestationError, match="who checked"):
            SignatureMetadata(signer="x", state=SignatureState.VALID)

    def test_an_external_verifier_may_supply_a_result(self):
        signature = SignatureMetadata(signer="x", state=SignatureState.VALID,
                                      verified_by="sigstore")
        assert signature.state is SignatureState.VALID

    def test_it_round_trips(self):
        signature = SignatureMetadata(signer="x", algorithm="ed25519", key_id="k1")
        assert SignatureMetadata.from_dict(signature.to_dict()) == signature


class TestAttestationReferences:

    def test_a_reference_must_state_its_kind(self):
        with pytest.raises(AttestationError, match="kind"):
            AttestationRef(kind="")

    def test_a_subject_digest_must_be_a_digest(self):
        with pytest.raises(AttestationError, match="content digest"):
            AttestationRef(kind="slsa-provenance", subject_digest="v1.2.3")

    def test_a_reference_may_omit_a_subject(self):
        assert AttestationRef(kind="in-toto").subject_digest == ""

    def test_external_formats_all_fit_one_shape(self):
        for kind in ("slsa-provenance", "in-toto", "sigstore-bundle", "vendor"):
            assert AttestationRef(kind=kind, subject_digest=D(1)).kind == kind


# ── link semantics ──────────────────────────────────────────────────────────

class TestLinkStatus:

    def test_matching_digests_are_linked(self):
        assert link(asserted_digest=D(1), actual_digest=D(1)).status is LinkStatus.LINKED

    def test_mismatched_digests_are_broken(self):
        broken = link(asserted_digest=D(1), actual_digest=D(2))
        assert broken.status is LinkStatus.BROKEN
        assert "is not the thing that is here" in broken.basis

    def test_a_named_thing_not_held_is_broken(self):
        broken = link(asserted_digest=D(1), actual_digest="")
        assert broken.status is LinkStatus.BROKEN
        assert "nothing held by this case carries that digest" in broken.basis

    def test_an_unasserted_hop_is_unlinked_not_broken(self):
        """Evidence that never claimed a parent has not been tampered with.

        Reporting it as a break would flood a case with alarms for the ordinary
        shape of unchained evidence, and the real breaks would be lost.
        """
        quiet = link()
        assert quiet.status is LinkStatus.UNLINKED
        assert "unrecorded rather than broken" in quiet.basis

    def test_a_link_carries_the_verifier_binary_when_supplied(self):
        identified = link(tool_identity={"name": "semgrep", "version": "1.2",
                                         "digest": D(9)})
        assert identified.to_dict()["tool_identity"]["digest"] == D(9)


class TestChainStatus:

    def test_nothing_asserted_is_not_assessed(self):
        assert AttestationChain().status is ChainStatus.NOT_ASSESSED
        assert "nothing is established" in AttestationChain().note()

    def test_one_break_makes_the_chain_broken(self):
        chain = AttestationChain(links=(
            link(asserted_digest=D(1), actual_digest=D(1)),
            link(asserted_digest=D(2), actual_digest=D(3))))
        assert chain.status is ChainStatus.BROKEN

    def test_links_that_stop_short_are_partial(self):
        chain = AttestationChain(links=(link(asserted_digest=D(1), actual_digest=D(1)),
                                        link(from_ref="c", to_ref="d")))
        assert chain.status is ChainStatus.PARTIAL
        assert "simply stops" in chain.note()

    def test_not_reaching_the_terminal_is_partial(self):
        chain = AttestationChain(terminal_ref="approval", links=(
            link(asserted_digest=D(1), actual_digest=D(1)),))
        assert chain.status is ChainStatus.PARTIAL

    def test_the_id_is_content_addressed(self):
        a = AttestationChain(links=(link(asserted_digest=D(1), actual_digest=D(1)),))
        b = AttestationChain(links=(link(asserted_digest=D(1), actual_digest=D(1)),))
        c = AttestationChain(links=(link(asserted_digest=D(2), actual_digest=D(2)),))
        assert a.chain_id == b.chain_id and a.chain_id != c.chain_id

    def test_it_serialises(self):
        payload = AttestationChain(links=(link(asserted_digest=D(1),
                                               actual_digest=D(1)),)).to_dict()
        assert payload["record_type"] == "attestation_chain"
        assert payload["schema_version"] == ATTESTATION_SCHEMA_VERSION


# ── walking a real case ─────────────────────────────────────────────────────

class TestChainFromCase:

    AGENT = {"record_type": "evidence", "evidence_id": "e_agent", "kind": "TRACE",
             "producer": {"producer_id": "agent://1", "kind": "agent"},
             "coverage_note": "agent event"}

    def test_an_intact_derivation_chain_is_continuous(self):
        chain = chain_from_case(case_from([
            self.AGENT,
            {"record_type": "evidence", "evidence_id": "e_ver", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://v", "kind": "tool"},
             "parent_evidence": ["e_agent"], "coverage_note": "verifier result"}]))
        assert chain.status is ChainStatus.CONTINUOUS

    def test_a_parent_this_case_does_not_hold_breaks_the_chain(self):
        """The signal that used to be erased.

        A record claiming derivation from evidence that was never supplied is
        exactly "what was used is not what is here". The ingest silently filtered
        such references out, so the walker reported CONTINUOUS over them.
        """
        chain = chain_from_case(case_from([
            self.AGENT,
            {"record_type": "evidence", "evidence_id": "e_ver", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://v", "kind": "tool"},
             "parent_evidence": ["never-supplied"], "coverage_note": "result"}]))
        assert chain.status is ChainStatus.BROKEN
        assert chain.broken

    def test_the_dropped_reference_is_also_noted_at_ingest(self):
        outcome = AssuranceSession.open(methodology=PROFILE).extend([
            self.AGENT,
            {"record_type": "evidence", "evidence_id": "e_ver", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://v", "kind": "tool"},
             "parent_evidence": ["never-supplied"], "coverage_note": "r"}]).finalize()
        assert any("does not hold" in n for n in outcome.normalisation.notes)

    def test_an_applies_to_digest_links_to_its_artifact(self):
        chain = chain_from_case(case_from([
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://v", "kind": "tool"},
             "applies_to_digest": D("a"), "coverage_note": "ran against the build"},
            {"record_type": "artifact", "logical_id": "build", "digest": D("a"),
             "digest_status": "OBSERVED"}]))
        assert any(l.relation == "applies_to" and l.status is LinkStatus.LINKED
                   for l in chain.links)

    def test_a_minimal_case_still_has_the_input_container_link(self):
        """Every case has one custody link whether anyone chained anything.

        Release-gate hashes the input itself and records it as evidence applying
        to its own digest, so the shortest possible chain is one hop that holds.
        Worth pinning: it means CONTINUOUS on a bare case says "the bytes we read
        are the bytes we hashed" and nothing more.
        """
        chain = chain_from_case(case_from([self.AGENT]))
        assert not chain.broken
        assert all(l.relation == "applies_to" for l in chain.links)
        assert chain.establishes_truth is False

    def test_it_works_without_the_cryptography_backend(self):
        """The assurance package is stdlib-only; the chain must not need keys.

        This container's `cryptography` wheel cannot even initialise, which makes
        it an honest test of that claim rather than a hypothetical one.
        """
        import release_gate.assurance.attestation as module
        assert "cryptography" not in module.__dict__
        assert chain_from_case(case_from([self.AGENT])) is not None


class TestNoBlockchain:

    def test_the_module_has_no_consensus_machinery(self):
        import release_gate.assurance.attestation as module
        source = module.__doc__ or ""
        assert "No blockchain" in source
        for word in ("consensus", "ledger", "mining", "token"):
            assert not hasattr(module, word)
