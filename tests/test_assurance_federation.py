"""Evidence held elsewhere, and what a reference to it does and does not settle.

The tests that matter here all guard the same thing from different sides: that
"we checked the digest without copying the data" cannot quietly come to mean less
than it sounds. An existence probe must not establish integrity, a store's own
checksum must not become OBSERVED, a mutable tag in a content-addressed registry
must not ride in on the registry's reputation, and a mismatch must read as a
refutation rather than as an absence of information.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind)
from release_gate.assurance.expectation import CoverageLedger, CoverageState
from release_gate.assurance.federation import (
    ESTABLISHMENT_TABLE, FEDERATED_SYSTEMS, Addressing, Custody, Establishment,
    FederatedSystem, FederationError, FederationLedger, Holding, MatchOutcome,
    Probe, Resolution, ResolutionMethod, SystemClass, holdings_in, resolve,
    resolve_all, system_for,
)
from release_gate.assurance.subject import DigestStatus, ReferenceKind

DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32
GIT_OID = "c" * 40


class Fixed:
    """A resolver that returns one probe, whatever it is asked."""

    def __init__(self, probe: Probe) -> None:
        self.probe_value = probe
        self.calls = 0

    def probe(self, holding: Holding) -> Probe:
        self.calls += 1
        return self.probe_value


class Broken:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def probe(self, holding: Holding) -> Probe:
        raise self.exc


def holding(**kwargs) -> Holding:
    base = dict(holding_id="h1", system="s3", locator="s3://bucket/key",
                claimed_digest=DIGEST, declared_by="ml-platform")
    base.update(kwargs)
    return Holding(**base)


# ── the seven classes ────────────────────────────────────────────────────────

class TestSystemClasses:

    def test_the_brief_names_seven_and_all_seven_exist(self):
        assert {c.value for c in SystemClass} == {
            "OBSERVABILITY", "CI", "OBJECT_STORE", "DATABASE",
            "THEOREM_PROVER", "RESEARCH_SYSTEM", "EXTERNAL_LAB"}

    def test_every_class_has_at_least_one_registered_system(self):
        covered = {s.system_class for s in FEDERATED_SYSTEMS.values()}
        assert covered == set(SystemClass)

    def test_every_class_describes_itself(self):
        for system_class in SystemClass:
            assert len(system_class.describe()) > 40

    def test_only_a_prover_holds_a_claim_another_party_can_recheck_cheaply(self):
        """The axis that separates a proof from an assay, and it is about cost."""
        recheckable = [c for c in SystemClass if c.independently_recheckable]
        assert recheckable == [SystemClass.THEOREM_PROVER]

    def test_the_registry_is_built_from_one_list(self):
        assert all(name == system.name for name, system in FEDERATED_SYSTEMS.items())

    def test_a_system_must_be_named(self):
        with pytest.raises(FederationError, match="must be named"):
            FederatedSystem(name=" ", label="x", system_class=SystemClass.CI,
                            addressing=Addressing.OPAQUE_ID)

    def test_an_unregistered_system_is_none_rather_than_a_guess(self):
        assert system_for("a-system-nobody-wrote-a-row-for") is None

    def test_retention_is_declared_and_never_measured(self):
        s3 = FEDERATED_SYSTEMS["github_actions"]
        assert s3.retention_is_declared
        assert not FEDERATED_SYSTEMS["gitlab_ci"].retention_is_declared

    def test_a_system_serialises(self):
        data = FEDERATED_SYSTEMS["oci_registry"].to_dict()
        assert data["addressing"] == "CONTENT_ADDRESSED"
        assert data["record_type"] == "federated_system"


class TestAddressing:
    """The load-bearing axis: the addressing decides verifiability, not the vendor."""

    def test_only_content_addressing_makes_identity_free(self):
        free = [a for a in Addressing if a.identity_is_free]
        assert free == [Addressing.CONTENT_ADDRESSED]

    def test_an_opaque_id_and_a_query_can_report_no_digest_at_all(self):
        assert not Addressing.OPAQUE_ID.can_report_a_digest
        assert not Addressing.QUERY.can_report_a_digest
        assert Addressing.CHECKSUMMED.can_report_a_digest
        assert Addressing.CONTENT_ADDRESSED.can_report_a_digest

    def test_two_object_stores_can_be_further_apart_than_two_classes(self):
        """The point of the axis: s3 and an OCI registry answer different questions."""
        assert (FEDERATED_SYSTEMS["s3"].system_class
                is FEDERATED_SYSTEMS["oci_registry"].system_class)
        assert (FEDERATED_SYSTEMS["s3"].addressing
                is not FEDERATED_SYSTEMS["oci_registry"].addressing)

    def test_a_database_holding_is_a_query_not_an_object(self):
        for name in ("postgres", "snowflake", "bigquery"):
            assert FEDERATED_SYSTEMS[name].addressing is Addressing.QUERY

    def test_each_addressing_mode_describes_itself(self):
        for mode in Addressing:
            assert len(mode.describe()) > 40


class TestCustody:

    def test_an_unrecorded_custodian_counts_as_crossing_the_boundary(self):
        """UNKNOWN is not domestic. Invariant 3 applied to provenance."""
        assert Custody.UNKNOWN.crosses_an_organisational_boundary
        assert Custody.OTHER_ORGANISATION.crosses_an_organisational_boundary
        assert not Custody.OWN.crosses_an_organisational_boundary
        assert not Custody.VENDOR.crosses_an_organisational_boundary

    def test_a_lab_is_another_organisation(self):
        for name in ("external_lab", "lab_lims"):
            assert FEDERATED_SYSTEMS[name].custody is Custody.OTHER_ORGANISATION


# ── a holding ────────────────────────────────────────────────────────────────

class TestHolding:

    def test_a_holding_needs_an_id_a_system_and_a_locator(self):
        with pytest.raises(FederationError, match="needs an id"):
            Holding(holding_id="", system="s3", locator="k")
        with pytest.raises(FederationError, match="must name the system"):
            Holding(holding_id="h", system="", locator="k")
        with pytest.raises(FederationError, match="must carry a locator"):
            Holding(holding_id="h", system="s3", locator="  ")

    def test_release_gate_never_holds_it(self):
        assert holding().is_held_by_release_gate is False
        assert holding(system="anything").is_held_by_release_gate is False

    def test_an_unknown_system_reads_as_the_weakest_option(self):
        """Not the handiest: an unclassifiable system gets no benefit of the doubt."""
        unknown = holding(system="some-internal-thing")
        assert not unknown.known_system
        assert unknown.addressing is Addressing.OPAQUE_ID
        assert unknown.custody is Custody.UNKNOWN
        assert unknown.system_class is None

    def test_classification_is_read_off_the_registry(self):
        lean = holding(system="lean", locator=GIT_OID)
        assert lean.system_class is SystemClass.THEOREM_PROVER
        assert lean.addressing is Addressing.CONTENT_ADDRESSED

    def test_a_content_addressed_locator_is_checkable_without_transfer(self):
        assert holding(system="oci_registry", locator=DIGEST
                       ).identity_checkable_without_transfer
        assert holding(system="git_remote", locator=GIT_OID
                       ).identity_checkable_without_transfer

    def test_a_mutable_tag_does_not_inherit_the_registry_s_addressing(self):
        """Both halves are required: the system's mode and this locator's shape."""
        tag = holding(system="oci_registry", locator="myapp:latest")
        assert tag.addressing is Addressing.CONTENT_ADDRESSED
        assert not tag.identity_checkable_without_transfer

    def test_an_opaque_id_is_never_checkable_without_transfer(self):
        assert not holding(system="langfuse", locator="trace-0a1b"
                           ).identity_checkable_without_transfer

    def test_a_holding_becomes_a_content_reference(self):
        reference = holding(system="s3").reference()
        assert reference.kind is ReferenceKind.OBJECT_STORE
        assert reference.detail["system"] == "s3"
        assert reference.detail["custody"] == "VENDOR"
        assert reference.detail["declared_by"] == "ml-platform"

    def test_an_unknown_system_still_produces_a_reference(self):
        reference = holding(system="mystery").reference()
        assert reference.kind is ReferenceKind.EXTERNAL
        assert "system_class" not in reference.detail

    def test_a_holding_serialises_its_boundary(self):
        data = holding(system="external_lab", locator="SAMPLE-1").to_dict()
        assert data["crosses_an_organisational_boundary"] is True
        assert data["is_held_by_release_gate"] is False


# ── the grid ─────────────────────────────────────────────────────────────────

class TestEstablishmentTable:

    def test_the_table_is_exhaustive_over_the_methods(self):
        """A grid rather than branches, so one question has one answer in one place."""
        assert set(ESTABLISHMENT_TABLE) == set(ResolutionMethod)

    def test_only_recomputing_yields_observed(self):
        observed = [m for m, e in ESTABLISHMENT_TABLE.items()
                    if e.digest_status is DigestStatus.OBSERVED]
        assert observed == [ResolutionMethod.RECOMPUTED]

    def test_only_recomputing_moves_the_payload(self):
        moves = [m for m in ResolutionMethod if m.transfers_payload]
        assert moves == [ResolutionMethod.RECOMPUTED]

    def test_an_existence_probe_establishes_neither_identity_nor_integrity(self):
        """An object at the right key with the wrong contents passes this and only this."""
        row = ESTABLISHMENT_TABLE[ResolutionMethod.EXISTENCE_PROBE]
        assert row.identity is Establishment.NOT_ASSESSED
        assert row.integrity is Establishment.NOT_ASSESSED
        assert row.availability is Establishment.ESTABLISHED

    def test_content_addressing_settles_identity_and_not_availability(self):
        """A CID nobody is pinning is a valid name for something nobody can fetch."""
        row = ESTABLISHMENT_TABLE[ResolutionMethod.ADDRESS_IS_DIGEST]
        assert row.identity is Establishment.ESTABLISHED
        assert row.integrity is Establishment.NOT_ASSESSED
        assert row.availability is Establishment.NOT_ASSESSED

    def test_a_stores_own_checksum_settles_integrity_on_the_stores_authority(self):
        """Establishment and authority are separate axes, and both travel."""
        row = ESTABLISHMENT_TABLE[ResolutionMethod.METADATA_DIGEST]
        assert row.integrity is Establishment.ESTABLISHED
        assert row.digest_status is DigestStatus.DECLARED

    def test_not_attempted_is_distinct_from_unreachable(self):
        """Nobody asked, versus asked and could not settle it (Invariant 3)."""
        assert (ESTABLISHMENT_TABLE[ResolutionMethod.NOT_ATTEMPTED].identity
                is Establishment.NOT_ASSESSED)
        assert (ESTABLISHMENT_TABLE[ResolutionMethod.UNREACHABLE].identity
                is Establishment.NOT_ESTABLISHED)

    def test_every_row_says_why(self):
        for method, row in ESTABLISHMENT_TABLE.items():
            assert len(row.why) > 40, method

    def test_only_established_and_refuted_count_as_settled(self):
        assert Establishment.ESTABLISHED.settled
        assert Establishment.REFUTED.settled
        assert not Establishment.NOT_ESTABLISHED.settled
        assert not Establishment.NOT_ASSESSED.settled


# ── probes and resolution ────────────────────────────────────────────────────

class TestProbe:

    def test_a_recomputed_probe_must_show_the_digest_it_computed(self):
        """The one path to OBSERVED may not be claimed without the evidence for it."""
        with pytest.raises(FederationError, match="must carry the digest it computed"):
            Probe(method=ResolutionMethod.RECOMPUTED)

    def test_negative_transfer_is_refused(self):
        with pytest.raises(FederationError, match="cannot be negative"):
            Probe(method=ResolutionMethod.EXISTENCE_PROBE, bytes_transferred=-1)

    def test_other_methods_need_no_digest(self):
        assert Probe(method=ResolutionMethod.EXISTENCE_PROBE).observed_digest is None


class TestResolution:

    def test_observed_is_refused_for_any_method_but_recomputing(self):
        """The mapping is a table; this is the guard against bypassing it."""
        with pytest.raises(FederationError, match="only RECOMPUTED yields"):
            Resolution(holding_id="h", method=ResolutionMethod.METADATA_DIGEST,
                       identity=Establishment.ESTABLISHED,
                       integrity=Establishment.ESTABLISHED,
                       availability=Establishment.ESTABLISHED,
                       digest_status=DigestStatus.OBSERVED, why="a store said so")

    def test_a_resolution_must_say_what_it_rests_on(self):
        with pytest.raises(FederationError, match="must say what it rests on"):
            Resolution(holding_id="h", method=ResolutionMethod.EXISTENCE_PROBE,
                       identity=Establishment.NOT_ASSESSED,
                       integrity=Establishment.NOT_ASSESSED,
                       availability=Establishment.ESTABLISHED,
                       digest_status=DigestStatus.UNKNOWN, why="")

    def test_resolving_never_retains_the_evidence(self):
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=DIGEST,
            present=True, bytes_transferred=0)))
        assert result.retains_the_evidence is False


class TestVerifyingWithoutCopying:
    """The brief's actual ask, and the ways it could be quietly overstated."""

    def test_a_checksummed_store_settles_identity_with_nothing_moved(self):
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=DIGEST,
            present=True, bytes_transferred=0)))
        assert result.match is MatchOutcome.MATCHED
        assert result.verified_without_copying
        assert result.digest_status is DigestStatus.DECLARED
        assert result.bytes_transferred == 0

    def test_content_addressing_settles_identity_without_contacting_anyone(self):
        """Identity yes, availability no — and the digest must come from elsewhere.

        The independent declarer is what makes this a check rather than a
        submission agreeing with itself; see
        `TestAPropertyADocumentCannotGrantItself`.
        """
        resolver = Fixed(Probe(method=ResolutionMethod.ADDRESS_IS_DIGEST,
                               bytes_transferred=0))
        result = resolve(holding(system="oci_registry", locator=DIGEST,
                                 digest_declared_by="release-manifest@platform-eng"),
                         resolver)
        assert result.identity is Establishment.ESTABLISHED
        assert result.availability is Establishment.NOT_ASSESSED
        assert result.verified_without_copying

    def test_recomputing_is_the_strongest_result_and_is_not_without_copying(self):
        """Counting it would make the measure report its own opposite."""
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.RECOMPUTED, observed_digest=DIGEST,
            present=True, bytes_transferred=1_048_576)))
        assert result.digest_status is DigestStatus.OBSERVED
        assert result.integrity is Establishment.ESTABLISHED
        assert not result.verified_without_copying
        assert result.bytes_transferred == 1_048_576

    def test_an_existence_probe_is_not_verification(self):
        result = resolve(holding(system="langfuse", locator="t-1", claimed_digest=None),
                         Fixed(Probe(method=ResolutionMethod.EXISTENCE_PROBE,
                                     present=True, bytes_transferred=0)))
        assert not result.verified_without_copying
        assert result.match is MatchOutcome.NOT_COMPARED
        assert result.is_a_gap

    def test_a_mismatch_is_never_verified_however_cheap_it_was(self):
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=OTHER,
            present=True, bytes_transferred=0)))
        assert not result.verified_without_copying


class TestAPropertyADocumentCannotGrantItself:
    """The hole found by asking what a submitted document can award itself.

    `ADDRESS_IS_DIGEST` compares the locator against the claimed digest. Read off
    one evidence record, both come from the same producer, so an agent could set
    `verified_without_copying` with no external interaction whatsoever by choosing
    both sides of its own comparison. A security property an attacker can grant
    themselves is not a property.
    """

    class Free:
        def probe(self, holding):
            return Probe(method=ResolutionMethod.ADDRESS_IS_DIGEST, bytes_transferred=0)

    def _submitted(self) -> Holding:
        """A holding as `holdings_in` reads one: one record, one declarer."""
        from release_gate.assurance.subject import ContentReference

        record = EvidenceRecord(
            evidence_type=EvidenceType.DATA_ARTIFACT, source="agent://claimer",
            producer=Producer(producer_id="agent://claimer", kind=ProducerKind.AGENT),
            content_reference=ContentReference(
                kind="OBJECT_STORE", locator=DIGEST,
                detail={"system": "oci_registry", "declared_by": "agent://claimer"}),
            digest=DIGEST)
        return holdings_in([record])[0]

    def test_a_document_comparing_itself_to_itself_verifies_nothing(self):
        result = resolve(self._submitted(), self.Free())
        assert result.match is MatchOutcome.MATCHED
        assert result.self_referential
        assert not result.verified_without_copying
        assert result.is_a_gap

    def test_the_reason_names_the_party_on_both_sides(self):
        result = resolve(self._submitted(), self.Free())
        assert "agent://claimer" in result.why
        assert "compares a submission against itself" in result.why

    def test_a_second_party_naming_the_expected_digest_is_a_real_check(self):
        """The fix must not refuse the case it exists to distinguish."""
        corroborated = Holding(
            holding_id="h", system="oci_registry", locator=DIGEST,
            claimed_digest=DIGEST, declared_by="agent://claimer",
            digest_declared_by="release-manifest@platform-eng")
        result = resolve(corroborated, self.Free())
        assert not result.self_referential
        assert result.verified_without_copying
        assert not result.is_a_gap

    def test_the_same_party_named_twice_is_still_one_party(self):
        same = Holding(holding_id="h", system="oci_registry", locator=DIGEST,
                       claimed_digest=DIGEST, declared_by="agent://claimer",
                       digest_declared_by="agent://claimer")
        assert not same.digest_is_independently_declared
        assert resolve(same, self.Free()).self_referential

    def test_independence_is_not_inferred_from_whitespace(self):
        padded = Holding(holding_id="h", system="oci_registry", locator=DIGEST,
                         claimed_digest=DIGEST, declared_by="agent://claimer",
                         digest_declared_by="  agent://claimer  ")
        assert not padded.digest_is_independently_declared

    def test_a_store_reported_digest_is_not_self_referential(self):
        """Narrow on purpose: the store computed its digest without the producer."""
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=DIGEST,
            present=True, bytes_transferred=0)))
        assert not result.self_referential
        assert result.verified_without_copying

    def test_a_ledger_reads_a_self_referential_holding_as_unresolved(self):
        ledger = resolve_all([self._submitted()], self.Free())
        assert len(ledger.unresolved) == 1
        assert ledger.verified_without_copying == ()

    def test_it_costs_coverage_like_any_other_gap(self):
        rows = resolve_all([self._submitted()], self.Free()).expectations()
        assert [r.assessed for r in rows] == [False]
        assert rows[0].dimension == "federated.oci_registry"

    def test_the_flag_travels_in_the_serialisation_and_the_render(self):
        result = resolve(self._submitted(), self.Free())
        assert result.to_dict()["self_referential"] is True
        assert "SELF_REFERENTIAL" in result.render()

    def test_holdings_read_off_a_record_never_claim_a_second_declarer(self):
        """There is no second party on one record, so none is invented."""
        assert self._submitted().digest_declared_by == ""
        assert not self._submitted().digest_is_independently_declared


class TestAdjudication:

    def test_a_mismatch_refutes_rather_than_failing_to_establish(self):
        """The strongest negative result must not read as an absence of information."""
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=OTHER,
            present=True)))
        assert result.match is MatchOutcome.MISMATCHED
        assert result.identity is Establishment.REFUTED
        assert result.integrity is Establishment.REFUTED
        assert "is not the object this case is about" in result.why

    def test_a_mismatch_does_not_refute_what_was_never_assessed(self):
        """Content addressing assesses no bytes, so there is no integrity to refute."""
        result = resolve(holding(system="oci_registry", locator=DIGEST,
                                 claimed_digest=OTHER),
                         Fixed(Probe(method=ResolutionMethod.ADDRESS_IS_DIGEST)))
        assert result.identity is Establishment.REFUTED
        assert result.integrity is Establishment.NOT_ASSESSED

    def test_a_tag_claimed_as_content_addressed_is_refused_with_its_reason(self):
        result = resolve(holding(system="oci_registry", locator="myapp:latest"),
                         Fixed(Probe(method=ResolutionMethod.ADDRESS_IS_DIGEST)))
        assert result.method is ResolutionMethod.UNREACHABLE
        assert result.identity is Establishment.NOT_ESTABLISHED
        assert "not shaped like a digest" in result.why

    def test_an_absent_object_refutes_availability(self):
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.EXISTENCE_PROBE, present=False)))
        assert result.availability is Establishment.REFUTED
        assert result.is_a_gap

    def test_a_present_object_upgrades_availability_that_was_not_assessed(self):
        result = resolve(holding(system="oci_registry", locator=DIGEST,
                                 claimed_digest=DIGEST),
                         Fixed(Probe(method=ResolutionMethod.ADDRESS_IS_DIGEST,
                                     present=True)))
        assert result.availability is Establishment.ESTABLISHED

    def test_a_resolver_that_raises_becomes_a_gap_and_not_a_crash(self):
        """The `subject.recheck` lesson: this question is asked in the approval path."""
        result = resolve(holding(), Broken(ConnectionError("credential revoked")))
        assert result.method is ResolutionMethod.UNREACHABLE
        assert "ConnectionError" in result.why
        assert "credential revoked" in result.why

    def test_no_resolver_means_not_attempted_rather_than_a_local_read(self):
        """A locator arrives in a submitted document; reading it would be the oracle."""
        result = resolve(holding(locator="/etc/shadow"))
        assert result.method is ResolutionMethod.NOT_ATTEMPTED
        assert result.identity is Establishment.NOT_ASSESSED

    def test_a_resolver_may_not_return_a_bare_value(self):
        class Rogue:
            def probe(self, holding):
                return DIGEST

        with pytest.raises(FederationError, match="must return a Probe"):
            resolve(holding(), Rogue())

    def test_a_digest_compares_across_the_prefix(self):
        bare = Fixed(Probe(method=ResolutionMethod.METADATA_DIGEST,
                           observed_digest="ab" * 32, present=True))
        assert resolve(holding(), bare).match is MatchOutcome.MATCHED

    def test_nothing_to_compare_against_is_not_a_pass(self):
        result = resolve(holding(claimed_digest=None), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=DIGEST,
            present=True)))
        assert result.match is MatchOutcome.NOT_COMPARED

    def test_the_render_names_the_mechanism(self):
        result = resolve(holding(), Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=DIGEST,
            present=True, bytes_transferred=0)))
        text = result.render()
        assert "METADATA_DIGEST" in text and "digest=DECLARED" in text


# ── the ledger ───────────────────────────────────────────────────────────────

class TestLedger:

    def _ledger(self) -> FederationLedger:
        return resolve_all(
            [holding(holding_id="a", system="oci_registry", locator=DIGEST),
             holding(holding_id="b", system="langfuse", locator="t-1",
                     claimed_digest=None),
             holding(holding_id="c", system="external_lab", locator="S-1")],
            Fixed(Probe(method=ResolutionMethod.EXISTENCE_PROBE, present=True,
                        bytes_transferred=0)))

    def test_a_resolution_with_no_holding_is_refused(self):
        """A claim about evidence the case never declared."""
        with pytest.raises(FederationError, match="does not hold"):
            FederationLedger(
                holdings=(holding(holding_id="a"),),
                resolutions=(resolve(holding(holding_id="ghost")),))

    def test_an_empty_ledger_says_every_record_is_local(self):
        assert "every record in this case is local" in FederationLedger().render()

    def test_holdings_are_counted_by_class(self):
        assert self._ledger().by_class == {
            "EXTERNAL_LAB": 1, "OBJECT_STORE": 1, "OBSERVABILITY": 1}

    def test_unresolved_covers_holdings_nobody_tried(self):
        ledger = resolve_all([holding(holding_id="a")], None)
        assert [h.holding_id for h in ledger.unresolved] == ["a"]

    def test_a_refuted_holding_is_not_merely_unresolved(self):
        """Resolved and wrong is a different finding from not settled."""
        ledger = resolve_all([holding(holding_id="a")], Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=OTHER,
            present=True)))
        assert [r.holding_id for r in ledger.refuted] == ["a"]
        assert ledger.unresolved == ()

    def test_unavailable_holdings_are_listed(self):
        ledger = resolve_all([holding(holding_id="a")], Fixed(Probe(
            method=ResolutionMethod.EXISTENCE_PROBE, present=False)))
        assert [r.holding_id for r in ledger.unavailable] == ["a"]

    def test_cross_organisation_holdings_are_listed(self):
        assert [h.holding_id for h in self._ledger().cross_organisation] == ["a", "c"]

    def test_bytes_moved_is_summed_and_reported(self):
        ledger = resolve_all(
            [holding(holding_id="a"), holding(holding_id="b")],
            Fixed(Probe(method=ResolutionMethod.RECOMPUTED, observed_digest=DIGEST,
                        present=True, bytes_transferred=500)))
        assert ledger.bytes_transferred == 1000
        assert "1,000 bytes" in ledger.render()

    def test_unmeasured_transfer_is_none_rather_than_zero(self):
        """Zero bytes moved and nobody counting are different claims."""
        ledger = resolve_all([holding(holding_id="a")], Fixed(Probe(
            method=ResolutionMethod.EXISTENCE_PROBE, present=True)))
        assert ledger.bytes_transferred is None
        assert "not measured" in ledger.render()

    def test_a_ledger_is_not_a_completeness_claim(self):
        """Evidence in a system nobody mentioned is the omission this cannot see."""
        assert FederationLedger().is_a_completeness_claim is False
        assert self._ledger().is_a_completeness_claim is False

    def test_the_render_refuses_to_promise_durability(self):
        text = self._ledger().render()
        assert "not that it will be" in text
        assert "only the holdings somebody declared" in text

    def test_of_returns_the_resolution_for_a_holding(self):
        ledger = self._ledger()
        assert ledger.of("a").holding_id == "a"
        assert ledger.of("nope") is None

    def test_a_ledger_serialises(self):
        data = self._ledger().to_dict()
        assert data["record_type"] == "federation_ledger"
        assert data["is_a_completeness_claim"] is False


class TestCoverageConsequence:
    """Unresolved holdings must reach the coverage ledger, not a separate report."""

    def test_an_unresolved_holding_lands_as_not_assessed(self):
        rows = resolve_all([holding(holding_id="a", system="langfuse",
                                    locator="t-1")], None).expectations()
        assert len(rows) == 1
        assert rows[0].assessed is False
        ledger = CoverageLedger(rows=rows)
        assert ledger.of("federated.langfuse").state is CoverageState.NOT_ASSESSED

    def test_two_holdings_in_one_system_do_not_hide_each_other(self):
        """`CoverageLedger.of` returns the first match, so one row per system."""
        rows = resolve_all([holding(holding_id="a", system="langfuse", locator="t-1"),
                            holding(holding_id="b", system="langfuse", locator="t-2")],
                           None).expectations()
        assert len(rows) == 1
        assert "a" in rows[0].observed_from and "b" in rows[0].observed_from
        assert "2 holding(s)" in rows[0].note

    def test_a_refutation_gets_its_own_row_rather_than_the_same_shape(self):
        """'Could not check' and 'checked, and wrong' must not share a finding."""
        rows = resolve_all([holding(holding_id="a")], Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=OTHER,
            present=True))).expectations()
        assert [r.dimension for r in rows] == ["federated.mismatch.a"]
        assert "does not match the digest this case claims" in rows[0].note

    def test_a_fully_resolved_ledger_costs_no_coverage(self):
        rows = resolve_all([holding(holding_id="a")], Fixed(Probe(
            method=ResolutionMethod.METADATA_DIGEST, observed_digest=DIGEST,
            present=True))).expectations()
        assert rows == ()

    def test_every_row_names_who_declared_the_holding(self):
        rows = resolve_all([holding(holding_id="a", declared_by="")], None).expectations()
        assert "an unnamed party" in rows[0].observed_from


# ── the record model already carried this ────────────────────────────────────

class TestRoundTripThroughTheRecordModel:
    """No new ingest path, and no second evidence model."""

    def _record(self, held: Holding) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_type=EvidenceType.DATA_ARTIFACT, source="ml-platform",
            producer=Producer(producer_id="tool://exporter", kind=ProducerKind.TOOL),
            content_reference=held.reference(), digest=held.claimed_digest)

    def test_a_holding_survives_a_trip_through_an_evidence_record(self):
        original = holding(system="s3", locator="s3://bucket/weights.bin")
        back = holdings_in([self._record(original)])
        assert len(back) == 1
        assert back[0].system == "s3"
        assert back[0].locator == "s3://bucket/weights.bin"
        assert back[0].claimed_digest == DIGEST
        assert back[0].declared_by == "ml-platform"

    def test_the_classification_comes_back_too(self):
        back = holdings_in([self._record(holding(system="lean", locator=GIT_OID))])
        assert back[0].system_class is SystemClass.THEOREM_PROVER
        assert back[0].identity_checkable_without_transfer

    def test_local_records_are_skipped_in_silence(self):
        local = EvidenceRecord(
            evidence_type=EvidenceType.TEST_RESULT, source="ci",
            producer=Producer(producer_id="ci://pytest", kind=ProducerKind.TOOL))
        assert holdings_in([local]) == ()

    def test_the_holding_points_back_at_the_record_it_came_from(self):
        record = self._record(holding())
        back = holdings_in([record])
        assert back[0].supports_evidence == (record.record_id,)

    def test_one_record_yields_one_holding_however_often_it_appears(self):
        record = self._record(holding())
        assert len(holdings_in([record, record])) == 1

    def test_a_record_with_no_reference_at_all_is_skipped(self):
        class Bare:
            record_id = "r1"
            content_reference = None

        assert holdings_in([Bare()]) == ()
