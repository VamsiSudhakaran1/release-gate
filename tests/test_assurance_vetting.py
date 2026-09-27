"""Whom an organisation vetted, and the four ways that could be overstated.

The tests here guard one property from several sides: an explicit trust decision
must not become a thing anybody can pick up. So a name never matches, an asserted
identifier never reaches full standing, a revocation reaches backwards, a lapsed
window does not, and a registry read out of a submitted document does not exist.

The first test is the one that matters most and looks least like a test:
release-gate ships zero vetted verifiers.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind, TrustDecision, TrustStatus)
from release_gate.assurance.expectation import CoverageLedger, CoverageState
from release_gate.assurance.vetting import (
    PROOF_KEYS, Consultation, Identification, VerifierEntry, VerifierKind,
    VerifierStanding, VettingError, VettingRegistry, VettingReport, attempts_in,
    consult, consult_attempt, empty_registry, identity_values_of, report_for,
    vetting_report,
)

PROVER = "sha256:" + "11" * 32
OTHER = "sha256:" + "22" * 32
WORKFLOW = "acme/svc@refs/heads/main:test.yml"
IN_WINDOW = "2026-06-01T00:00:00Z"
BEFORE = "2025-01-01T00:00:00Z"
AFTER = "2028-01-01T00:00:00Z"
OWN_CLOCK = "release-gate's own clock, stamped when the attempt arrived"
PRODUCER_CLOCK = "the producer's declared timestamp"


def decision(status: TrustStatus = TrustStatus.ACCEPTED, **kwargs) -> TrustDecision:
    base = dict(status=status, basis="reviewed by platform security",
                decided_by="security-eng@acme")
    base.update(kwargs)
    return TrustDecision(**base)


def entry(**kwargs) -> VerifierEntry:
    base = dict(entry_id="e-prover", verifier_id="tool://trusted-prover",
                kind=VerifierKind.EXECUTABLE,
                identification=Identification.CONTENT_DIGEST,
                identified_by=(PROVER,),
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                decision=decision())
    base.update(kwargs)
    return VerifierEntry(**base)


def registry(*entries: VerifierEntry, source: str = "ops/vetting.yaml") -> VettingRegistry:
    built = VettingRegistry(source=source)
    for item in entries or (entry(),):
        built.register(item)
    return built


class Attempt:
    """The shape `consult_attempt` reads, without building a whole case."""

    def __init__(self, verifier="tool://trusted-prover", timestamp=IN_WINDOW,
                 stamped_on_arrival=False, detail=None, verification_id="v1"):
        self.verifier = verifier
        self.timestamp = timestamp
        self.stamped_on_arrival = stamped_on_arrival
        self.detail = detail or {}
        self.verification_id = verification_id


# ── nothing is shipped ───────────────────────────────────────────────────────

class TestNothingIsShipped:
    """The brief's hardest line: do not hardcode trusted vendors."""

    def test_the_registry_ships_empty(self):
        assert len(empty_registry()) == 0
        assert empty_registry().entries == ()
        assert not empty_registry()

    def test_it_says_so_unconditionally(self):
        assert empty_registry().ships_trusted_vendors is False
        assert registry().ships_trusted_vendors is False

    def test_no_module_level_list_of_entries_exists(self):
        """Every other registry here ships rows; this one must not have the shape."""
        import release_gate.assurance.vetting as module

        shipped = [name for name, value in vars(module).items()
                   if isinstance(value, (list, tuple))
                   and any(isinstance(v, VerifierEntry) for v in value)]
        assert shipped == []

    def test_there_is_no_loader_from_a_document(self):
        """A case that carried its own registry would be self-vetting (§10ah)."""
        assert not hasattr(VettingRegistry, "from_dict")
        assert not hasattr(VettingRegistry, "from_records")
        import release_gate.assurance.vetting as module
        assert not any("from_" in name for name in module.__all__)

    def test_ingest_still_maps_no_trust_at_all(self):
        """A submitted record cannot declare its own TrustDecision, and still cannot."""
        from release_gate.assurance.ingest import detect_document, normalise

        doc = [{"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
                "producer": {"producer_id": "agent://x", "kind": "agent"},
                "trust": {"status": "ACCEPTED", "basis": "we are reliable",
                          "decided_by": "agent://x"}}]
        content = json.dumps(doc, sort_keys=True).encode()
        normalisation = normalise(doc, detect_document(doc, filename="s"),
                                  source="s", content=content)
        assert normalisation.evidence[0].trust is None

    def test_a_vetting_record_in_a_document_becomes_no_registry(self):
        """The §10ah boundary: a document may describe a registry, never be one."""
        from release_gate.assurance.ingest import detect_document, normalise

        doc = [{"record_type": "verifier_entry", "entry_id": "mine",
                "verifier_id": "tool://mine", "kind": "EXECUTABLE",
                "identified_by": [PROVER]}]
        content = json.dumps(doc, sort_keys=True).encode()
        normalisation = normalise(doc, detect_document(doc, filename="s"),
                                 source="s", content=content)
        # Whatever the ingest made of it, no registry came out of it.
        assert not hasattr(normalisation, "vetting")
        assert not hasattr(normalisation, "registry")


# ── the kinds ────────────────────────────────────────────────────────────────

class TestVerifierKinds:

    def test_the_brief_names_four_and_there_is_an_escape_hatch(self):
        assert {k.value for k in VerifierKind} == {
            "EXECUTABLE", "CI_WORKFLOW", "LABORATORY", "HUMAN", "OTHER"}

    def test_each_kind_describes_itself(self):
        for kind in VerifierKind:
            assert len(kind.describe()) > 40

    def test_only_an_executable_can_be_pinned_to_its_own_content(self):
        assert (VerifierKind.EXECUTABLE.strongest_available_identification
                is Identification.CONTENT_DIGEST)

    def test_a_laboratory_is_asserted_by_nature_and_not_by_oversight(self):
        """Its accreditation number is on its own report. That is the world, not a bug."""
        strongest = VerifierKind.LABORATORY.strongest_available_identification
        assert strongest is Identification.ASSERTED_NAME
        assert not strongest.can_support_full_standing

    def test_each_kind_maps_to_the_producer_vocabulary_already_in_use(self):
        assert VerifierKind.HUMAN.principal_kind is ProducerKind.HUMAN
        assert VerifierKind.CI_WORKFLOW.principal_kind is ProducerKind.TOOL
        assert VerifierKind.LABORATORY.principal_kind is ProducerKind.EXTERNAL


class TestIdentification:

    def test_an_asserted_name_can_never_support_full_standing(self):
        supports = [i for i in Identification if i.can_support_full_standing]
        assert set(supports) == {Identification.CONTENT_DIGEST,
                                 Identification.PLATFORM_IDENTITY,
                                 Identification.ACCOUNT}

    def test_nothing_matching_supports_nothing(self):
        assert not Identification.NONE.can_support_full_standing

    def test_each_grade_describes_itself(self):
        for grade in Identification:
            assert len(grade.describe()) > 40

    def test_the_proof_keys_are_data(self):
        assert set(PROOF_KEYS) == {Identification.CONTENT_DIGEST,
                                   Identification.PLATFORM_IDENTITY,
                                   Identification.ACCOUNT,
                                   Identification.ASSERTED_NAME}
        assert all(keys for keys in PROOF_KEYS.values())


# ── an entry ─────────────────────────────────────────────────────────────────

class TestVerifierEntry:

    def test_an_entry_needs_an_id_and_a_verifier(self):
        with pytest.raises(VettingError, match="needs an id"):
            entry(entry_id=" ")
        with pytest.raises(VettingError, match="must name the verifier"):
            entry(verifier_id="")

    def test_trust_requires_a_named_decider(self):
        """`TrustDecision` has refused to exist without one since §10d."""
        with pytest.raises(VettingError, match="requires a TrustDecision"):
            entry(decision="ACCEPTED")
        with pytest.raises(Exception):
            decision(decided_by="")

    def test_identity_evidence_must_say_what_kind_it_is(self):
        with pytest.raises(VettingError, match="without saying what kind"):
            entry(identification=Identification.NONE, identified_by=(PROVER,))

    def test_an_entry_that_can_only_be_matched_by_name_is_refused(self):
        with pytest.raises(VettingError, match="must not be matched"):
            entry(identification=Identification.CONTENT_DIGEST, identified_by=())

    def test_a_digest_that_cannot_be_compared_pins_nothing(self):
        with pytest.raises(VettingError, match="not a content identifier"):
            entry(identified_by=("trusted-prover-v3",))

    def test_a_window_that_never_opens_is_refused(self):
        with pytest.raises(VettingError, match="never opens"):
            entry(valid_from="2027-01-01T00:00:00Z", valid_until="2026-01-01T00:00:00Z")

    def test_a_name_is_never_identity_evidence(self):
        """The whole anti-squatting property, at the level it is enforced."""
        vetted = entry()
        assert vetted.recognises([PROVER])
        assert not vetted.recognises(["tool://trusted-prover"])
        assert not vetted.recognises([])
        assert not vetted.recognises([OTHER])

    def test_matching_ignores_case_and_padding_but_not_content(self):
        vetted = entry(identification=Identification.PLATFORM_IDENTITY,
                       identified_by=(WORKFLOW,))
        assert vetted.recognises([f"  {WORKFLOW.upper()}  "])
        assert not vetted.recognises([WORKFLOW + "x"])

    def test_an_entry_serialises_its_grading(self):
        data = entry().to_dict()
        assert data["can_support_full_standing"] is True
        assert data["record_type"] == "verifier_entry"
        assert data["decision"]["decided_by"] == "security-eng@acme"


class TestTheWindow:

    def test_an_unstated_window_covers_everything_and_says_so(self):
        open_ended = entry(valid_from=None, valid_until=None)
        assert not open_ended.window_is_stated
        assert open_ended.covers(BEFORE) and open_ended.covers(AFTER)
        assert "does not lapse on its own" in open_ended.window_basis

    def test_a_stated_window_bounds_both_ends(self):
        bounded = entry()
        assert bounded.covers(IN_WINDOW)
        assert not bounded.covers(BEFORE)
        assert not bounded.covers(AFTER)
        assert "vetted from" in bounded.window_basis

    def test_a_missing_moment_is_refused_rather_than_replaced_with_now(self):
        """'When did this run' with no answer must be reported, not guessed away."""
        with pytest.raises(VettingError, match="needs a moment"):
            entry().covers(None)

    def test_withdrawal_is_a_judgement_and_not_a_date(self):
        assert entry(decision=decision(TrustStatus.REVOKED)).withdrawn
        assert entry(decision=decision(TrustStatus.REJECTED)).withdrawn
        assert not entry(decision=decision(TrustStatus.ACCEPTED)).withdrawn
        assert not entry(decision=decision(TrustStatus.PROVISIONAL)).withdrawn


# ── consulting ───────────────────────────────────────────────────────────────

class TestConsultWithNoRegistry:

    def test_no_registry_means_unvetted_and_not_rejected(self):
        result = consult(None, verifier_id="tool://anything")
        assert result.standing is VerifierStanding.UNVETTED
        assert "no vetting registry is configured" in result.why

    def test_an_empty_registry_reads_the_same_way(self):
        result = consult(empty_registry(), verifier_id="tool://anything")
        assert result.standing is VerifierStanding.UNVETTED

    def test_absence_from_a_list_nobody_wrote_says_nothing(self):
        assert "says nothing" in consult(None, verifier_id="x").why


class TestNameSquatting:
    """The attack the registry is shaped to refuse."""

    def test_the_vetted_name_alone_buys_nothing(self):
        result = consult(registry(), verifier_id="tool://trusted-prover",
                         identity_values=(), as_of=IN_WINDOW)
        assert result.standing is VerifierStanding.UNVETTED
        assert not result.standing.relied_on

    def test_the_reason_distinguishes_squatting_from_being_unknown(self):
        """Two different UNVETTEDs: named-but-unproven, and not named at all."""
        squatted = consult(registry(), verifier_id="tool://trusted-prover",
                           as_of=IN_WINDOW)
        unknown = consult(registry(), verifier_id="tool://nobody-mentioned",
                          as_of=IN_WINDOW)
        assert "would hand a vetting to whoever typed it" in squatted.why
        assert "CONTENT_DIGEST expected" in squatted.why
        assert "records no decision" in unknown.why
        assert "nobody looked" in unknown.why

    def test_the_wrong_digest_does_not_match_either(self):
        result = consult(registry(), verifier_id="tool://trusted-prover",
                         identity_values=(OTHER,), as_of=IN_WINDOW)
        assert result.standing is VerifierStanding.UNVETTED

    def test_the_real_digest_does(self):
        result = consult(registry(), verifier_id="tool://trusted-prover",
                         identity_values=(PROVER,), as_of=IN_WINDOW,
                         as_of_basis=OWN_CLOCK)
        assert result.standing is VerifierStanding.VETTED
        assert result.identification is Identification.CONTENT_DIGEST
        assert result.entry_id == "e-prover"


class TestTheTemporalAnswers:

    def test_a_check_inside_the_window_is_vetted(self):
        assert consult(registry(), verifier_id="x", identity_values=(PROVER,),
                       as_of=IN_WINDOW, as_of_basis=OWN_CLOCK
                       ).standing is VerifierStanding.VETTED

    def test_a_check_outside_the_window_has_lapsed_rather_than_failed(self):
        result = consult(registry(), verifier_id="x", identity_values=(PROVER,),
                         as_of=AFTER, as_of_basis=OWN_CLOCK)
        assert result.standing is VerifierStanding.LAPSED
        assert "checks inside the window keep their standing" in result.why

    def test_expiry_does_not_reach_backwards(self):
        """A lapse means nobody alleged anything, so earlier checks stand."""
        lapsed_now = consult(registry(), verifier_id="x", identity_values=(PROVER,),
                             as_of=AFTER, as_of_basis=OWN_CLOCK)
        earlier = consult(registry(), verifier_id="x", identity_values=(PROVER,),
                          as_of=IN_WINDOW, as_of_basis=OWN_CLOCK)
        assert lapsed_now.standing is VerifierStanding.LAPSED
        assert earlier.standing is VerifierStanding.VETTED

    def test_revocation_does_reach_backwards(self):
        """A judgement about the verifier applies to everything it ever said."""
        revoked = registry(entry(decision=decision(
            TrustStatus.REVOKED, basis="signing key compromised")))
        result = consult(revoked, verifier_id="x", identity_values=(PROVER,),
                         as_of=BEFORE, as_of_basis=OWN_CLOCK)
        assert result.standing is VerifierStanding.WITHDRAWN
        assert "before the decision" in result.why

    def test_a_withdrawal_outranks_an_acceptance_that_also_matched(self):
        both = VettingRegistry()
        both.register(entry(entry_id="e-ok", decision=decision()))
        both.register(entry(entry_id="e-bad",
                            decision=decision(TrustStatus.REVOKED)))
        result = consult(both, verifier_id="x", identity_values=(PROVER,),
                         as_of=IN_WINDOW)
        assert result.standing is VerifierStanding.WITHDRAWN
        assert result.entry_id == "e-bad"

    def test_an_unknown_moment_is_provisional_and_named_as_such(self):
        result = consult(registry(), verifier_id="x", identity_values=(PROVER,),
                         as_of=None)
        assert result.standing is VerifierStanding.PROVISIONAL
        assert "nothing records when the check ran" in result.why

    def test_a_producer_clock_bounds_the_standing(self):
        """A lapsed vetting must not be resurrected by a backdated timestamp."""
        result = consult(registry(), verifier_id="x", identity_values=(PROVER,),
                         as_of=IN_WINDOW, as_of_basis=PRODUCER_CLOCK)
        assert result.standing is VerifierStanding.PROVISIONAL
        assert result.rests_on_a_producer_clock
        assert "could supply an earlier one" in result.why

    def test_an_unstated_window_is_provisional_because_nobody_will_revisit_it(self):
        open_ended = registry(entry(valid_from=None, valid_until=None))
        result = consult(open_ended, verifier_id="x", identity_values=(PROVER,),
                         as_of=IN_WINDOW, as_of_basis=OWN_CLOCK)
        assert result.standing is VerifierStanding.PROVISIONAL
        assert "revisit this decision" in result.why


class TestTheDecisionItself:

    def test_an_asserted_identifier_never_reaches_full_standing(self):
        """A lab vetted on a contract, matched on a number anybody can type."""
        lab = registry(entry(
            entry_id="e-lab", verifier_id="lab://acme-assays",
            kind=VerifierKind.LABORATORY,
            identification=Identification.ASSERTED_NAME,
            identified_by=("ISO17025-8823",),
            valid_from=None, valid_until=None,
            decision=decision(basis="accredited, under contract",
                              decided_by="quality@acme")))
        result = consult(lab, verifier_id="lab://acme-assays",
                         identity_values=("ISO17025-8823",), as_of=IN_WINDOW,
                         as_of_basis=OWN_CLOCK)
        assert result.standing is VerifierStanding.PROVISIONAL
        assert result.standing.relied_on
        assert "anybody who can type it" in result.why

    def test_a_decision_short_of_accepted_is_not_nobody_looking(self):
        careful = registry(entry(decision=decision(
            TrustStatus.PROVISIONAL, basis="pilot only, not yet reviewed")))
        result = consult(careful, verifier_id="x", identity_values=(PROVER,),
                         as_of=IN_WINDOW)
        assert result.standing is VerifierStanding.PROVISIONAL
        assert "stopped short" in result.why

    def test_not_established_recorded_deliberately_is_still_a_record(self):
        looked = registry(entry(decision=decision(TrustStatus.NOT_ESTABLISHED,
                                                  basis="review never finished")))
        result = consult(looked, verifier_id="x", identity_values=(PROVER,),
                         as_of=IN_WINDOW)
        assert result.standing is VerifierStanding.PROVISIONAL
        assert result.entry_id == "e-prover"


class TestConsultationGuards:

    def test_a_consultation_must_say_what_it_rests_on(self):
        with pytest.raises(VettingError, match="must say what it rests on"):
            Consultation(verifier_id="x", standing=VerifierStanding.UNVETTED, why="")

    def test_any_standing_but_unvetted_must_cite_its_entry(self):
        with pytest.raises(VettingError, match="must cite the entry"):
            Consultation(verifier_id="x", standing=VerifierStanding.VETTED,
                         identification=Identification.CONTENT_DIGEST,
                         why="because")

    def test_vetted_cannot_rest_on_a_name_anybody_can_type(self):
        with pytest.raises(VettingError, match="cannot rest on ASSERTED_NAME"):
            Consultation(verifier_id="x", standing=VerifierStanding.VETTED,
                         identification=Identification.ASSERTED_NAME,
                         entry_id="e", why="because")

    def test_only_vetted_and_provisional_are_relied_on(self):
        relied = [s for s in VerifierStanding if s.relied_on]
        assert set(relied) == {VerifierStanding.VETTED, VerifierStanding.PROVISIONAL}

    def test_each_standing_describes_itself(self):
        for standing in VerifierStanding:
            assert len(standing.describe()) > 40


class TestWhatVettingIsNot:
    """Trust is about whom to rely on, never about whether they were right."""

    def _all(self):
        return (consult(None, verifier_id="x"),
                consult(registry(), verifier_id="x", identity_values=(PROVER,),
                        as_of=IN_WINDOW, as_of_basis=OWN_CLOCK),
                consult(registry(entry(decision=decision(TrustStatus.REVOKED))),
                        verifier_id="x", identity_values=(PROVER,), as_of=IN_WINDOW))

    def test_it_never_establishes_correctness(self):
        assert all(c.establishes_correctness is False for c in self._all())

    def test_it_never_upgrades_epistemic_status(self):
        """A vetted verifier's DECLARED result is still DECLARED."""
        assert all(c.upgrades_epistemic_status is False for c in self._all())

    def test_the_refusals_survive_serialisation(self):
        data = self._all()[1].to_dict()
        assert data["establishes_correctness"] is False
        assert data["upgrades_epistemic_status"] is False

    def test_a_report_changes_no_result(self):
        assert VettingReport().changes_any_result is False
        assert VettingReport(registry_configured=True).changes_any_result is False

    def test_a_report_is_not_an_inventory_of_who_verified(self):
        assert VettingReport().is_a_completeness_claim is False


# ── reading an attempt ───────────────────────────────────────────────────────

class TestIdentityValuesOfAnAttempt:

    def test_the_conventional_keys_are_read(self):
        found = identity_values_of(Attempt(detail={
            "verifier_digest": PROVER, "workflow_identity": WORKFLOW}))
        assert set(found) == {PROVER, WORKFLOW}

    def test_the_verifier_name_is_never_included(self):
        """The one field an attacker fully controls."""
        found = identity_values_of(Attempt(verifier="tool://trusted-prover"))
        assert found == ()

    def test_a_non_mapping_detail_yields_nothing(self):
        assert identity_values_of(Attempt(detail="proved")) == ()

    def test_duplicates_collapse(self):
        found = identity_values_of(Attempt(detail={
            "verifier_digest": PROVER, "tool_digest": PROVER}))
        assert found == (PROVER,)

    def test_blank_values_are_skipped(self):
        assert identity_values_of(Attempt(detail={"verifier_digest": "  "})) == ()


class TestConsultingAnAttempt:

    def test_release_gates_own_clock_is_named_as_such(self):
        result = consult_attempt(registry(), Attempt(
            stamped_on_arrival=True, detail={"verifier_digest": PROVER}))
        assert result.standing is VerifierStanding.VETTED
        assert not result.rests_on_a_producer_clock

    def test_a_producer_timestamp_is_named_as_such(self):
        result = consult_attempt(registry(), Attempt(
            stamped_on_arrival=False, detail={"verifier_digest": PROVER}))
        assert result.standing is VerifierStanding.PROVISIONAL
        assert result.rests_on_a_producer_clock

    def test_an_attempt_with_no_timestamp_reports_that(self):
        result = consult_attempt(registry(), Attempt(
            timestamp=None, detail={"verifier_digest": PROVER}))
        assert result.standing is VerifierStanding.PROVISIONAL
        assert "nothing records when this check ran" in result.as_of_basis


# ── the report ───────────────────────────────────────────────────────────────

class TestReport:

    def test_one_consultation_per_verifier(self):
        report = vetting_report(
            [Attempt(verifier="ci://pytest", verification_id=f"v{i}")
             for i in range(5)], registry())
        assert len(report) == 1

    def test_the_worst_standing_for_a_verifier_is_the_one_reported(self):
        """A withdrawal must not be hidden by a later matching check."""
        revoked = VettingRegistry()
        revoked.register(entry(entry_id="e-bad",
                               decision=decision(TrustStatus.REVOKED)))
        report = vetting_report(
            [Attempt(verification_id="v1", stamped_on_arrival=True,
                     detail={"verifier_digest": PROVER}),
             Attempt(verification_id="v2", stamped_on_arrival=True, detail={})],
            revoked)
        assert len(report) == 1
        assert report.consultations[0].standing is VerifierStanding.WITHDRAWN

    def test_no_registry_produces_no_coverage_rows(self):
        """A case with no registry is exactly what it was before this module."""
        report = vetting_report([Attempt()], None)
        assert not report.registry_configured
        assert report.expectations() == ()
        assert "no registry is configured" in report.render()

    def test_an_empty_registry_produces_no_rows_either(self):
        assert vetting_report([Attempt()], empty_registry()).expectations() == ()

    def test_a_registry_turns_unvetted_into_a_finding(self):
        """The point of the module: a denominator makes an omission detectable."""
        rows = vetting_report([Attempt(verifier="tool://nobody-mentioned")],
                              registry()).expectations()
        assert [r.dimension for r in rows] == ["vetting.unvetted_verifiers"]
        assert rows[0].assessed is False
        ledger = CoverageLedger(rows=rows)
        assert (ledger.of("vetting.unvetted_verifiers").state
                is CoverageState.NOT_ASSESSED)

    def test_many_unvetted_verifiers_share_one_row_and_are_all_named(self):
        """One dimension per concern; `CoverageLedger.of` returns the first match."""
        rows = vetting_report(
            [Attempt(verifier="tool://a", verification_id="v1"),
             Attempt(verifier="tool://b", verification_id="v2")],
            registry()).expectations()
        assert len(rows) == 1
        assert "tool://a" in rows[0].note and "tool://b" in rows[0].note

    def test_a_withdrawn_verifier_gets_its_own_row(self):
        revoked = registry(entry(decision=decision(TrustStatus.REVOKED)))
        rows = vetting_report([Attempt(stamped_on_arrival=True,
                                       detail={"verifier_digest": PROVER})],
                              revoked).expectations()
        dims = [r.dimension for r in rows]
        assert "vetting.withdrawn.tool://trusted-prover" in dims

    def test_a_lapsed_check_gets_its_own_row(self):
        rows = vetting_report([Attempt(timestamp=AFTER, stamped_on_arrival=True,
                                       detail={"verifier_digest": PROVER})],
                              registry()).expectations()
        assert any(d.startswith("vetting.lapsed.") for d in
                   [r.dimension for r in rows])

    def test_a_fully_vetted_case_costs_no_coverage(self):
        report = vetting_report([Attempt(stamped_on_arrival=True,
                                         detail={"verifier_digest": PROVER})],
                                registry())
        assert report.expectations() == ()
        assert len(report.relied_on) == 1

    def test_the_render_names_the_registry_source_and_the_refusal(self):
        text = vetting_report([Attempt(stamped_on_arrival=True,
                                       detail={"verifier_digest": PROVER})],
                              registry()).render()
        assert "ops/vetting.yaml" in text
        assert "does not say" in text and "never upgrades what was DECLARED" in text

    def test_producer_clock_standings_are_counted(self):
        report = vetting_report([Attempt(detail={"verifier_digest": PROVER})],
                                registry())
        assert len(report.on_a_producer_clock) == 1
        assert "producer's own timestamp" in report.render()

    def test_a_report_serialises(self):
        data = vetting_report([Attempt()], registry()).to_dict()
        assert data["record_type"] == "vetting_report"
        assert data["changes_any_result"] is False
        assert data["by_standing"] == {"UNVETTED": 1}


class TestRegistryMechanics:

    def test_a_duplicate_entry_id_is_refused(self):
        built = registry()
        with pytest.raises(VettingError, match="already registered"):
            built.register(entry())

    def test_only_entries_can_be_registered(self):
        with pytest.raises(VettingError, match="only a VerifierEntry"):
            VettingRegistry().register({"entry_id": "x"})

    def test_reading_the_registry_by_verifier_is_not_matching(self):
        """For an operator asking what we say about a tool, never for standing."""
        built = registry()
        assert [e.entry_id for e in built.for_verifier("tool://trusted-prover")] == [
            "e-prover"]
        assert built.for_verifier("tool://other") == ()

    def test_the_registry_records_where_it_came_from(self):
        assert registry().to_dict()["source"] == "ops/vetting.yaml"
        assert registry().to_dict()["ships_trusted_vendors"] is False


# ── against a real case ──────────────────────────────────────────────────────

class TestAgainstARealCase:

    def _outcome(self):
        from release_gate.assurance.chaos import _assure, _base
        return _assure([dict(r) for r in _base()])

    def test_attempts_are_gathered_from_both_places_they_live(self):
        """Half the case vetted, silently, would be the worst kind of report."""
        outcome = self._outcome()
        found = attempts_in(outcome)
        graph = outcome.analysis.verification_graph
        assert len(found) >= len(graph.attempts)
        assert all(getattr(a, "verifier", None) is not None for a in found)

    def test_a_real_case_with_no_registry_reports_nothing(self):
        report = report_for(self._outcome(), None)
        assert report.expectations() == ()
        assert not report.registry_configured

    def test_a_real_case_with_a_registry_names_its_unvetted_verifiers(self):
        report = report_for(self._outcome(), registry())
        assert report.registry_configured
        unvetted = report.in_standing(VerifierStanding.UNVETTED)
        assert unvetted
        assert all(not c.standing.relied_on for c in unvetted)

    def test_the_report_is_derived_and_so_changes_no_digest(self):
        """`optional` is structural here: nothing consults a registry during assurance."""
        outcome = self._outcome()
        before = outcome.case.case_digest
        report_for(outcome, registry())
        assert outcome.case.case_digest == before

    def test_an_evidence_record_can_carry_a_vetted_producer_without_a_registry(self):
        """Nothing about this module is required to build a case."""
        record = EvidenceRecord(
            evidence_type=EvidenceType.TEST_RESULT, source="ci",
            producer=Producer(producer_id="ci://pytest", kind=ProducerKind.TOOL))
        assert record.trust is None
