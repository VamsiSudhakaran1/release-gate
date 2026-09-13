"""ClaimGraph — what is being asserted, and how well each assertion stands.

The properties under test: status is computed rather than declared, a conclusion
never outranks its assumptions, failed attempts stay and count, and no model
touches the authoritative path.
"""

import json

import pytest

from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
from release_gate.assurance.claims import (
    AttemptOutcome,
    Claim,
    ClaimEdgeType,
    ClaimError,
    ClaimGraph,
    ClaimProvenance,
    ClaimStatus,
    ClaimType,
    VerificationAttempt,
)
from release_gate.assurance.evidence import (
    EvidenceRecord,
    EvidenceType,
    Producer,
    ProducerKind,
    VerificationMethod,
)
from release_gate.assurance.records import SimpleRecord
from release_gate.assurance.subject import AssuranceSubject, SubjectType

DIGEST = "sha256:" + "a" * 64
AGENT = Producer("agent://planner/7", ProducerKind.AGENT, identity_basis="none")
PROVER = Producer("prover://lean/1", ProducerKind.TOOL, identity_basis="in-process")


def _declared(claim_ids=(), contradicts=(), **kw):
    return EvidenceRecord.declared(
        EvidenceType.OTHER, source="agent-log", producer=AGENT,
        supports_claims=tuple(claim_ids), contradicts_claims=tuple(contradicts), **kw)


def _verified(claim_ids=(), contradicts=(), producer=PROVER, **kw):
    kw.setdefault("method", VerificationMethod.THEOREM_PROVER)
    kw.setdefault("coverage_note", "checks the stated lemma only")
    return EvidenceRecord.verification(
        EvidenceType.FORMAL_PROOF, source="lean", producer=producer,
        applies_to_digest=DIGEST, supports_claims=tuple(claim_ids),
        contradicts_claims=tuple(contradicts), **kw)


def _graph(claims, *records, resolved=()):
    return ClaimGraph(claims, {r.evidence_id: r for r in records},
                      resolved_contradictions=resolved)


def _attempt(outcome, evidence_id="ev_x"):
    return VerificationAttempt(evidence_id=evidence_id,
                               method=VerificationMethod.THEOREM_PROVER, outcome=outcome)


# ── the taxonomies ──────────────────────────────────────────────────────────

def test_all_contract_statuses_exist():
    assert {s.value for s in ClaimStatus} == {
        "UNVERIFIED", "PARTIALLY_VERIFIED", "VERIFIED", "DISPUTED", "REFUTED",
        "UNKNOWN", "SUPERSEDED"}


def test_a_claim_must_state_something():
    with pytest.raises(ClaimError, match="must state something"):
        Claim("cl_1", "   ")


# ── status is computed, never declared ──────────────────────────────────────

def test_a_producer_supplied_status_is_ignored():
    document = Claim("cl_1", "the migration is safe").to_dict()
    document["status"] = "VERIFIED"
    rebuilt = Claim.from_dict(document)
    assert not hasattr(rebuilt, "status")
    assert _graph([rebuilt]).status("cl_1") is ClaimStatus.UNKNOWN


def test_no_evidence_means_unknown():
    graph = _graph([Claim("cl_1", "backward compatible")])
    assert graph.status("cl_1") is ClaimStatus.UNKNOWN
    assert "nothing on record" in graph.assessment("cl_1").basis


def test_an_agents_assertion_does_not_verify_its_own_claim():
    record = _declared(("cl_1",))
    graph = _graph([Claim("cl_1", "backward compatible")], record)
    assert graph.status("cl_1") is ClaimStatus.UNVERIFIED
    assert "none of it is a verification" in graph.assessment("cl_1").basis


def test_verified_evidence_verifies_a_claim():
    graph = _graph([Claim("cl_1", "lemma holds")], _verified(("cl_1",)))
    assert graph.status("cl_1") is ClaimStatus.VERIFIED


def test_a_claim_citing_absent_evidence_is_unknown_not_supported():
    graph = _graph([Claim("cl_1", "x", supporting_evidence=("ev_gone",))])
    assert graph.status("cl_1") is ClaimStatus.UNKNOWN
    assert any(a.kind == "MISSING_EVIDENCE" for a in graph.anomalies)


# ── a conclusion cannot outrank its assumptions ─────────────────────────────

def test_a_proof_resting_on_an_unproven_lemma_is_not_verified():
    root = Claim("cl_root", "Theorem T holds", ClaimType.CONCLUSION, is_root=True,
                 parents=("cl_lemma",))
    lemma = Claim("cl_lemma", "Lemma 887 holds", ClaimType.LEMMA)
    graph = _graph([root, lemma], _verified(("cl_root",)))
    assert graph.assessment("cl_root").direct_status is ClaimStatus.VERIFIED
    assert graph.status("cl_root") is ClaimStatus.UNKNOWN
    assert graph.assessment("cl_root").capped_by == ("cl_lemma",)


def test_verifying_the_lemma_lifts_the_conclusion():
    root = Claim("cl_root", "Theorem T holds", is_root=True, parents=("cl_lemma",))
    lemma = Claim("cl_lemma", "Lemma 887 holds", ClaimType.LEMMA)
    graph = _graph([root, lemma], _verified(("cl_root",)), _verified(("cl_lemma",)))
    assert graph.status("cl_root") is ClaimStatus.VERIFIED


def test_supporting_does_not_cap_the_way_depending_does():
    # The producer chooses the edge type, and the choice is visible rather than
    # inferred: corroboration is not the same as resting on something.
    depends = Claim("cl_a", "A", parents=("cl_weak",))
    supports = Claim("cl_b", "B", supports=("cl_weak",))
    weak = Claim("cl_weak", "W")
    graph = _graph([depends, supports, weak], _verified(("cl_a",)), _verified(("cl_b",)))
    assert graph.status("cl_a") is ClaimStatus.UNKNOWN
    assert graph.status("cl_b") is ClaimStatus.VERIFIED


def test_an_assumption_caps_like_a_parent():
    root = Claim("cl_root", "plan is sound", is_root=True, assumptions=("cl_assume",))
    assumption = Claim("cl_assume", "the contract permits transfer", ClaimType.ASSUMPTION)
    graph = _graph([root, assumption], _verified(("cl_root",)))
    assert graph.status("cl_root") is ClaimStatus.UNKNOWN
    assert graph.assumptions()[0].claim_id == "cl_assume"


def test_the_weakest_dependency_sets_the_ceiling():
    root = Claim("cl_root", "R", is_root=True, parents=("cl_ok", "cl_bad"))
    graph = _graph([root, Claim("cl_ok", "OK"), Claim("cl_bad", "BAD")],
                   _verified(("cl_root",)), _verified(("cl_ok",)),
                   _declared(contradicts=("cl_bad",)))
    assert graph.status("cl_bad") is ClaimStatus.REFUTED
    assert graph.status("cl_root") is ClaimStatus.REFUTED
    assert graph.assessment("cl_root").capped_by == ("cl_bad",)


def test_a_missing_dependency_caps_at_unknown_rather_than_being_ignored():
    root = Claim("cl_root", "R", is_root=True, parents=("cl_never_supplied",))
    graph = _graph([root], _verified(("cl_root",)))
    assert graph.status("cl_root") is ClaimStatus.UNKNOWN
    assert any(a.kind == "MISSING_DEPENDENCY" for a in graph.anomalies)


# ── contradictions and failed attempts (Invariant 7) ────────────────────────

def test_a_contradiction_with_no_support_refutes():
    graph = _graph([Claim("cl_1", "cost is $100")], _declared(contradicts=("cl_1",)))
    assert graph.status("cl_1") is ClaimStatus.REFUTED


def test_support_does_not_make_a_contradiction_go_away():
    # Only resolving a contradiction resolves it. A stronger verification
    # alongside it is a dispute, not a dismissal.
    graph = _graph([Claim("cl_1", "cost is $100")],
                   _verified(("cl_1",)), _declared(contradicts=("cl_1",)))
    assert graph.status("cl_1") is ClaimStatus.DISPUTED


def test_a_resolved_contradiction_is_discounted_but_retained():
    contradiction = _declared(contradicts=("cl_1",))
    graph = _graph([Claim("cl_1", "cost is $100")], _verified(("cl_1",)), contradiction,
                   resolved=(contradiction.evidence_id,))
    assert graph.status("cl_1") is ClaimStatus.VERIFIED
    assert graph.assessment("cl_1").contradicting == 1   # still on the record


def test_a_failed_verification_attempt_counts_as_a_refutation():
    claim = Claim("cl_1", "lemma holds",
                  verification_attempts=(_attempt(AttemptOutcome.FAILED),))
    graph = _graph([claim], _verified(("cl_1",)))
    assert graph.status("cl_1") is ClaimStatus.DISPUTED
    assert graph.assessment("cl_1").failed_attempts == 1


def test_passed_plus_inconclusive_is_partially_verified():
    claim = Claim("cl_1", "lemma holds", verification_attempts=(
        _attempt(AttemptOutcome.PASSED, "ev_1"),
        _attempt(AttemptOutcome.INCONCLUSIVE, "ev_2")))
    graph = _graph([claim])
    assert graph.status("cl_1") is ClaimStatus.PARTIALLY_VERIFIED


def test_all_attempts_passed_is_verified():
    claim = Claim("cl_1", "lemma holds", verification_attempts=(
        _attempt(AttemptOutcome.PASSED, "ev_1"), _attempt(AttemptOutcome.PASSED, "ev_2")))
    assert _graph([claim]).status("cl_1") is ClaimStatus.VERIFIED


def test_an_inconclusive_attempt_alone_leaves_the_claim_unverified():
    claim = Claim("cl_1", "lemma holds",
                  verification_attempts=(_attempt(AttemptOutcome.INCONCLUSIVE),))
    graph = _graph([claim])
    assert graph.status("cl_1") is ClaimStatus.UNVERIFIED
    assert graph.assessment("cl_1").inconclusive_attempts == 1


def test_failed_attempts_are_kept_on_the_claim():
    claim = Claim("cl_1", "x", verification_attempts=(
        _attempt(AttemptOutcome.FAILED, "ev_1"), _attempt(AttemptOutcome.PASSED, "ev_2")))
    assert len(_graph([claim]).claim("cl_1").verification_attempts) == 2


# ── supersession ────────────────────────────────────────────────────────────

def test_a_superseded_claim_is_marked_and_kept():
    old = Claim("cl_old", "cost is $100")
    new = Claim("cl_new", "cost is $400", supersedes="cl_old")
    graph = _graph([old, new], _verified(("cl_old",)))
    assert graph.status("cl_old") is ClaimStatus.SUPERSEDED
    assert graph.claim("cl_old") is not None


# ── no model in the authoritative path (Invariant 4) ────────────────────────

def test_a_model_extracted_claim_must_name_its_model():
    with pytest.raises(ClaimError, match="must name the model"):
        Claim("cl_1", "x", provenance=ClaimProvenance.DERIVED)


def test_model_extracted_claims_carry_derived_provenance_and_are_listed_apart():
    claim = Claim.model_extracted("cl_1", "the migration is reversible",
                                  model="some-extractor-v2")
    graph = _graph([claim])
    assert claim.provenance is ClaimProvenance.DERIVED
    assert graph.model_derived_claims() == (claim,)


def test_a_model_cannot_relabel_its_own_extraction_as_declared():
    with pytest.raises(ClaimError, match="carries\nDERIVED|carries DERIVED"):
        Claim("cl_1", "x", provenance=ClaimProvenance.DECLARED,
              extracted_by_model="some-extractor")


def test_model_asserted_equivalence_is_recorded_but_not_applied():
    # A model may propose that two statements mean the same thing; it may not
    # make them the same thing in a computation that gates a release.
    a = Claim("cl_a", "the index is concurrent")
    b = Claim.model_extracted("cl_b", "no table lock is taken", model="extractor-v2",
                              equivalent_to=("cl_a",))
    graph = _graph([a, b])
    assert graph.equivalence_classes() == ()
    assert graph.equivalence_classes(include_model_derived=True) == (("cl_a", "cl_b"),)


def test_declared_equivalence_is_applied():
    a = Claim("cl_a", "statement one")
    b = Claim("cl_b", "statement two", equivalent_to=("cl_a",))
    assert _graph([a, b]).equivalence_classes() == (("cl_a", "cl_b"),)


def test_claims_are_matched_by_id_and_nothing_else():
    # No fuzzy matching anywhere: two identically worded claims are two claims.
    a = Claim("cl_a", "the migration is backward compatible")
    b = Claim("cl_b", "the migration is backward compatible")
    graph = _graph([a, b], _verified(("cl_a",)))
    assert graph.status("cl_a") is ClaimStatus.VERIFIED
    assert graph.status("cl_b") is ClaimStatus.UNKNOWN


# ── load-bearing analysis ───────────────────────────────────────────────────

def test_load_bearing_is_everything_the_root_rests_on():
    root = Claim("cl_root", "R", is_root=True, parents=("cl_a",))
    graph = _graph([root, Claim("cl_a", "A", parents=("cl_b",)), Claim("cl_b", "B"),
                    Claim("cl_side", "unrelated")])
    assert graph.load_bearing() == ("cl_a", "cl_b")


def test_binding_constraints_are_the_ones_actually_holding_the_root_down():
    # The difference between "these matter" and "these three are why it is
    # not verified".
    root = Claim("cl_root", "R", is_root=True, parents=("cl_ok", "cl_open"))
    graph = _graph([root, Claim("cl_ok", "OK"), Claim("cl_open", "OPEN")],
                   _verified(("cl_root",)), _verified(("cl_ok",)))
    assert graph.status("cl_root") is ClaimStatus.UNKNOWN
    assert graph.binding_constraints() == ("cl_open",)


def test_a_counterfactual_says_what_settling_a_claim_would_change():
    root = Claim("cl_root", "R", is_root=True, parents=("cl_open",))
    graph = _graph([root, Claim("cl_open", "OPEN")], _verified(("cl_root",)))
    result = graph.counterfactual("cl_open")
    assert result["changes_root"] is True
    assert result["if_verified"] == "VERIFIED"
    assert result["if_refuted"] == "REFUTED"


def test_a_claim_nothing_rests_on_changes_nothing():
    root = Claim("cl_root", "R", is_root=True)
    graph = _graph([root, Claim("cl_side", "unrelated")], _verified(("cl_root",)))
    assert graph.counterfactual("cl_side")["changes_root"] is False


# ── structural safety ───────────────────────────────────────────────────────

def test_a_dependency_cycle_is_reported_and_grounds_nothing():
    claims = [Claim("cl_a", "A", parents=("cl_b",)), Claim("cl_b", "B", parents=("cl_a",))]
    graph = _graph(claims, _verified(("cl_a",)), _verified(("cl_b",)))
    assert any(a.kind == "DEPENDENCY_CYCLE" for a in graph.anomalies)
    assert graph.status("cl_a") is ClaimStatus.UNKNOWN


def test_a_claim_cannot_depend_on_itself():
    with pytest.raises(ClaimError, match="cannot depend on itself"):
        Claim("cl_a", "A", parents=("cl_a",))


def test_a_deep_dependency_chain_terminates():
    claims = [Claim("cl_0", "base")]
    claims += [Claim(f"cl_{i}", f"step {i}", parents=(f"cl_{i-1}",)) for i in range(1, 800)]
    graph = _graph(claims, _verified(("cl_0",)))
    assert len(graph.depends_closure("cl_799")) == 799
    assert graph.status("cl_799") is ClaimStatus.UNKNOWN   # only the base is verified


def test_verification_propagates_the_whole_way_up_a_chain():
    claims = [Claim("cl_0", "base")]
    claims += [Claim(f"cl_{i}", f"step {i}", parents=(f"cl_{i-1}",)) for i in range(1, 60)]
    records = [_verified((f"cl_{i}",)) for i in range(60)]
    graph = _graph(claims, *records)
    assert graph.status("cl_59") is ClaimStatus.VERIFIED


def test_evidence_can_both_support_one_claim_and_contradict_another():
    record = _verified(("cl_a",), contradicts=("cl_b",))
    graph = _graph([Claim("cl_a", "A"), Claim("cl_b", "B")], record)
    assert graph.status("cl_a") is ClaimStatus.VERIFIED
    assert graph.status("cl_b") is ClaimStatus.REFUTED


def test_a_claim_cannot_list_one_record_as_both():
    with pytest.raises(ClaimError, match="both supporting"):
        Claim("cl_1", "x", supporting_evidence=("ev_1",), contradicting_evidence=("ev_1",))


# ── optional for simple cases (Invariant 14) ────────────────────────────────

def _case(*claims, evidence=(), present=None):
    b = AssuranceCaseBuilder(
        case_type=CaseType.RESEARCH_RESULT, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("proof", SubjectType.RESEARCH_RESULT, "publish"))
    if present:
        b.declare_present("claims")
    for claim in claims:
        b.add("claims", claim)
    for record in evidence:
        b.add("evidence", record)
    return b.build()


def test_a_transactional_case_needs_no_claim_graph():
    b = AssuranceCaseBuilder(
        case_type=CaseType.DATA_CHANGE, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("x", SubjectType.DATA_CHANGE, "apply"))
    assert ClaimGraph.from_case(b.build()) is None


def test_a_case_that_declares_claims_gets_a_graph():
    graph = ClaimGraph.from_case(_case(Claim("cl_1", "something is asserted")))
    assert graph is not None and len(graph) == 1


def test_evidence_links_itself_to_claims_without_the_claim_knowing():
    record = _verified(("cl_1",))
    graph = ClaimGraph.from_case(_case(Claim("cl_1", "lemma holds"), evidence=[record]))
    assert graph.status("cl_1") is ClaimStatus.VERIFIED


def test_a_case_graph_says_what_it_could_not_model():
    b = AssuranceCaseBuilder(
        case_type=CaseType.RESEARCH_RESULT, objective="o", requested_decision="d",
        subject=AssuranceSubject.from_text("p", SubjectType.RESEARCH_RESULT, "publish"))
    b.add("claims", Claim("cl_1", "modelled"))
    b.add("claims", SimpleRecord("claim", "raw_1", {"statement": "not a Claim"}))
    for i in range(50):
        b.add("claims", Claim(f"cl_x{i}", f"claim {i}"), materialise=False)
    graph = ClaimGraph.from_case(b.build())
    notes = " ".join(graph.notes)
    assert "not Claims" in notes
    assert "50 claim(s) were counted but not materialised" in notes


# ── output ──────────────────────────────────────────────────────────────────

def test_the_summary_names_the_binding_constraints():
    root = Claim("cl_root", "R", is_root=True, parents=("cl_open",))
    graph = _graph([root, Claim("cl_open", "OPEN")], _verified(("cl_root",)))
    summary = graph.summary()
    assert summary["root_status"]["cl_root"] == "UNKNOWN"
    assert summary["binding_constraints"] == ["cl_open"]
    assert summary["by_status"]["UNKNOWN"] == 2


def test_the_graph_serialises_whole():
    graph = _graph([Claim("cl_1", "x")], _verified(("cl_1",)))
    payload = json.loads(json.dumps(graph.to_dict()))
    assert payload["schema_version"] == 1
    assert payload["assessments"][0]["effective_status"] == "VERIFIED"
    assert payload["digest"] == graph.digest()


def test_the_digest_does_not_depend_on_claim_order():
    claims = [Claim("cl_a", "A", parents=("cl_b",)), Claim("cl_b", "B")]
    records = [_verified(("cl_b",))]
    assert (_graph(claims, *records).digest()
            == _graph(list(reversed(claims)), *records).digest())


def test_a_dependency_declared_before_its_dependant_makes_no_difference():
    # Statuses relax to a fixed point, so declaration order cannot matter.
    forward = _graph([Claim("cl_a", "A", parents=("cl_b",)), Claim("cl_b", "B")],
                     _verified(("cl_a",)), _verified(("cl_b",)))
    reverse = _graph([Claim("cl_b", "B"), Claim("cl_a", "A", parents=("cl_b",))],
                     _verified(("cl_a",)), _verified(("cl_b",)))
    assert forward.status("cl_a") is reverse.status("cl_a") is ClaimStatus.VERIFIED


def test_an_unknown_claim_id_reports_unknown_rather_than_raising():
    assert _graph([Claim("cl_1", "x")]).status("cl_nope") is ClaimStatus.UNKNOWN


def test_the_frontier_shape_resolves_and_names_the_few_that_matter():
    # 3,114 lemmas, 2,996 machine-checked. A human needs the 118 that are not,
    # not the 2,996 that are.
    claims = [Claim("cl_root", "Theorem T holds", ClaimType.CONCLUSION, is_root=True,
                    parents=tuple(f"cl_l{i}" for i in range(3114)))]
    claims += [Claim(f"cl_l{i}", f"Lemma {i}", ClaimType.LEMMA) for i in range(3114)]
    records = [_verified((f"cl_l{i}",)) for i in range(2996)]

    graph = _graph(claims, *records)
    assert graph.status("cl_root") is ClaimStatus.UNKNOWN
    assert len(graph.load_bearing()) == 3114
    assert len(graph.binding_constraints()) == 118
    assert graph.summary()["by_status"]["VERIFIED"] == 2996
