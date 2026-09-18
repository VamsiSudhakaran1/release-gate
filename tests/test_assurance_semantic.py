"""Model-assisted semantic processing: proposals that never become decisions.

Four threads carry this file.

A proposal must be checkable — it names the model, the version, and the records
the model was shown, and a proposal without that last part is refused at
construction rather than by convention.

A proposal must not act. `applied` is unconditionally False at every
disposition, including the one where a deterministic check agreed, because what
was confirmed there is that two methods agree — not that the thing is so.

Confidence must stay inert. A model saying 0.99 and the same model saying 0.01
must produce identical findings, identical verdicts and identical fact sheets,
and there must be no ordering over proposals for a "best candidate" to emerge
from.

And a methodology must say explicitly whether a model's reading counts as
verification. Silence used to mean yes: `accepted_verification_types` empty
meant "any method" and `CROSS_MODEL_REVIEW` is a method, so every methodology
that had never considered models was crediting them.
"""

from __future__ import annotations

import dataclasses

import pytest

from release_gate.assurance.evidence import EpistemicStatus, ProducerKind
from release_gate.assurance.independence import analyse_independence
from release_gate.assurance.methodologies import SOFTWARE_AGENT_ASSURANCE_V1 as SW
from release_gate.assurance.methodology import (
    MODEL_VERIFICATION_METHODS, ModelVerificationStance, VerificationPresent)
from release_gate.assurance.quality import EvidenceFact, facts_for
from release_gate.assurance.semantic import (
    DETERMINISTIC_COUNTERPART, DeterministicOutcome, ProposalDisposition,
    SemanticError, SemanticProposal, SemanticTask, deterministic_first,
    model_identity, proposals_to_records)
from release_gate.assurance.session import AssuranceSession
from release_gate.assurance.verifiers import ToolFamily, ToolIdentity

MODEL = model_identity("some-classifier", version="2026-04")

RECORDS = [
    {"record_type": "claim", "claim_id": "c1",
     "proposition": "the refund path cannot double-charge",
     "producer": {"producer_id": "agent://a", "kind": "agent"},
     "supporting_evidence": ["e1"]},
    {"record_type": "claim", "claim_id": "c2",
     "proposition": "the refund path cannot double-charge",
     "producer": {"producer_id": "agent://b", "kind": "agent"}},
    {"record_type": "claim", "claim_id": "c3",
     "proposition": "refunds are never issued twice for one order",
     "producer": {"producer_id": "agent://c", "kind": "agent"}},
    {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
     "producer": {"producer_id": "ci://pytest", "kind": "tool"},
     "supports_claims": ["c1"], "coverage_note": "suite green"},
]


@pytest.fixture
def outcome():
    return AssuranceSession.open(methodology=SW).extend(list(RECORDS)).finalize()


def external_evidence_id(outcome):
    """The first record the independence analysis actually counts.

    It excludes release-gate's own records, so a proposal pointed at the input
    artifact release-gate hashed becomes its own lineage — correct, and not what
    a test about model echo chambers means to measure.
    """
    return next(r.evidence_id for r in outcome.normalisation.evidence
                if r.producer.kind is not ProducerKind.RELEASE_GATE)


def proposal(task, subjects, **kwargs):
    kwargs.setdefault("read_from", ("ev_something",))
    return SemanticProposal(task=task, model=MODEL, subjects=subjects, **kwargs)


# ── a proposal must be checkable ────────────────────────────────────────────

def test_a_proposal_carries_model_and_version_provenance():
    made = proposal(SemanticTask.SUMMARISATION, ("c1",))
    assert made.model.name == "some-classifier"
    assert made.model.version == "2026-04"
    assert made.model.reference == "some-classifier@2026-04"
    assert made.model.family is ToolFamily.LANGUAGE_MODEL
    # Asserted, not established: a model name in a payload is a claim about which
    # model ran, and release-gate did not watch it run.
    assert made.model.established is False
    assert made.to_dict()["model_identity_established"] is False


def test_a_proposal_that_names_nothing_it_read_is_refused():
    with pytest.raises(SemanticError, match="read_from is required"):
        SemanticProposal(task=SemanticTask.EXPLANATION, model=MODEL,
                         read_from=(), subjects=("c1",))


def test_a_proposal_without_a_model_identity_is_refused():
    with pytest.raises(SemanticError, match="must name the model"):
        SemanticProposal(task=SemanticTask.EXPLANATION, model="some-classifier",
                         read_from=("ev_1",), subjects=("c1",))


def test_a_confirmed_or_rejected_proposal_names_who_decided():
    for disposition in (ProposalDisposition.CONFIRMED_BY_HUMAN,
                        ProposalDisposition.REJECTED):
        with pytest.raises(SemanticError, match="requires disposed_by"):
            proposal(SemanticTask.EXPLANATION, ("c1",), disposition=disposition)
    accepted = proposal(SemanticTask.EXPLANATION, ("c1",),
                        disposition=ProposalDisposition.CONFIRMED_BY_HUMAN,
                        disposed_by="human://alice")
    assert accepted.disposed_by == "human://alice"


def test_identical_proposals_collide_and_a_disposition_does_not_change_the_id():
    one = proposal(SemanticTask.DUPLICATE_CANDIDATE, ("c1", "c2"), rationale="same")
    two = proposal(SemanticTask.DUPLICATE_CANDIDATE, ("c1", "c2"), rationale="same")
    assert one.proposal_id == two.proposal_id
    disposed = one.dispose(ProposalDisposition.CONFIRMED_BY_HUMAN, by="human://alice")
    assert disposed.proposal_id == one.proposal_id, (
        "a reviewer quoting an id must still be quoting the thing they approved")


# ── a proposal must not act ─────────────────────────────────────────────────

@pytest.mark.parametrize("disposition", list(ProposalDisposition))
def test_a_proposal_is_never_applied_at_any_disposition(disposition):
    kwargs = {"disposition": disposition}
    if disposition in (ProposalDisposition.CONFIRMED_BY_HUMAN,
                       ProposalDisposition.REJECTED):
        kwargs["disposed_by"] = "human://alice"
    made = proposal(SemanticTask.CLAIM_CLUSTERING, ("c1", "c3"), **kwargs)
    assert made.applied is False
    assert made.establishes_truth is False
    assert made.to_dict()["applied"] is False


def test_there_is_no_disposition_meaning_applied_automatically():
    values = {d.value for d in ProposalDisposition}
    assert not any("APPLIED" in v or "AUTO" in v for v in values)


def test_a_clustering_proposal_does_not_make_two_claims_equivalent(outcome):
    """`equivalent_to` is declared, never inferred — including by a model."""
    made = deterministic_first(
        proposal(SemanticTask.CLAIM_CLUSTERING, ("c1", "c3"),
                 read_from=(external_evidence_id(outcome),)),
        case=outcome.case, analysis=outcome.analysis)
    assert made.deterministic is DeterministicOutcome.EXTENDS
    for record in outcome.case.records("claims"):
        assert not record.to_dict().get("equivalent_to")


# ── confidence stays inert ──────────────────────────────────────────────────

def test_confidence_is_recorded_and_declared_non_authoritative():
    made = proposal(SemanticTask.SUMMARISATION, ("c1",),
                    model_reported_confidence=0.97)
    assert made.model_reported_confidence == 0.97
    assert made.confidence_is_authoritative is False
    assert made.to_dict()["confidence_is_authoritative"] is False
    assert "reads nothing from it" in made.note()


def test_a_confidence_outside_its_own_range_is_a_malformed_record():
    with pytest.raises(SemanticError, match="outside 0..1"):
        proposal(SemanticTask.SUMMARISATION, ("c1",), model_reported_confidence=1.4)


def test_confidence_moves_no_verdict_no_finding_and_no_fact(outcome):
    root = external_evidence_id(outcome)

    def fingerprint(confidence):
        made = proposal(SemanticTask.EVIDENCE_RETRIEVAL, ("c1",), read_from=(root,),
                        model_reported_confidence=confidence)
        extra = proposals_to_records([made])
        run = AssuranceSession.open(methodology=SW).extend(
            list(RECORDS) + [r.to_dict() for r in extra]).finalize()
        sheet = facts_for("claim:c1", case=run.case, analysis=run.analysis)
        return (run.decision,
                tuple(sorted((r.requirement_id, r.outcome.value)
                             for r in run.assessment.results)),
                tuple(sorted((f.fact.value, f.state.value) for f in sheet.findings)))

    assert fingerprint(0.01) == fingerprint(0.99)


def test_there_is_no_ordering_over_proposals_for_a_best_candidate_to_emerge():
    low = proposal(SemanticTask.DUPLICATE_CANDIDATE, ("c1", "c2"),
                   model_reported_confidence=0.2)
    high = proposal(SemanticTask.DUPLICATE_CANDIDATE, ("c1", "c3"),
                    model_reported_confidence=0.99)
    with pytest.raises(TypeError):
        low < high          # noqa: B015 — asserting the ordering does not exist
    for attribute in ("rank", "score", "best", "top", "priority"):
        assert not hasattr(high, attribute)


# ── the deterministic path runs first ───────────────────────────────────────

def test_every_task_states_whether_a_deterministic_counterpart_exists():
    assert set(DETERMINISTIC_COUNTERPART) == set(SemanticTask)
    for task, counterpart in DETERMINISTIC_COUNTERPART.items():
        assert counterpart.note, f"{task} says nothing about its structural limits"
        if counterpart.available:
            assert counterpart.mechanism


def test_the_three_tasks_with_no_counterpart_say_so(outcome):
    for task in (SemanticTask.CLAIM_EXTRACTION, SemanticTask.EXPLANATION,
                 SemanticTask.SUMMARISATION):
        made = deterministic_first(proposal(task, ("c1",)), case=outcome.case,
                                   analysis=outcome.analysis)
        assert made.deterministic is DeterministicOutcome.NO_COUNTERPART
        assert made.awaiting_disposition


def test_exact_duplicates_are_found_structurally_and_the_proposal_agrees(outcome):
    made = deterministic_first(
        proposal(SemanticTask.DUPLICATE_CANDIDATE, ("c1", "c2")),
        case=outcome.case, analysis=outcome.analysis)
    assert made.deterministic is DeterministicOutcome.AGREES
    assert made.disposition is ProposalDisposition.CONFIRMED_DETERMINISTICALLY
    # Confirmed that two methods agree — not that the thing is so.
    assert made.establishes_truth is False
    assert made.applied is False


def test_a_meaning_duplicate_extends_past_what_structure_can_see(outcome):
    made = deterministic_first(
        proposal(SemanticTask.DUPLICATE_CANDIDATE, ("c1", "c3")),
        case=outcome.case, analysis=outcome.analysis)
    assert made.deterministic is DeterministicOutcome.EXTENDS
    assert made.awaiting_disposition, "reaching past structure is not confirmation"
    assert "cannot see whether they mean the same thing" in made.deterministic_detail


def test_retrieval_agrees_where_the_declared_index_already_links(outcome):
    linked = deterministic_first(
        proposal(SemanticTask.EVIDENCE_RETRIEVAL, ("c1",)),
        case=outcome.case, analysis=outcome.analysis)
    assert linked.deterministic is DeterministicOutcome.AGREES

    unlinked = deterministic_first(
        proposal(SemanticTask.EVIDENCE_RETRIEVAL, ("c3",)),
        case=outcome.case, analysis=outcome.analysis)
    assert unlinked.deterministic is DeterministicOutcome.EXTENDS


def test_a_contradiction_candidate_is_measured_against_structural_detection():
    records = [
        {"record_type": "claim", "claim_id": "c1", "proposition": "p",
         "producer": {"producer_id": "agent://a", "kind": "agent"},
         "supporting_evidence": ["e1"], "contradicting_evidence": ["e2"]},
        {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://x", "kind": "tool"},
         "supports_claims": ["c1"], "coverage_note": "suite"},
        {"record_type": "evidence", "evidence_id": "e2", "kind": "OBSERVATION",
         "producer": {"producer_id": "agent://a", "kind": "agent"},
         "contradicts_claims": ["c1"], "coverage_note": "double-fires"},
    ]
    run = AssuranceSession.open(methodology=SW).extend(records).finalize()
    made = deterministic_first(
        proposal(SemanticTask.CONTRADICTION_CANDIDATE, ("c1",)),
        case=run.case, analysis=run.analysis)
    assert made.deterministic is DeterministicOutcome.AGREES
    assert "structural detection already holds an open contradiction" in (
        made.deterministic_detail)


# ── entering the case ───────────────────────────────────────────────────────

def test_a_proposal_enters_as_derived_evidence_through_the_one_model_seam():
    records = proposals_to_records([proposal(SemanticTask.SUMMARISATION, ("c1",))])
    assert len(records) == 1
    record = records[0]
    assert record.epistemic_status is EpistemicStatus.DERIVED
    assert not record.is_verification
    assert record.producer.model == "some-classifier@2026-04"
    assert record.content["semantic_proposal"]["applied"] is False


def test_the_records_the_model_read_become_its_ancestry(outcome):
    root = external_evidence_id(outcome)
    record = proposals_to_records(
        [proposal(SemanticTask.EVIDENCE_RETRIEVAL, ("c1",), read_from=(root,))])[0]
    assert record.parent_evidence == (root,)


def test_forty_confident_readings_of_one_source_are_one_lineage(outcome):
    """The echo chamber, in the one place it would be easiest to build.

    A model can produce readings as fast as anyone wants them. If each arrived as
    its own root, forty runs over one artifact would read as forty independent
    validations — which is the failure independence analysis exists to catch
    (Invariant 6), arriving through a door this module opened.
    """
    root = external_evidence_id(outcome)
    made = [proposal(SemanticTask.EVIDENCE_RETRIEVAL, ("c1",), read_from=(root,),
                     rationale=f"reading {i}", model_reported_confidence=0.99)
            for i in range(40)]
    records = proposals_to_records(made)
    profile = analyse_independence(
        list(outcome.normalisation.evidence) + records)
    assert profile.independent_roots == 1
    assert profile.records_examined == 41


# ── a methodology must say so explicitly ────────────────────────────────────

def test_silence_no_longer_means_a_models_reading_counts():
    assert SW.model_verification is ModelVerificationStance.UNSTATED
    assert SW.admits("CROSS_MODEL_REVIEW") is False
    assert "unstated position" in SW.model_verification_note


def test_an_accepting_methodology_credits_it_and_a_refusing_one_does_not():
    accepting = dataclasses.replace(
        SW, version="9.9.9", model_verification=ModelVerificationStance.ACCEPTED)
    assert accepting.admits("CROSS_MODEL_REVIEW") is True

    refusing = dataclasses.replace(
        SW, version="9.9.9", model_verification=ModelVerificationStance.REJECTED)
    assert refusing.admits("CROSS_MODEL_REVIEW") is False
    # Same answer as silence, different fact about the methodology.
    assert refusing.model_verification_note != SW.model_verification_note


def test_the_stance_is_covered_by_the_digest():
    changed = dataclasses.replace(
        SW, model_verification=ModelVerificationStance.ACCEPTED)
    assert changed.digest != SW.digest, (
        "a stance that could be flipped without changing the digest would be a "
        "standard nobody could pin")


def test_an_extension_inherits_the_parents_stance():
    refusing = dataclasses.replace(
        SW, model_verification=ModelVerificationStance.REJECTED)
    child = refusing.extend(methodology_id="child", version="1.0.0")
    assert child.model_verification is ModelVerificationStance.REJECTED


def test_a_requirement_naming_no_methods_does_not_credit_a_models_review():
    predicate = VerificationPresent()
    assert predicate.methods == ()
    assert "except a model's review" in predicate.describe()


def test_the_model_method_set_is_named_not_inferred():
    assert MODEL_VERIFICATION_METHODS == frozenset({"CROSS_MODEL_REVIEW"})


def test_a_proposal_submitted_over_the_wire_arrives_weaker_not_stronger():
    """DERIVED in process, DECLARED over the envelope, and that is correct.

    `epistemic_status` is a field a producer may not set, so the same content
    posted as JSON is a declaration. A reader could easily take this for a bug
    and route around it; the direction is what matters — a model's output can
    lose standing crossing the boundary, never gain it.
    """
    record = proposals_to_records([proposal(SemanticTask.SUMMARISATION, ("c1",))])[0]
    assert record.epistemic_status is EpistemicStatus.DERIVED

    run = AssuranceSession.open(methodology=SW).extend(
        list(RECORDS) + [record.to_dict()]).finalize()
    landed = [r.to_dict() for r in run.case.records("evidence")
              if r.to_dict().get("evidence_type") == "CLAIM_DERIVATION"]
    assert landed, "the proposal did not reach the case at all"
    assert landed[0]["epistemic_status"] == EpistemicStatus.DECLARED.value


def test_the_proposal_actually_reaches_the_case(outcome):
    """Guards the confidence-invariance test above from passing vacuously."""
    root = external_evidence_id(outcome)
    extra = proposals_to_records(
        [proposal(SemanticTask.EVIDENCE_RETRIEVAL, ("c1",), read_from=(root,))])
    run = AssuranceSession.open(methodology=SW).extend(
        list(RECORDS) + [r.to_dict() for r in extra]).finalize()
    assert (len(run.case.records("evidence"))
            > len(outcome.case.records("evidence")))
