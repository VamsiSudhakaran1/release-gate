"""Contradictions, kept.

The failure this guards against is quiet: evidence points both ways, a confident
summary is produced, and the disagreement never reaches the person signing.
Nothing is falsified; something is just not mentioned. Most of these tests try to
make that happen and are stopped.
"""

import json

import pytest

from release_gate.assurance.analysis import AnalysisDomain
from release_gate.assurance.attention import AttentionReason
from release_gate.assurance.case import (
    AssuranceCaseBuilder, CaseType, CaseValidationError, CaseVerdict, Decision,
)
from release_gate.assurance.claims import Claim, ClaimGraph
from release_gate.assurance.contradiction import (
    Contradiction,
    ContradictionError,
    ContradictionKind,
    ContradictionLedger,
    ContradictionSide,
    ContradictionStatus,
    detect_contradictions,
)
from release_gate.assurance.evidence import (
    EvidenceRecord, EvidenceType, Producer, ProducerKind,
)
from release_gate.assurance.methodology import (
    ALL_CASE_TYPES, AssuranceMethodology, NoUnresolved, Requirement,
    RequirementEffect, RequirementOutcome,
)
from release_gate.assurance.records import Presence, SimpleRecord
from release_gate.assurance.subject import (
    AssuranceSubject, ContentReference, DigestMethod, DigestStatus, ReferenceKind,
    SubjectType,
)
from release_gate.assurance.zero_config import assure, render_text


def ev(producer, *, supports=(), contradicts=(), parents=(), note=""):
    return EvidenceRecord.declared(
        EvidenceType.OTHER, source="s",
        producer=Producer(producer_id=producer, kind=ProducerKind.AGENT),
        supports_claims=tuple(supports), contradicts_claims=tuple(contradicts),
        parent_evidence=tuple(parents), content={"n": note})


def contradiction(**kwargs):
    kwargs.setdefault("target_claims", ("cl_root",))
    kwargs.setdefault("sides", (ContradictionSide(label="a", evidence=("ev_1",)),
                                ContradictionSide(label="b", evidence=("ev_2",))))
    return Contradiction(**kwargs)


def _write(tmp_path, name, rows):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(path)


DISAGREEMENT = [
    {"record_type": "claim", "claim_id": "cl_root",
     "proposition": "the migration applies without data loss", "is_root": True,
     "producer": {"producer_id": "agent://planner", "kind": "agent"},
     "supporting_evidence": ["ev_sim"], "contradicting_evidence": ["ev_fuzz"]},
    {"record_type": "evidence", "evidence_id": "ev_sim", "kind": "SIMULATION_RESULT",
     "producer": {"producer_id": "ci://sim/44", "kind": "tool"},
     "supports_claims": ["cl_root"]},
    {"record_type": "evidence", "evidence_id": "ev_fuzz", "kind": "COUNTEREXAMPLE",
     "producer": {"producer_id": "fuzz://2", "kind": "tool"},
     "contradicts_claims": ["cl_root"]},
]


# ── closing one requires saying what closed it ───────────────────────────────

class TestCannotBeClosedSilently:

    def test_resolved_requires_a_resolution(self):
        with pytest.raises(ContradictionError, match="state its resolution"):
            contradiction(status=ContradictionStatus.RESOLVED,
                          resolution_evidence=("ev_9",))

    def test_resolved_requires_resolution_evidence(self):
        with pytest.raises(ContradictionError, match="resolution_evidence"):
            contradiction(status=ContradictionStatus.RESOLVED,
                          resolution="the fuzz case was a bad fixture")

    def test_invalid_requires_a_reason(self):
        with pytest.raises(ContradictionError, match="say why"):
            contradiction(status=ContradictionStatus.INVALID)

    def test_superseded_requires_a_reason(self):
        with pytest.raises(ContradictionError, match="say why"):
            contradiction(status=ContradictionStatus.SUPERSEDED)

    def test_resolve_carries_both(self):
        closed = contradiction().resolve("the fixture was wrong", ("ev_9",))
        assert closed.status is ContradictionStatus.RESOLVED
        assert closed.resolution_evidence == ("ev_9",)
        assert closed.resolved is True

    def test_a_contradiction_must_name_what_it_is_about(self):
        with pytest.raises(ContradictionError, match="name what it is about"):
            Contradiction(target_claims=())

    def test_the_id_survives_resolution(self):
        """A reviewer shown an id must still find it after someone closes it."""
        original = contradiction()
        assert original.resolve("r", ("ev_9",)).contradiction_id \
            == original.contradiction_id

    def test_invalidating_records_who_said_so(self):
        dismissed = contradiction().invalidate("the two claims are about different rows")
        assert dismissed.status is ContradictionStatus.INVALID
        assert "different rows" in dismissed.resolution


# ── the statuses ─────────────────────────────────────────────────────────────

class TestStatuses:

    def test_all_five_exist(self):
        assert {s.value for s in ContradictionStatus} == {
            "OPEN", "RESOLVED", "SUPERSEDED", "INVALID", "UNKNOWN"}

    def test_unknown_counts_as_open(self):
        """'We cannot tell whether this stands' is not a closed contradiction."""
        pending = contradiction(status=ContradictionStatus.UNKNOWN)
        assert pending.is_open is True
        assert pending.resolved is False

    def test_superseded_and_invalid_are_closed(self):
        for status in (ContradictionStatus.SUPERSEDED, ContradictionStatus.INVALID):
            closed = contradiction(status=status, resolution="because")
            assert closed.is_open is False

    def test_open_is_the_default(self):
        assert contradiction().status is ContradictionStatus.OPEN


# ── the eight fields ─────────────────────────────────────────────────────────

class TestRecordShape:

    def test_every_named_field_is_present(self):
        payload = contradiction().to_dict()
        for name in ("contradiction_id", "target_claims", "evidence_on_each_side",
                     "participants", "independent_roots", "resolution",
                     "resolution_evidence", "status"):
            assert name in payload, name

    def test_participants_are_the_union_of_both_sides(self):
        both = contradiction(sides=(
            ContradictionSide(label="a", participants=("x", "y")),
            ContradictionSide(label="b", participants=("y", "z"))))
        assert both.participants == ("x", "y", "z")

    def test_independent_roots_span_the_whole_disagreement(self):
        both = contradiction(sides=(
            ContradictionSide(label="a", roots=("r1",), independent_roots=1),
            ContradictionSide(label="b", roots=("r2",), independent_roots=1)))
        assert both.independent_roots == 2

    def test_a_side_derives_its_lineage_from_the_evidence(self):
        root = ev("upstream://1")
        derived = [ev(f"agent://{i}", parents=(root.evidence_id,), note=str(i))
                   for i in range(5)]
        side = ContradictionSide.from_evidence("supports", [root] + derived)
        assert side.independent_roots == 1
        assert len(side.participants) == 6

    def test_a_one_sided_lineage_is_flagged_without_being_judged(self):
        root = ev("upstream://1")
        a = ev("x://1", parents=(root.evidence_id,))
        b = ev("y://1", parents=(root.evidence_id,))
        both = contradiction(sides=(
            ContradictionSide.from_evidence("a", [root, a]),
            ContradictionSide.from_evidence("b", [root, b])))
        assert both.one_sided_lineage is True

    def test_it_round_trips(self):
        original = contradiction(detail="d")
        restored = Contradiction.from_dict(json.loads(json.dumps(original.to_dict())))
        assert restored.contradiction_id == original.contradiction_id

    def test_more_roots_on_one_side_does_not_settle_it(self):
        """Counting is inert here: more sources is not more true."""
        heavy = [ev(f"a://{i}", note=str(i)) for i in range(9)]
        light = [ev("b://1")]
        both = contradiction(sides=(
            ContradictionSide.from_evidence("supports", heavy),
            ContradictionSide.from_evidence("contradicts", light)))
        assert both.status is ContradictionStatus.OPEN
        blob = json.dumps(both.to_dict()).lower()
        for banned in ("winner", "prevails", "likely", "confidence", "probability"):
            assert banned not in blob, banned


# ── detection ────────────────────────────────────────────────────────────────

class TestDetection:

    def _graph(self, **kwargs):
        claim = Claim(claim_id="cl_root", statement="p", is_root=True,
                      producer=Producer(producer_id="agent://x"), **kwargs)
        return ClaimGraph([claim])

    def test_evidence_both_ways_on_one_claim(self):
        records = [ev("a://1", supports=("cl_root",)),
                   ev("b://1", contradicts=("cl_root",))]
        ledger = detect_contradictions(claim_graph=self._graph(), evidence=records)
        assert len(ledger) == 1
        assert ledger.contradictions[0].kind is ContradictionKind.CLAIM_EVIDENCE_CONFLICT

    def test_support_alone_is_not_a_contradiction(self):
        records = [ev("a://1", supports=("cl_root",))]
        assert len(detect_contradictions(claim_graph=self._graph(),
                                         evidence=records)) == 0

    def test_a_record_cannot_be_built_arguing_with_itself(self):
        """The constructor refuses it, which is why the ingest splits instead."""
        from release_gate.assurance.evidence import EvidenceError

        with pytest.raises(EvidenceError, match="both supports and contradicts"):
            ev("a://1", supports=("cl_root",), contradicts=("cl_root",))

    def test_a_root_claim_is_critical(self):
        records = [ev("a://1", supports=("cl_root",)),
                   ev("b://1", contradicts=("cl_root",))]
        ledger = detect_contradictions(claim_graph=self._graph(), evidence=records)
        assert ledger.contradictions[0].affects_critical is True
        assert "root claim" in ledger.contradictions[0].critical_basis

    def test_a_load_bearing_claim_is_critical(self):
        leaf = Claim(claim_id="cl_leaf", statement="q",
                     producer=Producer(producer_id="agent://x"))
        root = Claim(claim_id="cl_root", statement="p", is_root=True,
                     parents=("cl_leaf",),
                     producer=Producer(producer_id="agent://x"))
        graph = ClaimGraph([leaf, root])
        records = [ev("a://1", supports=("cl_leaf",)),
                   ev("b://1", contradicts=("cl_leaf",))]
        ledger = detect_contradictions(claim_graph=graph, evidence=records)
        target = next(c for c in ledger if "cl_leaf" in c.target_claims)
        assert target.affects_critical is True

    def test_an_uncritical_claim_is_not_marked(self):
        plain = Claim(claim_id="cl_side", statement="q",
                      producer=Producer(producer_id="agent://x"))
        records = [ev("a://1", supports=("cl_side",)),
                   ev("b://1", contradicts=("cl_side",))]
        ledger = detect_contradictions(claim_graph=ClaimGraph([plain]),
                                       evidence=records)
        assert ledger.contradictions[0].affects_critical is False

    def test_detection_is_deterministic(self):
        records = [ev("a://1", supports=("cl_root",)),
                   ev("b://1", contradicts=("cl_root",))]
        first = detect_contradictions(claim_graph=self._graph(), evidence=records)
        second = detect_contradictions(claim_graph=self._graph(), evidence=records)
        assert first.digest() == second.digest()


# ── the ledger ───────────────────────────────────────────────────────────────

class TestLedger:

    def test_critical_and_open_sort_first(self):
        ledger = ContradictionLedger([
            contradiction(target_claims=("cl_a",)),
            contradiction(target_claims=("cl_b",)).mark_critical("root"),
        ])
        assert ledger.contradictions[0].affects_critical is True

    def test_unresolved_critical_is_the_set_that_matters(self):
        ledger = ContradictionLedger([
            contradiction(target_claims=("cl_a",)).mark_critical("root"),
            contradiction(target_claims=("cl_b",)).mark_critical("root")
                .resolve("answered", ("ev_9",)),
        ])
        assert len(ledger.unresolved_critical()) == 1

    def test_resolving_returns_a_new_ledger(self):
        original = ContradictionLedger([contradiction()])
        target = original.contradictions[0]
        updated = original.with_resolution(
            target.contradiction_id, target.resolve("answered", ("ev_9",)))
        assert original.contradictions[0].is_open is True
        assert updated.contradictions[0].is_open is False

    def test_nothing_is_ever_dropped(self):
        original = ContradictionLedger([contradiction()])
        target = original.contradictions[0]
        updated = original.with_resolution(
            target.contradiction_id, target.invalidate("not a real conflict"))
        assert len(updated) == 1, "a dismissed contradiction stays on the record"

    def test_by_claim_finds_them(self):
        ledger = ContradictionLedger([contradiction(target_claims=("cl_x",))])
        assert len(ledger.by_claim("cl_x")) == 1
        assert len(ledger.by_claim("cl_other")) == 0


# ── the verdict may not omit one ─────────────────────────────────────────────

class TestVerdictCannotOmit:

    def _case(self, *contradictions):
        reference = ContentReference(kind=ReferenceKind.INLINE, locator="x",
                                     detail={"inline": "x"})
        subject = AssuranceSubject(
            subject_type=SubjectType.GENERAL_RESULT, requested_action="ship",
            content_reference=reference, digest="sha256:" + "a" * 64,
            digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED, digest_basis="test")
        builder = AssuranceCaseBuilder(
            case_type=CaseType.GENERAL_DECISION, objective="o",
            requested_decision="d", subject=subject)
        builder.collection("coverage")
        builder.add("coverage", SimpleRecord(record_type="coverage",
                                             record_id="cov_1",
                                             payload={"dimension": "overall"}))
        builder.declare_present("contradictions", "test")
        builder.extend("contradictions", contradictions)
        return builder.build().seal()

    def test_an_open_critical_contradiction_must_be_named(self):
        open_one = contradiction().mark_critical("a root claim")
        case = self._case(open_one)
        with pytest.raises(CaseValidationError, match="not named in this verdict"):
            case.render_verdict(CaseVerdict(decision=Decision.PROMOTE,
                                            fired_rules=("something.else",)))

    def test_naming_it_is_enough_to_proceed(self):
        """The engine does not decide for anyone; it forbids only the silence."""
        open_one = contradiction().mark_critical("a root claim")
        case = self._case(open_one)
        decided = case.render_verdict(CaseVerdict(
            decision=Decision.PROMOTE,
            fired_rules=("something.else", open_one.contradiction_id)))
        assert decided.verdict.decision is Decision.PROMOTE

    def test_naming_it_in_the_reasons_also_counts(self):
        open_one = contradiction().mark_critical("a root claim")
        case = self._case(open_one)
        decided = case.render_verdict(CaseVerdict(
            decision=Decision.HOLD, fired_rules=("r",),
            reasons=(f"{open_one.contradiction_id}: still contested",)))
        assert decided.verdict is not None

    def test_a_resolved_contradiction_need_not_be_named(self):
        closed = contradiction().mark_critical("a root claim").resolve("x", ("ev_9",))
        case = self._case(closed)
        assert case.render_verdict(CaseVerdict(decision=Decision.PROMOTE,
                                               fired_rules=("r",))) is not None

    def test_an_uncritical_open_contradiction_need_not_be_named(self):
        case = self._case(contradiction())
        assert case.render_verdict(CaseVerdict(decision=Decision.PROMOTE,
                                               fired_rules=("r",))) is not None

    def test_other_record_shapes_are_unaffected(self):
        reference = ContentReference(kind=ReferenceKind.INLINE, locator="x",
                                     detail={"inline": "x"})
        subject = AssuranceSubject(
            subject_type=SubjectType.GENERAL_RESULT, requested_action="ship",
            content_reference=reference, digest="sha256:" + "a" * 64,
            digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED, digest_basis="t")
        builder = AssuranceCaseBuilder(
            case_type=CaseType.GENERAL_DECISION, objective="o",
            requested_decision="d", subject=subject)
        builder.collection("coverage")
        builder.add("coverage", SimpleRecord(record_type="coverage", record_id="c",
                                             payload={"dimension": "overall"}))
        builder.declare_present("contradictions", "t")
        builder.add("contradictions", SimpleRecord(record_type="note", record_id="n",
                                                   payload={"x": 1}))
        case = builder.build().seal()
        assert case.render_verdict(CaseVerdict(decision=Decision.PROMOTE,
                                               fired_rules=("r",))) is not None


# ── the existing predicate still reads these ─────────────────────────────────

class TestPredicateCompatibility:

    def test_no_unresolved_reads_a_contradiction_object(self, tmp_path):
        methodology = AssuranceMethodology(
            methodology_id="no-open", version="1.0.0", domain="test",
            case_types=ALL_CASE_TYPES, description="no open contradictions",
            requirements=(Requirement(
                requirement_id="contradictions.resolved",
                description="no unresolved contradictions",
                predicate=NoUnresolved(collection="contradictions"),
                effect=RequirementEffect.BLOCK,
                remedy="resolve them"),))
        path = _write(tmp_path, "d.jsonl", DISAGREEMENT)
        outcome = assure(path, methodology=methodology)
        result = outcome.assessment.results[0]
        assert result.outcome is RequirementOutcome.UNSATISFIED
        assert result.observed["unresolved"] >= 1

    def test_resolved_is_derived_never_stored(self):
        """A caller cannot mark one resolved without moving its status."""
        payload = contradiction().to_dict()
        assert payload["resolved"] is False
        payload["resolved"] = True
        assert Contradiction.from_dict(payload).resolved is False


# ── the pipeline ─────────────────────────────────────────────────────────────

class TestPipeline:

    @pytest.fixture
    def disagreement(self, tmp_path):
        return _write(tmp_path, "d.jsonl", DISAGREEMENT)

    def test_the_disagreement_is_detected(self, disagreement):
        ledger = assure(disagreement).contradictions
        assert len(ledger.unresolved_critical()) == 1

    def test_the_verdict_names_it(self, disagreement):
        outcome = assure(disagreement)
        identifier = outcome.contradictions.unresolved_critical()[0].contradiction_id
        spoken = " ".join(outcome.case.verdict.fired_rules
                          + outcome.case.verdict.reasons)
        assert identifier in spoken

    def test_it_is_surfaced_before_anything_else(self, disagreement):
        text = render_text(assure(disagreement))
        assert "UNRESOLVED DISAGREEMENT" in text
        assert text.index("UNRESOLVED DISAGREEMENT") < text.index("WHAT WAS ASSESSED")

    def test_the_report_shows_both_sides(self, disagreement):
        text = render_text(assure(disagreement))
        assert "supports:" in text and "contradicts:" in text

    def test_it_becomes_an_attention_item(self, disagreement):
        reasons = {i.reason for i in assure(disagreement).attention}
        assert AttentionReason.UNRESOLVED_DISAGREEMENT in reasons

    def test_a_finding_carries_it_too(self, disagreement):
        finding = next(f for f in assure(disagreement).analysis.findings
                       if f.rule_id == "RG-CONTRA-005")
        assert finding.domain is AnalysisDomain.CONTRADICTION
        assert finding.effect is RequirementEffect.HOLD

    def test_contradictions_land_on_the_case_as_objects(self, disagreement):
        records = [r.to_dict() for r in assure(disagreement).case.records("contradictions")]
        assert any(r.get("record_type") == "contradiction" for r in records)

    def test_contradiction_coverage_is_stated(self, disagreement):
        rows = [r.to_dict() for r in assure(disagreement).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "contradiction")
        assert row["status"] == "NOT_ASSESSED"
        assert row["unresolved_critical"] == 1

    def test_coverage_never_claims_semantic_completeness(self, disagreement):
        rows = [r.to_dict() for r in assure(disagreement).case.records("coverage")]
        row = next(r for r in rows if r["dimension"] == "contradiction")
        assert "semantic disagreement is not assessed" in row["note"]

    def test_a_clean_case_records_none(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "cl_root", "proposition": "p",
                 "is_root": True,
                 "producer": {"producer_id": "agent://x", "kind": "agent"},
                 "supporting_evidence": ["ev_1"]},
                {"record_type": "evidence", "evidence_id": "ev_1",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "ci://1", "kind": "tool"},
                 "supports_claims": ["cl_root"]}]
        outcome = assure(_write(tmp_path, "clean.jsonl", rows))
        assert len(outcome.contradictions) == 0

    def test_the_outcome_serialises(self, disagreement):
        payload = json.loads(json.dumps(assure(disagreement).to_dict()))
        assert payload["contradictions"]["unresolved_critical"] == 1


class TestSelfConflictIsSplitNotDropped:
    """The ingest used to reject such a record entirely, losing the disagreement."""

    @pytest.fixture
    def self_conflicted(self, tmp_path):
        rows = [{"record_type": "claim", "claim_id": "cl_root", "proposition": "p",
                 "is_root": True,
                 "producer": {"producer_id": "agent://x", "kind": "agent"}},
                {"record_type": "evidence", "evidence_id": "ev_both",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "ci://1", "kind": "tool"},
                 "supports_claims": ["cl_root"], "contradicts_claims": ["cl_root"]}]
        return _write(tmp_path, "self.jsonl", rows)

    def test_the_record_is_not_dropped(self, self_conflicted):
        from release_gate.assurance.ingest import ingest_path

        normalisation = ingest_path(self_conflicted)
        assert normalisation.skipped == {}

    def test_it_becomes_two_halves(self, self_conflicted):
        from release_gate.assurance.ingest import ingest_path

        normalisation = ingest_path(self_conflicted)
        halves = [r for r in normalisation.evidence
                  if dict(r.content or {}).get("split_from_self_conflict")]
        assert len(halves) == 2
        assert {dict(h.content)["split_side"] for h in halves} == {"supports",
                                                                   "contradicts"}

    def test_the_disagreement_survives_as_a_contradiction(self, self_conflicted):
        ledger = assure(self_conflicted).contradictions
        assert len(ledger.unresolved_critical()) == 1

    def test_it_is_labelled_as_one_producer_not_two_parties(self, self_conflicted):
        found = assure(self_conflicted).contradictions.contradictions[0]
        assert found.kind is ContradictionKind.RECORD_SELF_CONFLICT
        assert found.participants == ("ci://1",)

    def test_the_split_is_recorded_in_the_notes(self, self_conflicted):
        from release_gate.assurance.ingest import ingest_path

        notes = " ".join(ingest_path(self_conflicted).notes)
        assert "split into its two halves" in notes
