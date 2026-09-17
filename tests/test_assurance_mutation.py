"""Result mutation detection: invalidate what changed, spare what provably did not.

The test that carries this file is the three-bucket one. Sorting verifications
into *invalidated* and *unaffected* is one bucket short, and the missing bucket
is the important one: a check that declared no dependencies cannot be shown to be
unaffected by anything, and calling it unaffected is how a stale verification
survives a mutation and goes on being counted as a passed check.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.methodologies import GENERAL_AUTONOMOUS_ACTION_V1 as PROFILE
from release_gate.assurance.mutation import (
    MUTATION_SCHEMA_VERSION, Affect, Dependency, DependencyIndex, DependencyKind,
    InvalidationReport, MutationError, MutationEvent, VerificationDependencies,
    dependencies_from_case,
)
from release_gate.assurance.session import AssuranceSession

def D(seed):
    """A distinct valid sha256 digest per seed. Padded, not repeated: `str(99) * 64`
    is 128 characters and the constructor rightly refuses it."""
    return "sha256:" + str(seed).rjust(64, "0")


def deps(verification_id, *pairs, verifier="v"):
    return VerificationDependencies(
        verification_id=verification_id, verifier=verifier,
        dependencies=tuple(Dependency(kind, logical_id, digest)
                           for kind, logical_id, digest in pairs))


@pytest.fixture
def index():
    return DependencyIndex([
        deps("v_proof", (DependencyKind.PROOF, "thm-7", D(1)), verifier="lean"),
        deps("v_data", (DependencyKind.DATASET, "corpus-v3", D(2)), verifier="eval"),
        deps("v_code", (DependencyKind.CODE, "app/run.py", D(3)),
             (DependencyKind.CONFIGURATION, "prod.toml", D(4)), verifier="ci"),
        deps("v_both", (DependencyKind.DATASET, "corpus-v3", D(2)),
             (DependencyKind.CODE, "app/run.py", D(3)), verifier="ci"),
        VerificationDependencies("v_silent", (), verifier="mystery-tool"),
    ])


DATASET_CHANGED = MutationEvent("corpus-v3", DependencyKind.DATASET, D(2), D(9),
                                detail="regenerated after a labelling fix")


# ── the third bucket ────────────────────────────────────────────────────────

class TestUndeterminedIsNotUnaffected:

    def test_a_verification_that_declared_nothing_is_undetermined(self, index):
        report = index.apply([DATASET_CHANGED])
        undetermined = {r.verification_id for r in report.undetermined}
        assert undetermined == {"v_silent"}

    def test_it_is_not_reported_as_unaffected(self, index):
        report = index.apply([DATASET_CHANGED])
        assert "v_silent" not in {r.verification_id for r in report.unaffected}

    def test_it_is_not_invalidated_either(self, index):
        """Throwing away good work to avoid thinking is the other failure."""
        report = index.apply([DATASET_CHANGED])
        assert "v_silent" not in {r.verification_id for r in report.invalidated}

    def test_the_reason_says_it_is_unknown_not_fine(self, index):
        report = index.apply([DATASET_CHANGED])
        assert "not known to be unaffected" in report.undetermined[0].reason

    def test_one_silent_check_makes_the_whole_report_imprecise(self, index):
        assert not index.apply([DATASET_CHANGED]).precise

    def test_the_note_calls_the_blast_radius_a_lower_bound(self, index):
        assert "lower bound" in index.apply([DATASET_CHANGED]).note()

    def test_a_fully_declared_set_is_precise(self):
        index = DependencyIndex([
            deps("v1", (DependencyKind.DATASET, "corpus", D(2))),
            deps("v2", (DependencyKind.PROOF, "thm", D(1)))])
        assert index.apply([DATASET_CHANGED]).precise


# ── precision ───────────────────────────────────────────────────────────────

class TestOnlyTheAffected:

    def test_only_dependents_are_invalidated(self, index):
        report = index.apply([DATASET_CHANGED])
        assert {r.verification_id for r in report.invalidated} == {"v_data", "v_both"}

    def test_unrelated_work_is_left_alone(self, index):
        """Invalidating everything is safe and useless."""
        report = index.apply([DATASET_CHANGED])
        assert {r.verification_id for r in report.unaffected} == {"v_proof", "v_code"}

    def test_being_spared_is_justified_not_assumed(self, index):
        report = index.apply([DATASET_CHANGED])
        assert all("none of them changed" in r.reason for r in report.unaffected)

    def test_invalidation_names_what_hit_it(self, index):
        report = index.apply([DATASET_CHANGED])
        hit = next(r for r in report.invalidated if r.verification_id == "v_both")
        assert hit.via == ("corpus-v3",)
        assert "dataset" in hit.reason

    def test_a_second_mutation_widens_the_radius_precisely(self, index):
        report = index.apply([
            DATASET_CHANGED,
            MutationEvent("prod.toml", DependencyKind.CONFIGURATION, D(4), D(8))])
        assert {r.verification_id for r in report.invalidated} == \
            {"v_data", "v_both", "v_code"}
        assert {r.verification_id for r in report.unaffected} == {"v_proof"}

    @pytest.mark.parametrize("kind,logical_id,digest", [
        (DependencyKind.PROOF, "thm-7", 1),
        (DependencyKind.CODE, "app/run.py", 3),
        (DependencyKind.CONFIGURATION, "prod.toml", 4),
    ])
    def test_every_mutation_source_invalidates_its_own_dependents(
            self, index, kind, logical_id, digest):
        report = index.apply([MutationEvent(logical_id, kind, D(digest), D(99))])
        assert report.invalidated
        assert all(logical_id in r.via for r in report.invalidated)

    def test_a_digest_match_catches_a_renamed_dependency(self):
        """Logical id alone would miss a thing renamed between runs."""
        index = DependencyIndex([deps("v1", (DependencyKind.DATASET, "old-name", D(2)))])
        report = index.apply([MutationEvent("new-name", DependencyKind.DATASET,
                                            D(2), D(9))])
        assert report.invalidated

    def test_a_name_match_catches_a_mutation_with_no_previous_digest(self):
        """Digest alone would miss a change nobody recorded the old state of."""
        index = DependencyIndex([deps("v1", (DependencyKind.DATASET, "corpus", D(2)))])
        report = index.apply([MutationEvent("corpus", DependencyKind.DATASET,
                                            "", D(9))])
        assert report.invalidated


# ── nothing changed ─────────────────────────────────────────────────────────

class TestNoChange:

    def test_an_event_that_records_no_change_is_refused(self):
        """A mutation event with two identical digests would invalidate work for
        nothing."""
        with pytest.raises(MutationError, match="did not change"):
            MutationEvent("corpus", DependencyKind.DATASET, D(2), D(2))

    def test_no_events_invalidates_nothing(self, index):
        report = index.apply([])
        assert not report.invalidated and not report.results
        assert "Nothing changed" in report.note()

    def test_a_mutation_of_something_nobody_used_invalidates_nothing(self, index):
        report = index.apply([MutationEvent("unused.txt", DependencyKind.OTHER,
                                            D(5), D(6))])
        assert not report.invalidated
        assert len(report.unaffected) == 4


# ── declaring dependencies ──────────────────────────────────────────────────

class TestDependencyShape:

    def test_a_dependency_must_name_what_it_is(self):
        with pytest.raises(MutationError, match="anonymous digest"):
            Dependency(DependencyKind.DATASET, "  ", D(1))

    def test_a_dependency_without_a_digest_is_refused(self):
        """It could never be compared to anything and would silently never
        invalidate."""
        with pytest.raises(MutationError, match="content digest"):
            Dependency(DependencyKind.DATASET, "corpus", "v3")

    def test_all_six_prompt_sources_are_representable(self):
        for kind in (DependencyKind.PROOF, DependencyKind.DATASET,
                     DependencyKind.CODE, DependencyKind.CONFIGURATION,
                     DependencyKind.ANSWER, DependencyKind.ACTION_PAYLOAD):
            assert Dependency(kind, "x", D(1)).kind is kind

    def test_a_dependency_round_trips(self):
        dependency = Dependency(DependencyKind.ANSWER, "reply-9", D(1))
        assert Dependency.from_dict(dependency.to_dict()) == dependency

    def test_declared_is_the_field_everything_turns_on(self):
        assert deps("v", (DependencyKind.CODE, "x", D(1))).declared
        assert not VerificationDependencies("v", ()).declared


# ── reading a real case ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def case():
    records = [
        {"record_type": "claim", "claim_id": "C-1",
         "proposition": "model is accurate", "is_root": True,
         "producer": {"producer_id": "a://1", "kind": "agent"},
         "verification_attempts": [
             {"evidence_id": "e1", "method": "EXPERIMENT", "outcome": "PASSED",
              "target_digest": D(1), "verifier": "eval-harness",
              "result": {"dependencies": [
                  {"kind": "DATASET", "logical_id": "corpus-v3", "digest": D(2)},
                  {"kind": "CODE", "logical_id": "scorer.py", "digest": D(3)}]}},
             {"evidence_id": "e2", "method": "FORMAL_PROOF", "outcome": "PASSED",
              "target_digest": D(1), "verifier": "lean",
              "result": {"dependencies": [
                  {"kind": "PROOF", "logical_id": "thm-7", "digest": D(7)}]}}]},
        {"record_type": "evidence", "evidence_id": "e1",
         "kind": "EXPERIMENT_RESULT",
         "producer": {"producer_id": "eval://1", "kind": "tool"},
         "supports_claims": ["C-1"], "coverage_note": "eval"},
        {"record_type": "evidence", "evidence_id": "e2", "kind": "FORMAL_PROOF",
         "producer": {"producer_id": "lean://1", "kind": "tool"},
         "supports_claims": ["C-1"], "coverage_note": "proof"},
    ]
    return AssuranceSession.open(methodology=PROFILE).extend(records).finalize().case



class TestFromCase:

    def test_declared_dependencies_are_read_off_the_attempts(self, case):
        index = dependencies_from_case(case)
        assert len(index) == 2
        assert not index.undeclared

    def test_a_dataset_change_invalidates_only_the_eval(self, case):
        report = dependencies_from_case(case).apply([DATASET_CHANGED])
        assert len(report.invalidated) == 1
        assert report.invalidated[0].verifier == "eval-harness"
        assert report.unaffected[0].verifier == "lean"
        assert report.precise

    def test_the_target_becomes_a_dependency(self, case):
        report = dependencies_from_case(case).apply([
            MutationEvent("C-1", DependencyKind.TARGET, D(1), D(9))])
        assert len(report.invalidated) == 2

    def test_a_malformed_dependency_does_not_lose_the_others(self):
        records = [
            {"record_type": "claim", "claim_id": "C-1", "proposition": "x",
             "is_root": True, "producer": {"producer_id": "a://1", "kind": "agent"},
             "verification_attempts": [
                 {"evidence_id": "e1", "method": "TEST_SUITE", "outcome": "PASSED",
                  "target_digest": D(1), "verifier": "ci",
                  "result": {"dependencies": [
                      {"kind": "DATASET", "logical_id": "corpus", "digest": "nope"},
                      {"kind": "CODE", "logical_id": "run.py", "digest": D(3)}]}}]},
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
             "producer": {"producer_id": "ci://1", "kind": "tool"},
             "supports_claims": ["C-1"], "coverage_note": "suite"},
        ]
        case = AssuranceSession.open(methodology=PROFILE).extend(records).finalize().case
        index = dependencies_from_case(case)
        report = index.apply([MutationEvent("run.py", DependencyKind.CODE, D(3), D(9))])
        assert report.invalidated

    def test_a_case_with_no_attempts_yields_an_empty_index(self):
        case = AssuranceSession.open(methodology=PROFILE).extend([
            {"record_type": "evidence", "evidence_id": "e1", "kind": "TRACE",
             "producer": {"producer_id": "a://1", "kind": "agent"},
             "coverage_note": "x"}]).finalize().case
        assert len(dependencies_from_case(case)) == 0


# ── reporting ───────────────────────────────────────────────────────────────

class TestReport:

    def test_it_serialises_with_all_three_buckets(self, index):
        payload = index.apply([DATASET_CHANGED]).to_dict()
        assert payload["record_type"] == "invalidation_report"
        assert payload["schema_version"] == MUTATION_SCHEMA_VERSION
        for bucket in ("invalidated", "unaffected", "undetermined"):
            assert bucket in payload
        assert payload["precise"] is False

    def test_the_report_id_is_content_addressed(self, index):
        a = index.apply([DATASET_CHANGED])
        b = index.apply([DATASET_CHANGED])
        assert a.report_id == b.report_id

    def test_the_note_names_what_changed(self, index):
        assert "corpus-v3 changed" in index.apply([DATASET_CHANGED]).note()

    def test_the_index_does_not_scan_per_event(self, index):
        """Lookup is by digest and logical id, not a sweep of every verification
        for every change — the quadratic that turns a config change into a stall.
        """
        assert index.hit_by(DATASET_CHANGED) == {"v_data", "v_both"}
