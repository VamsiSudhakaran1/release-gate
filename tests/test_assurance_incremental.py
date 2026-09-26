"""Reuse that cannot change an answer, and the fork primitive underneath it.

Two things are being held here. First, that a reuse claim is refused unless it is
justified and keyed on everything it reads — the spec-and-key agreement is what
stops a stale result surviving a change. Second, and this is the one that would
actually hurt if it broke, that folding a prefix once and forking it produces
byte-identical commitments to folding everything three times. A reuse that moved
a `case_digest` would have moved what every approval binds to.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from release_gate.assurance.case import AssuranceCaseBuilder, CaseType
from release_gate.assurance.incremental import (
    SPECS, STAGES, Change, Delta, Equivalence, IncrementalCache, IncrementalError,
    IncrementalReport, Reuse, ReuseDecision, Stability, StageSpec, plan,
    result_digest, reuse_key, spec_for, verify_reuse,
)
from release_gate.assurance.records import (
    RecordCollectionBuilder, RecordError, SimpleRecord,
)
from release_gate.assurance.canonical import digest_bytes
from release_gate.assurance.evidence import ContentReference, ReferenceKind
from release_gate.assurance.subject import (
    AssuranceSubject, DigestMethod, DigestStatus, SubjectType,
)


def rec(i: int, payload: object = None) -> SimpleRecord:
    return SimpleRecord(record_type="evidence", record_id=f"e{i}",
                        payload={"i": i if payload is None else payload})


def subject() -> AssuranceSubject:
    return AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="ship it",
        content_reference=ContentReference(ReferenceKind.INLINE, "a-test-fixture"),
        digest=digest_bytes(b"a test fixture"),
        digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED,
        digest_basis="sha256 over a fixture's bytes")


# ── stability ────────────────────────────────────────────────────────────────

class TestStability:

    def test_only_append_stable_permits_reuse(self):
        assert Stability.APPEND_STABLE.reusable_on_append
        assert not Stability.RETRACTABLE.reusable_on_append

    def test_unknown_is_not_treated_as_the_convenient_case(self):
        """Invariant 3. An unestablished property is not a permissive one."""
        assert not Stability.UNKNOWN.reusable_on_append

    def test_every_stability_says_what_it_means(self):
        for stability in Stability:
            assert len(stability.describe()) > 40

    def test_an_append_stable_claim_must_be_justified(self):
        with pytest.raises(IncrementalError, match="must say what makes appending safe"):
            StageSpec(name="x", stability=Stability.APPEND_STABLE, reads=("records",))

    def test_a_retractable_stage_owes_no_argument(self):
        """Recomputation is the position that permits nothing, so it costs nothing."""
        spec = StageSpec(name="x", stability=Stability.RETRACTABLE, reads=("records",))
        assert spec.why == ""
        assert not spec.reusable_on_append

    def test_a_stage_must_declare_what_it_reads(self):
        with pytest.raises(IncrementalError, match="must declare what it reads"):
            StageSpec(name="x", stability=Stability.RETRACTABLE, reads=())

    def test_a_stage_needs_a_name(self):
        with pytest.raises(IncrementalError, match="needs a name"):
            StageSpec(name="", stability=Stability.RETRACTABLE, reads=("records",))


class TestRegistry:

    def test_the_registry_is_built_from_the_one_list(self):
        assert set(SPECS) == {spec.name for spec in STAGES}
        assert len(SPECS) == len(STAGES)

    def test_no_stage_is_registered_twice(self):
        names = [spec.name for spec in STAGES]
        assert len(names) == len(set(names))

    def test_an_unregistered_stage_is_unknown_and_recomputes(self):
        spec = spec_for("something_nobody_classified")
        assert spec.stability is Stability.UNKNOWN
        assert not spec.reusable_on_append

    def test_exactly_one_stage_is_append_stable(self):
        """The shape of the table is the finding, and it is not the expected shape.

        `detect` and `normalise` were classified APPEND_STABLE on plausible
        reasoning and both were wrong — see the next class, which holds the
        classification to the engine's actual behaviour rather than to a `why`.
        """
        reusable = [name for name, spec in SPECS.items() if spec.reusable_on_append]
        assert reusable == ["fold"]

    def test_the_analysis_stages_are_retractable(self):
        assert not SPECS["analyse"].reusable_on_append
        assert not SPECS["assess"].reusable_on_append

    def test_a_spec_serialises(self):
        data = SPECS["fold"].to_dict()
        assert data["stability"] == "APPEND_STABLE"
        assert data["reusable_on_append"] is True
        assert data["record_type"] == "incremental_stage"


class TestTheClassificationMatchesTheEngine:
    """A stability claim held to behaviour, not to the sentence justifying it.

    A `why` is an argument and arguments are wrong sometimes; these two were. What
    stops the classification drifting back is a test that appends records and looks
    at what the engine does, so a future edit that makes ingest genuinely resumable
    has to come past here.
    """

    def _document(self):
        from release_gate.assurance.corpus import _clean_release
        return [dict(r) for r in _clean_release()]

    def test_appending_records_can_change_what_document_this_is(self):
        """Why `detect` is RETRACTABLE: the score is a proportion, not a presence."""
        from release_gate.assurance.ingest import detect_document

        base = self._document()
        before = detect_document(base, filename="s.jsonl")
        assert before.kind.value == "ASSURANCE_ENVELOPE"

        junk = [{"record_type": "something_nobody_registered", "id": i}
                for i in range(200)]
        after = detect_document(base + junk, filename="s.jsonl")
        assert after.kind is not before.kind
        assert after.confidence < before.confidence
        assert not SPECS["detect"].reusable_on_append

    def test_normalise_inherits_that_because_it_reads_the_detection(self):
        """So its output over n+1 records is not an extension of its output over n."""
        from release_gate.assurance.ingest import detect_document, normalise
        import json

        base = self._document()
        junk = [{"record_type": "something_nobody_registered", "id": i}
                for i in range(200)]

        def evidence_count(document):
            content = json.dumps(document, sort_keys=True).encode()
            detection = detect_document(document, filename="s.jsonl")
            return len(normalise(document, detection, source="s.jsonl",
                                 content=content).evidence)

        # Not merely "fewer than it would be" — appending records took evidence away.
        assert evidence_count(base + junk) < evidence_count(base)
        assert not SPECS["normalise"].reusable_on_append

    def test_the_fold_is_append_stable_and_says_why(self):
        assert SPECS["fold"].reusable_on_append
        assert "multiset" in SPECS["fold"].why


# ── keys ─────────────────────────────────────────────────────────────────────

class TestReuseKey:

    def test_the_same_inputs_give_the_same_key(self):
        a = reuse_key("analyse", {"case": "c1", "normalisation": "n1"})
        b = reuse_key("analyse", {"case": "c1", "normalisation": "n1"})
        assert a == b

    def test_a_changed_input_changes_the_key(self):
        a = reuse_key("analyse", {"case": "c1", "normalisation": "n1"})
        b = reuse_key("analyse", {"case": "c2", "normalisation": "n1"})
        assert a != b

    def test_two_stages_over_one_input_do_not_collide(self):
        a = reuse_key("analyse", {"case": "c", "normalisation": "n"})
        b = reuse_key("seal", {"case": "c", "verdict": "n"})
        assert a != b

    def test_an_undeclared_input_is_refused(self):
        """A key covering more than the spec admits hides that the spec is wrong."""
        with pytest.raises(IncrementalError, match="not declared in reads"):
            reuse_key("analyse", {"case": "c", "normalisation": "n", "weather": "fine"})

    def test_a_missing_declared_input_is_refused(self):
        """The failure mode: a key that cannot detect the input it does not cover."""
        with pytest.raises(IncrementalError, match="absent from the key"):
            reuse_key("analyse", {"case": "c"})

    def test_key_order_does_not_matter(self):
        a = reuse_key("analyse", {"case": "c", "normalisation": "n"})
        b = reuse_key("analyse", {"normalisation": "n", "case": "c"})
        assert a == b


# ── what changed ─────────────────────────────────────────────────────────────

class TestPlan:

    def test_the_same_records_are_unchanged(self):
        delta = plan(["a", "b"], ["a", "b"])
        assert delta.change is Change.NONE
        assert delta.unchanged and delta.append_only

    def test_an_append_is_an_append(self):
        delta = plan(["a", "b"], ["a", "b", "c"])
        assert delta.change is Change.APPENDED
        assert delta.appended == 1
        assert delta.append_only

    def test_a_removal_is_a_rewrite(self):
        delta = plan(["a", "b", "c"], ["a", "b"])
        assert delta.change is Change.REWRITTEN
        assert not delta.append_only

    def test_a_swap_that_keeps_the_count_is_still_a_rewrite(self):
        """The case a length check gets wrong, which is why the keys are per-record."""
        delta = plan(["a", "b"], ["a", "z"])
        assert delta.change is Change.REWRITTEN
        assert delta.diverged_at == 1
        assert delta.previous == delta.current == 2

    def test_a_reorder_is_a_rewrite(self):
        assert plan(["a", "b"], ["b", "a"]).change is Change.REWRITTEN

    def test_every_delta_describes_itself(self):
        for delta in (plan([], []), plan(["a"], ["a", "b"]), plan(["a"], ["z"]),
                      plan(["a", "b"], ["a"])):
            assert len(delta.describe()) > 10
            assert delta.to_dict()["record_type"] == "incremental_delta"

    def test_a_rewrite_with_no_divergence_point_still_describes_itself(self):
        delta = Delta(change=Change.REWRITTEN, previous=3, current=1)
        assert "rewritten" in delta.describe()


# ── the cache ────────────────────────────────────────────────────────────────

class TestIncrementalCache:

    def test_a_hit_returns_what_was_put(self):
        cache = IncrementalCache()
        cache.put("k", 42)
        assert cache.get("k") == 42
        assert cache.hits == 1 and cache.misses == 0

    def test_a_miss_counts(self):
        cache = IncrementalCache()
        assert cache.get("nope") is None
        assert cache.misses == 1

    def test_the_limit_is_honoured(self):
        cache = IncrementalCache(limit=2)
        for i in range(5):
            cache.put(f"k{i}", i)
        assert len(cache) == 2
        assert cache.evictions == 3

    def test_a_cache_must_hold_something(self):
        with pytest.raises(IncrementalError, match="at least one entry"):
            IncrementalCache(limit=0)

    def test_eviction_cannot_change_a_result(self):
        """Unconditionally False, and the reason eviction order needs no determinism.

        The mirror of `compaction`, where retention IS visible in the case and must
        therefore be deterministic. Nothing here is visible in a result.
        """
        assert IncrementalCache().eviction_can_change_a_result is False
        assert IncrementalCache(limit=1).eviction_can_change_a_result is False

    def test_a_reused_key_survives_eviction_pressure(self):
        """LRU, so the entry being asked for is the one that stays."""
        cache = IncrementalCache(limit=2)
        cache.put("hot", 1)
        cache.put("cold", 2)
        cache.get("hot")
        cache.put("new", 3)
        assert cache.get("hot") == 1
        assert cache.get("cold") is None

    def test_the_summary_reports_a_hit_rate_only_once_asked(self):
        cache = IncrementalCache()
        assert cache.summary()["hit_rate"] is None
        cache.put("k", 1)
        cache.get("k")
        assert cache.summary()["hit_rate"] == 1.0

    def test_clear_empties_it(self):
        cache = IncrementalCache()
        cache.put("k", 1)
        cache.clear()
        assert len(cache) == 0 and "k" not in cache


# ── the decision, and the report ─────────────────────────────────────────────

class TestReuse:

    def test_a_decision_must_say_why(self):
        with pytest.raises(IncrementalError, match="must say why"):
            Reuse(stage="fold", decision=ReuseDecision.REUSED, key="k", why="")

    def test_a_reuse_carries_its_stage_stability(self):
        decision = Reuse(stage="fold", decision=ReuseDecision.REUSED, key="k",
                         why="the records did not move")
        assert decision.stability is Stability.APPEND_STABLE

    def test_only_reuse_avoided_work(self):
        assert not ReuseDecision.REUSED.did_work
        assert ReuseDecision.RECOMPUTED.did_work
        assert ReuseDecision.REFUSED.did_work

    def test_refused_is_distinct_from_recomputed(self):
        """Both did the work; only one had a choice, which is what an operator asks about."""
        assert ReuseDecision.REFUSED is not ReuseDecision.RECOMPUTED

    def test_the_report_is_not_a_rating(self):
        assert IncrementalReport().is_a_performance_rating is False

    def test_an_empty_report_says_so_rather_than_rendering_nothing(self):
        assert "nothing was offered" in IncrementalReport().render()

    def test_a_report_renders_its_decisions_and_delta(self):
        report = IncrementalReport(
            decisions=(Reuse(stage="fold", decision=ReuseDecision.REUSED, key="k",
                             why="unchanged"),),
            delta=plan(["a"], ["a", "b"]))
        text = report.render()
        assert "REUSED" in text and "fold" in text and "appended" in text
        assert report.to_dict()["record_type"] == "incremental_report"


# ── proving a reuse did not change the answer ────────────────────────────────

class TestVerifyReuse:

    def test_an_equivalent_reuse_is_identical(self):
        outcome = verify_reuse("fold", lambda: {"a": 1}, lambda: {"a": 1})
        assert outcome.identical
        assert "equivalent" in outcome.render()

    def test_a_reuse_that_changed_the_result_is_caught(self):
        outcome = verify_reuse("fold", lambda: {"a": 1}, lambda: {"a": 2})
        assert not outcome.identical
        assert "REUSE CHANGED THE RESULT" in outcome.render()

    def test_a_disagreement_about_the_verdict_is_named(self):
        class Fake:
            def __init__(self, decision, digest):
                self.decision, self.case_digest = decision, digest

        outcome = verify_reuse(
            "finalization", lambda: Fake("PROMOTE", "sha256:" + "a" * 64),
            lambda: Fake("HOLD", "sha256:" + "b" * 64))
        assert not outcome.identical
        assert any("decision" in d for d in outcome.differences)
        assert any("case_digest" in d for d in outcome.differences)

    def test_equivalence_serialises(self):
        data = verify_reuse("fold", lambda: 1, lambda: 1).to_dict()
        assert data["identical"] is True
        assert data["record_type"] == "incremental_equivalence"

    def test_a_result_digest_prefers_a_binding_state(self):
        """What an approval covers, not an incidental serialisation beside it.

        A `to_dict` that agreed while the binding state did not would let a reuse
        that moved what an approval binds to pass this check.
        """
        from release_gate.assurance.canonical import digest_object

        class Both:
            def binding_state(self):
                return {"what": "an approval binds to"}

            def to_dict(self):
                return {"what": "something else entirely"}

        assert result_digest(Both()) == digest_object({"what": "an approval binds to"})

    def test_a_result_with_no_view_at_all_still_digests(self):
        assert result_digest(object()).startswith("sha256:")

    def test_the_differences_are_empty_when_nothing_exposes_a_verdict(self):
        assert verify_reuse("fold", lambda: 1, lambda: 1).differences == ()


# ── the fork primitive ───────────────────────────────────────────────────────

class TestForkedFold:

    def test_a_forked_prefix_plus_the_rest_equals_one_pass(self):
        """The property every reuse in this architecture rests on."""
        prefix = RecordCollectionBuilder("evidence")
        for i in range(5):
            prefix.add(rec(i))
        forked = prefix.fork()
        forked.add(rec(99))

        scratch = RecordCollectionBuilder("evidence")
        for i in list(range(5)) + [99]:
            scratch.add(rec(i))

        assert forked.build().fold_digest == scratch.build().fold_digest
        assert forked.build().total_count == scratch.build().total_count

    def test_the_order_records_arrive_in_after_a_fork_does_not_matter(self):
        """The fold is a multiset, so there is no ordering a fork could get wrong."""
        prefix = RecordCollectionBuilder("evidence")
        prefix.add(rec(0))
        a, b = prefix.fork(), prefix.fork()
        a.add(rec(1)); a.add(rec(2))
        b.add(rec(2)); b.add(rec(1))
        assert a.build().fold_digest == b.build().fold_digest

    def test_forks_cannot_see_each_others_records(self):
        prefix = RecordCollectionBuilder("evidence")
        prefix.add(rec(0))
        a, b = prefix.fork(), prefix.fork()
        a.add(rec(1))
        b.add(rec(2))
        assert a.build().total_count == b.build().total_count == 2
        assert a.build().fold_digest != b.build().fold_digest

    def test_a_fork_does_not_inherit_a_duplicate_from_its_sibling(self):
        """A shared `_seen_ids` would have one branch reject the other's record."""
        prefix = RecordCollectionBuilder("evidence")
        a, b = prefix.fork(), prefix.fork()
        a.add(rec(1))
        b.add(rec(1))  # the same id, in the other branch: legitimate
        assert a.build().total_count == b.build().total_count == 1

    def test_a_fork_still_catches_a_duplicate_within_itself(self):
        prefix = RecordCollectionBuilder("evidence")
        prefix.add(rec(1))
        forked = prefix.fork()
        with pytest.raises(RecordError, match="duplicate record_id"):
            forked.add(rec(1))

    def test_the_original_is_untouched_by_what_a_fork_does(self):
        prefix = RecordCollectionBuilder("evidence")
        prefix.add(rec(0))
        forked = prefix.fork()
        for i in range(1, 20):
            forked.add(rec(i))
        assert prefix.build().total_count == 1

    def test_presence_and_notes_carry_across_a_fork(self):
        prefix = RecordCollectionBuilder("claims")
        prefix.declare_present("the ingest looked")
        forked = prefix.fork()
        built = forked.build()
        assert built.presence.value == "PRESENT"
        assert "the ingest looked" in built.notes

    def test_a_fork_keeps_the_materialised_records(self):
        prefix = RecordCollectionBuilder("evidence")
        prefix.add(rec(0))
        forked = prefix.fork()
        assert [r.record_id for r in forked.build().materialised] == ["e0"]


class TestForkedCase:

    def _prefix(self) -> AssuranceCaseBuilder:
        builder = AssuranceCaseBuilder(
            case_type=CaseType.CODE_CHANGE, objective="ship a change",
            requested_decision="may this ship?", subject=subject(),
            metadata={"zero_config": True})
        builder.extend("evidence", [rec(i) for i in range(4)])
        builder.declare_present("claims", "looked")
        return builder

    def test_a_forked_case_digests_the_same_as_one_built_directly(self):
        prefix = self._prefix()
        direct = self._prefix().build()
        assert prefix.fork().build().case_digest == direct.case_digest

    def test_two_forks_diverge_only_by_what_was_added_to_them(self):
        prefix = self._prefix()
        a, b = prefix.fork(), prefix.fork()
        a.add("evidence", rec(100))
        b.add("evidence", rec(200))
        assert a.build().case_digest != b.build().case_digest
        assert a.build().collection("evidence").total_count == 5

    def test_adding_to_a_fork_leaves_the_prefix_alone(self):
        prefix = self._prefix()
        prefix.fork().add("evidence", rec(500))
        assert prefix.build().collection("evidence").total_count == 4

    def test_metadata_is_copied_not_shared(self):
        prefix = self._prefix()
        forked = prefix.fork()
        forked.metadata["extra"] = True
        assert "extra" not in prefix.metadata


# ── the pipeline itself ──────────────────────────────────────────────────────

class TestZeroConfigFoldsOnce:
    """The acceptance criterion: the fold-once path must move no digest."""

    def _pieces(self):
        import json
        from release_gate.assurance.consequence import default_consequence_registry
        from release_gate.assurance.corpus import _clean_release
        from release_gate.assurance.ingest import detect_document, normalise
        from release_gate.assurance import zero_config as zc

        document = [dict(r) for r in _clean_release()]
        content = json.dumps(document, sort_keys=True).encode()
        detection = detect_document(document, filename="s.jsonl")
        normalisation = normalise(document, detection, source="s.jsonl", content=content)
        consequence = default_consequence_registry().build(
            None, capabilities=normalisation.capabilities,
            declared=list(normalisation.declared_consequence))
        subj = zc._subject_for(Path("s.jsonl"), normalisation, "ship it")
        return zc, normalisation, consequence, subj

    def test_a_forked_prefix_builds_the_case_the_direct_path_builds(self):
        zc, normalisation, consequence, subj = self._pieces()
        kwargs = dict(objective="o", requested_decision="d", methodology=None,
                      consequence=consequence)
        direct = zc._build_case(subj, normalisation, **kwargs)
        prefix = zc._case_prefix(subj, normalisation, **kwargs)
        forked = zc._case_tail(prefix.fork(), normalisation,
                              consequence=consequence).build()
        assert forked.case_digest == direct.case_digest

    def test_three_cases_from_one_prefix_match_three_independent_folds(self):
        zc, normalisation, consequence, subj = self._pieces()
        kwargs = dict(objective="o", requested_decision="d", methodology=None,
                      consequence=consequence)
        prefix = zc._case_prefix(subj, normalisation, **kwargs)
        for _ in range(3):
            assert (zc._case_tail(prefix.fork(), normalisation,
                                  consequence=consequence).build().case_digest
                    == zc._build_case(subj, normalisation, **kwargs).case_digest)

    def test_the_whole_path_is_reproducible(self):
        """Two runs over one input, one digest. Reuse must not have made this untrue."""
        from release_gate.assurance.corpus import _clean_release
        from release_gate.assurance.session import AssuranceSession

        digests = set()
        for _ in range(2):
            session = AssuranceSession.open(source_name="s.jsonl")
            session.extend([dict(r) for r in _clean_release()])
            digests.add(session.finalize().case.case_digest)
        assert len(digests) == 1
