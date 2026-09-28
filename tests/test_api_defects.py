"""Two defects in the product surface, found while documenting it.

Both are the same shape: **a call that looks like it worked and did not.**

* `Case.add_execution()` took the steps of a run, flattened them to a scalar
  under `content`, built no execution graph, and left the case reporting
  `execution_reconstruction: NOT_ASSESSED` — so the very next thing the case said
  was *supply the run's trace*, about the trace it had just been handed.

* `create_case(methodology="research-mathematics-v1")` threw the `-v1` away. The
  id was split at `-v` and the newest version of any major came back. With one
  version published nobody could tell; with two, a caller who wrote a version got
  a different one.

Neither raised. Neither logged. That is what makes them worth their own file.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.api import ApiError, Case, create_case


# ── add_execution ───────────────────────────────────────────────────────────

class TestAddExecutionBuildsAGraph:

    @staticmethod
    def _graph(case: Case):
        """The execution graph the case actually ends up with."""
        return getattr(case.finalize().outcome.analysis, "execution_graph", None)

    def test_the_steps_on_their_own_build_a_graph(self):
        """The shape a caller reaches for first, and the one that did nothing."""
        case = create_case(objective="apply the migration", subject="thing-1")
        case.add_execution([
            {"type": "tool_call", "tool": "postgres_query"},
            {"type": "llm_call", "model": "planner", "tokens": 900},
            {"type": "tool_call", "tool": "shell"},
        ])
        graph = self._graph(case)
        assert graph is not None, "the steps were accepted and no graph was built"
        assert len(graph.nodes) > 1

    def test_the_native_trace_shape_still_works(self):
        """What every existing caller passes. It must not change."""
        case = create_case(objective="apply the migration", subject="thing-1")
        case.add_execution({"trace_id": "run-01",
                            "steps": [{"type": "tool_call", "tool": "write_file"}]})
        assert self._graph(case) is not None

    def test_both_spellings_reach_the_same_graph(self):
        """A wrapper that produced a *different* graph would be its own defect."""
        bare = create_case(objective="o", subject="thing-1")
        bare.add_execution([{"type": "tool_call", "tool": "shell"}])
        wrapped = create_case(objective="o", subject="thing-1")
        wrapped.add_execution({"steps": [{"type": "tool_call", "tool": "shell"}]})
        assert len(self._graph(bare).nodes) == len(self._graph(wrapped).nodes)

    def test_the_case_stops_asking_for_what_it_was_given(self):
        """The symptom that exposed this.

        With no graph, `execution_reconstruction` reads NOT_ASSESSED and the
        required-evidence list asks for the run's trace — which the caller had
        already supplied. A gate that asks twice for the same thing is one nobody
        can close out.
        """
        case = create_case(objective="apply the migration", subject="thing-1",
                           methodology="general-autonomous-action")
        case.add_execution([{"type": "tool_call", "tool": "shell"}])
        case.add_evidence("the test suite passed", kind="TEST_RESULT")
        asks = " ".join(case.required_evidence()).lower()
        assert "trace or tool-call log" not in asks

    @pytest.mark.parametrize("payload", [
        "a trace", 42, None, {"trace_id": "t"}, {"steps": "not a list"}])
    def test_a_payload_that_cannot_become_a_trace_is_refused(self, payload):
        """Refused rather than stored.

        The alternative is what was happening: the call succeeds, nothing is
        reconstructed, and the failure surfaces later as a requirement the caller
        believes they have already met.
        """
        case = create_case(objective="o", subject="thing-1")
        with pytest.raises(ApiError, match="needs a trace it can reconstruct"):
            case.add_execution(payload)

    def test_the_refusal_says_what_a_step_looks_like(self):
        case = create_case(objective="o", subject="thing-1")
        with pytest.raises(ApiError) as exc:
            case.add_execution("a trace")
        assert "tool_call" in str(exc.value)


# ── the methodology reference ───────────────────────────────────────────────

class TestTheMethodologyReferenceIsHonoured:

    def test_an_exact_pin_resolves_to_that_version(self):
        """`id@X.Y.Z` was not supported at all: it raised "not a registered
        methodology", so the API could not pin a version even deliberately."""
        case = create_case(objective="x", methodology="research-mathematics@1.0.0")
        assert case.session.methodology.version == "1.0.0"

    def test_and_a_different_pin_resolves_to_that_one(self):
        case = create_case(objective="x", methodology="research-mathematics@1.1.0")
        assert case.session.methodology.version == "1.1.0"

    def test_the_v_suffix_pins_the_major_line(self):
        """The brief's spelling, which read as a pin and was discarded.

        `-v1` now means the newest 1.x, which is what somebody writing it means.
        It must never return a 2.x.
        """
        case = create_case(objective="x", methodology="research-mathematics-v1")
        assert case.session.methodology.version.startswith("1.")

    def test_a_bare_id_still_takes_the_newest(self):
        """Left working on purpose: it is what the CLI does, and the case records
        the ref it resolved to, so the bar that was applied is on the record."""
        from release_gate.assurance.methodologies import default_registry

        case = create_case(objective="x", methodology="research-mathematics")
        newest = default_registry().latest("research-mathematics").version
        assert case.session.methodology.version == newest

    def test_a_version_that_is_not_registered_is_refused(self):
        """Not quietly rounded to a neighbour. The version is what fixes the bar,
        so a missing one is an error rather than an invitation to choose."""
        with pytest.raises(ApiError):
            create_case(objective="x", methodology="research-mathematics@9.9.9")

    def test_nor_a_major_line_that_does_not_exist(self):
        with pytest.raises(ApiError, match="asks for version"):
            create_case(objective="x", methodology="research-mathematics-v7")

    def test_a_mistyped_id_still_names_what_is_registered(self):
        with pytest.raises(ApiError, match="not a registered methodology"):
            create_case(objective="x", methodology="reserch-mathematics")

    def test_the_resolved_version_reaches_the_case(self):
        """Whatever spelling was used, the case says which bar it was argued
        against — that is what makes the choice auditable after the fact."""
        case = create_case(objective="x", methodology="research-mathematics@1.0.0")
        case.add_evidence("something happened", kind="OBSERVATION")
        ref = case.finalize().outcome.case.methodology
        assert ref.methodology_id == "research-mathematics"
        assert ref.version == "1.0.0"
        assert ref.digest
