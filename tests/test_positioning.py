"""The six claims the project will not make, and the numbers the README prints.

**This file is a tripwire, not a proof.** A substring check reads text and never
meaning, and this codebase has been caught by that often enough to say so where the
check lives: an earlier version of a similar guard matched `"socket"` looking for
`soc`, and another matched an SSRF check against its own source. So the phrase tests
below look for a forbidden claim in the *affirmative* — the same phrase in a sentence
that negates it is the documentation doing its job, and there are a dozen of those.

What is actually load-bearing here is the second half: the figures in `README.md` and
`docs/POSITIONING.md` are re-measured against the running demonstrations, so a claim
that drifts from its implementation fails rather than being noticed later.
"""

from __future__ import annotations

import pathlib
import re

import pytest

#: Documentation a reader takes as the project's own claims.
#:
#: Two exclusions, both because a lexical check cannot tell a claim from an argument
#: about one. The architecture spec quotes and dissects these phrasings at length,
#: which is the opposite of claiming them. And `docs/POSITIONING.md` **enumerates the
#: six** — a scan of it is guaranteed to match every one, which is what the document is
#: for; `test_the_positioning_document_names_all_six` asserts the words are present
#: there rather than absent.
SURFACES = ("README.md", "docs/README.md",
            "docs/QUICKSTART.md", "docs/ARCHITECTURE.md", "docs/EXTENDED_README.md",
            "benchmark/ASSURANCE.md", "integrations/README.md")

#: Affirmative phrasings of the six. Each is a claim about release-gate's output, not
#: a word that must never appear — "safety" is a product noun and appears throughout.
FORBIDDEN = (
    "safe to deploy",
    "is safe",
    "guaranteed correct",
    "guarantees correctness",
    "unhackable",
    "cannot be gamed",
    "solves hallucination",
    "eliminates hallucination",
    "replaces experts",
    "replaces human",
    "no longer need",
)

#: Words that turn one of the above into a refusal. Checked within the sentence, which
#: is the smallest unit where "never safe to deploy" is distinguishable from
#: "safe to deploy".
NEGATIONS = ("not", "never", "no ", "cannot", "refus", "without", "nor ", "neither")


def sentences(text: str):
    for raw in re.split(r"(?<=[.!?])\s+|\n\n+|\n[-*|]\s*", text):
        stripped = raw.strip()
        if stripped:
            yield stripped


def surfaces():
    for name in SURFACES:
        path = pathlib.Path(name)
        if path.is_file():
            yield name, path.read_text()


class TestTheSixNonClaims:

    def test_the_surfaces_exist_to_be_checked(self):
        """A guard over files that are not there would pass by accident."""
        found = {name for name, _ in surfaces()}
        assert "README.md" in found and "docs/QUICKSTART.md" in found
        assert len(found) >= 6

    def test_the_guard_catches_an_overclaim_when_there_is_one(self):
        """It found `"All checks passed. Safe to deploy."` in QUICKSTART, so it works.

        Pinned by construction rather than by that line, which has since been fixed.
        """
        planted = "All checks passed. Safe to deploy."
        offending = [s for s in sentences(planted)
                     if "safe to deploy" in s.lower()
                     and not any(n in s.lower() for n in NEGATIONS)]
        assert offending, "the guard would not catch the claim it was written for"

    @pytest.mark.parametrize("phrase", FORBIDDEN)
    def test_no_surface_claims_it(self, phrase):
        offenders = []
        for name, text in surfaces():
            for sentence in sentences(text):
                lowered = sentence.lower()
                if phrase not in lowered:
                    continue
                if any(negation in lowered for negation in NEGATIONS):
                    continue
                offenders.append(f"{name}: {sentence[:120]}")
        assert offenders == [], offenders

    def test_the_positioning_document_names_all_six(self):
        """The refusals must be stated somewhere, not merely absent."""
        text = pathlib.Path("docs/POSITIONING.md").read_text().lower()
        for word in ("safe", "guaranteed correct", "unhackable", "uncontested",
                     "hallucination", "replaces experts"):
            assert word in text, word

    def test_the_readme_states_what_it_will_not_tell_you(self):
        text = pathlib.Path("README.md").read_text()
        assert "What it will not tell you" in text
        assert "docs/POSITIONING.md" in text


@pytest.fixture(scope="module")
def measured():
    """Both demonstrations, run once, reduced to the figures the documents print."""
    from release_gate.assurance.trace import trace_verdict
    from release_gate.demos import frontier_research, single_agent

    rows = {}
    for name, module in (("single_agent", single_agent),
                         ("frontier", frontier_research)):
        outcome = module.run().outcome
        producers = {
            str(getattr(getattr(record, "producer", None), "producer_id", ""))
            for record in outcome.case.collection("evidence").materialised}
        rows[name] = {
            "producers": len([p for p in producers if p]),
            "evidence": outcome.case.collection("evidence").total_count,
            "claims": outcome.case.collection("claims").total_count,
            "attention": len(outcome.attention.items),
            "decision": outcome.decision.value,
            "unexplained": len(trace_verdict(outcome).unexplained),
        }
    return rows


class TestThePublishedFiguresAreMeasured:
    """The load-bearing half: a claim that drifts from its implementation fails here."""

    def test_the_producer_counts_in_both_documents_are_real(self, measured):
        """"Thousands of parallel researchers" has to be a measurement."""
        assert measured["single_agent"]["producers"] == 4
        assert measured["frontier"]["producers"] == 10_254
        for name in ("README.md", "docs/POSITIONING.md"):
            text = pathlib.Path(name).read_text()
            assert "10,254" in text, name

    def test_the_evidence_and_claim_counts_are_real(self, measured):
        assert measured["frontier"]["evidence"] == 10_258
        assert measured["frontier"]["claims"] == 2_420
        for name in ("README.md", "docs/POSITIONING.md"):
            text = pathlib.Path(name).read_text()
            assert "10,258" in text and "2,420" in text, name

    def test_the_attention_counts_are_real(self, measured):
        assert measured["single_agent"]["attention"] == 1
        assert measured["frontier"]["attention"] == 13

    def test_reconstructing_the_evidence_leaves_nothing_unexplained(self, measured):
        """"Reconstructs the evidence" is the claim; zero unexplained steps is the test."""
        assert measured["single_agent"]["unexplained"] == 0
        assert measured["frontier"]["unexplained"] == 0

    def test_the_verdicts_the_documents_print_are_the_verdicts_reached(self, measured):
        assert measured["single_agent"]["decision"] == "PROMOTE"
        assert measured["frontier"]["decision"] == "BLOCK"


class TestThePrimaryClaimIsStructural:
    """"Before a human accepts responsibility" is enforced, not advised."""

    def test_a_case_has_no_decision_until_it_is_finalized(self):
        from release_gate.assurance.api import create_case
        from release_gate.assurance.session import SessionError

        case = create_case(objective="o", subject="thing-1")
        with pytest.raises(SessionError, match="has not been finalized"):
            case.session.outcome

    def test_a_decision_names_the_state_an_approval_would_bind_to(self):
        from release_gate.assurance.api import create_case

        case = create_case(objective="o", subject="thing-1")
        assert case.finalize().case_digest.startswith("sha256:")


class TestTheEngineeringClaimIsQualified:
    """Sufficiency is measured against a methodology, or reported as not assessed."""

    def test_with_no_methodology_sufficiency_is_not_assessed(self):
        from release_gate.assurance.api import create_case

        decision = create_case(objective="o", subject="thing-1").finalize()
        assert any("METHODOLOGY_REQUIRED" in reason for reason in decision.reasons)
        assert "domain_sufficiency" in decision.not_assessed

    def test_the_positioning_document_says_so_rather_than_implying_it(self):
        text = pathlib.Path("docs/POSITIONING.md").read_text()
        assert "NOT_ASSESSED" in text
        assert "not about clearing it" in text
