"""A refused consequence declaration must say so.

Every dimension has a fixed vocabulary, and a value outside it is refused rather
than coerced — that part was always right. What was wrong is that the refusal
was silent: the dimension went to UNKNOWN, nothing landed in `skipped`, nothing
reached `notes`, and the value appeared nowhere in `--json`. An operator who
declared the stakes and typed `ALL_USERS` for a SCOPE was told, in the report,
that the stakes were never stated.

That is the failure this repository names everywhere else: a gap that reads as a
clean answer. Every other rejection in the ingest reports itself (a bad record
produces `a adversarial record was rejected: 'DISPUTED' is not a valid
AdversarialOutcome`); the consequence parser was the one path with no channel to
report through.

The distinction these tests defend is not "the value was dropped". It is that a
dimension reading UNKNOWN because **nobody stated it** and one reading UNKNOWN
because **somebody stated it and was refused** are different facts, and only the
second is something a person can go and fix.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from release_gate.assurance.consequence import (
    ConsequenceDimension, descriptors_from_mapping, values_for)
from release_gate.assurance.zero_config import assure

BAD_VALUE = {"record_type": "consequence", "REVERSIBILITY": "IRREVERSIBLE",
             "SCOPE": "ALL_USERS"}
BAD_DIMENSION = {"record_type": "consequence", "BLAST_RADIUS": "HUGE"}
STEP = {"record_type": "execution", "trace_id": "t",
        "steps": [{"type": "tool_call", "tool": "bash"}]}


def _run(*records):
    path = tempfile.mktemp(suffix=".jsonl")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(json.dumps(r) for r in records))
        return assure(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


class TestTheParserCanReportWhatItRefused:
    """`descriptors_from_mapping` keeps its return type; the channel is opt-in."""

    def test_a_refused_value_is_appended_to_the_collector(self):
        rejected: list[str] = []
        out = descriptors_from_mapping({"SCOPE": "ALL_USERS"}, source="t",
                                       rejected=rejected)
        assert out == []
        assert len(rejected) == 1
        assert "ALL_USERS" in rejected[0]
        assert "SCOPE" in rejected[0]

    def test_the_line_names_the_admissible_values(self):
        """A refusal that does not say what would have worked is a dead end."""
        rejected: list[str] = []
        descriptors_from_mapping({"DATA_IMPACT": "DESTRUCTIVE"}, source="t",
                                 rejected=rejected)
        for value in values_for(ConsequenceDimension.DATA_IMPACT):
            assert value in rejected[0], f"{value} is admissible but not offered"

    def test_a_refused_dimension_name_is_reported_too(self):
        rejected: list[str] = []
        descriptors_from_mapping({"BLAST_RADIUS": "HUGE"}, source="t",
                                 rejected=rejected)
        assert len(rejected) == 1
        assert "BLAST_RADIUS" in rejected[0]

    def test_an_accepted_value_produces_no_line(self):
        rejected: list[str] = []
        out = descriptors_from_mapping({"SCOPE": "BROAD"}, source="t",
                                       rejected=rejected)
        assert len(out) == 1 and rejected == []

    def test_declaring_unknown_is_not_a_refusal(self):
        """Declaring UNKNOWN is the same as declaring nothing — and always was."""
        rejected: list[str] = []
        out = descriptors_from_mapping({"SCOPE": "UNKNOWN"}, source="t",
                                       rejected=rejected)
        assert out == [] and rejected == []

    def test_the_collector_stays_optional(self):
        """Callers that pass nothing must behave exactly as before."""
        assert descriptors_from_mapping({"SCOPE": "ALL_USERS"}, source="t") == []

    def test_strict_still_raises_rather_than_collecting(self):
        from release_gate.assurance.consequence import ConsequenceError

        rejected: list[str] = []
        with pytest.raises(ConsequenceError):
            descriptors_from_mapping({"SCOPE": "ALL_USERS"}, source="t",
                                     strict=True, rejected=rejected)


class TestTheRefusalReachesTheCase:

    def test_the_normalisation_carries_it_as_a_field(self):
        n = _run(BAD_VALUE, STEP).normalisation
        assert n.refused_consequence, "a refused declaration left no trace"
        assert any("ALL_USERS" in line for line in n.refused_consequence)

    def test_it_lands_in_notes_where_every_other_rejection_lands(self):
        n = _run(BAD_VALUE, STEP).normalisation
        assert any("ALL_USERS" in note for note in n.notes)

    def test_the_line_says_which_record_it_came_from(self):
        """Two records, one bad: the note has to name which. Positions are 1-based."""
        n = _run(STEP, BAD_VALUE).normalisation
        assert any("record 2" in line for line in n.refused_consequence), \
            n.refused_consequence

    def test_the_value_survives_into_the_serialised_outcome(self):
        blob = json.dumps(_run(BAD_VALUE, STEP).to_dict(), default=str)
        assert "ALL_USERS" in blob, "the refused value is still invisible in --json"

    def test_the_valid_dimensions_in_the_same_record_are_unaffected(self):
        """Refusing one value must not discard the ones that were right."""
        n = _run(BAD_VALUE, STEP).normalisation
        kept = {d.dimension.value for d in n.declared_consequence}
        assert kept == {"REVERSIBILITY"}

    def test_a_clean_record_produces_no_refusals(self):
        good = {"record_type": "consequence", "SCOPE": "BROAD",
                "REVERSIBILITY": "IRREVERSIBLE"}
        assert _run(good, STEP).normalisation.refused_consequence == ()


class TestTheOperatorSeesIt:
    """The whole point: it has to appear in the report a person actually reads."""

    def _report(self, *records) -> str:
        from release_gate.assurance.zero_config import render_text

        return render_text(_run(*records))

    def test_the_stakes_block_names_the_refused_value(self):
        text = self._report(BAD_VALUE, STEP)
        assert "ALL_USERS" in text, "the report still hides the refused value"

    def test_it_is_printed_beside_the_unknown_list_it_explains(self):
        text = self._report(BAD_VALUE, STEP)
        assert "UNKNOWN:" in text and "REFUSED" in text
        assert text.index("UNKNOWN:") < text.index("REFUSED"), \
            "the explanation should follow the list it explains"

    def test_a_refused_dimension_name_is_shown(self):
        assert "BLAST_RADIUS" in self._report(BAD_DIMENSION, STEP)

    def test_nothing_is_printed_when_nothing_was_refused(self):
        good = {"record_type": "consequence", "SCOPE": "BROAD"}
        assert "REFUSED" not in self._report(good, STEP)

    def test_the_report_does_not_find_these_by_matching_prose(self):
        """The renderer reads the typed field, not the notes list.

        A note that merely *mentions* the phrase must not be promoted into the
        stakes block — matching on prose is how a renderer starts inventing
        findings that the engine never made.
        """
        import dataclasses

        from release_gate.assurance.zero_config import render_text

        outcome = _run(STEP)
        assert outcome.normalisation.refused_consequence == ()
        tampered = dataclasses.replace(
            outcome.normalisation,
            notes=outcome.normalisation.notes
            + ("'X' is not admissible for SCOPE — but this is only a note",))
        text = render_text(dataclasses.replace(outcome, normalisation=tampered))
        assert "REFUSED" not in text
