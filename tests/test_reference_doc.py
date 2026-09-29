"""`docs/REFERENCE.md` has to describe the CLI that exists.

The README calls it "full command and feature reference" and links it. It went
885 lines without one mention of `release-gate assure` — the command the README
calls the product — because a doc that is written once and linked forever has
nothing holding it to the code.

So the parts a reader would follow are asserted against the implementation:
every flag `assure` accepts, every input kind it can detect, every methodology
it ships, every organisation-config key it will take. Each of those lists came
out of the code when this was written, and each of them is exactly the kind of
list that rots silently.

Prose is not policed here. What is policed is that a name a reader would type
still exists, and that a name the code has still appears.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "docs" / "REFERENCE.md"


@pytest.fixture(scope="module")
def reference() -> str:
    return REFERENCE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def assure_section(reference: str) -> str:
    """Just the `assure` part, so a match elsewhere cannot stand in for it."""
    start = reference.index("### `assure`")
    rest = reference[start + 10:]
    end = rest.index("\n### ") if "\n### " in rest else len(rest)
    return rest[:end]


def _assure_flags() -> set[str]:
    """Every `--flag` the assure command reads, from the source that reads it.

    The whole function, not a fixed window from its start: `--full` is read on
    the last line of it, and a window that stopped short reported it as a flag
    the reference had invented.
    """
    source = (ROOT / "release_gate" / "cli.py").read_text(encoding="utf-8")
    start = source.index("def _run_assure_command")
    rest = source[start + 1:]
    end = rest.index("\ndef ") if "\ndef " in rest else len(rest)
    return set(re.findall(r"'(--[a-z][a-z-]+)'", rest[:end]))


class TestTheCommandIsDocumentedAtAll:

    def test_the_commands_table_lists_assure(self, reference):
        rows = [l for l in reference.splitlines() if l.startswith("| `release-gate assure")]
        assert rows, "the Commands table does not mention `release-gate assure`"

    def test_there_is_a_section_for_it(self, reference):
        assert "### `assure`" in reference


class TestEveryFlagIsDocumented:

    def test_every_flag_has_a_row_in_the_flags_table(self, assure_section):
        """A row, not a mention.

        The first version of this test accepted the flag appearing anywhere in
        the section — and the usage block at the top names them all, so a row
        could be deleted from the table with the test still green. What a
        reader needs is the row that says what the flag does.
        """
        rows = "\n".join(l for l in assure_section.splitlines()
                          if l.startswith("| `--"))
        missing = sorted(f for f in _assure_flags() if f"`{f}" not in rows)
        assert not missing, (
            "assure accepts flags with no row in the flags table: " + ", ".join(missing))

    def test_the_usage_block_names_them_too(self, assure_section):
        """The copy-pasteable line at the top should not omit one either."""
        usage = assure_section[:assure_section.index("Takes one file")]
        for flag in _assure_flags():
            # --diagnostics and --list-methodologies are modes, documented as rows.
            if flag in ("--diagnostics", "--list-methodologies"):
                continue
            assert flag in usage, f"{flag} is missing from the usage block"

    def test_no_flag_is_documented_that_does_not_exist(self, assure_section):
        """The other direction: a reader must not be told to type something gone."""
        real = _assure_flags()
        documented = set(re.findall(r"`(--[a-z][a-z-]+)`", assure_section))
        # --format is named only to say it does NOT exist, which is the point.
        documented.discard("--format")
        phantom = sorted(f for f in documented if f not in real)
        assert not phantom, (
            "the reference documents flags assure does not accept: " + ", ".join(phantom))


class TestTheListsMatchTheCode:

    def test_every_input_kind_it_can_detect_is_listed(self, assure_section):
        from release_gate.assurance.ingest import InputKind

        missing = [k.value for k in InputKind
                   if k is not InputKind.UNRECOGNISED and k.value not in assure_section]
        assert not missing, f"input kinds absent from the reference: {missing}"

    def test_unrecognised_is_described_rather_than_listed_as_a_format(self, assure_section):
        """It is an answer, not an input kind, and the doc should say so."""
        assert "UNRECOGNISED" in assure_section

    def test_every_methodology_that_ships_is_named(self, assure_section):
        from release_gate.assurance.methodologies import default_registry

        registry = default_registry()
        missing = [f"{i}@{v}" for i in registry.ids() for v in registry.versions(i)
                   if f"{i}@{v}" not in assure_section]
        assert not missing, f"methodologies absent from the reference: {missing}"

    def test_no_methodology_is_named_that_is_not_registered(self, assure_section):
        from release_gate.assurance.methodologies import default_registry

        registry = default_registry()
        real = {f"{i}@{v}" for i in registry.ids() for v in registry.versions(i)}
        named = set(re.findall(r"\b([a-z][a-z-]+@\d+\.\d+\.\d+)\b", assure_section))
        phantom = sorted(n for n in named if n not in real)
        assert not phantom, f"the reference names unregistered methodologies: {phantom}"

    def test_every_organisation_config_key_is_documented(self, assure_section):
        """A config key is refused if misspelled, so the list has to be right."""
        import dataclasses

        from release_gate.assurance.organisation import OrganisationConfig

        missing = [f.name for f in dataclasses.fields(OrganisationConfig)
                   if f"`{f.name}`" not in assure_section]
        assert not missing, f"config keys absent from the reference: {missing}"

    def test_the_risk_appetite_levels_are_the_real_ones(self, assure_section):
        from release_gate.assurance.level import AssuranceLevel

        for level in AssuranceLevel:
            assert f"`{level.name}`" in assure_section, (
                f"risk_appetite admits {level.name} but the reference omits it")


class TestTheExitCodesAreStated:

    @pytest.mark.parametrize("code,verdict", [("0", "PROMOTE"), ("10", "HOLD"), ("1", "BLOCK")])
    def test_each_code_appears_with_its_verdict(self, assure_section, code, verdict):
        assert re.search(rf"`{code}`\s*{verdict}", assure_section), (
            f"the reference does not pair exit {code} with {verdict}")


class TestTheChangelogCoversTheEngine:
    """Eighty-eight commits built it and the changelog described the website."""

    def _changelog(self) -> str:
        return (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_the_release_that_shipped_it_says_so(self):
        text = self._changelog()
        head = text[text.index("## [0.11.0]"):text.index("## [0.10.1]")]
        assert "### 🧩 The assurance engine" in head, (
            "0.11.0 shipped the assurance engine and its entry does not cover it")

    def test_the_attack_count_is_the_number_that_ships(self):
        """It said eighteen, from a commit message; twenty attacks ship."""
        source = (ROOT / "release_gate" / "assurance" / "hostile.py").read_text(encoding="utf-8")
        shipped = sum(1 for line in source.splitlines() if line.startswith("def _t_"))
        words = {18: "Eighteen", 20: "Twenty", 21: "Twenty-one", 22: "Twenty-two"}
        assert words.get(shipped, str(shipped)) + " attacks" in self._changelog(), (
            f"{shipped} attacks ship; the changelog states a different number")
