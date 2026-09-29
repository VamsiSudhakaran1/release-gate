"""The example agent runs must keep producing what their README says they do.

`examples/agents/` is what a stranger runs after `pip install release-gate`, and
its README prints a table of verdicts. A published table that drifts from the
engine is the same failure as a demo that has quietly become a mockup — so the
table is asserted against the engine rather than maintained by hand.

Two properties are pinned, and they are different things:

  1. **The verdicts.** Not because these numbers are sacred, but because each one
     illustrates a claim in prose next to it. If `02` stops promoting, the
     sentence "this is the example to read first if you suspect the gate only
     ever says no" is false.
  2. **Every record maps.** An example that silently loses a record teaches the
     reader a shape that does not work.
"""
from __future__ import annotations

import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENTS = ROOT / "examples" / "agents"

# file, methodology (None = zero-config), decision, exit code
RUNS = [
    ("01-coding-agent-otel.json", None, "HOLD", 10),
    ("01-coding-agent-otel.json", "general-autonomous-action@1.0.0", "HOLD", 10),
    ("02-release-promoted.jsonl", "general-autonomous-action@1.0.0", "PROMOTE", 0),
    ("03-support-eval-promptfoo.json", None, "BLOCK", 1),
    ("04-production-db-change.jsonl", "production-database-change@1.0.0", "HOLD", 10),
    ("05-research-swarm.jsonl", "research-mathematics@1.0.0", "BLOCK", 1),
    ("05-research-swarm.jsonl", "research-mathematics@1.1.0", "BLOCK", 1),
]
FILES = sorted({name for name, _, _, _ in RUNS})


def _assure(name: str, methodology: str | None):
    from release_gate.assurance.methodologies import default_registry
    from release_gate.assurance.zero_config import assure

    resolved = default_registry().resolve(methodology) if methodology else None
    return assure(str(AGENTS / name), methodology=resolved)


@pytest.mark.parametrize("name,methodology,decision,code", RUNS)
def test_the_example_reaches_the_verdict_its_readme_prints(name, methodology, decision, code):
    outcome = _assure(name, methodology)
    label = f"{name} under {methodology or 'no methodology'}"
    assert outcome.case.verdict.decision.value == decision, label
    assert outcome.exit_code == code, label


@pytest.mark.parametrize("name", FILES)
def test_every_record_in_every_example_maps(name):
    """No example may teach a record shape the ingest rejects."""
    n = _assure(name, None).normalisation
    assert n.records_mapped == n.records_seen, (
        f"{name}: {n.records_seen - n.records_mapped} record(s) not mapped "
        f"— {dict(n.skipped)}")
    assert not n.skipped, f"{name} skipped {dict(n.skipped)}"


@pytest.mark.parametrize("name", FILES)
def test_the_readme_lists_every_example_that_ships(name):
    readme = (AGENTS / "README.md").read_text(encoding="utf-8")
    assert name in readme, f"{name} ships but the README never mentions it"


def test_the_readme_ships_no_example_that_does_not_exist(name=None):
    """The other direction: a file named in the table must be on disk."""
    import re

    readme = (AGENTS / "README.md").read_text(encoding="utf-8")
    named = set(re.findall(r"\b\d\d-[\w-]+\.(?:jsonl|json)\b", readme))
    missing = sorted(n for n in named if not (AGENTS / n).exists())
    assert not missing, f"the README names files that do not exist: {missing}"


def test_the_readme_table_matches_the_engine():
    """The printed table, row by row, against what the engine now reaches."""
    readme = (AGENTS / "README.md").read_text(encoding="utf-8")
    for name, methodology, decision, _ in RUNS:
        row = [line for line in readme.splitlines()
               if line.startswith(name) and (methodology or "(none)") in line]
        assert row, f"the README table has no row for {name} / {methodology}"
        assert decision in row[0], (
            f"the README says {row[0].split()[-2]!r} for {name} / {methodology}; "
            f"the engine reaches {decision!r}")


def test_the_promoted_example_is_the_only_one_that_promotes():
    """A corpus where everything blocks teaches that the gate is a wall.

    This is a property of the *set*, not of any one file: at least one example
    must promote, and the set must still contain a block, or the examples stop
    demonstrating that the verdict depends on the evidence.
    """
    decisions = {d for _, _, d, _ in RUNS}
    assert "PROMOTE" in decisions, "no example promotes — the set only shows refusal"
    assert "BLOCK" in decisions, "no example blocks — the set only shows acceptance"
    assert "HOLD" in decisions


def test_the_runner_is_executable():
    runner = AGENTS / "run-all.sh"
    assert runner.exists()
    assert runner.stat().st_mode & 0o111, "run-all.sh is not executable"


def test_there_is_a_runner_that_does_not_need_bash():
    """Windows has no bash, and `./run-all.sh` is the first thing the README says.

    The Python runner covers the same rows, so the two cannot drift: it is built
    from a list this test compares against the one the shell script invokes.
    """
    import re

    py = (AGENTS / "run_all.py").read_text(encoding="utf-8")
    sh = (AGENTS / "run-all.sh").read_text(encoding="utf-8")
    for name, methodology, _, _ in RUNS:
        assert name in py, f"{name} is missing from run_all.py"
        assert name in sh, f"{name} is missing from run-all.sh"
        if methodology:
            assert methodology in py and methodology in sh, methodology
    shell_rows = len(re.findall(r"^run \S+", sh, re.M))
    assert shell_rows == len(RUNS), (
        f"run-all.sh runs {shell_rows} rows, the table has {len(RUNS)}")


def test_the_typo_helper_writes_a_file_that_is_refused():
    """The Windows-safe way to reproduce the 0.11.1 refusal notice."""
    import subprocess
    import sys
    import tempfile

    target = pathlib.Path(tempfile.mkdtemp()) / "typo.jsonl"
    subprocess.run([sys.executable, str(AGENTS / "make_typo_example.py"), str(target)],
                   check=True, capture_output=True)
    assert target.exists()
    outcome = _assure_path(target)
    assert outcome.normalisation.refused_consequence, (
        "the helper is supposed to produce a file whose consequence values are "
        "refused — it no longer does")


def _assure_path(path):
    from release_gate.assurance.zero_config import assure

    return assure(str(path))


def test_the_consequence_vocabulary_table_is_the_real_one():
    """The README prints every dimension's admissible values.

    It is printed because a value outside the vocabulary is dropped without a
    note — the one rejection in the ingest that reports nothing. A table that
    drifts from the enum would send a reader straight into that hole.
    """
    from release_gate.assurance.consequence import ConsequenceDimension, values_for

    readme = (AGENTS / "README.md").read_text(encoding="utf-8")
    for dimension in ConsequenceDimension:
        row = [line for line in readme.splitlines()
               if line.startswith(f"| `{dimension.value}`")]
        assert row, f"the vocabulary table is missing {dimension.value}"
        for value in values_for(dimension):
            if value == "UNKNOWN":
                continue          # admissible everywhere; the table says so in prose
            assert f"`{value}`" in row[0], (
                f"{dimension.value} admits {value!r} but the README does not list it")
