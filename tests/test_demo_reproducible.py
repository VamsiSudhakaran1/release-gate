"""The published demo must actually reproduce — on GitHub and on the website.

`examples/demo-code-risk/` is the one artifact a stranger runs before trusting
anything else we claim, and it is quoted verbatim in three places (the demo's own
README, the repo README, and public/demo.html). If the engine's output drifts
from those quotes, the demo becomes a mockup — exactly what we tell people we
don't ship.

So this suite:
  1. runs the real demo end to end (git repo + `release-gate pr`), and
  2. asserts every claim the docs make about it, including the provenance chain,
  3. then checks the published pages still quote the live output.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-code-risk"


def _run_demo() -> str:
    """Run build_demo.sh and return its combined output, ANSI stripped."""
    env = {**os.environ, "PATH": os.environ.get("PATH", ""), "NO_COLOR": "1"}
    proc = subprocess.run(
        ["bash", str(DEMO / "build_demo.sh")],
        capture_output=True, text=True, timeout=300, env=env, cwd=str(DEMO),
    )
    out = proc.stdout + proc.stderr
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", out)


@pytest.fixture(scope="module")
def demo_output():
    if shutil.which("git") is None:
        pytest.skip("git is required to build the demo repo")
    return _run_demo()


def test_demo_blocks_the_pull_request(demo_output):
    # The headline claim: the PR that introduces eval(model_output) is BLOCKed.
    assert "BLOCK" in demo_output
    assert "Agent Code Safety:** 100 → 76" in demo_output, \
        "the score delta quoted in the docs changed"


def test_demo_high_is_confirmed_and_cites_the_traced_origin(demo_output):
    # The tier contract, demonstrated on a real file: this HIGH is confirmed
    # because the value was traced to the LLM call, and the finding says so.
    assert "**HIGH** (high · confirmed): Dangerous execution sink  `agent.py:25`" in demo_output
    assert "traced to the model's own output at line 17" in demo_output, \
        "the HIGH no longer cites its origin line — provenance evidence regressed"


def test_demo_reports_only_what_the_diff_introduced(demo_output):
    # The gate's whole premise: net-new risk only, never inherited debt.
    assert "Introduced by this change" in demo_output
    assert "not pre-existing" in demo_output


def test_demo_agent_files_are_the_ones_analyzed():
    # Guard against the demo sources silently drifting from the quoted lines.
    vuln = (DEMO / "vulnerable" / "agent.py").read_text(encoding="utf-8").splitlines()
    assert vuln[16].strip().startswith("resp = client.chat.completions.create"), \
        "line 17 is quoted as the model call in the docs"
    assert vuln[24].strip().startswith("return eval(expr"), \
        "line 25 is quoted as the eval sink in the docs"


def test_published_pages_quote_the_live_output(demo_output):
    """The website and READMEs must quote what the engine actually prints."""
    claim = "traced to the model's own output at line 17"
    pages = {
        "examples/demo-code-risk/README.md": ROOT / "examples/demo-code-risk/README.md",
        "README.md": ROOT / "README.md",
        "public/demo.html": ROOT / "public" / "demo.html",
    }
    for label, path in pages.items():
        text = path.read_text(encoding="utf-8")
        assert claim in text, (
            f"{label} no longer quotes the live demo output "
            f"({claim!r}) — regenerate it from `./build_demo.sh`")


def test_tier_contrast_case_stays_medium():
    """The 'we don't cry wolf' half of the demo, checked in-process.

    The same eval-shaped sink with an origin we cannot see must NOT be a HIGH.
    This is the claim the demo page makes next to the confirmed finding.
    """
    sys.path.insert(0, str(ROOT))
    from release_gate.agent_analysis import analyze_python
    src = (DEMO / "lookalike" / "agent.py").read_text(encoding="utf-8")
    findings = analyze_python(src, "agent.py")
    assert findings, "the lookalike must still be reported, just not as a HIGH"
    assert not [f for f in findings if f["severity"] in ("high", "critical")], \
        "a value with no visible origin was graded HIGH — tier contract broken"
    assert any(f["basis"] == "inferred" for f in findings)
