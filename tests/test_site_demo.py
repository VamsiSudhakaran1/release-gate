"""The website has to submit the same bytes and print the same numbers.

`public/assurance.html` is a working demo: a visitor pastes a run, the page POSTs
it to `/api/assure`, and the engine that answers is the one `pip install
release-gate` installs. That only stays true if three things hold, and each of
them has failed somewhere in this repo before:

  1. **The one-click samples are the example files.** They used to be typed into
     the page. A visitor who clicks "an agent's migration" and a reader who runs
     `release-gate assure examples/assurance/single-action.jsonl` must submit
     identical bytes, or the page is a mockup of the product rather than the
     product.
  2. **The verdicts the samples reach are pinned.** If the engine's answer to a
     shipped example changes, a page telling people what to expect is wrong
     before anyone notices.
  3. **The page is reachable and the embedded copy is current.** The site's
     homepage is embedded into a Python module for the serverless bundle;
     editing the HTML without regenerating it ships the old page.

The figures the homepage prints are guarded in `tests/test_positioning.py`,
against the same measurement the README is held to — the homepage is added to
those surfaces rather than given a second, independently-drifting check.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / "public" / "assurance.html"
INDEX = ROOT / "public" / "index.html"

# key in the page's SAMPLES literal -> (file it must equal, methodology it
# preselects, the decision the engine reaches on it).
SAMPLES = {
    "action": ("examples/assurance/single-action.jsonl",
               "general-autonomous-action@1.0.0", "BLOCK"),
    "trace": ("examples/assurance/agent-trace.json", None, "HOLD"),
    "research": ("examples/assurance/research-claim.jsonl",
                 "research-mathematics@1.1.0", "BLOCK"),
}


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _js_samples(text: str) -> dict[str, str]:
    """Pull the `const SAMPLES = {...}` literal back out of the page.

    The generator writes each sample with `json.dumps`, so every value is a JSON
    string literal and can be read back without a JS engine.
    """
    block = re.search(r"const SAMPLES = \{(.*?)\n\};", text, re.S)
    assert block, "public/assurance.html has no `const SAMPLES = {...};` block"
    out: dict[str, str] = {}
    for key, literal in re.findall(r'^\s*(\w+):\s*("(?:[^"\\]|\\.)*")',
                                   block.group(1), re.M):
        out[key] = json.loads(literal)
    return out


class TestTheSamplesAreTheFiles:
    """What the page submits is what the CLI reads — byte for byte."""

    def test_every_sample_is_present(self, page):
        assert set(_js_samples(page)) == set(SAMPLES)

    @pytest.mark.parametrize("key", sorted(SAMPLES))
    def test_the_sample_equals_the_file_on_disk(self, page, key):
        rel = SAMPLES[key][0]
        on_disk = (ROOT / rel).read_text(encoding="utf-8").rstrip("\n")
        assert _js_samples(page)[key] == on_disk, (
            f"the {key!r} sample has drifted from {rel} — run "
            "`python scripts/sync_demo_samples.py`")

    def test_the_generator_agrees_that_nothing_has_drifted(self):
        """The check the release runs, run here so CI is not the first to know."""
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sync_demo_samples.py"), "--check"],
            capture_output=True, text=True, cwd=str(ROOT))
        assert proc.returncode == 0, proc.stderr or proc.stdout

    def test_the_page_names_the_command_that_reproduces_each_sample(self, page):
        """"Same bytes from the CLI" is only fair if the path is the real one."""
        for rel, _, _ in SAMPLES.values():
            assert rel in page, f"the page never names {rel}"

    @pytest.mark.parametrize("key", sorted(SAMPLES))
    def test_the_methodology_the_page_preselects_is_registered(self, key):
        from release_gate.assurance.methodologies import default_registry

        wanted = SAMPLES[key][1]
        if wanted is None:
            return
        registry = default_registry()
        assert registry.resolve(wanted) is not None


class TestTheVerdictsThePageWillShow:
    """If the engine's answer to a shipped example moves, this is where it shows."""

    @pytest.mark.parametrize("key", sorted(SAMPLES))
    def test_the_sample_reaches_the_decision_the_docs_describe(self, key):
        from release_gate.assurance.methodologies import default_registry
        from release_gate.assurance.zero_config import assure

        rel, meth, expected = SAMPLES[key]
        methodology = default_registry().resolve(meth) if meth else None
        outcome = assure(str(ROOT / rel), methodology=methodology)
        assert outcome.case.verdict.decision.value == expected, (
            f"{rel} under {meth or 'no methodology'} now reaches "
            f"{outcome.case.verdict.decision.value}, not {expected}")

    @pytest.mark.parametrize("key", sorted(SAMPLES))
    def test_every_record_in_the_sample_is_accounted_for(self, key):
        """A sample that quietly loses records would demo the wrong thing.

        Not "nothing was skipped" — skipping is legitimate and counted. What is
        asserted is that mapped plus skipped equals seen, so the page can never
        show a total with a silent hole in it.
        """
        from release_gate.assurance.zero_config import assure

        rel = SAMPLES[key][0]
        n = assure(str(ROOT / rel)).normalisation
        assert n.records_mapped + n.skipped_total == n.records_seen

    def test_the_verdict_is_never_promote_without_a_methodology(self):
        """The page's own copy says it holds until a standard is named."""
        from release_gate.assurance.zero_config import assure

        for rel, _, _ in SAMPLES.values():
            outcome = assure(str(ROOT / rel))
            assert outcome.case.verdict.decision.value != "PROMOTE", rel


class TestThePageIsReachableAndCurrent:

    def test_the_homepage_links_to_the_demo(self):
        text = INDEX.read_text(encoding="utf-8")
        assert 'href="/assurance.html"' in text, (
            "public/index.html no longer links the assurance demo — the page "
            "exists but nothing on the site reaches it")

    def test_the_homepage_says_what_the_engine_is(self):
        """The site led with the scanner for a long time after the README moved on.

        This does not police wording; it asserts the homepage mentions the
        product the README calls the product, so the two cannot describe
        different companies.
        """
        text = INDEX.read_text(encoding="utf-8")
        assert 'id="assurance"' in text
        assert "NOT_ASSESSED" in text, (
            "the homepage no longer states that a verdict carries its coverage")

    def test_the_embedded_copy_matches_the_live_page(self):
        """`public/index.html` is bundled as a module for the serverless function.

        Editing the HTML without running `scripts/embed_frontend.py` ships the
        previous page in production while local dev looks correct — a drift that
        is invisible from the repo.
        """
        from release_gate_api._frontend import INDEX_HTML

        assert INDEX_HTML == INDEX.read_text(encoding="utf-8"), (
            "release_gate_api/_frontend.py is stale — run "
            "`python scripts/embed_frontend.py`")

    def test_the_demo_page_posts_to_the_endpoint_that_exists(self, page):
        """The page's one server dependency, checked against the router."""
        assert "'/api/assure'" in page or '"/api/assure"' in page
        from release_gate_api._app import app

        routes = {getattr(r, "path", None) for r in app.routes}
        assert "/api/assure" in routes


class TestTheHomepageFiguresAreTheMeasuredOnes:
    """The homepage prints the README's table. Same numbers, same measurement."""

    def test_the_record_total_is_the_one_the_demo_folds(self):
        from release_gate.demos.frontier_research import (
            DEFAULT_SCENARIO, build_normalisation)

        normalisation, _ = build_normalisation(DEFAULT_SCENARIO)
        printed = f"{normalisation.records_seen:,}"
        for name in ("README.md", "public/index.html"):
            assert printed in (ROOT / name).read_text(encoding="utf-8"), (
                f"{name} prints a record total that is not "
                f"{printed} — regenerate it from the demo")


class TestThePaletteCannotDriftBack:
    """Static guards for the two mistakes the redesign actually made.

    The contrast work itself was measured in a browser — ten page/theme
    combinations, every text node composited against what is really behind it —
    which is not something to run in this suite. What *is* worth pinning are the
    two specific ways the palette broke, because both were invisible in the
    source and both would come back the moment someone adds a button.
    """

    PAGES = ("public/index.html", "public/assurance.html", "public/demo.html",
             "public/research.html", "public/perfect-code.html")

    def test_no_page_hardcodes_white_on_an_accent_fill(self):
        """White over indigo was fine. White over gold is 1.5:1.

        A dozen inline styles paired `background:var(--accent)` with a literal
        `color:#fff`, which was correct until the accent changed and then was
        unreadable on every one of them. The pairing now goes through
        `--on-accent`, so the theme decides it.
        """
        import re

        bad = []
        for rel in self.PAGES:
            text = (ROOT / rel).read_text(encoding="utf-8")
            for m in re.finditer(r"background:\s*var\(--accent[^)]*\)\s*;\s*color:\s*#fff",
                                 text, re.I):
                bad.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
        assert not bad, ("white is hardcoded over an accent fill at " + ", ".join(bad)
                         + " — use var(--on-accent)")

    def test_the_indigo_the_palette_replaced_is_gone_from_the_pages(self):
        """#6366f1 was the old brand colour and survived in inline styles."""
        for rel in self.PAGES:
            text = (ROOT / rel).read_text(encoding="utf-8")
            assert "#6366f1" not in text, (
                f"{rel} still carries the replaced indigo literal")

    def test_every_page_defines_the_accent_text_colour(self):
        for rel in self.PAGES:
            text = (ROOT / rel).read_text(encoding="utf-8")
            if "var(--on-accent)" in text:
                assert "--on-accent:" in text, f"{rel} uses --on-accent but never defines it"

    def test_dark_is_the_default_on_every_page(self):
        """A visitor crossing between pages must not cross between themes.

        Each page's unset `:root` renders dark; light is reached only by
        choosing it. The check is that no page's default background is the
        paper colour.
        """
        import re

        for rel in self.PAGES:
            text = (ROOT / rel).read_text(encoding="utf-8")
            # A default block is any :root selector list with no [data-theme]
            # and no :not() on it — ":root {", ":root,\n:root[data-theme=\"dark\"] {"
            # both qualify for the unset case, and the last one wins.
            roots = re.findall(r"(:root[^{}@]*)\{([^}]*)\}", text)
            defaults = [body for sel, body in roots
                        if "--bg:" in body and ":not(" not in sel
                        and not re.search(r':root\s*\[data-theme="light"\]', sel)]
            assert defaults, f"{rel} has no :root block defining --bg"
            last = defaults[-1]
            m = re.search(r"--bg:\s*(#[0-9A-Fa-f]{6})", last)
            assert m, f"{rel}: could not read the default --bg"
            r, g, b = (int(m.group(1)[i:i + 2], 16) for i in (1, 3, 5))
            assert (r + g + b) / 3 < 80, (
                f"{rel} defaults to a light background ({m.group(1)}) — the rest "
                "of the site defaults to dark")
