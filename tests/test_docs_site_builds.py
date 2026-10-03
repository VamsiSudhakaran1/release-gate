"""The docs/ folder is a GitHub Pages site, and Pages runs every page through Liquid.

`jekyll-optional-front-matter` renders every Markdown file in docs/ as a Liquid
template, so text a page means literally can end the whole build. A spec line
quoting a payload of four opening braces did exactly that: Liquid read `{{` as an
output tag, found no `}}` on the line, and every Pages build on main failed from
then on. Nothing in the suite noticed, because nothing here builds the site.

This is the subset of Liquid's tokenizer that matters: an output tag opens with
`{{` and must close with `}}` on the same line, a tag opens with `{%` and must
close with `%}`. Checked against Liquid 4.0.4 (the version GitHub Pages runs):
it accepts every file this test accepts.
"""

from __future__ import annotations

import pathlib
import re

import pytest

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
PAGES = sorted(p for p in DOCS.rglob("*.md") if "_site" not in p.parts)

_OUTPUT = re.compile(r"\{\{(?P<body>[^\n]*?)\}\}")
_TAG = re.compile(r"\{%(?P<body>[^\n]*?)%\}")


def _unterminated(text: str, opener: str, pattern: re.Pattern) -> list:
    closed = {m.start() for m in pattern.finditer(text)}
    lines = []
    for match in re.finditer(re.escape(opener), text):
        start = match.start()
        # `{{{{` is two openers back to back; the first one has to close.
        if start not in closed and not any(s < start < e for s, e in
                                           ((m.start(), m.end())
                                            for m in pattern.finditer(text))):
            lines.append(text.count("\n", 0, start) + 1)
    return lines


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(DOCS)))
def test_liquid_would_not_end_the_build(page):
    text = page.read_text(encoding="utf-8")
    bad = (_unterminated(text, "{{", _OUTPUT) + _unterminated(text, "{%", _TAG))
    assert not bad, (
        f"{page.relative_to(DOCS)} has a Liquid opener with no closer on line(s) "
        f"{sorted(set(bad))[:5]}; GitHub Pages fails to build docs/ on it. Reword "
        "the text, or put it in a code span that does not contain the braces.")


def test_it_finds_what_broke_the_build():
    """The line that broke Pages, as it was."""
    line = "a payload spelling `{{{{` in a field does not read as depth\nmore\n"
    assert _unterminated(line, "{{", _OUTPUT)
    assert not _unterminated("    name: governance-${{ github.run_id }}\n", "{{", _OUTPUT)
    assert not _unterminated("checks{{status:{report['overall']}}} > 0\n", "{{", _OUTPUT)
