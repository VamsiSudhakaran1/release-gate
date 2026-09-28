#!/usr/bin/env python3
"""Keep the website demo's samples identical to the example files on disk.

`public/assurance.html` offers three one-click sample runs. Those samples used
to be typed into the page by hand, which is the same failure the rest of this
repo guards against everywhere else: a published artifact that quietly stops
matching the thing it claims to show. A visitor who clicks "an agent's action"
and a reader who runs

    release-gate assure examples/assurance/single-action.jsonl

must be submitting the same bytes, or the page is a mockup of the product.

So the samples are generated from `examples/assurance/*`, and
`tests/test_site_demo.py` fails if the page drifts from them. Run:

    python scripts/sync_demo_samples.py            # rewrite the block
    python scripts/sync_demo_samples.py --check    # fail if it would change
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "public" / "assurance.html"

# sample key -> the file a reader would pass to the CLI to get the same result.
SAMPLES: dict[str, str] = {
    "action": "examples/assurance/single-action.jsonl",
    "trace": "examples/assurance/agent-trace.json",
    "research": "examples/assurance/research-claim.jsonl",
}

_BLOCK = re.compile(r"const SAMPLES = \{.*?\n\};", re.S)


def render_block() -> str:
    """The `const SAMPLES = {...};` literal, built from the files themselves."""
    lines = ["const SAMPLES = {"]
    for i, (key, rel) in enumerate(SAMPLES.items()):
        text = (ROOT / rel).read_text(encoding="utf-8").rstrip("\n")
        # json.dumps gives a correctly escaped JS string literal for any content,
        # including the newlines that make a JSONL file several records.
        literal = json.dumps(text)
        comma = "," if i < len(SAMPLES) - 1 else ""
        lines.append(f"  // {rel}")
        lines.append(f"  {key}: {literal}{comma}")
    lines.append("};")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    page = PAGE.read_text(encoding="utf-8")
    if not _BLOCK.search(page):
        print("no `const SAMPLES = {...};` block found in", PAGE, file=sys.stderr)
        return 2
    updated = _BLOCK.sub(lambda _: render_block(), page, count=1)
    if "--check" in argv:
        if updated != page:
            print("public/assurance.html has drifted from examples/assurance/ — "
                  "run `python scripts/sync_demo_samples.py`", file=sys.stderr)
            return 1
        print("public/assurance.html matches examples/assurance/")
        return 0
    if updated == page:
        print("already in sync")
        return 0
    PAGE.write_text(updated, encoding="utf-8")
    print(f"rewrote the samples in {PAGE.relative_to(ROOT)} from "
          + ", ".join(SAMPLES.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
