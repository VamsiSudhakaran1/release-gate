"""Shared call-to-action footer for CLI output.

Every CLI command prints a short, consistent teaser that points the user to
release-gate.com for the full picture — the detailed findings, the shareable
web report, and the downloadable PDF. The terminal shows enough to create
interest; the website shows the full breakdown.

Keep this lightweight and dependency-free so every command can call it.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

WEB_BASE = os.environ.get("RELEASE_GATE_WEB_BASE", "https://release-gate.com").rstrip("/")


def web_url(path: str = "") -> str:
    if not path:
        return WEB_BASE
    return f"{WEB_BASE}/{path.lstrip('/')}"


def print_web_cta(
    *,
    run_id: Optional[str] = None,
    teaser: Optional[str] = None,
    label: str = "Full report, detailed findings & PDF",
    locked: Optional[int] = None,
    stream=None,
) -> None:
    """Print a consistent 'see the full picture online' footer.

    run_id   if present, link straight to the saved run's web report
    teaser   one-line hook shown above the link (e.g. "4 high-severity issues")
    locked   number of additional details withheld from the terminal, teased
             as available on the web ("+12 more findings online")
    """
    out = stream or sys.stdout
    url = web_url(f"r/{run_id}") if run_id else WEB_BASE
    print("", file=out)
    print("  ── See the full picture ──", file=out)
    if teaser:
        print(f"  {teaser}", file=out)
    if locked and locked > 0:
        print(f"  +{locked} more detail{'s' if locked != 1 else ''} in the full report", file=out)
    print(f"  {label}:", file=out)
    print(f"  → {url}", file=out)
