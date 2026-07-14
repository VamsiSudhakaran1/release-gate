#!/usr/bin/env python3
"""Fail if the version drifts across the repo.

pyproject.toml is the single source of truth. Every machine-consumable version
pin — the package __version__, the API/health version, the SARIF tool version,
and every `VamsiSudhakaran1/release-gate@vX.Y.Z` Action pin on the site and in
the docs — must match it. Wired into CI so "polish" is enforced, not remembered.

    python scripts/check_version_sync.py        # exits 1 on any mismatch
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"',
                  (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    if not m:
        print("FATAL: no version in pyproject.toml", file=sys.stderr)
        sys.exit(2)
    return m.group(1)


def main() -> int:
    version = _pyproject_version()
    errors: list[str] = []

    # 1. Exact-string pins that must equal the pyproject version.
    exact = {
        "release_gate/__init__.py": f'__version__ = "{version}"',
        "release_gate_api/_app.py": f'"status": "ok", "version": "{version}"',
    }
    for rel, needle in exact.items():
        text = (ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        if needle not in text:
            errors.append(f"{rel}: expected {needle!r} (pyproject is {version})")

    # 2. Every Action pin across site + docs must be @v<version>. Any other
    #    release-gate@vX.Y.Z is a stale pin.
    action_re = re.compile(r"VamsiSudhakaran1/release-gate@v(\d+\.\d+\.\d+)")
    for rel in ("public/index.html", "README.md"):
        text = (ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        for pinned in set(action_re.findall(text)):
            if pinned != version:
                errors.append(f"{rel}: Action pin @v{pinned} != pyproject {version}")

    if errors:
        print("Version drift detected (source of truth: pyproject.toml = "
              f"{version}):", file=sys.stderr)
        for e in errors:
            print("  [X] " + e, file=sys.stderr)
        print("\nBump every reference to match, or run this after a release bump.",
              file=sys.stderr)
        return 1

    print(f"[OK] version {version} consistent across pyproject, package, API, and "
          "all Action pins (site + README).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
