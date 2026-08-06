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

    # 2. Every Action pin anywhere in the repo must be @v<version>. Any other
    #    release-gate@vX.Y.Z is a stale pin a user would copy verbatim.
    #
    #    DISCOVERED, not listed. A hardcoded file list silently stopped covering
    #    new docs: `integrations/` shipped with @v0.9.4 pins and this check
    #    passed the release anyway. A copy-pasteable pin pointing at the wrong
    #    release is exactly the drift this guard exists to prevent, so the guard
    #    has to find files rather than be told about them.
    action_re = re.compile(
        r"VamsiSudhakaran1/release-gate@v(\d+\.\d+\.\d+)"
        r"|rev:\s*v(\d+\.\d+\.\d+)")
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "release_gate.egg-info", "dist", "build"}
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in (".md", ".html", ".yml", ".yaml"):
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        # The changelog is a HISTORY of releases — old versions belong in it.
        if path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(ROOT).as_posix()
        for a, b in set(action_re.findall(text)):
            pinned = a or b
            if pinned and pinned != version:
                errors.append(f"{rel}: Action pin v{pinned} != pyproject {version}")

    if errors:
        print("Version drift detected (source of truth: pyproject.toml = "
              f"{version}):", file=sys.stderr)
        for e in errors:
            print("  [X] " + e, file=sys.stderr)
        print("\nBump every reference to match, or run this after a release bump.",
              file=sys.stderr)
        return 1

    print(f"[OK] version {version} consistent across pyproject, package, API, and "
          "every Action pin found in the repo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
