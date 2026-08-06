#!/usr/bin/env python3
"""Bump the release version everywhere the version-sync guard checks — in one
cross-platform command (works in Windows cmd/PowerShell, macOS, Linux; no `sed`).

    python scripts/bump_version.py 0.8.6

pyproject.toml is the source of truth. This updates it plus every pin
check_version_sync.py enforces — the package __version__, the API/health
version, and the GitHub Action pins in public/index.html and README.md — then
re-embeds the frontend and runs the sync check to prove nothing drifted.

It does NOT commit or tag; it prints the exact git commands to finish the
release (pushing the tag is what triggers .github/workflows/publish.yml).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _current_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"',
                  (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit("FATAL: no version in pyproject.toml")
    return m.group(1)


def _sub(rel: str, pattern: str, repl: str, count: int = 0) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=count, flags=re.M)
    if n == 0:
        sys.exit(f"FATAL: nothing to update in {rel} (pattern {pattern!r}) — "
                 "check the file by hand.")
    path.write_text(new, encoding="utf-8")
    print(f"  updated {rel} ({n} pin{'s' if n != 1 else ''})")


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+[\w.\-]*", sys.argv[1]):
        sys.exit("usage: python scripts/bump_version.py X.Y.Z")
    new = sys.argv[1]
    old = _current_version()
    if new == old:
        sys.exit(f"version is already {new}")
    print(f"bumping {old} -> {new}")

    _sub("pyproject.toml", r'^(version\s*=\s*)"[^"]+"', rf'\g<1>"{new}"', count=1)
    _sub("release_gate/__init__.py", r'(__version__\s*=\s*)"[^"]+"', rf'\g<1>"{new}"', count=1)
    _sub("release_gate_api/_app.py", rf'("version":\s*)"{re.escape(old)}"', rf'\g<1>"{new}"')
    # Action pins are DISCOVERED, not listed. A hardcoded file list quietly
    # stopped covering new docs — `integrations/` shipped pinned at @v0.9.4 and
    # two older docs sat at @v0.7.3 / @v0.8.5 for several releases, because
    # nothing walked the tree. Users copy these verbatim, so a stale pin hands
    # them the wrong release.
    pin_re = re.compile(r"(VamsiSudhakaran1/release-gate@v|rev:\s*v)(\d+\.\d+\.\d+)")
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "release_gate.egg-info", "dist", "build"}
    updated = 0
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in (".md", ".html", ".yml", ".yaml"):
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.name == "CHANGELOG.md":   # a release history keeps its old versions
            continue
        text = path.read_text(encoding="utf-8")
        newtext, n = pin_re.subn(rf"\g<1>{new}", text)
        if n:
            path.write_text(newtext, encoding="utf-8")
            print(f"  updated {path.relative_to(ROOT).as_posix()} "
                  f"({n} pin{'s' if n != 1 else ''})")
            updated += n
    if not updated:
        sys.exit("FATAL: no Action pins found to update — check the repo by hand.")

    print("  re-embedding frontend (scripts/embed_frontend.py) ...")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "embed_frontend.py")],
                   check=True)

    print("  verifying (scripts/check_version_sync.py) ...")
    rc = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_version_sync.py")]).returncode
    if rc != 0:
        return rc

    print(
        f"\n[OK] Bumped to {new}. Reminder: move docs/CHANGELOG.md '[Unreleased]' "
        f"to '[{new}]'.\n\nFinish the release:\n"
        f"  git commit -am \"Release v{new}\"\n"
        f"  git push origin main\n"
        f"  git tag v{new}\n"
        f"  git push origin v{new}      (this triggers the Publish workflow)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
