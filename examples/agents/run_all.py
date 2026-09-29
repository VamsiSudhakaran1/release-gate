#!/usr/bin/env python3
"""Run every example and print what each one decides — on any OS.

`run-all.sh` needs bash, which Windows does not have by default. This does the
same thing through the Python API, so `python run_all.py` works identically in
cmd, PowerShell, and a shell.

Nothing here is pinned to an expected answer: the verdicts are whatever the
engine reaches on these inputs today.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# file, methodology (None = zero-config)
RUNS = [
    ("01-coding-agent-otel.json", None),
    ("01-coding-agent-otel.json", "general-autonomous-action@1.0.0"),
    ("02-release-promoted.jsonl", "general-autonomous-action@1.0.0"),
    ("03-support-eval-promptfoo.json", None),
    ("04-production-db-change.jsonl", "production-database-change@1.0.0"),
    ("05-research-swarm.jsonl", "research-mathematics@1.0.0"),
    ("05-research-swarm.jsonl", "research-mathematics@1.1.0"),
]


def main() -> int:
    try:
        from release_gate.assurance.methodologies import default_registry
        from release_gate.assurance.zero_config import assure
    except ImportError:
        print("release-gate is not importable from this interpreter.\n"
              "Activate the virtualenv you installed it into, then re-run:\n"
              "  Windows:  .venv\\Scripts\\activate\n"
              "  macOS/Linux:  source .venv/bin/activate", file=sys.stderr)
        return 2

    import release_gate
    print(f"release-gate {release_gate.__version__}\n")
    print(f"{'INPUT':<34} {'METHODOLOGY':<34} {'VERDICT':<9} EXIT")
    print("-" * 92)

    registry = default_registry()
    worst = 0
    for name, methodology in RUNS:
        resolved = registry.resolve(methodology) if methodology else None
        outcome = assure(str(HERE / name), methodology=resolved)
        decision = outcome.case.verdict.decision.value
        print(f"{name:<34} {methodology or '(none)':<34} "
              f"{decision:<9} {outcome.exit_code}")
        worst = max(worst, 0)          # reporting only; never fail on a verdict

    print("\n exit codes: 0 PROMOTE * 10 HOLD * 1 BLOCK")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
