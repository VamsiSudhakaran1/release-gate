#!/usr/bin/env python3
"""Regenerate docs/RULES.md from release_gate/rules.py (the single source of truth)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release_gate.rules import render_catalog_md
out = Path(__file__).resolve().parent.parent / "docs" / "RULES.md"
out.write_text(render_catalog_md() + "\n", encoding="utf-8")
print(f"wrote {out}")
