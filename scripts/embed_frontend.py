#!/usr/bin/env python3
"""Regenerate release_gate_api/_frontend.py from public/index.html.

The frontend HTML must be embedded as a Python module so Vercel's serverless
function bundles it (static files in public/ are not traced/bundled with a
pyproject entrypoint). Run this after editing public/index.html:

    python scripts/embed_frontend.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
out = ROOT / "release_gate_api" / "_frontend.py"
with out.open("w", encoding="utf-8") as f:
    f.write('"""Auto-generated from public/index.html so the frontend is bundled\n')
    f.write("with the Vercel serverless function. Regenerate with:\n")
    f.write("    python scripts/embed_frontend.py\n\"\"\"\n\n")
    f.write("INDEX_HTML = ")
    f.write(repr(html))
    f.write("\n")
print(f"wrote {out} ({len(html)} chars)")
