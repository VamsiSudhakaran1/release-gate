"""Partition a scanned corpus by whether each project gates centrally.

    python benchmark/triage_corpus.py /path/to/corpus

Why this exists: RG-GATE-001 only legitimately fires on projects that do NOT
implement a central approval layer. homeassistant-ai/ha-mcp taught us that the
hard way — we filed an issue asking for controls it already had. Since the
scanner learned to detect a gate layer, that flag doubles as a TARGETING signal:

  gate_layer=True  -> gates centrally; findings suppressed; NOT a target.
  gate_layer=False -> the population where the finding is real.

Run this BEFORE writing to any maintainer.
"""
import sys, re, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release_gate.verify import scan_code_findings
import release_gate.verify as v

root = Path(sys.argv[1])
rows = []
for repo in sorted(p for p in root.iterdir() if p.is_dir()):
    try:
        fs = scan_code_findings(repo)
    except Exception as e:
        rows.append({"repo": repo.name, "error": f"{type(e).__name__}: {e}"[:120]})
        continue
    cov = dict(v.LAST_SCAN_COVERAGE)
    gate = [f for f in fs if f.get("rule_id") == "RG-GATE-001"
            and "gates centrally" not in f.get("title", "")]
    tools = []
    for f in gate:
        m = re.search(r"tool `([^`]+)`", f.get("evidence") or "")
        if m:
            tools.append(m.group(1))
    rows.append({
        "repo": repo.name,
        "gate_layer": cov.get("gate_layer"),
        "total": len(fs),
        "high": sum(1 for f in fs if f.get("severity") in ("high", "critical")),
        "ungated_tools": len(gate),
        "tools": tools[:12],
    })
print(json.dumps(rows, indent=1))
