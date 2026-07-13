"""Rule identity: every finding carries a stable, citable rule id."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.rules import RULES, rule_for_title, render_catalog_md
from release_gate.agent_analysis import analyze_python
from release_gate.verify import _scan_js_file


def test_rule_ids_are_unique_and_well_formed():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule id"
    import re
    for r in RULES:
        assert re.fullmatch(r"RG-[A-Z]+-\d{3}", r.id), r.id
        assert r.compliance and r.summary and r.remediation


def test_every_canonical_title_resolves_to_its_rule():
    for r in RULES:
        assert rule_for_title(r.title) is r


def test_reworded_titles_still_resolve_by_keyword():
    # Ids must survive wording changes — the classifier catches variants.
    assert rule_for_title("Dynamic execution sink (agent code)").id == "RG-EXEC-003"
    assert rule_for_title("Prompt injection risk (template literal)").id == "RG-PROMPT-001"
    assert rule_for_title("pickle.loads on unverified data").id == "RG-EXEC-002"


def test_python_findings_carry_rule_ids():
    fs = analyze_python(
        "def h(request):\n    return eval(request)\n"
        "from openai import OpenAI\nc=OpenAI()\nc.chat.completions.create(messages=m)\n",
        "x.py")
    assert fs
    for f in fs:
        assert f.get("rule_id"), f"{f['title']} has no rule_id"
        assert f["rule_id"].startswith("RG-")


def test_js_findings_carry_rule_ids():
    fs = _scan_js_file("a.ts", "const r = await generateText({ model: m, prompt: p });\n")
    assert fs and all(f.get("rule_id", "").startswith("RG-") for f in fs)


def test_sarif_uses_stable_rule_id_and_help_uri():
    import json, tempfile, os
    from release_gate.audit import emit_sarif
    report = {"code_findings": [{
        "title": "Dangerous execution sink", "file": "a.py", "line": 3,
        "severity": "high", "recommendation": "Use ast.literal_eval.",
        "rule_id": "RG-EXEC-001"}], "missing": []}
    p = tempfile.mktemp(suffix=".sarif")
    emit_sarif(report, p)
    sarif = json.load(open(p)); os.unlink(p)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "RG-EXEC-001"
    assert rule["helpUri"].endswith("#RG-EXEC-001")
    assert sarif["runs"][0]["results"][0]["ruleId"] == "RG-EXEC-001"


def test_rules_doc_in_sync():
    """docs/RULES.md must match the generator — run scripts/gen_rules_doc.py."""
    doc = (Path(__file__).resolve().parent.parent / "docs" / "RULES.md")
    assert doc.read_text(encoding="utf-8").strip() == render_catalog_md().strip(), \
        "docs/RULES.md is stale — run: python scripts/gen_rules_doc.py"
