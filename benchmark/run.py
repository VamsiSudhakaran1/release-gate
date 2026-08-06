#!/usr/bin/env python3
"""release-gate accuracy benchmark — reproducible precision/recall.

Runs the static engine over a labeled corpus (benchmark/cases.yaml) and reports
per-rule and overall precision, recall, F1, plus the clean-case false-positive
rate. This is the "accuracy demonstrated, not asserted" artifact: anyone can
re-run it, and every result is checked against ground truth we publish.

    python benchmark/run.py            # human report
    python benchmark/run.py --json     # machine output
    python benchmark/run.py --md       # regenerate benchmark/RESULTS.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402
# Use the PRODUCTION file scanners (same path scan_code_findings uses), so the
# benchmark exercises exactly what ships — including the secret scan, which the
# AST analyzer alone doesn't cover.
from release_gate.verify import _scan_file, _scan_js_file  # noqa: E402

ROOT = Path(__file__).resolve().parent


def _findings(case) -> list:
    # A `files:` case is a whole miniature REPO, scanned through the real
    # directory walker. Repo-level rules (RG-PII-001's masked-here/raw-there
    # comparison) are claims about a project, not a file, so a single-snippet
    # harness cannot express either their true positives or — more importantly —
    # the clean cases that prove they stay quiet.
    if "files" in case:
        import tempfile
        from release_gate.verify import scan_code_findings
        with tempfile.TemporaryDirectory() as d:
            for name, src in case["files"].items():
                p = Path(d) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(src)
            return list(scan_code_findings(Path(d)))
    code, lang = case["code"], case.get("lang", "py")
    if lang in ("ts", "js", "tsx", "jsx"):
        return _scan_js_file(f"case.{lang}", code)
    return _scan_file("case.py", code)


def _rule_ids(case) -> set:
    return {f.get("rule_id") for f in _findings(case) if f.get("rule_id")}


# Rules whose HIGH tier is backed by a traced value, and so must carry a
# provenance chain. Rules that grade HIGH on STRUCTURE alone (a system-prompt
# constructor, an unbounded loop) are proven by the shape of the code itself,
# so they assert confirmed without a value chain.
_TAINT_RULES = {"RG-EXEC-001", "RG-EXEC-004", "RG-ACTION-002", "RG-ACTION-003",
                "RG-ACTION-004", "RG-PROMPT-002", "RG-PII-001"}


def audit_high_tier(cases) -> list:
    """THE HIGH-TIER INVARIANT — the check that keeps HIGHs watertight.

    Every HIGH the engine emits anywhere in the corpus must be `confirmed`, and
    every HIGH from a taint-based rule must carry a `provenance` block with the
    origin and sink line numbers. A reader can then open those two lines and
    check the claim. Violations are returned; the test suite fails on any.

    This exists because a HIGH is the only thing we ask a maintainer to act on.
    Before 0.9.4 a variable NAME could mint one, and each such HIGH that turned
    out to be the project's own trusted data cost more credibility than ten
    missed MEDIUMs would have.
    """
    violations = []
    for c in cases:
        for f in _findings(c):
            if f.get("severity") not in ("high", "critical"):
                continue
            rid, basis = f.get("rule_id"), f.get("basis")
            if basis != "confirmed":
                violations.append((c["id"], rid, f"HIGH with basis={basis!r}"))
            elif not (f.get("evidence") or "").strip():
                # Added after RG-LOOP-001 emitted 39 confirmed HIGHs with an
                # EMPTY evidence field on one repo. A HIGH a reader cannot check
                # is exactly what this invariant exists to prevent, and keying
                # only on the taint rules let it through.
                violations.append((c["id"], rid, "HIGH with empty evidence"))
            elif rid in _TAINT_RULES and not f.get("provenance"):
                violations.append((c["id"], rid, "HIGH with no provenance chain"))
    return violations


def evaluate(cases) -> dict:
    tp = fp = fn = 0
    per_rule: dict = {}
    clean_total = clean_quiet = 0
    misclassified = []
    for c in cases:
        expected = set(c.get("expect") or [])
        got = _rule_ids(c)
        if c["label"] == "clean":
            clean_total += 1
            if not got:
                clean_quiet += 1
        for r in expected:
            d = per_rule.setdefault(r, {"tp": 0, "fp": 0, "fn": 0})
            if r in got:
                tp += 1; d["tp"] += 1
            else:
                fn += 1; d["fn"] += 1
                misclassified.append((c["id"], "MISS", r))
        for r in got - expected:
            fp += 1
            per_rule.setdefault(r, {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
            misclassified.append((c["id"], "FALSE-POSITIVE", r))

    def pr(t, f_):  # precision-style ratio, 1.0 when no predictions
        return round(t / (t + f_), 4) if (t + f_) else 1.0

    return {
        "cases": len(cases),
        "vulnerable": sum(1 for c in cases if c["label"] == "vulnerable"),
        "clean": clean_total,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": pr(tp, fp),
        "recall": pr(tp, fn),
        "f1": round(2 * pr(tp, fp) * pr(tp, fn) / (pr(tp, fp) + pr(tp, fn)), 4)
              if (pr(tp, fp) + pr(tp, fn)) else 0.0,
        "clean_quiet_rate": round(clean_quiet / clean_total, 4) if clean_total else 1.0,
        "high_tier_violations": audit_high_tier(cases),
        "per_rule": {k: {**v, "precision": pr(v["tp"], v["fp"]),
                         "recall": pr(v["tp"], v["fn"])}
                     for k, v in sorted(per_rule.items())},
        "misclassified": misclassified,
    }


def load_cases():
    return yaml.safe_load((ROOT / "cases.yaml").read_text(encoding="utf-8"))["cases"]


def render_md(res: dict) -> str:
    o = ["# release-gate accuracy benchmark — results", "",
         "> Generated by `python benchmark/run.py --md`. Ground truth lives in "
         "`benchmark/cases.yaml`; re-run it yourself.", "",
         f"**Corpus:** {res['cases']} labeled cases "
         f"({res['vulnerable']} vulnerable · {res['clean']} clean look-alikes).",
         "",
         "| Metric | Value |", "|---|---|",
         f"| Precision | **{res['precision']:.1%}** |",
         f"| Recall | **{res['recall']:.1%}** |",
         f"| F1 | {res['f1']:.3f} |",
         f"| Clean cases kept quiet (no false positive) | **{res['clean_quiet_rate']:.1%}** |",
         f"| True pos · False pos · False neg | {res['tp']} · {res['fp']} · {res['fn']} |",
         f"| HIGH-tier integrity violations | **{len(res['high_tier_violations'])}** |",
         "",
         "### The HIGH-tier invariant", "",
         "Every HIGH in this corpus is machine-checked to be `basis=confirmed` "
         "**and** — for the taint-based rules — to carry a `provenance` block "
         "naming the origin line, the value, and the sink line. A HIGH is the "
         "only thing we ask a maintainer to act on, so it may never rest on a "
         "variable *name*: `payload` was AutoGPT's own HMAC-signed cache, "
         "`func_body` was langflow's own template, and both were reported as "
         "confirmed RCE on the strength of their spelling. Since 0.9.4 a name "
         "yields at most a MEDIUM that asks you to confirm the source.",
         "", "## Per-rule", "", "| Rule | TP | FP | FN | Precision | Recall |",
         "|---|---|---|---|---|---|"]
    for rid, d in res["per_rule"].items():
        o.append(f"| {rid} | {d['tp']} | {d['fp']} | {d['fn']} | "
                 f"{d['precision']:.0%} | {d['recall']:.0%} |")
    o += ["", "## Methodology", "",
          "- **Coverage:** every rule in the catalog — including the full v0.9.0 "
          "agent-safety set (RG-PROMPT-002, RG-ACTION-002/003/004, RG-SECRET-002, "
          "RG-PARSE-001, RG-TOOL-001/RG-GATE-001, and the RG-EXEC-004 taint-aware "
          "deserialization upgrade) — carries at least two vulnerable cases and two "
          "clean look-alikes here, so the zero-false-positive result is reproducible "
          "per rule, not just asserted.",
          "- **Clean cases are drawn from real frameworks** (mem0, smolagents, "
          "crewAI, gpt-researcher, the RAG-context-in-user-turn shape…) where a "
          "naive scanner false-positives — each is a permanent regression guard. "
          "They include aliasing (a retrieved value read through `hits[0]."
          "page_content`) and the FP controls (a key used as `api_key=` auth, a "
          "parameterized query, list-argv `subprocess` concatenation).",
          "- **Vulnerable cases** are canonical instances of each rule.",
          "- A vulnerable case scores a true positive only if the engine emits "
          "the exact expected rule id; any unexpected emission is a false positive.",
          "- This is a corpus that grows with every rule and every false positive "
          "we fix (the list-argv `subprocess` guard was added the day a real scan "
          "surfaced it). It is not a substitute for third-party audit — it's the "
          "reproducible evidence a reviewer can check today.", "",
          "## Known limitations (kept in the corpus on purpose)", "",
          "- **Taint is intra-procedural.** A tainted value that flows *across a "
          "function boundary* (a helper returns model output; the caller sends it "
          "to a sink) is not followed — see the `*-cross-function-KNOWN-MISS` "
          "cases, deliberately labeled vulnerable so they show as recall misses "
          "here rather than being quietly dropped. This is a precision-first "
          "trade-off: we would rather miss a cross-function flow than infer one and "
          "cry wolf. Inter-procedural analysis is on the roadmap.", ""]
    if res["misclassified"]:
        o += ["## Misclassifications (current)", ""]
        o += [f"- `{cid}`: {kind} {rid}" for cid, kind, rid in res["misclassified"]]
        o.append("")
    return "\n".join(o)


def main() -> int:
    res = evaluate(load_cases())
    if "--json" in sys.argv:
        print(json.dumps(res, indent=2)); return 0
    if "--md" in sys.argv:
        (ROOT / "RESULTS.md").write_text(render_md(res) + "\n", encoding="utf-8")
        print(f"wrote {ROOT / 'RESULTS.md'}"); return 0
    print(f"cases={res['cases']}  precision={res['precision']:.1%}  "
          f"recall={res['recall']:.1%}  clean-quiet={res['clean_quiet_rate']:.1%}  "
          f"(TP {res['tp']} · FP {res['fp']} · FN {res['fn']})")
    hv = res["high_tier_violations"]
    status = ("OK — every HIGH is confirmed + provenance-backed" if not hv
              else f"{len(hv)} VIOLATION(S)")
    print(f"high-tier integrity: {status}")
    for cid, rid, why in hv:
        print(f"  VIOLATION: {cid} -> {rid}: {why}")
    for cid, kind, rid in res["misclassified"]:
        print(f"  {kind}: {cid} -> {rid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
