"""Branded PDF report generation for a release-gate run.

Two tiers, driven by the caller's plan:

  free  → summary only: score, decision, finding counts, first couple of
          safeguards. The detail is teased ("12 more findings in the full
          report") to drive an upgrade.
  paid  → the full picture: every safeguard, every code finding with
          file:line + recommendation, and the framework mapping.

fpdf2 is pure-Python (no system libraries) so it runs on Vercel's serverless
runtime. Import it lazily so a missing dependency degrades to a clear error
instead of crashing app import.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

ACCENT = (99, 102, 241)      # indigo
HEADING = (17, 24, 39)
MUTED = (107, 114, 128)
RED = (220, 38, 38)
AMBER = (217, 119, 6)
GREEN = (22, 163, 74)

WEB_BASE = "https://release-gate.com"

_DECISION_COLOR = {"PROMOTE": GREEN, "PASS": GREEN, "HOLD": AMBER, "BLOCK": RED}
_SEVERITY_COLOR = {"high": RED, "critical": RED, "medium": AMBER, "low": MUTED}

# How much detail the free tier may see before it's locked behind upgrade.
FREE_SAFEGUARDS = 2
FREE_FINDINGS = 0


def _ascii(s: Any) -> str:
    """fpdf2's core fonts are latin-1; strip anything that won't encode."""
    text = str(s if s is not None else "")
    return text.encode("latin-1", "replace").decode("latin-1")


def render_report_pdf(
    report: Dict[str, Any],
    *,
    repo_url: str = "",
    run_id: Optional[str] = None,
    full: bool = False,
    created_at: Optional[str] = None,
) -> bytes:
    """Render a run report dict to PDF bytes.

    full=False produces the free summary; full=True the paid detailed report.
    """
    from fpdf import FPDF

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(18, 18, 18)
    pdf.add_page()

    score = report.get("score")
    decision = (report.get("decision") or "").upper()
    safeguards = report.get("safeguards", {}) or {}
    findings = report.get("code_findings", []) or []
    # Free reports arrive pre-redacted; trust an explicit count if present.
    findings_count = report.get("_code_findings_count")
    if findings_count is None:
        findings_count = len(findings)

    # ── Header ──────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 10, _ascii("release-gate"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*HEADING)
    pdf.cell(0, 8, _ascii("Agent Deployment Readiness Report"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    if repo_url:
        pdf.cell(0, 5, _ascii(f"Target: {repo_url}"), new_x="LMARGIN", new_y="NEXT")
    if created_at:
        pdf.cell(0, 5, _ascii(f"Generated: {created_at}"), new_x="LMARGIN", new_y="NEXT")
    if not full:
        pdf.set_text_color(*AMBER)
        pdf.cell(0, 5, _ascii("FREE SUMMARY - upgrade for the full detailed report"),
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # ── Two-axis scorecard: Agent Code Safety + Governance ──────────────
    cs = report.get("code_safety") or {}
    gov = report.get("governance") or {}
    if cs.get("applicable"):
        cs_col = _DECISION_COLOR.get((cs.get("decision") or "").upper(), MUTED)
        _axis_band(pdf, "Agent Code Safety", cs.get("score"), cs.get("decision"),
                   f"{cs.get('high',0)} high / {cs.get('medium',0)} med / {cs.get('low',0)} low",
                   cs_col)
    else:
        dcol = _DECISION_COLOR.get(decision, MUTED)
        _axis_band(pdf, "Readiness", score, decision, "", dcol)
    if gov:
        lvl = gov.get("level", "")
        gcol = GREEN if lvl == "Mature" else (AMBER if lvl == "Partial" else RED)
        _axis_band(pdf, "Governance", gov.get("score"), lvl,
                   f"{gov.get('present',0)}/{gov.get('total',0)} safeguards declared", gcol)
    pdf.ln(2)

    # ── Summary counts ──────────────────────────────────────────────────
    passed_sg = sum(1 for v in safeguards.values()
                    if (v is True) or (isinstance(v, dict) and v.get("present")))
    _section(pdf, "Summary")
    _kv(pdf, "Safeguards present", f"{passed_sg} / {len(safeguards)}")
    _kv(pdf, "Code findings", str(findings_count))
    if full:
        highs = sum(1 for f in findings if f.get("severity") in ("high", "critical"))
        _kv(pdf, "High-severity findings", str(highs))
    pdf.ln(2)

    # ── Safeguards ──────────────────────────────────────────────────────
    _section(pdf, "Safeguards")
    items = list(safeguards.items())
    shown = items if full else items[:FREE_SAFEGUARDS]
    for name, v in shown:
        present = (v is True) or (isinstance(v, dict) and v.get("present"))
        mark = "[PASS]" if present else "[MISS]"
        col = GREEN if present else RED
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*col)
        pdf.cell(16, 5, _ascii(mark))
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*HEADING)
        pdf.multi_cell(0, 5, _ascii(name.replace("_", " ")), new_x="LMARGIN", new_y="NEXT")
    if not full and len(items) > FREE_SAFEGUARDS:
        _locked(pdf, f"+{len(items) - FREE_SAFEGUARDS} more safeguards in the full report")
    pdf.ln(2)

    # ── Code findings ───────────────────────────────────────────────────
    _section(pdf, "Code findings")
    if full and findings:
        for f in findings:
            sev = (f.get("severity") or "low").lower()
            col = _SEVERITY_COLOR.get(sev, MUTED)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*col)
            pdf.cell(20, 5, _ascii(f"[{sev.upper()}]"))
            pdf.set_text_color(*HEADING)
            pdf.multi_cell(0, 5, _ascii(f.get("title") or f.get("type") or "finding"),
                           new_x="LMARGIN", new_y="NEXT")
            loc = f.get("file") or ""
            if f.get("line"):
                loc = f"{loc}:{f.get('line')}"
            if loc:
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(*MUTED)
                pdf.multi_cell(0, 4, _ascii(f"   {loc}"), new_x="LMARGIN", new_y="NEXT")
            rec = f.get("recommendation") or f.get("fix")
            if rec:
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(*MUTED)
                pdf.multi_cell(0, 4, _ascii(f"   -> {rec}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
    elif full:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(0, 5, _ascii("No code findings recorded for this run."),
                       new_x="LMARGIN", new_y="NEXT")
    else:
        _locked(pdf, f"{findings_count} code finding(s) - prompt-injection surfaces, exec "
                     "sinks, uncapped LLM calls and hardcoded secrets - are detailed in the "
                     "full report.")
    pdf.ln(2)

    # ── Framework mapping (paid) ────────────────────────────────────────
    fw = report.get("frameworks") or report.get("framework_mapping")
    if full and isinstance(fw, dict) and fw:
        _section(pdf, "Compliance mapping")
        for std, val in fw.items():
            label = std if isinstance(std, str) else str(std)
            summary = val.get("summary") if isinstance(val, dict) else str(val)
            _kv(pdf, label, _ascii(summary or ""))

    # ── Footer CTA ──────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.set_draw_color(*ACCENT)
    pdf.set_line_width(0.3)
    pdf.line(18, pdf.get_y(), 18 + pdf.epw, pdf.get_y())
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*MUTED)
    url = f"{WEB_BASE}/r/{run_id}" if run_id else WEB_BASE
    if not full:
        pdf.multi_cell(0, 4, _ascii(f"Unlock the full report (every finding + file:line + "
                                    f"fixes + compliance mapping): {url}"),
                       new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.multi_cell(0, 4, _ascii(f"View online or re-scan: {url}"),
                       new_x="LMARGIN", new_y="NEXT")

    out = pdf.output()
    return bytes(out)


def _axis_band(pdf, title: str, score, label, sub, color) -> None:
    """Render one score axis as a left-bordered band."""
    y0 = pdf.get_y()
    pdf.set_fill_color(248, 247, 255)
    pdf.set_draw_color(*color)
    pdf.set_line_width(0.6)
    pdf.rect(18, y0, pdf.epw, 16, style="DF")
    pdf.set_xy(21, y0 + 2.5)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 4, _ascii(title.upper()), new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(21, y0 + 6.5)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*HEADING)
    pdf.cell(34, 8, _ascii(f"{score if score is not None else '--'}/100"))
    pdf.set_xy(58, y0 + 7.5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*color)
    pdf.cell(40, 6, _ascii(str(label or "")))
    if sub:
        pdf.set_xy(100, y0 + 8)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 5, _ascii(sub))
    pdf.set_y(y0 + 18)


def _section(pdf, title: str) -> None:
    pdf.ln(1)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 6, _ascii(title.upper()), new_x="LMARGIN", new_y="NEXT")


def _kv(pdf, key: str, val: str) -> None:
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    pdf.cell(55, 5, _ascii(key))
    pdf.set_text_color(*HEADING)
    pdf.set_font("Helvetica", "B", 9)
    pdf.multi_cell(0, 5, _ascii(val), new_x="LMARGIN", new_y="NEXT")


def _locked(pdf, msg: str) -> None:
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*AMBER)
    pdf.multi_cell(0, 5, _ascii(f"[LOCKED] {msg}"), new_x="LMARGIN", new_y="NEXT")
