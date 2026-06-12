"""
Report rendering for release-gate.

Provides two output formats:
  - Terminal: colour-rich, money-first Impact Simulator display
  - HTML: self-contained report suitable for CI artefact storage
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------

def render_terminal(impact: Dict[str, Any], check_results: Dict[str, Any]) -> None:
    """Print the Impact Simulator report to stdout."""
    verdict = impact["verdict"]
    gaps = impact["governance_gaps"]
    normal = impact["normal"]
    runaway = impact["runaway"]
    delta = impact["risk_delta"]
    budget = impact["budget"]

    _hr("=")
    print("  release-gate  |  Impact Simulator")
    _hr("=")
    print()

    # Agent profile
    print(f"  Model            {impact['model']} ({impact['provider'].title()})")
    print(f"  Requests/day     {impact['requests_per_day']:,}")
    tokens = impact["tokens_per_request"]
    print(f"  Tokens/request   {tokens['input']:,} in + {tokens['output']:,} out")
    print()

    # Cost table
    _hr("-")
    print(f"  {'Scenario':<30} {'Daily':>10}  {'Monthly':>12}  {'Annual':>14}")
    _hr("-")
    _cost_row("Normal operation", normal["daily"], normal["monthly"], normal["annual"])
    _cost_row(
        f"Runaway loop ({runaway['assumption'].split(' (')[0]})",
        runaway["daily"],
        runaway["monthly"],
        runaway["annual"],
        alarm=True,
    )
    _hr("-")
    _cost_row(
        "Risk delta (money at stake)",
        delta["daily"],
        delta["monthly"],
        delta["monthly"] * 12,
        highlight=True,
    )
    print()

    # Budget headroom
    max_daily = budget.get("max_daily")
    if max_daily is not None:
        status = budget["normal_status"]
        symbol = "✓" if status == "PASS" else ("⚠" if status == "WARN" else "✗")
        headroom = budget.get("headroom", 0)
        print(f"  Budget cap       ${max_daily:,.2f}/day   [{symbol} {status}]  "
              f"(headroom: ${headroom:,.2f}/day)")
    else:
        print("  Budget cap       NOT SET  — unlimited spend possible")
    print()

    # Governance gaps
    if gaps:
        _hr("-")
        print("  GOVERNANCE GAPS — Business Impact")
        _hr("-")
        for i, gap in enumerate(gaps, 1):
            print(f"  {i}. [{gap['check']}] {gap['field'].upper()} not declared")
            print(f"     → {gap['impact']}")
        print()

    # Individual check results
    _hr("-")
    print(f"  {'CHECK':<25} {'STATUS':<8}")
    _hr("-")
    for check_name, result in sorted(check_results.items()):
        status = result.get("status", "UNKNOWN")
        symbol = "✓" if status == "PASS" else ("⚠" if status == "WARN" else "✗")
        print(f"  {check_name:<25} {symbol} {status}")
    print()

    # Final verdict
    _hr("=")
    verdict_icons = {"BLOCK": "✗  BLOCKED", "WARN": "⚠  WARNING", "PASS": "✓  APPROVED"}
    print(f"  FINAL VERDICT:  {verdict_icons.get(verdict, verdict)}")
    _hr("=")
    print()


def _hr(char: str = "-", width: int = 72) -> None:
    print("  " + char * width)


def _cost_row(
    label: str,
    daily: float,
    monthly: float,
    annual: float,
    alarm: bool = False,
    highlight: bool = False,
) -> None:
    prefix = "!" if alarm else (" " if not highlight else "*")
    print(f"  {prefix} {label:<28} ${daily:>9,.2f}  ${monthly:>11,.2f}  ${annual:>13,.2f}")


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>release-gate Impact Report — {project}</title>
<style>
  body {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#0d1117;color:#c9d1d9;margin:0;padding:2rem;}}
  h1 {{color:#f0f6fc;font-size:1.4rem;border-bottom:1px solid #30363d;padding-bottom:.5rem;}}
  h2 {{color:#8b949e;font-size:.9rem;text-transform:uppercase;letter-spacing:.08em;
       margin:1.5rem 0 .4rem;}}
  table {{width:100%;border-collapse:collapse;font-size:.875rem;margin-bottom:1rem;}}
  th {{text-align:left;color:#8b949e;font-weight:500;padding:.35rem .6rem;
       border-bottom:1px solid #21262d;}}
  td {{padding:.35rem .6rem;border-bottom:1px solid #161b22;}}
  .pass {{color:#3fb950;}} .warn {{color:#d29922;}} .fail,.block {{color:#f85149;}}
  .money {{font-variant-numeric:tabular-nums;text-align:right;}}
  .runaway {{color:#f85149;}}
  .delta {{color:#d29922;font-weight:600;}}
  .gap-check {{font-size:.75rem;color:#8b949e;}}
  .gap-impact {{font-size:.8rem;color:#c9d1d9;padding-left:1rem;}}
  .badge {{display:inline-block;padding:.2rem .6rem;border-radius:4px;
           font-weight:700;font-size:.8rem;}}
  .badge-pass {{background:#1f4d2e;color:#3fb950;}}
  .badge-warn {{background:#4a3000;color:#d29922;}}
  .badge-block,.badge-fail {{background:#4a1010;color:#f85149;}}
  .meta {{color:#8b949e;font-size:.75rem;margin-top:2rem;}}
</style>
</head>
<body>
<h1>&#x1F6AA; release-gate &mdash; Impact Report</h1>
<p><strong>Project:</strong> {project} &nbsp;|&nbsp;
   <strong>Model:</strong> {model} ({provider}) &nbsp;|&nbsp;
   <strong>Generated:</strong> {timestamp}</p>

<h2>Cost Projections</h2>
<table>
  <tr><th>Scenario</th><th class="money">Daily</th>
      <th class="money">Monthly</th><th class="money">Annual</th></tr>
  <tr>
    <td>Normal operation</td>
    <td class="money">${normal_daily}</td>
    <td class="money">${normal_monthly}</td>
    <td class="money">${normal_annual}</td>
  </tr>
  <tr class="runaway">
    <td>Runaway loop <small>({runaway_assumption})</small></td>
    <td class="money">${runaway_daily}</td>
    <td class="money">${runaway_monthly}</td>
    <td class="money">${runaway_annual}</td>
  </tr>
  <tr class="delta">
    <td>Risk delta (money at stake)</td>
    <td class="money">${delta_daily}</td>
    <td class="money">${delta_monthly}</td>
    <td class="money">${delta_annual}</td>
  </tr>
</table>

{budget_html}

<h2>Governance Gaps</h2>
{gaps_html}

<h2>Check Results</h2>
<table>
  <tr><th>Check</th><th>Status</th></tr>
  {checks_html}
</table>

<h2>Verdict</h2>
<span class="badge badge-{verdict_lower}">{verdict}</span>

<p class="meta">Generated by release-gate &mdash; github.com/VamsiSudhakaran1/release-gate</p>
</body>
</html>
"""


def render_html(
    impact: Dict[str, Any],
    check_results: Dict[str, Any],
    project_name: str = "AI Agent",
    output_path: str = "release-gate-report.html",
) -> str:
    """Write a self-contained HTML impact report and return the path."""

    normal = impact["normal"]
    runaway = impact["runaway"]
    delta = impact["risk_delta"]
    budget = impact["budget"]
    gaps = impact["governance_gaps"]
    verdict = impact["verdict"]

    # Budget row
    max_daily = budget.get("max_daily")
    if max_daily is not None:
        status = budget["normal_status"]
        css = "pass" if status == "PASS" else ("warn" if status == "WARN" else "fail")
        headroom = budget.get("headroom", 0)
        budget_html = (
            f'<h2>Budget</h2>'
            f'<p>Cap: <strong>${max_daily:,.2f}/day</strong> &mdash; '
            f'Status: <span class="{css}">{status}</span> &mdash; '
            f'Headroom: <strong>${headroom:,.2f}/day</strong></p>'
        )
    else:
        budget_html = (
            '<h2>Budget</h2>'
            '<p class="fail"><strong>NOT SET</strong> — unlimited spend possible</p>'
        )

    # Gaps
    if gaps:
        rows = "".join(
            f'<tr><td><span class="gap-check">[{g["check"]}] {g["field"].upper()}</span>'
            f'<br><span class="gap-impact">→ {g["impact"]}</span></td></tr>'
            for g in gaps
        )
        gaps_html = f"<table><tr><th>Missing safeguard &amp; business impact</th></tr>{rows}</table>"
    else:
        gaps_html = '<p class="pass">&#x2713; No governance gaps detected.</p>'

    # Check results
    checks_html = ""
    for name, result in sorted(check_results.items()):
        status = result.get("status", "UNKNOWN")
        css = "pass" if status == "PASS" else ("warn" if status == "WARN" else "fail")
        checks_html += f'<tr><td>{name}</td><td class="{css}">{status}</td></tr>'

    html = _HTML_TEMPLATE.format(
        project=project_name,
        model=impact["model"],
        provider=impact["provider"].title(),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        normal_daily=f"{normal['daily']:,.2f}",
        normal_monthly=f"{normal['monthly']:,.2f}",
        normal_annual=f"{normal['annual']:,.2f}",
        runaway_assumption=runaway["assumption"],
        runaway_daily=f"{runaway['daily']:,.2f}",
        runaway_monthly=f"{runaway['monthly']:,.2f}",
        runaway_annual=f"{runaway['annual']:,.2f}",
        delta_daily=f"{delta['daily']:,.2f}",
        delta_monthly=f"{delta['monthly']:,.2f}",
        delta_annual=f"{delta['monthly'] * 12:,.2f}",
        budget_html=budget_html,
        gaps_html=gaps_html,
        checks_html=checks_html,
        verdict=verdict,
        verdict_lower=verdict.lower(),
    )

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
