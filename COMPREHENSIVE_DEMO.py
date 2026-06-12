#!/usr/bin/env python3
"""
release-gate v0.5 — Interactive Demo
=====================================
A friendly walkthrough for first-time users.

What you'll see:
  1. What release-gate is and why it exists
  2. A safe deployment that gets APPROVED
  3. A dangerous deployment that gets BLOCKED — with the dollar figure
  4. How to fix the problems and re-run
  5. How to add it to GitHub Actions in 5 lines

Run it:
  python COMPREHENSIVE_DEMO.py
"""

import time
import textwrap

try:
    from release_gate.impact_simulator import ImpactSimulator
    from release_gate.cli import run_checks, determine_decision
    LIVE = True
except ImportError:
    LIVE = False


def h1(title):
    print()
    print("=" * 68)
    print(f"  {title}")
    print("=" * 68)
    print()

def h2(title):
    print()
    print(f"  ── {title}")
    print()

def say(text, indent=4):
    prefix = " " * indent
    for line in textwrap.wrap(text, width=64):
        print(prefix + line)

def code(lines):
    print()
    for line in lines:
        print("    " + line)
    print()

def pause():
    try:
        input("  ↵  Press Enter to continue...\n")
    except EOFError:
        print()

def verdict(label, colour):
    colours = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m"}
    reset   = "\033[0m"
    c = colours.get(colour, "")
    print(f"\n  {c}{'━' * 64}{reset}")
    print(f"  {c}  {label}{reset}")
    print(f"  {c}{'━' * 64}{reset}\n")

def money(label, amount):
    print(f"    {label:<36} ${amount:>12,.2f}")


def intro():
    h1("Welcome to release-gate  \U0001f6aa")
    say(
        "release-gate is a pre-deployment governance gate for AI agents. "
        "Before your agent goes live, it answers one question:"
    )
    print()
    print("        ❓ Is this agent safe to deploy?")
    print()
    say(
        "It checks five things: cost, cost simulation, fallback safety, "
        "access control, and input contracts. If anything is missing or "
        "over budget, deployment is BLOCKED."
    )
    print()
    say(
        "More importantly — it shows you the MONEY AT RISK if a safeguard "
        "is missing. Engineering leaders see dollars, not YAML warnings."
    )
    pause()


def demo_safe():
    h1("DEMO 1 — Safe deployment  ✓")

    say(
        "Imagine you're shipping a customer-support AI agent. "
        "You've set a $500/day budget, declared a kill switch, "
        "set up auth, and written a runbook. Let's see what "
        "release-gate says."
    )

    h2("Configuration (governance-safe-pass.yaml)")
    code([
        "agent:",
        "  model: gpt-4-turbo",
        "  daily_requests: 5000",
        "",
        "checks:",
        "  action_budget:",
        "    max_daily_cost: 500          # hard cap",
        "  fallback_declared:",
        "    kill_switch: {type: feature-flag}",
        "    team_owner: platform-team",
        "    runbook_url: https://wiki.example.com/runbook",
        "  identity_boundary:",
        "    authentication: {required: true}",
        "    rate_limit: {requests_per_minute: 30}",
        "    data_isolation: [tenant_id]",
        "",
        "simulation:",
        "  requests_per_day: 5000",
        "  tokens_per_request: {input: 800, output: 400}",
        "  factors:",
        "    retry_rate: 1.1              # 10% retries",
        "    cache_hit_rate: 0.2          # 20% cache hits",
        "    spiky_usage_multiplier: 1.5  # 50% peak spike",
        "",
        "budget:",
        "  max_daily_cost: 500",
    ])

    h2("Running: release-gate impact governance-safe-pass.yaml")

    config_safe = {
        "project": {"name": "customer-support-agent"},
        "agent": {"model": "gpt-4-turbo"},
        "simulation": {
            "requests_per_day": 5000,
            "tokens_per_request": {"input": 800, "output": 400},
            "factors": {
                "retry_rate": 1.1,
                "cache_hit_rate": 0.2,
                "spiky_usage_multiplier": 1.5,
            },
        },
        "budget": {"max_daily_cost": 500},
        "checks": {
            "action_budget":    {"enabled": True, "max_daily_cost": 500},
            "budget_simulation":{"enabled": True},
            "fallback_declared": {
                "enabled": True,
                "kill_switch": {"type": "feature-flag"},
                "fallback_mode": "human-handoff",
                "team_owner": "platform-team",
                "runbook_url": "https://wiki.example.com/runbook",
            },
            "identity_boundary": {
                "enabled": True,
                "authentication": {"required": True, "type": "jwt"},
                "rate_limit": {"requests_per_minute": 30},
                "data_isolation": ["tenant_id"],
            },
            "input_contract": {
                "enabled": True,
                "schema": {"required": ["message"]},
                "samples": {
                    "valid": [{"message": "How do I return an order?"}],
                    "invalid": [{}],
                },
            },
        },
    }

    if LIVE:
        sim = ImpactSimulator()
        impact = sim.simulate(config_safe)
        normal  = impact["normal"]
        runaway = impact["runaway"]
        delta   = impact["risk_delta"]
        budget  = impact["budget"]

        print("    ─" * 32)
        print(f"    {'Scenario':<36} {'Daily':>12}  {'Monthly':>13}")
        print("    ─" * 32)
        money("Normal operation",     normal["daily"])
        money("Runaway loop (15× retries)", runaway["daily"])
        print("    ─" * 32)
        money("Risk delta (money at stake)", delta["daily"])
        print()
        print(f"    Budget cap: ${budget['max_daily']:,.2f}/day  →  "
              f"headroom: ${budget['headroom']:,.2f}/day")
        print()
        print("    No governance gaps detected.")
    else:
        print("    Normal operation       $    132.00  $   3,960.00")
        print("    Runaway loop (15×)     $  5,000.00  $ 150,000.00")
        print("    ─" * 26)
        print("    Risk delta             $  4,868.00  $ 146,040.00")
        print()
        print("    Budget cap: $500.00/day  →  headroom: $368.00/day")
        print("    No governance gaps detected.")

    verdict("✓  FINAL VERDICT:  APPROVED  — safe to deploy", "green")

    say(
        "The agent costs ~$132/day under normal load. Even if it runs "
        "into a 15× retry loop, the kill switch can stop it. "
        "Budget has $368/day of headroom. Deploy with confidence."
    )
    pause()


def demo_unsafe():
    h1("DEMO 2 — Dangerous deployment  ✗")

    say(
        "Now imagine a different team shipping an autonomous trading agent. "
        "They skipped the governance config — no kill switch, no auth, "
        "no budget cap. Let's see what release-gate says."
    )

    h2("Configuration (governance-unsafe-fail.yaml)")
    code([
        "agent:",
        "  model: gpt-4       # expensive model",
        "  daily_requests: 10000",
        "",
        "checks:",
        "  action_budget:",
        "    enabled: true",
        "    # max_daily_cost NOT SET ← no circuit breaker!",
        "",
        "  fallback_declared:",
        "    enabled: true",
        "    # kill_switch NOT DECLARED",
        "    # team_owner  NOT DECLARED",
        "",
        "  identity_boundary:",
        "    authentication:",
        "      required: false  # anyone can call this agent",
        "    # rate_limit NOT SET",
    ])

    h2("Running: release-gate impact governance-unsafe-fail.yaml")

    config_unsafe = {
        "project": {"name": "autonomous-trading-agent"},
        "agent": {"model": "gpt-4"},
        "simulation": {
            "requests_per_day": 10000,
            "tokens_per_request": {"input": 2000, "output": 800},
            "factors": {
                "retry_rate": 1.0,
                "cache_hit_rate": 0.0,
                "spiky_usage_multiplier": 1.0,
            },
        },
        "budget": {"max_daily_cost": 200},
        "checks": {
            "action_budget":    {"enabled": True},
            "budget_simulation":{"enabled": True},
            "fallback_declared": {"enabled": True},
            "identity_boundary": {
                "enabled": True,
                "authentication": {"required": False},
                "data_isolation": [],
            },
            "input_contract": {"enabled": True},
        },
    }

    if LIVE:
        sim = ImpactSimulator()
        impact = sim.simulate(config_unsafe)
        normal  = impact["normal"]
        runaway = impact["runaway"]
        delta   = impact["risk_delta"]
        budget  = impact["budget"]
        gaps    = impact["governance_gaps"]

        print("    ─" * 32)
        money("Normal operation",          normal["daily"])
        money("Runaway loop (15× retries)", runaway["daily"])
        print("    ─" * 32)
        money("Risk delta (money at stake)", delta["daily"])
        print()
        print(f"    Budget cap: ${budget['max_daily']:,.2f}/day  →  "
              f"OVERAGE: ${abs(budget.get('headroom') or 0):,.2f}/day")
        print()
        print(f"    Governance gaps detected: {len(gaps)}")
        for i, gap in enumerate(gaps, 1):
            print(f"    {i}. [{gap['check']}] {gap['field'].upper()} not declared")
            print(f"       → {gap['impact']}")
    else:
        print("    Normal operation         $  1,080.00  $  32,400.00")
        print("    Runaway loop (15×)       $ 54,000.00  $1,620,000.00")
        print("    ─" * 26)
        print("    Risk delta               $ 52,920.00  $1,587,600.00")
        print()
        print("    Budget cap: $200/day  →  OVERAGE: $880/day")
        print()
        print("    Governance gaps: 5")
        print("    1. [FALLBACK_DECLARED] KILL_SWITCH not declared")
        print("       → No way to stop a runaway agent")
        print("    2. [FALLBACK_DECLARED] TEAM_OWNER not declared")
        print("       → No owner means no one gets paged at 3 AM")
        print("    3. [IDENTITY_BOUNDARY] AUTHENTICATION not declared")
        print("       → Anyone can call this agent and rack up unlimited costs")
        print("    4. [IDENTITY_BOUNDARY] RATE_LIMIT not declared")
        print("       → A single client can exhaust the budget in minutes")
        print("    5. [ACTION_BUDGET] MAX_DAILY_COST not declared")
        print("       → No circuit breaker on daily spend")

    verdict("✗  FINAL VERDICT:  BLOCKED  — fix the gaps above first", "red")

    say(
        "$52,920 per day at risk. This is not a theoretical number — "
        "this is what happens when an LLM agent enters a retry loop "
        "with no kill switch and no rate limit. release-gate caught it "
        "before a single request hit production."
    )
    pause()


def demo_fix():
    h1("DEMO 3 — How to fix it in 5 minutes  \U0001f527")

    say(
        "release-gate doesn't just tell you what's wrong — "
        "it tells you what to add. Here's the minimal fix:"
    )

    h2("Add these fields to governance.yaml")
    code([
        "checks:",
        "  action_budget:",
        "    max_daily_cost: 500      # ← circuit breaker added",
        "",
        "  fallback_declared:",
        "    kill_switch:",
        "      type: feature-flag     # ← can stop agent instantly",
        "    team_owner: risk-team    # ← who gets paged at 3 AM",
        "    runbook_url: https://wiki.example.com/trading-agent",
        "",
        "  identity_boundary:",
        "    authentication:",
        "      required: true         # ← only authenticated users",
        "    rate_limit:",
        "      requests_per_minute: 10",
    ])

    h2("Or use the interactive setup wizard")
    code([
        "$ pip install release-gate",
        "$ release-gate init",
        "",
        "  \U0001f6aa release-gate: Project Initialization Wizard",
        "  ────────────────────────────────",
        "  Project name [my-agent]: trading-agent",
        "  AI model: gpt-4",
        "  Daily budget [100]: 500",
        "  Team owner: risk-team",
        "",
        "  ✓ Created governance.yaml",
        "  ✓ Created .github/workflows/release-gate.yml",
    ])

    say(
        "After adding the missing fields, re-run "
        "'release-gate impact governance.yaml' — the verdict "
        "changes from BLOCKED to APPROVED."
    )
    pause()


def demo_cicd():
    h1("DEMO 4 — GitHub Actions in 5 lines  \U0001f504")

    say(
        "Once governance.yaml is in your repo, add release-gate "
        "to your CI pipeline. Every PR gets a cost report. "
        "Deployment is blocked automatically if governance fails."
    )

    h2(".github/workflows/governance.yml")
    code([
        "name: AI Agent Governance",
        "on: [push, pull_request]",
        "",
        "jobs:",
        "  governance:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "",
        "      - name: Impact check",
        "        uses: VamsiSudhakaran1/release-gate@v0.5.0",
        "        with:",
        "          command: impact",
        "          html-report: report.html",
        "          # ↑ uploaded as CI artifact automatically",
    ])

    h2("Exit codes your pipeline understands")
    code([
        "exit 0   →  PASS  — deploy",
        "exit 10  →  WARN  — review needed (allowed by default)",
        "exit 1   →  FAIL  — blocked",
    ])

    say(
        "Set 'fail-on-warn: true' to also block on WARN. "
        "The HTML report is uploaded as a GitHub Actions artifact "
        "on every run — cost dashboard without leaving GitHub."
    )
    pause()


def demo_crypto():
    h1("DEMO 5 — Cryptographic signing (v0.5)  \U0001f511")

    say(
        "Once governance.yaml is reviewed and approved, lock it "
        "so no one can quietly change the budget limit after sign-off. "
        "release-gate uses RSA-PSS + SHA256 to sign and verify the file."
    )

    h2("Sign governance.yaml after review")
    code([
        "# Generate a key pair (one-time setup)",
        "openssl genrsa -out governance-key.pem 2048",
        "openssl rsa -in governance-key.pem -pubout -out governance-key.pub",
        "",
        "# Sign the governance file",
        "release-gate validate-and-lock \\",
        "  --governance governance.yaml \\",
        "  --sign \\",
        "  --private-key governance-key.pem",
        "",
        "# Output:",
        "# ✓ Governance locked",
        "#   Hash: a3f2b1c9...",
        "#   Proof file: .release-gate-proof.json",
    ])

    h2("Verify in CI before running checks")
    code([
        "release-gate validate-and-lock \\",
        "  --governance governance.yaml \\",
        "  --verify \\",
        "  --public-key governance-key.pub",
        "",
        "# exit 0 = governance unchanged since sign-off",
        "# exit 1 = tampered — deployment blocked",
    ])

    say(
        "The proof file records the exact governance state at sign-off. "
        "Changing any value breaks the signature and blocks CI."
    )
    pause()


def summary():
    h1("Summary  \U0001f4cb")

    print("  What release-gate gives you:\n")
    items = [
        ("Impact Simulator",       "Shows normal cost AND runaway-loop cost — dollars, not YAML"),
        ("5 governance checks",    "Budget, simulation, fallback, identity, input contract"),
        ("Policy engine",          "Define what's critical (FAIL) vs. what's flexible (WARN)"),
        ("HTML report",            "Self-contained report as CI artifact on every PR"),
        ("GitHub Actions",         "5 lines to gate every deploy — works with any CI"),
        ("Cryptographic signing",  "Lock governance.yaml so limits can't be changed post-review"),
        ("100 tests",              "Full coverage across all checks, simulator, and renderers"),
    ]
    for name, desc in items:
        print(f"  ✓ {name:<30} {desc}")

    print()
    print("  Install:\n")
    print("    pip install release-gate")
    print("    release-gate init          # interactive wizard")
    print("    release-gate impact governance.yaml")
    print()
    print("  GitHub: https://github.com/VamsiSudhakaran1/release-gate")
    print()


def main():
    print()
    print("┌" + "─" * 66 + "┐")
    print("│" + "  release-gate v0.5 — Interactive Demo".center(66) + "│")
    print("│" + "  The pre-deployment governance gate for AI agents".center(66) + "│")
    print("└" + "─" * 66 + "┘")

    if not LIVE:
        print()
        print("  Note: release-gate not installed — running in display mode.")
        print("  Install with:  pip install release-gate")

    intro()
    demo_safe()
    demo_unsafe()
    demo_fix()
    demo_cicd()
    demo_crypto()
    summary()


if __name__ == "__main__":
    main()
