#!/usr/bin/env python3
"""
release-gate v0.3 Comprehensive Demo
Shows all features, decision flows, and real-world scenarios
"""

import json
import yaml
from pathlib import Path


def print_header(title):
    """Print a formatted header"""
    print("\n")
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)
    print()


def print_section(title):
    """Print a section header"""
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}\n")


def demo_scenario_1_cost_well_under_budget():
    """Demo 1: Cost is well under budget (Auto-approval)"""
    print_header("DEMO 1: Cost Well Under Budget ✅")
    
    config = {
        "project": {"name": "simple-chatbot"},
        "agent": {
            "model": "gpt-4-turbo",
            "daily_requests": 100,
            "avg_input_tokens": 500,
            "avg_output_tokens": 300,
            "retry_rate": 1.0
        },
        "checks": {
            "action_budget": {
                "enabled": True,
                "max_daily_cost": 50
            }
        }
    }
    
    print("CONFIGURATION:")
    print(yaml.dump(config, default_flow_style=False))
    
    print("\nCALCULATION:")
    print("""
    Model: GPT-4-Turbo
    Pricing: $0.00001 input, $0.00003 output
    
    Daily Calculation:
      Input cost:  $0.00001 × (500 tokens / 1000) × 100 requests = $0.50
      Output cost: $0.00003 × (300 tokens / 1000) × 100 requests = $0.90
      Total daily: $1.40
    
    Monthly: $1.40 × 30 = $42.00
    """)
    
    print("\nDECISION LOGIC:")
    print("""
    Auto-approval threshold: $50 × 0.1 = $5.00
    Manual approval threshold: $50 × 0.5 = $25.00
    Max daily budget: $50.00
    
    Daily cost: $1.40
    Is $1.40 <= $5.00? YES
    → AUTO-APPROVAL ✓
    """)
    
    print("\nOUTPUT:")
    print("""
    ┌──────────────────────────────────────────┐
    │ 🚪 release-gate: Validation              │
    ├──────────────────────────────────────────┤
    
    💰 ACTION_BUDGET: ✓ PASS
       Cost Control: Automatic Approval
    
       Daily Cost:   $1.40
       Monthly Cost: $42.00
       Budget:       $50.00
       Safety Margin: 35.7x
    
       ✓ Daily cost is well under the limit
       ✓ Safety margin is comfortable (35.7x)
       ✓ No manual approval needed
    
    ✅ FINAL DECISION: PASS (Safe to deploy)
    └──────────────────────────────────────────┘
    """)
    
    print("\n📋 WHAT THIS MEANS:")
    print("  • Agent can be deployed immediately")
    print("  • Costs are well controlled")
    print("  • No manual review needed")
    print("  • Plenty of budget headroom (35x safety margin)")


def demo_scenario_2_cost_near_limit():
    """Demo 2: Cost near limit (Manual approval needed)"""
    print_header("DEMO 2: Cost Near Budget Limit ⚠️")
    
    config = {
        "project": {"name": "premium-search"},
        "agent": {
            "model": "gpt-4-turbo",
            "daily_requests": 1000,
            "avg_input_tokens": 1500,
            "avg_output_tokens": 800,
            "retry_rate": 1.2
        },
        "checks": {
            "action_budget": {
                "enabled": True,
                "max_daily_cost": 50
            }
        }
    }
    
    print("CONFIGURATION:")
    print(yaml.dump(config, default_flow_style=False))
    
    print("\nCALCULATION:")
    print("""
    Model: GPT-4-Turbo
    Pricing: $0.00001 input, $0.00003 output
    
    Daily Calculation:
      Input cost:  $0.00001 × (1500 / 1000) × 1000 × 1.2 = $18.00
      Output cost: $0.00003 × (800 / 1000) × 1000 × 1.2 = $28.80
      Total daily: $46.80
    
    Monthly: $46.80 × 30 = $1,404.00
    """)
    
    print("\nDECISION LOGIC:")
    print("""
    Auto-approval threshold: $50 × 0.1 = $5.00
    Manual approval threshold: $50 × 0.5 = $25.00
    Max daily budget: $50.00
    
    Daily cost: $46.80
    Is $46.80 <= $5.00? NO
    Is $46.80 <= $25.00? NO
    Is $46.80 <= $50.00? YES
    → MANUAL APPROVAL NEEDED ⚠️
    """)
    
    print("\nOUTPUT:")
    print("""
    ┌──────────────────────────────────────────┐
    │ 🚪 release-gate: Validation              │
    ├──────────────────────────────────────────┤
    
    💰 ACTION_BUDGET: ⚠️ WARN
       Cost Control: At Budget Limit
    
       Daily Cost:   $46.80
       Monthly Cost: $1,404.00
       Budget:       $50.00
       Safety Margin: 1.1x
    
       ⚠️ Daily cost is near the maximum budget
       ⚠️ Safety margin is minimal (only 1.1x)
       ⚠️ Consider raising budget or optimizing cost
    
    ❓ FINAL DECISION: WARN (Manual review recommended)
       Sending approval notifications...
       - Slack: #ai-governance
       - Email: ai-team@company.com
    └──────────────────────────────────────────┘
    """)
    
    print("\n📋 WHAT THIS MEANS:")
    print("  • Deployment is paused")
    print("  • Team lead needs to review")
    print("  • Cost is at budget limit with no headroom")
    print("  • Should either:")
    print("    - Raise budget to $50-60")
    print("    - Optimize agent to reduce cost")
    print("    - Manually approve if acceptable risk")


def demo_scenario_3_cost_exceeds_budget():
    """Demo 3: Cost exceeds budget (FAIL - deployment blocked)"""
    print_header("DEMO 3: Cost Exceeds Budget ❌")
    
    config = {
        "project": {"name": "high-volume-search"},
        "agent": {
            "model": "gpt-4",  # Expensive model
            "daily_requests": 5000,
            "avg_input_tokens": 2000,
            "avg_output_tokens": 1000,
            "retry_rate": 1.5  # High retry rate
        },
        "checks": {
            "action_budget": {
                "enabled": True,
                "max_daily_cost": 100
            }
        }
    }
    
    print("CONFIGURATION:")
    print(yaml.dump(config, default_flow_style=False))
    
    print("\nCALCULATION:")
    print("""
    Model: GPT-4 (Expensive)
    Pricing: $0.00003 input, $0.0001 output
    
    Daily Calculation:
      Input cost:  $0.00003 × (2000 / 1000) × 5000 × 1.5 = $450.00
      Output cost: $0.0001 × (1000 / 1000) × 5000 × 1.5 = $750.00
      Total daily: $1,200.00
    
    Monthly: $1,200.00 × 30 = $36,000.00
    
    ANNUAL: $1,200.00 × 365 = $438,000.00
    """)
    
    print("\nDECISION LOGIC:")
    print("""
    Max daily budget: $100.00
    Daily cost: $1,200.00
    
    Is $1,200.00 <= $100.00? NO
    → DEPLOYMENT BLOCKED ❌
    """)
    
    print("\nOUTPUT:")
    print("""
    ┌──────────────────────────────────────────┐
    │ 🚪 release-gate: Validation              │
    ├──────────────────────────────────────────┤
    
    💰 ACTION_BUDGET: ❌ FAIL
       Cost Control: Budget Exceeded
    
       Daily Cost:    $1,200.00
       Monthly Cost:  $36,000.00
       Annual Cost:   $438,000.00
       Budget:        $100.00
       Daily Overage: $1,100.00
    
       ✗ Daily cost EXCEEDS maximum budget by 12x
       ✗ This is how agents cost companies millions
       ✗ BLOCKED: Cannot deploy without fixing cost
    
    ❌ FINAL DECISION: FAIL (Deployment blocked)
    └──────────────────────────────────────────┘
    """)
    
    print("\n📋 REMEDIATION OPTIONS:")
    print("""
    Option 1: Use cheaper model (GPT-4-Turbo)
      Model:    GPT-4-Turbo (3.3x cheaper)
      New cost: $1,200 / 3.3 = $363.63/day → Still too high
      Status:   Still FAIL
    
    Option 2: Reduce daily request volume
      Daily requests: 5000 → 250
      New cost: $1,200 × (250/5000) = $60.00/day → PASS ✓
      Status:   OK, but reduces functionality
    
    Option 3: Reduce context size
      Input tokens: 2000 → 500
      New cost: ~$300/day → Still high
      Status:   FAIL
    
    Option 4: Use cheapest model (Claude-3-Sonnet)
      Model:    Claude-3-Sonnet
      Input:    $0.000003
      Output:   $0.000015
      New cost: ~$150/day → Still FAIL
      Status:   FAIL
    
    Option 5: Increase budget
      Current: $100/day
      Required: $1,200/day
      Cost: $438,000/year
      Status:   Financially not viable for most organizations
    
    RECOMMENDED:
    1. Use GPT-4-Turbo + reduce request volume to 250/day
    2. Or use Claude-3-Sonnet + reduce request volume to 500/day
    3. Or reconsider use case (is this agent necessary?)
    """)
    
    print("\n⚠️ WHAT THIS PREVENTS:")
    print("  • Agent is NOT deployed")
    print("  • $438,000/year mistake is prevented")
    print("  • Team must fix cost configuration first")
    print("  • This is why release-gate exists")


def demo_scenario_4_no_budget_defined():
    """Demo 4: No budget defined (FAIL - mandatory)"""
    print_header("DEMO 4: No Budget Defined (Mandatory) ❌")
    
    config = {
        "project": {"name": "experimental-agent"},
        "agent": {
            "model": "gpt-4-turbo",
            "daily_requests": 1000,
            "avg_input_tokens": 1000,
            "avg_output_tokens": 500
        },
        "checks": {
            "action_budget": {
                "enabled": True
                # max_daily_cost: NOT DEFINED ← Problem!
            }
        }
    }
    
    print("CONFIGURATION:")
    print(yaml.dump(config, default_flow_style=False))
    
    print("\nPROBLEM:")
    print("""
    max_daily_cost is NOT defined!
    This is a MANDATORY field.
    
    Why? Because:
    • Without limits, cost is unlimited
    • Agents can spiral to $50K/day
    • This is how real disasters happen
    • release-gate won't allow it
    """)
    
    print("\nOUTPUT:")
    print("""
    ┌──────────────────────────────────────────┐
    │ 🚪 release-gate: Validation              │
    ├──────────────────────────────────────────┤
    
    💰 ACTION_BUDGET: ❌ FAIL
       Cost Control: No Budget Defined
    
       Estimated daily cost: $50.00
       Budget configured: NONE (REQUIRED!)
    
       ✗ Agent cost cannot be unlimited
       ✗ max_daily_cost is mandatory
       ✗ BLOCKED: Define budget and retry
    
    ❌ FINAL DECISION: FAIL (Deployment blocked)
    └──────────────────────────────────────────┘
    """)
    
    print("\n📋 HOW TO FIX:")
    print("""
    Add to governance.yaml:
    
    checks:
      action_budget:
        enabled: true
        max_daily_cost: 50  ← ADD THIS LINE
    
    Then re-run:
    $ release-gate check --config governance.yaml
    """)


def demo_scenario_5_all_4_checks():
    """Demo 5: All 4 checks together"""
    print_header("DEMO 5: All 4 Checks Working Together")
    
    print("CONFIGURATION:")
    config = {
        "project": {"name": "customer-support"},
        "agent": {
            "model": "gpt-4-turbo",
            "daily_requests": 500,
            "avg_input_tokens": 800,
            "avg_output_tokens": 400
        },
        "checks": {
            "action_budget": {
                "enabled": True,
                "max_daily_cost": 100
            },
            "input_contract": {
                "enabled": True,
                "schema": {
                    "type": "object",
                    "required": ["user_query"],
                    "properties": {
                        "user_query": {"type": "string", "minLength": 1}
                    }
                }
            },
            "fallback_declared": {
                "enabled": True,
                "kill_switch": {"type": "feature_flag", "name": "disable_support"},
                "fallback": {"mode": "escalate_to_human"}
            },
            "identity_boundary": {
                "enabled": True,
                "authentication": "required",
                "rate_limit": 10
            }
        }
    }
    print(yaml.dump(config, default_flow_style=False)[:500] + "...")
    
    print("\nRUNNING ALL 4 CHECKS:")
    print("""
    ┌──────────────────────────────────────────┐
    │ 🚪 release-gate: All 4 Checks            │
    ├──────────────────────────────────────────┤
    
    1️⃣  ACTION_BUDGET Check
        ├─ Model: GPT-4-Turbo ✓
        ├─ Daily requests: 500 ✓
        ├─ Input tokens: 800 ✓
        ├─ Output tokens: 400 ✓
        ├─ Estimated daily cost: $10.50 ✓
        ├─ Budget: $100.00 ✓
        └─ Result: ✅ PASS (9.5x safety margin)
    
    2️⃣  INPUT_CONTRACT Check
        ├─ Schema defined: YES ✓
        ├─ Required fields: [user_query] ✓
        ├─ Field types: user_query is string ✓
        └─ Result: ✅ PASS (Schema properly configured)
    
    3️⃣  FALLBACK_DECLARED Check
        ├─ Kill switch: enabled ✓
        ├─ Fallback mode: escalate_to_human ✓
        ├─ Team ownership: not defined ⚠️
        └─ Result: ✅ PASS (Essentials configured)
    
    4️⃣  IDENTITY_BOUNDARY Check
        ├─ Authentication: required ✓
        ├─ Rate limit: 10 req/min ✓
        ├─ Data isolation: not defined ⚠️
        └─ Result: ✅ PASS (Security enforced)
    
    ╔══════════════════════════════════════════╗
    ║ ✅ FINAL DECISION: PASS                 ║
    ║    All 4 checks passed                  ║
    ║    Safe to deploy                       ║
    ╚══════════════════════════════════════════╝
    └──────────────────────────────────────────┘
    """)
    
    print("\n📋 WHAT EACH CHECK VALIDATED:")
    print("""
    ✅ ACTION_BUDGET: Cost is under control ($10.50 << $100)
    ✅ INPUT_CONTRACT: Requests have proper schema
    ✅ FALLBACK_DECLARED: Agent can be killed if needed
    ✅ IDENTITY_BOUNDARY: Only authenticated users can access
    
    DEPLOYMENT READY!
    """)


def demo_scenario_6_dynamic_pricing():
    """Demo 6: Dynamic pricing and auto-detection"""
    print_header("DEMO 6: Dynamic Pricing & Auto-Detection")
    
    print("SCENARIO: You don't know the exact model cost")
    print()
    
    print("STEP 1: release-gate detects model from code")
    print("""
    Your agent code:
    ────────────────────────────────────────
    from openai import OpenAI
    
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",  ← Auto-detected!
        messages=[...]
    )
    ────────────────────────────────────────
    
    release-gate extracts: model = "gpt-4o"
    """)
    
    print("\nSTEP 2: Looks up pricing from pricing.json")
    print("""
    {
      "gpt-4o": {
        "input": 0.000005,
        "output": 0.000015,
        "provider": "OpenAI"
      }
    }
    """)
    
    print("\nSTEP 3: Calculates cost automatically")
    print("""
    Model: GPT-4o (auto-detected)
    Pricing: $0.000005 input, $0.000015 output
    
    Daily calculation:
      Input:  $0.000005 × (500 / 1000) × 100 = $0.25
      Output: $0.000015 × (300 / 1000) × 100 = $0.45
      Total:  $0.70/day
    """)
    
    print("\nSTEP 4: Custom model support")
    print("""
    Add to pricing.json:
    {
      "my-internal-model": {
        "input": 0.0001,
        "output": 0.0002
      }
    }
    
    Use in governance.yaml:
    agent:
      model: my-internal-model  ← Works immediately!
    
    No code changes needed!
    """)
    
    print("\n✅ RESULT:")
    print("  • No hardcoding of models")
    print("  • Supports any model (past, present, future)")
    print("  • Auto-detects from code")
    print("  • User-extensible via JSON")


def demo_end_to_end_workflow():
    """Demo: Complete end-to-end workflow"""
    print_header("DEMO 7: Complete End-to-End Workflow")
    
    print("DEVELOPER'S JOURNEY:")
    print()
    
    print("1️⃣  DEVELOP AGENT")
    print("""
    Write your agent code:
    ────────────────────────────────────────
    from openai import OpenAI
    
    def customer_support_agent(query):
        client = OpenAI()
        return client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": query}]
        )
    ────────────────────────────────────────
    """)
    
    print("\n2️⃣  CREATE GOVERNANCE CONFIG")
    print("""
    governance.yaml:
    ────────────────────────────────────────
    project:
      name: customer-support
    
    agent:
      model: gpt-4-turbo
      daily_requests: 500
      avg_input_tokens: 800
      avg_output_tokens: 400
    
    checks:
      action_budget:
        enabled: true
        max_daily_cost: 100
    ────────────────────────────────────────
    """)
    
    print("\n3️⃣  VALIDATE BEFORE DEPLOYMENT")
    print("""
    $ release-gate check --config governance.yaml
    
    ┌──────────────────────────────────────────┐
    │ 🚪 release-gate: Validation              │
    ├──────────────────────────────────────────┤
    
    💰 ACTION_BUDGET: ✓ PASS
       Daily cost: $10.50 << Budget: $100
    
    ✅ FINAL DECISION: PASS
    └──────────────────────────────────────────┘
    """)
    
    print("\n4️⃣  DEPLOY WITH CONFIDENCE")
    print("""
    $ git commit -m "Add customer support agent with governance"
    $ git push origin main
    $ kubectl apply -f deployment.yaml
    
    ✅ Agent deployed securely
    ✅ Costs under control ($10.50/day max)
    ✅ Safety measures in place
    ✅ Governance enforced
    """)
    
    print("\n5️⃣  MONITOR & ADJUST")
    print("""
    Real usage after 1 week:
      Actual daily cost: $8.20 (under $10.50 estimate)
      Perfect! Everything is under budget.
    
    Real usage after 3 months:
      Actual daily cost: $35.00 (still under $100 budget)
      Plenty of headroom.
    
    release-gate prevented $50K mistakes while allowing
    profitable operation.
    """)


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  release-gate v0.3: Comprehensive Feature Demo".center(68) + "║")
    print("║" + "  Governance Enforcement for AI Agents".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    
    demo_scenario_1_cost_well_under_budget()
    demo_scenario_2_cost_near_limit()
    demo_scenario_3_cost_exceeds_budget()
    demo_scenario_4_no_budget_defined()
    demo_scenario_5_all_4_checks()
    demo_scenario_6_dynamic_pricing()
    demo_end_to_end_workflow()
    
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + "  Demo Complete!".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    print("Key Takeaways:")
    print("  ✅ release-gate prevents $50K+ cost disasters")
    print("  ✅ Automatic cost estimation with full transparency")
    print("  ✅ Dynamic pricing supports any model")
    print("  ✅ Auto-detection from code")
    print("  ✅ All 4 governance checks work together")
    print("  ✅ Clear decision flow (PASS/WARN/FAIL)")
    print()


if __name__ == '__main__':
    main()
