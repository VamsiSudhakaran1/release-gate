# release-gate

🚪 **Governance enforcement for AI agents** — Prevent cost explosions, ensure safety measures, and enforce access control before deployment.

[![GitHub License](https://img.shields.io/github/license/VamsiSudhakaran1/release-gate)](LICENSE)
[![Tests](https://github.com/VamsiSudhakaran1/release-gate/actions/workflows/tests.yml/badge.svg)](https://github.com/VamsiSudhakaran1/release-gate/actions)
[![PyPI Version](https://img.shields.io/pypi/v/release-gate)?v=1](https://pypi.org/project/release-gate/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## The Problem It Solves

**Your AI agent costs you $50,000 in a single day.** No warning. No limit. No questions.

This happens because:
- ❌ No cost limits are set
- ❌ No one validates agent configuration
- ❌ Request volumes spiral unexpectedly
- ❌ Token usage balloons with complex prompts
- ❌ One retry loop = 10x cost multiplier

**release-gate stops this before it happens.**

---

## What It Does (The 4 Checks)

release-gate sits between testing and deployment, validating agents against 4 critical checks:

### 🎯 PRIMARY CHECK: ACTION_BUDGET (NEW v0.3)

**Prevents cost explosions** — The hero feature that stops $50K mistakes.

```yaml
checks:
  action_budget:
    enabled: true
    max_daily_cost: 100  # Sets the limit
```

What happens:

```
Agent estimated to cost $250/day
Budget set to $100/day
Status: ❌ FAIL - Deployment blocked

Remediation:
  Option 1: Use cheaper model (gpt-4-turbo saves 70%)
  Option 2: Reduce daily request volume
  Option 3: Increase budget to $250/day
```

**Cost Calculation (Full Transparency):**
```
Model: GPT-4-Turbo
Daily requests: 500
Input tokens/request: 800
Output tokens/request: 400
Estimated daily cost: $12.50
Monthly cost: $375.00
Safety margin: 8x (well under $100 budget)
Status: ✅ PASS
```

### Supporting Checks (Existing v0.2)

#### 📋 INPUT_CONTRACT
Ensures request schemas are defined and tested.
- ✅ Schema explicitly defined
- ✅ Valid inputs pass validation
- ✅ Invalid inputs fail validation
- Prevents input-based failures

#### ⏹ FALLBACK_DECLARED
Ensures agent can be stopped if something goes wrong.
- ✅ Kill switch defined (feature flag)
- ✅ Fallback mode exists (escalate to human)
- ✅ Team ownership clear
- ✅ Runbook provided

#### 🔐 IDENTITY_BOUNDARY
Enforces access control and rate limiting.
- ✅ Authentication required
- ✅ Rate limits configured
- ✅ Data isolation defined
- Prevents unauthorized access

---

## Quick Start (5 Minutes)

### 1. Install
```bash
pip install release-gate
```

### 2. Create governance.yaml
```yaml
project:
  name: my-agent

agent:
  model: gpt-4-turbo
  daily_requests: 500
  avg_input_tokens: 800
  avg_output_tokens: 400
  retry_rate: 1.1

checks:
  action_budget:
    enabled: true
    max_daily_cost: 100
```

### 3. Run Validation
```bash
release-gate check --config governance.yaml
```

### 4. See Decision
```
┌──────────────────────────────────────────┐
│ 🚪 release-gate: All 4 Checks            │
├──────────────────────────────────────────┤

💰 ACTION_BUDGET: ✓ PASS
   Daily Cost: $12.50
   Budget: $100.00
   Safety Margin: 8.0x

📋 INPUT_CONTRACT: ✓ PASS
   Schema defined

⏹ FALLBACK_DECLARED: ✓ PASS
   Kill switch configured

🔐 IDENTITY_BOUNDARY: ✓ PASS
   Authentication required

✅ FINAL DECISION: PASS (Safe to deploy)
└──────────────────────────────────────────┘
```

---

## Real-World Example: The $50K Mistake

### Scenario
You deploy a customer support agent without checking costs:

```yaml
agent:
  model: gpt-4           # Expensive model
  daily_requests: 5000   # High volume
  avg_input_tokens: 2000 # Long context
  avg_output_tokens: 1000
```

**Without release-gate:**
```
Day 1: Agent costs $250
Day 2: No one notices
Day 3: Cost spike warning
...
Week 2: You've spent $50,000
```

**With release-gate:**
```
$ release-gate check --config governance.yaml

❌ FAIL - Cost Control: Budget Exceeded

Daily cost: $250.00
Budget: $100.00
Daily overage: $150.00
Monthly overage: $4,500.00

❌ BLOCKED: Cannot deploy without fixing cost configuration

Remediation Options:
  Option 1: Use gpt-4-turbo (3.3x cheaper)
           New cost: $75.88/day → PASS ✓
  
  Option 2: Reduce daily requests to 1000
           New cost: $50/day → PASS ✓
  
  Option 3: Increase budget to $250/day
           Then re-run validation
```

**Result:** Deployment blocked. Problem caught before it costs you $50K.

---

## Key Features

### 💰 ACTION_BUDGET: Cost Control (v0.3 New)

#### Automatic Cost Estimation
```python
# Reads agent config
agent:
  model: gpt-4-turbo
  daily_requests: 500
  avg_input_tokens: 800
  avg_output_tokens: 400
  retry_rate: 1.1

# Automatically calculates:
# Input cost: $0.00001 × 800 ÷ 1000 × 500 × 1.1 = $4.40/day
# Output cost: $0.00003 × 400 ÷ 1000 × 500 × 1.1 = $6.60/day
# Total: $11.00/day
```

#### Smart Thresholds
```yaml
checks:
  action_budget:
    max_daily_cost: 100
    auto_approve_threshold: 10      # < $10 = instant PASS
    manual_approval_threshold: 50   # $10-$50 = needs review
    # $50+ = approval routing
```

#### Approval Routing (Future)
```yaml
approval_routes:
  - type: slack
    channel: "#ai-governance"
    mentions: ["@platform-leads"]
  - type: email
    to: ["ai-team@company.com"]
    cc: ["security@company.com"]
```

### 🔄 Dynamic Pricing

#### No Hardcoding
```python
# Instead of hardcoded enums:
# - Supports ANY model (past, present, future)
# - Auto-detects from code
# - User-extensible via JSON
```

#### Auto-Detection
```python
# Code:
client = OpenAI(model="gpt-4o")
response = client.chat.completions.create(model="gpt-4o")

# release-gate automatically detects: gpt-4o
# Looks up pricing
# Estimates cost
# All automatic
```

#### Custom Models
```json
{
  "models": {
    "my-internal-llama": {
      "input": 0.0001,
      "output": 0.0002,
      "provider": "Internal"
    }
  }
}
```

Add a custom model. No code changes. Instant support.

---

## Installation

### Via pip
```bash
pip install release-gate
```

### From source
```bash
git clone https://github.com/VamsiSudhakaran1/release-gate.git
cd release-gate
pip install -e .
```

### Requirements
- Python 3.8+
- PyYAML >= 6.0
- jsonschema >= 4.0

---

## Configuration

### Minimal (Cost Control Only)
```yaml
project:
  name: my-agent

agent:
  model: gpt-4-turbo
  daily_requests: 100
  avg_input_tokens: 500
  avg_output_tokens: 300

checks:
  action_budget:
    enabled: true
    max_daily_cost: 50
```

### Complete (All 4 Checks)
```yaml
project:
  name: customer-support-agent
  version: 1.0.0

agent:
  model: gpt-4-turbo
  daily_requests: 500
  avg_input_tokens: 800
  avg_output_tokens: 400
  retry_rate: 1.1

checks:
  action_budget:
    enabled: true
    max_daily_cost: 100
    auto_approve_threshold: 10
    manual_approval_threshold: 50
  
  input_contract:
    enabled: true
    schema:
      type: object
      required: [user_query]
      properties:
        user_query:
          type: string
  
  fallback_declared:
    enabled: true
    kill_switch:
      type: feature_flag
      name: disable_agent
    fallback:
      mode: escalate_to_human
    ownership:
      team: support-team
      oncall: "oncall@company.com"
  
  identity_boundary:
    enabled: true
    authentication: required
    rate_limit: 10
    data_isolation:
      - customer_data_only
```

---

## Usage

### Command Line
```bash
# Simple validation
release-gate check --config governance.yaml

# JSON output (for CI/CD)
release-gate check --config governance.yaml --output json

# YAML output (save to repo)
release-gate check --config governance.yaml --output yaml > audit.yaml
```

### GitHub Actions
```yaml
name: Governance Gate
on: [pull_request, push]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install release-gate
      - run: release-gate check --config governance.yaml
```

### Python API
```python
from release_gate.checks.action_budget import ActionBudgetCheck
import yaml

with open('governance.yaml') as f:
    config = yaml.safe_load(f)

check = ActionBudgetCheck()
result = check.evaluate(config)

if result['status'] == 'PASS':
    print("✅ Safe to deploy")
else:
    print("❌ Fix cost configuration")
    for step in result.get('remediation_steps', []):
        print(f"  - {step}")
```

---

## Exit Codes

- **0** = PASS (all checks passed, safe to deploy)
- **10** = WARN (manual review recommended)
- **1** = FAIL (deployment blocked, fix issues)

Perfect for CI/CD pipelines.

---

## Roadmap

### v0.3 (Current) ✅
- [x] ACTION_BUDGET check (cost control)
- [x] Dynamic pricing system
- [x] Auto-model detection
- [x] Custom model support
- [x] All 4 checks working together

### v0.4 (Planned)
- [ ] GitHub Actions marketplace integration
- [ ] Web dashboard
- [ ] Advanced approval workflows
- [ ] Enterprise SSO/RBAC

### v1.0 (Vision)
- [ ] Real-time pricing API integration
- [ ] Advanced policy templates
- [ ] Multi-agent governance
- [ ] Analytics & reporting

---

## Supported Models

### OpenAI
- GPT-4
- GPT-4 Turbo
- GPT-4o

### Anthropic
- Claude 3 Opus
- Claude 3 Sonnet
- Claude 3.5 Sonnet

### Open Source
- Llama 70B
- Mistral Large

### Custom
- Any model (add to pricing.json)

---

## Examples

See `examples/` directory:
- `governance-simple.yaml` - Minimal setup
- `governance-complete.yaml` - Full setup
- `pricing.json` - All supported models
- `test_action_budget.py` - Test suite

---

## Architecture

### 4 Independent Checks
Each check validates independently:
- **ACTION_BUDGET** validates cost
- **INPUT_CONTRACT** validates schema
- **FALLBACK_DECLARED** validates safety
- **IDENTITY_BOUNDARY** validates access

No cross-dependencies. Easy to extend.

### Decision Logic
```
If ANY check FAILS → FAIL (deployment blocked)
Else if ANY check WARNS → WARN (manual review)
Else → PASS (all good)
```

All 4 checks are equal partners in the decision.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Support

- 📖 [Documentation](docs/)
- 🐛 [Issues](https://github.com/VamsiSudhakaran1/release-gate/issues)
- 💬 [Discussions](https://github.com/VamsiSudhakaran1/release-gate/discussions)
- 🌐 [Website](https://release-gate.com)

---

## License

MIT — See [LICENSE](LICENSE) for details.

---

## The Vision

**Every AI agent should have cost limits, safety measures, and access controls before deployment.**

release-gate makes this simple, automatic, and transparent.

---

**Prevent cost explosions. Enforce governance. Deploy with confidence.** 🚀

Built by [Vamsi](https://github.com/VamsiSudhakaran1) • [release-gate.com](https://release-gate.com)
