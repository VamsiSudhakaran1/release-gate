# release-gate

**Governance enforcement for AI agents. Cost control, safety measures, and access boundaries before deployment.**

[![PyPI version](https://badge.fury.io/py/release-gate.svg)](https://badge.fury.io/py/release-gate)
[![GitHub stars](https://img.shields.io/github/stars/VamsiSudhakaran1/release-gate)](https://github.com/VamsiSudhakaran1/release-gate)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **v0.5.0** — Cryptographic governance signing (RSA-PSS + SHA256), config schema validation, simulation parameter bounds checking, and comprehensive test coverage.

## What is release-gate?

release-gate sits between your tests and your deployment. It validates that your AI agent meets governance requirements before it goes live.

**No infrastructure. No complex setup. One command to set it all up.**

## Quick Start

```bash
# 1. Install
pip install release-gate

# 2. Initialize (interactive setup)
release-gate init

# 3. Deploy
git add governance.yaml GOVERNANCE.md
git commit -m "feat: add release-gate governance"
git push
```

That's it! Governance is now active on every push and PR.

---

## Features

- **⚡ One Command Setup** - `release-gate init` creates everything in 5 minutes
- **💰 Budget Simulation Engine** - Project realistic costs with retries, caching, spiky usage
- **🛡️ Policy Engine** - Define what's critical (blocks) vs flexible (warns)
- **🔒 Access Control** - Identity boundaries with authentication, rate limiting, data isolation
- **✅ Input Validation** - Contract checking with schema validation
- **📊 Impact Reporting** - See CRITICAL, HIGH, MEDIUM issues with clear remediation
- **🔄 Multi-Platform CI/CD** - GitHub Actions, GitLab CI, Jenkins support
- **🔑 Cryptographic Signing** *(v0.5)* - RSA-PSS + SHA256 signatures lock governance.yaml against tampering
- **🧪 Config Schema Validation** - YAML structure validated at load time with clear error messages
- **⚙️ Simulation Bounds Checking** - Invalid multiplier values (`retry_rate`, `cache_hit_rate`) are caught before they produce nonsensical cost projections

---

## The 5 Governance Checks

| Check | Purpose | Impact |
|-------|---------|--------|
| **ACTION_BUDGET** | Prevent cost explosions | Blocks if daily cost exceeds budget |
| **BUDGET_SIMULATION** | Project realistic costs | Accounts for retries, caching, peak usage |
| **FALLBACK_DECLARED** | Ensure safety measures | Requires kill switch, runbook, team owner |
| **IDENTITY_BOUNDARY** | Access control | Enforce auth, rate limits, data isolation |
| **INPUT_CONTRACT** | Input validation | Schema validation with sample testing |

---

## Setup Options

### Option 1: Interactive Setup (Recommended - 5 Minutes)

```bash
release-gate init
```

**The wizard will ask:**
- Project name
- AI model (10+ options: OpenAI, Anthropic, Google, XAI)
- Daily budget
- Expected requests per day
- Average tokens per request
- Team owner
- Runbook/documentation URL
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins)

**Auto-generates:**
- ✓ `governance.yaml` - Fully configured
- ✓ `GOVERNANCE.md` - Documentation
- ✓ CI/CD pipeline config - Platform-specific
- ✓ Updated `.gitignore`

**Example interaction:**

```
🚪 release-gate: Project Initialization Wizard
================================================

📋 STEP 1: Project Details
Project name [my-agent]: my-awesome-agent

🤖 STEP 2: Agent Configuration
Select AI model:
  1. gpt-4-turbo (OpenAI)
  2. gpt-4 (OpenAI)
  3. gpt-3.5-turbo (OpenAI)
  4. claude-3-opus (Anthropic)
  5. claude-3-sonnet (Anthropic)
  ...
Select option [1]: 1
✓ Model: gpt-4-turbo

💰 STEP 3: Budget Configuration
Max daily cost (USD) [100]: 50
✓ Budget: $50.00/day

📊 STEP 4: Usage Simulation
Expected requests per day [1000]: 500
Average input tokens per request [800]: 800
Average output tokens per request [400]: 400

🛡️ STEP 5: Safety Configuration
Team owner [platform-team]: my-team
Runbook URL [https://...]: https://wiki.example.com/runbook

🔄 STEP 6: CI/CD Integration
Select CI/CD platform:
  1. GitHub Actions
  2. GitLab CI
  3. Jenkins
  4. Other / Manual
Select option [1]: 1
✓ CI/CD: GitHub Actions

========================================================
✅ Configuration Complete!
📝 Generating files...
✓ Created governance.yaml
✓ Created GOVERNANCE.md
✓ Created .github/workflows/release-gate.yml

🚀 Setup Complete! Ready to deploy.
========================================================

Next steps:
  1. Review governance.yaml
  2. Commit files to git
  3. Push to repository
  4. Test with: release-gate run governance.yaml
```

---

### Option 2: Manual Setup (Advanced)

Create `governance.yaml`:

```yaml
project:
  name: my-agent

agent:
  model: gpt-4-turbo

policy:
  fail_on:
    - ACTION_BUDGET
    - BUDGET_SIMULATION
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
  warn_on:
    - INPUT_CONTRACT

checks:
  action_budget:
    enabled: true
    max_daily_cost: 100

  budget_simulation:
    enabled: true
    simulation:
      requests_per_day: 1000
      tokens_per_request:
        input: 800
        output: 400
      factors:
        retry_rate: 1.2        # 20% retries
        cache_hit_rate: 0.3    # 30% cache hits
        spiky_usage_multiplier: 1.5  # Peak is 50% higher

  fallback_declared:
    enabled: true
    kill_switch:
      type: "feature-flag"
      location: "config/kill-switches"
    fallback_mode: "escalate-to-human"
    team_owner: "platform-team"
    runbook_url: "https://wiki.example.com/runbook"

  identity_boundary:
    enabled: true
    authentication:
      required: true
      type: "oauth2"
    rate_limit:
      requests_per_minute: 10
    data_isolation:
      - "customer_id isolation"

  input_contract:
    enabled: true
    schema:
      type: "object"
      required:
        - "user_query"
      properties:
        user_query:
          type: "string"
    samples:
      valid:
        - user_query: "What is the weather?"
      invalid:
        - user_query: ""
```

---

## Run Validation

```bash
release-gate run governance.yaml
```

**Output:**

```
================================================================================
🚪 release-gate: Governance Validation
================================================================================

CHECK                    STATUS   IMPACT
──────────────────────────────────────────────────────────────
ACTION_BUDGET            ✓ PASS   —
BUDGET_SIMULATION        ✓ PASS   —
FALLBACK_DECLARED        ✓ PASS   —
IDENTITY_BOUNDARY        ✓ PASS   —
INPUT_CONTRACT           ✓ PASS   —

──────────────────────────────────────────────────────────────

✅ FINAL DECISION: PASS
All checks passed. Safe to deploy.

💰 BUDGET SIMULATION DETAILS:
   Model: gpt-4-turbo
   Daily Cost: $12.50
   Monthly Cost: $375.00
   Annual Cost: $4,562.50
   Budget: $100.00/day
   Safety Margin: 8.00x
   Usage: 12.5% of budget

================================================================================
```

---

## CI/CD Integration

### GitHub Actions

Init creates `.github/workflows/release-gate.yml`:

```yaml
name: release-gate Governance Check
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install release-gate
      - run: release-gate run governance.yaml
```

### GitLab CI

Init creates `.gitlab-ci.yml`:

```yaml
governance:
  stage: validate
  image: python:3.10
  script:
    - pip install release-gate
    - release-gate run governance.yaml
  allow_failure: false
```

### Jenkins

Init creates `Jenkinsfile`:

```groovy
pipeline {
    agent any
    stages {
        stage('Governance') {
            steps {
                sh 'pip install release-gate'
                sh 'release-gate run governance.yaml'
            }
        }
    }
}
```

---

## Budget Simulation Engine

The Budget Simulation Engine projects realistic costs by accounting for:

- **Request volume** - How many requests per day
- **Token consumption** - Input and output tokens per request
- **Retries** - Failed requests that retry (20-30% typical)
- **Caching** - Repeated queries hitting cache (30-50% typical)
- **Spiky usage** - Peak times are higher than average (1.5-2x typical)

### Supported Models

**OpenAI:**
- gpt-4-turbo ($10 input, $30 output per 1M tokens)
- gpt-4 ($30 input, $60 output)
- gpt-3.5-turbo ($0.50 input, $1.50 output)

**Anthropic:**
- claude-3-opus ($15 input, $75 output)
- claude-3-sonnet ($3 input, $15 output)
- claude-3-haiku ($0.25 input, $1.25 output)

**Google:**
- gemini-2.0-flash ($0.075 input, $0.3 output)

**XAI (Grok):**
- grok-2 ($2 input, $10 output)
- grok-3 ($5 input, $15 output)

### Example: Cost Projection

```yaml
simulation:
  requests_per_day: 1000
  tokens_per_request:
    input: 800
    output: 400
  factors:
    retry_rate: 1.2
    cache_hit_rate: 0.3
    spiky_usage_multiplier: 1.5
```

**Calculation:**

```
Daily input tokens: 1000 * 800 * 1.2 * (1-0.3) * 1.5 = 1,008,000
Daily output tokens: 1000 * 400 * 1.2 * (1-0.3) * 1.5 = 504,000

Input cost: 1,008,000 / 1,000,000 * $10 = $10.08
Output cost: 504,000 / 1,000,000 * $30 = $15.12

Daily cost: $25.20
Monthly cost: $756
Annual cost: $9,198
Safety margin: 3.97x
```

---

## Policy Engine

Control what's critical vs flexible:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET        # Cost limits are critical
    - FALLBACK_DECLARED    # Safety measures are critical
  warn_on:
    - IDENTITY_BOUNDARY    # Access control needs review
    - INPUT_CONTRACT       # Schema validation needs review
```

**Decision Logic:**

- **PASS** - All critical checks passed (exit code 0)
- **WARN** - Non-critical check failed (exit code 10)
- **FAIL** - Critical check failed (exit code 1)

---

## Use Cases

### Startup with Limited Budget
```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - BUDGET_SIMULATION
```
Strict cost control before anything else.

### Enterprise with Safety Requirements
```yaml
policy:
  fail_on:
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
    - ACTION_BUDGET
```
Safety and access control are non-negotiable.

### Development Team
```yaml
policy:
  fail_on:
    - ACTION_BUDGET
  warn_on:
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
```
Cost matters most, other issues get warnings.

---

## FAQ

**Q: Do I need to use init?**
A: No. You can write `governance.yaml` manually. But init is much faster (5 minutes vs 30 minutes).

**Q: Does release-gate require a backend?**
A: No. Zero infrastructure. Runs entirely in your CI/CD pipeline.

**Q: Does it send data to external services?**
A: No. All pricing is built-in. No external API calls. Privacy-first.

**Q: Can I customize the checks?**
A: Yes. Each check can be enabled/disabled and configured in `governance.yaml`.

**Q: What models does Budget Simulation support?**
A: 10+ models out-of-the-box. Custom models can be added with custom pricing.

**Q: How accurate is the cost projection?**
A: Medium confidence. Actual costs depend on real usage patterns. Monitor and adjust after deployment.

**Q: Can I use this with custom models?**
A: Yes. Register custom pricing programmatically or in configuration.

---

## Roadmap

### Current ✅
- Init command with interactive wizard
- Budget Simulation Engine (10+ models)
- Policy Engine (fail_on vs warn_on)
- All 5 checks working
- Impact reporting
- Multi-platform CI/CD

### Next
- Action Scope Declared (allowed/blocked tools)
- Ownership Enforced (team + oncall)
- Deployment Fingerprint (reproducibility)
- GitHub PR bot integration

### Future
- Runtime integration hooks
- Constraint engine (symbolic rules)
- Enterprise dashboards
- Policy packs for industries

---

## Cryptographic Governance (v0.5)

Lock your `governance.yaml` against post-review tampering using RSA-PSS + SHA256.

### Generate a key pair

```bash
openssl genrsa -out governance-key.pem 2048
openssl rsa -in governance-key.pem -pubout -out governance-key.pub
```

### Sign and lock

```bash
release-gate validate-and-lock \
  --governance governance.yaml \
  --sign \
  --private-key governance-key.pem
```

This writes `.release-gate-proof.json` and `.governance.sig` next to your governance file.

### Verify in CI

```bash
release-gate validate-and-lock \
  --governance governance.yaml \
  --verify \
  --public-key governance-key.pub
```

Exit code `0` = valid. Exit code `1` = tampered or missing signature.

> **Security note:** Store the private key in your secrets manager (e.g., GitHub Secrets, Vault). Only the public key needs to be committed to the repository.

---

## Simulation Parameter Constraints

To prevent nonsensical cost projections, `release-gate` enforces these ranges on
`simulation.factors` values:

| Parameter | Valid range | Default |
|-----------|-------------|---------|
| `retry_rate` | 1.0 – 10.0 | 1.0 |
| `cache_hit_rate` | 0.0 – 1.0 | 0.0 |
| `spiky_usage_multiplier` | 1.0 – 20.0 | 1.0 |

Values outside these ranges will produce a `FAIL` result with a descriptive error message before any cost math is attempted.

---

## Development

```bash
git clone https://github.com/VamsiSudhakaran1/release-gate
cd release-gate
pip install -e ".[dev]"

# Run all tests (excluding crypto if cryptography package is not installed)
pytest tests/ --ignore=tests/test_crypto.py

# Run including crypto tests (requires working cryptography installation)
pytest tests/
```

---

## Contributing

Found a bug? Have a feature request? Open an [issue](https://github.com/VamsiSudhakaran1/release-gate/issues).

---

## License

MIT - See [LICENSE](LICENSE)

---

## Contact

- **GitHub:** [VamsiSudhakaran1/release-gate](https://github.com/VamsiSudhakaran1/release-gate)
- **Email:** vamsi.sudhakaran@gmail.com
- **Website:** [release-gate.com](https://release-gate.com)

---

**Built to turn AI governance from a checklist into a checkpoint.** 🚀
