# release-gate

**Governance enforcement for AI agents. Cost control, safety measures, and access boundaries before deployment.**

[![PyPI version](https://badge.fury.io/py/release-gate.svg)](https://badge.fury.io/py/release-gate)
[![GitHub stars](https://img.shields.io/github/stars/VamsiSudhakaran1/release-gate)](https://github.com/VamsiSudhakaran1/release-gate)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **v0.5.0** — Cryptographic governance signing (RSA-PSS + SHA256), config schema validation, simulation parameter bounds checking, and comprehensive test coverage.

## What is release-gate?

release-gate sits between your tests and your deployment. It validates that your AI agent meets governance requirements before it goes live — and **shows you the money at risk** if it doesn't.

**No infrastructure. No complex setup. One command to set it all up.**

```
$ release-gate impact governance.yaml

  release-gate  |  Impact Simulator
  ════════════════════════════════════════════════════════════════════════

  Model            gpt-4 (OpenAI)
  Requests/day     10,000
  Tokens/request   2,000 in + 800 out

  ────────────────────────────────────────────────────────────────────────
  Scenario                            Daily       Monthly          Annual
  ────────────────────────────────────────────────────────────────────────
    Normal operation             $ 1,080.00  $  32,400.00  $   394,200.00
  ! Runaway loop (15x retries + 5x traffic) $54,000.00  $1,620,000.00  $19,710,000.00
  ────────────────────────────────────────────────────────────────────────
  * Risk delta (money at stake)  $52,920.00  $1,587,600.00  $19,051,200.00

  Budget cap       $200.00/day   [✗ FAIL]  (headroom: $-880.00/day)

  GOVERNANCE GAPS — Business Impact
  ────────────────────────────────────────────────────────────────────────
  1. [FALLBACK_DECLARED] KILL_SWITCH not declared
     → No way to stop a runaway agent — manual intervention required
  2. [FALLBACK_DECLARED] TEAM_OWNER not declared
     → No owner means no one gets paged when costs spike at 3 AM
  3. [IDENTITY_BOUNDARY] RATE_LIMIT not declared
     → No rate limit — a single client can exhaust budget in minutes
  4. [ACTION_BUDGET] MAX_DAILY_COST not declared
     → Unlimited spend — no circuit breaker on daily cost

  FINAL VERDICT:  ✗  BLOCKED
```

**Engineering leaders see money, not YAML warnings.**

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

## Commands

| Command | What it does |
|---------|-------------|
| `release-gate impact <config.yaml>` | **Impact Simulator** — shows normal cost, runaway-loop cost, money at risk, and governance gaps with business impact |
| `release-gate run <config.yaml>` | Governance checks — PASS/WARN/FAIL with exit codes for CI |
| `release-gate init` | Interactive setup wizard |
| `release-gate validate-and-lock` | Cryptographic signing/verification (v0.5) |

### Flags
| Flag | Description |
|------|-------------|
| `--html-report <file.html>` | Write self-contained HTML impact report (ideal for CI artifacts) |
| `--output-evidence <file.json>` | Save full JSON evidence |
| `--fail-on-warn` | Treat WARN as FAIL in CI (GitHub Action only) |

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

---

## CI/CD Integration

### GitHub Actions

Add release-gate to any AI agent repo in 5 lines:

```yaml
# .github/workflows/governance.yml
- name: release-gate Impact Check
  uses: VamsiSudhakaran1/release-gate@v0.5.0
  with:
    config: governance.yaml
    command: impact
    html-report: report.html   # uploaded as CI artifact automatically
```

The HTML report is uploaded as a CI artifact on every run — give your team a live dashboard of cost risk without leaving GitHub.

### Full options

```yaml
- uses: VamsiSudhakaran1/release-gate@v0.5.0
  with:
    config: governance.yaml       # default: governance.yaml
    command: impact               # or: run
    html-report: report.html      # optional HTML report
    output-evidence: evidence.json # optional JSON evidence
    fail-on-warn: "true"          # treat WARN as failure (default: false)
    python-version: "3.11"        # default: 3.11
```

### Demo scenarios

| Config | Expected result |
|--------|----------------|
| `examples/governance-safe-pass.yaml` | ✓ APPROVED — full governance |
| `examples/governance-unsafe-fail.yaml` | ✗ BLOCKED — missing kill switch, rate limit, budget cap |

### GitLab CI

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

**OpenAI:** gpt-4-turbo, gpt-4, gpt-3.5-turbo
**Anthropic:** claude-3-opus, claude-3-sonnet, claude-3-haiku
**Google:** gemini-2.0-flash
**XAI (Grok):** grok-2, grok-3

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

## Cryptographic Governance (v0.5)

Lock your `governance.yaml` against post-review tampering using RSA-PSS + SHA256.

```bash
# Generate a key pair (one-time setup)
openssl genrsa -out governance-key.pem 2048
openssl rsa -in governance-key.pem -pubout -out governance-key.pub

# Sign and lock
release-gate validate-and-lock \
  --governance governance.yaml \
  --sign \
  --private-key governance-key.pem

# Verify in CI
release-gate validate-and-lock \
  --governance governance.yaml \
  --verify \
  --public-key governance-key.pub
```

Exit code `0` = valid. Exit code `1` = tampered or missing signature.

> **Security note:** Store the private key in your secrets manager (e.g., GitHub Secrets, Vault). Only the public key needs to be committed.

---

## Simulation Parameter Constraints

To prevent nonsensical cost projections, `release-gate` enforces these ranges on
`simulation.factors` values:

| Parameter | Valid range | Default |
|-----------|-------------|----------|
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
