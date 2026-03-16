# release-gate v0.1.0 - Project Overview & Status

## What You Have

A foundational deployment readiness gate for AI agents.

**v0.1.0 includes:**
✅ INPUT_CONTRACT check (schema + sample validation)
✅ FALLBACK_DECLARED check (governance enforcement)
✅ CLI tool (init + run commands)
✅ JSON and text output
✅ Exit codes for CI/CD
✅ Complete documentation

**v0.1.0 does NOT include:**
❌ Runtime agent execution
❌ Sample output validation
❌ Formal verification
❌ Runtime monitoring

See CHANGELOG.md for complete feature list and roadmap.

### Files Included

1. **cli.py** - Main command-line tool
   - `python cli.py init --project NAME` - Create new project
   - `python cli.py run --config CONFIG` - Run gate checks

2. **README.md** - Full documentation
   - Features and checks
   - Configuration guide
   - Examples
   - Use cases

3. **QUICKSTART.md** - Quick start guide
   - 5-minute demo
   - Common commands
   - Troubleshooting

4. **requirements.txt** - Python dependencies
   - pyyaml (YAML parsing)
   - jsonschema (Schema validation)

5. **example-config.yaml** - Example configuration
   - Real-world setup
   - Video generation API
   - Both checks configured

6. **valid_requests.jsonl** - Valid request examples
   - Examples your agent SHOULD accept
   - Paired with invalid samples

7. **invalid_requests.jsonl** - Invalid request examples
   - Examples your agent SHOULD reject
   - Used to test schema validation

## What It Does

### Check 1: INPUT_CONTRACT
Validates that your AI agent's request schema is well-defined and tested.

**Prevents:**
- Non-owner commands
- Resource exhaustion
- Unexpected behavior

### Check 2: FALLBACK_DECLARED
Validates that operational safety mechanisms are in place.

**Requires:**
- Kill switch (how to disable)
- Fallback behavior (what if it fails)
- Ownership (who's responsible)
- Runbook (incident response)

## Quick Demo (5 minutes)

```bash
# 1. Install
pip install -r requirements.txt

# 2. Initialize
python cli.py init --project demo

# 3. Run
python cli.py run --config release-gate.yaml --format text
```

Expected: **Overall: ✓ PASS**

## Features

✅ Prevents 9 of 11 documented agent failures
✅ CLI-based, no external services
✅ YAML configuration, easy to understand
✅ JSON reports for CI/CD integration
✅ Exit codes for automation (0=PASS, 10=WARN, 1=FAIL)
✅ Human-readable text output
✅ Machine-readable JSON output

## Use Cases

### 1. CI/CD Gate
Block deployments that don't meet governance requirements.

### 2. Compliance Audit
Generate audit trails for regulatory requirements.

### 3. Team Safety
Ensure shared infrastructure is responsibly managed.

### 4. Documentation
Enforce operational runbooks and incident response.

## How to Use

### Initialize Your System

```bash
python cli.py init --project my-video-service
```

Creates:
- release-gate.yaml (you customize this)
- valid_requests.jsonl (add your examples)
- invalid_requests.jsonl (add edge cases)

### Customize Configuration

Edit `release-gate.yaml`:
1. Update project name and version
2. Define your request schema
3. Add operational safety info

### Add Examples

Update sample files:
- `valid_requests.jsonl` - Requests you accept
- `invalid_requests.jsonl` - Requests you reject

### Run the Gate

```bash
# Human-readable output
python cli.py run --config release-gate.yaml --format text

# Machine-readable output
python cli.py run --config release-gate.yaml --format json
```

### Integrate with CI/CD

```bash
# GitHub Actions, GitLab CI, Jenkins, etc.
python cli.py run --config release-gate.yaml

# Check exit code
if [ $? -ne 0 ]; then
  echo "Deployment blocked"
  exit 1
fi
```

## Exit Codes

- **0** (PASS) - Safe to deploy
- **10** (WARN) - Warnings found, review carefully
- **1** (FAIL) - Do not deploy, fix issues first

## Real-World Example

See `example-config.yaml` for a complete video generation API setup.

Includes:
- Full schema validation
- Valid request examples
- Invalid request examples
- Kill switch configuration
- Fallback behavior
- Team ownership
- Runbook URL

## Technology

- **Language:** Python 3.7+
- **Dependencies:** pyyaml, jsonschema (only 2!)
- **License:** MIT
- **Infrastructure:** None - runs locally

## Design Philosophy

**1. Governance vs Functionality**
- QA tests: "Does it work?"
- release-gate tests: "Is it safe?"

**2. Inspired by Research**
- Based on "Agents of Chaos" paper
- Prevents 9 of 11 documented failures
- Focus on real production scenarios

**3. Simple and Practical**
- No backend servers
- No data transmission
- Easy to understand YAML
- Clear, actionable results

## What's Next

1. **Today:** Run the demo
2. **This week:** Configure for your system
3. **This month:** Integrate with CI/CD
4. **Next quarter:** Gather feedback from teams

## Support

**Stuck?**

1. Read QUICKSTART.md (5-minute guide)
2. Read README.md (complete reference)
3. Run `python cli.py init --project test` to see defaults
4. Review example-config.yaml for real example

## For More Information

- See **QUICKSTART.md** for quick start
- See **README.md** for complete documentation
- See **example-config.yaml** for real-world example

---

## Getting Started Right Now

```bash
# 1. Install
pip install -r requirements.txt

# 2. See help
python cli.py init --project help

# 3. Create a project
python cli.py init --project my-system

# 4. Run the gate
python cli.py run --config release-gate.yaml --format text

# Done! That's the complete workflow.
```

---

**release-gate: Making autonomous agents deterministically reliable.** 🚀
