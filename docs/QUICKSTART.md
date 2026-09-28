# release-gate Quick Start Guide

## 5-Minute Demo

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Initialize a Project

```bash
python cli.py init --project demo-agent
```

This creates:
- `release-gate.yaml` - Configuration
- `valid_requests.jsonl` - Valid request examples
- `invalid_requests.jsonl` - Invalid request examples

### Step 3: Run the Gate

```bash
python cli.py run --config release-gate.yaml --format text
```

Expected output:
```
Overall: ✓ PASS
```

## What It Does

**INPUT_CONTRACT Check:**
- Validates your request schema is defined
- Checks valid requests pass the schema
- Checks invalid requests fail the schema

**FALLBACK_DECLARED Check:**
- Ensures kill switch is declared
- Ensures fallback behavior is defined
- Ensures team ownership is assigned
- Ensures incident runbook exists

## Configuration

Edit `release-gate.yaml`:

```yaml
checks:
  input_contract:
    schema:
      type: object
      required: [prompt, duration]
      properties:
        prompt: {type: string}
        duration: {type: number}
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    kill_switch:
      type: feature_flag
      name: disable_my_system
    fallback:
      mode: static_placeholder
    ownership:
      team: my-team
      oncall: oncall-contact
    runbook_url: https://wiki/runbooks/my-system
```

## Sample Files

### valid_requests.jsonl

Examples of requests your agent SHOULD accept:

```json
{"prompt":"A cat playing guitar","duration":5}
{"prompt":"A dog dancing","duration":10}
```

### invalid_requests.jsonl

Examples of requests your agent SHOULD reject:

```json
{"prompt":"","duration":5}
{"prompt":"Test","duration":120}
```

## Commands

### Initialize
```bash
python cli.py init --project my-system
```

### Run with Text Output (Human-Readable)
```bash
python cli.py run --config release-gate.yaml --format text
```

### Run with JSON Output (Machine-Readable)
```bash
python cli.py run --config release-gate.yaml --format json
```

## Understanding Results

### ✓ PASS (Exit Code 0)
Every check this lane runs passed — nothing it looks for was found. That is not the
same as safe to deploy, and release-gate will not say the second thing: what a pass
establishes is bounded by what was checked, and the coverage note on each result says
what that was.

### ⚠ WARN (Exit Code 10)
Some warnings found. Review before deploying.

### ✗ FAIL (Exit Code 1)
Critical issues found. Fix before deploying.

## Using in CI/CD

```bash
#!/bin/bash
python cli.py run --config release-gate.yaml --env staging
if [ $? -ne 0 ]; then
  echo "Deployment blocked"
  exit 1
fi
echo "Deployment approved"
```

## Common Issues

**"Config file not found"**
- Make sure file exists and path is correct

**"No schema defined"**
- Add schema to input_contract in release-gate.yaml

**"Invalid schema"**
- Check YAML syntax

**"Missing fields"**
- Add kill_switch, fallback, ownership, runbook_url

## Files

- `cli.py` - Main tool (python cli.py init, python cli.py run)
- `README.md` - Full documentation
- `requirements.txt` - Python dependencies
- `example-config.yaml` - Example configuration
- `valid_requests.jsonl` - Example valid requests
- `invalid_requests.jsonl` - Example invalid requests

## Next Steps

1. Read README.md for full documentation
2. Edit release-gate.yaml for your system
3. Add real request examples to sample files
4. Integrate into CI/CD pipeline
5. Share with your team

---

For detailed documentation, see README.md
