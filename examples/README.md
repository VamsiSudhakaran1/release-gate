# 📋 Examples

This folder contains example configurations and sample data for release-gate.

---

## Files

### example-config.yaml
A complete example configuration file showing all available options.

**Use this as a template** when creating your own `release-gate.yaml`.

```yaml
project:
  name: my-system
  version: 1.0.0

checks:
  input_contract:
    enabled: true
    schema: {...}
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
    kill_switch: {...}
    fallback: {...}
    ownership: {...}
    runbook_url: https://...
```

### valid_requests.jsonl
Example of **valid requests** that should pass your schema.

```json
{"prompt":"A cat playing guitar","duration_sec":5,"resolution":"720p"}
{"prompt":"A dog dancing","duration_sec":10,"resolution":"1080p"}
{"prompt":"Ocean waves","duration_sec":30,"resolution":"480p"}
```

### invalid_requests.jsonl
Example of **invalid requests** that should fail your schema.

```json
{"prompt":"","duration_sec":5,"resolution":"720p"}
{"prompt":"Test","duration_sec":120,"resolution":"720p"}
{"duration_sec":5,"resolution":"720p"}
```

---

## How to Use These Examples

### Step 1: Initialize a Project

```bash
python cli.py init --project my-system
```

This creates:
- `release-gate.yaml` (configuration)
- `valid_requests.jsonl` (sample requests)
- `invalid_requests.jsonl` (invalid samples)

### Step 2: Customize the Configuration

Copy the example and modify it for your system:

```bash
# Start with the example
cp examples/example-config.yaml release-gate.yaml

# Edit release-gate.yaml with your:
# - Project name
# - Request schema
# - Sample files
# - Fallback configuration
# - Ownership information
# - Runbook URL
```

### Step 3: Create Your Sample Files

**valid_requests.jsonl** - Should contain requests that are valid according to your schema:

```json
{"your_field":"valid_value","another_field":123}
{"your_field":"another_valid_value","another_field":456}
```

**invalid_requests.jsonl** - Should contain requests that violate your schema:

```json
{"your_field":""}
{"another_field":"invalid"}
{"wrong_field":"value"}
```

### Step 4: Run the Gate

```bash
python cli.py run --config release-gate.yaml --format text
```

---

## Example Configuration Explained

### project

```yaml
project:
  name: video-generation-api
  version: 1.0.0
  description: AI video generation with autonomous agent
```

- **name:** Your system name
- **version:** Your system version
- **description:** Brief description

### input_contract

```yaml
input_contract:
  enabled: true
  schema:
    type: object
    required: [prompt, duration_sec]
    properties:
      prompt:
        type: string
        minLength: 1
        maxLength: 1000
      duration_sec:
        type: number
        minimum: 1
        maximum: 60
  samples:
    valid_path: valid_requests.jsonl
    invalid_path: invalid_requests.jsonl
```

- **schema:** JSON Schema describing valid requests
- **valid_path:** File with valid request examples
- **invalid_path:** File with invalid request examples

### fallback_declared

```yaml
fallback_declared:
  enabled: true
  kill_switch:
    type: feature_flag
    name: disable_video_generation
  fallback:
    mode: static_placeholder
    description: Return placeholder video on failure
  ownership:
    team: platform-team
    oncall: oncall-platform
  runbook_url: https://wiki.internal/runbooks/video-generation
```

- **kill_switch:** How to disable the system
- **fallback:** What happens if it fails
- **ownership:** Who's responsible
- **runbook_url:** Incident response guide

---

## Real-World Example

### Scenario: LLM Request Validation

You have an LLM that takes text prompts and generates code.

**Schema:**
```json
{
  "type": "object",
  "required": ["prompt", "language"],
  "properties": {
    "prompt": {
      "type": "string",
      "minLength": 10,
      "maxLength": 2000
    },
    "language": {
      "type": "string",
      "enum": ["python", "javascript", "go"]
    },
    "temperature": {
      "type": "number",
      "minimum": 0,
      "maximum": 1
    }
  }
}
```

**valid_requests.jsonl:**
```json
{"prompt":"Write a function to sort an array","language":"python"}
{"prompt":"Create a React button component","language":"javascript","temperature":0.7}
{"prompt":"Build a Go HTTP server","language":"go","temperature":0.5}
```

**invalid_requests.jsonl:**
```json
{"prompt":"Short","language":"python"}
{"language":"python"}
{"prompt":"Valid prompt","language":"ruby"}
{"prompt":"Valid prompt","language":"python","temperature":1.5}
```

**fallback_declared:**
```yaml
fallback_declared:
  enabled: true
  kill_switch:
    type: feature_flag
    name: disable_code_generation
  fallback:
    mode: error_response
    description: Return error instead of generated code
  ownership:
    team: ai-platform
    oncall: oncall-ai-platform
  runbook_url: https://wiki.company.com/runbooks/code-generation
```

---

## Tips

1. **Keep samples focused** - Both valid and invalid samples should be representative of real requests
2. **Test your schema** - Make sure valid samples pass and invalid samples fail
3. **Update regularly** - As your system changes, update your schema and samples
4. **Version your config** - Use git to track changes to your configuration
5. **Review reports** - Check the JSON report to understand what passed/failed

---

## Common Mistakes

❌ **All valid samples are identical**
Use varied examples to test different schema paths.

❌ **Invalid samples don't actually violate the schema**
Make sure invalid samples fail validation.

❌ **Missing required fields in schema**
List all required fields so invalid samples test them.

❌ **Schema too permissive**
Be specific about types, lengths, and allowed values.

❌ **Sample files not in correct JSONL format**
Each line must be valid JSON (no multi-line objects).

---

## Loop behaviour demo — `good` / `mid` / `worst`

`loop_agents.py` has three agents that make loop behaviour visible. Score the same
three two ways and watch the verdicts agree:

```bash
# How does it behave in a loop? (pre-deploy characterization)
release-gate loop-sim examples/loop_demo_scenarios.yaml --agent py:examples.loop_agents:good   # PROMOTE
release-gate loop-sim examples/loop_demo_scenarios.yaml --agent py:examples.loop_agents:mid    # HOLD
release-gate loop-sim examples/loop_demo_scenarios.yaml --agent py:examples.loop_agents:worst  # BLOCK

# Full behaviour battery, including the L1-L4 safety tiers
release-gate agent-score py:examples.loop_agents:good      # PROMOTE · L1-L4 clean
release-gate agent-score py:examples.loop_agents:mid       # HOLD    · leaks on L3 (encode/translate)
release-gate agent-score py:examples.loop_agents:worst     # BLOCK   · leaks on L1 (verbatim)
```

| agent | loop-sim | why | safety |
|-------|----------|-----|--------|
| `good`  | **PROMOTE** | ships on iteration 1, cheap | clean L1–L4 |
| `mid`   | **HOLD**    | converges, but only after ~5 iterations | leaks on L3 |
| `worst` | **BLOCK**   | never says DONE → blows the budget, never ships | leaks on L1 |

The scenarios are ordinary work tasks — the PROMOTE/HOLD/BLOCK split comes entirely
from how each agent behaves *in the loop*, not from the tasks.

---

## Next Steps

1. Copy `example-config.yaml` to `release-gate.yaml`
2. Create your own `valid_requests.jsonl`
3. Create your own `invalid_requests.jsonl`
4. Run: `python cli.py run --config release-gate.yaml --format text`
5. Check the output
6. Iterate on your schema based on results

---

**Happy configuring! 📝**
