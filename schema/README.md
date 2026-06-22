# release-gate JSON Schemas

This directory contains [JSON Schema draft-07](https://json-schema.org/draft-07/json-schema-release-notes.html) schemas for the two YAML files consumed by `release-gate`.

| Schema | Validates |
|---|---|
| `governance.schema.json` | `governance.yaml` — deployment governance policy |
| `evals.schema.json` | `evals.yaml` — behavior evaluation test cases |

Schemas are also served at:
- `https://release-gate.com/schema/governance.schema.json`
- `https://release-gate.com/schema/evals.schema.json`

## VS Code — YAML extension

Install the [YAML extension by Red Hat](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml), then add to your workspace `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "https://release-gate.com/schema/governance.schema.json": "governance.{yaml,yml}",
    "https://release-gate.com/schema/evals.schema.json": "evals.{yaml,yml}"
  }
}
```

The release-gate VS Code extension configures this automatically when activated.

## CLI validation with jsonschema

```bash
pip install jsonschema pyyaml

# Validate governance.yaml
python -c "
import jsonschema, yaml, json, sys
schema = json.load(open('schema/governance.schema.json'))
data = yaml.safe_load(open('governance.yaml'))
jsonschema.validate(data, schema)
print('governance.yaml is valid')
"

# Validate evals.yaml
python -c "
import jsonschema, yaml, json, sys
schema = json.load(open('schema/evals.schema.json'))
data = yaml.safe_load(open('evals.yaml'))
jsonschema.validate(data, schema)
print('evals.yaml is valid')
"
```
