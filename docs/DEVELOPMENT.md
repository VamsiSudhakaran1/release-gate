# 🛠️ Development Setup

## Quick Start for Developers

### 1. Clone Repository

```bash
git clone https://github.com/VamsiSudhakaran1/release-gate.git
cd release-gate
```

### 2. Create Virtual Environment (Optional)

```bash
# macOS/Linux
python -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python cli.py --help
```

---

## Project Structure

```
release-gate/
├── cli.py              Main application
├── requirements.txt    Dependencies
├── README.md           Main documentation
├── LICENSE             MIT license
│
├── docs/               📖 Documentation
│   ├── QUICKSTART.md
│   ├── EXTENDED_README.md
│   ├── CHANGELOG.md
│   ├── CONTRIBUTING.md
│   ├── ARCHITECTURE.md (how it works)
│   └── DEVELOPMENT.md  (this file)
│
├── examples/           📋 Example configs
│   ├── example-config.yaml
│   ├── valid_requests.jsonl
│   └── invalid_requests.jsonl
│
└── tests/              🧪 Test suite
    ├── test_release_gate.py
    └── README.md
```

---

## Development Workflow

### 1. Create a Test Project

```bash
python cli.py init --project test-project
```

This creates:
- `release-gate.yaml` - Configuration template
- `valid_requests.jsonl` - Valid request examples
- `invalid_requests.jsonl` - Invalid request examples

### 2. Run the Gate

```bash
# Text output
python cli.py run --config release-gate.yaml --format text

# JSON output
python cli.py run --config release-gate.yaml --format json

# Custom output file
python cli.py run --config release-gate.yaml --output my-report.json
```

### 3. Run Tests

```bash
# Run all tests
python tests/test_release_gate.py

# Expected: 10 passed, 0 failed
```

### 4. Modify Code

Edit `cli.py` to make changes:

```python
# Example: Add a new check
def _check_my_control(config):
    """New governance control"""
    # Implementation
    return {
        "name": "my_control",
        "result": "PASS|WARN|FAIL",
        "evidence": {...}
    }
```

### 5. Test Changes

```bash
# Quick manual test
python cli.py init --project dev-test
python cli.py run --config release-gate.yaml --format text

# Full test suite
python tests/test_release_gate.py

# All should pass
```

### 6. Commit and Push

```bash
git add .
git commit -m "feat: description of change"
git push origin main
```

---

## Key Files to Understand

### cli.py
- **Total lines:** ~520
- **Key functions:**
  - `init_project()` - Create new project
  - `run_gate()` - Main check orchestrator
  - `_check_input_contract()` - Validate request schema
  - `_check_fallback_declared()` - Validate governance
  - `_load_jsonl_file()` - Load sample files
  - `_display_text_report()` - Format output

### requirements.txt
```
pyyaml>=6.0
jsonschema>=4.0
```

Only 2 dependencies - keep it minimal!

---

## Testing

### Run Tests

```bash
python tests/test_release_gate.py
```

### Test Coverage

10 tests covering:
1. ✅ Initialization
2. ✅ PASS case (exit 0)
3. ✅ FAIL case (exit 1)
4. ✅ JSON output
5. ✅ Custom output file
6. ✅ Sample validation
7. ✅ WARN case (exit 10)
8. ✅ WARN exit code
9. ✅ WARN in summary
10. ✅ FAIL precedence

### Add New Tests

Edit `tests/test_release_gate.py`:

```python
def test_my_feature():
    """Test description"""
    # Arrange
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Act
        code, stdout, stderr = run_cli("init", "--project", "test", cwd=tmpdir)
        
        # Assert
        assert code == 0
        assert (tmpdir / "release-gate.yaml").exists()
```

---

## Code Style

### Python Style
- Use 4 spaces for indentation
- Clear variable names (no single letters except i, j)
- Docstrings on all functions
- Comments on complex logic

### Good Example
```python
def _check_input_contract(config, config_dir, jsonschema):
    """
    Validate INPUT_CONTRACT check.
    
    Tests:
    1. Schema is defined and valid
    2. Valid samples pass
    3. Invalid samples fail
    """
    # Get schema from config
    schema = config.get("checks", {}).get("input_contract", {}).get("schema")
    
    if not schema:
        return {"result": "FAIL", "evidence": {"error": "No schema"}}
    
    # Validate schema syntax
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except Exception as e:
        return {"result": "FAIL", "evidence": {"error": str(e)}}
    
    # Rest of implementation
    ...
```

### YAML Style
- 2 spaces indentation
- Clear field names
- Comments explaining sections

---

## Common Tasks

### Add a New Check

1. Create function in `cli.py`:
```python
def _check_my_control(config):
    """Check description"""
    # Implementation
    return {"name": "...", "result": "...", "evidence": {...}}
```

2. Call it in `run_gate()`:
```python
my_check = _check_my_control(config)
results["checks"].append(my_check)
```

3. Update result aggregation:
```python
if my_check["result"] == "FAIL":
    results["overall"] = "FAIL"
elif my_check["result"] == "WARN" and results["overall"] != "FAIL":
    results["overall"] = "WARN"
```

4. Add test in `tests/test_release_gate.py`

### Update Documentation

Update relevant files:
- `docs/README.md` - Doc index
- `docs/EXTENDED_README.md` - Comprehensive guide
- `docs/CHANGELOG.md` - Features
- `docs/ARCHITECTURE.md` - How it works

### Update Examples

Add to `examples/`:
- New example config
- Valid samples
- Invalid samples

---

## Dependencies

### Current Dependencies
- **pyyaml** - Parse YAML configs
- **jsonschema** - Validate JSON schemas

### Add Dependencies
```bash
# Add to requirements.txt
pip install new-package
pip freeze > requirements.txt
```

### Keep Minimal
- Avoid heavy frameworks
- Keep startup time fast
- Favor stdlib when possible

---

## Debugging

### Enable Verbose Output

```bash
# Run with stderr output
python cli.py run --config release-gate.yaml 2>&1
```

### Add Debug Prints

```python
# In cli.py
if debug:
    print(f"DEBUG: config = {config}", file=sys.stderr)
```

### Test Specific Feature

```bash
# Create focused test
python -c "from cli import _check_input_contract; ..."
```

---

## Git Workflow

### Branches

```bash
# Create feature branch
git checkout -b feature/my-feature
git checkout -b fix/my-bug

# Make changes
git add .
git commit -m "Description of change"

# Push to GitHub
git push origin feature/my-feature

# Create Pull Request on GitHub
```

### Commit Messages

```
Good:
- "feat: Add ACTION_BUDGET check"
- "fix: WARN not propagating correctly"
- "docs: Improve ARCHITECTURE guide"
- "test: Add WARN test scenarios"

Avoid:
- "fixed stuff"
- "updated code"
- "wip"
```

---

## Performance Tips

### Optimize Sample Loading
```python
# Instead of reading all at once
with open(file) as f:
    lines = f.readlines()  # Fast

# Sample validation
for sample in samples:
    validator.iter_errors(sample)  # Efficient
```

### Minimize Dependencies
- No external APIs
- No database calls
- Local file processing only
- Keep < 200ms total

---

## Releasing to PyPI

Pushing a version tag publishes the package. `.github/workflows/publish.yml`
does the rest, through PyPI Trusted Publishing (OIDC), so no API token is
stored anywhere.

**Once.**

1. On PyPI, go to the `release-gate` project, then *Publishing*. Add a GitHub
   publisher with owner `VamsiSudhakaran1`, repository `release-gate`,
   workflow `publish.yml` and environment `pypi`.
2. On GitHub, go to *Settings*, then *Environments*, and create `pypi`.
   Requiring a reviewer there puts a person between the tag and the upload.

**Each release, from an up-to-date `main`.**

```bash
python scripts/bump_version.py 0.12.0   # every version pin; re-embeds the site; checks sync
# then move CHANGELOG's [Unreleased] entries under "## [0.12.0] — YYYY-MM-DD"
pytest tests/ -q
git commit -am "Release 0.12.0"
git push origin main
git tag v0.12.0 && git push origin v0.12.0
```

The tag runs three jobs:

1. **guard.** The tag must equal the package version and every version pin
   must agree. Then the full suite and the accuracy benchmark run, the sdist
   and wheel are built, and `twine check` validates them. Any failure stops
   the release.
2. **publish.** Uploads the sdist and wheel to PyPI.
3. **release.** Creates the GitHub Release and installs `release-gate==0.12.0`
   from PyPI as a smoke test. It also moves the floating `v0.12` tag, which
   `uses: …@v0.12` follows.

To republish an existing tag, run the *Publish* workflow by hand with that tag.

---

## Troubleshooting

### ImportError: No module named 'yaml'
```bash
pip install pyyaml
```

### Schema validation fails
- Check JSON Schema syntax
- Validate with jsonschema tool
- Review examples in `examples/`

### Tests fail
```bash
# Check Python version
python --version  # Should be 3.7+

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Run single test
python tests/test_release_gate.py
```

---

## Resources

- [JSON Schema Docs](https://json-schema.org/)
- [PyYAML Docs](https://pyyaml.org/)
- [jsonschema Library](https://python-jsonschema.readthedocs.io/)

---

## Support

For development help:
1. Check `ARCHITECTURE.md`
2. Review `examples/`
3. Look at test cases
4. Check git history for similar changes

---

Happy developing! 🚀
