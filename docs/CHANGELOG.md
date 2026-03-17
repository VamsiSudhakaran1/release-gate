# Changelog

All notable changes to release-gate will be documented in this file.

## [0.2.0] - 2026-03-17

### ✨ Features

- **IDENTITY_BOUNDARY Check**: New check for access control and rate limiting
  - Validates authentication is required or explicitly allowed
  - Validates rate limits are configured per user/client
  - Validates data isolation boundaries are defined
  - Reports detailed evidence on auth enforcement
  
- **ACTION_BUDGET Check**: New check for resource and cost controls
  - Validates max tokens per request is defined
  - Validates max retries per request is defined
  - Validates max daily/monthly cost is defined
  - Validates max concurrent requests is defined
  - Reports detailed evidence on all budget constraints

- **Phase 2 Example Configs**: Real-world configuration examples
  - `example-phase2-video.yaml`: Video generation API example
  - `example-phase2-audio.yaml`: Audio processing example
  - `example-phase2-llm.yaml`: LLM assistant example

- **Phase 2 Documentation**: Comprehensive release notes
  - `PHASE_2_RELEASE_NOTES.md`: Complete guide to new checks
  - Configuration examples for different use cases
  - Upgrade path from v0.1 to v0.2

### 📋 What v0.2.0 Validates

✅ Request schema is syntactically valid JSON Schema (Draft 7)
✅ All valid test samples pass the defined schema
✅ All invalid test samples fail the defined schema
✅ Kill switch mechanism is declared
✅ Fallback behavior is specified
✅ Team ownership and on-call contact assigned
✅ Incident response runbook URL provided
✅ **Authentication is required or explicitly allowed**
✅ **Rate limits are configured**
✅ **Data isolation boundaries are defined**
✅ **Max tokens per request is limited**
✅ **Max retries per request is limited**
✅ **Max daily/monthly cost is limited**
✅ **Max concurrent requests is limited**

### 🔄 Breaking Changes

None. v0.1 configs continue to work. New checks are optional.

### 📊 Comparison: v0.1 vs v0.2

| Feature | v0.1 | v0.2 |
|---------|------|------|
| INPUT_CONTRACT | ✓ | ✓ |
| FALLBACK_DECLARED | ✓ | ✓ |
| IDENTITY_BOUNDARY | ✗ | ✓ |
| ACTION_BUDGET | ✗ | ✓ |

---

## [0.1.0] - 2026-03-16

### ✨ Features

- **INPUT_CONTRACT Check**: Validates request schema and test samples
  - Checks JSON Schema syntax is valid
  - Tests all valid samples pass the schema
  - Tests all invalid samples fail the schema
  - Reports detailed evidence and suggestions

- **FALLBACK_DECLARED Check**: Ensures operational safeguards are documented
  - Validates kill switch is declared (type + name)
  - Validates fallback mode is defined
  - Validates team ownership is assigned
  - Validates incident runbook URL is provided

- **CLI Tool**: Easy-to-use command-line interface
  - `init` command: Initialize new projects with templates
  - `run` command: Execute governance checks
  - Multiple output formats (text, JSON)
  - Custom output file path with `--output` flag
  - Environment specification with `--env` flag

- **CI/CD Integration**: Ready for deployment pipelines
  - Exit codes: 0 (PASS), 10 (WARN), 1 (FAIL)
  - JSON output for programmatic processing
  - Sample JSON report with evidence and suggestions

- **Local Execution**: Privacy-first design
  - All processing happens locally
  - No external API calls
  - No data transmission
  - Safe for confidential configurations

### 📋 What v0.1.0 Validates

✅ Request schema is syntactically valid JSON Schema (Draft 7)
✅ All valid test samples pass the defined schema
✅ All invalid test samples fail the defined schema
✅ Kill switch mechanism is declared
✅ Fallback behavior is specified
✅ Team ownership and on-call contact assigned
✅ Incident response runbook URL provided

### ❌ What v0.1.0 Does NOT Do

This is intentional - these are planned for future versions:

❌ Runtime testing (agent execution simulation) → v0.2
❌ Sample output validation (golden regression) → v0.2
❌ Action/resource budget verification → v0.2
❌ Performance/latency validation → v0.2
❌ Formal verification (neuro-symbolic proofs) → v0.3
❌ Runtime monitoring and anomaly detection → v0.4+

### 📚 Documentation

- Complete README with examples
- Extended README (8,000+ words) with comprehensive guide
- Quick-start guide (QUICKSTART.md)
- Installation instructions
- Configuration reference
- CI/CD integration examples (GitHub Actions, GitLab CI, Jenkins, Kubernetes)
- Contributing guidelines
- Code of conduct

### 🎯 Known Limitations

1. **Configuration Validation Only**
   - Checks if governance fields are declared
   - Does NOT verify safeguards actually work
   - Does NOT test agent behavior at runtime

2. **Semantic Mismatch Detection**
   - Cannot detect if input data matches its declared type
   - Example: Brain MRI schema with actual leg X-ray data
   - Requires v0.2+ runtime testing

3. **Fraudulent Documentation**
   - Cannot verify if documented safeguards are truthful
   - Cannot confirm implementation matches documentation
   - Requires v0.3+ formal verification

4. **No Behavior Verification**
   - Configuration can be filled out but not actually used
   - No guarantee that kill switch actually disables the agent
   - No proof that fallback mode actually executes

### 🔄 Exit Codes

| Code | Status | Meaning | CI/CD Action |
|------|--------|---------|--------------|
| 0 | PASS | All checks passed | Deploy automatically |
| 10 | WARN | Some warnings (invalid samples accepted) | Manual review recommended |
| 1 | FAIL | Critical failures | Block deployment |

### 📦 Dependencies

- `pyyaml>=6.0` - YAML configuration parsing
- `jsonschema>=4.0` - JSON Schema validation

Minimal dependencies by design. Only standard validation libraries, no heavy frameworks.

### 🚀 Getting Started

```bash
# Install
pip install -r requirements.txt

# Initialize project
python cli.py init --project my-system

# Run gate
python cli.py run --config release-gate.yaml --format text
```

### 🔗 Links

- **GitHub**: https://github.com/VamsiSudhakaran1/release_gate
- **Issues**: https://github.com/VamsiSudhakaran1/release_gate/issues
- **Discussions**: https://github.com/VamsiSudhakaran1/release_gate/discussions

### 🙏 Inspiration

- "Agents of Chaos: Red-Teaming of Autonomous AI Agents" (Shapira et al., 2026)
- DARPA Assured Neuro-Symbolic Research (ANSR)
- Production lessons learned from deploying autonomous agents

---

## Future Versions (Roadmap)

### v0.2.0 - Runtime Verification (Planned)

- GOLDEN_REGRESSION check: Test actual agent behavior
- ACTION_BUDGET_DECLARED check: Verify resource constraints
- LATENCY_GATE check: Performance verification
- Richer JSON reports with per-sample evidence

### v0.3.0 - Formal Verification (Planned)

- Neuro-symbolic verification layer
- Formal proof generation
- CSL-Core guardrails integration
- Valori-style state replay

### v0.4.0+ - Runtime Monitoring (Future)

- Continuous governance verification
- Anomaly detection
- Self-healing mechanisms
- Dashboard and web UI

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License - See [LICENSE](LICENSE) for details.
