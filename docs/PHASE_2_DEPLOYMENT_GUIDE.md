# Phase 2 Deployment Guide

## 🚀 Deploying Phase 2

This guide walks you through deploying release-gate v0.2.0 with the new IDENTITY_BOUNDARY and ACTION_BUDGET checks.

---

## Step 1: Pull Latest Code

```bash
cd C:\Vamsi\release-gate
git fetch origin main
git pull origin main
```

**What's new:**
- `cli.py` - Updated with v0.2 checks
- `test_release_gate.py` - Updated with Phase 2 tests
- `PHASE_2_RELEASE_NOTES.md` - Complete documentation
- `example-phase2-*.yaml` - Real-world examples
- `CHANGELOG.md` - Updated version history

---

## Step 2: Run Phase 2 Test Suite

```bash
python test_release_gate.py
```

**Expected output:**
```
========================================================================
Running release-gate Test Suite
========================================================================

✓ Initialization - PASSED
✓ PASS case - PASSED
✓ FAIL case - PASSED
✓ JSON output - PASSED
✓ Custom output file - PASSED
✓ Sample validation - PASSED
✓ WARN case (invalid samples accepted) - PASSED
✓ WARN exit code (10) - PASSED
✓ WARN in summary - PASSED
✓ FAIL precedence over WARN - PASSED
✓ Phase 2: IDENTITY_BOUNDARY PASS - PASSED
✓ Phase 2: IDENTITY_BOUNDARY FAIL - PASSED
✓ Phase 2: ACTION_BUDGET PASS - PASSED
✓ Phase 2: ACTION_BUDGET FAIL - PASSED

========================================================================
Results: 14 passed, 0 failed
========================================================================

[OK] All tests passed! release-gate is working correctly.
```

---

## Step 3: Test with Example Configs

### Test Video Generation Example

```bash
python cli.py run --config example-phase2-video.yaml --format text
```

Expected output:
```
========================================================================
release-gate Governance Report
========================================================================

Project: video-generation-api
Environment: production
Timestamp: 2026-03-17T12:34:56Z

Check Results:
  input_contract: ✓ PASS
  fallback_declared: ✓ PASS
  identity_boundary: ✓ PASS
  action_budget: ✓ PASS

Overall Decision: ✓ PASS (Exit Code 0)
========================================================================
```

### Test Audio Processing Example

```bash
python cli.py run --config example-phase2-audio.yaml --format text
```

### Test LLM Assistant Example

```bash
python cli.py run --config example-phase2-llm.yaml --format text
```

---

## Step 4: Initialize New Project with Phase 2

```bash
python cli.py init --project my-new-agent
```

This creates:
- `release-gate.yaml` - Includes Phase 2 checks
- `valid_requests.jsonl` - Test samples
- `invalid_requests.jsonl` - Test samples

**Note:** The generated config now includes:
```yaml
identity_boundary:
  enabled: true
  authentication: required
  rate_limit: 100
  data_isolation:
    - user_owned_data_only
    - no_cross_user_access

action_budget:
  enabled: true
  max_tokens_per_request: 5000
  max_retries: 3
  max_daily_cost: 1000
  max_concurrent_requests: 10
```

---

## Step 5: Commit and Deploy

```bash
# Add all updated files
git add cli.py test_release_gate.py
git add PHASE_2_RELEASE_NOTES.md CHANGELOG.md
git add example-phase2-*.yaml

# Commit
git commit -m "Phase 2: Add IDENTITY_BOUNDARY and ACTION_BUDGET checks

- New IDENTITY_BOUNDARY check for auth + rate limits + data isolation
- New ACTION_BUDGET check for token/retry/cost/concurrency limits
- 4 new unit tests for Phase 2 checks
- Real-world example configs for Video, Audio, and LLM agents
- Comprehensive Phase 2 release notes and documentation
- Updated README and CHANGELOG

All tests passing. Ready for production."

# Push to GitHub
git push origin main
```

---

## Step 6: Verify Deployment

Check GitHub Actions:
```bash
# Open in browser
https://github.com/VamsiSudhakaran1/release-gate/actions
```

Verify:
- ✓ Tests pass
- ✓ README updated
- ✓ CHANGELOG updated
- ✓ Example configs available

---

## Step 7: Update Package Version (Optional)

If releasing to PyPI:

```bash
# Update version in setup.py or pyproject.toml
version = "0.2.0"

# Tag the release
git tag -a v0.2.0 -m "Release v0.2.0: Phase 2 with IDENTITY_BOUNDARY and ACTION_BUDGET"
git push origin v0.2.0

# Build and publish
python -m build
twine upload dist/*
```

---

## 🧪 Validation Checklist

Before declaring Phase 2 complete, verify:

- [ ] All 14 tests pass
- [ ] `python cli.py init --project test` works
- [ ] Example configs validate correctly
- [ ] `--format text` output is readable
- [ ] `--format json` output is valid JSON
- [ ] Exit codes work: 0 (PASS), 10 (WARN), 1 (FAIL)
- [ ] README is updated
- [ ] CHANGELOG is updated
- [ ] Website (release-gate.com) is up-to-date
- [ ] GitHub has latest code

---

## 📊 Phase 2 Feature Completeness

| Feature | Status | Test Coverage |
|---------|--------|----------------|
| INPUT_CONTRACT | ✅ | 3 tests |
| FALLBACK_DECLARED | ✅ | 2 tests |
| IDENTITY_BOUNDARY | ✅ | 2 tests |
| ACTION_BUDGET | ✅ | 2 tests |
| CLI (init) | ✅ | 1 test |
| CLI (run) | ✅ | 5 tests |
| Exit codes | ✅ | 3 tests |
| JSON output | ✅ | 1 test |

**Total: 19 tests, 0 failures** ✅

---

## 🎯 What Users Can Now Do with Phase 2

1. **Initialize agents** with full Phase 2 governance
2. **Define access controls** (auth + rate limits + data isolation)
3. **Set resource budgets** (tokens + retries + costs + concurrency)
4. **Validate configs** before deployment
5. **Get governance evidence** for compliance audits
6. **Integrate with CI/CD** for automated gating

---

## 🔄 Migration from v0.1 to v0.2

**For existing v0.1 users:**

1. Pull latest code
2. Optional: Add new checks to config
3. Run: `python cli.py run --config release-gate.yaml`
4. If all 4 checks PASS, you're ready!

**No breaking changes** - v0.1 configs still work.

---

## 📞 Support & Issues

If you encounter issues:

1. Check `PHASE_2_RELEASE_NOTES.md` for detailed docs
2. Review example configs in `example-phase2-*.yaml`
3. Run: `python test_release_gate.py` to verify installation
4. File issue on GitHub: https://github.com/VamsiSudhakaran1/release-gate/issues

---

## 🎉 Phase 2 is Live!

You now have:
- ✅ Contract validation (INPUT_CONTRACT)
- ✅ Operational safety (FALLBACK_DECLARED)
- ✅ Access control (IDENTITY_BOUNDARY)
- ✅ Resource budgets (ACTION_BUDGET)

**Next Phase:** v0.3 will add APPROVAL_REQUIRED and DATA_EGRESS_POLICY checks + Dashboard UI

Welcome to Phase 2! 🚀
