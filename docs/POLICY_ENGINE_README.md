# Policy Engine Documentation

## What is the Policy Engine?

By default, release-gate blocks deployment if **any** check fails. But teams have different risk tolerances and priorities.

The **policy engine** lets you customize what triggers FAIL (blocks deployment) vs WARN (needs approval) for each check.

---

## Quick Example

### Strict Policy (Default)
All checks must pass:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT

checks:
  action_budget:
    max_daily_cost: 100
```

Result:
- ✗ Any check fails → **FAIL** (deployment blocked)
- ✓ All checks pass → **PASS** (deploy immediately)

---

### Soft Policy
Only cost and safety are critical:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - FALLBACK_DECLARED
  warn_on:
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT

checks:
  action_budget:
    max_daily_cost: 100
```

Result:
- ✗ Cost/safety check fails → **FAIL** (deployment blocked)
- ✗ Auth/schema check fails → **WARN** (needs review, doesn't block)
- ✓ All checks pass → **PASS** (deploy immediately)

---

## How Policies Work

### fail_on
List of checks that **block deployment** if they fail.

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - FALLBACK_DECLARED
```

If either of these checks FAIL, the entire decision is FAIL.

### warn_on
List of checks that **warn but don't block** if they fail.

```yaml
policy:
  warn_on:
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT
```

If either of these checks FAIL, the decision is WARN (not FAIL).

---

## Common Policy Patterns

### Pattern 1: Strict (Pre-Production)
Everything must pass:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT
  warn_on: []
```

---

### Pattern 2: Development
Only cost and safety are critical:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - FALLBACK_DECLARED
  warn_on:
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT
```

---

### Pattern 3: Internal Tool
Only cost matters:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
  warn_on:
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT
```

---

### Pattern 4: No Policy (Default)
Everything blocks if it fails:

```yaml
# policy: not specified
# Falls back to: fail on anything
```

---

## Decision Tree

```
Check results: {check_name: status}

1. Any check in fail_on list has FAIL? → FINAL: FAIL
2. Any check in warn_on list has FAIL/WARN? → FINAL: WARN
3. Any check not in fail_on/warn_on has FAIL? → FINAL: FAIL
4. Any check has WARN? → FINAL: WARN
5. Otherwise → FINAL: PASS
```

---

## Example Outputs

### Strict Policy - All Pass
```
CHECK                    STATUS   IMPACT
────────────────────────────────────
ACTION_BUDGET            ✓ PASS   —
FALLBACK_DECLARED        ✓ PASS   —
IDENTITY_BOUNDARY        ✓ PASS   —
INPUT_CONTRACT           ✓ PASS   —

✅ FINAL DECISION: PASS
```

### Soft Policy - Auth Check Fails
```
CHECK                    STATUS   IMPACT
────────────────────────────────────
ACTION_BUDGET            ✓ PASS   —
FALLBACK_DECLARED        ✓ PASS   —
IDENTITY_BOUNDARY        ✗ FAIL   HIGH
INPUT_CONTRACT           ✓ PASS   —

⚠️ FINAL DECISION: WARN
```

### Soft Policy - Budget Exceeds
```
CHECK                    STATUS   IMPACT
────────────────────────────────────
ACTION_BUDGET            ✗ FAIL   CRITICAL
FALLBACK_DECLARED        ✓ PASS   —
IDENTITY_BOUNDARY        ✓ PASS   —
INPUT_CONTRACT           ✓ PASS   —

❌ FINAL DECISION: FAIL
```

---

## When to Use Each Policy

| Scenario | Policy | Reason |
|----------|--------|--------|
| Pre-production | Strict | All checks must pass |
| Development | Soft | Iterate fast, catch critical issues |
| Internal tool | Cost-focused | Only budget matters |
| Compliance requirement | Strict | Audit trail needs everything |
| AI startup (fast iteration) | Soft | Move quickly, watch critical checks |
| Enterprise AI system | Strict | Maximum safety |

---

## Migration Guide

### If you have no policy (old way)
Default behavior: fail if anything fails (equivalent to strict policy)

### To switch to soft policy
Add to governance.yaml:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET
    - FALLBACK_DECLARED
  warn_on:
    - IDENTITY_BOUNDARY
    - INPUT_CONTRACT
```

### To stay strict (no change needed)
Just don't add a policy section. Default is strict.

---

## CLI with Policies

```bash
# Run with strict policy
release-gate run governance-strict.yaml

# Run with soft policy
release-gate run governance-soft.yaml

# Run with custom policy
release-gate run governance-custom.yaml
```

All will respect the policy defined in the YAML file.

---

## Exit Codes with Policies

Policies don't change exit codes:

| Decision | Exit Code |
|----------|-----------|
| PASS | 0 |
| WARN | 10 |
| FAIL | 1 |

Use in CI/CD:
```bash
release-gate run config.yaml
if [ $? -eq 0 ]; then
    # Deploy
elif [ $? -eq 10 ]; then
    # Need approval
else
    # Block deployment
fi
```

---

## Best Practices

1. **Start strict**, relax as you gain confidence
2. **Document your policy** - comment why each check is critical
3. **Audit policy changes** - treat like code review
4. **Use patterns** - don't create custom policies randomly
5. **Test policies** - validate they work as intended

---

## What's Next

The policy engine is Phase 1. Coming soon:

- **Phase 2:** Budget simulation, GitHub PR bot, audit evidence
- **Phase 3:** Policy packs (pre-built strategies), constraint engine

The policy engine is your foundation for all future features.
