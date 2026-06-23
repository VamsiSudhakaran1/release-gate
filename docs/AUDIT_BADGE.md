# Self-serve audit: badge + CI job summary

`release-gate audit` is designed to be run by a maintainer on **their own**
repo — not done to them. It scans for AI agent frameworks, checks which
deployment safeguards are declared, and produces a 0–100 readiness score with
a `PROMOTE` / `HOLD` / `BLOCK` decision.

There are three ways to surface the result where people already look.

## 1. README badge

Show your readiness score on the repo front page:

```bash
release-gate audit . --badge
```

This prints a copy-paste Markdown snippet:

```markdown
[![AI deployment readiness](https://img.shields.io/badge/release--gate-85%2F100%20HOLD-yellow)](https://github.com/VamsiSudhakaran1/release-gate)
```

The badge color tracks the decision — green (PROMOTE), yellow (HOLD),
red (BLOCK), grey (no agent detected).

## 2. CI job summary (GitHub Actions)

Add the audit to CI. The Markdown report is written straight to the
GitHub Actions **job summary**, so every run shows the score and the
missing-safeguard table without opening logs.

```yaml
name: AI deployment readiness
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: VamsiSudhakaran1/release-gate@v0.7.3
        with:
          command: audit
          path: .
          # Block the build on BLOCK by default. HOLD passes unless you
          # set fail-on-warn: true.
          fail-on-warn: false
```

Run it locally the same way CI does:

```bash
release-gate audit . --markdown
```

## 3. Generate a starter config

When the audit flags missing safeguards, scaffold a ready-to-commit
`governance.yaml` pre-filled from what the scan already knows (project name,
detected model, frameworks). Values only your team knows are left as honest
`# TODO` markers:

```bash
release-gate audit . --emit-config -o governance.yaml
```

Then fill in the TODOs and gate every deploy:

```bash
release-gate score governance.yaml
```

## Exit codes

| Decision | Exit code | Meaning |
| --- | :---: | --- |
| PROMOTE | `0` | Ready to deploy |
| HOLD | `10` | Deploy with caution (passes CI unless `fail-on-warn: true`) |
| BLOCK | `1` | Not ready — missing critical safeguards |
| no agent detected | `0` | Repo doesn't use an AI agent framework — neutral, never fails CI |
