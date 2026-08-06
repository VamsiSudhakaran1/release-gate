# release-gate × GitHub Actions

**The gate, where the decision actually gets made.**

The other integrations turn platform evidence into a verdict. This one puts that
verdict in the one place it can stop something: the merge button.

---

## Install (1 minute)

```yaml
# .github/workflows/release-gate.yml
name: release-gate

on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # required for `command: pr`

      - uses: VamsiSudhakaran1/release-gate@v0.10.1
        with:
          command: pr
          base: origin/main
          pr-comment: true
```

That's the whole install. `command: pr` gates on **what this diff introduced** —
net-new agent risk only. Inherited debt is shown but never gated, because a gate
that blocks you for someone else's 2023 commit gets turned off on day two.

## Adding platform evidence

Any evidence from the other integrations drops into the same action:

```yaml
      - uses: VamsiSudhakaran1/release-gate@v0.10.1
        with:
          command: score
          config: governance.yaml
          traces: langfuse-traces.json          # or OTel / Arize — auto-detected
          eval-results: promptfoo-results.json  # already graded; never re-graded
          html-report: release-gate-report.html
          sarif-output: release-gate.sarif
```

`traces` accepts release-gate's native format **or** a raw Langfuse /
OpenTelemetry / Arize-Phoenix export. The platform is detected and converted in
place — there is no separate conversion step to wire up.

## Available inputs

| Input | What it does |
|---|---|
| `command` | `pr` (change gate), `audit`, `score`, `evidence-pack`, `impact`, `run`, `loop-sim` |
| `config` | Path to `governance.yaml` (default) |
| `base` | Base ref for `command: pr` — needs `fetch-depth: 0` |
| `traces` | Native trace file **or** a raw Langfuse / OTel / Arize export |
| `eval-results` | Eval results that already ran (e.g. promptfoo). Mutually exclusive with `evals` |
| `evals` | An `evals.yaml` for release-gate to *run* |
| `agent` | Run evals live: `py:module:fn`, `cmd:./script`, or an HTTPS URL |
| `sarif-output` | Write SARIF 2.1.0 and upload to GitHub Code Scanning |
| `pr-comment` | Post/update a sticky summary comment on the PR |
| `html-report` | Write a self-contained HTML evidence file |
| `output-evidence` | Write the JSON readiness report |
| `fail-on-warn` | Treat HOLD as a failure (default: `false`) |

Outputs: `decision`, `score`, `daily-cost`, `runaway-cost`.

## Exit codes are the whole contract

| Code | Decision | What CI should do |
|---|---|---|
| `0` | PROMOTE | Merge |
| `10` | HOLD | Needs a human; not a hard stop |
| `1` | BLOCK | Stop |

The three-state design is deliberate. A two-state gate forces every judgement
call into "block," and a gate that blocks on ambiguity is a gate that gets
bypassed. HOLD is the pressure valve that keeps BLOCK meaningful — by default it
does not fail the job. Set `fail-on-warn: true` in regulated environments where
"needs a human" should stop the line.

## The full pipeline

What the release/governance layer looks like when it's wired end to end:

```yaml
name: release-gate

on: [pull_request]

permissions:
  contents: read
  pull-requests: write
  security-events: write        # for SARIF upload

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      - uses: actions/setup-node@v4
        with: { node-version: "20" }

      # 1. Evaluation layer — grade the outputs.
      - name: Run evals
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          npm install -g promptfoo
          promptfoo eval -o promptfoo-results.json || true

      # 2. Observability layer — what the running version actually did.
      - name: Pull traces
        env:
          LANGFUSE_HOST: ${{ secrets.LANGFUSE_HOST }}
          LANGFUSE_PUBLIC_KEY: ${{ secrets.LANGFUSE_PUBLIC_KEY }}
          LANGFUSE_SECRET_KEY: ${{ secrets.LANGFUSE_SECRET_KEY }}
        run: |
          curl --fail --silent --show-error \
            -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" \
            "$LANGFUSE_HOST/api/public/traces?limit=100" \
            -o langfuse-traces.json

      # 3. Release & governance layer — one verdict over all of it.
      - uses: VamsiSudhakaran1/release-gate@v0.10.1
        with:
          command: score
          config: governance.yaml
          traces: langfuse-traces.json
          eval-results: promptfoo-results.json
          sarif-output: release-gate.sarif
          html-report: release-gate-report.html
          pr-comment: true
```

Three layers, three tools, each doing the job it's best at. release-gate does not
compete with steps 1 and 2 — it is the thing that consumes them and answers the
question neither one asks.

## Other CI systems

The same evidence and exit codes work anywhere. Ready-to-copy templates:
[GitLab CI](../../ci-templates/gitlab-ci.yml) ·
[CircleCI](../../ci-templates/circleci.yml) ·
[Azure Pipelines](../../ci-templates/azure-pipelines.yml) ·
[Jenkins](../../ci-templates/jenkins/Jenkinsfile)

## Pre-commit

For the fastest possible feedback, before CI is even involved:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/VamsiSudhakaran1/release-gate
    rev: v0.10.1
    hooks:
      - id: release-gate
```
