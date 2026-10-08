# CI Templates for release-gate

Two kinds of template, for five CI systems.

- **`admission/`** is the full release flow: build, tests, external evals and
  security scanners. Their evidence is collected, then
  `release-gate assure --evidence` decides PROMOTE, HOLD or BLOCK, then deploy.
- **The top-level files** run `release-gate audit` on a merge request or push.

## The one rule: HOLD is not BLOCK

Every release-gate gate exits `0` PROMOTE, `10` HOLD or `1` BLOCK. A CI step
that fails on any non-zero code turns HOLD into BLOCK. Every template here
handles `10` on its own, and one variable, `RELEASE_GATE_HOLD_POLICY`, says what
HOLD does:

| Hold policy | PROMOTE | HOLD | BLOCK or error |
|---|---|---|---|
| `normal` (default) | continue / deploy | a person reviews, then deploy | stop |
| `strict` | continue / deploy | stop pending approval | stop |

Any other value is an error before anything runs, so a typo never loosens the
gate.

## Admission pipelines (`admission/`)

| Platform | File | Under `normal`, HOLD goes to a person through |
|---|---|---|
| GitHub Actions | `admission/github-actions.yml` | the Action's `command: assure`, then a job on a protected `release-review` environment |
| GitLab CI | `admission/gitlab-ci.yml` | exit 10 as an allowed failure (amber), then the manual `deploy:reviewed` job |
| Azure Pipelines | `admission/azure-pipelines.yml` | `SucceededWithIssues`, then a `ManualValidation@0` agentless job |
| Jenkins | `admission/Jenkinsfile` | an UNSTABLE build, then an `input` step limited to `RELEASE_GATE_REVIEWERS` |
| CircleCI | `admission/circleci/config.yml` + `release.yml` | a setup workflow continues into a workflow whose `approval` job a person approves (enable dynamic config) |

Each one:

1. collects every tool's output into `release-gate-out/evidence/`;
2. runs `release-gate assure "$RELEASE_GATE_INPUT" --evidence … --admission`;
3. accepts the exit code only when the Admission Report's own `decision` agrees.
   Anything else, an error included, is `ERROR`, and the job stops;
4. writes `release-gate-out/decision.env`, which later jobs read, and keeps
   `release-gate-out/` (the Admission Report as text and JSON, and the sealed
   case) as an artifact on every run, including failed ones;
5. deploys only on PROMOTE, or on HOLD after the review step under `normal`.

Set `RELEASE_GATE_INPUT` to your claims file (`admission/claims.jsonl` is a
starting point) and `RELEASE_GATE_METHODOLOGY` to the methodology that says
what *enough* means for this release. `RELEASE_GATE_RESOLUTION_POLICY`,
`RELEASE_GATE_CONFIG` and `RELEASE_GATE_CANDIDATE` are optional. The candidate
line is commented out in each template: once a candidate is named, every
producer must state what it ran against, or its support holds.

`examples/demo-admission/` is a release decided this way: BLOCK under one
declared policy and HOLD under the other. CI runs it through the GitHub Action
on every push.

## Audit templates (top level)

| File | What it does |
|---|---|
| `gitlab-ci.yml` | `release-gate audit` on merge requests, SARIF to the security widget. HOLD passes with a warning (`allow_failure: exit_codes: [10]`) |
| `circleci.yml` | The audit on `cimg/python:3.11`. Stores the SARIF and the JSON report on every run. HOLD passes under `normal` and fails under `strict` |
| `azure-pipelines.yml` | The audit on pushes to `main`. HOLD finishes the step `SucceededWithIssues` under `normal` and fails it under `strict`. The SARIF is published even when the step fails |
| `jenkins/Jenkinsfile` | The audit as one stage. HOLD marks the build UNSTABLE under `normal` and fails it under `strict`. SARIF and JSON are archived on every build |

The audit's JSON report comes from `release-gate audit . --json > release-gate.json`.
`--json` takes no value: the earlier `--json release-gate.json` wrote no file.

## How the templates are tested

`tests/test_ci_admission.py` takes each template's gate script out of the file
you would copy, and runs it:

- under `sh` and under `bash`;
- against a stub `release-gate` that returns every exit code and report
  combination;
- and once against the real CLI on the demo.

It also evaluates the GitHub `if:` and Azure `condition:` routing over every
decision and job result, and runs the GitLab deploy jobs against every
decision. What the tests show: HOLD under `normal` never deploys without
review, and nothing deploys on BLOCK or error.
