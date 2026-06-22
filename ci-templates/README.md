# CI Templates for release-gate

Drop-in CI configurations for running `release-gate audit` on every pull request or merge event.

## GitLab CI (`gitlab-ci.yml`)

Runs `release-gate audit` on every merge request event. Produces a SARIF report and uploads it
as a GitLab SAST artifact so findings appear in the merge request security widget. Requires
Python 3.11-slim and installs release-gate automatically.

## CircleCI (`circleci.yml`)

Runs the audit on the `cimg/python:3.11` executor. Produces both a SARIF file and a JSON report,
then stores the SARIF as a CircleCI artifact for download. Wire this job into your existing
`workflows` block alongside your test and build jobs.

## Azure DevOps (`azure-pipelines.yml`)

Triggered on pushes to `main`. Installs release-gate via pip, runs the audit, and publishes
the SARIF file as a build artifact using `PublishBuildArtifacts`. The `condition: always()`
ensures the artifact is uploaded even when the audit step exits non-zero.

## Jenkins (`jenkins/Jenkinsfile`)

A declarative pipeline with a single `AI Safeguard Audit` stage. Installs release-gate via pip,
runs the audit with SARIF and JSON output, and archives the SARIF artifact. The `post { always }`
block re-archives the SARIF so it is retained even on a failed build.
