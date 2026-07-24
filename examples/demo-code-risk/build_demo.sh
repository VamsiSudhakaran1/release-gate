#!/usr/bin/env bash
# Reproduce the release-gate PR-gate demo end to end.
#
#   base (main): examples/demo-code-risk/fixed/agent.py    — safe, allowlisted
#   PR branch:   examples/demo-code-risk/vulnerable/agent.py — adds eval(model_output)
#
# Builds a throwaway git repo, commits the safe version as `main`, opens a
# branch that introduces the eval (the "PR"), and runs `release-gate pr` to show
# the net-new verdict. Everything below is real, captured output — no mockups.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d -t rg-pr-demo-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
git init -q
git config user.email demo@release-gate.com
git config user.name "release-gate demo"

# --- main: the safe baseline ------------------------------------------------
cp "$HERE/fixed/agent.py" agent.py
git add agent.py
git commit -q -m "analysis-agent: allowlisted aggregations"
git branch -M main

# --- PR branch: introduce a natural-language query that evals model output --
git checkout -q -b feat/nl-query
cp "$HERE/vulnerable/agent.py" agent.py
git add agent.py
git commit -q -m "feat: natural-language queries via model-generated pandas"

echo "############### release-gate pr --base main ###############"
release-gate pr --base main || true
echo
echo "############### release-gate pr --base main --comment ###############"
release-gate pr --base main --comment || true
