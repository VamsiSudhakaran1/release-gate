#!/usr/bin/env bash
# Reproduce the release-gate PR-gate demo end to end.
#
#   base (main): examples/demo-code-risk/fixed/agent.py      — safe, allowlisted
#   PR branch:   examples/demo-code-risk/vulnerable/agent.py — adds eval(model_output)
#   contrast:    examples/demo-code-risk/lookalike/agent.py  — the same shape with
#                no visible origin, which must NOT be graded HIGH
#
# Builds a throwaway git repo, commits the safe version as `main`, opens a branch
# that introduces the eval (the "PR"), and runs `release-gate pr` to show the
# net-new verdict. Everything printed below is real output — no mockups.
#
#   ./build_demo.sh            # print the demo
#   ./build_demo.sh --check    # print it AND assert every claim the docs make
#                              # (exit 1 on drift — this is what CI runs)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d -t rg-pr-demo-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

if ! command -v release-gate >/dev/null 2>&1; then
  echo "release-gate is not on PATH — run: pip install release-gate" >&2
  exit 127
fi

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

OUT="$WORK/pr-comment.md"
echo "############### release-gate pr --base main ###############"
release-gate pr --base main || true
echo
echo "############### release-gate pr --base main --comment ###############"
release-gate pr --base main --comment 2>&1 | tee "$OUT" || true

# --- the contrast: a dangerous SHAPE with no provable origin ---------------
# Scanned in the SAME service as the agent, so one report shows both tiers:
# the traced flow is a confirmed HIGH; the identical-looking sink whose origin we
# cannot see is a MEDIUM that asks you to confirm it. That gap is the product.
echo
echo "############### both tiers, one scan ###############"
echo "# agent.py  — eval() of a value traced to the model call  -> confirmed HIGH"
echo "# cache.py  — pickle.loads(payload), a bare parameter     -> inferred MEDIUM"
echo
LOOK="$WORK/tiers"
mkdir -p "$LOOK"
cp "$HERE/vulnerable/agent.py" "$LOOK/agent.py"
cp "$HERE/lookalike/agent.py" "$LOOK/cache.py"
TIERS="$WORK/tiers.txt"
release-gate audit "$LOOK" --full 2>&1 | tee "$TIERS" | sed -n '/Code findings/,+12p' || true

if [ "$CHECK" -eq 1 ]; then
  echo
  echo "############### --check: asserting the published claims ###############"
  fail() { echo "DEMO DRIFT: $1" >&2; exit 1; }
  grep -q "BLOCK" "$OUT" || fail "the PR is no longer BLOCKed"
  grep -q "100 → 76" "$OUT" || fail "the score delta quoted in the docs changed"
  grep -q 'high · confirmed): Dangerous execution sink  `agent.py:25`' "$OUT" \
    || fail "the confirmed HIGH at agent.py:25 changed shape"
  grep -q "traced to the model's own output at line 17" "$OUT" \
    || fail "the HIGH no longer cites its traced origin line"
  grep -q "Introduced by this change" "$OUT" \
    || fail "net-new scoping disappeared from the comment"
  # The tier contract, on real files: traced flow is HIGH, bare name is not.
  grep -q "HIGH.*confirmed.*Dangerous execution sink" "$TIERS" \
    || fail "the traced model-output flow is no longer a confirmed HIGH"
  grep -q "MEDIUM.*inferred.*Deserialization of unverified data" "$TIERS" \
    || fail "the bare-parameter sink is no longer an inferred MEDIUM"
  grep -q "origin unknown" "$TIERS" \
    || fail "the inferred finding no longer says its origin is unknown"
  echo "OK — every claim in the demo docs reproduces from this run."
fi
