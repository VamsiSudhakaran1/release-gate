#!/usr/bin/env bash
# Run every example and print what each one decides.
#
# These are inputs, not fixtures: each is the shape a real system emits, and the
# verdict below is whatever release-gate reaches on it — nothing here is pinned
# to an expected answer. Run it against a fresh `pip install release-gate` and
# you should see the same table.
set -uo pipefail
cd "$(dirname "$0")"

RG="${RG:-release-gate}"
printf '%-34s %-34s %-9s %s\n' "INPUT" "METHODOLOGY" "VERDICT" "EXIT"
printf '%.0s─' {1..92}; printf '\n'

run() {
  local file="$1" meth="${2:-}"
  local args=("$file"); [ -n "$meth" ] && args+=(--methodology "$meth")
  local out; out="$("$RG" assure "${args[@]}" 2>&1)"; local rc=$?
  local verdict; verdict="$(printf '%s' "$out" | grep -oE '(PROMOTE|HOLD|BLOCK)' | head -1)"
  printf '%-34s %-34s %-9s %s\n' "$file" "${meth:-(none)}" "${verdict:-?}" "$rc"
}

run 01-coding-agent-otel.json
run 01-coding-agent-otel.json      general-autonomous-action@1.0.0
run 02-release-promoted.jsonl      general-autonomous-action@1.0.0
run 03-support-eval-promptfoo.json
run 04-production-db-change.jsonl  production-database-change@1.0.0
run 05-research-swarm.jsonl        research-mathematics@1.0.0
run 05-research-swarm.jsonl        research-mathematics@1.1.0

printf '\n exit codes: 0 PROMOTE · 10 HOLD · 1 BLOCK\n'
