#!/usr/bin/env bash
# preflight-hook.test.sh — end-to-end check of the example PreToolUse hook
# (docs/examples/preflight-hook.sh): a fresh demo/setup.sh fixture, the hook's
# shape table, and the gate's verdict before and after a real drill. Prints
# one line per case and a final N/N; exits non-zero on any mismatch.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
fixture="$(mktemp -d /tmp/rg-hook-test.XXXXXX)"
trap 'rm -rf "$fixture"' EXIT

bash "$repo/demo/setup.sh" "$fixture" >/dev/null
go build -o "$fixture/bin/restoregap" "$repo/cmd/restoregap"
echo "just a readme, not guarded" > "$fixture/README.md"
export PATH="$fixture/bin:$PATH"
export RESTOREGAP_LEDGER="$fixture/ledger.jsonl"

# The guard + drill context the hook's blocks depend on (same command the
# README demo uses; discovery picks up ./restoregap.local.yml from cwd).
(cd "$fixture" && restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml)

pass=0 fail=0
# check <want-exit> <command...>: feed one tool-call command to the hook and
# compare its exit code.
check() {
  want=$1; shift
  json="$(jq -cn --arg c "$*" '{tool_name:"Bash",tool_input:{command:$c}}')"
  got=0
  (cd "$fixture" && printf '%s' "$json" | bash "$repo/docs/examples/preflight-hook.sh") >/dev/null 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then
    pass=$((pass + 1))
    printf 'ok    exit=%d  %s\n' "$got" "$*"
  else
    fail=$((fail + 1))
    printf 'FAIL  exit=%d (want %d)  %s\n' "$got" "$want" "$*"
  fi
}

# Before any drill: every destructive shape on the guarded path blocks.
check 2 rm proj/app.db
check 2 rm -rf proj
check 2 mv proj/app.db /tmp/rg-hook-test-dst
check 2 truncate -s0 proj/app.db
check 2 dd if=/dev/zero of=proj/app.db bs=1 count=1
check 2 shred proj/app.db
# Unguarded path, unmatched shape, and an unmatched-command shape all pass.
check 0 rm README.md
check 0 ls -la
check 0 git push --force origin main

# A real drill records the proof; the same deletion is allowed now.
(cd "$fixture" && restoregap drill) >/dev/null 2>&1
check 0 rm proj/app.db

total=$((pass + fail))
echo "$pass/$total"
[ "$fail" -eq 0 ]
