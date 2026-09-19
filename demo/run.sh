#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

# Run the complete stranger demo against an isolated fixture and ledger.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${RESTOREGAP_BIN:-restoregap}"
out="${1:-}"
owned=0
if [[ -z "$out" ]]; then
  out="$(mktemp -d "${TMPDIR:-/tmp}/restoregap-demo.XXXXXX")"
  owned=1
fi
cleanup() { if [[ "$owned" = 1 ]]; then rm -rf -- "$out"; fi; }
trap cleanup EXIT

command -v "$bin" >/dev/null || { echo "demo/run.sh: restoregap not found; set RESTOREGAP_BIN or install it first" >&2; exit 1; }
case "$bin" in */*) bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")" ;; esac
bash "$repo_dir/demo/setup.sh" "$out"
out="$(cd "$out" && pwd)"
ledger="$out/ledger.jsonl"
context="$out/restoregap.local.yml"
intent="$out/rm-app-db.yml"
export RESTOREGAP_LEDGER="$ledger"
export RESTOREGAP_CONTEXT="$context"
export XDG_STATE_HOME="$out/xdg-state"
export XDG_CONFIG_HOME="$out/xdg-config"
unset RESTOREGAP_POLICY_DIRS RESTOREGAP_OWNER
expired_at="$(($(date -u +%Y) + 1))-01-01T00:00:00Z"

run_expect() {
  local want="$1" label="$2" got
  shift 2
  echo "\$ $label"
  set +e
  (cd "$out" && "$@")
  got=$?
  set -e
  [[ "$got" = "$want" ]] || { echo "demo/run.sh: expected exit $want, got $got: $label" >&2; exit 1; }
}

run_expect 1 "restoregap check proj backup/proj" "$bin" check proj backup/proj
(cd "$out" && "$bin" drill propose proj/app.db --source backup/app.db > "$context")
run_expect 1 "restoregap preflight --intent rm-app-db.yml (before drill)" "$bin" preflight --intent "$intent"
run_expect 0 "restoregap drill --expires-in 1h" "$bin" drill --expires-in 1h
run_expect 0 "restoregap preflight --intent rm-app-db.yml (fresh proof)" "$bin" preflight --intent "$intent"
run_expect 1 "restoregap preflight --intent rm-app-db.yml (expired proof)" "$bin" preflight --intent "$intent" --as-of "$expired_at"
run_expect 0 "restoregap ledger verify ledger.jsonl" "$bin" ledger verify "$ledger"
echo "demo/run.sh: PASS (isolated fixture: $out)"
