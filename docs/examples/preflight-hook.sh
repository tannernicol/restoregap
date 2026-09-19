#!/usr/bin/env bash
# Claude Code PreToolUse hook: read the Bash command Claude Code sends on
# stdin, match the FIRST matching shape below, write a v2 intent YAML, and
# let `restoregap preflight` decide. Flags anywhere are allowed.
#   rm <p>…                          -> delete_file (non-flag args)
#   shred <p>…                       -> delete_file
#   mv <src>… <dst>                  -> move_file   (all but last)
#   truncate … <p>                   -> modify_file
#   leading `> <p>` or `: > <p>`     -> modify_file
#   dd … of=<p>                      -> modify_file
#   git push --force | -f | --force-with-lease, git branch -D …,
#   terraform destroy, dropdb …      -> run_command
# This is the example net for Claude Code; your agent's own
# permissions.deny / sandbox is the general net — Restore Gap decides
# whether a *guarded* change is allowed.
set -euo pipefail

# Read the event once: a second jq reading stdin would see EOF and silently
# allow the call. A malformed event cannot establish what was evaluated.
event="$(cat)"
tool="$(jq -er '.tool_name | select(type == "string" and length > 0)' <<<"$event")" || exit 2
cmd="$(jq -r '.tool_input.command // empty' <<<"$event")" || exit 2
coverage=()
require_coverage=0
if [[ "${RESTOREGAP_REQUIRE_COVERAGE:-0}" == 1 ]]; then
  coverage=(--require-coverage)
  require_coverage=1
fi
action='' desc='' paths=() targets=()

unrecognized_operation() {
  if (( require_coverage )); then
    printf 'not evaluated: unrecognized operation\n' >&2
    exit 2
  fi
  exit 0
}

# File-editing tools, not just Bash. A hook registered only for `matcher:
# "Bash"` lets an agent edit a DECLARED lifeline with its file-writing tools
# and never reach the gate — the shell shapes below are only one of the ways
# an agent changes a file. Bash commands still fall through to the parser.
case "$tool" in
  Edit|Write|MultiEdit|NotebookEdit)
    edit_path="$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' <<<"$event")" || exit 2
    [[ -n "$edit_path" ]] || exit 2
    edit_path="$(realpath -m -- "$edit_path")"
    # Let the evaluator match policy globs. A literal-text prefilter misses
    # paths covered by wildcards and disagrees with normal context discovery.
    intent_edit="$(mktemp)"
    trap 'rm -f "$intent_edit"' EXIT
    {
      printf 'version: 2\naction: modify_file\npaths:\n'
      printf "  - '%s'\n" "${edit_path//\'/\'\'}"
      printf 'actor: agent/claude\ndescription: %s\n' "'declared lifeline edited via $tool'"
    } >"$intent_edit"
    restoregap preflight --intent "$intent_edit" --context-window coding-agent "${coverage[@]}" >&2 || exit 2
    exit 0
    ;;
esac

if [[ "$tool" != Bash && $require_coverage -eq 1 ]]; then
  unrecognized_operation
fi
[[ -n "$cmd" ]] || unrecognized_operation

# nonflags prints cmd's non-flag words after the verb.
nonflags() {
  local -a ws
  read -r -a ws <<<"$cmd"
  local a
  for a in "${ws[@]:1}"; do [[ "$a" == -* ]] || printf '%s\n' "$a"; done
}

# runshape gates a whole-command shape; paths anchor to the repo root, or
# cwd outside a repo.
runshape() {
  action=run_command desc="$1 intercepted by PreToolUse hook"
  paths=("$(git rev-parse --show-toplevel 2>/dev/null || pwd)")
}

re_redirect='^(:[[:space:]]*)?>[[:space:]]*([^[:space:]]+)'
read -r -a w <<<"$cmd"
if [[ "$cmd" =~ $re_redirect ]]; then
  action=modify_file desc='redirect truncation' paths=("${BASH_REMATCH[2]}")
elif [[ "${w[0]}" == rm || "${w[0]}" == shred ]]; then
  action=delete_file desc="${w[0]} intercepted by PreToolUse hook"
  mapfile -t paths < <(nonflags)
elif [[ "${w[0]}" == mv ]]; then
  mapfile -t all < <(nonflags)
  if (( ${#all[@]} > 1 )); then
    action=move_file desc='mv intercepted by PreToolUse hook'
    paths=("${all[@]:0:${#all[@]}-1}")
    targets=("${all[${#all[@]}-1]}")
  fi
elif [[ "${w[0]}" == truncate ]]; then
  action=modify_file desc='truncate intercepted by PreToolUse hook'
  mapfile -t paths < <(nonflags)
elif [[ "${w[0]}" == dd ]]; then
  for a in "${w[@]:1}"; do
    if [[ "$a" == of=* ]]; then
      action=modify_file desc='dd of= intercepted by PreToolUse hook' paths=("${a#of=}")
    fi
  done
elif [[ "${w[0]}" == git ]]; then
  rest=" ${w[*]:1} "
  if [[ "${w[1]}" == push && ( "$rest" == *--force* || "$rest" == *" -f "* ) ]] ||
     [[ "${w[1]}" == branch && "$rest" == *" -D "* ]]; then
    runshape git
  fi
elif [[ "${w[0]}" == terraform && "${w[1]}" == destroy ]]; then
  runshape 'terraform destroy'
elif [[ "${w[0]}" == dropdb ]]; then
  runshape dropdb
fi

[[ -n "$action" && ${#paths[@]} -gt 0 ]] || unrecognized_operation
intent="$(mktemp)"
trap 'rm -f "$intent"' EXIT
scalar() { printf "'%s'" "${1//\'/\'\'}"; } # single-quoted YAML scalar
{
  printf 'version: 2\naction: %s\npaths:\n' "$action"
  for p in "${paths[@]}"; do printf '  - %s\n' "$(scalar "$(realpath -m -- "$p")")"; done
  if (( ${#targets[@]} > 0 )); then
    printf 'target_paths:\n'
    for p in "${targets[@]}"; do printf '  - %s\n' "$(scalar "$(realpath -m -- "$p")")"; done
  fi
  printf 'command: %s\nactor: agent/claude\ndescription: %s\n' "$(scalar "$cmd")" "$(scalar "$desc")"
} >"$intent"
restoregap preflight --intent "$intent" --context-window coding-agent "${coverage[@]}" >&2 || exit 2
