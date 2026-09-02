# Agent Gate — a coding agent tries to delete a file

A PreToolUse hook intercepts every `Bash` call your coding agent makes,
before the shell runs it. `restoregap preflight` decides whether that call
is safe, by checking it against a declared, *verified* recovery proof —
not just "a backup exists somewhere."

## The wiring

The OSS `restoregap` binary does not turn a shell command into an intent —
`preflight` only ever consumes an already-built intent YAML or diff, and
the MCP server's `preflight_intent`/`preflight_diff` tools take the same
inputs. **That translation happens in the hook itself**,
`docs/examples/preflight-hook.sh` (bash + jq, 80 lines): it reads the tool
call Claude Code sends on stdin, matches the command against a shape
table, and writes the v2 intent (schema in `internal/intent`) that
`preflight` understands. First matching shape wins, flags allowed, every
path resolved with `realpath -m`:

| Shape | Intent |
|---|---|
| `rm <p>…` | `delete_file` (all non-flag args) |
| `shred <p>…` | `delete_file` |
| `mv <src>… <dst>` | `move_file` (all but the last arg) |
| `truncate … <p>` | `modify_file` |
| leading `> <p>` or `: > <p>` | `modify_file` |
| `dd … of=<p>` | `modify_file` |
| `git push --force` / `-f` / `--force-with-lease` | `run_command` |
| `git branch -D …` | `run_command` |
| `terraform destroy` | `run_command` |
| `dropdb …` | `run_command` |

Anything else exits 0 untouched. This is the example net for Claude Code;
your agent's own permissions.deny / sandbox is the general net — Restore
Gap decides whether a *guarded* change is allowed.
`docs/examples/preflight-hook.test.sh` (`make hook-test`) runs the whole
table against a fresh demo fixture.

Register it in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "docs/examples/preflight-hook.sh" }
      ] }
    ]
  }
}
```

Claude Code sends `{"tool_name":"Bash","tool_input":{"command":"..."}}` on
stdin before every Bash call; exit 2 blocks the call and the hook's stderr
becomes the message the agent sees. This is the same fixture as
`docs/walkthrough.md` — every line below is real output.

## The transcript

```console
$ demo/setup.sh /tmp/rg-agent-demo && cd /tmp/rg-agent-demo
$ export RESTOREGAP_LEDGER=$PWD/ledger.jsonl
$ restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml

# The agent tries: rm proj/app.db
$ echo '{"tool_name":"Bash","tool_input":{"command":"rm proj/app.db"}}' \
    | docs/examples/preflight-hook.sh
context: restoregap.local.yml (discovered)
# BLOCK
Restore Gap blocked this change. Supply proof, change the plan, or record an owner override.
- Refresh or supply proof "app-db-recovery", or record an owner override before proceeding.
…                                                     # verdict table + detail trimmed here
$ echo $?      # 2 — Claude Code blocks the tool call, agent sees this on stderr

# Prove the recovery actually works — a real reconstruction in a sandbox, not "a copy exists."
$ restoregap drill
context: restoregap.local.yml (discovered)
✓ app-db-recovery — data-valid (L3) in 0s: integrity ok; users=95 (>= 90% of live 100 = 90)

# Same attempt, same hook, now with a fresh proof on file.
$ echo '{"tool_name":"Bash","tool_input":{"command":"rm proj/app.db"}}' \
    | docs/examples/preflight-hook.sh
context: restoregap.local.yml (discovered)
# PASS
Restore Gap found no unresolved recovery risk.
…
$ echo $?      # 0 — the agent's rm proceeds
```

The proof expires in 30 days by default (`drill --expires-in`); after that,
the same `rm proj/app.db` blocks again until another `restoregap drill`
records a fresh one.
