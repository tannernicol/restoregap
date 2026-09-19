# Put recovery evidence before an agent's change

Restore Gap evaluates the **proposed operation** and returns a decision. It never
executes the operation or automatically runs a recovery to make the gate pass.
The caller must enforce the result before it lets the operation proceed.

## Start with a faithful input

Prefer an intent supplied by the tool integration, or an actual diff supplied by
CI. The CLI and MCP use the same evaluator:

```sh
restoregap preflight --context restoregap.yml --intent change.yml \
  --require-coverage --format json
```

For MCP, call `preflight_intent` or `preflight_diff` with `require_coverage: true`.
MCP is a decision interface, not an enforcement boundary by itself. An agent that
can omit the call, change the policy or execute the operation through another
route can bypass it. Keep the enforcing caller, trusted policy and signing keys
outside the agent's writable scope.

| Result | Caller behavior |
|---|---|
| Exit 0 | Evaluation completed without a blocking result. Inspect warnings; use `--fail-on-warn` when warnings must stop work. |
| Exit 1 | Policy blocked the proposal, or a warning was made fatal. Stop. |
| Exit 2 | Input or command usage failed. No permission to proceed was established. |
| Exit 3 | The gate could not complete reliably. Stop and repair the gate. |

Treat every nonzero exit as a stop. The structured `gate_state` distinguishes a
policy decision from a broken gate. Preserve the JSON result for the agent to
explain the next step; do not turn a block into an automatic override.

Strict coverage requires an applicable guard for every supplied path, destination,
package and command. One covered file does not cover another file in the same
intent. A command string supplied alongside paths also needs applicable command
coverage. This does not parse arbitrary shell semantics or discover resources the
caller omitted. Existing integrations retain the older permissive behavior unless
they explicitly enable strict coverage.

For evidence-backed changes, set `require_verified: true` and `require_bound: true`
on the guard. A bound proof records the tested recovery recipe and its explicit
recovery dependencies. A changed recipe or a proposed change to one of those
dependencies makes that evidence insufficient. The caller must supply the entire
change set; separating dependent changes into undisclosed requests hides that
relationship from any local evaluator.

## Example tool hook

[preflight-hook.sh](examples/preflight-hook.sh) is a narrow Claude Code
`PreToolUse` example. It reads the event once, translates supported tool calls to
an intent, and maps every failing gate result to hook exit 2. It uses Bash 4+,
`jq` and GNU `realpath -m`; this particular shell adapter is not a portable shell
parser. The Go CLI and MCP are the portable interfaces.

Register the script with an absolute path appropriate to your installation:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit", "hooks": [
        { "type": "command", "command": "/opt/restoregap/preflight-hook.sh" }
      ] }
    ]
  }
}
```

Recognized file-edit tools go directly to the evaluator, including paths covered
by policy globs. Supported shell shapes are deliberately limited:

| Shape | Intent |
|---|---|
| `rm`, `shred` | `delete_file` |
| `mv` | `move_file` |
| `truncate`, leading redirection, `dd … of=` | `modify_file` |
| forceful `git push`, `git branch -D`, `terraform destroy`, `dropdb` | `run_command` |

By default, unmatched commands pass through this example without evaluation. Quoting, shell
expansion, compound commands, aliases and interpreter code exceed its simple word
parser. Use your agent's sandbox and deny rules, or a tool integration supplying
structured operations, for those cases. A `terraform destroy` command match is
not Terraform-plan or provider-resource analysis.

`RESTOREGAP_CONTEXT` and `RESTOREGAP_LEDGER` select the policy and local ledger.
Set `RESTOREGAP_REQUIRE_COVERAGE=1` to enable strict coverage for the hook's
recognized inputs. In strict mode, an operation the narrow parser cannot
recognize is blocked with `not evaluated: unrecognized operation`; malformed
events also block rather than silently skipping the gate. Leave it unset to
retain the example hook's permissive unmatched-command behavior.

Run the fixture from the repository root:

```sh
bash docs/examples/preflight-hook.test.sh
```

It exercises guarded shell calls and file edits before and after a real drill,
wildcard policy matching, malformed input, strict unknown-file coverage and
explicitly unmatched commands. All data, context and ledger paths are isolated
from the operator's policy.

## Read the decision history

```sh
restoregap ledger show --limit 10
restoregap ledger show --format json
restoregap ledger verify
```

The ledger connects the proposal, findings, supporting evidence and next step.
Older records that did not capture a proposal remain visibly incomplete; their
history is never filled in using today's policy. Overrides are explicit owner
exceptions. Neither a pass nor a block is an execution receipt.

A separate, explicit `restoregap drill` refreshes recovery evidence. Review its
commands and credentials before running it: a temporary recovery directory is
not an operating-system sandbox. See the [restic recipe](examples/restic.md).
