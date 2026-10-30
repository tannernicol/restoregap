# Put recovery evidence before an agent's change

```sh
restoregap agent install claude --scope user
```

Use `gemini` for Gemini CLI. Add `--dry-run` to preview which settings keys would be
written without writing anything (the installer never prints file contents,
because agent settings files can hold tokens), or `--scope project` to install
for the current project. Repeating an install leaves identical settings untouched. Existing
hooks, MCP servers, and unrelated settings are preserved. The command uses the
running binary's absolute path, so install the binary in its permanent location
first.

User hooks go in `~/.claude/settings.json` or `~/.gemini/settings.json`; project
hooks go in the corresponding directory under the current project. Both receive
`mcpServers.restoregap` from `restoregap mcp --print-config`. Claude additionally
requires its MCP registration in `~/.claude.json` (user) or `.mcp.json` (project),
so the installer updates that file too and names the keys it changed in both files. Restart the agent
to load the changes; Claude may request approval for project MCP servers.

### Claude Code plugin install

With `restoregap` installed on `PATH`, from a checkout of this repository:

```sh
claude plugin marketplace add .
claude plugin install restoregap@restoregap
```

For a session without installation: `claude --plugin-dir .`. Choose either the
plugin or `restoregap agent install claude` to avoid evaluating each call twice.
The plugin registers the same PreToolUse matcher and MCP server. Its launcher
resolves `restoregap` from `PATH`; if missing, the hook denies with
`restoregap not installed`. A failed gate process also blocks. Plugin components
use `${CLAUDE_PLUGIN_ROOT}` so a cached install works from any project directory.
The manifests follow the [plugin schema](https://code.claude.com/docs/en/plugins-reference)
and [marketplace schema](https://code.claude.com/docs/en/plugin-marketplaces).

### Cursor

```sh
restoregap agent install cursor
```

Use `--scope project` for `.cursor/hooks.json` and `.cursor/mcp.json` in the
current project; the default writes those files under your home directory.
The installer preserves existing entries and registers `beforeShellExecution`
and `beforeMCPExecution` with `failClosed: true`. The adapter returns
`permission: allow|deny` with `user_message` and `agent_message`, per the
[Cursor hook contract](https://cursor.com/docs/agent/hooks). Shell commands and
recognized MCP tool names use the same translations as Claude; unknown operations
are allowed unless `RESTOREGAP_REQUIRE_COVERAGE=1`. An MCP server launch command
is never mistaken for the tool's proposed shell operation. These two events do
not intercept Cursor's native file edits. No Codex adapter is provided.

### Check wiring

`restoregap discover --all` reports each configured agent's hook and MCP wiring;
`restoregap status` includes those results from the latest discovery snapshot.
Missing hooks print the corresponding `restoregap agent install` command.
Coverage here means configured wiring, not proof that the running agent loaded
it or that every operation has recovery evidence. Discovery reads user and
current-project settings, including Claude's separate MCP registry; it does not
inspect the plugin cache or infer plugin activation.

The installed hook runs `restoregap agent hook claude` (or `gemini` / `cursor`). It reads one
stdin event, resolves paths and policy discovery from the event's `cwd`, and
returns a structured allow/deny with exit 0. Malformed events deny. A broken
gate denies with `recovery gate unavailable: <cause>`. Recognized operations use
the existing evaluator and record the decision in the local ledger. The hook
never executes the proposed command or the suggested recovery drill.

The hook writes its short-lived intent file to `RESTOREGAP_RUNTIME_DIR` when it
is set; otherwise it uses `$XDG_RUNTIME_DIR/restoregap`, then
`$XDG_STATE_HOME/restoregap/run` (defaulting to
`~/.local/state/restoregap/run`), and finally the system temp directory. The
selected directory is created with mode `0700`. If that write fails, the hook
evaluates the proposal in memory and logs one degraded-mode notice to stderr:
an operation with no declared guard still passes so the operator can repair
storage, unless global or scoped strict coverage blocks it; an operation
matching a declared guard also denies and names the write error. A compound
command with several recognized operations is evaluated in memory instead,
since an intent file holds one operation, and the ledger still records every
one.

A real deny from the demo fixture before its first drill:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Restore Gap preflight could not prove the declared recovery path survives this change.; Refresh or supply proof \"app-db-recovery\", or record an owner override before proceeding.; required proof: app-db-recovery; run: restoregap drill --context '/tmp/restoregap-agent-proof-86xz46yt/restoregap.yml' --proof 'app-db-recovery'"
  }
}
```

The temporary context path above is from that fixture; each response names its
own context and required proof. Review the named drill before running it, then
retry the operation. When no drill is declared, the response says so instead of
inventing a command that could make the guard pass. A drill may also need its
source or recovery recipe repaired before it can produce acceptable evidence.

Claude emits `hookSpecificOutput.permissionDecision` and
`permissionDecisionReason`; Gemini emits top-level `decision` and `reason`.
These follow the [Claude hook contract](https://code.claude.com/docs/en/hooks)
and [Gemini hook contract](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md).
Claude MCP permission rules use `mcp__restoregap__<tool>` names; see the
[Claude MCP reference](https://code.claude.com/docs/en/mcp). Inspection tools have
short titles and `readOnlyHint: true`. `preflight_intent`, `preflight_diff`, and
`acknowledge_risk` advertise `readOnlyHint: false`: they can write ledger records,
even though preflight never executes the proposed change. MCP exposes no `plan`
argument; the CLI's separate `preflight --plan` skips decision recording.

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
`coverage.commands` patterns compare against the intent's `command` field. The
agent hooks normalize shell wrappers (for example, SSH options and `user@host`)
before creating that intent; direct CLI and MCP intent callers must supply the
same normalized command themselves. MCP deliberately evaluates the YAML it
receives and does not parse or normalize a shell string.
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

## Portable shell reference

[preflight-hook.sh](examples/preflight-hook.sh) is a narrow Claude Code
`PreToolUse` example. It reads the event once, translates supported tool calls to
an intent, and maps every failing gate result to hook exit 2. It uses Bash 4+,
`jq` and GNU `realpath -m`; this particular shell adapter is not a portable shell
parser. The installed Go hook needs no Bash, jq, or realpath, and is the stronger
implementation: it understands quoting, compound commands and wrapped commands
(see below). Gemini maps
`run_shell_command`, `write_file`, and `replace` to the same intent shapes.

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
by policy globs.

### What the shell hook understands

The installed Go hook (`restoregap agent hook`) reads a Bash command the way a
shell would split it, without running or expanding anything, and evaluates every
simple command it finds in one preflight. It is stronger than the example shell
hook above, which looks only at the first word of the first line. The example
is kept as a small portable reference; use the Go hook when you can.

**Splitting.** Single and double quotes, backslash escapes and `#` comments are
honored, so `rm "my file.db"` is one path and `echo "rm -rf /"` is not a delete.
`&&`, `||`, `;`, `|`, `&`, newlines and subshell parentheses separate commands,
so `echo ok && rm -rf ~/Backups/x` evaluates the `rm`. `$(...)` and backtick
substitutions are parsed as additional commands, because they can hide a delete.
`$VAR` and `${VAR}` stay as typed. Leading `VAR=value` assignments and `if`/`then`/`do`
keywords are skipped. A leading `~` in a path means your home directory.

Here-documents (`<<EOF`, `<<-EOF`, `<<'EOF'`) are stdin text: the body up to the
closing line is skipped, so `git commit -m "$(cat <<'EOF' … EOF)" && rm guarded`
still evaluates the `rm`, and an `rm -rf /` written inside a body is not an
operation. Command substitutions in an unquoted body do run, so they are
evaluated. The rest of the line holding the `<<` is parsed as usual
(`cat <<EOF | tee x` is a write to `x`).

**Working directory.** `cd` and `pushd` carry through `&&`, `||`, `;` and
newlines, so `cd /guarded && rm -rf *` resolves against `/guarded`, and
`cd sub && cd .. && rm x` against the starting directory. A relative `cd`
joins the directory so far. `cd` alone, `cd ~`, `cd -`, `popd`, and a `cd` to
anything containing a variable or glob reset to the hook's own directory,
because the real one is not known. A `cd` does not carry out of a pipeline,
a background `&` or a `( … )` subshell; `$(…)` bodies and `bash -c` strings
start in the directory the line has reached.

**Unwrapped before classifying.** `sudo`, `doas`, `env`, `nice`, `nohup`, `time`,
`timeout`, `command`, `exec`, `builtin`, `stdbuf`, and `bash|sh|zsh|dash|ksh -c STRING`
(including `-lc`, `-ec`) are removed and the command inside is classified; they
do not appear in the command text a guard matches. `ssh [options] host CMD`,
`docker exec` (also `docker container exec`, `podman exec`, `docker compose exec`,
`docker-compose exec`) and `kubectl exec POD -- CMD` are unwrapped too, but
keep their wrapper as a prefix (see below).

**Shapes.**

| Shape | Intent |
|---|---|
| `rm`, `shred`, `unlink`, `rmdir`; `find ROOT … -delete` or `-exec rm …` (on `ROOT`) | `delete_file` |
| `mv SRC… DST`, `mv -t DIR SRC…` | `move_file` |
| `truncate`, `dd … of=`, redirection (`> f`, `>> f`, `: > f`, `cmd > f`), `tee [-a] FILE…`, `chmod`/`chown`/`chgrp` operands | `modify_file` |
| `cp`, `install`, `rsync` — the destination only; a destination containing `:` is another host and becomes `run_command`, and so does a lone remote `rsync` operand (a listing). rsync's remote operands also reach another host (see below) | `modify_file` |
| `scp` — a local destination, as for `cp`; `sftp HOST LOCAL` — the local file a download writes. Both also reach another host (see below) | `modify_file` |
| `scp` to a `host:path` or `scp://` destination; `sftp HOST` | `run_command` |
| `git push` with `--force`, `-f`, `--force-with-lease`, `--force-if-includes` or a `+ref`; `git branch -D`; `git reset --hard`; `git clean` with `-f`/`-x`/`-d`; `git stash drop\|clear`; `git checkout .`, `git restore .` | `run_command` |
| `terraform destroy`, `terraform apply -destroy`, `tofu destroy`, `pulumi destroy`, `dropdb` | `run_command` |
| `psql`, `mysql`, `mariadb`, `sqlite3` whose `-c`/`-e`/`--command` argument or trailing SQL contains `DROP`, `TRUNCATE` or `DELETE FROM`; `redis-cli flushall\|flushdb` | `run_command` |
| `docker`/`podman`: `rm`, `container rm\|prune`, `volume rm\|prune`, `system prune`, `compose down`, `stack rm`; `docker-compose down` | `run_command` |
| `kubectl delete`, `helm uninstall\|delete`, `systemctl disable\|mask` (not `stop`) | `run_command` |
| `zfs destroy`, `zpool destroy`, `btrfs subvolume delete`, `lvremove`, `vgremove`, `wipefs`, `mkfs*`, `sgdisk --zap*`, `parted … rm\|mklabel` | `run_command` |
| `restic forget\|prune`, `borg prune\|delete\|compact`, `rclone delete\|purge\|sync\|move`, `aws s3 rm\|rb`, `aws s3 sync … --delete`, `gsutil rm\|rb` | `run_command` |
| `crontab -r`, `launchctl bootout\|remove`, `gh repo delete`, `gh release delete`, `xargs rm` | `run_command` |

`git`, `terraform`, `tofu`, `pulumi` and `dropdb` operations are anchored to the
working repository's root (or the working directory outside a repository), so a
path guard on that repository matches them. Every other `run_command` matches
only `commands:` globs. Close lookalikes are not operations: `docker ps`,
`git push` without force, `systemctl stop`, `rclone ls`, `psql -c "select 1"`.

**Remote and container operations.** Anything that runs through `ssh`,
`docker exec` or `kubectl exec` happens somewhere else, so it is always a
`run_command` with no paths: a path on another host is never compared with a
local path guard. The command text keeps the wrapper as a prefix, with `sudo`
and similar removed:

| Typed | Matched as |
|---|---|
| `ssh -p 2222 -i key nas sudo docker rm restoregap-cloud` | `ssh nas docker rm restoregap-cloud` |
| `ssh nas "docker volume rm v && rm -rf /data"` | `ssh nas docker volume rm v` and `ssh nas rm -rf /data` |
| `docker exec -u 0 restoregap-cloud rm /data/cloud.db` | `docker exec restoregap-cloud rm /data/cloud.db` |
| `docker compose exec web sh -c "rm x"` | `docker compose exec web rm x` |
| `kubectl exec mypod -- rm /data/x` | `kubectl exec mypod rm /data/x` |
| `scp -P 2222 report ops@nas:/srv/` | `scp -P 2222 report ops@nas:/srv/` and `ssh nas scp -t /srv/` |
| `scp nas:/srv/report .` | a write to `.` (as `scp nas:/srv/report .`) and `ssh nas scp -f /srv/report` |
| `sftp -b cmds nas` | `sftp -b cmds nas`, `ssh nas [unsupported-options]` and `ssh nas sftp` |
| `rsync -a -e "ssh -p 2222" src/ ops@nas:/srv/` | `rsync -a -e ssh -p 2222 src/ ops@nas:/srv/` and `ssh nas rsync --server . /srv/` |
| `rsync -a nas:/srv/x .` | a write to `.` and `ssh nas rsync --server --sender . /srv/x` |
| `rsync -a src nas::backup` | `rsync -a src nas::backup` and `ssh nas rsync --server --daemon . backup` |
| `ssh 192.0.521 touch x` | `ssh 192.0.521 touch x` and `ssh 192.0.2.9 touch x` |

Guard these with `commands:` globs such as `ssh nas docker rm restoregap-cloud*`
or `*docker volume rm *restoregap*`. A `user@` prefix on the ssh host is dropped.

`scp`, `sftp` and `rsync` connect through ssh, so each operand on another host
(`[user@]host:path`, `[user@][v6addr]:path`, `scp://` or `sftp://`) is also
evaluated as the ssh command it amounts to: `scp -t PATH` for the destination
it writes, `scp -f PATH` for a source it reads, `sftp [PATH]` for a session,
and `rsync --server . PATH` (with `--sender` for a source or a lone operand).
An rsync daemon (`host::module`, `rsync://host/module`) is recorded the same way
with `--daemon`, although without `-e` it is reached over TCP rather than ssh,
so host coverage applies to it too. Host coverage such as `ssh nas *`
therefore applies to `scp report nas:/x`, `sftp nas` and `rsync -a x nas:/y`,
and the command text itself still matches globs such as `*scp *nas:*` and
`*rsync *nas:*`. scp's rule decides what is remote: a leading `:` or a `/` before
the first `:` is a local path. `-P`, `-i`, `-l`, `-c`, `-o` with a vetted
option, and the transfer flags (`-3`, `-r`, `-p`, `-q`, `-C`, ...) are dropped
like the ssh options below; `-F`, `-J`, `-S`, `-A`, `-X`, other `-o` settings
and sftp's batch file `-b` add an unsupported-options operation. An scp or
sftp command whose hosts cannot be read (a host written with `$VAR`, a glob or
a brace list, an empty host, too few operands, `-D`, or scp's internal `-t`/`-f`)
is not parsed, which denies it under strict or command-scoped coverage.
For rsync, `--rsync-path`, `-M`/`--remote-option` and the ssh options below
inside `-e` add the unsupported-options operation, and the same unreadable hosts
fail the parse. So does a remote shell (`-e`, `--rsh`) that is not `ssh` with
only its own options (`-e rsh`, `-e "docker exec -i"`, `-e "ssh nas"`) when an
operand is remote; for a local copy `-e` is ignored. A remote shell set through
`RSYNC_RSH` is not seen.

A host typed in a form ssh resolves differently is evaluated as typed and in
each canonical spelling: lowercase without a trailing dot (`NAS.` is `nas`);
an IPv6 literal without brackets or zone, compressed
(`[FD7A:115C:A1E0:0:0:0:1A2B:3C4D]` is `fd7a:115c:a1e0::1a2b:3c4d`); and a
numeric IPv4 address in any form `inet_aton` or macOS `getaddrinfo` accepts as
a dotted quad (`192.0.521`, `0300.00.02.011`, `3221225993`, `0xC0000209`
and, on macOS, `7516193289` are all `192.0.2.9`; `192.0.02.010` is checked
as both `192.0.2.8` and `192.0.2.10`). An `ssh://[user@]host[:port]`
destination is also checked as its host (`ssh ssh://nas x` as `ssh nas x`).
This applies to ssh hosts, including nested ones, and to scp, sftp and rsync
hosts. It is computed offline, so an `ssh_config` alias is still only its own
name.
A guard constrains every match dimension it lists at once, so one guard with
both `paths:` and `commands:` matches only an operation that has both. Declare
the backup set under one guard and the deployment commands under another, each
requiring the same proof.
A remote string is re-parsed, so each command in it is evaluated separately.
Every wrapped command is evaluated, including harmless ones such as
`ssh nas uptime`, which pass as "no declared guard matched" unless a guard
matches the command text.

The SSH parser only drops explicitly vetted connection options (`-p`, `-i`,
`-l`, selected transport flags, and `-o BatchMode`, `ConnectTimeout`, or
`StrictHostKeyChecking`). Custom SSH config (`-F`), command hooks such as
`ProxyCommand`, `LocalCommand`, or `RemoteCommand`, forwarding/control/local
output options, and unknown `-o` settings add a separate unsupported-options
operation. A scoped host policy must cover that operation explicitly; the
read-only command guard will not cover it. The parser cannot inspect user or
system SSH configuration, included files, or `Host`/`Match` rules. Treat that
ambient configuration as trusted for a scoped SSH host, or do not rely on its
normalized command guards.

**Compound commands.** All recognized operations in one tool call are evaluated
together in one preflight and recorded together in the ledger. If any is
blocked, the whole call is denied, and the reason ends with
`(N operations evaluated)`.

**Unrecognized and unparseable.** By default, a command with nothing recognized
passes with `not evaluated: unrecognized operation`. Recognized pieces of a
compound command are evaluated and the rest are ignored. A command the parser
cannot follow (unbalanced quotes, an unterminated heredoc, `<(...)` process
substitution, more than 64 KiB, nesting deeper than four levels, more than 16
spellings of nested ssh hosts, or an scp, sftp or rsync command whose hosts or
remote shell cannot be read) is allowed
with `not evaluated: could not parse command (<reason>)`, noted once on stderr
per hook run, only when no global or command-scoped strict coverage applies. If
a discovered policy declares `coverage.commands`, parse failures are denied
because the hook cannot determine whether the command falls inside that scope.
Unreadable or invalid policy files also deny that parse-failure path.

**Strict mode** (`RESTOREGAP_REQUIRE_COVERAGE=1`) denies an unparseable command,
and denies a command with nothing recognized with
`not evaluated: unrecognized operation`. In a compound command, the recognized
pieces are evaluated first (a real block wins), and the call is then denied with
`not evaluated: unrecognized operation in compound command` if any other piece
is unrecognized. Builtins and read-only tools do not count as unrecognized
pieces: `cd`, `pushd`, `popd`, `echo`, `printf`, `true`, `false`, `test`, `[`,
`[[`, `export`, `unset`, `set`, `read`, `type`, `which`, `command -v`, `pwd`,
`exit`, `return`, `source`, `.`; `ls`, `cat`, `head`, `tail`, `less`, `more`,
`wc`, `sort`, `uniq`, `cut`, `tr`, `grep`, `egrep`, `fgrep`, `rg`, `awk`, `diff`,
`stat`, `file`, `du`, `df`, `date`, `uname`, `hostname`, `whoami`, `id`, `sleep`;
`sed` without `-i`; `find` without `-delete`, `-exec` or `-fprint`; `env` with no
command; and `git` `status`, `log`, `diff`, `show`, `rev-parse`, `fetch`,
`ls-files`, `grep`, `blame`, `describe`, `branch` and `tag` without a delete
flag, `remote -v`, `stash list`. So `cd /tmp && rm x` is evaluated as the `rm`
alone, while `cd /tmp && mystery-tool && rm x` is denied. A line made only of
such commands (`ls -la`) still has nothing recognized and is denied. `tee`,
`cp` and `mv` are never benign. Strict mode also applies per-resource coverage
to every recognized operation, so a wrapped command needs a `commands:` guard to
be covered, and an `rm` still needs a guard that covers its path.

**Out of scope.** The hook does not see interpreter code (`python -c`,
`node -e`), scripts run by path (`./cleanup.sh`, `bash cleanup.sh`; `source` is not
followed), aliases or shell functions, `find -exec` with anything but
`rm`/`shred`/`unlink`/`rmdir`, SQL piped on standard input, or a heredoc fed to
an interpreter (`bash <<EOF`) — the body is skipped. It does not expand variables
or globs, so `rm $DIR/x` is the literal path `$DIR/x`, and a `cd` into a
variable resets the tracked directory. A `terraform destroy` command match is not Terraform-plan
or provider-resource analysis. Use your agent's sandbox and deny rules, or a
tool integration supplying structured operations, for those cases.

`RESTOREGAP_CONTEXT` and `RESTOREGAP_LEDGER` select the policy and local ledger.
Set `RESTOREGAP_REQUIRE_COVERAGE=1` to enable strict coverage for the hook's
recognized inputs; malformed events also block rather than silently skipping
the gate. Leave it unset to retain the hooks' permissive unmatched-command
behavior.

Run the example shell hook's fixture from the repository root:

```sh
bash docs/examples/preflight-hook.test.sh
```

It exercises guarded shell calls and file edits before and after a real drill,
wildcard policy matching, malformed input, strict unknown-file coverage and
explicitly unmatched commands. All data, context and ledger paths are isolated
from the operator's policy.

## Direction-aware transfer guards

A guard that matches `*scp *host:*` blocks every scp that names the host, in
both directions. Often you want the two directions to carry different proof:
pulling private data off a host should need the owner's explicit release, while
pushing an archive copy onto it should need proof that the local original is
intact. The engine has no exclusion matcher and context layers merge
tighten-only, so you cannot carve an exception out of a broad guard from another
file. Encode the direction in the glob shape instead:

| Pattern | Matches | Meaning |
|---|---|---|
| `*scp *host:* *` | a `host:` operand followed by another operand | download (host is a source) |
| `*scp * host:*` | the `host:` operand is last | upload (host is the destination) |
| `ssh host scp -t <path>` | the normalized remote side of an upload | what path guards see |
| `*sftp *host:*` | any sftp session | both directions; keep it under the owner release |

Keep the owner-release requirement on the download shapes and on sftp. Give
uploads their own guard per destination folder with a real recovery proof, and
run with `--require-coverage` so an upload to any folder without a guard fails
closed. When the originals drill is scheduled (launchd, cron), keep its
artifact and recovery source outside macOS privacy-protected folders such as
`~/Downloads`; a background process blocks there waiting for a consent prompt. Private-data path guards still apply to uploads through the normalized
`ssh host scp -t <path>` form. A complete example, with a weekly re-drill of the
originals' digests, is in [`docs/examples/archive-upload-guard.yml`](examples/archive-upload-guard.yml).

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
