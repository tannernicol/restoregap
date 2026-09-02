# DISCOVER — the denominator `status` never computes

`restoregap discover` answers "what did I forget to declare?", not "are my
declared things proven?" (that's `status`). It is purely deterministic
enumeration plus a diff: no LLM, no network, no API key, works offline. The
judgment about which gaps matter belongs to the agent reading the report.

## Candidate kinds

| kind | source |
|---|---|
| `container-volume` | a running container's writable bind mount, outside /tmp, /proc, /sys, /dev, /var/run, and not a socket |
| `database` | a `*.sqlite`/`*.sqlite3`/`*.db` file under `$HOME` over 64KiB (bounded walk, depth 5) |
| `repo` | a git repo under `$HOME` (depth 3) with no remote, or with commits not on ANY remote-tracking branch (checked across every declared remote, not just `origin`) |
| `service-state` | an enabled-or-active systemd `--user` unit whose declared content references a path under `$HOME` that looks like state (`/data`, `/state`, `/db`, or `.db`/`.sqlite*`) |
| `machine-id`, `package-manifest`, `etc-config` | fixed, always-emitted: the machine floor a rebuild needs even though nobody "backs them up" |

## Coverage rule

A candidate is `covered` only when its path is equal to, or a path-ancestor
of, a declared drill's `artifact` or `recovery_source` — or matched by a
guard's declared path glob (`internal/globmatch.MatchPathAny`, the same
matcher `internal/rules` uses to decide whether a guard applies to a real
intent). Nothing else can make a candidate covered.

## Weight table (blast-radius hint, from Kind alone)

| weight | kinds | why |
|---|---|---|
| 4 | `machine-id`, `package-manifest`, `etc-config` | the machine floor |
| 3 | `database` | a running service's own data |
| 2 | `container-volume`, `service-state` | host-side state outside the image/package |
| 1 | `repo` | local, unpushed work, scoped to what's unpushed |

## Noise suppression (default excludes + ignore files)

A real audit found the uncovered list dominated by regenerable noise —
Firefox profile databases, Zoom's encrypted cache, `.beads/beads.db` in
every repo, `.archive/` copies of retired projects — burying the genuine
finds. Suppression is a RENDERING decision, never a data one: a suppressed
candidate is still fully counted (`counts.suppressed`, a subset of
`counts.uncovered`) and still visible, with `suppressed_by` naming the
exact rule, whenever `--all` is passed.

- **Built-in defaults** (`defaultExcludeGlobs`, one documented `var` in
  `internal/discover/exclude.go`): browser profiles (`.mozilla`,
  `.config/*/Default`, `.config/*/Profile *`, any path segment containing
  `chrome`/`chromium`/`firefox`), `.archive/**`, `.cache/**`,
  `.local/share/Trash/**`, `node_modules`, `.venv`, `__pycache__`,
  `.git/**`, and common OS/tool caches (Zoom's message cache, `Cache`,
  `CacheStorage`, `GPUCache`, `Code Cache`).
- **`.restoregapignore`** in the directory `discover` is run from (one glob
  per line, `#` comments) — the same file and format `restoregap check`
  already reads, so an owner mutes a repo-local false positive without a
  code change.
- **`$XDG_CONFIG_HOME/restoregap/discoverignore`** (or
  `~/.config/restoregap/discoverignore`) — the machine-wide equivalent.

## Ranked, grouped, truncated default view

Uncovered candidates are ranked by CONSEQUENCE, not alphabet: weight
descending, then size descending — a 5.6GB database always outranks a
460KB cache of the same weight. Three or more candidates sharing a kind
and basename (twelve repos' `.beads/beads.db`) collapse into one line —
`database  beads.db  ×12 (8.7 MB total)  — 12 locations` — expandable
under `--all`. The default view shows the top 20 resulting lines, then
`... and N more (--all)`.

## Duplicate paths (dedup)

The same file reachable via two apparent paths — a symlink alias, or a
bind mount exposing one host directory at two locations (docker compose's
`~/ntfy` and `~/infra-config/compose/ntfy` both containing `auth.db`) — is
one candidate, not two. Because a bind mount involves no symlink at all,
matching is by the underlying `(device, inode)` pair (falling back to
`EvalSymlinks`, then the raw path, when a file cannot be stat'd), and the
non-primary path is kept in `alternate_paths` rather than dropped.

## Ambient growth: snapshot, new-candidate detection, trend

Every `discover` run (unless `--no-save`) writes
`$XDG_STATE_HOME/restoregap/discover/latest.json`, rotating the previous
run to `previous.json` first, and appends one row to `history.jsonl`
(capped at the newest 500 scans). Each candidate carries `first_seen`,
carried forward by `kind:path` from the previous scan or set to now; a
candidate absent from the previous scan is `new` — surfaced in text output,
`counts.new`/`new` in JSON, and `restoregap discover --trend`'s table.
`restoregap status` reads `latest.json` (never runs a scan itself) to print
one `coverage: N of M candidates covered` line, or `coverage: not scanned`
when the snapshot is missing, unreadable, or older than 7 days.

## Integrity rule

**Discovery never marks anything covered, and no caller — including an
agent over MCP — can make it.** `covered` is recomputed fresh from a
context's declared drills/guards on every run; a previous scan read back
from disk is used ONLY to carry forward `first_seen`, never `covered`. The
MCP `discover` tool additionally never writes the on-disk snapshot at all
(only the CLI does) — it is read-only in the strongest sense. Coverage
becomes real only when someone declares a drill and that drill actually
runs; `discover` proposes nothing and proves nothing.
