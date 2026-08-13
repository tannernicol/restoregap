# Drill authoring — for agents

This is the contract for authoring a `drills:` block on a machine you don't
own the setup of. You are the primary operator of this feature: a human
rarely hand-writes a drill; you read the target system, find its real
recovery source, and declare a drill that proves it. Nothing here may assume
this machine's paths, backup tooling, or installed CLIs — every drill you
write runs on whatever host the operator points you at, with whatever
recovery tooling they already have.

A drill proves a recovery by performing it: reconstruct the artifact from its
declared recovery source inside a throwaway sandbox, then check the result
against typed, measurable outcomes. Only a drill produces `verified: true`.
See `README.md` for the wider tool and `docs/ARCHITECTURE.md` for the
context-document format this is one block of (`drills:` inside a v2
`restoregap.yml`).

## Start here: propose, don't hand-write

The mechanical parts of a drill — type detection, invariants, budgets — are
derivable by measuring the live artifact. Only the `recover:` command needs
knowledge the tool cannot have (which backup tool, which paths). So measure
first, hand-write only what's left:

```console
$ restoregap check /srv/app/data.db /backups/app          # what's live, what backs it up
$ restoregap drill propose /srv/app/data.db --source /backups/app --out draft.yml
#   ... fill in / verify the recover: stub draft.yml marks # TODO ...
$ restoregap drill --lint --context draft.yml
$ restoregap drill --context draft.yml                    # a few times, over real days
$ restoregap drill --calibrate --context draft.yml --ledger <ledger> --apply
#   ... wire a scheduler (see step 9 below) ...
```

`restoregap drill propose <artifact> [--source <path>]` reads the LIVE
artifact, measures it, and prints a paste-ready `drills:` YAML entry to
stdout (or `--out <file>`) — it never writes into an existing context file,
so it's always safe to run again. Type is detected by content, not name
(sqlite databases carry no reliable extension): sqlite (magic bytes), git
(bare or worktree), keys (an `.ssh`/`.gnupg`-shaped directory), file_tree
(any other directory), byte_identical (any other file). With `--source`,
the recovery source itself is classified (a restic or borg repo, a
dated-snapshot directory, an archive directory, or a plain path) and a
matching `recover:`/`pin_check:` stub is emitted, always clearly marked
`# TODO` for you to verify — propose never scans the filesystem hunting for
a backup layout it wasn't told about; guessing wrong is worse than asking.

**The `floor()` rule.** Every measured count constraint (`tables:` row
counts, `refs:`, `files:`) is given ~15% headroom below the measured value,
then rounded DOWN to something a human would write: under 10, just `>= 1`;
otherwise, 2 significant figures (2379 measured → `>= 2000`, 65 measured →
`>= 55`). One implementation (`internal/drill.Floor`), documented here, in
`restoregap drill propose --help`, and nowhere else, so there is exactly one
place to look when a number in a proposed drill looks surprising.

**Why budgets start empty.** `propose` emits NO `budgets:` block, on
purpose. An experienced operator with full system context hand-authored 13
drills in one sitting; measured against real runs afterward, every single
hand-written RTO budget came in 44x–8333x looser than the worst observed
run — decorative budgets that could never fail no matter what broke.
Guessing at a budget is worse than leaving it undeclared. Run the drill a
few times for real, then derive one from what actually happened:
`restoregap drill --calibrate --context <file> --ledger <ledger>`.

**`restoregap drill --calibrate`** reads verified drill telemetry back out
of the ledger (`--ledger`, required) for every drill declared in
`--context`, and proposes RTO/RPO budgets from it — printing the proposal,
never writing unless `--apply` is also given. A drill needs at least
`--min-runs` (default 3) verified runs before a budget is proposed for it
at all; fewer prints a `skip:` line instead of guessing from one sample.
RTO is proposed from the p95 of observed `rto_ms` (below 20 samples, p95
degenerates to the max — intended, not a bug, for a small sample) as
`max(p95 × margin, 30s)` (`--margin`, default 4; the 30s floor exists
because a sub-second drill times even a generous margin can still land
under a second, which would flake on any contended disk), rounded up to a
friendly duration. RPO — a property of the backup schedule, not of drill
duration — gets its own looser shape: `max(p95 × 1.5, p95 + 6h)`, rounded up
to the next whole hour, proposed only when at least `--min-runs` runs
actually measured `rpo_ms`. Every declared budget is also sanity-checked
against what was observed, printed even without `--apply`: `warn: <proof>:
budget <X> is <N>x the worst observed run — it cannot fail` when it's far
too loose, or `... is only <N>x observed p95 — expect flakes` when it's too
tight. `--apply` rewrites ONLY the `budgets:` block of each matched drill,
preserving everything else in the document — comments, checks, unrelated
proofs — byte-for-byte; it never lowers a budget silently, always printing
both the declared and proposed values either way.

## Schema

```yaml
version: 2
drills:
  - proof: <id>                    # required — the proof this drill produces/refreshes
    artifact: <path>                # required — the live artifact being protected
    recovery_source: <string>       # optional — informational + passed to recover/pin_check as RG_RECOVERY_SOURCE
    recover: <sh -c command>        # required — reconstructs the artifact; see env contract below
    pin_check: <sh -c command>      # optional but strongly recommended — see "pin_check contract" below
    budgets:
      rto: <Go duration>            # optional, e.g. 5m, 90s, 2h
      rpo: <Go duration>            # optional — requires a check that can measure freshness (see below)
    validate:                       # optional — empty means the implicit single byte_identical check
      - type: byte_identical | sqlite | git | file_tree | command | serve | key_fingerprint
        # ... type-specific fields, see below
```

`proof`, `artifact`, and `recover` are required; everything else has a
sensible default. `validate: []` (or omitting it) is a byte-identical drill:
recover, then compare the recovered bytes to the live artifact exactly. That
default only works when the live artifact is a single, byte-stable file —
anything else (a directory, a database that changes between the moment you
declared the drill and the moment it runs) needs an explicit `validate:`
block with a check type suited to it.

### Check types

Every `validate:` entry is one declared check; its outcome becomes one
recorded `{type, pass, detail}` entry on the proof.

**`byte_identical`** — no extra fields. `RG_TARGET` must be a single file;
its bytes must match `artifact` exactly. This is the only check that reads
`artifact` at drill time (to hash the live original before recovery starts).

**`sqlite`** — opens `RG_TARGET` read-only via the pure-Go sqlite driver
(no system sqlite3 required).
```yaml
- type: sqlite
  integrity: true                       # PRAGMA integrity_check must return exactly "ok"
  tables:                               # table name -> row-count constraint (see grammar below)
    orders: ">= 500"
    users: ">= 10"
  freshness:                            # optional; feeds the RPO measurement
    table: orders
    column: created_at                  # accepts RFC3339, "YYYY-MM-DD HH:MM:SS", "YYYY-MM-DD", or unix seconds
```
`freshness` reads `SELECT MAX(column) FROM table`. RPO is `now − parsed
value`. An unparseable value fails the check loudly, quoting exactly that
cell (nothing else from the row — it's a timestamp column, not a secret).

**`git`** — `RG_TARGET` must be a git repository (worktree or bare).
```yaml
- type: git
  refs: ">= 1"                          # optional; count of `git for-each-ref` lines
```
`git fsck --no-progress` must exit 0. If `git` isn't on `PATH`, the check
fails closed — a git drill without git present proves nothing, so it is
never silently skipped. When an `rpo` budget is declared and nothing with
higher priority (sqlite's explicit `freshness:`) already measured it, the
last commit's timestamp (`git log -1 --format=%ct`) is used automatically.

**`file_tree`** — `RG_TARGET` must be a directory.
```yaml
- type: file_tree
  files: ">= 3"                         # optional; regular-file count under RG_TARGET
  must_exist:                           # paths relative to RG_TARGET; must exist and be non-empty
    - config/settings.yml
    - data/current
```
`must_exist` entries fail if missing, if a file is zero bytes, or if a
directory has no entries. Like `git`, the newest file's mtime becomes the
RPO source automatically — but only when an `rpo` budget is declared and
nothing higher-priority already answered it.

**`command`** — an arbitrary invariant, for anything the other types can't
express (referential integrity, a business rule, a checksum manifest).
```yaml
- type: command
  run: sqlite3 "$RG_TARGET" "SELECT 1" | grep -q 1
```
Runs via `sh -c`; exit 0 is pass. The first line of combined stdout+stderr
(truncated to ~200 chars) becomes the check's recorded detail either way. A
`command`-only `validate:` list is the one case that doesn't require
`recover` to populate `RG_TARGET` at all — useful when the invariant you're
proving lives entirely in side effects the command inspects itself.

**`serve`** — the L4 rung: boot the recovered artifact and require it to
answer. Its own section below (### Calibrating RPO needs samples across the backup cycle

RTO calibrates well from any handful of runs. RPO does not: it measures the
age of the newest recovered record, which is a sawtooth that resets every
time the backup runs. Three drills run minutes after a refresh will teach
`--calibrate` that your RPO is minutes — and the proposed budget will then
fail for the rest of the cycle. Real case: a weekly OS-state bundle, drilled
three times right after a manual refresh, produced a 7h RPO proposal against
a 168h refresh cycle. Before applying an RPO proposal, ask whether your
samples cover at least one full backup interval; if they don't, keep the
budget you derived from the schedule itself.

## Boot it: the serve check) covers the full
schema, the RG_PORT contract, and when it's honest to add — it's the one
check type meaty enough to deserve one.

**`key_fingerprint`** — proves recovered key material is the RIGHT key
material, by fingerprint, never by reading, decrypting, or printing the key
itself. Losing an encryption key is the failure mode where intact backups
are worthless (ciphertext nobody can open); every user has ssh keys, most
self-hosters have a gpg key guarding a password store, so this is the most
portable high-stakes check there is. Hand-rolling the equivalent as a
`command` check invites the mistake of comparing file bytes instead of
fingerprints — key files legitimately re-serialize (a re-exported gpg key,
an ssh key re-written by a different tool) without the underlying key
material changing at all, so a byte comparison would fail a perfectly good
recovery.
```yaml
- type: key_fingerprint
  keys: ssh                             # or gpg — required, selects the fingerprinting scheme
  expect_from: /home/user/.ssh          # optional: every LIVE key here must appear in the recovered set
  expect: ["SHA256:...", "..."]         # optional: explicit fingerprints that must appear
  min_keys: 1                           # optional, default 1: minimum keys found in the recovered set
```
`RG_TARGET` may be a single key file or a directory (walked recursively).
For `keys: ssh`, each candidate file is checked via `ssh-keygen -lf`; a file
it rejects is simply not a key and is skipped silently (a recovery kit
legitimately holds `README`/`known_hosts.old`/`config` alongside real
keys). For `keys: gpg`, each candidate file is checked via `gpg --show-keys
--with-colons`, which needs **no keyring and imports nothing** — every
invocation runs against its own throwaway `--homedir`, so the check cannot
mutate the operator's real gpg state (not "probably doesn't" — structurally
cannot, even the very first time gpg has ever run on that machine, which
would otherwise create keybox/trustdb scaffolding as a side effect). A
private key and its public counterpart fingerprint identically, so
`id_ed25519`/`id_ed25519.pub` both being present in a recovery copy counts
as one key, never two.

At least one of `expect_from`, `expect`, or a positive `min_keys` must be
declared — a `key_fingerprint` check with none of those would pass on any
recovered set at all, including an empty one, which `drill --lint` flags
even in the one case that isn't a hard parse error: `min_keys` left at its
default of 1 with no `expect_from`/`expect` proves a key exists, but never
that it's the RIGHT one, which is this check type's entire reason to exist.

**Wall-1 (non-negotiable, settled product decision):** this check reads key
files ONLY to derive fingerprints via the external tool. It never prints,
logs, stores, or places into the proof any key content, passphrase, or
decrypted material — fingerprints and counts only, always. If it ever finds
that missing, that is a bug, not a style preference.

### Constraint grammar

`tables`, `refs`, and `files` constraints all share one grammar:
`>= N`, `> N`, `== N`, `<= N`, `< N` — an operator, optional whitespace, an
integer. Nothing else parses.

### Budgets

`budgets.rto` and `budgets.rpo` are Go duration strings (`5m`, `90s`, `26h`).
RTO is measured wall-clock from just before `recover` starts to just after
the last `validate:` check finishes. A budget that's exceeded is recorded as
a synthetic failing check (`budget_rto` / `budget_rpo`) so it shows up in the
scorecard, not just as a silently-lower verified rate.

**RPO source precedence**, when more than one check could supply it: a
`sqlite` check's explicit `freshness:` always wins; `git`'s last-commit time
is next; `file_tree`'s newest-mtime is last resort. `git`/`file_tree` are
only consulted at all when `budgets.rpo` is declared (no point paying for the
extra `git log`/directory walk otherwise).

**Declaring `budgets.rpo` with nothing capable of measuring freshness is a
hard failure** — a synthetic `budget_rpo` check fails loudly ("rpo budget
declared but nothing measures freshness"), never a silent pass. `drill --lint`
catches this before you ever run the drill for real (see below).

Don't hand-write these numbers. See "Start here: propose, don't hand-write"
above for `restoregap drill --calibrate`, which derives both from real
ledger telemetry instead.

### `pin_check` contract

`pin_check` is a separate, cheap probe: does the *pinned recovery source*
still exist, without performing a recovery. Run via `sh -c` with only
`RG_RECOVERY_SOURCE` set (`RG_SANDBOX`/`RG_TARGET` are unset — there is no
recovery in progress). **Exit 0 means the source is still alive**; nonzero
means it's gone. `restoregap drill --pins-only` runs every declared
`pin_check`: a failure flips that proof to `disputed` immediately; a success
leaves the existing proof record completely untouched (a pin check is not a
drill and must never refresh `observed_at` or expiry). A drill with no
`pin_check` is simply skipped in `--pins-only` mode — silently, but that
silence is itself a coverage gap worth noticing (see the recipe below).

Good `pin_check` shapes: "does this snapshot repo list at least one
snapshot", "does this S3 prefix have an object newer than N days", "does
this replica respond to a trivial query". Bad shape: anything that takes as
long as the real recovery — that's not a pin check, that's a drill with
extra steps.

### Environment contract

| Var | Set for | Meaning |
|---|---|---|
| `RG_SANDBOX` | `recover`, `validate` checks | private, empty scratch directory; removed after the drill |
| `RG_TARGET` | `recover`, `validate` checks | where `recover` must write the reconstructed artifact — a file for `byte_identical`/`sqlite`, a directory for `git`/`file_tree`/`serve` |
| `RG_RECOVERY_SOURCE` | `recover`, `validate` checks (including the `serve` command itself), `pin_check` | the declared `recovery_source` string, verbatim |
| `RG_PORT` | the `serve` command, and `serve`'s `command`-type probes only | the free port the serve command must bind to — see below. NOT set for `pin_check` or for non-serve checks |

Note the one asymmetry: a `serve` check's own boot command gets all four
vars; a `command`-type *probe* inside that same `serve` check gets
`RG_PORT`/`RG_TARGET`/`RG_SANDBOX` but NOT `RG_RECOVERY_SOURCE` — a probe's
job is to ask the booted server something, not to know where it came from.

`recover` writing something other than what the declared checks expect (a
file when `git` needs a repo, nothing at all) is a drill failure, not a
config error to debug after the fact — that's exactly what `drill --lint`
and a first real `drill` run are for.

### Calibrating RPO needs samples across the backup cycle

RTO calibrates well from any handful of runs. RPO does not: it measures the
age of the newest recovered record, which is a sawtooth that resets every
time the backup runs. Three drills run minutes after a refresh will teach
`--calibrate` that your RPO is minutes — and the proposed budget will then
fail for the rest of the cycle. Real case: a weekly OS-state bundle, drilled
three times right after a manual refresh, produced a 7h RPO proposal against
a 168h refresh cycle. Before applying an RPO proposal, ask whether your
samples cover at least one full backup interval; if they don't, keep the
budget you derived from the schedule itself.

## Boot it: the serve check

`serve` is the strongest claim a drill can make: not just "the bytes came
back" or "the database opens and the invariants hold", but "the actual
service booted against the recovered data and answered a real request".

```yaml
- type: serve
  run: /usr/local/bin/app -addr 127.0.0.1:$RG_PORT -db "$RG_TARGET"
  ready_timeout: 30s              # optional, default 30s
  probes:                         # required, at least one
    - type: http
      path: /api/summary          # full URL is http://127.0.0.1:$RG_PORT<path>
      expect_status: 200          # optional, default 200
      expect_body: net_worth      # optional response-body substring
    - type: command
      run: some-cli --port "$RG_PORT" healthcheck
```

**The honest isolation claim.** This is process-level isolation only: an
isolated, throwaway process plus the drill's own sandbox directory — **never
a container**, and never claim otherwise. The engine has zero docker/container
dependency; it picks a free port, starts `run` as a plain child process in
its own process group, polls, and kills. Your `run` command MAY itself shell
out to `docker run` if that's genuinely how the artifact is served in
production — that's your choice to make, not a capability the engine
provides or a claim it makes on your behalf. (This product's history
includes walking back an overstated "container" claim once; it does not get
made again.)

**RG_PORT contract.** restoregap binds `127.0.0.1:0` to obtain a free port,
closes the listener, and passes the port number as `RG_PORT` — your `run`
command must bind to `127.0.0.1:$RG_PORT` (not `0.0.0.0`, not a hardcoded
port: another drill, or another instance of your own service, may be running
concurrently). There's an inherent small race (something else could grab the
port between restoregap releasing it and your process binding it) — the
standard, portable price of doing this without a container runtime or
root-only tooling.

**Readiness and probes.** The FIRST declared probe is polled every 250ms
until it passes or `ready_timeout` elapses; the time it took is recorded
("ready in 800ms"). If your process exits before that first probe ever
passes, the check fails immediately with the tail of its output — a process
that never got ready proves nothing, so this is never silently skipped or
retried past the deadline. Once ready, every remaining probe runs exactly
once, in order; all must pass. An `http` probe failure reports the status
code got vs want, and — if `expect_body` didn't match — says only "body
match failed", **never the response body itself**: the recovered artifact
can carry real data, and this repo never prints data. A `command` probe's
detail is always just its first output line.

**The kill guarantee.** The serve process (and its whole process group, so
anything it forks) is killed on every single exit path — success, a failed
probe, a ready timeout, or an internal error before probing even started:
SIGTERM, five seconds' grace, then SIGKILL. A leaked server process is a
test that corrupts the next drill run (it's still holding the port, or a
lock on a sandbox file the next run's cleanup can't remove). You do not need
to add your own cleanup trap in `run` for this — restoregap's kill reaches
the whole tree regardless of what your process does or doesn't do on
SIGTERM.

**Sandbox paths only — the engine cannot enforce this, you must.** Your
`serve` command (and everything it reads) must reference only `$RG_TARGET`
/ `$RG_SANDBOX` — never a live production path, live database, or live
config. Nothing in the engine stops a `run` command from pointing at real
data instead of the recovered copy; if it does, the check will pass, and it
will have proven nothing about recovery at all, just that production is (of
course) up. That defeats the entire premise of a drill. Review every `serve`
check you author for this before it ships.

**sqlite WAL gotcha.** If your serve process opens a sqlite `RG_TARGET` in
its normal (non-read-only) mode, it may create `-wal`/`-shm` files next to
it inside the sandbox. That's expected and harmless — they're removed along
with the rest of the sandbox when the drill finishes.

**Large artifacts: put the sandbox on disk.** Sandboxes are created under the
OS temp directory, which on most Linux systems is `tmpfs` — that is, RAM.
Restoring a multi-gigabyte artifact there quietly spends memory the machine
may need, and a large enough restore can take the box down during the very
exercise meant to prove it survives. For anything big, pass
`--sandbox-dir /path/on/disk` (a scratch directory with room for the fully
restored artifact). Check your own machine before assuming: `findmnt -no
FSTYPE /tmp` and `df -h /tmp`.

**When NOT to add `serve`.** Not every artifact has a natural service to
boot — a config directory, a static export, an SSH key, most `file_tree`
and plenty of `sqlite` targets never "serve" anything. Their honest ceiling
is `data-valid`, and that's fine: the whole point of the recovery inventory
(`restoregap status`) is to SHOW that ceiling honestly, not to pressure
every drill toward L4. Adding a `serve` check that boots something
artificial just to claim a higher rung is a vanity check exactly like a
`>= 0` table constraint — it proves nothing real and makes the inventory
lie by omission.

## Recovery levels

Every proof's evidence is expressed as one of four rungs — declared once
here, used everywhere else (`restoregap status`'s inventory, the `drill`
CLI's verified line, ledger telemetry) so the same word always means the
same thing:

| Level | Rung | Earned by |
|---|---|---|
| `declared` | L1 | A drill exists in the config, but there's no current live verified proof — never drilled, or the last proof expired, went stale, was disputed (e.g. a failed `pin_check`), or simply never verified. |
| `restores` | L2 | A verified drill whose passing checks include `byte_identical`, `file_tree`, and/or `command` — recovery reconstructs validated content. |
| `data-valid` | L3 | A verified drill that also includes a passing `sqlite`, `git`, and/or `key_fingerprint` check — the recovered data opens and its own invariants hold (or, for keys, is provably the right key material by fingerprint), not just "bytes exist". |
| `serves` | L4 | A verified drill that also includes a passing `serve` check — the artifact boots as a real service and answers. |

The level is the MAX rung among a proof's passing checks — a drill
declaring both `serve` and `sqlite` checks that both pass is `serves`, not
merely `data-valid`. An RTO/RPO budget miss (`budget_rto`/`budget_rpo`) can
only ever block verification; it never promotes a rung on its own.

## The authoring loop

Run this loop once per artifact you're asked to protect. Each step earns the
next — don't skip to "declare checks" before you've actually looked at what
recovers this artifact today.

1. **Identify the artifact.** The live path (or directory) that must stay
   recoverable. Confirm it's real — `ls`/`stat` it, don't take a claim on
   faith.
2. **Find its real recovery source.** Not "there's probably a backup" —
   the actual command, repo, snapshot tool, or replica that this machine (or
   its operator) already uses to restore this artifact. If there isn't
   one, that's the finding: say so, don't invent a `recover:` command that
   has never actually been run.
3. **`restoregap drill propose <artifact> --source <source> --out draft.yml`.**
   Measures the artifact for you: type detection, real invariants (row
   counts, ref counts, file counts, key fingerprints) with `floor()`
   headroom already applied, and a classified `recover:`/`pin_check:` stub
   — see "Start here" above. This replaces hand-writing steps 4 and 5 from
   here on; you're reviewing a measured draft, not inventing one.
4. **Fill in / verify the `recover` command the stub proposed.** It must
   reconstruct into `$RG_TARGET` using `$RG_RECOVERY_SOURCE`. Prefer the
   operator's existing restore command over a hand-rolled equivalent — the
   drill should prove the thing they'd actually run at 3am, not a parallel
   path that's never been exercised. Every propose stub is marked `# TODO`
   for exactly this reason: it's a draft, not a claim that it already works.
5. **Review the proposed checks.** `propose` measured real invariants
   already — table counts, ref counts, file counts — so this is a review
   pass, not a from-scratch design: does the largest table's freshness
   column actually mean "last write", do the seeded `must_exist:` entries
   need replacing with the ones that actually matter, is a
   referential-integrity or business-rule `command` check worth adding on
   top of what was measured.
6. **Declare `pin_check`, if propose didn't already stub one.** Almost every
   drill should have one — it's the cheap, frequent probe that catches a
   pruned or rotated snapshot in the days between full drills, when a full
   drill would be too expensive to run daily.
7. **`restoregap drill --lint --context <file>`.** Static, no execution, no
   writes. Fixes the RPO-budget-with-no-freshness-source class of mistake
   and flags a missing `pin_check` before you've run anything for real.
8. **`restoregap drill --context <file>`.** The real thing: recover into a
   sandbox, run every declared check, measure RTO/RPO, record the proof.
   Read the failure detail if it doesn't verify — it names the failing check
   first.
9. **Run it a few times, then `restoregap drill --calibrate --context <file>
   --ledger <ledger> --apply`.** Budgets started empty on purpose (see "Why
   budgets start empty" above) — this is where they get filled in, from
   what the drill actually measured, not a guess.
10. **Wire a scheduler.** Full `drill` weekly (or whatever cadence the
    recovery's cost and the artifact's importance justify); `drill --pins-only`
    daily. The full drill is the strong proof; the pin check is what keeps
    that proof from going stale silently between runs.
11. **Check `restoregap status`.** Its recovery inventory shows every
    declared drill's earned level (see Recovery levels above) PLUS every
    proof that has no drill at all (an attestation — evidence ingested,
    never actually drilled), sorted weakest first — the honest picture of
    what actually comes back, and to what point. A `data-valid` ceiling you
    meant to be `data-valid` is a fine, honest result; a `declared` row you
    thought was `serves` is the gap this whole loop exists to catch. Pass
    `--context` more than once (`restoregap status --context a.yml
    --context b.yml ...`) to see several context files as one machine —
    real deployments typically keep one context file per drill, since each
    drill's own timer rewrites its own proof into that same file.

`drill_lint` is also available over MCP (same checks, read-only, takes
`context_path`) for an agent working through a chat interface rather than a
shell — running a drill for real stays CLI-only by design; see
`internal/mcpserver/mcpserver.go`'s package doc for why.

## Worked example: a sqlite database, restored from a generic snapshot tool

Every path below is fake. Replace `recover:`/`pin_check:` with whatever your
actual backup tool uses, and replace the checks with your own real
invariants — this is a shape to copy, not a config to paste unmodified.

```yaml
version: 2
drills:
  - proof: app-db-recovery
    artifact: /srv/app/data.db
    recovery_source: /backups/app
    recover: |
      snapshot-tool restore --repo "$RG_RECOVERY_SOURCE" --latest --target "$RG_TARGET"
    pin_check: snapshot-tool snapshots --repo "$RG_RECOVERY_SOURCE" --latest >/dev/null
    budgets:
      rto: 10m
      rpo: 26h
    validate:
      - type: sqlite
        integrity: true
        tables:
          orders: ">= 500"
          users: ">= 10"
        freshness:
          table: orders
          column: created_at
      - type: command
        run: |
          sqlite3 "$RG_TARGET" \
            "SELECT COUNT(*) FROM orders WHERE user_id NOT IN (SELECT id FROM users)" \
            | grep -qx 0
```

The full file is checked in at `examples/drill-sqlite.yml`, including a
commented-out `serve` check (the L4 pattern from above, against a generic
app binary) — uncomment it once you have a real one to boot. Lint it, then
run it, against your own copy with your own paths:

```console
$ restoregap drill --lint --context examples/drill-sqlite.yml
$ restoregap drill --context examples/drill-sqlite.yml
```
