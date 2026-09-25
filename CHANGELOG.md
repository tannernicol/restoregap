# Changelog

All notable changes to Restore Gap. Format follows Keep a Changelog; versions
follow SemVer. Pre-1.0: minor versions may change flags or file formats, and
each such change is called out here.

## [Unreleased]

## [0.11.6] — 2026-09-25

- The agent hook now matches declared guards on both the lexical and the
  canonical form of a path, so a workspace or temporary directory reached
  through a symlink (macOS keeps `/var` under `/private/var`) no longer lets a
  guarded change through. Aliases apply to matching only; proof validation is
  unchanged.

## [0.11.5] — 2026-09-24

- The agent hook can now keep its intent files outside an unavailable temporary
  directory. Set `RESTOREGAP_RUNTIME_DIR` to choose its runtime directory; when
  it is unset, Restore Gap falls back through the XDG runtime and state
  directories before using the system temporary directory.
- If the hook cannot write its intent, it enters explicit degraded mode: an
  unguarded operation proceeds with a once-logged note, while an operation that
  matches a declared guard is denied and reports the storage error. A missing
  runtime directory must never silently weaken a declared recovery gate.
- The README now links to the companion [deadman](https://github.com/tannernicol/deadman)
  template: an off-property GitHub Actions watcher for a host that stops
  emitting its expected heartbeat.

## [0.11.4] — 2026-09-20

- The agent hook now says why it allowed: it names the proof a declared guard
  cleared the proposal on, or states that no guard matched and the verdict
  rests on declared coverage rather than a drill proof. Both are allowed; only
  the first is evidence, and an agent must not read them as the same answer.

## [0.11.3] — 2026-09-19

- Agent-first install: `restoregap agent install claude|gemini|cursor` writes
  the pre-tool hook and the MCP server entry into the agent's settings file,
  idempotently, and prints the diff. `restoregap agent hook <vendor>` answers
  in the vendor's own decision format with the reason, the required proof and
  the exact drill command. A Claude Code plugin manifest (`.claude-plugin/`)
  installs the same hook and MCP server; its launcher denies fail-closed when
  the binary is not on PATH.
- `restoregap discover` reports every coding agent found on the host and
  whether the recovery gate is wired, with the install command as the gap.
- MCP tools carry honest `readOnlyHint` annotations and titles.
- The README first screen and the landing page lead with the agent workflow:
  install, deny with reason, drill, allow, ledger.
- The dashboard names a pass that matched no declared guard instead of
  showing it as proven. `make release-status` reports whether a release is
  lined up to publish.

## [0.11.2] — 2026-09-19

- The README opens with a compact SQLite decision-and-ledger example, and the
  landing page names that concrete workflow before explaining the architecture.
- The example agent hook refuses unrecognized operations when strict coverage
  is enabled. Default passthrough behavior stays compatible. This is a narrow
  hook, not a general shell parser or an operating-system security boundary.

## [0.11.1] — 2026-09-19

Native macOS release verification exposed Linux assumptions in test fixtures.
Configuration-discovery tests now isolate HOME and use the platform's actual user
configuration directory. GPG fixtures use short, unique temporary homes so
macOS socket path limits do not prevent key generation. Runtime behavior and
file formats are unchanged from 0.11.0.

## [0.11.0] — 2026-09-19

The local decision layer now binds recovery evidence to the tested recipe and
explains each decision in the CLI, dashboard and ledger.

- Opt-in `preflight --require-coverage` and MCP `require_coverage` check every
  supplied resource. A mixed covered/uncovered proposal blocks with the missing
  resource named. Declared recovery dependency changes invalidate affected proofs
  across the whole proposal.
- New drill proofs record recipe/dependency binding; `require_bound: true` lets
  guards require it. Version-2 signatures cover decision-bearing metadata.
  Legacy evidence remains readable and explicitly identified.
- Recovery and verifier subprocesses have a configurable deadline, bounded output
  and process-group cleanup. Proof updates use a validated atomic transaction
  under a stable lock; concurrent updates preserve each other's records.
- `ledger show` presents proposals, decisions, supporting evidence, next steps and
  owner overrides with chain health. The dashboard surfaces the latest decision.
  Evaluation never applies the proposed change; local recording remains allowed.
- `bundle export --summary-only` creates a bounded signed offline JSON handoff
  excluding raw configuration and operational text. Verification requires an
  independently trusted `--expected-key`. Full archives retain their format and
  optionally accept the same expected-key check.
- The example agent hook reads its event once and includes move destinations;
  regression fixtures cover destructive operations that previously bypassed it.
- Architecture, agent integration, restic first-drill and review-handoff guides
  describe the supported scope and trust boundary. No hosted service or
  provider-aware infrastructure adapter is added.

Compatibility: existing guard defaults and preflight exit codes remain stable.
New optional ledger fields preserve old records; use the new binary to append
to a ledger containing new records. Bound-proof requirements are opt-in for
existing contexts. Explicit drill commands can execute configured recovery
commands; the evaluator remains read-only over target systems.

## [0.10.1] — 2026-09-18

Release packaging and first-run documentation now match the local gate:

- the installer validates the selected release tag and exact archive checksum
  before extracting or installing, with both `sha256sum` and macOS `shasum`
  paths;
- the demo refuses symlinks and non-empty output directories, works with
  macOS-compatible shell utilities, and has an isolated end-to-end runner;
- README and walkthrough language describe the opt-in local gate without
  implying universal command interception or an operating-system sandbox.

## [0.10.0] — 2026-09-18

Closes the blind spot the 0.9.x line never answered: `check`/`drill`/`preflight`
all start from something *declared*, so they could only ever say "is what I
declared still recoverable?" — never "what did I never declare?"

- **`restoregap discover`** — enumerate recovery candidates on this host
  (databases over 64KiB, containers' writable bind mounts, git repos with no
  remote or with commits not on any remote-tracking branch, systemd user
  units whose state lives under `$HOME`, the machine-id/package-manifest/etc
  floor) and diff them against declared proofs/guards; a candidate is
  "covered" only when a drill's `artifact`/`recovery_source` or a guard's
  matched path already names it. `--trend` prints the last 10 scans as a
  coverage table; `--prompt` emits a ready-to-hand agent brief ranked by
  consequence; `--all` lists covered candidates too. Also exposed as an MCP
  `discover` tool. A follow-up pass suppressed noise, ranked findings by
  consequence, and deduped bind-mount paths.
- `preflight` now blocks deleting or moving a **directory above** a guarded
  path: `rm -rf ~/.ssh` fires a guard on `~/.ssh/id_ed25519` even though the
  key is never named (a subtree delete destroys it). Applies to `delete_file`
  and `move_file`, not `modify_file`; the finding names both paths.
- **Security fix:** command guards were bypassable with an absolute path —
  a guard matched on a relative form could be walked around by spelling the
  same path absolutely.
- **fix(ledger):** every entry is fsynced before the lock is released.
  "Recorded" used to mean "in the page cache" during exactly the crash the
  ledger exists to survive.
- `status`/`preflight` now discover every `*.yml` context file in the user's
  config directory, not just an explicit `--context`/`$RESTOREGAP_CONTEXT`
  path.
- `restoregap accept --reason` and `restoregap next` — accept a proof gap
  with a recorded reason, or ask "what's the highest-consequence thing to
  drill or accept next" and get one exact command back. `status` gained a
  recovery taxonomy (layer → category → proof), environment/scope roll-up,
  and a "to green" panel.
- `restoregap explain <proof>` — a proof's recovery level, evidence, and
  which guards it satisfies, in one place. Preflight renders human-readable
  on a TTY (falls back to markdown when piped), reports a context-file
  count, and splits the net statement into restored vs. attested-only.
- A passing decision now clears only the guards it actually blocked, not
  every guard in scope (`fix(dora)`).
- `status`'s "expiring soon" window is relative to each proof's own
  lifetime, not a fixed constant.
- **Enterprise:** host identity/epoch, policy revisions, signed bundles, and
  offline fleet merge — a policy and its proofs can now be authored on one
  machine and merged onto another without a network round-trip.
- **Ratchet:** overrides are dated exceptions, and `protect-check` refuses a
  diff that rewrites the very rules it is graded by.
- `restoregap.com` landing page (mobile UI gate applied); long install-line
  code no longer gets cut off on narrow screens.
- Release engineering: SPDX headers on first-party sources (REUSE spec),
  goreleaser now produces SPDX+CycloneDX SBOMs, checksums, and a
  reproducible build (`-trimpath`, pinned module timestamps); cosign
  keyless signing is wired in but stays commented out until launch. CI
  release workflow refuses to cut a tag that leaves the README install pin
  stale.
- `docs/examples`: a portable remote-config snapshot producer
  (`ssh host → local dir or rclone remote`).

## [0.9.2] — 2026-08-17

The launch follow-ups, each one traceable to a real run on the author's machine.

- `action.yml`: a composite GitHub Action (`restoregap-preflight`) that
  installs the release binary, preflights the PR diff against `diff-base`,
  writes the rendered report to the job summary, and fails the check on
  `block` (or `warn`, with `fail-on: warn`). See `docs/github-action.md`.
- Copy: `ledger verify` prints "acknowledged repair(s)" instead of "anchored
  anomaly/anomalies"; `status` inventory summary line now reads "N of M
  provably restorable (restores or better) · K boot and serve".
- `preflight --plan`: evaluate and print the verdict exactly as a normal run,
  but append nothing to the ledger. A 10-minute readiness timer
  re-preflighting the same two unexecuted intents wrote ~3,000 identical
  warn entries in a week — a plan is not a decision.
- `preflight` renders plain text instead of markdown when stdout is an
  interactive terminal and `--format` was not given (piped/CI output keeps
  the markdown default; explicit `--format` always wins).
- `check --exclude <glob>` (repeatable) and a `.restoregapignore` file
  (gitignore-style globs, one per line, `#` comments) read from `<live>` when
  present: matching entries are dropped from both sides before comparison
  and never counted as missing/stale/only-in-recovery. Found by dogfooding
  `check` against `~/.config/restoregap`'s own backup: 403 reported
  "missing" entries, 400 of them `restoregap.local.yml.bak.*` snapshots.

## [0.9.1] — 2026-08-17

Found by dogfooding on the author's own estate the same day 0.9.0 was cut:
thirteen green drills lived in one file each, and the gate read one file, so a
coding agent deleting the money database passed with no findings.

- `preflight`/`status --context` is now repeatable and merges every declared
  file's guards/facts/proofs/drills (`contextspec.LoadAll`); a duplicate id
  across files is a hard error naming both, never a silent last-wins. The
  MCP server applies the same `$RESTOREGAP_CONTEXT`/`restoregap.local.yml`
  discovery when a tool call omits `context_path`, instead of silently
  falling through to the built-in default policy.

## [0.9.0] — 2026-08-17

First tagged release. Everything before this shipped from `main` and reported
`0.0.0-dev`.

### The three rungs
- `restoregap check <live> <recovery>` — zero-config drift: what exists in
  exactly one place, and what exists in both but is stale in the copy you
  would restore from. Exit 1 on drift, so it can sit in cron or CI today.
- `restoregap drill` — prove a recovery for real, using a temporary working area: `recover:`
  command + typed `validate:` checks (sqlite integrity/row-counts/freshness,
  git fsck/refs, file trees, key fingerprints, byte-identical, arbitrary
  command) + measured RTO/RPO against declared budgets. Proofs are
  ed25519-signed and **expire by default**. `drill propose <artifact>`
  measures a live artifact and writes a complete, loadable
  `restoregap.local.yml` (drill + guard). `--lint` and `--calibrate` keep
  declared floors honest.
- `restoregap preflight` — the gate: an intent file, a git diff, or a
  Terraform plan is refused until the recovery it depends on is proven and
  fresh. Owner overrides are first-class and audited. Ships with built-in
  guards for SSH keys and recovery bundles that apply with **no** config.

### Around them
- Append-only, hash-chained decision ledger (`restoregap ledger verify`),
  discovered from `$RESTOREGAP_LEDGER` / `$XDG_STATE_HOME`.
- `restoregap status` — guards, proof freshness, and the recovery inventory
  (what provably comes back, to what level, and how old the proof is).
- `restoregap saves` — provable near-misses: changes the gate refused that
  would have broken a recovery.
- `restoregap mcp serve` — the same gates as MCP tools for coding agents.
- `restoregap evidence ingest|export` — the drill record as a self-contained
  file for whoever asks whether you *test* restores.
- `docs/walkthrough.md` carries the full transcript; the README first screen is
  one sentence, the demo, and a quick start.
- One static binary per platform (linux/darwin × amd64/arm64) with a
  `checksums.txt`; the README demo is recorded from `demo/setup.sh` so the
  gif cannot drift from what the CLI prints.
