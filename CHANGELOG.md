# Changelog

All notable changes to Restore Gap. Format follows Keep a Changelog; versions
follow SemVer. Pre-1.0: minor versions may change flags or file formats, and
each such change is called out here.

## [Unreleased]

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
- `restoregap drill` — prove a recovery for real, in a sandbox: `recover:`
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
