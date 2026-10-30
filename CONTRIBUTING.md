# Contributing

Thanks for looking. A few things that will save us both time.

## The rules that will not bend

Restore Gap is small on purpose. Before you write code, know what will not be
merged no matter how well it is done:

- **Nothing that reads secret values.** Metadata only (names, counts,
  fingerprints). The `Inventory` type has nowhere to put content, and that is
  deliberate.
- **Nothing that phones home** or adds a network dependency to the core
  binary. Update checks included.
- **Nothing that turns `preflight` into a warning.** It is a gate. A recovery
  gap blocks or it is not a gap.
- **No new configuration for `check`.** Its entire value is that it takes two
  paths and needs nothing else. `--exclude` / `.restoregapignore` is the one
  filter it has (a real config dir drowns in `.bak` snapshots without it) and
  it should stay the only one.

Ideas outside those lines are still worth an issue — just open the discussion
before the pull request.

## What is genuinely wanted

- **Real drills.** A `drills:` block that proves recovery of something you
  actually run (Postgres, restic, borg, a Docker volume, a Home Assistant
  config, …), with typed `validate:` checks. See `docs/drill-authoring.md`
  and `examples/`. These are the highest-value contributions — each one is
  a recovery someone else no longer has to work out from scratch.
- **Bug reports with a reproduction.** `restoregap` output plus the smallest
  fixture that shows it. Anything from a fresh machine or an unusual platform
  is especially useful.
- **README friction.** If a step in the 60-second story did not do what the
  README says, that is a bug in the README or the tool, and either way it is
  wanted.

## Mechanics

```console
$ go test ./...
$ go vet ./... && gofmt -l .
$ make reuse-lint
```

Keep pull requests to one change. Tests live next to the code they cover;
golden fixtures under `testdata/`. Commit messages say *why*, not just what.
The demo gif is regenerated with `make demo` (needs `vhs`); do not hand-edit
it.

New source files carry two SPDX lines at the top (any comment style the
language has):

```go
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol
```

Files that cannot carry comments — generated output, golden fixtures, images,
JSON, platform-managed files — are declared in `REUSE.toml` instead.
`make reuse-lint` checks the lot (REUSE spec; it skips with a notice if the
`reuse` tool is not installed — see the pinned install line in the
`Makefile`).

MIT licensed; by contributing you agree your contribution is too.
