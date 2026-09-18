# Restore Gap

**Everyone tests the alarm. Nobody runs the drill.**

You know the drill.

*Prove your recovery works — then refuse the risky change until it does.*

[![ci](https://github.com/tannernicol/restoregap/actions/workflows/ci.yml/badge.svg)](https://github.com/tannernicol/restoregap/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/tannernicol/restoregap?include_prereleases&label=release)](https://github.com/tannernicol/restoregap/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/tannernicol/restoregap)](go.mod)

![restoregap: check finds the stale copy, drill proves the restore, preflight refuses the change until it does](demo/demo.gif)

> Your nightly backup job says **success**. That was the alarm test — nobody left the building.
> Restore Gap runs the drill: it restores the backup for real, in a sandbox, with a stopwatch, and writes down the result.
> Your coding agent goes to `rm app.db`. **BLOCK** — no proof. Under a second later: restored, 95 users, under budget. **PASS.**
> Thirty days later that proof expires and it's **BLOCK** again — on a clock, whether you feel like it or not. Look alive.

One static binary, MIT, no account, no phone-home. Built for people who run their
own machines and let scripts or agents change them.

## Quick start

```console
$ curl -sSfLO https://raw.githubusercontent.com/tannernicol/restoregap/v0.10.0/scripts/install.sh && sh install.sh   # pinned tag; verifies checksums

# Try it on the bundled fixture: a project, a "backup" that quietly went stale, an agent about to delete the db
$ demo/setup.sh /tmp/rg-demo && cd /tmp/rg-demo
$ export RESTOREGAP_LEDGER=$PWD/ledger.jsonl    # a recovery tool must not pollute your real ledger with demo entries

# The proof — a real restore in a sandbox, which diff can't give you:
$ restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml
$ restoregap preflight --intent rm-app-db.yml   # BLOCK — proof "app-db-recovery" missing        (exit 1)
$ restoregap drill                              # ✓ app-db-recovery — restored in 0.0s — data-valid (L3): integrity ok; users=95 (>= 90% of live 100 = 90)
$ restoregap preflight --intent rm-app-db.yml   # PASS — and BLOCK again the day that proof expires (exit 0)

# The zero-config front door — what exists in exactly one place (copy/rsync-style backups):
$ restoregap check proj backup/proj          # zero config, exit 1 on drift — a project and its stale "backup"
tree: 3 live / 2 recovery — 1 MISSING FROM RECOVERY, 2 STALE IN RECOVERY
  these exist in exactly one place:
    .env
  these exist in both but the recovery copy is out of date:
    app.conf
    app.db
next: turn this into a proof — restoregap drill propose proj
```

`check` compares directory trees today (and a secret-store shape). If your
recovery copy is a restic, borg, or ZFS target, it can't see inside it yet —
say which one you use on [the comparators issue](https://github.com/tannernicol/restoregap/issues/2)
and it gets built in order of votes.

Every line above is real output from the fixture in `demo/setup.sh`. Full
transcript, the intent file, and the ledger: **[docs/walkthrough.md](docs/walkthrough.md)**.

## Five words

- **proof** — a recorded, expiring result of a real restore (byte-identical or typed checks) with its RTO/RPO.
- **drill** — the sandboxed restore that produces a proof; `drill propose` writes one from a live artifact.
- **guard** — a rule naming what must be proven before a matching change is allowed.
- **change / intent** — the thing about to happen: an intent file, a diff, or a Terraform plan; agents send it over MCP.
- **ledger** — the append-only, hash-chained record of every verdict, proof, and override.

## What it does

| Rung | Command | Claim it lets you make |
|---|---|---|
| Drift | `restoregap check <live> <recovery>` | "these entries exist in exactly one place" — zero config, exit 1 on drift, `--exclude` (or `.restoregapignore` in `<live>`) drops known-noisy globs before comparing |
| Proof | `restoregap drill` (+ `drill propose`) | "this restored, byte-identically or by typed checks, inside its RTO/RPO budget" |
| Gate | `restoregap preflight` (intent / diff / Terraform plan) | "this change is refused until that proof exists and is fresh" |

With no config at all, SSH keys and recovery bundles are already guarded.
Why this is a tool and not a 40-line script: [docs/why-not-a-script.md](docs/why-not-a-script.md).
Agents get the same gates over MCP: `restoregap mcp serve` — see
[docs/agent-gate.md](docs/agent-gate.md). Restore Gap is the reason to
allow a guarded change; your agent's deny rules or sandbox are the general
net — see the shape table in
[docs/examples/preflight-hook.sh](docs/examples/preflight-hook.sh).

## Install

Linux and macOS, amd64 and arm64, one static binary. The installer (pinned to
a tag, so what you read is what runs) downloads the latest release, verifies
it against the release's `checksums.txt`, and puts it in `~/.local/bin` —
never sudo, never `curl | sh`:

```console
$ curl -sSfLO https://raw.githubusercontent.com/tannernicol/restoregap/v0.10.0/scripts/install.sh
$ less install.sh && sh install.sh
```

Or pick an archive from the [releases page](https://github.com/tannernicol/restoregap/releases)
yourself, or build from source: `go install github.com/tannernicol/restoregap/cmd/restoregap@latest`
(Go 1.25+). Windows is one line in `.goreleaser.yml` once someone who runs it
there asks.

Every release ships a `checksums.txt` next to the archives — verify before you
run anything: `sha256sum -c checksums.txt --ignore-missing`. Each archive also
carries SBOMs (`*.spdx.json`, `*.cdx.json`), and the build is reproducible
(`-trimpath`, pinned module timestamps), so a rebuild of the same tag matches
its checksum.

## For agents (Claude Code, Codex, …)

Agents are the riskiest operators of your recovery surface. `restoregap mcp
--print-config` gives you the MCP server; every destructive intent then gets
preflighted against your declared lifelines — fail-closed, ledgered,
override-only-by-owner.

## Free forever, and what a paid layer would be

The binary is MIT and complete: every rung above — drift, proof, gate, ledger,
MCP — runs locally, offline, with no account, and always will. Nothing is
withheld to sell later.

What a single binary structurally cannot give you is *time* and *breadth*:
drift over months, proofs across all your machines in one view, and a
recovery proof a third party can verify without shelling into your box. If the
free tool earns its keep, that hosted layer is the thing to pay for. It does
not exist yet and will not be started on speculation — if you would pay for
it, say so on [the interest-check issue](https://github.com/tannernicol/restoregap/issues/1)
and say what "all your machines" means for you (2? 20?). That number decides
whether it gets built.

Already running it on more than one host? `bundle export` + `bundle merge` gets you
that fleet view today, free — see [docs/ENTERPRISE.md](docs/ENTERPRISE.md).

## FAQ

**I already have restic / borg / ZFS snapshots.**
Good — that's the alarm. When did you last restore from one, and how long did
it take? `restoregap drill` answers that on a schedule and writes it down —
say which one you use on [the comparators issue](https://github.com/tannernicol/restoregap/issues/2).

**My agent already has deny rules.**
Deny rules are the net. Restore Gap is the reason you can say yes: the change
is allowed because the way back is proven and fresh.

**Isn't this just `diff`?**
`diff` proves two files match today. A drill proves you can come back
tomorrow, and how long it takes.

**Does it phone home?**
No account, no telemetry, no network calls except the ones your restore
needs. It doesn't have a home.

## Docs

[Walkthrough](docs/walkthrough.md) · [Why not a script?](docs/why-not-a-script.md) ·
[Authoring drills](docs/drill-authoring.md) · [Discover](docs/DISCOVER.md) ·
[Agent gate](docs/agent-gate.md) · [GitHub Action](docs/github-action.md) ·
[Schema](docs/SCHEMA.md) · [The recovery story](docs/recovery-story.md) ·
[Enterprise](docs/ENTERPRISE.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md) · [Changelog](CHANGELOG.md) · MIT.
