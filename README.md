# Restore Gap

**Prove your recovery works. Then make the change.**

[![ci](https://github.com/tannernicol/restoregap/actions/workflows/ci.yml/badge.svg)](https://github.com/tannernicol/restoregap/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/tannernicol/restoregap?include_prereleases&label=release)](https://github.com/tannernicol/restoregap/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/tannernicol/restoregap)](go.mod)

Your backup job says **success**. Can you
recover the thing it protects, and is that proof still fresh when a risky local
change is about to happen?

Restore Gap is a local, MIT-licensed CLI. It records recovery proofs, evaluates
declared changes against those proofs, and keeps an append-only ledger. It does
not intercept every command, provide an operating-system sandbox, or replace
your agent's permissions and deny rules. The gate applies where you explicitly
wire it: a hook, a CI check, or the MCP server.

Demo recording: [watch the terminal recording](demo/demo.gif).

## Quick start

Install the v0.10.1 release, then run the isolated demo fixture. The demo needs
`sqlite3` because its fixture is a real SQLite database.

```console
$ curl -sSfLO https://raw.githubusercontent.com/tannernicol/restoregap/v0.10.1/scripts/install.sh
$ less install.sh
$ RESTOREGAP_VERSION=v0.10.1 sh install.sh
$ export PATH="$HOME/.local/bin:$PATH"   # use /usr/local/bin when installing as root
$ git clone --depth 1 --branch v0.10.1 https://github.com/tannernicol/restoregap.git
$ cd restoregap
$ demo/run.sh
```

`demo/run.sh` creates a fresh temporary fixture, points `RESTOREGAP_CONTEXT`,
`RESTOREGAP_LEDGER`, and `XDG_STATE_HOME` into it, then runs the real flow:
drift check, missing-proof block, drill, fresh-proof pass, expiry block, and
ledger verification. Pass a fresh empty directory to keep the fixture for
inspection: `demo/run.sh /tmp/restoregap-demo`.

The installer supports Linux and macOS on amd64 and arm64. It verifies the
selected archive against the matching entry in `checksums.txt` before it
extracts or installs anything. As a normal user it installs to
`~/.local/bin`; as root it installs to `/usr/local/bin`. It never asks for
sudo. The release also includes SBOM documents and reproducible build settings.

Or choose an archive from the [releases page](https://github.com/tannernicol/restoregap/releases),
or build from source with `go install github.com/tannernicol/restoregap/cmd/restoregap@latest`
(Go 1.25+).

## The local gate

The smallest useful loop is:

| Rung | Command | What it establishes |
|---|---|---|
| Drift | `restoregap check <live> <recovery>` | Which entries exist in exactly one place or differ today. |
| Proof | `restoregap drill` | Whether a declared recovery source can reconstruct the artifact and pass its checks. |
| Gate | `restoregap preflight` | Whether a declared intent, diff, or Terraform plan has a fresh proof for the guards it touches. |

`drill propose` measures a live artifact and writes a draft context. You review
that context, then run the drill. A proof expires; an expired proof does not
clear a guard. The ledger records decisions, drill results, and owner
overrides. Verify it with `restoregap ledger verify`.

The built-in policy covers SSH keys and recovery bundles even without a custom
context. For an agent integration, `restoregap mcp serve` exposes the same
preflight decision surface. The example hook in
[docs/examples/preflight-hook.sh](docs/examples/preflight-hook.sh) shows how a
narrow set of destructive command shapes can be translated into intents; it is
an example integration, not universal command interception.

## Five words

- **proof** — a recorded, expiring result of a real restore with its checks and recovery timing.
- **drill** — the declared recovery run that produces a proof.
- **guard** — a rule naming what must be proven before a matching change is allowed.
- **intent** — the change under evaluation: an intent file, diff, or Terraform plan.
- **ledger** — the append-only, hash-chained record of verdicts and overrides.

## What it does not claim

Restore Gap checks the recovery process you declare. It does not inspect inside
every backup product, make an undeclared recovery path safe, provide an OS-level
sandbox, or turn an agent into a generally safe operator. Your backup tooling,
host isolation, permissions, and agent controls remain responsible for those
parts. For restic, borg, or ZFS targets, see the
[comparators issue](https://github.com/tannernicol/restoregap/issues/2).

## A possible hosted layer

The binary is complete and stays free, local, offline, and MIT licensed. A
future hosted service is only a proposal: optional evidence retention and
custody, expected-proof monitoring over time, and private links for sharing a
recovery record. It does not exist yet, and no hosted feature is required to
use the CLI. If that would help, describe the workflow on the
[interest-check issue](https://github.com/tannernicol/restoregap/issues/1).

## FAQ

**I already have restic, borg, or ZFS snapshots.**

Good. Restore Gap sits beside scheduled verification and custom recovery
scripts as a local evidence and gate layer. `restoregap drill` records whether
the declared path worked and how long it took, then the guard ties that fresh
evidence to the local change it protects.

**My agent already has deny rules.**

Deny rules remain useful. Restore Gap adds a proof-based decision for the
specific guarded change you wire into it.

**Isn't this just `diff`?**

`diff` compares files. A drill performs the declared restore and records which
checks passed at that time. It cannot guarantee a future restore will succeed.

**Does it phone home?**

No account or telemetry is required. The CLI runs locally and makes network
calls only when your declared recovery command makes them.

## Docs

[Walkthrough](docs/walkthrough.md) · [Why not a script?](docs/why-not-a-script.md) ·
[Authoring drills](docs/drill-authoring.md) · [Discover](docs/DISCOVER.md) ·
[Agent gate](docs/agent-gate.md) · [GitHub Action](docs/github-action.md) ·
[Schema](docs/SCHEMA.md) · [The recovery story](docs/recovery-story.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md) · [Changelog](CHANGELOG.md) · MIT.
