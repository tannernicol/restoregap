# Restore Gap

**Prove your recovery works — then refuse the risky change until it does.**

[![release](https://img.shields.io/github/v/release/tannernicol/restoregap?include_prereleases&label=release)](https://github.com/tannernicol/restoregap/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/tannernicol/restoregap)](go.mod)

![restoregap: check finds the stale copy, drill proves the restore, preflight refuses the change until it does](demo/demo.gif)

Your backups exist. Your access is proven. The restore can still be dead — and
only a drill finds out. Restore Gap finds the copy that quietly went stale,
restores it for real to prove it, and gates the destructive change (yours or
your coding agent's) on that proof. One static binary, no account, no
phone-home. For anyone who runs their own machines and lets scripts or agents
change them. Not a backup tool, not monitoring, not a compliance dashboard.

## Quick start

```console
$ curl -sSfL https://raw.githubusercontent.com/tannernicol/restoregap/main/scripts/install.sh | sh   # or go install, below
$ restoregap check proj backup/proj          # zero config, exit 1 on drift — a project and its stale "backup"
tree: 3 live / 2 recovery — 1 MISSING FROM RECOVERY, 2 STALE IN RECOVERY
  these exist in exactly one place:
    .env
  these exist in both but the recovery copy is out of date:
    app.conf
    app.db
next: turn this into a proof — restoregap drill propose proj
```

Then turn the drifting copy into a proof, and gate the change on it:

```console
$ restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml
$ restoregap preflight --intent rm-app-db.yml   # BLOCK — proof "app-db-recovery" missing        (exit 1)
$ restoregap drill                              # ✓ app-db-recovery — data-valid (L3): integrity ok; users=95 (>= 90% of live 100)
$ restoregap preflight --intent rm-app-db.yml   # PASS — and BLOCK again the day that proof expires (exit 0)
```

Every line above is real output from the fixture in `demo/setup.sh`. Full
transcript, the intent file, and the ledger: **[docs/walkthrough.md](docs/walkthrough.md)**.

## What it does

| Rung | Command | Claim it lets you make |
|---|---|---|
| Drift | `restoregap check <live> <recovery>` | "these entries exist in exactly one place" — zero config, exit 1 on drift |
| Proof | `restoregap drill` (+ `drill propose`, `--lint`, `--calibrate`) | "this restored, byte-identically or by typed checks, inside its RTO/RPO budget" |
| Gate | `restoregap preflight` (intent / diff / Terraform plan) | "this change is refused until that proof exists and is fresh" |
| Posture | `restoregap status`, `restoregap saves` | guards, proof freshness, ledger health; provable near-misses |
| Zero-config safety | built in | SSH keys & recovery bundles blocked even with NO config |
| Agents | `restoregap mcp serve` | the same gates over MCP (8 tools, including drill_lint) |
| Evidence | `restoregap evidence ingest` / `evidence export --framework soc2` | the drill record, exported for whoever asks whether you *test* restores |

The evidence packet is a by-product of the gate, not the product: the compliance
mappings in `docs/COMPLIANCE_MAP.md` are primary-source-verified, `direct` vs
`supporting` strength is always labeled, and Restore Gap never overclaims a
control — but the buyer is the engineer who wants a seatbelt, not the auditor
who wants a report.

## Install

Linux and macOS, amd64 and arm64, one static binary. The installer downloads
the latest release, verifies it against the release's `checksums.txt`, and
puts it in `~/.local/bin` (never sudo):

```console
$ curl -sSfL https://raw.githubusercontent.com/tannernicol/restoregap/main/scripts/install.sh | sh
```

Or pick an archive from the [releases page](https://github.com/tannernicol/restoregap/releases)
yourself, or build from source: `go install github.com/tannernicol/restoregap/cmd/restoregap@latest`
(Go 1.25+). Windows is one line in `.goreleaser.yml` once someone who runs it
there asks.

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

## Docs

[Walkthrough](docs/walkthrough.md) · [Authoring drills](docs/drill-authoring.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md) · [Changelog](CHANGELOG.md) · MIT.
