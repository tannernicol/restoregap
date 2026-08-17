# Restore Gap

**Prove your recovery works — then refuse the risky change until it does.**
Your recovery path can't depend on what just broke: Restore Gap finds the copy
that quietly went stale, restores it for real to prove it, and gates the
destructive change (yours or your coding agent's) on that proof.

One static Go binary. No runtime, no daemon, no account, no phone-home. Every
report is a self-contained file you can keep, diff, or hand to whoever asks.

> Not a backup tool, not a linter. Restore Gap is the gate between "we have
> backups" and "we can prove a restore works" — before the change that would
> have made you find out the hard way.

## The 60-second story

Three commands, each one earning the right to the next.

```console
# 1. Drift — no config. Does the copy you'd restore from still match the thing it protects?
$ restoregap check ~/proj /mnt/backup/proj
tree: 3 live / 2 recovery — 1 MISSING FROM RECOVERY, 1 STALE IN RECOVERY
  these exist in exactly one place:
    .env
  these exist in both but the recovery copy is out of date:
    app.conf
next: turn this into a proof — restoregap drill propose ~/proj
$ echo $?      # 1 — and your nightly backup job said "success" the whole time

# 2. Proof — declare the drill by measuring the live artifact, then actually restore it in a sandbox.
$ restoregap drill propose ~/proj/app.db --source /mnt/backup/app.db > restoregap.local.yml
$ restoregap preflight --intent rm-app-db.yml         # rm-app-db.yml: 5 lines of YAML, see below
# BLOCK — Refresh or supply proof "app-db-recovery", or record an owner override before proceeding.
$ restoregap drill
✓ app-db-recovery — data-valid (L3) in 0.2s: integrity ok; users=1210 (>= 90% of live 1210 = 1089)

# 3. Gate — the same change is allowed now, and refused again the day that proof expires.
$ restoregap preflight --intent rm-app-db.yml
# PASS
$ echo $?      # 0 — 30 days from now, without a fresh drill, it is 1 again
```

`check` needs no configuration and exits 1 on drift, so it can sit in cron or CI
today. `drill` turns a drifting copy into a **verified, expiring proof** — only a
real reconstruction counts (a `recover:` command that "succeeds" while restoring
garbage fails closed). `preflight` is the thesis: *prove your recovery works,
then refuse the risky change until it does.* Every decision lands in an
append-only, hash-chained ledger (`restoregap ledger verify`; default under
`$XDG_STATE_HOME/restoregap/`). Owner overrides are first-class and audited —
never silent.

`rm-app-db.yml` is the intent — a few lines of YAML (`version: 2`,
`action: delete_file`, `path: /home/user/proj/app.db`, `actor: agent/claude`,
`description: …`); a git diff (`--diff`) or a Terraform plan
(`--terraform-plan`) works too. `drill propose` writes a complete
`restoregap.local.yml` (drill + the guard that gates the artifact on it);
`restoregap context init` writes a starter one instead. Commands find that
file in the current directory without `--context`.

## What it does

| Rung | Command | Claim it lets you make |
|---|---|---|
| Drift | `restoregap check <live> <recovery>` | "these entries exist in exactly one place" — zero config, exit 1 on drift |
| Proof | `restoregap drill` (+ `drill propose`, `--lint`, `--calibrate`) | "this restored, byte-identically or by typed checks, inside its RTO/RPO budget" |
| Gate | `restoregap preflight` (intent / diff / Terraform plan) | "this change is refused until that proof exists and is fresh" |
| Posture | `restoregap status`, `restoregap saves` | guards, proof freshness, ledger health; provable near-misses |
| Zero-config safety | built in | SSH keys & recovery bundles blocked even with NO config |
| Agents | `restoregap mcp serve` | the same gates over MCP (8 tools, including drill_lint) |
| Evidence | `restoregap evidence export --framework soc2` | the drill record, exported for whoever asks whether you *test* restores |

The evidence packet is a by-product of the gate, not the product: the compliance
mappings in `docs/COMPLIANCE_MAP.md` are primary-source-verified, `direct` vs
`supporting` strength is always labeled, and Restore Gap never overclaims a
control — but the buyer is the engineer who wants a seatbelt, not the auditor
who wants a report.

## Install

Single binary, cross-compiled for linux/macOS:

```console
$ go install github.com/tannernicol/restoregap/cmd/restoregap@latest   # or grab a release binary
$ restoregap --version
```

## For agents (Claude Code, Codex, …)

Agents are the riskiest operators of your recovery surface. Add the MCP
server and every destructive intent gets preflighted against your declared
lifelines — fail-closed, ledgered, override-only-by-owner:

```console
$ restoregap mcp --print-config
```

## Develop

```console
$ go test ./...   # includes semantic-parity cases captured from the original implementation
$ go vet ./... && gofmt -l .
$ cd ui && npm run build && npm run check   # design-system bundle (committed in dist/)
```

Architecture: `docs/ARCHITECTURE.md`. UI system: `ui/README.md`. Authoring a
`drills:` block (agent-facing contract, worked example): `docs/drill-authoring.md`.
License: MIT.
