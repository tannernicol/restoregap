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

![restoregap: check finds the stale copy, drill proves the restore, preflight refuses the change until it does](demo/demo.gif)

**Who it's for:** anyone who runs their own machines — a homelab, a NAS, a VPS,
a dev box — and lets scripts or coding agents make destructive changes on them.
It answers one question before the change lands: *if this goes wrong, is there
a proven, independent way back?* It is not a backup tool, not monitoring, and
not a compliance dashboard.

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
error: recovery copy is not faithful
$ echo $?      # 1 — and your nightly backup job said "success" the whole time

# 2. Proof — declare the drill by measuring the live artifact, then actually restore it in a sandbox.
$ restoregap drill propose ~/proj/app.db --source /mnt/backup/app.db > restoregap.local.yml
$ restoregap preflight --intent rm-app-db.yml         # rm-app-db.yml: 5 lines of YAML, see below
context: restoregap.local.yml (discovered)
# BLOCK
Restore Gap blocked this change. Supply proof, change the plan, or record an owner override.
- Refresh or supply proof "app-db-recovery", or record an owner override before proceeding.
…                                                     # verdict table + detail trimmed here
ledger: ~/.local/state/restoregap/ledger.jsonl (default)
$ restoregap drill
context: restoregap.local.yml (discovered)
✓ app-db-recovery — data-valid (L3) in 0.2s: integrity ok; users=1210 (>= 90% of live 1210 = 1089)

# 3. Gate — the same change is allowed now, and refused again the day that proof expires.
$ restoregap preflight --intent rm-app-db.yml
context: restoregap.local.yml (discovered)
# PASS
Restore Gap found no unresolved recovery risk.
…
$ echo $?      # 0 — 30 days from now, without a fresh drill, it is 1 again
```

Trying it in a scratch directory? Every verdict is appended to the machine's
ledger, so point a throwaway run at its own file first:
`export RESTOREGAP_LEDGER=$PWD/ledger.jsonl` (or pass `--ledger`). The whole
walkthrough above is reproducible with `demo/setup.sh` — that is what the gif
was recorded from.

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
| Evidence | `restoregap evidence ingest` / `evidence export --framework soc2` | the drill record, exported for whoever asks whether you *test* restores |

The evidence packet is a by-product of the gate, not the product: the compliance
mappings in `docs/COMPLIANCE_MAP.md` are primary-source-verified, `direct` vs
`supporting` strength is always labeled, and Restore Gap never overclaims a
control — but the buyer is the engineer who wants a seatbelt, not the auditor
who wants a report.

## Install

One static binary, no dependencies. Linux and macOS, amd64 and arm64.

**Release binary** — from the [releases page](https://github.com/tannernicol/restoregap/releases):

```console
$ curl -sSfLO https://github.com/tannernicol/restoregap/releases/latest/download/restoregap_$(uname -s | tr A-Z a-z)_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz
$ tar -xzf restoregap_*.tar.gz restoregap && install -m 0755 restoregap ~/.local/bin/
$ restoregap --version
```

Every release ships a `checksums.txt` next to the archives — verify before you
run anything: `sha256sum -c checksums.txt --ignore-missing`.

**From source** (Go 1.25+):

```console
$ go install github.com/tannernicol/restoregap/cmd/restoregap@latest
```

Windows is not built yet — it is one line in `.goreleaser.yml` once someone
who runs it there asks.

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
