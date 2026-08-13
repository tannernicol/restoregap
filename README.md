# Restore Gap

**Recovery Policy as Code.** Declare what must stay recoverable, gate risky
changes on recovery *proof*, and export audit-ready evidence — the same
artifacts cyber-insurance underwriters and SOC 2 auditors ask for.

One static Go binary. No runtime, no agents, no phone-home. Every report is a
self-contained HTML file you can email, archive, or attach to an audit.

> Not a backup tool, not a linter. Restore Gap is the gate between "we have
> backups" and "we can prove a restore works" — before the change that would
> have made you find out the hard way.

## The 60-second story

```console
$ restoregap context init                 # declare your lifelines
$ restoregap evidence ingest --proof kit-restore-drill \
    --command "restic restore latest --target /tmp/drill" --expires-in 720h
$ restoregap preflight --intent delete-old-ssh-key.yml --context restoregap.local.yml
# BLOCK
Restore Gap blocked this change. Supply proof, change the plan, or record an owner override.
- Refresh or supply proof "ssh-key-recovery-copy", or record an owner override before proceeding.
$ echo $?                                 # 1 — your pre-commit hook / agent just stopped
```

Every decision lands in an append-only, hash-chained ledger
(`restoregap ledger verify`). Owner overrides are first-class and audited —
never silent.

## What it does

| Surface | Command |
|---|---|
| Gate a change (file/package/command intent, or a git diff) | `restoregap preflight` |
| Gate Terraform plans on RDS/S3/KMS recovery requirements | `restoregap preflight --terraform-plan` |
| Zero-config safety: SSH keys & recovery bundles blocked even with NO config | built in |
| Recovery-chain posture: guards, proof freshness, ledger health | `restoregap status` |
| Record proofs (hash-bound, optionally command-verified) | `restoregap evidence ingest` |
| Export framework evidence packets (cyber-insurance, SOC 2, ISO 27001, NIST, CIS, HIPAA, DORA) | `restoregap evidence export --framework soc2` |
| Scan a GitHub org for recovery gaps + vendor coverage limits | `restoregap scan` |
| Agents: same gates over MCP (8 tools, including drill_lint) | `restoregap mcp serve` |

The compliance mappings are primary-source-verified (`docs/COMPLIANCE_MAP.md`)
— including the carrier ransomware questionnaires that ask, verbatim, whether
you *test* restores. `direct` vs `supporting` strength is always labeled;
Restore Gap never overclaims a control.

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
