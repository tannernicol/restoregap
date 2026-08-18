# Walkthrough — the 60-second story, in full

This is the complete transcript behind the demo gif and the README quick start.
Every line is the real output of the fixture in `demo/setup.sh`; run it and you
will see exactly this.

Three commands, each one earning the right to the next: a small project, a
"backup" of it that quietly went stale, and a coding agent about to delete the
database.

```console
$ demo/setup.sh /tmp/rg-demo && cd /tmp/rg-demo
$ export RESTOREGAP_LEDGER=$PWD/ledger.jsonl        # keep a try-out run out of your real ledger

# 1. Drift — no config. Does the copy you'd restore from still match the thing it protects?
$ restoregap check proj backup/proj
tree: 3 live / 2 recovery — 1 MISSING FROM RECOVERY, 2 STALE IN RECOVERY
  these exist in exactly one place:
    .env
  these exist in both but the recovery copy is out of date:
    app.conf
    app.db
next: turn this into a proof — restoregap drill propose proj
error: recovery copy is not faithful
$ echo $?      # 1 — and your nightly backup job said "success" the whole time

# 2. Proof — declare the drill by measuring the live artifact, then actually restore it in a sandbox.
$ restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml
$ restoregap preflight --intent rm-app-db.yml         # rm-app-db.yml: 5 lines of YAML, see below
context: restoregap.local.yml (discovered)
ledger: /tmp/rg-demo/ledger.jsonl (default)
# BLOCK
Restore Gap blocked this change. Supply proof, change the plan, or record an owner override.
- Refresh or supply proof "app-db-recovery", or record an owner override before proceeding.
…                                                     # verdict table + detail trimmed here
$ restoregap drill
context: restoregap.local.yml (discovered)
✓ app-db-recovery — data-valid (L3) in 0s: integrity ok; users=95 (>= 90% of live 100 = 90)

# 3. Gate — the same change is allowed now, and refused again the day that proof expires.
$ restoregap preflight --intent rm-app-db.yml
context: restoregap.local.yml (discovered)
ledger: /tmp/rg-demo/ledger.jsonl (default)
# PASS
Restore Gap found no unresolved recovery risk.
…
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
`action: delete_file`, `path: /tmp/rg-demo/proj/app.db`, `actor: agent/claude`,
`description: …`; `demo/setup.sh` writes it); a git diff (`--diff`) or a Terraform plan
(`--terraform-plan`) works too. `drill propose` writes a complete
`restoregap.local.yml` (drill + the guard that gates the artifact on it);
`restoregap context init` writes a starter one instead. Commands find that
file in the current directory without `--context`.


## Where the pieces live

- **The intent** (`rm-app-db.yml`) is what a person or agent is about to do:
  `version: 2`, `action: delete_file`, `path:`, `actor:`, `description:`. A git
  diff (`preflight --diff`) or a Terraform plan (`--terraform-plan`) is an
  intent too.
- **The context** (`restoregap.local.yml`) holds guards, drills and proofs.
  `drill propose` writes a complete one; `restoregap context init` writes a
  starter. Commands find it in the current directory, or via
  `$RESTOREGAP_CONTEXT`.
- **The ledger** is append-only and hash-chained (`restoregap ledger verify`),
  default under `$XDG_STATE_HOME/restoregap/`. Owner overrides are first-class
  and audited — never silent.
- **Built-in guards** protect SSH keys and recovery bundles even with no
  context at all.

Next: `restoregap status` (guards, proof freshness, what provably comes back),
`restoregap saves` (the changes the gate refused that would have broken a
recovery), and `docs/drill-authoring.md` for real drills (Postgres, restic,
Docker volumes, …).
