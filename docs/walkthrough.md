# Walkthrough

This walkthrough uses the same fixture as the README. It is a local gate
story: a recovery copy has drifted, a declared proof is missing, and a local
intent stays blocked until a drill records a fresh result.

The fixture requires `sqlite3`. From a checkout of the release tag:

```console
$ demo/setup.sh /tmp/rg-demo
$ cd /tmp/rg-demo
$ export RESTOREGAP_LEDGER=$PWD/ledger.jsonl
$ export RESTOREGAP_CONTEXT=$PWD/restoregap.local.yml
```

## 1. Find drift

```console
$ restoregap check proj backup/proj
```

The command compares the declared live and recovery paths and exits 1 when
they differ. It does not inspect inside a restic, borg, or ZFS repository.

## 2. Declare and gate a recovery

```console
$ restoregap drill propose proj/app.db --source backup/app.db > restoregap.local.yml
$ restoregap preflight --intent rm-app-db.yml
```

The first preflight is expected to block because `app-db-recovery` has no fresh
proof. The context is a declaration for this local gate; review it before
running the recovery command it contains.

## 3. Run the drill, then allow the change

```console
$ restoregap drill
$ restoregap preflight --intent rm-app-db.yml
```

The drill records a verified proof only when the declared recovery and its
checks pass. The second preflight can then pass for the matching guarded
intent. Proofs expire by default, so the same intent blocks again after the
proof's validity window unless a new drill is run.

`restoregap drill` uses a temporary working area for the declared recovery
operation. Restore Gap does not provide an operating-system sandbox or protect
arbitrary commands; isolation and permissions remain properties of the
recovery command and the host where you run it.

## 4. Read the decision, then verify the record

```console
$ restoregap ledger show "$RESTOREGAP_LEDGER" --limit 10
$ restoregap ledger verify "$RESTOREGAP_LEDGER"
```

The history connects the proposed database deletion to the missing-proof block,
the recorded drill, and the fresh-proof pass. Each new decision retains its
reason, evidence and next step. These are decisions: Restore Gap did not delete
the database. An external caller decides whether to apply the proposed change.

The ledger is append-only and hash-chained. It records drill results and gate
decisions, including owner overrides. Pointing `RESTOREGAP_LEDGER` and
`XDG_STATE_HOME` at the fixture keeps this walkthrough away from your normal
state.

For the complete isolated run, use `demo/run.sh` from the checkout. It executes
the same flow and checks each expected exit status without relying on your
normal context or ledger.

For agents, `preflight --require-coverage` refuses supplied resources outside
declared guard coverage. The [agent integration guide](agent-gate.md) explains
where enforcement must live. For a reviewer on another machine, create an
[offline signed summary](evidence-handoff.md); the [restic example](examples/restic.md)
shows how to replace the fixture with a real backup source.
