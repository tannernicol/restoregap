# First real proof with restic

Keep restic as the backup engine. Restore Gap records whether a particular
snapshot can reconstruct your application data and pass the checks you declare.
This example uses a SQLite database; use a consistent database backup rather than
copying a running database without its required journal files.

1. Set `RESTIC_REPOSITORY` and your usual restic credential mechanism in the
   environment of the operator running the drill. Keep credentials out of YAML.
2. Run `restic snapshots` and choose the snapshot you intend to test. Use its
   exact ID in the recipe, so a successful test refers to a specific snapshot.
3. Review this context. Replace the illustrative paths, snapshot ID, table name
   and minimum row count with your actual requirements.

```yaml
version: 2
guards:
  - id: app-database
    kind: lifeline
    match:
      paths: [/srv/app/app.db]
    requires:
      proofs: [app-recovery]
    require_verified: true
    require_bound: true
drills:
  - proof: app-recovery
    artifact: /srv/app/app.db
    recovery_source: /backups/restic
    recover: restic dump SNAPSHOT_ID /srv/app/app.db > "$RG_TARGET"
    dependencies:
      paths: [/backups/restic/**]
      packages: [restic]
    validate:
      - type: sqlite
        integrity: true
        tables:
          users: ">= 2"
proofs: []
```

The paths inside a restic snapshot may differ from the current live paths. Check
them with `restic ls SNAPSHOT_ID` before declaring the `dump` command. For a remote
repository, name the real source and explicitly declare relevant local credentials,
configuration or commands as recovery dependencies; a URL does not automatically
discover cloud IAM, networking or retention dependencies.

```sh
restoregap drill --lint --context restoregap.yml
restoregap drill --context restoregap.yml --timeout 10m
```

The drill is an explicit execution step. It writes the recovered database to a
temporary workspace, records a proof in the context file and appends a local drill
event. It does not restore over the live database. Your declared shell command
still runs with your permissions; review it as you would any restore script.

Before a proposed change, use a separate intent file:

```yaml
version: 2
action: modify_file
path: /srv/app/app.db
actor: agent/operator
```

```sh
restoregap preflight --context restoregap.yml --intent change.yml --require-coverage
restoregap ledger show
```

This step evaluates and records the decision; it does not modify the database.
Changing the tested recipe makes its old bound proof insufficient. Changing a
declared recovery dependency in the supplied proposal makes that proof insufficient
for the affected change. Unknown resources block when strict coverage is enabled.

The repository fixture for this documentation restored a two-row SQLite database
from a real restic snapshot, then passed SQLite integrity and row-count checks.
A recovery command that exited zero without writing `RG_TARGET` failed. Those
checks establish a scoped observation, not that every application dependency or
future disaster has been tested. A scratch fixture is not customer validation.

Source: [restic restore and dump documentation](https://restic.readthedocs.io/en/stable/050_restore.html).
