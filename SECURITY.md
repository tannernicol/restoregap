# Security

Restore Gap's whole job is to stand between a risky change and your recovery
path, so a bug that lets a change through, or that leaks something it should
never have read, matters more than usual.

## What Restore Gap never does (report it if it does)

- It never reads, decrypts, stores, transmits, or prints a **secret value**.
  It compares metadata — names, counts, fingerprints. There is no code path
  for content, by design.
- It never phones home. No telemetry, no update check, no network calls
  except the ones *you* declare in a drill's `recover:` command.
- It never executes anything outside a drill you declared. `check`,
  `preflight`, `status`, `ledger`, `evidence` are read-only apart from the
  ledger append.

If you find behaviour that contradicts any of the above, that is a security
bug even if it "works".

## Reporting

Please **do not** open a public issue for anything that could be exploited.
Use GitHub's private vulnerability reporting on this repository ("Report a
vulnerability" under the Security tab). Include the version (`restoregap
--version`), the command, and the smallest reproduction you can. You will get
an acknowledgement within a few days; this is a one-person project, so a fix
may take a little longer than that — you will be told what to expect.

Anything that is a hardening suggestion rather than an exploitable bug is
welcome as a normal issue.

## Supported versions

Only the latest release. There is no backport branch.
