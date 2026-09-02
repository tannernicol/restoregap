# Why this isn't a 40-line script

The first version of this *was* a script: `diff -rq live backup && echo ok`.
Every bullet below is a way that script lied, found while running Restore Gap
against one real estate (13 lifelines, ~38 proofs) for a summer. None of them
is exotic. All of them are what "do my backups work?" actually means.

## Five things a "backup exists" check cannot tell you

1. **Existing is not restorable.** A file that is present, the right size, and
   yesterday's date can still fail to open. The only test is a restore into a
   sandbox with a typed check on the result — `file_tree` must-exist, a
   `command` validator, or a data-level check like `users=95 (>= 90% of live
   100)`. Restore Gap records *which level* passed (L1 bytes → L3 data-valid),
   so a green never means more than it proved.

2. **Unreachable is not failed — and neither is "stale".** A NAS that is
   offline at 3 a.m. must not be reported the same way as a copy that restored
   and came back corrupt; and a credential store whose sealed copy is three
   entries behind the live one (1,303 vs 1,300) must be reported as *drift*,
   not as "backup OK, file present". Three distinct outcomes, three distinct
   status lines, all fail closed for gating. Conflating them was the first
   real bug found in dogfood.

3. **A proof has a half-life.** A restore that worked in July is a memory in
   August. Every proof carries an expiry; attestations nobody re-observes go
   cold and get flagged. The retention of the thing you restore *from* must
   outlive the proof — restic pruning at 2 days under a 30-day proof was the
   second real bug. A script has no notion of either clock.

4. **Direction matters.** "Different" is not a finding. Newer-in-live means
   the backup is behind; newer-in-recovery means the live side is what got
   corrupted. `check` reports them differently because the remediation is the
   opposite. (Third real bug: the first version couldn't tell.)

5. **Races are real.** A drill that runs 25 seconds before the nightly
   regeneration of the artifact it verifies will fail honestly and wrongly.
   Proof windows, timers, and drills have to be reasoned about together.

## Why the gate is the hard part, not the diff

- **Fail-closed with a paper trail.** A change is refused until the proof
  exists *and is fresh*; every verdict, proof, and owner override goes into
  a hash-chained ledger you can verify (`restoregap ledger verify`). Warn-only
  tools get ignored inside a week — we measured it.
- **Plans are not decisions.** Readiness probes that re-evaluate the same
  unexecuted intent every ten minutes go to a separate ledger, or they flood
  the real one (~3,000 identical lines a week, also measured).
- **One verdict, several doors.** An intent file, a diff, a Terraform plan,
  and an MCP tool call must all reach the same answer for the same change —
  `parity-drill` proves it, every release.
- **Zero-config safety.** With no configuration at all, SSH private keys and
  recovery bundles are already guarded. The things you would forget to declare
  are the things you cannot afford to lose.

## Secrets: there is nowhere for the content to go

The comparison type (`Inventory`) has no field for file contents. Secret
stores are compared by fingerprints over *ciphertext*; the reseal path works
in a RAM-backed tmpfs, passes the passphrase over a file descriptor (never
argv, env, or logs), and installs the new sealed copy only after a round-trip
decrypt and a count that is ≥ the previous one — otherwise it rolls back.
Read `SECURITY.md` for the contract; report anything that contradicts it.

## What is honestly still thin

- When a drill fails, the ledger records *that* it failed, not yet the failing
  validator's first line. (Tracked; post-launch.)
- The OSS translation from a shell command to an intent covers `rm <path>`
  today (`docs/examples/preflight-hook.sh`); the broader mapping lives in a
  private wrapper and is being ported.
- `check` sees directory trees and secret stores. Restic, borg, and ZFS
  comparators are built in vote order — [issue #2](https://github.com/tannernicol/restoregap/issues/2).

If you would rather build this yourself: take the bullets above as the test
list. That is the part that took the summer, not the code.
