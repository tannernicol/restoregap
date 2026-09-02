# ENTERPRISE — running Restore Gap across many hosts

Everything below runs on the free, MIT binary, on your own machines, with no
account and no phone-home. This doc is "how a company with many hosts wires
it up", not a pitch for something that doesn't exist yet — see the end.

## The shape

1. **Org policy dir.** Ship a shared, read-only context tree (guards, no
   secrets) to every host — `/etc/restoregap` by convention, first in
   `RESTOREGAP_POLICY_DIRS`. It sets the floor every host inherits.
2. **Per-host contexts.** Each host keeps its own proofs, drills, and local
   guards in `$XDG_CONFIG_HOME/restoregap`, second in the search order. A
   host may add guards or tighten an org guard (stricter enforcement, more
   required proofs, a shorter max age) — never loosen or remove one. A
   loosening attempt is reported and ignored, never silently applied
   (docs/SCHEMA.md §5).
3. **Bundles pushed to a share.** Each host runs `restoregap bundle export`
   (cron, CI, or a timer) and drops the signed `.tgz` onto shared storage —
   S3, an internal share, a Gitea/GitHub artifact, whatever you already use
   to move files between hosts. Nothing calls home; the binary never
   initiates that push itself.
4. **`bundle merge` → fleet page.** One place (a laptop, a CI job, a cron
   box with read access to the share) runs `restoregap bundle merge
   host-a.tgz host-b.tgz ... --out fleet/`. Every bundle is verified before
   it is trusted; a tampered or corrupt one aborts the whole merge. The
   result is `fleet.json` (machine-readable) and `fleet.html` (a
   self-contained dashboard: environment × system roll-up, then the full
   layer tree with a host column) — open it locally, or serve it from
   wherever you already serve internal static pages.
5. **History and audit trail.** `restoregap history <proof-id>` on any one
   host answers "when was this last proven, by whom, under which policy" —
   the local ledger is the source of truth; nothing needs a central
   database to answer that question for a single host.

## What a hosted tier would add (not built, not started on speculation)

A single binary structurally cannot give you *time* and *breadth* across an
estate: drift trends over months, every host's fleet view already merged
without you running `bundle merge` by hand, retention scaled to host count,
alerts when a bundle stops arriving, and a verify URL a third party (an
auditor, a customer) can check without shelling into any of your boxes.
Retention × hosts is the actual pricing axis — a 3-host estate and a
300-host estate are not the same product.

None of this exists yet. It will not be built speculatively; see the
interest-check issue linked from the README.

## What it never does, hosted or not

- **No agent.** No daemon runs on your hosts beyond what you already invoke
  yourself (a cron job, a CI step, a timer unit you own).
- **No phone-home from the binary.** `restoregap` never makes an outbound
  network call on its own initiative. Bundles move because *you* push them
  somewhere; the binary never uploads anything itself.
- **No data it wasn't handed.** A hosted tier only ever sees what a bundle
  you pushed contains — context files, a ledger slice, proof-evidence
  metadata (never evidence file contents, never anything under a secret
  store path). It never reaches into a live host to look for more.
