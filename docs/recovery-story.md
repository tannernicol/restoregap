# The recovery story — a policy set for "there is always a way back"

Restore Gap's one claim is: **there is always a proven, independent way back.**
A way back that depends on what just broke is not a way back.

This document is the policy that makes that claim *checkable*. It says what
must exist, what may share nothing, and what must be drilled — so the tool can
declare it, check it, and refuse a risky change until it holds. It is written
for one owner with a house full of machines and a couple of cloud accounts;
the same rules scale to a team by adding custodians.

Restore Gap never holds, reads, or decrypts a key or a locked copy. Everything
below is metadata: *where* things are, *what* they open, *when* they were last
proven. That boundary is structural (see ARCHITECTURE.md) and this policy is
designed to sit entirely on the metadata side of it.

## 1. Vocabulary

| Term | Meaning |
|---|---|
| **Lifeline** | Something whose loss ends the estate: the root key, the recovery kit, the offsite backup repository, the source of truth for config. |
| **Custodian** | A place a copy lives. Every custodian holds one of `key` (unlock material), `ciphertext` (the locked copy), or `both`. Kinds: `owner-memory`, `hardware-token`, `paper`, `trusted-person`, `this-host`, `local-nas`, `removable-media`, `cloud-account`, `second-machine`. |
| **Domain** | What dies together. `house` (fire, flood, burglary, a bad power event), one `cloud-account`, one `device`, `owner-memory` (forgot, concussion), `owner-person` (incapacity, death), `network`. A custodian sits in one or more domains. |
| **Path** | A complete way back: (key custodian, ciphertext custodian, written procedure) that ends in a restored, hash-verified file on a machine that is not yours. **A factor is not a path.** A YubiKey in a drawer is not a path; "YubiKey + the kit on Drive + the printed map + a fresh laptop → restored password store" is. |
| **Min-cut** | The smallest set of domains whose simultaneous loss disconnects every path. Min-cut 1 means one bad day ends everything, however many green checkmarks you have. |

## 2. The rules

**R1 — Any ONE path restores.** Never a threshold across the owner's own paths.
A 2-of-3 across passphrase / hardware token / phone turns every *correlated*
loss into a lockout: house fire takes the token and the paper together; a head
injury takes the passphrase and the PIN together. The enemy of recovery is
availability loss, not a thief holding two of your factors. The security of a
single-path unlock comes from **custody** (R4), not from a threshold.

**R2 — Min-cut ≥ 2 MUST, ≥ 3 SHOULD.** Named domains that must each be
individually survivable: `house`, `owner-memory`, and your primary
`cloud-account`. If losing any one of those disconnects every path, the
estate is red regardless of how many proofs are green.

**R3 — Owner-memory is a domain, and a PIN counts.** A hardware token that
needs a PIN and a memorized passphrase live in the *same* domain. At least one
path must need **nothing** from memory: a printed key, a trusted person, or a
token slot configured touch-only with no PIN. This is the incapacity rule —
the case where the tool shows three green paths and the family still cannot
get in.

**R4 — Key and ciphertext are never co-located at a non-owner custodian.**
The printed key goes to the trusted person or the safe-deposit box; the locked
kit goes to the cloud. Whoever obtains one of them has nothing. This is the
rule that makes R1 safe. A "just in case" USB with the kit handed to the same
person who holds the paper defeats it silently — declare custody honestly.

**R5 — Every copy of key material travels with a map.** What this is, what it
opens, where every ciphertext copy lives, which software and version opens it,
and the recipient fingerprint it was made for. The map is the tool's policy
file rendered for a human — pure metadata, safe to print, safe to hand to a
non-technical relative.

**R6 — Threshold splitting belongs at non-owner custodians only.** A 2-of-3
split among spouse / bank box / lawyer is right when no single outsider should
hold the whole key. It is never the *sole* lane, never applied to the owner's
own paths, and it costs a domain (the spouse's share sits in `house`). If you
use it: print the recombination instructions and a pinned tool hash on every
share, and drill it with the actual people. Heirs with three cards and no
working tool is the failure scenario.

**R7 — Cloud login factors are not unlock material.** An authenticator app,
push prompt, or SMS proves who you are *to a service*; it decrypts nothing
offline. A cloud account is a **custodian**, and it gets its own row: its
account-recovery path must itself satisfy R2 (backup codes printed and stored
in a different domain from the phone; a hardware token enrolled on the
account). Otherwise losing the phone loses the custodian, and an authenticator
that restores *via* the account is circular after phone loss. Storing raw key
material with a cloud provider to make the account a "path" appoints the most
frequently, arbitrarily, and appeal-lessly lost custodian a self-hoster has as
a trusted person. Refused.

**R8 — Solo drills.** Each path is drilled with every other path physically
absent (token unplugged, passphrase withheld, phone off), on a machine that is
not yours (live USB, fresh VM, borrowed laptop), starting from the printed map
only, ending in a hash-verified restored file. The common false pass: the
drill succeeds on your own workstation because the plugin, the VPN login, and
the backup cache are already there; the real recovery on a new laptop fails
because installing the plugin needs a network the recovery box cannot reach.
A path never drilled solo is an attestation, not a proof.

**R9 — Ciphertext custodians are drilled too.** A fresh-browser cloud pull, a
NAS pull over the out-of-band route, a removable-media read. A key in hand
with nothing to decrypt is the mirror-image failure of R8.

**R10 — Rotation is a metadata check.** Every wrapped copy records the
recipient fingerprint it was made for. After a root-key rotation, every copy
not re-made is stale and flagged — compared by fingerprint, never by opening
anything.

**R11 — Every path has a freshness bound.** Kit copy age, drill age, map age.
Past the bound the path is red, not "probably fine."

## 3. What this policy refuses

- A threshold across the owner's own paths ("2 of 3 among passphrase, token, phone").
- An authenticator app as an unlock path.
- Raw key material at a cloud custodian.
- A drill run on the owner's own workstation.
- A key copy without its map.
- A path that has never been walked end-to-end by someone other than the tool.

## 4. Worked example — a typical self-hoster, before and after

Before (very common, and every proof is green):

| Path | Key custodian (domain) | Ciphertext custodian (domain) |
|---|---|---|
| A | kit passphrase — `owner-memory` | kit on NAS (`house`), on Drive (`cloud-account`), on a thumb drive (`house`) |
| B | hardware token + PIN — `device` + `owner-memory` | same |
| C | GPG passphrase — `owner-memory` | protected key export on NAS / Drive / thumb |

Min-cut = **1** (`owner-memory`). Forgetting, a concussion, or incapacity ends
the estate while the dashboard shows three unlock ways. Also: the only
custodian outside `house` is one cloud account, so `{house, cloud-account}` is
a second cut of size 2.

After:

| Path | Key custodian (domain) | Ciphertext custodian (domain) |
|---|---|---|
| A | kit passphrase — `owner-memory` | kit on NAS, Drive, thumb, second laptop (`device-2`) |
| B | token #1 touch-only slot — `device-1` (no PIN) | same |
| B' | token #2 at the office — `office` | same |
| C | printed root key + map — `trusted-person` (R4: they hold no ciphertext) | same |
| D | Drive account row: printed backup codes — `paper-safe` (`house`), token #1 enrolled | — |

Min-cut = **3**: no single domain, and no pair of domains, disconnects every
path. C is the incapacity path (R3). Path C's key holder has nothing to
decrypt (R4). Each of A, B, B', C is drilled solo on a live USB (R8); Drive,
NAS, and thumb are each pulled fresh (R9).

## 5. How the tool carries this

Today: declare each path as a drill context (a `recover` command that walks
that path and restores a known file), guard the changes that could break a
path, and let `check` / `drill` / `preflight` do what they already do. The
NAS access proofs shipped in `docs/examples` (break-glass, off-box snapshot,
out-of-band route) are three paths for one lifeline and are the pattern.

Proposed (not yet implemented — tracked as a launch-bar candidate): a `paths:`
block in the context spec so the tool can compute R2/R3/R4/R10/R11 itself
instead of relying on the author to get the taxonomy right:

```yaml
lifeline: root-key
paths:
  - id: kit-passphrase
    key:        {custodian: owner-memory, domains: [owner-memory]}
    ciphertext: {custodian: cloud-account, domains: [cloud-account], copies: [nas, thumb, laptop-2]}
    recipient_fingerprint: "SHA256:..."
    drill: recovery-kit-solo-passphrase       # an existing drill context
    max_age: 30d
  - id: token-1
    key:        {custodian: hardware-token, domains: [device-1]}   # touch-only, no PIN
    ciphertext: {custodian: cloud-account, domains: [cloud-account]}
    ...
  - id: paper
    key:        {custodian: trusted-person, domains: [trusted-person]}
    ciphertext: {custodian: none}                                   # R4
    ...
policy:
  min_cut: {must: 2, should: 3}
  memory_free_path: required     # R3
```

`check` would report: min-cut and which domains form it, any path whose key
and ciphertext share a non-owner custodian (R4), any copy whose recipient
fingerprint is not the current one (R10), any path past `max_age` (R11), and
whether a memory-free path exists (R3). Nothing in that block is a secret.

## 6. One-page summary for the map (print this with every key copy)

1. Any one of the listed paths gets everything back. You do not need two.
2. If you are reading this because the owner cannot help: use the path marked
   *needs nothing from memory*.
3. Every path ends in the same place: a restored file whose hash matches the
   one printed here.
4. The people who hold a key hold no locked copy; the places that hold locked
   copies hold no key. Ask the tool (or this sheet) where each is.
5. If the recipient fingerprint on your copy does not match the one on this
   sheet, your copy is stale — use another path.
