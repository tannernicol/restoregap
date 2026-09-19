# SCHEMA — Restore Gap's portability contract

This is the one place that pins down every on-disk/on-wire shape another
tool (or a future version of this one) needs to read: the context file
schema, the decision ledger's entry kinds, the portable bundle format, the
fleet merge key, the epoch rule, the tighten-only policy rule, and how all
of the above are versioned. Nothing here is aspirational — every field
named is a real Go struct field in `internal/contextspec`, `internal/ledger`,
or `internal/bundle`; grep those packages when this doc and the code
disagree, and trust the code.

## 1. Context file (`restoregap.yml` / `restoregap.local.yml`)

`version: 2` (current — see §6 Versioning). A context file declares:

- **`guards`** — the unified lifeline/guard concept. Each guard has an
  `id`, `kind` (`lifeline` | `guard`), a `match` (paths/commands/packages/
  actions/actors/context_windows — ANDed across fields, ORed within one),
  `requires: {proofs: [...], facts: [...]}`, `enforcement` (`block` | `warn`),
  optional `max_proof_age_hours`, `recovery_copy`, `alternate_paths`,
  `require_verified`, `require_bound`, and the taxonomy fields below.
- **`facts`** — a reviewed statement of ground truth: `id`, `statement`,
  `provenance`, and an expiry (`expires_at` or `max_age_days`).
- **`proofs`** — declared evidence a guard's `requires.proofs` may name:
  `id`, `status` (`observed` | `validated` | `stale` | `disputed` |
  `unreachable`), `observed_at`, `expires_at`, `sha256`, `evidence_url`,
  an optional Ed25519 `signature: {version, public_key, signature}` (hex keys), `verified`
  (a recorded full drill passed its configured checks), `command`,
  optional `recipe_digest` and captured `dependencies: {paths, commands, packages}`,
  `measurements` (RTO/RPO/per-check outcomes, drill-produced only), an
  optional `accepted: {by, at, reason, review_by}` (§"tighten-only" below
  never applies to acceptances — they are a per-proof owner decision, not a
  policy layer), and the **layer/category/scope/host/epoch** fields:
  - `layer` — one of the fixed vocabulary (§2), own-declared or falls back to
    the requiring guard's layer, then `unfiled`.
  - `category` — free-form subgroup within layer, no fixed vocabulary.
  - `scope: {environment, system, host, owner, tags}` — every field a free
    string except `tags` ([]string); a context file's own top-level `scope`
    is the default every guard/proof inherits, field by field, unless it
    overrides one itself.
  - `host: {name, id}` — the machine that recorded this proof (§4). Absent
    on hand-authored or pre-stamping proofs.
  - `epoch` — the epoch id (§4) the proof was recorded under. Empty means
    unstamped; a non-empty epoch that differs from the current machine's
    marks the proof "from a previous epoch — re-drill" (excluded from
    green, counts as unreviewed).
- **`drills`** — how one artifact is reconstructed and validated: `proof`,
  `artifact`, `recover`, `recovery_source`, `validate` (typed checks:
  `byte_identical` | `sqlite` | `git` | `file_tree` | `command` | `serve` |
  `key_fingerprint`), `budgets: {rto, rpo}`, optional `pin_check`, and explicit
  recovery `dependencies: {paths, commands, packages}`.
- **top-level `scope`** — the file's own organizational default (§ above).

### Recovery binding and signatures

New full drills record `recipe_digest` as a SHA-256 digest of the artifact,
recovery source, recovery/pin commands, typed checks, budgets and normalized
dependency lists. They also capture those dependencies on the proof. Both must
match the current drill declaration before bound evidence can satisfy a guard.
Changing a proof ID's recipe cannot silently reuse its old successful test.

`require_bound: true` rejects older, unbound evidence; it is opt-in for existing
guards. Combine it with `require_verified: true` when a guard needs a full drill.
Dependencies describe the recovery path, not automatically every live artifact.
The evaluator checks all supplied intents for changes to those declared paths,
commands or packages before accepting the affected proof. It performs no cloud
discovery or resource inspection. A change outside the supplied scope is unknown.

New signed full-drill records use signature `version: 2`: domain-separated,
structured JSON covers status, observation/expiry times, verification flag,
content hash, command, exact measurements/checks, recipe digest, dependencies and
stamped host/epoch. Signatures without `version` keep their legacy message format
and limited field coverage. They do not acquire v2 guarantees on import. An
unrecognized version fails validation. Origin is trusted only when the public
key is independently trusted; merely including a key with a record is insufficient.

Only generated evidence fields are replaced by a new drill or ingestion. Scope
metadata survives. A manual attestation cannot inherit an old drill's verified
flag, measurements, binding or signature. A pin check observes source reachability;
it cannot create a fresh full-recovery proof. All proof writes use a locked,
validated, atomic transaction with restrictive file modes preserved.

## 2. Layer and state vocabularies (frozen; extend by widening, never renaming)

Layers, in blast-radius order (`contextspec.LayerOrder`):
`recovery-kit` · `identity-secrets` · `system-os` · `infra-network` ·
`backups-offsite` · `git-code` · `data-apps` · `agents-context` ·
`cross-cutting` (guards only — never a proof's own declared layer) ·
`unfiled` (computed-only fallback: no declared layer, no requiring guard).

Proof states (`internal/status`, refined state model):
`restored` (recovery level reaches restores/data-valid/serves) ·
`observed` (declared level, but `observed_at`+`expires_at` both set and
still inside their own freshness window) · `accepted` (an active, non-lapsed
`accepted:` block) · `unreviewed` (everything else at declared level) ·
`disputed` · `expired` · `unreachable` · `lapsed` (an acceptance whose
`review_by` passed). The last four are jointly addressable as the
meta-value `attention`. This is the exact vocabulary `bundle merge`,
`fleet.json`, and `history` use — never a shortened or renamed subset.

## 3. Decision ledger (`internal/ledger`, schema 2)

Append-only JSONL, hash-chained: each `Entry` carries `schema`, `id` (ULID),
`created_at`, `entry_type`, `actor`, a closed-union `payload` (exactly one
field set, matching `entry_type`), `prev` (previous entry's hash, or the
genesis hash), and `hash` (SHA-256 over the RFC 8785/JCS canonical form of
the entry minus `hash`). Concurrency: one exclusive flock per ledger file
around the whole read-last-hash + write critical section, one `write()` per
entry — N concurrent writers never interleave. Durability: every entry is
fsynced before the flock is released, unconditionally (no option to skip
it) — a verdict that isn't actually on disk did not happen. A brand-new
ledger file's containing directory is also fsynced, best-effort, so the
file's existence itself survives a crash on a fresh ledger.

Entry types and what each payload records:

| `entry_type` | Payload fields | Meaning |
|---|---|---|
| `decision` | verdict, findings, actor, operation, executed, intents, evaluated_at, context_window, gate_state, broken_reason, checks, duration_ms, tool_version | one preflight evaluation |
| `override` | finding_id, approved_by, reason, expires_at, acknowledgement | an owner override of one finding |
| `acknowledgement` | finding_id, note | reviewed without changing verdict |
| `checkpoint` | entry_count, last_hash | a point-in-time chain summary |
| `drill` | proof_id, mode (`drill` \| `pin_check`), verified, level, rto_ms, rpo_ms, budget_rto_met, budget_rpo_met, checks | one drill or pin_check run. `history`'s vocabulary calls a `pin_check` entry "attest" — proof the pinned source still exists, without a full recovery |
| `chain_anchor` | entry_id, stored_hash, recomputed_hash, reason, approved_by | an owner-approved attestation for one historical hash mismatch (never an in-place repair — `prev` makes that impossible without cascading) |
| `accept` | proof_id, by, reason, review_at | an owner's `restoregap accept` |
| `accept_clear` | proof_id, by | clearing a recorded acceptance |
| `epoch` | label | a human-labelled epoch marker (`restoregap epoch new`); no gating effect |

Every entry optionally carries three portability stamps, all `omitempty`
(entries written before they existed re-encode byte-identically and their
hashes still verify):

- `host: {name, id}` — the machine that wrote the entry (§4).
- `epoch` — the epoch id in force when it was written (§4).
- `policy: {revision, files: [{path, sha256}]}` — the policy text in force
  (§5).

New decisions capture `operation: preflight`, `executed: false` (Restore Gap
did not execute the change) and the supplied intents, including paths,
destinations, commands, packages and actor. Findings retain their explanation,
proof description, next step and applied owner override. These optional fields
are snapshots, never reconstructed from today's policy. `ledger show` presents
them with chain health; legacy records explicitly lack proposal details.
`created_at` records the actual append time; `evaluated_at` separately identifies
the proof-freshness evaluation time, including a supplied `--as-of` simulation.
The local ledger can contain sensitive operational text; summary export excludes
it. New readers verify old records unchanged. Old binaries may not understand
the added fields and must not be used to append to a newer ledger.

`restoregap history <proof-id>` reads exactly this: every `drill`, `accept`,
and `accept_clear` entry naming the proof, oldest first, each line carrying
its date, recovery level (drill entries only), and its host/epoch/policy
stamps.

## 4. Identity & epoch (`internal/hostid`)

- `host.id` = `sha256(/etc/machine-id)[:16 hex]`, falling back to
  `sha256(hostname + first non-loopback MAC)[:16 hex]` when no machine-id
  exists (some containers).
- `epoch` = `sha256(machine-id + root filesystem UUID)[:12 hex]` — the UUID
  comes from `findmnt -no UUID /`, falling back to parsing `/proc/mounts`.
- **Epoch rule**: a proof or ledger entry's recorded `epoch` that differs
  from the current machine's `hostid.Current().Epoch` is evidence from a
  different world — a reinstall, a restored disk image, or a different
  machine entirely. It is never treated as currently valid, however fresh
  its own timestamps claim to be: `status` marks it "from a previous epoch —
  re-drill" and counts it unreviewed, excluded from green.
- Neither id is a secret; both exist to be compared, printed, and shipped
  inside bundles.

## 5. Policy revisions and the tighten-only layering rule

- **Policy revision** = SHA-256 over the sorted `(path, sha256)` list of
  every context file in force — same file set, same order of files,
  independent of the order they were *discovered* in, always produces the
  same revision. This is what `restoregap policy` prints and every
  `decision`/`drill`/`accept` ledger entry stamps itself with.
- **Layered policy** (`internal/policy`): `RESTOREGAP_POLICY_DIRS` (colon
  list, default `/etc/restoregap:$XDG_CONFIG_HOME/restoregap`) orders
  context directories org-first, host-last. Facts/proofs/drills merge by
  union (a duplicate id across files is an error naming both). **Guards
  merge tighten-only by id**: a later (host) layer may add a new guard, or
  make an existing one from an earlier (org) layer stricter — raise
  enforcement from `warn` to `block`, add required proofs, lower
  `max_proof_age_hours`, add matched paths — but it may never loosen or
  remove one. A loosening attempt is never applied; it is reported as a
  `Finding` (`policy/loosened <id> in <file>`, WARN verdict) and the
  earlier, stricter guard wins.

## 6. Portable signed bundle (`internal/bundle`, `format_version: 1`)

A single tar.gz, `bundle export`'s output:

- `manifest.json` — `format_version`, `host: {name, id}`, `epoch`,
  `policy_revision`, `generated_at`, `scope` (the `--since`/`--env`/
  `--system`/`--host` filters export ran with), `counts: {guards, proofs,
  ledger_entries}`, `context_files: [{name, sha256}]`, `ledger_slice:
  {name, sha256, entry_count, first_prev}`, `evidence: [{proof_id, path,
  exists, size_bytes, sha256}]` (**metadata only — never the evidence
  file's own bytes**, and never an entry at all for a path under a secret
  store — `excluded_secret_evidence` counts what was skipped, never names
  it), and `excluded_secret_evidence` (int).
- `manifest.sig` — detached signature: `{public_key, signature}` (hex),
  the same Ed25519 key-material shape a signed proof's own `signature:`
  block uses.
- `context/*` — the context files in force, embedded verbatim.
- `ledger/slice.jsonl` — the `--since`-bounded ledger slice, independently
  hash-chain-verifiable from `first_prev` forward.

`bundle verify` checks the signature, every content digest the manifest
claims, and the embedded slice's own hash chain — exit 0/1, printing the
host/epoch/policy revision it vouches for. `bundle inspect` prints the
manifest without checking anything (never trust `inspect` alone for
anything that matters).

`--expected-key <hex-public-key>` additionally checks an independently trusted
signer. Without it, the archive's included public key establishes internal
integrity only, not trusted origin.

### Signed summary JSON (`schema_version: 1`)

`bundle export --summary-only` is a separate bounded format, signed over a
domain-separated canonical Go JSON payload. It contains generation/evaluation
times, an optional explicit operator label, all/filtered scope selection with
digested selectors, fixed signed limitations, opaque
proof ID digests, outcome/method/assurance enums, observation/expiry times,
recipe/dependency digests, finite measurements and check-type/pass pairs,
policy digest, and ledger integrity/count/tail/anchor count. It carries no raw
context, ledger entries, paths, commands, URLs or check detail.

`bundle verify summary.json --expected-key <hex-public-key>` requires that key;
it never trusts the envelope's embedded public key alone. It rejects unknown
versions/fields, duplicate keys, trailing data, oversized input, invalid
measurements and signature mismatch. Schema limits are 1 MiB, 4096 proofs and
64 checks per proof. Signing the envelope does not strengthen the underlying
proof's assurance. See [the review workflow](evidence-handoff.md).

## 7. Offline fleet merge (`bundle merge`, `fleet.json`)

`bundle merge <bundle...> [--out dir]` verifies every input bundle (refusing
the whole merge on the first unverifiable one — never a silent partial
fleet), classifies each bundle's own proofs exactly as that host's own
`status` would (same `Classify`/layer/state pipeline, applied as of the
bundle's own `generated_at`/`epoch` — a bundle is a snapshot), and merges
every resulting row into `fleet.json`:

- **Merge key**: `(guard/proof id, scope.environment, scope.system, host)`
  — the same four-field shape a two-bundle merge and the single-host
  `status --format json` scope rows already key on, extended with the
  resolved host (a proof's own `scope.host` when it declares one, else the
  exporting bundle's host name).
- **Later `generated_at` wins** a key collision; every collision — win or
  lose — is recorded in `fleet.json`'s `conflicts` list, never silently
  dropped.
- `fleet.json` carries, per proof: id, layer, category, state, level, why,
  host, epoch, full scope, artifact, context file, source bundle, and
  `generated_at`.
- `fleet.html` is a self-contained, forced-dark dashboard: an environment ×
  system roll-up table, then the same layer→category→proof tree with an
  added host column, filtered by layer/state/environment/system/host via
  CSS `:has()` — no JavaScript.
- `restoregap status --fleet <dir>` renders the identical tree as a
  terminal report from the same `fleet.json`.

## 8. Versioning policy

- **Context schema** (`contextspec.CurrentVersion`, currently 2): any
  command reading a context file whose `version` is *newer* than
  `CurrentVersion` refuses immediately with one line naming both versions
  and exits 2 — it never guesses at an unknown shape. `restoregap migrate
  [--dry-run]` upgrades a file forward version-by-version (v1 → v2 → ...
  → current), writing a `.bak.<UTC>` of the original first.
- **Bundle format** (`bundle.FormatVersion`, currently 1) is versioned
  independently of the context schema — the wrapper (manifest shape, tar
  layout, signature scheme) and the payload (context file version) evolve
  on separate clocks; `bundle verify`/`bundle inspect` check
  `format_version`, not the embedded context files' own version.
- **Ledger schema** (`ledger.SchemaVersion`, currently 2): every field added
  since v2's freeze is `omitempty`, so an older v2 entry re-encodes
  byte-identically today and its hash still verifies — a compatibility
  invariant pinned by a canonical-form test, not just a comment.
- Nothing above bumps silently: a version constant changes only when the
  shape it names actually changes, and every bump is a refusal-with-a-clear-
  message on the old side, never a guess.
