# restoregap semantic reference cases

Captured 2026-07-16 from the Python CLI (authoritative checkout
`.work/restore-gap-audit/scanner`, run as `uv run restoregap ...` from the
checkout root). Scope (per Tanner, 2026-07-16): these are **semantic reference
cases** for the Go rewrite, not byte-exact parity goldens. Compare the semantic
content of `out.json` — verdict, which `rule_id`s fired, `decision`,
`risk_class`, `proof_status`, `required_next_step` — plus the exit code. Do not
diff bytes.

## Exit-code semantics of `restoregap preflight`

Source: `src/restoregap/cli/gate_cmds.py:1189-1193` (local `--diff`/`--intent`
mode) and `src/restoregap/cli/__init__.py:1550-1552` (`--terraform-plan`
recovery mode).

| Preflight verdict | default exit | with `--fail-on-warn` |
|---|---|---|
| `pass` (incl. zero findings) | 0 | 0 |
| `warn` (warnings, no blocks) | 0 | 1 |
| `block` (any blocking finding) | 1 | 1 |

- Local mode: verdict is derived from findings — any `decision == "block"`
  finding ⇒ `block`; else any `decision == "warn"` ⇒ `warn`; else `pass`
  (`src/restoregap/adapters/local/preflight.py:2577`).
- Recovery (`--terraform-plan`) mode: verdict is `"fail"`/`"pass"` (any failing
  check ⇒ `fail` ⇒ exit 1, `src/restoregap/recovery_preflight.py:188`).
  `--fail-on-warn` has no effect in this mode.
- Zero-config protection: with no `--context`, local preflight loads a built-in
  default policy, so deleting an SSH private key still **blocks** (see
  `cases/zero-config-ssh-key-delete`). Supplying an explicit minimal context
  (`version: 1`) replaces that default, which is how the heuristic WARN cases
  are constructed.

## JSON output shape (`--format json`)

Local mode (`--diff` / `--intent`) — top-level keys:

- `adapter`: always `"local"`
- `verdict`: `"block" | "warn" | "pass"`
- `summary`: one-line human headline string
- `findings`: list of finding objects, each with `decision_id`, `change`
  (`adapter`, `resource_address`, `resource_type`, `resource_id`,
  `environment`, `actions`, `relevant_attributes`), `risk_class`, `rule_id`,
  `decision` (`block|pass|warn`), `proof_status`
  (`missing|present|stale|contradicted|not_required|unknown`), `title`,
  `proof`, `observed_failure` (list), `required_next_step`, `evidence_refs`
  (list of `{source, observed_at, evidence_url, sha256}`)

Recovery mode (`--terraform-plan`) — top-level keys:

- `verdict`: `"fail" | "pass"`
- `summary`: object of counters/thresholds (`material_database_changes`,
  `recovery_access_findings`, `blocking_findings`, `failing_checks`,
  `passing_checks`, `max_restore_point_age_hours`, `min_retention_days`,
  `max_restore_test_age_days`, `require_backup_outside_resource_account`,
  `target_environment`)
- `changes`: parsed Terraform database changes
- `findings`: same finding shape as local mode
- `issues`: check items (`status` `pass|fail`, `check_id`, `title`, `resource`,
  `proof`, `required_proof`, `observed_failure`, `required_next_step`,
  `accepted_exceptions`, `evidence_refs`)

## Nondeterministic fields (mask when comparing)

- All runs used `--as-of`, so `observed_at`/evaluation timestamps in `out.json`
  are frozen. `evidence_url`/labels embed the **absolute path** of the input
  file as passed on the command line (host-specific).
- `ledger.jsonl` files contain wall-clock `created_at`, random uuid4
  `entry_id`/`run_id`, and hence run-specific `prev_hash`/`entry_hash`.
  `decision_id`, `change_id`, and `finding_fingerprint` are deterministic.

## Deprecated material

`ledger/hash_vectors.json`, the override/acknowledgement ledger flow outputs in
`ledger/`, and each case's `out.md` were captured for the earlier byte-exact
parity goal and are **deprecated** — kept only for reference, not part of the
Go behavioral contract.
