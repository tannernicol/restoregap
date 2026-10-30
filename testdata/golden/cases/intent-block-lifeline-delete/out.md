BLOCK - Recovery proof is missing for 2 local change(s).

Missing proof:
- `agent-runtime-state-backup`
- `portable-recovery-kit`

To proceed:
- Supply fresh proof for the missing proof names above.
- Owner override: use `acknowledge_risk` with `decision_id=dec_local_a3e524ad223e7e1fd0b1417b`, owner, reason, expiry, and rationale.

# Restore Gap Local Preflight

This checks proposed local/self-hosted intents, commands, package updates, or config diffs. It does not prove the final host state.

Verdict: `block`

Blocked 2 recovery-critical change(s) (local.lifeline_artifact.delete_or_modify, local.undo_plan.capture_failed). Supply proof, change the plan, or record an acknowledged risk to proceed.

## Restore Gap preflight could not prove the declared recovery path survives this change.

- Decision: `block`
- Rule: `local.lifeline_artifact.delete_or_modify`
- Resource: `openclaw-runtime-state`
- Location: `~/.openclaw/credentials/telegram/default/creds.json`
- Proof status: `missing`
- Proof: Assurance contract `selfhosted-agent-recovery-assurance` is not satisfied for this declared action.
- Missing or untrusted proof:
  - Required knowledge before proceeding: runtime owner and rollback path, affected services and credentials, out-of-band access path.
  - Required checks before proceeding: independent access path is still available, recovery kit or state backup is current, rollback command is documented outside the agent runtime.
  - Missing proof: agent-runtime-state-backup, portable-recovery-kit.
- Required next step: Refresh or supply proof for `agent-runtime-state-backup`; Refresh or supply proof for `portable-recovery-kit`; complete checks: independent access path is still available, recovery kit or state backup is current, rollback command is documented outside the agent runtime; load knowledge: runtime owner and rollback path, affected services and credentials, out-of-band access path, or record an owner override before proceeding.

## Restore Gap could not capture a customer-run undo plan.

- Decision: `block`
- Rule: `local.undo_plan.capture_failed`
- Resource: `local-undo-plan-delete-file`
- Location: `~/.openclaw/credentials/telegram/default/creds.json`
- Proof status: `missing`
- Proof: no proven way back: file snapshot source does not exist or is not a regular file: /home/user/.openclaw/credentials/telegram/default/creds.json
- Missing or untrusted proof:
  - no proven way back: file snapshot source does not exist or is not a regular file: /home/user/.openclaw/credentials/telegram/default/creds.json
- Required next step: Capture a hash-bound customer-run undo plan in the ledger before running this covered action.
