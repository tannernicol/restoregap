BLOCK - Recovery proof is missing for 1 local change(s).

Missing proof:
- `independent-access-path`
- `ssh-key-recovery-copy`

To proceed:
- Supply fresh proof for the missing proof names above.
- Owner override: use `acknowledge_risk` with `decision_id=dec_local_2b2d917d9feeb70aea4db821`, owner, reason, expiry, and rationale.

# Restore Gap Local Preflight

This checks proposed local/self-hosted intents, commands, package updates, or config diffs. It does not prove the final host state.

Verdict: `block`

Blocked 1 recovery-critical change(s) (local.lifeline_artifact.delete_or_modify). Supply proof, change the plan, or record an acknowledged risk to proceed.

## Restore Gap preflight could not prove the declared recovery path survives this change.

- Decision: `block`
- Rule: `local.lifeline_artifact.delete_or_modify`
- Resource: `default-ssh-private-keys`
- Location: `~/.ssh/id_ed25519`
- Proof status: `missing`
- Proof: Assurance contract `default-ssh-key-assurance` is not satisfied for this declared action.
- Missing or untrusted proof:
  - Required knowledge before proceeding: which alternate account or console can still administer the host, where the customer-owned key recovery copy lives.
  - Required checks before proceeding: independent access path is reachable without the touched SSH key, key recovery copy or replacement path is current.
  - Missing proof: ssh-key-recovery-copy, independent-access-path.
- Required next step: Refresh or supply proof for `ssh-key-recovery-copy`; Refresh or supply proof for `independent-access-path`; complete checks: independent access path is reachable without the touched SSH key, key recovery copy or replacement path is current; load knowledge: which alternate account or console can still administer the host, where the customer-owned key recovery copy lives, or record an owner override before proceeding.

## Restore Gap captured a customer-run undo plan.

- Decision: `pass`
- Rule: `local.undo_plan.captured`
- Resource: `local-undo-plan-delete-file`
- Location: `~/.ssh/id_ed25519`
- Proof status: `present`
- Proof: Undo plan undo_ae393070016ba298761ab6b3 is hash-bound as sha256:ae393070016ba298761ab6b38481494d3136000dc5e115d512e2e74f76760dd6.
- Required next step: Keep the ledger entry; run `restoregap undo --id undo_ae393070016ba298761ab6b3 --ledger <path>` to print the customer-run plan. Restore Gap never restores.
