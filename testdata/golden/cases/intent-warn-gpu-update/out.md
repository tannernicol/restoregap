WARN - 1 local change(s) need recovery-contract review.

To proceed:
- Continue under the caller's normal approval workflow.

# Restore Gap Local Preflight

This checks proposed local/self-hosted intents, commands, package updates, or config diffs. It does not prove the final host state.

Verdict: `warn`

1 change(s) have no recovery contract yet; proceeding under the caller's normal approval.

## Restore Gap preflight could not prove the declared recovery path survives this change.

- Decision: `warn`
- Rule: `local.update_guard.package_or_system_update`
- Resource: `system-update`
- Location: `nvidia-driver`
- Proof status: `unknown`
- Proof: local.update_guard.package_or_system_update matched nvidia-driver. No declared update_guards context was supplied.
- Missing or untrusted proof:
  - Package/system update appears to touch graphics, kernel, or boot stack packages, but no matching update_guards context was supplied.
- Required next step: Declare update_guards in restoregap.local.yml before enforcing this surface, or review the update manually.
