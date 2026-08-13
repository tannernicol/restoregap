BLOCK - Recovery proof is missing for 1 local change(s).

To proceed:
- Supply fresh proof for the missing proof names above.
- Owner override: use `acknowledge_risk` with `decision_id=dec_local_efce3b6692abd592b2d5f96d`, owner, reason, expiry, and rationale.

# Restore Gap Local Preflight

This checks proposed local/self-hosted intents, commands, package updates, or config diffs. It does not prove the final host state.

Verdict: `block`

Blocked 1 recovery-critical change(s) (local.caddy.admin_route.rewrite). Supply proof, change the plan, or record an acknowledged risk to proceed.

## Restore Gap preflight could not prove the declared recovery path survives this change.

- Decision: `block`
- Rule: `local.caddy.admin_route.rewrite`
- Resource: `home-admin`
- Location: `Caddyfile:1`
- Proof status: `missing`
- Proof: local.caddy.admin_route.rewrite matched Caddyfile:1. Declared recovery/access lifeline proof is missing or unknown.
- Missing or untrusted proof:
  - Declared Caddy admin/control route changed without local recovery path proof.
- Required next step: Restore the removed site declaration, update restoregap.local.yml to the intended route, or record an owner override explaining why this declared route no longer needs to survive.
