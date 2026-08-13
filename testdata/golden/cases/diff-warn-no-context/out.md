WARN - 1 local change(s) need recovery-contract review.

To proceed:
- Continue under the caller's normal approval workflow.

# Restore Gap Local Preflight

This checks proposed local/self-hosted intents, commands, package updates, or config diffs. It does not prove the final host state.

Verdict: `warn`

1 change(s) have no recovery contract yet; proceeding under the caller's normal approval.

## Restore Gap preflight could not prove the declared recovery path survives this change.

- Decision: `warn`
- Rule: `local.caddy.admin_route.rewrite`
- Resource: `caddy:Caddyfile`
- Location: `Caddyfile:1`
- Proof status: `unknown`
- Proof: local.caddy.admin_route.rewrite matched Caddyfile:1. Declared recovery/access lifeline proof is missing or unknown.
- Missing or untrusted proof:
  - Local Caddy admin-route-like declaration changed, but no matching admin_routes context was supplied.
- Required next step: Declare admin_routes in restoregap.local.yml to enforce this route, or review the changed Caddy site declaration.
