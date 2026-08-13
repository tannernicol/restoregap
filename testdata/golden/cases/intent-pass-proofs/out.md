PASS - Declared recovery proof is present for 1 local change(s).

To proceed:
- Continue under the caller's normal approval workflow.

# Restore Gap Local Preflight

This checks proposed local/self-hosted intents, commands, package updates, or config diffs. It does not prove the final host state.

Verdict: `pass`

Verified the recovery path for 1 recovery-critical change(s): declared proof is present, safe to proceed.

## Restore Gap preflight found the declared recovery assurance.

- Decision: `pass`
- Rule: `local.command_guard.runtime_command`
- Resource: `agent-runtime-control-plane`
- Location: `openclaw`
- Proof status: `present`
- Proof: Assurance contract `selfhosted-agent-recovery-assurance` is satisfied by reviewed facts `none` and proof `agent-runtime-state-backup, portable-recovery-kit`.
- Required next step: Proceed under the caller's normal approval workflow; Restore Gap found the declared recovery assurance facts/proof for this action.
