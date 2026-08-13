// Package engine is the pure decision core of restoregap: it maps normalized
// change intents, declared recovery context, and proof state to verdicts.
// It performs no I/O; adapters normalize inputs and the ledger records outputs.
package engine

// Verdict is the decision for a single finding. String values are part of the
// frozen JSON contract with the Python implementation (see docs/ARCHITECTURE.md).
type Verdict string

// The Verdict values. Ordered least to most restrictive; Decide fails closed
// toward VerdictBlock.
const (
	VerdictPass  Verdict = "pass"
	VerdictWarn  Verdict = "warn"
	VerdictBlock Verdict = "block"
)

// RiskClass classifies what is at stake if the change proceeds unproven.
type RiskClass string

// The RiskClass values.
const (
	RiskDataLossUnrecoverable RiskClass = "data_loss_unrecoverable"
	RiskRecoveryProofGap      RiskClass = "recovery_proof_gap"
	RiskServiceContinuity     RiskClass = "service_continuity_risk"
	RiskCannotProveSafe       RiskClass = "cannot_prove_safe"
	RiskNone                  RiskClass = "none"
)

// ProofStatus is the validated state of the evidence backing a change.
type ProofStatus string

// The ProofStatus values.
const (
	ProofMissing      ProofStatus = "missing"
	ProofPresent      ProofStatus = "present"
	ProofStale        ProofStatus = "stale"
	ProofContradicted ProofStatus = "contradicted"
	ProofNotRequired  ProofStatus = "not_required"
	ProofUnknown      ProofStatus = "unknown"
)

// Enforcement is an assurance contract's declared strictness.
type Enforcement string

// The Enforcement values.
const (
	EnforceBlock Enforcement = "block"
	EnforceWarn  Enforcement = "warn"
)

// Decide is the single verdict function. Fail-closed: anything unproven on a
// non-trivial risk blocks unless the matching contract explicitly downgrades
// to warn. This must stay behavior-identical to the Python engine; parity is
// asserted by the golden fixtures in testdata/golden.
func Decide(risk RiskClass, proof ProofStatus, enforcement Enforcement) Verdict {
	if risk == RiskNone || proof == ProofNotRequired {
		return VerdictPass
	}
	switch proof {
	case ProofPresent:
		return VerdictPass
	case ProofMissing, ProofStale, ProofContradicted, ProofUnknown:
		if enforcement == EnforceWarn {
			return VerdictWarn
		}
		return VerdictBlock
	}
	return VerdictBlock
}
