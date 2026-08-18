// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package engine

// Finding is one evaluated guard match: the risk it represents, the proof
// state backing it, the resulting verdict, and what to do next. Findings are
// the sole output of the engine — no I/O, no rendering.
type Finding struct {
	ID               string
	GuardID          string
	Kind             string // "lifeline" | "guard" — mirrors contextspec.GuardKind, kept as string to avoid an engine->contextspec import
	Resource         string // path, command, or package that matched
	Actions          []string
	RiskClass        RiskClass
	ProofStatus      ProofStatus
	Verdict          Verdict
	Title            string
	Proof            string
	RequiredNextStep string
}

// Override is a resolved ledger override applying to a finding: it may
// downgrade a block/warn finding to pass, recorded with its own audit trail.
// The ledger package produces these; engine only consumes them.
type Override struct {
	FindingID  string
	ApprovedBy string
	Reason     string
}

// ApplyOverrides downgrades any finding with a matching, still-active
// override to pass, recording that an override was applied in the required
// next step for traceability. Findings without a matching override are
// returned unchanged.
func ApplyOverrides(findings []Finding, overrides []Override) []Finding {
	if len(overrides) == 0 {
		return findings
	}
	byFinding := make(map[string]Override, len(overrides))
	for _, o := range overrides {
		byFinding[o.FindingID] = o
	}
	out := make([]Finding, len(findings))
	for i, f := range findings {
		out[i] = f
		if f.Verdict == VerdictPass {
			continue
		}
		if o, ok := byFinding[f.ID]; ok {
			out[i].Verdict = VerdictPass
			out[i].RequiredNextStep = "Owner override recorded (" + o.ApprovedBy + "): " + o.Reason
		}
	}
	return out
}
