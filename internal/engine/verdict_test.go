// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package engine

import "testing"

func TestDecide(t *testing.T) {
	cases := []struct {
		name        string
		risk        RiskClass
		proof       ProofStatus
		enforcement Enforcement
		want        Verdict
	}{
		{"no risk passes", RiskNone, ProofUnknown, EnforceBlock, VerdictPass},
		{"proof not required passes", RiskRecoveryProofGap, ProofNotRequired, EnforceBlock, VerdictPass},
		{"present proof passes", RiskDataLossUnrecoverable, ProofPresent, EnforceBlock, VerdictPass},
		{"missing proof blocks", RiskDataLossUnrecoverable, ProofMissing, EnforceBlock, VerdictBlock},
		{"stale proof blocks", RiskRecoveryProofGap, ProofStale, EnforceBlock, VerdictBlock},
		{"contradicted proof blocks", RiskServiceContinuity, ProofContradicted, EnforceBlock, VerdictBlock},
		{"unreachable proof blocks", RiskDataLossUnrecoverable, ProofUnreachable, EnforceBlock, VerdictBlock},
		{"unreachable proof only downgrades with warn contract", RiskDataLossUnrecoverable, ProofUnreachable, EnforceWarn, VerdictWarn},
		{"unknown proof fails closed", RiskCannotProveSafe, ProofUnknown, EnforceBlock, VerdictBlock},
		{"warn contract downgrades", RiskRecoveryProofGap, ProofMissing, EnforceWarn, VerdictWarn},
	}
	for _, c := range cases {
		if got := Decide(c.risk, c.proof, c.enforcement); got != c.want {
			t.Errorf("%s: Decide(%s,%s,%s) = %s, want %s", c.name, c.risk, c.proof, c.enforcement, got, c.want)
		}
	}
}
