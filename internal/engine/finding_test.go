// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package engine

import "testing"

func TestApplyOverridesDowngradesMatchingFinding(t *testing.T) {
	findings := []Finding{
		{ID: "f1", Verdict: VerdictBlock},
		{ID: "f2", Verdict: VerdictWarn},
		{ID: "f3", Verdict: VerdictPass},
	}
	overrides := []Override{{FindingID: "f1", ApprovedBy: "tanner", Reason: "acknowledged, off-machine copy confirmed"}}
	got := ApplyOverrides(findings, overrides)

	if got[0].Verdict != VerdictPass {
		t.Errorf("f1 verdict = %s, want pass (overridden)", got[0].Verdict)
	}
	if got[1].Verdict != VerdictWarn {
		t.Errorf("f2 verdict = %s, want warn (untouched)", got[1].Verdict)
	}
	if got[2].Verdict != VerdictPass {
		t.Errorf("f3 verdict = %s, want pass (untouched)", got[2].Verdict)
	}
}

func TestApplyOverridesNoOverridesReturnsSameFindings(t *testing.T) {
	findings := []Finding{{ID: "f1", Verdict: VerdictBlock}}
	got := ApplyOverrides(findings, nil)
	if got[0].Verdict != VerdictBlock {
		t.Errorf("verdict = %s, want block", got[0].Verdict)
	}
}

func TestOverall(t *testing.T) {
	cases := []struct {
		name     string
		verdicts []Verdict
		want     Verdict
	}{
		{"empty", nil, VerdictPass},
		{"all pass", []Verdict{VerdictPass, VerdictPass}, VerdictPass},
		{"one warn", []Verdict{VerdictPass, VerdictWarn}, VerdictWarn},
		{"one block wins over warn", []Verdict{VerdictWarn, VerdictBlock}, VerdictBlock},
	}
	for _, c := range cases {
		var findings []Finding
		for _, v := range c.verdicts {
			findings = append(findings, Finding{Verdict: v})
		}
		if got := Overall(findings); got != c.want {
			t.Errorf("%s: Overall() = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		verdict    Verdict
		failOnWarn bool
		want       int
	}{
		{VerdictPass, false, 0},
		{VerdictPass, true, 0},
		{VerdictWarn, false, 0},
		{VerdictWarn, true, 1},
		{VerdictBlock, false, 1},
		{VerdictBlock, true, 1},
	}
	for _, c := range cases {
		if got := ExitCode(c.verdict, c.failOnWarn); got != c.want {
			t.Errorf("ExitCode(%s, %v) = %d, want %d", c.verdict, c.failOnWarn, got, c.want)
		}
	}
}
