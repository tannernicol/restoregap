// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package dora

import (
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/ledger"
)

func drill(at time.Time, proofID string, verified bool, rtoMS int64) ledger.Entry {
	return ledger.Entry{
		EntryType: ledger.EntryDrill, CreatedAt: at,
		Payload: ledger.Payload{Drill: &ledger.DrillPayload{ProofID: proofID, Verified: verified, RTOMs: rtoMS}},
	}
}

func decision(at time.Time, guardID, verdict, gateState string) ledger.Entry {
	return ledger.Entry{
		EntryType: ledger.EntryDecision, CreatedAt: at,
		Payload: ledger.Payload{Decision: &ledger.DecisionPayload{
			Verdict: verdict, GateState: gateState,
			Findings: []ledger.FindingRecord{{GuardID: guardID, Verdict: verdict}},
		}},
	}
}

func TestComputeFourKeys(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	entries := []ledger.Entry{
		drill(now.Add(-6*day), "ssh-keys", true, 60_000),
		drill(now.Add(-4*day), "ssh-keys", false, 0),
		drill(now.Add(-2*day), "db", true, 180_000),
		drill(now.Add(-1*day), "db", true, 120_000),
	}
	m := Compute(entries, 7*day, now)

	if m.Drills != 4 || m.DrillsFailed != 1 {
		t.Fatalf("drills=%d failed=%d, want 4/1", m.Drills, m.DrillsFailed)
	}
	if got := m.DrillFrequency; got < 0.57 || got > 0.58 {
		t.Errorf("frequency = %v, want ~0.571/day", got)
	}
	if m.DrillFailureRate == nil || *m.DrillFailureRate != 0.25 {
		t.Errorf("failure rate = %v, want 0.25", m.DrillFailureRate)
	}
	// restores: 60s, 180s, 120s -> median 120s
	if m.TimeToRestore == nil || *m.TimeToRestore != 120*time.Second {
		t.Errorf("time to restore = %v, want 2m", m.TimeToRestore)
	}
	// ssh-keys broke at -4d and recovered... never in this fixture.
	if len(m.Unrecovered) != 1 || m.Unrecovered[0] != "ssh-keys (proof)" {
		t.Errorf("unrecovered = %v, want [ssh-keys (proof)]", m.Unrecovered)
	}
}

// TestLifelineMTTRPairsBreakWithRecovery is the metric that says how long a
// known-broken lifeline is tolerated.
func TestLifelineMTTRPairsBreakWithRecovery(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		decision(now.Add(-50*time.Hour), "backups", "block", ""),
		decision(now.Add(-40*time.Hour), "backups", "pass", ""), // 10h gap
		drill(now.Add(-30*time.Hour), "nas", false, 0),
		drill(now.Add(-28*time.Hour), "nas", true, 1000), // 2h gap
	}
	m := Compute(entries, 7*24*time.Hour, now)
	if m.LifelineMTTR == nil || *m.LifelineMTTR != 6*time.Hour {
		t.Fatalf("MTTR = %v, want 6h (median of 10h and 2h)", m.LifelineMTTR)
	}
	if len(m.Unrecovered) != 0 {
		t.Errorf("unrecovered = %v, want none", m.Unrecovered)
	}
}

// TestBrokenGateIsNotALifelineFailure pins the gauntlet-v2 lesson: a gate that
// could not run says nothing about the lifeline.
func TestBrokenGateIsNotALifelineFailure(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	m := Compute([]ledger.Entry{decision(now.Add(-time.Hour), "backups", "block", "broken")}, 24*time.Hour, now)
	if len(m.Unrecovered) != 0 || m.LifelineMTTR != nil {
		t.Fatalf("a broken gate must not count as a lifeline failure: %+v", m)
	}
}

// TestEmptyLedgerReportsNoData: absent measurement must not look like a
// perfect score.
func TestEmptyLedgerReportsNoData(t *testing.T) {
	now := time.Now().UTC()
	m := Compute(nil, 14*24*time.Hour, now)
	if m.Drills != 0 || m.DrillFailureRate != nil || m.TimeToRestore != nil || m.LifelineMTTR != nil {
		t.Fatalf("empty ledger must report nil medians, got %+v", m)
	}
}

// TestPassingDecisionClearsGuards pins the fix for a real defect found by
// running this on the live ledger (2026-08-18): a passing decision names no
// findings, so a guard that blocked once could never clear and four guards
// sat in STILL BROKEN forever — "not re-evaluated" wearing the costume of
// "broken".
func TestPassingDecisionClearsGuards(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		decision(now.Add(-5*time.Hour), "launcher", "block", ""),
		// A later PASS with no findings at all — the shape a real pass has.
		{EntryType: ledger.EntryDecision, CreatedAt: now.Add(-3 * time.Hour),
			Payload: ledger.Payload{Decision: &ledger.DecisionPayload{Verdict: "pass"}}},
	}
	m := Compute(entries, 24*time.Hour, now)
	if len(m.Unrecovered) != 0 {
		t.Fatalf("a passing decision must clear blocked guards, got %v", m.Unrecovered)
	}
	if m.LifelineMTTR == nil || *m.LifelineMTTR != 2*time.Hour {
		t.Fatalf("MTTR = %v, want 2h", m.LifelineMTTR)
	}
	// A drill proof is NOT cleared by a passing decision: different namespace,
	// different evidence.
	withDrill := append(entries, drill(now.Add(-4*time.Hour), "nas", false, 0))
	if got := Compute(withDrill, 24*time.Hour, now); len(got.Unrecovered) != 1 {
		t.Fatalf("a failed drill must survive a passing decision, got %v", got.Unrecovered)
	}
}
