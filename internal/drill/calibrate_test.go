// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// drillTelemetryEntry builds one ledger entry of type "drill" the way
// appendDrillLedgerEntries (internal/cli/drill.go) records a real run —
// Calibrate must read exactly this shape.
func drillTelemetryEntry(proof string, rtoMs int64, rpoMs *int64, verified bool) ledger.Entry {
	return ledger.Entry{
		EntryType: ledger.EntryDrill,
		Payload: ledger.Payload{Drill: &ledger.DrillPayload{
			ProofID: proof, Mode: "drill", Verified: verified, RTOMs: rtoMs, RPOMs: rpoMs,
		}},
	}
}

func TestCalibrateSkipsBelowMinRuns(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	entries := []ledger.Entry{
		drillTelemetryEntry("p", 1000, nil, true),
		drillTelemetryEntry("p", 1100, nil, true),
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Skip == "" {
		t.Fatalf("expected a skip (2 runs < default min 3), got %+v", r)
	}
	if !strings.Contains(r.Skip, "2 verified run") || !strings.Contains(r.Skip, "need 3") {
		t.Errorf("skip message should name the counts, got %q", r.Skip)
	}
}

func TestCalibrateIgnoresUnverifiedAndPinCheckAndOtherProofs(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	entries := []ledger.Entry{
		drillTelemetryEntry("p", 1000, nil, true),
		drillTelemetryEntry("p", 1000, nil, false), // unverified — must not count
		{EntryType: ledger.EntryDrill, Payload: ledger.Payload{Drill: &ledger.DrillPayload{ProofID: "p", Mode: "pin_check", Verified: true, RTOMs: 1000}}},
		drillTelemetryEntry("other-proof", 1000, nil, true), // different drill
		{EntryType: ledger.EntryDecision},                   // wrong entry type, Drill payload nil
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	if results[0].Skip == "" {
		t.Fatalf("only 1 genuinely matching run; expected a skip, got %+v", results[0])
	}
}

// TestCalibrateMaxBased: fewer than 20 samples means p95 (nearest-rank)
// degenerates to the max sample — intended, not a bug.
func TestCalibrateMaxBased(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p", Budgets: contextspec.DrillBudgets{RTO: 20 * time.Minute}}}
	var entries []ledger.Entry
	for _, ms := range []int64{1000, 2000, 17200} { // 3 samples, max = 17.2s
		entries = append(entries, drillTelemetryEntry("p", ms, nil, true))
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	r := results[0]
	if r.Skip != "" {
		t.Fatalf("3 runs meets the default min-runs of 3; unexpected skip: %s", r.Skip)
	}
	if !r.RTODegenerate {
		t.Error("expected RTODegenerate with only 3 samples")
	}
	if r.ObservedRTOP95 != 17200*time.Millisecond {
		t.Errorf("ObservedRTOP95 = %s, want 17.2s (the max, since n<20)", r.ObservedRTOP95)
	}
	// max(17.2s * 4, 30s) = 68.8s -> round up to next 30s -> 90s.
	if r.ProposedRTO != 90*time.Second {
		t.Errorf("ProposedRTO = %s, want 90s", r.ProposedRTO)
	}
}

// TestCalibrateRTOFloorWins: a very fast drill's margin-scaled p95 must not
// beat the 30s absolute floor — this is the case the floor exists for
// (0.4s would flake on any contended disk).
func TestCalibrateRTOFloorWins(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	var entries []ledger.Entry
	for _, ms := range []int64{1100, 1100, 1100} { // p95 = 1.1s; *4 margin = 4.4s, well under the 30s floor
		entries = append(entries, drillTelemetryEntry("p", ms, nil, true))
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	r := results[0]
	if r.Skip != "" {
		t.Fatalf("unexpected skip: %s", r.Skip)
	}
	if r.ProposedRTO != 30*time.Second {
		t.Errorf("ProposedRTO = %s, want 30s (the floor)", r.ProposedRTO)
	}
}

// TestCalibrateP95Based: 20+ samples means p95 (nearest-rank) is no longer
// the max — the "genuinely computed percentile" branch.
func TestCalibrateP95Based(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	var entries []ledger.Entry
	for i := 1; i <= 20; i++ { // 1000ms..20000ms; nearest-rank p95 of 20 samples = the 19th smallest = 19000ms
		entries = append(entries, drillTelemetryEntry("p", int64(i)*1000, nil, true))
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	r := results[0]
	if r.RTODegenerate {
		t.Error("20 samples should no longer be degenerate")
	}
	if r.ObservedRTOP95 != 19*time.Second {
		t.Errorf("ObservedRTOP95 = %s, want 19s (rank 19 of 20, not the max)", r.ObservedRTOP95)
	}
}

func TestCalibrateMinRunsFlag(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	entries := []ledger.Entry{
		drillTelemetryEntry("p", 1000, nil, true),
		drillTelemetryEntry("p", 1000, nil, true),
	}
	results := Calibrate(drills, entries, CalibrateOptions{MinRuns: 2})
	if results[0].Skip != "" {
		t.Errorf("--min-runs 2 with 2 runs should not skip, got %q", results[0].Skip)
	}
}

func TestCalibrateMarginFlag(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	var entries []ledger.Entry
	for i := 0; i < 3; i++ {
		entries = append(entries, drillTelemetryEntry("p", 10000, nil, true)) // p95 = 10s
	}
	results := Calibrate(drills, entries, CalibrateOptions{Margin: 2})
	// max(10s * 2, 30s) = 30s (the floor still wins) -> use a margin that beats the floor:
	if results[0].ProposedRTO != 30*time.Second {
		t.Fatalf("ProposedRTO = %s, want 30s", results[0].ProposedRTO)
	}
	results = Calibrate(drills, entries, CalibrateOptions{Margin: 10})
	// max(10s * 10, 30s) = 100s -> round up to next 30s -> 120s.
	if results[0].ProposedRTO != 120*time.Second {
		t.Errorf("ProposedRTO with margin=10 = %s, want 120s", results[0].ProposedRTO)
	}
}

func TestCalibrateRPORequiresItsOwnMinRuns(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	rpo1 := int64(3600_000)
	entries := []ledger.Entry{
		drillTelemetryEntry("p", 1000, &rpo1, true),
		drillTelemetryEntry("p", 1000, nil, true), // no rpo measured this run
		drillTelemetryEntry("p", 1000, nil, true),
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	if results[0].HasRPO {
		t.Error("only 1 run measured RPO; must not propose one")
	}
}

func TestCalibrateRPOProposal(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p"}}
	var entries []ledger.Entry
	for i := 0; i < 3; i++ {
		rpo := int64(3600_000) // 1h
		entries = append(entries, drillTelemetryEntry("p", 1000, &rpo, true))
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	r := results[0]
	if !r.HasRPO {
		t.Fatal("3 runs all measured rpo; expected a proposal")
	}
	// max(1h * 1.5, 1h + 6h) = max(1.5h, 7h) = 7h -> already a whole hour.
	if r.ProposedRPO != 7*time.Hour {
		t.Errorf("ProposedRPO = %s, want 7h", r.ProposedRPO)
	}
}

// TestCalibrateNeverLowersSilently: Calibrate always reports the declared
// budget alongside the proposal, even when the proposal is lower — the
// caller decides whether to --apply, nothing here refuses on direction.
func TestCalibrateNeverLowersSilently(t *testing.T) {
	drills := []contextspec.Drill{{Proof: "p", Budgets: contextspec.DrillBudgets{RTO: 20 * time.Minute}}}
	var entries []ledger.Entry
	for i := 0; i < 3; i++ {
		entries = append(entries, drillTelemetryEntry("p", 1100, nil, true))
	}
	results := Calibrate(drills, entries, CalibrateOptions{})
	r := results[0]
	if r.DeclaredRTO != 20*time.Minute {
		t.Errorf("DeclaredRTO = %s, want 20m", r.DeclaredRTO)
	}
	if r.ProposedRTO >= r.DeclaredRTO {
		t.Fatalf("test setup: expected the proposal to be lower than declared")
	}
}

func TestHeadroomWarningsTooLoose(t *testing.T) {
	warnings := headroomWarnings(20*time.Minute, 1*time.Second) // 1200x
	if len(warnings) != 1 || !strings.Contains(warnings[0], "cannot fail") {
		t.Errorf("expected a 'cannot fail' warning, got %+v", warnings)
	}
}

func TestHeadroomWarningsTooTight(t *testing.T) {
	warnings := headroomWarnings(10*time.Second, 9*time.Second) // 1.11x
	if len(warnings) != 1 || !strings.Contains(warnings[0], "expect flakes") {
		t.Errorf("expected an 'expect flakes' warning, got %+v", warnings)
	}
}

func TestHeadroomWarningsSaneBudgetIsQuiet(t *testing.T) {
	warnings := headroomWarnings(10*time.Second, 5*time.Second) // 2x — comfortably in range
	if len(warnings) != 0 {
		t.Errorf("expected no warning for a sane budget, got %+v", warnings)
	}
}

func TestHeadroomWarningsUndeclaredBudgetIsQuiet(t *testing.T) {
	if warnings := headroomWarnings(0, 5*time.Second); len(warnings) != 0 {
		t.Errorf("no budget declared; expected no warning, got %+v", warnings)
	}
}
