package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/ledger"
)

const calibrateYAML = `version: 2
drills:
  - proof: money-db-recovery
    artifact: %s
    recover: "true"
    budgets:
      rto: 20m
`

// appendCalibrateTelemetry writes n verified "drill" ledger entries for
// proof with the given rto in milliseconds — the same shape
// appendDrillLedgerEntries (drill.go) writes for a real run.
func appendCalibrateTelemetry(t *testing.T, ledgerPath, proof string, n int, rtoMs int64) {
	t.Helper()
	for i := 0; i < n; i++ {
		payload := ledger.DrillPayload{ProofID: proof, Mode: "drill", Verified: true, RTOMs: rtoMs}
		if _, err := ledger.AppendNow(ledgerPath, ledger.EntryDrill, "test", ledger.Payload{Drill: &payload}); err != nil {
			t.Fatalf("append telemetry: %v", err)
		}
	}
}

func TestDrillCalibrateRequiresLedger(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(calibrateYAML, artifact))

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("--calibrate without --ledger must error")
	}
}

func TestDrillCalibrateSkipsBelowMinRuns(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(calibrateYAML, artifact))
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	appendCalibrateTelemetry(t, ledgerPath, "money-db-recovery", 2, 1100)

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate", "--ledger", ledgerPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "skip:") || !strings.Contains(out.String(), "need 3") {
		t.Errorf("expected a skip line, got %q", out.String())
	}
}

func TestDrillCalibratePrintsProposalWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(calibrateYAML, artifact))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	appendCalibrateTelemetry(t, ledgerPath, "money-db-recovery", 3, 1100) // p95=1.1s -> propose 30s

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate", "--ledger", ledgerPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "propose 30s") {
		t.Errorf("expected the proposal line, got %q", out.String())
	}
	if !strings.Contains(out.String(), "declared 20m0s") {
		t.Errorf("expected the declared budget in the line, got %q", out.String())
	}
	// Never write without --apply.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("--calibrate without --apply must never write the context file")
	}
}

func TestDrillCalibrateHeadroomWarning(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(calibrateYAML, artifact)) // budgets.rto: 20m
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	// p95 = 1.1s; declared 20m is ~1090x that — must warn "cannot fail".
	appendCalibrateTelemetry(t, ledgerPath, "money-db-recovery", 3, 1100)

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate", "--ledger", ledgerPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "warn: money-db-recovery:") || !strings.Contains(out.String(), "cannot fail") {
		t.Errorf("expected a headroom warning printed even without --apply, got %q", out.String())
	}
}

func TestDrillCalibrateApplyRewritesOnlyBudgets(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	yaml := `version: 2
drills:
  - proof: money-db-recovery
    artifact: ` + artifact + `
    recover: "true"
    # a hand-written comment on the drill itself
    budgets:
      rto: 20m
proofs:
  - id: unrelated-proof
    status: observed
    observed_at: "2026-01-01T00:00:00Z"
`
	path := writeContext(t, yaml)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	appendCalibrateTelemetry(t, ledgerPath, "money-db-recovery", 3, 1100) // -> propose 30s

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate", "--ledger", ledgerPath, "--apply"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "money-db-recovery: rto 20m -> 30s") {
		t.Errorf("expected a change line, got %q", out.String())
	}

	reloaded := loadContext(t, path)
	if len(reloaded.Drills) != 1 || reloaded.Drills[0].Budgets.RTO.String() != "30s" {
		t.Fatalf("budgets.rto was not rewritten: %+v", reloaded.Drills)
	}
	if len(reloaded.Proofs) != 1 || reloaded.Proofs[0].ID != "unrelated-proof" {
		t.Errorf("unrelated proof must be preserved: %+v", reloaded.Proofs)
	}
}

func TestDrillCalibrateApplyNoopWhenNothingChanges(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	// Already-calibrated budget: 3 runs at 1.1s propose exactly 30s.
	yaml := `version: 2
drills:
  - proof: money-db-recovery
    artifact: ` + artifact + `
    recover: "true"
    budgets:
      rto: 30s
`
	path := writeContext(t, yaml)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	appendCalibrateTelemetry(t, ledgerPath, "money-db-recovery", 3, 1100)

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate", "--ledger", ledgerPath, "--apply"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("nothing needed changing; the file must not be rewritten")
	}
}

func TestDrillCalibrateMinRunsAndMarginFlags(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(calibrateYAML, artifact))
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	appendCalibrateTelemetry(t, ledgerPath, "money-db-recovery", 2, 10000) // only 2 runs

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--calibrate", "--ledger", ledgerPath, "--min-runs", "2", "--margin", "10"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	// p95=10s * margin 10 = 100s -> round up to next 30s -> 120s.
	if !strings.Contains(out.String(), "propose 120s") {
		t.Errorf("expected --min-runs/--margin to be honored, got %q", out.String())
	}
}
