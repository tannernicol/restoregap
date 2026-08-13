package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/drill"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// runDrillCalibrateCmd derives RTO/RPO budgets from verified ledger drill
// telemetry and prints the proposal (plus any headroom warnings) for every
// matched drill. It writes nothing unless apply is true, in which case only
// the budgets: block of each matched drill is rewritten — everything else
// in the document is preserved via the same map round-trip
// recordDrillProofs already uses.
func runDrillCalibrateCmd(cmd *cobra.Command, contextPath string, drills []contextspec.Drill, ledgerPath string, minRuns int, margin float64, apply bool) error {
	if ledgerPath == "" {
		return fmt.Errorf("drill --calibrate: --ledger is required (calibrate reads telemetry back from it)")
	}
	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return fmt.Errorf("drill --calibrate: %w", err)
	}

	results := drill.Calibrate(drills, entries, drill.CalibrateOptions{MinRuns: minRuns, Margin: margin})

	out := cmd.OutOrStdout()
	var toApply []drill.CalibrateResult
	for _, r := range results {
		_, _ = fmt.Fprintln(out, formatCalibrateLine(r))
		for _, w := range r.Warnings {
			_, _ = fmt.Fprintf(out, "warn: %s: %s\n", r.Proof, w)
		}
		if r.Skip == "" {
			toApply = append(toApply, r)
		}
	}

	if !apply || len(toApply) == 0 {
		return nil
	}
	changed, err := applyCalibratedBudgets(contextPath, toApply)
	if err != nil {
		return fmt.Errorf("drill --calibrate --apply: %w", err)
	}
	for _, c := range changed {
		_, _ = fmt.Fprintln(out, c)
	}
	return nil
}

// formatCalibrateLine renders one drill's calibration outcome: a skip
// reason, or the declared/observed/proposed RTO (plus RPO, when enough
// samples measured it).
func formatCalibrateLine(r drill.CalibrateResult) string {
	if r.Skip != "" {
		return fmt.Sprintf("%s\tskip: %s", r.Proof, r.Skip)
	}
	line := fmt.Sprintf("%s\tRTO declared %s\tobserved p95 %s\t-> propose %s",
		r.Proof, durationOrNone(r.DeclaredRTO), r.ObservedRTOP95.Round(100*time.Millisecond), drill.FormatCalibratedRTO(r.ProposedRTO))
	if r.HasRPO {
		line += fmt.Sprintf("; RPO declared %s observed p95 %s -> propose %s",
			durationOrNone(r.DeclaredRPO), r.ObservedRPOP95.Round(time.Second), drill.FormatCalibratedRPO(r.ProposedRPO))
	}
	return line
}

func durationOrNone(d time.Duration) string {
	if d <= 0 {
		return "none"
	}
	return d.String()
}

// applyCalibratedBudgets rewrites ONLY the budgets: block of each drill
// named in results, preserving everything else in the document byte-for-
// byte apart from that block — the same map round-trip
// recordDrillProofs (drill.go) uses to merge proof results back in without
// re-marshaling through typed structs and losing comments/keys this tool
// does not own. It returns one "<proof>: rto X -> Y" line per field
// actually changed, and writes the file only when something changed.
func applyCalibratedBudgets(path string, results []drill.CalibrateResult) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	drillsRaw, _ := doc["drills"].([]any)
	var changed []string
	for i, dr := range drillsRaw {
		dm, ok := dr.(map[string]any)
		if !ok {
			continue
		}
		proof, _ := dm["proof"].(string)
		r, ok := findCalibrateResult(results, proof)
		if !ok {
			continue
		}
		budgets, _ := dm["budgets"].(map[string]any)
		if budgets == nil {
			budgets = map[string]any{}
		}
		applyBudgetField(budgets, "rto", drill.FormatCalibratedRTO(r.ProposedRTO), proof, &changed)
		if r.HasRPO {
			applyBudgetField(budgets, "rpo", drill.FormatCalibratedRPO(r.ProposedRPO), proof, &changed)
		}
		dm["budgets"] = budgets
		drillsRaw[i] = dm
	}
	doc["drills"] = drillsRaw

	if len(changed) == 0 {
		return nil, nil
	}
	encoded, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return nil, err
	}
	return changed, nil
}

func findCalibrateResult(results []drill.CalibrateResult, proof string) (drill.CalibrateResult, bool) {
	for _, r := range results {
		if r.Proof == proof {
			return r, true
		}
	}
	return drill.CalibrateResult{}, false
}

// applyBudgetField sets budgets[field] to newVal, recording a change line
// (and returning true) only when the value actually differs from what was
// there before.
func applyBudgetField(budgets map[string]any, field, newVal, proof string, changed *[]string) bool {
	old, _ := budgets[field].(string)
	if old == newVal {
		return false
	}
	budgets[field] = newVal
	oldDisplay := old
	if oldDisplay == "" {
		oldDisplay = "none"
	}
	*changed = append(*changed, fmt.Sprintf("%s: %s %s -> %s", proof, field, oldDisplay, newVal))
	return true
}
