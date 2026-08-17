package drill

import (
	"fmt"
	"os"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// LintSeverity ranks one drill lint finding.
type LintSeverity string

// The LintSeverity values.
const (
	LintError LintSeverity = "error"
	LintWarn  LintSeverity = "warn"
)

// LintFinding is one problem found by statically inspecting a declared
// drill — no recovery is performed and nothing is written.
type LintFinding struct {
	Proof    string
	Severity LintSeverity
	Message  string
}

// Lint statically checks one declared drill for problems that would only
// otherwise surface mid-run (an RPO budget nothing can measure) or that
// silently degrade coverage between full drills (no pin_check). It performs
// no recovery and touches nothing beyond a Stat of the artifact path.
//
// Required-field and enum/duration validity are NOT re-checked here: they
// are already enforced, per-drill-indexed, by contextspec.Parse before a
// Drill value can exist at all (see fromRawDrill/fromRawDrillCheck) — a
// document that fails to parse never reaches Lint, and reworking Load into a
// partial/collecting parser is out of scope for this pass.
func Lint(d contextspec.Drill) []LintFinding {
	var out []LintFinding

	checks := d.Validate
	if len(checks) == 0 {
		checks = []contextspec.DrillCheck{{Type: "byte_identical"}}
	}

	// Same rule Run/applyBudgets enforce at drill time (freshnessDeclared,
	// drill.go): reuse it rather than re-deriving "can anything here measure
	// RPO" a second way that could quietly drift from the engine's own
	// answer.
	if d.Budgets.RPO > 0 && !freshnessDeclared(checks) {
		out = append(out, LintFinding{
			Proof: d.Proof, Severity: LintError,
			Message: "budgets.rpo is declared but no check here can measure freshness — add a sqlite check with " +
				"freshness: {table, column}, or a git/file_tree check (a drill run would hard-fail this the same way)",
		})
	}

	out = append(out, lintTableConstraints(d.Proof, checks)...)

	if d.PinCheck == "" {
		out = append(out, LintFinding{
			Proof: d.Proof, Severity: LintWarn,
			Message: "no pin_check declared — pins are the cheap, frequent check that catches a pruned or rotated " +
				"recovery snapshot between full drills; declare one so `drill --pins-only` can watch it daily",
		})
	}

	if d.Artifact != "" {
		if _, err := os.Stat(d.Artifact); err != nil {
			out = append(out, LintFinding{
				Proof: d.Proof, Severity: LintWarn,
				Message: fmt.Sprintf("artifact %s does not exist on this machine (fine if this drill targets a different host)", d.Artifact),
			})
		}
	}

	for _, c := range checks {
		if c.Type != "key_fingerprint" {
			continue
		}
		// Parse already refuses a key_fingerprint check that asserts
		// literally nothing (no expect_from, no expect, min_keys: 0); this
		// is the weaker-but-still-real gap: it only asserts that at least
		// one key exists, never that it's the RIGHT one — which is the
		// entire reason this check type exists.
		if c.ExpectFrom == "" && len(c.Expect) == 0 && c.MinKeys <= 1 {
			out = append(out, LintFinding{
				Proof: d.Proof, Severity: LintWarn,
				Message: "key_fingerprint recovers keys but only asserts that at least one exists; add expect_from " +
					"pointing at the live key directory so a missing key is caught",
			})
		}
	}

	return out
}

// lintTableConstraints checks every sqlite check's tables: entries for
// syntax errors under either grammar (absolute or percent-of-live) — split
// out of Lint to keep its cyclomatic complexity under the repo lint budget.
func lintTableConstraints(proof string, checks []contextspec.DrillCheck) []LintFinding {
	var out []LintFinding
	for _, c := range checks {
		if c.Type != "sqlite" {
			continue
		}
		for _, table := range sortedKeys(c.Tables) {
			if err := validateTableConstraintSyntax(c.Tables[table]); err != nil {
				out = append(out, LintFinding{
					Proof: proof, Severity: LintError,
					Message: fmt.Sprintf("tables.%s: %v", table, err),
				})
			}
		}
	}
	return out
}
