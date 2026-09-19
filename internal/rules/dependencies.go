// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/globmatch"
	"github.com/tannernicol/restoregap/internal/intent"
)

// recoveryDependencyConflicts evaluates every captured proof against the
// complete proposed intent set once. The returned map is read-only decision
// input: callers report conflicts for the proof that a guard requires rather
// than mutating that proof's status or signature.
func recoveryDependencyConflicts(ctx contextspec.Context, intents []intent.ChangeIntent) map[string][]string {
	conflicts := make(map[string][]string)
	for _, proof := range ctx.Proofs {
		if reasons := RecoveryDependencyIntersection(proof, intents); len(reasons) > 0 {
			conflicts[proof.ID] = reasons
		}
	}
	return conflicts
}

// RecoveryDependencyIntersection reports explicit recovery dependencies from
// a proof that are touched by any intent in the complete proposed change set.
// It performs no I/O or dependency inference: only declared dependency lists
// participate. Callers should apply every returned reason to every guard that
// uses the proof, even when another intent is the one that intersects it.
func RecoveryDependencyIntersection(proof contextspec.Proof, intents []intent.ChangeIntent) []string {
	if proof.Dependencies == nil {
		return nil
	}
	deps := contextspec.NormalizeDependencies(*proof.Dependencies)
	seen := map[string]bool{}
	var reasons []string
	add := func(reason string) {
		if !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
	}
	for _, ci := range intents {
		for _, dependency := range deps.Paths {
			for _, path := range ci.AllPaths() {
				if globmatch.MatchPathAny([]string{dependency}, path) || (intent.DestroysSubtree(ci.Action) && globmatch.IsAncestor(path, dependency)) {
					add("path: " + dependency)
					break
				}
			}
		}
		if ci.Command != "" {
			for _, dependency := range deps.Commands {
				if globmatch.MatchCommandAny([]string{dependency}, ci.Command) {
					add("command: " + dependency)
				}
			}
		}
		for _, dependency := range deps.Packages {
			for _, packageName := range ci.Packages {
				if globmatch.MatchAny([]string{dependency}, packageName) {
					add("package: " + dependency)
					break
				}
			}
		}
	}
	return reasons
}
