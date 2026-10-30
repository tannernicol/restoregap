// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/intent"
)

func TestRecoveryDependencyIntersectionUsesWholeIntentSet(t *testing.T) {
	proof := contextspec.Proof{Dependencies: &contextspec.Dependencies{
		Paths: []string{"infra/recovery/**"}, Commands: []string{"terraform apply *"}, Packages: []string{"restic"},
	}}
	intents := []intent.ChangeIntent{
		{Action: intent.ActionModifyFile, Paths: []string{"app/main.go"}},
		{Action: intent.ActionModifyFile, Paths: []string{"infra/recovery/recipe.hcl"}},
		{Action: intent.ActionRunCommand, Command: "terraform apply -auto-approve"},
		{Action: intent.ActionPackageUpdate, Packages: []string{"restic"}},
	}
	got := RecoveryDependencyIntersection(proof, intents)
	if len(got) != 3 || got[0] != "path: infra/recovery/**" || got[1] != "command: terraform apply *" || got[2] != "package: restic" {
		t.Fatalf("intersection = %v, want all three dependencies in intent order", got)
	}
}

func TestRecoveryDependencyIntersectionHandlesSubtreeDestroy(t *testing.T) {
	proof := contextspec.Proof{Dependencies: &contextspec.Dependencies{Paths: []string{"secrets/recovery.key"}}}
	intents := []intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"secrets"}}}
	if got := RecoveryDependencyIntersection(proof, intents); len(got) != 1 {
		t.Fatalf("subtree deletion did not intersect recovery dependency: %v", got)
	}
}
