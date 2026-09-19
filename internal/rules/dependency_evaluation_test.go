// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/intent"
)

func dependencyContext(t *testing.T, requireBound bool) contextspec.Context {
	t.Helper()
	drill := contextspec.Drill{
		Proof:          "restore",
		Artifact:       "/srv/live",
		RecoverySource: "/srv/recovery",
		Recover:        "cp /srv/recovery /srv/live",
		Dependencies: contextspec.Dependencies{
			Paths:    []string{"/etc/recovery.key"},
			Packages: []string{"restic"},
		},
	}
	deps := contextspec.NormalizeDependencies(drill.Dependencies)
	return contextspec.Context{
		Version: 2,
		Guards: []contextspec.Guard{{
			ID: "live", Kind: contextspec.GuardKindLifeline,
			Match:    contextspec.Matcher{Paths: []string{"/srv/live"}, Actions: []string{string(intent.ActionDeleteFile)}},
			Requires: contextspec.Requirement{Proofs: []string{"restore"}}, Enforcement: contextspec.EnforcementBlock,
			RequireVerified: false, RequireBound: requireBound,
		}},
		Proofs: []contextspec.Proof{{
			ID: "restore", Status: contextspec.ProofRecordValidated,
			ObservedAt: proofTime(), Verified: true,
			RecipeDigest: contextspec.RecipeDigest(drill), Dependencies: &deps,
		}},
		Drills: []contextspec.Drill{drill},
	}
}

func proofTime() *time.Time {
	now := fixedNow
	return &now
}

func TestEvaluateDependencyConflictUsesWholeIntentSetAndKeepsContextImmutable(t *testing.T) {
	ctx := dependencyContext(t, true)
	before := ctx
	intents := []intent.ChangeIntent{
		{Action: intent.ActionDeleteFile, Paths: []string{"/srv/live"}},
		// This intent does not match the live guard. It still intersects the
		// proof's recovery dependency and must invalidate the live decision.
		{Action: intent.ActionModifyFile, Paths: []string{"/etc/recovery.key"}},
	}
	findings := EvaluateWithOptions(intents, ctx, fixedNow, EvaluateOptions{})
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("cross-intent dependency conflict = %+v, want one block", findings)
	}
	if !strings.Contains(findings[0].Proof, "path: /etc/recovery.key") {
		t.Fatalf("dependency reason missing from proof detail: %q", findings[0].Proof)
	}
	if !strings.Contains(findings[0].RequiredNextStep, "independent recovery evidence") || !strings.Contains(findings[0].RequiredNextStep, "same dependency") {
		t.Fatalf("dependency next step is not actionable: %q", findings[0].RequiredNextStep)
	}
	if !reflect.DeepEqual(ctx, before) {
		t.Fatal("EvaluateWithOptions mutated context or proof data")
	}
}

func TestEvaluateDependencyConflictRequiresANDAcrossAlternatives(t *testing.T) {
	ctx := dependencyContext(t, false)
	intents := []intent.ChangeIntent{
		{Action: intent.ActionDeleteFile, Paths: []string{"/srv/live"}},
		{Action: intent.ActionPackageUpdate, Packages: []string{"vim"}},
		{Action: intent.ActionPackageUpdate, Packages: []string{"restic"}},
	}
	findings := Evaluate(intents, ctx, fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock {
		t.Fatalf("independent alternative invented OR semantics: %+v", findings)
	}
}

func TestEvaluateUnchangedArtifactAndUndeclaredDependencyPasses(t *testing.T) {
	ctx := dependencyContext(t, true)
	findings := Evaluate([]intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"/srv/live"}}}, ctx, fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictPass {
		t.Fatalf("unchanged undeclared dependency = %+v, want pass", findings)
	}
}

func TestEvaluateRecipeChangeAndLegacyRequireBoundBlock(t *testing.T) {
	ctx := dependencyContext(t, true)
	for _, change := range []struct {
		name  string
		apply func(*contextspec.Drill)
	}{
		{name: "recover command", apply: func(d *contextspec.Drill) { d.Recover = "cp /srv/changed-recovery /srv/live" }},
		{name: "recovery source", apply: func(d *contextspec.Drill) { d.RecoverySource = "/srv/changed-source" }},
	} {
		changed := ctx
		changed.Drills = append([]contextspec.Drill(nil), ctx.Drills...)
		change.apply(&changed.Drills[0])
		findings := Evaluate([]intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"/srv/live"}}}, changed, fixedNow)
		if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock || !strings.Contains(findings[0].Proof, "recipe binding") {
			t.Fatalf("changed %s = %+v, want binding block", change.name, findings)
		}
	}

	legacy := dependencyContext(t, false)
	legacy.Proofs[0].RecipeDigest = ""
	legacy.Proofs[0].Dependencies = nil
	legacy.Guards[0].RequireBound = true
	findings := Evaluate([]intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"/srv/live"}}}, legacy, fixedNow)
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock || !strings.Contains(findings[0].Proof, "without a recovery binding") {
		t.Fatalf("legacy require_bound = %+v, want block", findings)
	}
}
