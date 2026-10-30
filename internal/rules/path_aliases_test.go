// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/intent"
)

func aliasBoundContext(t *testing.T) contextspec.Context {
	t.Helper()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	drill := contextspec.Drill{Proof: "restore", Artifact: "/real/live", RecoverySource: "/real/recovery", Recover: "cp /real/recovery /real/live", Dependencies: contextspec.Dependencies{Paths: []string{"/alias/recovery.key"}}}
	deps := contextspec.NormalizeDependencies(drill.Dependencies)
	proof := contextspec.Proof{ID: "restore", Status: contextspec.ProofRecordValidated, ObservedAt: &now, Verified: true, RecipeDigest: contextspec.RecipeDigest(drill), Dependencies: &deps}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature, err = contextspec.SignProofV2(private, proof)
	if err != nil {
		t.Fatal(err)
	}
	return contextspec.Context{Version: 2, Guards: []contextspec.Guard{{ID: "live", Kind: contextspec.GuardKindLifeline, Match: contextspec.Matcher{Paths: []string{"/alias/live"}, Actions: []string{string(intent.ActionDeleteFile)}}, Requires: contextspec.Requirement{Proofs: []string{"restore"}}, Enforcement: contextspec.EnforcementBlock, RequireVerified: true, RequireBound: true}}, Proofs: []contextspec.Proof{proof}, Drills: []contextspec.Drill{drill}}
}

func TestPathAliasesPreserveBoundProofAndContextBytes(t *testing.T) {
	ctx := aliasBoundContext(t)
	before, err := json.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	findings := EvaluateWithOptions([]intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"/real/live"}}}, ctx, now, EvaluateOptions{PathAliases: map[string]string{"/alias/live": "/real/live"}, RequireCoverage: true})
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictPass {
		t.Fatalf("alias guard findings = %+v, want one pass", findings)
	}
	if got := ctx.CheckProofWithBinding("restore", 0, true, true, now); got.State != contextspec.StatePresent {
		t.Fatalf("bound signed proof after evaluation = %s (%s)", got.State, got.Detail)
	}
	after, err := json.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("EvaluateWithOptions changed original context JSON")
	}
}

func TestPathAliasesBlockCanonicalRecoveryDependencyIntersection(t *testing.T) {
	ctx := aliasBoundContext(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	findings := EvaluateWithOptions([]intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"/real/live"}}, {Action: intent.ActionModifyFile, Paths: []string{"/real/recovery.key"}}}, ctx, now, EvaluateOptions{PathAliases: map[string]string{"/alias/live": "/real/live", "/alias/recovery.key": "/real/recovery.key"}})
	if len(findings) != 1 || findings[0].Verdict != engine.VerdictBlock || !strings.Contains(findings[0].Proof, "path: ") {
		t.Fatalf("alias dependency findings = %+v, want dependency block", findings)
	}
}
