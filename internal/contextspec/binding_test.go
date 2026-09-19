// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import (
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"
)

func boundFixture(t *testing.T) (Context, Proof, Drill, ed25519.PrivateKey) {
	t.Helper()
	drill := Drill{
		Proof: "p", Artifact: "/tmp/live", RecoverySource: "restic:snap",
		Recover: "restic restore latest", PinCheck: "restic snapshots",
		Validate:     []DrillCheck{{Type: "sqlite", Integrity: true, Tables: map[string]string{"users": ">=1"}}},
		Budgets:      DrillBudgets{RTO: 5 * time.Minute},
		Dependencies: Dependencies{Paths: []string{"/etc/restic"}, Commands: []string{"restic snapshots"}, Packages: []string{"restic"}},
	}
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	deps := NormalizeDependencies(drill.Dependencies)
	proof := Proof{ID: "p", Status: ProofRecordValidated, ObservedAt: &now, Verified: true,
		SHA256: "sha256:abc", Command: drill.Recover, RecipeDigest: RecipeDigest(drill), Dependencies: &deps}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature, err = SignProofV2(private, proof)
	if err != nil {
		t.Fatal(err)
	}
	return Context{Version: 2, Proofs: []Proof{proof}, Drills: []Drill{drill}}, proof, drill, private
}

func TestParseRejectsNonFiniteMeasurements(t *testing.T) {
	for _, value := range []string{".nan", ".inf", "-.inf"} {
		doc := `version: 2
proofs:
  - id: p
    status: observed
    observed_at: "2026-09-19T00:00:00Z"
    measurements:
      rto_seconds: ` + value + `
`
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Fatalf("Parse accepted non-finite rto_seconds %q", value)
		}
	}
	for _, value := range []string{".nan", ".inf", "-.inf"} {
		doc := `version: 2
proofs:
  - id: p
    status: observed
    observed_at: "2026-09-19T00:00:00Z"
    measurements:
      rto_seconds: 1
      rpo_seconds: ` + value + `
`
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Fatalf("Parse accepted non-finite rpo_seconds %q", value)
		}
	}
}

func TestRecipeDigestStableAndDoesNotMutateDependencies(t *testing.T) {
	drill := Drill{Artifact: "a", Recover: "r", Dependencies: Dependencies{
		Paths: []string{"b", "a", "a"}, Commands: []string{"z", "x"}, Packages: []string{"pkg"},
	}}
	original := append([]string(nil), drill.Dependencies.Paths...)
	one := RecipeDigest(drill)
	two := RecipeDigest(drill)
	if one != two || !reflect.DeepEqual(drill.Dependencies.Paths, original) {
		t.Fatalf("recipe digest was unstable or mutated dependencies: %q %q %+v", one, two, drill.Dependencies)
	}
	drill.Dependencies.Paths[0] = "changed"
	if RecipeDigest(drill) == one {
		t.Fatal("changed explicit dependency did not change recipe digest")
	}
}

func TestCheckProofBindingAndRequireBound(t *testing.T) {
	ctx, proof, drill, _ := boundFixture(t)
	now := *proof.ObservedAt
	if got := ctx.CheckProofWithBinding("p", 0, true, true, now); got.State != StatePresent {
		t.Fatalf("bound proof = %s (%s), want present", got.State, got.Detail)
	}
	drill.Recover = "changed recovery command"
	ctx.Drills[0] = drill
	if got := ctx.CheckProofWithBinding("p", 0, true, true, now); got.State != StateContradicted {
		t.Fatalf("changed recipe = %s (%s), want contradicted", got.State, got.Detail)
	}

	legacy := ctx
	legacy.Proofs = []Proof{{ID: "legacy", Status: ProofRecordObserved, ObservedAt: proof.ObservedAt}}
	if got := legacy.CheckProofWithBinding("legacy", 0, false, false, now); got.State != StatePresent {
		t.Fatalf("legacy default check = %s (%s), want present", got.State, got.Detail)
	}
	if got := legacy.CheckProofWithBinding("legacy", 0, false, true, now); got.State != StateMissing {
		t.Fatalf("legacy require_bound = %s (%s), want missing", got.State, got.Detail)
	}
}

func TestV2SignatureCoversDecisionFields(t *testing.T) {
	ctx, proof, _, _ := boundFixture(t)
	now := *proof.ObservedAt
	mutations := []func(*Proof){
		func(p *Proof) { p.Verified = false },
		func(p *Proof) { expiry := now.Add(time.Hour); p.ExpiresAt = &expiry },
		func(p *Proof) { observed := now.Add(time.Nanosecond); p.ObservedAt = &observed },
		func(p *Proof) { expiry := now.Add(time.Nanosecond); p.ExpiresAt = &expiry },
		func(p *Proof) { p.Dependencies = &Dependencies{Paths: []string{"changed"}} },
	}
	for i, mutate := range mutations {
		tampered := proof
		mutate(&tampered)
		copyCtx := ctx
		copyCtx.Proofs = []Proof{tampered}
		if got := copyCtx.CheckProofWithBinding("p", 0, false, true, now); got.State != StateContradicted {
			t.Errorf("mutation %d = %s (%s), want contradicted", i, got.State, got.Detail)
		}
	}
}

func TestLegacySignatureRemainsReadableButDoesNotClaimBinding(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	p := Proof{ID: "legacy", Status: ProofRecordValidated, ObservedAt: &now, SHA256: "sha256:old", Verified: true}
	message := []byte(SignedMessage(p.ID, string(p.Status), now.Format(time.RFC3339), p.SHA256, nil))
	p.Signature = &Signature{PublicKeyHex: hex.EncodeToString(private.Public().(ed25519.PublicKey)), SignatureHex: hex.EncodeToString(ed25519.Sign(private, message))}
	ctx := Context{Version: 2, Proofs: []Proof{p}}
	if got := ctx.CheckProofWithBinding("legacy", 0, false, false, now); got.State != StatePresent {
		t.Fatalf("legacy signature = %s (%s), want present", got.State, got.Detail)
	}
	if got := ctx.CheckProofWithBinding("legacy", 0, false, true, now); got.State != StateMissing {
		t.Fatalf("legacy require_bound = %s (%s), want missing", got.State, got.Detail)
	}
}
