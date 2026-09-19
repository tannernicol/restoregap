// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/drill"
)

func TestFullDrillBindsRecipeAndPinFailureClearsAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restoregap.yml")
	doc := `version: 2
drills:
  - proof: p
    artifact: /tmp/artifact
    recovery_source: restic:snap
    recover: restic restore latest
    pin_check: restic snapshots
    dependencies:
      paths: [/etc/restic]
      commands: [restic snapshots]
      packages: [restic]
proofs:
  - id: p
    status: observed
    observed_at: "2026-09-19T00:00:00Z"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	result := drill.Result{Proof: "p", Verified: true, PostHash: "sha256:post", Checks: []contextspec.CheckOutcome{{Type: "byte_identical", Pass: true, Detail: "match"}}}
	if err := recordDrillProofs(path, []drill.Result{result}, ctx.Drills, time.Hour, private, "drill"); err != nil {
		t.Fatal(err)
	}
	ctx, err = contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := ctx.Proofs[0]
	if p.RecipeDigest != contextspec.RecipeDigest(ctx.Drills[0]) || p.Dependencies == nil || p.Signature == nil || p.Signature.Version != 2 {
		t.Fatalf("full drill did not persist v2 binding: %+v", p)
	}
	if got := ctx.CheckProofWithBinding("p", 0, true, true, now); got.State != contextspec.StatePresent {
		t.Fatalf("fresh bound proof = %s (%s), want present", got.State, got.Detail)
	}

	pinRPO := 2.0
	passingPin := drill.Result{Proof: "p", Verified: true, Checks: []contextspec.CheckOutcome{{Type: "byte_identical", Pass: true, Detail: "pin only"}}, RTOSeconds: 3, RPOSeconds: &pinRPO}
	if err := recordDrillProofs(path, []drill.Result{passingPin}, ctx.Drills, time.Hour, private, "pin_check"); err != nil {
		t.Fatal(err)
	}
	ctx, err = contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p = ctx.Proofs[0]
	if p.Status != contextspec.ProofRecordObserved || p.Verified || p.RecipeDigest != "" || p.Dependencies != nil || p.Measurements != nil || p.Signature != nil {
		t.Fatalf("passing pin retained full-drill authority: %+v", p)
	}

	failedPin := drill.Result{Proof: "p", Verified: false, SourceUnreachable: true}
	if err := recordDrillProofs(path, []drill.Result{failedPin}, ctx.Drills, 0, private, "pin_check"); err != nil {
		t.Fatal(err)
	}
	ctx, err = contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p = ctx.Proofs[0]
	if p.RecipeDigest != "" || p.Dependencies != nil || p.Verified || p.Signature != nil {
		t.Fatalf("pin failure inherited full-drill authority: %+v", p)
	}
}

func TestChangedRecipeSameProofIDContradictsBoundProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restoregap.yml")
	doc := `version: 2
drills:
  - proof: p
    artifact: /tmp/artifact
    recover: echo one
proofs:
  - id: p
    status: validated
    observed_at: "2026-09-19T00:00:00Z"
    verified: true
    recipe_digest: sha256:wrong
    dependencies: {paths: [], commands: [], packages: []}
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx.CheckProofWithBinding("p", 0, false, true, time.Now()); got.State != contextspec.StateContradicted {
		t.Fatalf("changed recipe binding = %s (%s), want contradicted", got.State, got.Detail)
	}
}
