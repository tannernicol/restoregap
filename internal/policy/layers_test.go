// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writeLayerFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const orgGuard = `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/data/**"]}
    enforcement: warn
    requires: {proofs: [p1]}
    max_proof_age_hours: 48
`

func TestMergeAddsNewGuardFromLaterLayer(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", orgGuard)
	host := writeLayerFile(t, dir, "host.yml", `version: 2
guards:
  - id: g2
    kind: guard
    match: {paths: ["/other/**"]}
    enforcement: block
`)

	ctx, findings, err := Merge([]string{org, host})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a pure add, got %+v", findings)
	}
	if len(ctx.Guards) != 2 {
		t.Fatalf("expected both guards present, got %d: %+v", len(ctx.Guards), ctx.Guards)
	}
	if _, ok := ctx.GuardByID("g1"); !ok {
		t.Error("org guard g1 must remain")
	}
	if _, ok := ctx.GuardByID("g2"); !ok {
		t.Error("host-added guard g2 must be present")
	}
}

func TestMergeTightensEnforcementAndRequirements(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", orgGuard)
	host := writeLayerFile(t, dir, "host.yml", `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/data/**", "/data2/**"]}
    enforcement: block
    requires: {proofs: [p1, p2]}
    max_proof_age_hours: 24
`)

	ctx, findings, err := Merge([]string{org, host})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a legal tighten, got %+v", findings)
	}
	g, ok := ctx.GuardByID("g1")
	if !ok {
		t.Fatal("g1 must be present")
	}
	if g.Enforcement != "block" {
		t.Errorf("expected tightened enforcement block, got %q", g.Enforcement)
	}
	if g.MaxProofAgeHours != 24 {
		t.Errorf("expected tightened max_proof_age_hours 24, got %d", g.MaxProofAgeHours)
	}
	if len(g.Requires.Proofs) != 2 {
		t.Errorf("expected the added required proof p2 to stick, got %v", g.Requires.Proofs)
	}
	if len(g.Match.Paths) != 2 {
		t.Errorf("expected the added matched path to stick, got %v", g.Match.Paths)
	}
}

func TestMergeIgnoresLoosenedEnforcementAndReportsFinding(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", orgGuard)
	host := writeLayerFile(t, dir, "host.yml", `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/data/**"]}
    enforcement: warn
    requires: {proofs: []}
`)

	ctx, findings, err := Merge([]string{org, host})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one loosening finding, got %+v", findings)
	}
	f := findings[0]
	if f.ID != "policy/loosened" || f.GuardID != "g1" || f.File != host || f.Verdict != "warn" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if got := f.String(); got != "policy/loosened g1 in "+host {
		t.Errorf("unexpected finding string: %q", got)
	}
	g, ok := ctx.GuardByID("g1")
	if !ok {
		t.Fatal("g1 must remain")
	}
	if len(g.Requires.Proofs) != 1 || g.Requires.Proofs[0] != "p1" {
		t.Errorf("the org guard's required proof must survive the ignored loosening attempt, got %v", g.Requires.Proofs)
	}
}

func TestMergeIgnoresRaisedMaxAgeAndDroppedPath(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", orgGuard)
	host := writeLayerFile(t, dir, "host.yml", `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/other/**"]}
    enforcement: warn
    requires: {proofs: [p1]}
    max_proof_age_hours: 96
`)

	ctx, findings, err := Merge([]string{org, host})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding (raised max age AND dropped path both loosen — still one guard-level finding), got %+v", findings)
	}
	g, _ := ctx.GuardByID("g1")
	if g.MaxProofAgeHours != 48 {
		t.Errorf("raising max_proof_age_hours must be ignored, got %d", g.MaxProofAgeHours)
	}
	if len(g.Match.Paths) != 1 || g.Match.Paths[0] != "/data/**" {
		t.Errorf("dropping a matched path must be ignored, got %v", g.Match.Paths)
	}
}

func TestMergeCannotRemoveAnOrgGuardByOmission(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", orgGuard)
	// The host layer never mentions g1 at all — a guard the data model has
	// no way to actively delete, only to not-tighten.
	host := writeLayerFile(t, dir, "host.yml", `version: 2
guards:
  - id: g2
    kind: guard
    match: {paths: ["/other/**"]}
    enforcement: warn
`)

	ctx, findings, err := Merge([]string{org, host})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("omission is not a loosening attempt, expected no findings, got %+v", findings)
	}
	if _, ok := ctx.GuardByID("g1"); !ok {
		t.Error("g1 must survive even though the host layer never re-declares it")
	}
	if _, ok := ctx.GuardByID("g2"); !ok {
		t.Error("g2 must be added")
	}
}

func TestMergeUnboundedToBoundedTightens(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/data/**"]}
    enforcement: warn
`)
	host := writeLayerFile(t, dir, "host.yml", `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/data/**"]}
    enforcement: warn
    max_proof_age_hours: 12
`)
	ctx, findings, err := Merge([]string{org, host})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("adding a bound where none existed tightens, expected no findings, got %+v", findings)
	}
	g, _ := ctx.GuardByID("g1")
	if g.MaxProofAgeHours != 12 {
		t.Errorf("expected the newly added bound to apply, got %d", g.MaxProofAgeHours)
	}
}

func TestMergeSameSetDifferentOrderSameResultForNonConflictingGuards(t *testing.T) {
	dir := t.TempDir()
	a := writeLayerFile(t, dir, "a.yml", `version: 2
guards:
  - id: g1
    kind: guard
    match: {paths: ["/a/**"]}
    enforcement: warn
`)
	b := writeLayerFile(t, dir, "b.yml", `version: 2
guards:
  - id: g2
    kind: guard
    match: {paths: ["/b/**"]}
    enforcement: warn
`)
	ctx1, f1, err := Merge([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, f2, err := Merge([]string{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if len(f1) != 0 || len(f2) != 0 {
		t.Fatalf("expected no findings either order, got %+v / %+v", f1, f2)
	}
	if len(ctx1.Guards) != 2 || len(ctx2.Guards) != 2 {
		t.Fatalf("expected both guards regardless of order: %+v / %+v", ctx1.Guards, ctx2.Guards)
	}
}

func TestMergeDuplicateProofIDAcrossFilesErrors(t *testing.T) {
	dir := t.TempDir()
	a := writeLayerFile(t, dir, "a.yml", `version: 2
proofs:
  - id: p1
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
`)
	b := writeLayerFile(t, dir, "b.yml", `version: 2
proofs:
  - id: p1
    status: validated
    observed_at: "2026-08-02T00:00:00Z"
`)
	if _, _, err := Merge([]string{a, b}); err == nil {
		t.Fatal("expected a duplicate proof id across files to error, same as contextspec.LoadAll")
	}
}

func TestMergeSinglePathIsPlainLoad(t *testing.T) {
	dir := t.TempDir()
	org := writeLayerFile(t, dir, "org.yml", orgGuard)
	ctx, findings, err := Merge([]string{org})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if findings != nil {
		t.Fatalf("a single path can never conflict, expected nil findings, got %+v", findings)
	}
	if len(ctx.Guards) != 1 {
		t.Fatalf("expected the one declared guard, got %+v", ctx.Guards)
	}
}
