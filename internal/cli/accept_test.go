// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// acceptFixture is one never-drilled, currently-good attestation — the
// undrillable-proof case `restoregap accept` exists for.
const acceptFixture = `version: 2
proofs:
  - id: phone-reprovision-path
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`

func runAccept(t *testing.T, ledgerPath string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("RESTOREGAP_LEDGER", ledgerPath)
	cmd := newAcceptCmd()
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestAcceptWritesAcceptedBlock: the happy path — accepted: lands on the
// named proof, a sibling .bak.<UTC> backup is left, and a ledger "accept"
// entry records who/why.
func TestAcceptWritesAcceptedBlock(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", acceptFixture)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	out, err := runAccept(t, ledgerPath, "--context", ctxPath, "phone-reprovision-path",
		"--reason", "cannot be drilled unattended", "--by", "owner/tanner")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "accepted phone-reprovision-path") {
		t.Errorf("expected confirmation output, got %q", out)
	}

	ctx := loadContext(t, ctxPath)
	proof, ok := findProof(ctx.Proofs, "phone-reprovision-path")
	if !ok {
		t.Fatal("proof missing after accept")
	}
	if proof.Accepted == nil {
		t.Fatal("accepted: block was not written")
	}
	if proof.Accepted.By != "owner/tanner" || proof.Accepted.Reason != "cannot be drilled unattended" {
		t.Errorf("unexpected acceptance: %+v", proof.Accepted)
	}
	if !proof.Accepted.ReviewBy.After(proof.Accepted.At) {
		t.Errorf("review_by must be after at, got %+v", proof.Accepted)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sawBackup bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "restoregap.yml.bak.") {
			sawBackup = true
		}
	}
	if !sawBackup {
		t.Error("expected a sibling restoregap.yml.bak.<UTC> backup")
	}

	ledgerEntries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var sawAccept bool
	for _, e := range ledgerEntries {
		if e.EntryType == ledger.EntryAccept && e.Payload.Accept != nil &&
			e.Payload.Accept.ProofID == "phone-reprovision-path" && e.Payload.Accept.By == "owner/tanner" {
			sawAccept = true
		}
	}
	if !sawAccept {
		t.Errorf("expected an accept ledger entry, got %+v", ledgerEntries)
	}
}

// TestAcceptClearRemovesBlock: --clear deletes accepted: from the proof and
// appends an accept_clear ledger entry.
func TestAcceptClearRemovesBlock(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", acceptFixture)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	if _, err := runAccept(t, ledgerPath, "--context", ctxPath, "phone-reprovision-path",
		"--reason", "cannot be drilled unattended"); err != nil {
		t.Fatalf("accept: %v", err)
	}

	out, err := runAccept(t, ledgerPath, "--context", ctxPath, "--clear", "phone-reprovision-path")
	if err != nil {
		t.Fatalf("accept --clear: %v (%s)", err, out)
	}
	if !strings.Contains(out, "cleared acceptance") {
		t.Errorf("expected clear confirmation, got %q", out)
	}

	ctx := loadContext(t, ctxPath)
	proof, ok := findProof(ctx.Proofs, "phone-reprovision-path")
	if !ok {
		t.Fatal("proof missing after clear")
	}
	if proof.Accepted != nil {
		t.Errorf("accepted: block should be gone, got %+v", proof.Accepted)
	}

	ledgerEntries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var sawClear bool
	for _, e := range ledgerEntries {
		if e.EntryType == ledger.EntryAcceptClear && e.Payload.AcceptClear != nil &&
			e.Payload.AcceptClear.ProofID == "phone-reprovision-path" {
			sawClear = true
		}
	}
	if !sawClear {
		t.Errorf("expected an accept_clear ledger entry, got %+v", ledgerEntries)
	}
}

// TestAcceptClearNoAcceptanceIsNoop: clearing a proof with no acceptance
// recorded is a silent, idempotent no-op — nothing to audit.
func TestAcceptClearNoAcceptanceIsNoop(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", acceptFixture)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	out, err := runAccept(t, ledgerPath, "--context", ctxPath, "--clear", "phone-reprovision-path")
	if err != nil {
		t.Fatalf("accept --clear: %v (%s)", err, out)
	}
	if !strings.Contains(out, "nothing to clear") {
		t.Errorf("expected a nothing-to-clear message, got %q", out)
	}
	if _, err := os.Stat(ledgerPath); err == nil {
		t.Error("a no-op clear must not create a ledger file")
	}
}

// TestAcceptRefusesEmptyReason: exit 2, no write, no backup — an acceptance
// without a reason is a rubber stamp.
func TestAcceptRefusesEmptyReason(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", acceptFixture)
	before, err := os.ReadFile(ctxPath)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	_, err = runAccept(t, ledgerPath, "--context", ctxPath, "phone-reprovision-path")
	if err == nil {
		t.Fatal("expected an error for an empty --reason")
	}
	exit, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if exit.Code != 2 {
		t.Errorf("exit code = %d, want 2", exit.Code)
	}
	after, err := os.ReadFile(ctxPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("context file must be unchanged when --reason is empty")
	}
}

// TestAcceptUnknownProofSuggestsClosest: exit 2, naming the nearest declared
// id — the same did-you-mean helper explain uses.
func TestAcceptUnknownProofSuggestsClosest(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", acceptFixture)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	_, err := runAccept(t, ledgerPath, "--context", ctxPath, "phone-reprovision-pat", "--reason", "x")
	if err == nil {
		t.Fatal("expected an error for an unknown proof id")
	}
	exit, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if exit.Code != 2 {
		t.Errorf("exit code = %d, want 2", exit.Code)
	}
	if !strings.Contains(exit.Message, "no proof phone-reprovision-pat") ||
		!strings.Contains(exit.Message, "did you mean: phone-reprovision-path") {
		t.Errorf("message should name the id and the nearest candidate, got %q", exit.Message)
	}
}

// TestAcceptAlreadyRestoredPrintsNote: accepting a proof that already earns
// restores-or-better is allowed, but the command says so rather than
// silently writing a meaningless acceptance.
func TestAcceptAlreadyRestoredPrintsNote(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", `version: 2
drills:
  - proof: vault-recovery
    artifact: /fake/vault
    recover: "true"
proofs:
  - id: vault-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
    verified: true
`)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	out, err := runAccept(t, ledgerPath, "--context", ctxPath, "vault-recovery", "--reason", "belt and suspenders")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}
	if !strings.Contains(out, "note:") || !strings.Contains(out, "already") {
		t.Errorf("expected a note about the proof already restoring, got %q", out)
	}

	ctx := loadContext(t, ctxPath)
	proof, ok := findProof(ctx.Proofs, "vault-recovery")
	if !ok || proof.Accepted == nil {
		t.Fatal("acceptance should still be written even though the proof already restores")
	}
}

// TestAcceptPreservesLayerCategoryScope: taxonomy spec section A requires
// that unknown-to-accept fields round-trip unchanged whenever a command
// rewrites a context file — accept already rewrites the file to add
// accepted:, so a proof's own declared layer:/category:/scope: (fields
// accept.go never reads or writes) must survive byte-for-byte through that
// rewrite, and the accepted: block must land alongside them, not in place of
// them.
func TestAcceptPreservesLayerCategoryScope(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", `version: 2
proofs:
  - id: phone-reprovision-path
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
    layer: recovery-kit
    category: phone-reprov
    scope:
      environment: prod
      system: identity
      owner: tanner
      tags: ["kit"]
`)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	out, err := runAccept(t, ledgerPath, "--context", ctxPath, "phone-reprovision-path",
		"--reason", "cannot be drilled unattended", "--by", "owner/tanner")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}

	ctx := loadContext(t, ctxPath)
	proof, ok := findProof(ctx.Proofs, "phone-reprovision-path")
	if !ok {
		t.Fatal("proof missing after accept")
	}
	if proof.Accepted == nil {
		t.Fatal("accepted: block was not written")
	}
	if proof.Layer != "recovery-kit" {
		t.Errorf("Layer = %q, want %q to survive the accept rewrite", proof.Layer, "recovery-kit")
	}
	if proof.Category != "phone-reprov" {
		t.Errorf("Category = %q, want %q to survive the accept rewrite", proof.Category, "phone-reprov")
	}
	if proof.Scope.Environment != "prod" || proof.Scope.System != "identity" || proof.Scope.Owner != "tanner" || len(proof.Scope.Tags) != 1 || proof.Scope.Tags[0] != "kit" {
		t.Errorf("Scope = %+v, want environment=prod system=identity owner=tanner tags=[kit] to survive the accept rewrite", proof.Scope)
	}
	if proof.Scope.Host == "" {
		t.Error("accept must stamp scope.host with the current hostname (taxonomy spec section F) when the proof declares none")
	}
}

// TestAcceptStampsScopeHost (taxonomy spec section F): attesting writes
// scope.host onto the proof when it declares none — the seam a later
// machine-id stamp (bead tanner-jyzp) will harden — while the file-level
// scope default fields still apply to the reloaded proof.
func TestAcceptStampsScopeHost(t *testing.T) {
	dir := t.TempDir()
	ctxPath := writeFile(t, dir, "restoregap.yml", `version: 2
scope:
  environment: prod
  system: money
proofs:
  - id: phone-reprovision-path
    status: observed
    observed_at: "2026-08-20T00:00:00Z"
`)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	out, err := runAccept(t, ledgerPath, "--context", ctxPath, "phone-reprovision-path",
		"--reason", "cannot be drilled unattended", "--by", "owner/tanner")
	if err != nil {
		t.Fatalf("Execute: %v (%s)", err, out)
	}

	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skipf("hostname unavailable on this machine, cannot assert the host stamp")
	}
	ctx := loadContext(t, ctxPath)
	proof, ok := findProof(ctx.Proofs, "phone-reprovision-path")
	if !ok {
		t.Fatal("proof missing after accept")
	}
	if proof.Scope.Host != host {
		t.Errorf("scope.host = %q, want the current hostname %q", proof.Scope.Host, host)
	}
	if eff := contextspec.EffectiveProofScope(ctx, proof); eff.Environment != "prod" || eff.System != "money" || eff.Host != host {
		t.Errorf("effective scope = %+v, want the file-level defaults (prod/money) plus the stamped host", eff)
	}
}
