// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/drill"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// TestDrillSignatureMatchesVerifier: a signature is only useful if the thing
// that checks it agrees on what was signed. contextspec.SignedMessage builds
// id|status|observed_at|sha256[|m=digest], so signing anything else would
// validate at write time and fail at read time — worse than not signing at
// all. This pins the message shape so the two cannot drift apart.
func TestDrillSignatureMatchesVerifier(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer := ed25519.NewKeyFromSeed(seed)

	id, status, observedAt, sha := "p1", "validated", "2026-08-04T00:00:00Z", "sha256:abc"
	msg := contextspec.SignedMessage(id, status, observedAt, sha, nil)
	sig := ed25519.Sign(signer, []byte(msg))

	pub, err := hex.DecodeString(hex.EncodeToString(signer.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatalf("public key round-trip: %v", err)
	}
	if !ed25519.Verify(pub, []byte(msg), sig) {
		t.Fatal("signature must verify over id|status|observed_at|sha256")
	}
	if ed25519.Verify(pub, []byte(msg+"x"), sig) {
		t.Error("a different message must not verify")
	}
}

func writeContext(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restoregap.yml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write context: %v", err)
	}
	return path
}

func loadContext(t *testing.T, path string) contextspec.Context {
	t.Helper()
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return ctx
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// ---- buildDrillProofEntry / recordDrillProofs --------------------------

func TestBuildDrillProofEntryVerifiedWithMeasurements(t *testing.T) {
	rpo := 3600.0
	res := drill.Result{
		Proof: "money-db", Verified: true, PostHash: "sha256:deadbeef",
		RTOSeconds: 4.21, RPOSeconds: &rpo,
		Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: true, Detail: "integrity ok"}},
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	entry := buildDrillProofEntry(res, "./recover.sh", now, time.Hour, nil)

	if entry["status"] != "validated" || entry["verified"] != true {
		t.Errorf("unexpected status/verified: %+v", entry)
	}
	if entry["command"] != "./recover.sh" {
		t.Errorf("command = %v, want the recover command", entry["command"])
	}
	if entry["expires_at"] == nil {
		t.Error("expires_at should be set when ttl > 0")
	}
	m, ok := entry["measurements"].(map[string]any)
	if !ok {
		t.Fatalf("measurements missing or wrong type: %+v", entry)
	}
	if m["rto_seconds"] != 4.21 {
		t.Errorf("rto_seconds = %v, want 4.21", m["rto_seconds"])
	}
	if m["rpo_seconds"] != &rpo {
		// compare by value since it's a pointer copy
		if got, ok := m["rpo_seconds"].(*float64); !ok || got == nil || *got != rpo {
			t.Errorf("rpo_seconds = %v, want %v", m["rpo_seconds"], rpo)
		}
	}
	checks, ok := m["checks"].([]any)
	if !ok || len(checks) != 1 {
		t.Fatalf("unexpected checks: %+v", m["checks"])
	}
}

// TestBuildDrillProofEntryEngineFailureHasNoMeasurements: a result with no
// Checks (a hard engine failure, or a pin_check verdict) must not carry a
// measurements: block — nothing was actually measured.
func TestBuildDrillProofEntryEngineFailureHasNoMeasurements(t *testing.T) {
	res := drill.Result{Proof: "p", Verified: false, Detail: "sandbox creation failed"}
	entry := buildDrillProofEntry(res, "./recover.sh", time.Now(), 0, nil)
	if entry["status"] != "disputed" || entry["verified"] != false {
		t.Errorf("unexpected status/verified: %+v", entry)
	}
	if _, present := entry["measurements"]; present {
		t.Errorf("measurements must be absent when no checks ran, got %+v", entry["measurements"])
	}
	if _, present := entry["signature"]; present {
		t.Error("a disputed record must never carry a signature")
	}
}

// TestBuildDrillProofEntryFailedChecksStillCarryMeasurements: a drill that
// ran to completion but failed a check (or a budget) is not the same as one
// that never ran — its measurements are exactly the useful telemetry, so
// they must still be attached even though verified is false.
func TestBuildDrillProofEntryFailedChecksStillCarryMeasurements(t *testing.T) {
	res := drill.Result{
		Proof: "p", Verified: false, RTOSeconds: 1.5,
		Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: false, Detail: "integrity FAILED: corrupt"}},
	}
	entry := buildDrillProofEntry(res, "./recover.sh", time.Now(), 0, nil)
	if _, present := entry["measurements"]; !present {
		t.Error("a failed-but-executed drill must still carry its measurements")
	}
}

// TestBuildDrillProofEntrySignsExactlyWhatVerifies: the signature attached
// must verify via contextspec.CheckProof against the same entry — proving
// the sign side and verify side (contextspec.SignedMessage) agree, not just
// that they happen to share a helper name.
func TestBuildDrillProofEntrySignsExactlyWhatVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rpo := 60.0
	res := drill.Result{
		Proof: "p", Verified: true, PostHash: "sha256:abc", RTOSeconds: 2, RPOSeconds: &rpo,
		Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: true, Detail: "ok"}},
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	entry := buildDrillProofEntry(res, "./recover.sh", now, 0, priv)

	sig, ok := entry["signature"].(map[string]any)
	if !ok {
		t.Fatalf("expected a signature, got %+v", entry)
	}
	if sig["public_key"] != hex.EncodeToString(pub) {
		t.Errorf("public_key mismatch")
	}

	observed, err := time.Parse(time.RFC3339, entry["observed_at"].(string))
	if err != nil {
		t.Fatalf("parse observed_at: %v", err)
	}
	rpoPtr := entry["measurements"].(map[string]any)["rpo_seconds"].(*float64)
	proof := contextspec.Proof{
		ID: "p", Status: contextspec.ProofRecordValidated, ObservedAt: &observed, SHA256: "sha256:abc",
		Measurements: &contextspec.Measurements{RTOSeconds: 2, RPOSeconds: rpoPtr, Checks: res.Checks},
		Signature: &contextspec.Signature{
			PublicKeyHex: sig["public_key"].(string), SignatureHex: sig["signature"].(string),
		},
	}
	ctx := contextspec.Context{Proofs: []contextspec.Proof{proof}}
	if got := ctx.CheckProof("p", 0, false, observed); got.State != contextspec.StatePresent {
		t.Errorf("signature built by buildDrillProofEntry must verify, got %s (%s)", got.State, got.Detail)
	}
}

const oneDrillYAML = `version: 2
drills:
  - proof: widget-recovery
    artifact: %s
    recover: %s
proofs:
  - id: unrelated-proof
    status: observed
    observed_at: "2026-01-01T00:00:00Z"
`

func TestRecordDrillProofsPreservesUnrelatedProofs(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("same\n"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	recover := fmt.Sprintf("cat %s > \"$RG_TARGET\"", artifact)
	path := writeContext(t, fmt.Sprintf(oneDrillYAML, artifact, recover))
	ctx := loadContext(t, path)

	results, err := runDrills(&bytes.Buffer{}, ctx.Drills, "", "")
	if err != nil {
		t.Fatalf("runDrills: %v", err)
	}
	if err := recordDrillProofs(path, results, ctx.Drills, 0, nil, "drill"); err != nil {
		t.Fatalf("recordDrillProofs: %v", err)
	}

	reloaded := loadContext(t, path)
	if len(reloaded.Proofs) != 2 {
		t.Fatalf("expected 2 proofs (unrelated + drilled), got %d: %+v", len(reloaded.Proofs), reloaded.Proofs)
	}
	var drilled, unrelated *contextspec.Proof
	for i := range reloaded.Proofs {
		switch reloaded.Proofs[i].ID {
		case "widget-recovery":
			drilled = &reloaded.Proofs[i]
		case "unrelated-proof":
			unrelated = &reloaded.Proofs[i]
		}
	}
	if drilled == nil || !drilled.Verified {
		t.Fatalf("widget-recovery proof missing or not verified: %+v", drilled)
	}
	if drilled.Measurements == nil || len(drilled.Measurements.Checks) != 1 || drilled.Measurements.Checks[0].Type != "byte_identical" {
		t.Errorf("unexpected measurements: %+v", drilled.Measurements)
	}
	if unrelated == nil || unrelated.Status != contextspec.ProofRecordObserved {
		t.Errorf("unrelated proof was not preserved: %+v", unrelated)
	}
}

// ---- pins-only ----------------------------------------------------------

const pinsOnlyYAML = `version: 2
drills:
  - proof: money-db-recovery
    artifact: /does/not/matter
    recovery_source: /backups/money
    recover: echo unused
    pin_check: %s
proofs:
  - id: money-db-recovery
    status: validated
    observed_at: "2026-08-01T00:00:00Z"
    sha256: sha256:existing
    verified: true
`

func TestPinsOnlyPassLeavesProofByteIdenticallyUntouched(t *testing.T) {
	path := writeContext(t, fmt.Sprintf(pinsOnlyYAML, "true"))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	ctx := loadContext(t, path)
	var out bytes.Buffer
	cmd := newDrillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--pins-only"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (output: %s)", err, out.String())
	}
	_ = ctx

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("a passing pin check must leave the context file byte-identical\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(out.String(), "pin ok") {
		t.Errorf("expected a pin-ok line, got %q", out.String())
	}
}

// TestPinsOnlyFailRecordsUnreachableNotDisputed: a pin_check attempts
// nothing but reaching the pinned source, so when the source path does not
// exist (the 2026-08-18 NAS-outage shape) the recorded status must be
// `unreachable` — "could not even try" — never `disputed`, which is reserved
// for a recovery that ran and did not verify. The command still exits
// non-zero: the distinction changes the report, never the gate.
func TestPinsOnlyFailRecordsUnreachableNotDisputed(t *testing.T) {
	path := writeContext(t, fmt.Sprintf(pinsOnlyYAML, "test -f \"$RG_RECOVERY_SOURCE\""))

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--pins-only"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("a failed pin check must exit non-zero")
	}

	reloaded := loadContext(t, path)
	if len(reloaded.Proofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(reloaded.Proofs))
	}
	p := reloaded.Proofs[0]
	if p.Status != contextspec.ProofRecordUnreachable || p.Verified {
		t.Errorf("proof should be unreachable/unverified after a failed pin, got status=%s verified=%v", p.Status, p.Verified)
	}
	if p.Measurements != nil {
		t.Error("an unreachable pin-check record must not carry measurements")
	}
	if p.Signature != nil {
		t.Error("an unreachable pin-check record must not carry a signature")
	}
	if !strings.Contains(out.String(), "pin FAILED") {
		t.Errorf("expected a pin-FAILED line, got %q", out.String())
	}
	if !strings.Contains(out.String(), "could not reach") {
		t.Errorf("the failing pin line must say the source could not be reached, got %q", out.String())
	}
	if strings.Contains(out.String(), "disputed") {
		t.Errorf("an unreachable pin failure must never read as disputed, got %q", out.String())
	}
}

func TestPinsOnlySkipsDrillsWithoutPinCheck(t *testing.T) {
	yaml := `version: 2
drills:
  - proof: no-pin
    artifact: /does/not/matter
    recover: echo unused
`
	path := writeContext(t, yaml)
	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--pins-only"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("a drill with no pin_check must be skipped silently, not error: %v (%s)", err, out.String())
	}
	if out.String() != "" {
		t.Errorf("expected no output for an all-skipped run, got %q", out.String())
	}
}

// ---- full-drill recording: disputed vs unreachable ------------------------
//
// The recording rule under test, end to end through the real command: a
// recovery that RAN and failed (a declared check, or a declared budget) is
// `disputed`; a recovery whose SOURCE could not be reached is `unreachable`.
// All of these exit non-zero — the statuses differ, the gate does not.

// runFullDrill executes `restoregap drill` (full run) on a context built
// from one drills: entry and returns the recorded proof plus the combined
// output.
func runFullDrill(t *testing.T, drillsYAML string) (contextspec.Proof, string, error) {
	t.Helper()
	path := writeContext(t, fmt.Sprintf("version: 2\ndrills:\n%s", drillsYAML))
	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path})
	err := cmd.Execute()
	reloaded := loadContext(t, path)
	if len(reloaded.Proofs) != 1 {
		t.Fatalf("expected 1 recorded proof, got %d (err=%v, out=%s)", len(reloaded.Proofs), err, out.String())
	}
	return reloaded.Proofs[0], out.String(), err
}

// TestFullDrillFailedCheckRecordsDisputed: the recovery ran, the artifact
// came back, and a declared check failed — the classic "your copy is bad".
func TestFullDrillFailedCheckRecordsDisputed(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "content\n")
	recover := fmt.Sprintf("cat %s > \"$RG_TARGET\"", artifact)
	p, out, err := runFullDrill(t, fmt.Sprintf(`  - proof: p
    artifact: %s
    recover: %s
    validate:
      - type: command
        run: "exit 1"
`, artifact, recover))
	if err == nil {
		t.Fatal("a failed declared check must exit non-zero")
	}
	if p.Status != contextspec.ProofRecordDisputed || p.Verified {
		t.Errorf("a failed check records disputed, got status=%s verified=%v", p.Status, p.Verified)
	}
	if !strings.Contains(out, "disputed") {
		t.Errorf("operator output should name the disputed recording, got %q", out)
	}
}

// TestFullDrillMissedBudgetRecordsDisputed: the recovery ran and its checks
// passed, but a declared RTO budget was blown — measured against real
// telemetry, so still a verified-failure, still disputed.
func TestFullDrillMissedBudgetRecordsDisputed(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "content\n")
	recover := fmt.Sprintf("cat %s > \"$RG_TARGET\"", artifact)
	p, out, err := runFullDrill(t, fmt.Sprintf(`  - proof: p
    artifact: %s
    recover: %s
    budgets: { rto: 1ns }
`, artifact, recover))
	if err == nil {
		t.Fatal("a missed budget must exit non-zero")
	}
	if p.Status != contextspec.ProofRecordDisputed || p.Verified {
		t.Errorf("a missed budget records disputed, got status=%s verified=%v", p.Status, p.Verified)
	}
	if !strings.Contains(out, "disputed") {
		t.Errorf("operator output should name the disputed recording, got %q", out)
	}
}

// TestFullDrillUnreachableSourceRecordsUnreachable: the recover command
// fails because the source is missing — nothing was attempted that could
// verify anything. The recorded status and the operator output must both say
// unreachable, and neither may say disputed.
func TestFullDrillUnreachableSourceRecordsUnreachable(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "content\n")
	p, out, err := runFullDrill(t, fmt.Sprintf(`  - proof: p
    artifact: %s
    recovery_source: /nonexistent/recovery/source.gpg
    recover: cat "$RG_RECOVERY_SOURCE" > "$RG_TARGET"
`, artifact))
	if err == nil {
		t.Fatal("an unreachable source must exit non-zero")
	}
	if p.Status != contextspec.ProofRecordUnreachable || p.Verified {
		t.Errorf("a source-unreachable failure records unreachable, got status=%s verified=%v", p.Status, p.Verified)
	}
	if !strings.Contains(out, "unreachable") {
		t.Errorf("operator output should say the source could not be reached, got %q", out)
	}
	if strings.Contains(out, "disputed") {
		t.Errorf("a source-unreachable failure must not read as disputed, got %q", out)
	}
}

// ---- formatDrillLine ------------------------------------------------------

func TestFormatDrillLine(t *testing.T) {
	rpo := 11532.0
	pass := drill.Result{
		Proof: "p", Verified: true, RTOSeconds: 4.2, RPOSeconds: &rpo, Detail: "integrity ok",
		Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: true, Detail: "integrity ok"}},
	}
	line := formatDrillLine(pass)
	if !strings.HasPrefix(line, "✓ p — data-valid (L3) in") || !strings.Contains(line, "integrity ok") {
		t.Errorf("unexpected pass line: %q", line)
	}
	if !strings.Contains(line, "RPO") {
		t.Errorf("pass line should surface RPO when measured: %q", line)
	}

	// A serve check earns the top rung, and the level shown must not
	// duplicate a second, hand-rolled type -> rung mapping in this package
	// — it has to come from contextspec.LevelFromChecks.
	servePass := drill.Result{
		Proof: "p", Verified: true, RTOSeconds: 2.1, Detail: "ready in 800ms",
		Checks: []contextspec.CheckOutcome{{Type: "serve", Pass: true, Detail: "ready in 800ms"}},
	}
	line = formatDrillLine(servePass)
	if !strings.HasPrefix(line, "✓ p — serves (L4) in") {
		t.Errorf("unexpected serve pass line: %q", line)
	}

	fail := drill.Result{
		Proof: "p", Verified: false, RTOSeconds: 1, Detail: "sqlite: integrity FAILED: corrupt",
		Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: false, Detail: "integrity FAILED: corrupt"}},
	}
	line = formatDrillLine(fail)
	if !strings.HasPrefix(line, "✗ p — NOT verified") || !strings.Contains(line, "integrity FAILED") {
		t.Errorf("unexpected fail line: %q", line)
	}
	if strings.Contains(line, "(L") {
		t.Errorf("a failed drill must never claim a level, got %q", line)
	}

	errRes := drill.Result{Proof: "p", Err: fmt.Errorf("boom")}
	line = formatDrillLine(errRes)
	if line != "✗ p — boom" {
		t.Errorf("unexpected error line: %q", line)
	}
}

// ---- ledger telemetry -----------------------------------------------------

func TestAppendDrillLedgerEntries(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	rpo := 100.0
	results := []drill.Result{
		{Proof: "p1", Verified: true, RTOSeconds: 4.2, RPOSeconds: &rpo,
			Checks: []contextspec.CheckOutcome{{Type: "sqlite", Pass: true}}},
	}
	drills := []contextspec.Drill{{Proof: "p1", Budgets: contextspec.DrillBudgets{RTO: time.Minute, RPO: time.Hour}}}

	var warn bytes.Buffer
	appendDrillLedgerEntries(&warn, ledgerPath, "ctx.yml", "agent/claude", "drill", results, drills)
	if warn.Len() != 0 {
		t.Errorf("unexpected warning: %s", warn.String())
	}

	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 || entries[0].Payload.Drill == nil {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	got := entries[0].Payload.Drill
	if got.ProofID != "p1" || got.Mode != "drill" || !got.Verified {
		t.Errorf("unexpected payload: %+v", got)
	}
	if got.Level != "data-valid" {
		t.Errorf("Level = %q, want data-valid (from the passing sqlite check)", got.Level)
	}
	if got.RTOMs != 4200 {
		t.Errorf("RTOMs = %d, want 4200", got.RTOMs)
	}
	if got.BudgetRTOMet == nil || !*got.BudgetRTOMet {
		t.Errorf("BudgetRTOMet = %v, want true (4.2s within a 1m budget)", got.BudgetRTOMet)
	}
	if got.BudgetRPOMet == nil || !*got.BudgetRPOMet {
		t.Errorf("BudgetRPOMet = %v, want true (100s within a 1h budget)", got.BudgetRPOMet)
	}
}

// TestAppendDrillLedgerEntriesNonFatalOnFailure: recovery proof already
// happened by the time telemetry is appended — a broken ledger path must
// warn, never make the drill command itself fail.
func TestAppendDrillLedgerEntriesNonFatalOnFailure(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "no-such-dir", "ledger.jsonl")
	results := []drill.Result{{Proof: "p1", Verified: true}}
	var warn bytes.Buffer
	appendDrillLedgerEntries(&warn, badPath, "", "", "drill", results, nil)
	if !strings.Contains(warn.String(), "WARNING") || !strings.Contains(warn.String(), "p1") {
		t.Errorf("expected a loud warning naming the proof, got %q", warn.String())
	}
}

func TestAppendDrillLedgerEntriesSkippedWhenNoLedgerPath(t *testing.T) {
	var warn bytes.Buffer
	appendDrillLedgerEntries(&warn, "", "", "", "drill", []drill.Result{{Proof: "p1"}}, nil)
	if warn.Len() != 0 {
		t.Errorf("no --ledger flag means no telemetry attempt at all, got %q", warn.String())
	}
}

// ---- drill --lint ----------------------------------------------------

const lintCleanYAML = `version: 2
drills:
  - proof: clean
    artifact: %s
    recover: "true"
    pin_check: "true"
`

const lintDirtyYAML = `version: 2
drills:
  - proof: no-pin-no-artifact
    artifact: /nonexistent/path/for/lint/test
    recover: "true"
  - proof: rpo-no-source
    artifact: %s
    recover: "true"
    pin_check: "true"
    budgets: { rpo: 1h }
`

func TestDrillLintCleanExitsZeroWithNoOutput(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(lintCleanYAML, artifact))

	var out bytes.Buffer
	cmd := newDrillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--lint"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("a clean drill must not error: %v (%s)", err, out.String())
	}
	if out.String() != "" {
		t.Errorf("a clean drill should print nothing, got %q", out.String())
	}
}

func TestDrillLintReportsFindingsAndExitCode(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(lintDirtyYAML, artifact))

	var out, errOut bytes.Buffer
	cmd := newDrillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--context", path, "--lint"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("an error-level finding must fail the command")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an *ExitError so the process exits 1, got %T: %v", err, err)
	}
	if exitErr.Code != 1 {
		t.Errorf("Code = %d, want 1", exitErr.Code)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	// no-pin-no-artifact: 2 warns (pin_check, artifact). rpo-no-source: 1 error (rpo).
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), out.String())
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "error: ") && !strings.HasPrefix(l, "warn: ") {
			t.Errorf("line not agent-parseable (missing error:/warn: prefix): %q", l)
		}
	}
	joined := out.String()
	if !strings.Contains(joined, "error: rpo-no-source:") {
		t.Errorf("expected the rpo error tagged with its proof id, got %q", joined)
	}
	if !strings.Contains(joined, "warn: no-pin-no-artifact:") {
		t.Errorf("expected warns tagged with their proof id, got %q", joined)
	}
}

func TestDrillLintDoesNotRecoverOrWrite(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	marker := filepath.Join(dir, "recover-ran")
	yaml := fmt.Sprintf(`version: 2
drills:
  - proof: must-not-run
    artifact: %s
    recover: "touch %s"
`, artifact, marker)
	path := writeContext(t, yaml)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	var out bytes.Buffer
	cmd := newDrillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--lint"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("--lint must never run the recover command")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("--lint must never write the context file")
	}
}

func TestDrillLintProofFilter(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(lintDirtyYAML, artifact))

	var out bytes.Buffer
	cmd := newDrillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--lint", "--proof", "rpo-no-source"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rpo-no-source alone still has its error finding")
	}
	if strings.Contains(out.String(), "no-pin-no-artifact") {
		t.Errorf("--proof filter should exclude the other drill entirely, got %q", out.String())
	}
}

func TestDrillLintUnknownProofErrors(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "x")
	path := writeContext(t, fmt.Sprintf(lintCleanYAML, artifact))

	var out bytes.Buffer
	cmd := newDrillCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--context", path, "--lint", "--proof", "nope"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("an unknown --proof value must error")
	}
}

// TestRecordDrillProofsPreservesTaxonomyFieldsAndStampsHost (taxonomy spec
// sections A and F): a re-drill rewrites the drilled proof's own fields but
// must round-trip everything it does not own — layer:/category:/scope: —
// and stamp scope.host with the current hostname when the proof declares
// no host of its own (never overriding one it does declare).
func TestRecordDrillProofsPreservesTaxonomyFieldsAndStampsHost(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("same\n"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	recover := fmt.Sprintf("cat %s > \"$RG_TARGET\"", artifact)
	path := writeContext(t, fmt.Sprintf(`version: 2
drills:
  - proof: widget-recovery
    artifact: %s
    recover: %s
proofs:
  - id: widget-recovery
    status: observed
    observed_at: "2026-01-01T00:00:00Z"
    layer: data-apps
    category: widgets
    scope:
      environment: prod
      system: money
`, artifact, recover))
	ctx := loadContext(t, path)

	results, err := runDrills(&bytes.Buffer{}, ctx.Drills, "", "")
	if err != nil {
		t.Fatalf("runDrills: %v", err)
	}
	if err := recordDrillProofs(path, results, ctx.Drills, 0, nil, "drill"); err != nil {
		t.Fatalf("recordDrillProofs: %v", err)
	}

	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skipf("hostname unavailable on this machine, cannot assert the host stamp")
	}

	reloaded := loadContext(t, path)
	var drilled *contextspec.Proof
	for i := range reloaded.Proofs {
		if reloaded.Proofs[i].ID == "widget-recovery" {
			drilled = &reloaded.Proofs[i]
		}
	}
	if drilled == nil {
		t.Fatal("widget-recovery proof missing after drill")
	}
	if !drilled.Verified {
		t.Fatalf("drill did not verify: %+v", drilled)
	}
	if drilled.Layer != "data-apps" || drilled.Category != "widgets" {
		t.Errorf("a re-drill must not drop the proof's declared layer/category, got %q/%q", drilled.Layer, drilled.Category)
	}
	if drilled.Scope.Environment != "prod" || drilled.Scope.System != "money" {
		t.Errorf("a re-drill must not drop the proof's declared scope fields, got %+v", drilled.Scope)
	}
	if drilled.Scope.Host != host {
		t.Errorf("scope.host = %q, want the current hostname %q", drilled.Scope.Host, host)
	}
}
