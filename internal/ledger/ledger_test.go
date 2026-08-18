// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func appendDecision(t *testing.T, path string, seq int, verdict string) Entry {
	t.Helper()
	now := time.Date(2026, 5, 14, 12, 0, seq, 0, time.UTC)
	id, err := NewULID(now, deterministicReader(seq))
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	entry, err := Append(path, EntryDecision, "agent/claude", Payload{
		Decision: &DecisionPayload{
			Verdict: verdict,
			Findings: []FindingRecord{
				{FindingID: "f1", GuardID: "g1", Resource: "~/.ssh/id_ed25519", Verdict: verdict, RiskClass: "cannot_prove_safe", ProofStatus: "missing"},
			},
			Actor: "agent/claude",
		},
	}, now, id)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return entry
}

// deterministicReader returns a reader whose bytes depend on seq, so
// successive test entries get distinct (but reproducible) ULIDs.
func deterministicReader(seq int) *repeatReader { return &repeatReader{b: byte(seq + 1)} }

type repeatReader struct{ b byte }

func (r *repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// TestAppendDrillPayloadRoundTrips: drill telemetry entries carry
// RTO/RPO as integer milliseconds (canonical.go's float-free invariant), and
// must round-trip and chain-verify exactly like every other entry type.
func TestAppendDrillPayloadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	rpoMs := int64(11532000)
	budgetRTOMet := true
	budgetRPOMet := false

	if _, err := AppendNow(path, EntryDrill, "agent/claude", Payload{
		Drill: &DrillPayload{
			ProofID: "money-db-recovery", Mode: "drill", Verified: false, Level: "data-valid",
			RTOMs: 4210, RPOMs: &rpoMs,
			BudgetRTOMet: &budgetRTOMet, BudgetRPOMet: &budgetRPOMet,
			Checks: []DrillCheckRecord{{Type: "sqlite", Pass: true}, {Type: "budget_rpo", Pass: false}},
		},
	}); err != nil {
		t.Fatalf("AppendNow: %v", err)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 || entries[0].Payload.Drill == nil {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	got := entries[0].Payload.Drill
	if got.ProofID != "money-db-recovery" || got.Mode != "drill" || got.Verified {
		t.Errorf("unexpected payload: %+v", got)
	}
	if got.Level != "data-valid" {
		t.Errorf("Level = %q, want data-valid", got.Level)
	}
	if got.RPOMs == nil || *got.RPOMs != rpoMs {
		t.Errorf("RPOMs = %v, want %d", got.RPOMs, rpoMs)
	}
	if got.BudgetRTOMet == nil || !*got.BudgetRTOMet || got.BudgetRPOMet == nil || *got.BudgetRPOMet {
		t.Errorf("unexpected budget verdicts: rto=%v rpo=%v", got.BudgetRTOMet, got.BudgetRPOMet)
	}
	if len(got.Checks) != 2 {
		t.Errorf("Checks = %+v, want 2 entries", got.Checks)
	}

	if res := VerifyEntries(entries); !res.OK {
		t.Errorf("chain should verify: %s", res.Reason)
	}
}

func TestAppendAndVerifyChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	e1 := appendDecision(t, path, 1, "block")
	e2 := appendDecision(t, path, 2, "pass")

	if e1.Prev != GenesisHash {
		t.Errorf("first entry prev = %q, want genesis", e1.Prev)
	}
	if e2.Prev != e1.Hash {
		t.Errorf("second entry prev = %q, want first entry's hash %q", e2.Prev, e1.Hash)
	}

	result, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK || result.EntryCount != 2 {
		t.Fatalf("Verify() = %+v, want OK with 2 entries", result)
	}
}

func TestVerifyEmptyLedgerIsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.jsonl")
	result, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK || result.EntryCount != 0 {
		t.Fatalf("Verify() on missing file = %+v, want OK/0", result)
	}
}

func TestVerifyDetectsTamperedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	appendDecision(t, path, 1, "block")
	appendDecision(t, path, 2, "pass")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := []byte(replaceOnce(string(raw), `"verdict":"pass"`, `"verdict":"block"`))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("Verify() should detect the tampered entry")
	}
	if result.FailedAt != 2 {
		t.Errorf("FailedAt = %d, want 2", result.FailedAt)
	}
}

func TestVerifyDetectsBrokenChainLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	appendDecision(t, path, 1, "block")
	appendDecision(t, path, 2, "pass")
	appendDecision(t, path, 3, "warn")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Corrupt entry 2's prev pointer so it no longer chains from entry 1.
	tampered := []byte(replaceOnce(string(raw), `"prev":"sha256:`, `"prev":"sha256:ffffffff`))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("Verify() should detect the broken chain link")
	}
	if result.FailedAt != 1 {
		t.Errorf("FailedAt = %d, want 1 (first entry's prev was corrupted)", result.FailedAt)
	}
}

func TestVerifyDetectsMalformedJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	appendDecision(t, path, 1, "block")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteString("{not valid json\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()

	if _, err := Verify(path); err == nil {
		t.Fatal("expected an error reading a ledger with a malformed JSON line")
	}
}

func replaceOnce(s, old, newStr string) string {
	idx := indexOf(s, old)
	if idx == -1 {
		return s
	}
	return s[:idx] + newStr + s[idx+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestActiveOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	id1, _ := NewULID(now, deterministicReader(1))
	if _, err := Append(path, EntryOverride, "tanner", Payload{Override: &OverridePayload{
		FindingID: "f1", ApprovedBy: "tanner", Reason: "confirmed off-machine copy", ExpiresAt: &future,
	}}, now, id1); err != nil {
		t.Fatalf("Append: %v", err)
	}
	id2, _ := NewULID(now.Add(time.Second), deterministicReader(2))
	if _, err := Append(path, EntryOverride, "tanner", Payload{Override: &OverridePayload{
		FindingID: "f2", ApprovedBy: "tanner", Reason: "expired override", ExpiresAt: &past,
	}}, now, id2); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	overrides := ActiveOverrides(entries, now)
	if len(overrides) != 1 || overrides[0].FindingID != "f1" {
		t.Fatalf("ActiveOverrides = %+v, want only f1 (f2's override expired)", overrides)
	}
}
