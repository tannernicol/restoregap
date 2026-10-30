// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

// TestAppendFsyncsBeforeReleasingTheLock is table-driven over fresh-ledger vs
// existing-ledger appends. It injects the syncFile/syncDir seams (a real
// fsync on a temp-dir filesystem isn't reliably observable from a unit test)
// to prove Append always calls syncFile exactly once per entry, and calls
// syncDir only when this Append is the one that just created the ledger
// file — see Append's doc comment for why both matter.
func TestAppendFsyncsBeforeReleasingTheLock(t *testing.T) {
	cases := []struct {
		name          string
		preexisting   bool // append one entry (creating the ledger) before the append under test
		wantDirSynced bool
	}{
		{name: "fresh ledger syncs file and directory", preexisting: false, wantDirSynced: true},
		{name: "existing ledger syncs file only, not directory again", preexisting: true, wantDirSynced: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ledger.jsonl")

			if tc.preexisting {
				appendDecision(t, path, 0, "pass")
			}

			origSyncFile, origSyncDir := syncFile, syncDir
			var fileSyncs, dirSyncs int
			syncFile = func(f *os.File) error {
				fileSyncs++
				return origSyncFile(f)
			}
			syncDir = func(dirPath string) error {
				dirSyncs++
				return origSyncDir(dirPath)
			}
			defer func() { syncFile, syncDir = origSyncFile, origSyncDir }()

			appendDecision(t, path, 1, "block")

			if fileSyncs != 1 {
				t.Errorf("syncFile calls = %d, want exactly 1", fileSyncs)
			}
			if gotDirSynced := dirSyncs > 0; gotDirSynced != tc.wantDirSynced {
				t.Errorf("syncDir called = %v (calls=%d), want %v", gotDirSynced, dirSyncs, tc.wantDirSynced)
			}
		})
	}
}

// TestAppendSurvivesDirectorySyncFailure proves the degrade-gracefully
// guarantee from Append's doc comment: a platform (here, an injected
// failure standing in for one that cannot open its ledger directory for
// sync) must not fail the append itself. Only the ledger file's own fsync
// is load-bearing; the directory fsync is a best-effort hardening extra.
func TestAppendSurvivesDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	origSyncDir := syncDir
	syncDir = func(string) error { return fmt.Errorf("injected: directory cannot be opened for sync") }
	defer func() { syncDir = origSyncDir }()

	entry := appendDecision(t, path, 1, "block")
	if entry.Hash == "" {
		t.Fatal("expected a valid entry despite the injected directory-sync failure")
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected the entry to be durably written despite the directory-sync failure, got %d entries", len(entries))
	}

	result, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected a valid chain, got: %s", result.Reason)
	}
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

// TestActiveOverridesLegacyNoExpiryHasThirtyDayMigrationGrace proves that an
// override written by an older binary remains readable during the documented
// migration window, but cannot become a permanent amnesty. This is deliberately
// a no-expires_at fixture: new writes must never create it.
func TestActiveOverridesLegacyNoExpiryHasThirtyDayMigrationGrace(t *testing.T) {
	created := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	legacy := Entry{
		Schema: SchemaVersion, ID: "legacy-override", CreatedAt: created, EntryType: EntryOverride,
		Payload: Payload{Override: &OverridePayload{FindingID: "f1", ApprovedBy: "tanner", Reason: "old binary"}},
	}

	if got := ActiveOverrides([]Entry{legacy}, created.Add(30*24*time.Hour-time.Second)); len(got) != 1 {
		t.Fatalf("legacy override should remain active through its 30-day migration grace, got %+v", got)
	}
	if got := ActiveOverrides([]Entry{legacy}, created.Add(30*24*time.Hour)); len(got) != 0 {
		t.Fatalf("legacy override must stop masking the finding after its 30-day migration grace, got %+v", got)
	}
}

// TestAppendConcurrentWritersProduceAValidChainWithExactCount is section 4's
// concurrency contract (docs/SCHEMA.md §Concurrent-safe ledger): timers,
// agents, and hooks on one box all append to the same ledger file at once.
// 50 goroutines each append 20 entries (1000 total) to one ledger path with
// no external synchronization beyond what Append itself provides (the
// <path>.lock flock around read-last-hash + write); the result must be
// exactly 1000 entries and a chain that verifies end to end — no
// interleaved writes, no lost entries, no broken links.
func TestAppendConcurrentWritersProduceAValidChainWithExactCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	const writers = 50
	const perWriter = 20
	var wg sync.WaitGroup
	errCh := make(chan error, writers*perWriter)
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				actor := fmt.Sprintf("agent/writer-%d", w)
				if _, err := AppendNow(path, EntryEpoch, actor, Payload{Epoch: &EpochPayload{Label: fmt.Sprintf("w%d-i%d", w, i)}}); err != nil {
					errCh <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent Append: %v", err)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != writers*perWriter {
		t.Fatalf("expected exactly %d entries, got %d", writers*perWriter, len(entries))
	}

	result, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected a valid chain, got broken at entry %d: %s", result.FailedAt, result.Reason)
	}
	if result.EntryCount != writers*perWriter {
		t.Fatalf("Verify counted %d entries, want %d", result.EntryCount, writers*perWriter)
	}
}
