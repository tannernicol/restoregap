// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chainEntry finishes building e: sets Prev to prev, computes and sets Hash
// from e's current content, and returns it. Building entries this way (hand
// constructed + hashEntry, no file I/O) lets these tests place a chain_anchor
// entry anywhere in the sequence — including invalid positions Append could
// never produce on its own, like before the entry it claims to vouch for.
func chainEntry(t *testing.T, prev string, e Entry) Entry {
	t.Helper()
	e.Prev = prev
	e.Hash = ""
	hash, err := hashEntry(e)
	if err != nil {
		t.Fatalf("hashEntry: %v", err)
	}
	e.Hash = hash
	return e
}

func decisionEntry(id string, seq int, verdict string) Entry {
	now := time.Date(2026, 5, 14, 12, 0, seq, 0, time.UTC)
	return Entry{
		Schema: SchemaVersion, ID: id, CreatedAt: now, EntryType: EntryDecision, Actor: "agent/claude",
		Payload: Payload{Decision: &DecisionPayload{
			Verdict: verdict,
			Findings: []FindingRecord{
				{FindingID: "f1", GuardID: "g1", Resource: "example-resource", Verdict: verdict, RiskClass: "cannot_prove_safe", ProofStatus: "missing"},
			},
			Actor: "agent/claude",
		}},
	}
}

// tamperPayload returns a copy of e with its Decision payload's Verdict
// flipped but its Hash left exactly as-is — simulating an entry whose
// content was mutated after it was written and hashed, the same corruption
// TestVerifyDetectsTamperedEntry (ledger_test.go) exercises via raw-byte
// replacement. e must carry a Decision payload.
func tamperPayload(e Entry) Entry {
	flipped := "block"
	if e.Payload.Decision.Verdict == "block" {
		flipped = "pass"
	}
	e.Payload = Payload{Decision: &DecisionPayload{
		Verdict: flipped,
		Findings: []FindingRecord{
			{FindingID: "f1", GuardID: "g1", Resource: "example-resource", Verdict: e.Payload.Decision.Verdict, RiskClass: "cannot_prove_safe", ProofStatus: "missing"},
		},
		Actor: "agent/claude",
	}}
	return e
}

func anchorEntry(id string, seq int, targetID, storedHash string) Entry {
	now := time.Date(2026, 5, 14, 12, 5, seq, 0, time.UTC)
	return Entry{
		Schema: SchemaVersion, ID: id, CreatedAt: now, EntryType: EntryChainAnchor, Actor: "human/owner",
		Payload: Payload{ChainAnchor: &ChainAnchorPayload{
			EntryID: targetID, StoredHash: storedHash, RecomputedHash: "sha256:whatever-was-recomputed",
			Reason: "gap_snapshot payload mutated after writing; original bytes unrecoverable", ApprovedBy: "tanner",
		}},
	}
}

// TestVerifyChainAnchor covers the anchor-honoring rules in VerifyEntries:
// a valid anchor lets a known, owner-approved mismatch pass with the entry
// recorded in AnchoredAnomalies; a mismatched StoredHash or an anchor placed
// before the entry it claims to vouch for must not be honored, and the
// original FAIL behavior is unchanged; tampering the anchor entry itself
// still breaks the chain (nothing vouches for the voucher).
func TestVerifyChainAnchor(t *testing.T) {
	e1 := chainEntry(t, GenesisHash, decisionEntry("01E1", 1, "block"))

	// e2Clean is what entry 2 looked like when it was written and hashed;
	// tamper(e2Clean) has the same id/prev/hash but different content — the
	// "content mutated after writing, hash locked in by e3's prev" scenario
	// from the motivation.
	e2Clean := chainEntry(t, e1.Hash, decisionEntry("01E2", 2, "pass"))
	e2Tampered := tamperPayload(e2Clean)

	validAnchor := chainEntry(t, e2Tampered.Hash, anchorEntry("01E3", 3, e2Tampered.ID, e2Clean.Hash))
	wrongStoredHashAnchor := chainEntry(t, e2Tampered.Hash, anchorEntry("01E3", 3, e2Tampered.ID, "sha256:not-the-real-hash"))

	// earlyAnchor sits BEFORE the entry it claims to vouch for: e1 -> anchor
	// -> e2, instead of e1 -> e2 -> anchor. e2CleanAfterEarlyAnchor is entry
	// 2 as it would have been hashed with THIS prev (the anchor's hash, not
	// e1's); e2Tampered2 is the same "mutated after writing" corruption
	// applied to it. earlyAnchor's own hash is computed once and never
	// mutated afterward, so it stays internally self-consistent — its
	// StoredHash just happens to reference e2Clean.Hash, computed under a
	// different (wrong) prev, and is therefore both early AND wrong; either
	// alone is enough for VerifyEntries to refuse it.
	earlyAnchor := chainEntry(t, e1.Hash, anchorEntry("01E3", 3, "01E2", e2Clean.Hash))
	e2CleanAfterEarlyAnchor := chainEntry(t, earlyAnchor.Hash, decisionEntry("01E2", 2, "pass"))
	e2Tampered2 := tamperPayload(e2CleanAfterEarlyAnchor)

	tamperedAnchor := validAnchor
	tamperedAnchor.Payload.ChainAnchor = &ChainAnchorPayload{
		EntryID: e2Tampered.ID, StoredHash: e2Clean.Hash, RecomputedHash: "sha256:whatever-was-recomputed",
		Reason: "a different reason, edited after the anchor was written", ApprovedBy: "tanner",
	}

	tests := []struct {
		name            string
		entries         []Entry
		wantOK          bool
		wantFailedAt    int
		wantAnchoredIDs []string
	}{
		{
			name:            "valid anchor after the mismatched entry is honored",
			entries:         []Entry{e1, e2Tampered, validAnchor},
			wantOK:          true,
			wantAnchoredIDs: []string{e2Tampered.ID},
		},
		{
			name:         "anchor with the wrong stored hash is not honored",
			entries:      []Entry{e1, e2Tampered, wrongStoredHashAnchor},
			wantOK:       false,
			wantFailedAt: 2,
		},
		{
			name:         "anchor appearing before the target entry is not honored",
			entries:      []Entry{e1, earlyAnchor, e2Tampered2},
			wantOK:       false,
			wantFailedAt: 3,
		},
		{
			name:         "tampering the anchor entry itself still breaks the chain",
			entries:      []Entry{e1, e2Tampered, tamperedAnchor},
			wantOK:       false,
			wantFailedAt: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := VerifyEntries(tt.entries)
			if res.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v (reason: %s)", res.OK, tt.wantOK, res.Reason)
			}
			if !tt.wantOK && res.FailedAt != tt.wantFailedAt {
				t.Errorf("FailedAt = %d, want %d", res.FailedAt, tt.wantFailedAt)
			}
			if tt.wantOK {
				if strings.Join(res.AnchoredAnomalies, ",") != strings.Join(tt.wantAnchoredIDs, ",") {
					t.Errorf("AnchoredAnomalies = %v, want %v", res.AnchoredAnomalies, tt.wantAnchoredIDs)
				}
			}
		})
	}
}

// TestAnchorFunc exercises ledger.Anchor's refusal rules and its happy path
// through the real Append machinery (file-backed, real ULIDs/hashes) —
// TestVerifyChainAnchor above covers VerifyEntries' honoring rules with
// hand-built entries; this covers the writer.
func TestAnchorFunc(t *testing.T) {
	fixedNow := time.Date(2026, 5, 14, 13, 0, 0, 0, time.UTC)
	fixedID := "01F00000000000000000000000"

	t.Run("missing reason is refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ledger.jsonl")
		if _, err := Anchor(path, "any-id", "", "tanner", "human/owner", fixedNow, fixedID); err == nil {
			t.Fatal("expected an error for empty --reason")
		}
	})

	t.Run("missing approved-by is refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ledger.jsonl")
		if _, err := Anchor(path, "any-id", "some reason", "", "human/owner", fixedNow, fixedID); err == nil {
			t.Fatal("expected an error for empty --approved-by")
		}
	})

	t.Run("unknown entry id is refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ledger.jsonl")
		appendDecision(t, path, 1, "block")
		if _, err := Anchor(path, "does-not-exist", "some reason", "tanner", "human/owner", fixedNow, fixedID); err == nil {
			t.Fatal("expected an error for an unknown entry id")
		}
	})

	t.Run("an entry that already verifies is refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ledger.jsonl")
		e1 := appendDecision(t, path, 1, "block")
		if _, err := Anchor(path, e1.ID, "some reason", "tanner", "human/owner", fixedNow, fixedID); err == nil {
			t.Fatal("expected an error anchoring an entry that already verifies")
		}
	})

	t.Run("a second anchor for the same entry is refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ledger.jsonl")
		e1 := appendDecision(t, path, 1, "block")
		tamperVerdict(t, path, "block", "pass")
		id1, _ := NewULID(fixedNow, deterministicReader(10))
		if _, err := Anchor(path, e1.ID, "first anchor", "tanner", "human/owner", fixedNow, id1); err != nil {
			t.Fatalf("first Anchor: %v", err)
		}
		id2, _ := NewULID(fixedNow.Add(time.Second), deterministicReader(11))
		if _, err := Anchor(path, e1.ID, "second anchor", "tanner", "human/owner", fixedNow.Add(time.Second), id2); err == nil {
			t.Fatal("expected an error writing a second anchor for the same entry")
		}
	})

	t.Run("valid anchor appends and the chain verifies with the anomaly recorded", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ledger.jsonl")
		e1 := appendDecision(t, path, 1, "block")
		tamperVerdict(t, path, "block", "pass")

		id1, _ := NewULID(fixedNow, deterministicReader(10))
		anchored, err := Anchor(path, e1.ID, "gap_snapshot payload mutated after writing; original bytes unrecoverable", "tanner", "human/owner", fixedNow, id1)
		if err != nil {
			t.Fatalf("Anchor: %v", err)
		}
		if anchored.EntryType != EntryChainAnchor || anchored.Payload.ChainAnchor == nil {
			t.Fatalf("unexpected anchor entry: %+v", anchored)
		}
		if anchored.Payload.ChainAnchor.EntryID != e1.ID {
			t.Errorf("ChainAnchor.EntryID = %q, want %q", anchored.Payload.ChainAnchor.EntryID, e1.ID)
		}

		entries, err := ReadAll(path)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		res := VerifyEntries(entries)
		if !res.OK {
			t.Fatalf("expected chain to verify with the anchor honored: %s", res.Reason)
		}
		if len(res.AnchoredAnomalies) != 1 || res.AnchoredAnomalies[0] != e1.ID {
			t.Errorf("AnchoredAnomalies = %v, want [%s]", res.AnchoredAnomalies, e1.ID)
		}
	})
}

// tamperVerdict rewrites path's raw bytes, replacing one occurrence of
// old's verdict JSON with newVerdict's — the same "content mutated after
// writing, hash left untouched" corruption TestVerifyDetectsTamperedEntry
// (ledger_test.go) exercises.
func tamperVerdict(t *testing.T, path, oldVerdict, newVerdict string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := replaceOnce(string(raw), `"verdict":"`+oldVerdict+`"`, `"verdict":"`+newVerdict+`"`)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
