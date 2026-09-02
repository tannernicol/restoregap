// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package ledger

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestCanonicalizeSortsKeysAndOmitsHash(t *testing.T) {
	e := Entry{
		Schema:    2,
		ID:        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CreatedAt: time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
		EntryType: EntryDecision,
		Actor:     "agent/claude",
		Payload: Payload{Decision: &DecisionPayload{
			Verdict: "block",
			Findings: []FindingRecord{
				{FindingID: "f1", GuardID: "g1", Resource: "~/.ssh/id_ed25519", Verdict: "block", RiskClass: "cannot_prove_safe", ProofStatus: "missing"},
			},
			Actor: "agent/claude",
		}},
		Prev: GenesisHash,
		Hash: "sha256:should-be-dropped",
	}
	got, err := canonicalize(e)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if bytes.Contains(got, []byte("should-be-dropped")) {
		t.Errorf("canonical form must never include the hash field: %s", got)
	}
	// Keys must appear in sorted order at the top level.
	idx := func(key string) int { return bytes.Index(got, []byte(`"`+key+`"`)) }
	order := []string{"actor", "created_at", "entry_type", "id", "payload", "prev", "schema"}
	for i := 1; i < len(order); i++ {
		if idx(order[i-1]) >= idx(order[i]) {
			t.Errorf("canonical keys not sorted (%s before %s): %s", order[i-1], order[i], got)
		}
	}
	if bytes.Contains(got, []byte("  ")) || bytes.Contains(got, []byte("\n")) {
		t.Errorf("canonical form must be compact (no indentation/newlines): %s", got)
	}
}

func TestCanonicalizeIsDeterministic(t *testing.T) {
	e := Entry{
		Schema: 2, ID: "x", CreatedAt: time.Unix(0, 0).UTC(), EntryType: EntryCheckpoint, Actor: "a",
		Payload: Payload{Checkpoint: &CheckpointPayload{EntryCount: 3, LastHash: GenesisHash}},
		Prev:    GenesisHash,
	}
	a, err := canonicalize(e)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, err := canonicalize(e)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("canonicalize is not deterministic: %s vs %s", a, b)
	}
}

func TestHashEntryIgnoresHashField(t *testing.T) {
	base := Entry{Schema: 2, ID: "x", CreatedAt: time.Unix(0, 0).UTC(), EntryType: EntryCheckpoint, Actor: "a",
		Payload: Payload{Checkpoint: &CheckpointPayload{EntryCount: 1, LastHash: GenesisHash}}, Prev: GenesisHash}
	withHash := base
	withHash.Hash = "sha256:anything"

	h1, err := hashEntry(base)
	if err != nil {
		t.Fatalf("hashEntry: %v", err)
	}
	h2, err := hashEntry(withHash)
	if err != nil {
		t.Fatalf("hashEntry: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hashEntry should be independent of the entry's own (pre-existing) hash field: %s vs %s", h1, h2)
	}
}

// TestV2DecisionWithoutNewFieldsStillVerifies pins the optional-field
// compatibility rule: adding execution metadata to a v2 payload must not
// change the canonical bytes or hash of a v2 entry that never had it.
func TestV2DecisionWithoutNewFieldsStillVerifies(t *testing.T) {
	e := Entry{
		Schema: 2, ID: "legacy", CreatedAt: time.Unix(0, 0).UTC(), EntryType: EntryDecision, Actor: "agent/test",
		Payload: Payload{Decision: &DecisionPayload{Verdict: "block", Actor: "agent/test"}}, Prev: GenesisHash,
	}
	h, err := hashEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	e.Hash = h
	if got := VerifyEntries([]Entry{e}); !got.OK {
		t.Errorf("legacy v2 entry no longer verifies: %s", got.Reason)
	}
	canonical, err := canonicalize(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"gate_state", "broken_reason", "duration_ms", "tool_version", "checks"} {
		if bytes.Contains(canonical, []byte(absent)) {
			t.Errorf("legacy canonical form unexpectedly contains %s: %s", absent, canonical)
		}
	}
}

func TestValidateNoFloats(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"plain integer", `{"n": 3}`, false},
		{"nested integer", `{"a": {"b": [1, 2, 3]}}`, false},
		{"float", `{"n": 3.5}`, true},
		{"exponent", `{"n": 3e10}`, true},
		{"string is fine", `{"n": "3.5"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dec := json.NewDecoder(bytes.NewReader([]byte(c.json)))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("decode: %v", err)
			}
			err := ValidateNoFloats(v)
			if c.wantErr && err == nil {
				t.Errorf("expected error for %s", c.json)
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error for %s: %v", c.json, err)
			}
		})
	}
}
