// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/ledger"
)

func runHistory(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newHistoryCmd()
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// seedHistoryLedger appends one drill, one pin_check ("attest"), one
// accept, and one accept_clear entry for proofID, each an hour apart
// starting at base, stamped with a host/epoch/policy so `history`'s columns
// have something to print — plus one unrelated proof's drill entry, to
// prove history filters by proof id rather than dumping the whole ledger.
func seedHistoryLedger(t *testing.T, path, proofID string, base time.Time) {
	t.Helper()
	host := ledger.HostRecord{Name: "host-a", ID: "aaaaaaaaaaaaaaaa"}
	policy := ledger.PolicyRecord{Revision: "revA", Files: []ledger.PolicyFileRecord{{Path: "restoregap.yml", SHA256: "deadbeef"}}}
	opts := []ledger.AppendOption{ledger.WithHost(host), ledger.WithEpoch("epocha00000"), ledger.WithPolicy(policy)}

	writes := []struct {
		offset  time.Duration
		id      string
		typ     ledger.EntryType
		payload ledger.Payload
	}{
		{0, "e1", ledger.EntryDrill, ledger.Payload{Drill: &ledger.DrillPayload{ProofID: proofID, Mode: "drill", Verified: true, Level: "restores"}}},
		{time.Hour, "e2", ledger.EntryDrill, ledger.Payload{Drill: &ledger.DrillPayload{ProofID: proofID, Mode: "pin_check", Verified: true, Level: "declared"}}},
		{2 * time.Hour, "e3", ledger.EntryAccept, ledger.Payload{Accept: &ledger.AcceptPayload{ProofID: proofID, By: "tanner", Reason: "vendor SLA"}}},
		{3 * time.Hour, "e4", ledger.EntryAcceptClear, ledger.Payload{AcceptClear: &ledger.AcceptClearPayload{ProofID: proofID, By: "tanner"}}},
		{4 * time.Hour, "e5", ledger.EntryDrill, ledger.Payload{Drill: &ledger.DrillPayload{ProofID: "unrelated-proof", Mode: "drill", Verified: true, Level: "restores"}}},
	}
	for _, w := range writes {
		if _, err := ledger.Append(path, w.typ, "human/tanner", w.payload, base.Add(w.offset), w.id, opts...); err != nil {
			t.Fatalf("seed ledger entry %s: %v", w.id, err)
		}
	}
}

// TestHistoryPrintsFullTimelineOldestFirst: `history <proof-id>` prints
// exactly the drill/attest/accept/clear entries naming that proof, oldest
// first, and never an unrelated proof's entry.
func TestHistoryPrintsFullTimelineOldestFirst(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedHistoryLedger(t, ledgerPath, "ssh-key-recovery", base)

	out, err := runHistory(t, "--ledger", ledgerPath, "ssh-key-recovery")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 history lines, got %d:\n%s", len(lines), out)
	}
	wantKinds := []string{"drill", "attest", "accept", "clear"}
	for i, want := range wantKinds {
		if !strings.Contains(lines[i], "  "+want+"  ") {
			t.Errorf("line %d = %q, want it to name kind %q in position", i, lines[i], want)
		}
	}
	if strings.Contains(out, "unrelated-proof") {
		t.Errorf("history leaked an unrelated proof's entry:\n%s", out)
	}
	if !strings.Contains(lines[0], "level:restores") {
		t.Errorf("drill line missing its recovery level: %q", lines[0])
	}
	if !strings.Contains(lines[0], "host:host-a") || !strings.Contains(lines[0], "epoch:epocha00000") || !strings.Contains(lines[0], "policy:revA") {
		t.Errorf("drill line missing host/epoch/policy stamps: %q", lines[0])
	}
}

// TestHistorySinceBoundsTheWindow: --since excludes entries older than the
// window, keeping only the recent tail.
func TestHistorySinceBoundsTheWindow(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	// Entries land at base+0h/+1h/+2h/+3h == now-3h/-2h/-1h/-0h. A 30-minute
	// window keeps only the newest (accept_clear, effectively "now") and
	// excludes the other three, each at least an hour old.
	base := time.Now().UTC().Add(-3 * time.Hour)
	seedHistoryLedger(t, ledgerPath, "ssh-key-recovery", base)

	out, err := runHistory(t, "--ledger", ledgerPath, "--since", "30m", "ssh-key-recovery")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 line inside the --since window, got %d:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], "  clear  ") {
		t.Errorf("expected the surviving line to be the accept_clear entry, got %q", lines[0])
	}
}

// TestHistoryUnknownProofPrintsFriendlyMessage: an id with no ledger
// entries at all is not an error — it is "nothing recorded yet".
func TestHistoryUnknownProofPrintsFriendlyMessage(t *testing.T) {
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	seedHistoryLedger(t, ledgerPath, "ssh-key-recovery", time.Now().UTC())

	out, err := runHistory(t, "--ledger", ledgerPath, "no-such-proof")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if !strings.Contains(out, "no history for no-such-proof") {
		t.Errorf("expected a friendly no-history message, got %q", out)
	}
}

func TestHistoryRegisteredOnRoot(t *testing.T) {
	for _, build := range extraCommands {
		if cmd := build(); cmd.Name() == "history" {
			return
		}
	}
	t.Fatal("history command is not registered via extraCommands")
}
