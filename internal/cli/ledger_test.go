package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// writeHealthyLedger appends one decision entry to a fresh ledger at path
// and returns its id.
func writeHealthyLedger(t *testing.T, path string) string {
	t.Helper()
	entry, err := ledger.AppendNow(path, ledger.EntryDecision, "agent/claude", ledger.Payload{
		Decision: &ledger.DecisionPayload{Verdict: "block", Findings: []ledger.FindingRecord{
			{FindingID: "f1", GuardID: "g1", Resource: "example-resource", Verdict: "block", RiskClass: "cannot_prove_safe", ProofStatus: "missing"},
		}, Actor: "agent/claude"},
	})
	if err != nil {
		t.Fatalf("AppendNow: %v", err)
	}
	return entry.ID
}

// tamperEntryContent mutates path's stored bytes so the given entry id's
// content no longer matches its (unchanged) hash — the "corrupted after
// writing" scenario chain_anchor exists to attest to.
func tamperEntryContent(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(raw), `"verdict":"block"`, `"verdict":"pass"`, 1)
	if tampered == string(raw) {
		t.Fatal("tamperEntryContent: nothing replaced, fixture drifted")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// TestLedgerAnchorRefusesHealthyEntry: `ledger anchor` on an entry that
// still verifies has nothing to attest to and must refuse, not silently
// write a no-op attestation.
func TestLedgerAnchorRefusesHealthyEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	id := writeHealthyLedger(t, path)

	cmd := newLedgerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"anchor", path, id, "--reason", "test", "--approved-by", "tanner"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected an error anchoring a healthy entry, got output: %s", out.String())
	}

	entries, err := ledger.ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("refused anchor must not append anything: got %d entries, want 1", len(entries))
	}
}

// TestLedgerAnchorMissingFlagsRefused: --reason and --approved-by are both
// required; an empty flag must refuse before anything is written.
func TestLedgerAnchorMissingFlagsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	id := writeHealthyLedger(t, path)
	tamperEntryContent(t, path)

	cmd := newLedgerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"anchor", path, id, "--approved-by", "tanner"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error with --reason omitted")
	}
}

// TestLedgerAnchorAppendsAndVerifyReportsAnomaly: the CLI happy path end to
// end — anchor a genuinely mismatched entry, then confirm `ledger verify`
// reports OK with the entry called out as an anchored anomaly, matching the
// documented "OK — N entries (1 anchored anomaly: <id>)" rendering.
func TestLedgerAnchorAppendsAndVerifyReportsAnomaly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	id := writeHealthyLedger(t, path)
	tamperEntryContent(t, path)

	anchorCmd := newLedgerCmd()
	var anchorOut bytes.Buffer
	anchorCmd.SetOut(&anchorOut)
	anchorCmd.SetArgs([]string{"anchor", path, id, "--reason", "gap_snapshot mutated after writing; original bytes unrecoverable", "--approved-by", "tanner"})
	if err := anchorCmd.Execute(); err != nil {
		t.Fatalf("anchor: %v (output: %s)", err, anchorOut.String())
	}
	if !strings.Contains(anchorOut.String(), id) {
		t.Errorf("anchor output = %q, want it to mention entry id %s", anchorOut.String(), id)
	}

	verifyCmd := newLedgerCmd()
	var verifyOut bytes.Buffer
	verifyCmd.SetOut(&verifyOut)
	verifyCmd.SetArgs([]string{"verify", path})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("verify: %v (output: %s)", err, verifyOut.String())
	}
	got := verifyOut.String()
	if !strings.HasPrefix(got, "OK —") {
		t.Errorf("verify output = %q, want it to start with %q", got, "OK —")
	}
	if !strings.Contains(got, "1 anchored anomaly: "+id) {
		t.Errorf("verify output = %q, want it to report entry %s as the anchored anomaly", got, id)
	}

	// A second anchor for the same entry must be refused (anchors are
	// append-only history, never replaced).
	secondCmd := newLedgerCmd()
	var secondOut bytes.Buffer
	secondCmd.SetOut(&secondOut)
	secondCmd.SetArgs([]string{"anchor", path, id, "--reason", "second attempt", "--approved-by", "tanner"})
	if err := secondCmd.Execute(); err == nil {
		t.Fatal("expected an error writing a second anchor for the same entry")
	}
}
