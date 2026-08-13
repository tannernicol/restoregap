package preflight

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunErrors(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: /tmp/x\n")
	cases := []struct {
		name    string
		req     Request
		wantErr string
	}{
		{"no input", Request{Format: "md"}, "--intent or --diff is required"},
		{"both inputs", Request{Format: "md", IntentPath: intentPath, DiffPath: intentPath}, "only one of"},
		{"bad format", Request{Format: "xml", IntentPath: intentPath}, "--format"},
		{"bad as-of", Request{Format: "md", IntentPath: intentPath, AsOf: "yesterday"}, "--as-of"},
		{"missing intent file", Request{Format: "md", IntentPath: "/nonexistent.yml"}, "--intent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Run(context.Background(), c.req)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func TestRunZeroConfigBenignPasses(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: /tmp/scratch/notes.txt\n")
	res, err := Run(context.Background(), Request{Format: "json", IntentPath: intentPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", res.ExitCode)
	}
	var out struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(res.Rendered, &out); err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "pass" {
		t.Errorf("verdict = %q, want pass", out.Verdict)
	}
}

func TestRunRecordsLedgerDecision(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: ~/.ssh/id_ed25519\n")
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	res, err := Run(context.Background(), Request{Format: "json", IntentPath: intentPath, LedgerPath: ledgerPath, Actor: "agent/test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 1 {
		t.Errorf("exit = %d, want 1 (zero-config lifeline block)", res.ExitCode)
	}
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	if !strings.Contains(string(raw), `"block"`) {
		t.Errorf("ledger entry does not record the block decision: %s", raw)
	}
}

// rdsMissingEvidenceTFPlan is a Terraform plan replacing a prod RDS
// instance with no --evidence supplied at all: recovery.Build always emits
// a single "terraform.rds.restore-proof-missing" issue at index 0 for this
// shape (see TestBuildMissingEvidenceFails in internal/recovery), so its
// ledger finding id is deterministic: "recovery-0-terraform.rds.restore-proof-missing".
