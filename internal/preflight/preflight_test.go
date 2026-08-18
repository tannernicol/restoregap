// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

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

// multiCtxGuardYAML declares a guard on /x/app.db that requires a proof
// this file does NOT itself declare — multiCtxProofYAML does, in a
// separate file, exactly the split a real deployment uses (one file per
// drill, since each drill's proof-writing timer owns and rewrites its own
// file).
const multiCtxGuardYAML = `version: 2
guards:
  - id: app-db-guard
    kind: guard
    match: {paths: ["/x/app.db"]}
    requires: {proofs: [app-db-recovery]}
    enforcement: block
`

const multiCtxProofYAML = `version: 2
proofs:
  - id: app-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
`

// TestRunMultiContextMergesGuardAndProofAcrossFiles is the bug this feature
// exists to fix, reproduced directly: a guard in one context file requires
// a proof declared only in a second file. Loading both must merge them and
// PASS; loading only the guard's file must BLOCK — proving preflight never
// silently treats a real, satisfied guard as ungated just because its proof
// lives in a context file it wasn't told about.
func TestRunMultiContextMergesGuardAndProofAcrossFiles(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: /x/app.db\n")
	pathA := writeTemp(t, "a.yml", multiCtxGuardYAML)
	pathB := writeTemp(t, "b.yml", multiCtxProofYAML)

	t.Run("both contexts merged: proof declared in the other file satisfies the guard, PASS", func(t *testing.T) {
		res, err := Run(context.Background(), Request{
			Format: "json", IntentPath: intentPath, ContextPaths: []string{pathA, pathB}, AsOf: "2026-08-20T12:00:00Z",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("exit = %d, want 0 (pass): %s", res.ExitCode, res.Rendered)
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
	})

	t.Run("only the guard's file loaded: proof undeclared, BLOCK", func(t *testing.T) {
		res, err := Run(context.Background(), Request{
			Format: "json", IntentPath: intentPath, ContextPaths: []string{pathA}, AsOf: "2026-08-20T12:00:00Z",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode != 1 {
			t.Fatalf("exit = %d, want 1 (block): %s", res.ExitCode, res.Rendered)
		}
		var out struct {
			Verdict string `json:"verdict"`
		}
		if err := json.Unmarshal(res.Rendered, &out); err != nil {
			t.Fatal(err)
		}
		if out.Verdict != "block" {
			t.Errorf("verdict = %q, want block — a proven recovery declared elsewhere must never gate nothing just because this run only saw one of its files", out.Verdict)
		}
	})
}

// TestRunPlanDoesNotWriteLedger: --plan must evaluate and render exactly as
// a normal run does (same verdict, same exit code) but append nothing to
// the ledger — a readiness probe re-evaluating the same unexecuted intent
// on a timer must not spam the ledger with identical entries.
func TestRunPlanDoesNotWriteLedger(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: ~/.ssh/id_ed25519\n")
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")

	res, err := Run(context.Background(), Request{
		Format: "json", IntentPath: intentPath, LedgerPath: ledgerPath, Actor: "agent/test", Plan: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 1 {
		t.Errorf("exit = %d, want 1 (zero-config lifeline block, same as without --plan)", res.ExitCode)
	}
	if _, err := os.Stat(ledgerPath); !os.IsNotExist(err) {
		t.Errorf("--plan must not create the ledger file, stat err = %v", err)
	}
}

// TestRunWithoutPlanStillWritesLedger is the control for the above: without
// --plan, existing behavior (a ledger entry per run) is unchanged.
func TestRunWithoutPlanStillWritesLedger(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: ~/.ssh/id_ed25519\n")
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")

	if _, err := Run(context.Background(), Request{
		Format: "json", IntentPath: intentPath, LedgerPath: ledgerPath, Actor: "agent/test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ledgerPath); err != nil {
		t.Errorf("without --plan the ledger file must be created, stat err = %v", err)
	}
}

// rdsMissingEvidenceTFPlan is a Terraform plan replacing a prod RDS
// instance with no --evidence supplied at all: recovery.Build always emits
// a single "terraform.rds.restore-proof-missing" issue at index 0 for this
// shape (see TestBuildMissingEvidenceFails in internal/recovery), so its
// ledger finding id is deterministic: "recovery-0-terraform.rds.restore-proof-missing".
