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
	"time"

	"github.com/tannernicol/restoregap/internal/engine"
	"github.com/tannernicol/restoregap/internal/intent"
	"github.com/tannernicol/restoregap/internal/ledger"
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

func TestRunRequireCoverageBlocksUncoveredResourceWithoutChangingDefault(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npaths: [/covered, /uncovered]\n")
	contextPath := writeTemp(t, "context.yml", `version: 2
guards:
  - id: covered
    kind: guard
    match: {paths: ["/covered"], actions: [delete_file]}
`)
	legacy, err := Run(context.Background(), Request{Format: "json", IntentPath: intentPath, ContextPaths: []string{contextPath}, Plan: true})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ExitCode != 0 {
		t.Fatalf("default coverage exit = %d, want 0: %s", legacy.ExitCode, legacy.Rendered)
	}
	strict, err := Run(context.Background(), Request{Format: "json", IntentPath: intentPath, ContextPaths: []string{contextPath}, RequireCoverage: true, Plan: true})
	if err != nil {
		t.Fatal(err)
	}
	if strict.ExitCode != 1 || !strings.Contains(string(strict.Rendered), "/uncovered") {
		t.Fatalf("strict coverage result = exit %d, want block naming /uncovered: %s", strict.ExitCode, strict.Rendered)
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

// TestRunUnreadableContextRecordsGateBroken is the fail-closed distinction:
// a directory supplied as a context is not a policy block. The gate did not
// run, so it must return the frozen unavailable exit code and leave an
// auditable broken decision in an otherwise healthy ledger.
func TestRunUnreadableContextRecordsGateBroken(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: /tmp/x\n")
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	badContext := t.TempDir() // contextspec.Load cannot read a directory as YAML

	res, err := Run(context.Background(), Request{
		Format: "text", IntentPath: intentPath, ContextPaths: []string{badContext},
		LedgerPath: ledgerPath, Actor: "agent/test", ToolVersion: "test-version",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3; report:\n%s", res.ExitCode, res.Rendered)
	}
	if !strings.Contains(string(res.Rendered), "GATE BROKEN") || !strings.Contains(string(res.Rendered), "load_context") {
		t.Errorf("broken report must name the failed check, got:\n%s", res.Rendered)
	}

	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) != 1 || entries[0].Payload.Decision == nil {
		t.Fatalf("got %#v, want one decision entry", entries)
	}
	d := entries[0].Payload.Decision
	if d.GateState != "broken" || !strings.Contains(d.BrokenReason, "load_context") {
		t.Errorf("gate state = %q, broken reason = %q; want broken load_context", d.GateState, d.BrokenReason)
	}
	if len(d.Checks) == 0 || d.Checks[len(d.Checks)-1].Outcome != "broken" {
		t.Errorf("broken entry must retain the failed check, got %#v", d.Checks)
	}
	if got := ledger.VerifyEntries(entries); !got.OK {
		t.Errorf("new broken entry must still verify: %s", got.Reason)
	}
}

func TestRunDecisionRecordsExecutionMetadata(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: /tmp/x\n")
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	if _, err := Run(context.Background(), Request{
		Format: "json", IntentPath: intentPath, LedgerPath: ledgerPath,
		Actor: "agent/test", ToolVersion: "v9.9.9",
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	d := entries[0].Payload.Decision
	if d.GateState != "ran" || d.ToolVersion != "v9.9.9" || len(d.Checks) == 0 {
		t.Errorf("missing decision execution metadata: %#v", d)
	}
	if d.DurationMS < 0 {
		t.Errorf("duration = %d, want non-negative", d.DurationMS)
	}
	if d.Operation != "preflight" || d.Executed == nil || *d.Executed {
		t.Errorf("decision must describe an unexecuted preflight: operation=%q executed=%v", d.Operation, d.Executed)
	}
	if len(d.Intents) != 1 || d.Intents[0].Action != "delete_file" || len(d.Intents[0].Paths) != 1 {
		t.Errorf("decision did not retain proposed intent: %#v", d.Intents)
	}
	for _, c := range d.Checks {
		if c.DurationMS < 0 || c.Outcome == "" || c.ID == "" {
			t.Errorf("invalid check record: %#v", c)
		}
	}
	// Exercise the exact zero-duration edge too: it is valid and should not
	// silently turn into a float in the durable entry.
	if _, err := ledger.Append(ledgerPath, ledger.EntryDecision, "agent/test", ledger.Payload{Decision: &ledger.DecisionPayload{
		Verdict: "pass", GateState: "ran", DurationMS: 0,
	}}, time.Now().UTC(), "01J000000000000000000000001"); err != nil {
		t.Fatalf("append zero-duration decision: %v", err)
	}
}

func TestRunAsOfSeparatesEvaluationAndRecordingTimes(t *testing.T) {
	intentPath := writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: /tmp/scratch/notes.txt\n")
	contextPath := writeTemp(t, "context.yml", "version: 2\n")
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	future := "2027-01-01T00:00:00Z"
	before := time.Now().UTC()
	res, err := Run(context.Background(), Request{
		Format: "json", IntentPath: intentPath, ContextPaths: []string{contextPath},
		LedgerPath: ledgerPath, AsOf: future, Actor: "agent/test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want pass: %s", res.ExitCode, res.Rendered)
	}
	entries, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Payload.Decision == nil {
		t.Fatalf("entries = %#v, want one decision", entries)
	}
	entry := entries[0]
	if !entry.CreatedAt.After(before) || entry.CreatedAt.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("created_at = %s, want recording time near now", entry.CreatedAt)
	}
	evaluated := entry.Payload.Decision.EvaluatedAt
	if evaluated == nil || !evaluated.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("evaluated_at = %v, want pinned policy time", evaluated)
	}
	view := ledger.Recent(entries, 1).Decisions[0]
	if view.EvaluatedAt == nil || !view.EvaluatedAt.Equal(*evaluated) {
		t.Fatalf("decision view lost evaluated_at: %#v", view)
	}
}

func TestRunDecisionScopeCoversPassBlockNoMatchAndBroken(t *testing.T) {
	intent := func(t *testing.T, path string) string {
		t.Helper()
		return writeTemp(t, "intent.yml", "version: 2\naction: delete_file\npath: "+path+"\n")
	}
	cases := []struct {
		name       string
		intentPath string
		context    []string
		wantExit   int
		want       []string
	}{
		{
			name: "pass", intentPath: "scratch", wantExit: 0,
			want: []string{"PASS", "Decision: PASS", "Proposed change:", "did not execute", "paths: /tmp/scratch"},
		},
		{
			name: "block", intentPath: "key", wantExit: 1,
			want: []string{"BLOCK", "Decision: BLOCK", "Proposed change:", "did not execute", "paths: /home/user/.ssh/id_ed25519"},
		},
		{
			name: "no match", intentPath: "unmatched", wantExit: 0,
			want: []string{"PASS", "No findings.", "paths: /tmp/unmatched"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := "/tmp/" + tc.intentPath
			if tc.name == "block" {
				path = "/home/user/.ssh/id_ed25519"
			}
			res, err := Run(context.Background(), Request{Format: "text", IntentPath: intent(t, path), Plan: true})
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != tc.wantExit {
				t.Fatalf("exit = %d, want %d:\n%s", res.ExitCode, tc.wantExit, res.Rendered)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(res.Rendered), want) {
					t.Errorf("output missing %q:\n%s", want, res.Rendered)
				}
			}
		})
	}
	t.Run("broken", func(t *testing.T) {
		res, err := Run(context.Background(), Request{
			Format: "text", IntentPath: intent(t, "/tmp/broken"), ContextPaths: []string{t.TempDir()}, Plan: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode != 3 {
			t.Fatalf("exit = %d, want 3:\n%s", res.ExitCode, res.Rendered)
		}
		for _, want := range []string{"GATE BROKEN", "Decision: BLOCK", "did not execute", "paths: /tmp/broken"} {
			if !strings.Contains(string(res.Rendered), want) {
				t.Errorf("broken output missing %q:\n%s", want, res.Rendered)
			}
		}
	})
}

func TestRecordDecisionCapturesFindingDetailAndOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	executed := false
	finding := engine.Finding{
		ID: "guard/g1", GuardID: "g1", Resource: "/srv/data", Verdict: engine.VerdictPass,
		Actions: []string{"delete_file"}, Proof: "recovery was fresh", RequiredNextStep: "owner review",
		Override: &engine.Override{ApprovedBy: "tanner", Reason: "off-host copy confirmed"},
	}
	if err := recordDecision(Request{LedgerPath: path, Actor: "agent/test"}, []engine.Finding{finding}, engine.VerdictPass, time.Now().UTC(), "ran", "", nil, 1,
		[]intent.ChangeIntent{{Action: intent.ActionDeleteFile, Paths: []string{"/srv/data"}}}); err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	d := entries[0].Payload.Decision
	if d.Operation != "preflight" || d.Executed == nil || *d.Executed != executed || len(d.Intents) != 1 {
		t.Fatalf("decision metadata = %#v", d)
	}
	f := d.Findings[0]
	if len(f.Actions) != 1 || f.Proof == "" || f.RequiredNextStep == "" || f.Override == nil || f.Override.ApprovedBy != "tanner" {
		t.Fatalf("finding detail = %#v", f)
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
