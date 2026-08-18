// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// TestMain gives every test in this package an isolated XDG_STATE_HOME for
// the whole run. Several commands now default --ledger to
// $XDG_STATE_HOME/restoregap/ledger.jsonl when the flag is omitted, and a
// good number of existing tests exercise those commands without passing
// --ledger — without this they would create ~/.local/state/restoregap on
// whatever machine runs `go test`. RESTOREGAP_LEDGER/RESTOREGAP_CONTEXT are
// cleared so no test result depends on the outer shell's environment.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "restoregap-cli-test-state-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("XDG_STATE_HOME", dir)
	_ = os.Unsetenv("RESTOREGAP_LEDGER")
	_ = os.Unsetenv("RESTOREGAP_CONTEXT")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newTestCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test"}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	return cmd, &out
}

// ---- discoverContext -------------------------------------------------------

func TestDiscoverContextExplicitPassesThroughSilently(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd, out := newTestCmd()
	got := discoverContext(cmd, "explicit.yml")
	if got != "explicit.yml" {
		t.Errorf("got %q, want the explicit path unchanged", got)
	}
	if out.Len() != 0 {
		t.Errorf("an explicitly passed --context must never be announced, got %q", out.String())
	}
}

func TestDiscoverContextEnvVar(t *testing.T) {
	dir := t.TempDir()
	ctxPath := filepath.Join(dir, "somewhere.yml")
	if err := os.WriteFile(ctxPath, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RESTOREGAP_CONTEXT", ctxPath)
	t.Chdir(t.TempDir()) // no restoregap.local.yml/restoregap.yml here

	cmd, out := newTestCmd()
	got := discoverContext(cmd, "")
	if got != ctxPath {
		t.Errorf("got %q, want $RESTOREGAP_CONTEXT value %q", got, ctxPath)
	}
	if !strings.Contains(out.String(), "context: "+ctxPath+" (discovered)") {
		t.Errorf("expected a discovery announcement naming %q, got %q", ctxPath, out.String())
	}
}

func TestDiscoverContextPrefersLocalOverPlain(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("restoregap.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, out := newTestCmd()
	got := discoverContext(cmd, "")
	if got != "restoregap.local.yml" {
		t.Errorf("got %q, want restoregap.local.yml preferred over restoregap.yml", got)
	}
	if !strings.Contains(out.String(), "context: restoregap.local.yml (discovered)") {
		t.Errorf("expected a discovery announcement, got %q", out.String())
	}
}

func TestDiscoverContextFallsBackToPlainYml(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, _ := newTestCmd()
	got := discoverContext(cmd, "")
	if got != "restoregap.yml" {
		t.Errorf("got %q, want restoregap.yml", got)
	}
}

func TestDiscoverContextEnvVarColonListTakesFirstEntry(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.yml")
	pathB := filepath.Join(dir, "b.yml")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("version: 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RESTOREGAP_CONTEXT", pathA+":"+pathB)
	t.Chdir(t.TempDir())

	cmd, out := newTestCmd()
	got := discoverContext(cmd, "")
	if got != pathA {
		t.Errorf("got %q, want the first entry of the colon list %q", got, pathA)
	}
	if !strings.Contains(out.String(), "context: "+pathA+" (discovered)") {
		t.Errorf("expected a discovery announcement naming %q, got %q", pathA, out.String())
	}
}

// ---- discoverContextPaths (repeatable --context) ---------------------------

func TestDiscoverContextPathsExplicitPassesThroughSilently(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd, out := newTestCmd()
	got := discoverContextPaths(cmd, []string{"a.yml", "b.yml"})
	if len(got) != 2 || got[0] != "a.yml" || got[1] != "b.yml" {
		t.Errorf("got %v, want the explicit paths unchanged", got)
	}
	if out.Len() != 0 {
		t.Errorf("explicitly passed --context values must never be announced, got %q", out.String())
	}
}

func TestDiscoverContextPathsEnvVarColonList(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.yml")
	pathB := filepath.Join(dir, "b.yml")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("version: 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RESTOREGAP_CONTEXT", pathA+":"+pathB)
	t.Chdir(t.TempDir())

	cmd, out := newTestCmd()
	got := discoverContextPaths(cmd, nil)
	if len(got) != 2 || got[0] != pathA || got[1] != pathB {
		t.Errorf("got %v, want [%q %q]", got, pathA, pathB)
	}
	if !strings.Contains(out.String(), "context: "+pathA+", "+pathB+" (discovered)") {
		t.Errorf("expected a discovery announcement naming both paths, got %q", out.String())
	}
}

func TestDiscoverContextPathsFallsBackToSingleLocalFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, _ := newTestCmd()
	got := discoverContextPaths(cmd, nil)
	if len(got) != 1 || got[0] != "restoregap.local.yml" {
		t.Errorf("got %v, want [restoregap.local.yml]", got)
	}
}

func TestDiscoverContextPathsNothingFound(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd, out := newTestCmd()
	got := discoverContextPaths(cmd, nil)
	if got != nil {
		t.Errorf("got %v, want nil when nothing is discoverable", got)
	}
	if out.Len() != 0 {
		t.Errorf("nothing discovered must announce nothing, got %q", out.String())
	}
}

func TestDiscoverContextNothingFound(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd, out := newTestCmd()
	got := discoverContext(cmd, "")
	if got != "" {
		t.Errorf("got %q, want \"\" when nothing is discoverable", got)
	}
	if out.Len() != 0 {
		t.Errorf("nothing discovered must announce nothing, got %q", out.String())
	}
}

func TestRequireContextRefusesWithFriendlyMessage(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd, _ := newTestCmd()
	_, err := requireContext(cmd, "", "drill")
	if err == nil {
		t.Fatal("expected an error when nothing is discoverable and nothing was passed")
	}
	if !strings.Contains(err.Error(), "restoregap context init") || !strings.Contains(err.Error(), "--context") {
		t.Errorf("error should point at `restoregap context init` or --context, got %q", err.Error())
	}
}

func TestRequireContextUsesDiscovered(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd, _ := newTestCmd()
	got, err := requireContext(cmd, "", "drill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "restoregap.local.yml" {
		t.Errorf("got %q, want the discovered file", got)
	}
}

// ---- defaultLedgerPath / resolveLedger -------------------------------------

func TestResolveLedgerExplicitPassesThroughUndefaulted(t *testing.T) {
	path, defaulted, err := resolveLedger("explicit.jsonl")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "explicit.jsonl" || defaulted {
		t.Errorf("got (%q, %v), want (\"explicit.jsonl\", false)", path, defaulted)
	}
}

func TestResolveLedgerEnvVar(t *testing.T) {
	want := filepath.Join(t.TempDir(), "custom", "ledger.jsonl")
	t.Setenv("RESTOREGAP_LEDGER", want)

	path, defaulted, err := resolveLedger("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != want || !defaulted {
		t.Errorf("got (%q, %v), want (%q, true)", path, defaulted, want)
	}
}

func TestResolveLedgerXDGStateHome(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("RESTOREGAP_LEDGER", "")

	path, defaulted, err := resolveLedger("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(stateDir, "restoregap", "ledger.jsonl")
	if path != want || !defaulted {
		t.Errorf("got (%q, %v), want (%q, true)", path, defaulted, want)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		t.Errorf("expected the parent directory to be created, stat err: %v", err)
	}
}

func TestResolveLedgerHomeFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("RESTOREGAP_LEDGER", "")

	path, defaulted, err := resolveLedger("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(home, ".local", "state", "restoregap", "ledger.jsonl")
	if path != want || !defaulted {
		t.Errorf("got (%q, %v), want (%q, true)", path, defaulted, want)
	}
}

// ---- CLI-level: preflight, status, evidence, drill, ledger ----------------

// zeroConfigBlockIntent deletes a path the built-in default policy protects
// (an SSH private key), so preflight run with no --context blocks — giving
// the ledger-writing path (recordDecision) something to exercise even
// without an explicit --context/--ledger.
const zeroConfigBlockIntent = `version: 2
action: delete_file
path: /home/user/.ssh/id_ed25519
`

func TestPreflightDefaultsLedgerAndAnnouncesIt(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("RESTOREGAP_LEDGER", "")

	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath, "--format", "json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}

	wantLedger := filepath.Join(stateDir, "restoregap", "ledger.jsonl")
	if !strings.Contains(out.String(), "ledger: "+wantLedger+" (default)") {
		t.Errorf("expected a footer line naming the default ledger, got %q", out.String())
	}
	entries, rerr := ledger.ReadAll(wantLedger)
	if rerr != nil {
		t.Fatalf("ReadAll(%s): %v", wantLedger, rerr)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 decision recorded in the default ledger, got %d", len(entries))
	}
}

func TestPreflightExplicitLedgerNotLabeledDefault(t *testing.T) {
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)
	ledgerPath := filepath.Join(dir, "explicit-ledger.jsonl")

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath, "--format", "json", "--ledger", ledgerPath})
	_ = cmd.Execute()

	if !strings.Contains(out.String(), "ledger: "+ledgerPath+" (explicit)") {
		t.Errorf("expected the footer to label an explicit --ledger as explicit, got %q", out.String())
	}
}

// TestPreflightRepeatableContextMergesAcrossFiles exercises --context as a
// repeatable flag end to end through the CLI: a guard declared in one file
// is satisfied by a proof declared only in a second, passed as two separate
// --context flags.
func TestPreflightRepeatableContextMergesAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", "version: 2\naction: delete_file\npath: /x/app.db\n")
	guardPath := writeFile(t, dir, "guard.yml", `version: 2
guards:
  - id: app-db-guard
    kind: guard
    match: {paths: ["/x/app.db"]}
    requires: {proofs: [app-db-recovery]}
    enforcement: block
`)
	proofPath := writeFile(t, dir, "proof.yml", `version: 2
proofs:
  - id: app-db-recovery
    status: validated
    observed_at: "2026-08-20T00:00:00Z"
`)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--intent", intentPath, "--format", "json", "--as-of", "2026-08-20T12:00:00Z",
		"--context", guardPath, "--context", proofPath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), `"verdict": "pass"`) {
		t.Errorf("expected pass (proof from the second --context satisfies the guard from the first), got %q", out.String())
	}
}

func TestStatusDiscoversLocalContext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte(starterContext), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "context: restoregap.local.yml (discovered)") {
		t.Errorf("expected status to announce the discovered context, got %q", out.String())
	}
	if strings.Contains(out.String(), "built-in default local lifeline policy") {
		t.Errorf("status should report the discovered file's guards, not the zero-config default; got %q", out.String())
	}
}

func TestStatusFallsBackToBuiltinDefaultWhenNothingDiscoverable(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd := newStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "built-in default local lifeline policy") {
		t.Errorf("expected the built-in zero-config policy when nothing is discoverable, got %q", out.String())
	}
	if strings.Contains(out.String(), "(discovered)") {
		t.Errorf("falling back to the built-in default must not claim anything was discovered, got %q", out.String())
	}
}

func TestEvidenceIngestDiscoversContextInsteadOfDemandingIt(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte(starterContext), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newEvidenceCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"ingest", "--proof", "ssh-key-recovery-copy"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("evidence ingest should discover ./restoregap.local.yml, got error: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "context: restoregap.local.yml (discovered)") {
		t.Errorf("expected a discovery announcement, got %q", out.String())
	}

	updated, err := os.ReadFile("restoregap.local.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "ssh-key-recovery-copy") {
		t.Errorf("expected the proof to be recorded into the discovered context file")
	}
}

func TestEvidenceIngestRefusesWithFriendlyMessageWhenNothingDiscoverable(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd := newEvidenceCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"ingest", "--proof", "whatever"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error with no --context and nothing discoverable")
	}
	if !strings.Contains(err.Error(), "restoregap context init") {
		t.Errorf("expected the friendly refusal message, got %q", err.Error())
	}
}

func TestDrillRefusesWithFriendlyMessageWhenNoContext(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--lint"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error with no --context and nothing discoverable")
	}
	if !strings.Contains(err.Error(), "restoregap context init") || !strings.Contains(err.Error(), "--context") {
		t.Errorf("expected the friendly refusal message, got %q", err.Error())
	}
}

func TestDrillDiscoversContext(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	artifact := writeFile(t, dir, "artifact", "x")
	if err := os.WriteFile("restoregap.local.yml", []byte(fmt.Sprintf(lintCleanYAML, artifact)), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newDrillCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--lint"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "context: restoregap.local.yml (discovered)") {
		t.Errorf("expected a discovery announcement, got %q", out.String())
	}
}

func TestLedgerVerifyDefaultsWhenNoArgGiven(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("RESTOREGAP_LEDGER", "")
	wantLedger := filepath.Join(stateDir, "restoregap", "ledger.jsonl")
	if err := os.MkdirAll(filepath.Dir(wantLedger), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := ledger.AppendNow(wantLedger, ledger.EntryDecision, "test", ledger.Payload{
		Decision: &ledger.DecisionPayload{Verdict: "pass"},
	}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}

	cmd := newLedgerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.HasPrefix(out.String(), "OK") {
		t.Errorf("expected verify OK against the default ledger, got %q", out.String())
	}
}

func TestLedgerListDefaultsWhenNoArgGiven(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("RESTOREGAP_LEDGER", "")
	wantLedger := filepath.Join(stateDir, "restoregap", "ledger.jsonl")
	if err := os.MkdirAll(filepath.Dir(wantLedger), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := ledger.AppendNow(wantLedger, ledger.EntryDecision, "test", ledger.Payload{
		Decision: &ledger.DecisionPayload{Verdict: "pass"},
	}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}

	cmd := newLedgerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"list"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "decision") {
		t.Errorf("expected the seeded entry listed, got %q", out.String())
	}
}

func TestLedgerAnchorDefaultsWhenOnlyEntryIDGiven(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("RESTOREGAP_LEDGER", "")
	wantLedger := filepath.Join(stateDir, "restoregap", "ledger.jsonl")
	if err := os.MkdirAll(filepath.Dir(wantLedger), 0o755); err != nil {
		t.Fatal(err)
	}

	entry := writeHealthyLedger(t, wantLedger)
	tamperEntryContent(t, wantLedger)

	cmd := newLedgerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"anchor", entry, "--reason", "test", "--approved-by", "tanner"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("anchor with a single positional (entry-id only) arg should use the default ledger: %v (%s)", err, out.String())
	}
}
