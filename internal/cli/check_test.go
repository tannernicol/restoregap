package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCheckFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestCheckUnfaithfulPrintsNextStepHint: when the recovery copy is not
// faithful, the text report must end with a pointer to the next rung
// (`drill propose`) — a drill is the one thing that actually proves a
// recovery instead of merely comparing it, and check's whole point is to
// surface a gap, not leave the operator to independently discover what to
// do about it.
func TestCheckUnfaithfulPrintsNextStepHint(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	recovery := filepath.Join(dir, "recovery")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("mkdir live: %v", err)
	}
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatalf("mkdir recovery: %v", err)
	}
	writeCheckFile(t, live, "a.txt", "a")
	writeCheckFile(t, live, "b.txt", "b") // only in live -> not faithful
	writeCheckFile(t, recovery, "a.txt", "a")

	var out bytes.Buffer
	cmd := newCheckCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{live, recovery})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error (exit 1) for an unfaithful recovery copy")
	}
	if ee, ok := err.(*ExitError); !ok || ee.Code != 1 {
		t.Fatalf("expected ExitError{Code: 1}, got %#v", err)
	}

	want := "next: turn this into a proof — restoregap drill propose " + live
	if !bytes.Contains(out.Bytes(), []byte(want)) {
		t.Errorf("output missing next-step hint, want substring %q, got:\n%s", want, out.String())
	}
}

// TestCheckFaithfulPrintsNoHint: a faithful recovery copy has no gap to turn
// into a proof, so the hint must not appear.
func TestCheckFaithfulPrintsNoHint(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	recovery := filepath.Join(dir, "recovery")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("mkdir live: %v", err)
	}
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatalf("mkdir recovery: %v", err)
	}
	writeCheckFile(t, live, "a.txt", "a")
	writeCheckFile(t, recovery, "a.txt", "a")

	var out bytes.Buffer
	cmd := newCheckCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{live, recovery})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected a faithful recovery copy to succeed, got: %v (%s)", err, out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("next:")) {
		t.Errorf("a faithful recovery copy must not print the next-step hint, got:\n%s", out.String())
	}
}

// TestCheckExcludeFlagDropsMatchingEntries: real dogfood motivation — a
// .config/restoregap live root full of restoregap.local.yml.bak.* config
// snapshots reported hundreds of false "missing" entries. --exclude (which
// is repeatable) must drop matches from the report and print the summary
// line naming what was excluded and why.
func TestCheckExcludeFlagDropsMatchingEntries(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	recovery := filepath.Join(dir, "recovery")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("mkdir live: %v", err)
	}
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatalf("mkdir recovery: %v", err)
	}
	writeCheckFile(t, live, "a.txt", "a")
	writeCheckFile(t, live, "restoregap.local.yml.bak.1", "snap1")
	writeCheckFile(t, live, "restoregap.local.yml.bak.2", "snap2")
	writeCheckFile(t, recovery, "a.txt", "a")

	var out bytes.Buffer
	cmd := newCheckCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{live, recovery, "--exclude", "restoregap.local.yml.bak.*"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected excluded-only drift to report faithful, got: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "excluded: 2 entries (patterns: restoregap.local.yml.bak.*)") {
		t.Errorf("expected excluded summary line, got:\n%s", out.String())
	}
	if strings.Contains(out.String(), "bak.1") || strings.Contains(out.String(), "bak.2") {
		t.Errorf("excluded entries must not appear in the report, got:\n%s", out.String())
	}
}

// TestCheckRestoregapIgnoreFileExcludesEntries: patterns are also read from
// <live>/.restoregapignore when present, gitignore-style (one glob per
// line, # comments), with no flag required.
func TestCheckRestoregapIgnoreFileExcludesEntries(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	recovery := filepath.Join(dir, "recovery")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("mkdir live: %v", err)
	}
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatalf("mkdir recovery: %v", err)
	}
	writeCheckFile(t, live, "a.txt", "a")
	writeCheckFile(t, live, "cache.tmp", "junk")
	writeCheckFile(t, recovery, "a.txt", "a")
	writeCheckFile(t, live, ".restoregapignore", "# comment line\n\n*.tmp\n")

	var out bytes.Buffer
	cmd := newCheckCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{live, recovery})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected .restoregapignore to exclude cache.tmp, got: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "excluded: 1 entries (patterns: *.tmp)") {
		t.Errorf("expected excluded summary line naming the file pattern, got:\n%s", out.String())
	}
}

// TestCheckExcludePatternMatchingNothingPrintsNoSummaryLine: an --exclude
// pattern that matches zero entries must not add a summary line the
// operator then has to explain to themselves.
func TestCheckExcludePatternMatchingNothingPrintsNoSummaryLine(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	recovery := filepath.Join(dir, "recovery")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("mkdir live: %v", err)
	}
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatalf("mkdir recovery: %v", err)
	}
	writeCheckFile(t, live, "a.txt", "a")
	writeCheckFile(t, recovery, "a.txt", "a")

	var out bytes.Buffer
	cmd := newCheckCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{live, recovery, "--exclude", "*.nonexistent"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected faithful copy, got: %v (%s)", err, out.String())
	}
	if strings.Contains(out.String(), "excluded:") {
		t.Errorf("a pattern matching nothing must not print a summary line, got:\n%s", out.String())
	}
}

// TestCheckUnfaithfulJSONHasNoHint: the hint is a text-report affordance
// only; JSON output is a stable machine contract and must not gain a new
// field for it.
func TestCheckUnfaithfulJSONHasNoHint(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	recovery := filepath.Join(dir, "recovery")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatalf("mkdir live: %v", err)
	}
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatalf("mkdir recovery: %v", err)
	}
	writeCheckFile(t, live, "a.txt", "a")
	writeCheckFile(t, live, "b.txt", "b")
	writeCheckFile(t, recovery, "a.txt", "a")

	var out bytes.Buffer
	cmd := newCheckCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{live, recovery, "--format", "json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error (exit 1) for an unfaithful recovery copy")
	}
	if bytes.Contains(out.Bytes(), []byte("next:")) {
		t.Errorf("JSON output must not contain the text-only next-step hint, got:\n%s", out.String())
	}
}
