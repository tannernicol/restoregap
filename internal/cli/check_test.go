package cli

import (
	"bytes"
	"os"
	"path/filepath"
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
