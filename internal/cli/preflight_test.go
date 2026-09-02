package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withForcedTTY overrides isTTYStdout for the duration of the test.
func withForcedTTY(t *testing.T, tty bool) {
	t.Helper()
	old := isTTYStdout
	isTTYStdout = func(io.Writer) bool { return tty }
	t.Cleanup(func() { isTTYStdout = old })
}

// TestPreflightForcedTTYRendersPlainText: stdout at an interactive terminal,
// --format not given, must render plain text — no pipe tables, no #/**.
func TestPreflightForcedTTYRendersPlainText(t *testing.T) {
	withForcedTTY(t, true)
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}

	got := out.String()
	if strings.Contains(got, "|") {
		t.Errorf("forced-TTY output must contain no pipe table, got:\n%s", got)
	}
	if strings.Contains(got, "#") || strings.Contains(got, "**") {
		t.Errorf("forced-TTY output must contain no markdown headers/bold, got:\n%s", got)
	}
	if !strings.Contains(got, "BLOCK") {
		t.Errorf("expected the BLOCK headline, got:\n%s", got)
	}
}

// TestPreflightNonTTYStaysMarkdown: cmd.SetOut(&bytes.Buffer{}) is never a
// TTY, so the existing markdown default must be unaffected by this feature
// even without forcing isTTYStdout false explicitly.
func TestPreflightNonTTYStaysMarkdown(t *testing.T) {
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}
	if !strings.HasPrefix(out.String(), "# BLOCK\n") {
		t.Errorf("non-TTY output must stay markdown, got:\n%s", out.String())
	}
}

// TestPreflightForcedTTYExplicitFormatWins: --format explicitly given must
// win over TTY detection, even when stdout is forced to look like a
// terminal — an explicit choice is never silently overridden.
func TestPreflightForcedTTYExplicitFormatWins(t *testing.T) {
	withForcedTTY(t, true)
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath, "--format", "md"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}
	if !strings.HasPrefix(out.String(), "# BLOCK\n") {
		t.Errorf("explicit --format md must win over TTY detection, got:\n%s", out.String())
	}
}

// TestPreflightExplicitFormatMarkdownAlias: --format markdown is the
// documented spelling and must render exactly like --format md.
func TestPreflightExplicitFormatMarkdownAlias(t *testing.T) {
	withForcedTTY(t, true)
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath, "--format", "markdown"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}
	if !strings.HasPrefix(out.String(), "# BLOCK\n") {
		t.Errorf("--format markdown must render markdown even on a forced TTY, got:\n%s", out.String())
	}
}

// TestPreflightExplicitFormatAutoOnTTYRendersText: --format auto passed
// explicitly must behave exactly like the omitted-flag default (auto is the
// default value, not a separate code path).
func TestPreflightExplicitFormatAutoOnTTYRendersText(t *testing.T) {
	withForcedTTY(t, true)
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath, "--format", "auto"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}
	got := out.String()
	if strings.Contains(got, "|") || strings.Contains(got, "#") || strings.Contains(got, "**") {
		t.Errorf("--format auto on a forced TTY must render plain text, got:\n%s", got)
	}
	if !strings.HasPrefix(got, "BLOCK — ") {
		t.Errorf("expected the dash-joined BLOCK headline, got:\n%s", got)
	}
}

// TestPreflightPlanFlagSkipsLedger: an explicit --ledger path must not be
// created at all when --plan is passed, through the real CLI flag surface
// (internal/preflight has the Request-level coverage; this is the wiring).
func TestPreflightPlanFlagSkipsLedger(t *testing.T) {
	dir := t.TempDir()
	intentPath := writeFile(t, dir, "intent.yml", zeroConfigBlockIntent)
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	cmd := newPreflightCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--intent", intentPath, "--format", "json", "--ledger", ledgerPath, "--plan"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a block exit for an undeclared ssh-key delete")
	}
	if _, err := os.Stat(ledgerPath); !os.IsNotExist(err) {
		t.Errorf("--plan must not create the ledger file, stat err = %v", err)
	}
}
