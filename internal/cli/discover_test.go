// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/tannernicol/restoregap/internal/discover"
)

// TestDiscoverRegisteredOnRoot: discover self-registers through
// extraCommands, same mechanism as every other leaf command, so it shows
// up in --help.
func TestDiscoverRegisteredOnRoot(t *testing.T) {
	for _, build := range extraCommands {
		if build().Use == "discover" {
			return
		}
	}
	t.Fatal("discover is not registered in extraCommands — it will not appear in --help")
}

// isolatedDiscoverEnv points $HOME and $XDG_STATE_HOME at fresh temp dirs
// so a discover run in these tests never touches the real machine's home
// directory or snapshot history.
func isolatedDiscoverEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("RESTOREGAP_CONTEXT", "")
}

func TestDiscoverTextRun(t *testing.T) {
	isolatedDiscoverEnv(t)
	var out bytes.Buffer
	cmd := newDiscoverCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("discover: %v (output:\n%s)", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("coverage:")) {
		t.Errorf("expected a coverage summary line, got:\n%s", out.String())
	}
}

func TestDiscoverJSONRun(t *testing.T) {
	isolatedDiscoverEnv(t)
	var out bytes.Buffer
	cmd := newDiscoverCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("discover --format json: %v (output:\n%s)", err, out.String())
	}
	var report struct {
		GeneratedAt string `json:"generated_at"`
		Counts      struct {
			Candidates int `json:"candidates"`
		} `json:"counts"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if report.GeneratedAt == "" {
		t.Error("expected a non-empty generated_at")
	}
}

func TestDiscoverNoSaveDoesNotWriteSnapshot(t *testing.T) {
	isolatedDiscoverEnv(t)
	var out bytes.Buffer
	cmd := newDiscoverCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--no-save"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("discover --no-save: %v", err)
	}
	stateDir, err := discover.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(discover.LatestPath(stateDir)); statErr == nil {
		t.Error("--no-save must not write latest.json")
	}
}

// TestDiscoverPromptRun: --prompt emits the agent brief (rules block +
// header) instead of the plain enumerate/diff text, using the same
// discover.RenderPrompt the HTML page's Fix-this block calls — see
// internal/discover/prompt_test.go for the rules-block/bullet assertions
// this only needs to confirm are wired up here.
func TestDiscoverPromptRun(t *testing.T) {
	isolatedDiscoverEnv(t)
	var out bytes.Buffer
	cmd := newDiscoverCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--prompt"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("discover --prompt: %v (output:\n%s)", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(discover.PromptRules)) {
		t.Errorf("expected the rules block, got:\n%s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("restoregap discover — scope:")) {
		t.Errorf("expected the prompt header, got:\n%s", out.String())
	}
}

func TestDiscoverTrendWithNoHistory(t *testing.T) {
	isolatedDiscoverEnv(t)
	var out bytes.Buffer
	cmd := newDiscoverCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--trend"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("discover --trend: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("no scan history")) {
		t.Errorf("expected the empty-history message, got:\n%s", out.String())
	}
}
