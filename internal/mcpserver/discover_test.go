// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/discover"
)

// mcpDiscoverDrillYAML declares one drill covering artifact, so a discover
// call against this context can assert a specific candidate came back
// covered.
const mcpDiscoverDrillYAML = `version: 2
drills:
  - proof: covered-db
    artifact: %s
    recover: "true"
`

// isolatedDiscoverHome points $HOME (the database/repo collectors' walk
// root) and $XDG_STATE_HOME (the snapshot dir) at fresh temp dirs, so these
// tests never walk or touch the real machine.
func isolatedDiscoverHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
}

func TestDiscoverToolListedInToolDefs(t *testing.T) {
	for _, d := range toolDefs() {
		if d.Name == "discover" {
			return
		}
	}
	t.Fatal("discover not found in toolDefs()")
}

func TestDiscoverToolReturnsValidReport(t *testing.T) {
	isolatedDiscoverHome(t)
	path := writeContext(t, "version: 2\n")

	text, err := callTool(context.Background(), "discover", toolArgs{ContextPath: path})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	var report discover.Report
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		t.Fatalf("discover tool did not return valid Report JSON: %v\n%s", err, text)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("expected a non-zero generated_at")
	}
}

func TestDiscoverToolNeverWritesSnapshot(t *testing.T) {
	isolatedDiscoverHome(t)
	stateDir, err := discover.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	before, beforeErr := discover.ReadHistory(stateDir)

	path := writeContext(t, "version: 2\n")
	if _, err := callTool(context.Background(), "discover", toolArgs{ContextPath: path}); err != nil {
		t.Fatalf("callTool: %v", err)
	}

	after, afterErr := discover.ReadHistory(stateDir)
	if beforeErr == nil && afterErr == nil && len(after) != len(before) {
		t.Errorf("discover tool call must never append to scan history: before=%d after=%d", len(before), len(after))
	}
}

func TestDiscoverToolDefaultFiltersToUncovered(t *testing.T) {
	isolatedDiscoverHome(t)
	dir := t.TempDir()
	artifact := filepath.Join(dir, "covered.db")
	path := writeContext(t, fmt.Sprintf(mcpDiscoverDrillYAML, artifact))

	text, err := callTool(context.Background(), "discover", toolArgs{ContextPath: path})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	var report discover.Report
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, c := range report.Candidates {
		if c.Covered {
			t.Errorf("default (all=false) response must only contain uncovered candidates, got %+v", c)
		}
	}
}

// TestDiscoverToolPromptReturnsAgentBrief: the prompt arg returns the same
// plain-text agent brief `restoregap discover --prompt` prints, not JSON —
// so an agent can fetch it directly over MCP rather than scraping the page.
func TestDiscoverToolPromptReturnsAgentBrief(t *testing.T) {
	isolatedDiscoverHome(t)
	path := writeContext(t, "version: 2\n")

	text, err := callTool(context.Background(), "discover", toolArgs{ContextPath: path, Prompt: true})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	if !strings.Contains(text, discover.PromptRules) {
		t.Errorf("expected the rules block, got:\n%s", text)
	}
	var report discover.Report
	if err := json.Unmarshal([]byte(text), &report); err == nil {
		t.Errorf("prompt output must be plain text, not JSON, got:\n%s", text)
	}
}

func TestDiscoverToolAllIncludesEverything(t *testing.T) {
	isolatedDiscoverHome(t)
	path := writeContext(t, "version: 2\n")

	withoutAll, err := callTool(context.Background(), "discover", toolArgs{ContextPath: path})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	withAll, err := callTool(context.Background(), "discover", toolArgs{ContextPath: path, All: true})
	if err != nil {
		t.Fatalf("callTool: %v", err)
	}
	var a, b discover.Report
	if err := json.Unmarshal([]byte(withoutAll), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(withAll), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Candidates) < len(a.Candidates) {
		t.Errorf("all=true returned fewer candidates (%d) than the default (%d)", len(b.Candidates), len(a.Candidates))
	}
	// Counts always reflect the FULL picture regardless of the all filter.
	if a.Counts.Candidates != b.Counts.Candidates {
		t.Errorf("Counts.Candidates must not change with the all filter: %d vs %d", a.Counts.Candidates, b.Counts.Candidates)
	}
}
