// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/discover"
)

// isolatedStateDir points $XDG_STATE_HOME at a fresh temp dir for the
// duration of t, so discoverCoverageLine never reads this machine's real
// discover snapshot.
func isolatedStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	return filepath.Join(dir, "restoregap", "discover")
}

func TestDiscoverCoverageLineAbsent(t *testing.T) {
	isolatedStateDir(t)
	got := discoverCoverageLine(time.Now().UTC())
	if got != discoverNotScannedLine {
		t.Errorf("discoverCoverageLine() = %q, want %q", got, discoverNotScannedLine)
	}
}

func TestDiscoverCoverageLineFresh(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	report := &discover.Report{GeneratedAt: now.Add(-time.Hour), Counts: discover.Counts{Candidates: 71, Covered: 42}}
	if err := discover.SaveSnapshot(stateDir, report); err != nil {
		t.Fatal(err)
	}
	got := discoverCoverageLine(now)
	want := "coverage: 42 of 71 candidates covered"
	if got != want {
		t.Errorf("discoverCoverageLine() = %q, want %q", got, want)
	}
}

func TestDiscoverCoverageLineFreshWithNew(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	previous := &discover.Report{GeneratedAt: now.Add(-48 * time.Hour), Counts: discover.Counts{Candidates: 68, Covered: 38}}
	if err := discover.SaveSnapshot(stateDir, previous); err != nil {
		t.Fatal(err)
	}
	current := &discover.Report{
		GeneratedAt: now.Add(-time.Hour), Counts: discover.Counts{Candidates: 71, Covered: 42, New: 3},
		PreviousGeneratedAt: previous.GeneratedAt,
	}
	if err := discover.SaveSnapshot(stateDir, current); err != nil {
		t.Fatal(err)
	}
	got := discoverCoverageLine(now)
	want := "coverage: 42 of 71 candidates covered · 3 new since " + previous.GeneratedAt.Format("2006-01-02")
	if got != want {
		t.Errorf("discoverCoverageLine() = %q, want %q", got, want)
	}
}

func TestDiscoverCoverageLineStale(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	report := &discover.Report{GeneratedAt: now.Add(-8 * 24 * time.Hour), Counts: discover.Counts{Candidates: 71, Covered: 42}}
	if err := discover.SaveSnapshot(stateDir, report); err != nil {
		t.Fatal(err)
	}
	got := discoverCoverageLine(now)
	if got != discoverNotScannedLine {
		t.Errorf("discoverCoverageLine() = %q, want %q (stale snapshot)", got, discoverNotScannedLine)
	}
}

func TestDiscoverCoverageLineMalformed(t *testing.T) {
	stateDir := isolatedStateDir(t)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(discover.LatestPath(stateDir), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := discoverCoverageLine(time.Now().UTC())
	if got != discoverNotScannedLine {
		t.Errorf("discoverCoverageLine() = %q, want %q (malformed snapshot)", got, discoverNotScannedLine)
	}
}

// ---- gatherDiscoverCoverage: fresh / stale / absent -----------------------

func TestGatherDiscoverCoverageAbsent(t *testing.T) {
	isolatedStateDir(t)
	dc := gatherDiscoverCoverage(time.Now().UTC())
	if dc.State != "absent" {
		t.Errorf("State = %q, want absent", dc.State)
	}
	if dc.Line != discoverNotScannedLine {
		t.Errorf("Line = %q, want %q", dc.Line, discoverNotScannedLine)
	}
	if len(dc.Uncovered) != 0 || dc.Prompt != "" {
		t.Errorf("absent coverage must carry no candidate data, got %+v", dc)
	}
}

func TestGatherDiscoverCoverageStaleCarriesNoNumbers(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	report := &discover.Report{
		GeneratedAt: now.Add(-8 * 24 * time.Hour),
		Counts:      discover.Counts{Candidates: 71, Covered: 42, Uncovered: 29},
		Candidates:  []discover.Candidate{{Kind: discover.KindRepo, Name: "r", Path: "/p", Weight: 1}},
	}
	if err := discover.SaveSnapshot(stateDir, report); err != nil {
		t.Fatal(err)
	}
	dc := gatherDiscoverCoverage(now)
	if dc.State != "stale" {
		t.Errorf("State = %q, want stale", dc.State)
	}
	if strings.Contains(dc.Line, "71") || strings.Contains(dc.Line, "42") {
		t.Errorf("a stale snapshot must never present its counts as current, got Line=%q", dc.Line)
	}
	if !strings.Contains(dc.Line, "run restoregap discover") {
		t.Errorf("expected a re-scan pointer, got %q", dc.Line)
	}
	if len(dc.Uncovered) != 0 || dc.Prompt != "" {
		t.Errorf("a stale snapshot must not drive the Fix-this candidate list/prompt, got %+v", dc)
	}
}

func TestGatherDiscoverCoverageFreshRanksTopByConsequence(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	report := &discover.Report{
		GeneratedAt: now.Add(-time.Hour),
		Counts:      discover.Counts{Candidates: 3, Covered: 1, Uncovered: 2},
		Candidates: []discover.Candidate{
			{Kind: discover.KindEtcConfig, Name: "etc", Path: "/etc", Weight: 4, SizeBytes: 10},
			{Kind: discover.KindRepo, Name: "repo", Path: "/home/user/repo", Weight: 1, SizeBytes: 999},
			{Kind: discover.KindDatabase, Name: "money.db", Path: "/home/user/money.db", Weight: 3, Covered: true},
		},
	}
	if err := discover.SaveSnapshot(stateDir, report); err != nil {
		t.Fatal(err)
	}
	dc := gatherDiscoverCoverage(now)
	if dc.State != "fresh" {
		t.Fatalf("State = %q, want fresh", dc.State)
	}
	if len(dc.Uncovered) != 2 {
		t.Fatalf("len(Uncovered) = %d, want 2", len(dc.Uncovered))
	}
	if dc.Uncovered[0].Name != "etc" {
		t.Errorf("expected the higher-weight etc-config candidate first, got %+v", dc.Uncovered)
	}
	if dc.Prompt == "" || !strings.Contains(dc.Prompt, discover.PromptRules) {
		t.Errorf("expected a non-empty prompt containing the rules block, got %q", dc.Prompt)
	}
}

func TestGatherDiscoverCoverageFreshNoUncoveredHasNoPrompt(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	report := &discover.Report{
		GeneratedAt: now.Add(-time.Hour),
		Counts:      discover.Counts{Candidates: 1, Covered: 1, Uncovered: 0},
		Candidates:  []discover.Candidate{{Kind: discover.KindDatabase, Name: "money.db", Path: "/home/user/money.db", Weight: 3, Covered: true}},
	}
	if err := discover.SaveSnapshot(stateDir, report); err != nil {
		t.Fatal(err)
	}
	dc := gatherDiscoverCoverage(now)
	if dc.Prompt != "" {
		t.Errorf("a fully-covered estate must carry no remediation prompt, got %q", dc.Prompt)
	}
	if len(dc.Uncovered) != 0 {
		t.Errorf("expected no uncovered candidates, got %+v", dc.Uncovered)
	}
}

// TestGatherDiscoverCoverageFreshListsEveryUncoveredCandidate: the HTML
// coverage block does its own top-N/rest split, so gatherDiscoverCoverage
// itself must carry every non-suppressed uncovered candidate, not a
// pre-truncated slice.
func TestGatherDiscoverCoverageFreshListsEveryUncoveredCandidate(t *testing.T) {
	stateDir := isolatedStateDir(t)
	now := time.Now().UTC()
	var candidates []discover.Candidate
	for i := 0; i < 12; i++ {
		candidates = append(candidates, discover.Candidate{Kind: discover.KindRepo, Name: "r", Path: "/p", Weight: 1})
	}
	report := &discover.Report{
		GeneratedAt: now.Add(-time.Hour),
		Counts:      discover.Counts{Candidates: 12, Covered: 0, Uncovered: 12},
		Candidates:  candidates,
	}
	if err := discover.SaveSnapshot(stateDir, report); err != nil {
		t.Fatal(err)
	}
	dc := gatherDiscoverCoverage(now)
	if len(dc.Uncovered) != 12 {
		t.Fatalf("len(Uncovered) = %d, want 12", len(dc.Uncovered))
	}
}

// TestGatherPopulatesDiscoverLine: Gather itself must set Summary.DiscoverLine
// so both the text and HTML renderers see it — this test would fail loudly
// if a future refactor forgot to wire discoverCoverageLine into Gather.
func TestGatherPopulatesDiscoverLine(t *testing.T) {
	isolatedStateDir(t)
	s, err := Gather(Request{})
	if err != nil {
		t.Fatal(err)
	}
	if s.DiscoverLine != discoverNotScannedLine {
		t.Errorf("Gather().DiscoverLine = %q, want %q", s.DiscoverLine, discoverNotScannedLine)
	}
}
