// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustSave(t *testing.T, stateDir string, r *Report) {
	t.Helper()
	if err := SaveSnapshot(stateDir, r); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}
}

func TestSaveSnapshotWritesLatestAndRotatesPrevious(t *testing.T) {
	dir := t.TempDir()
	t1 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	r1 := &Report{GeneratedAt: t1, Candidates: []Candidate{{Kind: KindDatabase, Path: "/a"}}}
	mustSave(t, dir, r1)

	if _, err := os.Stat(LatestPath(dir)); err != nil {
		t.Fatalf("latest.json missing: %v", err)
	}
	if _, err := os.Stat(PreviousPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("previous.json should not exist after the first save, err=%v", err)
	}

	t2 := t1.Add(24 * time.Hour)
	r2 := &Report{GeneratedAt: t2, Candidates: []Candidate{{Kind: KindDatabase, Path: "/a"}}}
	mustSave(t, dir, r2)

	prev, ok := loadReport(PreviousPath(dir))
	if !ok {
		t.Fatal("previous.json should exist and be readable after a second save")
	}
	if !prev.GeneratedAt.Equal(t1) {
		t.Errorf("previous.json GeneratedAt = %v, want %v (the FIRST report)", prev.GeneratedAt, t1)
	}
	latest, ok := loadReport(LatestPath(dir))
	if !ok || !latest.GeneratedAt.Equal(t2) {
		t.Fatalf("latest.json = %+v, ok=%v; want GeneratedAt %v", latest, ok, t2)
	}
}

func TestApplyPreviousScanFirstRunHasNoNewList(t *testing.T) {
	now := time.Now().UTC()
	candidates := []Candidate{{Kind: KindDatabase, Path: "/a"}, {Kind: KindDatabase, Path: "/b"}}
	newKeys := applyPreviousScan(candidates, nil, now)
	if len(newKeys) != 0 {
		t.Errorf("newKeys = %v; want none on a first-ever scan (nothing to compare against)", newKeys)
	}
	for _, c := range candidates {
		if !c.FirstSeen.Equal(now) {
			t.Errorf("candidate %+v FirstSeen = %v, want %v", c, c.FirstSeen, now)
		}
	}
}

func TestApplyPreviousScanDetectsNewCandidate(t *testing.T) {
	earlier := time.Now().UTC().Add(-time.Hour)
	now := time.Now().UTC()
	previous := []Candidate{{Kind: KindDatabase, Path: "/a", FirstSeen: earlier}}
	current := []Candidate{
		{Kind: KindDatabase, Path: "/a"},
		{Kind: KindDatabase, Path: "/b"}, // new
	}
	newKeys := applyPreviousScan(current, previous, now)
	if len(newKeys) != 1 || newKeys[0] != candidateKey(current[1]) {
		t.Fatalf("newKeys = %v; want exactly [%s]", newKeys, candidateKey(current[1]))
	}
	if !current[0].FirstSeen.Equal(earlier) {
		t.Errorf("existing candidate FirstSeen = %v, want carried-forward %v", current[0].FirstSeen, earlier)
	}
	if !current[1].FirstSeen.Equal(now) {
		t.Errorf("new candidate FirstSeen = %v, want %v", current[1].FirstSeen, now)
	}
}

func TestApplyPreviousScanCandidateDisappearing(t *testing.T) {
	earlier := time.Now().UTC().Add(-time.Hour)
	now := time.Now().UTC()
	previous := []Candidate{
		{Kind: KindDatabase, Path: "/a", FirstSeen: earlier},
		{Kind: KindDatabase, Path: "/b", FirstSeen: earlier}, // gone this scan (e.g. container removed)
	}
	current := []Candidate{{Kind: KindDatabase, Path: "/a"}}
	newKeys := applyPreviousScan(current, previous, now)
	if len(newKeys) != 0 {
		t.Errorf("newKeys = %v; want none — a disappearing candidate is not a 'new' one", newKeys)
	}
	if len(current) != 1 {
		t.Fatalf("current candidates mutated in length: %+v", current)
	}
	if !current[0].FirstSeen.Equal(earlier) {
		t.Errorf("surviving candidate FirstSeen = %v, want carried-forward %v", current[0].FirstSeen, earlier)
	}
}

func TestApplyPreviousScanNeverCarriesCoverage(t *testing.T) {
	// Even if a hand-crafted previous snapshot claims a candidate was
	// covered, applyPreviousScan must never copy Covered/CoveredBy forward
	// — only FirstSeen. Collect() is what (re-)computes Covered, always
	// fresh from the live context.
	previous := []Candidate{{Kind: KindDatabase, Path: "/a", Covered: true, CoveredBy: "guard:fake"}}
	current := []Candidate{{Kind: KindDatabase, Path: "/a", Covered: false}}
	applyPreviousScan(current, previous, time.Now().UTC())
	if current[0].Covered || current[0].CoveredBy != "" {
		t.Fatalf("applyPreviousScan must never set Covered/CoveredBy; got %+v", current[0])
	}
}

func TestAppendHistoryCapsAt500(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 520; i++ {
		r := &Report{
			GeneratedAt: base.Add(time.Duration(i) * time.Hour),
			Counts:      Counts{Candidates: i, Covered: i},
		}
		if err := appendHistory(dir, r); err != nil {
			t.Fatalf("appendHistory[%d]: %v", i, err)
		}
	}
	rows, err := ReadHistory(dir)
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(rows) != maxHistoryLines {
		t.Fatalf("len(rows) = %d, want %d", len(rows), maxHistoryLines)
	}
	// Oldest kept row should be the 21st write (index 20), since 520-500=20
	// were dropped.
	if rows[0].Candidates != 20 {
		t.Errorf("rows[0].Candidates = %d, want 20 (the oldest surviving row)", rows[0].Candidates)
	}
	if rows[len(rows)-1].Candidates != 519 {
		t.Errorf("last row Candidates = %d, want 519 (the newest write)", rows[len(rows)-1].Candidates)
	}
}

func TestReadStatusSummaryFreshAbsentStaleMalformed(t *testing.T) {
	now := time.Now().UTC()

	t.Run("absent", func(t *testing.T) {
		dir := t.TempDir()
		if _, ok := ReadStatusSummary(dir, now); ok {
			t.Error("expected ok=false for a missing latest.json")
		}
	})

	t.Run("fresh", func(t *testing.T) {
		dir := t.TempDir()
		r := &Report{GeneratedAt: now.Add(-time.Hour), Counts: Counts{Candidates: 10, Covered: 7, New: 2}}
		mustSave(t, dir, r)
		s, ok := ReadStatusSummary(dir, now)
		if !ok {
			t.Fatal("expected ok=true for a fresh snapshot")
		}
		if s.Candidates != 10 || s.Covered != 7 || s.New != 2 {
			t.Errorf("summary = %+v, want candidates=10 covered=7 new=2", s)
		}
	})

	t.Run("stale", func(t *testing.T) {
		dir := t.TempDir()
		r := &Report{GeneratedAt: now.Add(-8 * 24 * time.Hour), Counts: Counts{Candidates: 10, Covered: 7}}
		mustSave(t, dir, r)
		if _, ok := ReadStatusSummary(dir, now); ok {
			t.Error("expected ok=false for a snapshot older than 7 days")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(LatestPath(dir), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, ok := ReadStatusSummary(dir, now); ok {
			t.Error("expected ok=false for malformed JSON")
		}
	})
}

func TestReportJSONShape(t *testing.T) {
	r := &Report{
		GeneratedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		Host:        "test-host",
		Counts:      Counts{Candidates: 2, Covered: 1, Uncovered: 1, New: 1},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "money.db", Path: "/home/user/money/money.db", SizeBytes: 1024, Covered: true, CoveredBy: "drill:money-db", Weight: 3, FirstSeen: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
			{Kind: KindRepo, Name: "proj", Path: "/home/user/proj", Weight: 1, FirstSeen: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)},
		},
		New: []string{"repo:/home/user/proj"},
	}
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(encoded)
	for _, field := range []string{
		`"generated_at"`, `"host"`, `"counts"`, `"candidates"`, `"new"`,
		`"kind"`, `"name"`, `"path"`, `"size_bytes"`, `"covered"`, `"covered_by"`, `"weight"`, `"first_seen"`,
		`"candidates": 2`, `"covered": 1`, `"uncovered": 1`,
	} {
		if !strings.Contains(s, field) {
			t.Errorf("JSON missing expected field/value %s\n%s", field, s)
		}
	}

	var roundTrip Report
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundTrip.Candidates) != 2 || roundTrip.Candidates[0].Path != r.Candidates[0].Path {
		t.Errorf("round-tripped report lost data: %+v", roundTrip)
	}
}

func TestDefaultStateDirHonorsXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/xdg-state-test")
	dir, err := DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/xdg-state-test", "restoregap", "discover")
	if dir != want {
		t.Errorf("DefaultStateDir() = %q, want %q", dir, want)
	}
}
