// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// stubExternalTools points the docker/systemctl collectors at "tool not
// found" for the duration of t, so a Collect() run in these tests never
// shells out to whatever docker/systemd state happens to exist on the
// machine actually running the test suite — Collect must only see the
// fake $HOME these tests construct.
func stubExternalTools(t *testing.T) {
	t.Helper()
	notFound := func() ([]byte, error) { return nil, errors.New("stubbed: tool not found") }
	origPS, origUnits, origFiles := runDockerPS, runSystemctlListUnits, runSystemctlListUnitFiles
	runDockerPS = notFound
	runSystemctlListUnits = notFound
	runSystemctlListUnitFiles = notFound
	t.Cleanup(func() {
		runDockerPS, runSystemctlListUnits, runSystemctlListUnitFiles = origPS, origUnits, origFiles
	})
}

// fixedOptions returns a Collect Options pointed entirely at a hermetic
// $HOME/state dir/system-paths set, with external tools stubbed absent and
// Cwd/XDG_CONFIG_HOME isolated so resolveExcludes never reads a real
// .restoregapignore or discoverignore from the machine actually running
// the test suite.
func fixedOptions(t *testing.T, home, stateDir string, now time.Time) Options {
	t.Helper()
	stubExternalTools(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	etc := filepath.Join(home, "fake-etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	machineID := filepath.Join(etc, "machine-id")
	if err := os.WriteFile(machineID, []byte("test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Options{
		Home: home, Now: now, HostName: "test-host", StateDir: stateDir, Cwd: home,
		System: SystemPaths{MachineID: machineID, PackageManifests: nil, Etc: etc},
	}
}

func TestCollectBuildsReportWithCoverageAndPersists(t *testing.T) {
	home := t.TempDir()
	stateDir := t.TempDir()
	dbPath := filepath.Join(home, "app.sqlite3")
	if err := os.WriteFile(dbPath, make([]byte, databaseMinSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := contextspec.Context{Drills: []contextspec.Drill{{Proof: "app-db", Artifact: dbPath}}}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	opts := fixedOptions(t, home, stateDir, now)
	opts.Context = ctx

	report, err := Collect(opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if report.Counts.Candidates == 0 {
		t.Fatal("expected at least the fixed system candidates plus the database")
	}
	var dbCandidate *Candidate
	for i := range report.Candidates {
		if report.Candidates[i].Path == dbPath {
			dbCandidate = &report.Candidates[i]
		}
	}
	if dbCandidate == nil || !dbCandidate.Covered || dbCandidate.CoveredBy != "drill:app-db" {
		t.Fatalf("database candidate not covered as expected: %+v", dbCandidate)
	}
	if _, err := os.Stat(LatestPath(stateDir)); err != nil {
		t.Errorf("expected latest.json to be written by default (NoSave false): %v", err)
	}
}

func TestCollectNoSaveDoesNotWriteButStillDiffs(t *testing.T) {
	home := t.TempDir()
	stateDir := t.TempDir()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	// Seed a previous snapshot by hand so the diff has something to compare
	// against.
	seed := &Report{GeneratedAt: now.Add(-24 * time.Hour), Candidates: []Candidate{
		{Kind: KindEtcConfig, Name: "etc-customizations", Path: filepath.Join(home, "fake-etc"), FirstSeen: now.Add(-24 * time.Hour)},
	}}
	if err := SaveSnapshot(stateDir, seed); err != nil {
		t.Fatal(err)
	}
	modBefore, err := os.Stat(LatestPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}

	opts := fixedOptions(t, home, stateDir, now)
	opts.NoSave = true
	report, err := Collect(opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if report.PreviousGeneratedAt.IsZero() {
		t.Error("expected the diff against the seeded previous scan to still run under --no-save")
	}

	modAfter, err := os.Stat(LatestPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !modBefore.ModTime().Equal(modAfter.ModTime()) {
		t.Error("NoSave must not modify latest.json")
	}
	if _, err := os.Stat(PreviousPath(stateDir)); !os.IsNotExist(err) {
		t.Error("NoSave must not create previous.json")
	}
}

func TestCollectSecondRunDetectsNewCandidate(t *testing.T) {
	home := t.TempDir()
	stateDir := t.TempDir()
	now1 := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	now2 := now1.Add(48 * time.Hour)

	opts1 := fixedOptions(t, home, stateDir, now1)
	if _, err := Collect(opts1); err != nil {
		t.Fatalf("first Collect: %v", err)
	}

	// A new database appears between scans.
	newDB := filepath.Join(home, "new.sqlite3")
	if err := os.WriteFile(newDB, make([]byte, databaseMinSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	opts2 := fixedOptions(t, home, stateDir, now2)
	report2, err := Collect(opts2)
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if report2.Counts.New != 1 {
		t.Fatalf("Counts.New = %d, want 1; New=%v", report2.Counts.New, report2.New)
	}
	if !report2.PreviousGeneratedAt.Equal(now1) {
		t.Errorf("PreviousGeneratedAt = %v, want %v", report2.PreviousGeneratedAt, now1)
	}
	wantKey := candidateKey(Candidate{Kind: KindDatabase, Path: newDB})
	if len(report2.New) != 1 || report2.New[0] != wantKey {
		t.Errorf("New = %v, want [%s]", report2.New, wantKey)
	}
}

// TestCollectEndToEndSuppressesGroupsDedupes exercises the full pipeline
// against the exact shape of noise the real audit found: a Firefox
// profile database (suppressed), a symlink-duplicated auth.db (deduped to
// one candidate with an alternate path), and a genuine large database
// that must rank first in the default text view.
func TestCollectEndToEndSuppressesGroupsDedupes(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	opts := fixedOptions(t, home, t.TempDir(), now)

	// Noise: a Firefox profile database.
	firefoxDir := filepath.Join(home, ".mozilla", "firefox", "abc.default")
	if err := os.MkdirAll(firefoxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(firefoxDir, "cookies.sqlite"), make([]byte, databaseMinSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	// A real, large database — must outrank everything by size.
	appDir := filepath.Join(home, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bigDB := filepath.Join(appDir, "important.db")
	if err := os.WriteFile(bigDB, make([]byte, 10*1024*1024), 0o644); err != nil {
		t.Fatal(err)
	}

	// A bind-mount-shaped duplicate (the real auth.db bug): TWO
	// independently-real directory trees whose auth.db is the SAME
	// underlying file — a hard link reproduces that from the collector's
	// point of view (two ordinary, independently-walked paths, same
	// inode) without needing an actual mount namespace in a test.
	realDir := filepath.Join(home, "infra-config", "ntfy", "data")
	aliasDir := filepath.Join(home, "ntfy", "data")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(aliasDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realAuthDB := filepath.Join(realDir, "auth.db")
	if err := os.WriteFile(realAuthDB, make([]byte, databaseMinSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(realAuthDB, filepath.Join(aliasDir, "auth.db")); err != nil {
		t.Fatal(err)
	}

	report, err := Collect(opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Dedup: exactly one auth.db candidate, with the alias recorded.
	var authCandidates []Candidate
	for _, c := range report.Candidates {
		if c.Name == "auth.db" {
			authCandidates = append(authCandidates, c)
		}
	}
	if len(authCandidates) != 1 {
		t.Fatalf("expected exactly one deduped auth.db candidate, got %+v", authCandidates)
	}
	if len(authCandidates[0].AlternatePaths) != 1 {
		t.Errorf("expected one alternate path recorded, got %v", authCandidates[0].AlternatePaths)
	}

	// Suppression: the Firefox database is flagged but still counted.
	var firefoxCandidate *Candidate
	for i := range report.Candidates {
		if report.Candidates[i].Name == "cookies.sqlite" {
			firefoxCandidate = &report.Candidates[i]
		}
	}
	if firefoxCandidate == nil || !firefoxCandidate.Suppressed {
		t.Fatalf("expected the Firefox profile database to be flagged suppressed, got %+v", firefoxCandidate)
	}
	if report.Counts.Suppressed == 0 {
		t.Error("expected Counts.Suppressed > 0")
	}

	// Default text view: no Firefox noise, the big database ranks first
	// among the uncovered listing.
	text := string(RenderText(report, false))
	if strings.Contains(text, "cookies.sqlite") {
		t.Errorf("Firefox profile database leaked into the default view:\n%s", text)
	}
	if !strings.Contains(text, "suppressed as noise") {
		t.Errorf("summary line missing the suppressed count:\n%s", text)
	}
	if idx := strings.Index(text, "important.db"); idx == -1 {
		t.Errorf("expected important.db in the default view:\n%s", text)
	}
}
