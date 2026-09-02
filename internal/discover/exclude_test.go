// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplySuppressionDefaultExcludesBrowserProfile(t *testing.T) {
	candidates := []Candidate{
		{Kind: KindDatabase, Path: "/home/user/.mozilla/firefox/abc.default/cookies.sqlite"},
		{Kind: KindDatabase, Path: "/home/user/.config/google-chrome/Default/first_party_sets.db"},
		{Kind: KindDatabase, Path: "/home/user/money/money.db"}, // not noise
	}
	applySuppression(candidates, defaultExcludePatterns())

	if !candidates[0].Suppressed || candidates[0].SuppressedBy == "" {
		t.Errorf("firefox profile db not suppressed: %+v", candidates[0])
	}
	if !candidates[1].Suppressed {
		t.Errorf("chrome profile db not suppressed: %+v", candidates[1])
	}
	if candidates[2].Suppressed {
		t.Errorf("real database wrongly suppressed: %+v", candidates[2])
	}
}

func TestApplySuppressionDefaultExcludesArchiveAndCache(t *testing.T) {
	candidates := []Candidate{
		{Kind: KindDatabase, Path: "/home/user/.archive/retired-project-2026/data/db.sqlite"},
		{Kind: KindDatabase, Path: "/home/user/.cache/some-tool/state.db"},
		{Kind: KindDatabase, Path: "/home/user/.zoom/data/session.asyn.enc.db"},
		{Kind: KindRepo, Path: "/home/user/proj/node_modules/pkg/.git"},
	}
	applySuppression(candidates, defaultExcludePatterns())
	for _, c := range candidates {
		if !c.Suppressed {
			t.Errorf("expected %q to be suppressed as noise", c.Path)
		}
	}
}

func TestApplySuppressionNeverSuppressesUnrelatedPath(t *testing.T) {
	candidates := []Candidate{
		{Kind: KindDatabase, Path: "/home/user/stacks/audiobookshelf/config/absdatabase.sqlite"},
	}
	applySuppression(candidates, defaultExcludePatterns())
	if candidates[0].Suppressed {
		t.Errorf("a real application database must not match the default noise list: %+v", candidates[0])
	}
}

func TestReadIgnoreFileMissingIsNotError(t *testing.T) {
	patterns, err := readIgnoreFile(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("missing ignore file must not error: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("expected no patterns, got %v", patterns)
	}
}

func TestReadIgnoreFileSkipsBlankAndCommentLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".restoregapignore")
	content := "# comment\n\n**/foo/**\n  \n**/bar/**\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	patterns, err := readIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 2 || patterns[0] != "**/foo/**" || patterns[1] != "**/bar/**" {
		t.Fatalf("patterns = %v, want [**/foo/** **/bar/**]", patterns)
	}
}

// TestResolveExcludesReadsRepoLocalIgnoreFile: requirement #2, repo-root
// case — a candidate matching a pattern in <cwd>/.restoregapignore must be
// suppressed, attributed to that file.
func TestResolveExcludesReadsRepoLocalIgnoreFile(t *testing.T) {
	cwd := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // isolate the machine-wide file too
	if err := os.WriteFile(filepath.Join(cwd, ".restoregapignore"), []byte("**/synthetic-test-noise/**\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	excludes, err := resolveExcludes(cwd)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []Candidate{{Kind: KindDatabase, Path: "/home/user/synthetic-test-noise/x.db"}}
	applySuppression(candidates, excludes)
	if !candidates[0].Suppressed {
		t.Fatal("expected the repo-local .restoregapignore pattern to suppress the candidate")
	}
	if candidates[0].SuppressedBy != "ignore:.restoregapignore:**/synthetic-test-noise/**" {
		t.Errorf("SuppressedBy = %q, want the repo-local ignore file attributed", candidates[0].SuppressedBy)
	}
}

// TestResolveExcludesReadsMachineWideIgnoreFile: requirement #2, the
// $XDG_CONFIG_HOME/restoregap/discoverignore case.
func TestResolveExcludesReadsMachineWideIgnoreFile(t *testing.T) {
	cwd := t.TempDir() // no .restoregapignore here
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	dir := filepath.Join(configHome, "restoregap")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "discoverignore"), []byte("**/machine-wide-noise/**\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	excludes, err := resolveExcludes(cwd)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []Candidate{{Kind: KindDatabase, Path: "/home/user/machine-wide-noise/x.db"}}
	applySuppression(candidates, excludes)
	if !candidates[0].Suppressed {
		t.Fatal("expected the machine-wide discoverignore pattern to suppress the candidate")
	}
	if candidates[0].SuppressedBy != "ignore:discoverignore:**/machine-wide-noise/**" {
		t.Errorf("SuppressedBy = %q, want the machine-wide ignore file attributed", candidates[0].SuppressedBy)
	}
}

func TestDiscoverIgnorePathHonorsXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg-config-test")
	path, err := discoverIgnorePath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/xdg-config-test", "restoregap", "discoverignore")
	if path != want {
		t.Errorf("discoverIgnorePath() = %q, want %q", path, want)
	}
}
