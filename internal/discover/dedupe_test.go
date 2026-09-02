// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDedupeByRealPathMergesSymlinkedDuplicate reproduces the real audit's
// exact finding: the same auth.db reachable via two apparent paths because
// one directory is a symlink alias of the other (a compose bind mount and
// a convenience symlink both pointing at it).
func TestDedupeByRealPathMergesSymlinkedDuplicate(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "infra-config", "compose", "ntfy", "data")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(real, "auth.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "ntfy")
	if err := os.Symlink(filepath.Join(root, "infra-config", "compose", "ntfy"), alias); err != nil {
		t.Fatal(err)
	}
	aliasedPath := filepath.Join(alias, "data", "auth.db")

	candidates := []Candidate{
		{Kind: KindDatabase, Name: "auth.db", Path: aliasedPath, SizeBytes: 1},
		{Kind: KindDatabase, Name: "auth.db", Path: dbPath, SizeBytes: 1},
	}
	merged := dedupeByRealPath(candidates)
	if len(merged) != 1 {
		t.Fatalf("dedupeByRealPath = %+v; want exactly one merged candidate", merged)
	}
	if merged[0].Path != dbPath {
		t.Errorf("merged Path = %q, want the canonical %q", merged[0].Path, dbPath)
	}
	if len(merged[0].AlternatePaths) != 1 || merged[0].AlternatePaths[0] != aliasedPath {
		t.Errorf("AlternatePaths = %v, want [%s]", merged[0].AlternatePaths, aliasedPath)
	}
}

func TestDedupeByRealPathKeepsDistinctFilesSeparate(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a", "auth.db")
	b := filepath.Join(root, "b", "auth.db")
	for _, p := range []string{a, b} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	merged := dedupeByRealPath([]Candidate{
		{Kind: KindDatabase, Name: "auth.db", Path: a},
		{Kind: KindDatabase, Name: "auth.db", Path: b},
	})
	if len(merged) != 2 {
		t.Fatalf("dedupeByRealPath = %+v; want two distinct candidates (different real files)", merged)
	}
}

func TestDedupeByRealPathDifferentKindsNeverMerge(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "x")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	merged := dedupeByRealPath([]Candidate{
		{Kind: KindDatabase, Name: "x", Path: p},
		{Kind: KindContainerVolume, Name: "some-container", Path: p},
	})
	if len(merged) != 2 {
		t.Fatalf("dedupeByRealPath = %+v; want two candidates (same path, different kind)", merged)
	}
}

func TestResolveSymlinkPathFallsBackWhenUnresolvable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if got := resolveSymlinkPath(missing); got != missing {
		t.Errorf("resolveSymlinkPath(%q) = %q, want the path unchanged on lookup failure", missing, got)
	}
	if got := resolveSymlinkPath(""); got != "" {
		t.Errorf("resolveSymlinkPath(\"\") = %q, want \"\"", got)
	}
}

// TestDedupeByRealPathPreservesDeliberateNameForFixedKinds is a real
// regression: dedupe's basename-recompute must NOT clobber a
// deliberately-chosen name — package-manifest and etc-config both keep a
// descriptive Name set by collectSystem, independent of their path's
// basename (unlike database/repo, whose Name genuinely IS the basename).
func TestDedupeByRealPathPreservesDeliberateNameForFixedKinds(t *testing.T) {
	root := t.TempDir()
	rpmDir := filepath.Join(root, "usr", "lib", "sysimage", "rpm")
	if err := os.MkdirAll(rpmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	merged := dedupeByRealPath([]Candidate{
		{Kind: KindPackageManifest, Name: "package-manifest", Path: rpmDir},
	})
	if len(merged) != 1 || merged[0].Name != "package-manifest" {
		t.Fatalf("merged = %+v; want Name unchanged (\"package-manifest\")", merged)
	}

	etcDir := filepath.Join(root, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	merged = dedupeByRealPath([]Candidate{
		{Kind: KindEtcConfig, Name: "etc-customizations", Path: etcDir},
	})
	if len(merged) != 1 || merged[0].Name != "etc-customizations" {
		t.Fatalf("merged = %+v; want Name unchanged (\"etc-customizations\")", merged)
	}
}

// TestDedupeByRealPathPreservesUnitNameForServiceState: service-state's
// Name is the systemd unit name, unrelated to its state Path's basename.
func TestDedupeByRealPathPreservesUnitNameForServiceState(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "myapp", "data", "state.db")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	merged := dedupeByRealPath([]Candidate{
		{Kind: KindServiceState, Name: "myapp.service", Path: statePath},
	})
	if len(merged) != 1 || merged[0].Name != "myapp.service" {
		t.Fatalf("merged = %+v; want Name unchanged (\"myapp.service\")", merged)
	}
}
