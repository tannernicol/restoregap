// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func TestCoverIsCoveredByDrillArtifact(t *testing.T) {
	ctx := contextspec.Context{Drills: []contextspec.Drill{
		{Proof: "money-db", Artifact: "/home/user/money/money.db", RecoverySource: "s3://bucket/money.db"},
	}}
	idx := newCoverageIndex(ctx)
	ok, by := idx.cover("/home/user/money/money.db")
	if !ok || by != "drill:money-db" {
		t.Fatalf("cover() = %v, %q; want true, \"drill:money-db\"", ok, by)
	}
}

func TestCoverIsCoveredByRecoverySource(t *testing.T) {
	ctx := contextspec.Context{Drills: []contextspec.Drill{
		{Proof: "media", Artifact: "/artifact/ignored", RecoverySource: "/mnt/backup/media"},
	}}
	idx := newCoverageIndex(ctx)
	ok, by := idx.cover("/mnt/backup/media")
	if !ok || by != "drill:media" {
		t.Fatalf("cover() = %v, %q; want true, \"drill:media\"", ok, by)
	}
}

func TestCoverIsCoveredByDrillArtifactAncestor(t *testing.T) {
	// A candidate file living inside a directory a drill's artifact names
	// wholesale still counts as covered.
	ctx := contextspec.Context{Drills: []contextspec.Drill{
		{Proof: "docs", Artifact: "/home/user/docs", RecoverySource: "/mnt/backup/docs"},
	}}
	idx := newCoverageIndex(ctx)
	ok, _ := idx.cover("/home/user/docs/tax/2026.pdf")
	if !ok {
		t.Fatal("expected candidate nested under a drill's artifact directory to be covered")
	}
}

func TestCoverIsCoveredByGuardMatchedPath(t *testing.T) {
	ctx := contextspec.Context{Guards: []contextspec.Guard{
		{ID: "ssh-keys", Match: contextspec.Matcher{Paths: []string{"**/.ssh/id_*"}}},
	}}
	idx := newCoverageIndex(ctx)
	ok, by := idx.cover("/home/user/.ssh/id_ed25519")
	if !ok || by != "guard:ssh-keys" {
		t.Fatalf("cover() = %v, %q; want true, \"guard:ssh-keys\"", ok, by)
	}
}

func TestCoverIsUncovered(t *testing.T) {
	ctx := contextspec.Context{
		Drills: []contextspec.Drill{{Proof: "money-db", Artifact: "/home/user/money/money.db"}},
		Guards: []contextspec.Guard{{ID: "ssh-keys", Match: contextspec.Matcher{Paths: []string{"**/.ssh/id_*"}}}},
	}
	idx := newCoverageIndex(ctx)
	ok, by := idx.cover("/home/user/immich/library.db")
	if ok || by != "" {
		t.Fatalf("cover() = %v, %q; want false, \"\"", ok, by)
	}
}

// TestCoverNeverSetExternally is the integrity check the whole feature
// hinges on: a candidate can only read covered=true because a REAL declared
// drill or guard names its path. Nothing else — not a hand-built Candidate,
// not a previous snapshot on disk — can make cover() return true.
func TestCoverNeverSetExternally(t *testing.T) {
	// An empty context: nothing declared at all.
	idx := newCoverageIndex(contextspec.Context{})
	for _, path := range []string{
		"/home/user/money/money.db",
		"/etc/machine-id",
		"/mnt/backup/anything",
		"",
	} {
		if ok, by := idx.cover(path); ok || by != "" {
			t.Errorf("cover(%q) with an empty context = %v, %q; want false, \"\" — coverage must never come from anywhere but a declared drill/guard", path, ok, by)
		}
	}
}

func TestPathOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/home/user/foo", "/home/user/foo", true},
		{"/home/user/foo", "/home/user/foo/bar.txt", true},
		{"/home/user/foo/bar.txt", "/home/user/foo", true},
		{"/home/user/foo", "/home/user/foobar", false}, // must not be a raw substring match
		{"", "/home/user/foo", false},
		{"/home/user/foo", "", false},
	}
	for _, c := range cases {
		if got := pathOverlap(c.a, c.b); got != c.want {
			t.Errorf("pathOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestCoverMatchesAcrossSymlinkedPrefix pins the macOS failure mode: a
// drill written with a symlinked prefix (/tmp, /var) must still cover a
// candidate whose Path was canonicalised (/private/tmp, /private/var), and
// the reverse. The symlink is built by hand so the test fails on Linux too
// if the canonical form is ever dropped.
func TestCoverMatchesAcrossSymlinkedPrefix(t *testing.T) {
	root := canonicalDir(t, t.TempDir())
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "app.db")
	if err := os.WriteFile(realFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(link, "app.db")

	// Drill names the symlink spelling; the candidate is canonical.
	viaLink := newCoverageIndex(contextspec.Context{Drills: []contextspec.Drill{{Proof: "app", Artifact: linkFile}}})
	if ok, by := viaLink.cover(realFile); !ok || by != "drill:app" {
		t.Errorf("cover(%q) with a symlink-spelled drill = %v, %q; want true, \"drill:app\"", realFile, ok, by)
	}
	// Drill names the canonical spelling; the candidate arrives as the alias.
	viaReal := newCoverageIndex(contextspec.Context{Drills: []contextspec.Drill{{Proof: "app", Artifact: realFile}}})
	if ok, by := viaReal.cover(linkFile); !ok || by != "drill:app" {
		t.Errorf("cover(%q) with a canonical drill = %v, %q; want true, \"drill:app\"", linkFile, ok, by)
	}
}

// TestCoverCandidateTriesAlternatePaths pins that a guard glob written in
// the spelling the operator used still covers a candidate whose primary
// Path was canonicalised, because dedupe keeps the original spelling in
// AlternatePaths.
func TestCoverCandidateTriesAlternatePaths(t *testing.T) {
	idx := newCoverageIndex(contextspec.Context{Guards: []contextspec.Guard{
		{ID: "alias-only", Match: contextspec.Matcher{Paths: []string{"/alias/**/*.db"}}},
	}})
	cand := Candidate{
		Kind: KindDatabase, Name: "a.db",
		Path:           "/canonical/data/a.db",
		AlternatePaths: []string{"/alias/data/a.db"},
	}
	if ok, by := idx.coverCandidate(cand); !ok || by != "guard:alias-only" {
		t.Fatalf("coverCandidate = %v, %q; want true, \"guard:alias-only\"", ok, by)
	}
	cand.AlternatePaths = nil
	if ok, _ := idx.coverCandidate(cand); ok {
		t.Fatal("coverCandidate matched with no alternate path naming the alias")
	}
}
