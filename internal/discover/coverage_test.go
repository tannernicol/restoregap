// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
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
