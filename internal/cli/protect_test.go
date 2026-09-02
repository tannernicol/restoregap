// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package cli

import (
	"strings"
	"testing"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func lifeline(id string, paths ...string) contextspec.Guard {
	return contextspec.Guard{ID: id, Kind: contextspec.GuardKindLifeline, Match: contextspec.Matcher{Paths: paths}}
}

// TestProtectFindingsUnDeclaringALifeline is the defect this command exists
// for: delete the backup and its declaration in one diff, and every other gate
// passes because the rule it would have broken is gone.
func TestProtectFindingsUnDeclaringALifeline(t *testing.T) {
	base := contextspec.Context{Guards: []contextspec.Guard{lifeline("ssh-keys", "/srv/testuser/.ssh/**"), lifeline("db", "/var/db/**")}}
	head := contextspec.Context{Guards: []contextspec.Guard{lifeline("db", "/var/db/**")}}

	got := protectFindings(base, head, []string{"/repo/context.yml"}, []string{"internal/x.go"}, "/repo")
	if len(got) != 1 || !strings.Contains(got[0], "ssh-keys") {
		t.Fatalf("dropping a lifeline must be a finding, got %v", got)
	}

	// Same declarations on both sides: nothing to say.
	if got := protectFindings(base, base, []string{"/repo/context.yml"}, []string{"internal/x.go"}, "/repo"); len(got) != 0 {
		t.Fatalf("unrelated change must pass, got %v", got)
	}
}

// TestProtectFindingsTouchingDeclarationsAndProtectedPaths covers the two
// file-level rules: the declaration file itself, and a file a lifeline covers.
func TestProtectFindingsTouchingDeclarationsAndProtectedPaths(t *testing.T) {
	ctx := contextspec.Context{Guards: []contextspec.Guard{
		{ID: "backups", Kind: contextspec.GuardKindLifeline, Match: contextspec.Matcher{Paths: []string{"/repo/backups/**"}}, RecoveryCopy: "/repo/recovery/**"},
		{ID: "ordinary", Kind: contextspec.GuardKindGuard, Match: contextspec.Matcher{Paths: []string{"/repo/internal/**"}}},
	}}
	paths := []string{"/repo/restoregap.yml"}

	cases := []struct {
		name    string
		changed []string
		want    bool
	}{
		{"edits the declaration file", []string{"restoregap.yml"}, true},
		{"edits a lifeline-protected path", []string{"backups/nightly.tar.age"}, true},
		{"edits the recovery copy", []string{"recovery/nightly.tar.age"}, true},
		{"ordinary guard is not a lifeline", []string{"internal/service.go"}, false},
		{"unrelated code", []string{"README.md"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := protectFindings(ctx, ctx, paths, tc.changed, "/repo")
			if (len(got) > 0) != tc.want {
				t.Fatalf("findings=%v, want blocked=%v", got, tc.want)
			}
		})
	}
}
