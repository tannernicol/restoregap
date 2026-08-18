// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func TestLint(t *testing.T) {
	dir := t.TempDir()
	existingArtifact := writeFile(t, dir, "artifact", "x")
	missingArtifact := filepath.Join(dir, "does-not-exist")

	cases := []struct {
		name       string
		drill      contextspec.Drill
		wantSevs   []LintSeverity // in order
		wantSubstr []string       // parallel substrings, one per wantSevs entry
	}{
		{
			name:  "fully clean: pin_check declared, artifact present, no rpo budget",
			drill: contextspec.Drill{Proof: "clean", Artifact: existingArtifact, Recover: "true", PinCheck: "true"},
		},
		{
			name:       "missing pin_check is a warn",
			drill:      contextspec.Drill{Proof: "no-pin", Artifact: existingArtifact, Recover: "true"},
			wantSevs:   []LintSeverity{LintWarn},
			wantSubstr: []string{"pin_check"},
		},
		{
			name:       "missing artifact is a warn, not an error (portable: may target another host)",
			drill:      contextspec.Drill{Proof: "elsewhere", Artifact: missingArtifact, Recover: "true", PinCheck: "true"},
			wantSevs:   []LintSeverity{LintWarn},
			wantSubstr: []string{"does not exist"},
		},
		{
			name: "rpo budget with an implicit byte_identical-only check is an error",
			drill: contextspec.Drill{
				Proof: "rpo-no-source", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Budgets: contextspec.DrillBudgets{RPO: time.Hour},
			},
			wantSevs:   []LintSeverity{LintError},
			wantSubstr: []string{"no check here can measure freshness"},
		},
		{
			name: "rpo budget with sqlite freshness declared is clean",
			drill: contextspec.Drill{
				Proof: "rpo-sqlite", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Budgets:  contextspec.DrillBudgets{RPO: time.Hour},
				Validate: []contextspec.DrillCheck{{Type: "sqlite", Freshness: &contextspec.DrillFreshness{Table: "t", Column: "c"}}},
			},
		},
		{
			name: "rpo budget with a git check is clean (auto-derived freshness)",
			drill: contextspec.Drill{
				Proof: "rpo-git", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Budgets:  contextspec.DrillBudgets{RPO: time.Hour},
				Validate: []contextspec.DrillCheck{{Type: "git"}},
			},
		},
		{
			name: "rpo budget with only a command check is an error",
			drill: contextspec.Drill{
				Proof: "rpo-command-only", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Budgets:  contextspec.DrillBudgets{RPO: time.Hour},
				Validate: []contextspec.DrillCheck{{Type: "command", Run: "true"}},
			},
			wantSevs:   []LintSeverity{LintError},
			wantSubstr: []string{"no check here can measure freshness"},
		},
		{
			name: "everything wrong at once: error first, then warns, all proof-tagged",
			drill: contextspec.Drill{
				Proof: "everything", Artifact: missingArtifact, Recover: "true",
				Budgets: contextspec.DrillBudgets{RPO: time.Hour},
			},
			wantSevs:   []LintSeverity{LintError, LintWarn, LintWarn},
			wantSubstr: []string{"no check here can measure freshness", "pin_check", "does not exist"},
		},
		{
			name: "key_fingerprint with only min_keys is a warn (asserts existence, not identity)",
			drill: contextspec.Drill{
				Proof: "keys-existence-only", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Validate: []contextspec.DrillCheck{{Type: "key_fingerprint", Keys: "ssh", MinKeys: 1}},
			},
			wantSevs:   []LintSeverity{LintWarn},
			wantSubstr: []string{"only asserts that at least one exists"},
		},
		{
			name: "key_fingerprint with expect_from is clean",
			drill: contextspec.Drill{
				Proof: "keys-expect-from", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Validate: []contextspec.DrillCheck{{Type: "key_fingerprint", Keys: "ssh", ExpectFrom: "/home/user/.ssh", MinKeys: 1}},
			},
		},
		{
			name: "key_fingerprint with explicit expect: is clean",
			drill: contextspec.Drill{
				Proof: "keys-expect", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Validate: []contextspec.DrillCheck{{Type: "key_fingerprint", Keys: "gpg", Expect: []string{"DEADBEEF"}, MinKeys: 1}},
			},
		},
		{
			name: "sqlite tables: percent-of-live floor is clean",
			drill: contextspec.Drill{
				Proof: "tables-percent", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Validate: []contextspec.DrillCheck{{Type: "sqlite", Tables: map[string]string{"assistant_jobs": ">= 90%"}}},
			},
		},
		{
			name: "sqlite tables: explicit 'N% live' spelling is clean",
			drill: contextspec.Drill{
				Proof: "tables-percent-live", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Validate: []contextspec.DrillCheck{{Type: "sqlite", Tables: map[string]string{"assistant_jobs": ">= 90% live"}}},
			},
		},
		{
			name: "sqlite tables: malformed constraint is an error",
			drill: contextspec.Drill{
				Proof: "tables-malformed", Artifact: existingArtifact, Recover: "true", PinCheck: "true",
				Validate: []contextspec.DrillCheck{{Type: "sqlite", Tables: map[string]string{"assistant_jobs": "plenty"}}},
			},
			wantSevs:   []LintSeverity{LintError},
			wantSubstr: []string{"tables.assistant_jobs"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Lint(c.drill)
			if len(got) != len(c.wantSevs) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(c.wantSevs), got)
			}
			for i, f := range got {
				if f.Proof != c.drill.Proof {
					t.Errorf("finding[%d].Proof = %q, want %q", i, f.Proof, c.drill.Proof)
				}
				if f.Severity != c.wantSevs[i] {
					t.Errorf("finding[%d].Severity = %s, want %s", i, f.Severity, c.wantSevs[i])
				}
				if !strings.Contains(f.Message, c.wantSubstr[i]) {
					t.Errorf("finding[%d].Message = %q, want substring %q", i, f.Message, c.wantSubstr[i])
				}
			}
		})
	}
}
