// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

import "testing"

func TestDefaultCoversLifelinePaths(t *testing.T) {
	ctx := Default()
	if ctx.Version != 2 {
		t.Fatalf("Default() version = %d, want 2", ctx.Version)
	}
	for _, g := range ctx.Guards {
		if g.Kind != GuardKindLifeline {
			t.Errorf("guard %s: kind = %s, want lifeline", g.ID, g.Kind)
		}
		if g.Enforcement != EnforcementBlock {
			t.Errorf("guard %s: enforcement = %s, want block", g.ID, g.Enforcement)
		}
		if !g.Requires.Empty() {
			t.Errorf("guard %s: zero-config guards must declare no requirements (nothing to prove safety with)", g.ID)
		}
	}
	if len(ctx.Guards) == 0 {
		t.Fatal("Default() declared no guards")
	}
}
