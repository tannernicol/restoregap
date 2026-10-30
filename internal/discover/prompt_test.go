// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"strings"
	"testing"
	"time"
)

func TestRenderPromptContainsRulesBlockAndOneBulletPerUncovered(t *testing.T) {
	r := &Report{
		Host:        "test-host",
		GeneratedAt: time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC),
		Counts:      Counts{Candidates: 3, Covered: 1, Uncovered: 2},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "money.db", Path: "/home/user/money/money.db", SizeBytes: 100, Covered: true, Weight: 3},
			{Kind: KindRepo, Name: "proj", Path: "/home/user/proj", SizeBytes: 42, Covered: false, Weight: 1},
			{Kind: KindEtcConfig, Name: "etc-customizations", Path: "/etc", SizeBytes: 7, Covered: false, Weight: 4},
		},
	}
	out := RenderPrompt(r, false, "all")

	if !strings.Contains(out, PromptRules) {
		t.Errorf("expected the rules block verbatim, got:\n%s", out)
	}
	if !strings.Contains(out, "- "+string(KindRepo)+"  proj  /home/user/proj  42 bytes") {
		t.Errorf("expected a bullet for the uncovered repo candidate, got:\n%s", out)
	}
	if !strings.Contains(out, "- "+string(KindEtcConfig)+"  etc-customizations  /etc  7 bytes") {
		t.Errorf("expected a bullet for the uncovered etc-config candidate, got:\n%s", out)
	}
	if strings.Contains(out, "money.db") {
		t.Errorf("a covered candidate must not appear in the prompt, got:\n%s", out)
	}
	if n := strings.Count(out, "- "); n != 2 {
		t.Errorf("expected exactly 2 bullets (one per uncovered candidate), got %d in:\n%s", n, out)
	}
	for _, want := range []string{"host: test-host", "coverage: 1 of 3 candidates covered", "scope: all", "generated: 2026-08-24"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing header field %q, got:\n%s", want, out)
		}
	}
}

func TestRenderPromptCapsAtDisplayLimitUnlessAll(t *testing.T) {
	var candidates []Candidate
	for i := 0; i < promptDisplayLimit+5; i++ {
		candidates = append(candidates, Candidate{Kind: KindRepo, Name: "r", Path: "/p", Weight: 1})
	}
	r := &Report{Counts: Counts{Candidates: len(candidates), Uncovered: len(candidates)}, Candidates: candidates}

	capped := RenderPrompt(r, false, "all")
	if n := strings.Count(capped, "- "); n != promptDisplayLimit {
		t.Errorf("expected %d bullets under the default cap, got %d", promptDisplayLimit, n)
	}
	if !strings.Contains(capped, "... and 5 more (--all)") {
		t.Errorf("expected the fold-more line, got:\n%s", capped)
	}

	full := RenderPrompt(r, true, "all")
	if n := strings.Count(full, "- "); n != len(candidates) {
		t.Errorf("--all should list every uncovered candidate, got %d bullets, want %d", n, len(candidates))
	}
}

func TestRenderPromptSuppressedExcludedByDefault(t *testing.T) {
	r := &Report{
		Counts: Counts{Candidates: 1, Uncovered: 1, Suppressed: 1},
		Candidates: []Candidate{
			{Kind: KindRepo, Name: "noise", Path: "/p", Weight: 1, Suppressed: true, SuppressedBy: "default:*"},
		},
	}
	out := RenderPrompt(r, false, "all")
	if strings.Contains(out, "noise") {
		t.Errorf("a suppressed candidate must not appear in the default prompt, got:\n%s", out)
	}
	if !strings.Contains(out, "nothing uncovered") {
		t.Errorf("expected the nothing-uncovered line when every gap is suppressed, got:\n%s", out)
	}

	all := RenderPrompt(r, true, "all")
	if !strings.Contains(all, "noise") {
		t.Errorf("--all must include the suppressed candidate, got:\n%s", all)
	}
}
