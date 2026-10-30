// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderTextSummaryLineAndUncovered(t *testing.T) {
	r := &Report{
		Counts: Counts{Candidates: 3, Covered: 1, Uncovered: 2},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "money.db", Path: "/home/user/money/money.db", SizeBytes: 100, Covered: true, CoveredBy: "drill:money-db", Weight: 3},
			{Kind: KindRepo, Name: "proj", Path: "/home/user/proj", SizeBytes: 0, Covered: false, Weight: 1},
			{Kind: KindEtcConfig, Name: "etc-customizations", Path: "/etc", SizeBytes: 0, Covered: false, Weight: 4},
		},
	}
	out := string(RenderText(r, false))
	if !strings.HasPrefix(out, "coverage: 1 of 3 candidates covered (2 uncovered)\n") {
		t.Fatalf("unexpected summary line:\n%s", out)
	}
	if strings.Contains(out, "money.db") {
		t.Error("covered candidate must not appear without --all")
	}
	if !strings.Contains(out, "etc-customizations") || !strings.Contains(out, "proj") {
		t.Errorf("uncovered candidates missing from output:\n%s", out)
	}
	// etc-config (weight 4) must sort before repo (weight 1) — worst first.
	if strings.Index(out, "etc-customizations") > strings.Index(out, "proj") {
		t.Errorf("expected higher-weight candidate first:\n%s", out)
	}
}

func TestRenderTextAllIncludesCoveredWithCoveredBy(t *testing.T) {
	r := &Report{
		Counts: Counts{Candidates: 1, Covered: 1, Uncovered: 0},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "money.db", Path: "/home/user/money/money.db", Covered: true, CoveredBy: "drill:money-db", Weight: 3},
		},
	}
	out := string(RenderText(r, true))
	if !strings.Contains(out, "covered:") || !strings.Contains(out, "covered by drill:money-db") {
		t.Errorf("--all output missing covered section/attribution:\n%s", out)
	}
}

func TestRenderTextNewSection(t *testing.T) {
	r := &Report{
		Counts:              Counts{Candidates: 1, Covered: 0, Uncovered: 1, New: 1},
		PreviousGeneratedAt: time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC),
		Candidates:          []Candidate{{Kind: KindDatabase, Name: "new.db", Path: "/home/user/new.db", Weight: 3}},
		New:                 []string{"database:/home/user/new.db"},
	}
	out := string(RenderText(r, false))
	if !strings.Contains(out, "new since 2026-08-18:") {
		t.Errorf("missing new-since section header:\n%s", out)
	}
}

func TestRenderTextOmitsNewSectionWhenEmpty(t *testing.T) {
	r := &Report{Counts: Counts{Candidates: 0, Covered: 0, Uncovered: 0}}
	out := string(RenderText(r, false))
	if strings.Contains(out, "new since") {
		t.Errorf("unexpected new-since section with nothing new:\n%s", out)
	}
}

func TestRenderTrendDeltas(t *testing.T) {
	rows := []HistoryRow{
		{ScannedAt: time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC), Candidates: 68, Covered: 38},
		{ScannedAt: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC), Candidates: 70, Covered: 40},
		{ScannedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), Candidates: 71, Covered: 38},
	}
	out := string(RenderTrend(rows, 0))
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), out)
	}
	if !strings.HasSuffix(lines[0], "—") {
		t.Errorf("first row should have no delta: %q", lines[0])
	}
	if !strings.HasSuffix(lines[1], "+2") {
		t.Errorf("second row delta wrong: %q", lines[1])
	}
	if !strings.HasSuffix(lines[2], "-2") {
		t.Errorf("third row delta wrong: %q", lines[2])
	}
}

func TestRenderTrendLimitKeepsDeltaContinuity(t *testing.T) {
	rows := []HistoryRow{
		{ScannedAt: time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC), Candidates: 60, Covered: 30},
		{ScannedAt: time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC), Candidates: 68, Covered: 38},
		{ScannedAt: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC), Candidates: 70, Covered: 40},
	}
	out := string(RenderTrend(rows, 2))
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (limit), got %d:\n%s", len(lines), out)
	}
	// The first displayed row (2026-08-18) must show its delta against the
	// row before it (2026-08-17), even though that row was truncated away.
	if !strings.HasSuffix(lines[0], "+8") {
		t.Errorf("expected delta continuity across the truncation boundary: %q", lines[0])
	}
}

func TestRenderTrendEmpty(t *testing.T) {
	out := string(RenderTrend(nil, 10))
	if !strings.Contains(out, "no scan history") {
		t.Errorf("expected a friendly empty message, got %q", out)
	}
}

// TestRenderTextRanksBySizeWithinSameWeight is requirement #3: within the
// same weight class, a bigger candidate must print before a smaller one —
// never alphabetically. The real bug: a 460KB Zoom cache (database, weight
// 3) printed above a 5.6GB access log (also database, weight 3) because
// "3i6yb..." sorts before "access.sqlite".
func TestRenderTextRanksBySizeWithinSameWeight(t *testing.T) {
	r := &Report{
		Counts: Counts{Candidates: 2, Covered: 0, Uncovered: 2},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "3i6yb_cache.enc.db", Path: "/home/user/.zoom/data/3i6yb_cache.enc.db", SizeBytes: 460800, Weight: 3},
			{Kind: KindDatabase, Name: "access.sqlite", Path: "/home/user/.local/state/nas-access-log/access.sqlite", SizeBytes: 5669371904, Weight: 3},
		},
	}
	out := string(RenderText(r, false))
	if strings.Index(out, "access.sqlite") > strings.Index(out, "3i6yb_cache.enc.db") {
		t.Errorf("expected the larger same-weight candidate to rank first:\n%s", out)
	}
}

// TestRenderTextSuppressesNoiseByDefaultAndShowsUnderAll is requirement #1:
// the summary line names the suppressed count, a suppressed candidate does
// not appear in the default view, and --all shows it WITH its reason.
func TestRenderTextSuppressesNoiseByDefaultAndShowsUnderAll(t *testing.T) {
	r := &Report{
		Counts: Counts{Candidates: 2, Covered: 0, Uncovered: 2, Suppressed: 1},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "cookies.sqlite", Path: "/home/user/.mozilla/firefox/x/cookies.sqlite", Weight: 3, Suppressed: true, SuppressedBy: "default:**/.mozilla/**"},
			{Kind: KindDatabase, Name: "real.db", Path: "/home/user/app/real.db", Weight: 3},
		},
	}
	def := string(RenderText(r, false))
	if !strings.Contains(def, "1 suppressed as noise — --all to see") {
		t.Errorf("summary line missing suppressed count:\n%s", def)
	}
	if strings.Contains(def, "cookies.sqlite") {
		t.Errorf("suppressed candidate must not appear in the default view:\n%s", def)
	}
	if !strings.Contains(def, "real.db") {
		t.Errorf("non-suppressed candidate missing from default view:\n%s", def)
	}

	all := string(RenderText(r, true))
	if !strings.Contains(all, "cookies.sqlite") || !strings.Contains(all, "suppressed: default:**/.mozilla/**") {
		t.Errorf("--all must show the suppressed candidate with its reason:\n%s", all)
	}
}

// TestRenderTextGroupsRepeatedBasenames is requirement #4: three or more
// same-kind, same-basename candidates collapse into one line instead of
// listing every repo's beads.db separately.
func TestRenderTextGroupsRepeatedBasenames(t *testing.T) {
	var candidates []Candidate
	var total int64
	for i := 0; i < 12; i++ {
		size := int64(280000 + i*100)
		total += size
		candidates = append(candidates, Candidate{
			Kind: KindDatabase, Name: "beads.db", Path: filepath.Join("/home/user/repo", string(rune('a'+i)), ".beads", "beads.db"),
			SizeBytes: size, Weight: 3,
		})
	}
	r := &Report{Counts: Counts{Candidates: 12, Uncovered: 12}, Candidates: candidates}
	out := string(RenderText(r, false))
	if strings.Count(out, "beads.db") != 1 {
		t.Fatalf("expected exactly one grouped beads.db line, got:\n%s", out)
	}
	if !strings.Contains(out, "×12") || !strings.Contains(out, "12 locations") {
		t.Errorf("grouped line missing count markers:\n%s", out)
	}
	if !strings.Contains(out, HumanizeBytes(total)) {
		t.Errorf("grouped line missing total size %s:\n%s", HumanizeBytes(total), out)
	}
}

// TestRenderTextDoesNotGroupBelowThreshold: two candidates sharing a
// basename must NOT collapse — grouping only kicks in at groupMinCount.
func TestRenderTextDoesNotGroupBelowThreshold(t *testing.T) {
	r := &Report{
		Counts: Counts{Candidates: 2, Uncovered: 2},
		Candidates: []Candidate{
			{Kind: KindDatabase, Name: "beads.db", Path: "/home/user/repo1/.beads/beads.db", SizeBytes: 100, Weight: 3},
			{Kind: KindDatabase, Name: "beads.db", Path: "/home/user/repo2/.beads/beads.db", SizeBytes: 100, Weight: 3},
		},
	}
	out := string(RenderText(r, false))
	if strings.Contains(out, "×2") {
		t.Errorf("two repeats must not group (groupMinCount is 3):\n%s", out)
	}
	if !strings.Contains(out, "/home/user/repo1/.beads/beads.db") || !strings.Contains(out, "/home/user/repo2/.beads/beads.db") {
		t.Errorf("both individual candidates should still be listed:\n%s", out)
	}
}

// TestRenderTextTruncatesUncoveredAtDisplayLimit is requirement #3's other
// half: the default view caps at uncoveredDisplayLimit lines and names how
// many more exist.
func TestRenderTextTruncatesUncoveredAtDisplayLimit(t *testing.T) {
	var candidates []Candidate
	for i := 0; i < uncoveredDisplayLimit+5; i++ {
		candidates = append(candidates, Candidate{
			Kind: KindDatabase, Name: fmt.Sprintf("db%d.db", i), Path: fmt.Sprintf("/home/user/app%d/db.db", i),
			SizeBytes: int64(1000 - i), Weight: 3,
		})
	}
	r := &Report{Counts: Counts{Candidates: len(candidates), Uncovered: len(candidates)}, Candidates: candidates}
	out := string(RenderText(r, false))
	if !strings.Contains(out, "... and 5 more (--all)") {
		t.Errorf("expected a truncation footer for the 5 overflow candidates:\n%s", out)
	}
	if strings.Count(out, "database  db") != uncoveredDisplayLimit {
		t.Errorf("expected exactly %d displayed lines, got:\n%s", uncoveredDisplayLimit, out)
	}
}

// TestHumanizeBytes spot-checks the grouped-line size formatter.
func TestHumanizeBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{500, "500 B"},
		{534011904, "534.0 MB"},
		{8700000, "8.7 MB"},
		{5669371904, "5.7 GB"},
	}
	for _, c := range cases {
		if got := HumanizeBytes(c.in); got != c.want {
			t.Errorf("HumanizeBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
