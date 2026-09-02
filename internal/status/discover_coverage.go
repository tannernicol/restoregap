// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"fmt"
	"time"

	"github.com/tannernicol/restoregap/internal/discover"
)

// discoverNotScannedLine is shown whenever discover's snapshot is missing,
// unreadable, malformed, or stale — every one of those cases reads the
// same to a human: "go run discover", not a silently absent line.
const discoverNotScannedLine = "coverage: not scanned (run restoregap discover)"

// discoverCoverageLine renders status's one-line pointer to `restoregap
// discover`'s last snapshot, evaluated as of now (s.GeneratedAt, so a fixed
// --as-of run stays reproducible). It ONLY reads a file already on disk —
// status must never trigger a scan itself, so this is a plain local file
// read, not a call into discover.Collect.
func discoverCoverageLine(now time.Time) string {
	stateDir, err := discover.DefaultStateDir()
	if err != nil {
		return discoverNotScannedLine
	}
	summary, ok := discover.ReadStatusSummary(stateDir, now)
	if !ok {
		return discoverNotScannedLine
	}
	return renderDiscoverLine(summary)
}

// renderDiscoverLine is discoverCoverageLine's/gatherDiscoverCoverage's
// shared "coverage: N of M candidates covered [· K new since <date>]" text
// — factored out so both call sites render byte-identical text from a
// discover.StatusSummary.
func renderDiscoverLine(summary discover.StatusSummary) string {
	line := fmt.Sprintf("coverage: %d of %d candidates covered", summary.Covered, summary.Candidates)
	if summary.New > 0 && !summary.PreviousGeneratedAt.IsZero() {
		line += fmt.Sprintf(" · %d new since %s", summary.New, summary.PreviousGeneratedAt.Format("2006-01-02"))
	}
	return line
}

// discoverCoverageStaleLine is the HTML coverage block's line when a real
// snapshot exists but has aged past discover's own freshness window — a
// stale number is never presented as current, so this deliberately drops
// the counts and only names when the snapshot was taken.
func discoverCoverageStaleLine(generatedAt time.Time) string {
	return fmt.Sprintf("coverage: stale snapshot from %s — run restoregap discover", generatedAt.Format("2006-01-02"))
}

// DiscoverCoverage is status's whole view of `restoregap discover`'s last
// on-disk snapshot: the state it was found in (never a stale number
// presented as current), the one-line summary, every non-suppressed
// uncovered candidate ranked by consequence (the HTML coverage block slices
// off its own inline-vs-folded split), and the shared agent-remediation
// prompt (discover.RenderPrompt) for its "Fix this" <details> — all
// gathered once, at Gather time, from a plain on-disk read; status never
// triggers a scan.
type DiscoverCoverage struct {
	// State is "fresh" (a usable, current snapshot), "stale" (one exists
	// but has aged out), or "absent" (missing, unreadable, or malformed).
	State string
	// Line is the one-line summary the banner shows — discoverNotScannedLine,
	// discoverCoverageStaleLine's text, or renderDiscoverLine's text,
	// matching State.
	Line string
	// Uncovered is every non-suppressed uncovered candidate, already ranked
	// by consequence (discover.Collect's own weight/size ordering) —
	// populated only when State is "fresh".
	Uncovered []discover.Candidate
	// Prompt is discover.RenderPrompt's full agent brief — the exact text
	// `restoregap discover --prompt` prints — empty whenever Uncovered is
	// empty (a green coverage block carries no remediation scaffolding).
	Prompt string
}

// gatherDiscoverCoverage reads discover's on-disk snapshot exactly once, as
// of now, and builds status's whole coverage view — the HTML page's Q2
// section (and DiscoverLine's plain-text sibling) both derive from this,
// so they can never disagree about the state a snapshot was found in.
func gatherDiscoverCoverage(now time.Time) DiscoverCoverage {
	stateDir, err := discover.DefaultStateDir()
	if err != nil {
		return DiscoverCoverage{State: "absent", Line: discoverNotScannedLine}
	}
	report, state := discover.ReadLatestReport(stateDir, now)
	switch state {
	case discover.SnapshotAbsent:
		return DiscoverCoverage{State: "absent", Line: discoverNotScannedLine}
	case discover.SnapshotStale:
		return DiscoverCoverage{State: "stale", Line: discoverCoverageStaleLine(report.GeneratedAt)}
	}

	summary := discover.StatusSummary{
		GeneratedAt: report.GeneratedAt, Candidates: report.Counts.Candidates,
		Covered: report.Counts.Covered, New: report.Counts.New, PreviousGeneratedAt: report.PreviousGeneratedAt,
	}
	dc := DiscoverCoverage{State: "fresh", Line: renderDiscoverLine(summary)}

	for _, c := range report.Candidates {
		if !c.Covered && !c.Suppressed {
			dc.Uncovered = append(dc.Uncovered, c)
		}
	}
	if len(dc.Uncovered) > 0 {
		dc.Prompt = discover.RenderPrompt(&report, false, "all")
	}
	return dc
}

// coverageTopShown is how many uncovered candidates the HTML coverage
// block lists inline, by consequence, before folding the rest behind a
// <details> — the "top ~8" ask.
const coverageTopShown = 8

// coverageCandidateView is one uncovered candidate, formatted for the HTML
// coverage block's inline/foldable lists: kind, name, path, and a
// human-readable size (discover.HumanizeBytes — the exact same formatting
// `restoregap discover`'s own grouped-line total uses).
type coverageCandidateView struct {
	Kind string
	Name string
	Path string
	Size string
}

// coverageBlockData is the HTML page's whole Q2 ("what is not protected at
// all") section, pre-rendered so the template stays free of derivation
// logic: the coverage line in every state, and — only when State is fresh
// and there is something to fix — the visible top coverageTopShown
// candidates, the folded remainder, and the Fix-this remediation prompt. A
// page with nothing to fix (stale/absent, or fresh with zero uncovered)
// gets ShowDetail=false and renders no candidate list or prompt at all.
type coverageBlockData struct {
	State      string
	Line       string
	ShowDetail bool
	Top        []coverageCandidateView
	Rest       []coverageCandidateView
	RestCount  int
	Prompt     string
}

// buildCoverageBlock converts a DiscoverCoverage into the HTML page's Q2
// section data.
func buildCoverageBlock(dc DiscoverCoverage) coverageBlockData {
	cb := coverageBlockData{State: dc.State, Line: dc.Line}
	if dc.State != "fresh" || len(dc.Uncovered) == 0 {
		return cb
	}
	cb.ShowDetail = true
	views := make([]coverageCandidateView, len(dc.Uncovered))
	for i, c := range dc.Uncovered {
		views[i] = coverageCandidateView{Kind: string(c.Kind), Name: c.Name, Path: c.Path, Size: discover.HumanizeBytes(c.SizeBytes)}
	}
	if len(views) > coverageTopShown {
		cb.Top, cb.Rest = views[:coverageTopShown], views[coverageTopShown:]
	} else {
		cb.Top = views
	}
	cb.RestCount = len(cb.Rest)
	cb.Prompt = dc.Prompt
	return cb
}
