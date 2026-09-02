// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"fmt"
	"sort"
	"strings"
)

// TrendDisplayLimit is how many of the newest history rows `discover
// --trend` and the MCP tool's trend option show by default.
const TrendDisplayLimit = 10

// uncoveredDisplayLimit is how many uncovered lines (after grouping —
// groupMinCount) the default text view shows before folding the rest
// behind "... and N more (--all)". A gap list a person cannot read in one
// screen gets skimmed, not acted on.
const uncoveredDisplayLimit = 20

// groupMinCount is the minimum number of same-kind, same-basename
// candidates before they collapse into one grouped line — twelve
// near-identical `.beads/beads.db` rows is exactly the noise that makes a
// gap list feel unreadable.
const groupMinCount = 3

// RenderText renders report as `restoregap discover`'s plain-text output:
// a coverage summary line (naming how many uncovered candidates are
// suppressed noise, when any are), the uncovered candidates ranked by
// CONSEQUENCE (weight, then size — never alphabetically) with same-
// basename repeats collapsed into one grouped line and the list capped at
// uncoveredDisplayLimit, a new-since-last-scan section, and — only when
// all is true — the full ungrouped, untruncated listing including
// suppressed candidates (with why) and covered ones (with what covered
// them).
func RenderText(report *Report, all bool) []byte {
	var b strings.Builder
	b.WriteString(summaryLine(report))
	b.WriteString("\n")

	var uncovered, covered []Candidate
	for _, c := range report.Candidates {
		if c.Covered {
			covered = append(covered, c)
		} else {
			uncovered = append(uncovered, c)
		}
	}
	// Sort defensively (worst weight, then size, first) rather than
	// trusting the caller's ordering — Collect() already sorts, but
	// RenderText must not silently depend on that.
	sortCandidates(uncovered)
	sortCandidates(covered)

	writeUncoveredSection(&b, uncovered, all)
	writeNewSection(&b, report, all)

	if all && len(covered) > 0 {
		b.WriteString("\ncovered:\n")
		for _, c := range covered {
			writeCandidateLine(&b, c)
		}
	}
	return []byte(b.String())
}

// summaryLine renders the "coverage: N of M candidates covered (...)"
// headline, naming the suppressed-as-noise count only when it is nonzero
// — the same "only mention it when it's not zero" rule the New section
// already follows.
func summaryLine(report *Report) string {
	if report.Counts.Suppressed > 0 {
		return fmt.Sprintf("coverage: %d of %d candidates covered (%d uncovered · %d suppressed as noise — --all to see)",
			report.Counts.Covered, report.Counts.Candidates, report.Counts.Uncovered, report.Counts.Suppressed)
	}
	return fmt.Sprintf("coverage: %d of %d candidates covered (%d uncovered)",
		report.Counts.Covered, report.Counts.Candidates, report.Counts.Uncovered)
}

// writeUncoveredSection writes the uncovered listing: --all gets every
// candidate, ungrouped, untruncated (suppressed ones included, with their
// reason); the default view drops suppressed noise first, then groups and
// truncates what remains.
func writeUncoveredSection(b *strings.Builder, uncovered []Candidate, all bool) {
	if all {
		if len(uncovered) == 0 {
			return
		}
		b.WriteString("\n")
		for _, c := range uncovered {
			writeCandidateLine(b, c)
		}
		return
	}
	visible := filterSuppressed(uncovered)
	if len(visible) == 0 {
		return
	}
	b.WriteString("\n")
	writeRankedUncovered(b, visible)
}

// filterSuppressed returns candidates with Suppressed entries removed.
func filterSuppressed(candidates []Candidate) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if !c.Suppressed {
			out = append(out, c)
		}
	}
	return out
}

// writeNewSection writes the "new since <date>:" section when report.New
// is non-empty — under the default view, suppressed new candidates are
// left out (noise is noise whether it is new or not); --all lists every
// one.
func writeNewSection(b *strings.Builder, report *Report, all bool) {
	if len(report.New) == 0 {
		return
	}
	byKey := make(map[string]Candidate, len(report.Candidates))
	for _, c := range report.Candidates {
		byKey[candidateKey(c)] = c
	}
	var shown []Candidate
	for _, key := range report.New {
		c, ok := byKey[key]
		if !ok {
			continue
		}
		if !all && c.Suppressed {
			continue
		}
		shown = append(shown, c)
	}
	if len(shown) == 0 {
		return
	}
	fmt.Fprintf(b, "\nnew since %s:\n", report.PreviousGeneratedAt.Format("2006-01-02"))
	for _, c := range shown {
		writeCandidateLine(b, c)
	}
}

// displayLine is one rendered line of the default (grouped, ranked,
// truncated) uncovered listing — either one candidate or one collapsed
// group — carrying just enough to re-sort by consequence after grouping.
type displayLine struct {
	weight   int
	sortSize int64
	text     string
}

// writeRankedUncovered groups same-kind/same-basename repeats
// (groupMinCount or more) into one line, ranks every resulting line by
// (weight DESC, size DESC), and writes the top uncoveredDisplayLimit,
// folding the rest behind a count.
func writeRankedUncovered(b *strings.Builder, candidates []Candidate) {
	lines := buildDisplayLines(candidates)
	sortDisplayLines(lines)

	shown := lines
	remaining := 0
	if len(lines) > uncoveredDisplayLimit {
		remaining = len(lines) - uncoveredDisplayLimit
		shown = lines[:uncoveredDisplayLimit]
	}
	for _, l := range shown {
		b.WriteString(l.text)
		b.WriteString("\n")
	}
	if remaining > 0 {
		fmt.Fprintf(b, "... and %d more (--all)\n", remaining)
	}
}

// sortDisplayLines ranks by (weight DESC, sortSize DESC) — the same
// consequence-first rule sortCandidates applies to raw candidates, lifted
// to also cover a grouped line's total size.
func sortDisplayLines(lines []displayLine) {
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].weight != lines[j].weight {
			return lines[i].weight > lines[j].weight
		}
		return lines[i].sortSize > lines[j].sortSize
	})
}

// buildDisplayLines groups candidates by (Kind, Name); a group reaching
// groupMinCount collapses into one grouped displayLine, everything else
// stays one displayLine per candidate. Group order follows first
// occurrence in candidates (already weight/size sorted on entry), so ties
// after sortDisplayLines stay in a stable, predictable order.
func buildDisplayLines(candidates []Candidate) []displayLine {
	type groupKey struct {
		kind Kind
		name string
	}
	groups := map[groupKey][]Candidate{}
	var order []groupKey
	for _, c := range candidates {
		k := groupKey{c.Kind, c.Name}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], c)
	}

	lines := make([]displayLine, 0, len(order))
	for _, k := range order {
		group := groups[k]
		if len(group) >= groupMinCount {
			lines = append(lines, groupedDisplayLine(group))
			continue
		}
		for _, c := range group {
			var sb strings.Builder
			writeCandidateLine(&sb, c)
			lines = append(lines, displayLine{
				weight: c.Weight, sortSize: c.SizeBytes,
				text: strings.TrimRight(sb.String(), "\n"),
			})
		}
	}
	return lines
}

// groupedDisplayLine collapses group (all sharing Kind and Name) into one
// line: "<kind>  <name>  ×<count> (<total> total)  — <count> locations".
func groupedDisplayLine(group []Candidate) displayLine {
	var total int64
	for _, c := range group {
		total += c.SizeBytes
	}
	text := fmt.Sprintf("%s  %s  ×%d (%s total)  — %d locations",
		group[0].Kind, group[0].Name, len(group), HumanizeBytes(total), len(group))
	return displayLine{weight: group[0].Weight, sortSize: total, text: text}
}

// writeCandidateLine writes one "<kind>  <name>  <path>  <size>" line,
// appending " (covered by <id>)" and/or " (suppressed: <rule>)" and/or
// " [also: <alt paths>]" when the candidate carries them.
func writeCandidateLine(b *strings.Builder, c Candidate) {
	fmt.Fprintf(b, "%s  %s  %s  %d", c.Kind, c.Name, c.Path, c.SizeBytes)
	if c.CoveredBy != "" {
		fmt.Fprintf(b, " (covered by %s)", c.CoveredBy)
	}
	if c.SuppressedBy != "" {
		fmt.Fprintf(b, " (suppressed: %s)", c.SuppressedBy)
	}
	if len(c.AlternatePaths) > 0 {
		fmt.Fprintf(b, " [also: %s]", strings.Join(c.AlternatePaths, ", "))
	}
	b.WriteString("\n")
}

// HumanizeBytes renders n as a decimal (1000-based) size string with one
// decimal place — "534.0 MB", "5.7 GB" — used for a grouped line's total
// (RenderText) and reused by status's HTML coverage block for each
// individual uncovered candidate's size, so the two never format a byte
// count two different ways.
func HumanizeBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	v := float64(n)
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// RenderTrend renders a compact table — date, covered/total, and the delta
// in covered count against the row before it — over ALL of rows, then
// keeps only the newest limit lines (0 or negative means "all"). Deltas
// are computed before truncating, so the first displayed row's delta is
// still meaningful rather than always reading "—".
func RenderTrend(rows []HistoryRow, limit int) []byte {
	if len(rows) == 0 {
		return []byte("no scan history yet — run `restoregap discover`\n")
	}
	lines := make([]string, len(rows))
	for i, r := range rows {
		delta := "—"
		if i > 0 {
			d := r.Covered - rows[i-1].Covered
			switch {
			case d > 0:
				delta = fmt.Sprintf("+%d", d)
			case d < 0:
				delta = fmt.Sprintf("%d", d)
			default:
				delta = "0"
			}
		}
		lines[i] = fmt.Sprintf("%s  %d/%d  %s", r.ScannedAt.Format("2006-01-02"), r.Covered, r.Candidates, delta)
	}
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}
