// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxHistoryLines caps discover/history.jsonl at the newest N scans, kept
// on every write so the trend file never grows unbounded on a long-running
// host.
const maxHistoryLines = 500

// discoverStatusMaxAge is how old latest.json may be before `restoregap
// status` treats it as stale rather than showing its coverage line.
const discoverStatusMaxAge = 7 * 24 * time.Hour

// DefaultStateDir resolves discover's snapshot directory:
// $XDG_STATE_HOME/restoregap/discover, else
// ~/.local/state/restoregap/discover — the same default-path story the
// decision ledger already uses (internal/cli/discovery.go's
// defaultLedgerPath), so this codebase has exactly one story for "where do
// we keep durable local state" rather than two that can drift.
func DefaultStateDir() (string, error) {
	stateDir := os.Getenv("XDG_STATE_HOME")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("discover: resolve default state dir: %w", err)
		}
		stateDir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(stateDir, "restoregap", "discover"), nil
}

// LatestPath is stateDir's current snapshot.
func LatestPath(stateDir string) string { return filepath.Join(stateDir, "latest.json") }

// PreviousPath is stateDir's snapshot from the run before the current one.
func PreviousPath(stateDir string) string { return filepath.Join(stateDir, "previous.json") }

// HistoryPath is stateDir's append-only (capped) trend log.
func HistoryPath(stateDir string) string { return filepath.Join(stateDir, "history.jsonl") }

// candidateKey is the stable identity a candidate is diffed across scans
// by: kind and path (never name or size, which can change without the
// candidate itself being a different thing).
func candidateKey(c Candidate) string { return string(c.Kind) + ":" + c.Path }

// loadReport reads and parses a Report from path. ok is false for any
// reason the file cannot be used as a previous scan — missing, unreadable,
// or malformed — never an error a caller needs to handle specially: "no
// usable previous scan" and "no previous scan" are the same case to a
// diff.
func loadReport(path string) (Report, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // path is our own state-dir file
	if err != nil {
		return Report{}, false
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return Report{}, false
	}
	return r, true
}

// applyPreviousScan diffs candidates against previous's, in place: each
// candidate's FirstSeen is carried forward by candidateKey from previous
// when present, else set to now. It returns the sorted keys of every
// candidate NOT present in previous — empty when previous itself is empty
// (ok=false upstream), which is what keeps a host's very first scan from
// reporting every candidate as "new".
func applyPreviousScan(candidates []Candidate, previous []Candidate, now time.Time) []string {
	prevSeen := make(map[string]time.Time, len(previous))
	for _, pc := range previous {
		prevSeen[candidateKey(pc)] = pc.FirstSeen
	}
	var newKeys []string
	for i := range candidates {
		key := candidateKey(candidates[i])
		if seen, ok := prevSeen[key]; ok {
			candidates[i].FirstSeen = seen
			continue
		}
		candidates[i].FirstSeen = now
		if len(previous) > 0 {
			newKeys = append(newKeys, key)
		}
	}
	sort.Strings(newKeys)
	return newKeys
}

// SaveSnapshot persists report as stateDir's new latest.json: whatever was
// there is rotated to previous.json first (best-effort — a missing latest
// is simply the first-ever scan, not an error), then one row is appended to
// history.jsonl. Called only when the caller has not asked for a
// --no-save/read-only run.
func SaveSnapshot(stateDir string, report *Report) error {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("discover: create state dir: %w", err)
	}
	latest := LatestPath(stateDir)
	if data, err := os.ReadFile(latest); err == nil { //nolint:gosec // stateDir is our own resolved path
		if err := os.WriteFile(PreviousPath(stateDir), data, 0o644); err != nil {
			return fmt.Errorf("discover: rotate previous snapshot: %w", err)
		}
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("discover: encode snapshot: %w", err)
	}
	if err := os.WriteFile(latest, encoded, 0o644); err != nil {
		return fmt.Errorf("discover: write latest snapshot: %w", err)
	}
	return appendHistory(stateDir, report)
}

// HistoryRow is one line of discover/history.jsonl: the sticky numbers a
// trend is made of.
type HistoryRow struct {
	ScannedAt  time.Time `json:"scanned_at"`
	Candidates int       `json:"candidates"`
	Covered    int       `json:"covered"`
	Uncovered  int       `json:"uncovered"`
	New        int       `json:"new"`
}

// appendHistory appends one HistoryRow for report to stateDir's
// history.jsonl, then keeps only the newest maxHistoryLines lines.
func appendHistory(stateDir string, report *Report) error {
	path := HistoryPath(stateDir)
	lines := readHistoryLines(path)
	row := HistoryRow{
		ScannedAt: report.GeneratedAt, Candidates: report.Counts.Candidates,
		Covered: report.Counts.Covered, Uncovered: report.Counts.Uncovered, New: report.Counts.New,
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("discover: encode history row: %w", err)
	}
	lines = append(lines, string(encoded))
	if len(lines) > maxHistoryLines {
		lines = lines[len(lines)-maxHistoryLines:]
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("discover: write history: %w", err)
	}
	return nil
}

// readHistoryLines reads path's non-empty lines, best-effort: a missing or
// unreadable file is treated as an empty history, never an error — the
// same "no previous scan" tolerance loadReport applies to latest.json.
func readHistoryLines(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // path is our own state-dir file
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// ReadHistory reads every row in stateDir's history.jsonl (already capped
// at maxHistoryLines by appendHistory), oldest first. Malformed lines are
// skipped rather than aborting the read. Callers that only want to DISPLAY
// the newest few rows should still pass the full slice to RenderTrend,
// which needs the row before the display window to compute the first
// shown row's delta.
func ReadHistory(stateDir string) ([]HistoryRow, error) {
	lines := readHistoryLines(HistoryPath(stateDir))
	var rows []HistoryRow
	for _, line := range lines {
		var row HistoryRow
		if err := json.Unmarshal([]byte(line), &row); err == nil {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// StatusSummary is the minimal snapshot data `restoregap status` reads for
// its one coverage line — deliberately not the full Report, so status
// never needs to reason about individual candidates.
type StatusSummary struct {
	GeneratedAt time.Time
	Candidates  int
	Covered     int
	New         int
	// PreviousGeneratedAt is the scan New was computed against — the date
	// a "N new since <date>" line refers to. Zero when the latest scan had
	// no previous scan to diff against.
	PreviousGeneratedAt time.Time
}

// SnapshotState is the on-disk snapshot's read outcome, as of the caller's
// evaluation time: SnapshotFresh (a usable, recent-enough report),
// SnapshotStale (a real report exists but is older than
// discoverStatusMaxAge), or SnapshotAbsent (missing, unreadable, or
// malformed — indistinguishable to a caller, since all three mean "nothing
// usable here"). status's HTML coverage block renders a distinct shape for
// each; a stale number is never presented as current.
type SnapshotState string

// The SnapshotState values.
const (
	SnapshotFresh  SnapshotState = "fresh"
	SnapshotStale  SnapshotState = "stale"
	SnapshotAbsent SnapshotState = "absent"
)

// ReadLatestReport reads stateDir's latest.json and reports its staleness
// state as of now alongside the parsed Report. The Report is only ever
// meaningfully populated when state is SnapshotFresh or SnapshotStale (a
// stale report still names its own GeneratedAt, so a caller can say "stale
// as of <date>"); SnapshotAbsent always returns a zero Report.
func ReadLatestReport(stateDir string, now time.Time) (Report, SnapshotState) {
	report, ok := loadReport(LatestPath(stateDir))
	if !ok {
		return Report{}, SnapshotAbsent
	}
	if now.Sub(report.GeneratedAt) > discoverStatusMaxAge {
		return report, SnapshotStale
	}
	return report, SnapshotFresh
}

// ReadStatusSummary reads stateDir's latest.json and returns its summary.
// ok is false when the file is missing, unreadable, malformed, or older
// than discoverStatusMaxAge as of now — status renders its "not scanned"
// line in every one of those cases alike, never a stale number presented
// as current.
func ReadStatusSummary(stateDir string, now time.Time) (StatusSummary, bool) {
	report, state := ReadLatestReport(stateDir, now)
	if state != SnapshotFresh {
		return StatusSummary{}, false
	}
	return StatusSummary{
		GeneratedAt: report.GeneratedAt, Candidates: report.Counts.Candidates,
		Covered: report.Counts.Covered, New: report.Counts.New,
		PreviousGeneratedAt: report.PreviousGeneratedAt,
	}, true
}
