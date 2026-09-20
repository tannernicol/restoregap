// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/hostid"
)

// Options configures a Collect run. Every field has a real-machine default
// applied when left zero, so callers only override what a test or a
// specific invocation needs — tests use this to inject a fake $HOME, a
// fake state dir, and a fixed clock instead of ever touching the real
// machine.
type Options struct {
	// Home is the directory the database/repo collectors walk. Defaults to
	// os.UserHomeDir().
	Home string
	// Context is the merged (or built-in default) context to diff
	// candidates against.
	Context contextspec.Context
	// Now is the evaluation time stamped onto the report and used for
	// FirstSeen/staleness. Defaults to time.Now().UTC().
	Now time.Time
	// HostName is the report's Host field. Defaults to hostid.Current().
	HostName string
	// System overrides the fixed system-floor candidate paths. Defaults to
	// defaultSystemPaths().
	System SystemPaths
	// StateDir overrides discover's snapshot directory. Defaults to
	// DefaultStateDir(). A previous scan is still read (read-only) from
	// here even when NoSave is set — only writing is skipped.
	StateDir string
	// NoSave skips rotating/writing latest.json, previous.json, and
	// history.jsonl. The new-since-last-scan diff still runs against
	// whatever snapshot already exists, unaffected by this flag.
	NoSave bool
	// Cwd is where Collect looks for a repo-local .restoregapignore
	// (resolveExcludes, exclude.go). Defaults to os.Getwd(). The
	// machine-wide discoverignore is always $XDG_CONFIG_HOME/restoregap/
	// discoverignore (or ~/.config/restoregap/discoverignore) regardless
	// of Cwd — see discoverIgnorePath.
	Cwd string
}

// Collect runs every collector, diffs the result against opts.Context
// (coverage) and the previous scan (first-seen/new), and — unless NoSave —
// persists the result as the new snapshot. It never fails because an
// external tool (docker, systemctl) or the recovery estate itself is
// absent; the only errors it returns are for resolving $HOME/cwd/the state
// directory or a failed snapshot write.
func Collect(opts Options) (*Report, error) {
	home, now, host, sp, cwd, err := resolveCollectDefaults(opts)
	if err != nil {
		return nil, err
	}

	candidates := dedupeByRealPath(collectAll(home, sp))
	candidates = append(candidates, collectAgents(home, cwd)...)
	covered, suppressedUncovered, err := annotateCandidates(candidates, opts.Context, cwd)
	if err != nil {
		return nil, err
	}
	sortCandidates(candidates)

	report := &Report{
		GeneratedAt: now,
		Host:        host,
		Candidates:  candidates,
		Counts: Counts{
			Candidates: len(candidates), Covered: covered, Uncovered: len(candidates) - covered,
			Suppressed: suppressedUncovered,
		},
	}

	if err := applyStateDir(opts, report, now); err != nil {
		return nil, err
	}
	return report, nil
}

// resolveCollectDefaults fills in every Options field Collect needs a
// real-machine default for, left as a single early return so Collect
// itself carries none of this branching.
func resolveCollectDefaults(opts Options) (home string, now time.Time, host string, sp SystemPaths, cwd string, err error) {
	home = opts.Home
	if home == "" {
		if home, err = os.UserHomeDir(); err != nil {
			return "", time.Time{}, "", SystemPaths{}, "", fmt.Errorf("discover: resolve home: %w", err)
		}
	}
	now = opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	host = opts.HostName
	if host == "" {
		host = hostid.Current().HostName
	}
	sp = opts.System
	if sp.isZero() {
		sp = defaultSystemPaths()
	}
	cwd = opts.Cwd
	if cwd == "" {
		if cwd, err = os.Getwd(); err != nil {
			return "", time.Time{}, "", SystemPaths{}, "", fmt.Errorf("discover: resolve cwd: %w", err)
		}
	}
	return home, now, host, sp, cwd, nil
}

// annotateCandidates computes Covered/CoveredBy (from ctx's declared
// drills/guards) and Suppressed/SuppressedBy (from cwd's resolved
// excludes) on every candidate IN PLACE, returning the covered count and
// the suppressed-but-uncovered count Counts needs.
func annotateCandidates(candidates []Candidate, ctx contextspec.Context, cwd string) (covered, suppressedUncovered int, err error) {
	index := newCoverageIndex(ctx)
	for i := range candidates {
		if candidates[i].Kind == KindAgent {
			if candidates[i].Covered {
				covered++
			}
			continue
		}
		ok, by := index.cover(candidates[i].Path)
		candidates[i].Covered = ok
		candidates[i].CoveredBy = by
		if ok {
			covered++
		}
	}

	excludes, err := resolveExcludes(cwd)
	if err != nil {
		return 0, 0, err
	}
	applySuppression(candidates, excludes)
	for _, c := range candidates {
		if c.Suppressed && !c.Covered {
			suppressedUncovered++
		}
	}
	return covered, suppressedUncovered, nil
}

// applyStateDir resolves the snapshot state directory, diffs report
// against the previous scan (FirstSeen/New), and — unless opts.NoSave —
// persists report as the new snapshot. A report with no resolvable state
// dir is left undiffed (every candidate's FirstSeen stays zero) rather
// than erroring: a state dir failure is not a reason to refuse the scan
// itself.
func applyStateDir(opts Options, report *Report, now time.Time) error {
	stateDir := opts.StateDir
	if stateDir == "" {
		if d, err := DefaultStateDir(); err == nil {
			stateDir = d
		}
	}
	if stateDir == "" {
		return nil
	}

	if previous, ok := loadReport(LatestPath(stateDir)); ok {
		report.PreviousGeneratedAt = previous.GeneratedAt
		report.New = applyPreviousScan(report.Candidates, previous.Candidates, now)
		report.Counts.New = len(report.New)
	} else {
		for i := range report.Candidates {
			report.Candidates[i].FirstSeen = now
		}
	}
	if opts.NoSave {
		return nil
	}
	return SaveSnapshot(stateDir, report)
}

// collectAll runs every collector and concatenates their results, in a
// fixed order so text output's default (unsorted-within-weight) ordering
// is stable run to run.
func collectAll(home string, sp SystemPaths) []Candidate {
	var out []Candidate
	out = append(out, collectContainers()...)
	out = append(out, collectDatabases(home)...)
	out = append(out, collectRepos(home)...)
	out = append(out, collectServices(home)...)
	out = append(out, collectSystem(sp)...)
	return out
}

// sortCandidates ranks by CONSEQUENCE, not alphabet: worst weight first,
// then largest size first (a 460KB cache must never outrank a 5.6GB
// database just because its kind sorts first alphabetically), then kind
// and name for a stable, readable tie-break. The ordering both
// RenderText's uncovered/covered sections and the persisted Report's own
// Candidates order rely on.
func sortCandidates(candidates []Candidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Weight != candidates[j].Weight {
			return candidates[i].Weight > candidates[j].Weight
		}
		if candidates[i].SizeBytes != candidates[j].SizeBytes {
			return candidates[i].SizeBytes > candidates[j].SizeBytes
		}
		if candidates[i].Kind != candidates[j].Kind {
			return candidates[i].Kind < candidates[j].Kind
		}
		return candidates[i].Name < candidates[j].Name
	})
}
