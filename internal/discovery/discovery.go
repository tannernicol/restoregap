// Package discovery implements the shared $RESTOREGAP_CONTEXT /
// restoregap.local.yml / restoregap.yml / user-config-directory lookup order
// used by every entry point that wants a zero-config context fallback: the
// CLI (internal/cli) and the MCP server (internal/mcpserver). It is a plain,
// cobra-free package on purpose — internal/cli already imports internal/mcpserver (to
// wire `restoregap mcp serve`), so mcpserver cannot import internal/cli
// without a cycle; both instead import this one.
package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// ContextPaths returns the discovered context file path(s), or nil when
// nothing is discoverable. $RESTOREGAP_CONTEXT may hold a colon-separated
// list of paths — every one of them is returned, in declared order, so a
// caller that aggregates multiple contexts (status, preflight) sees the
// whole list. A caller that wants exactly one path uses ContextPaths()[0].
//
// When the env var is unset, the tiers are: ./restoregap.local.yml if
// present, else ./restoregap.yml, else every *.yml in the ordered policy
// directories (PolicyDirs — org dir(s) first, host config dir last),
// sorted within each directory. One context file per drill is the real
// deployment shape, so the config directory routinely holds several files
// and ALL of them are returned — repeatable-context callers (status,
// preflight) merge them, single-context callers take the first. Callers
// that fall further back to a built-in default policy treat a nil result
// as "nothing discoverable".
//
// A single-host install with no org policy directory sees exactly the same
// paths this returned before policy layering existed: PolicyDirs' default
// host tier IS the historical $XDG_CONFIG_HOME/restoregap, and an absent
// /etc/restoregap contributes no files.
func ContextPaths() []string {
	if v := os.Getenv("RESTOREGAP_CONTEXT"); v != "" {
		var out []string
		for _, p := range strings.Split(v, ":") {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	for _, candidate := range []string{"restoregap.local.yml", "restoregap.yml"} {
		if isRegularFile(candidate) {
			return []string{candidate}
		}
	}
	return flattenGroups(LayeredConfigFiles())
}

// PolicyDirs returns the ordered policy directories layered guard merge
// reads from (docs/SCHEMA.md §Layered policy): $RESTOREGAP_POLICY_DIRS, a
// colon-separated list, when set; otherwise "/etc/restoregap" (org — a
// company's fleet-wide floor) followed by the host's own config directory
// ($XDG_CONFIG_HOME/restoregap, or ~/.config/restoregap — unchanged from
// the pre-layering single-tier discovery). Earlier entries are "org", later
// are "host": internal/policy's tighten-only merge lets a later entry add
// guards or tighten an existing one, never loosen or remove it.
func PolicyDirs() []string {
	if v := os.Getenv("RESTOREGAP_POLICY_DIRS"); v != "" {
		var out []string
		for _, p := range strings.Split(v, ":") {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	dirs := []string{"/etc/restoregap"}
	if host := hostConfigDir(); host != "" {
		dirs = append(dirs, host)
	}
	return dirs
}

// hostConfigDir is the per-host config directory PolicyDirs' default host
// tier uses: $XDG_CONFIG_HOME/restoregap, or ~/.config/restoregap. Empty
// when neither can be resolved (no HOME, no XDG override).
func hostConfigDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "restoregap")
}

// LayeredConfigFiles returns, for each of PolicyDirs' directories in order,
// its discovered *.yml context files (same exclusion/loadability rules as
// the pre-layering single-directory discovery). A directory that does not
// exist (the common case for /etc/restoregap on a single-host install)
// contributes an empty (not nil-erroring) slice — the org tier is optional,
// not required. Grouped by directory so internal/policy's tighten-only
// merge knows which files are "org" versus "host".
func LayeredConfigFiles() [][]string {
	dirs := PolicyDirs()
	groups := make([][]string, len(dirs))
	for i, dir := range dirs {
		groups[i] = filesInDir(dir)
	}
	return groups
}

// flattenGroups concatenates LayeredConfigFiles' per-directory groups into
// the single ordered list ContextPaths' non-layering callers expect.
func flattenGroups(groups [][]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// CandidatePaths is ContextPaths without the loadability check: every file
// normal discovery would consider, whether or not contextspec.Load can read
// it yet. `restoregap migrate` needs exactly this — a v1 document, or one
// declaring a version newer than this binary understands, is precisely
// what ContextPaths silently excludes (with a stderr warning) and what
// migrate exists to fix. Explicit --context or $RESTOREGAP_CONTEXT paths
// are returned exactly as given, same as ContextPaths — migrate never
// second-guesses a path the caller named directly.
func CandidatePaths() []string {
	if v := os.Getenv("RESTOREGAP_CONTEXT"); v != "" {
		var out []string
		for _, p := range strings.Split(v, ":") {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	for _, candidate := range []string{"restoregap.local.yml", "restoregap.yml"} {
		if isRegularFile(candidate) {
			return []string{candidate}
		}
	}
	var out []string
	for _, dir := range PolicyDirs() {
		out = append(out, candidateFilesInDir(dir)...)
	}
	return out
}

// candidateFilesInDir is filesInDir minus the "does contextspec.Load
// succeed" gate — the exclusion-name filter (backups/archives/sealed
// snapshots) still applies, since those are never context documents at any
// version.
func candidateFilesInDir(dir string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	var out []string
	for _, path := range matches {
		if isExcludedConfigName(filepath.Base(path)) {
			continue
		}
		out = append(out, path)
	}
	return out
}

// configExcludedNames are base-name patterns for files that live in a
// policy/config directory but are not contexts: editor/rotation backups
// (*.bak*), archived generations (*.archive*), and sealed snapshots
// (*-sealed*). They are skipped silently — they are expected to be there,
// unlike a *.yml that fails to load.
var configExcludedNames = []string{"*.bak*", "*.archive*", "*-sealed*"}

// filesInDir is one policy directory's discovery tier: every context
// document directly inside it, sorted so the result is deterministic
// regardless of glob order. A *.yml that fails to load as a context
// document is skipped with one stderr warning rather than aborting — one
// stray hand-edited file must not make every command on the machine blind
// to the other fourteen. A directory that does not exist yields nil, same
// as an empty one — the org tier is optional on a single-host install.
func filesInDir(dir string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	var out []string
	for _, path := range matches {
		if isExcludedConfigName(filepath.Base(path)) {
			continue
		}
		if _, err := contextspec.Load(path); err != nil {
			warnf("restoregap: skipping %s: not a loadable context file: %v\n", path, err)
			continue
		}
		out = append(out, path)
	}
	return out
}

func isExcludedConfigName(name string) bool {
	for _, pattern := range configExcludedNames {
		if ok, err := filepath.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// warnf is discovery's warning sink, a package var so tests can capture
// skip warnings instead of scraping the real stderr.
var warnf = func(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
