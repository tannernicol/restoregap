// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tannernicol/restoregap/internal/globmatch"
)

// defaultExcludeGlobs are path globs (internal/globmatch's doublestar
// syntax) suppressed from discover's DEFAULT view: regenerable caches,
// retired copies, and browser-profile churn that would otherwise crowd out
// the recovery candidates actually worth an owner's attention. A real
// estate audit found these dominating the uncovered list — Firefox profile
// SQLite files, Zoom's encrypted message cache, .archive/ copies of
// retired projects — while genuine finds (a 5.6GB access log, a bounty-rag
// database) were buried among them. Suppression is a RENDERING decision,
// never a data one: a suppressed candidate is still fully counted and
// still available (with SuppressedBy set) via --all — see docs/DISCOVER.md.
var defaultExcludeGlobs = []string{
	// Browser profiles: cookies, favicons, form history, cert stores —
	// regenerates from a fresh profile, never something to recover
	// individually.
	"**/.mozilla/**",
	"**/.config/*/Default/**",
	"**/.config/*/Profile */**",
	"**/*chrome*/**",
	"**/*chromium*/**",
	"**/*firefox*/**",
	// Retired copies — already superseded by definition; if it mattered it
	// would not have been archived.
	"**/.archive/**",
	// Regenerable caches, build artifacts, and version-control internals.
	"**/.cache/**",
	"**/.local/share/Trash/**",
	"**/node_modules/**",
	"**/.venv/**",
	"**/__pycache__/**",
	"**/.git/**",
	// Other common OS/tool caches.
	"**/.zoom/data/**",
	"**/Cache/**",
	"**/CacheStorage/**",
	"**/GPUCache/**",
	"**/Code Cache/**",
}

// excludePattern is one suppression glob plus where it came from, so a
// suppressed candidate's SuppressedBy can name the exact rule an owner
// would edit to un-suppress it.
type excludePattern struct {
	Pattern string
	Source  string // "default" | "ignore:.restoregapignore" | "ignore:discoverignore"
}

// defaultExcludePatterns wraps defaultExcludeGlobs as excludePatterns
// sourced "default".
func defaultExcludePatterns() []excludePattern {
	out := make([]excludePattern, len(defaultExcludeGlobs))
	for i, p := range defaultExcludeGlobs {
		out[i] = excludePattern{Pattern: p, Source: "default"}
	}
	return out
}

// discoverIgnorePath resolves the machine-wide suppression list:
// $XDG_CONFIG_HOME/restoregap/discoverignore, else
// ~/.config/restoregap/discoverignore.
func discoverIgnorePath() (string, error) {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("discover: resolve discoverignore path: %w", err)
		}
		configDir = filepath.Join(home, ".config")
	}
	return filepath.Join(configDir, "restoregap", "discoverignore"), nil
}

// readIgnoreFile parses a gitignore-style pattern file: one glob per line,
// blank lines and #-comments skipped. A missing file is not an error — the
// same contract `restoregap check`'s own .restoregapignore reader uses
// (internal/cli/check.go), so both behave identically even though this
// package cannot import cli (cli already imports discover).
func readIgnoreFile(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-resolved config/repo path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("discover: reading %s: %w", path, err)
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, nil
}

// resolveExcludes builds the full suppression list: the built-in defaults,
// then cwd's repo-local .restoregapignore, then the machine-wide
// discoverignore — the same one-glob-per-line format across all three.
func resolveExcludes(cwd string) ([]excludePattern, error) {
	excludes := defaultExcludePatterns()

	repoPatterns, err := readIgnoreFile(filepath.Join(cwd, ".restoregapignore"))
	if err != nil {
		return nil, err
	}
	excludes = appendExcludeSource(excludes, repoPatterns, "ignore:.restoregapignore")

	ignorePath, err := discoverIgnorePath()
	if err != nil {
		return nil, err
	}
	machinePatterns, err := readIgnoreFile(ignorePath)
	if err != nil {
		return nil, err
	}
	excludes = appendExcludeSource(excludes, machinePatterns, "ignore:discoverignore")

	return excludes, nil
}

// appendExcludeSource appends patterns to excludes, each tagged source.
func appendExcludeSource(excludes []excludePattern, patterns []string, source string) []excludePattern {
	for _, p := range patterns {
		excludes = append(excludes, excludePattern{Pattern: p, Source: source})
	}
	return excludes
}

// applySuppression flags every candidate matching any of excludes — first
// match wins, so SuppressedBy names whichever rule matched first (defaults
// are checked before ignore files) even if more than one would have
// matched.
func applySuppression(candidates []Candidate, excludes []excludePattern) {
	for i := range candidates {
		for _, ex := range excludes {
			if globmatch.MatchPath(ex.Pattern, candidates[i].Path) {
				candidates[i].Suppressed = true
				candidates[i].SuppressedBy = ex.Source + ":" + ex.Pattern
				break
			}
		}
	}
}
