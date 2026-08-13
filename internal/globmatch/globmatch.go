// Package globmatch implements a small, dependency-free glob matcher shared
// by contextspec guard matching and the rule engine. It supports two modes:
//
//   - Match: single-segment glob (`*`, `?`, `[...]`) via path.Match — used for
//     commands, packages, actors.
//   - MatchPath: doublestar-style path glob where `**` matches zero or more
//     whole path segments and each segment supports `*`/`?`/`[...]` via
//     path.Match — used for filesystem paths.
package globmatch

import (
	"os"
	"path"
	"strings"
)

// Match reports whether name matches a single-segment shell glob pattern.
// An invalid pattern never matches (mirrors path.Match's error contract).
func Match(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// MatchAny reports whether name matches any of the given patterns. A nil or
// empty pattern list matches nothing (callers treat "no patterns" as
// "matcher not in use", not "matches everything").
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if Match(p, name) {
			return true
		}
	}
	return false
}

// MatchPath reports whether name matches a doublestar-style path glob, where
// "**" matches zero or more whole path segments (including none). Both sides
// are home-normalized first: "~/x" in a declared pattern must match the
// absolute "/home/user/x" an intent may carry, and vice versa (the Python
// implementation expanded ~ the same way — a guard must not be bypassable by
// spelling the same file differently).
func MatchPath(pattern, name string) bool {
	return matchSegments(splitSegments(ExpandHome(pattern)), splitSegments(ExpandHome(name)))
}

// homeDir is resolved once; overridable in tests.
var homeDir, _ = os.UserHomeDir()

// ExpandHome rewrites a leading "~/" to the current user's home directory.
func ExpandHome(p string) string {
	if homeDir != "" && strings.HasPrefix(p, "~/") {
		return homeDir + p[1:]
	}
	return p
}

// MatchPathAny reports whether name matches any of the given path glob
// patterns.
func MatchPathAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if MatchPath(p, name) {
			return true
		}
	}
	return false
}

func splitSegments(s string) []string {
	if s == "" {
		return []string{}
	}
	var segs []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			segs = append(segs, s[start:i])
			start = i + 1
		}
	}
	segs = append(segs, s[start:])
	return segs
}

func matchSegments(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	if pat[0] == "**" {
		if matchSegments(pat[1:], name) {
			return true
		}
		if len(name) == 0 {
			return false
		}
		return matchSegments(pat, name[1:])
	}
	if len(name) == 0 {
		return false
	}
	if !Match(pat[0], name[0]) {
		return false
	}
	return matchSegments(pat[1:], name[1:])
}
