// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

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

// IsAncestor reports whether intentPath is a proper ancestor directory of
// every concrete path guardPattern can match: guardPattern's longest literal
// segment prefix lies at or under intentPath. It exists for destructive
// actions (delete_file, move_file) where removing or relocating intentPath
// destroys anything a guard declared beneath it, even though the intent
// never names the guarded path directly — MatchPath alone only catches the
// case where the intent names the guarded path (or a glob covering it)
// exactly. Both sides are home-normalized and path-cleaned first, so
// "~/.ssh" and "/home/user/.ssh" compare equal and a trailing slash or "."
// segment does not break the match.
func IsAncestor(intentPath, guardPattern string) bool {
	pathSegs := cleanSegments(intentPath)
	litSegs, hasWildcard := literalPrefix(cleanSegments(guardPattern))
	if len(pathSegs) == 0 || len(pathSegs) > len(litSegs) {
		return false
	}
	for i, s := range pathSegs {
		if s != litSegs[i] {
			return false
		}
	}
	// A fully literal guard path is destroyed by an intent strictly ABOVE it
	// (deleting /a/b/c is not deleting the *directory* /a/b/c's children —
	// that is the exact-match case MatchPath already covers). A guard glob
	// (e.g. /a/b/*) is destroyed by an intent at OR above its literal prefix,
	// because the wildcard already reaches below that prefix.
	return len(pathSegs) < len(litSegs) || hasWildcard
}

// literalPrefix returns the leading segments of a path glob up to (not
// including) its first wildcard segment — "**", or any segment containing a
// shell glob metacharacter — and whether any wildcard segment was found. A
// pattern with no wildcard segments returns all of segs (the guard's literal
// path in full) and false.
func literalPrefix(segs []string) ([]string, bool) {
	for i, s := range segs {
		if s == "**" || strings.ContainsAny(s, "*?[") {
			return segs[:i], true
		}
	}
	return segs, false
}

// cleanSegments home-expands, path-cleans (dropping "." segments, "//", and
// a trailing slash), and splits p into path segments for ancestor
// comparison.
func cleanSegments(p string) []string {
	if p == "" {
		return nil
	}
	return splitSegments(path.Clean(ExpandHome(p)))
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
