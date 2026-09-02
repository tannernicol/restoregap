// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"path/filepath"
	"strings"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/globmatch"
)

// coverageIndex is a context's drills and guards, held ready to diff many
// candidates against without re-walking the slice fields each time.
type coverageIndex struct {
	drills []contextspec.Drill
	guards []contextspec.Guard
}

// newCoverageIndex builds a coverageIndex from ctx.
func newCoverageIndex(ctx contextspec.Context) coverageIndex {
	return coverageIndex{drills: ctx.Drills, guards: ctx.Guards}
}

// cover reports whether path is covered by a declared drill's artifact or
// recovery_source, or by a guard's matched path, and names what covered it
// ("drill:<proof-id>" or "guard:<guard-id>"). Drill paths are compared by
// path containment (equal, or one an ancestor directory of the other) —
// paths, not raw strings, so "/home/user/foo" never falsely covers
// "/home/user/foobar". Guard paths reuse globmatch.MatchPathAny, the same
// glob-matching internal/rules uses to decide whether a guard matches a real
// path, so "a guard's matched path" means exactly what it already means
// everywhere else in this codebase.
func (c coverageIndex) cover(path string) (bool, string) {
	norm := normalizePath(path)
	for _, d := range c.drills {
		if pathOverlap(norm, normalizePath(d.Artifact)) || pathOverlap(norm, normalizePath(d.RecoverySource)) {
			return true, "drill:" + d.Proof
		}
	}
	for _, g := range c.guards {
		if globmatch.MatchPathAny(g.Match.Paths, path) {
			return true, "guard:" + g.ID
		}
	}
	return false, ""
}

// normalizePath home-expands and cleans p, so "~/x" and "/home/user/x"
// compare equal — the same normalization globmatch applies to guard paths.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(globmatch.ExpandHome(p))
}

// pathOverlap reports whether two normalized, non-empty paths name the same
// recovery target: equal, or one a proper ancestor directory of the other
// (a drill's artifact naming a directory that contains the candidate file,
// or a candidate directory that contains a drill's declared artifact).
func pathOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}
