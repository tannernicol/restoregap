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
	// drillForms[i] holds every spelling of drills[i]'s artifact and
	// recovery_source worth comparing: the lexical form as declared, plus
	// the symlink-resolved form when it differs (see pathForms).
	drillForms [][]string
}

// newCoverageIndex builds a coverageIndex from ctx.
func newCoverageIndex(ctx contextspec.Context) coverageIndex {
	forms := make([][]string, len(ctx.Drills))
	for i, d := range ctx.Drills {
		forms[i] = append(pathForms(d.Artifact), pathForms(d.RecoverySource)...)
	}
	return coverageIndex{drills: ctx.Drills, guards: ctx.Guards, drillForms: forms}
}

// pathForms returns the normalized lexical form of p and, when it differs,
// the symlink-resolved form. Coverage must match on both because dedupe
// canonicalises a candidate's Path (macOS keeps /tmp and /var under
// /private) while a drill or guard is written in whatever spelling the
// operator typed; comparing only one spelling would report a path the
// context plainly names as uncovered. This is the same lexical-plus-
// canonical matching the agent hook applies to guards (CHANGELOG 0.11.6).
// Resolution is best-effort: a path that does not exist (an s3:// URL, a
// restore target not yet created) just keeps its lexical form.
func pathForms(p string) []string {
	norm := normalizePath(p)
	if norm == "" {
		return nil
	}
	forms := []string{norm}
	if resolved := resolveSymlinkPath(norm); resolved != norm {
		forms = append(forms, resolved)
	}
	return forms
}

// coverCandidate reports whether c is covered, trying every spelling the
// candidate is known by: its (canonical) Path and each AlternatePath.
// dedupeByRealPath records the path as originally discovered in
// AlternatePaths precisely so it is not lost, which makes it the lexical
// spelling a guard glob or drill most likely used.
func (c coverageIndex) coverCandidate(cand Candidate) (bool, string) {
	if ok, by := c.cover(cand.Path); ok {
		return true, by
	}
	for _, alt := range cand.AlternatePaths {
		if ok, by := c.cover(alt); ok {
			return true, by
		}
	}
	return false, ""
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
	forms := pathForms(path)
	for i, d := range c.drills {
		if anyOverlap(forms, c.drillForms[i]) {
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

// anyOverlap reports whether any spelling in as overlaps any spelling in bs.
func anyOverlap(as, bs []string) bool {
	for _, a := range as {
		for _, b := range bs {
			if pathOverlap(a, b) {
				return true
			}
		}
	}
	return false
}
