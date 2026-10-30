// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// dedupeByRealPath merges candidates that are the SAME underlying file
// reached via different apparent paths — a symlink alias, or a bind mount
// exposing the same host directory at two locations (the real audit's
// example: the same auth.db reachable as both ~/ntfy/data/auth.db and
// ~/infra-config/compose/ntfy/data/auth.db). A bind mount involves no
// symlink at all — both paths are perfectly ordinary directories from the
// filesystem's point of view — so EvalSymlinks alone cannot tell them
// apart; only the underlying (device, inode) pair can (see fileIdentity).
// Candidates sharing Kind and identity are merged into one; every other
// apparent path is kept in AlternatePaths rather than silently dropped.
func dedupeByRealPath(candidates []Candidate) []Candidate {
	type key struct {
		kind Kind
		id   string
	}
	index := make(map[key]int, len(candidates))
	out := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		original := c.Path
		id := fileIdentity(c.Path)
		k := key{c.Kind, id}
		if pos, ok := index[k]; ok {
			mergeAlternatePath(&out[pos], original)
			for _, alt := range c.AlternatePaths {
				mergeAlternatePath(&out[pos], alt)
			}
			continue
		}
		// A true symlink alias (unlike a bind mount) is worth normalizing
		// away even for the FIRST candidate seen, so the primary Path is
		// never a symlink another candidate could equally have used.
		c.Path = resolveSymlinkPath(c.Path)
		if nameFollowsPath(c.Kind) {
			// Only database/repo candidates derive Name from their path's
			// basename (databases.go/repos.go); container-volume's Name is
			// its container's name, service-state's is its unit name, and
			// the three fixed system kinds carry a deliberately chosen
			// descriptive name (system.go) — none of those should be
			// clobbered by the canonical path's basename.
			c.Name = filepath.Base(c.Path)
		}
		index[k] = len(out)
		out = append(out, c)
		// The symlink normalization above may itself have changed Path —
		// record the original apparent path now, or it is lost.
		mergeAlternatePath(&out[len(out)-1], original)
	}
	return out
}

// nameFollowsPath reports whether kind's Candidate.Name is derived from
// its Path's basename by the collector that produced it — only true for
// database and repo, see collectDatabases/collectRepos.
func nameFollowsPath(kind Kind) bool {
	return kind == KindDatabase || kind == KindRepo
}

// fileIdentity returns a stable identity for path: "dev:ino" when the
// path can be stat'd — the only thing that actually catches a bind-mount
// alias, since two paths bind-mounted from the same underlying directory
// share a device+inode pair even though neither one is a symlink — falling
// back to the EvalSymlinks-resolved path (still catches a true symlink
// alias) when stat fails, and finally the raw path when even that fails.
func fileIdentity(path string) string {
	if path == "" {
		return ""
	}
	if info, err := os.Stat(path); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			return fmt.Sprintf("dev%d:ino%d", st.Dev, st.Ino)
		}
	}
	return resolveSymlinkPath(path)
}

// resolveSymlinkPath resolves symlinks in path, falling back to path
// itself (unresolved) when the lookup fails — a candidate that no longer
// exists, or is unreadable, is still a candidate; this pass just cannot
// prove it duplicates anything else.
func resolveSymlinkPath(path string) string {
	if path == "" {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// mergeAlternatePath records p on c as an alternate path, unless it is
// empty, already c's primary Path, or already recorded.
func mergeAlternatePath(c *Candidate, p string) {
	if p == "" || p == c.Path {
		return
	}
	for _, existing := range c.AlternatePaths {
		if existing == p {
			return
		}
	}
	c.AlternatePaths = append(c.AlternatePaths, p)
}
