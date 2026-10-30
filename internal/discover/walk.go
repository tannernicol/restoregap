// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// skipDirNames are directory basenames the bounded walk never descends
// into: version-control internals, dependency trees, and cache/venv
// directories that are either huge, regeneratable, or (for .git) already
// handled by the repo collector itself.
var skipDirNames = map[string]bool{
	"node_modules": true,
	".git":         true,
	".cache":       true,
	".venv":        true,
}

// walkBounded walks root up to maxDepth levels deep (root itself is depth
// 0), calling fn for every file and directory visited within that depth,
// INCLUDING a directory named in skipDirNames itself (a collector may care
// that the directory exists, e.g. the repo collector keying off ".git") —
// only its contents are never visited. Unreadable entries are skipped
// rather than aborting the walk — this is a best-effort survey, not a
// gate. Symlinks are not followed (filepath.WalkDir's default), so a
// symlink cycle cannot turn a bounded-depth walk into an unbounded one.
func walkBounded(root string, maxDepth int, fn func(path string, d fs.DirEntry)) {
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		fn(path, d)
		if d.IsDir() && path != root && skipDirNames[d.Name()] {
			return filepath.SkipDir
		}
		return nil
	})
}
