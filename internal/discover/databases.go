// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// databaseMinSize is the size floor below which a *.db/*.sqlite* file is
// noise (an empty schema, a test fixture) rather than a real recovery
// candidate.
const databaseMinSize = 64 * 1024 // 64 KiB

// databaseMaxDepth bounds the $HOME walk databases collect against.
const databaseMaxDepth = 5

// databaseExts are the file extensions collectDatabases treats as a
// database candidate.
var databaseExts = []string{".sqlite", ".sqlite3", ".db"}

// collectDatabases walks home (bounded depth databaseMaxDepth, skipping
// skipDirNames) for files matching databaseExts larger than
// databaseMinSize. It never fails: an unreadable home simply yields no
// candidates.
func collectDatabases(home string) []Candidate {
	var out []Candidate
	walkBounded(home, databaseMaxDepth, func(path string, d fs.DirEntry) {
		if d.IsDir() || !hasDatabaseExt(d.Name()) {
			return
		}
		info, err := d.Info()
		if err != nil || info.Size() <= databaseMinSize {
			return
		}
		out = append(out, Candidate{
			Kind: KindDatabase, Name: d.Name(), Path: path,
			SizeBytes: info.Size(), Weight: weightFor(KindDatabase),
		})
	})
	return out
}

// hasDatabaseExt reports whether name ends in one of databaseExts.
func hasDatabaseExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	for _, e := range databaseExts {
		if ext == e {
			return true
		}
	}
	return false
}
