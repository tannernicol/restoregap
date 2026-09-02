// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package policy owns the portability surfaces built on top of context
// files: the policy revision digest (which exact text was in force when a
// decision was made) and the org→host layered-policy merge (tighten-only).
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"github.com/tannernicol/restoregap/internal/hostid"
	"github.com/tannernicol/restoregap/internal/ledger"
)

// File is one context file hashed into a revision: where it lives and the
// sha256 of its bytes.
type File struct {
	Path   string
	SHA256 string
}

// Revision computes the policy revision over every context file in force:
// sha256 of the sorted (path, sha256) list, rendered as 16 hex chars. The
// sort makes the digest order-independent — the same context set passed in
// any order is the same policy — while file CONTENT still matters, so any
// edit to any guard flips the revision.
func Revision(paths []string) (string, []File, error) {
	files := make([]File, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return "", nil, fmt.Errorf("policy: cannot hash %s: %w", p, err)
		}
		sum := sha256.Sum256(raw)
		files = append(files, File{Path: p, SHA256: hex.EncodeToString(sum[:])})
	}
	return digestFiles(files), files, nil
}

// digestFiles renders the sorted-list digest both Revision and its callers
// share — sorted by path so declaration order cannot change the answer.
func digestFiles(files []File) string {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, f := range sorted {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", f.Path, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Record builds the ledger-stampable form of a revision over paths,
// memoizing the file hashes so a caller that stamps many entries computes
// each file's digest once.
func Record(paths []string) (*ledger.PolicyRecord, error) {
	rev, files, err := Revision(paths)
	if err != nil {
		return nil, err
	}
	rec := &ledger.PolicyRecord{Revision: rev, Files: make([]ledger.PolicyFileRecord, 0, len(files))}
	for _, f := range files {
		rec.Files = append(rec.Files, ledger.PolicyFileRecord{Path: f.Path, SHA256: f.SHA256})
	}
	return rec, nil
}

// StampOptions builds the standard ledger append options for the entry kinds
// that record which world they were decided in (decision/drill/accept):
// current host identity, current epoch, and the policy revision over the
// context files in force. A policy that cannot be hashed (unreadable file)
// still gets the host/epoch stamp — the entry names its machine even when it
// cannot name its policy text.
func StampOptions(paths []string) []ledger.AppendOption {
	id := hostid.Current()
	rec, err := Record(paths)
	if err != nil {
		rec = nil
	}
	return ledger.Stamp(&ledger.HostRecord{Name: id.HostName, ID: id.HostID}, id.Epoch, rec)
}
