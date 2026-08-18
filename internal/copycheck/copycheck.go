// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package copycheck compares a live location against its recovery copy and
// reports what exists in exactly one place.
//
// Backups rarely fail loudly. They go quietly out of date while the nightly job
// keeps reporting success, and the gap only surfaces when someone needs the
// copy — which is the worst possible moment to learn it is short three entries.
//
// Entries are compared by name AND by content fingerprint. Names alone are not
// enough and the difference is not academic: a copy can hold every entry a live
// store has, under identical names, while two of them are weeks-stale API
// tokens. Recovering from it would restore dead credentials, and a name-only
// check calls that "faithful".
//
// Fingerprints are SHA-256 over the bytes on disk, never plaintext. For a
// secret store those bytes are already ciphertext, so this stays safe to point
// at a password store: it can tell you an entry CHANGED without being able to
// tell you, or anyone reading its output, what the entry says.
package copycheck

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tannernicol/restoregap/internal/globmatch"
)

// Kind identifies which comparator was used, so the report can say what it
// thought it was looking at rather than silently guessing.
type Kind string

// The Kind values, one per comparator.
const (
	KindSecretStore Kind = "secret-store"
	KindTree        Kind = "tree"
)

// Result is the outcome of comparing one pair.
type Result struct {
	Kind          Kind
	LiveCount     int
	RecoveryCount int
	OnlyLive      []string
	OnlyRecovery  []string
	// Differing entries exist on both sides under the same name but do not
	// match byte for byte. Which side is WRONG is a separate question from
	// whether they differ, and the fingerprint alone cannot answer it.
	Differing []string
	// ExcludedCount is how many distinct entries (by name, unioned across
	// both sides) were dropped before comparison because they matched an
	// exclude pattern. They are never counted in LiveCount/RecoveryCount or
	// reported as missing, stale, or only-in-recovery.
	ExcludedCount int
	// LiveOlder is the subset of Differing where the live entry's mtime is
	// older than the recovery copy's — the signature of the live side having
	// been REVERTED rather than the backup having fallen behind.
	//
	// This distinction is load-bearing, not cosmetic. Until 2026-08-12 every
	// difference was reported as "the recovery copy is out of date", which is
	// an assertion the tool had no evidence for. In the incident that exposed
	// it, a sync job rewrote the live tree with a months-old copy: the live
	// side was the corrupt one and the recovery copy was the only good data
	// left. Telling that user their backup was stale invites them to refresh
	// it — destroying the last good copy. A recovery tool must never emit
	// advice whose obvious remedy is data loss.
	LiveOlder []string
}

// Faithful reports whether the recovery copy can stand in for the live one.
// Present-but-stale counts as unfaithful: an entry you cannot use is not
// meaningfully different from one you do not have.
func (r Result) Faithful() bool {
	return len(r.OnlyLive) == 0 && len(r.OnlyRecovery) == 0 && len(r.Differing) == 0
}

// Detect picks a comparator from the shape of the live location. A pass-style
// secret store announces itself with .gpg-id; anything else is compared as a
// plain tree.
func Detect(live string) Kind {
	if _, err := os.Stat(filepath.Join(live, ".gpg-id")); err == nil {
		return KindSecretStore
	}
	return KindTree
}

// fingerprint hashes a file's bytes. For a secret store these are ciphertext,
// so this never handles plaintext.
func fingerprint(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// entries maps each comparable entry name under root to its content fingerprint.
func entries(root string, kind Kind) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Version-control and metadata dirs are not recoverable content.
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if kind == KindSecretStore && !strings.HasSuffix(d.Name(), ".gpg") {
			return nil
		}
		// The exclude-pattern file itself is check's own configuration, not
		// recoverable content — it would otherwise report as permanently
		// missing from every recovery copy that (correctly) doesn't have one.
		if d.Name() == ".restoregapignore" {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fp, ferr := fingerprint(path)
		if ferr != nil {
			return ferr
		}
		out[rel] = fp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// applyExcludes drops every entry matching any of excludes from BOTH maps
// (by name, unioned across the two sides) and returns how many distinct
// names were dropped.
func applyExcludes(liveEntries, recEntries map[string]string, excludes []string) int {
	excluded := map[string]bool{}
	for name := range liveEntries {
		if globmatch.MatchPathAny(excludes, name) {
			excluded[name] = true
		}
	}
	for name := range recEntries {
		if globmatch.MatchPathAny(excludes, name) {
			excluded[name] = true
		}
	}
	for name := range excluded {
		delete(liveEntries, name)
		delete(recEntries, name)
	}
	return len(excluded)
}

// Compare runs the comparison. A resolved symlinked root is used so a kit
// reached through a link is scanned rather than silently skipped.
//
// excludes are path globs (internal/globmatch's doublestar syntax) matched
// against each entry's relative path. A match on either side drops that
// entry from BOTH sides before anything else runs, so it never counts
// toward LiveCount/RecoveryCount and never appears as missing, stale, or
// only-in-recovery.
func Compare(live, recovery string, kind Kind, excludes []string) (Result, error) {
	res := Result{Kind: kind}

	for _, dir := range []string{live, recovery} {
		info, err := os.Stat(dir)
		if err != nil {
			return res, fmt.Errorf("cannot read %s: %w", dir, err)
		}
		if !info.IsDir() {
			return res, fmt.Errorf("%s is not a directory", dir)
		}
	}

	liveEntries, err := entries(live, kind)
	if err != nil {
		return res, fmt.Errorf("scanning %s: %w", live, err)
	}
	recEntries, err := entries(recovery, kind)
	if err != nil {
		return res, fmt.Errorf("scanning %s: %w", recovery, err)
	}

	res.ExcludedCount = applyExcludes(liveEntries, recEntries, excludes)

	res.LiveCount = len(liveEntries)
	res.RecoveryCount = len(recEntries)

	for name, liveFP := range liveEntries {
		recFP, ok := recEntries[name]
		switch {
		case !ok:
			res.OnlyLive = append(res.OnlyLive, name)
		case recFP != liveFP:
			res.Differing = append(res.Differing, name)
			if liveOlderThanRecovery(live, recovery, name, kind) {
				res.LiveOlder = append(res.LiveOlder, name)
			}
		}
	}
	for name := range recEntries {
		if _, ok := liveEntries[name]; !ok {
			res.OnlyRecovery = append(res.OnlyRecovery, name)
		}
	}
	sort.Strings(res.OnlyLive)
	sort.Strings(res.OnlyRecovery)
	sort.Strings(res.Differing)
	sort.Strings(res.LiveOlder)
	return res, nil
}

// liveOlderThanRecovery reports whether the live entry is measurably older than
// its recovery counterpart. Mtime is weak evidence — it is trivially forged and
// often not preserved — so this is used only to ADD a warning, never to suppress
// one: an unreadable or equal mtime leaves the entry classified exactly as it
// was before. Reads timestamps only, never content.
func liveOlderThanRecovery(live, recovery, name string, kind Kind) bool {
	if kind != KindTree {
		return false // only a tree maps entry names onto plain files
	}
	liveInfo, err := os.Stat(filepath.Join(live, name))
	if err != nil {
		return false
	}
	recInfo, err := os.Stat(filepath.Join(recovery, name))
	if err != nil {
		return false
	}
	return liveInfo.ModTime().Before(recInfo.ModTime())
}

// Text renders the human report. The one-line summary leads because that is
// what ends up quoted in an alert, and a stale entry is named distinctly from a
// missing one — they need different fixes and carry different urgency.
func (r Result) Text() string {
	var b strings.Builder
	if r.Faithful() {
		fmt.Fprintf(&b, "%s: %d live / %d recovery — recovery copy is faithful\n",
			r.Kind, r.LiveCount, r.RecoveryCount)
		return b.String()
	}

	var parts []string
	if n := len(r.OnlyLive); n > 0 {
		parts = append(parts, fmt.Sprintf("%d MISSING FROM RECOVERY", n))
	}
	if n := len(r.Differing); n > 0 {
		// Only claim the recovery copy is the stale side when nothing suggests
		// otherwise; a live-older entry means the live tree is the suspect one.
		if len(r.LiveOlder) > 0 {
			parts = append(parts, fmt.Sprintf("%d DIFFERING (%d with LIVE OLDER)", n, len(r.LiveOlder)))
		} else {
			parts = append(parts, fmt.Sprintf("%d STALE IN RECOVERY", n))
		}
	}
	if n := len(r.OnlyRecovery); n > 0 {
		parts = append(parts, fmt.Sprintf("%d only in recovery", n))
	}
	fmt.Fprintf(&b, "%s: %d live / %d recovery — %s\n",
		r.Kind, r.LiveCount, r.RecoveryCount, strings.Join(parts, ", "))

	if len(r.OnlyLive) > 0 || len(r.OnlyRecovery) > 0 {
		b.WriteString("  these exist in exactly one place:\n")
		for _, e := range r.OnlyLive {
			fmt.Fprintf(&b, "    %s\n", e)
		}
		for _, e := range r.OnlyRecovery {
			fmt.Fprintf(&b, "    %s (recovery only)\n", e)
		}
	}
	r.writeDiffering(&b)
	return b.String()
}

// writeDiffering renders the entries that exist on both sides but do not match,
// naming which side is older when that is knowable. Split out of Text to keep
// its cyclomatic complexity under the repo lint budget.
func (r Result) writeDiffering(b *strings.Builder) {
	if len(r.Differing) == 0 {
		return
	}
	older := make(map[string]bool, len(r.LiveOlder))
	for _, e := range r.LiveOlder {
		older[e] = true
	}
	if len(r.LiveOlder) == 0 {
		b.WriteString("  these exist in both but the recovery copy is out of date:\n")
	} else {
		b.WriteString("  these exist in both but do not match:\n")
	}
	for _, e := range r.Differing {
		if older[e] {
			fmt.Fprintf(b, "    %s (LIVE IS OLDER)\n", e)
			continue
		}
		fmt.Fprintf(b, "    %s\n", e)
	}
	// The remedy for "your backup is behind" is to refresh the backup. If the
	// live side is the older one, that remedy overwrites good data with
	// reverted data, so the warning belongs where the user is already looking.
	if len(r.LiveOlder) > 0 {
		b.WriteString("  WARNING: the live copy is OLDER for the entries marked above.\n")
		b.WriteString("  That is what a reverted or rolled-back live tree looks like.\n")
		b.WriteString("  Do NOT refresh the recovery copy until you know which side is right —\n")
		b.WriteString("  the recovery copy may be the only correct data you still have.\n")
	}
}
